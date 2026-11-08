// Package configstage decides whether a config change only tightens (and
// applies at once) or loosens (and waits for the login gate), and holds the
// staged change meanwhile (spec 4.8).
package configstage

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/atas/nazar/core/config"
)

// Finding is one reason a change loosens the config.
type Finding struct {
	Target string // "ssh:github", "ssh:(keys without an entry)", "secret:GH_TOKEN" or a setting name
	Why    string
}

// Diff describes a change from the active config to a new one.
type Diff struct {
	Changes   []string    // human-readable list of what changed
	Loosening []Finding   // empty when the change only tightens
	Pins      []PinChange // app: team pins an approval records (never set by Classify)
}

// Loosens reports whether the change needs the login gate.
func (d Diff) Loosens() bool { return len(d.Loosening) > 0 }

// Empty reports whether nothing that matters changed.
func (d Diff) Empty() bool { return len(d.Changes) == 0 && len(d.Loosening) == 0 }

// unconfigured is the pseudo-key standing for keys with no config entry.
const unconfigured = "(keys without an entry)"

// maxFindingsPerTarget bounds the findings listed for one key. Two large
// rule lists can produce one finding per (old, new) rule pair; the prompt
// only needs enough to show why, so enumeration stops here with "and more".
const maxFindingsPerTarget = 20

// maxPairs bounds the (old slot, new slot) pairs the proof looks at for one
// key. Classify runs on every file change, on the watcher's goroutine; a
// file near config.MaxFileSize holds about 16k rules, and comparing every
// pair of them took tens of seconds. Above this many pairs the change is
// not compared at all: it is unprovable, so it needs the login gate (spec
// 4.8 skips the gate only for a change shown to tighten), and Classify says
// so at once. 1<<20 pairs is about a millisecond's work.
const maxPairs = 1 << 20

// slot is one place a request for a key can end up under first-match: a
// rule (rule != nil) or the fallback (rule == nil: every request that
// reaches it).
type slot struct {
	rule  *config.Rule
	pol   config.Policy
	label string
}

func slots(rules []config.Rule, fallback config.Policy) []slot {
	var out []slot
	for i := range rules {
		r := &rules[i]
		out = append(out, slot{rule: r, pol: r.Policy, label: fmt.Sprintf("rule %d", r.Index)})
	}
	return append(out, slot{pol: fallback, label: "fallback"})
}

func keySlots(c *config.Config, key string) []slot {
	var rules []config.Rule
	if k, ok := c.SSHAgent.Keys[key]; ok {
		rules = k.Rules
	}
	return slots(rules, c.Fallback(key))
}

func secretSlots(c *config.Config, name string) []slot {
	var rules []config.Rule
	if s, ok := c.Secrets[name]; ok {
		rules = s.Rules
	}
	return slots(rules, c.SecretFallback(name))
}

// gitHelper is secret name's helper.git mapping in c, or nil.
func gitHelper(c *config.Config, name string) *config.GitHelper {
	if s, ok := c.Secrets[name]; ok && s.Helper != nil {
		return s.Helper.Git
	}
	return nil
}

// helpers classifies a secret's helper.git mapping (secrets design 4): it
// names where git may be given the secret, so a mapping added, or one whose
// host or username changed, loosens when some request can get past the
// secret's new slots (open); one removed tightens. listed: the
// entry is in both configs (an added or removed entry is listed as that).
func helpers(d *Diff, target string, old, nw *config.GitHelper, listed, open bool) {
	if (old == nil && nw == nil) || (old != nil && nw != nil && *old == *nw) {
		return
	}
	if listed {
		switch {
		case nw == nil:
			d.Changes = append(d.Changes, fmt.Sprintf("%s: helper.git for %s removed", target, old))
		case old == nil:
			d.Changes = append(d.Changes, fmt.Sprintf("%s: helper.git for %s added", target, nw))
		default:
			d.Changes = append(d.Changes, fmt.Sprintf("%s: helper.git %s (user %q) → %s (user %q)", target, old, old.Username, nw, nw.Username))
		}
	}
	if nw != nil && open {
		d.Loosening = append(d.Loosening, Finding{Target: target, Why: "can now answer git for " + nw.String()})
	}
}

// envAllow is secret name's envAllow: list in c, or nil.
func envAllow(c *config.Config, name string) []string {
	if s, ok := c.Secrets[name]; ok {
		return s.EnvAllow
	}
	return nil
}

// envAllows classifies a secret's envAllow: list (secrets design 4, 6.3.4):
// a name added means the receiver gets that variable with whatever value
// the caller gives it, so it loosens, even while every rule blocks: no
// later change that opens the secret would show it again. A name removed
// tightens.
func envAllows(d *Diff, target string, old, nw []string) {
	for _, n := range nw {
		if slices.Contains(old, n) {
			continue
		}
		d.Changes = append(d.Changes, fmt.Sprintf("%s: envAllow adds %s", target, n))
		d.Loosening = append(d.Loosening, Finding{Target: target, Why: "the receiver gets " + n + " from the caller"})
	}
	for _, n := range old {
		if !slices.Contains(nw, n) {
			d.Changes = append(d.Changes, fmt.Sprintf("%s: envAllow drops %s", target, n))
		}
	}
}

// union returns the names in a or b, sorted, each once.
func union(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

// delivers reports whether some request can get past these slots (a slot
// whose gate is not block): only then can a delivery method matter.
func delivers(ss []slot) bool {
	for _, s := range ss {
		if s.pol.Gate != config.GateBlock {
			return true
		}
	}
	return false
}

// deliveries classifies a secret's deliver: list (secrets design 4). A
// method added loosens when some request can get past the secret's new
// slots (open): the value can then leave nazar a new way. A method removed
// tightens. A secret without an entry, like an entry without deliver:, has
// config.DefaultDeliver(), so writing the default out is no change. listed:
// the entry is in both configs; the change lines are for such an entry
// only (an added or removed entry is listed as that).
func deliveries(d *Diff, target string, old, nw []config.Delivery, listed, open bool) {
	for _, m := range nw {
		if slices.Contains(old, m) {
			continue
		}
		if listed {
			d.Changes = append(d.Changes, fmt.Sprintf("%s: deliver adds %s", target, m))
		}
		if open {
			d.Loosening = append(d.Loosening, Finding{Target: target, Why: fmt.Sprintf("can now be delivered by %s", m)})
		}
	}
	if !listed {
		return
	}
	for _, m := range old {
		if !slices.Contains(nw, m) {
			d.Changes = append(d.Changes, fmt.Sprintf("%s: deliver drops %s", target, m))
		}
	}
}

func slotText(s slot) string {
	if s.rule == nil {
		return s.pol.String()
	}
	return s.rule.Canonical()
}

// gateRank orders gates from weakest to strictest; -1 for one the package
// doesn't know. (A switch, not a map: AtLeastAsStrict runs up to maxPairs
// times per key on every file change.)
func gateRank(g config.Gate) int {
	switch g {
	case config.GateNone:
		return 0
	case config.GateDialog:
		return 1
	case config.GateLogin:
		return 2
	case config.GateBlock:
		return 3
	}
	return -1
}

// scopeBreadth orders scopes from narrowest to broadest; -1 when unknown.
func scopeBreadth(s config.Scope) int {
	switch s {
	case config.ScopeUse:
		return 0
	case config.ScopeSession:
		return 1
	case config.ScopeApp:
		return 2
	}
	return -1
}

// AtLeastAsStrict reports whether policy n asks at least as much as o in
// every dimension: gate, scope breadth and expiry. Block is stricter than
// everything; none is weaker than every prompt. Scope and expiry only
// matter between two prompting gates, and scope use remembers nothing, so
// its expiry is irrelevant. A gate or scope the package doesn't know is
// never "at least as strict".
func AtLeastAsStrict(n, o config.Policy) bool {
	nr, or := gateRank(n.Gate), gateRank(o.Gate)
	if nr < 0 || or < 0 {
		return false
	}
	if n.Gate == config.GateBlock {
		return true
	}
	if o.Gate == config.GateBlock || nr < or {
		return false
	}
	if !n.Gate.Prompts() || !o.Gate.Prompts() {
		return true // n == none == o, or n prompts where o was silent
	}
	ns, os := scopeBreadth(n.Scope), scopeBreadth(o.Scope)
	if ns < 0 || os < 0 || ns > os {
		return false
	}
	if n.Scope == config.ScopeUse {
		return true
	}
	return expireLE(n.Expire, o.Expire)
}

// expireLE reports whether expiry n is no longer than o (0 = never expires).
func expireLE(n, o time.Duration) bool {
	if o == 0 {
		return true
	}
	return n != 0 && n <= o
}

// Classify compares the active config with a new one, key by key over
// first-match slots. A change loosens when some request that reached an old
// slot could reach a new slot with a weaker policy. Two slots are known to
// be disjoint only when an earlier slot of the other config provably
// (config.Covers) stops those requests first; every other pair is assumed
// to overlap, because a matcher matches any process in the caller chain, so
// a chain can satisfy several rules at once. Removing or reordering rules
// can therefore loosen. Moving the agent socket and logging less in the
// audit log need approval too; the dialog timeout does not. A section this
// version cannot check is never approved silently: see unvetted. k8s
// contexts (target k8s:<name>) are compared like keys, with their cluster,
// identity, credential, a leftover clients: line and ttl_cert on top
// (k8sContexts); aws entries (target aws:<name>) likewise, with their ARNs,
// identity and duration (awsEntries).
// Secrets (target secret:<NAME>) are compared like keys, with their
// deliver: list on top (deliveries). The proof is bounded (maxPairs per key
// or secret): past that a change is reported as loosening because it could
// not be checked, never as safe.
func Classify(old, nw *config.Config) Diff {
	var d Diff
	for _, key := range append(union(old.KeyNames(), nw.KeyNames()), unconfigured) {
		target := "ssh:" + key
		var os, ns []slot
		inOld, inNew := true, true
		if key == unconfigured {
			os = []slot{{pol: old.Defaults.Fallback, label: "defaults.fallback"}}
			ns = []slot{{pol: nw.Defaults.Fallback, label: "defaults.fallback"}}
		} else {
			_, inOld = old.SSHAgent.Keys[key]
			_, inNew = nw.SSHAgent.Keys[key]
			os, ns = keySlots(old, key), keySlots(nw, key)
		}
		d.Changes = append(d.Changes, describe(target, "key", inOld, inNew, os, ns)...)
		d.Loosening = append(d.Loosening, loosenings(target, os, ns)...)
	}
	for _, name := range union(old.SecretNames(), nw.SecretNames()) {
		target := "secret:" + name
		_, inOld := old.Secrets[name]
		_, inNew := nw.Secrets[name]
		os, ns := secretSlots(old, name), secretSlots(nw, name)
		d.Changes = append(d.Changes, describe(target, "secret", inOld, inNew, os, ns)...)
		d.Loosening = append(d.Loosening, loosenings(target, os, ns)...)
		deliveries(&d, target, old.Deliver(name), nw.Deliver(name), inOld && inNew, delivers(ns))
		helpers(&d, target, gitHelper(old, name), gitHelper(nw, name), inOld && inNew, delivers(ns))
		envAllows(&d, target, envAllow(old, name), envAllow(nw, name))
	}
	k8sContexts(&d, old, nw)
	awsEntries(&d, old, nw)
	settings(&d, old, nw)
	unvetted(&d, old, nw)
	return d
}

// unvetted handles the sections Parse recognises but this version does not
// build (config.Config.Unimplemented; none since M12). Their rules cannot be
// checked, so a file that carries one is never blessed as approved without
// the login gate: every change to such a file loosens, and the diff names
// the section (spec 4.2: nazar never guesses at a schema it doesn't know;
// 4.8: only a pure tightening skips approval, and the diff lists every
// change). Otherwise malware could plant rules for itself under such a
// section, have the bytes saved as the approved config, and find them
// already trusted once a later version enforces that section. Dropping
// such a section only tightens. This is deliberately conservative: a
// tightening edit elsewhere in a file that carries one needs approval
// too, until config records what each unvetted section says.
func unvetted(d *Diff, old, nw *config.Config) {
	if bytes.Equal(old.Raw, nw.Raw) {
		return
	}
	was := map[string]bool{}
	for _, sec := range old.Unimplemented {
		was[sec] = true
	}
	for _, sec := range nw.Unimplemented {
		if was[sec] {
			d.Changes = append(d.Changes, sec+": section present, not checked by this version (it may have changed)")
		} else {
			d.Changes = append(d.Changes, sec+": section added, not checked by this version")
		}
		d.Loosening = append(d.Loosening, Finding{Target: sec, Why: fmt.Sprintf(
			"this version cannot check the %s section, so every change to a file that carries it needs approval", sec)})
		delete(was, sec)
	}
	for _, sec := range old.Unimplemented {
		if was[sec] {
			d.Changes = append(d.Changes, sec+": section removed")
		}
	}
}

// loosenings lists the (old slot, new slot) pairs that might share a
// request and where the new policy is weaker. Slot lists that read the same
// (same matchers, policies and order) mean the same, whatever their size.
// Otherwise, beyond maxPairs the proof is not attempted and the change
// counts as loosening: approval is required because nothing was shown.
func loosenings(target string, os, ns []slot) []Finding {
	if sameSlots(os, ns) {
		return nil
	}
	if len(os)*len(ns) > maxPairs {
		return []Finding{{Target: target, Why: fmt.Sprintf(
			"too many rules to compare; approval required (%d rules before, %d after)", len(os)-1, len(ns)-1)}}
	}
	// firstOld[j]: the lowest old slot that covers new slot j, or -1.
	// Requests reaching old slot i failed every earlier old slot, so if
	// firstOld[j] < i no request of new slot j reached old slot i. The
	// same holds the other way round with firstNew[i] < j.
	firstOld := firstCovering(os, ns)
	firstNew := firstCovering(ns, os)
	var out []Finding
	for j := range ns {
		for i := range os {
			if AtLeastAsStrict(ns[j].pol, os[i].pol) {
				continue
			}
			if (firstOld[j] >= 0 && firstOld[j] < i) || (firstNew[i] >= 0 && firstNew[i] < j) {
				continue
			}
			if len(out) == maxFindingsPerTarget {
				return append(out, Finding{Target: target, Why: "and more such pairs"})
			}
			out = append(out, Finding{Target: target, Why: fmt.Sprintf(
				"requests that got %s (%s) can now get %s (%s)", os[i].pol, os[i].label, ns[j].pol, ns[j].label)})
		}
	}
	return out
}

// sameSlots reports whether the two slot lists are the same rules with the
// same policies in the same order (by Canonical, so spelling and app names
// don't count). Under first-match that is the same behaviour exactly.
func sameSlots(os, ns []slot) bool {
	if len(os) != len(ns) {
		return false
	}
	for k := range os {
		if slotText(os[k]) != slotText(ns[k]) {
			return false
		}
	}
	return true
}

// covers reports whether every request reaching slot b's condition also
// matches slot a's. A fallback slot (nil rule) matches every request.
func covers(a, b *config.Rule) bool {
	if a == nil {
		return true
	}
	if b == nil {
		return config.CoversAll(*a)
	}
	return config.Covers(*a, *b)
}

// firstCovering returns, for each slot j of b, the lowest index i such that
// covers(a[i], b[j]), or -1. The interned matcher sets only filter the
// candidates (two rule lists near config.MaxFileSize would otherwise spend
// minutes rebuilding Canonical strings); an index is reported only when
// config.Covers or CoversAll confirms it, so the result is never less
// conservative than those.
func firstCovering(a, b []slot) []int {
	ids := map[string]int32{}
	ac, bc := conds(ids, a), conds(ids, b)
	out := make([]int, len(b))
	for j := range b {
		out[j] = -1
		for i := range a {
			if mightCover(ac[i], bc[j]) && covers(a[i].rule, b[j].rule) {
				out[j] = i
				break
			}
		}
	}
	return out
}

// cond is a slot's condition with its matchers interned as atom ids.
type cond struct {
	all bool // fallback slot: every request
	// toOpen: no to: at all. to: [any] (only in an approved config read
	// the old way, config.ParseApproved) matches every receiver too, but on
	// a key's rule it also ties each remembered approval to its receiver,
	// so a rule with it never counts as covering one without: removing it
	// is a change the proof can't show is safe, and waits for the gate.
	appsAny, toOpen bool
	apps, to        []int32
}

func conds(ids map[string]int32, ss []slot) []cond {
	intern := func(ms []config.Matcher) []int32 {
		out := make([]int32, 0, len(ms))
		for _, m := range ms {
			c := m.Canonical()
			id, ok := ids[c]
			if !ok {
				id = int32(len(ids))
				ids[c] = id
			}
			out = append(out, id)
		}
		return out
	}
	out := make([]cond, len(ss))
	for k, s := range ss {
		if s.rule == nil {
			out[k] = cond{all: true}
			continue
		}
		out[k] = cond{
			appsAny: hasKind(s.rule.Apps, config.MatchAny),
			toOpen:  len(s.rule.To) == 0,
			apps:    intern(s.rule.Apps),
			to:      intern(s.rule.To),
		}
	}
	return out
}

// mightCover mirrors config.Covers and CoversAll on interned atoms.
func mightCover(a, b cond) bool {
	if a.all {
		return true
	}
	if b.all {
		return a.appsAny && a.toOpen
	}
	if !a.appsAny && (len(b.apps) == 0 || !subset(b.apps, a.apps)) {
		return false
	}
	return a.toOpen || (len(b.to) > 0 && subset(b.to, a.to))
}

func subset(b, a []int32) bool {
	for _, x := range b {
		found := false
		for _, y := range a {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func hasKind(ms []config.Matcher, k config.MatcherKind) bool {
	for _, m := range ms {
		if m.Kind == k {
			return true
		}
	}
	return false
}

// describe lists what changed for one key or secret: its entry appearing
// or going, and every slot whose meaning (matchers and policy) is not found
// in the other config. Rules are compared by Canonical, so renaming an app, the
// order inside apps:, comments and spelling differences are not changes.
func describe(target, noun string, inOld, inNew bool, os, ns []slot) []string {
	var out []string
	switch {
	case !inOld && inNew:
		out = append(out, target+": "+noun+" entry added")
	case inOld && !inNew:
		out = append(out, target+": "+noun+" entry removed")
	}
	oldSet, newSet := map[string]int{}, map[string]int{}
	for _, s := range os {
		oldSet[slotText(s)]++
	}
	for _, s := range ns {
		newSet[slotText(s)]++
	}
	for _, s := range os {
		if t := slotText(s); newSet[t] > 0 {
			newSet[t]--
		} else {
			out = append(out, fmt.Sprintf("%s: removed %s: %s", target, s.label, t))
		}
	}
	for _, s := range ns {
		if t := slotText(s); oldSet[t] > 0 {
			oldSet[t]--
		} else {
			out = append(out, fmt.Sprintf("%s: added %s: %s", target, s.label, t))
		}
	}
	return out
}

func settings(d *Diff, old, nw *config.Config) {
	if old.SSHAgent.Socket != nw.SSHAgent.Socket {
		d.Changes = append(d.Changes, fmt.Sprintf("ssh_agent.socket: %s → %s", old.SSHAgent.Socket, nw.SSHAgent.Socket))
		d.Loosening = append(d.Loosening, Finding{Target: "ssh_agent.socket", Why: "the agent socket moves"})
	}
	if old.Audit.Args != nw.Audit.Args {
		d.Changes = append(d.Changes, fmt.Sprintf("audit.args: %s → %s", old.Audit.Args, nw.Audit.Args))
		if nw.Audit.Args == config.ArgsNone {
			// "none" logs less; it is asked for so a caller can't quietly
			// reduce what the audit log shows about it.
			d.Loosening = append(d.Loosening, Finding{Target: "audit.args", Why: "less is logged about each request"})
		}
	}
	if !slices.Equal(old.Defaults.TrustedPath, nw.Defaults.TrustedPath) {
		// Where nazar run resolves a receiver and the receiver's PATH:
		// adding, removing or reordering a directory can each make a name
		// resolve to another file (secrets design 4).
		d.Changes = append(d.Changes, fmt.Sprintf("defaults.trustedPath: %s → %s", pathList(old.Defaults.TrustedPath), pathList(nw.Defaults.TrustedPath)))
		d.Loosening = append(d.Loosening, Finding{Target: "defaults.trustedPath", Why: "nazar run receivers are found in, and given as PATH, other directories"})
	}
	if old.Defaults.Timeout != nw.Defaults.Timeout {
		d.Changes = append(d.Changes, fmt.Sprintf("defaults.timeout: %s → %s", old.Defaults.Timeout, nw.Defaults.Timeout))
	}
}

// pathList shows a directory list as [a, b], each element Go-quoted when it
// is not plain, so a crafted name can't forge a line of the dialog.
func pathList(dirs []string) string {
	out := make([]string, len(dirs))
	for i, d := range dirs {
		out[i] = q(d)
	}
	return "[" + strings.Join(out, ", ") + "]"
}
