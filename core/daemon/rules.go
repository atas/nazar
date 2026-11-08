package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/platform"
)

// The commands the Nazar window needs from the CLI (spec 6, 6.1; Milestone
// 5): a key's rules, the top-level apps, and edits of config.yaml that go
// through the usual staging. The window runs the CLI and nothing else, so
// everything it shows or changes is here, for people and agents too.

// shownConfig is the config whose rules `ssh-key rules`, `ssh-key list`
// and `apps list` show, and that config.edit edits: the staged change when
// there is one (it is what config.yaml says now), else the one in force.
func (d *Daemon) shownConfig() (*config.Config, bool) {
	if p, ok := d.stager.Pending(); ok {
		return p.Config, true
	}
	return d.stager.Active(), false
}

func policyInfo(p config.Policy) control.PolicyInfo {
	pi := control.PolicyInfo{Scope: string(p.Scope), Gate: string(p.Gate)}
	if p.Expire > 0 {
		pi.Expire = config.FormatDuration(p.Expire)
	}
	return pi
}

// matcherInfo describes m; Ref is how `--apps`/`--to` write it.
func matcherInfo(m config.Matcher) control.MatcherInfo {
	mi := control.MatcherInfo{Name: m.Name, Kind: string(m.Kind), Team: m.Team, ID: m.ID, Path: m.Path, Command: m.Command}
	switch {
	case m.Name != "":
		mi.Ref = m.Name
	case m.Kind == config.MatchApp:
		mi.Ref = "app:" + m.ID
	case m.Kind == config.MatchSigned && m.ID != "":
		mi.Ref = "signed:" + m.Team + ":" + m.ID
	case m.Kind == config.MatchSigned:
		mi.Ref = "signed:" + m.Team
	case m.Kind == config.MatchPath:
		mi.Ref = "path:" + m.Path
	}
	return mi
}

func matcherInfos(ms []config.Matcher) []control.MatcherInfo {
	out := []control.MatcherInfo{}
	for _, m := range ms {
		out = append(out, matcherInfo(m))
	}
	return out
}

// entryRules is the rules of e (an SSH key, a secret or a k8s context) in
// c: its rules, its own policy and the fallback for callers no rule
// matches.
func entryRules(e config.Entry, c *config.Config, staged bool) control.SSHKeyRules {
	r := control.SSHKeyRules{TypeMeta: control.Meta(control.KindSSHKeyRules), Name: e.Name, Staged: staged,
		ConfigHash: contentHash(c.Raw), Rules: []control.RuleInfo{}, FallbackSource: "defaults.fallback"}
	var rules []config.Rule
	var own *config.Policy
	ownSource := "key-gate"
	switch {
	case e.IsK8s():
		r.Fallback, ownSource = policyInfo(c.K8sFallback(e.Name)), "context-gate"
		k, ok := c.K8s[e.Name]
		if !ok || k == nil {
			return r
		}
		rules, own = k.Rules, k.Own
	case e.IsAWS():
		r.Fallback, ownSource = policyInfo(c.AWSFallback(e.Name)), "entry-gate"
		a, ok := c.AWS[e.Name]
		if !ok || a == nil {
			return r
		}
		rules, own = a.Rules, a.Own
	case e.IsSecret():
		r.Fallback, ownSource = policyInfo(c.SecretFallback(e.Name)), "secret-gate"
		s, ok := c.Secrets[e.Name]
		if !ok || s == nil {
			return r
		}
		rules, own = s.Rules, s.Own
	default:
		r.Fallback = policyInfo(c.Fallback(e.Name))
		k, ok := c.SSHAgent.Keys[e.Name]
		if !ok || k == nil {
			return r
		}
		rules, own = k.Rules, k.Own
	}
	r.Configured = true
	for _, rule := range rules {
		r.Rules = append(r.Rules, control.RuleInfo{Index: rule.Index, Apps: matcherInfos(rule.Apps), To: matcherInfos(rule.To),
			Policy: policyInfo(rule.Policy)})
	}
	if own != nil {
		o := policyInfo(*own)
		r.Own, r.FallbackSource = &o, ownSource
	}
	return r
}

// sshKeyRules is `nazar ssh-key rules <name>`: for a key that exists, has
// a config entry, or both.
func (d *Daemon) sshKeyRules(name string, out control.Emitter) error {
	if !config.ValidKeyName(name) {
		return control.NewProblem(control.CodeUsage, "invalid key name %q", name)
	}
	c, staged := d.shownConfig()
	r := entryRules(config.KeyEntry(name), c, staged)
	if !r.Configured {
		if _, err := d.keys.Get(name); errors.Is(err, keys.ErrNotFound) {
			return control.NewProblem(control.CodeError, "no SSH key or config entry named %q", name)
		}
	}
	return out.Emit(r)
}

// keyWarnings is what config check and status say about key k: its Secure
// Enclave protection against its gates, and the warnings Parse gave about
// its entry (a rule that can never match, a field that is ignored).
func (d *Daemon) keyWarnings(k keys.Info, c *config.Config) []string {
	w := []string{}
	if !k.Broken {
		if msg := presenceAdvice(c, k.Name, k.Auth); msg != "" {
			w = append(w, msg)
		}
	}
	prefix := "ssh_agent.keys." + k.Name
	for _, p := range d.stager.LastProblems() {
		if p.Severity == config.SevWarning && (p.Path == prefix || strings.HasPrefix(p.Path, prefix+".")) {
			w = append(w, p.Message)
		}
	}
	return w
}

// appsList is `nazar apps list`: the top-level apps: of the shown config,
// with pins, problems and the rules that use each.
func (d *Daemon) appsList(out control.Emitter) error {
	c, staged := d.shownConfig()
	res := control.AppList{TypeMeta: control.Meta(control.KindAppList), Staged: staged, ConfigHash: contentHash(c.Raw), Items: []control.AppEntry{}}
	problems := map[string]configstage.AppProblem{}
	for _, p := range configstage.AppProblems(c, d.trust, d.o.Platform) {
		problems[p.BundleID] = p
	}
	entry := func(name string, m config.Matcher, used []string) control.AppEntry {
		e := control.AppEntry{Name: name, Matcher: matcherInfo(m), UsedBy: append([]string{}, used...)}
		switch m.Kind {
		case config.MatchApp:
			if team, ok := d.trust.PinnedTeam(m.ID); ok {
				e.PinnedTeam = team
			}
			if p, ok := problems[m.ID]; ok {
				e.Problem, e.Fix = p.Reason, p.Fix
			}
		}
		return e
	}
	used := usedBy(c)
	names := make([]string, 0, len(c.Apps))
	for n := range c.Apps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		res.Items = append(res.Items, entry(n, c.Apps[n], used[n]))
	}
	// Then the matchers written inline in rules, once each, in key and rule
	// order (a config without top-level apps: is the common case).
	inline, order := map[string][]string{}, []config.Matcher{}
	for _, u := range ruleUses(c) {
		if u.m.Name != "" || (u.m.Kind != config.MatchApp && u.m.Kind != config.MatchSigned && u.m.Kind != config.MatchPath) {
			continue
		}
		k := u.m.Canonical()
		if _, seen := inline[k]; !seen {
			order = append(order, u.m)
		}
		inline[k] = append(inline[k], u.where)
	}
	for _, m := range order {
		res.Items = append(res.Items, entry("", m, inline[m.Canonical()]))
	}
	return out.Emit(res)
}

// usedBy maps each apps: name to the rules that use it ("github rule 1",
// "secret NOTES rule 2 (to)"), in the order of ruleUses.
func usedBy(c *config.Config) map[string][]string {
	out := map[string][]string{}
	for _, u := range ruleUses(c) {
		if u.m.Name != "" {
			out[u.m.Name] = append(out[u.m.Name], u.where)
		}
	}
	return out
}

// ruleUse is one matcher of one rule, and how the Apps list names that rule.
type ruleUse struct {
	m     config.Matcher
	where string
}

// ruleUses lists every matcher of every rule: the keys' ("github rule 1"),
// then the secrets' ("secret NOTES rule 1"), the k8s contexts' ("k8s hydra
// rule 1") and the aws entries' ("aws dev rule 1"), sorted by name, a rule's
// apps: before its to: ("... (to)"). The same name may be a key and a secret,
// hence the prefix.
func ruleUses(c *config.Config) []ruleUse {
	var out []ruleUse
	add := func(owner string, rules []config.Rule) {
		for _, r := range rules {
			for _, m := range r.Apps {
				out = append(out, ruleUse{m, fmt.Sprintf("%s rule %d", owner, r.Index)})
			}
			for _, m := range r.To {
				out = append(out, ruleUse{m, fmt.Sprintf("%s rule %d (to)", owner, r.Index)})
			}
		}
	}
	for _, n := range c.KeyNames() {
		add(n, c.SSHAgent.Keys[n].Rules)
	}
	for _, n := range c.SecretNames() {
		add("secret "+n, c.Secrets[n].Rules)
	}
	for _, n := range c.K8sNames() {
		add("k8s "+n, c.K8s[n].Rules)
	}
	for _, n := range c.AWSNames() {
		add("aws "+n, c.AWS[n].Rules)
	}
	return out
}

// configEdit is config.edit: it applies one edit to config.yaml, under the
// lock the file poller takes, and observes its own result at once without
// the background prompt. A tightening applies; a loosening is written and
// staged only with allowLoosen (the CLI's --allow-loosen-access, which then
// sends the config.apply that shows the one prompt) and otherwise refused
// with what it would loosen (control.LoosensRefusal, exit 2), nothing
// written, so an agent can show a rule to the person and only the person
// at the Mac can open access (spec 6). The edit is
// refused, and nothing written, when the file is invalid, is not exactly
// the approved config (ErrNotApproved below), changed since the caller
// read it (ifHash), or would be invalid afterwards. It is refused too
// while an earlier edit's loosening holds the background prompt (editHold)
// and while any login prompt is claimed or open (no hold may start under a
// prompt claimed before it).
//
// Only a file that holds exactly the approved config, with nothing
// pending, is edited, so what is classified is the edit's own
// change and nothing else: an edit on a file holding someone else's
// change (staged, or not observed yet) would otherwise be reported, and
// approved by `nazar config apply`, as the edit's own. It never observes
// content it did not write: a hand edit it refuses stays unobserved, and
// the poller prompts for it exactly as if the edit had not been asked for.
func (d *Daemon) configEdit(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	op := args["op"]
	e, edit, err := editFor(args)
	if err != nil {
		return err
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	env := config.Env{Home: d.o.Home}
	if data != nil {
		if _, probs := config.Parse(data, env); probs.HasErrors() {
			return control.NewProblem(control.CodeError, "config.yaml is invalid; fix it first (`nazar config check`)")
		}
	}
	if p := d.notApproved(data); p != nil {
		return p
	}
	// A context needs its cluster and identity, which only k8s ca create
	// writes on its own prompt: an edit never creates one. The file
	// is the approved config (notApproved), so this is the entry it edits.
	if e.IsK8s() && d.stager.Active().K8s[e.Name] == nil {
		return control.NewProblem(control.CodeError, "there is no k8s context %s in config.yaml; nazar k8s ca create %s sets one up", e.Name, e.Name)
	}
	if e.IsAWS() && d.stager.Active().AWS[e.Name] == nil {
		return control.NewProblem(control.CodeError, "there is no aws entry %s in config.yaml; nazar aws ca create %s sets one up", e.Name, e.Name)
	}
	if h := d.heldLocked(); h != "" {
		// The file was put back to the approved config after an edit's
		// loosening was staged, and that edit's apply has not come yet:
		// another edit now would take its place in the prompt the user is
		// waiting for (editHold).
		return control.NewProblem(control.CodeError, "a change made with nazar is waiting for approval (`nazar config apply`); approve it, or edit again in %s", seconds(d.hold.until.Sub(d.o.Now())+time.Second-1))
	}
	// No hold may start while a login prompt is claimed or open: the
	// claimer read the hold before claiming, and its prompt would then be
	// shown during the hold, for a change that is not this edit's, at the
	// moment the user expects their own (approveStagedShown reads it again;
	// this makes that read authoritative). Lock order reloadMu → prompts.mu.
	d.prompts.mu.Lock()
	open := d.prompts.open
	d.prompts.mu.Unlock()
	if open {
		return control.NewProblem(control.CodeError, "an approval prompt is open; answer it first, then edit again; nothing was changed")
	}
	if want, ok := args["ifHash"]; ok && want != contentHash(data) {
		again := "nazar ssh-key rules " + e.Name
		switch {
		case e.IsSecret():
			again = "nazar secret list"
		case e.IsK8s():
			again = "nazar k8s list"
		case e.IsAWS():
			again = "nazar aws list"
		}
		return control.NewProblem(control.CodeError, "config.yaml changed since it was read; read it again (`%s`)", again)
	}
	newData, err := edit(data)
	if err != nil {
		return control.NewProblem(control.CodeError, "%v", err)
	}
	nw, probs := config.Parse(newData, env)
	if probs.HasErrors() {
		p := control.NewProblem(control.CodeError, "the edited config.yaml would be invalid; nothing was changed")
		for _, pr := range probs {
			if pr.Severity == config.SevError {
				p.Details = append(p.Details, pr.Path+": "+pr.Message)
			}
		}
		return p
	}
	// A rule the key's recorded protection cannot serve is refused
	// here, with the fix, instead of failing at sign time (keyadvice.go says
	// why: the chip refuses a dialog or none gate, and a remembered login
	// lapses after minutes). Every edit that adds such a policy is refused,
	// whether or not it loosens access now: a rule added behind one that
	// shadows it is no loosening when added, and removing the shadowing rule
	// later adds no unfit policy, so a loosening-only check let it through
	// (a security review of --always-ask). One already in the approved
	// entry (a hand edit, or a rule added before Milestone 7) never stops
	// a tightening or a fitting rule: only a growing count is refused. Only
	// nazar's own edits are refused; a hand edit of the file is staged and
	// warned about as before.
	if old := d.stager.Active(); e.IsKey() && chipUnfit(nw, e.Name) > chipUnfit(old, e.Name) {
		key := e.Name
		if info, err := d.keys.Get(key); err == nil && info.Auth == platform.AuthUserPresence {
			return control.NewProblem(control.CodeError, "SSH key %s asks on every use (enforced by the chip); create another key for a looser rule (nothing was changed)", strconv.QuoteToASCII(key))
		}
	}
	res := control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Op: op, Path: d.o.ConfigPath,
		Hash: contentHash(newData), Problems: []control.ConfigProblem{}}
	what := fmt.Sprintf("config edit (%s %s)", op, e.Name)
	switch {
	case e.IsSecret():
		res.Secret, what = e.Name, fmt.Sprintf("config edit (%s secret:%s)", op, e.Name)
	case e.IsK8s():
		res.Context, what = e.Name, fmt.Sprintf("config edit (%s k8s:%s)", op, e.Name)
	case e.IsAWS():
		res.AWS, what = e.Name, fmt.Sprintf("config edit (%s aws:%s)", op, e.Name)
	default:
		res.Key = e.Name
	}
	// What config check says about the file as written, the new rule's
	// own warnings included.
	res.Problems = d.fileProblems(nw, probs)
	if bytes.Equal(newData, data) {
		// Nothing to write, and the file is the approved config: in force.
		res.Applied = true
		return out.Emit(res)
	}
	// An edit that loosens access is written only when the caller said so
	// (allowLoosen, the CLI's --allow-loosen-access, which then approves it
	// at once): without it, the file stays the approved config and the
	// caller is told what the change would loosen, so an agent can show a
	// rule to the person without touching the file or the prompt. The
	// classification is the one Observe would make of the written file:
	// the file is the approved config with nothing pending (notApproved
	// above), which is exactly what Preview compares against.
	pv, err := d.stager.Preview(newData)
	if err != nil {
		return control.NewProblem(control.CodeError, "%v", err)
	}
	if pv.Diff.Loosens() && args["allowLoosen"] != "true" {
		p := control.NewProblem(control.CodeUsage, "%s", control.LoosensRefusal)
		p.Details = append(p.Details, pv.Diff.Changes...)
		for _, f := range pv.Diff.Loosening {
			p.Details = append(p.Details, "loosens "+f.Target+": "+f.Why)
		}
		d.logOp("config", audit.Blocked, what+": refused: it loosens access and --allow-loosen-access was not given; nothing was changed", peer)
		return p
	}
	if err := writeFileAtomic(d.o.ConfigPath, newData); err != nil {
		return err
	}
	res.Changed = true
	// Observe exactly the bytes written, never a re-read of the file: a
	// hand edit that lands after the write is the poller's to see (and to
	// prompt for); this edit must not stage it, or mark it seen, as its own.
	d.mu.Lock()
	d.lastSeen = contentHash(newData)
	d.mu.Unlock()
	r := d.stager.Observe(newData)
	pend, staged := d.stager.Pending()
	switch {
	case r.Staged && staged && bytes.Equal(pend.Config.Raw, newData):
		// Classified against the approved config, which the file was: the
		// diff is exactly this edit's change.
		res.Staged = diffObj(pend, false)
		// Hold the background prompt for anything else until this change's
		// apply has been handled (editHold).
		d.hold = editHold{hash: res.Staged.Hash, until: d.o.Now().Add(editHoldFor)}
		d.logOp("config", audit.Blocked, what+": staged; run nazar config apply", peer)
	case r.Applied || (!r.Staged && !r.Invalid && sameContent(newData, d.stager.Active())):
		if r.Applied {
			d.prompts.forget() // the contents seen so far were changes against the old config
		}
		res.Applied = true
		d.logOp("config", audit.Allowed, what+": applied", peer)
	default:
		d.logOp("config", audit.Error, what+": written, but it could not be observed", peer)
		return control.NewProblem(control.CodeError, "config.yaml was written but the edit could not be observed; run `nazar config check`")
	}
	return out.Emit(res)
}

// chipUnfit counts the policies that can apply to key which a
// user-presence key cannot serve (config.ChipPresenceFits).
func chipUnfit(c *config.Config, key string) int {
	n := 0
	for _, p := range c.Policies(key) {
		if !config.ChipPresenceFits(p) {
			n++
		}
	}
	return n
}

// notApproved refuses an edit of data unless it is exactly the approved
// (active) config with nothing staged and the approved config was read
// from the vault (after a rebuild the built-in default is in force and
// the whole file waits for the gate). The refusal is a plain error (exit
// 1), never staged (exit 4) and never the loosening refusal (exit 2):
// either would present the other change as the edit's own, and a caller
// answers a staged edit with `nazar config apply`, which would put the
// other change's prompt in front of the user as the edit's own.
func (d *Daemon) notApproved(data []byte) *control.Problem {
	_, pending := d.stager.Pending()
	unreadable := d.stager.Unreadable()
	if !pending && unreadable == "" && sameContent(data, d.stager.Active()) {
		return nil
	}
	p := control.NewProblem(control.CodeError, "config.yaml has changes that are not approved yet; run `nazar config apply` or revert them first")
	switch {
	case pending:
		p.Details = append(p.Details, "a change to config.yaml is staged; `nazar config check` shows it")
	case unreadable != "":
		p.Details = append(p.Details, "the approved config could not be read ("+unreadable+"), so all of config.yaml waits for approval")
	default:
		p.Details = append(p.Details, "config.yaml differs from the approved config (changed by hand or by another program); `nazar config check` shows the change")
	}
	return p
}

// editFor checks config.edit's args (the CLI checked them too; this side
// trusts nothing) and returns the entry it edits (an SSH key's, a secret's
// a k8s context's or an aws entry's, looked up by its exact name in its
// own section) and the edit to run on config.yaml's bytes. A context's edit
// takes no to at all: the program that runs the plugin receives it (k8s
// design 2.1); nor does an aws entry's: the program that runs
// credential_process receives it (aws design 6.1).
func editFor(args map[string]string) (config.Entry, func([]byte) ([]byte, error), error) {
	usage := func(format string, a ...any) (config.Entry, func([]byte) ([]byte, error), error) {
		return config.Entry{}, nil, control.NewProblem(control.CodeUsage, format, a...)
	}
	key, isKey := args["key"]
	secret, isSecret := args["secret"]
	ctx, isK8s := args["context"]
	awsName, isAWS := args["aws"]
	named := 0
	for _, ok := range []bool{isKey, isSecret, isK8s, isAWS} {
		if ok {
			named++
		}
	}
	var e config.Entry
	switch {
	case named != 1:
		return usage("give exactly one of key, secret, context or aws, not both or neither")
	case isKey && !config.ValidKeyName(key):
		return usage("invalid key name %q", key)
	case isKey:
		e = config.KeyEntry(key)
	case isSecret && !config.ValidSecretName(secret):
		return usage("invalid secret name %q", secret)
	case isSecret:
		e = config.SecretEntry(secret)
	case isAWS && !config.ValidAWSName(awsName):
		return usage("invalid aws entry name %q", awsName)
	case isAWS:
		if _, ok := args["to"]; ok {
			return usage("aws rules take no to: the program that runs credential_process receives the credential")
		}
		e = config.AWSRef(awsName)
	case !config.ValidK8sContextName(ctx):
		return usage("invalid context name %q", ctx)
	default:
		if _, ok := args["to"]; ok {
			return usage("k8s rules take no to: the program that runs the plugin receives the credential")
		}
		e = config.K8sEntry(ctx)
	}
	edit := func(fn func([]byte) ([]byte, error)) (config.Entry, func([]byte) ([]byte, error), error) {
		return e, fn, nil
	}
	refs := func(name string) ([]string, bool, error) {
		raw, ok := args[name]
		if !ok {
			return nil, false, nil
		}
		var list []string
		if raw != "" {
			if err := json.Unmarshal([]byte(raw), &list); err != nil {
				return nil, true, fmt.Errorf("%s must be a JSON list of matchers", name)
			}
		}
		for _, r := range list {
			if _, err := config.ParseMatcherRef(r); err != nil {
				return nil, true, err
			}
		}
		return list, true, nil
	}
	apps, hasApps, err := refs("apps")
	if err != nil {
		return usage("%v", err)
	}
	to, hasTo, err := refs("to")
	if err != nil {
		return usage("%v", err)
	}
	var scope *config.Scope
	if v, ok := args["scope"]; ok {
		s := config.Scope(v)
		if s != config.ScopeUse && s != config.ScopeSession && s != config.ScopeApp {
			return usage("scope must be use, session or app, not %q", v)
		}
		scope = &s
	}
	var gate *config.Gate
	if v, ok := args["gate"]; ok {
		g := config.Gate(v)
		if g != config.GateLogin && g != config.GateDialog && g != config.GateNone && g != config.GateBlock {
			return usage("gate must be login, dialog, none or block, not %q", v)
		}
		gate = &g
	}
	var expire *time.Duration
	if v, ok := args["expire"]; ok {
		var d time.Duration
		if v != "" {
			if d, err = config.ParseDuration(v); err != nil {
				return usage("expire: %v", err)
			}
		}
		expire = &d
	}
	index := func(name string, zeroOK bool) (int, error) {
		v, ok := args[name]
		if !ok && zeroOK {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, fmt.Errorf("%s must be a rule number from 1", name)
		}
		return n, nil
	}
	switch args["op"] {
	case control.EditRuleAdd:
		if !hasApps || len(apps) == 0 || gate == nil {
			return usage("rule.add needs apps and gate")
		}
		at, err := index("at", true)
		if err != nil {
			return usage("%v", err)
		}
		spec := config.RuleSpec{Apps: apps, To: to, Gate: *gate}
		if scope != nil {
			spec.Scope = *scope
		}
		if expire != nil {
			spec.Expire = *expire
		}
		return edit(func(b []byte) ([]byte, error) { return config.AddRule(b, e, spec, at) })
	case control.EditRuleSet:
		i, err := index("index", false)
		if err != nil {
			return usage("%v", err)
		}
		if hasApps && len(apps) == 0 {
			return usage("a rule needs at least one apps matcher")
		}
		p := config.RulePatch{Scope: scope, Gate: gate, Expire: expire}
		if hasApps {
			p.Apps = apps
		}
		if hasTo {
			if to == nil {
				to = []string{}
			}
			p.To = &to
		}
		return edit(func(b []byte) ([]byte, error) { return config.SetRule(b, e, i, p) })
	case control.EditRuleRemove:
		i, err := index("index", false)
		if err != nil {
			return usage("%v", err)
		}
		return edit(func(b []byte) ([]byte, error) { return config.RemoveRule(b, e, i) })
	case control.EditKeySet:
		if !e.IsKey() {
			noun := "secret"
			if e.IsK8s() {
				noun = "context"
			}
			if e.IsAWS() {
				noun = "aws entry"
			}
			return usage("key.set is for SSH keys; a %s's own gate stays what config.yaml says", noun)
		}
		if hasApps || hasTo {
			return usage("key.set changes scope, gate and expire only")
		}
		p := config.PolicyPatch{Scope: scope, Gate: gate, Expire: expire}
		return edit(func(b []byte) ([]byte, error) { return config.SetKeyPolicy(b, key, p) })
	}
	return usage("unknown edit %q (rule.add, rule.set, rule.remove, key.set)", args["op"])
}

// keyUses remembers, per key, the last request the agent signed for
// (allowed or approved), from the audit events (Milestone 5: the Nazar
// window's "last used"). It lives in memory: since Nazar.app started.
type keyUses struct {
	mu sync.Mutex
	m  map[string]control.KeyUse
}

// record is the audit observer. Only the broker's sign decisions count:
// they carry a gate; control commands (key creation, deletion) don't.
func (u *keyUses) record(e audit.Event) {
	if e.Gate == "" || !strings.HasPrefix(e.Target, "ssh:") || (e.Decision != audit.Allowed && e.Decision != audit.Approved) {
		return
	}
	// The chain exactly as the audit line's chain= field has it (names
	// quoted, PIDs, identities, the deleted mark outside the name): joining
	// raw names would let a process named "a > b" read as two.
	chain := audit.FormatChain(e.Chain)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.m == nil {
		u.m = map[string]control.KeyUse{}
	}
	u.m[strings.TrimPrefix(e.Target, "ssh:")] = control.KeyUse{Time: e.Time, Decision: string(e.Decision), App: e.App, Chain: chain}
}

// last returns the last use of key name, or nil.
func (u *keyUses) last(name string) *control.KeyUse {
	u.mu.Lock()
	defer u.mu.Unlock()
	if use, ok := u.m[name]; ok {
		return &use
	}
	return nil
}
