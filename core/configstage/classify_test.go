package configstage

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Tests for spec 4.8 (config changes need approval), 4.2 (reloading,
// versioning) and 9 (config changed / invalid). Classification is semantic:
// a change loosens when some request could end up with a weaker gate, a
// broader scope or a longer expiry than before; only changes that tighten
// apply without the login gate.

var env = config.Env{Home: "/Users/u"}

const head = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
  cursor: {app: com.todesktop.230313mzl4w4u92}
  it2: {app: com.googlecode.iterm2}
  ssh: {signed: {team: apple, id: com.apple.openssh}}
`

func cfg(t *testing.T, body string) *config.Config {
	t.Helper()
	return cfgFull(t, head+body)
}

func cfgFull(t *testing.T, text string) *config.Config {
	t.Helper()
	c, probs := config.Parse([]byte(text), env)
	if probs.HasErrors() {
		t.Fatalf("%s\n%s", probs.Error(), text)
	}
	return c
}

const base = `ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
        - apps: [iterm, cursor]
          scope: session
          gate: login
          expire: 8h
`

func findingsText(d Diff) string {
	var all []string
	for _, f := range d.Loosening {
		all = append(all, f.Target+": "+f.Why)
	}
	return strings.Join(all, "\n")
}

func hasTarget(d Diff, target string) bool {
	for _, f := range d.Loosening {
		if f.Target == target {
			return true
		}
	}
	return false
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		old, nw string
		loosens bool
		why     string
	}{
		{"identical", base, base, false, ""},
		{"remove last rule (falls to block)", base, `ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
`, false, ""},
		{"stricter gate", base, strings.Replace(base, "gate: dialog", "gate: login", 1), false, ""},
		{"shorter expire", base, strings.Replace(base, "expire: 8h", "expire: 1h", 1), false, ""},
		{"narrower scope", base, strings.Replace(base, "scope: session\n          gate: dialog", "scope: use\n          gate: dialog", 1), false, ""},
		{"rename app matcher", base, strings.Replace(base, "[iterm, cursor]", "[it2, cursor]", 1), false, ""},
		{"add to: restriction", base, strings.Replace(base, "        - apps: [claude]\n", "        - apps: [claude]\n          to: [ssh]\n", 1), false, ""},
		{"looser gate", base, strings.Replace(base, "gate: login", "gate: dialog", 1), true, "gate=login scope=session expire=8h0m0s (rule 2) can now get gate=dialog"},
		{"gate none", base, strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "gate: none", 1), true, "gate=none"},
		{"longer expire", base, strings.Replace(base, "expire: 8h", "expire: 24h", 1), true, "expire=24h"},
		{"drop expire", base, strings.Replace(base, "\n          expire: 8h", "", 1), true, ""},
		{"broader scope", base, strings.Replace(base, "scope: session\n          gate: login", "scope: app\n          gate: login", 1), true, "scope=app"},
		{"add rule for a new app", base, base + `        - apps: [{signed: {team: NEWTEAM000}}]
          gate: login
`, true, "(fallback) can now get gate=login"},
		{"remove a rule so a looser later rule applies", `ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          gate: login
        - apps: [iterm]
          gate: none
`, `ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: none
`, true, "gate=login scope=use (rule 1) can now get gate=none (rule 1)"},
		{"reorder rules", `ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: login
        - apps: [claude]
          gate: dialog
`, `ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          gate: dialog
        - apps: [iterm]
          gate: login
`, true, "gate=login scope=use (rule 1) can now get gate=dialog scope=use (rule 1)"},
		{"remove key with own gate when fallback prompts", `defaults:
  fallback: {gate: login, scope: session}
ssh_agent:
  keys:
    hydra: {gate: block}
`, `defaults:
  fallback: {gate: login, scope: session}
`, true, "ssh:hydra"},
		{"remove key entry under block fallback", `ssh_agent:
  keys:
    hydra: {gate: login}
`, `audit: {args: redacted}
`, false, ""},
		{"loosen defaults.fallback", "", `defaults:
  fallback: {gate: login}
`, true, "(keys without an entry)"},
		{"widen to: restriction", strings.Replace(base, "        - apps: [claude]\n", "        - apps: [claude]\n          to: [ssh]\n", 1), base, true, ""},
		{"apps any added", base, base + `        - apps: [any]
          gate: dialog
`, true, ""},
		{"socket moves", base, base + "  socket: /tmp/other.sock\n", true, "socket"},
		{"timeout change is neutral", base, "defaults:\n  timeout: 30s\n" + base, false, ""},
		{"audit args none", base, "audit:\n  args: none\n" + base, true, "less is logged"},

		// More tightening that must apply at once.
		{"block a rule", base, strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1), false, ""},
		{"none becomes a prompt", strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "gate: none", 1), base, false, ""},
		{"remove a member from apps list", base, strings.Replace(base, "[iterm, cursor]", "[iterm]", 1), false, ""},
		{"reorder apps list members", base, strings.Replace(base, "[iterm, cursor]", "[cursor, iterm]", 1), false, ""},
		{"same expire spelled differently", base, strings.Replace(base, "expire: 8h", "expire: 480m", 1), false, ""},
		{"named app written inline", base, strings.Replace(base, "- apps: [claude]\n", "- apps: [{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}]\n", 1), false, ""},
		{"stricter rule inserted above a looser one", base, strings.Replace(base, "      rules:\n", "      rules:\n        - apps: [claude]\n          gate: login\n", 1), false, ""},
		{"leading any/block rule blocks everything", base, strings.Replace(base, "      rules:\n", "      rules:\n        - apps: [any]\n          gate: block\n", 1), false, ""},
		{"remove all rules (key falls to block)", base, "ssh_agent:\n  keys:\n    github:\n", false, ""},
		{"key's own gate becomes stricter", "ssh_agent:\n  keys:\n    hydra: {gate: dialog}\n", "ssh_agent:\n  keys:\n    hydra: {gate: login}\n", false, ""},
		{"key's own gate becomes block", "ssh_agent:\n  keys:\n    hydra: {gate: login}\n", "ssh_agent:\n  keys:\n    hydra: {gate: block}\n", false, ""},
		{"add a key that is blocked anyway", base, base + "    other: {gate: block}\n", false, ""},
		{"audit args none back to redacted", "audit:\n  args: none\n" + base, base, false, ""},
		{"socket spelled with ~ and absolute is the same socket", "ssh_agent:\n  socket: ~/.nazar/agent.sock\n", "ssh_agent:\n  socket: /Users/u/.nazar/agent.sock\n", false, ""},
		// session+8h → use: nothing is remembered any more, so the expiry
		// no longer matters (Parse drops it with scope: use). Spec 4.8:
		// changes that only tighten apply at once.
		{"session with expire becomes use", base, strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "scope: use\n          gate: login", 1), false, ""},

		// More loosening (attack shapes: malware
		// editing the file to let itself in).
		{"add a member to apps list", base, strings.Replace(base, "[iterm, cursor]", "[iterm, cursor, {signed: {team: EVILTEAM00}}]", 1), true, "ssh:github"},
		{"add apps: unknown rule", base, base + "        - apps: [unknown]\n          gate: dialog\n", true, "ssh:github"},
		{"add a new key with a prompting rule", base, base + "    newkey:\n      rules:\n        - apps: [iterm]\n          gate: login\n", true, "ssh:newkey"},
		{"add a new key with its own prompting gate", base, base + "    newkey: {gate: login}\n", true, "ssh:newkey"},
		{"key's own gate becomes weaker", "ssh_agent:\n  keys:\n    hydra: {gate: login}\n", "ssh_agent:\n  keys:\n    hydra: {gate: dialog}\n", true, "ssh:hydra"},
		{"key's own block lifted", "ssh_agent:\n  keys:\n    hydra: {gate: block}\n", "ssh_agent:\n  keys:\n    hydra: {gate: login}\n", true, "ssh:hydra"},
		{"key with own gate gets a rule", "ssh_agent:\n  keys:\n    hydra: {gate: login}\n", "ssh_agent:\n  keys:\n    hydra:\n      gate: login\n      rules:\n        - apps: [claude]\n          gate: dialog\n", true, "ssh:hydra"},
		{"key's own scope broadened", "ssh_agent:\n  keys:\n    hydra: {gate: login, scope: use}\n", "ssh_agent:\n  keys:\n    hydra: {gate: login, scope: app}\n", true, "ssh:hydra"},
		{"dialog to none for an app", base, strings.Replace(base, "scope: session\n          gate: dialog", "gate: none", 1), true, "gate=none"},
		{"block lifted on a rule", strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1), base, true, "ssh:github"},
		{"leading any rule inserted", base, strings.Replace(base, "      rules:\n", "      rules:\n        - apps: [any]\n          gate: login\n", 1), true, "ssh:github"},
		{"to: restriction replaced by another receiver", strings.Replace(base, "        - apps: [claude]\n", "        - apps: [claude]\n          to: [ssh]\n", 1),
			strings.Replace(base, "        - apps: [claude]\n", "        - apps: [claude]\n          to: [{signed: {team: EVILTEAM00}}]\n", 1), true, "ssh:github"},

		// An `apps: any` rule shields the fallback only when it has no to:
		// (config.CoversAll). With `to: ssh` a request from another
		// receiver still reaches the fallback, so weakening the fallback
		// behind such a rule loosens, in both directions: the rule in the
		// old config must not hide the old fallback, and a new one must not
		// hide the new fallback. The control shows the unrestricted rule
		// does shield it, so these pin the to: condition exactly.
		{"to:-restricted any rule does not shield the old fallback",
			"ssh_agent:\n  keys:\n    k:\n      gate: login\n      rules:\n        - apps: [any]\n          to: [ssh]\n          gate: login\n",
			"ssh_agent:\n  keys:\n    k:\n      gate: dialog\n      rules:\n        - apps: [any]\n          to: [ssh]\n          gate: login\n",
			true, "(fallback) can now get gate=dialog"},
		{"new to:-restricted any rule does not shield a weakened fallback",
			"ssh_agent:\n  keys:\n    k: {gate: login}\n",
			"ssh_agent:\n  keys:\n    k:\n      gate: dialog\n      rules:\n        - apps: [any]\n          to: [ssh]\n          gate: login\n",
			true, "(fallback) can now get gate=dialog"},
		{"unrestricted any rule shields the fallback (control)",
			"ssh_agent:\n  keys:\n    k:\n      gate: login\n      rules:\n        - apps: [any]\n          gate: login\n",
			"ssh_agent:\n  keys:\n    k:\n      gate: dialog\n      rules:\n        - apps: [any]\n          gate: login\n",
			false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Classify(cfg(t, c.old), cfg(t, c.nw))
			if d.Loosens() != c.loosens {
				t.Fatalf("Loosens=%v want %v\nfindings: %+v\nchanges: %v", d.Loosens(), c.loosens, d.Loosening, d.Changes)
			}
			if c.why != "" {
				if all := findingsText(d); !strings.Contains(all, c.why) {
					t.Fatalf("findings %q do not mention %q", all, c.why)
				}
			}
		})
	}
}

// Redefining what a named app means, without touching any rule, changes who
// gets in: the rules' text is identical but the matcher behind the name is
// now someone else (spec 4.8: "malware running as the user could add a rule
// for itself").
func TestClassifyRedefinedNamedApp(t *testing.T) {
	const appsOld = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
`
	rules := `ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          gate: dialog
        - apps: [iterm]
          gate: login
`
	for _, tc := range []struct{ name, apps string }{
		{"bundle id", strings.Replace(appsOld, "app: com.googlecode.iterm2", "app: com.evil.terminal", 1)},
		{"pinned team", strings.Replace(appsOld, "app: com.googlecode.iterm2", "app: com.googlecode.iterm2, team: EVILTEAM00", 1)},
		{"signed team", strings.Replace(appsOld, "team: Q6L2SF6YDW", "team: EVILTEAM00", 1)},
		{"signed id dropped", strings.Replace(appsOld, ", id: com.anthropic.claude-code", "", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Classify(cfgFull(t, appsOld+rules), cfgFull(t, tc.apps+rules))
			if !d.Loosens() || !hasTarget(d, "ssh:github") {
				t.Fatalf("redefining an app must loosen ssh:github: %+v", d)
			}
			if d.Empty() {
				t.Fatal("a redefined app is a change")
			}
		})
	}
}

// defaults.fallback applies to configured keys without their own gate too,
// not only to keys without an entry.
func TestClassifyFallbackReachesConfiguredKeys(t *testing.T) {
	d := Classify(cfg(t, base), cfg(t, "defaults:\n  fallback: {gate: dialog}\n"+base))
	if !d.Loosens() {
		t.Fatal("loosening the fallback must loosen")
	}
	if !hasTarget(d, "ssh:github") {
		t.Fatalf("github's unmatched callers now get dialog instead of block: %+v", d.Loosening)
	}
	if !hasTarget(d, "ssh:"+"(keys without an entry)") {
		t.Fatalf("keys without an entry now get dialog: %+v", d.Loosening)
	}
}

// Several keys loosened at once: every one is reported, so the approval
// prompt shows the whole diff (spec 4.8: "shows the diff").
func TestClassifyReportsEveryLoosenedKey(t *testing.T) {
	old := `ssh_agent:
  keys:
    a: {gate: login}
    b: {gate: login}
    c: {gate: login}
`
	nw := strings.Replace(strings.Replace(old, "a: {gate: login}", "a: {gate: dialog}", 1), "c: {gate: login}", "c: {gate: login, scope: app}", 1)
	d := Classify(cfg(t, old), cfg(t, nw))
	if !hasTarget(d, "ssh:a") || !hasTarget(d, "ssh:c") {
		t.Fatalf("want findings for ssh:a and ssh:c: %+v", d.Loosening)
	}
	if hasTarget(d, "ssh:b") {
		t.Fatalf("ssh:b did not change: %+v", d.Loosening)
	}
}

func TestClassifySelfIsNeverLoosening(t *testing.T) {
	for _, body := range []string{base, `ssh_agent:
  keys:
    k:
      rules:
        - apps: [claude]
          gate: dialog
        - apps: [any]
          gate: login
          scope: session
        - apps: [unknown]
          gate: dialog
    a: {gate: login}
`} {
		c := cfg(t, body)
		if d := Classify(c, c); d.Loosens() || len(d.Changes) != 0 {
			t.Fatalf("self-diff: %+v", d)
		}
	}
	def := config.Default(env)
	if d := Classify(def, def); d.Loosens() || !d.Empty() {
		t.Fatalf("default self-diff: %+v", d)
	}
}

// Comments, blank lines and key order change the bytes but not the meaning.
func TestClassifyCosmeticEditIsEmpty(t *testing.T) {
	nw := "# my keys\n" + strings.Replace(base, "      rules:\n", "      rules:   # first match wins\n\n", 1)
	d := Classify(cfg(t, base), cfg(t, nw))
	if d.Loosens() || !d.Empty() {
		t.Fatalf("cosmetic edit: %+v", d)
	}
}

// First run: the active config is the built-in default (fallback block), so
// any rule that lets someone in loosens; going back to the default tightens.
func TestClassifyAgainstDefault(t *testing.T) {
	def := config.Default(env)
	if d := Classify(def, cfg(t, base)); !d.Loosens() || !hasTarget(d, "ssh:github") {
		t.Fatalf("default → base must loosen ssh:github: %+v", d)
	}
	if d := Classify(cfg(t, base), def); d.Loosens() {
		t.Fatalf("base → default must only tighten: %+v", d.Loosening)
	}
}

// A section Parse recognises but this version does not build
// (config.Config.Unimplemented) can't be vetted: adding it, or editing a
// file that carries it, must go through the login gate and show up in the
// diff; dropping it only tightens (spec 4.2 "never guesses at a schema it
// doesn't know", 4.8). secrets: was here until M8 built it and k8s:
// until M12 (secrets_test.go and k8s_test.go pin how they are classified
// now); no section is unimplemented today, so the guard is tested on
// configs whose Unimplemented is set by hand.
func TestClassifyUnimplementedSectionNeedsApproval(t *testing.T) {
	for _, sec := range []string{"later:\n  anything: here\n"} {
		name := strings.SplitN(sec, ":", 2)[0]
		carrying := func(body string) *config.Config {
			c := cfg(t, body)
			c.Unimplemented = []string{name}
			c.Raw = append(c.Raw, sec...)
			return c
		}
		c := carrying(base)
		d := Classify(cfg(t, base), c)
		if d.Empty() || !d.Loosens() || !hasTarget(d, name) {
			t.Fatalf("adding %s: must loosen and name the section: %+v", name, d)
		}
		if text := strings.Join(d.Changes, "\n"); !strings.Contains(text, name+": section added") {
			t.Fatalf("adding %s: the diff must list it: %q", name, text)
		}
		// From the built-in default too (first run, or after a delete).
		if d := Classify(config.Default(env), c); !d.Loosens() || !hasTarget(d, name) {
			t.Fatalf("default → %s: %+v", name, d)
		}
		// The same file is no change.
		if d := Classify(c, c); !d.Empty() {
			t.Fatalf("%s self-diff: %+v", name, d)
		}
		// Any edit to a file carrying the section, even one that only
		// tightens elsewhere, is unvettable and needs approval.
		tight := carrying(strings.Replace(base, "gate: dialog", "gate: login", 1))
		if d := Classify(c, tight); !d.Loosens() || !hasTarget(d, name) || hasTarget(d, "ssh:github") {
			t.Fatalf("edit with %s present: must loosen on the section only: %+v", name, d)
		}
		if text := strings.Join(Classify(c, tight).Changes, "\n"); !strings.Contains(text, name+": section present") {
			t.Fatalf("edit with %s present: the diff must list it: %q", name, text)
		}
		// Removing it is a listed, non-loosening change.
		d = Classify(c, cfg(t, base))
		if d.Loosens() || d.Empty() || !strings.Contains(strings.Join(d.Changes, "\n"), name+": section removed") {
			t.Fatalf("removing %s: must tighten and be listed: %+v", name, d)
		}
	}
}

func TestDiffDescribesChanges(t *testing.T) {
	d := Classify(cfg(t, base), cfg(t, strings.Replace(base, "gate: login", "gate: dialog", 1)))
	text := strings.Join(d.Changes, "\n")
	if !strings.Contains(text, "removed rule 2") || !strings.Contains(text, "added rule 2") {
		t.Fatalf("changes %q", text)
	}
}

// Neutral and tightening changes are still listed as changes (so the diff
// shown is complete), but they never need approval.
func TestDiffEmptyAndNeutralChanges(t *testing.T) {
	if d := Classify(cfg(t, base), cfg(t, base)); !d.Empty() {
		t.Fatalf("identical: %+v", d)
	}
	for name, nw := range map[string]string{
		"timeout":  "defaults:\n  timeout: 30s\n" + base,
		"tighten":  strings.Replace(base, "gate: dialog", "gate: login", 1),
		"key gone": "ssh_agent:\n  keys:\n    other: {gate: block}\n",
	} {
		d := Classify(cfg(t, base), cfg(t, nw))
		if d.Loosens() || d.Empty() || len(d.Changes) == 0 {
			t.Errorf("%s: want listed, non-loosening changes: %+v", name, d)
		}
	}
}

func TestAtLeastAsStrict(t *testing.T) {
	p := func(g config.Gate, s config.Scope, e string) config.Policy {
		var d, _ = config.ParseDuration(e)
		if e == "" {
			d = 0
		}
		return config.Policy{Gate: g, Scope: s, Expire: d}
	}
	yes := [][2]config.Policy{
		{p(config.GateBlock, "use", ""), p(config.GateNone, "use", "")},
		{p(config.GateLogin, "use", ""), p(config.GateDialog, "app", "")},
		{p(config.GateDialog, "session", "1h"), p(config.GateNone, "use", "")},
		{p(config.GateLogin, "session", "1h"), p(config.GateLogin, "session", "")},
		// More cases.
		{p(config.GateBlock, "use", ""), p(config.GateBlock, "use", "")},
		{p(config.GateBlock, "use", ""), p(config.GateLogin, "app", "")},
		{p(config.GateNone, "use", ""), p(config.GateNone, "use", "")},
		{p(config.GateLogin, "session", "8h"), p(config.GateLogin, "session", "8h")},
		{p(config.GateLogin, "app", "1h"), p(config.GateDialog, "app", "2h")},
		{p(config.GateDialog, "use", ""), p(config.GateNone, "use", "")},
		// scope use remembers nothing, so it is at least as strict as any
		// remembered approval of the same gate, whatever its expiry.
		{p(config.GateLogin, "use", ""), p(config.GateLogin, "session", "8h")},
		{p(config.GateDialog, "use", ""), p(config.GateDialog, "app", "1h")},
	}
	no := [][2]config.Policy{
		{p(config.GateLogin, "use", ""), p(config.GateBlock, "use", "")},
		{p(config.GateDialog, "use", ""), p(config.GateLogin, "use", "")},
		{p(config.GateLogin, "app", ""), p(config.GateDialog, "session", "")},
		{p(config.GateLogin, "session", ""), p(config.GateLogin, "session", "1h")},
		// More cases.
		{p(config.GateNone, "use", ""), p(config.GateBlock, "use", "")},
		{p(config.GateNone, "use", ""), p(config.GateDialog, "use", "")},
		{p(config.GateNone, "use", ""), p(config.GateLogin, "session", "1h")},
		{p(config.GateDialog, "session", ""), p(config.GateLogin, "use", "")},
		{p(config.GateLogin, "session", ""), p(config.GateLogin, "use", "")},
		{p(config.GateLogin, "session", "2h"), p(config.GateLogin, "session", "1h")},
		{p(config.GateLogin, "app", "1h"), p(config.GateLogin, "session", "1h")},
	}
	for _, c := range yes {
		if !AtLeastAsStrict(c[0], c[1]) {
			t.Errorf("want %v >= %v", c[0], c[1])
		}
	}
	for _, c := range no {
		if AtLeastAsStrict(c[0], c[1]) {
			t.Errorf("want %v < %v", c[0], c[1])
		}
	}
}

// A file near config.MaxFileSize can hold thousands of rules. Classification
// runs on every file change, so a malicious or careless file must not hang
// the config loop; whatever shortcut is taken must stay conservative (a
// change it can't prove tightens is loosening).
// manyRules is a key "big" with n rules for distinct teams, all with the same
// gate. No rule covers another, so under first-match every (old, new) pair
// may share a request and the pairwise proof has n² pairs to look at.
func manyRules(n int, gate string) string {
	var b strings.Builder
	b.WriteString("ssh_agent:\n  keys:\n    big:\n      rules:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "        - apps: [{signed: {team: T%07d}}]\n          gate: %s\n", i, gate)
	}
	return b.String()
}

func TestClassifyLargeConfigIsBounded(t *testing.T) {
	// n+1 slots each (the fallback counts): just inside the pairwise budget,
	// so this still runs the full proof at scale.
	const n = 1000
	old, nw := cfg(t, manyRules(n, "login")), cfg(t, manyRules(n, "dialog"))
	done := make(chan Diff, 1)
	go func() { done <- Classify(old, nw) }()
	select {
	case d := <-done:
		if !d.Loosens() || !hasTarget(d, "ssh:big") {
			t.Fatalf("login → dialog on every rule must loosen ssh:big (%d findings)", len(d.Loosening))
		}
		if got := len(d.Loosening); got != maxFindingsPerTarget+1 {
			t.Fatalf("findings for one key must stop at %d plus 'and more', got %d", maxFindingsPerTarget, got)
		}
		if last := d.Loosening[len(d.Loosening)-1].Why; !strings.Contains(last, "and more") {
			t.Fatalf("the last finding must say there are more, got %q", last)
		}
		if strings.Contains(findingsText(d), "too many rules") {
			t.Fatal("a config inside the budget must be compared, not waved to the login gate")
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("Classify of %d rules did not finish within 60s", n)
	}
}

// A config near config.MaxFileSize has about 16k rules; comparing every
// (old, new) pair would take tens of seconds on each file change, during
// which the watcher is stuck. Above the budget Classify does not try: the
// change is unprovable, so it needs approval (spec 4.8 skips the gate only
// for a proven tightening), and it must say so quickly.
func TestClassifyNearMaxFileSizeIsFastAndNeedsApproval(t *testing.T) {
	huge := func(gate string) *config.Config {
		var b strings.Builder
		b.WriteString(head)
		b.WriteString("ssh_agent:\n  keys:\n    big:\n      rules:\n")
		for i := 0; b.Len() < config.MaxFileSize-128; i++ {
			fmt.Fprintf(&b, "        - apps: [{signed: {team: T%07d}}]\n          gate: %s\n", i, gate)
		}
		return cfgFull(t, b.String())
	}
	login, dialog := huge("login"), huge("dialog")
	if n := len(login.SSHAgent.Keys["big"].Rules); n*n <= maxPairs {
		t.Fatalf("test needs more than the budget: %d rules", n)
	}
	for _, tc := range []struct {
		name    string
		old, nw *config.Config
	}{
		{"looser", login, dialog},
		{"stricter but unprovable", dialog, login},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			d := Classify(tc.old, tc.nw)
			// Only for a Classify that hangs the agent: 10 s, because a busy
			// runner with -race once took over 1 s. What pins the budget is
			// the finding below, which only the early return writes.
			if took := time.Since(start); took > 10*time.Second {
				t.Fatalf("Classify of a %d-byte config took %s", len(tc.nw.Raw), took)
			}
			if !d.Loosens() || !hasTarget(d, "ssh:big") {
				t.Fatalf("an over-budget change must need approval, got %+v", d.Loosening)
			}
			if !strings.Contains(findingsText(d), "too many rules to compare; approval required") {
				t.Fatalf("the finding must say why: %s", findingsText(d))
			}
		})
	}
	if d := Classify(login, login); d.Loosens() {
		t.Fatal("the same huge config must not loosen against itself")
	}
}

// ---------------------------------------------------------------------------
// Stager: approved config in the vault, tightening at once, loosening staged
// until the login gate approves (spec 4.8), invalid files keep the last valid
// config (spec 4.2, 9).

func src(body string) []byte { return []byte(head + body) }

func open(t *testing.T) (*Stager, *fake.Vault, *[]*config.Config) {
	t.Helper()
	v := fake.NewVault()
	var applied []*config.Config
	s, err := Open(env, v, func(c *config.Config) { applied = append(applied, c) })
	if err != nil {
		t.Fatal(err)
	}
	return s, v, &applied
}

func yes(Pending) (bool, error) { return true, nil }

func TestFirstRunStagesRulesAndKeepsDefault(t *testing.T) {
	s, _, applied := open(t)
	if len(*applied) != 1 || len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("initial config must be the built-in default")
	}
	r := s.Observe(src(base))
	if !r.Staged || r.Applied {
		t.Fatalf("adding rules on first run must be staged: %+v", r)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("staged config must not be active")
	}
	if r2 := s.Observe(src(base)); !r2.Staged {
		t.Fatal("re-observing the same staged file must report staged")
	}
	if len(*applied) != 1 {
		t.Fatal("staging must not call onApply")
	}
}

func TestApproveAppliesAndPersists(t *testing.T) {
	s, v, applied := open(t)
	s.Observe(src(base))
	p, _ := s.Pending()
	ok, err := s.Approve(p.Config.Hash, yes)
	if !ok || err != nil {
		t.Fatalf("approve: %v %v", ok, err)
	}
	if len(s.Active().SSHAgent.Keys) != 1 || len(*applied) != 2 {
		t.Fatal("approved config not active")
	}
	s2, err := Open(env, v, nil)
	if err != nil || s2.Active().Hash != p.Config.Hash {
		t.Fatal("approved config not persisted in the vault")
	}
}

func TestPendingCarriesTheDiffShownToTheUser(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	p, ok := s.Pending()
	if !ok || !p.Diff.Loosens() || len(p.Diff.Changes) == 0 {
		t.Fatalf("pending diff: %+v", p.Diff)
	}
	var seen Pending
	if ok, err := s.Approve("", func(q Pending) (bool, error) { seen = q; return true, nil }); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if seen.Config == nil || seen.Config.Hash != p.Config.Hash || s.Active().Hash != seen.Config.Hash {
		t.Fatal("the config applied must be exactly the one shown to the approver")
	}
}

func TestDeniedApprovalKeepsOld(t *testing.T) {
	s, _, applied := open(t)
	s.Observe(src(base))
	ok, err := s.Approve("", func(Pending) (bool, error) { return false, nil })
	if ok || err != nil || len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatalf("denied: ok=%v err=%v", ok, err)
	}
	if _, still := s.Pending(); !still {
		t.Fatal("a denied change stays staged until the file changes")
	}
	if len(*applied) != 1 {
		t.Fatal("a denied change must not call onApply")
	}
}

func TestApproverErrorKeepsOld(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	boom := errors.New("gate timed out")
	ok, err := s.Approve("", func(Pending) (bool, error) { return false, boom })
	if ok || !errors.Is(err, boom) {
		t.Fatalf("want the approver's error, got %v %v", ok, err)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("applied despite the approver failing")
	}
	if _, still := s.Pending(); !still {
		t.Fatal("the change stays staged so `nazar config apply` can ask again")
	}
	// An approver that says yes but also reports an error is not a yes.
	ok, err = s.Approve("", func(Pending) (bool, error) { return true, boom })
	if ok || err == nil || len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatalf("(true, err) must not apply: %v %v", ok, err)
	}
}

func TestTighteningAppliesAtOnce(t *testing.T) {
	s, v, applied := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	tight := src(strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1))
	r := s.Observe(tight)
	if !r.Applied || r.Staged {
		t.Fatalf("tightening must apply at once: %+v", r)
	}
	if _, pending := s.Pending(); pending {
		t.Fatal("nothing should be pending")
	}
	if len(*applied) != 3 || (*applied)[2].Hash != s.Active().Hash {
		t.Fatal("onApply must see the tightened config")
	}
	if got, err := v.Get(ApprovedVaultItem); err != nil || string(got) != string(tight) {
		t.Fatal("the tightened config must be the approved one in the vault")
	}
}

// Deleting the file tightens to the built-in default, and that must be what
// is approved from now on: the vault item goes, so a restart starts from
// the default and the old file, if re-created, is staged again rather than
// silently reinstated (spec 4.8: on restart nazar loads the last approved
// config).
func TestDeletedFileFallsBackToDefault(t *testing.T) {
	s, v, _ := open(t)
	if r := s.Observe(nil); r.Staged || r.Invalid {
		t.Fatalf("no file on first run is no change: %+v", r)
	}
	s.Observe(src(base))
	s.Approve("", yes)
	if _, err := v.Get(ApprovedVaultItem); err != nil {
		t.Fatalf("precondition: base must be in the vault: %v", err)
	}
	r := s.Observe(nil)
	if !r.Applied || r.Staged || len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatalf("removing the file tightens to the built-in default: %+v", r)
	}
	if _, err := v.Get(ApprovedVaultItem); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("the retracted config must leave the vault, got err=%v", err)
	}
	s2, err := Open(env, v, nil)
	if err != nil || len(s2.Active().SSHAgent.Keys) != 0 || s2.Active().Hash != "" {
		t.Fatalf("restart after a delete must start from the built-in default: %v %+v", err, s2.Active())
	}
	if r := s2.Observe(src(base)); !r.Staged || r.Applied {
		t.Fatalf("the old file re-created after a delete must be staged again: %+v", r)
	}
}

// Malware with write access to config.yaml plants a k8s context for itself.
// nazar must not bless those bytes as approved: the change is staged, the
// vault keeps the previous approval, and the diff names the context. Until
// M12 k8s: was an unvettable section and every edit to a file carrying it
// was staged; since M12 a k8s: entry is judged by what it says, so a
// tightening elsewhere applies at once (TestTighteningBesideK8sAppliesAtOnce),
// and the rest of this test holds as it did. (The secrets: case is
// TestPlantedSecretRuleIsStagedNotApproved since M8.)
func TestUnimplementedSectionIsStagedNotApproved(t *testing.T) {
	for _, sec := range []string{k8sBase} {
		const name = "k8s:hydra"
		s, v, applied := open(t)
		s.Observe(src(k8sApps + base))
		s.Approve("", yes)
		h := s.Active().Hash
		before, _ := v.Get(ApprovedVaultItem)

		r := s.Observe(src(k8sApps + base + sec))
		if !r.Staged || r.Applied || r.Invalid || !hasTarget(r.Diff, name) {
			t.Fatalf("%s: adding a context must be staged: %+v", name, r)
		}
		if !strings.Contains(strings.Join(r.Diff.Changes, "\n"), name+": context entry added") {
			t.Fatalf("%s: the diff must list the context: %q", name, r.Diff.Changes)
		}
		if s.Active().Hash != h || len(*applied) != 2 {
			t.Fatalf("%s: the approved config must stay active", name)
		}
		if after, err := v.Get(ApprovedVaultItem); err != nil || string(after) != string(before) {
			t.Fatalf("%s: the vault must still hold the approved config, got %v %q", name, err, after)
		}
		if strings.Contains(string(before), "k8s:") {
			t.Fatalf("%s: precondition: approved config must not carry the section", name)
		}
		// Even restarted, the planted section is not the baseline.
		s2, err := Open(env, v, nil)
		if err != nil || s2.Active().Hash != h {
			t.Fatalf("%s: restart must start from the approved config: %v", name, err)
		}
		if r := s2.Observe(src(k8sApps + base + sec)); !r.Staged || r.Applied {
			t.Fatalf("%s: found at restart, the context must be staged again: %+v", name, r)
		}
		// The login gate can still accept it, and then it is persisted.
		if ok, err := s.Approve("", yes); !ok || err != nil {
			t.Fatalf("%s: approve: %v %v", name, ok, err)
		}
		if got, _ := v.Get(ApprovedVaultItem); !strings.Contains(string(got), "k8s:") {
			t.Fatalf("%s: an approved file is persisted as is", name)
		}
		// Dropping the section only tightens.
		if r := s.Observe(src(k8sApps + base)); !r.Applied || r.Staged {
			t.Fatalf("%s: removing the section applies at once: %+v", name, r)
		}
		if got, _ := v.Get(ApprovedVaultItem); strings.Contains(string(got), "k8s:") {
			t.Fatalf("%s: the vault must hold the file without the section", name)
		}
	}
}

func TestInvalidFileKeepsActive(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	h := s.Active().Hash
	r := s.Observe([]byte("apiVersion: nazar/v2\nkind: Config\n"))
	if !r.Invalid || s.Active().Hash != h || !s.LastProblems().HasErrors() {
		t.Fatalf("invalid file: %+v", r)
	}
	if r.Applied || r.Staged {
		t.Fatalf("an invalid file is neither applied nor staged: %+v", r)
	}
}

func TestInvalidFilesOfEveryKindKeepActive(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	h := s.Active().Hash
	for name, data := range map[string][]byte{
		"missing apiVersion": []byte("kind: Config\n"),
		"missing kind":       []byte("apiVersion: nazar/v1\n"),
		"wrong kind":         []byte("apiVersion: nazar/v1\nkind: Secret\n"),
		"not yaml":           []byte("\x00\x01{{{"),
		"empty":              {},
		// spec 4.2: gate none refuses Apple-signed matchers.
		"none for apple":    src("ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [ssh]\n          gate: none\n"),
		"fallback none":     src("defaults:\n  fallback: {gate: none}\n"),
		"key own gate none": src("ssh_agent:\n  keys:\n    k: {gate: none}\n"),
	} {
		r := s.Observe(data)
		if !r.Invalid || r.Applied || r.Staged || s.Active().Hash != h {
			t.Errorf("%s: %+v", name, r)
		}
		if !s.LastProblems().HasErrors() {
			t.Errorf("%s: LastProblems must report the errors", name)
		}
	}
	// A valid file again clears the problems.
	s.Observe(src(base))
	if s.LastProblems().HasErrors() {
		t.Fatal("LastProblems must be cleared by a valid file")
	}
}

func TestFileChangedDuringPromptIsStale(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	ok, err := s.Approve("", func(Pending) (bool, error) {
		s.Observe(src(base + "        - apps: [any]\n          gate: dialog\n"))
		return true, nil
	})
	if ok || !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v %v", ok, err)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("nothing may be applied")
	}
	p, still := s.Pending()
	if !still || !strings.Contains(string(p.Config.Raw), "apps: [any]") {
		t.Fatal("the newer file must be the one staged now")
	}
}

// The file breaks while the prompt is open: it no longer says what the user
// is being asked to approve, so the approval is stale and nothing is
// applied or left staged.
func TestFileBrokenDuringPromptIsStale(t *testing.T) {
	s, v, _ := open(t)
	s.Observe(src(base))
	ok, err := s.Approve("", func(Pending) (bool, error) {
		if r := s.Observe([]byte("garbage")); !r.Invalid {
			t.Errorf("garbage must be invalid: %+v", r)
		}
		return true, nil
	})
	if ok || !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v %v", ok, err)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("nothing may be applied")
	}
	if _, still := s.Pending(); still {
		t.Fatal("a broken file leaves nothing staged")
	}
	if _, err := v.Get(ApprovedVaultItem); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("nothing may be persisted, got err=%v", err)
	}
}

// An invalid file clears the staged change: `nazar config apply` must not
// find a change the file no longer says.
func TestInvalidFileClearsPending(t *testing.T) {
	s, _, _ := open(t)
	if r := s.Observe(src(base)); !r.Staged {
		t.Fatalf("precondition: %+v", r)
	}
	if r := s.Observe([]byte("apiVersion: nazar/v2\nkind: Config\n")); !r.Invalid {
		t.Fatalf("want invalid: %+v", r)
	}
	if _, still := s.Pending(); still {
		t.Fatal("an invalid file must clear the staged change")
	}
	if ok, err := s.Approve("", yes); ok || !errors.Is(err, ErrNothingStaged) {
		t.Fatalf("want ErrNothingStaged, got %v %v", ok, err)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("nothing may be applied")
	}
}

// The file is reverted to the active config while the prompt is open: the
// approval must not resurrect the reverted change.
func TestFileRevertedDuringPromptIsStale(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	h := s.Active().Hash
	s.Observe(src(strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "gate: none", 1)))
	ok, err := s.Approve("", func(Pending) (bool, error) {
		s.Observe(src(base))
		return true, nil
	})
	if ok || !errors.Is(err, ErrStale) || s.Active().Hash != h {
		t.Fatalf("want ErrStale and the old config, got %v %v", ok, err)
	}
}

// The file is tightened while the loosening prompt is open: the tightening
// applies at once, and the stale approval doesn't override it.
func TestFileTightenedDuringPrompt(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	tight := src(strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1))
	s.Observe(src(strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "gate: none", 1)))
	ok, err := s.Approve("", func(Pending) (bool, error) {
		if r := s.Observe(tight); !r.Applied {
			t.Errorf("tightening during the prompt must apply: %+v", r)
		}
		return true, nil
	})
	if ok || !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v %v", ok, err)
	}
	if string(s.Active().Raw) != string(tight) {
		t.Fatal("the tightened config must stay active")
	}
}

// One loosening is staged, then the file is swapped for another loosening.
// An approval aimed at the first one (by hash) must not apply the second.
func TestApproveByHashOfReplacedChangeIsStale(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	first, _ := s.Pending()
	s.Observe(src(base + "        - apps: [any]\n          gate: dialog\n"))
	called := false
	ok, err := s.Approve(first.Config.Hash, func(Pending) (bool, error) { called = true; return true, nil })
	if ok || !errors.Is(err, ErrStale) || called {
		t.Fatalf("want ErrStale without prompting, got %v %v called=%v", ok, err, called)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("nothing may be applied")
	}
}

func TestApproveWrongHashAndNothingStaged(t *testing.T) {
	s, _, _ := open(t)
	if _, err := s.Approve("", nil); !errors.Is(err, ErrNothingStaged) {
		t.Fatal(err)
	}
	s.Observe(src(base))
	if _, err := s.Approve("deadbeef", yes); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
}

func TestApproveWhileApprovingIsBusy(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	var inner error
	ok, err := s.Approve("", func(Pending) (bool, error) {
		_, inner = s.Approve("", yes)
		return true, nil
	})
	if !errors.Is(inner, ErrBusy) {
		t.Fatalf("a second prompt while one is open: want ErrBusy, got %v", inner)
	}
	if !ok || err != nil {
		t.Fatalf("the first approval still completes: %v %v", ok, err)
	}
}

func TestRevertingFileClearsPending(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	s.Observe(src(strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "gate: none", 1)))
	if _, p := s.Pending(); !p {
		t.Fatal("loosening must be pending")
	}
	s.Observe(src(base))
	if _, p := s.Pending(); p {
		t.Fatal("reverting to the active file must clear the pending change")
	}
}

// A tightening observed while a loosening is staged replaces it: the staged
// loosening is no longer what the file says.
func TestTighteningReplacesPending(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	s.Observe(src(strings.Replace(base, "scope: session\n          gate: login\n          expire: 8h", "gate: none", 1)))
	r := s.Observe(src(strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1)))
	if !r.Applied {
		t.Fatalf("tightening must apply: %+v", r)
	}
	if _, p := s.Pending(); p {
		t.Fatal("the older loosening must not stay staged")
	}
	if _, err := s.Approve("", yes); !errors.Is(err, ErrNothingStaged) {
		t.Fatalf("want ErrNothingStaged, got %v", err)
	}
}

// Spec 4.8: on restart, nazar loads the last approved config and stages any
// differences from the file on disk.
func TestRestartStagesDifferencesFromApproved(t *testing.T) {
	s, v, _ := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	h := s.Active().Hash

	s2, err := Open(env, v, nil)
	if err != nil || s2.Active().Hash != h {
		t.Fatal("restart must start from the approved config")
	}
	if r := s2.Observe(src(strings.Replace(base, "gate: login", "gate: dialog", 1))); !r.Staged || r.Applied {
		t.Fatalf("a loosened file found at restart must be staged: %+v", r)
	}
	if s2.Active().Hash != h {
		t.Fatal("approved config must stay active")
	}
}

// A vault item that no longer parses (corrupt, or valid under an older
// validator but refused now, like gate none for an Apple-signed matcher) is
// not trusted: nazar starts from the built-in default and stages the file.
func TestOpenWithUnusableApprovedConfigFallsBackToDefault(t *testing.T) {
	for name, item := range map[string][]byte{
		"garbage":          []byte("\x00not yaml"),
		"unknown version":  []byte("apiVersion: nazar/v9\nkind: Config\n"),
		"refused now":      src("ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [ssh]\n          gate: none\n"),
		"fallback is none": src("defaults:\n  fallback: {gate: none}\n"),
	} {
		v := fake.NewVault()
		if err := v.Put(ApprovedVaultItem, item); err != nil {
			t.Fatal(err)
		}
		var applied []*config.Config
		s, err := Open(env, v, func(c *config.Config) { applied = append(applied, c) })
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a := s.Active()
		if len(a.SSHAgent.Keys) != 0 || a.Defaults.Fallback.Gate != config.GateBlock {
			t.Errorf("%s: want the built-in default, got %+v", name, a)
		}
		if len(applied) != 1 || applied[0] != a {
			t.Errorf("%s: onApply must get the initial config once", name)
		}
	}
}

type getFailVault struct {
	*fake.Vault
	err error
}

func (v getFailVault) Get(string) ([]byte, error) { return nil, v.err }

// A vault that can't be read (locked Keychain) is an error, not "first run":
// silently starting from the default would forget what was approved.
func TestOpenVaultReadError(t *testing.T) {
	locked := errors.New("keychain locked")
	s, err := Open(env, getFailVault{fake.NewVault(), locked}, nil)
	if err == nil || s != nil {
		t.Fatalf("want an error, got %v %v", s, err)
	}
	if _, err := Open(env, getFailVault{fake.NewVault(), platform.ErrNotFound}, nil); err != nil {
		t.Fatalf("ErrNotFound is first run: %v", err)
	}
}

func TestApplyAuthenticated(t *testing.T) {
	s, v, applied := open(t)
	p, err := s.Preview(src(base))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyAuthenticated(p); err != nil {
		t.Fatal(err)
	}
	if len(s.Active().SSHAgent.Keys) != 1 {
		t.Fatal("not applied")
	}
	if len(*applied) != 2 {
		t.Fatal("onApply not called")
	}
	if got, err := v.Get(ApprovedVaultItem); err != nil || string(got) != string(src(base)) {
		t.Fatal("not persisted")
	}
	h := s.Active().Hash
	if _, err := s.Preview([]byte("nope")); err == nil {
		t.Fatal("invalid data must fail")
	}
	if s.Active().Hash != h {
		t.Fatal("invalid data changed the active config")
	}
}

// What ApplyAuthenticated makes active is what LastProblems
// describes (nazar-agent marks the bytes it wrote as seen, so no Observe
// follows): a secret's or a key's warnings right after `secret add` or
// `ssh-key create` are the new file's, not the old one's.
func TestApplyAuthenticatedSetsLastProblems(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	if s.LastProblems() != nil {
		t.Fatalf("base has problems: %v", s.LastProblems())
	}
	warned := []byte("apiVersion: nazar/v1\nkind: Config\nsecrets:\n  X:\n    gate: block\n    rules:\n      - apps: [any]\n        gate: login\n")
	if err := s.ApplyAuthenticated(mustPreview(t, s, warned)); err != nil {
		t.Fatal(err)
	}
	if w := s.LastProblems(); len(w) == 0 || w.HasErrors() || !strings.Contains(w[0].Path, "secrets.X") {
		t.Fatalf("LastProblems after the apply: %v", w)
	}
	if err := s.ApplyAuthenticated(mustPreview(t, s, src(base))); err != nil {
		t.Fatal(err)
	}
	if w := s.LastProblems(); w != nil {
		t.Fatalf("LastProblems must be cleared by an applied file without problems: %v", w)
	}
}

// A change Observe stages carries its warnings too, so applying that
// Pending never clears LastProblems.
func TestObserveStagedPendingCarriesProblems(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	warned := []byte("apiVersion: nazar/v1\nkind: Config\nsecrets:\n  X:\n    gate: block\n    rules:\n      - apps: [any]\n        gate: login\n")
	if r := s.Observe(warned); !r.Staged {
		t.Fatalf("not staged: %+v", r)
	}
	p, ok := s.Pending()
	if !ok || len(p.Problems) == 0 || !strings.Contains(p.Problems[0].Path, "secrets.X") {
		t.Fatalf("staged Pending's Problems: %v", p.Problems)
	}
}

func mustPreview(t *testing.T, s *Stager, data []byte) Pending {
	t.Helper()
	p, err := s.Preview(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyAuthenticatedClearsPending(t *testing.T) {
	s, _, _ := open(t)
	s.Observe(src(base))
	if err := s.ApplyAuthenticated(mustPreview(t, s, src(base))); err != nil {
		t.Fatal(err)
	}
	if _, p := s.Pending(); p {
		t.Fatal("the applied change must no longer be pending")
	}
}

func TestVaultFailureDoesNotApply(t *testing.T) {
	s, v, applied := open(t)
	s.Observe(src(base))
	v.FailPut = errors.New("keychain locked")
	if ok, err := s.Approve("", yes); ok || err == nil {
		t.Fatal("a config that can't be saved must not become active")
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("applied anyway")
	}
	if len(*applied) != 1 {
		t.Fatal("onApply called for a config that was not saved")
	}
	if err := s.ApplyAuthenticated(mustPreview(t, s, src(base))); err == nil || len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("ApplyAuthenticated must not apply what it can't save")
	}
}

// A tightening is in force the moment it is seen, whether or not the vault
// takes it: withholding it because the Keychain is locked would keep the
// looser config active (fail-open), and a Result saying "invalid" would hide
// that from status. The save failure is reported as a warning instead; after
// a restart Open loads the older approved config and the file, still
// stricter than it, applies again at once.
func TestTighteningAppliesEvenWhenVaultFails(t *testing.T) {
	s, v, applied := open(t)
	s.Observe(src(base))
	s.Approve("", yes)
	loose, _ := v.Get(ApprovedVaultItem)
	v.FailPut = errors.New("keychain locked")

	tight := src(strings.Replace(base, "scope: session\n          gate: dialog\n", "gate: block\n", 1))
	r := s.Observe(tight)
	if !r.Applied || r.Invalid || r.Staged || len(r.Problems) != 1 {
		t.Fatalf("a tightening must be in force even when it can't be saved: %+v", r)
	}
	tightHash := cfgFull(t, string(tight)).Hash
	if s.Active().Hash != tightHash {
		t.Fatal("the looser config stayed active")
	}
	if _, pending := s.Pending(); pending {
		t.Fatal("nothing should be pending")
	}
	if len(*applied) != 3 || (*applied)[2].Hash != tightHash {
		t.Fatal("onApply must see the tightened config")
	}
	want := "could not save the approved config: keychain locked (it is in force now and will be re-applied from the file after a restart)"
	check := func(name string, probs config.Problems) {
		t.Helper()
		if probs.HasErrors() {
			t.Fatalf("%s: a save failure after a tightening is a warning, not an error: %v", name, probs)
		}
		found := false
		for _, p := range probs {
			found = found || (p.Severity == config.SevWarning && p.Message == want)
		}
		if !found {
			t.Fatalf("%s must carry the warning %q, got %v", name, want, probs)
		}
	}
	check("Result.Problems", r.Problems)
	check("LastProblems", s.LastProblems())
	if got, _ := v.Get(ApprovedVaultItem); string(got) != string(loose) {
		t.Fatal("the vault must still hold the last config it accepted")
	}

	// A restart while the vault is still unreachable: the older approved
	// config loads and the stricter file applies again without a prompt.
	s2, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r := s2.Observe(tight); !r.Applied || s2.Active().Hash != tightHash {
		t.Fatalf("after a restart the file, stricter than the approved config, must apply at once: %+v", r)
	}
	check("LastProblems after restart", s2.LastProblems())

	// The vault comes back: the next change is saved and the warning clears.
	v.FailPut = nil
	tighter := []byte(strings.Replace(string(tight), "scope: session\n          gate: login\n          expire: 8h\n", "gate: block\n", 1))
	if r := s.Observe(tighter); !r.Applied || len(r.Problems) != 0 {
		t.Fatalf("tightening with the vault back: %+v", r)
	}
	if got, err := v.Get(ApprovedVaultItem); err != nil || string(got) != string(tighter) {
		t.Fatal("the tightened config must be the approved one in the vault once it can be saved")
	}
	if s.LastProblems() != nil {
		t.Fatalf("the warning must clear: %v", s.LastProblems())
	}
}

// Observe, Approve and the readers are used from different goroutines (file
// watcher, control socket, agent requests); run with -race.
func TestStagerConcurrentUse(t *testing.T) {
	s, _, _ := open(t)
	files := [][]byte{
		src(base),
		src(strings.Replace(base, "gate: login", "gate: dialog", 1)),
		src(strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1)),
		nil,
		[]byte("garbage"),
	}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				switch (g + i) % 4 {
				case 0:
					s.Observe(files[(g+i)%len(files)])
				case 1:
					s.Approve("", yes)
				case 2:
					_ = s.Active()
					s.Pending()
				case 3:
					s.LastProblems()
				}
			}
		}(g)
	}
	wg.Wait()
	if s.Active() == nil {
		t.Fatal("no active config")
	}
}
