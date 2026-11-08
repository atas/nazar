package daemon

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 5: what the Nazar window needs from the CLI, on the daemon's
// side: a key's rules, the top-level apps, and edits of config.yaml that go
// through the staging of spec 4.8 without opening a prompt of their own.

const editBase = `apiVersion: nazar/v1
kind: Config
# my apps
apps:
  iterm:
    app: com.googlecode.iterm2
  claude:
    signed:
      team: Q6L2SF6YDW
      id: com.anthropic.claude-code
  tool:
    signed:
      team: TOOLTEAM01
      id: tool
ssh_agent:
  keys:
    github:
      rules:
        - apps:
            - claude # Claude Code
          scope: session
          gate: dialog
        - apps:
            - iterm
          scope: session
          gate: login
          expire: 8h
    hydra:
      scope: use
      gate: login
`

// startEdit runs a daemon whose approved config is editBase (applied
// through the gate once) and whose prompts are allowed unless a test says
// otherwise.
func startEdit(t *testing.T) *env {
	t.Helper()
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.writeConfig(t, editBase)
	waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["github"] != nil })
	return e
}

func (e *env) rules(t *testing.T, name string) (control.SSHKeyRules, *control.Problem) {
	t.Helper()
	var r control.SSHKeyRules
	err := e.call(t, control.CmdSSHKeyRules, map[string]string{"name": name}, control.KindSSHKeyRules, &r)
	return r, control.AsProblem(err)
}

// edit sends config.edit as the CLI does with --allow-loosen-access
// (allowLoosen true, unless args say otherwise): a loosening is written and
// staged, as the tests of staging need. editPlain sends it as the CLI does
// without the flag.
func (e *env) edit(t *testing.T, args map[string]string) (control.ConfigEdit, *control.Problem) {
	t.Helper()
	if _, ok := args["allowLoosen"]; !ok {
		a := make(map[string]string, len(args)+1)
		for k, v := range args {
			a[k] = v
		}
		a["allowLoosen"] = "true"
		args = a
	}
	return e.editPlain(t, args)
}

func (e *env) editPlain(t *testing.T, args map[string]string) (control.ConfigEdit, *control.Problem) {
	t.Helper()
	var r control.ConfigEdit
	err := e.call(t, control.CmdConfigEdit, args, control.KindConfigEdit, &r)
	return r, control.AsProblem(err)
}

func refs(rs ...string) string {
	b, _ := json.Marshal(rs)
	return string(b)
}

func TestSSHKeyRulesListsTheConfig(t *testing.T) {
	e := startEdit(t)
	r, p := e.rules(t, "github")
	if p != nil {
		t.Fatal(p)
	}
	if r.Kind != control.KindSSHKeyRules || !r.Configured || r.Staged || len(r.Rules) != 2 || r.Own != nil ||
		r.FallbackSource != "defaults.fallback" || r.Fallback.Gate != "block" || r.ConfigHash != contentHash([]byte(editBase)) {
		t.Fatalf("%+v", r)
	}
	r1, r2 := r.Rules[0], r.Rules[1]
	if r1.Index != 1 || r1.Apps[0].Name != "claude" || r1.Apps[0].Kind != "signed" || r1.Apps[0].Ref != "claude" ||
		r1.Policy != (control.PolicyInfo{Scope: "session", Gate: "dialog"}) {
		t.Fatalf("rule 1: %+v", r1)
	}
	if r2.Policy.Expire != "8h" || len(r2.To) != 0 {
		t.Fatalf("rule 2: %+v", r2)
	}
	hydra, _ := e.rules(t, "hydra")
	if hydra.Own == nil || hydra.Own.Gate != "login" || hydra.FallbackSource != "key-gate" || len(hydra.Rules) != 0 {
		t.Fatalf("hydra: %+v", hydra)
	}
	if _, p := e.rules(t, "nosuch"); p.ExitCode() != control.ExitError {
		t.Fatalf("unknown key: %+v", p)
	}
	if _, p := e.rules(t, "../x"); p.ExitCode() != control.ExitUsage {
		t.Fatalf("bad name: %+v", p)
	}
}

// A new rule is a loosening: the file is written, the change is staged,
// nothing applies and NO prompt opens until `config apply`, which shows the
// one prompt; the background prompt never fires for it.
func TestRuleAddIsStagedWithoutAPrompt(t *testing.T) {
	e := startEdit(t)
	logins := e.logins()
	r0, _ := e.rules(t, "github")
	res, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("tool"),
		"scope": "use", "gate": "login", "at": "1", "ifHash": r0.ConfigHash})
	if p != nil {
		t.Fatal(p)
	}
	if !res.Changed || res.Applied || res.Staged == nil || !res.Staged.Loosens || res.Kind != control.KindConfigEdit {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(e.readConfig(t), "# my apps") || !strings.Contains(e.readConfig(t), "# Claude Code") {
		t.Fatalf("comments lost:\n%s", e.readConfig(t))
	}
	if len(e.d.stager.Active().SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatal("a loosening applied without approval")
	}
	time.Sleep(10 * e.o.PollInterval) // the poller would have prompted by now
	if e.logins() != logins {
		t.Fatal("an edit must not open a prompt of its own; `config apply` does")
	}
	staged, _ := e.rules(t, "github")
	if !staged.Staged || len(staged.Rules) != 3 || staged.Rules[0].Apps[0].Name != "tool" {
		t.Fatalf("rules after the edit: %+v", staged)
	}
	if lines := e.configAudit(t, audit.Blocked); len(lines) == 0 || !strings.Contains(lines[len(lines)-1]["reason"], "rule.add github") {
		t.Fatalf("the edit must be audited with its caller: %v", lines)
	}
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	if e.logins() != logins+1 || len(e.d.stager.Active().SSHAgent.Keys["github"].Rules) != 3 {
		t.Fatal("config apply must show one prompt and apply the rule")
	}
}

// Without allowLoosen (the CLI's --allow-loosen-access) an edit that
// loosens access is refused before anything is written: exit 2 with
// control.LoosensRefusal, the change and what it loosens in the details,
// config.yaml untouched, nothing staged, no hold on the background prompt,
// no prompt, and one blocked audit line with the caller. Only the exact
// value "true" allows it.
func TestLooseningEditWithoutTheFlagIsRefused(t *testing.T) {
	e := startEdit(t)
	logins := e.logins()
	blocked := len(e.configAudit(t, audit.Blocked))
	before := e.readConfig(t)
	add := map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("tool"), "scope": "use", "gate": "login", "at": "1"}
	for _, allow := range []string{"", "false", "TRUE", "yes", "1"} {
		args := map[string]string{"allowLoosen": allow}
		for k, v := range add {
			args[k] = v
		}
		if allow == "" {
			delete(args, "allowLoosen")
		}
		res, p := e.editPlain(t, args)
		if p == nil || p.ExitCode() != control.ExitUsage || p.Code != control.CodeUsage || p.Message != control.LoosensRefusal {
			t.Fatalf("allowLoosen %q: want the usage refusal %q, got %+v %+v", allow, control.LoosensRefusal, res, p)
		}
		if res.Changed || res.Staged != nil || res.Applied {
			t.Fatalf("allowLoosen %q: a refused edit reported a result: %+v", allow, res)
		}
		if len(p.Details) < 2 || !strings.Contains(p.Details[0], "added rule 1") || !strings.HasPrefix(p.Details[len(p.Details)-1], "loosens ssh:github: ") {
			t.Fatalf("allowLoosen %q: details must be the change and what it loosens: %q", allow, p.Details)
		}
		if p.Fix != "" {
			t.Fatalf("nazar-agent must never fill Fix (the CLI does): %+v", p)
		}
		if e.readConfig(t) != before {
			t.Fatalf("allowLoosen %q: the refused edit wrote config.yaml", allow)
		}
		if _, ok := e.d.stager.Pending(); ok {
			t.Fatalf("allowLoosen %q: the refused edit staged something", allow)
		}
	}
	if e.logins() != logins {
		t.Fatal("a refused edit must not prompt")
	}
	lines := e.configAudit(t, audit.Blocked)
	if len(lines) != blocked+5 || !strings.Contains(lines[len(lines)-1]["reason"], "rule.add github") || !strings.Contains(lines[len(lines)-1]["reason"], "allow-loosen-access") {
		t.Fatalf("each refusal must be audited blocked with the caller and the flag: %v", lines[blocked:])
	}
	// No hold was taken: another caller's edit with the flag goes through at
	// once, and the rules in force are what they were.
	if res, p := e.edit(t, add); p != nil || res.Staged == nil {
		t.Fatalf("the same edit with the flag: %+v %+v", res, p)
	}
	if len(e.d.stager.Active().SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatal("a refused edit changed the rules in force")
	}
}

// The refusal says exactly what the staged change would say: the details of
// the edit refused without the flag are the Changes and "loosens …" lines
// of the diff the same edit stages with it (Preview classifies the written
// file as Observe does, against the approved config the file holds).
func TestLoosensRefusalDetailsAreTheStagedDiff(t *testing.T) {
	e := startEdit(t)
	for _, args := range []map[string]string{
		{"op": control.EditRuleAdd, "key": "github", "apps": refs("tool"), "scope": "use", "gate": "login", "at": "1"},
		{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""},
		{"op": control.EditKeySet, "key": "hydra", "gate": "dialog"},
		{"op": control.EditRuleRemove, "key": "github", "index": "1"}, // removing rule 1 (dialog) lets rule 2 (login) match claude: tightens
	} {
		_, p := e.editPlain(t, args)
		res, p2 := e.edit(t, args)
		if p2 != nil {
			t.Fatalf("%v with the flag: %+v", args, p2)
		}
		if res.Staged == nil {
			if p != nil {
				t.Fatalf("%v tightens, so it needs no flag: %+v", args, p)
			}
			if res.Changed {
				// Undo the tightening so the next case sees the base config.
				e.activate(t, editBase)
			}
			continue
		}
		want := append([]string{}, res.Staged.Changes...)
		for _, l := range res.Staged.Loosening {
			want = append(want, "loosens "+l)
		}
		if p == nil || strings.Join(p.Details, "\n") != strings.Join(want, "\n") {
			t.Fatalf("%v: refusal details\n%s\nwant the staged diff\n%s", args, strings.Join(p.Details, "\n"), strings.Join(want, "\n"))
		}
		// Back to the base config for the next case.
		if diff, p := e.apply(t); p != nil || !diff.Applied {
			t.Fatalf("apply: %+v %+v", diff, p)
		}
		e.f.Advance(2 * time.Minute)
		e.activate(t, editBase)
	}
}

// The flag changes nothing for an edit that does not loosen: a tightening
// and a no-op are in force at once, prompt nothing, and need no flag.
func TestTighteningNeedsNoFlagAndTheFlagIsHarmless(t *testing.T) {
	e := startEdit(t)
	logins := e.logins()
	for _, args := range []map[string]string{
		{"op": control.EditKeySet, "key": "hydra", "gate": "block"},
		{"op": control.EditKeySet, "key": "hydra", "gate": "block", "allowLoosen": "true"},
		{"op": control.EditRuleSet, "key": "github", "index": "1", "gate": "dialog"},                        // what the file says
		{"op": control.EditRuleSet, "key": "github", "index": "1", "gate": "dialog", "allowLoosen": "true"}, // the same with the flag
		{"op": control.EditRuleRemove, "key": "github", "index": "2", "allowLoosen": "true"},
	} {
		res, p := e.editPlain(t, args)
		if p != nil || !res.Applied || res.Staged != nil {
			t.Fatalf("%v: want in force, got %+v %+v", args, res, p)
		}
	}
	if e.logins() != logins {
		t.Fatal("a tightening needs no prompt")
	}
	if _, ok := e.d.stager.Pending(); ok {
		t.Fatal("nothing may be staged")
	}
}

// Removing a rule only tightens: in force at once, no prompt.
func TestRuleRemoveAppliesAtOnce(t *testing.T) {
	e := startEdit(t)
	logins := e.logins()
	res, p := e.edit(t, map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "1"})
	if p != nil || !res.Applied || res.Staged != nil || !res.Changed {
		t.Fatalf("%+v %+v", res, p)
	}
	if k := e.d.stager.Active().SSHAgent.Keys["github"]; len(k.Rules) != 1 || k.Rules[0].Apps[0].Name != "iterm" {
		t.Fatalf("not in force: %+v", k.Rules)
	}
	if e.logins() != logins {
		t.Fatal("a tightening needs no prompt")
	}
}

func TestRuleSetAndKeySet(t *testing.T) {
	e := startEdit(t)
	// login → dialog on rule 2 is a loosening: staged.
	res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
	if p != nil || res.Staged == nil {
		t.Fatalf("%+v %+v", res, p)
	}
	r, _ := e.rules(t, "github")
	if r.Rules[1].Policy != (control.PolicyInfo{Scope: "session", Gate: "dialog"}) {
		t.Fatalf("rule 2: %+v", r.Rules[1])
	}
	// hydra: login → block tightens, but the file still holds the staged
	// loosening above, so the edit is refused: it would otherwise
	// be reported as staged with the other change.
	res, p = e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"})
	notApproved(t, "a tightening on a staged file", res, p)
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	res, p = e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"})
	if p != nil || !res.Changed || !res.Applied || res.Staged != nil {
		t.Fatalf("the tightening once nothing is staged: %+v %+v", res, p)
	}
	if _, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "none"}); p.ExitCode() != control.ExitError {
		t.Fatalf("a key's own gate none: %+v", p)
	}
}

// While config.yaml holds a staged loosening, nothing in it is in force,
// so no edit, a no-op included, may report "applied", and none may report
// "staged" either: that would present the other change as the
// edit's own, and a caller answers a staged edit with `nazar config apply`.
// Every such edit is refused and writes nothing.
func TestNoOpEditOnAStagedFileIsRefused(t *testing.T) {
	e := startEdit(t)
	res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog"})
	if p != nil || res.Staged == nil {
		t.Fatalf("stage a loosening: %+v %+v", res, p)
	}
	staged := e.readConfig(t)
	for _, args := range []map[string]string{
		{"op": control.EditKeySet, "key": "hydra", "gate": "login"},                  // what the file already says
		{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog"}, // the staged loosening again
		{"op": control.EditRuleSet, "key": "github", "index": "1", "gate": "dialog"}, // what the file already says
	} {
		res, p = e.edit(t, args)
		notApproved(t, fmt.Sprintf("no-op %v on a staged file", args), res, p)
		if e.readConfig(t) != staged {
			t.Fatalf("%v wrote config.yaml", args)
		}
	}
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "login" {
		t.Fatalf("hydra gate in force: %s", g)
	}
	if _, ok := e.d.stager.Pending(); !ok {
		t.Fatal("the loosening must still be staged")
	}
}

// On a clean file (nothing staged) a no-op edit is in force, as the file is.
func TestNoOpEditOnACleanFileIsApplied(t *testing.T) {
	e := startEdit(t)
	for _, args := range []map[string]string{
		{"op": control.EditKeySet, "key": "hydra", "gate": "login"},
		{"op": control.EditRuleSet, "key": "github", "index": "1", "gate": "dialog", "scope": "session"},
	} {
		res, p := e.edit(t, args)
		if p != nil || res.Changed || !res.Applied || res.Staged != nil || res.Hash != contentHash([]byte(editBase)) {
			t.Fatalf("no-op %v: %+v %+v", args, res, p)
		}
	}
	// After a tightening is in force, repeating it is a no-op in force too.
	res, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"})
	if p != nil || !res.Changed || !res.Applied {
		t.Fatalf("tightening: %+v %+v", res, p)
	}
	res, p = e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"})
	if p != nil || res.Changed || !res.Applied || res.Staged != nil {
		t.Fatalf("repeated tightening: %+v %+v", res, p)
	}
	if e.readConfig(t) == editBase {
		t.Fatal("the tightening must be in the file")
	}
}

// Every refusal leaves config.yaml as it was.
func TestEditRefusals(t *testing.T) {
	e := startEdit(t)
	before := e.readConfig(t)
	cases := []struct {
		name string
		args map[string]string
		code int
	}{
		{"stale hash", map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "1", "ifHash": "0000"}, control.ExitError},
		{"unknown app name", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("nosuch"), "gate": "login"}, control.ExitError},
		{"none with an Apple-signed matcher", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("signed:apple"), "gate": "none"}, control.ExitError},
		{"no such rule", map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "9"}, control.ExitError},
		{"bad index", map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "x"}, control.ExitUsage},
		{"bad gate", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("iterm"), "gate": "yes"}, control.ExitUsage},
		{"bad matcher", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("x: y"), "gate": "login"}, control.ExitUsage},
		{"apps not a list", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": "iterm", "gate": "login"}, control.ExitUsage},
		{"bad key", map[string]string{"op": control.EditRuleRemove, "key": "../x", "index": "1"}, control.ExitUsage},
		{"unknown op", map[string]string{"op": "rule.move", "key": "github"}, control.ExitUsage},
		{"bad expire", map[string]string{"op": control.EditKeySet, "key": "hydra", "expire": "soon"}, control.ExitUsage},
	}
	for _, c := range cases {
		if _, p := e.edit(t, c.args); p.ExitCode() != c.code {
			t.Errorf("%s: %+v, want exit %d", c.name, p, c.code)
		}
		if e.readConfig(t) != before {
			t.Fatalf("%s changed config.yaml", c.name)
		}
	}
	_, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("signed:apple"), "gate": "none"})
	if len(p.Details) == 0 || !strings.Contains(strings.Join(p.Details, "\n"), "gate: none") {
		t.Fatalf("the parse errors must be in the details: %+v", p)
	}
	// An invalid file is never edited.
	e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent: [broken\n")
	if _, p := e.edit(t, map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "1"}); p.ExitCode() != control.ExitError ||
		!strings.Contains(p.Message, "invalid") {
		t.Fatalf("invalid file: %+v", p)
	}
}

func TestAppsList(t *testing.T) {
	e := startEdit(t)
	var l control.AppList
	if err := e.call(t, control.CmdAppsList, nil, control.KindAppList, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 3 || l.Items[0].Name != "claude" || l.Items[1].Name != "iterm" || l.Items[2].Name != "tool" {
		t.Fatalf("%+v", l.Items)
	}
	claude, iterm, tool := l.Items[0], l.Items[1], l.Items[2]
	if strings.Join(claude.UsedBy, ",") != "github rule 1" || claude.Matcher.Team != "Q6L2SF6YDW" {
		t.Fatalf("claude: %+v", claude)
	}
	// iTerm2 is installed in the test env, so approving editBase pinned it.
	if iterm.PinnedTeam != "H7V7XYVQ7D" || iterm.Problem != "" {
		t.Fatalf("iterm: %+v", iterm)
	}
	if tool.Problem != "" || tool.Fix != "" || strings.Join(tool.UsedBy, ",") != "" || tool.Matcher.Ref != "tool" {
		t.Fatalf("tool: %+v", tool)
	}
}

// `ssh-key list` carries each key's rules, warnings and last use.
func TestKeyListCarriesPolicyAndLastUse(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	// ssh-key create takes no gate; the entry is written first (approved by
	// the allowed login gate) and the key is created under it.
	e.activate(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      scope: session\n      gate: dialog\n")
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	var l control.SSHKeyList
	e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l)
	k := l.Items[0]
	if k.LastUsed != nil || k.Policy == nil || k.Policy.FallbackSource != "key-gate" || k.Policy.Own.Gate != "dialog" || l.Since.IsZero() {
		t.Fatalf("before use: %+v since %v", k, l.Since)
	}
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	if err := e.signAs(t, tab.Peer()); err != nil {
		t.Fatal(err)
	}
	e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l)
	use := l.Items[0].LastUsed
	if use == nil || use.Decision != "approved" || use.App != "com.googlecode.iterm2" || !strings.Contains(use.Chain, "ssh") {
		t.Fatalf("last use: %+v", use)
	}
}

// `ssh-key list` carries each key's warnings, as the window shows them per
// key: the parse warnings about its own entry (and only its own: `git`
// never gets `github`'s) and the Secure Enclave advice about its gates,
// against the config the window shows (the staged one, when there is one).
// A key without warnings carries an empty list, never null.
func TestKeyListCarriesWarnings(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.writeConfig(t, `apiVersion: nazar/v1
kind: Config
ssh_agent:
  keys:
    github:
      rules:
        - apps: [any]
          gate: block
        - apps: [any]
          gate: login
    git:
      scope: session
      gate: dialog
    hydra:
      scope: use
      gate: login
`)
	waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["hydra"] != nil })
	for _, name := range []string{"github", "git", "hydra"} { // the entries exist: re-created, with the gates the entries give them
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": name}, control.KindSSHKey, &control.SSHKey{}); err != nil {
			t.Fatal(err)
		}
	}
	list := func() map[string]control.SSHKey {
		var l control.SSHKeyList
		if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l); err != nil {
			t.Fatal(err)
		}
		m := map[string]control.SSHKey{}
		for _, k := range l.Items {
			m[k.Name] = k
		}
		return m
	}
	keys := list()
	const neverWarning = "can never match: rule 1 always matches first"
	if w := keys["github"].Warnings; len(w) != 1 || w[0] != neverWarning {
		t.Fatalf("github: %q", w)
	}
	// A dialog gate is a choice made when the key was created, not a
	// problem: git carries no warning (and never github's).
	if w := keys["git"].Warnings; len(w) != 0 {
		t.Fatalf("git must carry no warning, and not github's: %q", w)
	}
	if w := keys["hydra"].Warnings; len(w) != 0 || !keys["hydra"].UserPresence {
		t.Fatalf("hydra: %q presence %v", w, keys["hydra"].UserPresence)
	}
	if b, _ := json.Marshal(keys["hydra"]); !strings.Contains(string(b), `"warnings":[]`) {
		t.Fatalf("a key without warnings must carry an empty list, not null: %s", b)
	}
	// Loosening hydra to dialog with nazar's own command is refused (its
	// Secure Enclave user presence can't serve a dialog gate); the same
	// loosening written by hand is staged, and the list shows the staged
	// config, so hydra now carries the advice about its user presence.
	if res, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "dialog"}); p == nil || p.ExitCode() != control.ExitError || res.Staged != nil {
		t.Fatalf("%+v %+v", res, p)
	}
	e.writeConfig(t, strings.Replace(e.readConfig(t), "scope: use\n      gate: login", "scope: use\n      gate: dialog", 1))
	waitFor(t, func() bool { keys = list(); return len(keys["hydra"].Warnings) == 1 })
	w := strings.Join(keys["hydra"].Warnings, "\n")
	if !strings.Contains(w, "re-create the key without user presence") {
		t.Fatalf("hydra after the staged loosening: %q", keys["hydra"].Warnings)
	}
	if w := keys["git"].Warnings; len(w) != 0 {
		t.Fatalf("git after the edit: %q", w)
	}
}

// More refusals, aimed at the edges an agent driving config.edit could use:
// an empty ifHash must not skip the check, a matcher with a newline must
// not inject YAML, and every malformed list or number is a usage error.
// Each leaves config.yaml as it was.
func TestEditRefusalsEdges(t *testing.T) {
	e := startEdit(t)
	before := e.readConfig(t)
	cases := []struct {
		name string
		args map[string]string
		code int
	}{
		{"empty ifHash", map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "1", "ifHash": ""}, control.ExitError},
		{"matcher with a newline", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("app:com.x\n  gate: none"), "gate": "login"}, control.ExitUsage},
		{"bad to matcher", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("iterm"), "to": refs("x: y"), "gate": "login"}, control.ExitUsage},
		{"empty apps", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": "", "gate": "login"}, control.ExitUsage},
		{"apps an empty list", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": "[]", "gate": "login"}, control.ExitUsage},
		{"rule.add without gate", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("iterm")}, control.ExitUsage},
		{"rule.add without apps", map[string]string{"op": control.EditRuleAdd, "key": "github", "gate": "login"}, control.ExitUsage},
		{"at zero", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("iterm"), "gate": "login", "at": "0"}, control.ExitUsage},
		{"at past the end", map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("iterm"), "gate": "login", "at": "9"}, control.ExitError},
		{"negative index", map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "-1"}, control.ExitUsage},
		{"missing index", map[string]string{"op": control.EditRuleRemove, "key": "github"}, control.ExitUsage},
		{"rule.set apps an empty list", map[string]string{"op": control.EditRuleSet, "key": "github", "index": "1", "apps": "[]"}, control.ExitUsage},
		{"key.set with apps", map[string]string{"op": control.EditKeySet, "key": "hydra", "apps": refs("iterm"), "gate": "login"}, control.ExitUsage},
		{"bad scope", map[string]string{"op": control.EditKeySet, "key": "hydra", "scope": "forever"}, control.ExitUsage},
		{"no such key", map[string]string{"op": control.EditRuleRemove, "key": "nosuch", "index": "1"}, control.ExitError},
		{"no op", map[string]string{"key": "github"}, control.ExitUsage},
	}
	for _, c := range cases {
		if _, p := e.edit(t, c.args); p.ExitCode() != c.code {
			t.Errorf("%s: %+v, want exit %d", c.name, p, c.code)
		}
		if e.readConfig(t) != before {
			t.Fatalf("%s changed config.yaml", c.name)
		}
	}
	if len(e.d.stager.Active().SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatal("a refused edit changed the rules in force")
	}
}

// A tightening is audited too, as applied, with its caller; the matching
// ifHash is accepted and the reply's Hash is the new file's.
func TestTighteningEditIsAudited(t *testing.T) {
	e := startEdit(t)
	r0, _ := e.rules(t, "github")
	res, p := e.edit(t, map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "2", "ifHash": r0.ConfigHash})
	if p != nil || !res.Applied || res.Op != control.EditRuleRemove || res.Key != "github" {
		t.Fatalf("%+v %+v", res, p)
	}
	if res.Hash != contentHash([]byte(e.readConfig(t))) || res.Hash == r0.ConfigHash {
		t.Fatalf("hash %q, file %q", res.Hash, contentHash([]byte(e.readConfig(t))))
	}
	lines := e.configAudit(t, audit.Allowed)
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1]["reason"], "rule.remove github") {
		t.Fatalf("the tightening must be audited: %v", lines)
	}
	r1, _ := e.rules(t, "github")
	if r1.Staged || len(r1.Rules) != 1 || r1.ConfigHash != res.Hash {
		t.Fatalf("rules after: %+v", r1)
	}
	// The old hash is now stale.
	if _, p := e.edit(t, map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "1", "ifHash": r0.ConfigHash}); p.ExitCode() != control.ExitError {
		t.Fatalf("stale hash after an edit: %+v", p)
	}
}

// Only the broker's sign decisions that let a request through count as a
// key's last use: never a denial, a block, a timeout, a control command
// (no gate) or a non-ssh target.
func TestKeyUsesRecordsOnlySigns(t *testing.T) {
	var u keyUses
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for _, ev := range []audit.Event{
		{Time: now, Decision: audit.Denied, Target: "ssh:github", Gate: "dialog"},
		{Time: now, Decision: audit.Blocked, Target: "ssh:github", Gate: "block"},
		{Time: now, Decision: audit.Timeout, Target: "ssh:github", Gate: "dialog"},
		{Time: now, Decision: audit.Error, Target: "ssh:github", Gate: "login"},
		{Time: now, Decision: audit.Allowed, Target: "ssh:github"},            // a control command
		{Time: now, Decision: audit.Allowed, Target: "config", Gate: "login"}, // not a key
		{Time: now, Decision: audit.Approved, Target: "trust:/x", Gate: "login"},
	} {
		u.record(ev)
	}
	if use := u.last("github"); use != nil {
		t.Fatalf("counted as a use: %+v", use)
	}
	u.record(audit.Event{Time: now, Decision: audit.Approved, Target: "ssh:github", Gate: "dialog", App: "com.googlecode.iterm2",
		Chain: []audit.Proc{{Name: "iTerm2", PID: 1}, {Name: "zsh", PID: 2}, {Name: "ssh", PID: 3}}})
	later := now.Add(time.Minute)
	u.record(audit.Event{Time: later, Decision: audit.Denied, Target: "ssh:github", Gate: "dialog"})
	use := u.last("github")
	// The chain as the audit log writes it: TestKeyUseChainIsTheAuditChain.
	if use == nil || !use.Time.Equal(now) || use.Decision != "approved" || use.App != "com.googlecode.iterm2" || use.Chain != "iTerm2(1) > zsh(2) > ssh(3)" {
		t.Fatalf("last use: %+v", use)
	}
	u.record(audit.Event{Time: later, Decision: audit.Allowed, Target: "ssh:github", Gate: "dialog"})
	if use := u.last("github"); use == nil || !use.Time.Equal(later) || use.Decision != "allowed" {
		t.Fatalf("a later allowed use: %+v", use)
	}
	if u.last("hydra") != nil {
		t.Fatal("another key")
	}
}

// Matchers written inline in rules (`apps: {app: …}`) are listed too, once
// each, with the rules that use them and their pinned team: a config with
// no top-level apps: must not show an empty list.
func TestAppsListShowsInlineMatchers(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.writeConfig(t, `apiVersion: nazar/v1
kind: Config
ssh_agent:
  keys:
    github:
      rules:
        - apps:
            - signed:
                team: Q6L2SF6YDW
                id: com.anthropic.claude-code
          scope: session
          gate: dialog
        - apps:
            - app: com.googlecode.iterm2
          scope: session
          gate: login
    hydra:
      rules:
        - apps:
            - app: com.googlecode.iterm2
          gate: login
`)
	e.d.Reload()
	waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["hydra"] != nil })
	var l control.AppList
	if err := e.call(t, control.CmdAppsList, nil, control.KindAppList, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 2 {
		t.Fatalf("%+v", l.Items)
	}
	iterm, claude := l.Items[0], l.Items[1]
	if iterm.Matcher.Ref != "app:com.googlecode.iterm2" {
		iterm, claude = claude, iterm
	}
	if claude.Name != "" || claude.Matcher.Ref != "signed:Q6L2SF6YDW:com.anthropic.claude-code" || strings.Join(claude.UsedBy, ",") != "github rule 1" {
		t.Fatalf("claude: %+v", claude)
	}
	if iterm.Matcher.Ref != "app:com.googlecode.iterm2" || iterm.PinnedTeam != "H7V7XYVQ7D" || strings.Join(iterm.UsedBy, ",") != "github rule 2,hydra rule 1" {
		t.Fatalf("iterm: %+v", iterm)
	}
}

// The list covers the rules of secrets, k8s contexts and aws entries as well
// as keys: an app only they name is listed, and each row names every rule
// that uses it, in key, secret, context, entry order, named and inline alike.
func TestAppsListCoversEveryKindOfRule(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.writeConfig(t, `apiVersion: nazar/v1
kind: Config
apps:
  tool: {signed: {team: TOOLTEAM01, id: com.example.tool}}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}]
          scope: session
          gate: dialog
secrets:
  NOTES:
    rules:
      - apps: [{app: com.googlecode.iterm2}]
        to: [{signed: {team: apple, id: com.apple.bash}}]
        scope: session
        gate: dialog
      - apps: [tool]
        to: [tool]
        scope: session
        gate: dialog
k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster: {server: "https://hydra.example:16443", ca_sha256: 3f8c0000000000000000000000000000000000000000000000000000000000e1}
      rules:
        - apps: [{app: com.googlecode.iterm2}]
          scope: session
          gate: dialog
        - apps: [{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}]
          scope: session
          gate: dialog
aws:
  dev:
    identity: {user: dev-nazar}
    trustAnchorArn: `+testAnchor+`
    profileArn: `+testProfile+`
    roleArn: `+testRole+`
    rules:
      - apps: [{app: com.googlecode.iterm2}]
        scope: session
        gate: dialog
      - apps: [tool]
        scope: session
        gate: dialog
`)
	e.d.Reload()
	waitFor(t, func() bool { return e.d.stager.Active().AWS["dev"] != nil })
	var l control.AppList
	if err := e.call(t, control.CmdAppsList, nil, control.KindAppList, &l); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range l.Items {
		got[it.Matcher.Ref] = strings.Join(it.UsedBy, ",")
	}
	want := map[string]string{
		"tool":                      "secret NOTES rule 2,secret NOTES rule 2 (to),aws dev rule 2",
		"app:com.googlecode.iterm2": "secret NOTES rule 1,k8s hydra rule 1,aws dev rule 1",
		"signed:Q6L2SF6YDW:com.anthropic.claude-code": "github rule 1,k8s hydra rule 2",
		"signed:apple:com.apple.bash":                 "secret NOTES rule 1 (to)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apps list:\n got %v\nwant %v", got, want)
	}
}

// A rule nazar's own commands would add that the key's recorded
// protection cannot serve (dialog or none, or login with scope session or
// app, on a user-presence key) is refused at edit time, with the steps that
// allow it, instead of failing at sign time. A fitting rule and a
// tightening are not refused. Hand edits of the file are still only warned
// about (keyAdvice).
func TestEditRefusedWhenThePresenceKeyCannotServeIt(t *testing.T) {
	e := startWith(t, withClock) // e.f.Advance moves the daemon's clock past any prompt cooldown
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.createKey(t, "hydra", platform.AuthUserPresence)
	e.createKey(t, "plain", platform.AuthNone)
	e.activate(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    hydra:
      scope: use
      gate: login
    plain:
      scope: use
      gate: login
`)
	before := e.readConfig(t)
	for _, args := range []map[string]string{
		{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "dialog"},
		{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "none"},
		{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "login", "scope": "session"},
		{"op": control.EditKeySet, "key": "hydra", "gate": "dialog"},
	} {
		_, p := e.edit(t, args)
		if p == nil || p.ExitCode() != control.ExitError {
			t.Fatalf("%v: want a refusal (exit 1), got %+v", args, p)
		}
		// One plain sentence: the chip asks on every use, so a looser rule
		// needs another key.
		for _, want := range []string{`SSH key "hydra" asks on every use (enforced by the chip); create another key for a looser rule`, "nothing was changed"} {
			if !strings.Contains(p.Message, want) {
				t.Errorf("%v: message %q lacks %q", args, p.Message, want)
			}
		}
		if e.readConfig(t) != before {
			t.Fatalf("%v: config.yaml was written", args)
		}
	}
	// The same rule on a key without presence is staged as any loosening
	// (a staged edit is a result with Staged set, not a Problem: the CLI
	// turns it into exit 4).
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "plain", "apps": refs("iterm"), "gate": "dialog"}); p != nil || r.Staged == nil || r.Applied {
		t.Fatalf("plain: %+v %+v", r, p)
	}
	e.f.Advance(2 * time.Minute)
	var d control.ConfigDiff
	if err := e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &d); err != nil || !d.Applied {
		t.Fatalf("apply: %+v %v", d, err)
	}
	// A fitting rule (login + use) and a tightening (block) on the presence
	// key go through: the rule applied at once (it loosens nothing against
	// the key's own login + use gate; a looser fitting rule would be
	// staged), the tightening too.
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "login"}); p != nil || !r.Changed || !r.Applied {
		t.Fatalf("login+use on hydra: %+v %+v", r, p)
	}
	if n := len(e.d.stager.Active().SSHAgent.Keys["hydra"].Rules); n != 1 {
		t.Fatalf("hydra has %d rules in force, want 1", n)
	}
	if r, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"}); p != nil || !r.Applied {
		t.Fatalf("tightening hydra to block: %+v %+v", r, p)
	}
	// Deleting the key (and with it the chip's protection) lifts the
	// refusal: the rule (here as rule 1, ahead of the login rule that would
	// shadow it) is staged as any loosening, and a key created under the
	// new entry comes back without user presence, so the rule can serve.
	e.f.Advance(2 * time.Minute)
	if err := e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "hydra"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatalf("delete hydra: %v", err)
	}
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "dialog", "at": "1"}); p != nil || r.Staged == nil {
		t.Fatalf("dialog rule on hydra once the key is gone: want it staged, got %+v %+v", r, p)
	}
	e.f.Advance(2 * time.Minute)
	if err := e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &d); err != nil || !d.Applied {
		t.Fatalf("apply the dialog rule: %+v %v", d, err)
	}
	e.f.Advance(2 * time.Minute)
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "hydra"}, control.KindSSHKey, &k); err != nil {
		t.Fatalf("create hydra under the new entry: %v", err)
	}
	if k.UserPresence {
		t.Fatalf("hydra came back with user presence under an entry with a dialog rule: %+v", k)
	}
}

// The refusal is for an edit that loosens a presence
// key into a policy its chip cannot serve. A presence key whose approved
// entry already has such a rule (written by hand, or by `rule add` before
// Milestone 7, which only warned) must still be tightened with nazar's own
// commands (AGENTS.md: a tightening applies at once); a fitting rule added
// to it is staged as any loosening; a new unfit rule is still refused.
func TestEditTightensAPresenceKeyThatAlreadyCannotServe(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.createKey(t, "hydra", platform.AuthUserPresence)
	e.activate(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    signed:
      team: H7V7XYVQ7D
      id: com.googlecode.iterm2
  claude:
    signed:
      team: Q6L2SF6YDW
      id: com.anthropic.claude-code
  tool:
    signed:
      team: TOOLTEAM01
      id: tool
ssh_agent:
  keys:
    hydra:
      scope: use
      gate: login
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
        - apps: [any]
          gate: none
`)
	e.f.Advance(2 * time.Minute)
	// tool from none to dialog is a tightening, but it adds a policy the
	// chip can't serve: refused like any such edit, so a rule can't be
	// slipped in behind another and uncovered later (a security review of
	// --always-ask). login with scope use is the tightening that
	// fits.
	if _, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("tool"), "gate": "dialog", "at": "2"}); p == nil || !strings.Contains(p.Message, "asks on every use (enforced by the chip)") {
		t.Fatalf("a dialog rule for tool on hydra: want the refusal, got %+v", p)
	}
	for _, args := range []map[string]string{
		{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("tool"), "gate": "login", "at": "2"},
		{"op": control.EditRuleSet, "key": "hydra", "index": "3", "apps": refs("iterm")},
		{"op": control.EditRuleSet, "key": "hydra", "index": "3", "gate": "dialog"},
		{"op": control.EditRuleSet, "key": "hydra", "index": "2", "gate": "block"},
		{"op": control.EditRuleRemove, "key": "hydra", "index": "3"},
		{"op": control.EditKeySet, "key": "hydra", "gate": "block"},
	} {
		if r, p := e.edit(t, args); p != nil || !r.Changed || !r.Applied || r.Staged != nil {
			t.Fatalf("%v: want the tightening applied, got %+v %+v", args, r, p)
		}
	}
	before := e.readConfig(t)
	if _, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "none"}); p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "asks on every use (enforced by the chip)") {
		t.Fatalf("a new none rule on hydra: want the refusal, got %+v", p)
	}
	if e.readConfig(t) != before {
		t.Fatal("the refused edit wrote config.yaml")
	}
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "login"}); p != nil || r.Staged == nil {
		t.Fatalf("a fitting login rule on hydra: want it staged, got %+v %+v", r, p)
	}
}
