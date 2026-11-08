package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// What the Secrets tab needs from the agent: a secret's rules as
// structured as a key's (secret.list's policy and warnings), and config.edit
// on secrets.<name>, staged and classified exactly as a key's edit.

const secretEditBase = `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
secrets:
  GH_TOKEN:
    gate: block
    rules:
      - apps: [iterm]
        to:
          - signed:
              team: apple
              id: com.apple.git-remote-http
        scope: session
        gate: login
  A:
    gate: block
  A.B:
    gate: block
    rules:
      - apps: [iterm]
        scope: use
        gate: login
`

// (If this base draws a parse warning for GH_TOKEN or A, fix the base, never
// the assertions below: GH_TOKEN names its receiver, A has no rule.)
func startSecretEdit(t *testing.T) *env {
	t.Helper()
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.writeConfig(t, secretEditBase)
	waitFor(t, func() bool { return e.d.stager.Active().Secrets["GH_TOKEN"] != nil })
	return e
}

func (e *env) secretList(t *testing.T) map[string]control.Secret {
	t.Helper()
	var l control.SecretList
	if err := e.call(t, control.CmdSecretList, nil, control.KindSecretList, &l); err != nil {
		t.Fatal(err)
	}
	m := map[string]control.Secret{}
	for _, s := range l.Items {
		m[s.Name] = s
	}
	return m
}

func TestSecretListCarriesPolicyAndWarnings(t *testing.T) {
	e := startSecretEdit(t)
	l := e.secretList(t)
	gh := l["GH_TOKEN"]
	p := gh.Policy
	if p == nil || p.Kind != control.KindSSHKeyRules || p.Name != "GH_TOKEN" || !p.Configured || p.Staged ||
		p.ConfigHash != contentHash([]byte(secretEditBase)) || p.FallbackSource != "secret-gate" || p.Own == nil || p.Own.Gate != "block" ||
		p.Fallback.Gate != "block" || len(p.Rules) != 1 {
		t.Fatalf("GH_TOKEN policy: %+v", p)
	}
	r := p.Rules[0]
	if r.Index != 1 || r.Apps[0].Ref != "iterm" || len(r.To) != 1 || r.To[0].Kind != "signed" || r.To[0].Ref != "signed:apple:com.apple.git-remote-http" ||
		r.Policy != (control.PolicyInfo{Scope: "session", Gate: "login"}) {
		t.Fatalf("rule 1: %+v", r)
	}
	// Warnings are the entry's own: A.B's rule has no to:, A has nothing,
	// though A prefixes A.B's path; never null.
	if gh.Warnings == nil || len(gh.Warnings) != 0 || l["A"].Warnings == nil || len(l["A"].Warnings) != 0 {
		t.Fatalf("GH_TOKEN %q, A %q", gh.Warnings, l["A"].Warnings)
	}
	if w := strings.Join(l["A.B"].Warnings, "\n"); !strings.Contains(w, "no to:") {
		t.Fatalf("A.B warnings %q", w)
	}
	// State and delivery as Milestone 8 built them: configured, not stored, the default deliver.
	if gh.Stored || gh.Broken || !gh.Configured || strings.Join(gh.Deliver, ",") != "helper,stdout" {
		t.Fatalf("%+v", gh)
	}
}

// A secret's new rule is a loosening: written and staged, no prompt, not in
// force until `config apply`; removing a rule tightens at once.
func TestSecretRuleEditIsStagedLikeAKey(t *testing.T) {
	e := startSecretEdit(t)
	logins := e.logins()
	pol := e.secretList(t)["GH_TOKEN"].Policy
	if pol == nil {
		t.Fatal("secret.list gives no policy")
	}
	hash := pol.ConfigHash
	res, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "secret": "GH_TOKEN", "apps": refs("iterm"),
		"scope": "session", "gate": "dialog", "at": "1", "ifHash": hash})
	if p != nil {
		t.Fatal(p)
	}
	if !res.Changed || res.Applied || res.Staged == nil || !res.Staged.Loosens || res.Secret != "GH_TOKEN" || res.Key != "" {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(strings.Join(res.Staged.Loosening, "\n"), "secret:GH_TOKEN") {
		t.Fatalf("loosening %q", res.Staged.Loosening)
	}
	if len(e.d.stager.Active().Secrets["GH_TOKEN"].Rules) != 1 {
		t.Fatal("a loosening applied without approval")
	}
	time.Sleep(10 * e.o.PollInterval) // the poller would have prompted by now
	if e.logins() != logins {
		t.Fatal("an edit must not open a prompt of its own")
	}
	if lines := e.configAudit(t, audit.Blocked); len(lines) == 0 || !strings.Contains(lines[len(lines)-1]["reason"], "rule.add secret:GH_TOKEN") {
		t.Fatalf("audit %v", lines)
	}
	if shown := e.secretList(t)["GH_TOKEN"].Policy; shown == nil || !shown.Staged || len(shown.Rules) != 2 || shown.Rules[0].Policy.Gate != "dialog" {
		t.Fatalf("shown after the edit: %+v", shown)
	}
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	if e.logins() != logins+1 || len(e.d.stager.Active().Secrets["GH_TOKEN"].Rules) != 2 {
		t.Fatal("config apply must show one prompt and apply the rule")
	}
	res, p = e.edit(t, map[string]string{"op": control.EditRuleRemove, "secret": "GH_TOKEN", "index": "1"})
	if p != nil || !res.Applied || res.Staged != nil || e.logins() != logins+1 {
		t.Fatalf("remove: %+v %+v", res, p)
	}
	if rs := e.d.stager.Active().Secrets["GH_TOKEN"].Rules; len(rs) != 1 || rs[0].Policy.Gate != "login" {
		t.Fatalf("not in force: %+v", rs)
	}
}

func TestSecretRuleEditRefusals(t *testing.T) {
	e := startSecretEdit(t)
	before := e.readConfig(t)
	cases := []struct {
		name string
		args map[string]string
		code int
		msg  string
	}{
		{"key and secret", map[string]string{"op": control.EditRuleRemove, "key": "GH_TOKEN", "secret": "GH_TOKEN", "index": "1"}, control.ExitUsage, "not both"},
		{"neither", map[string]string{"op": control.EditRuleRemove, "index": "1"}, control.ExitUsage, "not both or neither"},
		{"bad name", map[string]string{"op": control.EditRuleRemove, "secret": "../x", "index": "1"}, control.ExitUsage, "invalid secret name"},
		{"own gate", map[string]string{"op": control.EditKeySet, "secret": "GH_TOKEN", "gate": "login"}, control.ExitUsage, "SSH keys"},
		{"none with stdout", map[string]string{"op": control.EditRuleAdd, "secret": "GH_TOKEN", "apps": refs("iterm"), "gate": "none"}, control.ExitError, "would be invalid"},
		{"no such rule", map[string]string{"op": control.EditRuleRemove, "secret": "GH_TOKEN", "index": "9"}, control.ExitError, "secrets.GH_TOKEN"},
		{"stale hash", map[string]string{"op": control.EditRuleRemove, "secret": "GH_TOKEN", "index": "1", "ifHash": "0000"}, control.ExitError, "nazar secret list"},
	}
	for _, c := range cases {
		_, p := e.edit(t, c.args)
		if p.ExitCode() != c.code || !strings.Contains(p.Message, c.msg) {
			t.Errorf("%s: %+v, want exit %d with %q", c.name, p, c.code, c.msg)
		}
		if e.readConfig(t) != before {
			t.Fatalf("%s changed config.yaml", c.name)
		}
	}
	_, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "secret": "GH_TOKEN", "apps": refs("iterm"), "gate": "none"})
	if !strings.Contains(strings.Join(p.Details, "\n"), "gate: none") {
		t.Fatalf("the parse error must be in the details: %+v", p)
	}
}

// Added from Nazar UI.app (an app with no session between it and the
// CLI), the secret is blocked for everyone, and the prompt names the
// command that adds a rule.
func TestSecretAddFromNazarUIWritesNoRule(t *testing.T) {
	e := startSecrets(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	uiCode := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.ui", CDHash: []byte{0xd1}}
	ui := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Nazar UI.app/Contents/MacOS/NazarUI", Code: uiCode, App: &fake.App{BundleID: "dev.nazar.ui", Name: "Nazar UI"}})
	e.f.SetDefaultPeer(e.f.Launch(ui, cliProc("--json", "secret", "add", "X")))
	s, p := e.addSecret(t, "X", testValue)
	if p != nil || len(s.Rules) != 1 || s.Rules[0] != "fallback: gate=block" || s.Policy == nil || len(s.Policy.Rules) != 0 || s.Policy.FallbackSource != "secret-gate" {
		t.Fatalf("%+v %v", s, p)
	}
	if lines := strings.Join(e.f.Shown()[0].Prompt.Lines, "\n"); !strings.Contains(lines, "no rule yet: every caller is blocked until one is added (nazar secret rule add X …)") {
		t.Fatalf("prompt %q", lines)
	}
	if cfg := e.readConfig(t); strings.Contains(cfg, "dev.nazar.ui") || strings.Contains(cfg, "rules:") {
		t.Fatalf("no rule for the UI or anyone:\n%s", cfg)
	}
}
