package daemon

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// alwaysAskLine is the create prompt's last line for a key the chip
// guards on every use.
const alwaysAskLine = "Touch ID on every use, enforced by the chip: this key can never get a session, dialog or no-prompt rule"

// presenceRefusal is what nazar's own edits say when they would give an
// always-ask key a policy the chip can't serve.
const presenceRefusal = "asks on every use (enforced by the chip); create another key for a looser rule"

// checkChipPresence asserts that key name was created with Secure Enclave
// user presence at every level nazar can see: the registry record, the
// fake enclave itself (it refuses to sign without a live approval), and
// the config in force: every policy that can reach the key fits the chip
// (PresenceFits; an always-ask key only block reaches is one nobody may use
// yet).
func (e *env) checkChipPresence(t *testing.T, name string) {
	t.Helper()
	info, err := e.d.keys.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	if info.Auth != platform.AuthUserPresence {
		t.Errorf("%s: registry auth %v, want user presence", name, info.Auth)
	}
	if _, err := e.f.Sign(e.enclaveHandle(t, name), []byte("digest"), platform.ApprovalRef(0)); !errors.Is(err, platform.ErrAuthRequired) {
		t.Errorf("%s: the enclave must refuse to sign without the user's authentication, got %v", name, err)
	}
	if !e.d.stager.Active().PresenceFits(name) {
		t.Errorf("%s: a policy the chip can't serve reaches the key", name)
	}
}

// `ssh-key create <name> --always-ask` from a terminal tab: one step, one
// prompt. The entry is the key's own gate block plus one rule for the
// tab's app with gate login and scope use (no expiry), so every policy
// that can reach the key fits the chip and the key is created with user
// presence. The prompt's last line says so in plain words; the reply and
// `ssh-key list --json` say userPresence.
func TestCreateAlwaysAskWritesALoginUseRule(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned})
	e.f.SetDefaultPeer(tab.Peer())
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "prod", "alwaysAsk": "true"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if !k.UserPresence || !k.Configured {
		t.Fatalf("%+v", k)
	}
	wantRule := `1: apps=[app:"com.googlecode.iterm2":""] to=[] gate=login scope=use`
	if len(k.Rules) != 2 || k.Rules[0] != wantRule || k.Rules[1] != "fallback: gate=block" {
		t.Fatalf("rules %q, want [%q, fallback: gate=block]", k.Rules, wantRule)
	}
	cfg := e.readConfig(t)
	for _, bad := range []string{"session", "expire", "dialog", "none", "claude", "Q6L2SF6YDW"} {
		if strings.Contains(cfg, bad) {
			t.Errorf("config.yaml has %q:\n%s", bad, cfg)
		}
	}
	ck := e.d.stager.Active().SSHAgent.Keys["prod"]
	if ck == nil || ck.Own == nil || ck.Own.Gate != config.GateBlock || len(ck.Rules) != 1 ||
		ck.Rules[0].Policy != (config.Policy{Gate: config.GateLogin, Scope: config.ScopeUse}) {
		t.Fatalf("entry in force: %+v", ck)
	}
	e.checkChipPresence(t, "prod")
	shown := e.f.Shown()
	if len(shown) != 1 || shown[0].Kind != fake.KindAuthenticate {
		t.Fatalf("one login prompt, got %+v", shown)
	}
	lines := shown[0].Prompt.Lines
	if last := lines[len(lines)-1]; last != alwaysAskLine {
		t.Errorf("the prompt's last line is %q, want %q", last, alwaysAskLine)
	}
	if text := strings.Join(lines, "\n"); !strings.Contains(text, "com.googlecode.iterm2") || strings.Contains(text, "user presence: off") {
		t.Errorf("prompt: %s", text)
	}
	var l control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l); err != nil || len(l.Items) != 1 || !l.Items[0].UserPresence {
		t.Fatalf("list: %+v %v", l, err)
	}
}

// Without --always-ask nothing changes: the terminal rule is the session
// rule (defaultRule), the key has no user presence.
func TestCreateWithoutAlwaysAskIsUnchanged(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if k.UserPresence || len(k.Rules) != 2 || !strings.Contains(k.Rules[0], "scope=session expire=8h0m0s") {
		t.Fatalf("%+v", k)
	}
	if _, err := e.f.Sign(e.enclaveHandle(t, "github"), []byte("digest"), platform.ApprovalRef(0)); err != nil {
		t.Fatalf("a key without user presence carries no enclave policy, got %v", err)
	}
	lines := e.f.Shown()[0].Prompt.Lines
	if last := lines[len(lines)-1]; !strings.Contains(last, "user presence: off") {
		t.Fatalf("last line %q", last)
	}
}

// No terminal to give a rule to (Nazar UI.app, an unknown chain, a terminal
// without a team): --always-ask still makes a chip-guarded key, and the
// flag never widens who may ask for it (security review): the entry is the
// key's own gate block and no rule, exactly what create writes without the
// flag, so nobody may use the key until a rule is added, and only a rule
// the chip can serve (login with scope use) can be.
func TestCreateAlwaysAskWithoutATerminal(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc())
	uiCode := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.ui", CDHash: []byte{0xd1}}
	cliCode := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.cli", CDHash: []byte{0xd2}}
	cases := []struct {
		name string
		peer func() platform.ProcessRef
	}{
		{"ui", func() platform.ProcessRef {
			ui := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Nazar UI.app/Contents/MacOS/NazarUI", Code: uiCode, App: &fake.App{BundleID: "dev.nazar.ui", Name: "Nazar UI"}})
			return e.f.Launch(ui, fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Code: cliCode})
		}},
		{"detached", func() platform.ProcessRef {
			ref := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned})
			e.f.SetResponsible(ref, tab.App)
			return ref
		}},
	}
	for i, tc := range cases {
		e.f.SetDefaultPeer(tc.peer())
		name := fmt.Sprintf("k%d", i)
		var k control.SSHKey
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": name, "alwaysAsk": "true"}, control.KindSSHKey, &k); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !k.UserPresence || len(k.Rules) != 1 || k.Rules[0] != "fallback: gate=block" {
			t.Errorf("%s: %+v", tc.name, k)
		}
		ck := e.d.stager.Active().SSHAgent.Keys[name]
		if ck == nil || len(ck.Rules) != 0 || ck.Own == nil || *ck.Own != (config.Policy{Gate: config.GateBlock, Scope: config.ScopeUse}) {
			t.Errorf("%s: entry %+v", tc.name, ck)
		}
		e.checkChipPresence(t, name)
		shown := e.f.Shown()
		lines := shown[len(shown)-1].Prompt.Lines
		if last := lines[len(lines)-1]; last != alwaysAskLine {
			t.Errorf("%s: last line %q", tc.name, last)
		}
		if text := strings.Join(lines, "\n"); !strings.Contains(text, "no rule yet") || strings.Contains(text, "app:") {
			t.Errorf("%s: prompt %q", tc.name, text)
		}
		e.f.Advance(10 * time.Second)
	}
	// The only rule that can be added is one the chip serves.
	e.f.Advance(2 * time.Minute)
	if _, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "k0", "apps": refs("any"), "gate": "login", "scope": "session"}); p == nil || !strings.Contains(p.Message, presenceRefusal) {
		t.Fatalf("a session rule on k0: want the refusal, got %+v", p)
	}
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "k0", "apps": refs("app:com.googlecode.iterm2"), "gate": "login", "scope": "use"}); p != nil || r.Staged == nil {
		t.Fatalf("a login/use rule on k0: want it staged, got %+v %+v", r, p)
	}
}

// For a name config.yaml already has an entry for, --always-ask never
// rewrites the entry: it is refused (usage, no prompt, nothing written or
// created) unless every policy of the entry is one the chip can serve
// (login with scope use, or block), and then the key is created under that
// entry with user presence.
func TestCreateAlwaysAskUnderAnExistingEntry(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	const body = `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    hydra:
      scope: use
      gate: login
    sess:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
    blk:
      gate: block
    dlg:
      gate: dialog
`
	e.activate(t, body)
	asked := e.f.CountShown(fake.KindAuthenticate) // the approval of body
	for _, name := range []string{"sess", "dlg"} {
		err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": name, "alwaysAsk": "true"}, control.KindSSHKey, &control.SSHKey{})
		p := control.AsProblem(err)
		if p.ExitCode() != control.ExitUsage || !strings.Contains(p.Message, "already has an entry for") || !strings.Contains(p.Message, name) {
			t.Errorf("%s: %+v", name, p)
		}
		if _, err := e.d.keys.Get(name); err == nil {
			t.Errorf("%s: a key was created", name)
		}
	}
	if n := e.f.CountShown(fake.KindAuthenticate) - asked; n != 0 {
		t.Fatalf("a refused create asked %d times", n)
	}
	for _, name := range []string{"hydra", "blk"} {
		var k control.SSHKey
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": name, "alwaysAsk": "true"}, control.KindSSHKey, &k); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !k.UserPresence {
			t.Fatalf("%s: %+v", name, k)
		}
		e.checkChipPresence(t, name)
		e.f.Advance(10 * time.Second)
	}
	// Without the flag the block-only entry still gets no presence.
	if err := e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "blk"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	e.f.Advance(10 * time.Second)
	var plain control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "blk"}, control.KindSSHKey, &plain); err != nil || plain.UserPresence {
		t.Fatalf("blk without the flag: %+v %v", plain, err)
	}
	if cfg := e.readConfig(t); cfg != body {
		t.Fatalf("config.yaml was rewritten:\n%s", cfg)
	}
}

// The request argument is checked, not trusted: only "true" means
// always-ask; anything else is a usage error before any prompt.
func TestCreateAlwaysAskTakesOnlyTrue(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	for _, v := range []string{"false", "1", "yes", "TRUE", " true"} {
		err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k", "alwaysAsk": v}, control.KindSSHKey, &control.SSHKey{})
		if p := control.AsProblem(err); p.ExitCode() != control.ExitUsage {
			t.Errorf("%q: %+v", v, p)
		}
	}
	if e.f.CountShown(fake.KindAuthenticate) != 0 || e.readConfig(t) != "" {
		t.Fatal("nothing may be asked or written")
	}
}

// After --always-ask, nazar's own edits that would let anything reach the
// key by dialog, none, or a remembered login (scope session or app) are
// refused with one plain sentence; nothing is written. A fitting rule
// (login, scope use) for another app is still possible (staged, as any
// loosening), and tightening applies at once.
func TestAlwaysAskKeyRefusesLooserEdits(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "prod", "alwaysAsk": "true"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	e.f.Advance(2 * time.Minute)
	before := e.readConfig(t)
	for _, args := range []map[string]string{
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "dialog"},
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "none"},
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "login", "scope": "session"},
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "login", "scope": "app"},
		{"op": control.EditRuleSet, "key": "prod", "index": "1", "gate": "dialog"},
		{"op": control.EditRuleSet, "key": "prod", "index": "1", "gate": "none"},
		{"op": control.EditRuleSet, "key": "prod", "index": "1", "scope": "session"},
		{"op": control.EditRuleSet, "key": "prod", "index": "1", "scope": "app"},
		{"op": control.EditKeySet, "key": "prod", "gate": "dialog"},
		{"op": control.EditKeySet, "key": "prod", "gate": "login", "scope": "session"},
		{"op": control.EditKeySet, "key": "prod", "gate": "login", "scope": "app"},
	} {
		_, p := e.edit(t, args)
		if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, `SSH key "prod" `+presenceRefusal) {
			t.Errorf("%v: want the refusal, got %+v", args, p)
		}
		if e.readConfig(t) != before {
			t.Fatalf("%v: config.yaml was written", args)
		}
	}
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "prod", "apps": refs("signed:Q6L2SF6YDW:com.anthropic.claude-code"), "gate": "login", "scope": "use"}); p != nil || r.Staged == nil {
		t.Fatalf("a fitting login rule: want it staged, got %+v %+v", r, p)
	}
	e.f.Advance(2 * time.Minute)
	var d control.ConfigDiff
	if err := e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &d); err != nil || !d.Applied {
		t.Fatalf("apply: %+v %v", d, err)
	}
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleRemove, "key": "prod", "index": "2"}); p != nil || !r.Applied {
		t.Fatalf("a tightening applies at once: %+v %+v", r, p)
	}
	e.checkChipPresence(t, "prod")
}

// Security review: a rule the chip can't serve,
// added behind an earlier rule that shadows it, is no loosening when it is
// added, and removing the shadowing rule later adds no unfit policy, so the
// refusal must not depend on the edit loosening access. Every edit that
// adds such a policy to a user-presence key is refused, shadowed or not;
// nothing reaches config.yaml.
func TestAlwaysAskKeyRefusesAHiddenLooserRule(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "prod", "alwaysAsk": "true"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	e.f.Advance(2 * time.Minute)
	// A block rule for every app ahead of the rest: a tightening, in force at once.
	if r, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "block", "at": "1"}); p != nil || !r.Applied {
		t.Fatalf("block at 1: %+v %+v", r, p)
	}
	before := e.readConfig(t)
	for _, args := range []map[string]string{
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "login", "scope": "session"},
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "none"},
		{"op": control.EditRuleAdd, "key": "prod", "apps": refs("any"), "gate": "dialog"},
		{"op": control.EditRuleSet, "key": "prod", "index": "2", "scope": "session"}, // the terminal's rule, shadowed by rule 1
		{"op": control.EditKeySet, "key": "prod", "gate": "dialog"},
	} {
		if _, p := e.edit(t, args); p == nil || !strings.Contains(p.Message, presenceRefusal) {
			t.Errorf("%v behind a block rule: want the refusal, got %+v", args, p)
		}
		if e.readConfig(t) != before {
			t.Fatalf("%v: config.yaml was written", args)
		}
	}
}
