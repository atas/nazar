package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

type env struct {
	home  string
	f     *fake.Fake
	vault *fake.Vault
	sink  *audit.MemorySink
	d     *Daemon
	c     *control.Client
	o     Options // what the running daemon was built with (relaunch)
	halt  func()  // stops the running daemon, keeps home
	stop  func()

	reap []chan error // killed daemons (relaunch), reaped at stop
}

// launch builds a daemon from e.o and runs it until e.halt is called.
func (e *env) launch(t *testing.T) {
	t.Helper()
	d, err := New(e.o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	e.d = d
	e.halt = func() {
		cancel()
		<-done
	}
	// Dial, not stat: bind makes the file before listen accepts.
	waitFor(t, func() bool {
		c, err := net.Dial("unix", e.c.Socket)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
}

// relaunch is what a same-user process gets by killing Nazar.app (SIGKILL,
// same uid) and letting launchd or `open -a Nazar` start it again: a new
// daemon on the same home, vault, platform and audit log, with nothing of
// the old process's memory. The old daemon is not waited for, as a killed
// process does not finish what it was doing (a prompt on screen stays
// unanswered); it is reaped at cleanup, once the test released that
// prompt.
func (e *env) relaunch(t *testing.T) {
	t.Helper()
	old, done := e.halt, make(chan error, 1)
	e.reap = append(e.reap, done)
	go func() { old(); close(done) }()
	// The old listener is closed on cancel (its socket file goes with it),
	// before Run waits for its handlers, so the new daemon can bind the
	// same path.
	waitFor(t, func() bool { _, err := os.Stat(e.c.Socket); return err != nil })
	e.launch(t)
}

func start(t *testing.T) *env {
	t.Helper()
	return startWith(t, nil)
}

// startWith is start with a hook that can change the daemon's Options
// before New (for example its clock, set to the fake's own with
// o.Now = f.Now, or the gate timeout).
func startWith(t *testing.T, mod func(f *fake.Fake, o *Options)) *env {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "nzd")
	if err != nil {
		t.Fatal(err)
	}
	f := fake.New(time.Now())
	f.CodeHashFunc = func(p string) ([]byte, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		s := sha256.Sum256(b)
		return s[:20], nil
	}
	// app: team pins come from the INSTALLED app when a config change is
	// approved (spec 4.2), so iTerm2 is installed, as on a typical Mac.
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", fake.ITermCode)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	f.SetDefaultPeer(tab.Peer())
	sink := &audit.MemorySink{}
	vault := fake.NewVault()
	o := Options{Platform: f, Vault: vault, AuditSink: sink, Home: home,
		PollInterval: 20 * time.Millisecond, GateTimeout: func() time.Duration { return 2 * time.Second }}
	if mod != nil {
		mod(f, &o)
	}
	e := &env{home: home, f: f, vault: vault, sink: sink, o: o, c: &control.Client{Socket: layout.ControlSocket(home), Verifier: control.SameUserVerifier{}}}
	e.stop = func() {
		if e.halt != nil {
			e.halt()
		}
		for _, r := range e.reap {
			<-r
		}
		os.RemoveAll(home)
	}
	t.Cleanup(e.stop)
	e.launch(t)
	return e
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *env) call(t *testing.T, cmd string, args map[string]string, kind string, out any) error {
	t.Helper()
	return e.c.Call(context.Background(), control.NewRequest(cmd, args), kind, out)
}

func (e *env) writeConfig(t *testing.T, body string) {
	t.Helper()
	p := layout.ConfigFile(e.home)
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *env) readConfig(t *testing.T) string {
	b, _ := os.ReadFile(layout.ConfigFile(e.home))
	return string(b)
}

// `ssh-key create <name>` takes no gate or scope. From a terminal
// tab the entry it writes is the key's own gate block plus one rule for
// the tab's app (app:<bundle id>, login, scope session, expire 8h), the
// app's team is pinned by the same approval, the prompt shows the change
// as config apply would, and the key gets no chip-level user presence (a
// session rule remembers approvals). The tool that ran the command (here
// Claude Code) never gets a rule of its own.
func TestCreateKeyWritesTheTerminalRule(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned})
	e.f.SetDefaultPeer(tab.Peer())
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if k.Name != "github" || !k.Configured || k.UserPresence || k.APIVersion != "nazar/v1" {
		t.Fatalf("%+v", k)
	}
	wantRule := `1: apps=[app:"com.googlecode.iterm2":""] to=[] gate=login scope=session expire=8h0m0s`
	if len(k.Rules) != 2 || k.Rules[0] != wantRule || k.Rules[1] != "fallback: gate=block" {
		t.Fatalf("rules %q, want [%q, fallback: gate=block]", k.Rules, wantRule)
	}
	cfg := e.readConfig(t)
	for _, want := range []string{"github:", "gate: block", "app: com.googlecode.iterm2", "scope: session", "gate: login", "expire: 8h"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config.yaml lacks %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "claude") || strings.Contains(cfg, "Q6L2SF6YDW") {
		t.Fatalf("the tool that ran create must get no rule:\n%s", cfg)
	}
	if team, ok := e.d.trust.PinnedTeam("com.googlecode.iterm2"); !ok || team != "H7V7XYVQ7D" {
		t.Fatalf("the approval must pin the terminal's team, got %q %v", team, ok)
	}
	if _, err := os.Stat(filepath.Join(layout.KeysDir(e.home), "github.pub")); err != nil {
		t.Fatal(err)
	}
	shown := e.f.Shown()
	if len(shown) != 1 || shown[0].Kind != fake.KindAuthenticate {
		t.Fatalf("creating a key needs exactly one login prompt, got %+v", shown)
	}
	text := shown[0].Prompt.Title + "\n" + strings.Join(shown[0].Prompt.Lines, "\n")
	for _, want := range []string{`Create SSH key "github"?`, "ssh:github", "com.googlecode.iterm2", "H7V7XYVQ7D", "/Applications/iTerm.app", "user presence: off"} {
		if !strings.Contains(text, want) {
			t.Errorf("the prompt must show %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "enforced by the chip") || strings.Contains(text, "no rule yet") {
		t.Errorf("prompt: %s", text)
	}
	// The config is in force: nothing staged, and the tab may use the key.
	if _, staged := e.d.stager.Pending(); staged {
		t.Fatal("the created entry must be in force, not staged")
	}
	var r control.SSHKeyRules
	if err := e.call(t, control.CmdSSHKeyRules, map[string]string{"name": "github"}, control.KindSSHKeyRules, &r); err != nil || r.Staged || len(r.Rules) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
}

// No terminal, no rule: an unknown chain (a detached process, even one
// still responsible to iTerm2), an app that runs the CLI with no session
// between them (Nazar UI.app, with a team-signed or an ad-hoc CLI), and a
// terminal without a team to pin. The entry is gate block alone, the prompt
// says the key is blocked until a rule is added, and the key gets no user
// presence (nothing may use it yet, so nothing decides its protection).
func TestCreateKeyWithoutATerminalWritesNoRule(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc())
	uiCode := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.ui", CDHash: []byte{0xd1}}
	cliCode := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.cli", CDHash: []byte{0xd2}}
	adhocTerm := platform.CodeIdentity{Signed: true, SigningID: "org.example.term", CDHash: []byte{0xd3}} // no team
	cases := []struct {
		name string
		peer func() platform.ProcessRef
	}{
		{"detached", func() platform.ProcessRef {
			ref := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned})
			e.f.SetResponsible(ref, tab.App) // display only: never an identity
			return ref
		}},
		{"ui-team-cli", func() platform.ProcessRef {
			ui := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Nazar UI.app/Contents/MacOS/NazarUI", Code: uiCode, App: &fake.App{BundleID: "dev.nazar.ui", Name: "Nazar UI"}})
			return e.f.Launch(ui, fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Code: cliCode})
		}},
		{"ui-adhoc-cli", func() platform.ProcessRef {
			ui := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Nazar UI.app/Contents/MacOS/NazarUI", Code: uiCode, App: &fake.App{BundleID: "dev.nazar.ui", Name: "Nazar UI"}})
			return e.f.Launch(ui, fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Code: fake.Unsigned})
		}},
		{"adhoc-terminal", func() platform.ProcessRef {
			app := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Term.app/Contents/MacOS/Term", Code: adhocTerm, App: &fake.App{BundleID: "org.example.term", Name: "Term"}})
			sh := e.f.Launch(app, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
			return e.f.Launch(sh, fake.Proc{Path: "/Users/u/.local/bin/nazar", Code: fake.Unsigned})
		}},
	}
	for i, tc := range cases {
		e.f.SetDefaultPeer(tc.peer())
		name := fmt.Sprintf("k%d", i)
		var k control.SSHKey
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": name}, control.KindSSHKey, &k); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if k.UserPresence || !k.Configured || len(k.Rules) != 1 || k.Rules[0] != "fallback: gate=block" {
			t.Errorf("%s: %+v", tc.name, k)
		}
		shown := e.f.Shown()
		text := strings.Join(shown[len(shown)-1].Prompt.Lines, "\n")
		if !strings.Contains(text, "no rule yet") || !strings.Contains(text, "user presence: off") || strings.Contains(text, "app:") {
			t.Errorf("%s: prompt %q", tc.name, text)
		}
		if cfg := e.readConfig(t); strings.Contains(cfg, "rules:") || strings.Contains(cfg, "dev.nazar.ui") || strings.Contains(cfg, "org.example.term") {
			t.Errorf("%s: a rule was written:\n%s", tc.name, cfg)
		}
		e.f.Advance(10 * time.Second) // never inside a prompt's cooldown
	}
	if _, ok := e.d.trust.PinnedTeam("dev.nazar.ui"); ok {
		t.Fatal("nothing pinned Nazar UI")
	}
}

// The terminal's team is pinned from the INSTALLED app (spec 4.2). When Launch
// Services finds none (the app runs from a disk image), the rule is still
// written and approved, no pin is shown or recorded, and the matcher stays
// inactive and reported, with `nazar trust --app` as the fix, as any such
// matcher is (AppProblems).
func TestCreateKeyRuleWithoutAPinStaysInactive(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, _ *Options) { f.UninstallApp("/Applications/iTerm.app") })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if len(k.Rules) != 2 {
		t.Fatalf("the rule is written whether or not it can be pinned: %+v", k.Rules)
	}
	if _, ok := e.d.trust.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatal("nothing to pin from")
	}
	if text := strings.Join(e.f.Shown()[0].Prompt.Lines, "\n"); strings.Contains(text, "pinned") {
		t.Fatalf("no pin was shown: %s", text)
	}
	var chk control.ConfigCheck
	e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk)
	found := false
	for _, p := range chk.Problems {
		if strings.Contains(p.Message, "com.googlecode.iterm2") && strings.Contains(p.Message, "nazar trust --app") {
			found = true
		}
	}
	if !found {
		t.Fatalf("config check must report the unpinned terminal with its fix: %+v", chk.Problems)
	}
}

// Spec 4.5 as amended in Milestone 7: the protection of a key created under an
// entry the user wrote follows that entry, and only an entry every policy
// of which fits the chip, with at least one login + scope use, gets user
// presence. Checked at three levels: the create and pubkey replies, the
// registry record, and the fake enclave itself, which refuses to sign with
// a user-presence key without a live approval.
func TestCreateKeyProtectionFollowsItsEntry(t *testing.T) {
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
      scope: session
      gate: login
    blk:
      gate: block
    mix:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
    dlg:
      gate: dialog
`
	e.activate(t, body)
	for _, tc := range []struct {
		name         string
		userPresence bool
	}{
		{"hydra", true}, {"sess", false}, {"blk", false}, {"mix", true}, {"dlg", false},
	} {
		var created, shown control.SSHKey
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": tc.name}, control.KindSSHKey, &created); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if created.UserPresence != tc.userPresence {
			t.Errorf("%s: create reply UserPresence=%v, want %v", tc.name, created.UserPresence, tc.userPresence)
		}
		if err := e.call(t, control.CmdSSHKeyPubkey, map[string]string{"name": tc.name}, control.KindSSHKey, &shown); err != nil || shown.UserPresence != tc.userPresence {
			t.Errorf("%s: pubkey reply UserPresence=%v (%v), want %v", tc.name, shown.UserPresence, err, tc.userPresence)
		}
		info, err := e.d.keys.Get(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		wantAuth := platform.AuthNone
		if tc.userPresence {
			wantAuth = platform.AuthUserPresence
		}
		if info.Auth != wantAuth {
			t.Errorf("%s: registry auth %v, want %v", tc.name, info.Auth, wantAuth)
		}
		_, err = e.f.Sign(e.enclaveHandle(t, tc.name), []byte("digest"), platform.ApprovalRef(0))
		if tc.userPresence && !errors.Is(err, platform.ErrAuthRequired) {
			t.Errorf("%s: the enclave must refuse to sign without the user's authentication, got %v", tc.name, err)
		}
		if !tc.userPresence && err != nil {
			t.Errorf("%s: a key without user presence carries no enclave policy, got %v", tc.name, err)
		}
		// The prompt says which, and names the entry; the file is untouched.
		shownPrompts := e.f.Shown()
		text := strings.Join(shownPrompts[len(shownPrompts)-1].Prompt.Lines, "\n")
		if want := map[bool]string{true: "Touch ID on every use, enforced by the chip", false: "user presence: off"}[tc.userPresence]; !strings.Contains(text, want) || !strings.Contains(text, "ssh_agent.keys."+tc.name) {
			t.Errorf("%s: prompt %q", tc.name, text)
		}
		e.f.Advance(10 * time.Second)
	}
	if cfg := e.readConfig(t); cfg != body {
		t.Fatalf("create under an entry must not touch config.yaml:\n%s", cfg)
	}
}

// An old CLI or window that still sends scope or gate gets a usage error
// and no prompt: a choice nazar no longer takes must not look honoured.
func TestCreateRefusesScopeAndGateArgs(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	for _, args := range []map[string]string{{"name": "k", "gate": "dialog"}, {"name": "k", "scope": "session"}} {
		err := e.call(t, control.CmdSSHKeyCreate, args, control.KindSSHKey, &control.SSHKey{})
		if p := control.AsProblem(err); p.ExitCode() != control.ExitUsage || !strings.Contains(p.Message, "no --scope or --gate") {
			t.Fatalf("%v: %+v", args, p)
		}
	}
	if e.f.CountShown(fake.KindAuthenticate) != 0 || e.readConfig(t) != "" {
		t.Fatal("nothing may be asked or written")
	}
}

func TestCreateDeniedIsRefused(t *testing.T) {
	e := start(t)
	err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{})
	if p := control.AsProblem(err); p.ExitCode() != control.ExitRefused {
		t.Fatalf("%+v", p)
	}
	var list control.SSHKeyList
	e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list)
	if len(list.Items) != 0 || e.readConfig(t) != "" {
		t.Fatal("nothing may be created")
	}
}

// enclaveHandle reads the Secure Enclave handle of key name from the vault
// record the registry wrote, so a test can probe the fake enclave's own
// record of the key, not just what nazar reports about it.
func (e *env) enclaveHandle(t *testing.T, name string) []byte {
	t.Helper()
	b, err := e.vault.Get(keys.VaultPrefix + name)
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Handle []byte `json:"handle"`
	}
	if err := json.Unmarshal(b, &rec); err != nil || len(rec.Handle) == 0 {
		t.Fatalf("vault record for %q: %v %q", name, err, b)
	}
	return rec.Handle
}

const rules = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
`

func TestLooseningIsStagedUntilApproved(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.writeConfig(t, rules) // background prompt: default auth denies
	waitFor(t, func() bool { return e.f.CountShown(fake.KindAuthenticate) == 1 })
	waitFor(t, func() bool { return len(e.auditFor(t, "config")) == 1 })
	// After a denial, `config apply` is refused for a cooldown.
	e.f.Advance(configApplyCooldown + time.Second)
	var chk control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil {
		t.Fatal(err)
	}
	if !chk.Valid || chk.Staged == nil || !chk.Staged.Loosens {
		t.Fatalf("%+v", chk)
	}
	if len(e.d.stager.Active().SSHAgent.Keys) != 0 {
		t.Fatal("staged config must not be active")
	}
	e.f.ScriptAuth(fake.Answer{Allow: true})
	var diff control.ConfigDiff
	if err := e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &diff); err != nil {
		t.Fatal(err)
	}
	if !diff.Applied || len(e.d.stager.Active().SSHAgent.Keys) != 1 {
		t.Fatalf("%+v", diff)
	}
	// Approving the change records the pin it showed: the team of the
	// installed iTerm2 (spec 4.2 "pinned on first load").
	var pinned control.Status
	e.call(t, control.CmdStatus, nil, control.KindStatus, &pinned)
	if pinned.Pins["com.googlecode.iterm2"] != fake.ITermCode.Team() {
		t.Fatalf("approved change must pin the installed app's team: %+v", pinned.Pins)
	}
	if !promptMentions(e.f, fake.KindAuthenticate, fake.ITermCode.Team()) {
		t.Fatal("the config approval prompt must show the team it pins")
	}
	chk = control.ConfigCheck{}
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil || chk.Staged != nil {
		t.Fatalf("%+v %v", chk, err)
	}
	// Tightening applies at once, without a prompt.
	shown := len(e.f.Shown())
	e.writeConfig(t, strings.Replace(rules, "gate: dialog", "gate: login", 1))
	waitFor(t, func() bool {
		k := e.d.stager.Active().SSHAgent.Keys["github"]
		return k != nil && k.Rules[0].Policy.Gate == "login"
	})
	if len(e.f.Shown()) != shown {
		t.Fatal("tightening must not prompt")
	}
}

func TestInvalidConfigKeepsLastApproved(t *testing.T) {
	e := start(t)
	e.writeConfig(t, "apiVersion: nazar/v2\nkind: Config\n")
	var chk control.ConfigCheck
	e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk)
	if chk.Valid || len(chk.Problems) == 0 {
		t.Fatalf("%+v", chk)
	}
	var st control.Status
	e.call(t, control.CmdStatus, nil, control.KindStatus, &st)
	if len(st.Problems) == 0 {
		t.Fatal("status must show why the file was not applied")
	}
}

func sshsig() []byte {
	b := []byte("SSHSIG")
	for _, s := range [][]byte{[]byte("git"), nil, []byte("sha512"), bytes.Repeat([]byte{1}, 64)} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	return b
}

func TestAgentSignsThroughDaemonAndRevoke(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{})
	// `ssh-key create` wrote gate block plus the tab's login rule; this test
	// signs through a dialog rule instead.
	e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      gate: dialog\n      rules:\n        - apps: [{app: com.googlecode.iterm2}]\n          scope: session\n          gate: dialog\n")
	e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &control.ConfigDiff{})
	waitFor(t, func() bool { k := e.d.stager.Active().SSHAgent.Keys["github"]; return k != nil && len(k.Rules) == 1 })

	conn, err := net.Dial("unix", e.d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ag := agent.NewClient(conn)
	ks, err := ag.List()
	if err != nil || len(ks) != 1 {
		t.Fatalf("%v %v", ks, err)
	}
	pub, _ := ssh.ParsePublicKey(ks[0].Blob)
	sig, err := ag.Sign(pub, sshsig())
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(sshsig(), sig); err != nil {
		t.Fatal(err)
	}
	var st control.Status
	e.call(t, control.CmdStatus, nil, control.KindStatus, &st)
	if len(st.Approvals) != 1 || st.Approvals[0].Target != "ssh:github" || st.Approvals[0].Op != "sign:git" || st.Approvals[0].Covers != "git commits and tags" {
		t.Fatalf("%+v", st.Approvals)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan control.Approval, 4)
	go e.c.Do(ctx, control.Request{TypeMeta: control.Meta(control.KindRequest), Command: control.CmdStatus, Follow: true}, func(kind string, raw json.RawMessage) error {
		if kind == control.KindApproval {
			var a control.Approval
			json.Unmarshal(raw, &a)
			events <- a
		}
		return nil
	})
	time.Sleep(100 * time.Millisecond)
	var rr control.RevokeResult
	if err := e.call(t, control.CmdRevoke, map[string]string{"all": "true"}, control.KindRevokeResult, &rr); err != nil || rr.Revoked != 1 {
		t.Fatalf("%+v %v", rr, err)
	}
	select {
	case a := <-events:
		if a.Event != "removed" || a.Reason != "revoked" {
			t.Fatalf("%+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("status --follow did not stream the revoke")
	}
	if p := control.AsProblem(e.call(t, control.CmdRevoke, map[string]string{"all": "1", "key": "x"}, control.KindRevokeResult, &rr)); p.ExitCode() != control.ExitUsage {
		t.Fatalf("%+v", p)
	}
	found := false
	for _, l := range e.sink.Lines() {
		if strings.Contains(l, "decision=approved") && strings.Contains(l, "operation=\"sign git commit\"") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit line for the signature:\n%s", strings.Join(e.sink.Lines(), "\n"))
	}
}

func TestCreateRefusedWhileStaged(t *testing.T) {
	e := start(t)
	e.writeConfig(t, rules)
	waitFor(t, func() bool { _, ok := e.d.stager.Pending(); return ok })
	// The poller's own background prompt for the staged file (denied: the
	// default answer) is the one prompt there may be.
	waitFor(t, func() bool { return e.f.CountShown(fake.KindAuthenticate) == 1 })
	err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{})
	if p := control.AsProblem(err); p.ExitCode() != control.ExitStaged || !strings.Contains(p.Message, "nazar config check") {
		t.Fatalf("%+v", p)
	}
	// A staged entry for the very key: the message names the two commands
	// that get there (config apply, then create again), and nothing is
	// asked (the create prompt never approves a staged config).
	err = e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{})
	if p := control.AsProblem(err); p.ExitCode() != control.ExitStaged || !strings.Contains(p.Message, "nazar config apply") || !strings.Contains(p.Message, "nazar ssh-key create github") {
		t.Fatalf("%+v", p)
	}
	if e.f.CountShown(fake.KindAuthenticate) != 1 {
		t.Fatal("create must not ask while a change is staged")
	}
}

func TestDeleteNeedsLogin(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{})
	e.f.ScriptAuth(fake.Answer{Allow: false})
	if p := control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{})); p.ExitCode() != control.ExitRefused {
		t.Fatalf("%+v", p)
	}
	e.f.Advance(configApplyCooldown) // a denial cools every login prompt down
	if err := e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	var list control.SSHKeyList
	e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list)
	if len(list.Items) != 0 {
		t.Fatal("key not deleted")
	}
}

func TestAgentSocketMovesAfterApproval(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	newSock := filepath.Join(e.home, ".nazar2", "a.sock")
	e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  socket: "+newSock+"\n")
	waitFor(t, func() bool { return e.d.AgentSocket() == newSock })
	if _, err := os.Stat(newSock); err != nil {
		t.Fatal(err)
	}
}

func TestCreateKeepsSymlinkedConfig(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	dotfiles := filepath.Join(e.home, "dotfiles")
	os.MkdirAll(dotfiles, 0o700)
	real := filepath.Join(dotfiles, "nazar.yaml")
	os.WriteFile(real, []byte("apiVersion: nazar/v1\nkind: Config\n"), 0o600)
	link := layout.ConfigFile(e.home)
	os.MkdirAll(filepath.Dir(link), 0o700)
	os.Symlink(real, link)
	waitFor(t, func() bool { return e.d.stager.Active().Raw != nil })
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("config.yaml symlink was replaced by a regular file")
	}
	if b, _ := os.ReadFile(real); !strings.Contains(string(b), "k:") {
		t.Fatalf("symlink target not updated:\n%s", b)
	}
}
