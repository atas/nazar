package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The Nazar window (macos/Sources/NazarUI, spec 6.1) runs this CLI and
// nothing else. Two contracts keep the two sides from drifting:
//
//   - TestUIFixtures: the JSON the window decodes comes from the real CLI
//     and core (fake platform), written to macos/Tests/NazarUITests/Fixtures;
//     NazarUITests decodes those files with the window's models. A change
//     to an object's fields changes a fixture, fails here until the fixtures
//     are regenerated (NAZAR_UPDATE_FIXTURES=1), and then fails the Swift
//     side if its models no longer fit.
//   - TestUIActionsAreRealCommands: every command line the window can run
//     (Fixtures/ui-actions.json, which NazarUITests pins to UIAction) is a
//     real command of this CLI: run against the real core it never ends in
//     a usage error, and prints only nazar/v1 objects.

const uiFixtures = "../../macos/Tests/NazarUITests/Fixtures"

// fixtureSecretValue is the value of the fixtures' secret: no fixture may
// carry it.
const fixtureSecretValue = "nazar-m11-fixture-value-5e2a"

var fixtureT0 = time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)

// uiWorld is the real daemon on the fake platform behind a harness.
type uiWorld struct {
	h *harness
	f *fake.Fake
	d *daemon.Daemon
	v *fake.Vault
	// tab is an iTerm2 tab whose ssh is the agent socket's default peer.
	tab fake.Chain
}

func newUIWorld(t *testing.T) *uiWorld {
	t.Helper()
	h := newHarness(t)
	f := fake.New(fixtureT0)
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", fake.ITermCode)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	f.SetDefaultPeer(tab.Peer())
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	v := fake.NewVault()
	// A key record that does not decode: listed as broken, unusable.
	v.Put(keys.VaultPrefix+"old", []byte("{written by a build that is gone"))
	d, err := daemon.New(daemon.Options{Platform: f, Vault: v, AuditSink: &audit.MemorySink{}, Home: h.home,
		// The poller never runs: only the commands below look at config.yaml,
		// so no background prompt races them and the output is reproducible.
		ControlSocket: h.env["NAZAR_CONTROL_SOCKET"], PollInterval: time.Hour, Now: f.Now,
		GateTimeout: func() time.Duration { return 2 * time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(h.env["NAZAR_CONTROL_SOCKET"]); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &uiWorld{h: h, f: f, d: d, v: v, tab: tab}
}

// cli runs one command line with --json and returns stdout and the exit code.
func (w *uiWorld) cli(t *testing.T, args ...string) (string, int) {
	t.Helper()
	code := w.h.run(append([]string{"--json"}, args...)...)
	return w.h.out.String(), code
}

func (w *uiWorld) mustCLI(t *testing.T, want int, args ...string) string {
	t.Helper()
	out, code := w.cli(t, args...)
	if code != want {
		t.Fatalf("%v: exit %d, want %d\nstdout %s\nstderr %s", args, code, want, out, w.h.errb)
	}
	jsonLines(t, out)
	return out
}

// sign asks the agent for one signature from the tab (an approval for a
// dialog/session rule, and the key's last use).
func (w *uiWorld) sign(t *testing.T) {
	t.Helper()
	conn, err := net.Dial("unix", w.d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ag := agent.NewClient(conn)
	ks, err := ag.List()
	if err != nil || len(ks) == 0 {
		t.Fatalf("%v %v", ks, err)
	}
	pub, _ := ssh.ParsePublicKey(ks[0].Blob)
	msg := []byte("SSHSIG")
	for _, s := range [][]byte{[]byte("git"), nil, []byte("sha512"), bytes.Repeat([]byte{1}, 64)} {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(s)))
		msg = append(msg, s...)
	}
	if _, err := ag.Sign(pub, msg); err != nil {
		t.Fatal(err)
	}
}

// uiConfig is the config the fixtures show: the github entry as the
// window's fixtures expect it (own gate dialog, two rules), replacing the
// entry `ssh-key create` wrote (gate block, the iTerm2 login rule).
const uiConfig = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  kubectl: {signed: {team: KUBETEAM01, id: kubectl}}
ssh_agent:
  keys:
    github:
      scope: session
      gate: dialog
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
        - apps: [kubectl]
          scope: use
          gate: login
`

// uiK8s is the k8s section the Kubernetes tab's fixtures show, appended to
// config.yaml: hydra (its CA made, one rule for iTerm2) and hydra.eks (no
// CA; the managed-cluster warning, whose path hydra prefixes). loose keeps a
// CA and no entry.
const uiK8s = `k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster: {server: "https://hydra.example:16443", ca_sha256: 3f8c0000000000000000000000000000000000000000000000000000000000e1, tls_server_name: hydra.internal}
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
          expire: 8h
    hydra.eks:
      credential: ca-cert
      identity: {user: dev}
      cluster: {server: "https://hydra.eks.amazonaws.com", ca_sha256: 3f8c0000000000000000000000000000000000000000000000000000000000e1}
      gate: block
`

// addK8s sets up hydra and loose with k8s ca create (one login prompt each,
// from the iTerm2 tab; their clusters in ~/.kube/config, kubectl on PATH),
// then replaces their entries with uiK8s in config.yaml, approved with
// config apply: loose keeps its CA and has no entry (an old ca create).
func (w *uiWorld) addK8s(t *testing.T) {
	t.Helper()
	cfg := layout.ConfigFile(w.h.home)
	cur, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(testPEM(t, "cluster CA", nil, true))
	kube := filepath.Join(w.h.home, ".kube", "config")
	_ = os.MkdirAll(filepath.Dir(kube), 0o700)
	if err := os.WriteFile(kube, []byte("apiVersion: v1\nkind: Config\nclusters:\n"+
		"- name: hydra\n  cluster: {server: \"https://hydra.example:16443\", certificate-authority-data: "+b64+"}\n"+
		"- name: loose\n  cluster: {server: \"https://loose.example\", certificate-authority-data: "+b64+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(w.h.home, "bin")
	_ = os.MkdirAll(bin, 0o700)
	if err := os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	real, _ := filepath.EvalSymlinks(filepath.Join(bin, "kubectl"))
	w.f.SetCodeHash(real, []byte{0x6b, 0x75, 0x62, 0x65})
	w.h.env["PATH"] = bin
	w.h.a.selfPath = func() (string, error) { return "/Users/u/.local/bin/nazar", nil }
	for n, server := range map[string]string{"hydra": "https://hydra.example:16443", "loose": "https://loose.example"} {
		w.f.Advance(2 * time.Minute) // never inside a prompt cooldown
		args := []string{"k8s", "ca", "create", n, server}
		if n == "loose" {
			args = append(args, "--only-when-unlocked") // one CA of each access
		}
		w.mustCLI(t, 0, args...)
	}
	if err := os.WriteFile(cfg, append(append(bytes.TrimRight(cur, "\n"), '\n'), uiK8s...), 0o600); err != nil {
		t.Fatal(err)
	}
	w.f.Advance(2 * time.Minute)
	w.mustCLI(t, 0, "config", "apply")
}

// fixtureSet produces every fixture the window's tests read, by running
// the real CLI against the real core, in the order a session would.
func fixtureSet(t *testing.T) map[string]string {
	t.Helper()
	w := newUIWorld(t)
	fx := map[string]string{}
	fx["ssh-key-create"] = w.mustCLI(t, 0, "ssh-key", "create", "github")
	cfg := layout.ConfigFile(w.h.home)
	if err := os.WriteFile(cfg, []byte(uiConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	fx["config-apply"] = w.mustCLI(t, 0, "config", "apply")
	fx["config-check"] = w.mustCLI(t, 0, "config", "check")
	w.sign(t)
	// A key the chip asks for on every use (userPresence), made from the
	// iTerm2 tab after the signature above, so github stays the key it used.
	w.f.Advance(2 * time.Minute)
	w.mustCLI(t, 0, "ssh-key", "create", "prod", "--always-ask")
	fx["ssh-key-list"] = w.mustCLI(t, 0, "ssh-key", "list")
	fx["ssh-key-rules"] = w.mustCLI(t, 0, "ssh-key", "rules", "github")
	fx["ssh-key-pubkey"] = w.mustCLI(t, 0, "ssh-key", "pubkey", "github")
	fx["status"] = w.mustCLI(t, 0, "status")
	// The client-side findings the CLI adds to the Status object
	// (here: nazar's key file on a host no agent is set for, and git with
	// nazar's key but no signing program), from a fake runner. The window
	// shows them in a banner.
	w.h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", "", "no", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\nuser.signingkey ~/.nazar/keys/github.pub\n",
	})
	fx["status-setup"] = w.mustCLI(t, 0, "status")
	w.h.a.output = nil
	fx["apps-list"] = w.mustCLI(t, 0, "apps", "list")
	// gate none for iTerm2 above its dialog rule: a loosening. The window
	// sends --allow-loosen-access, so the edit is staged and approved in
	// one run: the ConfigEdit, then the ConfigDiff (exit 0); denied, the
	// ConfigEdit, then the Problem (exit 3) and the change stays staged.
	add := []string{"ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none", "--at", "1", "--allow-loosen-access"}
	fx["revoke"] = w.mustCLI(t, 0, "revoke", "--all") // the tab's approval from sign, before a config change ends it
	fx["config-edit-approved"] = w.mustCLI(t, 0, add...)
	// Then the rule it added is removed: a tightening, in force at once.
	fx["config-edit-applied"] = w.mustCLI(t, 0, "ssh-key", "rule", "remove", "github", "1")
	w.f.ScriptAuth(fake.Answer{Allow: false})
	fx["config-edit-denied"] = w.mustCLI(t, control.ExitRefused, add...)
	// The denied change stays staged: `config apply` (the banner's
	// "Approve…", no hash) asks again, denied once more and then approved
	// past the cooldown; then the rule is removed again.
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: false})
	fx["config-apply-denied"] = w.mustCLI(t, control.ExitRefused, "config", "apply")
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: true})
	w.mustCLI(t, 0, "config", "apply")
	w.mustCLI(t, 0, "ssh-key", "rule", "remove", "github", "1")
	w.f.Advance(2 * time.Minute) // never inside a prompt cooldown
	fx["ssh-key-delete-denied"] = func() string {
		w.f.ScriptAuth(fake.Answer{Allow: false})
		return w.mustCLI(t, control.ExitRefused, "ssh-key", "delete", "github")
	}()
	// Inside the cooldown of that denied prompt, an edit with the flag is
	// written and staged but its prompt can't be shown: the ConfigEdit, then
	// the Problem (code staged, exit 4); `config apply` asks later.
	fx["config-edit-staged"] = w.mustCLI(t, control.ExitStaged, add...)
	w.f.Advance(2 * time.Minute)
	w.mustCLI(t, 0, "config", "apply")
	w.mustCLI(t, 0, "ssh-key", "rule", "remove", "github", "1")
	w.f.Advance(2 * time.Minute)
	// The Secrets tab's reads and a rule edit, from the real core.
	// The secret is added from the iTerm2 tab (its login rule), its rule
	// list read, a rule added (a loosening: staged), approved, and the tab's
	// rule removed (a tightening: in force at once).
	w.f.Advance(2 * time.Minute) // out of the denied prompt's cooldown
	w.h.pipeIn(fixtureSecretValue + "\n")
	fx["secret-add"] = w.mustCLI(t, 0, "secret", "add", "GH_TOKEN")
	// NOTES added from Nazar UI.app (no terminal between it and the
	// CLI): blocked, with no rule; the tab opens its rule sheet.
	ui := w.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Nazar UI.app/Contents/MacOS/NazarUI",
		Code: platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.ui", CDHash: []byte{0xd1}},
		App:  &fake.App{BundleID: "dev.nazar.ui", Name: "Nazar UI"}})
	w.f.SetDefaultPeer(w.f.Launch(ui, fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar",
		Args: []string{"nazar", "--json", "secret", "add", "NOTES"}}))
	w.f.Advance(2 * time.Minute)
	w.h.pipeIn(fixtureSecretValue + "\n")
	fx["secret-add-window"] = w.mustCLI(t, 0, "secret", "add", "NOTES", "--only-when-unlocked") // the sheet's checkbox
	w.f.SetDefaultPeer(w.tab.Peer())
	fx["secret-list"] = w.mustCLI(t, 0, "secret", "list")
	// A rule for kubectl is a loosening: with the flag, staged and approved
	// in one run; then removed, a tightening in force at once.
	secretAdd := []string{"secret", "rule", "add", "GH_TOKEN", "--apps", "kubectl", "--gate", "login", "--scope", "use", "--allow-loosen-access"}
	fx["secret-rule-approved"] = w.mustCLI(t, 0, secretAdd...)
	fx["secret-rule-applied"] = w.mustCLI(t, 0, "secret", "rule", "remove", "GH_TOKEN", "1")
	// Denied (a rule for the tab's app, whose own rule was just removed), the
	// change stays staged, and an add while a change waits for approval is
	// refused before any prompt (exit 4 with nothing to approve: the window
	// runs no config apply).
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: false})
	w.mustCLI(t, control.ExitRefused, "secret", "rule", "add", "GH_TOKEN", "--apps", "app:com.googlecode.iterm2", "--gate", "login", "--scope", "session", "--allow-loosen-access")
	w.h.pipeIn(fixtureSecretValue + "\n")
	fx["secret-add-staged"] = w.mustCLI(t, control.ExitStaged, "secret", "add", "LATER")
	w.f.Advance(2 * time.Minute)
	w.mustCLI(t, 0, "config", "apply")
	w.mustCLI(t, 0, "secret", "rule", "remove", "GH_TOKEN", "2")
	// Delete and Add denied at the prompt, then a Delete approved.
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: false})
	fx["secret-rm-denied"] = w.mustCLI(t, control.ExitRefused, "secret", "rm", "GH_TOKEN")
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: false})
	w.h.pipeIn(fixtureSecretValue + "\n")
	fx["secret-add-denied"] = w.mustCLI(t, control.ExitRefused, "secret", "add", "LATER")
	w.f.Advance(2 * time.Minute)
	fx["secret-rm"] = w.mustCLI(t, 0, "secret", "rm", "NOTES")
	// The Kubernetes tab's reads, a rule edit and forget, from the
	// real core. A rule for Claude Code is a loosening (staged); forget is
	// refused while it waits (exit 4, nothing to approve: the window runs no
	// config apply); the rule is approved, then removed (a tightening, in
	// force at once); forget is denied once, then approved.
	w.addK8s(t)
	fx["k8s-list"] = w.mustCLI(t, 0, "k8s", "list")
	k8sAdd := []string{"k8s", "rule", "add", "hydra", "--apps", "signed:Q6L2SF6YDW:com.anthropic.claude-code", "--gate", "login", "--scope", "use", "--allow-loosen-access"}
	fx["k8s-rule-approved"] = w.mustCLI(t, 0, k8sAdd...)
	fx["k8s-rule-applied"] = w.mustCLI(t, 0, "k8s", "rule", "remove", "hydra", "2")
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: false})
	w.mustCLI(t, control.ExitRefused, k8sAdd...)
	fx["k8s-forget-staged"] = w.mustCLI(t, control.ExitStaged, "k8s", "forget", "hydra")
	w.f.Advance(2 * time.Minute)
	w.mustCLI(t, 0, "config", "apply")
	w.mustCLI(t, 0, "k8s", "rule", "remove", "hydra", "2")
	w.f.Advance(2 * time.Minute)
	w.f.ScriptAuth(fake.Answer{Allow: false})
	fx["k8s-forget-denied"] = w.mustCLI(t, control.ExitRefused, "k8s", "forget", "hydra")
	w.f.Advance(2 * time.Minute)
	fx["k8s-forget"] = w.mustCLI(t, 0, "k8s", "forget", "hydra")

	// The log: lines as the core's formatter writes them, from Nazar's
	// sender, as /usr/bin/log --style ndjson prints them.
	fmtr := audit.Formatter{Home: "/Users/u"}
	runLog := func(events ...audit.Event) func(context.Context, []string, func([]byte)) error {
		return func(_ context.Context, _ []string, line func([]byte)) error {
			for i, e := range events {
				b, _ := json.Marshal(map[string]string{"timestamp": "2026-10-11 00:0" + string(rune('0'+i)) + ":00.000000+0000",
					"eventMessage": fmtr.Format(e), "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID,
					"processImagePath": w.h.app.MainExe, "senderImagePath": w.h.app.MainExe})
				line(b)
			}
			return nil
		}
	}
	ev := audit.Event{Decision: audit.Approved, Reason: "approved", Target: "ssh:github", Destination: "github.com", Rule: "1",
		Scope: "session", Gate: "dialog", App: "com.googlecode.iterm2", Session: "4120@1791072000",
		Chain:    []audit.Proc{{Name: "bash", PID: 4120}, {Name: "claude-code (file deleted)", PID: 4188, Identity: "Q6L2SF6YDW:com.anthropic.claude-code"}, {Name: "ssh", PID: 4190}},
		Receiver: []string{"ssh", "git@github.com"}, Command: []string{"git", "push", "origin", "main"}, Cwd: "/Users/u/projects/foo"}
	blocked := audit.Event{Decision: audit.Blocked, Reason: "no rule matched", Target: "ssh:github", Rule: "fallback", Gate: "block",
		Chain: []audit.Proc{{Name: "python3", PID: 5000}}, Receiver: []string{"ssh", "git@github.com"}}
	w.h.a.runLog = runLog(ev, blocked)
	fx["log"] = w.mustCLI(t, 0, "log", "--since", "1h")
	// A secret's own lines, as its page reads them; the ssh line in
	// between is left out by the CLI's --target.
	viaGit := audit.Event{Decision: audit.Allowed, Reason: "cached approval", Target: "secret:GH_TOKEN", Delivery: "helper", Rule: "1",
		Scope: "session", Gate: "login", App: "com.googlecode.iterm2", Session: "4120@1791072000",
		Chain:    []audit.Proc{{Name: "bash", PID: 4120}, {Name: "git", PID: 4200}, {Name: "git-remote-https", PID: 4201}},
		Receiver: []string{"git-remote-https", "origin", "https://github.com/atas/nazar.git"}}
	script := audit.Event{Decision: audit.Blocked, Reason: "no rule matched", Target: "secret:GH_TOKEN", Delivery: "stdout", Rule: "fallback",
		Gate: "block", Chain: []audit.Proc{{Name: "python3", PID: 5000}}, Receiver: []string{"python3", "x.py"}}
	w.h.a.runLog = runLog(viaGit, ev, script)
	fx["secret-log"] = w.mustCLI(t, 0, "log", "--since", "24h", "--target", "secret:GH_TOKEN")
	// A context's own lines, as its page reads them: kubectl in the
	// iTerm2 tab approved, a program that is not a client blocked; the ssh
	// line in between is left out by the CLI's --target.
	viaKubectl := audit.Event{Decision: audit.Approved, Reason: "approved", Target: "k8s:hydra", Rule: "1",
		Scope: "session", Gate: "login", App: "com.googlecode.iterm2", Session: "4120@1791072000",
		Chain:    []audit.Proc{{Name: "bash", PID: 4120}, {Name: "kubectl", PID: 4300}, {Name: "nazar", PID: 4301}},
		Receiver: []string{"kubectl", "get", "pods"}}
	notClient := audit.Event{Decision: audit.Blocked, Reason: "the program that ran nazar can't be identified", Target: "k8s:hydra", Gate: "block",
		Chain: []audit.Proc{{Name: "python3", PID: 5000}, {Name: "nazar", PID: 5001}}}
	w.h.a.runLog = runLog(viaKubectl, ev, notClient)
	fx["k8s-log"] = w.mustCLI(t, 0, "log", "--since", "24h", "--target", "k8s:hydra")

	// The status stream: a Status, then approval changes, as the core
	// sends them (encoded by the real control types).
	s := newHarness(t)
	s.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		st := control.Status{TypeMeta: control.Meta(control.KindStatus), ActiveHash: "h", Approvals: []control.Approval{}}
		out.Emit(st)
		a := control.Approval{TypeMeta: control.Meta(control.KindApproval), Event: "added", Target: "ssh:github", Rule: "1:abcd1234",
			Scope: "session", ScopeID: "session:4120@1791072000", Op: "login:SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg", Covers: "github.com",
			Chain: "iTerm2 → bash → git → ssh", App: "com.googlecode.iterm2", Created: fixtureT0}
		out.Emit(a)
		a.Event, a.Reason = "removed", "session ended"
		out.Emit(a)
	})
	code := s.run("--json", "status", "--follow")
	if code != 0 {
		t.Fatalf("status --follow: %d %s", code, s.errb)
	}
	fx["status-follow"] = strings.ReplaceAll(s.out.String(), s.home, w.h.home)

	// Nazar.app not running.
	n := newHarness(t)
	if code := n.run("--json", "ssh-key", "list"); code != control.ExitUnavailable {
		t.Fatalf("unavailable: %d", code)
	}
	fx["unavailable"] = strings.ReplaceAll(n.out.String(), n.home, w.h.home)
	// No fixture carries a byte of a value.
	for name, out := range fx {
		if strings.Contains(out, fixtureSecretValue) || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(fixtureSecretValue))) {
			t.Fatalf("fixture %s carries the secret's value", name)
		}
		// Nor a certificate or a key (k8s list carries public facts only).
		if strings.Contains(out, "-----BEGIN") {
			t.Fatalf("fixture %s carries a PEM block", name)
		}
	}
	for name, out := range fx {
		fx[name] = normalizeFixture(t, out, w.h.home)
	}
	return fx
}

var timeKeys = map[string]bool{"time": true, "created": true, "expires": true, "trustedAt": true, "since": true, "notAfter": true}

var sessionRE = regexp.MustCompile(`[0-9]+@[0-9]+`)

// normalizeFixture makes CLI output reproducible: times, hashes, keys and
// the temporary home are replaced by fixed values; every object is written
// back as one line with sorted keys.
func normalizeFixture(t *testing.T, out, home string) string {
	t.Helper()
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		v = normalizeValue("", v, home)
		nb, _ := json.Marshal(v)
		b.Write(nb)
		b.WriteByte('\n')
	}
	return b.String()
}

func normalizeValue(key string, v any, home string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			x[k] = normalizeValue(k, val, home)
		}
		return x
	case []any:
		for i := range x {
			x[i] = normalizeValue(key, x[i], home)
		}
		return x
	case string:
		switch {
		case timeKeys[key]:
			return "2026-10-11T00:00:00Z"
		case key == "hash" || key == "configHash" || key == "activeHash":
			return "HASH"
		case key == "fingerprint":
			return "SHA256:FINGERPRINT"
		case key == "publicKey":
			return "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= github"
		case key == "cdhash":
			return "00"
		}
		return strings.ReplaceAll(x, home, "/Users/u")
	}
	return v
}

func TestUIFixtures(t *testing.T) {
	fx := fixtureSet(t)
	names := make([]string, 0, len(fx))
	for n := range fx {
		names = append(names, n)
	}
	sort.Strings(names)
	update := os.Getenv("NAZAR_UPDATE_FIXTURES") == "1"
	for _, n := range names {
		p := filepath.Join(uiFixtures, n+".jsonl")
		if update {
			if err := os.WriteFile(p, []byte(fx[n]), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != fx[n] {
			t.Errorf("%s is out of date (the CLI's JSON changed): run NAZAR_UPDATE_FIXTURES=1 go test ./cmd/nazar -run TestUIFixtures, then make swift-test\nwant:\n%s\nhave:\n%s", p, fx[n], got)
		}
	}
}

// placeholders are the values TestUIActionsAreRealCommands puts in the
// window's command templates (<hash> is read from the core first).
var placeholders = map[string]string{
	"<key>": "github", "<gate>": "dialog", "<scope>": "session", "<matcher>": "iterm", "<duration>": "8h",
	"<n>": "1", "<session>": "4120@1791072000", "<bundle-id>": "com.googlecode.iterm2", "<path>": "/bin/ls",
	"<secret>": "GH_TOKEN", "<target>": "secret:GH_TOKEN", "<context>": "hydra",
}

func TestUIActionsAreRealCommands(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(uiFixtures, "ui-actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var templates [][]string
	if err := json.Unmarshal(b, &templates); err != nil || len(templates) == 0 {
		t.Fatalf("ui-actions.json: %v", err)
	}
	w := newUIWorld(t)
	w.mustCLI(t, 0, "ssh-key", "create", "github")
	cfg := layout.ConfigFile(w.h.home)
	if err := os.WriteFile(cfg, []byte(uiConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	w.mustCLI(t, 0, "config", "apply")
	// The secret the Secrets tab's commands act on.
	w.h.pipeIn(fixtureSecretValue + "\n")
	w.mustCLI(t, 0, "secret", "add", "GH_TOKEN")
	// The contexts the Kubernetes tab's commands act on.
	w.addK8s(t)
	for _, tmpl := range templates {
		if len(tmpl) == 0 || tmpl[0] != "--json" {
			t.Fatalf("template %v: every window command runs with --json first", tmpl)
		}
		args := make([]string, 0, len(tmpl))
		follow := false
		for _, word := range tmpl[1:] {
			switch {
			case word == "--follow":
				follow = true
				args = append(args, word)
			case word == "<hash>" && args[0] == "k8s":
				args = append(args, k8sHash(t, w, "hydra"))
			case word == "<hash>" && args[0] == "secret":
				args = append(args, secretHash(t, w, "GH_TOKEN"))
			case word == "<secret>" && len(args) == 2 && args[0] == "secret" && args[1] == "add":
				// A new name, its value on stdin as the window writes it.
				name := "NEW_SECRET"
				if slices.Contains(tmpl, "--only-when-unlocked") {
					name = "NEW_SECRET_UNLOCKED"
				}
				args = append(args, name)
				w.h.pipeIn(fixtureSecretValue + "\n")
			case word == "<hash>":
				var r control.SSHKeyRules
				out, _ := w.cli(t, "ssh-key", "rules", "github")
				json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &r)
				args = append(args, r.ConfigHash)
			case word == "<key>" && len(args) == 2 && args[0] == "ssh-key" && args[1] == "create" && slices.Contains(tmpl, "--always-ask"):
				args = append(args, "prod") // a new key of its own: --always-ask never rewrites an entry
			case word == "<key>" && len(args) == 2 && args[0] == "ssh-key" && args[1] == "create" && slices.Contains(tmpl, "--only-when-unlocked"):
				args = append(args, "laptop")
			case word == "<key>" && len(args) == 2 && args[0] == "ssh-key" && args[1] == "create":
				args = append(args, "work") // a new key: github exists, with its config entry
			case strings.HasPrefix(word, "<"):
				v, ok := placeholders[word]
				if !ok {
					t.Fatalf("template %v: unknown placeholder %s", tmpl, word)
				}
				args = append(args, v)
			default:
				args = append(args, word)
			}
		}
		if follow {
			// A stream never ends on its own: run it against a stub that
			// answers once and hangs up; flags and output are what count.
			s := newHarness(t)
			s.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
			s.a.runLog = w.h.a.runLog
			if code := s.run(append([]string{"--json"}, args...)...); code == control.ExitUsage {
				t.Errorf("%v: usage error %s", tmpl, s.errb)
			}
			jsonLines(t, s.out.String())
			continue
		}
		w.f.Advance(2 * time.Minute) // never inside a prompt cooldown
		out, code := w.cli(t, args...)
		if code == control.ExitUsage || code == control.ExitUnavailable {
			t.Errorf("%v (as %v): exit %d\n%s%s", tmpl, args, code, out, w.h.errb)
			continue
		}
		jsonLines(t, out)
	}
}

// secretHash is the configHash of secret name's rules as `secret list`
// shows them, what the window passes to --if-hash.
func secretHash(t *testing.T, w *uiWorld, name string) string {
	t.Helper()
	var l control.SecretList
	out, _ := w.cli(t, "secret", "list")
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &l); err != nil {
		t.Fatalf("secret list: %v\n%s", err, out)
	}
	for _, s := range l.Items {
		if s.Name == name && s.Policy != nil {
			return s.Policy.ConfigHash
		}
	}
	t.Fatalf("no secret %s with rules in %s", name, out)
	return ""
}

// k8sHash is the configHash of context name's rules as `k8s list` shows
// them, what the window passes to --if-hash.
func k8sHash(t *testing.T, w *uiWorld, name string) string {
	t.Helper()
	var l control.K8sContextList
	out, _ := w.cli(t, "k8s", "list")
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &l); err != nil {
		t.Fatalf("k8s list: %v\n%s", err, out)
	}
	for _, c := range l.Items {
		if c.Name == name && c.Policy != nil {
			return c.Policy.ConfigHash
		}
	}
	t.Fatalf("no context %s with rules in %s", name, out)
	return ""
}
