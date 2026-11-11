package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
)

// These tests drive the CLI's Linux behaviour through a.linux, so they run
// on every OS: the harness is the macOS one with only the switch flipped.

func linuxHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.a.linux = true
	return h
}

func TestLinuxTraits(t *testing.T) {
	h := newHarness(t)
	if h.a.traits() != platform.MacTraits {
		t.Fatalf("macOS CLI traits %+v", h.a.traits())
	}
	h.a.linux = true
	if h.a.traits() != platform.LinuxTraits {
		t.Fatalf("Linux CLI traits %+v", h.a.traits())
	}
}

func TestLinuxRunRefuses(t *testing.T) {
	h := linuxHarness(t)
	h.a.resetForExec = func(int) error { t.Fatal("reset for exec on Linux"); return nil }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	const want = "nazar: run: nazar run is not available on Linux yet (it needs to watch the program's exec, which Linux allows only to root); deliver the secret with a helper or stdout instead\n"
	for _, args := range [][]string{
		{"run", "--secret", "API", "--", "/bin/true"},
		{"run", "--", "/bin/true"}, // refused before the arguments are judged
	} {
		if code := h.run(args...); code != control.ExitError || h.errb.String() != want {
			t.Fatalf("%v: exit %d, stderr %q", args, code, h.errb)
		}
		if h.execed != nil {
			t.Fatalf("%v: exec'd %v", args, h.execed)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("run reached nazar-agent on Linux: %+v", r)
	}
	if code := h.run("--json", "run", "--secret", "API", "--", "/bin/true"); code != control.ExitError {
		t.Fatalf("--json: exit %d", code)
	}
	var p control.Problem
	if err := json.Unmarshal(h.out.Bytes(), &p); err != nil || p.Code != control.CodeError || !strings.HasPrefix(p.Message, "run: nazar run is not available on Linux yet") {
		t.Fatalf("--json problem %q (%v)", h.out, err)
	}
}

func TestLinuxUIRefuses(t *testing.T) {
	h := linuxHarness(t)
	h.a.openUI = func(string) (string, error) { t.Fatal("opened the UI on Linux"); return "", nil }
	if code := h.run("ui"); code != control.ExitError || h.errb.String() != "nazar: ui: Nazar UI is macOS only\n" {
		t.Fatalf("exit %d, stderr %q", code, h.errb)
	}
}

func TestLinuxVersionSaysPreview(t *testing.T) {
	old := version
	version = "1.2.3"
	t.Cleanup(func() { version = old })
	h := linuxHarness(t)
	if code := h.run("version"); code != 0 || h.out.String() != "nazar 1.2.3 (Linux preview)\n" {
		t.Fatalf("exit %d, %q", code, h.out)
	}
	if code := h.run("--json", "version"); code != 0 {
		t.Fatalf("--json: exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != "Version" || objs[0]["version"] != "1.2.3" || objs[0]["preview"] != "linux" {
		t.Fatalf("%s", h.out)
	}
	// macOS: no preview, in either view.
	h.a.linux = false
	if code := h.run("version"); code != 0 || h.out.String() != "nazar 1.2.3\n" {
		t.Fatalf("macOS: exit %d, %q", code, h.out)
	}
	if code := h.run("--json", "version"); code != 0 || strings.Contains(h.out.String(), "preview") {
		t.Fatalf("macOS --json: %s", h.out)
	}
}

func TestLinuxConfigCheckRefusesSigned(t *testing.T) {
	const signedRefused = "signed: needs macOS code signatures; on Linux name the program's file with path: or a desktop app with app:"
	body := "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      rules:\n        - apps: [{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}]\n          gate: dialog\n"
	h := linuxHarness(t)
	writeConfig(t, h, body)
	if code := h.run("config", "check"); code != control.ExitError || !strings.Contains(h.out.String(), signedRefused) || !strings.Contains(h.out.String(), "isn't running") {
		t.Fatalf("exit %d\n%s%s", code, h.out, h.errb)
	}
	if code := h.run("--json", "config", "check"); code != control.ExitError {
		t.Fatalf("--json: exit %d\n%s", code, h.out)
	}
	var c control.ConfigCheck
	if err := json.Unmarshal(h.out.Bytes(), &c); err != nil || c.Valid {
		t.Fatalf("%s (%v)", h.out, err)
	}
	found := false
	for _, p := range c.Problems {
		found = found || (p.Severity == "error" && p.Message == signedRefused && p.Path == "ssh_agent.keys.github.rules[1].apps")
	}
	if !found {
		t.Fatalf("no refusal of signed: in %+v", c.Problems)
	}
	// The same file is valid on macOS.
	h.a.linux = false
	if code := h.run("config", "check"); code != 0 || strings.Contains(h.out.String(), signedRefused) {
		t.Fatalf("macOS: exit %d\n%s", code, h.out)
	}
}

func TestLinuxHelpWording(t *testing.T) {
	h := linuxHarness(t)
	if code := h.run("ssh-key", "create", "--help"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	var line string
	for _, l := range strings.Split(h.out.String(), "\n") {
		if strings.Contains(l, "--always-ask") && strings.HasPrefix(strings.TrimSpace(l), "--always-ask") {
			line = l
		}
	}
	if !strings.HasSuffix(line, "your password on every use, enforced by nazar; nazar refuses looser rules for this key") {
		t.Fatalf("--always-ask line %q in\n%s", line, h.out)
	}
	// The two choices are a byte of the key's record on Linux (THREAT-MODEL
	// 7.3, 7.11): the help says who enforces them, as lockedLine does,
	// never that they are fixed.
	if !strings.Contains(h.out.String(), "Both are "+linuxLockedBy+".") {
		t.Errorf("ssh-key create --help does not say %q:\n%s", "Both are "+linuxLockedBy+".", h.out)
	}
	for _, cmd := range [][]string{{"k8s", "ca", "create", "--help"}, {"aws", "ca", "create", "--help"}} {
		if code := h.run(cmd...); code != 0 {
			t.Fatalf("%v: exit %d %s", cmd, code, h.errb)
		}
		if want := "refuse the CA while the screen is locked (" + linuxLockedBy + ")."; !strings.Contains(h.out.String(), want) {
			t.Errorf("%v does not say %q:\n%s", cmd, want, h.out)
		}
	}
	// No help text, usage line or completion value names what Linux
	// doesn't have, or claims a chip's protection.
	texts := helpTexts(t, h.a)
	if code := h.run("help"); code != 0 {
		t.Fatal(code)
	}
	texts[h.out.String()] = "nazar help"
	h.a.json = false
	if code := h.a.run([]string{"bogus"}); code != control.ExitUsage {
		t.Fatal(code)
	}
	texts[h.errb.String()] = "usage error"
	for _, v := range h.a.gateCompletions() {
		texts[v] = "gate completion"
	}
	for text, where := range texts {
		for _, mac := range []string{"Touch ID", "Secure Enclave", "the chip", "the Mac", "Apple Watch", "signed:", "signing team", "Q6L2SF6YDW", "iterm2", "pbcopy", "fixed for"} {
			if strings.Contains(text, mac) {
				t.Errorf("%s says %q on Linux:\n%s", where, mac, text)
			}
		}
	}
}

// The human outputs nazar prints itself (not the agent's messages) say
// what Linux has.
func TestLinuxCLIMessages(t *testing.T) {
	h := linuxHarness(t)
	tr := h.a.traits()
	if got := h.a.lockedLine(true); got != "works while the screen is locked too (enforced by nazar from the key's record)" {
		t.Errorf("lockedLine(true) %q", got)
	}
	if got := h.a.lockedLine(false); got != "only when unlocked: nazar refuses it while the screen is locked (enforced by nazar from the key's record)" {
		t.Errorf("lockedLine(false) %q", got)
	}
	if got := h.a.caLockedLine(true); got != "The CA signs while the screen is locked too (enforced by nazar from the key's record)." {
		t.Errorf("caLockedLine(true) %q", got)
	}
	if got := h.a.caLockedLine(false); got != "The CA signs only while the screen is unlocked (enforced by nazar from the key's record)." {
		t.Errorf("caLockedLine(false) %q", got)
	}
	// On Linux the choice is a byte of the key's record, which any program
	// running as the user can rewrite (THREAT-MODEL 7.3, 7.11): the macOS
	// promise is never made.
	for _, got := range []string{h.a.lockedLine(true), h.a.lockedLine(false), h.a.caLockedLine(true), h.a.caLockedLine(false)} {
		if strings.Contains(got, "fixed for its life") || strings.Contains(got, "chip") {
			t.Errorf("Linux claims a chip's protection: %q", got)
		}
	}
	if got := h.a.alwaysAskMark(); got != "asks every time (nazar)" {
		t.Errorf("alwaysAskMark %q", got)
	}
	if got := h.a.approval(); got != tr.LoginGate {
		t.Errorf("approval %q", got)
	}
	if got := h.a.wrongAccess("secret X", "nazar secret rm X").Message; !strings.HasPrefix(got, "secret X works while the screen is locked, though --only-when-unlocked") {
		t.Errorf("wrongAccess %q", got)
	}
	// macOS stays as it was.
	h.a.linux = false
	if got := h.a.lockedLine(true); got != "works while the Mac is locked too, once you have logged in since it started (fixed for its life)" {
		t.Errorf("macOS lockedLine(true) %q", got)
	}
	if got := h.a.lockedLine(false); got != "only when unlocked: the chip refuses it while the Mac is locked (fixed for its life)" {
		t.Errorf("macOS lockedLine(false) %q", got)
	}
	if got := h.a.caLockedLine(true); got != "The CA signs while the Mac is locked too, once you have logged in since it started (fixed for its life)." {
		t.Errorf("macOS caLockedLine(true) %q", got)
	}
	if got := h.a.caLockedLine(false); got != "The CA signs only while the Mac is unlocked (fixed for its life)." {
		t.Errorf("macOS caLockedLine(false) %q", got)
	}
	if got := h.a.alwaysAskMark(); got != "asks every time (chip)" {
		t.Errorf("macOS alwaysAskMark %q", got)
	}
	if got := h.a.approval(); got != "Touch ID / Watch / password" {
		t.Errorf("macOS approval %q", got)
	}
}

func TestLinuxSSHKeyCreateOutput(t *testing.T) {
	h := linuxHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("ssh-key", "create", "hydra", "--always-ask"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	for _, want := range []string{"asks every time (nazar): your password on every use, enforced by nazar\n", "only when unlocked: nazar refuses it while the screen is locked (enforced by nazar from the key's record)\n"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, h.out)
		}
	}
	if strings.Contains(h.out.String(), "fixed for its life") || strings.Contains(h.out.String(), "chip") {
		t.Errorf("Linux output claims a chip's protection:\n%s", h.out)
	}
}

// invokedPath is what a kubeconfig and ~/.aws/config get on Linux: the
// path the user ran, so the link and not the versioned file behind it,
// which an upgrade removes (install.sh keeps ~/.local/bin/nazar, Homebrew
// <prefix>/bin/nazar). It must resolve to the running program.
func TestInvokedPath(t *testing.T) {
	root := t.TempDir()
	versioned := filepath.Join(root, "lib", "nazar", "1.0.0", "nazar")
	binDir := filepath.Join(root, "bin")
	link := filepath.Join(binDir, "nazar")
	other := filepath.Join(root, "other", "nazar")
	for _, p := range []string{versioned, other} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(versioned, link); err != nil {
		t.Fatal(err)
	}
	usrBin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, argv0, path, cwd, want string
	}{
		{"a bare name is looked up on PATH, and the link is kept", "nazar", usrBin + ":" + binDir, "/", link},
		{"a relative PATH entry is read from cwd", "nazar", "bin", root, link},
		{"an empty PATH entry is cwd", "nazar", ":" + usrBin, binDir, link},
		{"a relative path is made absolute from cwd", "./bin/nazar", "", root, link},
		{"a relative path with .. is cleaned", "lib/../bin/nazar", "", root, link},
		{"an absolute path is kept as given", link, "", "/", link},
		{"the versioned file itself, when that is what was run", versioned, "", "/", versioned},
	} {
		got, err := invokedPath(tc.argv0, tc.path, tc.cwd, versioned)
		if err != nil || got != tc.want {
			t.Errorf("%s: invokedPath(%q, %q, %q) = %q, %v; want %q", tc.name, tc.argv0, tc.path, tc.cwd, got, err, tc.want)
		}
	}
	// Another file of the same name is never written anywhere: not from
	// PATH, not as a path, and nothing is made up for a missing name.
	for _, tc := range []struct {
		name, argv0, path, cwd string
	}{
		{"PATH finds a different nazar", "nazar", filepath.Dir(other) + ":" + binDir, "/"},
		{"argv0 names a different file", other, "", "/"},
		{"argv0 names a missing file", filepath.Join(root, "missing"), "", "/"},
		{"nothing on PATH", "nazar", usrBin, "/"},
		{"an empty name", "", binDir, "/"},
	} {
		if got, err := invokedPath(tc.argv0, tc.path, tc.cwd, versioned); err == nil {
			t.Errorf("%s: invokedPath(%q, %q, %q) = %q, want an error", tc.name, tc.argv0, tc.path, tc.cwd, got)
		}
	}
	// What the running program resolves to is compared with the link
	// followed, so a program given by its link finds itself.
	if got, err := invokedPath("nazar", binDir, "/", link); err != nil || got != link {
		t.Errorf("exe given as the link: %q, %v", got, err)
	}
}

func TestLinuxTrustOutput(t *testing.T) {
	h := linuxHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: req.Args["app"], Team: "sha256:ab12", OldTeam: "sha256:cd34", Path: "/usr/bin/konsole", Changed: true})
	})
	if code := h.run("trust", "--app", "org.kde.konsole"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	const want = "pinned app org.kde.konsole to executable hash sha256:ab12, replacing sha256:cd34 (installed at /usr/bin/konsole)\napp: matchers for this app now match that executable\n"
	if h.out.String() != want {
		t.Fatalf("%q", h.out)
	}
}

func TestLinuxApprovalHints(t *testing.T) {
	h := linuxHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdStatus:
			out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{},
				Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: strings.Repeat("a", 64), Changes: []string{"ssh:github: added rule 1"}}})
		default:
			replyFor(req, out)
		}
	})
	h.run("config", "apply")
	if !strings.Contains(h.out.String(), "staged in config.yaml, waiting for your approval (your password):") {
		t.Fatalf("%s", h.out)
	}
}

// On Linux --apps completion offers no signed: (there are no code
// signatures) and app: names an app id.
func TestLinuxCompletionOffersNoSigned(t *testing.T) {
	h := newHarness(t)
	h.a.linux = true
	got, _ := h.complete(t, "ssh-key", "rule", "add", "g", "--apps", "")
	if !slices.Equal(got, []string{"any", "unknown", "app:", "path:"}) {
		t.Errorf("--apps on Linux: %q", got)
	}
}
