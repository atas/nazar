package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/atas/nazar/core/layout"
)

func plutil(t *testing.T, args ...string) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("needs macOS /usr/bin/plutil")
	}
	out, err := exec.Command("/usr/bin/plutil", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("plutil %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestInstallWritesAgentFolderAndLinks(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	if code := h.run("--json", "install", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist")
	plutil(t, "-lint", plist)
	if got := plutil(t, "-extract", "ProgramArguments.0", "raw", "-o", "-", plist); got != h.app.MainExe {
		t.Fatalf("program %q, want %q", got, h.app.MainExe)
	}
	if got := plutil(t, "-extract", "Label", "raw", "-o", "-", plist); got != "dev.nazar.agent" {
		t.Fatalf("label %q", got)
	}
	if got, err := plistProgram(plist); err != nil || got != h.app.MainExe {
		t.Fatalf("locateApp's reader sees %q, %v", got, err)
	}
	fi, err := os.Stat(layout.Root(h.home))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("~/.nazar: %v %v", fi, err)
	}
	for _, l := range []string{"nazar", "nazar-sign-git"} {
		if tgt, err := os.Readlink(filepath.Join(bin, l)); err != nil || tgt != h.app.CLI {
			t.Fatalf("%s -> %q, %v", l, tgt, err)
		}
	}
	want := []string{"bootout gui/501/dev.nazar.agent", "bootstrap gui/501 " + plist}
	if strings.Join(h.launchctl, "|") != strings.Join(want, "|") {
		t.Fatalf("launchctl %q, want %q", h.launchctl, want)
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.Kind != "Installation" || inst.App != h.app.Bundle || inst.PathHint == "" {
		t.Fatalf("%+v %v", inst, err)
	}
	// Again: idempotent (links to this bundle are replaced, not refused).
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatalf("second install: exit %d %s", code, h.errb)
	}
}

func TestInstallOnlyFromTheBundledCLI(t *testing.T) {
	h := newHarness(t)
	for _, exe := range []string{"/opt/homebrew/bin/nazar", h.app.MainExe} {
		h.a.executable = func() (string, error) { return exe, nil }
		if code := h.run("install"); code != 1 || !strings.Contains(h.errb.String(), "inside nazar-agent.app") {
			t.Fatalf("%s: exit %d %q", exe, code, h.errb)
		}
	}
	if len(h.launchctl) != 0 {
		t.Fatal("launchctl ran")
	}
	if _, err := os.Stat(filepath.Join(h.home, "Library", "LaunchAgents")); err == nil {
		t.Fatal("something was written")
	}
}

func TestInstallNeverClobbersTheUsersFiles(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	os.MkdirAll(bin, 0o755)
	mine := filepath.Join(bin, "nazar")
	os.WriteFile(mine, []byte("my script"), 0o755)
	if code := h.run("install", "--bin-dir", bin); code != 1 {
		t.Fatalf("regular file replaced: exit %d", code)
	}
	if b, _ := os.ReadFile(mine); string(b) != "my script" {
		t.Fatal("the user's file changed")
	}
	os.Remove(mine)
	os.Symlink("/usr/local/bin/other", mine)
	if code := h.run("install", "--bin-dir", bin); code != 1 {
		t.Fatalf("foreign link replaced: exit %d", code)
	}
	os.Remove(mine)
	os.Symlink("/Applications/Old Nazar.app/Contents/MacOS/nazar", mine) // an older install
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatalf("old Nazar link not replaced: exit %d %s", code, h.errb)
	}
	if len(h.launchctl) != 2 {
		t.Fatalf("launchctl %q: refused installs must not touch launchd", h.launchctl)
	}
}

func TestInstallRefusesAnOpenDotNazar(t *testing.T) {
	h := newHarness(t)
	os.Mkdir(layout.Root(h.home), 0o755)
	if code := h.run("install"); code != 1 || !strings.Contains(h.errb.String(), "chmod 700") {
		t.Fatalf("exit %d %q", code, h.errb)
	}
}

func TestUninstallRemovesOnlyWhatInstallMade(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatal(code)
	}
	os.WriteFile(filepath.Join(h.home, ".nazar", "keep"), nil, 0o600)
	h.launchctl = nil
	if code := h.run("uninstall", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if _, err := os.Stat(filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist")); !os.IsNotExist(err) {
		t.Fatal("plist left behind")
	}
	for _, l := range []string{"nazar", "nazar-sign-git"} {
		if _, err := os.Lstat(filepath.Join(bin, l)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind", l)
		}
	}
	if _, err := os.Stat(filepath.Join(h.home, ".nazar", "keep")); err != nil {
		t.Fatal("~/.nazar was not kept")
	}
	if strings.Join(h.launchctl, "|") != "bootout gui/501/dev.nazar.agent" {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	// A link that isn't nazar's survives uninstall.
	os.Symlink("/usr/local/bin/other", filepath.Join(bin, "nazar"))
	h.run("uninstall", "--bin-dir", bin)
	if _, err := os.Lstat(filepath.Join(bin, "nazar")); err != nil {
		t.Fatal("a foreign link was removed")
	}
}

func TestInstallUsesTheTestLabelAndRefusesBadOnes(t *testing.T) {
	h := newHarness(t)
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test.x1"
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if !strings.HasSuffix(h.launchctl[1], "/Library/LaunchAgents/dev.nazar.test.x1.plist") || h.launchctl[0] != "bootout gui/501/dev.nazar.test.x1" {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	for _, bad := range []string{"dev.nazar</string><key>x", "../x", "a b", ""} {
		if bad == "" {
			continue // empty means the default label
		}
		h.env["NAZAR_LAUNCH_LABEL"] = bad
		if code := h.run("install"); code != 2 {
			t.Errorf("label %q: exit %d", bad, code)
		}
	}
}

func TestLaunchAgentPlistEscapes(t *testing.T) {
	p := string(launchAgentPlist("dev.nazar", "/Apps/A&B <x>.app/Contents/MacOS/nazar-agent"))
	if !strings.Contains(p, "/Apps/A&amp;B &lt;x&gt;.app/Contents/MacOS/nazar-agent") {
		t.Fatalf("%s", p)
	}
}

// ---- Edge and attack cases (test author) ----

// lstatGone fails the test when path exists (as anything, a link included).
func lstatGone(t *testing.T, path, what string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s: %s exists (%v)", what, path, err)
	}
}

// The agent is exactly what spec 12 describes: it starts at login,
// restarts only after a crash, runs in the GUI session as an interactive
// process, and launches nothing but nazar-agent. No Sockets key: the app
// binds its own sockets (launchd socket activation would not stop a
// same-user process that takes over the socket path either).
func TestInstallPlistIsTheWholeAgent(t *testing.T) {
	h := newHarness(t)
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	dir := filepath.Join(h.home, "Library", "LaunchAgents")
	plist := filepath.Join(dir, "dev.nazar.agent.plist")
	for key, want := range map[string]string{
		"ProgramArguments":         "1", // raw of an array is its length
		"RunAtLoad":                "true",
		"KeepAlive.SuccessfulExit": "false",
		"ProcessType":              "Interactive",
		"LimitLoadToSessionType":   "Aqua",
	} {
		if got := plutil(t, "-extract", key, "raw", "-o", "-", plist); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	for _, absent := range []string{"Sockets", "Program", "EnvironmentVariables", "UserName"} {
		if out, err := exec.Command("/usr/bin/plutil", "-extract", absent, "raw", "-o", "-", plist).CombinedOutput(); err == nil {
			t.Errorf("unexpected key %s = %q", absent, out)
		}
	}
	fi, err := os.Lstat(plist)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("plist mode: %v %v", fi, err)
	}
	// Written atomically: no temp file is left next to it.
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("LaunchAgents holds %q, want only dev.nazar.agent.plist", names)
	}
}

// Whatever the bundle path, the plist hands launchd exactly that path: XML
// metacharacters and a CDATA terminator are escaped, never interpreted.
func TestLaunchAgentPlistRoundTripsHostilePaths(t *testing.T) {
	dir := t.TempDir()
	for i, prog := range []string{
		"/Applications/Nazar.app/Contents/MacOS/nazar-agent",
		"/Apps/A&B <x>.app/Contents/MacOS/nazar-agent",
		`/Apps/"q" 'a' ]]> --> <!-- .app/Contents/MacOS/nazar-agent`,
		"/Apps/</string><string>/bin/sh</string><string>.app/Contents/MacOS/nazar-agent",
		"/Users/zoë/Applications/Nazar 🧿.app/Contents/MacOS/nazar-agent",
	} {
		p := filepath.Join(dir, "a"+string(rune('0'+i))+".plist")
		if err := os.WriteFile(p, launchAgentPlist("dev.nazar.test-x1", prog), 0o644); err != nil {
			t.Fatal(err)
		}
		plutil(t, "-lint", p)
		if got := plutil(t, "-extract", "ProgramArguments", "raw", "-o", "-", p); got != "1" {
			t.Fatalf("%q: %s arguments (an injected <string>?)", prog, got)
		}
		if got, err := plistProgram(p); err != nil || got != prog {
			t.Fatalf("program %q read back as %q, %v", prog, got, err)
		}
		if got := plutil(t, "-extract", "Label", "raw", "-o", "-", p); got != "dev.nazar.test-x1" {
			t.Fatalf("label %q", got)
		}
	}
}

// A bundle path XML 1.0 cannot carry (a C0 control character) would be
// written as U+FFFD, so launchd would start a different path than the one
// install reports. Install must refuse instead, before writing anything.
func TestInstallRefusesABundlePathAPlistCannotHold(t *testing.T) {
	h := newHarness(t)
	weird := filepath.Join(h.home, "a\x01b")
	h.app = fakeBundle(t, weird)
	h.a.executable = func() (string, error) { return h.app.CLI, nil }
	bin := filepath.Join(h.home, "bin")
	if code := h.run("install", "--bin-dir", bin); code != 1 {
		t.Fatalf("exit %d %q: install accepted a path it cannot write into the plist", code, h.errb)
	}
	if strings.ContainsRune(h.errb.String(), '\x01') {
		t.Fatalf("raw control byte reached the terminal: %q", h.errb)
	}
	lstatGone(t, filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist"), "plist")
	lstatGone(t, filepath.Join(bin, "nazar"), "link")
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
}

// A refused link slot stops install before anything is written: not the
// other link, not the plist, not launchd. The second slot is checked too.
func TestInstallRefusedLinkSlotChangesNothing(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	os.MkdirAll(bin, 0o755)
	signGit := filepath.Join(bin, "nazar-sign-git")
	for name, mk := range map[string]func() error{
		"file":      func() error { return os.WriteFile(signGit, []byte("mine"), 0o755) },
		"directory": func() error { return os.Mkdir(signGit, 0o755) },
		"link to the main executable, not the CLI": func() error {
			return os.Symlink("/Applications/Nazar.app/Contents/MacOS/nazar-agent", signGit)
		},
		"link with dot-dots": func() error {
			return os.Symlink("/Applications/Nazar.app/Contents/MacOS/../MacOS/nazar", signGit)
		},
		"link into a folder that isn't a bundle": func() error {
			return os.Symlink("/opt/x/Contents/MacOS/nazar", signGit)
		},
	} {
		os.RemoveAll(signGit)
		if err := mk(); err != nil {
			t.Fatal(err)
		}
		before := slotState(signGit)
		if code := h.run("install", "--bin-dir", bin); code != 1 {
			t.Fatalf("%s: exit %d", name, code)
		}
		if after := slotState(signGit); after != before {
			t.Fatalf("%s: the user's %s became %s", name, before, after)
		}
		if !strings.Contains(h.errb.String(), signGit) {
			t.Errorf("%s: the error should name %s: %q", name, signGit, h.errb)
		}
		lstatGone(t, filepath.Join(bin, "nazar"), name+": first link")
		lstatGone(t, filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist"), name+": plist")
		if len(h.launchctl) != 0 {
			t.Fatalf("%s: launchctl %q", name, h.launchctl)
		}
	}
}

// slotState describes what is at path without following a link.
func slotState(path string) string {
	fi, err := os.Lstat(path)
	switch {
	case err != nil:
		return "missing"
	case fi.Mode()&os.ModeSymlink != 0:
		t, _ := os.Readlink(path)
		return "link to " + t
	case fi.IsDir():
		return "directory"
	default:
		b, _ := os.ReadFile(path)
		return "file " + string(b)
	}
}

// ~/.nazar must be a real private directory of this user: a symlink (even
// to a 0700 folder) or a file there is refused, and nothing follows it.
func TestInstallRefusesADotNazarThatIsNotAPrivateDirectory(t *testing.T) {
	h := newHarness(t)
	dot := layout.Root(h.home)
	elsewhere := filepath.Join(h.home, "elsewhere")
	os.Mkdir(elsewhere, 0o700)
	os.Symlink(elsewhere, dot)
	if code := h.run("install"); code != 1 {
		t.Fatalf("symlinked ~/.nazar: exit %d %q", code, h.errb)
	}
	if fi, err := os.Lstat(dot); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the user's link was replaced: %v %v", fi, err)
	}
	os.Remove(dot)
	os.WriteFile(dot, []byte("x"), 0o600)
	if code := h.run("install"); code != 1 {
		t.Fatalf("file at ~/.nazar: exit %d %q", code, h.errb)
	}
	if b, _ := os.ReadFile(dot); string(b) != "x" {
		t.Fatal("the user's file changed")
	}
	// The 0755 case also leaves the folder's mode alone (no silent chmod).
	os.Remove(dot)
	os.Mkdir(dot, 0o755)
	os.Chmod(dot, 0o755)
	h.run("install")
	if fi, _ := os.Stat(dot); fi.Mode().Perm() != 0o755 {
		t.Fatalf("install changed ~/.nazar to %o", fi.Mode().Perm())
	}
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	lstatGone(t, filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist"), "plist")
}

// A plist path an attacker (or an old tool) made a symlink must not be
// written through: the atomic rename replaces the link itself.
func TestInstallDoesNotWriteThroughASymlinkedPlist(t *testing.T) {
	h := newHarness(t)
	dir := filepath.Join(h.home, "Library", "LaunchAgents")
	os.MkdirAll(dir, 0o755)
	victim := filepath.Join(h.home, "victim")
	os.WriteFile(victim, []byte("untouched"), 0o600)
	os.Symlink(victim, filepath.Join(dir, "dev.nazar.agent.plist"))
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if b, _ := os.ReadFile(victim); string(b) != "untouched" {
		t.Fatalf("install wrote through the link: %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "dev.nazar.agent.plist")); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("plist is not a regular file: %v %v", fi, err)
	}
}

// launchctl: a failed bootout (nothing loaded) is fine; a failed bootstrap
// is an error naming the plist that was written.
func TestInstallReportsAFailedBootstrap(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	var calls []string
	h.a.launchctl = func(args ...string) error {
		calls = append(calls, args[0])
		switch args[0] {
		case "bootout":
			return errors.New("launchctl bootout: 3: No such process")
		case "print":
			return errors.New("launchctl print: 113: Could not find service")
		}
		return nil
	}
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatalf("bootout of an unloaded agent failed install: exit %d %s", code, h.errb)
	}
	h.a.launchctl = func(args ...string) error {
		calls = append(calls, args[0])
		switch args[0] {
		case "bootstrap":
			return errors.New("launchctl bootstrap: 5: Input/output error")
		case "print":
			return errors.New("launchctl print: 113: Could not find service")
		}
		return nil
	}
	if code := h.run("install", "--bin-dir", bin); code != 1 {
		t.Fatalf("failed bootstrap: exit %d", code)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist")
	if !strings.Contains(h.errb.String(), plist) || !strings.Contains(h.errb.String(), "Input/output error") {
		t.Fatalf("stderr %q should name %s and launchctl's error", h.errb, plist)
	}
	// The harness's `print` is "not found" at once; a bootstrap that failed
	// with error 5 is retried once.
	if strings.Join(calls, ",") != "bootout,print,bootstrap,bootout,print,bootstrap,print,bootstrap" {
		t.Fatalf("calls %q", calls)
	}
}

// Without the launchctl/uid seams (a build that never wired them), install
// and uninstall refuse rather than half-install.
func TestInstallWithoutLaunchctlRefuses(t *testing.T) {
	for _, c := range []string{"install", "uninstall"} {
		h := newHarness(t)
		h.a.launchctl = nil
		if code := h.run(c, "--bin-dir", filepath.Join(h.home, "bin")); code != 1 {
			t.Fatalf("%s: exit %d", c, code)
		}
		h = newHarness(t)
		h.a.uid = nil
		if code := h.run(c, "--bin-dir", filepath.Join(h.home, "bin")); code != 1 {
			t.Fatalf("%s without uid: exit %d", c, code)
		}
		lstatGone(t, filepath.Join(h.home, "Library"), c)
		lstatGone(t, filepath.Join(h.home, "bin"), c)
	}
}

// Usage errors (exit 2) are decided before anything is written or run.
func TestInstallUsageErrors(t *testing.T) {
	h := newHarness(t)
	long := strings.Repeat("a", 129)
	cases := [][]string{
		{"install", "--bin-dir", "rel/bin"},
		{"install", "--bin-dir", ""},
		{"install", "extra"},
		{"install", "--bogus"},
		{"uninstall", "--bin-dir", "rel/bin"},
		{"uninstall", "extra"},
	}
	for _, args := range cases {
		if code := h.run(args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
	for _, bad := range []string{".hidden", "-x", "dev/nazar", "a\nb", "dev.nazar\x00x", "a;b", long, "dev.nazar ", "ö"} {
		h.env["NAZAR_LAUNCH_LABEL"] = bad
		for _, c := range []string{"install", "uninstall"} {
			if code := h.run(c, "--bin-dir", filepath.Join(h.home, "bin")); code != 2 {
				t.Errorf("%s label %q: exit %d, want 2", c, bad, code)
			}
		}
	}
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	lstatGone(t, filepath.Join(h.home, "Library"), "Library")
	lstatGone(t, layout.Root(h.home), ".nazar")
	lstatGone(t, filepath.Join(h.home, "bin"), "bin")
	// 128 characters is still a valid label.
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test-" + strings.Repeat("b", 128-len("dev.nazar.test-"))
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("128-character label: exit %d %s", code, h.errb)
	}
}

// Who may run install: only the CLI inside a bundle whose nazar-agent exists.
func TestInstallRefusesEveryOtherExecutable(t *testing.T) {
	h := newHarness(t)
	noMain := filepath.Join(h.home, "Bare.app", "Contents", "MacOS")
	os.MkdirAll(noMain, 0o755)
	os.WriteFile(filepath.Join(noMain, "nazar"), []byte("#!/bin/sh\n"), 0o755)
	notBundle := filepath.Join(h.home, "x", "Contents", "MacOS")
	os.MkdirAll(notBundle, 0o755)
	os.WriteFile(filepath.Join(notBundle, "nazar"), []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(filepath.Join(notBundle, appExeName), []byte("#!/bin/sh\n"), 0o755)
	for name, exe := range map[string]func() (string, error){
		"bundle without nazar-agent":  func() (string, error) { return filepath.Join(noMain, "nazar"), nil },
		"Contents/MacOS outside .app": func() (string, error) { return filepath.Join(notBundle, "nazar"), nil },
		"another file in the bundle":  func() (string, error) { return filepath.Join(h.app.Bundle, "Contents", "MacOS", "nazar-sign-git"), nil },
		"unknown executable":          func() (string, error) { return "", errors.New("no path") },
	} {
		h.a.executable = exe
		if code := h.run("install"); code != 1 || !strings.Contains(h.errb.String(), "inside nazar-agent.app") {
			t.Errorf("%s: exit %d %q", name, code, h.errb)
		}
	}
	h.a.executable = nil
	if code := h.run("install"); code != 1 {
		t.Errorf("nil executable: exit %d", code)
	}
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	lstatGone(t, filepath.Join(h.home, "Library"), "Library")
	lstatGone(t, filepath.Join(h.home, ".local"), ".local")
}

// The default --bin-dir is ~/.local/bin, for install and uninstall alike;
// PathHint appears only when the bin dir is not on $PATH.
func TestInstallDefaultBinDirAndPathHint(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, ".local", "bin")
	h.env["PATH"] = "/usr/bin:" + bin + "/:/bin"
	if code := h.run("--json", "install"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.PathHint != "" {
		t.Fatalf("%+v %v: bin dir is on PATH, no hint expected", inst, err)
	}
	// git-credential-nazar is git's credential helper: git runs it
	// for `credential.<url>.helper = nazar`.
	if strings.Join(inst.Links, "|") != filepath.Join(bin, "nazar")+"|"+filepath.Join(bin, "nazar-sign-git")+"|"+filepath.Join(bin, "git-credential-nazar") ||
		inst.Label != "dev.nazar.agent" || inst.Uninstalled {
		t.Fatalf("%+v", inst)
	}
	if inst.Plist != filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist") {
		t.Fatalf("plist %q", inst.Plist)
	}
	for _, l := range []string{"nazar", "nazar-sign-git", "git-credential-nazar"} {
		if tgt, err := os.Readlink(filepath.Join(bin, l)); err != nil || tgt != h.app.CLI {
			t.Fatalf("%s -> %q, %v", l, tgt, err)
		}
	}
	h.env["PATH"] = "/usr/bin:/bin"
	if code := h.run("install"); code != 0 || !strings.Contains(h.out.String(), "add "+bin+" to PATH") {
		t.Fatalf("exit %d %q", code, h.out)
	}
	if code := h.run("uninstall"); code != 0 {
		t.Fatalf("uninstall: exit %d %s", code, h.errb)
	}
	for _, l := range []string{"nazar", "nazar-sign-git", "git-credential-nazar"} {
		lstatGone(t, filepath.Join(bin, l), "default bin dir")
	}
}

// Human output prints paths through term: a bundle path with a bidi
// override or other non-printing rune never reaches the terminal raw.
func TestInstallHumanOutputIsTerminalSafe(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("needs macOS /usr/bin/plutil (plistProgram)")
	}
	h := newHarness(t)
	h.app = fakeBundle(t, filepath.Join(h.home, "x‮gnp.exe"))
	h.a.executable = func() (string, error) { return h.app.CLI, nil }
	bin := filepath.Join(h.home, "b‮in")
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if strings.ContainsRune(h.out.String(), '‮') {
		t.Fatalf("raw bidi override on the terminal: %q", h.out)
	}
	if got, err := plistProgram(filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist")); err != nil || got != h.app.MainExe {
		t.Fatalf("program %q, %v", got, err)
	}
	if code := h.run("uninstall", "--bin-dir", bin); code != 0 || strings.ContainsRune(h.out.String(), '‮') {
		t.Fatalf("uninstall: exit %d %q", code, h.out)
	}
}

// uninstall's --json reply: links it removed (never null), what it kept,
// and Uninstalled. It works with nothing installed, and creates nothing.
func TestUninstallReplyAndNothingInstalled(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	if code := h.run("--json", "uninstall", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.errb, h.out)
	}
	if !strings.Contains(h.out.String(), `"links":[]`) || !strings.Contains(h.out.String(), `"uninstalled":true`) {
		t.Fatalf("reply %s", h.out)
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.Kind != "Installation" || !inst.Uninstalled {
		t.Fatalf("%+v %v", inst, err)
	}
	kept := strings.Join(inst.Kept, "|")
	for _, k := range []string{layout.Root(h.home), "Keychain"} {
		if !strings.Contains(kept, k) {
			t.Errorf("kept %q does not mention %s", inst.Kept, k)
		}
	}
	if strings.Join(h.launchctl, "|") != "bootout gui/501/dev.nazar.agent" {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	for _, p := range []string{"Library", ".nazar", "bin", ".config"} {
		lstatGone(t, filepath.Join(h.home, p), "uninstall created")
	}
	// A failing bootout (agent not loaded) does not fail uninstall.
	h.a.launchctl = func(...string) error { return errors.New("launchctl bootout: 3: No such process") }
	if code := h.run("uninstall", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	// After an install, the reply lists the three links it removed
	// (nazar, nazar-sign-git and, since M8, git-credential-nazar).
	h = newHarness(t)
	bin = filepath.Join(h.home, "bin")
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatal(code)
	}
	if code := h.run("--json", "uninstall", "--bin-dir", bin); code != 0 {
		t.Fatal(code)
	}
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || len(inst.Links) != 3 {
		t.Fatalf("%+v %v", inst, err)
	}
}

// uninstall removes a link only when it is the CLI of some Nazar.app
// bundle (this one or an older one); everything else in the bin dir stays.
func TestUninstallKeepsEverythingThatIsNotANazarCLILink(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	os.MkdirAll(bin, 0o755)
	keep := map[string]func(string) error{
		"file":   func(p string) error { return os.WriteFile(p, []byte("mine"), 0o755) },
		"dir":    func(p string) error { return os.Mkdir(p, 0o755) },
		"main":   func(p string) error { return os.Symlink("/Applications/Nazar.app/Contents/MacOS/nazar-agent", p) },
		"dotdot": func(p string) error { return os.Symlink("/Applications/Nazar.app/Contents/MacOS/../MacOS/nazar", p) },
		"other":  func(p string) error { return os.Symlink("/opt/homebrew/bin/nazar", p) },
	}
	for name, mk := range keep {
		for _, l := range []string{"nazar", "nazar-sign-git"} {
			p := filepath.Join(bin, l)
			os.RemoveAll(p)
			if err := mk(p); err != nil {
				t.Fatal(err)
			}
		}
		if code := h.run("uninstall", "--bin-dir", bin); code != 0 {
			t.Fatalf("%s: exit %d %s", name, code, h.errb)
		}
		for _, l := range []string{"nazar", "nazar-sign-git"} {
			if _, err := os.Lstat(filepath.Join(bin, l)); err != nil {
				t.Fatalf("%s: %s was removed", name, l)
			}
		}
	}
	// An older Nazar.app's CLI link is nazar's own and goes.
	for _, l := range []string{"nazar", "nazar-sign-git"} {
		p := filepath.Join(bin, l)
		os.RemoveAll(p)
		os.Symlink("/Applications/Old Nazar.app/Contents/MacOS/nazar", p)
	}
	if code := h.run("uninstall", "--bin-dir", bin); code != 0 {
		t.Fatal(code)
	}
	for _, l := range []string{"nazar", "nazar-sign-git"} {
		lstatGone(t, filepath.Join(bin, l), "old Nazar link")
	}
}

// uninstall keeps keys and config: ~/.nazar and all its contents are
// untouched.
func TestUninstallKeepsKeysAndConfig(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatal(code)
	}
	pub := filepath.Join(layout.KeysDir(h.home), "github.pub")
	os.MkdirAll(layout.ConfigDir(h.home), 0o700)
	os.MkdirAll(layout.KeysDir(h.home), 0o700)
	os.WriteFile(layout.ConfigFile(h.home), []byte("version: 1\n"), 0o600)
	os.WriteFile(pub, []byte("ecdsa"), 0o644)
	if code := h.run("uninstall", "--bin-dir", bin); code != 0 {
		t.Fatal(code)
	}
	for _, p := range []string{layout.ConfigFile(h.home), pub} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s removed", p)
		}
	}
	if fi, err := os.Stat(layout.Root(h.home)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("~/.nazar: %v %v", fi, err)
	}
}

func TestIsNazarCLI(t *testing.T) {
	for target, want := range map[string]bool{
		"/Applications/Nazar.app/Contents/MacOS/nazar":               true,
		"/Applications/Old Nazar.app/Contents/MacOS/nazar":           true,
		"/Users/u/Applications/Nazar.app/Contents/MacOS/nazar":       true,
		"/Applications/Nazar.app/Contents/MacOS/nazar-agent":         false,
		"/Applications/Nazar.app/Contents/MacOS/nazar-sign-git":      false,
		"/Applications/Nazar.app/Contents/MacOS/../MacOS/nazar":      false,
		"/Applications/Nazar.app/Contents/MacOS//nazar":              false,
		"/Applications/Nazar/Contents/MacOS/nazar":                   false,
		"/Applications/Nazar.app/Contents/Resources/nazar":           false,
		"/Applications/Nazar.app/MacOS/nazar":                        false,
		"/opt/homebrew/bin/nazar":                                    false,
		"/usr/local/bin/other":                                       false,
		"":                                                           false,
		"nazar":                                                      false,
		"/Applications/Nazar.app/Contents/MacOS/nazar/":              false,
		"/Applications/Nazar.app/Contents/MacOS/nazar\x00/x":         false,
		"/Applications/Nazar.app.d/Contents/MacOS/nazar/../../nazar": false,
	} {
		if got := isNazarCLI(target); got != want {
			t.Errorf("isNazarCLI(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestCheckLinkSlot(t *testing.T) {
	dir := t.TempDir()
	cli := "/Applications/Nazar.app/Contents/MacOS/nazar"
	slot := filepath.Join(dir, "nazar")
	if err := checkLinkSlot(slot, cli); err != nil {
		t.Fatalf("missing slot: %v", err)
	}
	for target, ok := range map[string]bool{
		cli: true,
		"/Applications/Old Nazar.app/Contents/MacOS/nazar":      true,
		"/Applications/Nazar.app/Contents/MacOS/nazar-agent":    false,
		"/usr/local/bin/other":                                  false,
		"relative/nazar":                                        false,
		"/Applications/Nazar.app/Contents/MacOS/../MacOS/nazar": false,
	} {
		os.Remove(slot)
		os.Symlink(target, slot)
		if err := checkLinkSlot(slot, cli); (err == nil) != ok {
			t.Errorf("link to %q: err %v, want ok=%v", target, err, ok)
		}
	}
	os.Remove(slot)
	os.WriteFile(slot, []byte("x"), 0o755)
	if err := checkLinkSlot(slot, cli); err == nil || !strings.Contains(err.Error(), slot) {
		t.Fatalf("regular file: %v", err)
	}
	os.Remove(slot)
	os.Mkdir(slot, 0o755)
	if err := checkLinkSlot(slot, cli); err == nil {
		t.Fatal("directory accepted")
	}
	// A link to a directory that happens to be named like the CLI is still
	// judged by its target string, never by following it.
	os.Remove(slot)
	real := filepath.Join(dir, "Nazar.app", "Contents", "MacOS")
	os.MkdirAll(real, 0o755)
	os.Symlink(real, slot)
	if err := checkLinkSlot(slot, cli); err == nil {
		t.Fatal("link to a bundle's MacOS folder accepted")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.plist")
	if err := writeFileAtomic(p, []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatalf("%q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if err := writeFileAtomic(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatalf("%q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o after replace", fi.Mode().Perm())
	}
	// The link itself is replaced; its target is never written.
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("v"), 0o600)
	l := filepath.Join(dir, "l.plist")
	os.Symlink(victim, l)
	if err := writeFileAtomic(l, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "v" {
		t.Fatalf("wrote through a link: %q", b)
	}
	if fi, err := os.Lstat(l); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("%v %v", fi, err)
	}
	// A missing folder is an error, and no temp file is ever left behind.
	if err := writeFileAtomic(filepath.Join(dir, "nope", "x"), []byte("x"), 0o644); err == nil {
		t.Fatal("missing folder accepted")
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "a.plist,l.plist,victim" {
		t.Fatalf("folder holds %q", names)
	}
}
