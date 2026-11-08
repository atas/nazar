package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/layout"
)

// Milestone 6: `nazar install` of nazar-agent migrates the Nazar.app install
// of Milestones 1-5 (LaunchAgent dev.nazar, links in ~/.local/bin into the
// old bundle), and `nazar uninstall` removes either. launchctl is the
// harness's stub: no test here reaches the real launchd.

const oldApp = "/Applications/Nazar.app"

// oldInstall lays out what the old Nazar.app's install left in h's home:
// the dev.nazar LaunchAgent plist (its program read through the
// plistProgram seam), links to the old CLI in ~/.local/bin, and the state
// that must never be touched (config, a public key, ~/.nazar). It returns
// the legacy plist path.
func oldInstall(t *testing.T, h *harness) string {
	t.Helper()
	agents := filepath.Join(h.home, "Library", "LaunchAgents")
	bin := filepath.Join(h.home, ".local", "bin")
	for _, d := range []string{agents, bin, layout.KeysDir(h.home), layout.ConfigDir(h.home)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	legacy := filepath.Join(agents, "dev.nazar.plist")
	if err := os.WriteFile(legacy, launchAgentPlist("dev.nazar", oldApp+"/Contents/MacOS/NazarApp"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.a.plistProgram = func(p string) (string, error) {
		if p != legacy {
			t.Fatalf("read plist %s, want %s", p, legacy)
		}
		return oldApp + "/Contents/MacOS/NazarApp", nil
	}
	for _, n := range []string{"nazar", "nazar-sign-git"} {
		if err := os.Symlink(oldApp+"/Contents/MacOS/nazar", filepath.Join(bin, n)); err != nil {
			t.Fatal(err)
		}
	}
	for p, v := range map[string]string{
		layout.ConfigFile(h.home):                           "apiVersion: nazar/v1\nkind: Config\n",
		filepath.Join(layout.KeysDir(h.home), "github.pub"): "ecdsa-sha2-nistp256 AAAA github\n",
	} {
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return legacy
}

// untouched checks that the state an install must never change is as
// oldInstall left it, and that the CLI sent no request (it has no key
// access; keys live in the agent's Keychain items).
func untouched(t *testing.T, h *harness) {
	t.Helper()
	for p, v := range map[string]string{
		layout.ConfigFile(h.home):                           "apiVersion: nazar/v1\nkind: Config\n",
		filepath.Join(layout.KeysDir(h.home), "github.pub"): "ecdsa-sha2-nistp256 AAAA github\n",
	} {
		if b, err := os.ReadFile(p); err != nil || string(b) != v {
			t.Fatalf("%s changed: %q, %v", p, b, err)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("install talked to the agent: %+v", r)
	}
}

func TestInstallMigratesTheOldNazarApp(t *testing.T) {
	h := newHarness(t)
	legacy := oldInstall(t, h)
	bin := filepath.Join(h.home, ".local", "bin")
	if code := h.run("--json", "install"); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.out, h.errb)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist")
	want := []string{"bootout gui/501/dev.nazar", "bootout gui/501/dev.nazar.agent", "bootstrap gui/501 " + plist}
	if strings.Join(h.launchctl, "|") != strings.Join(want, "|") {
		t.Fatalf("launchctl %q, want %q", h.launchctl, want)
	}
	lstatGone(t, legacy, "the old LaunchAgent plist")
	if got := plutil(t, "-extract", "ProgramArguments.0", "raw", "-o", "-", plist); got != h.app.MainExe {
		t.Fatalf("program %q, want %q", got, h.app.MainExe)
	}
	for _, n := range []string{"nazar", "nazar-sign-git"} {
		if tgt, err := os.Readlink(filepath.Join(bin, n)); err != nil || tgt != h.app.CLI {
			t.Fatalf("%s -> %q, %v; want the new CLI", n, tgt, err)
		}
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil {
		t.Fatal(err)
	}
	m := inst.Migrated
	if m == nil || m.Label != "dev.nazar" || m.Plist != legacy || m.App != oldApp ||
		strings.Join(m.Links, "|") != filepath.Join(bin, "nazar")+"|"+filepath.Join(bin, "nazar-sign-git") {
		t.Fatalf("migrated %+v", m)
	}
	untouched(t, h)

	// Once migrated, installing again finds nothing old.
	h.launchctl = nil
	if code := h.run("--json", "install"); code != 0 {
		t.Fatalf("again: exit %d %s", code, h.errb)
	}
	inst = Installation{}
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.Migrated != nil {
		t.Fatalf("again: %+v %v", inst, err)
	}
	if strings.Join(h.launchctl, "|") != "bootout gui/501/dev.nazar.agent|bootstrap gui/501 "+plist {
		t.Fatalf("again: launchctl %q", h.launchctl)
	}
}

// The human view says what was removed, where the old app still is, and
// that keys were not touched.
func TestInstallMigrationHumanView(t *testing.T) {
	h := newHarness(t)
	oldInstall(t, h)
	if code := h.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	for _, want := range []string{"removed the old LaunchAgent dev.nazar", "removed old links", "the old app is still at " + oldApp, "Keychain items were not touched"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("stdout lacks %q: %q", want, h.out)
		}
	}
}

// With --no-links (a package manager links the CLI), install links nothing,
// still removes the old Nazar.app's links in ~/.local/bin (they would
// shadow the package's), and leaves a link to this CLI and the user's own
// files alone.
func TestInstallNoLinks(t *testing.T) {
	h := newHarness(t)
	oldInstall(t, h)
	bin := filepath.Join(h.home, ".local", "bin")
	if err := os.Remove(filepath.Join(bin, "nazar-sign-git")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "nazar-sign-git"), []byte("mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.run("--json", "install", "--no-links"); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.out, h.errb)
	}
	lstatGone(t, filepath.Join(bin, "nazar"), "the old CLI link")
	if b, err := os.ReadFile(filepath.Join(bin, "nazar-sign-git")); err != nil || string(b) != "mine" {
		t.Fatalf("the user's file changed: %q %v", b, err)
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || len(inst.Links) != 0 || inst.PathHint != "" ||
		inst.Migrated == nil || strings.Join(inst.Migrated.Links, "|") != filepath.Join(bin, "nazar") {
		t.Fatalf("%+v %v", inst, err)
	}
	if strings.Contains(h.out.String(), `"links":null`) {
		t.Fatalf("links must be a list: %s", h.out)
	}
	// A link to this very CLI stays.
	if err := os.Symlink(h.app.CLI, filepath.Join(bin, "nazar")); err != nil {
		t.Fatal(err)
	}
	if code := h.run("install", "--no-links"); code != 0 {
		t.Fatalf("again: exit %d %s", code, h.errb)
	}
	if tgt, err := os.Readlink(filepath.Join(bin, "nazar")); err != nil || tgt != h.app.CLI {
		t.Fatalf("the link to this CLI went: %q %v", tgt, err)
	}
	untouched(t, h)
}

// --bin-dir elsewhere: install links there and removes the old links in
// ~/.local/bin, which it does not link into.
func TestInstallElsewhereRemovesOldLinks(t *testing.T) {
	h := newHarness(t)
	oldInstall(t, h)
	other := filepath.Join(h.home, "brew", "bin")
	if code := h.run("install", "--bin-dir", other); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	for _, n := range []string{"nazar", "nazar-sign-git"} {
		lstatGone(t, filepath.Join(h.home, ".local", "bin", n), "old link "+n)
		if tgt, err := os.Readlink(filepath.Join(other, n)); err != nil || tgt != h.app.CLI {
			t.Fatalf("%s -> %q, %v", n, tgt, err)
		}
	}
}

// Git may sign through the old ~/.local/bin/nazar-sign-git link
// (gpg.ssh.program). When install removes that link without replacing it
// (the cask's --no-links, or --bin-dir elsewhere) it says where to point
// git now; when the link is replaced in place, or was not nazar's, it
// says nothing.
func TestInstallSaysWhereGitSignsNow(t *testing.T) {
	const hint = "git config --global gpg.ssh.program "
	h := newHarness(t)
	oldInstall(t, h)
	old := filepath.Join(h.home, ".local", "bin", "nazar-sign-git")
	if code := h.run("install", "--no-links"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if !strings.Contains(h.out.String(), "git signs through "+old+"?") || !strings.Contains(h.out.String(), hint+"$(brew --prefix)/bin/nazar-sign-git") {
		t.Fatalf("--no-links must say where git signs now: %q", h.out)
	}

	h = newHarness(t)
	oldInstall(t, h)
	other := filepath.Join(h.home, "brew", "bin")
	if code := h.run("install", "--bin-dir", other); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if !strings.Contains(h.out.String(), hint+filepath.Join(other, "nazar-sign-git")) {
		t.Fatalf("--bin-dir must name its own nazar-sign-git: %q", h.out)
	}

	// Replaced in place: git's path still works.
	h = newHarness(t)
	oldInstall(t, h)
	if code := h.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if strings.Contains(h.out.String(), "gpg.ssh.program") {
		t.Fatalf("a replaced link needs no hint: %q", h.out)
	}

	// The user's own nazar-sign-git stays, so nothing changed for git.
	h = newHarness(t)
	oldInstall(t, h)
	old = filepath.Join(h.home, ".local", "bin", "nazar-sign-git")
	if err := os.Remove(old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte("mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.run("install", "--no-links"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if strings.Contains(h.out.String(), "gpg.ssh.program") {
		t.Fatalf("the user's file was kept; no hint: %q", h.out)
	}
	// --json carries the removed links and nothing of the human hint.
	h = newHarness(t)
	oldInstall(t, h)
	if code := h.run("--json", "install", "--no-links"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if strings.Contains(h.out.String(), "gpg.ssh.program") || strings.Contains(h.out.String(), "brew --prefix") {
		t.Fatalf("the hint is human output only: %s", h.out)
	}
}

// Refusals change nothing: --no-links with --bin-dir is a usage error, and
// a legacy plist path that is not a file is refused before launchd or any
// file is touched.
func TestInstallMigrationRefusals(t *testing.T) {
	h := newHarness(t)
	if code := h.run("install", "--no-links", "--bin-dir", filepath.Join(h.home, "b")); code != 2 {
		t.Fatalf("--no-links --bin-dir: exit %d", code)
	}
	agents := filepath.Join(h.home, "Library", "LaunchAgents")
	if err := os.MkdirAll(filepath.Join(agents, "dev.nazar.plist", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.run("install"); code != 1 || !strings.Contains(h.errb.String(), "is not a LaunchAgent plist") {
		t.Fatalf("legacy plist is a folder: exit %d %q", code, h.errb)
	}
	if code := h.run("uninstall"); code != 1 {
		t.Fatalf("uninstall with a legacy folder: exit %d", code)
	}
	lstatGone(t, filepath.Join(agents, "dev.nazar.agent.plist"), "plist")
	lstatGone(t, filepath.Join(h.home, ".local", "bin", "nazar"), "link")
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
}

// uninstall removes the agent's LaunchAgent and the old one when it is
// still there, and the links into a nazar bundle; keys and config stay.
func TestUninstallRemovesTheNewAndTheOld(t *testing.T) {
	h := newHarness(t)
	legacy := oldInstall(t, h)
	if code := h.run("--json", "uninstall"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if strings.Join(h.launchctl, "|") != "bootout gui/501/dev.nazar.agent|bootout gui/501/dev.nazar" {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	lstatGone(t, legacy, "legacy plist")
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || !inst.Uninstalled || inst.Migrated == nil ||
		inst.Migrated.Label != "dev.nazar" || len(inst.Links) != 2 {
		t.Fatalf("%+v %v", inst, err)
	}
	untouched(t, h)
	// Without an old install, uninstall touches only the agent's label.
	h.launchctl = nil
	if code := h.run("uninstall"); code != 0 || strings.Join(h.launchctl, "|") != "bootout gui/501/dev.nazar.agent" {
		t.Fatalf("exit %d, launchctl %q", code, h.launchctl)
	}
}

// Tests run with NAZAR_LAUNCH_LABEL set, and then the old label is derived
// from it: a test can never boot out the user's real dev.nazar.
func TestLegacyLabelFollowsTheTestLabel(t *testing.T) {
	h := newHarness(t)
	if l := h.a.legacyLabel(); l != "dev.nazar" {
		t.Fatalf("legacy label %q", l)
	}
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test.m6"
	if l := h.a.legacyLabel(); l != "dev.nazar.test.m6.legacy" {
		t.Fatalf("legacy label under a test label: %q", l)
	}
	agents := filepath.Join(h.home, "Library", "LaunchAgents")
	os.MkdirAll(agents, 0o755)
	os.WriteFile(filepath.Join(agents, "dev.nazar.plist"), []byte("<plist/>"), 0o644)
	if code := h.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	for _, c := range h.launchctl {
		if strings.HasSuffix(c, "/dev.nazar") {
			t.Fatalf("a test-labelled install reached dev.nazar: %q", h.launchctl)
		}
	}
	if _, err := os.Stat(filepath.Join(agents, "dev.nazar.plist")); err != nil {
		t.Fatal("a test-labelled install removed dev.nazar.plist")
	}
}

// Test author's additions: attack and edge cases of the migration.

// A legacy plist path that is a symlink (an attacker's, or an old tool's)
// is removed as a link: the file it points at is never written or removed.
// A bootout that fails (nothing loaded) does not stop the migration.
func TestInstallMigrationRemovesASymlinkedLegacyPlistOnly(t *testing.T) {
	h := newHarness(t)
	agents := filepath.Join(h.home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(h.home, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(agents, "dev.nazar.plist")
	if err := os.Symlink(victim, legacy); err != nil {
		t.Fatal(err)
	}
	var calls []string
	h.a.launchctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		switch {
		case args[0] == "print":
			return errors.New("launchctl print: exit status 113: Could not find service")
		case args[0] == "bootout" && args[1] == "gui/501/dev.nazar":
			return errors.New("launchctl bootout gui/501/dev.nazar: exit status 3: No such process")
		}
		return nil
	}
	if code := h.run("--json", "install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.out, h.errb)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "untouched" {
		t.Fatalf("the legacy link's target changed: %q %v", b, err)
	}
	lstatGone(t, legacy, "the legacy plist link")
	if len(calls) == 0 || calls[0] != "bootout gui/501/dev.nazar" {
		t.Fatalf("launchctl %q: the old agent is booted out first", calls)
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.Migrated == nil ||
		inst.Migrated.Label != "dev.nazar" || inst.Migrated.Plist != legacy || inst.Migrated.App != "" {
		t.Fatalf("%+v %v", inst.Migrated, err)
	}
}

// An old agent that does not go is reported, and install stops there: the
// new LaunchAgent is not written or bootstrapped, the old plist and the
// old links stay (so running install again retries the whole migration).
func TestInstallStopsWhenTheOldAgentWillNotGo(t *testing.T) {
	h := newHarness(t)
	legacy := oldInstall(t, h)
	var calls []string
	h.a.launchctl = func(args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "print" && args[1] != "gui/501/dev.nazar" {
			return errors.New("launchctl print: exit status 113: Could not find service")
		}
		return nil // the old agent is always still there
	}
	if code := h.run("install"); code != 1 {
		t.Fatalf("exit %d %s", code, h.out)
	}
	if !strings.Contains(h.errb.String(), "did not stop") || !strings.Contains(h.errb.String(), "launchctl bootout gui/501/dev.nazar") {
		t.Fatalf("stderr %q should say the old agent did not stop and how to stop it", h.errb)
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "bootstrap") || strings.HasSuffix(c, "/dev.nazar.agent") {
			t.Fatalf("launchctl %q: nothing of the new agent may run before the old one is gone", calls)
		}
	}
	if _, err := os.Lstat(legacy); err != nil {
		t.Fatalf("the old plist was removed although its agent still runs: %v", err)
	}
	lstatGone(t, filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist"), "new plist")
	for _, n := range []string{"nazar", "nazar-sign-git"} {
		if tgt, err := os.Readlink(filepath.Join(h.home, ".local", "bin", n)); err != nil || tgt != oldApp+"/Contents/MacOS/nazar" {
			t.Fatalf("%s -> %q, %v: the old link must stay", n, tgt, err)
		}
	}
	untouched(t, h)
}

// A refused link slot with an old install present changes nothing either:
// the old agent is not booted out and its plist and links stay.
func TestInstallRefusalLeavesTheOldInstall(t *testing.T) {
	h := newHarness(t)
	legacy := oldInstall(t, h)
	other := filepath.Join(h.home, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "nazar"), []byte("mine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.run("install", "--bin-dir", other); code != 1 {
		t.Fatalf("exit %d %s", code, h.out)
	}
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	if _, err := os.Lstat(legacy); err != nil {
		t.Fatalf("legacy plist: %v", err)
	}
	for _, n := range []string{"nazar", "nazar-sign-git"} {
		if tgt, err := os.Readlink(filepath.Join(h.home, ".local", "bin", n)); err != nil || tgt != oldApp+"/Contents/MacOS/nazar" {
			t.Fatalf("%s -> %q, %v", n, tgt, err)
		}
	}
	lstatGone(t, filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist"), "new plist")
	untouched(t, h)
}

// Only links into another nazar bundle's CLI are old links: a link in
// ~/.local/bin to anything else (a program named nazar outside a bundle,
// an unrelated tool) is the user's and stays.
func TestInstallElsewhereKeepsForeignLinks(t *testing.T) {
	h := newHarness(t)
	oldInstall(t, h)
	bin := filepath.Join(h.home, ".local", "bin")
	sg := filepath.Join(bin, "nazar-sign-git")
	if err := os.Remove(sg); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/opt/tools/nazar", sg); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(h.home, "brew", "bin")
	if code := h.run("--json", "install", "--bin-dir", other); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	lstatGone(t, filepath.Join(bin, "nazar"), "old link")
	if tgt, err := os.Readlink(sg); err != nil || tgt != "/opt/tools/nazar" {
		t.Fatalf("a foreign link went: %q %v", tgt, err)
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.Migrated == nil ||
		strings.Join(inst.Migrated.Links, "|") != filepath.Join(bin, "nazar") {
		t.Fatalf("%+v %v", inst.Migrated, err)
	}
}

// --no-links is install's only, and never goes with --bin-dir in either
// order or spelling.
func TestNoLinksUsage(t *testing.T) {
	h := newHarness(t)
	b := filepath.Join(h.home, "b")
	for _, args := range [][]string{
		{"install", "--bin-dir", b, "--no-links"},
		{"install", "--no-links", "--bin-dir=" + b},
		{"install", "-no-links", "-bin-dir", b},
		{"uninstall", "--no-links"},
	} {
		if code := h.run(args...); code != 2 {
			t.Errorf("%q: exit %d, want 2 (usage)", args, code)
		}
	}
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}
	lstatGone(t, filepath.Join(h.home, "Library"), "Library")
	lstatGone(t, b, "bin dir")
}

// Under a test label the derived legacy label is what is migrated: its
// plist is booted out and removed, and the real dev.nazar's is not.
func TestLegacyTestLabelIsMigrated(t *testing.T) {
	h := newHarness(t)
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test.m6b"
	agents := filepath.Join(h.home, "Library", "LaunchAgents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"dev.nazar.plist", "dev.nazar.test.m6b.legacy.plist"} {
		if err := os.WriteFile(filepath.Join(agents, n), []byte("<plist/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if code := h.run("--json", "install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	want := "bootout gui/501/dev.nazar.test.m6b.legacy|bootout gui/501/dev.nazar.test.m6b|bootstrap gui/501 " + filepath.Join(agents, "dev.nazar.test.m6b.plist")
	if strings.Join(h.launchctl, "|") != want {
		t.Fatalf("launchctl %q, want %q", h.launchctl, want)
	}
	lstatGone(t, filepath.Join(agents, "dev.nazar.test.m6b.legacy.plist"), "test legacy plist")
	if _, err := os.Stat(filepath.Join(agents, "dev.nazar.plist")); err != nil {
		t.Fatal("a test-labelled install removed dev.nazar.plist")
	}
	var inst Installation
	if err := json.Unmarshal(h.out.Bytes(), &inst); err != nil || inst.Migrated == nil || inst.Migrated.Label != "dev.nazar.test.m6b.legacy" {
		t.Fatalf("%+v %v", inst.Migrated, err)
	}
	// uninstall under the test label also leaves the real dev.nazar alone.
	h.launchctl = nil
	if code := h.run("uninstall", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("uninstall: exit %d %s", code, h.errb)
	}
	for _, c := range h.launchctl {
		if strings.HasSuffix(c, "/dev.nazar") {
			t.Fatalf("a test-labelled uninstall reached dev.nazar: %q", h.launchctl)
		}
	}
	if _, err := os.Stat(filepath.Join(agents, "dev.nazar.plist")); err != nil {
		t.Fatal("a test-labelled uninstall removed dev.nazar.plist")
	}
}

// uninstall's human view names the old LaunchAgent it removed, and says
// what it kept.
func TestUninstallHumanViewNamesTheOldAgent(t *testing.T) {
	h := newHarness(t)
	oldInstall(t, h)
	if code := h.run("uninstall"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	for _, want := range []string{"uninstalled dev.nazar.agent", "removed the old LaunchAgent dev.nazar", "kept "} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("stdout lacks %q: %q", want, h.out)
		}
	}
	untouched(t, h)
}
