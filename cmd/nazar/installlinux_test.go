package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/peertrust"
	linuxfiles "github.com/atas/nazar/packaging/linux"
)

// These tests drive `nazar install` on Linux through a.linux and seams, so
// they run on every OS, and nothing here runs systemctl, udevadm, usermod,
// groupadd or sudo, or opens a TPM.

const (
	testPolicyRel = "usr/share/polkit-1/actions/dev.nazar.authenticate.policy"
	testRuleRel   = "etc/udev/rules.d/70-nazar-tpm.rules"
)

// linuxInstall is a Linux-mode harness whose seams record: a CLI and an
// agent in a plain folder, a temporary system root holding the polkit
// action, a TPM that opens, and a user service manager that starts a stub
// agent on `restart`, so a status request proves the wait came after it.
type linuxInstall struct {
	*harness
	t         *testing.T
	cli       string
	agent     string
	sysRoot   string
	systemctl []string
	sys       []string
	// sysFail names the commands (by argv0) that fail, failOnCall the
	// systemctl call that does; noAgent: restart starts no agent.
	sysFail    map[string]bool
	failOnCall string
	noAgent    bool
	agentUp    bool
}

func newLinuxInstall(t *testing.T) *linuxInstall {
	t.Helper()
	h := linuxHarness(t)
	l := &linuxInstall{harness: h, t: t, sysFail: map[string]bool{}}
	root, err := filepath.EvalSymlinks(h.home)
	if err != nil {
		t.Fatal(err)
	}
	l.cli, l.agent = l.programs(filepath.Join(root, "opt", "nazar-1.0"))
	l.sysRoot = filepath.Join(root, "sysroot")
	l.writeInstalledPolicy("unix-user:alice")
	h.a.sysRoot = l.sysRoot
	h.a.executable = func() (string, error) { return l.cli, nil }
	h.a.euid = func() int { return 1000 }
	h.a.tpmAccess = func() error { return nil }
	h.a.systemctl = func(args ...string) error {
		call := strings.Join(args, " ")
		l.systemctl = append(l.systemctl, call)
		if call == l.failOnCall {
			return errors.New("systemctl " + call + ": exit status 1: boom")
		}
		if args[0] == "restart" && !l.noAgent && !l.agentUp {
			l.agentUp = true
			l.startAgent()
		}
		return nil
	}
	h.a.sysCommand = func(argv0 string, args ...string) error {
		l.sys = append(l.sys, strings.Join(append([]string{argv0}, args...), " "))
		if l.sysFail[argv0] {
			return errors.New(argv0 + ": exit status 2")
		}
		return nil
	}
	return l
}

func (l *linuxInstall) startAgent() {
	l.serve(l.t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
}

// programs writes a nazar and a nazar-agent in dir, with different bytes.
func (l *linuxInstall) programs(dir string) (cli, agent string) {
	l.t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		l.t.Fatal(err)
	}
	cli, agent = filepath.Join(dir, "nazar"), filepath.Join(dir, "nazar-agent")
	if err := os.WriteFile(cli, []byte("the cli "+dir), 0o755); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(agent, []byte("the agent "+dir), 0o755); err != nil {
		l.t.Fatal(err)
	}
	return cli, agent
}

func (l *linuxInstall) writeInstalledPolicy(owners string) {
	l.t.Helper()
	p := filepath.Join(l.sysRoot, testPolicyRel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		l.t.Fatal(err)
	}
	data := strings.ReplaceAll(string(packagingFile(l.t, "dev.nazar.authenticate.policy")), "@NAZAR_OWNERS@", owners)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		l.t.Fatal(err)
	}
}

func (l *linuxInstall) unitPath() string {
	return filepath.Join(l.home, ".config", "systemd", "user", "nazar-agent.service")
}

func (l *linuxInstall) binDir() string { return filepath.Join(l.home, ".local", "bin") }

// wroteNothing: no unit, no ~/.nazar, no links and no systemctl call.
func (l *linuxInstall) wroteNothing() {
	l.t.Helper()
	for _, p := range []string{filepath.Join(l.home, ".config"), layout.Root(l.home), filepath.Join(l.home, ".local")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			l.t.Errorf("%s was written (%v)", p, err)
		}
	}
	if len(l.systemctl) != 0 {
		l.t.Errorf("systemctl ran: %q", l.systemctl)
	}
}

// packagingFile is a file of packaging/linux, as the repository has it.
func packagingFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "packaging", "linux", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLinuxFilesAreThePackagingFiles(t *testing.T) {
	if got, want := string(linuxfiles.Policy), string(packagingFile(t, "dev.nazar.authenticate.policy")); got != want {
		t.Fatalf("embedded policy differs:\n%s", got)
	}
	if got, want := string(linuxfiles.UdevRule), string(packagingFile(t, "70-nazar-tpm.rules")); got != want {
		t.Fatalf("embedded rule differs:\n%s", got)
	}
	if !strings.Contains(string(packagingFile(t, "dev.nazar.authenticate.policy")), ">"+linuxfiles.OwnerPlaceholder+"<") {
		t.Fatalf("placeholder %q is not the file's", linuxfiles.OwnerPlaceholder)
	}
}

func TestLinuxInstallWritesUnit(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	want := `[Unit]
Description=nazar agent (SSH keys, secrets and credentials in the TPM)
PartOf=graphical-session.target
After=graphical-session.target

[Service]
ExecStart=` + l.agent + `
Restart=on-failure
RestartSec=2

[Install]
WantedBy=graphical-session.target
`
	got, err := os.ReadFile(l.unitPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("unit:\n%s\nwant:\n%s", got, want)
	}
	fi, err := os.Stat(l.unitPath())
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("unit mode %v %v", fi.Mode(), err)
	}
	// Nothing of launchd on Linux.
	if len(l.launchctl) != 0 {
		t.Fatalf("launchctl ran: %q", l.launchctl)
	}
	if _, err := os.Lstat(filepath.Join(l.home, "Library")); err == nil {
		t.Fatal("a LaunchAgents folder was written")
	}
}

func TestLinuxInstallRecordsHashes(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	rec, err := peertrust.Read(l.home)
	if err != nil {
		t.Fatal(err)
	}
	cliHash, err := peertrust.HashFile(l.cli)
	if err != nil {
		t.Fatal(err)
	}
	agentHash, err := peertrust.HashFile(l.agent)
	if err != nil {
		t.Fatal(err)
	}
	want := peertrust.Record{CLI: peertrust.Binary{Path: l.cli, SHA256: cliHash}, Agent: peertrust.Binary{Path: l.agent, SHA256: agentHash}}
	if rec != want {
		t.Fatalf("record %+v, want %+v", rec, want)
	}
	if cliHash == agentHash {
		t.Fatal("the fixture's programs are the same")
	}
	// An agent reached through a link is recorded, and started, as its real
	// file: what the kernel reports for the process and what the unit runs.
	real := filepath.Join(filepath.Dir(filepath.Dir(l.cli)), "real-agent")
	if err := os.Rename(l.agent, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, l.agent); err != nil {
		t.Fatal(err)
	}
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if rec, err = peertrust.Read(l.home); err != nil || rec.Agent.Path != real || rec.Agent.SHA256 != agentHash {
		t.Fatalf("record %+v %v", rec, err)
	}
	if b, _ := os.ReadFile(l.unitPath()); !strings.Contains(string(b), "ExecStart="+real+"\n") {
		t.Fatalf("unit:\n%s", b)
	}
}

func TestLinuxInstallSystemctlOrder(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	want := []string{"daemon-reload", "enable nazar-agent.service", "restart nazar-agent.service", "is-active graphical-session.target"}
	if strings.Join(l.systemctl, "|") != strings.Join(want, "|") {
		t.Fatalf("systemctl %q, want %q", l.systemctl, want)
	}
	// The stub agent starts on restart, so this request came after it.
	r := l.requests()
	if len(r) != 1 || r[0].Command != control.CmdStatus {
		t.Fatalf("requests %+v", r)
	}
	if !strings.Contains(l.out.String(), "nazar-agent.service") {
		t.Fatalf("output %q", l.out)
	}
	if strings.Contains(l.out.String(), "warning") {
		t.Fatalf("the target is active, yet install warns:\n%s", l.out)
	}
}

// The unit is started at login by graphical-session.target, and desktops
// such as Xfce, MATE, sway, i3 and Hyprland may never activate it. install
// started the agent itself, so everything looks fine until the next login:
// it warns, and still exits 0, when the target is not active in this
// session.
func TestLinuxInstallWarnsWithoutGraphicalSessionTarget(t *testing.T) {
	l := newLinuxInstall(t)
	l.failOnCall = "is-active graphical-session.target"
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	const want = "  warning: graphical-session.target is not active in this session, so nothing starts nazar-agent.service at your next login (GNOME and KDE activate it; Xfce, MATE, sway, i3 and Hyprland may not); start it then with: systemctl --user start nazar-agent.service\n"
	if !strings.Contains(l.out.String(), want) {
		t.Fatalf("output lacks the warning:\n%s", l.out)
	}
	if !strings.HasPrefix(l.out.String(), "installed ") {
		t.Fatalf("the install itself is not reported:\n%s", l.out)
	}
	l = newLinuxInstall(t)
	l.failOnCall = "is-active graphical-session.target"
	if code := l.run("--json", "install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	var out LinuxInstallation
	if err := json.Unmarshal(l.out.Bytes(), &out); err != nil {
		t.Fatalf("%v:\n%s", err, l.out)
	}
	if out.Warning != strings.TrimSuffix(strings.TrimPrefix(want, "  warning: "), "\n") {
		t.Fatalf("warning field %q", out.Warning)
	}
}

func TestLinuxInstallWaitsForTheAgent(t *testing.T) {
	// It never answers: install says so after 10 s.
	l := newLinuxInstall(t)
	l.noAgent = true
	var slept time.Duration
	l.a.sleep = func(d time.Duration) { slept += d }
	if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "journalctl --user -u nazar-agent.service") {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	if slept != 10*time.Second {
		t.Fatalf("waited %v, want 10s", slept)
	}
	// It comes up a while after the restart: install waits for it.
	l = newLinuxInstall(t)
	l.noAgent = true
	slept = 0
	l.a.sleep = func(d time.Duration) {
		slept += d
		if slept == 2*time.Second {
			l.startAgent()
		}
	}
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	if slept != 2*time.Second {
		t.Fatalf("waited %v", slept)
	}
}

func TestLinuxInstallSystemctlFails(t *testing.T) {
	for _, call := range []string{"daemon-reload", "enable nazar-agent.service", "restart nazar-agent.service"} {
		l := newLinuxInstall(t)
		l.failOnCall = call
		if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "boom") {
			t.Fatalf("%s: exit %d %q", call, code, l.errb)
		}
		if l.systemctl[len(l.systemctl)-1] != call {
			t.Fatalf("%s: went on: %q", call, l.systemctl)
		}
	}
}

func TestLinuxInstallLinks(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("--json", "install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	for _, n := range []string{"nazar", "nazar-sign-git", "git-credential-nazar"} {
		if tgt, err := os.Readlink(filepath.Join(l.binDir(), n)); err != nil || tgt != l.cli {
			t.Fatalf("%s -> %q, %v", n, tgt, err)
		}
	}
	var inst LinuxInstallation
	if err := json.Unmarshal(l.out.Bytes(), &inst); err != nil || inst.Kind != "Installation" || inst.Unit != "nazar-agent.service" ||
		inst.UnitFile != l.unitPath() || inst.Agent != l.agent || len(inst.Links) != 3 || inst.PathHint == "" {
		t.Fatalf("%+v %v", inst, err)
	}
	// Again: links to this CLI are replaced, not refused.
	if code := l.run("install"); code != 0 {
		t.Fatalf("second install: exit %d %s", code, l.errb)
	}
	// An upgrade: the CLI moved to a new version's folder, and the links
	// point at the old one, which may be gone by now.
	l.cli, l.agent = l.programs(filepath.Join(filepath.Dir(filepath.Dir(l.cli)), "nazar-2.0"))
	if code := l.run("install"); code != 0 {
		t.Fatalf("upgrade: exit %d %s", code, l.errb)
	}
	for _, n := range []string{"nazar", "nazar-sign-git", "git-credential-nazar"} {
		if tgt, err := os.Readlink(filepath.Join(l.binDir(), n)); err != nil || tgt != l.cli {
			t.Fatalf("upgrade: %s -> %q, %v", n, tgt, err)
		}
	}
	// A folder of its own.
	other := filepath.Join(l.home, "bin")
	if code := l.run("install", "--bin-dir", other); code != 0 {
		t.Fatalf("--bin-dir: exit %d %s", code, l.errb)
	}
	if tgt, err := os.Readlink(filepath.Join(other, "nazar")); err != nil || tgt != l.cli {
		t.Fatalf("--bin-dir: %q %v", tgt, err)
	}
	if code := l.run("install", "--bin-dir", "rel"); code != control.ExitUsage {
		t.Fatalf("relative --bin-dir: exit %d", code)
	}
}

// What is at a link's place and isn't nazar's is the user's: install says
// so before it writes anything.
func TestLinuxInstallNeverClobbersTheUsersFiles(t *testing.T) {
	for name, mk := range map[string]func(p string) error{
		"a file":          func(p string) error { return os.WriteFile(p, []byte("my script"), 0o755) },
		"a foreign link":  func(p string) error { return os.Symlink("/usr/local/bin/other", p) },
		"a relative link": func(p string) error { return os.Symlink("nazar", p) },
	} {
		l := newLinuxInstall(t)
		if err := os.MkdirAll(l.binDir(), 0o755); err != nil {
			t.Fatal(err)
		}
		mine := filepath.Join(l.binDir(), "nazar-sign-git")
		if err := mk(mine); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Lstat(mine)
		if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "not a nazar link") {
			t.Fatalf("%s: exit %d %q", name, code, l.errb)
		}
		after, err := os.Lstat(mine)
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("%s: it changed: %v", name, err)
		}
		for _, p := range []string{l.unitPath(), layout.Root(l.home), filepath.Join(l.binDir(), "nazar")} {
			if _, err := os.Lstat(p); err == nil {
				t.Fatalf("%s: %s was written", name, p)
			}
		}
		if len(l.systemctl) != 0 {
			t.Fatalf("%s: systemctl %q", name, l.systemctl)
		}
	}
}

func TestLinuxInstallNoLinks(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("--json", "install", "--no-links"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if _, err := os.Lstat(l.binDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bin folder: %v", err)
	}
	var inst LinuxInstallation
	if err := json.Unmarshal(l.out.Bytes(), &inst); err != nil || inst.Links == nil || len(inst.Links) != 0 || inst.PathHint != "" {
		t.Fatalf("%s %v", l.out, err)
	}
	if code := l.run("install", "--no-links", "--bin-dir", "/x"); code != control.ExitUsage {
		t.Fatalf("--no-links --bin-dir: exit %d", code)
	}
}

func TestInstallRefusesWithoutTPMAccess(t *testing.T) {
	l := newLinuxInstall(t)
	l.a.tpmAccess = func() error { return errors.New("open /dev/tpmrm0: permission denied") }
	want := "nazar: install: can't use the TPM yet: run once, then log out and back in: sudo " + l.cli + " install --system\n"
	if code := l.run("install"); code != control.ExitError || l.errb.String() != want {
		t.Fatalf("exit %d\n%q\nwant\n%q", code, l.errb, want)
	}
	l.wroteNothing()
}

func TestLinuxInstallRefusesWithoutPolicy(t *testing.T) {
	l := newLinuxInstall(t)
	if err := os.Remove(filepath.Join(l.sysRoot, testPolicyRel)); err != nil {
		t.Fatal(err)
	}
	want := "nazar: install: can't use the TPM yet: run once, then log out and back in: sudo " + l.cli + " install --system\n"
	if code := l.run("install"); code != control.ExitError || l.errb.String() != want {
		t.Fatalf("exit %d\n%q\nwant\n%q", code, l.errb, want)
	}
	l.wroteNothing()
}

func TestLinuxInstallRefusesAsRoot(t *testing.T) {
	l := newLinuxInstall(t)
	l.a.euid = func() int { return 0 }
	if code := l.run("install"); code != control.ExitError || !strings.HasPrefix(l.errb.String(), "nazar: install: run it as yourself") {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	l.wroteNothing()
}

func TestLinuxInstallRefusesOddAgentPath(t *testing.T) {
	for _, dir := range []string{"with space", "per%cent", "dol$lar", "new\nline", "sem;i", "qu\"ote"} {
		l := newLinuxInstall(t)
		l.cli, l.agent = l.programs(filepath.Join(filepath.Dir(filepath.Dir(l.cli)), dir))
		if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "can't be written into a systemd unit") {
			t.Fatalf("%q: exit %d %q", dir, code, l.errb)
		}
		l.wroteNothing()
	}
	// The same goes for where a link to the agent really leads.
	l := newLinuxInstall(t)
	odd := filepath.Join(filepath.Dir(filepath.Dir(l.cli)), "with space")
	if err := os.MkdirAll(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(odd, "nazar-agent")
	if err := os.Rename(l.agent, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, l.agent); err != nil {
		t.Fatal(err)
	}
	if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "can't be written into a systemd unit") {
		t.Fatalf("link: exit %d %q", code, l.errb)
	}
	l.wroteNothing()
}

func TestLinuxInstallNeedsTheAgentNextToIt(t *testing.T) {
	l := newLinuxInstall(t)
	if err := os.Remove(l.agent); err != nil {
		t.Fatal(err)
	}
	if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "no nazar-agent next to "+l.cli) {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	l.wroteNothing()
	// A program of another name would make links install can't recognize
	// again.
	l = newLinuxInstall(t)
	other := filepath.Join(filepath.Dir(l.cli), "other")
	if err := os.Rename(l.cli, other); err != nil {
		t.Fatal(err)
	}
	l.cli = other
	if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "named nazar") {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	l.wroteNothing()
}

// A nil seam refuses the command, as a nil launchctl does.
func TestLinuxInstallNilSeamsRefuse(t *testing.T) {
	for name, clear := range map[string]func(a *app){
		"systemctl": func(a *app) { a.systemctl = nil },
		"tpmAccess": func(a *app) { a.tpmAccess = nil },
		"euid":      func(a *app) { a.euid = nil },
	} {
		l := newLinuxInstall(t)
		clear(l.a)
		if code := l.run("install"); code != control.ExitError || !strings.Contains(l.errb.String(), "not available in this build") {
			t.Fatalf("%s: exit %d %q", name, code, l.errb)
		}
		l.wroteNothing()
	}
	for name, clear := range map[string]func(a *app){
		"sysCommand": func(a *app) { a.sysCommand = nil },
		"euid":       func(a *app) { a.euid = nil },
	} {
		l := newLinuxInstall(t)
		l.env["SUDO_USER"] = "bob"
		l.a.euid = func() int { return 0 }
		clear(l.a)
		if code := l.run("install", "--system"); code != control.ExitError || !strings.Contains(l.errb.String(), "not available in this build") {
			t.Fatalf("--system %s: exit %d %q", name, code, l.errb)
		}
	}
}

func TestLinuxUninstall(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	rec := peertrust.File(l.home)
	before, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	// Not ours, in the same folder: stays.
	mine := filepath.Join(l.binDir(), "mine")
	if err := os.Symlink(l.cli, mine); err != nil {
		t.Fatal(err)
	}
	l.systemctl = nil
	if code := l.run("--json", "uninstall"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if want := "disable --now nazar-agent.service"; strings.Join(l.systemctl, "|") != want {
		t.Fatalf("systemctl %q, want %q", l.systemctl, want)
	}
	if _, err := os.Lstat(l.unitPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit: %v", err)
	}
	for _, n := range []string{"nazar", "nazar-sign-git", "git-credential-nazar"} {
		if _, err := os.Lstat(filepath.Join(l.binDir(), n)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v", n, err)
		}
	}
	if _, err := os.Lstat(mine); err != nil {
		t.Fatalf("another link went: %v", err)
	}
	// ~/.nazar stays, whole.
	if after, err := os.ReadFile(rec); err != nil || string(after) != string(before) {
		t.Fatalf("the record changed: %v", err)
	}
	var inst LinuxInstallation
	if err := json.Unmarshal(l.out.Bytes(), &inst); err != nil || !inst.Uninstalled || inst.Kind != "Installation" || len(inst.Links) != 3 || len(inst.Kept) != 1 || inst.Kept[0] != layout.Root(l.home) {
		t.Fatalf("%s %v", l.out, err)
	}
	// Again, with nothing left: systemctl knows no such unit; that is fine.
	l.failOnCall = "disable --now nazar-agent.service"
	if code := l.run("uninstall"); code != 0 {
		t.Fatalf("second uninstall: exit %d %s", code, l.errb)
	}
}

// A foreign link in the bin folder is the user's, under uninstall too.
func TestLinuxUninstallLeavesTheUsersLinks(t *testing.T) {
	l := newLinuxInstall(t)
	if err := os.MkdirAll(l.binDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(l.binDir(), "nazar")
	if err := os.Symlink("/usr/local/bin/other", mine); err != nil {
		t.Fatal(err)
	}
	if code := l.run("uninstall"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if tgt, err := os.Readlink(mine); err != nil || tgt != "/usr/local/bin/other" {
		t.Fatalf("%q %v", tgt, err)
	}
}

// An agent that could not be stopped is still running: uninstall says so
// and removes nothing, so running it again in a session can finish the job.
func TestLinuxUninstallKeepsWhatItCouldNotStop(t *testing.T) {
	l := newLinuxInstall(t)
	if code := l.run("install"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	l.failOnCall = "disable --now nazar-agent.service"
	if code := l.run("uninstall"); code != control.ExitError || !strings.Contains(l.errb.String(), "boom") {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	if _, err := os.Lstat(l.unitPath()); err != nil {
		t.Fatalf("unit: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(l.binDir(), "nazar")); err != nil {
		t.Fatalf("link: %v", err)
	}
}

func TestLinuxUninstallRefuses(t *testing.T) {
	l := newLinuxInstall(t)
	l.a.euid = func() int { return 0 }
	if code := l.run("uninstall"); code != control.ExitError || !strings.HasPrefix(l.errb.String(), "nazar: uninstall: run it as yourself") {
		t.Fatalf("root: exit %d %q", code, l.errb)
	}
	if len(l.systemctl) != 0 {
		t.Fatalf("systemctl %q", l.systemctl)
	}
	l = newLinuxInstall(t)
	l.a.systemctl = nil
	if code := l.run("uninstall"); code != control.ExitError || !strings.Contains(l.errb.String(), "not available in this build") {
		t.Fatalf("nil seam: exit %d %q", code, l.errb)
	}
}

// installedOwners is the installed policy's owner annotation.
func installedOwners(t *testing.T, l *linuxInstall) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l.sysRoot, testPolicyRel))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`<annotate key="org.freedesktop.policykit.owner">([^<]*)</annotate>`).FindSubmatch(b)
	if m == nil {
		t.Fatalf("no owner in\n%s", b)
	}
	return string(m[1])
}

// systemHarness is a root run through sudo, on a system root with nothing
// of nazar's in it.
func systemHarness(t *testing.T, user string) *linuxInstall {
	t.Helper()
	l := newLinuxInstall(t)
	if err := os.RemoveAll(l.sysRoot); err != nil {
		t.Fatal(err)
	}
	l.a.euid = func() int { return 0 }
	l.env["SUDO_USER"] = user
	return l
}

func TestInstallSystemWritesFiles(t *testing.T) {
	l := systemHarness(t, "bob")
	if code := l.run("install", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if want := "done; log out and back in, then run as yourself: nazar install\n"; l.out.String() != want {
		t.Fatalf("output %q, want %q", l.out, want)
	}
	rule, err := os.ReadFile(filepath.Join(l.sysRoot, testRuleRel))
	if err != nil {
		t.Fatal(err)
	}
	if string(rule) != string(packagingFile(t, "70-nazar-tpm.rules")) {
		t.Fatalf("rule:\n%s", rule)
	}
	policy, err := os.ReadFile(filepath.Join(l.sysRoot, testPolicyRel))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.ReplaceAll(string(packagingFile(t, "dev.nazar.authenticate.policy")), "@NAZAR_OWNERS@", "unix-user:bob"); string(policy) != want {
		t.Fatalf("policy:\n%s\nwant:\n%s", policy, want)
	}
	if strings.Contains(string(policy), "@NAZAR_OWNERS@") {
		t.Fatalf("placeholder left in:\n%s", policy)
	}
	for _, rel := range []string{testPolicyRel, testRuleRel} {
		fi, err := os.Stat(filepath.Join(l.sysRoot, rel))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s: %v %v", rel, fi.Mode(), err)
		}
	}
	want := []string{
		"/usr/bin/getent group tss",
		"/usr/sbin/usermod -aG tss bob",
		"/usr/bin/udevadm control --reload-rules",
		"/usr/bin/udevadm trigger --subsystem-match=tpmrm --action=change",
	}
	if strings.Join(l.sys, "|") != strings.Join(want, "|") {
		t.Fatalf("commands %q, want %q", l.sys, want)
	}
	// Nothing of the user's: that is `nazar install`'s.
	l.wroteNothing()

	// No tss group yet: groupadd, before usermod.
	l = systemHarness(t, "bob")
	l.sysFail["/usr/bin/getent"] = true
	if code := l.run("install", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	want = []string{
		"/usr/bin/getent group tss",
		"/usr/sbin/groupadd --system tss",
		"/usr/sbin/usermod -aG tss bob",
		"/usr/bin/udevadm control --reload-rules",
		"/usr/bin/udevadm trigger --subsystem-match=tpmrm --action=change",
	}
	if strings.Join(l.sys, "|") != strings.Join(want, "|") {
		t.Fatalf("commands %q, want %q", l.sys, want)
	}
}

func TestInstallSystemCommandFails(t *testing.T) {
	for _, argv0 := range []string{"/usr/sbin/usermod", "/usr/bin/udevadm"} {
		l := systemHarness(t, "bob")
		l.sysFail[argv0] = true
		if code := l.run("install", "--system"); code != control.ExitError || !strings.Contains(l.errb.String(), argv0) || strings.Contains(l.out.String(), "done") {
			t.Fatalf("%s: exit %d out %q err %q", argv0, code, l.out, l.errb)
		}
	}
	// getent says no group, and groupadd can't make one.
	l := systemHarness(t, "bob")
	l.sysFail["/usr/bin/getent"] = true
	l.sysFail["/usr/sbin/groupadd"] = true
	if code := l.run("install", "--system"); code != control.ExitError || !strings.Contains(l.errb.String(), "groupadd") {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	for _, c := range l.sys {
		if strings.Contains(c, "usermod") {
			t.Fatalf("went on: %q", l.sys)
		}
	}
}

func TestInstallSystemAddsOwner(t *testing.T) {
	l := systemHarness(t, "bob")
	l.writeInstalledPolicy("unix-user:alice")
	if code := l.run("install", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if got := installedOwners(t, l); got != "unix-user:alice unix-user:bob" {
		t.Fatalf("owners %q", got)
	}
	// Again as bob: unchanged.
	p := filepath.Join(l.sysRoot, testPolicyRel)
	first, _ := os.ReadFile(p)
	if code := l.run("install", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if after, _ := os.ReadFile(p); string(after) != string(first) {
		t.Fatalf("changed:\n%s", after)
	}
	// Only the owner list of the installed file is kept: a default someone
	// edited to `yes` goes.
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(string(first), "auth_self", "yes")), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := l.run("install", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	if after, _ := os.ReadFile(p); string(after) != string(first) {
		t.Fatalf("kept more than the owners:\n%s", after)
	}
}

func TestInstallSystemRefusesPlaceholder(t *testing.T) {
	// PolicyFor itself.
	for _, owners := range [][]string{
		nil,
		{},
		{"bob"},
		{"unix-user:"},
		{"unix-group:wheel"},
		{"unix-user:Bob"},
		{"unix-user:-bob"},
		{"unix-user:bob jim"},
		{"unix-user:bob\n"},
		{"unix-user:bob</annotate>"},
		{"unix-user:alice", "@NAZAR_OWNERS@"},
	} {
		if b, err := linuxfiles.PolicyFor(owners); err == nil {
			t.Errorf("PolicyFor(%q) = %s", owners, b)
		}
	}
	if b, err := linuxfiles.PolicyFor([]string{"unix-user:alice", "unix-user:bob_2"}); err != nil ||
		!strings.Contains(string(b), ">unix-user:alice unix-user:bob_2<") || strings.Contains(string(b), linuxfiles.OwnerPlaceholder) {
		t.Fatalf("PolicyFor: %s %v", b, err)
	}

	refused := func(t *testing.T, l *linuxInstall) {
		t.Helper()
		if code := l.run("install", "--system"); code != control.ExitError {
			t.Fatalf("exit %d", code)
		}
		if _, err := os.Lstat(filepath.Join(l.sysRoot, testRuleRel)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rule: %v", err)
		}
		if len(l.sys) != 0 {
			t.Fatalf("commands ran: %q", l.sys)
		}
	}
	// A sudo user whose name is not one polkit can be told.
	t.Run("odd user", func(t *testing.T) {
		l := systemHarness(t, "Bob;rm")
		refused(t, l)
		if _, err := os.Lstat(filepath.Join(l.sysRoot, testPolicyRel)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("policy: %v", err)
		}
	})
	// A shipped file without the placeholder.
	t.Run("no placeholder in the file", func(t *testing.T) {
		old := linuxfiles.Policy
		linuxfiles.Policy = []byte("<policyconfig></policyconfig>")
		t.Cleanup(func() { linuxfiles.Policy = old })
		if b, err := linuxfiles.PolicyFor([]string{"unix-user:bob"}); err == nil {
			t.Fatalf("PolicyFor: %s", b)
		}
		l := systemHarness(t, "bob")
		refused(t, l)
		if _, err := os.Lstat(filepath.Join(l.sysRoot, testPolicyRel)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("policy: %v", err)
		}
	})
	// An installed file nazar can't read the owners of: adding to the list
	// would drop them, so it stops and leaves it.
	for name, body := range map[string]string{
		"placeholder left in": string(linuxfiles.Policy),
		"a group owner":       strings.ReplaceAll(string(linuxfiles.Policy), "@NAZAR_OWNERS@", "unix-group:wheel"),
		"not XML":             "<policyconfig><action",
	} {
		t.Run(name, func(t *testing.T) {
			l := systemHarness(t, "bob")
			p := filepath.Join(l.sysRoot, testPolicyRel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			refused(t, l)
			if !strings.Contains(l.errb.String(), p) {
				t.Fatalf("does not name the file: %q", l.errb)
			}
			if after, _ := os.ReadFile(p); string(after) != body {
				t.Fatalf("the file changed:\n%s", after)
			}
		})
	}
}

func TestInstallSystemNeedsSudo(t *testing.T) {
	const want = "nazar: install --system: run it with sudo\n"
	for name, setup := range map[string]func(l *linuxInstall){
		"not root":       func(l *linuxInstall) { l.a.euid = func() int { return 1000 } },
		"no sudo user":   func(l *linuxInstall) { delete(l.env, "SUDO_USER") },
		"root from root": func(l *linuxInstall) { l.env["SUDO_USER"] = "root" },
	} {
		l := systemHarness(t, "bob")
		setup(l)
		if code := l.run("install", "--system"); code != control.ExitError || l.errb.String() != want {
			t.Fatalf("%s: exit %d %q", name, code, l.errb)
		}
		if _, err := os.Lstat(l.sysRoot); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: wrote under the system root: %v", name, err)
		}
		if len(l.sys) != 0 {
			t.Fatalf("%s: commands ran: %q", name, l.sys)
		}
	}
	// --system takes no other flag.
	l := systemHarness(t, "bob")
	for _, args := range [][]string{{"install", "--system", "--no-links"}, {"install", "--system", "--bin-dir", "/x"}, {"uninstall", "--system", "--bin-dir", "/x"}} {
		if code := l.run(args...); code != control.ExitUsage {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}

func TestUninstallSystem(t *testing.T) {
	l := systemHarness(t, "bob")
	if code := l.run("install", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	l.sys = nil
	// Not root: nothing goes.
	l.a.euid = func() int { return 1000 }
	if code := l.run("uninstall", "--system"); code != control.ExitError || l.errb.String() != "nazar: uninstall --system: run it with sudo\n" {
		t.Fatalf("exit %d %q", code, l.errb)
	}
	if _, err := os.Lstat(filepath.Join(l.sysRoot, testPolicyRel)); err != nil {
		t.Fatal(err)
	}
	l.a.euid = func() int { return 0 }
	if code := l.run("--json", "uninstall", "--system"); code != 0 {
		t.Fatalf("exit %d %s", code, l.errb)
	}
	for _, rel := range []string{testPolicyRel, testRuleRel} {
		if _, err := os.Lstat(filepath.Join(l.sysRoot, rel)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: %v", rel, err)
		}
	}
	if len(l.sys) != 0 {
		t.Fatalf("commands ran: %q", l.sys)
	}
	var out SystemInstallation
	if err := json.Unmarshal(l.out.Bytes(), &out); err != nil || !out.Uninstalled || out.Kind != "SystemInstallation" {
		t.Fatalf("%s %v", l.out, err)
	}
	// Again, with nothing there: fine.
	if code := l.run("uninstall", "--system"); code != 0 {
		t.Fatalf("second: exit %d %s", code, l.errb)
	}
}

// --system is Linux's: a macOS CLI has no such flag, in its parser or its
// help, and takes no step of it.
func TestInstallSystemIsLinuxOnly(t *testing.T) {
	h := newHarness(t)
	h.a.sysCommand = func(string, ...string) error { t.Fatal("a system command ran on macOS"); return nil }
	h.env["SUDO_USER"] = "bob"
	for _, cmd := range []string{"install", "uninstall"} {
		if code := h.run(cmd, "--system"); code != control.ExitUsage {
			t.Fatalf("%s: exit %d %q", cmd, code, h.errb)
		}
		if code := h.run(cmd, "--help"); code != 0 || strings.Contains(h.out.String(), "--system") || strings.Contains(h.out.String(), "systemd") {
			t.Fatalf("%s help: exit %d\n%s", cmd, code, h.out)
		}
	}
	if len(h.launchctl) != 0 {
		t.Fatalf("launchctl %q", h.launchctl)
	}

	l := newLinuxInstall(t)
	for _, cmd := range []string{"install", "uninstall"} {
		if code := l.run(cmd, "--help"); code != 0 || !strings.Contains(l.out.String(), "--system") || !strings.Contains(l.out.String(), "systemd") || strings.Contains(l.out.String(), "LaunchAgent") || strings.Contains(l.out.String(), "Keychain") {
			t.Fatalf("%s help: exit %d\n%s", cmd, code, l.out)
		}
	}
	if code := l.run("help"); code != 0 || !strings.Contains(l.out.String(), "--system") {
		t.Fatalf("help: exit %d\n%s", code, l.out)
	}
}

func TestRunSysCommandNeedsAbsolutePath(t *testing.T) {
	if err := runSysCommand("getent", "group", "tss"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err %v", err)
	}
}
