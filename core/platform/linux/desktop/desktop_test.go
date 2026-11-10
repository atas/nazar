//go:build linux

package desktop

import (
	"crypto/sha256"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

const testID = "dev.nazar.TestApp"

// entryFor is a plain desktop entry whose Exec is exe.
func entryFor(exe string) string {
	return "[Desktop Entry]\nType=Application\nName=Test App\nExec=" + exe + " %U\n"
}

// writeEntry writes <dataDir>/applications/<id>.desktop.
func writeEntry(t *testing.T, dataDir, id, body string) {
	t.Helper()
	dir := filepath.Join(dataDir, "applications")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".desktop"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sleepPath() string {
	p, err := exec.LookPath("sleep")
	if err != nil {
		return "/bin/sleep"
	}
	return p
}

// TestMain lets a copy of this test binary stand for an installed program:
// run with a number of seconds and nothing else, it sleeps that long. The
// system's own sleep can't be copied under another name everywhere (a
// multi-call binary, as on Ubuntu 26.04, goes by the name it is run as).
func TestMain(m *testing.M) {
	if len(os.Args) == 2 {
		if secs, err := strconv.Atoi(os.Args[1]); err == nil {
			time.Sleep(time.Duration(secs) * time.Second)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// copySleep writes a program that sleeps (a copy of this test binary, see
// TestMain) to <dir>/<name> and returns its path with links resolved, as
// /proc/<pid>/exe names it. No fork may happen while the copy is open for
// writing, or running it fails with "text file busy".
func copySleep(t *testing.T, dir, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	syscall.ForkLock.RLock()
	err = os.WriteFile(path, data, 0o755)
	syscall.ForkLock.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	if path, err = filepath.EvalSymlinks(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// startRunning starts argv and waits until the process runs the file
// want (a launcher such as env execs it after a moment). The process is
// killed and reaped at cleanup.
func startRunning(t *testing.T, want string, argv ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	link := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe")
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if got, _ := os.Readlink(link); got == want {
			return cmd
		} else if time.Now().After(deadline) {
			t.Fatalf("child %d runs %q, want %q", cmd.Process.Pid, got, want)
		}
	}
}

// infoOf is the live record of pid, as core/caller would hold it.
func infoOf(t *testing.T, p *procfs.Procs, pid int) platform.ProcessInfo {
	t.Helper()
	st, err := procfs.ReadStat(pid)
	if err != nil {
		t.Fatal(err)
	}
	info, err := p.Process(platform.ProcessRef{PID: pid, Generation: procfs.Generation(st.StartTicks)})
	if err != nil {
		t.Fatalf("Process(%d): %v", pid, err)
	}
	return info
}

// zeroBundle reports whether b is the zero AppBundle (its Code holds a
// slice, so == does not apply).
func zeroBundle(b platform.AppBundle) bool {
	return b.BundleID == "" && b.Path == "" && !b.Code.Signed && b.Code.TeamID == "" && b.Code.CDHash == nil
}

func fileSum(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(data)
	return h[:]
}

// newIndex is an Index over dirs with a clock the test moves.
func newIndex(t *testing.T, p *procfs.Procs, dirs ...string) (*Index, *time.Time) {
	t.Helper()
	now := time.Now()
	x := NewIndex(dirs, p)
	x.now = func() time.Time { return now }
	return x, &now
}

// oneApp sets up a data dir with testID running the copy and returns the
// index, the copy's path and the running process's record.
func oneApp(t *testing.T) (*Index, *procfs.Procs, string, platform.ProcessInfo) {
	t.Helper()
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "testapp")
	writeEntry(t, dir, testID, entryFor(app))
	cmd := startRunning(t, app, app, "600")
	x, _ := newIndex(t, p, dir)
	return x, p, app, infoOf(t, p, cmd.Process.Pid)
}

func TestPinTeam(t *testing.T) {
	if got, want := PinTeam([]byte{0xab, 0x01, 0xff}), "sha256:ab01ff"; got != want {
		t.Errorf("PinTeam = %q, want %q", got, want)
	}
}

func TestDefaultDataDirs(t *testing.T) {
	got := DefaultDataDirs("/home/me")
	want := []string{"/home/me/.local/share", "/usr/local/share", "/usr/share"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("DefaultDataDirs = %q, want %q", got, want)
	}
}

func TestAppForDesktopEntry(t *testing.T) {
	x, _, app, info := oneApp(t)
	got, ok := x.AppFor([]platform.ProcessInfo{info})
	if !ok {
		t.Fatalf("AppFor(%v running %s) = not an app", info.Ref, app)
	}
	if got.Ref != info.Ref {
		t.Errorf("Ref = %v, want %v", got.Ref, info.Ref)
	}
	if got.BundleID != testID {
		t.Errorf("BundleID = %q, want %q", got.BundleID, testID)
	}
	if got.Name != "Test App" {
		t.Errorf("Name = %q, want %q", got.Name, "Test App")
	}
	if want := PinTeam(fileSum(t, app)); got.Code.Team() != want {
		t.Errorf("Code.Team() = %q, want %q", got.Code.Team(), want)
	}
	if !got.Code.Signed || got.Code.AdHoc || got.Code.Apple {
		t.Errorf("Code = %+v, want Signed with a team only", got.Code)
	}
	// The app is found behind a non-app child too (peer first).
	child := startRunning(t, mustReal(t, sleepPath()), sleepPath(), "600")
	chain := []platform.ProcessInfo{infoOf(t, x.procs, child.Process.Pid), info}
	if got2, ok := x.AppFor(chain); !ok || got2.Ref != info.Ref || got2.BundleID != testID {
		t.Errorf("AppFor(child, app) = %+v, %v; want the app", got2, ok)
	}
}

func mustReal(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func TestAppForIgnoresRecordPath(t *testing.T) {
	x, p, app, appInfo := oneApp(t)
	// A live non-app process whose record claims the app's path and code.
	other := startRunning(t, mustReal(t, sleepPath()), sleepPath(), "600")
	info := infoOf(t, p, other.Process.Pid)
	info.Path = app
	info.Code = platform.CodeIdentity{Signed: true, TeamID: PinTeam(fileSum(t, app)), CDHash: fileSum(t, app)}
	if got, ok := x.AppFor([]platform.ProcessInfo{info}); ok {
		t.Errorf("AppFor(live non-app with the app's path) = %+v, true", got)
	}
	// A forged record: a made-up ref with the app's path.
	forged := platform.ProcessInfo{
		Ref:  platform.ProcessRef{PID: 424242, Generation: 424242001},
		Path: app,
		Args: []string{app},
		Code: platform.CodeIdentity{Signed: true, TeamID: PinTeam(fileSum(t, app))},
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{forged}); ok {
		t.Errorf("AppFor(forged record) = %+v, true", got)
	}
	// A PID-only ref is not a chain record: never an app, even when the
	// PID is the running app's own (procfs would answer the app for the
	// bare PID; a recycled PID would be whoever holds it now).
	pidOnly := platform.ProcessInfo{Ref: platform.ProcessRef{PID: appInfo.Ref.PID}, Path: app}
	if got, ok := x.AppFor([]platform.ProcessInfo{pidOnly}); ok {
		t.Errorf("AppFor(pid-only record of the app's PID) = %+v, true", got)
	}
	// The app's real PID with a tampered generation names no live
	// process: not an app.
	tampered := appInfo
	tampered.Ref.Generation++
	if got, ok := x.AppFor([]platform.ProcessInfo{tampered}); ok {
		t.Errorf("AppFor(the app's PID, another generation) = %+v, true", got)
	}
	if got, ok := x.AppFor(nil); ok {
		t.Errorf("AppFor(nil) = %+v, true", got)
	}
	// The untouched record is the app, so the refusals above are the ref's.
	if got, ok := x.AppFor([]platform.ProcessInfo{appInfo}); !ok || got.Ref != appInfo.Ref {
		t.Errorf("AppFor(the app's own record) = %+v, %v; want the app", got, ok)
	}
}

func TestInstalledAppMatchesRunning(t *testing.T) {
	x, _, app, info := oneApp(t)
	b, err := x.InstalledApp(testID)
	if err != nil {
		t.Fatalf("InstalledApp(%s): %v", testID, err)
	}
	if b.BundleID != testID || b.Path != app {
		t.Errorf("InstalledApp = %+v, want id %s at %s", b, testID, app)
	}
	got, ok := x.AppFor([]platform.ProcessInfo{info})
	if !ok {
		t.Fatal("AppFor: not an app")
	}
	if b.Code.Team() == "" || b.Code.Team() != got.Code.Team() {
		t.Errorf("InstalledApp team %q, AppFor team %q; want the same non-empty pin", b.Code.Team(), got.Code.Team())
	}
}

func TestInstalledAppChangedFile(t *testing.T) {
	x, _, app, _ := oneApp(t)
	before, err := x.InstalledApp(testID)
	if err != nil {
		t.Fatal(err)
	}
	// A package upgrade puts a new file in the executable's place (the
	// running program keeps the old one, which is busy for writing).
	data, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app+".new", append(data, "\n# changed"...), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(app+".new", app); err != nil {
		t.Fatal(err)
	}
	after, err := x.InstalledApp(testID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Code.Team() == before.Code.Team() {
		t.Errorf("team %q unchanged after the file changed", after.Code.Team())
	}
	if want := PinTeam(fileSum(t, app)); after.Code.Team() != want {
		t.Errorf("team = %q, want %q (the new file)", after.Code.Team(), want)
	}
}

func TestInstalledAppMissing(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	gone := filepath.Join(dir, "gone")
	writeEntry(t, dir, "dev.nazar.Gone", entryFor(gone))
	x, _ := newIndex(t, p, dir)
	for _, id := range []string{"dev.nazar.Unknown", "dev.nazar.Gone", ""} {
		b, err := x.InstalledApp(id)
		if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%q) = %+v, %v; want zero, ErrNotFound", id, b, err)
		}
	}
}

func TestLauncherExecIsNotAnApp(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "launched")
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// flatpak and dash stand in for the real launchers. `run` is a link to
	// dash under a name that is no launcher, so that entry's launcher is
	// told only by the file the name resolves to.
	copySleep(t, bin, "flatpak")
	dash := copySleep(t, bin, "dash")
	run := filepath.Join(bin, "run")
	if err := os.Symlink(dash, run); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, dir, "dev.nazar.Env", entryFor("/usr/bin/env FOO=1 "+app))
	writeEntry(t, dir, "dev.nazar.Flatpak", entryFor("flatpak run org.x.Y"))
	writeEntry(t, dir, "dev.nazar.Shell", entryFor(run+" -c "+app))
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin}
	for _, id := range []string{"dev.nazar.Env", "dev.nazar.Flatpak", "dev.nazar.Shell"} {
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
		}
	}
	// The error says why, so the user is not told the app is not installed.
	_, err := x.InstalledApp("dev.nazar.Flatpak")
	if want := `desktop: dev.nazar.Flatpak: its program "flatpak" is a shell, interpreter or launcher that starts some other program, so no process can match app:"dev.nazar.Flatpak"`; err == nil || err.Error() != want {
		t.Errorf("InstalledApp(Flatpak) error = %v, want %q", err, want)
	}
	// The core shows the reason (a platform.NotFoundError) in place of
	// "not installed".
	var nf *platform.NotFoundError
	if !errors.As(err, &nf) || nf.Reason != `its program "flatpak" is a shell, interpreter or launcher that starts some other program, so no process can match app:"dev.nazar.Flatpak"` {
		t.Errorf("InstalledApp(Flatpak) error is not a NotFoundError with the reason: %v", err)
	}
	_, err = x.InstalledApp("dev.nazar.Shell")
	if want := "desktop: dev.nazar.Shell: its program " + strconv.Quote(dash) + ` is a shell, interpreter or launcher that starts some other program, so no process can match app:"dev.nazar.Shell"`; err == nil || err.Error() != want {
		t.Errorf("InstalledApp(Shell) error = %v, want %q", err, want)
	}
	// The program env started runs the app's file, but no entry names it.
	cmd := startRunning(t, app, "/usr/bin/env", "FOO=1", app, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, cmd.Process.Pid)}); ok {
		t.Errorf("AppFor(process a launcher started) = %+v, true", got)
	}
	// A long-lived process of the shell itself, started through the link
	// the entry names, is not the entry's app either: were the resolved
	// file not told to be a launcher, dev.nazar.Shell would own it.
	shell := startRunning(t, dash, run, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, shell.Process.Pid)}); ok {
		t.Errorf("AppFor(the shell the entry names) = %+v, true", got)
	}
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() = %+v, want none", apps)
	}
}

// TestInterpreterExecIsNotAnApp: an entry whose program is an interpreter,
// another shell, a runtime or a sandbox wrapper, with the real program in
// its arguments, is no app, and a process of that interpreter is never
// the app (it could be running anything).
func TestInterpreterExecIsNotAnApp(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin}
	var running []*exec.Cmd
	names := []string{"python3.11", "zsh", "firejail", "busybox", "java", "node18", "perl5.36.0", "wine64", "electron"}
	for i, name := range names {
		prog := copySleep(t, bin, name)
		id := "dev.nazar.Tool" + strconv.Itoa(i)
		// Half by absolute path, half by bare name (found in bins).
		program := prog
		if i%2 == 1 {
			program = name
		}
		writeEntry(t, dir, id, entryFor(program+" /opt/tool/main.py"))
		running = append(running, startRunning(t, prog, prog, "600"))
	}
	for i, name := range names {
		id := "dev.nazar.Tool" + strconv.Itoa(i)
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s, Exec=%s script) = %+v, %v; want zero, ErrNotFound", id, name, b, err)
		}
		if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running[i].Process.Pid)}); ok {
			t.Errorf("AppFor(a process of %s) = %+v, true; want no app", name, got)
		}
	}
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() = %+v, want none", apps)
	}
}

func TestIsLauncher(t *testing.T) {
	for name, want := range map[string]bool{
		"sh": true, "bash": true, "dash": true, "zsh": true, "zsh5": true, "fish": true, "ksh": true,
		"mksh": true, "busybox": true, "env": true, "python": true, "python3": true,
		"python3.11": true, "pypy3": true, "perl": true, "perl5.36.0": true, "ruby3.1": true,
		"node": true, "node18": true, "nodejs": true, "java": true, "lua5.4": true, "php8.2": true,
		"tclsh8.6": true, "guile-3.0": true, "gjs": true, "mono": true, "dotnet": true, "wine": true,
		"wine64": true, "wine64-preloader": true, "electron": true, "electron28": true,
		"firejail": true, "bwrap": true, "pkexec": true, "sudo": true, "nice": true, "flatpak": true,
		"flatpak-spawn": true, "snap": true, "gtk-launch": true, "xdg-open": true, "kde-open5": true,
		"kioclient5": true, "gapplication": true, "ld-linux-x86-64.so.2": true,
		"ld-linux-aarch64.so.1": true, "ld-linux.so.2": true,
		// more shells, interpreters and wrappers, and the free-threaded python
		"pwsh": true, "nu": true, "elvish": true, "xonsh": true, "awk": true, "gawk": true, "mawk": true,
		"R": true, "erl": true, "elixir": true, "ocaml": true, "sbcl": true, "tclkit": true, "cjs": true,
		"python3.13t": true, "pythonw": true, "uv": true, "uvx": true, "npx": true, "pipx": true,
		"systemd-inhibit": true, "gnome-session-inhibit": true, "systemd-nspawn": true, "runuser": true,
		"run0": true, "sg": true, "newgrp": true, "setpriv": true, "setarch": true, "linux64": true,
		"xargs": true, "flock": true, "time": true, "watch": true, "script": true, "strace": true,
		"ltrace": true, "gdb": true, "valgrind": true, "gksu": true, "gksudo": true, "kdesu": true,
		"kdesudo": true, "pasuspender": true, "vglrun": true, "cgexec": true, "aa-exec": true,
		"gnome-open": true, "mate-open": true, "kfmclient": true, "dex": true, "qemu-x86_64": true,
		"qemu-aarch64": true,
		// programs nazar gates, which run other programs too (subcommands, aliases, ProxyCommand)
		"git": true, "ssh": true,
		// apps and programs of their own
		"firefox": false, "code": false, "gnome-terminal-server": false, "sleep": false, "cat": false,
		"python3-config": false, "nodejs-doc": false, "java-wrapper": false, "3": false, "": false,
		"-3": false, "x86_64-linux-gnu-gcc-12": false, "qemu-system-x86_64": false, "t": false,
		"git-gui": false, "gitk": false, "sshfs": false,
	} {
		if got := isLauncher(name); got != want {
			t.Errorf("isLauncher(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestScriptExecIsNotAnApp: an entry whose program is a script (a #!
// wrapper such as Chrome's or VS Code's, a Python app) is no app: the
// kernel runs its interpreter, which is what /proc/<pid>/exe names, so a
// pin of the script could never match a process. A TryExec that is a
// script changes nothing: TryExec only says the program is installed, and
// the app is Exec's program.
func TestScriptExecIsNotAnApp(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	wrapper := filepath.Join(dir, "wrapper")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nsleep 600\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(dir, "notes")
	if err := os.WriteFile(text, []byte("not a program\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("#!"), 0o755); err != nil {
		t.Fatal(err)
	}
	gui := copySleep(t, dir, "gui")
	writeEntry(t, dir, "dev.nazar.Wrapper", entryFor(wrapper))
	writeEntry(t, dir, "dev.nazar.TryWrapper", tryEntry(wrapper, gui))
	writeEntry(t, dir, "dev.nazar.Text", entryFor(text))
	writeEntry(t, dir, "dev.nazar.Short", entryFor(short))
	x, _ := newIndex(t, p, dir)
	for _, id := range []string{"dev.nazar.Wrapper", "dev.nazar.Text", "dev.nazar.Short"} {
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
		}
	}
	_, err := x.InstalledApp("dev.nazar.Wrapper")
	if want := "desktop: dev.nazar.Wrapper: its program " + strconv.Quote(wrapper) + ` is a script, not a native executable; the process that runs it is its interpreter, so no process can match app:"dev.nazar.Wrapper"`; err == nil || err.Error() != want {
		t.Errorf("InstalledApp(Wrapper) error = %v, want %q", err, want)
	}
	if b, err := x.InstalledApp("dev.nazar.TryWrapper"); err != nil || b.Path != gui {
		t.Errorf("InstalledApp(TryWrapper, a script TryExec and a native Exec) = %+v, %v; want Exec's %s", b, err, gui)
	}
	// The running wrapper is its interpreter, and no app.
	sh := mustReal(t, "/bin/sh")
	running := startRunning(t, sh, wrapper)
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(the running wrapper) = %+v, true", got)
	}
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() = %+v, want none", apps)
	}
}

// TestNotAppReasons: every way an entry that exists is no app has an
// error that is ErrNotFound and says why; an id with no entry is the
// plain ErrNotFound.
func TestNotAppReasons(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	app := copySleep(t, dir, "shared")
	vanish := copySleep(t, dir, "vanish")
	unreadable := copySleep(t, dir, "unreadable")
	if err := os.Chmod(unreadable, 0o111); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, dir, "dev.nazar.Alpha", entryFor(app))
	writeEntry(t, dir, "dev.nazar.Beta", entryFor(app))
	writeEntry(t, dir, "dev.nazar.Bare", entryFor("nazar-no-such-program"))
	writeEntry(t, dir, "dev.nazar.Missing", entryFor(filepath.Join(dir, "missing")))
	writeEntry(t, dir, "dev.nazar.Relative", entryFor("bin/x"))
	writeEntry(t, dir, "dev.nazar.Empty", "[Desktop Entry]\nType=Application\nName=E\n")
	writeEntry(t, dir, "dev.nazar.Proc", entryFor("/proc/self/exe"))
	writeEntry(t, dir, "dev.nazar.Dev", entryFor("/dev/null"))
	writeEntry(t, dir, "dev.nazar.Vanish", entryFor(vanish))
	writeEntry(t, dir, "dev.nazar.Unreadable", entryFor(unreadable))
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin, "/nowhere"}
	want := map[string]string{
		"dev.nazar.Beta":     `desktop: dev.nazar.Beta: another entry, "dev.nazar.Alpha", is the app for the same program ` + strconv.Quote(app),
		"dev.nazar.Bare":     `desktop: dev.nazar.Bare: its program "nazar-no-such-program" is not in ` + bin + ", /nowhere",
		"dev.nazar.Missing":  "desktop: dev.nazar.Missing: its program " + strconv.Quote(filepath.Join(dir, "missing")) + " is not a file",
		"dev.nazar.Relative": `desktop: dev.nazar.Relative: its program "bin/x" is a relative path`,
		"dev.nazar.Empty":    "desktop: dev.nazar.Empty: its entry names no program",
		"dev.nazar.Proc":     `desktop: dev.nazar.Proc: its program "/proc/self/exe" is not an installed file`,
		"dev.nazar.Dev":      `desktop: dev.nazar.Dev: its program "/dev/null" is not an installed file`,
		"dev.nazar.Unknown":  platform.ErrNotFound.Error(),
	}
	if os.Geteuid() != 0 { // root reads any file
		want["dev.nazar.Unreadable"] = "desktop: dev.nazar.Unreadable: its program " + strconv.Quote(unreadable) + " cannot be read (permission denied), so it cannot be checked or pinned"
	}
	for id, want := range want {
		b, err := x.InstalledApp(id)
		if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
			continue
		}
		if err.Error() != want {
			t.Errorf("InstalledApp(%s) error = %q, want %q", id, err.Error(), want)
		}
	}
	if b, err := x.InstalledApp("dev.nazar.Alpha"); err != nil || b.Path != app {
		t.Errorf("InstalledApp(Alpha) = %+v, %v", b, err)
	}
	// The program went after the scan (the table is still the cached one:
	// the clock has not moved): there is nothing to hash, and the error
	// says the program is gone rather than that the app is not installed.
	if b, err := x.InstalledApp("dev.nazar.Vanish"); err != nil || b.Path != vanish {
		t.Fatalf("InstalledApp(Vanish) = %+v, %v; want %s", b, err, vanish)
	}
	if err := os.Remove(vanish); err != nil {
		t.Fatal(err)
	}
	b, err := x.InstalledApp("dev.nazar.Vanish")
	if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
		t.Fatalf("InstalledApp(Vanish, program removed) = %+v, %v; want zero, ErrNotFound", b, err)
	}
	if want := "desktop: dev.nazar.Vanish: its program " + strconv.Quote(vanish) + " is gone"; err.Error() != want {
		t.Errorf("InstalledApp(Vanish, program removed) error = %q, want %q", err.Error(), want)
	}
}

// TestKernelPathExecIsNotAnApp: /proc/self/exe resolves to whoever reads
// it, the agent itself here, and a device is no program: neither names an
// installed file, however it resolves, and a process of the agent's own
// binary is never the app.
func TestKernelPathExecIsNotAnApp(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	self := mustReal(t, "/proc/self/exe")
	link := filepath.Join(dir, "me")
	if err := os.Symlink("/proc/self/exe", link); err != nil {
		t.Fatal(err)
	}
	// However the path reaches /proc, it reaches it: climbing there with
	// `..`, as written or in a link, and through a link to a folder there.
	climb := filepath.Join(dir, "climb")
	if err := os.Symlink(strings.Repeat("../", strings.Count(dir, "/"))+"proc/self/exe", climb); err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(dir, "folder")
	if err := os.Symlink("/proc/self", folder); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, dir, "dev.nazar.Self", entryFor("/proc/self/exe"))
	writeEntry(t, dir, "dev.nazar.SelfLink", entryFor(link))
	writeEntry(t, dir, "dev.nazar.SelfDots", entryFor("/usr/../proc/self/exe"))
	writeEntry(t, dir, "dev.nazar.SelfClimb", entryFor(climb))
	writeEntry(t, dir, "dev.nazar.SelfFolder", entryFor(filepath.Join(folder, "exe")))
	x, _ := newIndex(t, p, dir)
	for _, id := range []string{"dev.nazar.Self", "dev.nazar.SelfLink", "dev.nazar.SelfDots", "dev.nazar.SelfClimb", "dev.nazar.SelfFolder"} {
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) || b.Path == self {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
		}
	}
	me := infoOf(t, p, os.Getpid())
	if got, ok := x.AppFor([]platform.ProcessInfo{me}); ok {
		t.Errorf("AppFor(the test binary) = %+v, true", got)
	}
}

// TestLinkDotsFollowTheKernel: `..` in a link, or in Exec, is the parent of
// where the path has really got to, after every link before it, not of
// the path as written. Resolved from the text, the pin and the match would
// be of a file the entry does not run, and every process of that file
// would be the app.
func TestLinkDotsFollowTheKernel(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	for _, sub := range []string{"real/bin", "real/lib", "tmp/lib"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, path string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(dir, path)); err != nil {
			t.Fatal(err)
		}
	}
	link(filepath.Join(dir, "real", "bin"), "tmp/bin")
	link("../lib/app", "real/bin/app")
	link("../lib/only", "real/bin/only")
	link("app", "real/lib/inner")
	link("../lib/app/../app", "real/bin/throughfile")
	runs := copySleep(t, filepath.Join(dir, "real", "lib"), "app")
	only := copySleep(t, filepath.Join(dir, "real", "lib"), "only")
	decoy := copySleep(t, filepath.Join(dir, "tmp", "lib"), "app")
	throughFile := filepath.Join(dir, "real/bin/throughfile")
	writeEntry(t, dir, "dev.nazar.Linked", entryFor(filepath.Join(dir, "tmp/bin/app")))
	writeEntry(t, dir, "dev.nazar.Only", entryFor(filepath.Join(dir, "tmp/bin/only")))
	writeEntry(t, dir, "dev.nazar.Written", entryFor(dir+"/tmp/bin/../lib/inner"))
	writeEntry(t, dir, "dev.nazar.ThroughFile", entryFor(throughFile))
	x, _ := newIndex(t, p, dir)
	if b, err := x.InstalledApp("dev.nazar.Linked"); err != nil || b.Path != runs || b.Code.Team() != PinTeam(fileSum(t, runs)) {
		t.Errorf("InstalledApp(Linked) = %+v, %v; want the file Exec runs, %s", b, err, runs)
	}
	// The lexical target of this one does not exist: the entry is still
	// an app, not `is not a file`.
	if b, err := x.InstalledApp("dev.nazar.Only"); err != nil || b.Path != only {
		t.Errorf("InstalledApp(Only) = %+v, %v; want %s", b, err, only)
	}
	// Written shares the file with Linked, which is first; its error names
	// the real path, which only the kernel's reading of its Exec reaches.
	wantWritten := `desktop: dev.nazar.Written: another entry, "dev.nazar.Linked", is the app for the same program ` + strconv.Quote(runs)
	if _, err := x.InstalledApp("dev.nazar.Written"); err == nil || err.Error() != wantWritten {
		t.Errorf("InstalledApp(Written) error = %v, want %s", err, wantWritten)
	}
	// A regular file has no parent to go back to through it: the kernel
	// says ENOTDIR, so the entry runs nothing.
	wantThrough := "desktop: dev.nazar.ThroughFile: its program " + strconv.Quote(throughFile) + " is not a file"
	if _, err := x.InstalledApp("dev.nazar.ThroughFile"); err == nil || err.Error() != wantThrough {
		t.Errorf("InstalledApp(ThroughFile) error = %v, want %s", err, wantThrough)
	}
	running := startRunning(t, runs, filepath.Join(dir, "tmp/bin/app"), "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != "dev.nazar.Linked" {
		t.Errorf("AppFor(what Exec runs) = %+v, %v; want dev.nazar.Linked", got, ok)
	}
	other := startRunning(t, decoy, decoy, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, other.Process.Pid)}); ok {
		t.Errorf("AppFor(the file the link's text suggests) = %+v, true", got)
	}
}

// TestUpgradedRunningAppIsUnknown: a process of the app that was running
// when a package upgrade replaced its file is no app until it is started
// again (its exe link is deleted, so procfs gives it no Path); the new
// file is what InstalledApp pins and what a new instance matches. Like
// any process that is no app, the old instance leaves the chain to the
// app above it: alone it is unknown, under another app it is that app.
func TestUpgradedRunningAppIsUnknown(t *testing.T) {
	x, p, app, info := oneApp(t)
	outer := copySleep(t, filepath.Dir(app), "outer")
	writeEntry(t, filepath.Dir(app), "dev.nazar.Outer", entryFor(outer))
	before, err := x.InstalledApp(testID)
	if err != nil {
		t.Fatal(err)
	}
	outerInfo := infoOf(t, p, startRunning(t, outer, outer, "600").Process.Pid)
	if got, ok := x.AppFor([]platform.ProcessInfo{info, outerInfo}); !ok || got.BundleID != testID {
		t.Fatalf("AppFor(app, outer) before the upgrade = %+v, %v; want %s", got, ok, testID)
	}
	data, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app+".new", append(data, "\n# upgraded"...), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(app+".new", app); err != nil {
		t.Fatal(err)
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{info}); ok {
		t.Errorf("AppFor(old instance after the upgrade) = %+v, true; want unknown", got)
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{info, outerInfo}); !ok || got.BundleID != "dev.nazar.Outer" {
		t.Errorf("AppFor(old instance under another app) = %+v, %v; want dev.nazar.Outer, as for any non-app process", got, ok)
	}
	live := infoOf(t, p, info.Ref.PID)
	if live.Path != "" {
		t.Errorf("procfs Path of the old instance = %q, want \"\" (deleted file)", live.Path)
	}
	for _, a := range x.Apps() {
		if a.Ref == info.Ref {
			t.Errorf("Apps() lists the old instance %+v", a)
		}
	}
	after, err := x.InstalledApp(testID)
	if err != nil || after.Code.Team() == before.Code.Team() || after.Code.Team() != PinTeam(fileSum(t, app)) {
		t.Errorf("InstalledApp after the upgrade = %+v, %v; want the new file's pin", after, err)
	}
	fresh := startRunning(t, app, app, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, fresh.Process.Pid)}); !ok || got.Code.Team() != after.Code.Team() {
		t.Errorf("AppFor(new instance) = %+v, %v; want the app with the new pin", got, ok)
	}
}

// TestSharedExecAcrossFolders: ids that share an executable are ranked by
// name across folders too, so a user's entry under a lower id takes a
// system program's identity, and the system id says which one did.
func TestSharedExecAcrossFolders(t *testing.T) {
	p := procfs.New()
	user, system := t.TempDir(), t.TempDir()
	app := copySleep(t, system, "browser")
	writeEntry(t, user, "aaa-browser", entryFor(app+" --profile dev"))
	writeEntry(t, system, "browser", entryFor(app))
	x, _ := newIndex(t, p, user, system)
	running := startRunning(t, app, app, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != "aaa-browser" {
		t.Errorf("AppFor = %+v, %v; want aaa-browser", got, ok)
	}
	b, err := x.InstalledApp("browser")
	if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
		t.Fatalf("InstalledApp(browser) = %+v, %v; want ErrNotFound", b, err)
	}
	if want := `desktop: browser: another entry, "aaa-browser", is the app for the same program ` + strconv.Quote(app); err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if b, err := x.InstalledApp("aaa-browser"); err != nil || b.Path != app {
		t.Errorf("InstalledApp(aaa-browser) = %+v, %v", b, err)
	}
}

// TestAppsOnlyThisUser: Apps lists this user's processes only.
func TestAppsOnlyThisUser(t *testing.T) {
	x, _, _, info := oneApp(t)
	if apps := x.Apps(); len(apps) != 1 || apps[0].Ref != info.Ref {
		t.Fatalf("Apps() = %+v, want the one instance %v", apps, info.Ref)
	}
	x.uid++ // as if the agent ran as another user
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() as another user = %+v, want none", apps)
	}
	if _, ok := x.AppFor([]platform.ProcessInfo{info}); !ok {
		t.Errorf("AppFor does not filter by user; it should still answer")
	}
}

// TestFixedTables pins the real tables NewIndex uses.
func TestFixedTables(t *testing.T) {
	x := NewIndex(nil, procfs.New())
	if want := map[string]string{"org.gnome.Terminal": "/usr/libexec/gnome-terminal-server"}; !maps.Equal(x.serverExes, want) {
		t.Errorf("serverExes = %v, want %v", x.serverExes, want)
	}
	if want := []string{"/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin", "/snap/bin"}; !slices.Equal(x.bins, want) {
		t.Errorf("binDirs = %v, want %v", x.bins, want)
	}
	if x.uid != os.Geteuid() {
		t.Errorf("uid = %d, want %d", x.uid, os.Geteuid())
	}
	// The Flatpak and Snap export folders: each data dir's Flatpak
	// installation, the system's, and snapd's.
	x = NewIndex(DefaultDataDirs("/home/me"), procfs.New())
	want := []string{"/home/me/.local/share/flatpak/exports/share", "/usr/local/share/flatpak/exports/share",
		"/usr/share/flatpak/exports/share", "/var/lib/flatpak/exports/share", "/var/lib/snapd/desktop"}
	if !slices.Equal(x.exports, want) {
		t.Errorf("exports = %v, want %v", x.exports, want)
	}
}

// TestServerExeKeepsExecChecks: the serverExes table says which file an
// app's process runs; it does not make any entry under its id an app. The
// desktop must still be able to start the app from Exec, so a Flatpak GNOME
// Terminal (Exec=flatpak run ...), a link to a shell, an entry with no Exec
// and one whose Exec names no file are no app, and a process of the server
// is not the app then. The table's file must itself be native: no process
// could ever run a script's file.
func TestServerExeKeepsExecChecks(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	copySleep(t, bin, "flatpak")
	server := copySleep(t, dir, "terminal-server")
	client := copySleep(t, dir, "terminal")
	missing := filepath.Join(dir, "missing")
	shell := filepath.Join(dir, "terminal-shell")
	if err := os.Symlink("/bin/sh", shell); err != nil {
		t.Fatal(err)
	}
	scriptServer := filepath.Join(dir, "script-server")
	if err := os.WriteFile(scriptServer, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, dir, "dev.nazar.FlatTerm", entryFor("flatpak run org.gnome.Terminal"))
	writeEntry(t, dir, "dev.nazar.ShellTerm", entryFor(shell))
	writeEntry(t, dir, "dev.nazar.NoExecTerm", "[Desktop Entry]\nType=Application\nName=T\n")
	writeEntry(t, dir, "dev.nazar.GoneTerm", entryFor(missing))
	writeEntry(t, dir, "dev.nazar.ScriptServer", entryFor(client))
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin}
	x.serverExes = map[string]string{
		"dev.nazar.FlatTerm":     server,
		"dev.nazar.ShellTerm":    server,
		"dev.nazar.NoExecTerm":   server,
		"dev.nazar.GoneTerm":     server,
		"dev.nazar.ScriptServer": scriptServer,
	}
	for id, want := range map[string]string{
		"dev.nazar.FlatTerm":     `desktop: dev.nazar.FlatTerm: its program "flatpak" is a shell, interpreter or launcher that starts some other program, so no process can match app:"dev.nazar.FlatTerm"`,
		"dev.nazar.ShellTerm":    "desktop: dev.nazar.ShellTerm: its program " + strconv.Quote(mustReal(t, shell)) + ` is a shell, interpreter or launcher that starts some other program, so no process can match app:"dev.nazar.ShellTerm"`,
		"dev.nazar.NoExecTerm":   "desktop: dev.nazar.NoExecTerm: its entry names no program",
		"dev.nazar.GoneTerm":     "desktop: dev.nazar.GoneTerm: its program " + strconv.Quote(missing) + " is not a file",
		"dev.nazar.ScriptServer": "desktop: dev.nazar.ScriptServer: its program " + strconv.Quote(scriptServer) + ` is a script, not a native executable; the process that runs it is its interpreter, so no process can match app:"dev.nazar.ScriptServer"`,
	} {
		b, err := x.InstalledApp(id)
		if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
		} else if err.Error() != want {
			t.Errorf("InstalledApp(%s) error = %q, want %q", id, err.Error(), want)
		}
	}
	running := startRunning(t, server, server, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(the server, with no entry that passes) = %+v, true", got)
	}
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() = %+v, want none", apps)
	}
}

// TestServerExeWithScriptExec: Ubuntu's /usr/bin/gnome-terminal is a wrapper
// script around the client (https://bugs.launchpad.net/bugs/1843872). An id
// in the table runs the table's file whatever kind of file starts it, so
// such an Exec is the app, not `is a script`. A script under any other id
// is still no app.
func TestServerExeWithScriptExec(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	server := copySleep(t, dir, "terminal-server")
	script := filepath.Join(bin, "terminal")
	if err := os.WriteFile(script, []byte("#!/usr/bin/python3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, dir, "dev.nazar.Term", entryFor("terminal"))
	writeEntry(t, dir, "dev.nazar.OtherScript", entryFor(script))
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin}
	x.serverExes = map[string]string{"dev.nazar.Term": server}
	b, err := x.InstalledApp("dev.nazar.Term")
	if err != nil || b.Path != server || b.Code.Team() != PinTeam(fileSum(t, server)) {
		t.Fatalf("InstalledApp(Term) = %+v, %v; want the server at %s with its pin", b, err, server)
	}
	running := startRunning(t, server, server, "600")
	got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)})
	if !ok || got.BundleID != "dev.nazar.Term" || got.Code.Team() != b.Code.Team() {
		t.Errorf("AppFor(the server) = %+v, %v; want dev.nazar.Term with InstalledApp's pin", got, ok)
	}
	want := "desktop: dev.nazar.OtherScript: its program " + strconv.Quote(script) + ` is a script, not a native executable; the process that runs it is its interpreter, so no process can match app:"dev.nazar.OtherScript"`
	if _, err := x.InstalledApp("dev.nazar.OtherScript"); err == nil || err.Error() != want {
		t.Errorf("InstalledApp(OtherScript) error = %v, want %s", err, want)
	}
}

// TestExportedEntrySaysWhy: a Flatpak or Snap app has its entry only in
// the folders those two export to. The index reads them so that
// InstalledApp says why such an id is no app, not that nothing is
// installed; nothing in them is ever an app, whatever the entry's Exec
// names, and an entry in the user's own folder under the same id is
// judged on its own, as the desktop would show the user's.
func TestExportedEntrySaysWhy(t *testing.T) {
	p := procfs.New()
	user, exports := t.TempDir(), t.TempDir()
	bin := filepath.Join(exports, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	copySleep(t, bin, "flatpak")
	native := copySleep(t, exports, "native")
	mine := copySleep(t, user, "mine")
	writeEntry(t, exports, "org.x.Flat", entryFor("flatpak run org.x.Flat"))
	writeEntry(t, exports, "org.x.Native", entryFor(native))
	writeEntry(t, exports, "org.x.Mine", entryFor(native))
	writeEntry(t, user, "org.x.Mine", entryFor(mine))
	x, _ := newIndex(t, p, user)
	x.bins = []string{bin}
	x.exports = []string{exports}
	for _, id := range []string{"org.x.Flat", "org.x.Native"} {
		b, err := x.InstalledApp(id)
		if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
			continue
		}
		if want := "desktop: " + id + ": its entry is a Flatpak or Snap export, and the app runs inside flatpak or snap, so no process can match app:" + strconv.Quote(id); err.Error() != want {
			t.Errorf("InstalledApp(%s) error = %q, want %q", id, err.Error(), want)
		}
	}
	if b, err := x.InstalledApp("org.x.Mine"); err != nil || b.Path != mine {
		t.Errorf("InstalledApp(Mine, the user's own entry) = %+v, %v; want %s", b, err, mine)
	}
	running := startRunning(t, native, native, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(a process of the file an exported entry names) = %+v, true", got)
	}
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() = %+v, want none", apps)
	}
	// Without the export folders the id is plainly not installed.
	x2, _ := newIndex(t, p, user)
	x2.exports = nil
	if _, err := x2.InstalledApp("org.x.Flat"); err != platform.ErrNotFound {
		t.Errorf("InstalledApp(Flat) with no export folders = %v; want the bare ErrNotFound", err)
	}
}

// TestUnreadableExeIsNoIdentity: a process whose executable can no longer
// be read (its mode changed under it) has no live Path (procfs: no
// identity to match, for path: rules and app: alike), so it is no app and
// the app above it in the chain answers, as for any non-app process. The
// one case left, a hash that fails only after the process was read with
// its Path (a race with such a change), is the app without a pin to
// compare: appOf says so, and AppFor stops there rather than let the app
// above answer for a process that does run an app's file.
func TestUnreadableExeIsNoIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file: the executable cannot be made unreadable")
	}
	x, p, app, info := oneApp(t)
	outer := copySleep(t, filepath.Dir(app), "outer")
	writeEntry(t, filepath.Dir(app), "dev.nazar.Outer", entryFor(outer))
	outerInfo := infoOf(t, p, startRunning(t, outer, outer, "600").Process.Pid)
	if got, ok := x.AppFor([]platform.ProcessInfo{info, outerInfo}); !ok || got.BundleID != testID {
		t.Fatalf("AppFor(app, outer) = %+v, %v; want %s", got, ok, testID)
	}
	if err := os.Chmod(app, 0o111); err != nil {
		t.Fatal(err)
	}
	if live, err := p.Process(info.Ref); err != nil || live.Path != "" {
		t.Fatalf("Process(unreadable exe) = %+v, %v; want no Path", live, err)
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{info}); ok {
		t.Errorf("AppFor(unreadable exe) = %+v, true; want unknown", got)
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{info, outerInfo}); !ok || got.BundleID != "dev.nazar.Outer" {
		t.Errorf("AppFor(unreadable exe, outer) = %+v, %v; want dev.nazar.Outer, as for any non-app process", got, ok)
	}
	for _, a := range x.Apps() {
		if a.Ref == info.Ref {
			t.Errorf("Apps() lists the unreadable instance %+v", a)
		}
	}
	// The race: the record was read with its Path, then the hash fails.
	// (The table still names the file: the clock has not moved.)
	if _, err := p.ExeHash(info.Ref); err == nil {
		t.Fatal("ExeHash of the unreadable file succeeded; the race cannot be staged")
	}
	if a, ok, isApp := x.appOf(x.snapshot(), info); ok || !isApp {
		t.Errorf("appOf(an app's file whose hash cannot be read) = %+v, %v, %v; want the app without a pin (not ok, isApp)", a, ok, isApp)
	}
}

// TestFutureMtimeSettles: a file with a timestamp ahead of the clock
// (clock skew, a package with odd timestamps) settles like any other, so
// the index does not read every entry and program again at every look.
func TestFutureMtimeSettles(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "ahead")
	writeEntry(t, dir, "dev.nazar.Ahead", entryFor(app))
	x, now := newIndex(t, p, dir)
	future := now.Add(time.Hour)
	for _, path := range []string{app, filepath.Join(dir, "applications", "dev.nazar.Ahead.desktop")} {
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatal(err)
		}
	}
	settle(t, x, now)
	n := scans(x)
	for range 3 {
		*now = now.Add(rescanEvery)
		if b, err := x.InstalledApp("dev.nazar.Ahead"); err != nil || b.Path != app {
			t.Fatalf("InstalledApp = %+v, %v", b, err)
		}
	}
	if got := scans(x); got != n {
		t.Errorf("scans = %d after three looks at files with a future timestamp, want %d", got, n)
	}
	// A change is still followed.
	writeEntry(t, dir, "dev.nazar.Added", entryFor(copySleep(t, dir, "added")))
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp("dev.nazar.Added"); err != nil || b.BundleID != "dev.nazar.Added" {
		t.Errorf("InstalledApp(added) = %+v, %v", b, err)
	}
}

// TestEntryFileTooLarge: a desktop file over maxEntry is no entry (the
// largest real ones are tens of kilobytes); a file under it is read.
func TestEntryFileTooLarge(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "big")
	writeEntry(t, dir, "dev.nazar.Big", entryFor(app)+"#"+strings.Repeat("x", maxEntry)+"\n")
	writeEntry(t, dir, "dev.nazar.Large", entryFor(app)+"#"+strings.Repeat("x", maxEntry/2)+"\n")
	x, _ := newIndex(t, p, dir)
	if b, err := x.InstalledApp("dev.nazar.Big"); err != platform.ErrNotFound || !zeroBundle(b) {
		t.Errorf("InstalledApp(Big) = %+v, %v; want zero, the bare ErrNotFound (no entry)", b, err)
	}
	if b, err := x.InstalledApp("dev.nazar.Large"); err != nil || b.Path != app {
		t.Errorf("InstalledApp(Large) = %+v, %v; want %s", b, err, app)
	}
}

func TestServerExeTable(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	server := copySleep(t, dir, "terminal-server")
	client := copySleep(t, dir, "terminal")
	const id = "dev.nazar.Terminal"
	writeEntry(t, dir, id, entryFor(client))
	x, _ := newIndex(t, p, dir)
	x.serverExes = map[string]string{id: server}
	running := startRunning(t, server, server, "600")
	got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)})
	if !ok || got.BundleID != id {
		t.Fatalf("AppFor(server process) = %+v, %v; want %s", got, ok, id)
	}
	if want := PinTeam(fileSum(t, server)); got.Code.Team() != want {
		t.Errorf("team = %q, want %q (the server's file)", got.Code.Team(), want)
	}
	b, err := x.InstalledApp(id)
	if err != nil || b.Path != server || b.Code.Team() != got.Code.Team() {
		t.Errorf("InstalledApp(%s) = %+v, %v; want the server at %s", id, b, err, server)
	}
	// What Exec names is not the app: the table replaced it.
	launcher := startRunning(t, client, client, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, launcher.Process.Pid)}); ok {
		t.Errorf("AppFor(the Exec program) = %+v, true", got)
	}
}

func TestHiddenAndNoDisplayIgnored(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "hiddenapp")
	writeEntry(t, dir, "dev.nazar.Hidden", entryFor(app)+"Hidden=true\n")
	writeEntry(t, dir, "dev.nazar.NoDisplay", entryFor(app)+"NoDisplay=true\n")
	writeEntry(t, dir, "dev.nazar.Link", "[Desktop Entry]\nType=Link\nName=Link\nURL=https://example.com\nExec="+app+"\n")
	writeEntry(t, dir, "dev.nazar.NoGroup", "[Other Group]\nType=Application\nName=X\nExec="+app+"\n")
	writeEntry(t, dir, "dev.nazar.NoType", "[Desktop Entry]\nName=X\nExec="+app+"\n")
	x, _ := newIndex(t, p, dir)
	for _, id := range []string{"dev.nazar.Hidden", "dev.nazar.NoDisplay", "dev.nazar.Link", "dev.nazar.NoGroup", "dev.nazar.NoType"} {
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want ErrNotFound", id, b, err)
		}
	}
	running := startRunning(t, app, app, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(process of hidden entries) = %+v, true", got)
	}
}

func TestUserFolderWins(t *testing.T) {
	p := procfs.New()
	user, system := t.TempDir(), t.TempDir()
	userApp := copySleep(t, user, "userapp")
	systemApp := copySleep(t, system, "systemapp")
	writeEntry(t, user, testID, strings.Replace(entryFor(userApp), "Test App", "User App", 1))
	writeEntry(t, system, testID, entryFor(systemApp))
	x, _ := newIndex(t, p, user, system)
	b, err := x.InstalledApp(testID)
	if err != nil || b.Path != userApp {
		t.Errorf("InstalledApp = %+v, %v; want the user's %s", b, err, userApp)
	}
	u := startRunning(t, userApp, userApp, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, u.Process.Pid)}); !ok || got.BundleID != testID || got.Name != "User App" {
		t.Errorf("AppFor(user's program) = %+v, %v; want %s named User App", got, ok, testID)
	}
	s := startRunning(t, systemApp, systemApp, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, s.Process.Pid)}); ok {
		t.Errorf("AppFor(system's program, shadowed) = %+v, true", got)
	}

	// A hidden entry in the user's folder removes the system's app.
	user2 := t.TempDir()
	writeEntry(t, user2, testID, entryFor(systemApp)+"Hidden=true\n")
	x2, _ := newIndex(t, p, user2, system)
	if b, err := x2.InstalledApp(testID); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(hidden by the user) = %+v, %v; want ErrNotFound", b, err)
	}
	if got, ok := x2.AppFor([]platform.ProcessInfo{infoOf(t, p, s.Process.Pid)}); ok {
		t.Errorf("AppFor(hidden by the user) = %+v, true", got)
	}
}

func TestSharedExecFirstID(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "shared")
	writeEntry(t, dir, "dev.nazar.Zeta", entryFor(app))
	writeEntry(t, dir, "dev.nazar.Alpha", entryFor(app))
	writeEntry(t, dir, "dev.nazar.Mid", entryFor(app))
	x, _ := newIndex(t, p, dir)
	running := startRunning(t, app, app, "600")
	got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)})
	if !ok || got.BundleID != "dev.nazar.Alpha" {
		t.Errorf("AppFor = %+v, %v; want dev.nazar.Alpha", got, ok)
	}
	if b, err := x.InstalledApp("dev.nazar.Alpha"); err != nil || b.Path != app {
		t.Errorf("InstalledApp(Alpha) = %+v, %v", b, err)
	}
	// The other ids never match as app:, so there is nothing to pin for them.
	for _, id := range []string{"dev.nazar.Zeta", "dev.nazar.Mid"} {
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want ErrNotFound (shadowed by dev.nazar.Alpha)", id, b, err)
		}
	}
}

func TestBareExecName(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	app := copySleep(t, bin, "nazar-test-bare")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if found, err := exec.LookPath("nazar-test-bare"); err != nil || mustReal(t, found) != app {
		t.Fatalf("LookPath = %q, %v; want %s on PATH", found, err, app)
	}
	writeEntry(t, dir, testID, entryFor("nazar-test-bare"))
	running := startRunning(t, app, app, "600")

	// Found only through $PATH: not resolved.
	x, _ := newIndex(t, p, dir)
	if b, err := x.InstalledApp(testID); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(bare name on PATH only) = %+v, %v; want ErrNotFound", b, err)
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(bare name on PATH only) = %+v, true", got)
	}

	// In one of the fixed folders: resolved to its real path.
	x2, _ := newIndex(t, p, dir)
	x2.bins = []string{filepath.Join(dir, "nowhere"), bin}
	if b, err := x2.InstalledApp(testID); err != nil || b.Path != app {
		t.Errorf("InstalledApp(bare name in a fixed folder) = %+v, %v; want %s", b, err, app)
	}
	if got, ok := x2.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != testID {
		t.Errorf("AppFor(bare name in a fixed folder) = %+v, %v; want %s", got, ok, testID)
	}
	// A relative path with a slash is neither a bare name nor a path, even
	// when it names a file from the agent's working directory.
	t.Chdir(dir)
	if _, err := os.Stat("bin/nazar-test-bare"); err != nil {
		t.Fatalf("the relative path does not resolve from the working directory: %v", err)
	}
	x3, _ := newIndex(t, p, dir)
	x3.bins = []string{bin}
	writeEntry(t, dir, "dev.nazar.Relative", entryFor("bin/nazar-test-bare"))
	b, err := x3.InstalledApp("dev.nazar.Relative")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(relative Exec) = %+v, %v; want ErrNotFound", b, err)
	}
	if want := `desktop: dev.nazar.Relative: its program "bin/nazar-test-bare" is a relative path`; err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
	// The program is testID's (the bare name in a fixed folder), not the
	// relative entry's, which would rank first for it were it an app.
	if got, ok := x3.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != testID {
		t.Errorf("AppFor(the program a relative Exec names) = %+v, %v; want %s", got, ok, testID)
	}
}

// TestTerminalEntryIsNotAnApp: a desktop entry with Terminal=true (vim,
// htop) is a command-line program the desktop opens a terminal for, not a
// desktop app: it is no app, so the terminal app above it in the chain is
// the app, as on macOS where a tool in a Terminal tab is never a bundle.
func TestTerminalEntryIsNotAnApp(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	tool := copySleep(t, dir, "vim")
	server := copySleep(t, dir, "terminal-server")
	writeEntry(t, dir, "dev.nazar.Vim", entryFor(tool)+"Terminal=true\n")
	writeEntry(t, dir, "dev.nazar.Term", entryFor(server))
	x, _ := newIndex(t, p, dir)
	b, err := x.InstalledApp("dev.nazar.Vim")
	if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
		t.Fatalf("InstalledApp(Terminal=true) = %+v, %v; want zero, ErrNotFound", b, err)
	}
	if want := "desktop: dev.nazar.Vim: its entry runs in a terminal (Terminal=true), so it is a command-line program, not a desktop app"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	srv := startRunning(t, server, server, "600")
	tl := startRunning(t, tool, tool, "600")
	srvInfo, tlInfo := infoOf(t, p, srv.Process.Pid), infoOf(t, p, tl.Process.Pid)
	if got, ok := x.AppFor([]platform.ProcessInfo{tlInfo}); ok {
		t.Errorf("AppFor(the terminal program) = %+v, true", got)
	}
	got, ok := x.AppFor([]platform.ProcessInfo{tlInfo, srvInfo})
	if !ok || got.BundleID != "dev.nazar.Term" || got.Ref != srvInfo.Ref {
		t.Errorf("AppFor(tool under the terminal) = %+v, %v; want dev.nazar.Term at %v", got, ok, srvInfo.Ref)
	}
	if apps := x.Apps(); len(apps) != 1 || apps[0].Ref != srvInfo.Ref {
		t.Errorf("Apps() = %+v, want the terminal only", apps)
	}
}

// TestRescanRetargetedExecutable: an upgrade that points the program's
// link at a new file (update-alternatives, /opt/app/current, a versioned
// install) and removes the old one changes nothing under applications,
// yet the index follows it: InstalledApp pins the new file and the new
// process is the app, so `nazar trust --app` works after the upgrade.
func TestRescanRetargetedExecutable(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	v1 := copySleep(t, dir, "app-1")
	v2 := copySleep(t, dir, "app-2")
	link := filepath.Join(dir, "app")
	if err := os.Symlink(v1, link); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, dir, testID, entryFor(link))
	x, now := newIndex(t, p, dir)
	settle(t, x, now)
	if b, err := x.InstalledApp(testID); err != nil || b.Path != v1 {
		t.Fatalf("InstalledApp before the upgrade = %+v, %v; want %s", b, err, v1)
	}
	if err := os.Symlink(v2, link+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(link+".new", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(v1); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(rescanEvery)
	b, err := x.InstalledApp(testID)
	if err != nil || b.Path != v2 || b.Code.Team() != PinTeam(fileSum(t, v2)) {
		t.Fatalf("InstalledApp after the upgrade = %+v, %v; want %s with its pin", b, err, v2)
	}
	running := startRunning(t, v2, v2, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != testID || got.Code.Team() != b.Code.Team() {
		t.Errorf("AppFor(the upgraded program) = %+v, %v; want %s", got, ok, testID)
	}
}

// TestRescanProgramAppears: an entry whose program is missing at the scan
// (installed later, or a bare name whose file lands in /usr/bin later) is
// an app once the file is there.
func TestRescanProgramAppears(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	late := filepath.Join(dir, "late")
	writeEntry(t, dir, "dev.nazar.Late", entryFor(late))
	writeEntry(t, dir, "dev.nazar.Bare", entryFor("nazar-late-bare"))
	x, now := newIndex(t, p, dir)
	x.bins = []string{bin}
	settle(t, x, now)
	for _, id := range []string{"dev.nazar.Late", "dev.nazar.Bare"} {
		if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) {
			t.Fatalf("InstalledApp(%s) before the file exists = %+v, %v; want ErrNotFound", id, b, err)
		}
	}
	// The bare name's file lands in the fixed folder: only that folder changed.
	bare := copySleep(t, bin, "nazar-late-bare")
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp("dev.nazar.Bare"); err != nil || b.Path != bare {
		t.Errorf("InstalledApp(Bare) once the file exists = %+v, %v; want %s", b, err, bare)
	}
	if b, err := x.InstalledApp("dev.nazar.Late"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(Late) while its file is still missing = %+v, %v; want ErrNotFound", b, err)
	}
	// Then the file an entry names by path appears: nothing else changed.
	settle(t, x, now)
	lateReal := copySleep(t, dir, "late")
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp("dev.nazar.Late"); err != nil || b.Path != lateReal {
		t.Errorf("InstalledApp(Late) once the file exists = %+v, %v; want %s", b, err, lateReal)
	}
	running := startRunning(t, lateReal, lateReal, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != "dev.nazar.Late" {
		t.Errorf("AppFor(the late program) = %+v, %v; want dev.nazar.Late", got, ok)
	}
}

// TestRescanChangeWithinSameTimestamp: a second change to an entry within
// the same coarse mtime (an editor that writes twice in a second, the
// same size) hides behind an unchanged stat; the index rescans once more
// after any recent change rather than trust the stat.
func TestRescanChangeWithinSameTimestamp(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	aa := copySleep(t, dir, "aa")
	bb := copySleep(t, dir, "bb")
	path := filepath.Join(dir, "applications", "dev.nazar.Same.desktop")
	writeEntry(t, dir, "dev.nazar.Same", entryFor(aa))
	x, now := newIndex(t, p, dir)
	if b, err := x.InstalledApp("dev.nazar.Same"); err != nil || b.Path != aa {
		t.Fatalf("InstalledApp = %+v, %v; want %s", b, err, aa)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The same size, the same mtime, the same inode: the stat cannot tell.
	if err := os.WriteFile(path, []byte(entryFor(bb)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if st2, err := os.Stat(path); err != nil || st2.Size() != st.Size() || !st2.ModTime().Equal(st.ModTime()) {
		t.Fatalf("the edit changed the stat: %v %v", st2, err)
	}
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp("dev.nazar.Same"); err != nil || b.Path != bb {
		t.Errorf("InstalledApp after a change the stat does not show = %+v, %v; want %s", b, err, bb)
	}
}

// TestSymlinkedApplicationsFolder: a data dir whose applications folder is
// a link (stow and other dotfile managers) holds the user's entries all
// the same, and they win over the system's.
func TestSymlinkedApplicationsFolder(t *testing.T) {
	p := procfs.New()
	user, store, system := t.TempDir(), t.TempDir(), t.TempDir()
	userApp := copySleep(t, store, "userapp")
	systemApp := copySleep(t, system, "systemapp")
	writeEntry(t, store, testID, entryFor(userApp))
	writeEntry(t, system, testID, entryFor(systemApp))
	if err := os.Symlink(filepath.Join(store, "applications"), filepath.Join(user, "applications")); err != nil {
		t.Fatal(err)
	}
	x, now := newIndex(t, p, user, system)
	if b, err := x.InstalledApp(testID); err != nil || b.Path != userApp {
		t.Fatalf("InstalledApp through the linked folder = %+v, %v; want %s", b, err, userApp)
	}
	running := startRunning(t, userApp, userApp, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != testID {
		t.Errorf("AppFor(user's program through the linked folder) = %+v, %v; want %s", got, ok, testID)
	}
	// A change behind the link is followed too.
	settle(t, x, now)
	if err := os.Remove(filepath.Join(store, "applications", testID+".desktop")); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp(testID); err != nil || b.Path != systemApp {
		t.Errorf("InstalledApp after the user's entry went = %+v, %v; want the system's %s", b, err, systemApp)
	}
}

// TestEntryFileNotRegular: a FIFO or a link to a device under a .desktop
// name is no entry, and the scan does not wait on it.
func TestEntryFileNotRegular(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "regular")
	writeEntry(t, dir, testID, entryFor(app))
	apps := filepath.Join(dir, "applications")
	if err := syscall.Mkfifo(filepath.Join(apps, "dev.nazar.Fifo.desktop"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(apps, "dev.nazar.Null.desktop")); err != nil {
		t.Fatal(err)
	}
	x, _ := newIndex(t, p, dir)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, id := range []string{"dev.nazar.Fifo", "dev.nazar.Null"} {
			if b, err := x.InstalledApp(id); !errors.Is(err, platform.ErrNotFound) {
				t.Errorf("InstalledApp(%s) = %+v, %v; want ErrNotFound", id, b, err)
			}
		}
		if b, err := x.InstalledApp(testID); err != nil || b.Path != app {
			t.Errorf("InstalledApp(%s) = %+v, %v; want %s", testID, b, err, app)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the scan hangs on a FIFO or a device under a .desktop name")
	}
}

func TestAppsAgreeWithAppFor(t *testing.T) {
	x, p, app, info := oneApp(t)
	// A second instance and a non-app process of this user, both live.
	second := startRunning(t, app, app, "600")
	startRunning(t, mustReal(t, sleepPath()), sleepPath(), "600")
	apps := x.Apps()
	want := map[platform.ProcessRef]bool{info.Ref: false, infoOf(t, p, second.Process.Pid).Ref: false}
	for _, a := range apps {
		if a.Ref.Generation == 0 || a.BundleID == "" {
			t.Errorf("Apps() lists %+v: not a full ref with an id", a)
			continue
		}
		if _, ok := want[a.Ref]; !ok {
			t.Errorf("Apps() lists %+v, which runs no app of the test's", a)
			continue
		}
		want[a.Ref] = true
		live := infoOf(t, p, a.Ref.PID)
		got, ok := x.AppFor([]platform.ProcessInfo{live})
		if !ok || got.Ref != a.Ref || got.BundleID != a.BundleID || got.Name != a.Name || got.Code.Team() != a.Code.Team() {
			t.Errorf("Apps() lists %+v but AppFor(its record) = %+v, %v", a, got, ok)
		}
		if a.Name != "Test App" || a.Code.Team() != PinTeam(fileSum(t, app)) {
			t.Errorf("Apps() entry %+v: want Name and the file's pin", a)
		}
	}
	for ref, seen := range want {
		if !seen {
			t.Errorf("Apps() does not list %v", ref)
		}
	}
}

func TestRescanOnFolderChange(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "late")
	writeEntry(t, dir, "dev.nazar.First", entryFor(app))
	x, now := newIndex(t, p, dir)
	if _, err := x.InstalledApp("dev.nazar.First"); err != nil {
		t.Fatal(err)
	}
	// A new entry is not seen at once (at most one scan per 2 s)...
	writeEntry(t, dir, "dev.nazar.Second", entryFor(copySleep(t, dir, "second")))
	if b, err := x.InstalledApp("dev.nazar.Second"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(just added) = %+v, %v; want ErrNotFound until the next scan", b, err)
	}
	// ...and is seen once the folder is looked at again.
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp("dev.nazar.Second"); err != nil || b.BundleID != "dev.nazar.Second" {
		t.Errorf("InstalledApp(after the rescan) = %+v, %v", b, err)
	}
	// A removed entry goes away the same way.
	if err := os.Remove(filepath.Join(dir, "applications", "dev.nazar.First.desktop")); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(rescanEvery)
	if b, err := x.InstalledApp("dev.nazar.First"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(removed) = %+v, %v; want ErrNotFound", b, err)
	}
}

// settle moves the clock past the index's unsettled window and scans, so
// the next rescan happens only for a change the look at the folders sees.
func settle(t *testing.T, x *Index, now *time.Time) {
	t.Helper()
	*now = now.Add(2 * rescanEvery)
	x.snapshot()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.unsettled {
		t.Fatal("index still unsettled after the clock moved on")
	}
}

func scans(x *Index) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.scans
}

// TestRescanSettledFolderNotRescanned: once settled, an unchanged folder
// is looked at but not read again, however often the interval passes; a
// change is.
func TestRescanSettledFolderNotRescanned(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "steady")
	writeEntry(t, dir, "dev.nazar.Steady", entryFor(app))
	x, now := newIndex(t, p, dir)
	settle(t, x, now)
	n := scans(x)
	for range 3 {
		*now = now.Add(rescanEvery)
		if _, err := x.InstalledApp("dev.nazar.Steady"); err != nil {
			t.Fatal(err)
		}
	}
	if got := scans(x); got != n {
		t.Errorf("scans = %d after three looks at an unchanged folder, want %d", got, n)
	}
	writeEntry(t, dir, "dev.nazar.Added", entryFor(copySleep(t, dir, "added")))
	*now = now.Add(rescanEvery)
	if _, err := x.InstalledApp("dev.nazar.Steady"); err != nil {
		t.Fatal(err)
	}
	if got := scans(x); got != n+1 {
		t.Errorf("scans = %d after a change, want %d", got, n+1)
	}
}

// TestRescanInPlaceEdit: an entry rewritten in place (an editor that does
// not rename, `>>`) changes no folder mtime, yet the index follows it:
// a new Exec, then Hidden=true.
func TestRescanInPlaceEdit(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	a := copySleep(t, dir, "a")
	b := copySleep(t, dir, "bb")
	path := filepath.Join(dir, "applications", "dev.nazar.Edited.desktop")
	writeEntry(t, dir, "dev.nazar.Edited", entryFor(a))
	x, now := newIndex(t, p, dir)
	settle(t, x, now)
	if got, err := x.InstalledApp("dev.nazar.Edited"); err != nil || got.Path != a {
		t.Fatalf("InstalledApp = %+v, %v; want %s", got, err, a)
	}
	if err := os.WriteFile(path, []byte(entryFor(b)), 0o644); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(rescanEvery)
	if got, err := x.InstalledApp("dev.nazar.Edited"); err != nil || got.Path != b {
		t.Errorf("InstalledApp after an in-place edit = %+v, %v; want %s", got, err, b)
	}
	running := startRunning(t, b, b, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != "dev.nazar.Edited" {
		t.Errorf("AppFor(new program) = %+v, %v; want dev.nazar.Edited", got, ok)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("Hidden=true\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	*now = now.Add(rescanEvery)
	if got, err := x.InstalledApp("dev.nazar.Edited"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp after Hidden=true was appended = %+v, %v; want ErrNotFound", got, err)
	}
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(hidden in place) = %+v, true", got)
	}
}

// TestRescanSubfolder: a change inside a subfolder of applications (ids
// such as kde4-foo) changes only that subfolder's mtime, yet the index
// follows it.
func TestRescanSubfolder(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "sub")
	sub := filepath.Join(dir, "applications", "kde4")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "one.desktop"), []byte(entryFor(app)), 0o644); err != nil {
		t.Fatal(err)
	}
	x, now := newIndex(t, p, dir)
	settle(t, x, now)
	if _, err := x.InstalledApp("kde4-one"); err != nil {
		t.Fatalf("InstalledApp(kde4-one) = %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "two.desktop"), []byte(entryFor(copySleep(t, dir, "two"))), 0o644); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(rescanEvery)
	if got, err := x.InstalledApp("kde4-two"); err != nil || got.BundleID != "kde4-two" {
		t.Errorf("InstalledApp(added in a subfolder) = %+v, %v", got, err)
	}
	if err := os.Remove(filepath.Join(sub, "one.desktop")); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(rescanEvery)
	if got, err := x.InstalledApp("kde4-one"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("InstalledApp(removed from a subfolder) = %+v, %v; want ErrNotFound", got, err)
	}
}

// tryEntry is a desktop entry with both TryExec and Exec.
func tryEntry(tryExec, exec string) string {
	return "[Desktop Entry]\nType=Application\nName=Try App\nTryExec=" + tryExec + "\nExec=" + exec + " %U\n"
}

// TestTryExecOnlySaysInstalled: TryExec only says the program is
// installed; what runs is Exec, so Exec's program is the app's file even
// when TryExec names another native program, and a process of TryExec's
// file is never the app (it would be the wrong program: Review Focus 1).
// A TryExec that names no file, as a path or as a bare name in the fixed
// folders, makes the entry no app, as the desktop hides such an entry;
// a TryExec that names a launcher changes nothing; an entry with no Exec
// runs nothing and is no app whatever TryExec says.
func TestTryExecOnlySaysInstalled(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	prog := copySleep(t, dir, "prog")
	wrapper := copySleep(t, dir, "wrapper")
	second := copySleep(t, dir, "second")
	third := copySleep(t, dir, "third")
	fourth := copySleep(t, dir, "fourth")
	copySleep(t, bin, "nazar-try-bare")
	py := copySleep(t, bin, "python3")
	gone := filepath.Join(dir, "gone")
	writeEntry(t, dir, "dev.nazar.Try", tryEntry(prog, wrapper))
	writeEntry(t, dir, "dev.nazar.Bare", tryEntry("nazar-try-bare", second))
	writeEntry(t, dir, "dev.nazar.Gone", tryEntry(gone, third))
	writeEntry(t, dir, "dev.nazar.BareGone", tryEntry("nazar-no-such-program", third))
	writeEntry(t, dir, "dev.nazar.PyTry", tryEntry(py, fourth))
	writeEntry(t, dir, "dev.nazar.NoExec", "[Desktop Entry]\nType=Application\nName=N\nTryExec="+prog+"\n")
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin}
	for id, want := range map[string]string{"dev.nazar.Try": wrapper, "dev.nazar.Bare": second, "dev.nazar.PyTry": fourth} {
		if b, err := x.InstalledApp(id); err != nil || b.Path != want || b.Code.Team() != PinTeam(fileSum(t, want)) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want Exec's %s with its pin", id, b, err, want)
		}
	}
	for id, want := range map[string]string{
		"dev.nazar.Gone":     "desktop: dev.nazar.Gone: its TryExec " + strconv.Quote(gone) + " names no installed file, so the desktop does not show the entry",
		"dev.nazar.BareGone": `desktop: dev.nazar.BareGone: its TryExec "nazar-no-such-program" names no installed file, so the desktop does not show the entry`,
		"dev.nazar.NoExec":   "desktop: dev.nazar.NoExec: its entry names no program",
	} {
		b, err := x.InstalledApp(id)
		if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
		} else if err.Error() != want {
			t.Errorf("InstalledApp(%s) error = %q, want %q", id, err.Error(), want)
		}
	}
	// A process of Exec's file is the app; a process of TryExec's file,
	// which the entry does not run, is not, and neither is a process of
	// the Exec of an entry hidden by its TryExec.
	running := startRunning(t, wrapper, wrapper, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != "dev.nazar.Try" || got.Code.Team() != PinTeam(fileSum(t, wrapper)) {
		t.Errorf("AppFor(Exec's program) = %+v, %v; want dev.nazar.Try with the file's pin", got, ok)
	}
	for _, file := range []string{prog, third, py} {
		other := startRunning(t, file, file, "600")
		if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, other.Process.Pid)}); ok {
			t.Errorf("AppFor(a process of %s) = %+v, true; want no app", file, got)
		}
	}
	if apps := x.Apps(); len(apps) != 1 || apps[0].BundleID != "dev.nazar.Try" {
		t.Errorf("Apps() = %+v, want the one process of Exec's program", apps)
	}
}

// TestTryExecKeepsTheLauncherCheck: TryExec only says the program is
// installed; what runs is Exec. An entry whose Exec is a shell, an
// interpreter or a launcher (by the name written or by the file it
// resolves to) is no app whatever file TryExec names, or the pin would be
// of a file the entry never runs, and every process of that file would
// be the app.
func TestTryExecKeepsTheLauncherCheck(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	git := copySleep(t, dir, "git")
	dash := copySleep(t, bin, "dash")
	run := filepath.Join(bin, "run")
	if err := os.Symlink(dash, run); err != nil {
		t.Fatal(err)
	}
	py := copySleep(t, bin, "python3")
	writeEntry(t, dir, "dev.nazar.ShellTry", tryEntry(git, "sh -c real-gui"))
	writeEntry(t, dir, "dev.nazar.LinkTry", tryEntry(git, run+" -c real-gui"))
	writeEntry(t, dir, "dev.nazar.PyTry", tryEntry(git, py+" /opt/app/main.py"))
	x, _ := newIndex(t, p, dir)
	x.bins = []string{bin}
	for id, prog := range map[string]string{"dev.nazar.ShellTry": "sh", "dev.nazar.LinkTry": dash, "dev.nazar.PyTry": py} {
		b, err := x.InstalledApp(id)
		if !errors.Is(err, platform.ErrNotFound) || !zeroBundle(b) {
			t.Errorf("InstalledApp(%s) = %+v, %v; want zero, ErrNotFound", id, b, err)
			continue
		}
		if want := "desktop: " + id + ": its program " + strconv.Quote(prog) + " is a shell, interpreter or launcher that starts some other program, so no process can match app:" + strconv.Quote(id); err.Error() != want {
			t.Errorf("InstalledApp(%s) error = %q, want %q", id, err.Error(), want)
		}
	}
	running := startRunning(t, git, git, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); ok {
		t.Errorf("AppFor(TryExec's file, which no entry runs) = %+v, true", got)
	}
	if apps := x.Apps(); len(apps) != 0 {
		t.Errorf("Apps() = %+v, want none", apps)
	}
}

// TestInvalidIDIgnored: a desktop file whose name has a control character
// or white space is no entry: such an id can never be an app: value, and
// it would otherwise reach logs and messages and, being lexically first,
// take over the program of a well-named entry.
func TestInvalidIDIgnored(t *testing.T) {
	p := procfs.New()
	dir := t.TempDir()
	app := copySleep(t, dir, "idapp")
	apps := filepath.Join(dir, "applications")
	writeEntry(t, dir, "dev.nazar.Good", entryFor(app))
	bad := []string{"dev.nazar.New\nline", "dev.nazar.Esc\x1b[0m", "dev nazar.Space", "dev.nazar.Tab\t", "dev.nazar.Bad\xff"}
	for _, id := range bad {
		if err := os.WriteFile(filepath.Join(apps, id+".desktop"), []byte(entryFor(app)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	x, _ := newIndex(t, p, dir)
	for _, id := range bad {
		if b, err := x.InstalledApp(id); err != platform.ErrNotFound || !zeroBundle(b) {
			t.Errorf("InstalledApp(%q) = %+v, %v; want zero, the bare ErrNotFound (no entry)", id, b, err)
		}
	}
	if b, err := x.InstalledApp("dev.nazar.Good"); err != nil || b.Path != app {
		t.Errorf("InstalledApp(Good) = %+v, %v; want %s", b, err, app)
	}
	running := startRunning(t, app, app, "600")
	if got, ok := x.AppFor([]platform.ProcessInfo{infoOf(t, p, running.Process.Pid)}); !ok || got.BundleID != "dev.nazar.Good" {
		t.Errorf("AppFor = %+v, %v; want dev.nazar.Good", got, ok)
	}
}

func TestExecWord(t *testing.T) {
	for in, want := range map[string]string{
		`/usr/bin/foo --flag %U`:        "/usr/bin/foo",
		`"/opt/my app/bin/app" %F`:      "/opt/my app/bin/app",
		`"/opt/q\\"uote/app"`:           `/opt/q"uote/app`,
		`foo`:                           "foo",
		`  /usr/bin/spaced  `:           "/usr/bin/spaced",
		``:                              "",
		`"unterminated`:                 "",
		"/usr/bin/foo\\\\bar":           `/usr/bin/foo\bar`,
		"/usr/bin/env FOO=1 /opt/x/app": "/usr/bin/env",
		// A closing quote must end the argument: "/usr/bin/sleep"x is no
		// argument the spec allows, and a shell would run /usr/bin/sleepx.
		`"/usr/bin/sleep"x`:   "",
		`"/usr/bin/sleep"`:    "/usr/bin/sleep",
		`"/usr/bin/sleep"	%U`: "/usr/bin/sleep",
	} {
		if got := execWord(in); got != want {
			t.Errorf("execWord(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseEntry(t *testing.T) {
	e, ok := parseEntry([]byte("# comment\n[Other]\nType=Link\n[Desktop Entry]\nType = Application\nName=Hello\nName[de]=Hallo\nTryExec=/usr/bin/hello\nExec=/usr/bin/hello %U\nNoDisplay=false\n"))
	if !ok {
		t.Fatal("parseEntry: not an application")
	}
	if e.Name != "Hello" || e.TryExec != "/usr/bin/hello" || e.Exec != "/usr/bin/hello %U" || e.Terminal {
		t.Errorf("parseEntry = %+v", e)
	}
	// Terminal=true is an application entry still; the index tells it apart.
	e, ok = parseEntry([]byte("[Desktop Entry]\nType=Application\nName=Vim\nExec=vim %F\nTerminal=true\n"))
	if !ok || !e.Terminal || e.Exec != "vim %F" {
		t.Errorf("parseEntry(Terminal=true) = %+v, %v; want an application with Terminal set", e, ok)
	}
	if e, ok := parseEntry([]byte("[Desktop Entry]\nType=Application\nName=X\nExec=/x\nTerminal=false\n")); !ok || e.Terminal {
		t.Errorf("parseEntry(Terminal=false) = %+v, %v", e, ok)
	}
	// 1 is true to the desktop's key file reader (an old spelling).
	if e, ok := parseEntry([]byte("[Desktop Entry]\nType=Application\nName=X\nExec=/x\nTerminal=1\n")); !ok || !e.Terminal {
		t.Errorf("parseEntry(Terminal=1) = %+v, %v; want Terminal set", e, ok)
	}
	// Name and TryExec take the string escapes; Exec is kept as written
	// for execWord.
	e, ok = parseEntry([]byte("[Desktop Entry]\nType=Application\nName=Hello\\sWorld\\n\nTryExec=/opt/my\\sapp/x\nExec=/opt/my\\sapp/x %U\n"))
	if !ok || e.Name != "Hello World\n" || e.TryExec != "/opt/my app/x" || e.Exec != `/opt/my\sapp/x %U` {
		t.Errorf("parseEntry(escapes) = %+v, %v", e, ok)
	}
	for name, body := range map[string]string{
		"hidden":      "[Desktop Entry]\nType=Application\nHidden=true\nExec=/x\n",
		"nodisplay":   "[Desktop Entry]\nType=Application\nNoDisplay=true\nExec=/x\n",
		"hidden=1":    "[Desktop Entry]\nType=Application\nHidden=1\nExec=/x\n",
		"nodisplay=1": "[Desktop Entry]\nType=Application\nNoDisplay=1\nExec=/x\n",
		"link":        "[Desktop Entry]\nType=Link\nURL=https://x\n",
		"no type":     "[Desktop Entry]\nName=X\nExec=/x\n",
		"no group":    "Type=Application\nExec=/x\n",
		"other group": "[Desktop Action new]\nType=Application\nExec=/x\n",
		"empty":       "",
	} {
		if e, ok := parseEntry([]byte(body)); ok {
			t.Errorf("parseEntry(%s) = %+v, true", name, e)
		}
	}
	// Keys in a later group do not belong to the entry.
	e, ok = parseEntry([]byte("[Desktop Entry]\nType=Application\nName=A\nExec=/a\n[Desktop Action b]\nName=B\nExec=/b\n"))
	if !ok || e.Name != "A" || e.Exec != "/a" {
		t.Errorf("parseEntry(with action) = %+v, %v", e, ok)
	}
}
