//go:build linux

package dialog

// The dialog program under test is never zenity or kdialog: TestMain builds
// internal/linuxtest/fakedialog, and every Dialog here runs it through a
// small shell wrapper that gives it the scripted answers' socket and its
// log file (the allowlist would strip them from the environment, which is
// the point of the allowlist). Nothing here shows a window.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/internal/linuxtest/answers"
)

// fakePath is the fakedialog binary, built once in TestMain.
var fakePath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "nzdlg")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakePath = filepath.Join(dir, "fakedialog")
	build := exec.Command(goTool(), "build", "-o", fakePath, "github.com/atas/nazar/internal/linuxtest/fakedialog")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build fakedialog:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

// entry is one line of the fake's log: what it was run with.
type entry struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
}

// fake is one scripted dialog program: the answers queue it pops from, the
// log it appends to and the wrapper script Confirm runs.
type fake struct {
	q       *answers.Queue
	log     string
	program string
}

// newFake writes the wrapper. With then empty the wrapper execs the fake,
// so its exit code is the fake's; otherwise it runs the fake and then the
// shell line then (an `exit 7`, say), which decides the exit code.
func newFake(t *testing.T, then string) *fake {
	t.Helper()
	q := answers.NewQueue(t)
	dir := t.TempDir()
	f := &fake{q: q, log: filepath.Join(dir, "dialog.log"), program: filepath.Join(dir, "dialog")}
	run := "exec '" + fakePath + "' \"$@\"\n"
	if then != "" {
		run = "'" + fakePath + "' \"$@\"\n" + then + "\n"
	}
	script := "#!/bin/sh\nexport NAZAR_TEST_ANSWERS='" + q.Socket() + "' NAZAR_TEST_DIALOG_LOG='" + f.log + "'\n" + run
	if err := os.WriteFile(f.program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

// script writes a program that does nothing but exit with code, for the
// ends a dialog program can have that the fake does not produce itself.
func script(t *testing.T, code int) string {
	t.Helper()
	return shell(t, fmt.Sprintf("exit %d", code))
}

// shell writes a program whose body is the given sh lines.
func shell(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dialog")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// newForkedFake writes a wrapper that runs the fake in the background,
// records its PID in the returned file and waits for it: a dialog
// program that is a script around the real window, as a distribution
// might ship. Killing the wrapper alone leaves the fake running.
func newForkedFake(t *testing.T) (f *fake, pidFile string) {
	t.Helper()
	q := answers.NewQueue(t)
	dir := t.TempDir()
	f = &fake{q: q, log: filepath.Join(dir, "dialog.log"), program: filepath.Join(dir, "dialog")}
	pidFile = filepath.Join(dir, "pid")
	script := "#!/bin/sh\nexport NAZAR_TEST_ANSWERS='" + q.Socket() + "' NAZAR_TEST_DIALOG_LOG='" + f.log + "'\n" +
		"'" + fakePath + "' \"$@\" &\necho $! > '" + pidFile + "'\nwait\n"
	if err := os.WriteFile(f.program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return f, pidFile
}

// alive is whether pid is a running process (a zombie, reaped or not, is
// not alive: it holds no window).
func alive(pid int) bool {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "State:") {
			return !strings.Contains(line, "Z")
		}
	}
	return true
}

// entries reads the fake's log; a missing log is no entries.
func (f *fake) entries(t *testing.T) []entry {
	t.Helper()
	file, err := os.Open(f.log)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var out []entry
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		var e entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// one is the single log entry the dialog must have produced.
func (f *fake) one(t *testing.T) entry {
	t.Helper()
	es := f.entries(t)
	if len(es) != 1 {
		t.Fatalf("the fake ran %d times, want 1", len(es))
	}
	return es[0]
}

// x11 is a graphical session as the agent would see it, with things that
// must not reach the dialog program mixed in.
func x11() []string {
	return []string{
		"DISPLAY=:0",
		"HOME=/home/nazartest",
		"LANG=C.UTF-8",
		"PATH=/home/nazartest/.local/bin:/usr/local/bin:/usr/bin:/bin",
		"SECRET_TOKEN=hunter2",
		"SSH_AUTH_SOCK=/run/user/1000/nazar/agent.sock",
	}
}

func (f *fake) dialog(k Kind, env func() []string) Dialog {
	return Dialog{Program: f.program, Kind: k, Env: env}
}

var prompt = platform.Prompt{
	Title:       `Terminal wants to use key "github"`,
	Lines:       []string{"a <b>& c", "ssh git@github.com", "Allow for this session?"},
	CommandLine: 2,
	Timeout:     60 * time.Second,
}

func TestZenityArgs(t *testing.T) {
	got := Args(Zenity, prompt)
	want := []string{
		"--question", "--no-markup", "--default-cancel",
		`--title=Terminal wants to use key "github"`,
		"--text=a <b>& c\nssh git@github.com\nAllow for this session?",
		"--ok-label=Allow", "--cancel-label=Deny",
		"--timeout=60",
	}
	if !slices.Equal(got, want) {
		t.Errorf("zenity argv\n got %q\nwant %q", got, want)
	}
}

func TestZenityTimeoutRoundsUp(t *testing.T) {
	p := prompt
	p.Timeout = 1500 * time.Millisecond
	got := Args(Zenity, p)
	if got[len(got)-1] != "--timeout=2" {
		t.Errorf("1.5 s gives %q, want --timeout=2", got[len(got)-1])
	}
}

func TestKDialogArgs(t *testing.T) {
	got := Args(KDialog, prompt)
	want := []string{
		"--title", `Terminal wants to use key "github"`,
		"--warningyesno", "<qt>a &lt;b&gt;&amp; c<br>ssh git@github.com<br>Allow for this session?</qt>",
		"--yes-label", "Allow",
		"--no-label", "Deny",
	}
	if !slices.Equal(got, want) {
		t.Errorf("kdialog argv\n got %q\nwant %q", got, want)
	}
}

// A title or line that looks like an option is still text: zenity gets it
// inside `--title=`/`--text=`, kdialog as the value right after `--title`
// or wrapped in <qt>. No element of either argv is an option nazar did not
// put there.
func TestArgsCannotBeOptions(t *testing.T) {
	p := platform.Prompt{Title: "--text=pwned", Lines: []string{"--help", "--timeout=0"}, Timeout: 30 * time.Second}

	z := Args(Zenity, p)
	if len(z) != 8 {
		t.Fatalf("zenity argv has %d elements, want 8: %q", len(z), z)
	}
	if z[3] != "--title=--text=pwned" {
		t.Errorf("zenity title element is %q", z[3])
	}
	if z[4] != "--text=--help\n--timeout=0" {
		t.Errorf("zenity text element is %q", z[4])
	}
	fixed := []string{"--question", "--no-markup", "--default-cancel", "--ok-label=Allow", "--cancel-label=Deny", "--timeout=30"}
	for i, a := range z {
		if i == 3 || i == 4 {
			continue
		}
		if !slices.Contains(fixed, a) {
			t.Errorf("unexpected zenity element %q", a)
		}
	}

	k := Args(KDialog, p)
	want := []string{"--title", "--text=pwned", "--warningyesno", "<qt>--help<br>--timeout=0</qt>", "--yes-label", "Allow", "--no-label", "Deny"}
	if !slices.Equal(k, want) {
		t.Errorf("kdialog argv\n got %q\nwant %q", k, want)
	}
}

func TestAllow(t *testing.T) {
	f := newFake(t, "")
	f.q.Push(true)
	ok, err := f.dialog(Zenity, x11).Confirm(prompt)
	if err != nil || !ok {
		t.Fatalf("Confirm = %v, %v; want true, nil", ok, err)
	}
	e := f.one(t)
	if want := Args(Zenity, prompt); !slices.Equal(e.Argv[1:], want) {
		t.Errorf("the program got %q, want %q", e.Argv[1:], want)
	}
}

func TestDeny(t *testing.T) {
	f := newFake(t, "")
	f.q.Push(false)
	ok, err := f.dialog(KDialog, x11).Confirm(prompt)
	if err != nil || ok {
		t.Fatalf("Confirm = %v, %v; want false, nil", ok, err)
	}
	e := f.one(t)
	if want := Args(KDialog, prompt); !slices.Equal(e.Argv[1:], want) {
		t.Errorf("the program got %q, want %q", e.Argv[1:], want)
	}
}

func wantDenied(t *testing.T, ok bool, err error, how platform.DialogHow) {
	t.Helper()
	if ok {
		t.Fatalf("Confirm allowed (err %v)", err)
	}
	var d platform.DialogDenied
	if !errors.As(err, &d) {
		t.Fatalf("Confirm error %v, want DialogDenied{%v}", err, how)
	}
	if d.How != how {
		t.Errorf("DialogDenied{%v}, want %v", d.How, how)
	}
	if !errors.Is(err, platform.ErrDenied) {
		t.Errorf("%v does not wrap ErrDenied", err)
	}
}

// With no answer the fake sits there for 10 s; Confirm must not wait for
// it: it kills the program at Timeout + 2 s and reports the timeout. The
// same path serves both programs (kdialog has no countdown of its own).
func TestTimedOut(t *testing.T) {
	for _, k := range []Kind{Zenity, KDialog} {
		t.Run(k.String(), func(t *testing.T) {
			t.Parallel()
			f := newFake(t, "")
			p := prompt
			p.Timeout = time.Second
			start := time.Now()
			ok, err := f.dialog(k, x11).Confirm(p)
			took := time.Since(start)
			wantDenied(t, ok, err, platform.DialogTimedOut)
			if took > p.Timeout+3*time.Second {
				t.Errorf("Confirm took %v, want under %v", took, p.Timeout+3*time.Second)
			}
			if took < p.Timeout+2*time.Second {
				t.Errorf("Confirm took %v; the program should have been given %v", took, p.Timeout+2*time.Second)
			}
			f.one(t)
		})
	}
}

// The dialog program is a wrapper script around the window: at the
// timeout Confirm must take the window down too, not only the script,
// or a window nobody listens to stays on screen.
func TestTimedOutKillsTheWholeGroup(t *testing.T) {
	f, pidFile := newForkedFake(t)
	p := prompt
	p.Timeout = time.Second
	ok, err := f.dialog(Zenity, x11).Confirm(p)
	wantDenied(t, ok, err, platform.DialogTimedOut)
	f.one(t)
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Sscan(string(raw), &pid); err != nil || pid <= 0 {
		t.Fatalf("pid file %q: %v", raw, err)
	}
	deadline := time.Now().Add(time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("the window process %d is still running after Confirm returned", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The program answered Allow and then its process ended with another
// code: that is not an answer.
func TestCrashIsClosed(t *testing.T) {
	f := newFake(t, "exit 7")
	f.q.Push(true)
	ok, err := f.dialog(Zenity, x11).Confirm(prompt)
	wantDenied(t, ok, err, platform.DialogClosed)
	f.one(t)
}

// Every exit code the real programs document, per program.
func TestExitCodes(t *testing.T) {
	cases := []struct {
		kind Kind
		code int
		ok   bool
		how  platform.DialogHow // when ok is false and an error is expected
		nilE bool               // (false, nil)
	}{
		{Zenity, 0, true, 0, true},
		{Zenity, 1, false, 0, true},
		{Zenity, 2, false, platform.DialogClosed, false},
		{Zenity, 5, false, platform.DialogTimedOut, false},
		{Zenity, 255, false, platform.DialogClosed, false},
		{KDialog, 0, true, 0, true},
		{KDialog, 1, false, 0, true},
		{KDialog, 2, false, 0, true},
		{KDialog, 5, false, platform.DialogClosed, false},
		{KDialog, 255, false, platform.DialogClosed, false},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%v_%d", c.kind, c.code), func(t *testing.T) {
			d := Dialog{Program: script(t, c.code), Kind: c.kind, Env: x11}
			ok, err := d.Confirm(prompt)
			if c.nilE {
				if err != nil || ok != c.ok {
					t.Fatalf("Confirm = %v, %v; want %v, nil", ok, err, c.ok)
				}
				return
			}
			wantDenied(t, ok, err, c.how)
		})
	}
}

// programEnv runs the fake with env and returns the environment it saw.
func programEnv(t *testing.T, env []string) map[string]string {
	t.Helper()
	f := newFake(t, "")
	f.q.Push(true)
	if ok, err := f.dialog(Zenity, func() []string { return env }).Confirm(prompt); err != nil || !ok {
		t.Fatalf("Confirm = %v, %v", ok, err)
	}
	got := map[string]string{}
	for _, kv := range f.one(t).Env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	return got
}

// wantEnv checks that the program saw exactly want: the wrapper adds the
// two test variables (that is what it is for) and the shell may export
// its own bookkeeping; nothing else may appear.
func wantEnv(t *testing.T, got, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q reached the program, want %q", k, got[k], v)
		}
	}
	tolerated := []string{"NAZAR_TEST_ANSWERS", "NAZAR_TEST_DIALOG_LOG", "PWD", "OLDPWD", "SHLVL", "_"}
	for k := range got {
		if _, ok := want[k]; ok || slices.Contains(tolerated, k) {
			continue
		}
		t.Errorf("%s reached the program", k)
	}
}

// Only the allowlisted variables reach the program, with nazar's PATH in
// place of the agent's. This is a Wayland session that also has an X11
// display (XWayland), as Plasma and GNOME set up: the program must not
// see DISPLAY or XAUTHORITY, and must be told to use Wayland only, or Qt
// opens an X11 window where any same-user client can click Allow.
func TestEnvAllowlist(t *testing.T) {
	got := programEnv(t, []string{
		"DISPLAY=:1", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/home/nazartest/.Xauthority",
		"XDG_RUNTIME_DIR=/run/user/1000", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"LANG=en_IE.UTF-8", "LC_ALL=C", "HOME=/home/nazartest",
		"PATH=/home/nazartest/.local/bin:/usr/bin",
		"SECRET_TOKEN=hunter2", "AWS_SECRET_ACCESS_KEY=x", "SSH_AUTH_SOCK=/a", "NAZAR_SOCKET=/b",
		"LD_PRELOAD=/evil.so", "XDG_CURRENT_DESKTOP=GNOME", "TERM=xterm", "XDG_SESSION_TYPE=wayland",
	})
	for _, k := range []string{"DISPLAY", "XAUTHORITY"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s=%q reached the program on a Wayland session", k, v)
		}
	}
	wantEnv(t, got, map[string]string{
		"WAYLAND_DISPLAY": "wayland-0", "GDK_BACKEND": "wayland", "QT_QPA_PLATFORM": "wayland",
		"XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
		"LANG": "en_IE.UTF-8", "LC_ALL": "C", "HOME": "/home/nazartest",
		"PATH": "/usr/bin:/bin",
	})
}

// The user's own backend choice in the agent's environment cannot send
// the window back to X11 on a Wayland session.
func TestWaylandOverridesUsersBackend(t *testing.T) {
	got := programEnv(t, []string{
		"WAYLAND_DISPLAY=wayland-1", "DISPLAY=:0", "XDG_RUNTIME_DIR=/run/user/1000", "HOME=/home/nazartest",
		"QT_QPA_PLATFORM=xcb", "GDK_BACKEND=x11",
	})
	wantEnv(t, got, map[string]string{
		"WAYLAND_DISPLAY": "wayland-1", "GDK_BACKEND": "wayland", "QT_QPA_PLATFORM": "wayland",
		"XDG_RUNTIME_DIR": "/run/user/1000", "HOME": "/home/nazartest", "PATH": "/usr/bin:/bin",
	})
}

// On an X11 session (no WAYLAND_DISPLAY) the X11 variables reach the
// program as they are and no backend is forced on it.
func TestX11EnvKeepsDisplay(t *testing.T) {
	got := programEnv(t, []string{
		"DISPLAY=:1", "XAUTHORITY=/home/nazartest/.Xauthority", "WAYLAND_DISPLAY=",
		"XDG_RUNTIME_DIR=/run/user/1000", "HOME=/home/nazartest", "QT_QPA_PLATFORM=wayland",
	})
	wantEnv(t, got, map[string]string{
		"DISPLAY": ":1", "XAUTHORITY": "/home/nazartest/.Xauthority", "WAYLAND_DISPLAY": "",
		"XDG_RUNTIME_DIR": "/run/user/1000", "HOME": "/home/nazartest", "PATH": "/usr/bin:/bin",
	})
}

// No DISPLAY and no WAYLAND_DISPLAY: nothing to show a window on. Confirm
// says so at once, runs nothing and consumes no answer.
func TestNoDisplayFailsFast(t *testing.T) {
	f := newFake(t, "")
	f.q.Push(true)
	env := func() []string { return []string{"HOME=/home/nazartest", "XDG_RUNTIME_DIR=/run/user/1000", "DISPLAY="} }
	start := time.Now()
	ok, err := f.dialog(Zenity, env).Confirm(prompt)
	took := time.Since(start)
	if ok || err == nil || err.Error() != "no graphical session for the dialog" {
		t.Fatalf("Confirm = %v, %v", ok, err)
	}
	if errors.Is(err, platform.ErrDenied) {
		t.Errorf("a missing display is an error, not the user's denial: %v", err)
	}
	if took > 100*time.Millisecond {
		t.Errorf("Confirm took %v, want under 100 ms", took)
	}
	if es := f.entries(t); len(es) != 0 {
		t.Errorf("the program ran %d times", len(es))
	}
	if allow, got := f.q.Pop(0); !got || !allow {
		t.Errorf("the queued answer was consumed")
	}
}

func TestWaylandIsEnough(t *testing.T) {
	f := newFake(t, "")
	f.q.Push(true)
	env := func() []string { return []string{"WAYLAND_DISPLAY=wayland-0", "XDG_RUNTIME_DIR=/run/user/1000"} }
	if ok, err := f.dialog(Zenity, env).Confirm(prompt); err != nil || !ok {
		t.Fatalf("Confirm = %v, %v", ok, err)
	}
}

func TestMissingProgramIsAnError(t *testing.T) {
	d := Dialog{Program: filepath.Join(t.TempDir(), "none"), Kind: Zenity, Env: x11}
	ok, err := d.Confirm(prompt)
	if ok || err == nil {
		t.Fatalf("Confirm = %v, %v", ok, err)
	}
	if errors.Is(err, platform.ErrDenied) {
		t.Errorf("a program that cannot start is an error, not the user's denial: %v", err)
	}
}

// neitherInstalled is Find on a machine with no dialog program.
func neitherInstalled(desktop string, env func() []string) (Dialog, error) {
	return find(desktop, env, func(string) bool { return false })
}

// On a graphical session with no dialog program the gate names what to
// install, not the display: this is what `nazar log` shows for the refusal.
func TestNoProgramSaysWhatToInstall(t *testing.T) {
	d, err := neitherInstalled("GNOME", x11)
	if err == nil {
		t.Fatalf("find with neither program: %+v", d)
	}
	for name, d := range map[string]Dialog{"what find returned": d, "a zero program": {Env: x11}} {
		start := time.Now()
		ok, err := d.confirm(prompt, neitherInstalled)
		if ok || err == nil || err.Error() != "no dialog program: install zenity or kdialog" {
			t.Errorf("%s: confirm = %v, %v", name, ok, err)
		}
		if errors.Is(err, platform.ErrDenied) {
			t.Errorf("%s: a missing program is an error, not the user's denial: %v", name, err)
		}
		if took := time.Since(start); took > 100*time.Millisecond {
			t.Errorf("%s: confirm took %v, want under 100 ms", name, took)
		}
	}
}

// Find runs once, at the agent's start. Installing zenity later is enough:
// the next prompt looks again, on the same desktop, and shows the window.
func TestProgramInstalledAfterStartIsUsed(t *testing.T) {
	f := newFake(t, "")
	f.q.Push(true)
	d, err := neitherInstalled("plasma:KDE", x11)
	if err == nil {
		t.Fatalf("find with neither program: %+v", d)
	}
	var desktops []string
	installed := func(desktop string, env func() []string) (Dialog, error) {
		desktops = append(desktops, desktop)
		return f.dialog(Zenity, env), nil
	}
	if ok, err := d.confirm(prompt, installed); err != nil || !ok {
		t.Fatalf("confirm = %v, %v", ok, err)
	}
	if !slices.Equal(desktops, []string{"plasma:KDE"}) {
		t.Errorf("looked for the program on desktops %q", desktops)
	}
	if es := f.entries(t); len(es) != 1 {
		t.Errorf("the program ran %d times, want once", len(es))
	}
}

// Nowhere to draw is the first thing to fix, and needs no program: a
// machine with neither a display nor zenity still says it has no display.
func TestNoDisplayComesBeforeNoProgram(t *testing.T) {
	looked := false
	look := func(desktop string, env func() []string) (Dialog, error) {
		looked = true
		return neitherInstalled(desktop, env)
	}
	headless := func() []string { return []string{"HOME=/home/nazartest"} }
	d := Dialog{Env: headless}
	if ok, err := d.confirm(prompt, look); ok || err == nil || err.Error() != "no graphical session for the dialog" {
		t.Errorf("confirm = %v, %v", ok, err)
	}
	if looked {
		t.Errorf("looked for a program with nowhere to draw")
	}
}

// The toolkit could not open the display: GTK exits 1 like a denial, Qt
// aborts like a crash. Neither showed a window, so neither is the user's
// decision: Confirm returns an error that carries the toolkit's line.
func TestDisplayFailureIsAnError(t *testing.T) {
	cases := []struct {
		name string
		kind Kind
		body string
		line string
	}{
		{"gtk", Zenity, `echo "" >&2; echo "(zenity:4242): Gtk-WARNING **: 20:24:01.123: cannot open display: :1" >&2; exit 1`,
			"(zenity:4242): Gtk-WARNING **: 20:24:01.123: cannot open display: :1"},
		{"gtk-wayland", Zenity, `echo "Unable to init server: Could not connect: Connection refused" >&2; echo "(zenity:7): Gtk-WARNING **: cannot open display" >&2; exit 1`,
			"(zenity:7): Gtk-WARNING **: cannot open display"},
		// GTK 4 (zenity 4.0.5 on Fedora 41, a stale DISPLAY or a dead
		// Wayland socket) words it differently and still exits 1.
		{"gtk4", Zenity, `echo "(zenity:5120): Gtk-WARNING **: 10:02:17.448: Failed to open display" >&2; exit 1`,
			"(zenity:5120): Gtk-WARNING **: 10:02:17.448: Failed to open display"},
		{"qt-xcb", KDialog, `echo "qt.qpa.xcb: could not connect to display :1" >&2; echo "This application failed to start because no Qt platform plugin could be initialized." >&2; kill -ABRT $$`,
			"qt.qpa.xcb: could not connect to display :1"},
		{"qt-wayland", KDialog, `echo "Failed to create wl_display (No such file or directory)" >&2; echo "qt.qpa.plugin: Could not load the Qt platform plugin \"wayland\" in \"\" even though it was found." >&2; kill -ABRT $$`,
			"Failed to create wl_display (No such file or directory)"},
		{"qt-no-plugin", KDialog, `echo "qt.qpa.plugin: Could not find the Qt platform plugin \"wayland\" in \"\"" >&2; kill -ABRT $$`,
			`qt.qpa.plugin: Could not find the Qt platform plugin "wayland" in ""`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Dialog{Program: shell(t, c.body), Kind: c.kind, Env: x11}
			ok, err := d.Confirm(prompt)
			if ok || err == nil {
				t.Fatalf("Confirm = %v, %v", ok, err)
			}
			if errors.Is(err, platform.ErrDenied) {
				t.Errorf("a display failure is an error, not the user's denial: %v", err)
			}
			want := fmt.Sprintf("dialog: %v could not open the display: %s", c.kind, c.line)
			if err.Error() != want {
				t.Errorf("error\n got %q\nwant %q", err, want)
			}
		})
	}
}

// Ordinary toolkit noise on stderr (a missing module, a theme warning) is
// not a display failure: exit 1 with it is still the user's denial, and
// exit 0 is still Allow.
func TestStderrNoiseIsNotADisplayFailure(t *testing.T) {
	noise := `echo 'Gtk-Message: Failed to load module "canberra-gtk-module"' >&2; echo "QStandardPaths: XDG_RUNTIME_DIR not set" >&2; `
	d := Dialog{Program: shell(t, noise+"exit 1"), Kind: Zenity, Env: x11}
	if ok, err := d.Confirm(prompt); ok || err != nil {
		t.Errorf("exit 1 with noise: Confirm = %v, %v; want false, nil", ok, err)
	}
	d = Dialog{Program: shell(t, noise+"exit 0"), Kind: KDialog, Env: x11}
	if ok, err := d.Confirm(prompt); !ok || err != nil {
		t.Errorf("exit 0 with noise: Confirm = %v, %v; want true, nil", ok, err)
	}
}

// A very loud program cannot make Confirm hold its whole output.
func TestStderrIsBounded(t *testing.T) {
	h := &head{limit: 8}
	for range 1000 {
		if n, err := h.Write([]byte("0123456789")); n != 10 || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	if h.String() != "01234567" {
		t.Errorf("kept %q", h.String())
	}
}

// For an unknown app kdialog shows the broker's warning line in bold, the
// nearest thing to the red header on macOS. Zenity's text has no markup.
func TestKDialogUnknownIsBold(t *testing.T) {
	p := prompt
	p.Unknown = true
	p.Lines = append([]string{"Unknown app: nazar could not tell which app started this."}, p.Lines...)
	k := Args(KDialog, p)
	want := "<qt><b>Unknown app: nazar could not tell which app started this.</b><br>a &lt;b&gt;&amp; c<br>ssh git@github.com<br>Allow for this session?</qt>"
	if k[3] != want {
		t.Errorf("kdialog text\n got %q\nwant %q", k[3], want)
	}
	z := Args(Zenity, p)
	if z[4] != "--text=Unknown app: nazar could not tell which app started this.\na <b>& c\nssh git@github.com\nAllow for this session?" {
		t.Errorf("zenity text %q", z[4])
	}
	if !slices.Contains(z, "--no-markup") {
		t.Errorf("zenity lost --no-markup: %q", z)
	}
}

func TestFindPrefersKDialogOnKDE(t *testing.T) {
	both := func(string) bool { return true }
	only := func(p string) func(string) bool { return func(q string) bool { return q == p } }
	none := func(string) bool { return false }
	cases := []struct {
		desktop string
		exists  func(string) bool
		program string
		kind    Kind
	}{
		{"KDE", both, "/usr/bin/kdialog", KDialog},
		{"plasma:KDE", both, "/usr/bin/kdialog", KDialog},
		{"kde", both, "/usr/bin/kdialog", KDialog},
		{"GNOME", both, "/usr/bin/zenity", Zenity},
		{"ubuntu:GNOME", both, "/usr/bin/zenity", Zenity},
		{"", both, "/usr/bin/zenity", Zenity},
		{"KDE", only("/usr/bin/zenity"), "/usr/bin/zenity", Zenity},
		{"GNOME", only("/usr/bin/kdialog"), "/usr/bin/kdialog", KDialog},
		{"XFCE:KDEish", both, "/usr/bin/zenity", Zenity},
	}
	for _, c := range cases {
		d, err := find(c.desktop, x11, c.exists)
		if err != nil {
			t.Errorf("find(%q): %v", c.desktop, err)
			continue
		}
		if d.Program != c.program || d.Kind != c.kind {
			t.Errorf("find(%q) = %s (%v), want %s (%v)", c.desktop, d.Program, d.Kind, c.program, c.kind)
		}
		if d.Env == nil {
			t.Errorf("find(%q) dropped the environment source", c.desktop)
		}
	}
	if _, err := find("KDE", x11, none); err == nil || err.Error() != "no dialog program: install zenity or kdialog" {
		t.Errorf("find with neither program: %v", err)
	}
}

// Find itself only looks at two fixed paths; in the test image neither
// exists, and on a desktop it names one of them. It never runs anything.
func TestFindLooksOnlyAtUsrBin(t *testing.T) {
	d, err := Find("GNOME", x11)
	if err != nil {
		if err.Error() != "no dialog program: install zenity or kdialog" {
			t.Errorf("Find: %v", err)
		}
		return
	}
	if d.Program != "/usr/bin/zenity" && d.Program != "/usr/bin/kdialog" {
		t.Errorf("Find chose %q", d.Program)
	}
}
