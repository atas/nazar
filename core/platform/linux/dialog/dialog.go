//go:build linux

// Package dialog is the `dialog` gate on Linux: an Allow/Deny window shown
// by the desktop's own zenity or kdialog, run by the agent as a child
// process (spec "Decided": no cgo, no toolkit of our own). The program is
// chosen by Find, at the agent's start and again at each prompt for as long
// as neither is installed, and Confirm runs it per prompt with the prompt's
// text as arguments and a small, fixed environment.
//
// What the program says is all we have. Exit 0 is Allow; exit 1 (and
// kdialog's 2, its Cancel) is a denial with no reason, as zenity cannot
// tell Deny from Esc; zenity's 5 is its own countdown running out; any
// other end, including the program dying or being killed by us when it
// outlives the prompt's timeout, is "closed without an answer". Nothing
// else counts as Allow. One end is not an answer at all: the toolkit could
// not open the display (a stale DISPLAY or WAYLAND_DISPLAY in a user
// service that outlived its session). GTK exits 1 for that, like a denial,
// so Confirm reads the program's stderr and reports a display failure as
// an error, never as the user's decision.
//
// The window is weaker than nazar's own on macOS (THREAT-MODEL 4.5), and
// the docs say so (spec "Weaker than macOS" 4): Allow is live from the
// first frame, with no arming delay and no grey-out on focus loss; the
// keyboard can answer it (Enter sits on Deny, but Tab and Space reach
// Allow); a synthetic click is not told from a real one. On X11 any
// same-user program can press the button (XTest). On Wayland the program
// is run Wayland-only, so it never falls back to XWayland's X11 window.
// The prompt's text is on the program's command line, which every local
// user can read through /proc unless the machine mounts it with hidepid.
package dialog

import (
	"errors"
	"fmt"
	"html"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/atas/nazar/core/platform"
)

// Kind is which dialog program Confirm runs; the argv and the exit codes
// differ.
type Kind int

const (
	Zenity Kind = iota + 1
	KDialog
)

func (k Kind) String() string {
	switch k {
	case Zenity:
		return "zenity"
	case KDialog:
		return "kdialog"
	}
	return fmt.Sprintf("Kind(%d)", int(k))
}

// The only places a dialog program is taken from: the distribution's
// packages, never a user-writable folder or a PATH lookup.
const (
	zenityPath  = "/usr/bin/zenity"
	kdialogPath = "/usr/bin/kdialog"
)

// allowedEnv is every variable the dialog program may see: where to draw
// (DISPLAY, WAYLAND_DISPLAY, XAUTHORITY, XDG_RUNTIME_DIR), the session bus
// for the desktop's theme and accessibility services, the locale and the
// home folder for the toolkit's settings. PATH is replaced, not passed.
// x11Env is the part that is dropped on a Wayland session (see filterEnv).
var allowedEnv = []string{
	"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR",
	"DBUS_SESSION_BUS_ADDRESS", "LANG", "LC_ALL", "HOME",
}

var x11Env = []string{"DISPLAY", "XAUTHORITY"}

const fixedPath = "PATH=/usr/bin:/bin"

// waylandOnly makes GTK and Qt use their Wayland backends and nothing
// else. Without it Qt 5 (kdialog on Debian 12 and Kubuntu 24.04) defaults
// to xcb and opens an X11 window under XWayland, where XTest applies, and
// GTK would fall back to X11 if Wayland failed. With it a program that
// cannot use Wayland fails closed.
var waylandOnly = []string{"GDK_BACKEND=wayland", "QT_QPA_PLATFORM=wayland"}

// grace is how much longer than the prompt's timeout the program may run
// before Confirm kills it: zenity's own countdown should end it first.
const grace = 2 * time.Second

// stderrLimit is how much of the program's stderr Confirm keeps to tell a
// display failure from an answer; the rest is discarded.
const stderrLimit = 4096

// displayFailures are what GTK and Qt print when they cannot open the
// display (or find their platform plugin), in lower case. A line of
// stderr containing one means no window was shown, whatever the exit code.
var displayFailures = []string{
	"cannot open display",          // GTK 3: gtk_init, exit 1
	"failed to open display",       // GTK 4 (zenity 4, read from Fedora 41): gtk_init, exit 1
	"could not connect to display", // Qt xcb, then abort
	"failed to create wl_display",  // Qt wayland, then abort
	"no qt platform plugin could be initialized",
	"could not find the qt platform plugin",
	"could not load the qt platform plugin",
}

// Dialog is one dialog program. Env is the environment it is run from
// (the agent's, os.Environ in production), read at every Confirm because
// a user service may learn DISPLAY after it starts; only the allowlisted
// variables, plus PATH=/usr/bin:/bin, reach the program. An empty Program
// is none found yet: Confirm looks again for Desktop's choice.
type Dialog struct {
	Program string          // absolute path
	Kind    Kind            // how to talk to it
	Env     func() []string // the environment the program gets (allowlisted)
	Desktop string          // XDG_CURRENT_DESKTOP, for looking again
}

// Find picks the program: kdialog first when XDG_CURRENT_DESKTOP names
// KDE, zenity first otherwise, whichever is installed under /usr/bin. It
// runs nothing. With neither installed the error says what to install, and
// the Dialog it returns as well is still usable: its Confirm looks again,
// so installing one needs no restart of the agent, and until then returns
// the same error.
func Find(currentDesktop string, env func() []string) (Dialog, error) {
	return find(currentDesktop, env, isExecutable)
}

func find(currentDesktop string, env func() []string, exists func(string) bool) (Dialog, error) {
	order := []Dialog{{Program: zenityPath, Kind: Zenity, Env: env}, {Program: kdialogPath, Kind: KDialog, Env: env}}
	if isKDE(currentDesktop) {
		order[0], order[1] = order[1], order[0]
	}
	for _, d := range order {
		if exists(d.Program) {
			return d, nil
		}
	}
	return Dialog{Env: env, Desktop: currentDesktop}, errors.New("no dialog program: install zenity or kdialog")
}

// isKDE: XDG_CURRENT_DESKTOP is a colon-separated list ("plasma:KDE",
// "ubuntu:GNOME"); KDE anywhere in it, in any case, is KDE.
func isKDE(currentDesktop string) bool {
	for _, part := range strings.Split(currentDesktop, ":") {
		if strings.EqualFold(part, "KDE") {
			return true
		}
	}
	return false
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// Args is the program's argv for a prompt, without argv[0]. Every value
// the prompt supplies is the value of an option (`--title=…`, or the
// argument right after `--title`) or wrapped in <qt>…</qt>, so a title or
// a line that starts with `--` is text, never an option. For an unknown
// app kdialog shows the first line (the broker's "Unknown app" warning)
// in bold, as macOS shows its red header; zenity has no markup under
// --no-markup, so there the title alone says "Unknown app".
func Args(k Kind, p platform.Prompt) []string {
	switch k {
	case KDialog:
		lines := make([]string, len(p.Lines))
		for i, l := range p.Lines {
			lines[i] = html.EscapeString(l)
		}
		if p.Unknown && len(lines) > 0 {
			lines[0] = "<b>" + lines[0] + "</b>"
		}
		return []string{
			"--title", p.Title,
			"--warningyesno", "<qt>" + strings.Join(lines, "<br>") + "</qt>",
			"--yes-label", "Allow",
			"--no-label", "Deny",
		}
	default:
		return []string{
			"--question", "--no-markup", "--default-cancel",
			"--title=" + p.Title,
			"--text=" + strings.Join(p.Lines, "\n"),
			"--ok-label=Allow", "--cancel-label=Deny",
			"--timeout=" + fmt.Sprint(ceilSeconds(p.Timeout)),
		}
	}
}

func ceilSeconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}

// Confirm shows the prompt and returns what the user answered: true only
// for Allow. A denial is (false, nil) when the program cannot say how, or
// a platform.DialogDenied for its countdown (DialogTimedOut) or any end
// that is not an answer (DialogClosed). Without DISPLAY or WAYLAND_DISPLAY
// in the environment there is nowhere to draw: Confirm returns an error
// at once and starts nothing. With no program found (see Find) it looks
// again and returns what to install if there is still none. A program that
// cannot be started, or whose toolkit says it could not open the display,
// is an error too, not a denial. The program runs in its own process group, which is killed
// whole at Timeout + grace, so a wrapper script cannot leave a window up.
func (d Dialog) Confirm(p platform.Prompt) (bool, error) {
	return d.confirm(p, Find)
}

// confirm is Confirm with its way of looking for a program as an argument:
// a test must never find and run the machine's real zenity.
func (d Dialog) confirm(p platform.Prompt, look func(string, func() []string) (Dialog, error)) (bool, error) {
	env, graphical := filterEnv(d.Env)
	if !graphical {
		return false, errors.New("no graphical session for the dialog")
	}
	if d.Program == "" {
		var err error
		if d, err = look(d.Desktop, d.Env); err != nil {
			return false, err
		}
	}
	cmd := exec.Command(d.Program, Args(d.Kind, p)...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr := &head{limit: stderrLimit}
	cmd.Stderr = stderr
	// A stray holder of the stderr pipe (a process that escaped the group)
	// must not keep Wait from returning once the program has ended.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("dialog: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(p.Timeout + grace)
	defer timer.Stop()
	select {
	case err := <-done:
		if line := displayFailure(stderr.String()); line != "" {
			return false, fmt.Errorf("dialog: %v could not open the display: %s", d.Kind, line)
		}
		return outcome(d.Kind, cmd, err)
	case <-timer.C:
		killGroup(cmd)
		<-done
		return false, platform.DialogDenied{How: platform.DialogTimedOut}
	}
}

// killGroup ends the program and everything it started: the whole process
// group Setpgid gave it, then the process itself in case it left the group.
func killGroup(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	cmd.Process.Kill()
}

// filterEnv keeps the allowlisted variables of the source and sets PATH.
// graphical is whether DISPLAY or WAYLAND_DISPLAY has a value. On a
// Wayland session (WAYLAND_DISPLAY set) the X11 variables are dropped and
// the toolkits are told to use Wayland only, so the window is never an
// XWayland one (spec "Weaker than macOS" 4 holds only off X11).
func filterEnv(source func() []string) (env []string, graphical bool) {
	var kept []string
	wayland := false
	if source != nil {
		for _, kv := range source() {
			name, value, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			for _, allowed := range allowedEnv {
				if name == allowed {
					kept = append(kept, kv)
					if (name == "DISPLAY" || name == "WAYLAND_DISPLAY") && value != "" {
						graphical = true
					}
					if name == "WAYLAND_DISPLAY" && value != "" {
						wayland = true
					}
					break
				}
			}
		}
	}
	for _, kv := range kept {
		name, _, _ := strings.Cut(kv, "=")
		if wayland && slices.Contains(x11Env, name) {
			continue
		}
		env = append(env, kv)
	}
	if wayland {
		env = append(env, waylandOnly...)
	}
	return append(env, fixedPath), graphical
}

// displayFailure is the first line of stderr that says the toolkit could
// not open the display, or "" when there is none.
func displayFailure(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		lower := strings.ToLower(line)
		for _, marker := range displayFailures {
			if strings.Contains(lower, marker) {
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}

// outcome maps how the program ended to the answer.
func outcome(k Kind, cmd *exec.Cmd, waitErr error) (bool, error) {
	var exit *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exit) {
		// Not an exit status at all (an I/O failure around the process).
		return false, platform.DialogDenied{How: platform.DialogClosed}
	}
	code := cmd.ProcessState.ExitCode() // -1 when killed by a signal
	switch {
	case code == 0:
		return true, nil
	case code == 1, code == 2 && k == KDialog:
		return false, nil
	case code == 5 && k == Zenity:
		return false, platform.DialogDenied{How: platform.DialogTimedOut}
	}
	return false, platform.DialogDenied{How: platform.DialogClosed}
}

// head keeps the first limit bytes written to it and discards the rest.
type head struct {
	buf   []byte
	limit int
}

func (h *head) Write(p []byte) (int, error) {
	if room := h.limit - len(h.buf); room > 0 {
		if len(p) > room {
			h.buf = append(h.buf, p[:room]...)
		} else {
			h.buf = append(h.buf, p...)
		}
	}
	return len(p), nil
}

func (h *head) String() string { return string(h.buf) }
