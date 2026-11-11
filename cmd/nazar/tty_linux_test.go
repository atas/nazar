//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/control"
)

// openPty opens a pseudo-terminal, returning its controlling side and the
// terminal a program would have as stdin.
func openPty(t *testing.T) (ptmx, pts *os.File) {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { ptmx.Close() })
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("pty number: %v", err)
	}
	pts, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open the pty's terminal: %v", err)
	}
	t.Cleanup(func() { pts.Close() })
	return ptmx, pts
}

// TestIsTerminalOnlyForATerminal: /dev/null is a character device but not
// a terminal, so `nazar k8s ca create` run with stdin from /dev/null must
// not prompt, and `secret add` must read it as piped input. Only a real
// terminal (here a pty) answers the termios request.
func TestIsTerminalOnlyForATerminal(t *testing.T) {
	null, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if isTerminal(int(null.Fd())) {
		t.Error("/dev/null is taken for a terminal")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(int(r.Fd())) {
		t.Error("a pipe is taken for a terminal")
	}

	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(int(f.Fd())) {
		t.Error("a regular file is taken for a terminal")
	}

	_, pts := openPty(t)
	if !isTerminal(int(pts.Fd())) {
		t.Error("a pty is not taken for a terminal")
	}
}

// TestTermiosAnswer: only ENOTTY says "not a terminal". Any other failure
// on a character device (a seccomp sandbox answering EPERM, say) may be a
// real terminal, where reading the value would echo it, so it counts as
// one and `secret add` refuses.
func TestTermiosAnswer(t *testing.T) {
	for _, c := range []struct {
		name       string
		err        error
		charDevice bool
		want       bool
	}{
		{"answered", nil, true, true},
		{"ENOTTY on a character device, like /dev/null", unix.ENOTTY, true, false},
		{"ENOTTY on anything else", unix.ENOTTY, false, false},
		{"EPERM on a character device", unix.EPERM, true, true},
		{"EPERM on anything else", unix.EPERM, false, false},
		{"stdin closed", unix.EBADF, false, false},
	} {
		if got := termiosAnswer(c.err, func() bool { return c.charDevice }); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSecretAddAtATerminalRefuses runs the real CLI with a pty as stdin, the
// path `nazar secret add NAME` takes when typed by hand on Linux: it says to
// pipe the value, never promises hidden typing, and reads nothing, so what
// was typed stays with the terminal and is never echoed as a value.
func TestSecretAddAtATerminalRefuses(t *testing.T) {
	if readHiddenLine != nil {
		t.Fatal("this test is for a build with no hidden prompt")
	}
	cli := buildNazar(t, t.TempDir())

	ptmx, pts := openPty(t)
	const typed = "typed-at-the-terminal\n"
	if _, err := ptmx.WriteString(typed); err != nil {
		t.Fatal(err)
	}
	waiting := func() int {
		n, err := unix.IoctlGetInt(int(pts.Fd()), unix.TIOCINQ)
		if err != nil {
			t.Fatalf("TIOCINQ: %v", err)
		}
		return n
	}
	// The kernel moves the line to the terminal's input asynchronously.
	for deadline := time.Now().Add(5 * time.Second); waiting() != len(typed); {
		if time.Now().After(deadline) {
			t.Fatalf("the terminal holds %d bytes, want %d", waiting(), len(typed))
		}
		time.Sleep(5 * time.Millisecond)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(cli, "secret", "add", "GH_TOKEN")
	cmd.Stdin = pts
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("secret add at a terminal did not exit")
	}

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != control.ExitUsage {
		t.Fatalf("exit: %v, want %d; stderr %q", err, control.ExitUsage, stderr.String())
	}
	got := stderr.String()
	if !strings.Contains(got, `printf '%s' "$NAME" | nazar secret add NAME`) {
		t.Errorf("stderr does not name the piped form: %q", got)
	}
	for _, bad := range []string{"typing is hidden", "< file", "typed-at-the-terminal"} {
		if strings.Contains(got, bad) {
			t.Errorf("stderr has %q: %q", bad, got)
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout: %q", stdout.String())
	}
	if n := waiting(); n != len(typed) {
		t.Errorf("the terminal holds %d bytes after the refusal, want the %d typed: the CLI read from it", n, len(typed))
	}
}

// TestBuiltCLIHelpDropsThePrompt: main wires the switch, so the real CLI's
// help on Linux promises no hidden prompt.
func TestBuiltCLIHelpDropsThePrompt(t *testing.T) {
	cli := buildNazar(t, t.TempDir())
	for _, args := range [][]string{{"help"}, {"secret", "add", "--help"}} {
		cmd := exec.Command(cli, args...)
		cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		if strings.Contains(strings.ReplaceAll(string(out), "no hidden prompt", ""), "hidden prompt") {
			t.Errorf("%v promises a hidden prompt:\n%s", args, out)
		}
	}
}

// TestSecretAddWithStdinFromDevNull runs the real CLI with stdin from
// /dev/null, a character device but no terminal: that is piped input with
// nothing in it, so the value is empty, not a refusal to read a terminal.
func TestSecretAddWithStdinFromDevNull(t *testing.T) {
	cli := buildNazar(t, t.TempDir())
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()

	var stderr bytes.Buffer
	cmd := exec.Command(cli, "secret", "add", "GH_TOKEN")
	cmd.Stdin = null
	cmd.Stderr = &stderr
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
	err = cmd.Run()

	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != control.ExitUsage {
		t.Fatalf("exit: %v, want %d; stderr %q", err, control.ExitUsage, stderr.String())
	}
	if got := stderr.String(); !strings.Contains(got, "the value is empty") || strings.Contains(got, "no hidden prompt") {
		t.Fatalf("stderr: %q, want the value called empty, not a terminal refusal", got)
	}
}
