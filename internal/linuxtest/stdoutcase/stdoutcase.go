//go:build linux

// Package stdoutcase is the conformance Stdout hook on Linux, over real
// processes: the test process is the reader, as kubectl is for its exec
// plugin, and every writer is its child (/bin/sleep, or /bin/sh and
// /bin/bash that exec it). Nothing writes to any of the pipes; every end
// the test keeps is closed, and every child killed and reaped, when the
// test ends. Test-only code; nothing in it ships.
package stdoutcase

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"golang.org/x/sys/unix"
)

// Start sets up c and returns the writer (the process whose fd 1 the case
// set up, a child of this process) and the reader (this process), both as
// full refs. The children live until t ends; for StdoutGone the writer has
// exited and been reaped before Start returns.
func Start(t *testing.T, c conformance.StdoutCase) (writer, reader platform.ProcessRef) {
	t.Helper()
	self := ref(t, os.Getpid())
	keep := func(cl io.Closer) { t.Cleanup(func() { cl.Close() }) }
	sleep := func() *exec.Cmd { return exec.Command("/bin/sleep", "600") }
	// started starts cmd with its fd 1 set to f, which this process then
	// closes: the child holds the only copy.
	started := func(cmd *exec.Cmd, f *os.File) *exec.Cmd {
		cmd.Stdout = f
		start(t, cmd)
		f.Close()
		return cmd
	}
	switch c {
	case conformance.StdoutPiped, conformance.StdoutGone:
		cmd := sleep()
		out, err := cmd.StdoutPipe() // the read end stays here
		if err != nil {
			t.Fatal(err)
		}
		start(t, cmd)
		keep(out)
		w := ref(t, cmd.Process.Pid)
		if c == conformance.StdoutGone {
			cmd.Process.Kill()
			cmd.Wait() // reaped: gone for the platform too
		}
		return w, self
	case conformance.StdoutSharedReadEnd:
		// This process reads the writer's pipe, and its other child holds
		// a copy of the read end on fd 0.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(r)
		holder := sleep()
		holder.Stdin = r
		start(t, holder)
		return ref(t, started(sleep(), w).Process.Pid), self
	case conformance.StdoutSharedWriteEnd:
		// This process alone reads the writer's pipe, and its other child
		// holds a copy of the write end on fd 1, as a co-writer does.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(r)
		cowriter := sleep()
		cowriter.Stdout = w
		start(t, cowriter)
		return ref(t, started(sleep(), w).Process.Pid), self
	case conformance.StdoutInheritedReadEnd:
		// This process reads the writer's pipe through an fd that is not
		// close-on-exec, as a process holds a pipe it inherited. The flag
		// is cleared once the writer runs, and no other child starts while
		// this process keeps it, so the read end has no other reference.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(r)
		cmd := started(sleep(), w)
		if _, err := unix.FcntlInt(r.Fd(), unix.F_SETFD, 0); err != nil {
			t.Fatal(err)
		}
		return ref(t, cmd.Process.Pid), self
	case conformance.StdoutPipedElsewhere:
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cat := exec.Command("/bin/cat")
		cat.Stdin = r
		out, err := cat.StdoutPipe() // this process reads another pipe: cat's
		if err != nil {
			t.Fatal(err)
		}
		start(t, cat)
		keep(out)
		r.Close()
		return ref(t, started(sleep(), w).Process.Pid), self
	case conformance.StdoutRelayed:
		cmd := exec.Command("/bin/bash", "-c", "exec > >(exec /bin/cat); echo ready >&2; exec /bin/sleep 600")
		return ref(t, whenReady(t, cmd, keep).Process.Pid), self
	case conformance.StdoutClosed:
		cmd := exec.Command("/bin/sh", "-c", "exec 1>&-; echo ready >&2; exec /bin/sleep 600")
		return ref(t, whenReady(t, cmd, keep).Process.Pid), self
	case conformance.StdoutFile:
		f, err := os.CreateTemp(t.TempDir(), "stdout")
		if err != nil {
			t.Fatal(err)
		}
		return ref(t, started(sleep(), f).Process.Pid), self
	case conformance.StdoutTerminal:
		return ref(t, started(sleep(), terminal(t, keep)).Process.Pid), self
	case conformance.StdoutSocket:
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		keep(os.NewFile(uintptr(fds[0]), "socket"))
		return ref(t, started(sleep(), os.NewFile(uintptr(fds[1]), "socket")).Process.Pid), self
	case conformance.StdoutReadEnd:
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(w)
		return ref(t, started(sleep(), r).Process.Pid), self
	}
	t.Fatalf("unknown stdout case %q", c)
	return platform.ProcessRef{}, platform.ProcessRef{}
}

// ref is the full ref of a live process, from /proc.
func ref(t *testing.T, pid int) platform.ProcessRef {
	t.Helper()
	st, err := procfs.ReadStat(pid)
	if err != nil {
		t.Fatalf("stat of %d: %v", pid, err)
	}
	return platform.ProcessRef{PID: pid, Generation: procfs.Generation(st.StartTicks)}
}

// start starts cmd and has it killed and reaped when t ends.
func start(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", cmd.Path, err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
}

// terminal opens a pty from /dev/ptmx (O_NOCTTY: never this process's
// terminal), keeps its controller here and returns its terminal side for a
// child's fd 1.
func terminal(t *testing.T, keep func(io.Closer)) *os.File {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("no pty: %v", err)
	}
	keep(ptmx)
	fd := int(ptmx.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("pty number: %v", err)
	}
	tty, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tty
}

// whenReady starts a shell script with its stdout piped to this process
// and returns once it said "ready" on stderr, after its own redirection.
func whenReady(t *testing.T, cmd *exec.Cmd, keep func(io.Closer)) *exec.Cmd {
	t.Helper()
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	errp, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	start(t, cmd)
	keep(out)
	keep(errp)
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(errp).ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if strings.TrimSpace(line) != "ready" {
			t.Fatalf("%s: %q on stderr, want ready", cmd.Path, line)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not get ready", cmd.Path)
	}
	return cmd
}
