//go:build darwin

package main

/*
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

// nz_openpt opens a pty controller (O_NOCTTY: never this host's terminal)
// and writes its terminal's path to name; -1 on any failure.
static int nz_openpt(char *name, size_t n) {
	int fd = posix_openpt(O_RDWR | O_NOCTTY);
	if (fd < 0) return -1;
	char *p = (grantpt(fd) == 0 && unlockpt(fd) == 0) ? ptsname(fd) : NULL;
	if (p == NULL || strlen(p) >= n) return -1;
	strcpy(name, p);
	return fd;
}
*/
import "C"

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"golang.org/x/sys/unix"
)

// stdout is the conformance Stdout hook over real processes: this
// host is the reader, as kubectl is for its exec plugin, and every writer
// is its child (/bin/sleep, or /bin/sh and /bin/bash that exec it).
// Nothing writes to any of the pipes; every end this host keeps is closed
// when the subtest ends.
func (c *children) stdout(t *testing.T, sc conformance.StdoutCase) (platform.ProcessRef, platform.ProcessRef) {
	self := platform.ProcessRef{PID: os.Getpid(), Generation: generation(t, os.Getpid())}
	keep := func(cl io.Closer) {
		c.mu.Lock()
		c.close = append(c.close, func() { cl.Close() })
		c.mu.Unlock()
	}
	ref := func(cmd *exec.Cmd) platform.ProcessRef {
		return platform.ProcessRef{PID: cmd.Process.Pid, Generation: generation(t, cmd.Process.Pid)}
	}
	sleep := func() *exec.Cmd { return exec.Command("/bin/sleep", "600") }
	// started starts cmd with its fd 1 set to f, which this host then
	// closes: the child holds the only copy.
	started := func(cmd *exec.Cmd, f *os.File) *exec.Cmd {
		cmd.Stdout = f
		c.start(cmd)
		f.Close()
		return cmd
	}
	switch sc {
	case conformance.StdoutPiped, conformance.StdoutGone:
		cmd := sleep()
		out, err := cmd.StdoutPipe() // the read end stays here
		if err != nil {
			t.Fatal(err)
		}
		c.start(cmd)
		keep(out)
		w := ref(cmd)
		if sc == conformance.StdoutGone {
			c.exit(w)
		}
		return w, self
	case conformance.StdoutSharedReadEnd:
		// This host reads the writer's pipe, and its other child holds a
		// copy of the read end on fd 0.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(r)
		holder := sleep()
		holder.Stdin = r
		c.start(holder)
		return ref(started(sleep(), w)), self
	case conformance.StdoutSharedWriteEnd:
		// This host alone reads the writer's pipe, and its other child
		// holds a copy of the write end on fd 1, as a co-writer does.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(r)
		cowriter := sleep()
		cowriter.Stdout = w
		c.start(cowriter)
		return ref(started(sleep(), w)), self
	case conformance.StdoutInheritedReadEnd:
		// This host reads the writer's pipe through an fd that is not
		// close-on-exec, as a process holds a pipe it inherited. It is
		// cleared once the writer runs, and no other child starts while
		// this host keeps it, so the read end has no other reference.
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(r)
		writer := started(sleep(), w)
		if _, err := unix.FcntlInt(r.Fd(), unix.F_SETFD, 0); err != nil {
			t.Fatal(err)
		}
		return ref(writer), self
	case conformance.StdoutPipedElsewhere:
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cat := exec.Command("/bin/cat")
		cat.Stdin = r
		out, err := cat.StdoutPipe() // this host reads another pipe: cat's
		if err != nil {
			t.Fatal(err)
		}
		c.start(cat)
		keep(out)
		r.Close()
		return ref(started(sleep(), w)), self
	case conformance.StdoutRelayed:
		cmd := exec.Command("/bin/bash", "-c", "exec > >(exec /bin/cat); echo ready >&2; exec /bin/sleep 600")
		return ref(c.whenReady(t, cmd, keep)), self
	case conformance.StdoutClosed:
		cmd := exec.Command("/bin/sh", "-c", "exec 1>&-; echo ready >&2; exec /bin/sleep 600")
		return ref(c.whenReady(t, cmd, keep)), self
	case conformance.StdoutFile:
		f, err := os.CreateTemp(t.TempDir(), "stdout")
		if err != nil {
			t.Fatal(err)
		}
		return ref(started(sleep(), f)), self
	case conformance.StdoutTerminal:
		var name [128]C.char
		fd := C.nz_openpt(&name[0], C.size_t(len(name)))
		if fd < 0 {
			t.Fatal("no pty")
		}
		keep(os.NewFile(uintptr(fd), "ptmx"))
		tty, err := os.OpenFile(C.GoString(&name[0]), os.O_RDWR|unix.O_NOCTTY, 0)
		if err != nil {
			t.Fatal(err)
		}
		return ref(started(sleep(), tty)), self
	case conformance.StdoutSocket:
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		keep(os.NewFile(uintptr(fds[0]), "socket"))
		return ref(started(sleep(), os.NewFile(uintptr(fds[1]), "socket"))), self
	case conformance.StdoutReadEnd:
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		keep(w)
		return ref(started(sleep(), r)), self
	}
	t.Fatalf("unknown stdout case %q", sc)
	return platform.ProcessRef{}, platform.ProcessRef{}
}

// whenReady starts a shell script with its stdout piped to this host and
// returns once it said "ready" on stderr, after its own redirection.
func (c *children) whenReady(t *testing.T, cmd *exec.Cmd, keep func(io.Closer)) *exec.Cmd {
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	errp, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	c.start(cmd)
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
