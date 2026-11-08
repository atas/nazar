//go:build darwin

package main

// The Stdout hook sets up what each case says, as an independent
// observer sees it: lsof's record of the writer's fd 1 (its type, and for
// a pipe its peer end's kernel address) and of the fds this host holds.
// The suite's answers come from the platform's own query; this pins the
// ground truth they are judged against.

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/atas/nazar/core/platform/conformance"
	"golang.org/x/sys/unix"
)

// lsofFD is one fd of lsof -F ftdn: its number, type (PIPE, REG, CHR,
// unix, …), device (a pipe end's address) and name (a pipe's peer end, as
// ->0x…).
type lsofFD struct{ fd, typ, dev, name string }

func lsofFDs(t *testing.T, pid int) []lsofFD {
	t.Helper()
	out, err := exec.Command("/usr/sbin/lsof", "-n", "-P", "-p", strconv.Itoa(pid), "-F", "ftdn").Output()
	if err != nil && len(out) == 0 {
		t.Fatalf("lsof -p %d: %v", pid, err)
	}
	var fds []lsofFD
	for _, l := range strings.Split(string(out), "\n") {
		if l == "" {
			continue
		}
		switch v := l[1:]; l[0] {
		case 'f':
			fds = append(fds, lsofFD{fd: v})
		case 't':
			fds[len(fds)-1].typ = v
		case 'd':
			fds[len(fds)-1].dev = v
		case 'n':
			fds[len(fds)-1].name = v
		}
	}
	return fds
}

func fd1(t *testing.T, pid int) (lsofFD, bool) {
	for _, f := range lsofFDs(t, pid) {
		if f.fd == "1" {
			return f, true
		}
	}
	return lsofFD{}, false
}

// holdsPeer reports whether pid holds the other end of the pipe end p.
func holdsPeer(t *testing.T, pid int, p lsofFD) bool {
	_, ok := peerFD(t, pid, p)
	return ok
}

// peerFD is the fd through which pid holds the other end of the pipe end p.
func peerFD(t *testing.T, pid int, p lsofFD) (int, bool) {
	for _, f := range lsofFDs(t, pid) {
		if f.typ == "PIPE" && "->"+f.dev == p.name {
			fd, err := strconv.Atoi(strings.TrimRight(f.fd, "rwu"))
			return fd, err == nil
		}
	}
	return 0, false
}

func TestStdoutHookSetsUpEachCase(t *testing.T) {
	self := os.Getpid()
	for _, tc := range []struct {
		c        conformance.StdoutCase
		typ      string // lsof's type of the writer's fd 1; "" for no fd 1
		selfPeer bool   // this host holds the other end of that pipe
	}{
		{conformance.StdoutPiped, "PIPE", true},
		{conformance.StdoutPipedElsewhere, "PIPE", false},
		{conformance.StdoutSharedReadEnd, "PIPE", true},
		{conformance.StdoutSharedWriteEnd, "PIPE", true},
		{conformance.StdoutInheritedReadEnd, "PIPE", true},
		{conformance.StdoutRelayed, "PIPE", false},
		{conformance.StdoutFile, "REG", false},
		{conformance.StdoutTerminal, "CHR", false},
		{conformance.StdoutSocket, "unix", false},
		{conformance.StdoutReadEnd, "PIPE", true}, // the write end: lsof does not say which
		{conformance.StdoutClosed, "", false},
	} {
		t.Run(string(tc.c), func(t *testing.T) {
			c := &children{t: t}
			t.Cleanup(c.killAll)
			w, r := c.stdout(t, tc.c)
			if r.PID != self || r.Generation != generation(t, self) {
				t.Fatalf("reader %v, want this host", r)
			}
			if w.Generation != generation(t, w.PID) {
				t.Fatalf("writer %v is not a full live ref", w)
			}
			f, ok := fd1(t, w.PID)
			if tc.typ == "" {
				if ok {
					t.Fatalf("fd 1 is open: %+v", f)
				}
				return
			}
			if !ok || f.typ != tc.typ {
				t.Fatalf("fd 1 = %+v, want type %s", f, tc.typ)
			}
			if tc.typ == "PIPE" && holdsPeer(t, self, f) != tc.selfPeer {
				t.Fatalf("this host holds the other end of fd 1's pipe: %v, want %v", !tc.selfPeer, tc.selfPeer)
			}
			// The read end this host holds is close-on-exec, as a pipe it
			// opened itself is, but for the inherited case.
			if tc.selfPeer && tc.c != conformance.StdoutReadEnd {
				fd, ok := peerFD(t, self, f)
				flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
				if !ok || err != nil || (flags&unix.FD_CLOEXEC != 0) != (tc.c != conformance.StdoutInheritedReadEnd) {
					t.Fatalf("this host's fd %d of the pipe: flags %#x, %v", fd, flags, err)
				}
			}
			// This host's other child holds the read end too.
			if tc.c == conformance.StdoutSharedReadEnd {
				out, _ := exec.Command("/usr/bin/pgrep", "-P", strconv.Itoa(self), "-x", "sleep").Output()
				held := false
				for _, s := range strings.Fields(string(out)) {
					if pid, err := strconv.Atoi(s); err == nil && pid != w.PID && holdsPeer(t, pid, f) {
						held = true
					}
				}
				if !held {
					t.Fatalf("no other child of this host holds the other end of fd 1's pipe (%q)", out)
				}
			}
			// This host's other child holds the write end too, on its fd 1:
			// the same end (lsof's address of it), not another pipe's.
			if tc.c == conformance.StdoutSharedWriteEnd {
				out, _ := exec.Command("/usr/bin/pgrep", "-P", strconv.Itoa(self), "-x", "sleep").Output()
				held := false
				for _, s := range strings.Fields(string(out)) {
					if pid, err := strconv.Atoi(s); err == nil && pid != w.PID {
						if cf, ok := fd1(t, pid); ok && cf.typ == "PIPE" && cf.dev == f.dev {
							held = true
						}
					}
				}
				if !held {
					t.Fatalf("no other child of this host holds fd 1's write end (%q)", out)
				}
			}
			// The other pipe ends in cat (the relay's child, or this host's),
			// whose own stdout comes here.
			if tc.c == conformance.StdoutRelayed || tc.c == conformance.StdoutPipedElsewhere {
				parent := self
				if tc.c == conformance.StdoutRelayed {
					parent = w.PID
				}
				out, _ := exec.Command("/usr/bin/pgrep", "-P", strconv.Itoa(parent), "-x", "cat").Output()
				cat, err := strconv.Atoi(strings.TrimSpace(strings.Split(string(out), "\n")[0]))
				if err != nil || !holdsPeer(t, cat, f) {
					t.Fatalf("cat (%q) does not hold the other end of fd 1's pipe", out)
				}
				if cf, ok := fd1(t, cat); !ok || cf.typ != "PIPE" || !holdsPeer(t, self, cf) {
					t.Fatalf("cat's fd 1 = %+v: not a pipe this host reads", cf)
				}
			}
		})
	}
	t.Run("gone", func(t *testing.T) {
		c := &children{t: t}
		t.Cleanup(c.killAll)
		w, _ := c.stdout(t, conformance.StdoutGone)
		if k, err := unix.SysctlKinfoProc("kern.proc.pid", w.PID); err == nil && int(k.Proc.P_pid) == w.PID &&
			uint64(k.Proc.P_starttime.Sec)*1_000_000+uint64(k.Proc.P_starttime.Usec) == w.Generation {
			t.Fatalf("writer %v still live", w)
		}
	})
}
