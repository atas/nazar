//go:build linux

package pipes

// platform.StdoutThrough over real processes: this test process is the
// reader, as the Go SDK is for credential_process, /bin/sh -c the shell
// that stays as the parent (given two commands, every sh stays), and
// /bin/sleep the writer, as nazar's CLI is. Nothing is written to the
// pipes; every child is killed and reaped when the test ends.

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

// childOf waits until pid has n children and returns the first one's pid.
func childOf(t *testing.T, pid, n int) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ents, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		var kids []int
		for _, e := range ents {
			p, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			if st, err := procfs.ReadStat(p); err == nil && st.PPID == pid {
				kids = append(kids, p)
			}
		}
		if len(kids) >= n {
			return kids[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d has fewer than %d children", pid, n)
	return 0
}

// startShell runs /bin/sh -c script with its stdout piped to this process
// and returns the shell's pid; the shell and what it ran (its own process
// group) are killed and reaped at the end. The read end stays open here
// until then.
func startShell(t *testing.T, script string) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Process.Kill()
		cmd.Wait()
		out.Close()
	})
	return cmd.Process.Pid
}

// The shell stays, holding the write end on its fd 1, and the sleep it
// started holds the same write end on its fd 1: the plain check says no
// (a co-writer), and the check through the shell says yes, as many times
// as it is asked.
func TestThroughShell(t *testing.T) {
	sh := startShell(t, "/bin/sleep 600; exit 0")
	sleep := childOf(t, sh, 1)
	self, via, w := fullRef(t, os.Getpid()), fullRef(t, sh), fullRef(t, sleep)
	if ok, err := New().StdoutReadBy(w, self); ok || err != nil {
		t.Fatalf("StdoutReadBy with the shell holding the write end too = %v, %v; want false and no error", ok, err)
	}
	for i := range 3 {
		if ok, err := New().(platform.StdoutThrough).StdoutReadByThrough(w, via, self); !ok || err != nil {
			t.Fatalf("StdoutReadByThrough (call %d) = %v, %v; want true", i+1, ok, err)
		}
	}
}

// Through is not a loophole: a shell that redirected its own fd 1 away
// (so it holds no write end), a shell that reads the pipe itself (the
// sleep's stdout is a pipe to the shell's command substitution, not to
// us), and a fourth holder of the pipe are all false; the shell being the
// reader itself is asked the wrong way round and is false; and a via that
// is gone is ErrNoProcess.
func TestThroughShellOtherCases(t *testing.T) {
	th := New().(platform.StdoutThrough)
	t.Run("shell without the write end", func(t *testing.T) {
		// The sleep gets the pipe, the shell then drops its own copy.
		sh := startShell(t, "/bin/sleep 600 & exec 1>/dev/null; wait")
		sleep := childOf(t, sh, 1)
		self, via, w := fullRef(t, os.Getpid()), fullRef(t, sh), fullRef(t, sleep)
		// Until the shell has run `exec 1>/dev/null` the shell still holds
		// the end; wait for it to go.
		deadline := time.Now().Add(5 * time.Second)
		for {
			target, err := os.Readlink(fdPath(sh, 1))
			if err == nil && target == "/dev/null" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the shell's fd 1 is still %q", target)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if ok, err := th.StdoutReadByThrough(w, via, self); ok || err != nil {
			t.Fatalf("through a shell with no write end = %v, %v; want false", ok, err)
		}
		// Without the shell's copy the plain check is the right one, and
		// it says yes.
		if ok, err := New().StdoutReadBy(w, self); !ok || err != nil {
			t.Fatalf("StdoutReadBy once the shell let go = %v, %v; want true", ok, err)
		}
	})
	t.Run("shell reads the pipe itself", func(t *testing.T) {
		sh := startShell(t, "x=$(/bin/sleep 600); exit 0")
		sleep := childOf(t, sh, 1)
		self, via, w := fullRef(t, os.Getpid()), fullRef(t, sh), fullRef(t, sleep)
		if ok, err := th.StdoutReadByThrough(w, via, self); ok || err != nil {
			t.Fatalf("through a shell that reads it = %v, %v; want false", ok, err)
		}
	})
	t.Run("a fourth holder", func(t *testing.T) {
		sh := startShell(t, "/bin/sleep 600 & /bin/sleep 600; exit 0")
		// Two sleeps hold the write end: whichever we ask about, the other
		// is one holder too many.
		sleep := childOf(t, sh, 1)
		self, via, w := fullRef(t, os.Getpid()), fullRef(t, sh), fullRef(t, sleep)
		if ok, err := th.StdoutReadByThrough(w, via, self); ok || err != nil {
			t.Fatalf("through with a fourth holder = %v, %v; want false", ok, err)
		}
	})
	t.Run("the wrong way round", func(t *testing.T) {
		sh := startShell(t, "/bin/sleep 600; exit 0")
		sleep := childOf(t, sh, 1)
		self, via, w := fullRef(t, os.Getpid()), fullRef(t, sh), fullRef(t, sleep)
		if ok, err := th.StdoutReadByThrough(w, self, via); ok || err != nil {
			t.Fatalf("via and reader swapped = %v, %v; want false", ok, err)
		}
	})
	t.Run("via gone", func(t *testing.T) {
		sh := startShell(t, "/bin/sleep 600; exit 0")
		sleep := childOf(t, sh, 1)
		self, w := fullRef(t, os.Getpid()), fullRef(t, sleep)
		gone := platform.ProcessRef{PID: sh, Generation: 1}
		if ok, err := th.StdoutReadByThrough(w, gone, self); ok || err == nil {
			t.Fatalf("a stale via = %v, %v; want ErrNoProcess", ok, err)
		}
	})
}
