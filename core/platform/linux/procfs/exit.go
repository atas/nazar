//go:build linux

package procfs

import (
	"os"
	"time"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// pollEvery is how often the generation is checked when there is no pidfd
// to wait on.
const pollEvery = 200 * time.Millisecond

// OnProcessExit runs fn exactly once, on its own goroutine, after the
// instance ref names exits; promptly when it is gone already, never
// existed, or is not a full ref. It waits on a pidfd of the process, which
// turns readable when it exits, through the runtime's poller, as
// cmd/nazar's watchParent does; the pidfd counts only if the PID still
// holds the named instance once it is open, so a recycled PID is never
// watched for a process that is gone. Without pidfds (Linux before 5.3, a
// seccomp filter) the generation is polled every 200 ms instead.
func (p *Procs) OnProcessExit(ref platform.ProcessRef, fn func()) {
	if ref.Generation == 0 || !p.alive(ref) {
		go fn()
		return
	}
	if !p.noPidfd {
		if fd, err := unix.PidfdOpen(ref.PID, 0); err == nil {
			if !p.alive(ref) {
				unix.Close(fd)
				go fn()
				return
			}
			if p.watchPidfd(fd, ref, fn) {
				return
			}
		}
	}
	go p.poll(ref, fn)
}

// alive reports whether the full ref names a live process now.
func (p *Procs) alive(ref platform.ProcessRef) bool {
	_, err := check(ref)
	return err == nil
}

// watchPidfd hands the pidfd to the runtime's poller and runs fn on its
// goroutine when the process exits. It reports false, with the fd closed,
// when the poller can't take the fd; the caller polls then.
func (p *Procs) watchPidfd(fd int, ref platform.ProcessRef, fn func()) bool {
	if unix.SetNonblock(fd, true) != nil {
		unix.Close(fd)
		return false
	}
	f := os.NewFile(uintptr(fd), "pidfd")
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		return false
	}
	go func() {
		defer f.Close()
		// The first call asks the poller to wait; the next one is the exit.
		woken := false
		err := rc.Read(func(uintptr) bool {
			defer func() { woken = true }()
			return woken
		})
		if err != nil { // the poller can't wait on it
			p.poll(ref, fn)
			return
		}
		// Counted once the wait has returned: a pidfd the poller took and
		// then refused ends in the poll above, not here.
		p.pidfdWaits.Add(1)
		fn()
	}()
	return true
}

// poll runs fn once the ref no longer names a live process, checking
// every pollEvery.
func (p *Procs) poll(ref platform.ProcessRef, fn func()) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for range t.C {
		if !p.alive(ref) {
			fn()
			return
		}
	}
}
