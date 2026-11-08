//go:build darwin

package mounts

import (
	"sync"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// VQ_MOUNT and VQ_UNMOUNT, <sys/mount.h>.
const vqMount, vqUnmount = 0x0008, 0x0010

type kq struct{}

// New is the kqueue mount watch.
func New() platform.Mounts { return kq{} }

// WatchMounts: the knote is armed before it returns, so every mount or
// unmount that completes after that ORs its bit into the knote (EV_CLEAR)
// until changed reads it. A poll that fails (but EINTR) is a change.
func (kq) WatchMounts() (func() bool, func(), error) {
	fd, err := unix.Kqueue()
	if err != nil {
		return nil, nil, err
	}
	unix.CloseOnExec(fd)
	add := []unix.Kevent_t{{Filter: unix.EVFILT_FS, Flags: unix.EV_ADD | unix.EV_CLEAR}}
	if _, err := unix.Kevent(fd, add, nil, nil); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	var mu sync.Mutex
	seen, closed := false, false
	changed := func() bool {
		mu.Lock()
		defer mu.Unlock()
		ev := make([]unix.Kevent_t, 4)
		for !seen && !closed {
			n, err := unix.Kevent(fd, nil, ev, &unix.Timespec{})
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				seen = true
				break
			}
			for _, e := range ev[:n] {
				seen = seen || e.Fflags&(vqMount|vqUnmount) != 0
			}
			if n < len(ev) {
				break
			}
		}
		return seen || closed
	}
	stop := func() {
		mu.Lock()
		defer mu.Unlock()
		if !closed {
			closed = true
			unix.Close(fd)
		}
	}
	return changed, stop, nil
}
