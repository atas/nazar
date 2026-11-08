//go:build darwin

package main

import (
	"context"
	"os"

	"golang.org/x/sys/unix"
)

// watchParent calls gone when the parent the CLI had at start exits: a
// kqueue NOTE_EXIT on its pid, read once, no polling. The pid is watched
// only if it is still the parent after the watch is in place, so a parent
// that exited first (its pid free for another process) is never mistaken
// for a live one: gone is called at once. Nothing is watched when launchd
// is the parent already, or when no kqueue can be had. The kqueue lives
// until ctx ends.
func watchParent(ctx context.Context, gone func()) {
	ppid := os.Getppid()
	if ppid == 1 {
		return
	}
	kq, err := unix.Kqueue()
	if err != nil {
		return
	}
	// A user event wakes the wait when ctx ends first.
	wake := unix.Kevent_t{Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{wake}, nil, nil); err != nil {
		unix.Close(kq)
		return
	}
	exit := unix.Kevent_t{Ident: uint64(ppid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
	_, err = unix.Kevent(kq, []unix.Kevent_t{exit}, nil, nil)
	if err == unix.ESRCH || os.Getppid() != ppid {
		unix.Close(kq)
		gone()
		return
	}
	if err != nil {
		unix.Close(kq)
		return
	}
	woken := make(chan struct{})
	context.AfterFunc(ctx, func() {
		unix.Kevent(kq, []unix.Kevent_t{{Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER}}, nil, nil)
		close(woken)
	})
	go func() {
		ev := make([]unix.Kevent_t, 1)
		for {
			n, err := unix.Kevent(kq, nil, ev, nil)
			if err == unix.EINTR {
				continue
			}
			if err == nil && n == 1 && ev[0].Filter == unix.EVFILT_PROC {
				gone()
			}
			break
		}
		// Closed only after the wake-up was sent, never under it.
		<-woken
		unix.Close(kq)
	}()
}
