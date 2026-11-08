//go:build linux

package main

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// watchParent calls gone when the parent the CLI had at start exits: a
// pidfd of it, which turns readable when it exits, waited on by the
// runtime's poller (no polling). As on macOS, the pidfd is used only if the
// pid is still the parent once it is open, so a parent that exited first
// (its pid free for another process) is never mistaken for a live one:
// gone is called at once. Without pidfds (Linux before 5.3, or a seccomp
// filter) the orphan's parent pid is checked once a second instead (it is
// given to init or a subreaper). Nothing is watched when init is the
// parent already. The pidfd is closed when ctx ends.
func watchParent(ctx context.Context, gone func()) {
	ppid := os.Getppid()
	if ppid == 1 {
		return
	}
	fd, err := unix.PidfdOpen(ppid, 0)
	if err == unix.ESRCH || os.Getppid() != ppid {
		if err == nil {
			unix.Close(fd)
		}
		gone()
		return
	}
	if err == nil && unix.SetNonblock(fd, true) != nil {
		unix.Close(fd)
		err = unix.EINVAL
	}
	if err != nil {
		go pollParent(ctx, ppid, gone)
		return
	}
	f := os.NewFile(uintptr(fd), "parent pidfd")
	rc, err := f.SyscallConn()
	if err != nil {
		f.Close()
		go pollParent(ctx, ppid, gone)
		return
	}
	context.AfterFunc(ctx, func() { f.Close() })
	go func() {
		// The first call asks the poller to wait; the next one is the exit.
		woken := false
		err := rc.Read(func(uintptr) bool {
			defer func() { woken = true }()
			return woken
		})
		switch {
		case err == nil:
			gone()
		case ctx.Err() == nil: // the poller can't wait on it
			pollParent(ctx, ppid, gone)
		}
	}()
}

// pollParent calls gone once the parent pid is no longer ppid, checking
// once a second until ctx ends.
func pollParent(ctx context.Context, ppid int, gone func()) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if os.Getppid() != ppid {
				gone()
				return
			}
		}
	}
}
