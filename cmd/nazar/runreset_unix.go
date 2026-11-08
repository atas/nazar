//go:build darwin || linux

package main

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// closeOnExec marks every open fd from 3 up close-on-exec, as /dev/fd
// lists them (no fd is handed over to a run's program: secrets design
// 6.3, D1). Names only: macOS's /dev/fd can't stat some fds (Go's own
// kqueue), which os.ReadDir would.
func closeOnExec() error {
	dir, err := os.Open("/dev/fd")
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd < 3 {
			continue
		}
		// The listing's own fd is gone by now: EBADF is no leak.
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil && err != unix.EBADF {
			return err
		}
	}
	return nil
}
