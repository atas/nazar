package run

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ctimeNs is the inode change time of st.
func ctimeNs(st *syscall.Stat_t) int64 { return st.Ctimespec.Nano() }

// mountedBy is the uid that mounted the volume f is on, as the kernel
// recorded it (statfs f_owner): 0 for the volumes macOS mounts
// itself (the system and data volumes, a disk plugged in), the user's uid
// for a disk image, a share or a file-system extension a process of the
// user mounted (measured on macOS 27). A variable: the tests' seam.
var mountedBy = func(f *os.File) (uint32, error) {
	c, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var st unix.Statfs_t
	var serr error
	if err := c.Control(func(fd uintptr) { serr = unix.Fstatfs(int(fd), &st) }); err != nil {
		return 0, err
	}
	return st.Owner, serr
}
