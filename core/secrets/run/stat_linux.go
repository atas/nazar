package run

import (
	"os"
	"syscall"
)

// ctimeNs is the inode change time of st.
func ctimeNs(st *syscall.Stat_t) int64 { return st.Ctim.Nano() }

// mountedBy: Linux records no mount owner; its seams are test grade
// (the mount watch, D12). A variable: the tests' seam.
var mountedBy = func(*os.File) (uint32, error) { return 0, nil }
