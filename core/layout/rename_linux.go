package layout

import "golang.org/x/sys/unix"

// renameNoReplace is rename(2) that fails with EEXIST instead of replacing
// an existing to (renameat2 RENAME_NOREPLACE). A link at from is moved as a
// link, never followed.
func renameNoReplace(from, to string) error {
	return unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE)
}
