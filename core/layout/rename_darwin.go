package layout

import "golang.org/x/sys/unix"

// renameNoReplace is rename(2) that fails with EEXIST instead of replacing
// an existing to (renamex_np RENAME_EXCL). A link at from is moved as a
// link, never followed.
func renameNoReplace(from, to string) error {
	return unix.RenamexNp(from, to, unix.RENAME_EXCL)
}
