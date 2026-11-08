//go:build !darwin

package main

import (
	"errors"
	"syscall"
)

// stdinIsTerminal reports whether stdin is a character device (a
// terminal), so that `secret add` refuses to read a value there with echo
// on: there is no hidden prompt off macOS.
func stdinIsTerminal() bool {
	var st syscall.Stat_t
	return syscall.Fstat(0, &st) == nil && st.Mode&syscall.S_IFMT == syscall.S_IFCHR
}

func readHiddenLine() ([]byte, error) {
	return nil, errors.New("no hidden prompt on this system; pipe the value: nazar secret add NAME < file")
}
