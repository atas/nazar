//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// stdinIsTerminal reports whether stdin (fd 0) is a terminal.
func stdinIsTerminal() bool { return isTerminal(0) }

// isTerminal reports whether fd is a terminal: the kernel answers a
// termios request (TCGETS) only for a terminal device, so a pipe, a file
// and /dev/null (a character device, but not a terminal) all say no.
func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return termiosAnswer(err, func() bool {
		var st unix.Stat_t
		return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFCHR
	})
}

// termiosAnswer judges a TCGETS result. ENOTTY is the kernel saying this is
// no terminal. Any other failure says nothing about the device, so a
// character device still counts as a terminal: `secret add` then refuses
// rather than read a value that a real terminal would echo.
func termiosAnswer(err error, charDevice func() bool) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, unix.ENOTTY):
		return false
	}
	return charDevice()
}

// readHiddenLine is nil: there is no hidden prompt on Linux yet, so `secret
// add` refuses to read a value from a terminal, where it would be echoed
// (errNoHiddenPrompt).
var readHiddenLine func() ([]byte, error)
