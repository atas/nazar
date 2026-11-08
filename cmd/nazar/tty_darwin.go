//go:build darwin

package main

import (
	"bytes"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/secrets/seal"
)

// fionread is FIONREAD of <sys/filio.h>, _IOR('f', 127, int): the bytes a
// terminal holds for the next read (x/sys/unix has no constant for it on
// darwin).
const fionread = 0x4004667f

// stdinIsTerminal reports whether stdin (fd 0) is a terminal: the kernel
// answers a termios request only for a terminal device, so a pipe, a file
// and /dev/null all say no.
func stdinIsTerminal() bool {
	_, err := unix.IoctlGetTermios(0, unix.TIOCGETA)
	return err == nil
}

// readHiddenLine reads one line from the terminal on stdin with echo off
// (`nazar secret add`, secrets design 7.1): line editing and signals stay
// as they are, so Ctrl-C still interrupts and Ctrl-D ends an empty line.
// The line is judged by checkHiddenLine with what the terminal still holds
// after it: a multi-line paste is refused. The terminal's settings are
// restored with TIOCSETAF, which also discards any input left (the other
// lines of a paste never reach the shell), on every return and on SIGINT,
// SIGTERM, SIGHUP or SIGQUIT before the CLI exits (130); the newline the
// user typed, which the terminal did not show, is written to stderr. At
// most seal.MaxValue+1 bytes are kept.
func readHiddenLine() ([]byte, error) {
	const fd = 0
	saved, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return nil, err
	}
	hidden := *saved
	hidden.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHONL
	hidden.Lflag |= unix.ICANON | unix.ISIG
	restore := func() { _ = unix.IoctlSetTermios(fd, unix.TIOCSETAF, saved) }

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})
	defer func() {
		signal.Stop(sigs)
		close(done)
	}()
	go func() {
		select {
		case <-sigs:
			restore()
			os.Stderr.WriteString("\n")
			os.Exit(130)
		case <-done:
		}
	}()

	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &hidden); err != nil {
		return nil, err
	}
	defer restore()
	defer os.Stderr.WriteString("\n")

	var line []byte
	buf := make([]byte, 1024)
	defer clear(buf)
	for {
		n, err := unix.Read(fd, buf)
		if n > 0 {
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, '\n'); i >= 0 {
				line = appendBounded(line, chunk[:i])
				pending := n - i - 1
				if more, err := unix.IoctlGetInt(fd, fionread); err == nil {
					pending += more
				}
				if err := checkHiddenLine(line, pending); err != nil {
					clear(line)
					return nil, err
				}
				return line, nil
			}
			line = appendBounded(line, chunk)
		}
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			clear(line)
			return nil, err
		case n == 0: // Ctrl-D at the start of a line, or end of input
			if err := checkHiddenLine(line, 0); err != nil {
				clear(line)
				return nil, err
			}
			return line, nil
		}
	}
}

// appendBounded appends b to line up to seal.MaxValue+1 bytes in all, so
// a value over the bound is still seen as one (and refused), and growing
// copies are cleared.
func appendBounded(line, b []byte) []byte {
	room := seal.MaxValue + 1 - len(line)
	if room <= 0 {
		return line
	}
	if len(b) > room {
		b = b[:room]
	}
	if cap(line)-len(line) < len(b) {
		grown := make([]byte, len(line), 2*cap(line)+len(b))
		copy(grown, line)
		clear(line)
		line = grown
	}
	return append(line, b...)
}
