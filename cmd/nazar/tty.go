package main

import (
	"bytes"
	"errors"
)

// errNoHiddenPrompt is why `secret add` refuses at a terminal in a build
// with no hidden prompt (off macOS): the value would show as it is typed.
// It names the piped form, so that no one is sent to write the value to a
// file.
var errNoHiddenPrompt = errors.New(`no hidden prompt on this system, so a value typed here would show; nothing was read: pipe it from a shell that has it: printf '%s' "$NAME" | nazar secret add NAME`)

// maxHiddenLine is the longest value the hidden prompt accepts: a terminal
// in canonical mode keeps at most MAX_CANON bytes of a line (1024 on macOS,
// the newline included), so a line this long or longer may have been cut
// short. Longer values are piped on stdin.
const maxHiddenLine = 1022

// checkHiddenLine judges one line typed or pasted at the hidden prompt,
// with pending the bytes the terminal still holds after it (FIONREAD).
// More input pending is a multi-line paste: the other lines would reach
// the shell as commands once nazar exits (the caller discards them), so
// nothing is stored. An escape sequence is a terminal's paste marker or
// cursor key, not part of a token. No message repeats the value.
func checkHiddenLine(line []byte, pending int) error {
	switch {
	case pending > 0:
		return errors.New("more than one line was entered; nothing was added and the rest was discarded: pipe it (nazar secret add NAME < file)")
	case len(line) > maxHiddenLine:
		return errors.New("the value is too long for the hidden prompt (the terminal may have cut it short); nothing was added: pipe it (nazar secret add NAME < file)")
	case bytes.IndexByte(line, 0x1b) >= 0:
		return errors.New("the value has an escape sequence (a terminal's paste markers?); nothing was added: pipe it (nazar secret add NAME < file)")
	}
	return nil
}
