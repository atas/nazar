// Command fakedialog stands in for zenity or kdialog in the Linux platform
// tests: the dialog gate runs it where it would run the real program, and
// the scripted user (internal/linuxtest/answers) decides the outcome. It
// first appends its argv and environment as one JSON line to the file
// NAZAR_TEST_DIALOG_LOG names (when set), so a test can check exactly what
// the real program would have been shown and given. Then it pops the next
// answer from the queue at NAZAR_TEST_ANSWERS: allow exits 0, deny exits 1,
// and no answer within 10 s exits 5 (zenity's own timeout code). Test-only
// code; nothing in it ships.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/atas/nazar/internal/linuxtest/answers"
)

// wait is how long the fake stays "on screen" without an answer before it
// ends as zenity does when its countdown runs out.
const wait = 10 * time.Second

type entry struct {
	Argv []string `json:"argv"`
	Env  []string `json:"env"`
}

func main() {
	if path := os.Getenv("NAZAR_TEST_DIALOG_LOG"); path != "" {
		if err := appendLine(path, entry{Argv: os.Args, Env: os.Environ()}); err != nil {
			fmt.Fprintln(os.Stderr, "fakedialog:", err)
			os.Exit(7)
		}
	}
	allow, ok := answers.PopFrom(os.Getenv("NAZAR_TEST_ANSWERS"), wait)
	switch {
	case !ok:
		os.Exit(5)
	case allow:
		os.Exit(0)
	default:
		os.Exit(1)
	}
}

func appendLine(path string, e entry) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}
