//go:build !linux

// Command nazar-agent is nazar's agent on Linux (main_linux.go). On any
// other OS this is a stub that says so: on macOS the agent is
// nazar-agent.app, built from macos/ with the core in bridge/.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "nazar-agent: this is the Linux agent; on macOS the agent is nazar-agent.app (make agent)")
	os.Exit(1)
}
