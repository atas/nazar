//go:build linux

package main

import (
	"errors"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/peertrust"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

// On Linux no code signature names a program, so the macOS check of the
// control socket's peer (checkAgentPeer against a code requirement) has
// nothing to check: a CLI that is not in Linux mode (a.linux false)
// refuses rather than silently trusting, as every other non-macOS build
// does. In Linux mode the CLI checks the peer by binary hash instead
// (checkLinuxAgent).
var errNoCodeSigning = errors.New("no code-signature check for the control socket on this platform")

func checkAgentPeer(int, string) error             { return errNoCodeSigning }
func selfTeamID() (string, error)                  { return "", errNoCodeSigning }
func designatedRequirement(string) (string, error) { return "", errNoCodeSigning }

// checkLinuxAgent: the process listening on the control socket runs as
// this user and runs the nazar-agent that `nazar install` recorded in
// home's ~/.nazar/install.json, and this CLI runs the nazar recorded there
// (core/peertrust). The second check is what an upgrade with the old agent
// still running meets: the agent still matches, it would refuse this CLI,
// and only this side can say why. The record is read on every call, so a
// re-run `nazar install` applies at once.
func checkLinuxAgent(fd int, home string) error {
	if err := peertrust.CheckAgent(fd, home, procfs.New()); err != nil {
		return err
	}
	if err := peertrust.CheckSelf(home); err != nil {
		return &control.SelfError{Err: err}
	}
	return nil
}
