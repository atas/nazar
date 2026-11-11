//go:build !linux && (!darwin || !cgo)

package main

import "errors"

// There is no code-signature check off macOS, or in a macOS build without
// cgo (Linux has its own check, by binary hash: verifier_linux.go);
// everything refuses rather than silently trusting.
var errNoCodeSigning = errors.New("no code-signature check for the control socket on this platform")

func checkAgentPeer(int, string) error             { return errNoCodeSigning }
func selfTeamID() (string, error)                  { return "", errNoCodeSigning }
func designatedRequirement(string) (string, error) { return "", errNoCodeSigning }
