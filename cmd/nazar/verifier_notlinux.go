//go:build !linux

package main

import "errors"

// checkLinuxAgent is the Linux check of the control socket's peer by
// binary hash (verifier_linux.go). A build for another OS has no /proc to
// read the peer's image from, so a CLI put in Linux mode there (a.linux,
// which tests set) trusts no peer at all.
func checkLinuxAgent(int, string) error {
	return errors.New("the check of nazar-agent by binary hash is not in this build")
}
