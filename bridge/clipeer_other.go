//go:build !darwin

package main

import "github.com/atas/nazar/core/platform"

// cliVerifier: no code-signature check off macOS, so no peer is the nazar
// CLI and no secret value is returned to anyone.
func cliVerifier(platform.Platform, func(string, ...any)) func(fd int) (platform.ProcessRef, error) {
	return nil
}
