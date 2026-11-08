//go:build !darwin

package mounts

import "github.com/atas/nazar/core/platform"

// New is nil off macOS: no mount watch, so late-env is refused.
func New() platform.Mounts { return nil }
