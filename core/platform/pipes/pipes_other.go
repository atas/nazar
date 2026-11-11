//go:build !linux && (!darwin || !cgo)

package pipes

import "github.com/atas/nazar/core/platform"

// New is nil off macOS and Linux (and in a macOS build without cgo): no
// stdout check, so k8s.credential is refused.
func New() platform.Pipes { return nil }
