//go:build !darwin || !cgo

package pipes

import "github.com/atas/nazar/core/platform"

// New is nil off macOS (and in a build without cgo): no stdout check, so
// k8s.credential is refused.
func New() platform.Pipes { return nil }
