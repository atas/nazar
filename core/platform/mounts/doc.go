// Package mounts is platform.Mounts on macOS (secrets design 6.3, D12): one
// kqueue per watch with an EVFILT_FS knote, which the kernel posts VQ_MOUNT
// and VQ_UNMOUNT to from inside mount(2) and unmount(2), before they return.
// Elsewhere New returns nil and late-env is refused.
package mounts
