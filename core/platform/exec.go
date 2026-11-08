package platform

import "errors"

// ErrUnreadable: the platform cannot read what was asked of a live process
// (its startup environment, say). Never treated as "nothing there": a
// process whose environment is hidden (an Apple platform binary on macOS)
// can't be checked, so it can't be a late-env receiver (secrets design
// 6.3.4).
var ErrUnreadable = errors.New("platform: not readable")

// Exec is what nazar run's late-env handover needs beyond Platform
// (secrets design 6.3 step 6; 6.3 D8). It is optional: a daemon without
// it refuses late-env before any prompt. On macOS it is kqueue's
// EVFILT_PROC/NOTE_EXEC and KERN_PROCARGS2; the fake implements it for
// tests.
type Exec interface {
	// OnProcessExec calls fn on every exec of the live process ref names,
	// with the process as the platform read it at that exec: its path
	// (realpath), argv, working directory and code identity, read before
	// the event is let go, because a program may rewrite its argv soon
	// after (npm does within about 40 ms, spike S12). fn is not called
	// after cancel returns, nor after the process exited. fn is called in
	// order, one call at a time, possibly on another goroutine, and must
	// not call cancel or Environment. Environment may wait for fn: hold no
	// lock fn takes while calling it. Two execs in one moment may be reported as one,
	// read after the later: every record describes the image the process
	// runs when it was read. Only the live instance a full ref names is
	// watched: any other ref is an error.
	OnProcessExec(ref ProcessRef, fn func(ProcessInfo)) (cancel func(), err error)
	// Environment returns the startup environment of the live process ref
	// names: what its last exec was given, NAME=VALUE in order. ErrNoProcess
	// for a process that is gone; ErrUnreadable when the platform can't
	// read it, never an empty list in its place. It answers only while a
	// watch on ref is on, from the read taken at the last exec that watch
	// saw (where argv and the environment share one area, macOS
	// KERN_PROCARGS2, npm's argv rewrite some 40 ms after exec zero-fills
	// it and a later read would misparse it): ErrUnreadable for a process
	// not watched, or not exec'd since its first watch began, so a stale
	// environment is never answered. An exec that happened before the call
	// is seen before the answer, by Environment and by every fn. macOS cannot tell an empty startup
	// environment from a hidden one: both are ErrUnreadable there.
	Environment(ref ProcessRef) ([]string, error)
}

// Mounts tells nazar run's late-env hand-over whether a volume was mounted
// or unmounted while it ran (secrets design 6.3, D12): a disk image or a
// share mounted over a folder hides what the folder holds without changing
// it, so a file put in front of a pinned one and taken away again leaves
// every pin matching.
// Optional, as Exec: a daemon without it refuses late-env before any
// prompt. On macOS it is a kqueue EVFILT_FS watch (package mounts).
type Mounts interface {
	// WatchMounts starts a watch of every mount and unmount on this
	// computer, by any process. changed reports whether one happened since
	// WatchMounts was called: one that completed before is never reported,
	// one that completed after it returned always is. It stays true once
	// true, and is true when the platform can't tell and after stop (fail
	// closed). stop ends the watch; twice is harmless. Both may be called
	// from any goroutine.
	WatchMounts() (changed func() bool, stop func(), err error)
}
