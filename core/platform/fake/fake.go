// Package fake is a scriptable, in-memory platform.Platform for tests: process
// trees, gate answers, process exits, warnings, and a software P-256 "enclave".
package fake

import (
	"sync"
	"time"

	"github.com/atas/nazar/core/platform"
)

var _ platform.Platform = (*Fake)(nil)

// Fake implements platform.Platform. The zero value is not usable; call New.
//
// Every method may be called from any goroutine. Callbacks (exit watchers,
// screen-lock handlers, gate funcs) run outside the fake's lock, so they may
// call back into the fake.
type Fake struct {
	mu sync.Mutex
	// execMu is held by Exec while it calls the watchers, and by
	// Environment: an exec is seen by every watcher before Environment
	// answers it (platform.Exec). Taken before mu.
	execMu sync.Mutex

	now     time.Time
	nextPID int

	procs       map[platform.ProcessRef]platform.ProcessInfo
	apps        map[platform.ProcessRef]platform.AppInfo
	responsible map[platform.ProcessRef]platform.ProcessRef
	exitFns     map[platform.ProcessRef][]func()
	lockFns     []func()
	codeHashes  map[string][]byte
	// Exec (exec.go): watchers, startup environments, hidden ones.
	execWatches map[platform.ProcessRef][]*execWatch
	envs        map[platform.ProcessRef][]string
	envHidden   map[platform.ProcessRef]bool
	unseen      map[platform.ProcessRef][]platform.ProcessInfo // ExecUnseen, not yet delivered
	installed   map[string]platform.AppBundle                  // by bundle path
	// Pipes (pipes.go): whose read end each scripted fd 1 is.
	stdout map[platform.ProcessRef]platform.ProcessRef
	// foreign: writers whose pipe's read end another process holds too,
	// or the reader inherited.
	foreign map[platform.ProcessRef]bool
	// StdoutFunc, when set, answers StdoutReadBy instead (error injection).
	StdoutFunc func(writer, reader platform.ProcessRef) (bool, error)
	// Mounts (mounts.go): the watches on.
	mountWatches []*mountWatch
	// MountsErr, when set, fails WatchMounts (set before use).
	MountsErr error

	peers       map[int]platform.ProcessRef
	defaultPeer platform.ProcessRef
	// PeerFunc, when set, overrides the peer table.
	PeerFunc func(fd int) (platform.ProcessRef, error)
	// CodeHashFunc answers CodeHash for paths without a scripted hash.
	CodeHashFunc func(path string) ([]byte, error)
	// InstalledAppFunc, when set, answers InstalledApp instead of the
	// installed bundles (error injection).
	InstalledAppFunc func(bundleID string) (platform.AppBundle, error)

	gates

	enclave
	warnings []platform.Warning

	// Launchd is the root process (pid 1, Apple-signed).
	Launchd platform.ProcessRef
}

// New returns a Fake whose clock starts at start and which already has a
// launchd process.
func New(start time.Time) *Fake {
	f := &Fake{
		now:         start,
		nextPID:     100,
		procs:       map[platform.ProcessRef]platform.ProcessInfo{},
		apps:        map[platform.ProcessRef]platform.AppInfo{},
		responsible: map[platform.ProcessRef]platform.ProcessRef{},
		exitFns:     map[platform.ProcessRef][]func(){},
		codeHashes:  map[string][]byte{},
		installed:   map[string]platform.AppBundle{},
		peers:       map[int]platform.ProcessRef{},
		stdout:      map[platform.ProcessRef]platform.ProcessRef{},
		foreign:     map[platform.ProcessRef]bool{},
	}
	f.gates.init()
	f.enclave.init()
	f.Launchd = platform.ProcessRef{PID: 1, Generation: 1}
	f.procs[f.Launchd] = platform.ProcessInfo{
		Ref: f.Launchd, UID: 0, StartTime: start, Path: "/sbin/launchd", Args: []string{"/sbin/launchd"},
		Code: platform.CodeIdentity{Signed: true, Apple: true, SigningID: "com.apple.xpc.launchd"},
	}
	return f
}

// Now returns the fake clock.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves the fake clock forward.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

// Warnings returns every warning shown so far, in order.
func (f *Fake) Warnings() []platform.Warning {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]platform.Warning, len(f.warnings))
	for i, w := range f.warnings {
		w.Lines = append([]string(nil), w.Lines...)
		out[i] = w
	}
	return out
}

// ShowWarning records the warning (non-modal: returns at once).
func (f *Fake) ShowWarning(w platform.Warning) {
	f.mu.Lock()
	w.Lines = append([]string(nil), w.Lines...)
	f.warnings = append(f.warnings, w)
	f.mu.Unlock()
}

// LockScreen fires every OnScreenLock callback, in registration order.
func (f *Fake) LockScreen() {
	f.mu.Lock()
	fns := append([]func(){}, f.lockFns...)
	f.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

// OnScreenLock registers fn to run on every LockScreen.
func (f *Fake) OnScreenLock(fn func()) {
	f.mu.Lock()
	f.lockFns = append(f.lockFns, fn)
	f.mu.Unlock()
}
