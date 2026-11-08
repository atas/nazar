package cbridge

import (
	"sync"
	"sync/atomic"
)

// Exit, screen-lock and exec callbacks come back from Swift as tokens
// (NazarProcessExited / NazarScreenLocked / NazarProcessExecd, exported by
// the c-archive's main package). There is one registry per process, like
// the Go runtime.
var events = struct {
	next  atomic.Uint64
	mu    sync.Mutex
	exits map[uint64]func()
	locks map[uint64]func()
	execs map[uint64]*execWatch
}{exits: map[uint64]func(){}, locks: map[uint64]func(){}, execs: map[uint64]*execWatch{}}

func addExec(w *execWatch) uint64 {
	t := events.next.Add(1)
	events.mu.Lock()
	events.execs[t] = w
	events.mu.Unlock()
	return t
}

func dropExec(t uint64) {
	events.mu.Lock()
	delete(events.execs, t)
	events.mu.Unlock()
}

func addExit(fn func()) uint64 {
	t := events.next.Add(1)
	events.mu.Lock()
	events.exits[t] = fn
	events.mu.Unlock()
	return t
}

func addLock(fn func()) uint64 {
	t := events.next.Add(1)
	events.mu.Lock()
	events.locks[t] = fn
	events.mu.Unlock()
	return t
}

// ProcessExited runs the exit callback registered under token, at most
// once and never on the caller's (Swift's) thread. Unknown tokens are
// ignored, so a duplicate or forged token can't run anything twice.
func ProcessExited(token uint64) {
	events.mu.Lock()
	fn := events.exits[token]
	delete(events.exits, token)
	events.mu.Unlock()
	if fn != nil {
		go fn()
	}
}

// ScreenLocked runs the screen-lock callback registered under token.
func ScreenLocked(token uint64) {
	events.mu.Lock()
	fn := events.locks[token]
	events.mu.Unlock()
	if fn != nil {
		go fn()
	}
}

// pendingExits is the number of exit callbacks not yet fired (tests).
func pendingExits() int {
	events.mu.Lock()
	defer events.mu.Unlock()
	return len(events.exits)
}
