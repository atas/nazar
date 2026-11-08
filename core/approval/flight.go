package approval

import "sync"

// Flight runs at most one fn per key at a time; concurrent callers with the
// same key wait for that call and receive its result. This is how requests
// waiting on the same scope share one dialog (spec 4.4). Keys differing in
// any part (target, rule, scope, receiver) never share. A Flight remembers
// nothing: once the call finishes, the next call for the key runs fn again.
// The zero value is ready to use.
type Flight[T any] struct {
	mu    sync.Mutex
	calls map[Key]*call[T]
}

type call[T any] struct {
	done chan struct{}
	val  T // set before done is closed; stays zero if fn panicked
}

// Do runs fn for k, or waits for the call already running for k. shared is
// true for callers that received another caller's result. If fn panics, the
// panic propagates to the leader, waiters get the zero value (shared), and
// the key is free again for later calls.
func (f *Flight[T]) Do(k Key, fn func() T) (v T, shared bool) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[Key]*call[T]{}
	}
	if c, ok := f.calls[k]; ok {
		f.mu.Unlock()
		<-c.done
		return c.val, true
	}
	c := &call[T]{done: make(chan struct{})}
	f.calls[k] = c
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.calls, k)
		f.mu.Unlock()
		close(c.done)
	}()
	c.val = fn()
	return c.val, false
}
