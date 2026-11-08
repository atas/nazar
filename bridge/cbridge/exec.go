package cbridge

/*
#cgo CFLAGS: -I${SRCDIR}/../../macos/Sources/CNazarBridge/include
#include "nazar_bridge.h"
static int nz_has_exec(const NazarCallbacks *c) { return c->watch_exec && c->cancel_exec && c->environment; }
static int32_t nz_watch_exec(const NazarCallbacks *c, int64_t pid, uint64_t gen, uint64_t t) { return c->watch_exec(pid, gen, t); }
static void nz_cancel_exec(const NazarCallbacks *c, uint64_t t) { c->cancel_exec(t); }
static int32_t nz_environment(const NazarCallbacks *c, int64_t pid, uint64_t gen, NzBuf *o) { return c->environment(pid, gen, o); }
*/
import "C"

import (
	"math"
	"sync"
	"unsafe"

	"github.com/atas/nazar/core/platform"
)

// Exec is the bridge's platform.Exec, or nil when the Swift layer does
// not offer all three exec callbacks (secrets design 6.3, D8: the daemon then
// refuses late-env before any prompt).
func (b *Bridge) Exec() platform.Exec {
	if C.nz_has_exec(b.cb) == 0 {
		return nil
	}
	return execSeam{b}
}

type execSeam struct{ b *Bridge }

// full reports whether ref can name one live instance across the ABI.
func full(ref platform.ProcessRef) bool {
	return ref.PID > 0 && ref.PID <= math.MaxInt32 && ref.Generation != 0
}

func (e execSeam) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	if !full(ref) || fn == nil {
		return nil, platform.ErrNoProcess
	}
	w := newExecWatch(ref, fn)
	t := addExec(w)
	if err := statusErr("watch exec", C.nz_watch_exec(e.b.cb, C.int64_t(ref.PID), C.uint64_t(ref.Generation), C.uint64_t(t))); err != nil {
		dropExec(t)
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock() // waits for a running fn
			w.cancelled = true
			w.mu.Unlock()
			dropExec(t)
			C.nz_cancel_exec(e.b.cb, C.uint64_t(t))
		})
	}, nil
}

func (e execSeam) Environment(ref platform.ProcessRef) ([]string, error) {
	if !full(ref) {
		return nil, platform.ErrNoProcess
	}
	var out C.NzBuf
	st := C.nz_environment(e.b.cb, C.int64_t(ref.PID), C.uint64_t(ref.Generation), &out)
	js, err := e.b.take(out)
	flushExecs(ref) // every exec the platform read before answering reaches fn first
	if serr := statusErr("environment", st); serr != nil {
		return nil, serr
	}
	var env []string
	if err != nil || decodeStrict(js, &env) != nil || len(env) == 0 {
		return nil, platform.ErrUnreadable // never an empty list in place of a hidden one
	}
	return env, nil
}

// execWatch is one OnProcessExec registration. Events queue in q and
// reach fn one at a time, in order; mu is held while fn runs and by
// cancel, so fn never runs after cancel returned. pushed and done count
// the events queued and handled; delivered is signalled at each one.
type execWatch struct {
	ref platform.ProcessRef
	fn  func(platform.ProcessInfo)

	mu        sync.Mutex
	cancelled bool

	qmu          sync.Mutex
	delivered    sync.Cond // on qmu
	q            []platform.ProcessInfo
	running      bool
	pushed, done uint64
}

func newExecWatch(ref platform.ProcessRef, fn func(platform.ProcessInfo)) *execWatch {
	w := &execWatch{ref: ref, fn: fn}
	w.delivered.L = &w.qmu
	return w
}

// flushExecs waits until every exec queued for ref when it is called has
// reached its fn; later ones are not waited for.
func flushExecs(ref platform.ProcessRef) {
	events.mu.Lock()
	var ws []*execWatch
	for _, w := range events.execs {
		if w.ref == ref {
			ws = append(ws, w)
		}
	}
	events.mu.Unlock()
	marks := make([]uint64, len(ws))
	for i, w := range ws {
		marks[i] = w.mark()
	}
	for i, w := range ws {
		w.wait(marks[i])
	}
}

// mark is the count of events queued so far, for wait.
func (w *execWatch) mark() uint64 {
	w.qmu.Lock()
	defer w.qmu.Unlock()
	return w.pushed
}

// wait returns once the first n events were handled.
func (w *execWatch) wait(n uint64) {
	w.qmu.Lock()
	for w.done < n {
		w.delivered.Wait()
	}
	w.qmu.Unlock()
}

func (w *execWatch) push(p platform.ProcessInfo) {
	w.qmu.Lock()
	w.q = append(w.q, p)
	w.pushed++
	start := !w.running
	w.running = true
	w.qmu.Unlock()
	if start {
		go w.run()
	}
}

func (w *execWatch) run() {
	for {
		w.qmu.Lock()
		if len(w.q) == 0 {
			w.running = false
			w.qmu.Unlock()
			return
		}
		p := w.q[0]
		w.q = w.q[1:]
		w.qmu.Unlock()
		w.mu.Lock()
		if !w.cancelled {
			w.fn(p)
		}
		w.mu.Unlock()
		w.qmu.Lock()
		w.done++
		w.delivered.Broadcast()
		w.qmu.Unlock()
	}
}

// ProcessExecd delivers one exec event of the watch under token: the
// process record as Swift read it at the exec. A record that does not
// decode, or names another instance, still counts as an exec, of nothing
// (the watched ref, no path, no argv, no code), so it matches no plan.
// Unknown tokens run nothing. It only queues: it never blocks Swift.
func ProcessExecd(token uint64, record []byte) {
	events.mu.Lock()
	w := events.execs[token]
	events.mu.Unlock()
	if w == nil {
		return
	}
	info := platform.ProcessInfo{Ref: w.ref}
	var wp wireProcess
	if decodeStrict(record, &wp) == nil {
		if got := wp.info(); got.Ref == w.ref {
			info = got
		}
	}
	w.push(info)
}

// ExecEvent is the c-archive's NazarProcessExecd: the record is Swift's
// memory, valid for the call only, and copied here; NULL, empty or over
// maxDocument is a record that does not decode.
func ExecEvent(token uint64, record unsafe.Pointer, n uint64) {
	var b []byte
	if record != nil && n > 0 && n <= maxDocument {
		b = C.GoBytes(record, C.int(n))
	}
	ProcessExecd(token, b)
}
