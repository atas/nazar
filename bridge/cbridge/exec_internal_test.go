package cbridge

import (
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// Environment waits for the execs queued when it answered, never for
// later ones: a process that keeps exec'ing, or a slow fn on a later
// exec, never holds Environment.
func TestExecFlushWaitsOnlyForEarlierExecs(t *testing.T) {
	relA, relB := make(chan struct{}), make(chan struct{})
	defer close(relB)
	w := newExecWatch(platform.ProcessRef{PID: 1, Generation: 1}, func(p platform.ProcessInfo) {
		if p.Path == "/a" {
			<-relA
		} else {
			<-relB
		}
	})
	w.push(platform.ProcessInfo{Path: "/a"})
	n := w.mark()
	w.push(platform.ProcessInfo{Path: "/b"})
	done := make(chan struct{})
	go func() { w.wait(n); close(done) }()
	select {
	case <-done:
		t.Fatal("wait returned before /a reached fn")
	case <-time.After(50 * time.Millisecond):
	}
	close(relA)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait waited for an exec queued after its mark")
	}
}
