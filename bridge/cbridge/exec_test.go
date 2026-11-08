package cbridge_test

import (
	"bytes"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/bridge/cbridge/cfake"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// platform.Exec through the C ABI. The three exec callbacks are optional
// (secrets design 6.3, D8): without all three the bridge has no Exec and
// the daemon refuses late-env. Events cross as process records, in
// order, to fn on Go's own goroutine, never after cancel returned; a
// record that does not decode, or names another instance, still counts
// as an exec, but of nothing (an empty path), so it never passes a plan.

func TestExecIsOptional(t *testing.T) {
	for _, partial := range []bool{false, true} {
		p, free := cfake.NoExecTable(partial)
		b, err := cbridge.New(p)
		free()
		if err != nil {
			t.Fatalf("partial=%v: a table without the exec callbacks is still a table: %v", partial, err)
		}
		if x := b.Exec(); x != nil {
			t.Errorf("partial=%v: Exec() = %v, want nil", partial, x)
		}
	}
	if _, b, _, _ := newHarness(t); b.Exec() == nil {
		t.Fatal("a full table has an Exec")
	}
}

func recvExec(t *testing.T, ch <-chan platform.ProcessInfo) platform.ProcessInfo {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no exec event")
	}
	return platform.ProcessInfo{}
}

func TestExecEventsThroughTheCABI(t *testing.T) {
	h, b, _, _ := newHarness(t)
	x := b.Exec()
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/nazar"})
	got := make(chan platform.ProcessInfo, 8)
	cancel, err := x.OnProcessExec(ref, func(p platform.ProcessInfo) { got <- p })
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"A=1", "B=two words"}
	code := platform.CodeIdentity{AdHoc: true, CDHash: []byte{1, 2, 3}}
	h.f.Exec(ref, fake.Proc{Path: "/bin/node", Args: []string{"/bin/node", "/s.js"}, Cwd: "/", Code: code}, env)
	if p := recvExec(t, got); p.Ref != ref || p.Path != "/bin/node" || !slices.Equal(p.Args, []string{"/bin/node", "/s.js"}) ||
		p.Cwd != "/" || !bytes.Equal(p.Code.CDHash, code.CDHash) {
		t.Fatalf("event %+v", p)
	}
	if e, err := x.Environment(ref); err != nil || !slices.Equal(e, env) {
		t.Fatalf("Environment = %q, %v", e, err)
	}
	other := `{"pid":` + itoa(ref.PID) + `,"generation":` + utoa(ref.Generation+1) +
		`,"parentPid":1,"parentGeneration":0,"uid":501,"startMicros":1,"path":"/bin/node","args":["/bin/node"],"cwd":"/",` + zeroCode + `,"comm":"node"}`
	for _, raw := range []string{"{", "", other} {
		cfake.Corrupt("exec", []byte(raw))
		h.f.Exec(ref, fake.Proc{Path: "/bin/node", Args: []string{"/bin/node"}, Cwd: "/", Code: code}, env)
		if p := recvExec(t, got); p.Ref != ref || p.Path != "" || p.Args != nil || p.Cwd != "" || p.Code.CDHash != nil {
			t.Fatalf("record %q must count as an exec of nothing, got %+v", raw, p)
		}
	}
	h.f.SetEnvironmentUnreadable(ref, true)
	if _, err := x.Environment(ref); !errors.Is(err, platform.ErrUnreadable) {
		t.Fatalf("hidden: %v", err)
	}
	cancel()
	cancel()
	h.f.Exec(ref, fake.Proc{Path: "/bin/sh", Cwd: "/"}, env)
	for tok := uint64(0); tok < 1000; tok++ {
		cbridge.ProcessExecd(tok, []byte("{}")) // forged tokens run nothing
	}
	select {
	case p := <-got:
		t.Fatalf("event after cancel: %+v", p)
	case <-time.After(100 * time.Millisecond):
	}
	// Refs that name no single instance never reach C.
	for _, bad := range []platform.ProcessRef{{}, {PID: ref.PID}, {PID: -1, Generation: 1}, {PID: 1 << 40, Generation: 1}} {
		if _, err := x.OnProcessExec(bad, func(platform.ProcessInfo) {}); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("OnProcessExec(%v): %v", bad, err)
		}
		if _, err := x.Environment(bad); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Environment(%v): %v", bad, err)
		}
	}
}

// fn runs on Go's own goroutine, one call at a time and in order: a slow
// fn never holds up the platform's event handler (Swift's queue).
func TestExecEventsDoNotBlockThePlatform(t *testing.T) {
	h, b, _, _ := newHarness(t)
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/nazar"})
	release, order := make(chan struct{}), make(chan string, 4)
	cancel, err := b.Exec().OnProcessExec(ref, func(p platform.ProcessInfo) { <-release; order <- p.Path })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	done := make(chan struct{})
	go func() {
		h.f.Exec(ref, fake.Proc{Path: "/a", Cwd: "/"}, nil)
		h.f.Exec(ref, fake.Proc{Path: "/b", Cwd: "/"}, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the platform's event handler waited for fn")
	}
	close(release)
	if a, b := <-order, <-order; a != "/a" || b != "/b" {
		t.Fatalf("order %s, %s", a, b)
	}
}

// An exec the platform read before Environment answered has reached fn
// by the time Environment returns (platform.Exec: "an exec that happened
// before the call is seen before the answer"), even with fn on Go's own
// goroutine: a caller never compares a later image's environment with an
// earlier image's record without seeing the later exec.
func TestExecSeenBeforeEnvironmentAnswers(t *testing.T) {
	h, b, _, _ := newHarness(t)
	x := b.Exec()
	ref := h.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/nazar"})
	var seen atomic.Int32
	cancel, err := x.OnProcessExec(ref, func(platform.ProcessInfo) {
		time.Sleep(50 * time.Millisecond)
		seen.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	for i := int32(1); i <= 3; i++ {
		h.f.Exec(ref, fake.Proc{Path: "/bin/node", Cwd: "/"}, []string{"A=1"})
		if _, err := x.Environment(ref); err != nil {
			t.Fatal(err)
		}
		if n := seen.Load(); n != i {
			t.Fatalf("Environment answered after exec %d with fn called %d times", i, n)
		}
	}
}
