package main

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// launchd stands in for /bin/launchctl: it answers `print` with "found"
// until gone() is true, and records every call and every pause.
type launchd struct {
	mu        sync.Mutex
	calls     []string
	slept     time.Duration
	printsTil int     // `print` finds the service this many times, then not
	bootstrap []error // answers for successive bootstraps (nil when exhausted)
}

func (l *launchd) install(h *harness) {
	h.a.launchctl = func(args ...string) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.calls = append(l.calls, args[0])
		switch args[0] {
		case "print":
			if l.printsTil > 0 {
				l.printsTil--
				return nil
			}
			return errors.New("launchctl print gui/501/dev.nazar.agent: exit status 113: Could not find service \"dev.nazar.agent\" in domain for user gui: 501")
		case "bootstrap":
			if len(l.bootstrap) > 0 {
				err := l.bootstrap[0]
				l.bootstrap = l.bootstrap[1:]
				return err
			}
		}
		return nil
	}
	h.a.sleep = func(d time.Duration) {
		l.mu.Lock()
		l.slept += d
		l.mu.Unlock()
	}
}

func (l *launchd) sequence() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.calls, ",")
}

var errEIO = errors.New("launchctl bootstrap gui/501 /x/dev.nazar.agent.plist: exit status 5: Bootstrap failed: 5: Input/output error")

// bootout returns before the old agent is gone; install waits for
// `launchctl print` to stop finding it before bootstrapping.
func TestInstallWaitsForTheOldAgentToGo(t *testing.T) {
	h := newHarness(t)
	l := &launchd{printsTil: 3}
	l.install(h)
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if got := l.sequence(); got != "bootout,print,print,print,print,bootstrap" {
		t.Fatalf("launchctl calls %q", got)
	}
	if l.slept != 3*bootoutPoll {
		t.Fatalf("slept %v, want %v", l.slept, 3*bootoutPoll)
	}
}

// The wait is bounded: an agent that never goes still gets one bootstrap
// after bootoutWait, whose error is reported.
func TestInstallWaitIsBounded(t *testing.T) {
	h := newHarness(t)
	l := &launchd{printsTil: 1 << 30, bootstrap: []error{errors.New("launchctl bootstrap: exit status 37: Operation already in progress")}}
	l.install(h)
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if l.slept != bootoutWait {
		t.Fatalf("slept %v, want exactly %v", l.slept, bootoutWait)
	}
	if !strings.HasSuffix(l.sequence(), ",print,bootstrap") || strings.Count(l.sequence(), "bootstrap") != 1 {
		t.Fatalf("calls %q: one bootstrap, after the wait (error 37 is not retried)", l.sequence())
	}
	if !strings.Contains(h.errb.String(), "Operation already in progress") {
		t.Fatalf("stderr %q", h.errb)
	}
}

// Error 5 from bootstrap is retried exactly once, after waiting again.
func TestInstallRetriesBootstrapOnceOnEIO(t *testing.T) {
	h := newHarness(t)
	l := &launchd{bootstrap: []error{errEIO}}
	l.install(h)
	if code := h.run("--json", "install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.out, h.errb)
	}
	if got := l.sequence(); got != "bootout,print,bootstrap,print,bootstrap" {
		t.Fatalf("calls %q", got)
	}

	h2 := newHarness(t)
	l2 := &launchd{bootstrap: []error{errEIO, errEIO, nil}}
	l2.install(h2)
	if code := h2.run("install", "--bin-dir", filepath.Join(h2.home, "bin")); code != 1 {
		t.Fatalf("second EIO: exit %d, want 1", code)
	}
	if got := l2.sequence(); strings.Count(got, "bootstrap") != 2 {
		t.Fatalf("calls %q: exactly one retry", got)
	}
	if !strings.Contains(h2.errb.String(), "Input/output error") {
		t.Fatalf("stderr %q", h2.errb)
	}
}

// The retry's wait is bounded too: an agent that never goes and a
// bootstrap that keeps failing with error 5 cost at most two waits and
// two bootstraps, then install reports the error (never loops).
func TestInstallRetryWaitIsBounded(t *testing.T) {
	h := newHarness(t)
	l := &launchd{printsTil: 1 << 30, bootstrap: []error{errEIO, errEIO, errEIO}}
	l.install(h)
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if l.slept != 2*bootoutWait {
		t.Fatalf("slept %v, want exactly %v", l.slept, 2*bootoutWait)
	}
	if got := l.sequence(); strings.Count(got, "bootstrap") != 2 || strings.Count(got, "bootout") != 1 || !strings.HasSuffix(got, ",print,bootstrap") {
		t.Fatalf("calls %q: one bootout, two bootstraps each after a wait", got)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.agent.plist")
	if !strings.Contains(h.errb.String(), plist) || !strings.Contains(h.errb.String(), "Input/output error") {
		t.Fatalf("stderr %q should name %s and launchctl's error", h.errb, plist)
	}
}

// The wait polls the service install boots out (gui/<uid>/<label>, the
// test label when set), and bootstrap keeps its arguments; an agent that
// is gone at once costs no pause.
func TestInstallWaitPollsTheBootedOutService(t *testing.T) {
	h := newHarness(t)
	h.env["NAZAR_LAUNCH_LABEL"] = "dev.nazar.test.w1"
	var mu sync.Mutex
	var calls []string
	var slept time.Duration
	h.a.launchctl = func(args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, strings.Join(args, " "))
		if args[0] == "print" {
			return errors.New("launchctl print: exit status 113: Could not find service")
		}
		return nil
	}
	h.a.sleep = func(d time.Duration) { slept += d }
	if code := h.run("install", "--bin-dir", filepath.Join(h.home, "bin")); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", "dev.nazar.test.w1.plist")
	want := []string{
		"bootout gui/501/dev.nazar.test.w1",
		"print gui/501/dev.nazar.test.w1",
		"bootstrap gui/501 " + plist,
	}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("launchctl %q, want %q", calls, want)
	}
	if slept != 0 {
		t.Fatalf("slept %v for an agent that was already gone", slept)
	}
}

// uninstall is unchanged: it boots out and does not wait (a following
// install waits on its own).
func TestUninstallDoesNotWait(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(h.home, "bin")
	if code := h.run("install", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	l := &launchd{printsTil: 1 << 30}
	l.install(h)
	if code := h.run("uninstall", "--bin-dir", bin); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if got := l.sequence(); got != "bootout" || l.slept != 0 {
		t.Fatalf("uninstall: calls %q, slept %v", got, l.slept)
	}
}

func TestBootstrapEIO(t *testing.T) {
	for msg, want := range map[string]bool{
		errEIO.Error(): true,
		"launchctl bootstrap gui/501 p: exit status 5: Bootstrap failed: 5: Input/output error":    true,
		"launchctl bootstrap gui/501 p: exit status 37: Operation already in progress":             false,
		"launchctl bootstrap gui/501 p: exit status 125: Domain does not support specified action": false,
		"launchctl bootstrap gui/501 p: exit status 1: Bootstrap failed: 15: Unknown error":        false,
	} {
		if got := bootstrapEIO(errors.New(msg)); got != want {
			t.Errorf("bootstrapEIO(%q) = %v", msg, got)
		}
	}
}
