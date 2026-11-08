package fake

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// The fake's platform.Exec: OnProcessExec fires on every exec of
// the watched process with its record as of the exec; Environment is the
// startup environment the exec gave it, ErrUnreadable when the test says
// so or when none was given, never an empty list for "hidden".
func TestFakeExec(t *testing.T) {
	f := New(time.Now())
	var _ platform.Exec = f
	ref := f.Launch(platform.ProcessRef{}, Proc{Path: "/nazar", Args: []string{"nazar", "run"}})
	if _, err := f.Environment(ref); !errors.Is(err, platform.ErrUnreadable) {
		t.Fatalf("no environment given: %v", err)
	}
	var got []platform.ProcessInfo
	cancel, err := f.OnProcessExec(ref, func(p platform.ProcessInfo) { got = append(got, p) })
	if err != nil {
		t.Fatal(err)
	}
	f.Exec(ref, Proc{Path: "/bin/node", Args: []string{"node", "/s.js"}, Cwd: "/"}, []string{"A=1"})
	f.Exec(ref, Proc{Path: "/bin/sh", Args: []string{"sh"}, Cwd: "/"}, []string{"B=2"})
	if len(got) != 2 || got[0].Path != "/bin/node" || got[0].Ref != ref || got[1].Path != "/bin/sh" || got[0].Cwd != "/" {
		t.Fatalf("events %+v", got)
	}
	if env, err := f.Environment(ref); err != nil || !slices.Equal(env, []string{"B=2"}) {
		t.Fatalf("environment %q %v", env, err)
	}
	f.SetEnvironmentUnreadable(ref, true)
	if _, err := f.Environment(ref); !errors.Is(err, platform.ErrUnreadable) {
		t.Fatalf("unreadable: %v", err)
	}
	cancel()
	f.Exec(ref, Proc{Path: "/bin/x"}, nil)
	if len(got) != 2 {
		t.Fatal("no event after cancel")
	}
	f.Exit(ref)
	if _, err := f.OnProcessExec(ref, func(platform.ProcessInfo) {}); err == nil {
		t.Fatal("watching a process that is gone must fail")
	}
	if _, err := f.Environment(ref); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("gone: %v", err)
	}
}

// The environment is answered only while a watch is on, as on
// macOS, where it is read at the exec event: an exec no watch saw, and
// the last cancel, leave ErrUnreadable (never a stale list).
func TestFakeExecEnvironmentOnlyWhileWatched(t *testing.T) {
	f := New(time.Now())
	ref := f.Launch(platform.ProcessRef{}, Proc{Path: "/nazar"})
	f.Exec(ref, Proc{Path: "/bin/node", Cwd: "/"}, []string{"A=1"})
	if _, err := f.Environment(ref); !errors.Is(err, platform.ErrUnreadable) {
		t.Fatalf("an exec no watch saw: %v", err)
	}
	c1, _ := f.OnProcessExec(ref, func(platform.ProcessInfo) {})
	c2, _ := f.OnProcessExec(ref, func(platform.ProcessInfo) {})
	f.Exec(ref, Proc{Path: "/bin/node", Cwd: "/"}, []string{"A=2"})
	c1()
	if env, err := f.Environment(ref); err != nil || !slices.Equal(env, []string{"A=2"}) {
		t.Fatalf("one watch left: %q %v", env, err)
	}
	c2()
	c2() // twice is harmless
	if _, err := f.Environment(ref); !errors.Is(err, platform.ErrUnreadable) {
		t.Fatalf("after the last cancel: %v", err)
	}
}

// Environment never answers an exec's environment before every watcher
// saw that exec (platform.Exec), even from another goroutine while Exec
// is still calling them.
func TestExecSeenBeforeEnvironmentAnswers(t *testing.T) {
	f := New(time.Now())
	ref := f.Launch(platform.ProcessRef{}, Proc{Path: "/nazar"})
	started, release := make(chan struct{}), make(chan struct{})
	cancel, err := f.OnProcessExec(ref, func(platform.ProcessInfo) { close(started); <-release })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	go f.Exec(ref, Proc{Path: "/bin/node", Cwd: "/"}, []string{"A=1"})
	<-started
	got := make(chan error, 1)
	go func() { _, err := f.Environment(ref); got <- err }()
	select {
	case err := <-got:
		close(release)
		t.Fatalf("Environment answered (%v) while a watcher had not yet seen the exec", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-got; err != nil {
		t.Fatalf("Environment after the exec: %v", err)
	}
}

// ExecUnseen is an exec the platform has taken but not yet handed
// to the watchers (the Mac's kqueue event still queued): the process is the
// new image at once, and the watchers hear of it at the next Environment,
// before it answers, once.
func TestFakeExecUnseenReachesTheWatchersAtEnvironment(t *testing.T) {
	f := New(time.Now())
	ref := f.Launch(platform.ProcessRef{}, Proc{Path: "/nazar"})
	var got []string
	cancel, err := f.OnProcessExec(ref, func(p platform.ProcessInfo) { got = append(got, p.Path) })
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	f.ExecUnseen(ref, Proc{Path: "/bin/node", Cwd: "/"}, []string{"A=1"})
	if len(got) != 0 {
		t.Fatal("an unseen exec reached a watcher before Environment")
	}
	if p, _ := f.Process(ref); p.Path != "/bin/node" {
		t.Fatalf("the process is %q, want the new image at once", p.Path)
	}
	env, err := f.Environment(ref)
	if err != nil || !slices.Equal(env, []string{"A=1"}) || !slices.Equal(got, []string{"/bin/node"}) {
		t.Fatalf("environment %q %v, watchers saw %q", env, err, got)
	}
	f.Environment(ref)
	f.Exec(ref, Proc{Path: "/bin/sh", Cwd: "/"}, []string{"B=2"})
	if !slices.Equal(got, []string{"/bin/node", "/bin/sh"}) {
		t.Fatalf("watchers saw %q", got)
	}
}
