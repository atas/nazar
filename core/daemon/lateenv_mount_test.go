package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The mount watch (D12): a volume mounted over a folder hides what the
// folder holds without changing a single pin, so a loader or a script put
// in front of the pinned one for a moment and taken away again would be
// served with every pin matching. Any mount or unmount on the Mac from
// before the pins are taken to the write refuses the run (decision=denied,
// the approval dropped); no watch outlives its run.

const mountedReason = "receiver changed at exec: a volume was mounted or unmounted"

func TestRunVolumeMountedDuringTheRunIsNeverServed(t *testing.T) {
	refused := func(t *testing.T, r *runEnv, cli platform.ProcessRef, plan control.RunPlan) {
		t.Helper()
		if got := r.connect(t, plan, cli); got != "" && !strings.HasPrefix(got, "dial:") {
			t.Fatalf("served after a mount: %d bytes", len(got))
		}
		if f := r.lastAudit(t, audit.Denied); f["reason"] != mountedReason {
			t.Fatalf("audit %v", f)
		}
		waitFor(t, func() bool { return r.f.MountWatches() == 0 })
	}
	t.Run("while the dialog is open", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		open := make(chan struct{})
		r.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true, Wait: open})
		cli := r.asCLI(cliProc("run"))
		type result struct {
			plan control.RunPlan
			p    *control.Problem
		}
		done := make(chan result, 1)
		go func() {
			plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
			done <- result{plan, p}
		}()
		waitFor(t, func() bool { return r.f.CountShown(fake.KindConfirm) == 1 })
		r.f.MountChange()
		close(open)
		res := <-done
		if res.p != nil {
			t.Fatal(res.p)
		}
		r.execAs(t, cli, res.plan, nil)
		refused(t, r, cli, res.plan)
	})
	t.Run("between the plan and the exec", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		cli, plan := r.runNode(t)
		r.f.MountChange()
		r.execAs(t, cli, plan, nil)
		refused(t, r, cli, plan)
	})
	t.Run("between the exec check and the connection", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		cli, plan := r.runNode(t)
		r.serving(t, cli, plan)
		r.f.MountChange()
		refused(t, r, cli, plan)
	})
	t.Run("no mount: served, and the watch ends with the run", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		cli, plan := r.runNode(t)
		r.execAs(t, cli, plan, nil)
		if got := r.connect(t, plan, cli); got != wantLine() {
			t.Fatalf("got %d bytes, want the line", len(got))
		}
		waitFor(t, func() bool { return r.f.MountWatches() == 0 })
	})
	t.Run("a refusal before the prompt ends the watch too", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		r.asCLI(cliProc("run"))
		if _, p := r.run(t, []string{"node", "-e", "1"}, nil, nil); p == nil {
			t.Fatal("a command line to: does not name was not refused")
		}
		waitFor(t, func() bool { return r.f.MountWatches() == 0 })
	})
}

// Without the seam, or when no watch can be made, late-env is refused
// before any prompt, as without Exec.
func TestRunWithoutAMountWatchIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(f *fake.Fake, o *Options)
		msg  string
	}{
		{"no mount seam", func(_ *fake.Fake, o *Options) { o.Mounts = nil }, "late-env is not available"},
		{"the watch fails", func(f *fake.Fake, _ *Options) { f.MountsErr = errors.New("no kqueue") }, "volumes can't be watched"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startRun(t, tc.mod)
			r.ready(t, itermRule)
			r.asCLI(cliProc("run"))
			_, p := r.run(t, []string{"node", r.srv}, nil, nil)
			if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, tc.msg) {
				t.Fatalf("problem %+v, want %q", p, tc.msg)
			}
			if n := r.f.CountShown(fake.KindConfirm); n != 0 {
				t.Fatalf("%d dialogs", n)
			}
		})
	}
}

// npxRun asks for the npx run, execs its plan, waits until the agent
// serves (a process outside the run was refused), and returns the CLI, the
// plan and a bin of the target below it, ready to connect.
func (r *runEnv) npxRun(t *testing.T) (platform.ProcessRef, control.RunPlan, platform.ProcessRef) {
	t.Helper()
	cli := r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"npx", "-y", "@brave/brave-search-mcp-server"}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.serving(t, cli, plan)
	pkg := filepath.Join(r.root, "npm/_npx/abc/node_modules/@brave/brave-search-mcp-server")
	do(t, os.MkdirAll(filepath.Join(pkg, "dist"), 0o755))
	do(t, os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"@brave/brave-search-mcp-server","bin":{"b":"dist/index.js"}}`), 0o644))
	do(t, os.WriteFile(filepath.Join(pkg, "dist/index.js"), []byte("x"), 0o644))
	sh := r.f.Launch(cli, fake.Proc{Path: "/bin/sh", Args: []string{"sh", "-c", "b"}})
	return cli, plan, r.f.Launch(sh, fake.Proc{Path: r.node, Args: []string{"node", filepath.Join(pkg, "dist/index.js")}})
}

// againAs is a second exec of the run's own image and plan: only the count
// can tell it from the first.
func (r *runEnv) againAs(t *testing.T, plan control.RunPlan) fake.Proc {
	return fake.Proc{Path: plan.ExecPath, Args: plan.ExecArgv, Cwd: "/", Code: platform.CodeIdentity{AdHoc: true, CDHash: r.codeOf(t, plan.ExecPath)}}
}

// (a) An exec of the CLI's process that the platform has taken but not yet
// handed to the agent (the Mac's kqueue event still queued) is counted
// before a connection is judged: a bin below an npx that exec'd again is
// not served.
func TestRunQueuedSecondExecIsCountedBeforeServing(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli, plan, target := r.npxRun(t)
	r.f.ExecUnseen(cli, r.againAs(t, plan), plan.Env)
	if got := r.connect(t, plan, target); got != "" {
		t.Fatalf("served after a second exec: %d bytes", len(got))
	}
	if f := r.lastAudit(t, audit.Denied); f["reason"] != "receiver changed at exec: it exec'd again" {
		t.Fatalf("audit %v", f)
	}
}

// (a) An exec while the agent judges the peer and re-reads the pins is
// counted right before the write.
func TestRunSecondExecWhileThePeerIsJudged(t *testing.T) {
	var hook atomic.Pointer[func()]
	r := startRun(t, func(f *fake.Fake, _ *Options) {
		hash := f.CodeHashFunc
		f.CodeHashFunc = func(p string) ([]byte, error) {
			if h := hook.Swap(nil); h != nil {
				(*h)()
			}
			return hash(p)
		}
	})
	r.ready(t, itermRule)
	cli, plan, target := r.npxRun(t)
	again := func() { r.f.ExecUnseen(cli, r.againAs(t, plan), plan.Env) }
	hook.Store(&again) // runs inside the re-check before the write
	if got := r.connect(t, plan, target); got != "" {
		t.Fatalf("served after an exec during the check: %d bytes", len(got))
	}
	if hook.Load() != nil {
		t.Fatal("the hook never ran: the test did not reach the re-check")
	}
	if f := r.lastAudit(t, audit.Denied); f["reason"] != "receiver changed at exec: it exec'd again" {
		t.Fatalf("audit %v", f)
	}
}
