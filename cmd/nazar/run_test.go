package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/control"
)

// Secrets design 6.3 step 5, 6.3.5 and D3: `nazar run
// --secret NAME -- command…`. The CLI sends the command line and its own
// environment, gets the RunPlan back, checks the plan's files and folder
// with its own fstat, resets the process (fds, umask, core limit, signals)
// and execs exactly the plan. Everything after `--` is the command's, byte
// for byte; the value never passes through the CLI.

// fileOf is the identity the agent would send for p.
func fileOf(t *testing.T, p string) control.RunFile {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	return control.RunFile{Path: p, Dev: uint64(st.Dev), Ino: st.Ino, Size: st.Size, MtimeNs: st.Mtim.Nano(), CtimeNs: st.Ctim.Nano()}
}

func rootIdentity(t *testing.T) (uint64, uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat("/", &st); err != nil {
		t.Fatal(err)
	}
	return uint64(st.Dev), st.Ino
}

// runFixture is a node and a script, and the plan the agent would send
// for them.
type runFixture struct {
	node, srv string
	plan      control.RunPlan
	resets    int
}

func newRunFixture(t *testing.T, h *harness) *runFixture {
	t.Helper()
	f := &runFixture{node: filepath.Join(h.home, "bin", "node"), srv: filepath.Join(h.home, "srv", "server.js")}
	for _, p := range []string{f.node, f.srv} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x "+p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dev, ino := rootIdentity(t)
	f.plan = control.RunPlan{TypeMeta: control.Meta(control.KindRunPlan), ExecPath: f.node, ExecArgv: []string{f.node, f.srv},
		Env: []string{"PATH=/usr/bin", "HOME=/Users/u", "NODE_OPTIONS=--require \"/x/node/env.cjs\"", "NAZAR_SECRET_NAMES=API_KEY"},
		Cwd: "/", CwdDev: dev, CwdIno: ino, Files: []control.RunFile{fileOf(t, f.node), fileOf(t, f.srv)}}
	h.a.resetForExec = func(dirFD int) error {
		f.resets++
		var st unix.Stat_t
		if err := unix.Fstat(dirFD, &st); err != nil || st.Ino != ino {
			t.Errorf("the folder to change to is not /: %v", err)
		}
		return nil
	}
	return f
}

// serveRun answers secret.run with plan (or the Problem p).
func (h *harness) serveRun(t *testing.T, plan func() control.RunPlan, p *control.Problem) {
	t.Helper()
	h.serve(t, func(ctx context.Context, req control.Request, out control.Emitter) {
		if req.Command != control.CmdSecretRun {
			out.Emit(control.NewProblem(control.CodeUsage, "unexpected %s", req.Command))
			return
		}
		if p != nil {
			out.Emit(p)
			return
		}
		out.Emit(plan())
		<-ctx.Done() // the agent keeps the connection until the CLI execs
	})
}

func TestRunSendsTheCommandAndExecsThePlan(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.serveRun(t, func() control.RunPlan { return f.plan }, nil)
	code := h.run("run", "--secret", "API_KEY", "--", "npx", "-y", "@brave/brave-search-mcp-server", "--json", "--yes", "--")
	if code != control.ExitError || !strings.Contains(h.errb.String(), "stub exec") {
		t.Fatalf("exit %d, stderr %q", code, h.errb.String())
	}
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].Command != control.CmdSecretRun {
		t.Fatalf("requests %+v", reqs)
	}
	args := reqs[0].Args
	var argv, env []string
	if err := json.Unmarshal([]byte(args["argv"]), &argv); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(args["callerEnv"]), &env); err != nil {
		t.Fatal(err)
	}
	// Everything after `--` is the command's: -y, --json, --yes and a
	// second -- included.
	if !slices.Equal(argv, []string{"npx", "-y", "@brave/brave-search-mcp-server", "--json", "--yes", "--"}) {
		t.Fatalf("argv %q", argv)
	}
	if !slices.Equal(env, h.a.environ()) || args["name"] != "API_KEY" || len(args) != 3 {
		t.Fatalf("args %v", args)
	}
	if h.a.json {
		t.Fatal("a --json after -- is the command's, not nazar's")
	}
	want := append(append([]string{f.node}, f.plan.ExecArgv...), f.plan.Env...)
	if !slices.Equal(h.execed, want) {
		t.Fatalf("exec %q, want %q", h.execed, want)
	}
	if f.resets != 1 {
		t.Fatalf("%d resets before exec", f.resets)
	}
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{"run", "--secret", "API_KEY", "node", "x"},
		{"run", "--", "node", "x"},
		{"run", "--secret", "API_KEY", "--"},
		{"run", "--secret", "A", "--secret", "B", "--", "node", "x"},
		{"run", "--secret=", "--", "node", "x"},
		{"run", "--secret", "API_KEY", "extra", "--", "node", "x"},
		{"run", "--secret", "API_KEY", "--cwd", "/tmp", "--", "node", "x"},
	} {
		h := newHarness(t)
		newRunFixture(t, h)
		h.serveRun(t, func() control.RunPlan { t.Error("no request expected"); return control.RunPlan{} }, nil)
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%q: exit %d, want usage", args, code)
		}
		if len(h.requests()) != 0 || h.execed != nil {
			t.Errorf("%q: sent or exec'd", args)
		}
	}
}

func TestRunRefusalFromTheAgent(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.serveRun(t, nil, control.NewProblem(control.CodeRefused, "refused: to: mismatch"))
	if code := h.run("run", "--secret", "API_KEY", "--", "node", f.srv); code != control.ExitRefused {
		t.Fatalf("exit %d", code)
	}
	if h.execed != nil || f.resets != 0 || !strings.Contains(h.errb.String(), "to: mismatch") {
		t.Fatalf("exec %q, stderr %q", h.execed, h.errb.String())
	}
}

// The CLI execs nothing the agent did not pin: every file of the plan must
// be, by its own fstat, the file the agent saw, and the folder /.
func TestRunRefusesAPlanItCannotConfirm(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(t *testing.T, f *runFixture, p *control.RunPlan)
		msg  string
	}{
		{"a file rewritten", func(t *testing.T, f *runFixture, _ *control.RunPlan) {
			os.WriteFile(f.srv, []byte("evil() // longer than before"), 0o755)
		}, "server.js changed"},
		{"a file replaced", func(t *testing.T, f *runFixture, _ *control.RunPlan) {
			// renamed aside, not removed: a removed file's inode can come
			// back at once, with the same size and (coarse clock) times
			os.Rename(f.srv, f.srv+".old")
			os.WriteFile(f.srv, []byte("x "+f.srv), 0o755)
		}, "server.js changed"},
		{"a file now a symlink", func(t *testing.T, f *runFixture, _ *control.RunPlan) {
			os.Rename(f.srv, f.srv+".real")
			os.Symlink(f.srv+".real", f.srv)
		}, "server.js changed"},
		{"a file gone", func(t *testing.T, f *runFixture, _ *control.RunPlan) { os.Remove(f.node) }, "node changed"},
		{"a folder", func(t *testing.T, f *runFixture, p *control.RunPlan) {
			p.Files[1] = fileOf(t, filepath.Dir(f.srv))
		}, "srv changed"},
		{"the folder is not /", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.Cwd = "/tmp" }, "the plan"},
		{"/ is another folder", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.CwdIno++ }, "/ changed"},
		{"a relative image", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.ExecPath = "bin/node" }, "the plan"},
		{"an image not pinned", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.Files = p.Files[1:] }, "the plan"},
		{"no argv", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.ExecArgv = nil }, "the plan"},
		{"a variable without a name", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.Env = append(p.Env, "=x") }, "the plan"},
		{"a relative file", func(t *testing.T, _ *runFixture, p *control.RunPlan) { p.Files[1].Path = "srv/server.js" }, "the plan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			f := newRunFixture(t, h)
			plan := f.plan
			plan.Files = slices.Clone(plan.Files)
			tc.mod(t, f, &plan)
			h.serveRun(t, func() control.RunPlan { return plan }, nil)
			code := h.run("run", "--secret", "API_KEY", "--", "node", f.srv)
			if code != control.ExitError || h.execed != nil || f.resets != 0 {
				t.Fatalf("exit %d, exec %q, resets %d, stderr %q", code, h.execed, f.resets, h.errb.String())
			}
			if !strings.Contains(h.errb.String(), tc.msg) {
				t.Fatalf("stderr %q, want %q", h.errb.String(), tc.msg)
			}
		})
	}
}

// A CLI without the reset (nil) refuses rather than exec with the
// caller's process state.
func TestRunWithoutTheResetRefuses(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.a.resetForExec = nil
	h.serveRun(t, func() control.RunPlan { return f.plan }, nil)
	if code := h.run("run", "--secret", "API_KEY", "--", "node", f.srv); code != control.ExitError || h.execed != nil {
		t.Fatalf("exit %d, exec %q", code, h.execed)
	}
	if len(h.requests()) != 0 {
		t.Fatal("a CLI that can't exec must not ask the agent (a prompt for nothing)")
	}
}

// Cases a review found.

func TestRunUsageReview(t *testing.T) {
	h := newHarness(t)
	newRunFixture(t, h)
	h.serveRun(t, func() control.RunPlan { t.Error("no request expected"); return control.RunPlan{} }, nil)
	if code := h.run("run", "--secret", "bad name", "--", "node", "x"); code != control.ExitUsage || !strings.Contains(h.errb.String(), "run: invalid secret name") {
		t.Fatalf("exit %d, stderr %q", code, h.errb.String())
	}
	if len(h.requests()) != 0 {
		t.Fatal("sent")
	}
}

// An environment too large to send is refused before anything is sent,
// with a message that says so; variables nazar never passes on are not
// sent at all.
func TestRunCallerEnvironment(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.serveRun(t, func() control.RunPlan { return f.plan }, nil)
	h.a.environ = func() []string {
		return []string{"PATH=/usr/bin", "LANG=en_US.UTF-8", "HTTPS_PROXY=http://p:1", "NODE_OPTIONS=--require /tmp/x.cjs", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib", "SSH_AUTH_SOCK=/tmp/a"}
	}
	h.run("run", "--secret", "API_KEY", "--", "node", f.srv)
	var env []string
	json.Unmarshal([]byte(h.requests()[0].Args["callerEnv"]), &env)
	for _, kv := range env {
		if strings.HasPrefix(kv, "NODE_OPTIONS=") || strings.HasPrefix(kv, "DYLD_") {
			t.Errorf("sent %q, which nazar never passes on", kv)
		}
	}
	if !slices.Contains(env, "HTTPS_PROXY=http://p:1") || !slices.Contains(env, "LANG=en_US.UTF-8") {
		t.Errorf("env %q", env)
	}

	h2 := newHarness(t)
	f2 := newRunFixture(t, h2)
	h2.serveRun(t, func() control.RunPlan { return f2.plan }, nil)
	h2.a.environ = func() []string { return []string{"BIG=" + strings.Repeat("x", 200*1024)} }
	if code := h2.run("run", "--secret", "API_KEY", "--", "node", f2.srv); code != control.ExitError || !strings.Contains(h2.errb.String(), "environment") {
		t.Fatalf("exit %d, stderr %q", code, h2.errb.String())
	}
	if len(h2.requests()) != 0 {
		t.Fatal("a request that can't fit was sent")
	}
}

// --json: a refusal is one Problem object on stdout, nothing on stderr.
func TestRunJSONProblem(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.serveRun(t, nil, control.NewProblem(control.CodeRefused, "refused: to: mismatch"))
	h.out.Reset()
	h.errb.Reset()
	if code := h.a.run([]string{"--json", "run", "--secret", "API_KEY", "--", "node", f.srv}); code != control.ExitRefused {
		t.Fatalf("exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindProblem || h.errb.Len() != 0 {
		t.Fatalf("stdout %q, stderr %q", h.out.String(), h.errb.String())
	}
}

// A reply of another kind, or none, runs nothing.
func TestRunNoPlan(t *testing.T) {
	for name, fn := range map[string]handlerFunc{
		"another kind": func(_ context.Context, _ control.Request, out control.Emitter) {
			out.Emit(control.SecretValue{TypeMeta: control.Meta(control.KindSecretValue), Name: "API_KEY"})
		},
		"no reply": func(context.Context, control.Request, control.Emitter) {},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			f := newRunFixture(t, h)
			h.serve(t, fn)
			if code := h.run("run", "--secret", "API_KEY", "--", "node", f.srv); code != control.ExitError || h.execed != nil || f.resets != 0 {
				t.Fatalf("exit %d, exec %q, resets %d", code, h.execed, f.resets)
			}
		})
	}
}

// A pinned path that is now a device is never opened as one.
func TestRunPlanFileIsADevice(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	plan := f.plan
	plan.Files = []control.RunFile{plan.Files[0], fileOf(t, "/dev/null")}
	h.serveRun(t, func() control.RunPlan { return plan }, nil)
	if code := h.run("run", "--secret", "API_KEY", "--", "node", f.srv); code != control.ExitError || h.execed != nil || !strings.Contains(h.errb.String(), "null changed") {
		t.Fatalf("exit %d, stderr %q", code, h.errb.String())
	}
}
