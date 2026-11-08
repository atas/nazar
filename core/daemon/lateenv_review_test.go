package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/envpolicy"
)

// Cases the code reviews of the late-env handover added.

// dialAs opens a connection to the run's socket that the agent will see
// as from ref (the fake reads the default peer when it accepts).
func (r *runEnv) dialAs(t *testing.T, plan control.RunPlan, ref platform.ProcessRef) net.Conn {
	t.Helper()
	r.f.SetDefaultPeer(ref)
	c, err := net.Dial("unix", envVal(plan.Env, "NAZAR_SECRET_SOCK"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readAll(c net.Conn) string {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

// auditCount counts audit lines that contain every part.
func (r *runEnv) auditCount(parts ...string) int {
	n := 0
	for _, l := range r.sink.Lines() {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			n++
		}
	}
	return n
}

// serving execs plan in cli and returns once the agent is serving: a
// process outside the run connected and was refused.
func (r *runEnv) serving(t *testing.T, cli platform.ProcessRef, plan control.RunPlan) {
	t.Helper()
	r.execAs(t, cli, plan, nil)
	other := r.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/x/evil"})
	if got := r.connect(t, plan, other); got != "" {
		t.Fatalf("another process got %q", got)
	}
	waitFor(t, func() bool { return r.auditCount("unexpected socket peer") > 0 })
}

func (r *runEnv) runNode(t *testing.T) (platform.ProcessRef, control.RunPlan) {
	t.Helper()
	cli := r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	return cli, plan
}

// Connections made before the exec wait; each is judged only after the
// exec check, by who it is.
func TestRunConnectionsBeforeTheExec(t *testing.T) {
	t.Run("another process queued first", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		cli, plan := r.runNode(t)
		other := r.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/x/evil"})
		queued := r.dialAs(t, plan, other)
		time.Sleep(50 * time.Millisecond)
		r.execAs(t, cli, plan, nil)
		if got := readAll(queued); got != "" {
			t.Fatalf("a connection queued before the exec got %q", got)
		}
		if got := r.connect(t, plan, cli); got != wantLine() {
			t.Fatalf("the exec'd process got %q", got)
		}
	})
	t.Run("the run's own pid, then a bad exec", func(t *testing.T) {
		r := startRun(t, nil)
		r.ready(t, itermRule)
		cli, plan := r.runNode(t)
		early := r.dialAs(t, plan, cli)
		time.Sleep(50 * time.Millisecond)
		r.execAs(t, cli, plan, func(_ *fake.Proc, env *[]string) { *env = append(*env, "EXTRA=1") })
		if got := readAll(early); got != "" {
			t.Fatalf("nothing is answered after a bad exec, got %q", got)
		}
		if f := r.lastAudit(t, audit.Denied); f["reason"] != "unexpected environment: EXTRA" {
			t.Fatalf("audit %v", f)
		}
	})
}

// The pinned files are checked again right before the write (secrets design
// 6.3.3 b): a script swapped after the exec check, while the interpreter
// starts and its loader connects, is never served.
func TestRunScriptSwappedAfterTheExecCheck(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.serving(t, cli, plan)
	if err := os.WriteFile(r.srv, []byte("evil()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := r.connect(t, plan, cli); got != "" {
		t.Fatalf("a swapped script was served: %q", got)
	}
	if f := r.lastAudit(t, audit.Denied); f["reason"] != "receiver changed at exec: server.js changed" {
		t.Fatalf("audit %v", f)
	}
}

// A FIFO as the target's package.json never blocks the agent: the
// deadline still ends the run, and the agent still stops.
func TestRunFIFOPackageJSONDoesNotHang(t *testing.T) {
	r := startRun(t, func(_ *fake.Fake, o *Options) { o.RunHandoverTimeout = time.Second })
	r.ready(t, itermRule)
	cli := r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"npx", "-y", "@brave/brave-search-mcp-server"}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli, plan, nil)
	pkg := filepath.Join(r.root, "npm/_npx/abc/node_modules/@brave/brave-search-mcp-server")
	os.MkdirAll(filepath.Join(pkg, "dist"), 0o755)
	os.WriteFile(filepath.Join(pkg, "dist/index.js"), []byte("x"), 0o644)
	if err := syscall.Mkfifo(filepath.Join(pkg, "package.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := r.f.Launch(cli, fake.Proc{Path: r.node, Args: []string{"node", filepath.Join(pkg, "dist/index.js")}})
	if got := r.connect(t, plan, target); got != "" {
		t.Fatalf("got %q", got)
	}
	waitFor(t, func() bool { return r.auditCount(`reason="target never connected"`) == 1 })
	stopped := make(chan struct{})
	go func() { r.halt(); close(stopped) }()
	select {
	case <-stopped:
		r.halt = nil
	case <-time.After(3 * time.Second):
		t.Fatal("the agent does not stop")
	}
}

// An interpreter's peer is read again when it connects: an image a missed
// or late exec event put in its place is refused (macOS delivers exec
// events asynchronously).
func TestRunInterpreterPeerIsReadAtConnect(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.serving(t, cli, plan)
	info, err := r.f.Process(cli)
	if err != nil {
		t.Fatal(err)
	}
	info.Path, info.Args, info.Code = "/bin/sh", []string{"sh"}, platform.CodeIdentity{CDHash: []byte{9}}
	r.f.SetProcess(info) // no exec event
	if got := r.connect(t, plan, cli); got != "" {
		t.Fatalf("another image in the run's pid got %q", got)
	}
}

// A second exec while the agent is serving ends the run.
func TestRunSecondExecWhileServing(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.serving(t, cli, plan)
	r.f.Exec(cli, fake.Proc{Path: r.node, Args: plan.ExecArgv, Cwd: "/", Code: platform.CodeIdentity{CDHash: r.codeOf(t, r.node)}}, plan.Env)
	if f := r.lastAudit(t, audit.Denied); f["reason"] != "receiver changed at exec: it exec'd again" {
		t.Fatalf("audit %v", f)
	}
	if got := r.connect(t, plan, cli); got != "" && !strings.HasPrefix(got, "dial:") {
		t.Fatalf("got %q", got)
	}
}

// A child of the exec'd interpreter is not the receiver.
func TestRunChildOfTheInterpreterIsRefused(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.execAs(t, cli, plan, nil)
	child := r.f.Launch(cli, fake.Proc{Path: r.node, Args: []string{"node", r.srv}})
	if got := r.connect(t, plan, child); got != "" {
		t.Fatalf("a child got %q", got)
	}
	if got := r.connect(t, plan, cli); got != wantLine() {
		t.Fatalf("the exec'd process got %q", got)
	}
}

// The process exits after a good exec without connecting: the run ends
// then, not at the deadline, and the socket goes.
func TestRunExitAfterTheExec(t *testing.T) {
	r := startRun(t, func(_ *fake.Fake, o *Options) { o.RunHandoverTimeout = time.Minute })
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.execAs(t, cli, plan, nil)
	r.f.Exit(cli)
	waitFor(t, func() bool { return r.auditCount(`reason="target never connected"`) == 1 })
	waitFor(t, func() bool {
		_, err := os.Stat(envVal(plan.Env, "NAZAR_SECRET_SOCK"))
		return errors.Is(err, os.ErrNotExist)
	})
}

// The agent stopping ends a waiting handover at once.
func TestRunAgentStopping(t *testing.T) {
	r := startRun(t, func(_ *fake.Fake, o *Options) { o.RunHandoverTimeout = time.Minute })
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.execAs(t, cli, plan, nil)
	stopped := make(chan struct{})
	go func() { r.halt(); close(stopped) }()
	select {
	case <-stopped:
		r.halt = nil
	case <-time.After(3 * time.Second):
		t.Fatal("the agent does not stop while a handover waits")
	}
	if r.auditCount(`reason="nazar-agent stopped"`) != 1 {
		t.Fatalf("audit:\n%s", strings.Join(r.sink.Lines(), "\n"))
	}
	if _, err := os.Stat(envVal(plan.Env, "NAZAR_SECRET_SOCK")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the socket must be removed")
	}
}

// After a run refused at the exec, the next run of the same command asks
// again: the approval went with the refusal.
func TestRunDeniedAtExecAsksAgain(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	tab := r.f.ITermTab(platform.ProcessRef{}, cliProc("run"))
	cli := tab.Peer()
	r.f.SetDefaultPeer(cli)
	plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli, plan, func(_ *fake.Proc, env *[]string) { *env = append(*env, "EXTRA=1") })
	r.lastAudit(t, audit.Denied)
	cli2 := r.f.Launch(tab.Shell, cliProc("run"))
	r.f.SetDefaultPeer(cli2)
	plan2, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli2, plan2, nil)
	if got := r.connect(t, plan2, cli2); got != wantLine() {
		t.Fatalf("got %q", got)
	}
	if n := r.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("%d dialogs: a run refused at exec must not leave its approval behind", n)
	}
}

// A tightening applied while the dialog is open reaches the run: the plan
// built from the config before it is not run.
func TestRunConfigChangedDuringThePrompt(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	open := make(chan struct{})
	r.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true, Wait: open})
	r.asCLI(cliProc("run"))
	type result struct {
		plan control.RunPlan
		p    *control.Problem
	}
	done := make(chan result, 1)
	go func() {
		plan, p := r.run(t, []string{"node", r.srv}, []string{"HTTPS_PROXY=http://proxy:8080"}, nil)
		done <- result{plan, p}
	}()
	waitFor(t, func() bool { return r.f.CountShown(fake.KindConfirm) == 1 })
	tighter := strings.Replace(r.config(itermRule), "    envAllow: [HTTPS_PROXY]\n", "", 1)
	r.writeConfig(t, tighter)
	waitFor(t, func() bool { return string(r.d.stager.Active().Raw) == tighter })
	close(open)
	res := <-done
	if res.p == nil || !strings.Contains(res.p.Message, "config") {
		t.Fatalf("a plan from the old config: %+v %+v", res.plan, res.p)
	}
}

// Refused peers are logged once per pid, at most runMaxPeerLines of them,
// then one line with the count; each line is the run's (delivery,
// operation).
func TestRunRefusedPeerLinesAreCapped(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli, plan := r.runNode(t)
	r.execAs(t, cli, plan, nil)
	for i := 0; i < runMaxPeerLines+4; i++ {
		other := r.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/x/evil"})
		r.connect(t, plan, other)
		r.connect(t, plan, other)
	}
	if got := r.connect(t, plan, cli); got != wantLine() {
		t.Fatalf("got %q", got)
	}
	r.lastAudit(t, audit.Approved)
	waitFor(t, func() bool { return r.auditCount("4 more") == 1 })
	if n := r.auditCount(`reason="unexpected socket peer"`, "delivery=late-env", `operation="nazar run"`); n != runMaxPeerLines {
		t.Fatalf("%d refused-peer lines:\n%s", n, strings.Join(r.sink.Lines(), "\n"))
	}
}

// A Python receiver gets PYTHONPATH and no Node or npx variable.
func TestRunPythonPlan(t *testing.T) {
	r := startRun(t, nil)
	py := filepath.Join(r.bin, "python3")
	os.WriteFile(py, []byte(elfNode+" python"), 0o755)
	app := filepath.Join(r.root, "srv/app.py")
	os.WriteFile(app, []byte("print(1)\n"), 0o644)
	cfg := strings.Replace(r.config(strings.Replace(itermRule, "to: [srv, brave-mcp]", "to: [py]", 1)),
		"apps:\n", "apps:\n  py: {command: [python3, "+fmt.Sprintf("%q", app)+"]}\n", 1)
	r.approved(t, cfg)
	if _, err := r.d.secrets.Add("API_KEY", []byte(testValue), platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	r.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"python3", app}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	if envVal(plan.Env, "PYTHONPATH") != filepath.Join(r.loaders, "python") {
		t.Fatalf("env %q", plan.Env)
	}
	for _, k := range envpolicy.Names(plan.Env) {
		if k == "NODE_OPTIONS" || k == "NAZAR_TARGET" {
			t.Fatalf("env %q", plan.Env)
		}
	}
}

// Refusals before any prompt, of the request or of the agent's own setup.
func TestRunRefusedBeforeAnyPromptReview(t *testing.T) {
	sym := func(o *Options) string {
		d := filepath.Join(filepath.Dir(o.LoaderDir), "loaders-link")
		os.Symlink(o.LoaderDir, d)
		return d
	}
	for _, tc := range []struct {
		name string
		mod  func(f *fake.Fake, o *Options)
		args map[string]string
		code string
		msg  string
	}{
		{name: "a relative loader folder", mod: func(_ *fake.Fake, o *Options) { o.LoaderDir = "loaders" }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "a symlinked loader folder", mod: func(_ *fake.Fake, o *Options) { o.LoaderDir = sym(o) }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "a quote in the loader folder", mod: func(_ *fake.Fake, o *Options) { o.LoaderDir += `"x` }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "a colon in the loader folder", mod: func(_ *fake.Fake, o *Options) { o.LoaderDir += ":x" }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "a control character in the loader folder", mod: func(_ *fake.Fake, o *Options) { o.LoaderDir += "\x1b" }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "the Node loader missing", mod: func(_ *fake.Fake, o *Options) { os.Remove(filepath.Join(o.LoaderDir, "node", "env.cjs")) }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "no host", mod: func(_ *fake.Fake, o *Options) {
			o.RunHost = func(int) (envpolicy.Host, error) { return envpolicy.Host{}, errors.New("no") }
		}, code: control.CodeRefused, msg: "home folder"},
		{name: "the exec watch fails", mod: func(f *fake.Fake, o *Options) { o.Exec = noWatch{f} }, code: control.CodeError, msg: "could not be watched"},
		{name: "an unknown argument", args: map[string]string{"loader": "/tmp/x"}, code: control.CodeUsage, msg: "unknown argument"},
		{name: "cwd beside an unknown argument", args: map[string]string{"cwd": "/", "zz": "1"}, code: control.CodeUsage, msg: "no cwd"},
		{name: "argv not a list", args: map[string]string{"argv": `"node"`}, code: control.CodeUsage, msg: "argv"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startRun(t, tc.mod)
			r.ready(t, itermRule)
			r.asCLI(cliProc("run"))
			_, p := r.run(t, []string{"node", r.srv}, nil, tc.args)
			if p == nil || p.Code != tc.code || !strings.Contains(p.Message, tc.msg) {
				t.Fatalf("problem %+v, want %s %q", p, tc.code, tc.msg)
			}
			if tc.code != control.CodeError && r.f.CountShown(fake.KindConfirm) != 0 {
				t.Fatal("asked before refusing")
			}
		})
	}
}

// noWatch is an exec seam that cannot watch the CLI.
type noWatch struct{ platform.Exec }

func (noWatch) OnProcessExec(platform.ProcessRef, func(platform.ProcessInfo)) (func(), error) {
	return nil, errors.New("no watch")
}

func TestRunSocketPathTooLong(t *testing.T) {
	d := &Daemon{o: Options{Home: "/" + strings.Repeat("h", 80)}}
	if _, err := d.runSocket(); err == nil {
		t.Fatal("a socket path over 103 bytes must be refused")
	}
}

// Sockets a stopped agent left behind are removed when it starts again.
func TestRunStaleSocketsSwept(t *testing.T) {
	r := startRun(t, nil)
	dir := layout.RunDir(r.home)
	os.MkdirAll(dir, 0o700)
	stale := filepath.Join(dir, strings.Repeat("ab", 16)+".sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	l.SetUnlinkOnClose(false)
	l.Close()
	keep := filepath.Join(dir, "notes.txt")
	os.WriteFile(keep, []byte("x"), 0o600)
	r.halt()
	r.launch(t)
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a stale run socket was left")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("only run sockets are removed")
	}
}

var (
	_ = context.Background
	_ = json.Marshal
	_ = slices.Contains[[]string]
)
