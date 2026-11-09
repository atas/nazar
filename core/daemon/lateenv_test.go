package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/envpolicy"
	"github.com/atas/nazar/loaders"
)

// Secrets design 6.3, 6.3.2–6.3.4, 7.3 (D1, D2, D8–D10):
// secret.run on the fake platform. The agent resolves the command line,
// builds the receiver's environment, asks, replies with the RunPlan, and
// hands the value over the per-run socket only after it saw the CLI's exec
// and found the exec'd process to be exactly the plan; then only to the
// exec'd process itself (an interpreter) or to a bin of the target package
// below it (npx). Everything else is refused, and the value never appears
// in a plan, a Problem or an audit line.

type runEnv struct {
	*env
	root, bin, node, srv, npxCLI, loaders string
}

const elfNode = "\x7fELF fake node for the daemon tests"

func startRun(t *testing.T, mod func(f *fake.Fake, o *Options)) *runEnv {
	t.Helper()
	tmp := func() string {
		d, err := os.MkdirTemp("/tmp", "nzr")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(d) })
		if d, err = filepath.EvalSymlinks(d); err != nil { // /tmp is a symlink on macOS
			t.Fatal(err)
		}
		return d
	}
	// The loaders in a folder of their own, as in the agent's bundle: the
	// agent pins the folders above them, and the test writes npx's cache
	// into root during a run.
	root := tmp()
	r := &runEnv{root: root, bin: filepath.Join(root, "bin"), loaders: filepath.Join(tmp(), "loaders")}
	mk := func(p, body string, mode os.FileMode) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r.node = mk(filepath.Join(r.bin, "node"), elfNode, 0o755)
	mk(filepath.Join(r.loaders, "node", "env.cjs"), loaders.Node, 0o644)
	mk(filepath.Join(r.loaders, "python", "sitecustomize.py"), loaders.Python, 0o644)
	r.srv = mk(filepath.Join(root, "srv/server.js"), "console.log(1)\n", 0o644)
	r.npxCLI = mk(filepath.Join(root, "lib/node_modules/npm/bin/npx-cli.js"), "#!/usr/bin/env node\nrequire('../lib/cli.js')\n", 0o755)
	if err := os.Symlink(r.npxCLI, filepath.Join(r.bin, "npx")); err != nil {
		t.Fatal(err)
	}
	r.env = startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		o.Exec, o.Mounts = f, f
		o.LoaderDir = r.loaders
		o.RunHost = func(uid int) (envpolicy.Host, error) {
			return envpolicy.Host{Home: "/Users/u", User: "u", TmpDir: "/var/folders/x/T/"}, nil
		}
		o.RunExecTimeout = 5 * time.Second
		o.RunHandoverTimeout = 5 * time.Second
		if mod != nil {
			mod(f, o)
		}
	})
	return r
}

func (r *runEnv) config(rules string) string {
	return "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n" +
		"  srv: {command: [node, " + strconv.Quote(r.srv) + "]}\n" +
		"  brave-mcp: {command: [npx, -y, \"@brave/brave-search-mcp-server\"]}\n" +
		"defaults:\n  trustedPath: [" + strconv.Quote(r.bin) + "]\n" +
		"secrets:\n  API_KEY:\n    deliver: [late-env]\n    envAllow: [HTTPS_PROXY]\n    rules:\n" + rules
}

const itermRule = "      - apps: [iterm]\n        to: [srv, brave-mcp]\n        scope: session\n        gate: dialog\n"

// ready approves the config and stores the secret.
func (r *runEnv) ready(t *testing.T, rules string) {
	t.Helper()
	r.approved(t, r.config(rules))
	if _, err := r.d.secrets.Add("API_KEY", []byte(testValue), platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	r.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
}

var errGotPlan = errors.New("got the plan")

// run sends secret.run as the CLI would and returns the plan (or the
// Problem) without waiting for the connection to end: the CLI execs.
func (r *runEnv) run(t *testing.T, argv []string, callerEnv []string, extra map[string]string) (control.RunPlan, *control.Problem) {
	t.Helper()
	a, _ := json.Marshal(argv)
	ce, _ := json.Marshal(callerEnv)
	args := map[string]string{"name": "API_KEY", "argv": string(a), "callerEnv": string(ce)}
	for k, v := range extra {
		args[k] = v
	}
	var plan control.RunPlan
	err := r.c.Do(context.Background(), control.NewRequest(control.CmdSecretRun, args), func(kind string, raw json.RawMessage) error {
		if strings.Contains(string(raw), testValue) || strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte(testValue))) {
			t.Errorf("a reply carries the value")
		}
		if kind != control.KindRunPlan {
			return errors.New("unexpected " + kind)
		}
		if err := json.Unmarshal(raw, &plan); err != nil {
			return err
		}
		return errGotPlan
	})
	if errors.Is(err, errGotPlan) {
		return plan, nil
	}
	if err == nil {
		t.Fatal("no plan and no problem")
	}
	return plan, control.AsProblem(err)
}

func envVal(env []string, name string) string {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == name {
			return v
		}
	}
	return ""
}

func (r *runEnv) codeOf(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return s[:20]
}

// execAs is the CLI's execve as the platform sees it.
func (r *runEnv) execAs(t *testing.T, cli platform.ProcessRef, plan control.RunPlan, mod func(p *fake.Proc, env *[]string)) {
	t.Helper()
	p := fake.Proc{Path: plan.ExecPath, Args: plan.ExecArgv, Cwd: plan.Cwd, Code: platform.CodeIdentity{AdHoc: true, CDHash: r.codeOf(t, plan.ExecPath)}}
	env := slices.Clone(plan.Env)
	if mod != nil {
		mod(&p, &env)
	}
	r.f.Exec(cli, p, env)
}

// connect is a loader connecting from ref; it returns what it read.
func (r *runEnv) connect(t *testing.T, plan control.RunPlan, ref platform.ProcessRef) string {
	t.Helper()
	r.f.SetDefaultPeer(ref)
	c, err := net.Dial("unix", envVal(plan.Env, "NAZAR_SECRET_SOCK"))
	if err != nil {
		return "dial: " + err.Error()
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

func wantLine() string {
	return "API_KEY\t" + base64.StdEncoding.EncodeToString([]byte(testValue)) + "\n"
}

// lastAudit waits for an audit line about the secret and parses the last.
func (r *runEnv) lastAudit(t *testing.T, want audit.Decision) map[string]string {
	t.Helper()
	var f map[string]string
	waitFor(t, func() bool {
		lines := r.sink.Lines()
		for i := len(lines) - 1; i >= 0; i-- {
			m, err := audit.ParseLine(lines[i])
			if err == nil && m["target"] == "secret:API_KEY" && m["decision"] == string(want) {
				f = m
				return true
			}
		}
		return false
	})
	for _, l := range r.sink.Lines() {
		if strings.Contains(l, testValue) || strings.Contains(l, base64.StdEncoding.EncodeToString([]byte(testValue))) {
			t.Fatal("an audit line carries the value")
		}
	}
	return f
}

func TestRunHandsTheValueToTheExecdInterpreterOnly(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	tab := r.f.ITermTab(platform.ProcessRef{}, cliProc("run", "--secret", "API_KEY", "--", "node", r.srv))
	r.f.SetDefaultPeer(tab.Peer())
	cli := tab.Peer()
	caller := []string{"HTTPS_PROXY=http://proxy:8080", "NODE_OPTIONS=--require /tmp/evil.cjs", "PATH=/tmp/x:/usr/bin", "HOME=/tmp/h", "FOO=bar", "LANG=en_US.UTF-8"}
	plan, p := r.run(t, []string{"node", r.srv}, caller, nil)
	if p != nil {
		t.Fatal(p)
	}
	if plan.ExecPath != r.node || !slices.Equal(plan.ExecArgv, []string{r.node, r.srv}) || plan.Cwd != "/" {
		t.Fatalf("plan %+v", plan)
	}
	sock := envVal(plan.Env, "NAZAR_SECRET_SOCK")
	want := map[string]string{
		"PATH": r.bin, "HOME": "/Users/u", "USER": "u", "LOGNAME": "u", "TMPDIR": "/var/folders/x/T/", "LANG": "en_US.UTF-8",
		"HTTPS_PROXY": "http://proxy:8080", "NODE_OPTIONS": "--disable-sigusr1 --require " + strconv.Quote(filepath.Join(r.loaders, "node", "env.cjs")),
		"NAZAR_SECRET_NAMES": "API_KEY", "NAZAR_RUN_PID": strconv.Itoa(cli.PID), "NAZAR_SECRET_SOCK": sock,
	}
	if len(plan.Env) != len(want) {
		t.Fatalf("env %q", plan.Env)
	}
	for k, v := range want {
		if envVal(plan.Env, k) != v {
			t.Errorf("%s = %q, want %q", k, envVal(plan.Env, k), v)
		}
	}
	if filepath.Dir(sock) != layout.RunDir(r.home) || len(sock) > 103 {
		t.Fatalf("socket %q", sock)
	}
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	if len(plan.Files) != 2 || plan.Files[0].Path != r.node || plan.Files[1].Path != r.srv || plan.Files[0].Ino == 0 {
		t.Fatalf("files %+v", plan.Files)
	}
	// Before the exec nobody is served; a process that connects is kept
	// waiting, not refused, and never gets the value.
	r.execAs(t, cli, plan, nil)
	// Another process of the user connects first: refused, and it does not
	// consume the handover.
	other := r.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/x/evil"})
	if got := r.connect(t, plan, other); got != "" {
		t.Fatalf("another process got %q", got)
	}
	if got := r.connect(t, plan, cli); got != wantLine() {
		t.Fatalf("the exec'd process got %q", got)
	}
	f := r.lastAudit(t, audit.Approved)
	if f["delivery"] != "late-env" || f["env_passed"] != "HTTPS_PROXY" || f["operation"] != "nazar run" {
		t.Fatalf("audit %v", f)
	}
	waitFor(t, func() bool { _, err := os.Stat(sock); return errors.Is(err, os.ErrNotExist) })
	if got := r.connect(t, plan, cli); !strings.HasPrefix(got, "dial:") {
		t.Fatalf("after the handover the socket is gone, got %q", got)
	}
	blocked := false
	for _, l := range r.sink.Lines() {
		if strings.Contains(l, "unexpected socket peer") && strings.Contains(l, "decision=blocked") {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("the refused peer must be audited:\n%s", strings.Join(r.sink.Lines(), "\n"))
	}
	if n := r.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("%d dialogs", n)
	}
	// The session approval is remembered for this receiver: no dialog.
	cli2 := r.f.Launch(tab.Shell, cliProc("run"))
	r.f.SetDefaultPeer(cli2)
	plan2, p := r.run(t, []string{"node", r.srv}, caller, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli2, plan2, nil)
	if got := r.connect(t, plan2, cli2); got != wantLine() {
		t.Fatalf("second run got %q", got)
	}
	if n := r.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("a remembered approval must not ask again: %d dialogs", n)
	}
	// Another envAllow value is another receiver (D5): asked again.
	cli3 := r.f.Launch(tab.Shell, cliProc("run"))
	r.f.SetDefaultPeer(cli3)
	moved := slices.Clone(caller)
	moved[0] = "HTTPS_PROXY=http://elsewhere:8080"
	plan3, p := r.run(t, []string{"node", r.srv}, moved, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli3, plan3, nil)
	if got := r.connect(t, plan3, cli3); got != wantLine() {
		t.Fatalf("third run got %q", got)
	}
	if n := r.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("a receiver with another environment must ask: %d dialogs", n)
	}
}

// After the exec the agent compares the process with the plan, and refuses
// on any difference, or when it cannot read it (6.3 step 6, 6.3.4).
func TestRunRefusedAtExec(t *testing.T) {
	for _, tc := range []struct {
		name, why string
		mod       func(r *runEnv, p *fake.Proc, env *[]string)
		hide      bool // the environment is unreadable from the exec on
	}{
		{name: "an extra variable", why: "unexpected environment: npm_config_script_shell",
			mod: func(_ *runEnv, _ *fake.Proc, env *[]string) { *env = append(*env, "npm_config_script_shell=/tmp/x.sh") }},
		{name: "a variable missing", why: "unexpected environment: HOME",
			mod: func(_ *runEnv, _ *fake.Proc, env *[]string) {
				*env = slices.DeleteFunc(*env, func(kv string) bool { return strings.HasPrefix(kv, "HOME=") })
			}},
		{name: "a changed value", why: "unexpected environment: PATH",
			mod: func(_ *runEnv, _ *fake.Proc, env *[]string) {
				for i, kv := range *env {
					if strings.HasPrefix(kv, "PATH=") {
						(*env)[i] = "PATH=/tmp/x:" + kv[5:]
					}
				}
			}},
		{name: "another image", why: "receiver changed at exec",
			mod: func(_ *runEnv, p *fake.Proc, _ *[]string) { p.Path = "/tmp/x/node" }},
		{name: "other code", why: "receiver changed at exec",
			mod: func(_ *runEnv, p *fake.Proc, _ *[]string) { p.Code.CDHash = []byte{1} }},
		{name: "another argv", why: "receiver changed at exec",
			mod: func(_ *runEnv, p *fake.Proc, _ *[]string) { p.Args = append(slices.Clone(p.Args), "--x") }},
		{name: "another directory", why: "receiver changed at exec: cwd",
			mod: func(_ *runEnv, p *fake.Proc, _ *[]string) { p.Cwd = "/tmp/e" }},
		{name: "the script rewritten", why: "receiver changed at exec: server.js changed",
			mod: func(r *runEnv, _ *fake.Proc, _ *[]string) { os.WriteFile(r.srv, []byte("evil()\n"), 0o644) }},
		{name: "an unreadable environment", why: "unexpected environment: not readable", hide: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startRun(t, nil)
			r.ready(t, itermRule)
			cli := r.asCLI(cliProc("run"))
			plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
			if p != nil {
				t.Fatal(p)
			}
			if tc.hide {
				r.f.SetEnvironmentUnreadable(cli, true)
			}
			r.execAs(t, cli, plan, func(p *fake.Proc, env *[]string) {
				if tc.mod != nil {
					tc.mod(r, p, env)
				}
			})
			if got := r.connect(t, plan, cli); got != "" && !strings.HasPrefix(got, "dial:") {
				t.Fatalf("got %q", got)
			}
			f := r.lastAudit(t, audit.Denied)
			if !strings.HasPrefix(f["reason"], tc.why) {
				t.Fatalf("reason %q, want %q", f["reason"], tc.why)
			}
		})
	}
}

// A second exec of the run's process before the handover: the process that
// would connect is not the one the agent checked.
func TestRunSecondExecIsRefused(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli := r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli, plan, nil)
	r.f.Exec(cli, fake.Proc{Path: "/bin/sh", Args: []string{"sh"}, Cwd: "/"}, plan.Env)
	if got := r.connect(t, plan, cli); got != "" && !strings.HasPrefix(got, "dial:") {
		t.Fatalf("got %q", got)
	}
	if f := r.lastAudit(t, audit.Denied); !strings.HasPrefix(f["reason"], "receiver changed at exec") {
		t.Fatalf("audit %v", f)
	}
}

func TestRunWithoutExecOrConnection(t *testing.T) {
	r := startRun(t, func(_ *fake.Fake, o *Options) { o.RunExecTimeout, o.RunHandoverTimeout = time.Second, time.Second })
	r.ready(t, itermRule)
	// The CLI dies instead of exec'ing.
	cli := r.asCLI(cliProc("run"))
	if _, p := r.run(t, []string{"node", r.srv}, nil, nil); p != nil {
		t.Fatal(p)
	}
	r.f.Exit(cli)
	if f := r.lastAudit(t, audit.Error); f["reason"] != "target never exec'd" {
		t.Fatalf("audit %v", f)
	}
	// It execs, and nobody connects before the deadline.
	cli = r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	r.execAs(t, cli, plan, nil)
	waitFor(t, func() bool {
		for _, l := range r.sink.Lines() {
			if strings.Contains(l, `reason="target never connected"`) {
				return true
			}
		}
		return false
	})
	if _, err := os.Stat(envVal(plan.Env, "NAZAR_SECRET_SOCK")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the socket must be removed at the deadline")
	}
}

// npx (D2): the exec'd launcher never gets the value, nor a descendant that
// is not a bin of the target package; one that is, does.
func TestRunLauncherServesOnlyTheTargetsBin(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, itermRule)
	cli := r.asCLI(cliProc("run"))
	plan, p := r.run(t, []string{"npx", "-y", "@brave/brave-search-mcp-server"}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	if envVal(plan.Env, "NAZAR_TARGET") != "@brave/brave-search-mcp-server" ||
		!slices.Equal(plan.ExecArgv, []string{r.node, r.npxCLI, "-y", "@brave/brave-search-mcp-server"}) {
		t.Fatalf("plan %+v", plan)
	}
	r.execAs(t, cli, plan, nil)
	cache := filepath.Join(r.root, "npm/_npx/abc/node_modules")
	pkg := filepath.Join(cache, "@brave/brave-search-mcp-server")
	os.MkdirAll(filepath.Join(pkg, "dist"), 0o755)
	os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"@brave/brave-search-mcp-server","bin":{"b":"dist/index.js"}}`), 0o644)
	os.WriteFile(filepath.Join(pkg, "dist/index.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(pkg, "install.js"), []byte("x"), 0o644)
	if got := r.connect(t, plan, cli); got != "" {
		t.Fatalf("the launcher itself got %q", got)
	}
	install := r.f.Launch(cli, fake.Proc{Path: r.node, Args: []string{"node", filepath.Join(pkg, "install.js")}})
	if got := r.connect(t, plan, install); got != "" {
		t.Fatalf("an install script got %q", got)
	}
	outside := r.f.Launch(platform.ProcessRef{}, fake.Proc{Path: r.node, Args: []string{"node", filepath.Join(pkg, "dist/index.js")}})
	if got := r.connect(t, plan, outside); got != "" {
		t.Fatalf("a process outside the run got %q", got)
	}
	sh := r.f.Launch(cli, fake.Proc{Path: "/bin/sh", Args: []string{"sh", "-c", "b"}})
	target := r.f.Launch(sh, fake.Proc{Path: r.node, Args: []string{"node", filepath.Join(pkg, "dist/index.js")}})
	if got := r.connect(t, plan, target); got != wantLine() {
		t.Fatalf("the target got %q", got)
	}
	r.lastAudit(t, audit.Approved)
}

// Refused before any prompt: nothing is asked, nothing opened.
func TestRunRefusedBeforeAnyPrompt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mod   func(f *fake.Fake, o *Options)
		rules string
		argv  func(r *runEnv) []string
		extra map[string]string
		peer  func(r *runEnv) platform.ProcessRef
		code  string
		msg   string
	}{
		{name: "no exec seam", mod: func(_ *fake.Fake, o *Options) { o.Exec = nil }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "no loaders", mod: func(_ *fake.Fake, o *Options) { o.LoaderDir = "" }, code: control.CodeRefused, msg: "late-env is not available"},
		{name: "a receiver to: does not name", argv: func(r *runEnv) []string { return []string{"node", "-e", "console.log(process.env.API_KEY)"} },
			code: control.CodeRefused, msg: "to: mismatch"},
		{name: "a relative command", argv: func(*runEnv) []string { return []string{"./node", "x"} }, code: control.CodeUsage, msg: "is relative"},
		{name: "a cwd argument", extra: map[string]string{"cwd": "/tmp/e"}, code: control.CodeUsage, msg: "no cwd"},
		{name: "not the CLI", peer: func(r *runEnv) platform.ProcessRef {
			return r.asCLI(fake.Proc{Path: "/tmp/fake-nazar", Args: []string{"nazar"}})
		}, code: control.CodeRefused, msg: "peer is not the nazar CLI"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startRun(t, tc.mod)
			rules := itermRule
			if tc.rules != "" {
				rules = tc.rules
			}
			r.ready(t, rules)
			if tc.peer != nil {
				tc.peer(r)
			} else {
				r.asCLI(cliProc("run"))
			}
			argv := []string{"node", r.srv}
			if tc.argv != nil {
				argv = tc.argv(r)
			}
			_, p := r.run(t, argv, nil, tc.extra)
			if p == nil || p.Code != tc.code || !strings.Contains(p.Message, tc.msg) {
				t.Fatalf("problem %+v, want %s %q", p, tc.code, tc.msg)
			}
			if n := r.f.CountShown(fake.KindConfirm); n != 0 {
				t.Fatalf("%d dialogs", n)
			}
		})
	}
}

// A secret whose deliver: has no late-env is blocked before any prompt.
func TestRunNeedsLateEnvInDeliver(t *testing.T) {
	r := startRun(t, nil)
	r.approved(t, strings.Replace(strings.Replace(r.config(itermRule), "    deliver: [late-env]\n    envAllow: [HTTPS_PROXY]\n", "    deliver: [stdout]\n", 1),
		"        to: [srv, brave-mcp]\n", "", 1))
	r.d.secrets.Add("API_KEY", []byte(testValue), platform.AccessWhenUnlocked)
	r.asCLI(cliProc("run"))
	_, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "delivery not allowed") || r.f.CountShown(fake.KindConfirm) != 0 {
		t.Fatalf("problem %+v", p)
	}
}

// nazar run under a rule naming an app with gate: none and no to: starts any
// interpreter command its children ask for, with no prompt. Files are still
// pinned in the plan.
func TestRunSilentForAChildOfTheNamedApp(t *testing.T) {
	r := startRun(t, nil)
	r.ready(t, "      - apps: [iterm]\n        gate: none\n")
	r.f.SetDefaults(fake.Answer{}, fake.Answer{}) // a prompt would be refused
	logins, dialogs := r.f.CountShown(fake.KindAuthenticate), r.f.CountShown(fake.KindConfirm)
	r.asCLI(cliProc("run", "--secret", "API_KEY", "--", "node", r.srv))
	plan, p := r.run(t, []string{"node", r.srv}, nil, nil)
	if p != nil {
		t.Fatal(p)
	}
	if plan.ExecPath != r.node || len(plan.Files) != 2 || plan.Files[1].Path != r.srv {
		t.Fatalf("plan %+v", plan)
	}
	if r.f.CountShown(fake.KindAuthenticate) != logins || r.f.CountShown(fake.KindConfirm) != dialogs {
		t.Fatal("no prompt under gate: none")
	}
}
