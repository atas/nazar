//go:build darwin

package main

// nazar run end to end on the Mac, the port of the Linux end-to-end test
// (core/daemon/lateenv_e2e_linux_test.go). The daemon runs in this
// process on the Swift platform's process seams through the real C ABI:
// PeerOf, Process, CodeHash, ResponsibleFor, OnProcessExit and
// platform.Exec (kqueue NOTE_EXEC and KERN_PROCARGS2) are the
// ones nazar-agent uses. Keys, gates, the vault and installed apps are
// the Go fake's, so nothing can show a window or touch a keychain. The
// CLI and the loaders are those `make agent` put in build/nazar-agent.app
// (NAZAR_AGENT_APP, set by make integration-run). npx is the real one,
// installing from a registry this test serves on 127.0.0.1; every other
// host goes to a closed proxy port. The receiver's home is a temp folder
// (Options.RunHost), never the developer's.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/codesign"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/platform/mounts"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/secrets/envpolicy"
	"github.com/atas/nazar/internal/rune2e"
)

const (
	e2eSecret   = "BRAVE_API_KEY"
	refusedPeer = "unexpected socket peer" // core/daemon's audit reason
)

// realProcs is the platform of these tests: processes real, people fake.
type realProcs struct {
	*fake.Fake
	b *cbridge.Bridge

	mu    sync.Mutex
	peers []int // every pid PeerOf named on a run socket, in order
}

func (p *realProcs) PeerOf(fd int) (platform.ProcessRef, error) {
	ref, err := p.b.PeerOf(fd)
	if err == nil {
		if sa, e := unix.Getsockname(fd); e == nil {
			if u, ok := sa.(*unix.SockaddrUnix); ok && strings.Contains(u.Name, "/.nazar/run/") && len(filepath.Base(u.Name)) == 37 { // <32 hex>.sock, not the agent's own
				p.mu.Lock()
				p.peers = append(p.peers, ref.PID)
				p.mu.Unlock()
			}
		}
	}
	return ref, err
}

func (p *realProcs) peerPIDs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.peers)
}

func (p *realProcs) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	return p.b.Process(ref)
}
func (p *realProcs) CodeHash(path string) ([]byte, error) { return p.b.CodeHash(path) }
func (p *realProcs) ResponsibleFor(ref platform.ProcessRef) (platform.ProcessRef, bool) {
	return p.b.ResponsibleFor(ref)
}
func (p *realProcs) OnProcessExit(ref platform.ProcessRef, fn func()) { p.b.OnProcessExit(ref, fn) }

// verifyCLI is nazar-agent's check of a value command's peer
// (bridge/clipeer_darwin.go), with req pinning the bundle's CLI.
func verifyCLI(p platform.Platform, req string) func(fd int) (platform.ProcessRef, error) {
	return func(fd int) (platform.ProcessRef, error) {
		tok, err := codesign.PeerAuditToken(fd)
		if err != nil {
			return platform.ProcessRef{}, err
		}
		if err := codesign.CheckPeer(tok, req); err != nil {
			return platform.ProcessRef{}, err
		}
		info, err := p.Process(platform.ProcessRef{PID: tok.PID()})
		if err != nil {
			return platform.ProcessRef{}, err
		}
		return info.Ref, nil
	}
}

var cdhashRE = regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`)

// e2eWorld is one test's daemon on realProcs, in this process, with the
// bundle's CLI and loaders, a home for the CLI and one for the receiver.
type e2eWorld struct {
	rp                *realProcs
	sink              *audit.MemorySink
	log               rune2e.SyncBuf
	app, cli, loaders string
	tmp, home, rhome  string
	ownLoaders        bool // loaders is a copy this test may change, not the bundle's
	runs              int
}

func newE2EWorld(t *testing.T, b *cbridge.Bridge, ownLoaders bool, cfg func(w *e2eWorld) string) *e2eWorld {
	t.Helper()
	app := os.Getenv("NAZAR_AGENT_APP")
	if app == "" {
		t.Fatal("NAZAR_AGENT_APP is not set: make integration-run sets it to the bundle make agent built")
	}
	ex := b.Exec()
	if ex == nil {
		t.Fatal("the Swift layer offers no exec seam")
	}
	tmp, err := os.MkdirTemp("/tmp", "nze") // short: sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil { // /private/tmp: the platform reports realpaths
		t.Fatal(err)
	}
	w := &e2eWorld{app: app, tmp: tmp, home: filepath.Join(tmp, "home"), rhome: filepath.Join(tmp, "rhome"), ownLoaders: ownLoaders}
	if w.cli, err = filepath.EvalSymlinks(filepath.Join(app, "Contents", "MacOS", "nazar")); err != nil {
		t.Fatalf("the bundle's CLI: %v", err)
	}
	if w.loaders, err = filepath.EvalSymlinks(filepath.Join(app, "Contents", "Resources", "loaders")); err != nil {
		t.Fatalf("the bundle's loaders: %v", err)
	}
	if ownLoaders {
		// A copy of the bundle's two loaders, which the test may change, in
		// a folder of its own: the agent pins the folders above them, and
		// runs write their reports into tmp.
		top, err := os.MkdirTemp("/tmp", "nzl")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(top) })
		if top, err = filepath.EvalSymlinks(top); err != nil {
			t.Fatal(err)
		}
		own := filepath.Join(top, "loaders")
		for _, f := range []string{"node/env.cjs", "python/sitecustomize.py"} {
			body, err := os.ReadFile(filepath.Join(w.loaders, f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(filepath.Join(own, f)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(own, f), body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		w.loaders = own
	}
	for _, d := range []string{w.home, w.rhome} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("/usr/bin/codesign", "-dvvv", w.cli).CombinedOutput()
	m := cdhashRE.FindSubmatch(out)
	if m == nil {
		t.Fatalf("no cdhash for %s: %v\n%s", w.cli, err, out)
	}
	req, err := codesign.CLIRequirement("", string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	f := fake.New(time.Now())
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true}) // login (config apply) and dialog
	w.rp = &realProcs{Fake: f, b: b}
	vault := fake.NewVault()
	if _, err := secrets.NewStore(w.rp, vault, nil).Add(e2eSecret, []byte(rune2e.Value), platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	w.sink = &audit.MemorySink{}
	d, err := daemon.New(daemon.Options{
		Platform: w.rp, Vault: vault, AuditSink: w.sink, Home: w.home,
		PollInterval: 50 * time.Millisecond, GateTimeout: func() time.Duration { return time.Minute },
		Logf:      func(format string, args ...any) { fmt.Fprintf(&w.log, format+"\n", args...) },
		VerifyCLI: verifyCLI(w.rp, req), Exec: ex, Mounts: mounts.New(), LoaderDir: w.loaders,
		RunHost: func(int) (envpolicy.Host, error) {
			return envpolicy.Host{Home: w.rhome, User: me.Username, TmpDir: tmp}, nil
		},
		RunExecTimeout: 30 * time.Second, RunHandoverTimeout: 2 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("daemon log:\n%s\naudit:\n%s", w.log.String(), w.auditDump())
		}
	})
	w.waitUntil(t, "the control socket", func() bool {
		c, err := net.Dial("unix", layout.ControlSocket(w.home))
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	w.approve(t, cfg(w))
	return w
}

// runConfig is the one config of these tests: command is the probe's
// command line, dir the folder of its interpreter.
func runConfig(command, dir string) string {
	return "apiVersion: nazar/v1\nkind: Config\napps:\n  probe: {command: " + command + "}\n" +
		"defaults:\n  trustedPath: [" + strconv.Quote(dir) + ", \"/usr/bin\", \"/bin\"]\n" +
		"secrets:\n  " + e2eSecret + ":\n    deliver: [late-env]\n    envAllow: [E2E_REPORT]\n    rules:\n" +
		"      - apps: [any]\n        to: [probe]\n        scope: use\n        gate: dialog\n"
}

// cliEnv is the CLI's environment with PATH path.
func (w *e2eWorld) cliEnv(path string) []string {
	return []string{"HOME=" + w.home, "PATH=" + path, "NAZAR_TEST_PEER=same-user",
		"NAZAR_CONTROL_SOCKET=" + layout.ControlSocket(w.home)}
}

// nazar runs the bundle's CLI and returns its stdout and exit code.
func (w *e2eWorld) nazar(t *testing.T, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.cli, args...)
	cmd.Env = w.cliEnv("/usr/bin:/bin")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("nazar %v hung", args)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), 0
}

// approve writes body and waits until the daemon enforces it: it asks its
// login gate (the fake's: allow) and applies it.
func (w *e2eWorld) approve(t *testing.T, body string) {
	t.Helper()
	check := func() control.ConfigCheck {
		out, _ := w.nazar(t, "--json", "config", "check")
		var c control.ConfigCheck
		json.Unmarshal([]byte(out), &c)
		return c
	}
	before := check().ActiveHash
	p := layout.ConfigFile(w.home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	w.waitUntil(t, "the config in force", func() bool {
		c := check()
		if !c.Valid && len(c.Problems) > 0 {
			t.Fatalf("config.yaml is not valid: %+v", c.Problems)
		}
		return c.Valid && c.Staged == nil && c.ActiveHash != before
	})
}

// npmrc is the receiver's ~/.npmrc: npm reads its registry, cache and
// proxies from the receiver's home, never from the caller. Every host but
// this test's registry goes to a closed port.
func (w *e2eWorld) npmrc(t *testing.T, reg *rune2e.Registry) {
	t.Helper()
	rc := "registry=" + reg.URL() + "/\ncache=" + filepath.Join(w.rhome, ".npm") +
		"\nproxy=http://127.0.0.1:9/\nhttps-proxy=http://127.0.0.1:9/\nnoproxy=127.0.0.1,localhost\n" +
		"audit=false\nfund=false\nupdate-notifier=false\n"
	if err := os.WriteFile(filepath.Join(w.rhome, ".npmrc"), []byte(rc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// e2eRun is one `nazar run`, in its own process group so that nothing it
// started outlives the test.
type e2eRun struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	out     *rune2e.SyncBuf
	waitErr chan error
	report  string
}

func (w *e2eWorld) run(t *testing.T, argv ...string) *e2eRun {
	t.Helper()
	w.runs++
	r := &e2eRun{out: &rune2e.SyncBuf{}, waitErr: make(chan error, 1), report: filepath.Join(w.tmp, fmt.Sprintf("report-%d.json", w.runs))}
	r.cmd = exec.Command(w.cli, append([]string{"run", "--secret", e2eSecret, "--"}, argv...)...)
	// The caller's environment, hostile where it can be: none of it may
	// reach the receiver but E2E_REPORT (envAllow).
	r.cmd.Env = append(w.cliEnv(os.Getenv("PATH")), "E2E_REPORT="+r.report,
		"NODE_OPTIONS=--require /nonexistent/evil.cjs", "PYTHONPATH=/nonexistent", "npm_config_registry=http://127.0.0.1:1/")
	r.cmd.Dir = w.tmp
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // the group survives the CLI's execve
	r.cmd.WaitDelay = 5 * time.Second
	var err error
	if r.stdin, err = r.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	r.cmd.Stdout, r.cmd.Stderr = r.out, r.out
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { r.waitErr <- r.cmd.Wait() }()
	t.Cleanup(func() {
		r.stdin.Close()
		syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
		<-r.waitErr
	})
	return r
}

// changeWhileAsking starts a run, waits for its dialog, runs change while
// the dialog is open, then lets the dialog allow it.
func (w *e2eWorld) changeWhileAsking(t *testing.T, change func(), argv ...string) *e2eRun {
	t.Helper()
	release, asked := make(chan struct{}), make(chan struct{}, 1)
	w.rp.SetGateFuncs(nil, func(platform.Prompt) fake.Answer {
		select {
		case asked <- struct{}{}:
		default:
		}
		return fake.Answer{Allow: true, Wait: release}
	})
	defer w.rp.SetGateFuncs(nil, nil)
	r := w.run(t, argv...)
	select {
	case <-asked:
	case <-time.After(30 * time.Second):
		t.Fatalf("no dialog\n%s", r.out.String())
	}
	change()
	close(release)
	return r
}

// report waits for the target's report.
func (w *e2eWorld) report(t *testing.T, r *e2eRun) rune2e.Report {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		var rep rune2e.Report
		if b, err := os.ReadFile(r.report); err == nil && json.Unmarshal(b, &rep) == nil {
			return rep
		}
		if time.Now().After(deadline) {
			t.Fatalf("the target never reported\noutput:\n%s", r.out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// wait closes the run's stdin and returns its exit code.
func (w *e2eWorld) wait(t *testing.T, r *e2eRun) int {
	t.Helper()
	r.stdin.Close()
	select {
	case err := <-r.waitErr:
		r.waitErr <- err // for the cleanup
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatalf("the run: %v", err)
		}
		return 0
	case <-time.After(30 * time.Second):
		t.Fatalf("the run did not end with its stdin\n%s", r.out.String())
	}
	return -1
}

// end waits for a run that must succeed, then checks what it left.
func (w *e2eWorld) end(t *testing.T, r *e2eRun) {
	t.Helper()
	if code := w.wait(t, r); code != 0 {
		t.Errorf("the run exited %d\n%s", code, r.out.String())
	}
	w.clean(t)
}

// clean: no file under the test's folders holds the value (npm's cache
// and logs, both homes, the reports), no run socket is left, and the
// bundle is as make agent sealed it.
func (w *e2eWorld) clean(t *testing.T) {
	t.Helper()
	filepath.WalkDir(w.tmp, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if b, err := os.ReadFile(p); err == nil && rune2e.Holds(b) {
				t.Errorf("%s holds the value", p)
			}
		}
		return nil
	})
	ents, _ := os.ReadDir(layout.RunDir(w.home))
	for _, e := range ents {
		if n := e.Name(); n != "agent.sock" && n != "control.sock" { // the agent's own
			t.Errorf("run socket left: %s", n)
		}
	}
	if !w.ownLoaders {
		// A receiver must write nothing into the bundle (Python's
		// bytecode beside its loader would break the seal and the pin).
		var got []string
		filepath.WalkDir(w.loaders, func(p string, d fs.DirEntry, err error) error {
			if err == nil && p != w.loaders {
				rel, _ := filepath.Rel(w.loaders, p)
				got = append(got, rel)
			}
			return nil
		})
		if want := []string{"node", "node/env.cjs", "python", "python/sitecustomize.py"}; !slices.Equal(got, want) {
			t.Errorf("the bundle's loaders folder holds %q, want %q", got, want)
		}
		if out, err := exec.Command("/usr/bin/codesign", "--verify", "--strict", "--deep", w.app).CombinedOutput(); err != nil {
			t.Errorf("the bundle's seal no longer verifies: %v\n%s", err, out)
		}
	}
}

func (w *e2eWorld) auditDump() string { return strings.Join(w.sink.Lines(), "\n") }

// auditHas reports whether an audit line of the secret holds s.
func (w *e2eWorld) auditHas(s string) bool {
	for _, l := range w.sink.Lines() {
		if strings.Contains(l, "target=secret:"+e2eSecret) && strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// audited counts the run's approved lines and refused-peer lines.
func (w *e2eWorld) audited() (approved, refused int) {
	for _, l := range w.sink.Lines() {
		m, err := audit.ParseLine(l)
		if err != nil || m["target"] != "secret:"+e2eSecret {
			continue
		}
		switch {
		case m["decision"] == string(audit.Approved) && m["delivery"] == "late-env":
			approved++
		case m["reason"] == refusedPeer:
			refused++
		}
	}
	return approved, refused
}

func (w *e2eWorld) waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s\naudit:\n%s", what, w.auditDump())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// treeOf is pid and every process below it, from the kernel's process
// table (pids and parents only).
func treeOf(t *testing.T, pid int) []int {
	t.Helper()
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		t.Fatal(err)
	}
	parent := map[int]int{}
	for _, k := range procs {
		parent[int(k.Proc.P_pid)] = int(k.Eproc.Ppid)
	}
	out := []int{pid}
	for changed := true; changed; {
		changed = false
		for p, pp := range parent {
			if slices.Contains(out, pp) && !slices.Contains(out, p) {
				out = append(out, p)
				changed = true
			}
		}
	}
	return out
}

// noValueInTree reads every process of tree as any program of the user
// can, two ways: its KERN_PROCARGS2 (argv and startup environment) and
// `ps eww`. Neither may hold the value or its base64. controls are a pid
// and a variable its startup environment must show, so an empty or
// unreadable read can't pass. Only the run's own processes are read:
// others belong to the developer (a real MCP server holds a real key).
func noValueInTree(t *testing.T, tree []int, controls map[int]string) {
	t.Helper()
	var list []string
	for _, pid := range tree {
		list = append(list, strconv.Itoa(pid))
		b, err := unix.SysctlRaw("kern.procargs2", pid)
		if err != nil {
			if unix.Kill(pid, 0) == nil {
				t.Errorf("KERN_PROCARGS2 of %d: %v", pid, err)
			}
			continue
		}
		if rune2e.Holds(b) {
			t.Errorf("KERN_PROCARGS2 of %d holds the value", pid)
		}
		if want, ok := controls[pid]; ok && !bytes.Contains(b, []byte("\x00"+want)) {
			t.Fatalf("KERN_PROCARGS2 of %d has no %s: the scan would prove nothing", pid, want)
		}
	}
	out, err := exec.Command("/bin/ps", "-E", "-ww", "-o", "pid=,command=", "-p", strings.Join(list, ",")).Output()
	if err != nil {
		t.Fatalf("ps eww: %v", err)
	}
	if rune2e.Holds(out) {
		t.Errorf("ps eww of the run's processes holds the value")
	}
	for _, want := range controls {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("ps eww shows no %s: the scan would prove nothing", want)
		}
	}
}

// toolDir is the realpath of the first folder on this process's PATH
// whose name entry ok accepts by its realpath: a real installation, never
// a version manager's shim (mise's shims are links to mise itself).
func toolDir(name string, ok func(real, dir string) bool) (string, bool) {
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if !filepath.IsAbs(d) {
			continue
		}
		real, err := filepath.EvalSymlinks(filepath.Join(d, name))
		if err != nil {
			continue
		}
		dir, err := filepath.EvalSymlinks(d)
		if err == nil && ok(real, dir) {
			return dir, true
		}
	}
	return "", false
}

// isNpx: npm's npx-cli.js with a real node beside it.
func isNpx(real, dir string) bool {
	st, err := os.Lstat(filepath.Join(dir, "node"))
	return strings.HasSuffix(real, "/npm/bin/npx-cli.js") && err == nil && st.Mode().IsRegular()
}

var pythonRE = regexp.MustCompile(`^python3(\.[0-9]+)?$`)

// isPlainPython: a python3 nazar run serves (spike S14): not Apple's
// /usr/bin shim, not a framework build (it execs itself again).
func isPlainPython(real, _ string) bool {
	return pythonRE.MatchString(filepath.Base(real)) && !strings.HasPrefix(real, "/usr/bin/") && !strings.Contains(real, ".framework/")
}

// grabberMac is a dependency's install script that knows the protocol and
// tries the socket itself (spike S12: it runs before the target, with the
// loader's variables, which the loader leaves to every process but the
// target). Its own and its parent's startup environments, as ps eww shows
// them, go into its report, which the walk of every file left proves
// value-free.
const grabberMac = `const fs = require('fs'), net = require('net'), cp = require('child_process');
const sock = process.env.NAZAR_SECRET_SOCK || '';
const ps = pid => { try { return cp.execFileSync('/bin/ps', ['-E', '-ww', '-o', 'command=', '-p', String(pid)], {encoding: 'latin1'}); } catch (e) { return ''; } };
const env = ps(process.pid), penv = ps(process.ppid);
const done = got => { fs.writeFileSync(process.env.E2E_REPORT + '.grab', JSON.stringify({pid: process.pid, sock, got, env, penv})); };
if (!sock) { done(null); } else {
  const c = net.connect(sock); let got = '';
  c.on('data', d => got += d); c.on('close', () => done(got)); c.on('error', () => done(got));
}
`

func testRunThroughRealNpx(t *testing.T, b *cbridge.Bridge) {
	nodeDir, ok := toolDir("npx", isNpx)
	if !ok {
		t.Skip("no npx with a real node beside it on PATH (mise's, say): not tested")
	}
	var reg *rune2e.Registry
	w := newE2EWorld(t, b, false, func(w *e2eWorld) string {
		reg = rune2e.NewRegistry(t)
		// The script's path is absolute, as a target's is, so that only the
		// agent's check of the target package's bin (D2) refuses it.
		reg.Publish(t, "nazar-e2e-dep", map[string]any{"scripts": map[string]string{"postinstall": `node "$PWD/grab.js"`}},
			[]rune2e.File{{Name: "grab.js", Body: grabberMac, Mode: 0o644}})
		reg.Publish(t, "@nazar-e2e/probe-server", map[string]any{"bin": map[string]string{"probe-server": "bin/server.js"},
			"dependencies": map[string]string{"nazar-e2e-dep": "1.0.0"}}, []rune2e.File{{Name: "bin/server.js", Body: rune2e.ProbeServer, Mode: 0o755}})
		w.npmrc(t, reg)
		return runConfig(`[npx, -y, "@nazar-e2e/probe-server"]`, nodeDir)
	})
	r := w.run(t, "npx", "-y", "@nazar-e2e/probe-server")
	runPID := r.cmd.Process.Pid

	// 1. The target has the value in process.env, and nothing of nazar's.
	rep := w.report(t, r)
	if !rep.Got() {
		t.Fatalf("the target did not get the value: %+v\noutput:\n%s", rep, r.out.String())
	}
	if len(rep.Leftover) != 0 {
		t.Errorf("the target still has %q", rep.Leftover)
	}
	// 2. The tree, all alive now: npx (the run's pid: the CLI exec'd in
	// place), the shell npm started and the target. No process of it has
	// the value in what ps eww or KERN_PROCARGS2 shows, npx's included.
	tree := treeOf(t, runPID)
	if !slices.Contains(tree, rep.PID) || len(tree) < 2 {
		t.Fatalf("tree %v does not hold the target %d", tree, rep.PID)
	}
	if p, err := w.rp.Process(platform.ProcessRef{PID: runPID}); err != nil || filepath.Base(p.Path) != "node" {
		t.Fatalf("the run's pid is not npx's node: %+v %v", p, err)
	}
	noValueInTree(t, tree, map[int]string{rep.PID: "NODE_OPTIONS="})
	// 3. npx's own process never connected; the only peer served is the
	// target; the install script that connected first was refused,
	// audited, got nothing and did not consume the handover.
	if peers := w.rp.peerPIDs(); slices.Contains(peers, runPID) || !slices.Contains(peers, rep.PID) {
		t.Errorf("peers %v: npx is %d, the target %d", peers, runPID, rep.PID)
	}
	var grab struct {
		Sock string  `json:"sock"`
		Got  *string `json:"got"`
		Env  string  `json:"env"`
	}
	if b, err := os.ReadFile(r.report + ".grab"); err != nil || json.Unmarshal(b, &grab) != nil {
		t.Errorf("the install script did not run: %v", err)
	} else if grab.Sock == "" || grab.Got == nil || *grab.Got != "" || !strings.Contains(grab.Env, "NAZAR_SECRET_SOCK=") {
		t.Errorf("the install script got sock %q, answer %v, its ps eww had the socket variable: %v", grab.Sock, grab.Got, strings.Contains(grab.Env, "NAZAR_SECRET_SOCK="))
	}
	w.waitUntil(t, "the approved line", func() bool { a, _ := w.audited(); return a == 1 })
	if approved, refused := w.audited(); approved != 1 || refused != 1 {
		t.Errorf("audit: %d approved, %d refused peers, want 1 and 1:\n%s", approved, refused, w.auditDump())
	}
	// npm used this test's registry only (the caller's
	// npm_config_registry never reached it).
	if got := reg.Tarballs(); len(got) != 2 {
		t.Errorf("tarballs served: %v", got)
	}
	// 4. Nothing the run left on disk holds it; the bundle is untouched.
	w.end(t, r)
}

// The Python loader: python3 runs the script itself, so the exec'd process
// is the target and the only peer.
func testRunPython(t *testing.T, b *cbridge.Bridge) {
	pyDir, ok := toolDir("python3", isPlainPython)
	if !ok {
		t.Skip("no python3 nazar run can serve on PATH (mise's, say): not tested")
	}
	var probe string
	w := newE2EWorld(t, b, false, func(w *e2eWorld) string {
		probe = filepath.Join(w.tmp, "py", "probe.py")
		if err := os.MkdirAll(filepath.Dir(probe), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(probe, []byte(rune2e.ProbePy), 0o644); err != nil {
			t.Fatal(err)
		}
		return runConfig("[python3, "+strconv.Quote(probe)+"]", pyDir)
	})
	r := w.run(t, "python3", probe)
	rep := w.report(t, r)
	if !rep.Got() || len(rep.Leftover) != 0 {
		t.Fatalf("the target: %+v\noutput:\n%s", rep, r.out.String())
	}
	if rep.PID != r.cmd.Process.Pid {
		t.Fatalf("the target is pid %d, the run %d: python3 must be the exec'd process", rep.PID, r.cmd.Process.Pid)
	}
	noValueInTree(t, treeOf(t, rep.PID), map[int]string{rep.PID: "PYTHONPATH="})
	if peers := w.rp.peerPIDs(); !slices.Equal(peers, []int{rep.PID}) {
		t.Errorf("peers %v, want only the target %d", peers, rep.PID)
	}
	w.waitUntil(t, "the approved line", func() bool { a, _ := w.audited(); return a == 1 })
	if approved, refused := w.audited(); approved != 1 || refused != 0 {
		t.Errorf("audit: %d approved, %d refused:\n%s", approved, refused, w.auditDump())
	}
	w.end(t, r)
}

// A changed pinned file is never served: the receiver's script changed
// while the dialog is open (the CLI's fstat refuses), nazar's loader
// changed while the dialog is open (denied at the real exec event, the
// program runs without the value), and the loader still changed at rest
// (refused before any prompt). The loaders are a copy of the bundle's.
func testRunRefusesChangedPinnedFiles(t *testing.T, b *cbridge.Bridge) {
	nodeDir, ok := toolDir("node", func(real, _ string) bool { return filepath.Base(real) == "node" })
	if !ok {
		t.Skip("no node on PATH that is not a shim: not tested")
	}
	var server string
	w := newE2EWorld(t, b, true, func(w *e2eWorld) string {
		server = filepath.Join(w.tmp, "js", "server.js")
		if err := os.MkdirAll(filepath.Dir(server), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(server, []byte(rune2e.ProbeServer), 0o644); err != nil {
			t.Fatal(err)
		}
		return runConfig("[node, "+strconv.Quote(server)+"]", nodeDir)
	})

	// (a) The script, between the agent's pin and the CLI's fstat.
	r := w.changeWhileAsking(t, func() { appendTo(t, server, "\n// changed\n") }, "node", server)
	if code := w.wait(t, r); code == 0 || !strings.Contains(r.out.String(), "server.js changed since nazar-agent checked it") {
		t.Errorf("a changed script: exit %d\n%s", code, r.out.String())
	}
	if _, err := os.Stat(r.report); err == nil {
		t.Error("the changed script ran")
	}
	w.waitUntil(t, "the run's error line", func() bool { return w.auditHas("target never exec'd") })

	// (a2) A volume mounted and unmounted while the dialog is open (D12):
	// the check at the real NOTE_EXEC record denies; the program runs
	// without the value.
	r = w.changeWhileAsking(t, func() { mountScratch(t) }, "node", server)
	if rep := w.report(t, r); rep.Got() {
		t.Fatal("served although a volume was mounted during the run")
	}
	w.waitUntil(t, "the denied line", func() bool { return w.auditHas("receiver changed at exec: a volume was mounted or unmounted") })
	if code := w.wait(t, r); code != 0 || !strings.Contains(r.out.String(), "not delivered") {
		t.Errorf("a run denied for a mount: exit %d\n%s", code, r.out.String())
	}

	// (b) nazar's loader, between the agent's pin and the exec: the check
	// at the NOTE_EXEC record denies; the program runs without the value.
	r = w.changeWhileAsking(t, func() { appendTo(t, filepath.Join(w.loaders, "node", "env.cjs"), "\n// changed\n") }, "node", server)
	if rep := w.report(t, r); rep.Got() {
		t.Fatal("served although nazar's loader changed")
	}
	w.waitUntil(t, "the denied line", func() bool { return w.auditHas("receiver changed at exec: nazar's loader changed") })
	if code := w.wait(t, r); code != 0 || !strings.Contains(r.out.String(), "not delivered") {
		t.Errorf("a run denied at the exec: exit %d\n%s", code, r.out.String())
	}

	// (c) The loader as it is now, at rest: refused before any prompt.
	var asked atomic.Bool
	ask := func(platform.Prompt) fake.Answer { asked.Store(true); return fake.Answer{} }
	w.rp.SetGateFuncs(ask, ask)
	r = w.run(t, "node", server)
	if code := w.wait(t, r); code != control.ExitRefused || !strings.Contains(r.out.String(), "its loaders are missing or were changed") {
		t.Errorf("a changed loader at rest: exit %d\n%s", code, r.out.String())
	}
	if asked.Load() {
		t.Error("a prompt for a run that was refused")
	}
	if _, err := os.Stat(r.report); err == nil {
		t.Error("the program ran")
	}
	w.clean(t)
}
