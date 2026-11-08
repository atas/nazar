package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/envpolicy"
	"github.com/atas/nazar/internal/rune2e"
)

// nazar run end to end on Linux, with real processes: the real
// nazar CLI, the real npx (npm's npx-cli.js under the real node), a real
// install from a local registry and the real Node loader, against the
// daemon on procPlatform (the /proc seams). It proves the goal of the
// milestone: the target, the package's bin, has the value in process.env;
// no process's startup environment or command line holds it, nor any file
// the run left; and npx's own process never gets it.

// A dependency's install script that knows the protocol and tries the
// socket itself, from the startup environment npm gave it (spike S12: it
// runs before the target, with the loader).
const grabber = `const fs = require('fs'), net = require('net');
const env = fs.readFileSync('/proc/self/environ', 'latin1').split('\0');
const sock = (env.find(kv => kv.startsWith('NAZAR_SECRET_SOCK=')) || '').slice(18);
const penv = (() => { try { return fs.readFileSync('/proc/' + process.ppid + '/environ', 'latin1'); } catch (e) { return ''; } })();
// Its own and its parent's (npm's sh) startup environments go into the
// report, which the test's walk of every file left proves value-free.
const done = got => { fs.writeFileSync(process.env.E2E_REPORT + '.grab', JSON.stringify({pid: process.pid, sock, got, env: env.join('\n'), penv})); };
if (!sock) { done(null); } else {
  const c = net.connect(sock); let got = '';
  c.on('data', d => got += d); c.on('close', () => done(got)); c.on('error', () => done(got));
}
`

// e2eWorld is the daemon on procPlatform, the real CLI, and a home for
// the receiver.
type e2eWorld struct {
	*env
	pp              *procPlatform
	tmp, cli, rhome string
}

func newE2EWorld(t *testing.T, cfg func(w *e2eWorld) string) *e2eWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("end to end: builds the CLI and runs real interpreters")
	}
	_, here, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(here), "..", "..")
	tmp, err := os.MkdirTemp("/tmp", "nze")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	tmp, _ = filepath.EvalSymlinks(tmp)
	w := &e2eWorld{tmp: tmp, cli: filepath.Join(tmp, "nazar"), rhome: filepath.Join(tmp, "home")}
	build := exec.Command("go", "build", "-o", w.cli, "./cmd/nazar")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// The loaders as the agent bundle holds them: a copy, so
	// Python writes no __pycache__ into the repository, in a folder of its
	// own: the agent pins the folders above them, and runs write their
	// reports into tmp.
	top, err := os.MkdirTemp("/tmp", "nzl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(top) })
	top, _ = filepath.EvalSymlinks(top)
	loaders := filepath.Join(top, "loaders")
	for _, f := range []string{"node/env.cjs", "python/sitecustomize.py"} {
		b, err := os.ReadFile(filepath.Join(repo, "loaders", f))
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Dir(filepath.Join(loaders, f)), 0o755)
		if err := os.WriteFile(filepath.Join(loaders, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(w.rhome, 0o700)
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	w.env = startWith(t, func(f *fake.Fake, o *Options) {
		w.pp = newProcPlatform(f)
		o.Platform, o.Exec, o.LoaderDir = w.pp, w.pp, loaders
		o.Mounts = f
		o.VerifyCLI = func(fd int) (platform.ProcessRef, error) {
			ref, err := w.pp.PeerOf(fd)
			if err != nil {
				return platform.ProcessRef{}, err
			}
			if p, err := w.pp.Process(ref); err != nil || p.Path != w.cli {
				return platform.ProcessRef{}, fmt.Errorf("not the nazar CLI")
			}
			return ref, nil
		}
		o.RunHost = func(uid int) (envpolicy.Host, error) {
			return envpolicy.Host{Home: w.rhome, User: me.Username, TmpDir: tmp}, nil
		}
		o.RunExecTimeout, o.RunHandoverTimeout = 30*time.Second, 120*time.Second
	})
	w.approved(t, cfg(w))
	if _, err := w.d.secrets.Add("BRAVE_API_KEY", []byte(rune2e.Value), platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	w.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	return w
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
	r := &e2eRun{out: &rune2e.SyncBuf{}, waitErr: make(chan error, 1), report: filepath.Join(w.tmp, "report.json")}
	r.cmd = exec.Command(w.cli, append([]string{"run", "--secret", "BRAVE_API_KEY", "--"}, argv...)...)
	// The caller's environment, hostile where it can be: none of it may
	// reach the receiver but E2E_REPORT (envAllow).
	r.cmd.Env = []string{"HOME=" + w.home, "PATH=" + os.Getenv("PATH"), "NAZAR_TEST_PEER=same-user",
		"NAZAR_CONTROL_SOCKET=" + layout.ControlSocket(w.home), "E2E_REPORT=" + r.report,
		"NODE_OPTIONS=--require /nonexistent/evil.cjs", "PYTHONPATH=/nonexistent", "npm_config_registry=http://127.0.0.1:1/"}
	r.cmd.Dir = w.tmp
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // the pgid survives the CLI's execve
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

// awaitReport waits for the target's report.
func (w *e2eWorld) awaitReport(t *testing.T, r *e2eRun) rune2e.Report {
	t.Helper()
	var rep rune2e.Report
	deadline := time.Now().Add(90 * time.Second)
	for {
		if b, err := os.ReadFile(r.report); err == nil && json.Unmarshal(b, &rep) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the target never reported\noutput:\n%s\naudit:\n%s", r.out.String(), strings.Join(w.sink.Lines(), "\n"))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !rep.Got() {
		t.Fatalf("the target did not get the value: %+v\noutput:\n%s\naudit:\n%s", rep, r.out.String(), strings.Join(w.sink.Lines(), "\n"))
	}
	if len(rep.Leftover) != 0 {
		t.Errorf("the target still has %q", rep.Leftover)
	}
	return rep
}

// noValueInProc checks that no process on the machine holds the value in
// its startup environment or command line, and that every process of tree
// could be read.
func noValueInProc(t *testing.T, tree []int) {
	t.Helper()
	ents, _ := os.ReadDir("/proc")
	for _, d := range ents {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		for _, f := range []string{"environ", "cmdline"} {
			b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, f))
			if err != nil {
				if slices.Contains(tree, pid) && !os.IsNotExist(err) {
					t.Errorf("cannot read /proc/%d/%s of the tree: %v", pid, f, err)
				}
				continue
			}
			if rune2e.Holds(b) {
				t.Errorf("/proc/%d/%s holds the value", pid, f)
			}
		}
	}
}

// end closes the target's stdin and waits for the run to end, then checks
// that no file the run left holds the value and the socket is gone.
func (w *e2eWorld) end(t *testing.T, r *e2eRun) {
	t.Helper()
	r.stdin.Close()
	select {
	case err := <-r.waitErr:
		r.waitErr <- err // for the cleanup
		if err != nil {
			t.Errorf("the run: %v\n%s", err, r.out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not end with its stdin")
	}
	for _, root := range []string{w.tmp, w.home} {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() || p == w.cli {
				return nil
			}
			if b, err := os.ReadFile(p); err == nil && rune2e.Holds(b) {
				t.Errorf("%s holds the value", p)
			}
			return nil
		})
	}
	ents, _ := os.ReadDir(layout.RunDir(w.home))
	for _, e := range ents {
		if n := e.Name(); n != "agent.sock" && n != "control.sock" { // the agent's own
			t.Errorf("run socket left: %s", n)
		}
	}
}

// audited counts the run's approved lines and refused-peer lines.
func (w *e2eWorld) audited() (approved, refused int) {
	for _, l := range w.sink.Lines() {
		m, err := audit.ParseLine(l)
		if err != nil || m["target"] != "secret:BRAVE_API_KEY" {
			continue
		}
		switch {
		case m["decision"] == string(audit.Approved) && m["delivery"] == "late-env":
			approved++
		case m["reason"] == errUnexpectedPeer:
			refused++
		}
	}
	return approved, refused
}

func TestRunEndToEndThroughRealNpx(t *testing.T) {
	npx, err := exec.LookPath("npx")
	if err != nil {
		skipOutsideCI(t, "npx not installed")
	}
	nodeDir := filepath.Dir(npx)
	if _, err := os.Stat(filepath.Join(nodeDir, "node")); err != nil {
		skipOutsideCI(t, "node is not beside npx")
	}
	var reg *rune2e.Registry
	w := newE2EWorld(t, func(w *e2eWorld) string {
		reg = rune2e.NewRegistry(t)
		reg.Publish(t, "nazar-e2e-dep", map[string]any{"scripts": map[string]string{"postinstall": "node grab.js"}},
			[]rune2e.File{{Name: "grab.js", Body: grabber, Mode: 0o644}})
		reg.Publish(t, "@nazar-e2e/probe-server", map[string]any{"bin": map[string]string{"probe-server": "bin/server.js"},
			"dependencies": map[string]string{"nazar-e2e-dep": "1.0.0"}}, []rune2e.File{{Name: "bin/server.js", Body: rune2e.ProbeServer, Mode: 0o755}})
		// The receiver's home, as the agent knows it: npm reads its
		// registry and cache from here, never from the caller.
		npmrc := "registry=" + reg.URL() + "/\ncache=" + filepath.Join(w.rhome, ".npm") + "\naudit=false\nfund=false\nupdate-notifier=false\n"
		if err := os.WriteFile(filepath.Join(w.rhome, ".npmrc"), []byte(npmrc), 0o600); err != nil {
			t.Fatal(err)
		}
		return "apiVersion: nazar/v1\nkind: Config\napps:\n  probe: {command: [npx, -y, \"@nazar-e2e/probe-server\"]}\n" +
			"defaults:\n  trustedPath: [" + trustedPathOf(nodeDir) + "]\n" +
			"secrets:\n  BRAVE_API_KEY:\n    deliver: [late-env]\n    envAllow: [E2E_REPORT]\n    rules:\n" +
			"      - apps: [any]\n        to: [probe]\n        scope: use\n        gate: dialog\n"
	})
	r := w.run(t, "npx", "-y", "@nazar-e2e/probe-server")
	runPID := r.cmd.Process.Pid

	// 1. The target has the value in process.env, and nothing of nazar's.
	rep := w.awaitReport(t, r)
	// 2. The tree, all alive now: npx (the run's pid: the CLI exec'd in
	// place), its shell and the target. No process anywhere has the value
	// in its startup environment or command line.
	tree := descendants(runPID)
	if !slices.Contains(tree, rep.PID) || len(tree) < 2 {
		t.Fatalf("tree %v does not hold the target %d", tree, rep.PID)
	}
	if p, _ := w.pp.Process(platform.ProcessRef{PID: runPID}); !strings.HasSuffix(p.Path, "/node") {
		t.Fatalf("the run's pid is not npx's node: %+v", p)
	}
	// The scan reads real startup environments: the control.
	for pid, want := range map[int]string{runPID: "NAZAR_SECRET_SOCK=", rep.PID: "NODE_OPTIONS="} {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err != nil || !bytes.Contains(b, []byte(want)) {
			t.Fatalf("/proc/%d/environ has no %s: the scan would prove nothing (%v)", pid, want, err)
		}
	}
	noValueInProc(t, tree)
	// 3. npx's own process never got it: the run's pid never connected;
	// the only peer served is the target; the install script that tried
	// was refused, audited, and got nothing.
	peers := w.pp.peerPIDs()
	if slices.Contains(peers, runPID) || !slices.Contains(peers, rep.PID) {
		t.Errorf("peers %v: npx is %d, the target %d", peers, runPID, rep.PID)
	}
	var grab struct {
		PID  int     `json:"pid"`
		Sock string  `json:"sock"`
		Got  *string `json:"got"`
		Env  string  `json:"env"`
		PEnv string  `json:"penv"`
	}
	if b, err := os.ReadFile(r.report + ".grab"); err != nil || json.Unmarshal(b, &grab) != nil {
		t.Errorf("the install script did not run: %v", err)
	} else if grab.Sock == "" || grab.Got == nil || *grab.Got != "" || !strings.Contains(grab.PEnv, "NAZAR_SECRET_SOCK=") {
		t.Errorf("the install script got %+v", grab)
	}
	waitFor(t, func() bool { a, _ := w.audited(); return a == 1 })
	if approved, refused := w.audited(); approved != 1 || refused != 1 {
		t.Errorf("audit: %d approved, %d refused peers, want 1 and 1:\n%s", approved, refused, strings.Join(w.sink.Lines(), "\n"))
	}
	// npm used the local registry only (the caller's npm_config_registry
	// never reached it).
	if got := reg.Tarballs(); len(got) != 2 {
		t.Errorf("tarballs served: %v", got)
	}
	// 4. Nothing the run left on disk holds it (npm's cache and logs, the
	// install script's report of its own and npm's environment).
	w.end(t, r)
}

// The Python loader, end to end: python3 runs the script itself, so the
// exec'd process is the target and the only peer.
func TestRunEndToEndPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		skipOutsideCI(t, "python3 not installed")
	}
	var probe string
	w := newE2EWorld(t, func(w *e2eWorld) string {
		probe = filepath.Join(w.tmp, "py", "probe.py")
		os.MkdirAll(filepath.Dir(probe), 0o755)
		if err := os.WriteFile(probe, []byte(rune2e.ProbePy), 0o644); err != nil {
			t.Fatal(err)
		}
		return "apiVersion: nazar/v1\nkind: Config\napps:\n  probe: {command: [python3, " + strconv.Quote(probe) + "]}\n" +
			"defaults:\n  trustedPath: [" + trustedPathOf(filepath.Dir(py)) + "]\n" +
			"secrets:\n  BRAVE_API_KEY:\n    deliver: [late-env]\n    envAllow: [E2E_REPORT]\n    rules:\n" +
			"      - apps: [any]\n        to: [probe]\n        scope: use\n        gate: dialog\n"
	})
	r := w.run(t, "python3", probe)
	rep := w.awaitReport(t, r)
	if rep.PID != r.cmd.Process.Pid {
		t.Fatalf("the target is pid %d, the run %d: python3 must be the exec'd process", rep.PID, r.cmd.Process.Pid)
	}
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", rep.PID)); err != nil || !bytes.Contains(b, []byte("PYTHONPATH=")) {
		t.Fatalf("/proc/%d/environ has no PYTHONPATH: the scan would prove nothing (%v)", rep.PID, err)
	}
	noValueInProc(t, descendants(rep.PID))
	if peers := w.pp.peerPIDs(); !slices.Equal(peers, []int{rep.PID}) {
		t.Errorf("peers %v, want only the target %d", peers, rep.PID)
	}
	waitFor(t, func() bool { a, _ := w.audited(); return a == 1 })
	if approved, refused := w.audited(); approved != 1 || refused != 0 {
		t.Errorf("audit: %d approved, %d refused:\n%s", approved, refused, strings.Join(w.sink.Lines(), "\n"))
	}
	w.end(t, r)
}

// skipOutsideCI skips for a missing tool on a developer's machine, and
// fails in CI, where the proof must not vanish quietly.
func skipOutsideCI(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatal(why + ": the end-to-end proof needs it in CI")
	}
	t.Skip(why)
}

// trustedPathOf is dir, then /usr/bin and /bin (for sh), each once.
func trustedPathOf(dir string) string {
	var out []string
	for _, d := range []string{dir, "/usr/bin", "/bin"} {
		if q := strconv.Quote(d); !slices.Contains(out, q) {
			out = append(out, q)
		}
	}
	return strings.Join(out, ", ")
}

// descendants is pid and every process below it, from /proc.
func descendants(pid int) []int {
	parent := map[int]int{}
	ents, _ := os.ReadDir("/proc")
	for _, d := range ents {
		p, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		if pp, _, _, err := procStat(p); err == nil {
			parent[p] = pp
		}
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
