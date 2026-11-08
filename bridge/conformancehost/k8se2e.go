//go:build darwin

package main

// On the Mac (k8s design 2.0, 2.1 and 11; THREAT-MODEL 4.10, 5.16): check 0,
// check 1 (the CLI's parent, whatever program it is, is identified: there
// is no client list and nothing is trusted) and the stdout check on the
// chain the kernel reports. The daemon
// runs in this process on the Swift platform's process seams through the
// real C ABI (realProcs, as for nazar run): the CLI's audit token, its
// parent, their paths, command lines and running-code identities come from
// the kernel and Security.framework, and the stdout check is package pipes,
// as nazar-agent wires them. Keys, gates, the vault and the block warning
// are the Go fake's, so nothing is shown and no keychain is used. The
// plugin is the nazartest build of the CLI (NAZAR_TEST_CLI, which make
// integration-run builds and signs ad hoc as dev.nazar.cli); this daemon
// pins it by cdhash, and it reaches the daemon only through
// NAZAR_TEST_CONTROL_SOCKET, never the account's ~/.nazar. kubectl is the
// one on PATH (skipped when there is none), with a temp home and a temp
// kubeconfig, against a k8stest server on 127.0.0.1.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/codesign"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/k8s/k8stest"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/platform/pipes"
	"github.com/atas/nazar/core/policy"
	"github.com/atas/nazar/internal/rune2e"
)

// core/daemon's refusals of check 0 and of the stdout check.
const (
	k8sReasonNotCLI = "peer is not the nazar CLI"
	k8sReasonStdout = "the plugin's output does not go straight to the program that ran it"
)

// pyRunsCLI is python3 running the plugin as client-go does: its stdout a
// pipe python3 alone reads, so the stdout check passes and python3, like
// any program, receives the credential when the rules allow.
const pyRunsCLI = `import subprocess, sys
r = subprocess.run([sys.argv[1], "k8s", "credential", "hydra"], stdout=subprocess.PIPE)
sys.stdout.buffer.write(r.stdout)
sys.exit(r.returncode)
`

// k8sWorld is one daemon on realProcs with a context hydra that every
// caller may use through a dialog, and no program trusted.
type k8sWorld struct {
	rp              *realProcs
	sink            *audit.MemorySink
	log             rune2e.SyncBuf
	tmp, home, sock string
	cli, pin        string // the nazartest CLI and its cdhash
	srv             *k8stest.Server
}

func newK8sWorld(t *testing.T, b *cbridge.Bridge, kubectl string) *k8sWorld {
	t.Helper()
	cli := os.Getenv("NAZAR_TEST_CLI")
	if cli == "" {
		t.Fatal("NAZAR_TEST_CLI is not set: make integration-run sets it to the nazartest CLI it built")
	}
	cli, err := filepath.EvalSymlinks(cli)
	if err != nil {
		t.Fatal(err)
	}
	// Only the nazartest build may run here: the release CLI's k8s
	// credential dials the account's own nazar-agent, whatever the
	// environment says.
	if body, err := os.ReadFile(cli); err != nil || !bytes.Contains(body, []byte("NAZAR_TEST_CONTROL_SOCKET")) {
		t.Fatalf("NAZAR_TEST_CLI %s is not the nazartest build of the CLI (%v)", cli, err)
	}
	ps := pipes.New()
	if ps == nil {
		t.Fatal("no stdout check on macOS: every k8s credential would be refused")
	}
	tmp, err := os.MkdirTemp("/tmp", "nzk") // short: sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	if tmp, err = filepath.EvalSymlinks(tmp); err != nil { // /private/tmp: the platform reports realpaths
		t.Fatal(err)
	}
	w := &k8sWorld{tmp: tmp, home: filepath.Join(tmp, "home"), cli: cli, pin: cdhashOf(t, cli)}
	w.sock = layout.ControlSocket(w.home)
	if err := os.MkdirAll(w.home, 0o700); err != nil {
		t.Fatal(err)
	}
	req, err := codesign.CLIRequirement("", w.pin)
	if err != nil {
		t.Fatal(err)
	}
	f := fake.New(time.Now())
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true}) // login (trust, ca create, config) and dialog
	w.rp = &realProcs{Fake: f, b: b}
	w.sink = &audit.MemorySink{}
	d, err := daemon.New(daemon.Options{
		Platform: w.rp, Vault: fake.NewVault(), AuditSink: w.sink, Home: w.home,
		PollInterval: 50 * time.Millisecond, GateTimeout: func() time.Duration { return time.Minute },
		Logf:      func(format string, args ...any) { fmt.Fprintf(&w.log, format+"\n", args...) },
		VerifyCLI: verifyCLI(w.rp, req), Pipes: ps,
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
			t.Logf("daemon log:\n%s\naudit:\n%s", w.log.String(), strings.Join(w.sink.Lines(), "\n"))
		}
	})
	w.waitFor(t, "the control socket", func() bool {
		c, err := net.Dial("unix", w.sock)
		if err == nil {
			c.Close()
		}
		return err == nil
	})

	// The server, the context set up with k8s ca create from a kubeconfig
	// naming the server (a login prompt the fake allows), the server
	// trusting its CA, and last the context as this test wants it, pinned
	// to that server. Nothing is trusted with nazar trust.
	w.srv = k8stest.Start(t, nil)
	seed := filepath.Join(tmp, "seed-kubeconfig")
	if err := os.WriteFile(seed, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: hydra-admin\n  cluster:\n    server: "+w.srv.URL+
		"\n    certificate-authority-data: "+base64.StdEncoding.EncodeToString(w.srv.CAPEM)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := w.command(t, w.cli, "--json", "k8s", "ca", "create", "hydra", w.srv.URL)
	cmd.Env = append(cmd.Env, "KUBECONFIG="+seed, "PATH="+filepath.Dir(kubectl)+":/usr/bin:/bin")
	code, out, errs := runCmd(t, cmd)
	var setup struct {
		Context struct {
			CA struct {
				CertFile string `json:"certFile"`
			} `json:"ca"`
		} `json:"context"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &setup) != nil || setup.Context.CA.CertFile == "" {
		t.Fatalf("k8s ca create: exit %d %s %s", code, out, errs)
	}
	certPEM, err := os.ReadFile(setup.Context.CA.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("%s holds no PEM certificate", setup.Context.CA.CertFile)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	w.srv.TrustClientCA(caCert)
	pin, err := cluster.PinOf(cluster.Info{Server: w.srv.URL, CAData: w.srv.CAPEM})
	if err != nil {
		t.Fatal(err)
	}
	w.approve(t, "apiVersion: nazar/v1\nkind: Config\n"+
		"k8s:\n  contexts:\n    hydra:\n      credential: ca-cert\n      identity: {user: admin, groups: [system:masters]}\n"+
		"      cluster: {server: "+strconv.Quote(pin.Server)+", ca_sha256: "+pin.CASHA256+"}\n"+
		"      scope: use\n      gate: dialog\n")
	return w
}

// cliEnv is the environment of every process the test starts: the test
// home and this daemon's socket, both the one ordinary commands read and
// the one only the nazartest build's k8s credential reads.
func (w *k8sWorld) cliEnv() []string {
	return []string{"HOME=" + w.home, "PATH=/usr/bin:/bin", "NAZAR_TEST_PEER=same-user",
		"NAZAR_CONTROL_SOCKET=" + w.sock, "NAZAR_TEST_CONTROL_SOCKET=" + w.sock}
}

// command is name args with the world's environment, killed after a
// minute. stdin is /dev/null, so nothing can wait for an answer.
func (w *k8sWorld) command(t *testing.T, name string, args ...string) *exec.Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = w.cliEnv()
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

// runCmd runs cmd and returns its exit code, stdout and stderr.
func runCmd(t *testing.T, cmd *exec.Cmd) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return ee.ExitCode(), out.String(), errb.String()
	case err != nil:
		t.Fatalf("%s: %v", cmd.Path, err)
	}
	return 0, out.String(), errb.String()
}

// nazar runs the nazartest CLI and returns its stdout and exit code.
func (w *k8sWorld) nazar(t *testing.T, args ...string) (string, int) {
	t.Helper()
	code, out, _ := runCmd(t, w.command(t, w.cli, args...))
	return out, code
}

func (w *k8sWorld) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s\ndaemon log:\n%s", what, w.log.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// approve writes body and waits until the daemon enforces it (its login
// gate is the fake's: allow), as e2eWorld.approve does for nazar run.
func (w *k8sWorld) approve(t *testing.T, body string) {
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
	w.waitFor(t, "the config in force", func() bool {
		c := check()
		if !c.Valid && len(c.Problems) > 0 {
			t.Fatalf("config.yaml is not valid: %+v", c.Problems)
		}
		return c.Valid && c.Staged == nil && c.ActiveHash != before
	})
}

// kubeconfig writes a kubeconfig for the test server whose exec entry
// runs command args, and returns its path.
func (w *k8sWorld) kubeconfig(t *testing.T, command string, args ...string) string {
	t.Helper()
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = strconv.Quote(a) // a YAML double-quoted scalar
	}
	body := "apiVersion: v1\nkind: Config\nclusters:\n- name: hydra\n  cluster:\n    server: " + w.srv.URL +
		"\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString(w.srv.CAPEM) +
		"\nusers:\n- name: hydra\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n" +
		"      command: " + strconv.Quote(command) + "\n      args: [" + strings.Join(q, ", ") + "]\n" +
		"      provideClusterInfo: true\n      interactiveMode: Never\n" +
		"      env:\n      - {name: NAZAR_TEST_CONTROL_SOCKET, value: " + strconv.Quote(w.sock) + "}\n" +
		"contexts:\n- name: hydra\n  context: {cluster: hydra, user: hydra}\ncurrent-context: hydra\n"
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// execInfo is the KUBERNETES_EXEC_INFO kubectl sends for the test server.
func (w *k8sWorld) execInfo(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"apiVersion": "client.authentication.k8s.io/v1", "kind": "ExecCredential",
		"spec": map[string]any{"interactive": false,
			"cluster": map[string]any{"server": w.srv.URL, "certificate-authority-data": w.srv.CAPEM}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runKubectl runs `kubectl get --raw` of the pods through kc (the verb
// first, so the audit receiver shows it).
func (w *k8sWorld) runKubectl(t *testing.T, kubectl, kc string) (int, string, string) {
	t.Helper()
	cmd := w.command(t, kubectl, "get", "--raw", "/api/v1/namespaces/default/pods", "--kubeconfig", kc, "--request-timeout", "30s")
	cmd.Env = append(cmd.Env, "KUBECONFIG="+kc)
	return runCmd(t, cmd)
}

// k8sCounts is what a request may change: signatures (the CA signing a
// certificate), dialogs, block warnings, client certificates the server
// was shown.
type k8sCounts struct{ signs, dialogs, warnings, certs int }

func (w *k8sWorld) counts() k8sCounts {
	certs := 0
	for _, s := range w.srv.Seen() {
		if s.Presented {
			certs++
		}
	}
	return k8sCounts{w.rp.SignCalls(), w.rp.CountShown(fake.KindConfirm), len(w.rp.Warnings()), certs}
}

// lastAudit is the last audit line of the context, as fields.
func (w *k8sWorld) lastAudit(t *testing.T) map[string]string {
	t.Helper()
	lines := w.sink.Lines()
	for i := len(lines) - 1; i >= 0; i-- {
		if m, err := audit.ParseLine(lines[i]); err == nil && m["target"] == "k8s:hydra" {
			return m
		}
	}
	t.Fatal("no audit line for k8s:hydra")
	return nil
}

// minted runs kubectl through kc and wants a credential: 200 naming the
// context's identity, one dialog (scope: use), a signature, a verified
// certificate at the server and an approved audit line, which it returns.
func (w *k8sWorld) minted(t *testing.T, kubectl, kc string) map[string]string {
	t.Helper()
	before := w.counts()
	code, out, errs := w.runKubectl(t, kubectl, kc)
	if code != 0 || !strings.Contains(out, "web-1") || !strings.Contains(out, `"k8stest/user":"admin"`) {
		t.Fatalf("kubectl %s: exit %d\nstdout: %s\nstderr: %s", kubectl, code, out, errs)
	}
	now, seen := w.counts(), w.srv.Seen()
	last := seen[len(seen)-1]
	if now.signs <= before.signs || now.dialogs != before.dialogs+1 || now.certs != before.certs+1 ||
		!last.Verified || last.CN != "admin" || strings.Join(last.O, ",") != "system:masters" {
		t.Fatalf("before %+v, after %+v, the server saw %+v", before, now, last)
	}
	f := w.lastAudit(t)
	if f["decision"] != string(audit.Approved) {
		t.Fatalf("audit %v", f)
	}
	return f
}

// refused wants a request refused for reason with nothing minted: the
// reason in what the user sees, no dialog, no signature, no certificate at
// the server, a blocked audit line with the reason, and a block warning
// exactly when warned (check 1 warns; check 0 and the stdout check refuse
// before any policy is read and do not).
func (w *k8sWorld) refused(t *testing.T, before k8sCounts, stderr, reason string, warned bool) {
	const why = "can't be identified" // check 1's block warning
	t.Helper()
	now, f := w.counts(), w.lastAudit(t)
	if !strings.Contains(stderr, reason) || strings.Contains(stderr, "BEGIN") || now.signs != before.signs ||
		now.dialogs != before.dialogs || now.certs != before.certs ||
		f["decision"] != string(audit.Blocked) || !strings.HasPrefix(f["reason"], reason) {
		t.Fatalf("want refused (%s) with nothing minted: stderr %q, before %+v, after %+v, audit %v", reason, stderr, before, now, f)
	}
	ws := w.rp.Warnings()
	switch {
	case warned && (len(ws) != before.warnings+1 || !strings.Contains(strings.Join(ws[len(ws)-1].Lines, "\n"), why)):
		t.Fatalf("want one block warning naming the client check, got %+v", ws[before.warnings:])
	case !warned && len(ws) != before.warnings:
		t.Fatalf("want no block warning, got %+v", ws[before.warnings:])
	}
}

// kubectlRefused runs kubectl through kc and wants it refused for reason.
func (w *k8sWorld) kubectlRefused(t *testing.T, kubectl, kc, reason string, warned bool) {
	t.Helper()
	before := w.counts()
	code, out, errs := w.runKubectl(t, kubectl, kc)
	if code == 0 || !strings.Contains(errs, "exit code 3") || strings.Contains(out, "web-1") {
		t.Fatalf("kubectl %s: exit %d\nstdout: %s\nstderr: %s", kubectl, code, out, errs)
	}
	w.refused(t, before, errs, reason, warned)
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

func cdhashOf(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/codesign", "-dvvv", path).CombinedOutput()
	m := cdhashRE.FindSubmatch(out)
	if m == nil {
		t.Fatalf("no cdhash for %s: %v\n%s", path, err, out)
	}
	return string(m[1])
}

// signAdHoc re-signs path ad hoc (never an identity) as id, with no
// options: another signature, so another cdhash.
func signAdHoc(t *testing.T, path, id string) {
	t.Helper()
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", id, path).CombinedOutput(); err != nil {
		t.Fatalf("codesign %s: %v\n%s", path, err, out)
	}
}

// testK8sRealKubectl is TestNazarK8sRealKubectl.
func testK8sRealKubectl(t *testing.T, b *cbridge.Bridge) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("no kubectl on PATH")
	}
	w := newK8sWorld(t, b, kubectl)
	plugin := w.kubeconfig(t, w.cli, "k8s", "credential", "hydra")

	t.Run("kubectl, never trusted", func(t *testing.T) {
		// The receiver is the running kubectl's own command line
		// (KERN_PROCARGS2): the chain is the kernel's, not a script's.
		if f := w.minted(t, kubectl, plugin); !strings.Contains(f["receiver"], "kubectl") || !strings.Contains(f["receiver"], "get --raw") {
			t.Fatalf("receiver %q is not the kubectl that ran", f["receiver"])
		}
	})
	t.Run("a copy of kubectl at another path, then re-signed", func(t *testing.T) {
		// No client list (k8s design 2.1): a kubectl that moved or was
		// upgraded (another cdhash) works with no nazar trust.
		cp := filepath.Join(w.tmp, "copy", "kubectl")
		copyFile(t, kubectl, cp)
		w.minted(t, cp, plugin)
		next := filepath.Join(filepath.Dir(cp), ".kubectl.next")
		copyFile(t, cp, next)
		signAdHoc(t, next, "dev.nazar.test.kubectl")
		if cdhashOf(t, next) == cdhashOf(t, cp) {
			t.Fatal("re-signing did not change the cdhash")
		}
		if err := os.Rename(next, cp); err != nil { // a new file, never one changed under a running image
			t.Fatal(err)
		}
		w.minted(t, cp, plugin)
	})
	t.Run("python3 runs the CLI", func(t *testing.T) {
		// Without a developer folder /usr/bin/python3 would offer, in a
		// window, to install the tools.
		if exec.Command("/usr/bin/xcode-select", "-p").Run() != nil {
			t.Skip("no developer tools: /usr/bin/python3 would offer to install them")
		}
		before := w.counts()
		cmd := w.command(t, "/usr/bin/python3", "-I", "-c", pyRunsCLI, w.cli)
		cmd.Env = append(cmd.Env, "KUBERNETES_EXEC_INFO="+w.execInfo(t))
		code, out, errs := runCmd(t, cmd)
		now := w.counts()
		if code != 0 || !strings.Contains(out, "BEGIN CERTIFICATE") || now.dialogs != before.dialogs+1 || now.signs <= before.signs {
			t.Fatalf("python3 running the CLI: exit %d, before %+v, after %+v\nstderr: %s", code, before, now, errs)
		}
		if f := w.lastAudit(t); f["decision"] != string(audit.Approved) || !strings.Contains(strings.ToLower(f["receiver"]), "python") {
			t.Fatalf("audit %v", f)
		}
	})
	t.Run("the CLI's parent exited", func(t *testing.T) {
		before := w.counts()
		dir := t.TempDir()
		gate, errFile := filepath.Join(dir, "go"), filepath.Join(dir, "stderr")
		// The launcher starts a shell in the background, prints its PID and
		// exits. The shell waits for the gate, then becomes the genuine CLI,
		// launchd's child: the CLI does not exist before the test has seen
		// its parent go.
		cmd := w.command(t, "/bin/sh", "-c",
			`/bin/sh -c 'while [ ! -e "$1" ]; do sleep 0.05; done; exec "$0" k8s credential hydra' "$0" "$1" & echo $!`, w.cli, gate)
		cmd.Env = append(cmd.Env, "KUBERNETES_EXEC_INFO="+w.execInfo(t))
		r, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		ef, err := os.Create(errFile)
		if err != nil {
			t.Fatal(err)
		}
		defer ef.Close()
		cmd.Stdout, cmd.Stderr = pw, ef
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		pw.Close()
		br := bufio.NewReader(r)
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("the launcher printed %q: %v", line, err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("the launcher: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("the launcher printed %q", line)
		}
		gen := generation(t, pid)
		t.Cleanup(func() { // launchd's child, not ours: killed only while it is still that process
			if k, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil &&
				uint64(k.Proc.P_starttime.Sec)*1_000_000+uint64(k.Proc.P_starttime.Usec) == gen {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		})
		if k, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err != nil || k.Eproc.Ppid != 1 {
			t.Fatalf("the shell is not launchd's child: %v", err)
		}
		if err := os.WriteFile(gate, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		r.SetReadDeadline(time.Now().Add(time.Minute))
		out, err := io.ReadAll(br) // EOF once the CLI, which holds the write end, has exited
		if err != nil || len(out) != 0 {
			t.Fatalf("the CLI's stdout: %q %v", out, err)
		}
		errs, _ := os.ReadFile(errFile)
		w.refused(t, before, string(errs), policy.ReasonK8sCaller, true)
	})
	t.Run("an exec-hop relay", func(t *testing.T) {
		// THREAT-MODEL 5.16: both hops exec, so kubectl is still the CLI's
		// parent and passes check 1; tee would copy the reply to leak.
		leak := filepath.Join(t.TempDir(), "leak")
		kc := w.kubeconfig(t, "/bin/bash", "-c", `exec > >(exec /usr/bin/tee "$1"); exec "$0" k8s credential hydra`, w.cli, leak)
		w.kubectlRefused(t, kubectl, kc, k8sReasonStdout, false)
		if b, err := os.ReadFile(leak); err == nil && len(b) != 0 {
			t.Fatalf("the relay got %d bytes", len(b))
		}
	})
	t.Run("another build of the CLI", func(t *testing.T) {
		// The same code and identifier without the hardened runtime: an
		// ad-hoc build check 0 has not pinned.
		other := filepath.Join(w.tmp, "other", "nazar")
		copyFile(t, w.cli, other)
		signAdHoc(t, other, "dev.nazar.cli")
		if cdhashOf(t, other) == w.pin {
			t.Fatal("re-signing did not change the cdhash")
		}
		w.kubectlRefused(t, kubectl, w.kubeconfig(t, other, "k8s", "credential", "hydra"), k8sReasonNotCLI, false)
	})
	t.Run("the CLI at another path", func(t *testing.T) {
		// The pinned build anywhere is the same program (THREAT-MODEL 4.10).
		moved := filepath.Join(w.tmp, "moved", "nazar")
		copyFile(t, w.cli, moved)
		if cdhashOf(t, moved) != w.pin {
			t.Fatal("the copy has another cdhash")
		}
		w.minted(t, kubectl, w.kubeconfig(t, moved, "k8s", "credential", "hydra"))
	})
}
