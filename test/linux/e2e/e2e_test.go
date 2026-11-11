//go:build linux && linuxe2e

// Package e2e drives nazar on Linux end to end in the test image
// (test/linux): the real nazar-agent (its nazartest build, which takes its
// outside things from NAZAR_TEST_* variables) on a software TPM, with the
// image's polkitd answering through the test polkit agent, fakes for
// logind and the notification server on a private bus and fakedialog in
// place of zenity; the real nazar CLI (nazartest build: its k8s credential
// dials NAZAR_TEST_CONTROL_SOCKET), the image's ssh, sshd, git and
// kubectl. Each test has its own home, agent, TPM, bus and queue of
// answers, and nothing reaches the host: container.Require fails the run
// anywhere but the image.
package e2e

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
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/k8s/k8stest"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/peertrust"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/internal/linuxtest/answers"
	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/dbustest"
	"github.com/atas/nazar/internal/linuxtest/fakelogind"
	"github.com/atas/nazar/internal/linuxtest/fakenotify"
	"github.com/atas/nazar/internal/linuxtest/polkitagent"
	"github.com/atas/nazar/internal/linuxtest/swtpm"
)

// The image's test user (test/linux/Dockerfile), whose password the test
// polkit agent gives PAM on an allow.
const (
	testUser     = "nazartest"
	testPassword = "nazar-test-password"
)

// The programs under test and the image's, by absolute path.
const (
	sshPath     = "/usr/bin/ssh"
	sshAddPath  = "/usr/bin/ssh-add"
	gitPath     = "/usr/bin/git"
	kubectlPath = "/usr/local/bin/kubectl"
)

// termAppID is the desktop app id of the test's terminal app (installTerminalApp).
const termAppID = "dev.nazar.E2ETerm"

// bin holds nazar, nazar-agent, nazar-sign-git (a link to nazar) and
// fakedialog, built once in TestMain.
var bin string

func TestMain(m *testing.M) {
	if err := container.Check(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("/tmp", "nzbin")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, here, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(here), "..", "..", "..")
	for _, b := range [][3]string{
		{"nazar", "./cmd/nazar", "nazartest"},
		{"nazar-agent", "./cmd/nazar-agent", "nazartest"},
		{"fakedialog", "./internal/linuxtest/fakedialog", ""},
	} {
		args := []string{"build", "-o", filepath.Join(dir, b[0])}
		if b[2] != "" {
			args = append(args, "-tags", b[2])
		}
		cmd := exec.Command("go", append(args, b[1])...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("build %s: %v\n%s", b[0], err, out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	// The links nazar install makes: git's signing program and its
	// credential helper, both the CLI under another name.
	for _, link := range []string{"nazar-sign-git", "git-credential-nazar"} {
		if err := os.Symlink(filepath.Join(dir, "nazar"), filepath.Join(dir, link)); err != nil {
			fmt.Println(err)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	bin = dir
	code := container.Require(m)
	os.RemoveAll(dir)
	os.Exit(code)
}

// world is one test's nazar: a home, the agent on its own TPM and buses,
// and the scripted user.
type world struct {
	t         *testing.T
	home      string
	kh        string // the known_hosts file of the test's ssh runs
	dialogLog string // fakedialog's record of every window it stood for
	q         *answers.Queue
	logind    *fakelogind.Logind
	notify    *fakenotify.Server
	pk        *polkitagent.Agent
	tpm       string // the swtpm socket
	bus       string // the private bus address
	agent     *exec.Cmd
	agentLog  string
	// agentEnv is what a setup function adds to the agent's environment
	// (a NAZAR_TEST_* variable of its own) before the agent starts.
	agentEnv []string
}

// newWorld makes the home and the fakes, runs setup (anything that must be
// in place before the agent starts), then starts the agent and waits for
// its sockets.
func newWorld(t *testing.T, setup ...func(w *world)) *world {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "nze") // short: sun_path is 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	if home, err = filepath.EvalSymlinks(home); err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, home: home, kh: filepath.Join(home, "known_hosts"), dialogLog: filepath.Join(home, "dialogs.log"), agentLog: filepath.Join(home, "agent.log")}
	if err := os.WriteFile(w.kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// The install record, as `nazar install` writes it: both binaries by hash.
	rec := peertrust.Record{}
	for _, b := range []struct {
		name string
		bin  *peertrust.Binary
	}{{"nazar", &rec.CLI}, {"nazar-agent", &rec.Agent}} {
		path := filepath.Join(bin, b.name)
		sum, err := peertrust.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		*b.bin = peertrust.Binary{Path: path, SHA256: sum}
	}
	if err := peertrust.Write(home, rec); err != nil {
		t.Fatal(err)
	}

	w.q = answers.NewQueue(t)
	w.tpm = swtpm.Start(t)
	w.bus = dbustest.Start(t)
	uid := os.Getuid()
	w.logind = fakelogind.Serve(t, w.connect(), uid)
	w.notify = fakenotify.Serve(t, w.connect())

	// fakedialog as zenity: a wrapper gives it the queue's socket and the
	// log, which the dialog gate's allowlist would strip from the environment.
	dialog := filepath.Join(home, "dialog")
	script := "#!/bin/sh\nexport NAZAR_TEST_ANSWERS='" + w.q.Socket() + "'\nexport NAZAR_TEST_DIALOG_LOG='" + w.dialogLog + "'\nexec '" + filepath.Join(bin, "fakedialog") + "' \"$@\"\n"
	if err := os.WriteFile(dialog, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, f := range setup {
		f(w)
	}

	// The agent, with every outside thing named for it.
	logf, err := os.Create(w.agentLog)
	if err != nil {
		t.Fatal(err)
	}
	w.agent = exec.Command(filepath.Join(bin, "nazar-agent"))
	w.agent.Env = []string{
		"HOME=" + home, "PATH=/usr/bin:/bin", "LANG=C.UTF-8", "DISPLAY=:0",
		"NAZAR_TEST_HOME=" + home,
		"NAZAR_TEST_SWTPM=" + w.tpm,
		"NAZAR_TEST_LOGIND_BUS=" + w.bus,
		"NAZAR_TEST_SESSION_BUS=" + w.bus,
		"NAZAR_TEST_DIALOG=" + dialog,
	}
	w.agent.Env = append(w.agent.Env, w.agentEnv...)
	w.agent.Stdout, w.agent.Stderr = logf, logf
	if err := w.agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		w.agent.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { w.agent.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			w.agent.Process.Kill()
			<-done
		}
		logf.Close()
		if t.Failed() {
			t.Logf("nazar-agent log:\n%s", w.read(w.agentLog))
			t.Logf("audit log:\n%s", w.read(layout.AuditLog(home)))
			t.Logf("config.yaml:\n%s", w.read(layout.ConfigFile(home)))
		}
	})

	// The test polkit agent, for the agent process: polkitd asks it, and it
	// answers from the queue with the test user's password.
	system, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatalf("system bus: %v", err)
	}
	t.Cleanup(func() { system.Close() })
	st, err := procfs.ReadStat(w.agent.Process.Pid)
	if err != nil {
		t.Fatalf("the agent's process: %v\n%s", err, w.read(w.agentLog))
	}
	w.pk = polkitagent.Register(t, system, polkit.ProcessSubject(w.agent.Process.Pid, st.StartTicks, uid), testUser, testPassword, w.q)

	w.waitFor("the agent's sockets", func() bool {
		if w.agent.ProcessState != nil {
			t.Fatalf("nazar-agent exited: %v\n%s", w.agent.ProcessState, w.read(w.agentLog))
		}
		for _, p := range []string{layout.ControlSocket(home), layout.AgentSocket(home)} {
			if _, err := os.Stat(p); err != nil {
				return false
			}
		}
		return true
	})
	return w
}

// connect opens one connection to the private bus, closed at cleanup.
func (w *world) connect() *dbus.Conn {
	w.t.Helper()
	conn, err := dbus.Connect(w.bus)
	if err != nil {
		w.t.Fatalf("connect %s: %v", w.bus, err)
	}
	w.t.Cleanup(func() { conn.Close() })
	return conn
}

func (w *world) read(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

func (w *world) waitFor(what string, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			w.t.Fatalf("timed out waiting for %s\nnazar-agent log:\n%s", what, w.read(w.agentLog))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// env is the environment of every program the test runs: the test home
// (so the CLI finds this agent's sockets and record), no SSH_AUTH_SOCK,
// git without the user's config, the world's kubeconfig, and the control
// socket only the nazartest build's k8s credential reads. No
// NAZAR_TEST_PEER: the CLI checks the agent by hash, as shipped.
func (w *world) env(extra ...string) []string {
	return append([]string{"HOME=" + w.home, "PATH=/usr/bin:/bin:/usr/local/bin", "LC_ALL=C",
		"NAZAR_TEST_CONTROL_SOCKET=" + layout.ControlSocket(w.home),
		"KUBECONFIG=" + filepath.Join(w.home, "kubeconfig"),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}, extra...)
}

// run runs name args with the world's environment and stdin, bounded, and
// returns stdout+stderr and the exit code. An empty stdin means nothing
// can prompt.
func (w *world) run(stdin string, extra []string, name string, args ...string) (string, int) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = w.env(extra...)
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if ctx.Err() != nil {
		w.t.Fatalf("%s %v hung: %s", name, args, out.String())
	}
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		return out.String(), ee.ExitCode()
	case err != nil:
		w.t.Fatal(err)
	}
	return out.String(), 0
}

// nazar runs the CLI.
func (w *world) nazar(args ...string) (string, int) {
	w.t.Helper()
	return w.run("", nil, filepath.Join(bin, "nazar"), args...)
}

// createKey makes key name through the CLI, the login gate allowed, and
// returns its .pub path. The CLI's chain has no desktop app, so the entry
// the agent writes is the key's own gate block alone.
func (w *world) createKey(name string, flags ...string) string {
	w.t.Helper()
	w.q.Push(true)
	out, code := w.nazar(append([]string{"ssh-key", "create", name}, flags...)...)
	if code != 0 {
		w.t.Fatalf("ssh-key create %s: exit %d\n%s", name, code, out)
	}
	pub := filepath.Join(layout.KeysDir(w.home), name+".pub")
	if _, err := os.Stat(pub); err != nil {
		w.t.Fatalf("no public key file after create: %v\n%s", err, out)
	}
	return pub
}

// configCheck is `nazar --json config check`.
func (w *world) configCheck() control.ConfigCheck {
	w.t.Helper()
	out, code := w.nazar("--json", "config", "check")
	var c control.ConfigCheck
	if err := json.Unmarshal([]byte(out), &c); err != nil && code == 0 {
		w.t.Fatalf("config check: %v\n%s", err, out)
	}
	return c
}

// approveConfig writes body as config.yaml and waits until the agent
// enforces it: the daemon's poller stages the change and asks on the login
// gate, which the test agent allows.
func (w *world) approveConfig(body string) {
	w.t.Helper()
	before := w.configCheck().ActiveHash
	w.q.Push(true)
	p := layout.ConfigFile(w.home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		w.t.Fatal(err)
	}
	w.waitFor("the config in force", func() bool {
		c := w.configCheck()
		if !c.Valid && len(c.Problems) > 0 {
			w.t.Fatalf("config.yaml is not valid: %+v", c.Problems)
		}
		return c.Valid && c.Staged == nil && c.ActiveHash != "" && c.ActiveHash != before
	})
}

// keyConfig is a config with one rule for key name, whose apps are the
// programs at the given paths (each defined under apps: by its base name,
// as config.yaml wants).
func keyConfig(name, gate, scope string, paths ...string) string {
	var apps, names []string
	for _, p := range paths {
		n := strings.ReplaceAll(filepath.Base(p), "-", "")
		apps = append(apps, "  "+n+": {path: "+p+"}\n")
		names = append(names, n)
	}
	return "apiVersion: nazar/v1\nkind: Config\napps:\n" + strings.Join(apps, "") +
		"ssh_agent:\n  keys:\n    " + name + ":\n      rules:\n        - apps: [" + strings.Join(names, ", ") + "]\n          gate: " + gate + "\n          scope: " + scope + "\n"
}

// dialogs is how many windows fakedialog has stood for so far.
func (w *world) dialogs() int {
	return strings.Count(w.read(w.dialogLog), "\n")
}

// log is `nazar log --since 1m` with the given filters.
func (w *world) log(filters ...string) string {
	w.t.Helper()
	out, code := w.nazar(append([]string{"log", "--since", "1m"}, filters...)...)
	if code != 0 {
		w.t.Fatalf("nazar log: exit %d\n%s", code, out)
	}
	return out
}

// sshd is a user-level sshd on 127.0.0.1 that trusts one key.
type sshd struct {
	port    int
	hostPub string
}

func (w *world) startSSHD(pubFile string) *sshd {
	w.t.Helper()
	d := filepath.Join(w.home, "sshd")
	if err := os.MkdirAll(d, 0o700); err != nil {
		w.t.Fatal(err)
	}
	hostKey := filepath.Join(d, "host_ed25519")
	if out, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput(); err != nil {
		w.t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, err := os.ReadFile(pubFile)
	if err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "authorized_keys"), pub, 0o600); err != nil {
		w.t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s\nPidFile %s\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMaxStartups 100\n",
		port, hostKey, filepath.Join(d, "authorized_keys"), filepath.Join(d, "sshd.pid"))
	if err := os.WriteFile(filepath.Join(d, "sshd_config"), []byte(cfg), 0o600); err != nil {
		w.t.Fatal(err)
	}
	cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", filepath.Join(d, "sshd_config"))
	logf, err := os.Create(filepath.Join(d, "sshd.log"))
	if err != nil {
		w.t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		logf.Close()
		if w.t.Failed() {
			w.t.Logf("sshd log:\n%s", w.read(filepath.Join(d, "sshd.log")))
		}
	})
	w.waitFor("sshd", func() bool {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	hostPub, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(w.kh, []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, hostPub)), 0o600); err != nil {
		w.t.Fatal(err)
	}
	return &sshd{port: port, hostPub: hostKey + ".pub"}
}

// sshArgs are the ssh arguments for logging in to s with only the nazar
// key through this agent: -F /dev/null, the world's known_hosts, never
// interactive, and stdin from /dev/null (-n), so an ssh run from a shell
// that reads its commands from a pipe does not eat the shell's next line.
func (w *world) sshArgs(s *sshd, pubFile string) []string {
	return []string{"-F", "/dev/null", "-T", "-n",
		"-o", "IdentityAgent=" + layout.AgentSocket(w.home), "-o", "IdentitiesOnly=yes", "-i", pubFile,
		"-o", "UserKnownHostsFile=" + w.kh, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=10",
		"-p", fmt.Sprint(s.port), currentUser(w.t) + "@127.0.0.1"}
}

// ssh runs /usr/bin/ssh against s and returns the output and exit code.
func (w *world) ssh(s *sshd, pubFile, command string) (string, int) {
	w.t.Helper()
	return w.run("", nil, sshPath, append(w.sshArgs(s, pubFile), command)...)
}

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

// TestSSHKeyCreateAndUse: a key is made in the TPM behind the login gate,
// listed to ssh-add once a rule allows it, and used by ssh behind the
// dialog gate: an allow logs in, a deny does not, and the log shows it.
func TestSSHKeyCreateAndUse(t *testing.T) {
	w := newWorld(t)
	pub := w.createKey("github")
	w.approveConfig(keyConfig("github", "dialog", "use", sshPath, sshAddPath))

	pubLine, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.Fields(string(pubLine))[1]
	out, code := w.run("", []string{"SSH_AUTH_SOCK=" + layout.AgentSocket(w.home)}, sshAddPath, "-L")
	if code != 0 || !strings.Contains(out, blob) {
		t.Fatalf("ssh-add -L: exit %d\n%s\nwant the key %s", code, out, blob)
	}

	s := w.startSSHD(pub)
	w.q.Push(true)
	if out, code := w.ssh(s, pub, "echo nazar-ok"); code != 0 || !strings.Contains(out, "nazar-ok") {
		t.Fatalf("ssh after an allow: exit %d\n%s", code, out)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1", n)
	}
	w.q.Push(false)
	if out, code := w.ssh(s, pub, "echo nazar-ok"); code == 0 || strings.Contains(out, "nazar-ok") {
		t.Fatalf("ssh after a deny logged in: exit %d\n%s", code, out)
	}
	if n := w.dialogs(); n != 2 {
		t.Fatalf("%d dialogs shown, want 2", n)
	}
	denied := w.log("--decision", "denied")
	if !strings.Contains(denied, "decision=denied") || !strings.Contains(denied, "target=ssh:github") {
		t.Fatalf("nazar log --decision denied does not show the denial:\n%s\nall:\n%s", denied, w.log())
	}
	if all := w.log(); !strings.Contains(all, "decision=approved") || !strings.Contains(all, "ssh(") {
		t.Fatalf("nazar log does not show the approved login with its chain:\n%s", all)
	}
}

// TestGitSigning: a commit signed through nazar-sign-git, the key's rule
// naming git, verifies with git itself.
func TestGitSigning(t *testing.T) {
	w := newWorld(t)
	pub := w.createKey("gitsign")
	w.approveConfig(keyConfig("gitsign", "dialog", "use", gitPath))
	repo := filepath.Join(w.home, "repo")
	if out, code := w.run("", nil, gitPath, "init", "-q", repo); code != 0 {
		t.Fatalf("git init: %d %s", code, out)
	}
	git := func(args ...string) (string, int) {
		t.Helper()
		base := []string{"-C", repo,
			"-c", "user.name=nazar test", "-c", "user.email=test@example.invalid",
			"-c", "gpg.format=ssh", "-c", "user.signingkey=" + pub,
			"-c", "gpg.ssh.program=" + filepath.Join(bin, "nazar-sign-git")}
		return w.run("", nil, gitPath, append(base, args...)...)
	}
	w.q.Push(true)
	if out, code := git("commit", "-q", "-S", "--allow-empty", "-m", "signed by nazar"); code != 0 {
		t.Fatalf("signed commit: %d\n%s", code, out)
	}
	key, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(w.home, "allowed_signers")
	if err := os.WriteFile(allowed, []byte("test@example.invalid "+string(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, code := git("-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "HEAD"); code != 0 || !strings.Contains(out, `Good "git" signature`) {
		t.Fatalf("verify-commit: %d\n%s", code, out)
	}
	if all := w.log(); !strings.Contains(all, "decision=approved") || !strings.Contains(all, "target=ssh:gitsign") || !strings.Contains(all, `operation="sign git commit"`) {
		t.Fatalf("signing not audited:\n%s", all)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1", n)
	}
}

// TestSecretToRecordedCLIOnly: a secret added from stdin behind the login
// gate comes back through `nazar get` behind the dialog gate, and only to
// the CLI `nazar install` recorded: a copy of it that differs by one byte
// refuses itself, and a process that is not the CLI is refused by the
// agent.
func TestSecretToRecordedCLIOnly(t *testing.T) {
	const value = "nazar-e2e-value-7c1b"
	w := newWorld(t)
	w.q.Push(true)
	if out, code := w.run(value, nil, filepath.Join(bin, "nazar"), "secret", "add", "API"); code != 0 {
		t.Fatalf("secret add: exit %d\n%s", code, out)
	}
	// stdout delivery is judged on the receiver (what runs the script)
	// when the rule has a to:; without one any receiver may take it. A
	// `to: [any]` means the same and is refused as the old form.
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\nsecrets:\n  API:\n    deliver: [stdout]\n    rules:\n      - apps: [any]\n        gate: dialog\n        scope: use\n")
	w.q.Push(true)
	if out, code := w.nazar("get", "API"); code != 0 || out != value+"\n" {
		t.Fatalf("nazar get: exit %d, output %q", code, out)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1", n)
	}

	// A copy of the CLI with one more byte: not the recorded nazar. It
	// refuses itself before sending anything, and no prompt is shown.
	body, err := os.ReadFile(filepath.Join(bin, "nazar"))
	if err != nil {
		t.Fatal(err)
	}
	copyDir := filepath.Join(w.home, "copy")
	if err := os.Mkdir(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(copyDir, "nazar")
	if err := os.WriteFile(other, append(body, '\n'), 0o755); err != nil {
		t.Fatal(err)
	}
	w.q.Push(true)
	out, code := w.run("", nil, other, "get", "API")
	if code == 0 || strings.Contains(out, value) || !strings.Contains(out, "not the nazar that nazar install recorded") {
		t.Fatalf("the changed CLI: exit %d\n%s", code, out)
	}
	if allow, ok := w.q.Pop(0); !ok || !allow {
		t.Fatal("the changed CLI consumed the queued answer: a prompt was shown")
	}

	// This test process on the control socket: the agent itself refuses
	// the value to a peer that does not hash to the recorded CLI.
	c := &control.Client{Socket: layout.ControlSocket(w.home), Verifier: control.SameUserVerifier{}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var got []string
	err = c.Do(ctx, control.NewRequest(control.CmdSecretGet, map[string]string{"name": "API"}), func(kind string, raw json.RawMessage) error {
		got = append(got, kind+" "+string(raw))
		return nil
	})
	var p *control.Problem
	if !errors.As(err, &p) || !strings.Contains(p.Error(), "not the nazar CLI") || len(got) != 0 {
		t.Fatalf("secret.get from this process: err %v, replies %v; want a refusal naming the CLI check and no value", err, got)
	}
	if strings.Contains(strings.Join(got, "\n"), value) {
		t.Fatal("the value reached a process that is not the CLI")
	}
	if blocked := w.log("--decision", "blocked"); !strings.Contains(blocked, "target=secret:API") || !strings.Contains(blocked, "not the nazar CLI") {
		t.Fatalf("the refusal is not in the log:\n%s", blocked)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1: the refusals come before any prompt", n)
	}
}

// TestAlwaysAskEnforcedByNazar: a key made with --always-ask asks on the
// login gate for every signature, and nazar says it is the one enforcing
// that.
func TestAlwaysAskEnforcedByNazar(t *testing.T) {
	w := newWorld(t)
	w.q.Push(true)
	out, code := w.nazar("ssh-key", "create", "ci", "--always-ask")
	if code != 0 || !strings.Contains(out, "enforced by nazar") || strings.Contains(out, "chip") {
		t.Fatalf("ssh-key create --always-ask: exit %d\n%s", code, out)
	}
	pub := filepath.Join(layout.KeysDir(w.home), "ci.pub")
	// Only a rule that asks on every use may reach the key.
	w.approveConfig(keyConfig("ci", "login", "use", sshPath))
	out, code = w.nazar("ssh-key", "list")
	if code != 0 || !strings.Contains(out, "asks every time (nazar)") || strings.Contains(out, "chip") {
		t.Fatalf("ssh-key list: exit %d\n%s", code, out)
	}
	if out, code := w.nazar("ssh-key", "create", "--help"); code != 0 || !strings.Contains(out, "enforced by nazar") {
		t.Fatalf("ssh-key create --help: exit %d\n%s", code, out)
	}

	s := w.startSSHD(pub)
	before := len(w.pk.Messages())
	for i := 0; i < 2; i++ {
		w.q.Push(true)
		if out, code := w.ssh(s, pub, "echo nazar-ok"); code != 0 || !strings.Contains(out, "nazar-ok") {
			t.Fatalf("ssh %d: exit %d\n%s", i+1, code, out)
		}
	}
	if n := len(w.pk.Messages()) - before; n != 2 {
		t.Fatalf("%d login prompts for two signatures, want 2:\n%s", n, strings.Join(w.pk.Messages(), "\n---\n"))
	}
	if n := w.dialogs(); n != 0 {
		t.Fatalf("%d dialogs shown, want none: the key asks on the login gate", n)
	}
	// A looser rule for the key is refused, naming the enforcer.
	w.q.Push(true)
	out, code = w.nazar("ssh-key", "rule", "add", "ci", "--apps", "path:"+sshPath, "--gate", "dialog", "--scope", "session", "--allow-loosen-access")
	if code == 0 || !strings.Contains(out, "(enforced by nazar)") {
		t.Fatalf("a looser rule for the always-ask key: exit %d\n%s", code, out)
	}
	if allow, ok := w.q.Pop(0); !ok || !allow {
		t.Fatal("the refused rule consumed the queued answer: a prompt was shown")
	}
}

// TestWhenUnlockedKeyWhileLocked: a key made with --only-when-unlocked is
// refused while logind reports the screen locked, as an error and not the
// user's refusal, and works again once it is unlocked.
func TestWhenUnlockedKeyWhileLocked(t *testing.T) {
	w := newWorld(t)
	pub := w.createKey("locked", "--only-when-unlocked")
	w.approveConfig(keyConfig("locked", "dialog", "use", sshPath))
	s := w.startSSHD(pub)

	w.logind.SetLocked(true)
	w.q.Push(true) // an answer, should a dialog be shown anyway
	if out, code := w.ssh(s, pub, "echo nazar-ok"); code == 0 || strings.Contains(out, "nazar-ok") {
		t.Fatalf("ssh while locked logged in: exit %d\n%s", code, out)
	}
	w.q.Pop(0) // the answer, when no dialog took it
	errLines := w.log("--decision", "error")
	if !strings.Contains(errLines, "target=ssh:locked") || !strings.Contains(errLines, "the screen is locked") {
		t.Fatalf("the log does not say the screen is locked:\n%s\nall:\n%s", errLines, w.log())
	}
	if denied := w.log("--decision", "denied"); strings.Contains(denied, "target=ssh:locked") {
		t.Fatalf("a locked screen was logged as the user's refusal:\n%s", denied)
	}

	w.logind.SetLocked(false)
	w.q.Push(true)
	if out, code := w.ssh(s, pub, "echo nazar-ok"); code != 0 || !strings.Contains(out, "nazar-ok") {
		t.Fatalf("ssh once unlocked: exit %d\n%s", code, out)
	}
}

// installTerminalApp makes a desktop app for the test: a copy of bash
// under a name of its own (a shell by name is a launcher, no app) with a
// desktop entry in the home's applications folder. Commands run under it
// have an app in their chain, so a scope: session rule can remember them.
func installTerminalApp(w *world) {
	dir := filepath.Join(w.home, "apps")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		w.t.Fatal(err)
	}
	bash, err := os.ReadFile("/bin/bash")
	if err != nil {
		w.t.Fatal(err)
	}
	exe := filepath.Join(dir, "e2eterm")
	if err := os.WriteFile(exe, bash, 0o755); err != nil {
		w.t.Fatal(err)
	}
	// The script the app runs: a shell that reads its commands from stdin
	// (the session's root), then exit, so bash never execs over itself.
	if err := os.WriteFile(filepath.Join(dir, "session.sh"), []byte("/bin/bash\nexit $?\n"), 0o644); err != nil {
		w.t.Fatal(err)
	}
	apps := filepath.Join(w.home, ".local", "share", "applications")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		w.t.Fatal(err)
	}
	entry := "[Desktop Entry]\nType=Application\nName=E2E Terminal\nExec=" + exe + " %U\n"
	if err := os.WriteFile(filepath.Join(apps, termAppID+".desktop"), []byte(entry), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

// terminal is a shell running under the terminal app, as a tab's shell
// runs under a terminal: the test writes commands to it and reads what
// they print.
type terminal struct {
	w   *world
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

func (w *world) openTerminal() *terminal {
	w.t.Helper()
	cmd := exec.Command(filepath.Join(w.home, "apps", "e2eterm"), filepath.Join(w.home, "apps", "session.sh"))
	cmd.Env = w.env()
	in, err := cmd.StdinPipe()
	if err != nil {
		w.t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		w.t.Fatal(err)
	}
	logf, err := os.Create(filepath.Join(w.home, "terminal.log"))
	if err != nil {
		w.t.Fatal(err)
	}
	cmd.Stderr = logf
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() {
		in.Close()
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		logf.Close()
		if w.t.Failed() {
			w.t.Logf("terminal stderr:\n%s", w.read(filepath.Join(w.home, "terminal.log")))
		}
	})
	return &terminal{w: w, cmd: cmd, in: in, out: bufio.NewReader(out)}
}

// run runs one command line in the shell and returns what it printed and
// its exit code.
func (s *terminal) run(command string) (string, int) {
	s.w.t.Helper()
	if _, err := io.WriteString(s.in, command+"\necho \"RC=$?\"\n"); err != nil {
		s.w.t.Fatalf("writing to the terminal: %v", err)
	}
	type result struct {
		out  string
		code int
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var out strings.Builder
		for {
			line, err := s.out.ReadString('\n')
			if err != nil {
				ch <- result{out.String(), -1, err}
				return
			}
			if code, ok := strings.CutPrefix(line, "RC="); ok {
				var n int
				fmt.Sscanf(code, "%d", &n)
				ch <- result{out.String(), n, nil}
				return
			}
			out.WriteString(line)
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			s.w.t.Fatalf("the terminal ended: %v\n%s", r.err, r.out)
		}
		return r.out, r.code
	case <-time.After(60 * time.Second):
		s.w.t.Fatalf("the terminal did not finish %q", command)
	}
	return "", -1
}

// shellQuote quotes every argument for the shell.
func shellQuote(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// TestScreenLockEndsSessions: a session-scope approval of a terminal
// app's rule covers the next request from the same shell without a
// prompt, and logind's Lock signal ends it: the next request is asked
// again.
func TestScreenLockEndsSessions(t *testing.T) {
	w := newWorld(t, installTerminalApp)
	pub := w.createKey("term")
	// Approving a config with an app: matcher pins the installed app's
	// executable hash by the same approval.
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\napps:\n  term: {app: " + termAppID + "}\nssh_agent:\n  keys:\n    term:\n      rules:\n        - apps: [term]\n          gate: dialog\n          scope: session\n")
	if out, code := w.nazar("apps", "list"); code != 0 {
		t.Fatalf("apps list: exit %d\n%s", code, out)
	}
	s := w.startSSHD(pub)
	sh := w.openTerminal()
	ssh := shellQuote(append([]string{sshPath}, append(w.sshArgs(s, pub), "echo nazar-ok")...))

	w.q.Push(true)
	if out, code := sh.run(ssh); code != 0 || !strings.Contains(out, "nazar-ok") {
		t.Fatalf("first ssh: exit %d\n%s", code, out)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1", n)
	}
	// The same session, nothing queued: only the remembered approval can
	// let it through (a dialog would wait for an answer and time out).
	if out, code := sh.run(ssh); code != 0 || !strings.Contains(out, "nazar-ok") {
		t.Fatalf("second ssh in the session: exit %d\n%s", code, out)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown after the second ssh, want still 1", n)
	}
	if cached := w.log("--decision", "allowed"); !strings.Contains(cached, "target=ssh:term") {
		t.Fatalf("the second login was not served from the remembered approval:\n%s", w.log())
	}

	// The screen locks. The signal is delivered on its own time, so a
	// request that was still remembered is tried again until the lock has
	// ended the session.
	w.logind.EmitLock()
	prompted := false
	for i := 0; i < 50 && !prompted; i++ {
		before := w.dialogs()
		w.q.Push(true)
		if out, code := sh.run(ssh); code != 0 || !strings.Contains(out, "nazar-ok") {
			t.Fatalf("ssh after the lock: exit %d\n%s", code, out)
		}
		if w.dialogs() > before {
			prompted = true
		} else {
			w.q.Pop(0) // still remembered: the answer was not used
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !prompted {
		t.Fatalf("the lock did not end the session: no new dialog after it\n%s", w.log())
	}
	if n := w.dialogs(); n != 2 {
		t.Fatalf("%d dialogs shown in all, want 2", n)
	}
}

// TestKubectlCredential: a k8s context set up with nazar k8s ca create
// against a test API server, then the image's kubectl gets a client
// certificate through nazar's credential plugin after a dialog, and the
// server sees the context's identity.
func TestKubectlCredential(t *testing.T) {
	if _, err := os.Stat(kubectlPath); err != nil {
		t.Fatalf("no kubectl at %s, and the test image has one: %v", kubectlPath, err)
	}
	w := newWorld(t)
	srv := k8stest.Start(t, nil)
	kc := filepath.Join(w.home, "kubeconfig")
	seed := "apiVersion: v1\nkind: Config\nclusters:\n- name: hydra-admin\n  cluster:\n    server: " + srv.URL +
		"\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString(srv.CAPEM) + "\n"
	if err := os.WriteFile(kc, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	w.q.Push(true)
	out, code := w.nazar("--json", "k8s", "ca", "create", "hydra", srv.URL)
	var setup struct {
		Context struct {
			CA struct {
				CertFile string `json:"certFile"`
			} `json:"ca"`
		} `json:"context"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &setup) != nil || setup.Context.CA.CertFile == "" {
		t.Fatalf("k8s ca create: exit %d\n%s", code, out)
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
	srv.TrustClientCA(caCert)
	pin, err := cluster.PinOf(cluster.Info{Server: srv.URL, CAData: srv.CAPEM})
	if err != nil {
		t.Fatal(err)
	}
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\n" +
		"k8s:\n  contexts:\n    hydra:\n      credential: ca-cert\n      identity: {user: admin, groups: [system:masters]}\n" +
		"      cluster: {server: " + fmt.Sprintf("%q", pin.Server) + ", ca_sha256: " + pin.CASHA256 + "}\n" +
		"      scope: use\n      gate: dialog\n")

	// kubectl runs the exec entry ca create added to the kubeconfig: the
	// nazartest CLI, which reaches this agent through NAZAR_TEST_CONTROL_SOCKET.
	w.q.Push(true)
	out, code = w.run("", nil, kubectlPath, "--kubeconfig", kc, "--context", "hydra", "--request-timeout=30s", "get", "--raw", "/api/v1/namespaces/default/pods")
	if code != 0 || !strings.Contains(out, "web-1") || !strings.Contains(out, `"k8stest/user":"admin"`) {
		t.Fatalf("kubectl: exit %d\n%s", code, out)
	}
	seen := srv.Seen()
	if len(seen) == 0 {
		t.Fatal("the server saw no request")
	}
	last := seen[len(seen)-1]
	if !last.Verified || last.CN != "admin" || strings.Join(last.O, ",") != "system:masters" {
		t.Fatalf("the server saw %+v, want a verified certificate for admin in system:masters", last)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1", n)
	}
	if approved := w.log("--decision", "approved"); !strings.Contains(approved, "target=k8s:hydra") || !strings.Contains(approved, "kubectl") {
		t.Fatalf("the credential is not in the log with kubectl as the receiver:\n%s", approved)
	}
}

// TestRunRefusedOnLinux: nazar run is not in Linux v1; the CLI refuses it
// before the agent is asked, so no prompt is shown and no answer used.
func TestRunRefusedOnLinux(t *testing.T) {
	w := newWorld(t)
	w.q.Push(true)
	out, code := w.nazar("run", "--secret", "API", "--", "/bin/true")
	if code != 1 || !strings.Contains(out, "nazar run is not available on Linux yet") {
		t.Fatalf("nazar run: exit %d\n%s", code, out)
	}
	if allow, ok := w.q.Pop(0); !ok || !allow {
		t.Fatal("nazar run consumed the queued answer: a prompt was shown")
	}
	if n := w.dialogs(); n != 0 {
		t.Fatalf("%d dialogs shown, want none", n)
	}
	if all := w.log(); strings.Contains(all, "secret:API") {
		t.Fatalf("the refused run reached the agent:\n%s", all)
	}
}

// TestKubectlSurvivesUpgrade: the kubeconfig `nazar k8s ca create` writes
// names the path the user ran nazar by, install.sh's link
// ~/.local/bin/nazar, not the versioned file /proc/self/exe resolves to.
// An upgrade then lays out a new version, moves the link, removes the old
// folder and records the new hashes, as install.sh and `nazar install` do,
// and kubectl keeps working with no edit to the kubeconfig. The agent is
// byte-identical across this upgrade (the CLI is what changed), so the
// running agent still matches the record.
func TestKubectlSurvivesUpgrade(t *testing.T) {
	if _, err := os.Stat(kubectlPath); err != nil {
		t.Fatalf("no kubectl at %s, and the test image has one: %v", kubectlPath, err)
	}
	w := newWorld(t)
	lib := filepath.Join(w.home, ".local", "lib", "nazar")
	binDir := filepath.Join(w.home, ".local", "bin")
	link := filepath.Join(binDir, "nazar")
	cliBody, err := os.ReadFile(filepath.Join(bin, "nazar"))
	if err != nil {
		t.Fatal(err)
	}
	agentBody, err := os.ReadFile(filepath.Join(bin, "nazar-agent"))
	if err != nil {
		t.Fatal(err)
	}
	// install lays one version out as install.sh does, and records it as
	// `nazar install` does.
	install := func(version string, cli []byte) string {
		t.Helper()
		dir := filepath.Join(lib, version)
		for _, d := range []string{dir, binDir} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		rec := peertrust.Record{}
		for _, b := range []struct {
			name string
			body []byte
			bin  *peertrust.Binary
		}{{"nazar", cli, &rec.CLI}, {"nazar-agent", agentBody, &rec.Agent}} {
			p := filepath.Join(dir, b.name)
			if err := os.WriteFile(p, b.body, 0o755); err != nil {
				t.Fatal(err)
			}
			sum, err := peertrust.HashFile(p)
			if err != nil {
				t.Fatal(err)
			}
			*b.bin = peertrust.Binary{Path: p, SHA256: sum}
		}
		os.Remove(link)
		if err := os.Symlink(filepath.Join(dir, "nazar"), link); err != nil {
			t.Fatal(err)
		}
		if err := peertrust.Write(w.home, rec); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	old := install("1.0.0", cliBody)
	// The CLI as the user runs it: `nazar`, found on PATH through the link.
	viaPath := func(args ...string) (string, int) {
		t.Helper()
		return w.run("", []string{"PATH=" + binDir + ":/usr/bin:/bin:/usr/local/bin"},
			"/bin/sh", append([]string{"-c", `exec nazar "$@"`, "sh"}, args...)...)
	}

	srv := k8stest.Start(t, nil)
	kc := filepath.Join(w.home, "kubeconfig")
	seed := "apiVersion: v1\nkind: Config\nclusters:\n- name: hydra-admin\n  cluster:\n    server: " + srv.URL +
		"\n    certificate-authority-data: " + base64.StdEncoding.EncodeToString(srv.CAPEM) + "\n"
	if err := os.WriteFile(kc, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	w.q.Push(true)
	out, code := viaPath("--json", "k8s", "ca", "create", "hydra", srv.URL)
	var setup struct {
		Context struct {
			CA struct {
				CertFile string `json:"certFile"`
			} `json:"ca"`
		} `json:"context"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &setup) != nil || setup.Context.CA.CertFile == "" {
		t.Fatalf("k8s ca create: exit %d\n%s", code, out)
	}
	conf := w.read(kc)
	if !strings.Contains(conf, link) || strings.Contains(conf, old) {
		t.Fatalf("the kubeconfig must name the link %s, never the versioned file under %s:\n%s", link, old, conf)
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
	srv.TrustClientCA(caCert)
	pin, err := cluster.PinOf(cluster.Info{Server: srv.URL, CAData: srv.CAPEM})
	if err != nil {
		t.Fatal(err)
	}
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\n" +
		"k8s:\n  contexts:\n    hydra:\n      credential: ca-cert\n      identity: {user: admin, groups: [system:masters]}\n" +
		"      cluster: {server: " + fmt.Sprintf("%q", pin.Server) + ", ca_sha256: " + pin.CASHA256 + "}\n" +
		"      scope: use\n      gate: dialog\n")
	kubectl := func(when string) {
		t.Helper()
		w.q.Push(true)
		out, code := w.run("", nil, kubectlPath, "--kubeconfig", kc, "--context", "hydra", "--request-timeout=30s", "get", "--raw", "/api/v1/namespaces/default/pods")
		if code != 0 || !strings.Contains(out, `"k8stest/user":"admin"`) {
			t.Fatalf("kubectl %s: exit %d\n%s", when, code, out)
		}
	}
	kubectl("before the upgrade")

	// The upgrade: a new version whose CLI differs by a byte, the link
	// moved to it, the old folder gone, the record rewritten.
	install("1.0.1", append(slices.Clone(cliBody), '\n'))
	if err := os.RemoveAll(old); err != nil {
		t.Fatal(err)
	}
	if out, code := viaPath("ssh-key", "list"); code != 0 {
		t.Fatalf("the upgraded nazar: exit %d\n%s", code, out)
	}
	kubectl("after the upgrade")
	if n := w.dialogs(); n != 2 {
		t.Fatalf("%d dialogs shown, want 2", n)
	}
}
