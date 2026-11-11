//go:build integration

// Package integration drives real /usr/bin/ssh, /usr/sbin/sshd, ssh-add,
// ssh-keygen and git against nazar-testd (the core on the fake platform with
// a software P-256 key). Every ssh runs with -F /dev/null and throwaway files
// in a temp dir; nothing reads or writes ~/.ssh, ~/.gitconfig or the
// Keychain, and nothing can raise an authentication, Keychain or TCC prompt.
//
// The CLI is the nazartest build: its k8s credential dials
// NAZAR_TEST_CONTROL_SOCKET, which env sets to the world's socket, so no
// test can reach the account's nazar-agent through it (the release
// build's dials the passwd home's socket whatever the environment says).
package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/internal/linuxtest/container"
)

var bin string // directory with nazar, nazar-testd and the nazar-sign-git link

var repo string // the repository's root, where says reads the docs

// started records every long-running process the tests start (nazar-testd,
// sshd) and every temp home, so TestMain can prove
// that nothing is left behind.
var started struct {
	sync.Mutex
	procs []*exec.Cmd
	dirs  []string
}

func track(cmd *exec.Cmd) {
	started.Lock()
	started.procs = append(started.procs, cmd)
	started.Unlock()
}

func trackDir(d string) {
	started.Lock()
	started.dirs = append(started.dirs, d)
	started.Unlock()
}

func TestMain(m *testing.M) {
	if why := skipReason(runtime.GOOS, container.Check); why != "" {
		fmt.Println(why)
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("/tmp", "nzbin")
	if err != nil {
		panic(err)
	}
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..")
	repo = root
	for _, b := range [][3]string{{"nazar", "./cmd/nazar", "nazartest"}, {"nazar-testd", "./internal/cmd/nazar-testd", ""}} {
		cmd := exec.Command("go", "build", "-tags", b[2], "-o", filepath.Join(dir, b[0]), b[1])
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("build %s: %v\n%s", b[0], err, out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "nazar"), filepath.Join(dir, "nazar-sign-git")); err != nil {
		fmt.Printf("symlink nazar-sign-git: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	bin = dir
	code := m.Run()
	os.RemoveAll(dir)

	// Nothing the tests started may outlive them.
	started.Lock()
	defer started.Unlock()
	for _, c := range started.procs {
		if c.Process != nil && c.ProcessState == nil {
			fmt.Printf("process %d (%s) was never waited for\n", c.Process.Pid, c.Path)
			c.Process.Kill()
			code = 1
		}
	}
	for _, d := range started.dirs {
		if _, err := os.Lstat(d); err == nil {
			fmt.Printf("temp dir %s was left behind\n", d)
			os.RemoveAll(d)
			code = 1
		}
	}
	os.Exit(code)
}

// skipReason says why the suite does not run on goos, or "" when it does:
// on macOS always, on Linux only inside nazar's test container (check is
// container.Check), where sshd, ssh and git are the image's and nothing
// reaches the host. Anywhere else the suite prints the reason and exits 0,
// as it always has. nazar-testd's fake platform has macOS traits on Linux
// too (signed: rules pass, say), so a Linux run covers real ssh, sshd and
// git, not Linux gating or wording.
func skipReason(goos string, check func() error) string {
	switch goos {
	case "darwin":
		return ""
	case "linux":
		if err := check(); err != nil {
			return "integration tests need macOS, or Linux in the test container: " + err.Error()
		}
		return ""
	}
	return "integration tests need macOS"
}

// world is one test's home directory, nazar-testd and (optionally) sshd.
type world struct {
	t       *testing.T
	home    string
	script  string
	audit   string
	kh      string // the known_hosts file nazar names destinations from
	sock    string // agent socket
	ctlSock string
	daemon  *exec.Cmd
}

func newWorld(t *testing.T, script string) *world {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "nzit") // short: sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	trackDir(home)
	w := &world{t: t, home: home, script: filepath.Join(home, "script.json"), audit: filepath.Join(home, "audit.log"),
		kh: filepath.Join(home, "known_hosts"), sock: layout.AgentSocket(home), ctlSock: layout.ControlSocket(home)}
	w.setScript(script)
	if err := os.WriteFile(w.kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w.daemon = exec.Command(filepath.Join(bin, "nazar-testd"), "-home", home, "-script", w.script, "-audit", w.audit, "-known-hosts", w.kh, "-timeout", "3s")
	w.daemon.Env = w.env()
	logf, err := os.Create(filepath.Join(home, "testd.log"))
	if err != nil {
		t.Fatal(err)
	}
	w.daemon.Stdout, w.daemon.Stderr = logf, logf
	if err := w.daemon.Start(); err != nil {
		t.Fatal(err)
	}
	track(w.daemon)
	t.Cleanup(func() {
		w.daemon.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { w.daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			w.daemon.Process.Kill()
			<-done
		}
		logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(home, "testd.log"))
			t.Logf("nazar-testd log:\n%s", b)
			a, _ := os.ReadFile(w.audit)
			t.Logf("audit:\n%s", a)
		}
		os.RemoveAll(home)
	})
	w.waitFor(func() bool { _, err := os.Stat(w.sock); return err == nil })
	w.waitFor(func() bool { _, err := os.Stat(w.ctlSock); return err == nil })
	return w
}

func (w *world) setScript(s string) {
	if err := os.WriteFile(w.script, []byte(s), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) waitFor(cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			w.t.Fatal("timed out waiting")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// worldPath is the PATH of a world's commands. The test image keeps kubectl
// in /usr/local/bin (test/linux/Dockerfile), where a Mac's PATH here does not
// look.
func worldPath(goos string) string {
	if goos == "linux" {
		return "/usr/bin:/bin:/usr/sbin:/usr/local/bin"
	}
	return "/usr/bin:/bin:/usr/sbin:/opt/homebrew/bin"
}

// findKubectl is the kubectl a world with this PATH runs, or "".
func findKubectl(path string) string {
	for _, d := range filepath.SplitList(path) {
		if fi, err := os.Stat(filepath.Join(d, "kubectl")); err == nil && fi.Mode().IsRegular() {
			return filepath.Join(d, "kubectl")
		}
	}
	return ""
}

// noKubectlFails says whether a run with no kubectl is a failure rather than
// an untested step: a Mac may not have it, but on Linux the suite runs only in
// the test image, which installs it (skipReason).
func noKubectlFails(goos string) bool { return goos == "linux" }

// env is a minimal environment: HOME is the test home, no SSH_AUTH_SOCK,
// git ignores the user's global and system config, both control sockets
// are the world's and KUBECONFIG is in the world's home, never ~/.kube.
func (w *world) env(extra ...string) []string {
	return append([]string{"HOME=" + w.home, "PATH=" + worldPath(runtime.GOOS), "NAZAR_CONTROL_SOCKET=" + w.ctlSock,
		"NAZAR_TEST_CONTROL_SOCKET=" + w.ctlSock, "KUBECONFIG=" + filepath.Join(w.home, "kubeconfig"),
		"NAZAR_TEST_PEER=same-user", // nazar-testd is not Nazar.app
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C"}, extra...)
}

// nazar runs the CLI and returns stdout+stderr and the exit code. stdin is
// a pipe that is never written, so any attempt to prompt would hang the
// test.
func (w *world) nazar(args ...string) (string, int) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(bin, "nazar"), args...)
	cmd.Env = w.env()
	stdin, _ := cmd.StdinPipe()
	defer stdin.Close()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		w.t.Fatalf("nazar %v hung (stderr %s)", args, errb.String())
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		w.t.Fatal(err)
	}
	return out.String() + errb.String(), code
}

func (w *world) configPath() string {
	return layout.ConfigFile(w.home)
}

func (w *world) writeConfig(body string) {
	p := w.configPath()
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) readConfig() string {
	b, _ := os.ReadFile(w.configPath())
	return string(b)
}

// auditLines returns the audit lines so far.
func (w *world) auditLines() []string {
	b, _ := os.ReadFile(w.audit)
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func lineHas(l string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(l, p) {
			return false
		}
	}
	return true
}

func (w *world) auditHas(parts ...string) bool {
	return w.auditCount(parts...) > 0
}

// auditCount is the number of audit lines containing every part.
func (w *world) auditCount(parts ...string) int {
	n := 0
	for _, l := range w.auditLines() {
		if lineHas(l, parts) {
			n++
		}
	}
	return n
}

func (w *world) auditDump() string {
	return strings.Join(w.auditLines(), "\n")
}

// auditFields splits one audit line into its key=value fields as spec 4.6
// writes them: values are bare words or Go-quoted strings. A leading
// timestamp (the test sink's stand-in for the log's own) is skipped. A line
// that does not split cleanly fails the test: every line must be
// machine-readable.
func auditFields(t *testing.T, line string) [][2]string {
	t.Helper()
	var out [][2]string
	s := line
	if sp := strings.IndexByte(s, ' '); sp > 0 && !strings.Contains(s[:sp], "=") {
		s = s[sp+1:]
	}
	for len(s) > 0 {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || strings.ContainsAny(s[:eq], " \"") {
			t.Fatalf("audit line does not split into fields at %q: %s", s, line)
		}
		key := s[:eq]
		s = s[eq+1:]
		var val string
		if strings.HasPrefix(s, `"`) {
			end := 1
			for ; end < len(s); end++ {
				if s[end] == '\\' {
					end++
					continue
				}
				if s[end] == '"' {
					break
				}
			}
			if end >= len(s) {
				t.Fatalf("unterminated quoted value in audit line: %s", line)
			}
			v, err := strconv.Unquote(s[:end+1])
			if err != nil {
				t.Fatalf("bad quoted value %q in audit line: %v", s[:end+1], err)
			}
			val, s = v, s[end+1:]
		} else {
			sp := strings.IndexByte(s, ' ')
			if sp < 0 {
				sp = len(s)
			}
			val, s = s[:sp], s[sp:]
		}
		out = append(out, [2]string{key, val})
		if len(s) > 0 {
			if s[0] != ' ' {
				t.Fatalf("audit value not followed by a space at %q: %s", s, line)
			}
			s = s[1:]
		}
	}
	return out
}

// createKey makes key `name` through the CLI (the login gate is allowed by
// the script) and returns the .pub path. With no entry in config.yaml the
// agent writes one for the scripted chain's app (iTerm2 or Terminal: a
// login rule with scope session) or, for the unknown chain, gate block
// alone; tests that need other rules approve a config next.
func (w *world) createKey(name string) string {
	w.t.Helper()
	out, code := w.nazar("--json", "ssh-key", "create", name)
	if code != 0 {
		w.t.Fatalf("create: exit %d %s", code, out)
	}
	var k map[string]any
	if err := json.Unmarshal([]byte(out), &k); err != nil || k["kind"] != "SSHKey" || k["apiVersion"] != "nazar/v1" {
		w.t.Fatalf("create output %q", out)
	}
	return filepath.Join(layout.KeysDir(w.home), name+".pub")
}

// activeHash is the hash of the config Nazar is enforcing now. The world's
// status has no client-side finding: its HOME is not the account's, so
// ssh (which reads the account's ~/.ssh/config, whatever HOME says) is
// never run, and git and SSH_AUTH_SOCK are the world's own (env). A
// finding here is the developer's own setup leaking into the test.
func (w *world) activeHash() string {
	w.t.Helper()
	out, code := w.nazar("--json", "status")
	if code != 0 {
		w.t.Fatalf("status: exit %d %s", code, out)
	}
	var st struct {
		ActiveHash string            `json:"activeHash"`
		Setup      []json.RawMessage `json:"setup"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		w.t.Fatalf("status output %q: %v", out, err)
	}
	if len(st.Setup) != 0 {
		w.t.Fatalf("status reports the developer's setup, not the test world's: %s", out)
	}
	return st.ActiveHash
}

// approveConfig writes body and waits until Nazar enforces it: the active
// config changed and nothing is staged (the script must allow the login
// gate). Waiting for the active hash to move avoids passing before the
// daemon has even noticed the new file.
func (w *world) approveConfig(body string) {
	w.t.Helper()
	before := w.activeHash()
	w.writeConfig(body)
	w.waitFor(func() bool {
		out, code := w.nazar("--json", "config", "check")
		return code == 0 && !strings.Contains(out, `"staged"`) && w.activeHash() != before
	})
}

// sshd is a user-level sshd on 127.0.0.1 that trusts pubFile.
type sshd struct {
	port    int
	cmd     *exec.Cmd
	hostPub string // host public key file
}

func (w *world) startSSHD(pubFile string) *sshd {
	w.t.Helper()
	if _, err := os.Stat("/usr/sbin/sshd"); err != nil {
		w.t.Skip("no /usr/sbin/sshd")
	}
	d := filepath.Join(w.home, "sshd")
	os.MkdirAll(d, 0o700)
	hostKey := filepath.Join(d, "host_ed25519")
	if out, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey).CombinedOutput(); err != nil {
		w.t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	pub, err := os.ReadFile(pubFile)
	if err != nil {
		w.t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "authorized_keys"), pub, 0o600)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cfg := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s\nPidFile %s\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAllowAgentForwarding yes\nPerSourcePenalties no\nMaxStartups 100\n",
		port, hostKey, filepath.Join(d, "authorized_keys"), filepath.Join(d, "sshd.pid"))
	os.WriteFile(filepath.Join(d, "sshd_config"), []byte(cfg), 0o600)
	// PerSourcePenalties (OpenSSH 9.8 and later) keeps sshd from refusing
	// the tests' many quick logins. An older sshd (Debian bookworm's 9.2,
	// in the Linux test image) has no penalties and rejects the option as
	// unknown, so there it goes.
	if out, err := exec.Command("/usr/sbin/sshd", "-t", "-f", filepath.Join(d, "sshd_config")).CombinedOutput(); err != nil &&
		bytes.Contains(out, []byte("Bad configuration option: PerSourcePenalties")) {
		cfg = strings.Replace(cfg, "PerSourcePenalties no\n", "", 1)
		os.WriteFile(filepath.Join(d, "sshd_config"), []byte(cfg), 0o600)
	}
	s := &sshd{port: port, hostPub: hostKey + ".pub", cmd: exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", filepath.Join(d, "sshd_config"))}
	logf, _ := os.Create(filepath.Join(d, "sshd.log"))
	s.cmd.Stdout, s.cmd.Stderr = logf, logf
	if err := s.cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	track(s.cmd)
	w.t.Cleanup(func() {
		s.cmd.Process.Kill()
		s.cmd.Wait()
		logf.Close()
		if w.t.Failed() {
			b, _ := os.ReadFile(filepath.Join(d, "sshd.log"))
			w.t.Logf("sshd log:\n%s", b)
		}
	})
	w.waitFor(func() bool {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			c.Close()
		}
		return err == nil
	})
	hostPub, _ := os.ReadFile(s.hostPub)
	os.WriteFile(w.kh, []byte(fmt.Sprintf("[127.0.0.1]:%d %s", port, hostPub)), 0o600)
	return s
}

// hostFingerprint is the SHA256 fingerprint of the sshd's host key, as
// ssh-keygen -l prints it.
func (s *sshd) hostFingerprint(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/ssh-keygen", "-l", "-E", "sha256", "-f", s.hostPub).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -l: %v %s", err, out)
	}
	f := strings.Fields(string(out))
	if len(f) < 2 || !strings.HasPrefix(f[1], "SHA256:") {
		t.Fatalf("ssh-keygen -l output %q", out)
	}
	return f[1]
}

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

// sshOpts changes one ssh invocation.
type sshOpts struct {
	knownHosts string   // UserKnownHostsFile; default w.kh
	agent      string   // IdentityAgent; default w.sock
	extra      []string // more options before the destination
}

// sshArgs are the /usr/bin/ssh arguments for logging in to s with only the
// nazar key: -F /dev/null, throwaway known_hosts, never interactive.
func (w *world) sshArgs(s *sshd, pubFile string, o sshOpts) []string {
	kh := o.knownHosts
	if kh == "" {
		kh = w.kh
	}
	agent := o.agent
	if agent == "" {
		agent = w.sock
	}
	args := []string{"-F", "/dev/null", "-T",
		"-o", "IdentityAgent=" + agent, "-o", "IdentitiesOnly=yes", "-i", pubFile,
		"-o", "UserKnownHostsFile=" + kh, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ConnectTimeout=10",
		"-p", fmt.Sprint(s.port)}
	return append(args, o.extra...)
}

// ssh runs /usr/bin/ssh -F /dev/null against the test sshd with only the
// nazar key and returns combined output and exit code.
func (w *world) ssh(s *sshd, pubFile string, command string) (string, int) {
	w.t.Helper()
	return w.sshWith(s, pubFile, sshOpts{}, command)
}

func (w *world) sshWith(s *sshd, pubFile string, o sshOpts, command string) (string, int) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append(w.sshArgs(s, pubFile, o), currentUser(w.t)+"@127.0.0.1", command)
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh", args...)
	cmd.Env = w.env()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		w.t.Fatalf("ssh hung: %s", out)
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		w.t.Fatal(err)
	}
	return string(out), code
}

// run runs a program with the world's environment plus extra and returns
// combined output and exit code. stdin is empty, so nothing can prompt.
func (w *world) run(extra []string, name string, args ...string) (string, int) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = w.env(extra...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		w.t.Fatalf("%s %v hung: %s", name, args, out)
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		w.t.Fatal(err)
	}
	return string(out), code
}
