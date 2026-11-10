package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/unixsock"
)

// `nazar k8s credential <context>` (k8s design 1.1, 7) is client-go's
// exec plugin. It reads KUBERNETES_EXEC_INFO and nothing else from its
// environment, dials <passwd home>/.nazar/run/control.sock, and writes exactly
// the ExecCredential to stdout; on failure one line to stderr.

const execInfoJSON = `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"cluster":{"server":"https://hydra.example:16443"},"interactive":false}}`

var credExp = time.Date(2026, 10, 18, 0, 15, 0, 0, time.UTC)

// passwdServer runs a stub nazar-agent at <dir>/.nazar/run/control.sock that
// answers k8s.credential with reply (nil: a credential).
func passwdServer(t *testing.T, reply *control.Problem) (dir string, reqs *[]control.Request, dials *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzpw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.MkdirAll(layout.Root(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := unixsock.Listen(layout.ControlSocket(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var got []control.Request
	var n atomic.Int32
	srv := &control.Server{Resolve: func(int) *caller.Chain { n.Add(1); return &caller.Chain{} }, Handler: handlerFunc(func(_ context.Context, req control.Request, out control.Emitter) {
		got = append(got, req)
		if reply != nil {
			_ = out.Emit(reply)
			return
		}
		_ = out.Emit(control.K8sCredential{TypeMeta: control.Meta(control.KindK8sCredential), Name: req.Args["name"],
			ClientCertificateData: "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
			ClientKeyData:         "-----BEGIN EC PRIVATE KEY-----\nKEY\n-----END EC PRIVATE KEY-----\n",
			ExpirationTimestamp:   credExp})
	})}
	go func() { _ = srv.Serve(l) }()
	return dir, &got, &n
}

// decoySocket listens where an attacker-written env: block points and
// counts every connection.
func decoySocket(t *testing.T, path string) *atomic.Int32 {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	return &n
}

func credHarness(t *testing.T, reply *control.Problem) (*harness, *[]control.Request, *atomic.Int32) {
	t.Helper()
	h := newHarness(t)
	dir, reqs, dials := passwdServer(t, reply)
	h.a.accountHome = func() string { return dir }
	h.env["KUBERNETES_EXEC_INFO"] = execInfoJSON
	return h, reqs, dials
}

func TestK8sCredentialCLI(t *testing.T) {
	h, reqs, _ := credHarness(t, nil)
	if code := h.run("k8s", "credential", "hydra"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.errb)
	}
	want, err := k8s.EncodeExecCredential([]byte("-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN EC PRIVATE KEY-----\nKEY\n-----END EC PRIVATE KEY-----\n"), credExp)
	if err != nil {
		t.Fatal(err)
	}
	if h.out.String() != string(want) || h.errb.Len() != 0 {
		t.Fatalf("stdout must be exactly the ExecCredential:\n%q\nstderr %q", h.out, h.errb)
	}
	if len(*reqs) != 1 || (*reqs)[0].Command != control.CmdK8sCredential || (*reqs)[0].Args["name"] != "hydra" || (*reqs)[0].Args["execInfo"] != execInfoJSON {
		t.Fatalf("request %+v", *reqs)
	}

	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		code int
	}{
		"no exec info":   {[]string{"k8s", "credential", "hydra"}, map[string]string{"KUBERNETES_EXEC_INFO": ""}, control.ExitUsage},
		"too large":      {[]string{"k8s", "credential", "hydra"}, map[string]string{"KUBERNETES_EXEC_INFO": strings.Repeat("x", k8s.MaxExecInfo+1)}, control.ExitUsage},
		"invalid name":   {[]string{"k8s", "credential", "a/b"}, nil, control.ExitUsage},
		"no name":        {[]string{"k8s", "credential"}, nil, control.ExitUsage},
		"two names":      {[]string{"k8s", "credential", "a", "b"}, nil, control.ExitUsage},
		"--json":         {[]string{"--json", "k8s", "credential", "hydra"}, nil, control.ExitUsage},
		"unknown option": {[]string{"k8s", "credential", "--x", "hydra"}, nil, control.ExitUsage},
	} {
		h, reqs, dials := credHarness(t, nil)
		for k, v := range tc.env {
			h.env[k] = v
		}
		if code := h.run(tc.args...); code != tc.code {
			t.Errorf("%s: exit %d, want %d", name, code, tc.code)
		}
		if h.out.Len() != 0 || len(*reqs) != 0 || dials.Load() != 0 {
			t.Errorf("%s: nothing sent, nothing on stdout: %q, %d requests", name, h.out, len(*reqs))
		}
		if lines := strings.Count(h.errb.String(), "\n"); lines != 1 || !strings.HasPrefix(h.errb.String(), "nazar: ") {
			t.Errorf("%s: exactly one stderr line (kubectl shows it): %q", name, h.errb)
		}
	}

	// Refused by nazar-agent: exit 3, one line, nothing on stdout.
	h, _, _ = credHarness(t, control.NewProblem(control.CodeRefused, "refused: the program that ran nazar can't be identified"))
	if code := h.run("k8s", "credential", "hydra"); code != control.ExitRefused || h.out.Len() != 0 || h.errb.String() != "nazar: refused: the program that ran nazar can't be identified\n" {
		t.Fatalf("refused: exit %d, out %q, err %q", code, h.out, h.errb)
	}
	// nazar-agent not running: exit 5.
	h = newHarness(t)
	dir := t.TempDir()
	h.a.accountHome = func() string { return dir }
	h.env["KUBERNETES_EXEC_INFO"] = execInfoJSON
	if code := h.run("k8s", "credential", "hydra"); code != control.ExitUnavailable || h.out.Len() != 0 || strings.Count(h.errb.String(), "\n") != 1 {
		t.Fatalf("not running: exit %d, err %q", code, h.errb)
	}
}

func TestK8sCredentialRefusesAMalformedReply(t *testing.T) {
	h := newHarness(t)
	dir, err := os.MkdirTemp("/tmp", "nzpw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.MkdirAll(layout.Root(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := unixsock.Listen(layout.ControlSocket(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := &control.Server{Resolve: func(int) *caller.Chain { return &caller.Chain{} }, Handler: handlerFunc(func(_ context.Context, _ control.Request, out control.Emitter) {
		_ = out.Emit(control.K8sCredential{TypeMeta: control.Meta(control.KindK8sCredential), Name: "hydra", ClientKeyData: "KEY"})
	})}
	go func() { _ = srv.Serve(l) }()
	h.a.accountHome = func() string { return dir }
	h.env["KUBERNETES_EXEC_INFO"] = execInfoJSON
	if code := h.run("k8s", "credential", "hydra"); code != control.ExitError || h.out.Len() != 0 {
		t.Fatalf("a reply without a certificate: exit %d, out %q", code, h.out)
	}
}

// client-go passes the kubeconfig's exec env: entries to the plugin, so
// HOME, NAZAR_CONTROL_SOCKET, NAZAR_CONFIG and NAZAR_TEST_PEER are
// attacker-writable there: the plugin ignores them all (k8s design 1.1).
func TestK8sCredentialIgnoresTheEnvironment(t *testing.T) {
	h, reqs, dials := credHarness(t, nil)
	// A short dir: macOS limits a unix socket path to 104 bytes.
	decoy, err := os.MkdirTemp("/tmp", "nzk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(decoy) })
	homeDials := decoySocket(t, layout.ControlSocket(decoy))
	sockDials := decoySocket(t, filepath.Join(decoy, "sock"))
	h.env["HOME"] = decoy
	h.env["NAZAR_CONTROL_SOCKET"] = filepath.Join(decoy, "sock")
	h.env["NAZAR_CONFIG"] = filepath.Join(decoy, "config.yaml")
	h.env["NAZAR_TEST_CONTROL_SOCKET"] = filepath.Join(decoy, "sock") // only the nazartest build reads it
	if code := h.run("k8s", "credential", "hydra"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.errb)
	}
	if dials.Load() != 1 || len(*reqs) != 1 || homeDials.Load() != 0 || sockDials.Load() != 0 {
		t.Fatalf("the passwd home's socket must be dialled, and nothing else: %d %d %d", dials.Load(), homeDials.Load(), sockDials.Load())
	}
	// NAZAR_TEST_PEER=same-user does not drop the agent's signature check:
	// without a test verifier the release check runs (and refuses off
	// macOS), and no warning about the variable is printed.
	h, reqs, _ = credHarness(t, nil)
	h.a.verifier = nil
	h.env["NAZAR_TEST_PEER"] = "same-user"
	if code := h.run("k8s", "credential", "hydra"); code == control.ExitOK || len(*reqs) != 0 || strings.Contains(h.errb.String(), "NAZAR_TEST_PEER") {
		t.Fatalf("NAZAR_TEST_PEER must be ignored: exit %d, %d requests, err %q", code, len(*reqs), h.errb)
	}
	// The passwd lookup failing, or giving a relative or empty home: exit 1,
	// no dial anywhere.
	// (The user database's home is the one accountHome reads for the ssh
	// checks; "" is a failed lookup.)
	for name, look := range map[string]func() string{
		"failed":   func() string { return "" },
		"relative": func() string { return "home/u" },
	} {
		h, reqs, dials := credHarness(t, nil)
		h.a.accountHome = look
		h.env["HOME"] = decoy
		if code := h.run("k8s", "credential", "hydra"); code != control.ExitError || len(*reqs) != 0 || dials.Load() != 0 ||
			homeDials.Load() != 0 || h.errb.String() != "nazar: cannot find your home directory\n" {
			t.Fatalf("%s: exit %d, err %q", name, code, h.errb)
		}
	}
}

// The release build carries no test socket (k8s design 11, "release
// check"): k8scred_testsock.go is compiled only with -tags nazartest.
func TestReleaseBuildHasNoTestSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	list := func(tags ...string) string {
		args := append([]string{"list"}, tags...)
		args = append(args, "-f", "{{.GoFiles}}", ".")
		out, err := exec.Command("go", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		return string(out)
	}
	if strings.Contains(list(), "k8scred_testsock.go") || !strings.Contains(list("-tags", "nazartest"), "k8scred_testsock.go") {
		t.Fatal("k8scred_testsock.go must be in the nazartest build only")
	}
	build := func(tags ...string) []byte {
		bin := filepath.Join(t.TempDir(), "nazar")
		args := append([]string{"build"}, tags...)
		args = append(args, "-o", bin, ".")
		if out, err := exec.Command("go", args...).CombinedOutput(); err != nil {
			t.Fatalf("go build: %v\n%s", err, out)
		}
		b, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if bytes.Contains(build(), []byte("NAZAR_TEST_CONTROL_SOCKET")) {
		t.Fatal("the release build contains NAZAR_TEST_CONTROL_SOCKET")
	}
	if !bytes.Contains(build("-tags", "nazartest"), []byte("NAZAR_TEST_CONTROL_SOCKET")) {
		t.Fatal("the check must see the string in the nazartest build")
	}
}

// The release build has no way past the refusal of nazar run on Linux:
// run_testlinux.go is compiled only with -tags nazartest.
func TestReleaseBuildHasNoRunOnLinux(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	list := func(tags ...string) string {
		args := append([]string{"list"}, tags...)
		args = append(args, "-f", "{{.GoFiles}}", ".")
		out, err := exec.Command("go", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, out)
		}
		return string(out)
	}
	if strings.Contains(list(), "run_testlinux.go") || !strings.Contains(list("-tags", "nazartest"), "run_testlinux.go") {
		t.Fatal("run_testlinux.go must be in the nazartest build only")
	}
	build := func(tags ...string) []byte {
		bin := filepath.Join(t.TempDir(), "nazar")
		args := append([]string{"build"}, tags...)
		args = append(args, "-o", bin, ".")
		if out, err := exec.Command("go", args...).CombinedOutput(); err != nil {
			t.Fatalf("go build: %v\n%s", err, out)
		}
		b, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if bytes.Contains(build(), []byte("NAZAR_TEST_RUN_ON_LINUX")) {
		t.Fatal("the release build contains NAZAR_TEST_RUN_ON_LINUX")
	}
	if !bytes.Contains(build("-tags", "nazartest"), []byte("NAZAR_TEST_RUN_ON_LINUX")) {
		t.Fatal("the check must see the string in the nazartest build")
	}
}

// Security review: a reply for another context is not passed on.
func TestK8sCredentialRefusesAReplyForAnotherContext(t *testing.T) {
	h := newHarness(t)
	dir, err := os.MkdirTemp("/tmp", "nzpw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.MkdirAll(layout.Root(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := unixsock.Listen(layout.ControlSocket(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := &control.Server{Resolve: func(int) *caller.Chain { return &caller.Chain{} }, Handler: handlerFunc(func(_ context.Context, _ control.Request, out control.Emitter) {
		_ = out.Emit(control.K8sCredential{TypeMeta: control.Meta(control.KindK8sCredential), Name: "staging",
			ClientCertificateData: "C", ClientKeyData: "K", ExpirationTimestamp: credExp})
	})}
	go func() { _ = srv.Serve(l) }()
	h.a.accountHome = func() string { return dir }
	h.env["KUBERNETES_EXEC_INFO"] = execInfoJSON
	if code := h.run("k8s", "credential", "hydra"); code != control.ExitError || h.out.Len() != 0 {
		t.Fatalf("exit %d, out %q", code, h.out)
	}
}
