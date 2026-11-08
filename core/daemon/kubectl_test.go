package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/k8s/k8stest"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// k8s design 11: the real kubectl, through the real exec plugin
// path (the nazartest build of the nazar CLI), against a fake TLS API
// server that only accepts client certificates of the nazar CA. The caller
// chain nazar-agent judges is scripted on the fake platform; the binaries,
// the exec protocol, the control socket and TLS are real. Skipped when no
// kubectl is on PATH.

// buildTestCLI builds the nazartest CLI once per test binary.
func buildTestCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "nazar")
	cmd := exec.Command("go", "build", "-tags", "nazartest", "-o", bin, "../../cmd/nazar")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the nazartest CLI: %v\n%s", err, out)
	}
	return bin
}

// decoy is a socket nobody may dial: where HOME, NAZAR_CONTROL_SOCKET and
// NAZAR_CONFIG in the exec entry's env: block point.
type decoy struct {
	dir   string
	dials atomic.Int32
}

func newDecoy(t *testing.T) *decoy {
	t.Helper()
	// A short dir: macOS limits a unix socket path to 104 bytes.
	dir, err := os.MkdirTemp("/tmp", "nzk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	d := &decoy{dir: dir}
	if err := os.MkdirAll(layout.RunDir(d.dir), 0o700); err != nil {
		t.Fatal(err)
	}
	// A permissive decoy config: every caller, no prompt.
	if err := os.WriteFile(filepath.Join(d.dir, "config.yaml"), []byte("apiVersion: nazar/v1\nkind: Config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{layout.ControlSocket(d.dir), filepath.Join(d.dir, "sock")} {
		l, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				d.dials.Add(1)
				c.Close()
			}
		}()
	}
	return d
}

func kubeconfig(t *testing.T, server string, ca []byte, nazar string, provideClusterInfo bool, dec *decoy) string {
	t.Helper()
	pci := "true"
	if !provideClusterInfo {
		pci = "false"
	}
	body := `apiVersion: v1
kind: Config
clusters:
- name: hydra
  cluster:
    server: ` + server + `
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(ca) + `
users:
- name: hydra
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ` + nazar + `
      args: [k8s, credential, hydra]
      provideClusterInfo: ` + pci + `
      interactiveMode: Never
      env:
      - {name: HOME, value: ` + dec.dir + `}
      - {name: NAZAR_CONTROL_SOCKET, value: ` + filepath.Join(dec.dir, "sock") + `}
      - {name: NAZAR_CONFIG, value: ` + filepath.Join(dec.dir, "config.yaml") + `}
      - {name: NAZAR_TEST_PEER, value: same-user}
contexts:
- name: hydra
  context: {cluster: hydra, user: hydra}
current-context: hydra
`
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type kubectlRun struct {
	code           int
	stdout, stderr string
}

func runKubectl(t *testing.T, kubectl, kc, socket string) kubectlRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, kubectl, "--kubeconfig", kc, "get", "--raw", "/api/v1/namespaces/default/pods")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "NAZAR_TEST_CONTROL_SOCKET=" + socket}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := kubectlRun{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("kubectl: %v", err)
	}
	return r
}

func TestKubectlThroughNazar(t *testing.T) {
	kubectl, err := exec.LookPath("kubectl")
	if err != nil {
		t.Skip("no kubectl on PATH")
	}
	if kubectl, err = filepath.EvalSymlinks(kubectl); err != nil {
		t.Fatal(err)
	}
	nazar := buildTestCLI(t)
	e := startWith(t, func(f *fake.Fake, o *Options) { o.VerifyCLI, o.Pipes = genuineCLI(f), f })
	ca, err := e.d.k8sCA.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	srv := k8stest.Start(t, ca.Cert)
	pin, err := cluster.PinOf(cluster.Info{Server: srv.URL, CAData: srv.CAPEM})
	if err != nil {
		t.Fatal(err)
	}
	// Nothing names or trusts kubectl: the iTerm2 rule judges whoever ran it.
	e.approved(t, k8sConfig(pin.Server, pin.CASHA256))
	b, err := os.ReadFile(kubectl)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	kubeCodeReal := platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: sum[:20]}
	realKubectl := fake.Proc{Path: kubectl, Args: []string{"kubectl", "get", "--raw", "/api/v1/namespaces/default/pods"}, Code: kubeCodeReal}
	tab := e.f.ITermTab(platform.ProcessRef{}, realKubectl, credCLI("hydra"))
	e.f.SetDefaultPeer(tab.Peer())
	dec := newDecoy(t)
	socket := e.c.Socket

	// The right server: 200, and the server saw the identity's certificate.
	r := runKubectl(t, kubectl, kubeconfig(t, srv.URL, srv.CAPEM, nazar, true, dec), socket)
	if r.code != 0 || !strings.Contains(r.stdout, "web-1") || !strings.Contains(r.stdout, `"k8stest/user":"admin"`) {
		t.Fatalf("kubectl through nazar: exit %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	seen := srv.Seen()
	if len(seen) == 0 || !seen[len(seen)-1].Verified || seen[len(seen)-1].CN != "admin" || strings.Join(seen[len(seen)-1].O, ",") != "system:masters" {
		t.Fatalf("seen %+v", seen)
	}
	if f := e.lastAudit(t); f["target"] != "k8s:hydra" || f["decision"] != "approved" || !strings.HasPrefix(f["receiver"], "kubectl get --raw") {
		t.Fatalf("audit %v", f)
	}

	// A look-alike server with another CA (it would even accept the nazar
	// CA's certificates): refused by check 2, and it saw no certificate.
	evil := k8stest.Start(t, ca.Cert)
	r = runKubectl(t, kubectl, kubeconfig(t, evil.URL, evil.CAPEM, nazar, true, dec), socket)
	if r.code == 0 || !strings.Contains(r.stderr, "exit code 3") || !strings.Contains(r.stderr, "cluster mismatch") {
		t.Fatalf("look-alike: exit %d\nstderr: %s", r.code, r.stderr)
	}
	for _, s := range evil.Seen() {
		if s.Presented {
			t.Fatalf("the look-alike saw a client certificate: %+v", s)
		}
	}
	// The right server, but kubectl told not to send the cluster info.
	r = runKubectl(t, kubectl, kubeconfig(t, srv.URL, srv.CAPEM, nazar, false, dec), socket)
	if r.code == 0 || !strings.Contains(r.stderr, "exit code 3") || !strings.Contains(r.stderr, "no cluster info") {
		t.Fatalf("no cluster info: exit %d\nstderr: %s", r.code, r.stderr)
	}
	// The plugin run by a program whose identity can't be told (no
	// verified code signature) under the tab: refused, whatever the rules.
	// (python3 there would be judged as the tab, as any program is: no
	// client list, k8s design 2.1.)
	odd := e.f.Launch(tab.Shell, fake.Proc{Path: "/Users/u/bin/odd", Args: []string{"odd"}, Code: platform.CodeIdentity{CDHash: []byte{0x0d}}})
	e.f.SetDefaultPeer(e.f.Launch(odd, credCLI("hydra")))
	r = runKubectl(t, kubectl, kubeconfig(t, srv.URL, srv.CAPEM, nazar, true, dec), socket)
	if r.code == 0 || !strings.Contains(r.stderr, "exit code 3") || !strings.Contains(r.stderr, "can't be identified") {
		t.Fatalf("unidentified: exit %d\nstderr: %s", r.code, r.stderr)
	}
	// THREAT-MODEL 5.16: the plugin's output relayed through tee
	// by a wrapper with exec hops, in the tab whose session approval covers
	// kubectl: refused before anything is minted, and kubectl shows why.
	signs := e.f.SignCalls()
	k2 := e.f.Launch(tab.Shell, realKubectl)
	cli := e.f.Launch(k2, cliProc("k8s", "credential", "hydra"))
	tee := e.f.Launch(cli, fake.Proc{Path: "/usr/bin/tee", Args: []string{"tee", "/tmp/leak"}, Code: fake.AppleCode("com.apple.tee")})
	e.f.SetStdout(cli, tee)
	e.f.SetStdout(tee, k2)
	e.f.SetDefaultPeer(cli)
	r = runKubectl(t, kubectl, kubeconfig(t, srv.URL, srv.CAPEM, nazar, true, dec), socket)
	if r.code == 0 || !strings.Contains(r.stderr, "exit code 3") || !strings.Contains(r.stderr, errStdoutNotPiped) || e.f.SignCalls() != signs {
		t.Fatalf("relayed: exit %d\nstderr: %s", r.code, r.stderr)
	}
	// Check 0: the socket peer is not the genuine CLI.
	k := e.f.Launch(tab.Shell, realKubectl)
	e.f.SetDefaultPeer(e.f.Launch(k, fake.Proc{Path: nazar, Args: []string{"nazar"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true}}))
	r = runKubectl(t, kubectl, kubeconfig(t, srv.URL, srv.CAPEM, nazar, true, dec), socket)
	if r.code == 0 || !strings.Contains(r.stderr, "exit code 3") || !strings.Contains(r.stderr, "not the nazar CLI") {
		t.Fatalf("check 0: exit %d\nstderr: %s", r.code, r.stderr)
	}
	if n := dec.dials.Load(); n != 0 {
		t.Fatalf("the plugin dialled a socket its environment named: %d times", n)
	}
}
