package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/k8s/kubeconfig"
)

// k8s design: nazar k8s ca create sets a
// context up without the kubeconfig's credential. The CLI reads the
// context and the cluster (never a user entry), nazar-agent makes the CA,
// the config entry and the kubectl pin on one login prompt, and only then
// does the CLI add its three kubeconfig entries; ca show, list, forget.

func testPEM(t *testing.T, cn string, orgs []string, isCA bool) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: cn, Organization: orgs},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// The admin credential of the kubeconfig: nothing nazar prints, sends or
// writes may carry any of it.
const (
	hydraKeyData = "HYDRA-KEY-PLAINTEXT-0123456789"
	hydraToken   = "HYDRA-TOKEN-PLAINTEXT-9876543210"
)

type kubeWorld struct {
	*harness
	kc, body  string // the kubeconfig and what it held
	clusterCA []byte
	adminCert []byte
	kubectl   string
}

// kubeHarness is a harness with a kubeconfig at $KUBECONFIG holding the
// hydra context (the current one), its cluster and an admin user with a
// client certificate, a key and a token; kubectl on $PATH.
func kubeHarness(t *testing.T) *kubeWorld {
	t.Helper()
	h := newHarness(t)
	dir := t.TempDir()
	w := &kubeWorld{harness: h, kc: filepath.Join(dir, "config"), clusterCA: testPEM(t, "microk8s CA", nil, true),
		adminCert: testPEM(t, "admin", []string{"system:masters"}, false)}
	w.body = `apiVersion: v1
kind: Config
clusters:
- name: hydra-cluster
  cluster:
    server: https://hydra.example:16443
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString(w.clusterCA) + `
users:
- name: hydra-admin
  user:
    client-certificate-data: ` + base64.StdEncoding.EncodeToString(w.adminCert) + `
    client-key-data: ` + base64.StdEncoding.EncodeToString([]byte(hydraKeyData)) + `
    token: ` + hydraToken + `
contexts:
- name: hydra
  context: {cluster: hydra-cluster, user: hydra-admin}
current-context: hydra
`
	if err := os.WriteFile(w.kc, []byte(w.body), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "bin")
	w.kubectl = filepath.Join(bin, "kubectl")
	_ = os.MkdirAll(bin, 0o755)
	if err := os.WriteFile(w.kubectl, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.env["KUBECONFIG"] = w.kc
	h.env["PATH"] = "relative/bin:" + bin + ":/nonexistent"
	h.a.selfPath = func() (string, error) { return "/Users/u/.local/bin/nazar", nil }
	return w
}

// caHash is the pin of the kubeconfig's cluster CA.
func (w *kubeWorld) caHash(t *testing.T) string {
	t.Helper()
	h, err := cluster.CAHash(w.clusterCA)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// setUpReply is nazar-agent's reply to ca create.
func setUpReply(t *testing.T, name string) control.K8sContext {
	return control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: name, Configured: true, State: control.K8sStateOK,
		Identity: &control.K8sIdentity{User: "dev-nazar", Groups: []string{}},
		CA: &control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: name, Fingerprint: strings.Repeat("ab", 32), WhileLocked: true,
			CertFile: "/Users/u/.nazar/keys/k8s-ca-" + name + ".crt", CertPEM: string(testPEM(t, "nazar k8s CA "+name, nil, true))}}
}

// noCredential fails if s carries the kubeconfig's credential in any form.
func (w *kubeWorld) noCredential(t *testing.T, what, s string) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString
	for _, sec := range []string{hydraKeyData, b64([]byte(hydraKeyData)), hydraToken, b64(w.adminCert), string(w.adminCert)} {
		if strings.Contains(s, sec) {
			t.Errorf("%s carries the kubeconfig's credential", what)
		}
	}
}

// noCredentialAnywhere checks every output, every request and every file
// under the kubeconfig's directory but the kubeconfig and its backups.
func (w *kubeWorld) noCredentialAnywhere(t *testing.T) {
	t.Helper()
	w.noCredential(t, "stdout", w.out.String())
	w.noCredential(t, "stderr", w.errb.String())
	for _, r := range w.requests() {
		b, _ := json.Marshal(r)
		w.noCredential(t, "a request", string(b))
	}
	for _, dir := range []string{filepath.Dir(w.kc), w.home} {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || p == w.kc || strings.HasPrefix(p, w.kc+".nazar-backup-") {
				return nil
			}
			b, _ := os.ReadFile(p)
			w.noCredential(t, p, string(b))
			return nil
		})
	}
}

// added are the three entries ca create adds for name, as the CLI writes
// them into this kubeconfig (its lists at column 0).
func added(name, server, caB64 string) []string {
	n := "nazar-" + name
	return []string{
		"- name: \"" + n + "\"\n  cluster:\n    server: \"" + server + "\"\n    certificate-authority-data: \"" + caB64 + "\"\n",
		"- name: \"" + n + "\"\n  user:\n    exec:\n      apiVersion: \"client.authentication.k8s.io/v1\"\n      command: \"/Users/u/.local/bin/nazar\"\n" +
			"      args:\n      - \"k8s\"\n      - \"credential\"\n      - \"" + name + "\"\n      provideClusterInfo: true\n      interactiveMode: \"Never\"\n",
		"- name: \"" + name + "\"\n  context:\n    cluster: \"" + n + "\"\n    user: \"" + n + "\"\n",
	}
}

// onlyAdded fails unless the kubeconfig is its old body plus exactly the
// three entries for name, every other byte as it was.
func (w *kubeWorld) onlyAdded(t *testing.T, name string) {
	t.Helper()
	got, _ := os.ReadFile(w.kc)
	rest := string(got)
	for _, a := range added(name, "https://hydra.example:16443", base64.StdEncoding.EncodeToString(w.clusterCA)) {
		i := strings.Index(rest, a)
		if i < 0 {
			t.Fatalf("the kubeconfig lacks\n%s\nin\n%s", a, got)
		}
		// The install hint is the user entry's last line.
		j := i + len(a)
		if strings.HasPrefix(rest[j:], "      installHint: ") {
			j += strings.Index(rest[j:], "\n") + 1
		}
		rest = rest[:i] + rest[j:]
	}
	if rest != w.body {
		t.Fatalf("every other byte of the kubeconfig stays; the rest is:\n%s", rest)
	}
}

func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// No program is pinned (k8s design 2.1): set up works with no kubectl on
// PATH at all.
func TestK8sCACreateNeedsNoKubectl(t *testing.T) {
	w := kubeHarness(t)
	w.env["PATH"] = "/nonexistent"
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, w.errb)
	}
	if strings.Contains(w.out.String(), "is its client") {
		t.Fatalf("no client is named:\n%s", w.out)
	}
}

func TestK8sCACreateWithoutATerminal(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, w.errb)
	}
	reqs := w.requests()
	if len(reqs) != 1 || reqs[0].Command != control.CmdK8sCACreate {
		t.Fatalf("one request: %+v", reqs)
	}
	want := map[string]string{"name": "hydra-nazar", "server": "https://hydra.example:16443", "caSHA256": w.caHash(t), "tlsServerName": "",
		"proxyURL": "", "kubeconfig": w.kc}
	for k, v := range want {
		if reqs[0].Args[k] != v {
			t.Errorf("arg %s = %q, want %q", k, reqs[0].Args[k], v)
		}
	}
	if _, ok := reqs[0].Args["kubectl"]; ok {
		t.Error("no kubectl is pinned: none is sent")
	}
	w.onlyAdded(t, "hydra-nazar")
	backups, _ := filepath.Glob(w.kc + ".nazar-backup-*")
	if len(backups) != 1 {
		t.Fatalf("one backup: %v", dirFiles(t, filepath.Dir(w.kc)))
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != w.body {
		t.Fatal("the backup is the old file")
	}
	if fi, _ := os.Stat(w.kc); fi.Mode().Perm() != 0o600 {
		t.Fatal("the kubeconfig is 0600")
	}
	out := w.out.String()
	for _, s := range []string{"hydra-nazar is set up", "Added the context hydra-nazar and the cluster and user nazar-hydra-nazar to " + w.kc,
		backups[0], "/var/snap/microk8s/current/certs/nazar-ca-hydra-nazar.crt", "sudo snap restart microk8s.daemon-kubelite",
		"kubectl --context hydra create clusterrolebinding dev-nazar --clusterrole=cluster-admin --user=dev-nazar",
		"kubectl --context hydra-nazar get pods"} {
		if !strings.Contains(out, s) {
			t.Errorf("the output must say %q:\n%s", s, out)
		}
	}
	if w.errb.Len() != 0 {
		t.Errorf("nothing on stderr without a terminal: %s", w.errb)
	}
	w.noCredentialAnywhere(t)
	// --json: a K8sSetup.
	w.out.Reset()
	w2 := kubeHarness(t)
	w2.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w2.run("--json", "k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, w2.out)
	}
	var s control.K8sSetup
	if err := json.Unmarshal(w2.out.Bytes(), &s); err != nil || s.Kind != control.KindK8sSetup || !s.Added || s.Kubeconfig != w2.kc ||
		!strings.HasPrefix(s.Backup, w2.kc+".nazar-backup-") || s.Context.Name != "hydra-nazar" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestK8sCACreateArgumentsWithoutATerminal(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(control.NewProblem(control.CodeError, "no request expected"))
	})
	for name, tc := range map[string]struct {
		args []string
		code int
		says string
	}{
		"no arguments":        {[]string{"k8s", "ca", "create"}, control.ExitUsage, "without a terminal, give the context and the server"},
		"no server":           {[]string{"k8s", "ca", "create", "hydra-nazar"}, control.ExitUsage, "without a terminal, give the context and the server"},
		"three":               {[]string{"k8s", "ca", "create", "a", "https://hydra.example:16443", "x"}, control.ExitUsage, "at most"},
		"a flag":              {[]string{"k8s", "ca", "create", "--microk8s", "a", "https://hydra.example:16443"}, control.ExitUsage, ""},
		"another server":      {[]string{"k8s", "ca", "create", "hydra-nazar", "https://evil.example"}, control.ExitUsage, "no cluster in the kubeconfig has the server"},
		"not exactly":         {[]string{"k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443/"}, control.ExitUsage, "no cluster in the kubeconfig has the server"},
		"bad name":            {[]string{"k8s", "ca", "create", "a/b", "https://hydra.example:16443"}, control.ExitUsage, "invalid context name"},
		"the admin's context": {[]string{"k8s", "ca", "create", "hydra", "https://hydra.example:16443"}, control.ExitError, `context "hydra"`},
	} {
		if code := w.run(tc.args...); code != tc.code || !strings.Contains(w.errb.String(), tc.says) {
			t.Errorf("%s: exit %d, want %d with %q\n%s", name, code, tc.code, tc.says, w.errb)
		}
		w.noCredential(t, name, w.errb.String()+w.out.String())
	}
	if len(w.requests()) != 0 {
		t.Fatal("a refusal sends nothing")
	}
	if b, _ := os.ReadFile(w.kc); string(b) != w.body || len(dirFiles(t, filepath.Dir(w.kc))) != 1 {
		t.Fatal("a refusal changes nothing, leaves no file")
	}
}

func TestK8sCACreateRefusals(t *testing.T) {
	refused := func(t *testing.T, w *kubeWorld, code int, says string, args ...string) {
		t.Helper()
		w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
			_ = out.Emit(control.NewProblem(control.CodeError, "no request expected"))
		})
		if got := w.run(args...); got != code || !strings.Contains(w.errb.String(), says) {
			t.Fatalf("exit %d, want %d with %q\n%s", got, code, says, w.errb)
		}
		if len(w.requests()) != 0 {
			t.Fatal("nothing sent")
		}
		if b, _ := os.ReadFile(w.kc); string(b) != w.body {
			t.Fatal("the kubeconfig is as it was")
		}
		w.noCredential(t, "the refusal", w.errb.String())
	}
	create := []string{"k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"}
	t.Run("insecure cluster", func(t *testing.T) {
		w := kubeHarness(t)
		w.body = strings.Replace(w.body, "    server: https://hydra.example:16443\n", "    server: https://hydra.example:16443\n    insecure-skip-tls-verify: true\n", 1)
		_ = os.WriteFile(w.kc, []byte(w.body), 0o600)
		refused(t, w, control.ExitError, "insecure-skip-tls-verify", create...)
	})
	t.Run("two clusters, two CAs", func(t *testing.T) {
		w := kubeHarness(t)
		w.body = strings.Replace(w.body, "users:\n", "- name: evil\n  cluster:\n    server: https://hydra.example:16443\n    certificate-authority-data: "+
			base64.StdEncoding.EncodeToString(testPEM(t, "evil CA", nil, true))+"\nusers:\n", 1)
		_ = os.WriteFile(w.kc, []byte(w.body), 0o600)
		refused(t, w, control.ExitError, "several clusters with that server differ", create...)
	})
	t.Run("a relative nazar", func(t *testing.T) {
		w := kubeHarness(t)
		w.a.selfPath = func() (string, error) { return "nazar", nil }
		refused(t, w, control.ExitError, "absolute path", create...)
	})
	t.Run("a cluster or user of nazar's name", func(t *testing.T) {
		w := kubeHarness(t)
		w.body = strings.Replace(w.body, "contexts:\n", "- name: nazar-hydra-nazar\n  user: {token: x}\ncontexts:\n", 1)
		_ = os.WriteFile(w.kc, []byte(w.body), 0o600)
		refused(t, w, control.ExitError, `user "nazar-hydra-nazar"`, create...)
	})
}

// No prompt said yes: the kubeconfig is byte for byte as it was, and no
// temp file or backup is left.
func TestK8sCACreateWritesTheKubeconfigOnlyAfterYes(t *testing.T) {
	for name, reply := range map[string]*control.Problem{
		"denied":  control.NewProblem(control.CodeRefused, "not set up: user denied"),
		"changed": control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; nothing was made"),
		"error":   control.NewProblem(control.CodeError, "hydra-nazar is set up already"),
	} {
		w := kubeHarness(t)
		w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { _ = out.Emit(reply) })
		if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != reply.ExitCode() {
			t.Fatalf("%s: exit %d", name, code)
		}
		if b, _ := os.ReadFile(w.kc); string(b) != w.body {
			t.Fatalf("%s: the kubeconfig must be byte-identical", name)
		}
		if files := dirFiles(t, filepath.Dir(w.kc)); len(files) != 1 {
			t.Fatalf("%s: no temp or backup file left: %v", name, files)
		}
	}
	// nazar-agent not running: exit 5, nothing changed.
	w := kubeHarness(t)
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitUnavailable {
		t.Fatalf("not running: exit %d", code)
	}
	if b, _ := os.ReadFile(w.kc); string(b) != w.body || len(dirFiles(t, filepath.Dir(w.kc))) != 1 {
		t.Fatal("not running: nothing changed")
	}
	// A kubeconfig nazar can't write fails before anything is asked.
	w2 := kubeHarness(t)
	w2.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if os.Geteuid() != 0 {
		_ = os.Chmod(filepath.Dir(w2.kc), 0o500)
		t.Cleanup(func() { os.Chmod(filepath.Dir(w2.kc), 0o700) })
		if code := w2.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitError || len(w2.requests()) != 0 {
			t.Fatalf("unwritable: exit %d, %d requests", code, len(w2.requests()))
		}
	}
}

func TestK8sCACreateAlreadySetUp(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatal(code)
	}
	before, _ := os.ReadFile(w.kc)
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK || !strings.Contains(w.out.String(), "already has nazar's entries for hydra-nazar") {
		t.Fatalf("exit %d\n%s", code, w.out)
	}
	if r := w.requests(); len(r) != 2 || r[1].Args["kubeconfig"] != "" {
		t.Fatalf("asked again (nazar-agent answers at once when it is set up), with no kubeconfig to change: %+v", r)
	}
	if after, _ := os.ReadFile(w.kc); string(after) != string(before) {
		t.Fatal("nothing rewritten")
	}
	// Another nazar's entry of that name: refused, never "set up".
	_ = os.WriteFile(w.kc, []byte(strings.Replace(string(before), `command: "/Users/u/.local/bin/nazar"`, `command: "/opt/homebrew/bin/nazar"`, 1)), 0o600)
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitError || !strings.Contains(w.errb.String(), "nazar never changes an entry it did not write") {
		t.Fatalf("another nazar: exit %d %s", code, w.errb)
	}
}

// At a terminal: the defaults come from the current context and its
// cluster (never the user entry); Enter takes each.
func TestK8sCACreateAtATerminal(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	w.a.stdinTerminal = func() bool { return true }
	w.a.stdin = strings.NewReader("\n\n\n")
	if code := w.run("k8s", "ca", "create"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, w.errb)
	}
	fp := fingerprints(w.clusterCA)
	if len(fp) != 1 || !strings.HasPrefix(fp[0], "sha256 Fingerprint=") || len(fp[0]) != len("sha256 Fingerprint=")+32*3-1 || strings.ToUpper(fp[0][19:]) != fp[0][19:] {
		t.Fatalf("the fingerprint as openssl prints it: %q", fp)
	}
	asked := w.errb.String()
	for _, s := range []string{"kubectl config get-contexts", "kubectl config view --minify --context hydra -o jsonpath='{.clusters[0].cluster.server}'",
		"Context name [hydra-nazar]: ", "Server [https://hydra.example:16443]: ", "Server CA [" + fp[0] + "]",
		"sudo openssl x509 -in /var/snap/microk8s/current/certs/ca.crt -noout -fingerprint -sha256"} {
		if !strings.Contains(asked, s) {
			t.Errorf("the questions must show %q:\n%s", s, asked)
		}
	}
	r := w.requests()
	if len(r) != 1 || r[0].Args["name"] != "hydra-nazar" || r[0].Args["server"] != "https://hydra.example:16443" || r[0].Args["caSHA256"] != w.caHash(t) {
		t.Fatalf("%+v", r)
	}
	w.onlyAdded(t, "hydra-nazar")
	w.noCredentialAnywhere(t)
	t.Logf("transcript (stderr, then stdout):\n%s%s", asked, w.out)
}

func TestK8sCACreateAtATerminalWithACAFile(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	w.a.stdinTerminal = func() bool { return true }
	other := testPEM(t, "node CA", nil, true)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	// Text around the PEM block (a security review nit) never reaches the
	// kubeconfig: the certificate is written re-encoded, alone.
	_ = os.WriteFile(caFile, append(append([]byte("BESIDE-1 written by hand\n"), other...), "BESIDE-2\n"...), 0o600)
	// Another server: no default CA in the kubeconfig, so the file is asked
	// for; the context name is given as an argument.
	w.a.stdin = strings.NewReader("https://10.0.0.5:16443\n" + caFile + "\n")
	if code := w.run("k8s", "ca", "create", "lab"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, w.errb)
	}
	asked := w.errb.String()
	if !strings.Contains(asked, "Context name: lab") || !strings.Contains(asked, "the kubeconfig has none for this server") ||
		!strings.Contains(asked, fingerprints(other)[0]) {
		t.Fatalf("questions:\n%s", asked)
	}
	want, _ := cluster.CAHash(other)
	if r := w.requests(); len(r) != 1 || r[0].Args["server"] != "https://10.0.0.5:16443" || r[0].Args["caSHA256"] != want {
		t.Fatalf("%+v", r)
	}
	got, _ := os.ReadFile(w.kc)
	if !strings.Contains(string(got), `certificate-authority-data: "`+base64.StdEncoding.EncodeToString(other)+`"`) {
		t.Fatalf("the new cluster entry has the file's CA, and nothing else:\n%s", got)
	}
	// No CA at all: refused, saying where the file is on the node.
	w2 := kubeHarness(t)
	w2.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	w2.a.stdinTerminal = func() bool { return true }
	w2.a.stdin = strings.NewReader("lab\nhttps://10.0.0.5:16443\n\n")
	if code := w2.run("k8s", "ca", "create"); code != control.ExitUsage || !strings.Contains(w2.errb.String(), "copy /var/snap/microk8s/current/certs/ca.crt from the node") || len(w2.requests()) != 0 {
		t.Fatalf("exit %d\n%s", code, w2.errb)
	}
	// Not a certificate (a key, say): refused, its content never shown.
	w3 := kubeHarness(t)
	w3.a.stdinTerminal = func() bool { return true }
	keyFile := filepath.Join(t.TempDir(), "key")
	_ = os.WriteFile(keyFile, []byte("-----BEGIN EC PRIVATE KEY-----\n"+hydraKeyData+"\n-----END EC PRIVATE KEY-----\n"), 0o600)
	w3.a.stdin = strings.NewReader("lab\nhttps://10.0.0.5:16443\n" + keyFile + "\n")
	if code := w3.run("k8s", "ca", "create"); code != control.ExitError || strings.Contains(w3.errb.String(), hydraKeyData) {
		t.Fatalf("exit %d\n%s", code, w3.errb)
	}
	// A server that is not https (an empty one is the same): refused before
	// the CA is asked for.
	w5 := kubeHarness(t)
	w5.a.stdinTerminal = func() bool { return true }
	w5.a.stdin = strings.NewReader("lab\nhydra.example:16443\n")
	if code := w5.run("k8s", "ca", "create"); code != control.ExitUsage || !strings.Contains(w5.errb.String(), "must start with https://") ||
		strings.Contains(w5.errb.String(), "Server CA") || len(w5.requests()) != 0 {
		t.Fatalf("exit %d\n%s", code, w5.errb)
	}
	// An answer with an escape sequence, or no answer at all: refused.
	for _, in := range []string{"\x1b[200~hydra\n", ""} {
		w4 := kubeHarness(t)
		w4.a.stdinTerminal = func() bool { return true }
		w4.a.stdin = strings.NewReader(in)
		if code := w4.run("k8s", "ca", "create"); code != control.ExitUsage || len(w4.requests()) != 0 {
			t.Fatalf("%q: exit %d", in, code)
		}
	}
}

// The questions take values, never a yes: approval is nazar-agent's
// prompt. Answers that look like one are values (here a name and a
// server), refused as such; nothing is sent.
func TestK8sCACreateNeverTakesAYesForAnApproval(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	w.a.stdinTerminal = func() bool { return true }
	w.a.stdin = strings.NewReader("y\nyes\ny\n")
	if code := w.run("k8s", "ca", "create"); code == control.ExitOK || len(w.requests()) != 0 {
		t.Fatalf("exit %d, %d requests", code, len(w.requests()))
	}
	if b, _ := os.ReadFile(w.kc); string(b) != w.body {
		t.Fatal("nothing written")
	}
}

// Security review: a relative $KUBECONFIG entry is the file kubectl
// reads, relative to the working directory; nazar-agent gets it absolute.
func TestK8sCACreateWithARelativeKubeconfig(t *testing.T) {
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if req.Command == control.CmdK8sForget {
			_ = out.Emit(control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: req.Args["name"]})
			return
		}
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	wd, _ := os.Getwd()
	rel, err := filepath.Rel(wd, w.kc)
	if err != nil || filepath.IsAbs(rel) {
		t.Fatal(rel, err)
	}
	w.env["KUBECONFIG"] = rel
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatalf("exit %d %s", code, w.errb)
	}
	w.onlyAdded(t, "hydra-nazar")
	if code := w.run("k8s", "forget", "hydra-nazar"); code != control.ExitOK {
		t.Fatalf("exit %d %s", code, w.errb)
	}
	for _, r := range w.requests() {
		if r.Args["kubeconfig"] != w.kc {
			t.Fatalf("%s: kubeconfig %q", r.Command, r.Args["kubeconfig"])
		}
	}
	if b, _ := os.ReadFile(w.kc); string(b) != w.body {
		t.Fatal("forget removed the entries")
	}
}

// Security review: the temp file (a whole copy of the kubeconfig) is
// removed when the CLI is interrupted while the prompt is open.
func TestK8sTempFileGoesOnASignal(t *testing.T) {
	w := kubeHarness(t)
	set, err := kubeconfig.Load([]string{w.kc})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := set.Add(kubeconfig.Entries{Context: "x", Server: "https://hydra.example:16443", CAPEM: w.clusterCA, Command: "/n"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := kubeconfig.PrepareChange(ch)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(chan os.Signal, 1)
	exited := make(chan int, 1)
	stop := abortOnSignal(sigs, p, func(code int) { exited <- code })
	sigs <- os.Interrupt
	select {
	case code := <-exited:
		if code != 130 {
			t.Fatal(code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit on the signal")
	}
	stop()
	if _, err := os.Stat(p.TempPath()); !os.IsNotExist(err) {
		t.Fatal("the temp file is removed")
	}
	if b, _ := os.ReadFile(w.kc); string(b) != w.body {
		t.Fatal("the kubeconfig is as it was")
	}
	// Stopped before any signal: nothing happens.
	p2, _ := kubeconfig.PrepareChange(ch)
	sigs2 := make(chan os.Signal, 1)
	stop2 := abortOnSignal(sigs2, p2, func(int) { t.Error("no exit after stop") })
	stop2()
	sigs2 <- os.Interrupt
	time.Sleep(50 * time.Millisecond)
	if _, err := os.Stat(p2.TempPath()); err != nil {
		t.Fatal("the temp file stays for the commit")
	}
	p2.Abort()
}

// The kubeconfig of a new Mac: none yet. ~/.kube/config is made, 0600.
func TestK8sCACreateMakesAKubeconfig(t *testing.T) {
	h := newHarness(t)
	bin := filepath.Join(t.TempDir(), "bin")
	_ = os.MkdirAll(bin, 0o755)
	_ = os.WriteFile(filepath.Join(bin, "kubectl"), []byte("#!/bin/sh\n"), 0o755)
	h.env["PATH"] = bin
	h.a.selfPath = func() (string, error) { return "/Users/u/.local/bin/nazar", nil }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	h.a.stdinTerminal = func() bool { return true }
	ca := testPEM(t, "node CA", nil, true)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(caFile, ca, 0o600)
	h.a.stdin = strings.NewReader("lab\nhttps://10.0.0.5:16443\n" + caFile + "\n")
	if code := h.run("k8s", "ca", "create"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.errb)
	}
	kc := filepath.Join(h.home, ".kube", "config")
	if fi, err := os.Stat(kc); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v", err)
	}
	if r := h.requests(); len(r) != 1 || r[0].Args["kubeconfig"] != kc {
		t.Fatalf("%+v", r)
	}
	if b, _ := filepath.Glob(kc + ".nazar-backup-*"); len(b) != 0 {
		t.Fatal("no backup of a file that did not exist")
	}
}

func TestK8sCACommands(t *testing.T) {
	h := newHarness(t)
	caPEM := string(testPEM(t, "nazar k8s CA hydra", nil, true))
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		ca := control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: req.Args["name"], Fingerprint: strings.Repeat("ab", 32),
			CertFile: "/Users/u/.nazar/keys/k8s-ca-hydra.crt", Created: time.Unix(0, 0).UTC(), NotAfter: time.Unix(0, 0).UTC(), CertPEM: caPEM}
		_ = out.Emit(ca)
	})
	if code := h.run("k8s", "ca", "show", "hydra"); code != control.ExitOK || h.out.String() != caPEM {
		t.Fatalf("show prints the PEM and nothing else: %d %q", code, h.out)
	}
	h.out.Reset()
	if code := h.run("k8s", "ca", "show", "hydra", "--microk8s"); code != control.ExitOK {
		t.Fatal(code)
	}
	steps := h.out.String()
	// The bundle takes every nazar CA, so a second
	// context does not drop the first.
	for _, want := range []string{caPEM, "/var/snap/microk8s/current/certs/nazar-ca-hydra.crt", "/var/snap/microk8s/current/certs/nazar-ca-*.crt > /var/snap/microk8s/current/certs/client-ca.crt", "--client-ca-file=${SNAP_DATA}/certs/client-ca.crt",
		"args/kube-apiserver", "sudo snap restart microk8s.daemon-kubelite", "refresh-certs", "nazar never touches the cluster"} {
		if !strings.Contains(steps, want) {
			t.Errorf("the microk8s steps must contain %q:\n%s", want, steps)
		}
	}
	if strings.Contains(steps, "microk8s stop") {
		t.Errorf("the steps restart the control plane, never microk8s as a whole (microk8s stop stops every pod):\n%s", steps)
	}
	h.out.Reset()
	if code := h.run("--json", "k8s", "ca", "show", "hydra"); code != control.ExitOK {
		t.Fatal(code)
	}
	var ca control.K8sCA
	if err := json.Unmarshal(h.out.Bytes(), &ca); err != nil || ca.CertPEM != caPEM {
		t.Fatalf("%v %+v", err, ca)
	}
	for _, bad := range [][]string{{"k8s", "ca"}, {"k8s", "ca", "rotate", "hydra"}, {"k8s", "import", "hydra"}, {"k8s", "ca", "show"}} {
		if code := h.run(bad...); code != control.ExitUsage {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
}

func TestK8sListAndForget(t *testing.T) {
	h := newHarness(t)
	hostile := "evil\x1b[2J\u202e"
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdK8sList:
			_ = out.Emit(control.K8sContextList{TypeMeta: control.Meta(control.KindK8sContextList), Items: []control.K8sContext{
				{TypeMeta: control.Meta(control.KindK8sContext), Name: "hydra", Configured: true, Credential: "ca-cert", TTLCert: "15m0s",
					Identity: &control.K8sIdentity{User: "dev-nazar"},
					Cluster:  &control.K8sCluster{Server: "https://hydra.example:16443/" + hostile, CASHA256: strings.Repeat("cd", 32)},
					Rules:    []string{"1: x", "fallback: gate=block"}, Warnings: []string{"clients: no longer used; remove the line"},
					CA: &control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: "hydra", Fingerprint: strings.Repeat("ab", 32)}},
				{TypeMeta: control.Meta(control.KindK8sContext), Name: "old", State: control.K8sStateNoEntry, Remedy: "nazar k8s forget old, then nazar k8s ca create old",
					CA: &control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: "old", Fingerprint: strings.Repeat("ef", 32)}},
				{TypeMeta: control.Meta(control.KindK8sContext), Name: "loose", CABroken: true, UnusableReason: "unreadable", Remedy: "security delete-generic-password -s dev.nazar -a k8s-ca/loose"},
			}})
		case control.CmdK8sForget:
			_ = out.Emit(control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: "hydra"})
		}
	})
	if code := h.run("k8s", "list"); code != control.ExitOK {
		t.Fatal(code)
	}
	out := h.out.String()
	for _, want := range []string{"hydra", "CN=dev-nazar", "warning: clients: no longer used; remove the line", "loose", "security delete-generic-password -s dev.nazar -a k8s-ca/loose",
		"not in config.yaml: nazar k8s forget old, then nazar k8s ca create old"} {
		if !strings.Contains(out, want) {
			t.Errorf("list must show %q:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\u202e") || strings.Contains(out, "import") {
		t.Fatalf("raw control runes, or import:\n%q", out)
	}
	h.out.Reset()
	if code := h.run("k8s", "forget", "hydra"); code != control.ExitOK {
		t.Fatal(code)
	}
	if out := h.out.String(); !strings.Contains(out, "forgot") {
		t.Fatalf("forget output:\n%s", out)
	}
	if r := h.requests(); r[len(r)-1].Command != control.CmdK8sForget || r[len(r)-1].Args["name"] != "hydra" || r[len(r)-1].Args["kubeconfig"] != "" {
		t.Fatalf("no kubeconfig entries, none named: %+v", r)
	}
}

// forget removes the three entries ca create added, only after
// nazar-agent said yes, and only while they are exactly nazar's.
func TestK8sForgetRemovesNazarsKubeconfigEntries(t *testing.T) {
	w := kubeHarness(t)
	forgetReply := control.NewProblem(control.CodeRefused, "not forgotten: user denied")
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if req.Command == control.CmdK8sForget {
			if forgetReply != nil {
				_ = out.Emit(forgetReply)
				return
			}
			_ = out.Emit(control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: req.Args["name"]})
			return
		}
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatal(code)
	}
	set, _ := os.ReadFile(w.kc)
	// Denied: nothing removed.
	if code := w.run("k8s", "forget", "hydra-nazar"); code != control.ExitRefused {
		t.Fatal(code)
	}
	if b, _ := os.ReadFile(w.kc); string(b) != string(set) {
		t.Fatal("a denied forget changes nothing")
	}
	forgetReply = nil
	if code := w.run("k8s", "forget", "hydra-nazar"); code != control.ExitOK {
		t.Fatalf("exit %d %s", code, w.errb)
	}
	if r := w.requests(); r[len(r)-1].Args["kubeconfig"] != w.kc {
		t.Fatalf("the prompt names the kubeconfig: %+v", r[len(r)-1])
	}
	if b, _ := os.ReadFile(w.kc); string(b) != w.body {
		t.Fatalf("the kubeconfig is as it was before ca create:\n%s", b)
	}
	if out := w.out.String(); !strings.Contains(out, "Removed nazar's entries for hydra-nazar from "+w.kc) {
		t.Fatalf("%s", out)
	}
	// An entry changed by hand stays, named; the user's own context is
	// never touched.
	w2 := kubeHarness(t)
	w2.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if req.Command == control.CmdK8sForget {
			_ = out.Emit(control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: req.Args["name"]})
			return
		}
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w2.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443"); code != control.ExitOK {
		t.Fatal(code)
	}
	b, _ := os.ReadFile(w2.kc)
	changed := strings.Replace(string(b), "    user: \"nazar-hydra-nazar\"\n", "    user: \"nazar-hydra-nazar\"\n    namespace: prod\n", 1)
	_ = os.WriteFile(w2.kc, []byte(changed), 0o600)
	if code := w2.run("k8s", "forget", "hydra-nazar"); code != control.ExitOK {
		t.Fatal(code)
	}
	after, _ := os.ReadFile(w2.kc)
	if !strings.Contains(string(after), "namespace: prod") || strings.Contains(string(after), "credential") ||
		!strings.Contains(w2.out.String(), "kubectl config delete-context hydra-nazar") {
		t.Fatalf("%s\n%s", after, w2.out)
	}
	if code := w2.run("k8s", "forget", "hydra"); code != control.ExitOK || !strings.Contains(w2.out.String(), "kubectl config delete-context hydra") {
		t.Fatalf("%s", w2.out)
	}
	if b, _ := os.ReadFile(w2.kc); !strings.Contains(string(b), "- name: hydra\n  context: {cluster: hydra-cluster, user: hydra-admin}") {
		t.Fatal("the user's own context stays")
	}
	w2.noCredentialAnywhere(t)
}

// `ca show` passes on only a plain PEM certificate.
func TestK8sCAShowRefusesAMalformedCertificate(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: "hydra", CertPEM: "-----BEGIN CERTIFICATE-----\n\x1b[2J\n"})
	})
	if code := h.run("k8s", "ca", "show", "hydra"); code != control.ExitError || strings.Contains(h.out.String(), "\x1b") {
		t.Fatalf("exit %d %q", code, h.out)
	}
}
