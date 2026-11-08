//go:build integration

package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/layout"
)

// k8s design: every nazar k8s command of the
// test build against nazar-testd in a temp home, in the order docs/CLI.md's
// Kubernetes section gives them, then the real kubectl (when there is one)
// on the kubeconfig entries ca create added. says ties each phrase the docs
// quote to what nazar printed. nazar-testd vouches for no CLI (no
// VerifyCLI), so every k8s credential here is refused by check 0; a minted
// credential on real chains is make integration-run's. Nothing
// here can read ~/.kube, reach a cluster or the account's nazar-agent:
// HOME, KUBECONFIG and both control sockets are the world's (env), and the
// CLI must be the nazartest build.
func TestK8sCommandsAsTheDocsSay(t *testing.T) {
	cli := filepath.Join(bin, "nazar")
	if body, err := os.ReadFile(cli); err != nil || !strings.Contains(string(body), "NAZAR_TEST_CONTROL_SOCKET") {
		t.Fatalf("%s is not the nazartest build (%v): its k8s credential would dial the account's nazar-agent", cli, err)
	}
	w := newWorld(t, `{"auth":"allow"}`)
	kc := filepath.Join(w.home, "kubeconfig") // the world's KUBECONFIG
	original, secrets := adminKubeconfig(t)
	if err := os.WriteFile(kc, original, 0o600); err != nil {
		t.Fatal(err)
	}
	kubeconfig := func() string { b, _ := os.ReadFile(kc); return string(b) }
	// kubectl on the world's PATH, for the run at the end; set up needs
	// none (no program is pinned, k8s design 2.1).
	kubectl := ""
	for _, d := range filepath.SplitList(strings.TrimPrefix(w.env()[1], "PATH=")) {
		if fi, err := os.Stat(filepath.Join(d, "kubectl")); err == nil && fi.Mode().IsRegular() {
			kubectl = filepath.Join(d, "kubectl")
			break
		}
	}
	run := func(want int, args ...string) string {
		t.Helper()
		out, code := w.run(nil, cli, args...)
		if code != want {
			t.Fatalf("nazar %s: exit %d, want %d\n%s", strings.Join(args, " "), code, want, out)
		}
		return out
	}
	noSecret := func(what, out string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s shows the old client key", what)
			}
		}
	}

	says(t, run(0, "k8s", "list"), "No k8s contexts.")

	// Without a terminal, the context and the server are both needed.
	out := run(2, "k8s", "ca", "create", "hydra-nazar")
	says(t, out, "without a terminal, give the context and the server")
	says(t, run(2, "k8s", "ca", "create", "hydra-nazar", "https://127.0.0.1:2"), "no cluster in the kubeconfig has the server")

	// nazar k8s ca create hydra-nazar <server>: one prompt, then the
	// kubeconfig's three new entries and the steps.
	out = run(0, "k8s", "ca", "create", "hydra-nazar", "https://127.0.0.1:1")
	noSecret("ca create", out)
	says(t, out, "hydra-nazar is set up")
	says(t, out, "Added the context hydra-nazar and the cluster and user nazar-hydra-nazar to "+kc)
	says(t, out, "sudo snap restart microk8s.daemon-kubelite", "docs/design/k8s-design.md")
	says(t, out, "create clusterrolebinding", "docs/CLI.md")
	says(t, out, "--clusterrole=cluster-admin", "docs/CLI.md")
	says(t, out, "kubectl --context hydra-nazar get pods", "docs/CLI.md")
	if strings.Contains(out, "microk8s stop") {
		t.Errorf("the microk8s steps stop microk8s, and every pod with it:\n%s", out)
	}
	backups, _ := filepath.Glob(kc + ".nazar-backup-*")
	if len(backups) != 1 {
		t.Fatalf("one backup: %v", backups)
	}
	if b, _ := os.ReadFile(backups[0]); string(b) != string(original) {
		t.Error("the backup is not the old file, byte for byte")
	}
	if fi, err := os.Stat(backups[0]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the backup is 0600: %v %v", fi, err)
	}
	set := kubeconfig()
	// Every line of the old file is still there, in order; the admin's
	// credential is untouched and nazar's entries have none.
	rest := set
	for _, l := range strings.SplitAfter(string(original), "\n") {
		i := strings.Index(rest, l)
		if i < 0 {
			t.Fatalf("the kubeconfig lost %q:\n%s", l, set)
		}
		rest = rest[i+len(l):]
	}
	for _, want := range []string{`- name: "nazar-hydra-nazar"`, `command: "` + cli + `"`, `- "credential"`, "provideClusterInfo: true", `interactiveMode: "Never"`,
		`- name: "hydra-nazar"`} {
		if !strings.Contains(set, want) {
			t.Errorf("the kubeconfig lacks %q:\n%s", want, set)
		}
	}
	if !strings.Contains(set, "current-context: hydra\n") {
		t.Error("the current context stays")
	}
	c := w.readConfig()
	if !strings.Contains(c, "hydra-nazar:") || !strings.Contains(c, "com.googlecode.iterm2") || !strings.Contains(c, "-nazar") ||
		strings.Contains(c, "groups") || strings.Contains(c, "clients") {
		t.Errorf("config.yaml has no hydra-nazar entry with the terminal's login rule and identity <user>-nazar, and no clients:\n%s", c)
	}
	crt := filepath.Join(layout.KeysDir(w.home), "k8s-ca-hydra-nazar.crt")
	pemFile, err := os.ReadFile(crt)
	if err != nil {
		t.Fatal(err)
	}
	// The world's CLI warns on stderr (mixed into the output here) that it trusts
	// any same-user control socket; besides it, ca show prints the PEM.
	const peerWarning = "nazar: warning: NAZAR_TEST_PEER=same-user: not checking that the control socket is nazar-agent\n"
	if out = run(0, "k8s", "ca", "show", "hydra-nazar"); strings.Replace(out, peerWarning, "", 1) != string(pemFile) {
		t.Fatalf("ca show prints %s and nothing else:\n%s", crt, out)
	}
	says(t, run(0, "k8s", "ca", "show", "hydra-nazar", "--microk8s"), string(pemFile))
	// Again: set up already, nothing asked or changed.
	says(t, run(0, "k8s", "ca", "create", "hydra-nazar", "https://127.0.0.1:1"), "already has nazar's entries for hydra-nazar")
	if kubeconfig() != set {
		t.Fatal("ca create again changed the kubeconfig")
	}

	// nazar k8s list, and --json for scripts and agents.
	out = run(0, "k8s", "list")
	says(t, out, "ca-cert for CN=")
	says(t, out, "-nazar (ttl_cert")
	says(t, out, "CA: SHA-256 ")
	var list struct {
		Kind  string `json:"kind"`
		Items []struct {
			Name       string `json:"name"`
			Configured bool   `json:"configured"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(run(0, "--json", "k8s", "list")), &list); err != nil || list.Kind != "K8sContextList" ||
		len(list.Items) != 1 || list.Items[0].Name != "hydra-nazar" || !list.Items[0].Configured {
		t.Errorf("k8s list --json: %v %+v", err, list)
	}

	// nazar k8s credential is kubectl's to run, not a person's.
	says(t, run(2, "k8s", "credential", "hydra-nazar"), "nazar: no KUBERNETES_EXEC_INFO")

	// kubectl runs the entry ca create added; it reaches this nazar-testd
	// (the audit line), whose check 0 refuses it, before kubectl dials
	// anything.
	if kubectl == "" {
		t.Log("no kubectl on PATH: the kubectl run is not tested")
	} else {
		out, code := w.run(nil, kubectl, "--kubeconfig", kc, "--context", "hydra-nazar", "--request-timeout=5s", "get", "pods")
		if code == 0 || strings.Contains(out, "connection refused") {
			t.Fatalf("kubectl: exit %d\n%s", code, out)
		}
		says(t, out, "nazar: peer is not the nazar CLI")
		says(t, out, "getting credentials: exec:", "AGENTS.md")
		says(t, out, "failed with exit code 3", "AGENTS.md")
		says(t, out, "exit code 3", "docs/CLI.md")
		if !w.auditHas("decision=blocked", "target=k8s:hydra-nazar", "not the nazar CLI") {
			t.Errorf("no blocked k8s:hydra-nazar line in nazar-testd's audit:\n%s", w.auditDump())
		}
	}

	// nazar k8s forget hydra-nazar: the CA, its file and the entry go, and
	// the kubeconfig loses exactly nazar's entries.
	out = run(0, "k8s", "forget", "hydra-nazar")
	says(t, out, "Removed nazar's entries for hydra-nazar from "+kc)
	noSecret("forget", out)
	if _, err := os.Stat(crt); !os.IsNotExist(err) {
		t.Errorf("forget left %s (%v)", crt, err)
	}
	if c := w.readConfig(); strings.Contains(c, "hydra-nazar") {
		t.Errorf("config.yaml still has hydra-nazar:\n%s", c)
	}
	if kubeconfig() != string(original) {
		t.Errorf("forget leaves the kubeconfig as it was before ca create:\n%s", kubeconfig())
	}
	says(t, run(0, "k8s", "list"), "No k8s contexts.")
}

// says fails unless out contains phrase, and so does each doc named (a
// path from the repository's root): what a doc quotes is what nazar
// prints. A phrase must sit on one line of the doc.
func says(t *testing.T, out, phrase string, docs ...string) {
	t.Helper()
	if !strings.Contains(out, phrase) {
		t.Errorf("the output does not say %q:\n%s", phrase, out)
	}
	for _, d := range docs {
		b, err := os.ReadFile(filepath.Join(repo, d))
		if err != nil || !strings.Contains(string(b), phrase) {
			t.Errorf("%s does not say %q, which nazar prints (%v)", d, phrase, err)
		}
	}
}

// adminKubeconfig is a kubeconfig shaped like `microk8s config`'s: context
// hydra, its cluster's CA, and a user with an admin client certificate and
// key (throwaway, self-signed here; the cluster CA is the same
// certificate, and nothing dials the server). It returns the file and the
// key's base64, which no output may show.
func adminKubeconfig(t *testing.T) ([]byte, []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin", Organization: []string{"system:masters"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	cert := b64(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyData := b64(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
	body := "apiVersion: v1\nkind: Config\nclusters:\n- name: hydra\n  cluster:\n    server: https://127.0.0.1:1\n" +
		"    certificate-authority-data: " + cert + "\nusers:\n- name: admin\n  user:\n    client-certificate-data: " + cert +
		"\n    client-key-data: " + keyData + "\ncontexts:\n- name: hydra\n  context: {cluster: hydra, user: admin}\ncurrent-context: hydra\n"
	return []byte(body), []string{keyData}
}
