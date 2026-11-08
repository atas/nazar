package daemon

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// k8s design 1.2, 2, 6.1: k8s.credential is a value command,
// answered only to the genuine nazar CLI; nazar-agent parses the exec info,
// runs checks 1 to 3 and the gate, checks the context again at mint time
// and mints a certificate from the context's CA. Nothing but the reply
// carries the key or the certificate.

var kubeCode = platform.CodeIdentity{Signed: true, TeamID: "KUBETEAM01", SigningID: "kubectl", CDHash: []byte{0x0c}}

func kubeProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/usr/local/bin/kubectl", Args: append([]string{"kubectl"}, args...), Cwd: "/Users/u/projects/foo", Code: kubeCode}
}

// credCLI is the plugin as client-go runs it: its stdout a pipe whose
// read end its parent holds (THREAT-MODEL 5.16).
func credCLI(ctx string) fake.Proc {
	p := cliProc("k8s", "credential", ctx)
	p.StdoutToParent = true
	return p
}

func clusterCA(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func execInfo(t *testing.T, server string, ca []byte) string {
	t.Helper()
	cl := map[string]any{"server": server}
	if ca != nil {
		cl["certificate-authority-data"] = ca
	}
	b, err := json.Marshal(map[string]any{"apiVersion": k8s.ExecAPIVersion, "kind": "ExecCredential",
		"spec": map[string]any{"interactive": false, "cluster": cl}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type k8sEnv struct {
	*env
	server string
	ca     []byte // the cluster's CA (its serving side)
	body   string // the approved config.yaml
	logs   *logBuf
	shown0 int // prompts shown while setting up (the config approval)
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.WriteString(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n")
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func k8sConfig(server, hash string) string {
	return `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  kubectl: {signed: {team: KUBETEAM01, id: kubectl}}
k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      ttl_cert: 15m
      cluster: {server: "` + server + `", ca_sha256: ` + hash + `}
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
`
}

// startK8s runs a daemon whose CLI check accepts the fake's nazar CLI and
// whose stdout check is the fake's, with an approved hydra context and its
// CA made.
func startK8s(t *testing.T) *k8sEnv { return startK8sWith(t, nil) }

// startK8sWith is startK8s with mod applied to the options last.
func startK8sWith(t *testing.T, mod func(f *fake.Fake, o *Options)) *k8sEnv {
	t.Helper()
	logs := &logBuf{}
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		o.Logf = logs.Printf
		o.Pipes = f
		if mod != nil {
			mod(f, o)
		}
	})
	ke := &k8sEnv{env: e, server: "https://hydra.example:16443", ca: clusterCA(t, "hydra cluster CA"), logs: logs}
	pin, err := cluster.PinOf(cluster.Info{Server: ke.server, CAData: ke.ca})
	if err != nil {
		t.Fatal(err)
	}
	ke.body = k8sConfig(ke.server, pin.CASHA256)
	e.approved(t, ke.body)
	if _, err := e.d.k8sCA.Create("hydra", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{}) // nothing allowed unless a test says so
	ke.shown0 = len(e.f.Shown())
	return ke
}

func (e *k8sEnv) credential(t *testing.T, name, info string) (control.K8sCredential, *control.Problem) {
	t.Helper()
	var c control.K8sCredential
	err := e.call(t, control.CmdK8sCredential, map[string]string{"name": name, "execInfo": info}, control.KindK8sCredential, &c)
	return c, control.AsProblem(err)
}

func (e *k8sEnv) ok(t *testing.T) string { return execInfo(t, e.server, e.ca) }

func (e *k8sEnv) caCert(t *testing.T) *x509.Certificate {
	t.Helper()
	ca, err := e.d.k8sCA.Get("hydra")
	if err != nil {
		t.Fatal(err)
	}
	return ca.Cert
}

func TestK8sCredentialMintsForTheIdentity(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), credCLI("hydra"))
	e.f.SetDefaultPeer(tab.Peer())
	before := time.Now()
	c, p := e.credential(t, "hydra", e.ok(t))
	if p != nil {
		t.Fatal(p)
	}
	if c.Kind != control.KindK8sCredential || c.Name != "hydra" {
		t.Fatalf("%+v", c)
	}
	b, _ := pem.Decode([]byte(c.ClientCertificateData))
	if b == nil {
		t.Fatal("no certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "admin" || !slices.Equal(cert.Subject.Organization, []string{"system:masters"}) || cert.CheckSignatureFrom(e.caCert(t)) != nil {
		t.Fatalf("subject %v", cert.Subject)
	}
	if !c.ExpirationTimestamp.Equal(cert.NotAfter) || cert.NotAfter.Before(before.Add(14*time.Minute)) || cert.NotAfter.After(time.Now().Add(15*time.Minute)) {
		t.Fatalf("expirationTimestamp %v, notAfter %v", c.ExpirationTimestamp, cert.NotAfter)
	}
	kb, _ := pem.Decode([]byte(c.ClientKeyData))
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil || !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("the key is the certificate's")
	}
	f := e.lastAudit(t)
	if f["target"] != "k8s:hydra" || f["decision"] != "approved" || f["destination"] != e.server || f["operation"] != "k8s credential" ||
		!strings.HasPrefix(f["receiver"], "kubectl get pods") {
		t.Fatalf("audit %v", f)
	}
	// Another kubectl in the same tab: the session approval covers it, and
	// it gets a certificate of its own.
	k := e.f.Launch(tab.Shell, kubeProc("get", "svc"))
	e.f.SetDefaultPeer(e.f.Launch(k, credCLI("hydra")))
	c2, p := e.credential(t, "hydra", e.ok(t))
	if p != nil || c2.ClientKeyData == c.ClientKeyData {
		t.Fatalf("same tab: %+v", p)
	}
	if f := e.lastAudit(t); f["decision"] != "allowed" || f["reason"] != "cached approval" {
		t.Fatalf("audit %v", f)
	}
	// Another tab asks again.
	e.asCLI(kubeProc("get", "svc"), credCLI("hydra"))
	if _, p := e.credential(t, "hydra", e.ok(t)); p != nil {
		t.Fatal(p)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("one dialog per tab: %d", n)
	}
}

func (e *env) lastAudit(t *testing.T) map[string]string {
	t.Helper()
	lines := e.sink.Lines()
	if len(lines) == 0 {
		t.Fatal("no audit line")
	}
	f, err := audit.ParseLine(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestK8sCredentialAnswersOnlyTheGenuineCLI(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	signs := e.f.SignCalls()
	for name, impostor := range map[string]fake.Proc{
		"unsigned":         {Path: "/tmp/fake-nazar", Args: []string{"nazar", "k8s", "credential", "hydra"}},
		"ad hoc":           {Path: "/tmp/fake-nazar", Args: []string{"nazar"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "dev.nazar.cli"}},
		"another team":     {Path: "/tmp/fake-nazar", Args: []string{"nazar"}, Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "dev.nazar.cli"}},
		"kubectl itself":   kubeProc("get", "pods"),
		"another nazarcmd": {Path: "/tmp/x", Code: platform.CodeIdentity{Signed: true, TeamID: "NAZARTEAM0", SigningID: "dev.nazar.agent"}},
	} {
		e.asCLI(kubeProc("get", "pods"), impostor)
		c, p := e.credential(t, "hydra", e.ok(t))
		if p == nil || p.Code != control.CodeRefused || p.Message != errNotCLI || c.ClientKeyData != "" {
			t.Fatalf("%s: %+v %+v", name, p, c)
		}
		if f := e.lastAudit(t); f["decision"] != "blocked" || f["target"] != "k8s:hydra" || f["reason"] != errNotCLI {
			t.Fatalf("%s: audit %v", name, f)
		}
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 {
		t.Fatalf("nothing signed, nothing asked: %d signs, %d prompts", e.f.SignCalls()-signs, len(e.f.Shown())-e.shown0)
	}
	// A name nobody configured is refused the same way, named safely.
	e.asCLI(kubeProc(), fake.Proc{Path: "/tmp/fake-nazar"})
	if _, p := e.credential(t, "../../x\x1b", e.ok(t)); p == nil || p.Code != control.CodeRefused {
		t.Fatalf("%+v", p)
	}
	if f := e.lastAudit(t); f["target"] != "k8s:(invalid name)" {
		t.Fatalf("audit %v", f)
	}
}

// No client list (k8s design 2.1): whatever program runs the plugin in an
// allowed chain gets the credential, with no nazar trust; one whose code
// identity can't be told gets nothing, and no prompt.
func TestK8sCredentialGoesToAnyProgramInAnAllowedChain(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	py := fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "deploy.py"}, Code: fake.AppleCode("com.apple.python3")}
	helm := fake.Proc{Path: "/opt/homebrew/bin/helm", Args: []string{"helm", "list"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x4e}}}
	for name, procs := range map[string][]fake.Proc{
		"helm":      {helm, credCLI("hydra")},
		"python3":   {py, credCLI("hydra")},
		"the shell": {credCLI("hydra")},
	} {
		e.asCLI(procs...)
		c, p := e.credential(t, "hydra", e.ok(t))
		if p != nil || c.ClientCertificateData == "" {
			t.Fatalf("%s: %+v", name, p)
		}
	}
	signs, shown := e.f.SignCalls(), len(e.f.Shown())
	e.asCLI(fake.Proc{Path: "/usr/local/bin/kubectl", Args: []string{"kubectl"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "kubectl"}}, credCLI("hydra"))
	if _, p := e.credential(t, "hydra", e.ok(t)); p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "can't be identified") {
		t.Fatalf("no cdhash, no team: %+v", p)
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != shown {
		t.Fatal("nothing signed, nothing asked")
	}
	if w := e.f.Warnings(); len(w) == 0 || !strings.Contains(strings.Join(w[len(w)-1].Lines, "\n"), "can't be identified") {
		t.Fatalf("the block warning: %+v", w)
	}
}

func TestK8sCredentialRefusesOtherClusters(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	signs := e.f.SignCalls()
	insecure, _ := json.Marshal(map[string]any{"apiVersion": k8s.ExecAPIVersion, "kind": "ExecCredential",
		"spec": map[string]any{"cluster": map[string]any{"server": e.server, "certificate-authority-data": e.ca, "insecure-skip-tls-verify": true}}})
	noCluster, _ := json.Marshal(map[string]any{"apiVersion": k8s.ExecAPIVersion, "kind": "ExecCredential", "spec": map[string]any{"interactive": false}})
	for name, tc := range map[string][2]string{
		"look-alike CA": {execInfo(t, e.server, clusterCA(t, "look-alike")), "cluster mismatch: ca:"},
		"another host":  {execInfo(t, "https://10.0.0.9:16443", e.ca), "cluster mismatch: server:"},
		"another port":  {execInfo(t, "https://hydra.example:6443", e.ca), "cluster mismatch: server:"},
		"a path":        {execInfo(t, e.server+"/proxy", e.ca), "cluster mismatch: server:"},
		"no CA":         {execInfo(t, e.server, nil), "cluster mismatch: ca:"},
		"insecure":      {string(insecure), "cluster mismatch: insecure-skip-tls-verify"},
		"no cluster":    {string(noCluster), "no cluster info"},
	} {
		_, p := e.credential(t, "hydra", tc[0])
		if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, tc[1]) {
			t.Fatalf("%s: want %q, got %+v", name, tc[1], p)
		}
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 {
		t.Fatal("nothing signed, nothing asked")
	}
}

func TestK8sCredentialUsageErrors(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(kubeProc(), credCLI("hydra"))
	beta, _ := json.Marshal(map[string]any{"apiVersion": "client.authentication.k8s.io/v1beta1", "kind": "ExecCredential", "spec": map[string]any{}})
	for name, args := range map[string][2]string{
		"invalid name":    {"a/b", e.ok(t)},
		"unknown context": {"staging", e.ok(t)},
		"junk exec info":  {"hydra", "{"},
		"v1beta1":         {"hydra", string(beta)},
		"no exec info":    {"hydra", ""},
	} {
		_, p := e.credential(t, args[0], args[1])
		if p == nil || p.Code != control.CodeUsage {
			t.Errorf("%s: want a usage problem, got %+v", name, p)
		}
	}
	// A context with no CA: refused before any prompt, naming the fix.
	if err := e.d.k8sCA.Delete("hydra"); err != nil {
		t.Fatal(err)
	}
	_, p := e.credential(t, "hydra", e.ok(t))
	if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "nazar k8s ca create hydra") || len(e.f.Shown()) != e.shown0 {
		t.Fatalf("no CA: %+v", p)
	}
}

// The context is read again from the config in force when the certificate
// is minted: a context removed or re-pointed while the dialog was open
// mints nothing.
func TestK8sCredentialChecksAgainAtMint(t *testing.T) {
	for name, edit := range map[string]func(e *k8sEnv) string{
		"removed": func(e *k8sEnv) string {
			return "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n"
		},
		"re-pointed": func(e *k8sEnv) string {
			pin, _ := cluster.PinOf(cluster.Info{Server: "https://hydra.example:16443", CAData: clusterCA(t, "new")})
			return k8sConfig(e.server, pin.CASHA256)
		},
		// Security review: any change to the context while the
		// dialog was open mints nothing, tightenings and loosenings alike.
		"blocked": func(e *k8sEnv) string {
			return strings.Replace(e.body, "      rules:\n        - apps: [iterm]\n          scope: session\n          gate: dialog\n", "      gate: block\n", 1)
		},
		"groups widened": func(e *k8sEnv) string {
			return strings.Replace(e.body, "groups: [system:masters]", "groups: [system:masters, evil]", 1)
		},
		"ttl_cert longer":  func(e *k8sEnv) string { return strings.Replace(e.body, "ttl_cert: 15m", "ttl_cert: 1h", 1) },
		"ttl_cert shorter": func(e *k8sEnv) string { return strings.Replace(e.body, "ttl_cert: 15m", "ttl_cert: 5m", 1) },
		"turned off by a clients: line": func(e *k8sEnv) string {
			return strings.Replace(e.body, "      ttl_cert: 15m\n", "      ttl_cert: 15m\n      clients: [kubectl]\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := startK8s(t)
			hold := make(chan struct{})
			e.f.ScriptConfirm(fake.Answer{Allow: true, Wait: hold})
			e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
			var c control.K8sCredential
			done := e.callInBackground(t, control.CmdK8sCredential, map[string]string{"name": "hydra", "execInfo": e.ok(t)}, control.KindK8sCredential, &c)
			waitFor(t, func() bool { return e.f.CountShown(fake.KindConfirm) == 1 })
			signs := e.f.SignCalls()
			body := edit(e)
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
			e.writeConfig(t, body)
			// A removal applies at once; a re-pointed cluster loosens and
			// needs config apply (the login gate, allowed here).
			waitFor(t, func() bool {
				if string(e.d.stager.Active().Raw) == body {
					return true
				}
				_, _ = e.apply(t)
				return string(e.d.stager.Active().Raw) == body
			})
			close(hold)
			p := <-done
			if p == nil || c.ClientKeyData != "" || e.f.SignCalls() != signs {
				t.Fatalf("nothing may be minted: %+v (%d signs)", p, e.f.SignCalls()-signs)
			}
		})
	}
}

// The key and the certificate leave only in the reply: not in the audit
// log, the daemon's log, a Problem, status, config.yaml or any file.
func TestCredentialNeverLeavesThroughAnythingButTheReply(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	c, p := e.credential(t, "hydra", e.ok(t))
	if p != nil {
		t.Fatal(p)
	}
	// What is this credential's own: every base64 line of the key PEM, the
	// key's bytes, and the certificate's public key, signature and serial
	// (its issuer is the CA's subject, which the CA's record and file hold).
	var needles []string
	for _, l := range strings.Split(c.ClientKeyData, "\n") {
		if len(l) >= 24 && !strings.HasPrefix(l, "-----") {
			needles = append(needles, l[:24])
		}
	}
	kb, _ := pem.Decode([]byte(c.ClientKeyData))
	cb, _ := pem.Decode([]byte(c.ClientCertificateData))
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki := cert.RawSubjectPublicKeyInfo[len(cert.RawSubjectPublicKeyInfo)-64:]
	for _, b := range [][]byte{kb.Bytes[7:39], spki, cert.Signature[len(cert.Signature)-32:]} {
		needles = append(needles, string(b), base64.StdEncoding.EncodeToString(b)[:24], fmt.Sprintf("%x", b)[:24])
	}
	needles = append(needles, cert.SerialNumber.Text(16), cert.SerialNumber.String())
	// Every line of the certificate's PEM that is not also in the CA's own
	// certificate (the issuer name is).
	caB64 := base64.StdEncoding.EncodeToString(e.caCert(t).Raw)
	for _, l := range strings.Split(c.ClientCertificateData, "\n") {
		if len(l) >= 24 && !strings.HasPrefix(l, "-----") && !strings.Contains(caB64, l[:24]) {
			needles = append(needles, l[:24])
		}
	}
	var st control.Status
	_ = e.call(t, control.CmdStatus, nil, control.KindStatus, &st)
	stJSON, _ := json.Marshal(st)
	// A refused request's Problem.
	e.asCLI(kubeProc(), fake.Proc{Path: "/tmp/fake-nazar"})
	_, refused := e.credential(t, "hydra", e.ok(t))
	hay := map[string]string{
		"audit":   strings.Join(e.sink.Lines(), "\n"),
		"logs":    e.logs.String(),
		"status":  string(stJSON),
		"problem": refused.Message,
		"config":  e.readConfig(t),
	}
	_ = filepath.Walk(e.home, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			b, _ := os.ReadFile(path)
			hay["file "+path] = string(b)
		}
		return nil
	})
	names, _ := e.vault.List("")
	for _, name := range names {
		v, _ := e.vault.Get(name)
		hay["vault "+name] = string(v)
	}
	for where, text := range hay {
		for _, n := range needles {
			if strings.Contains(text, n) || bytes.Contains([]byte(text), []byte(n)) {
				t.Fatalf("credential material in %s", where)
			}
		}
	}
}

// A CA record this agent can't use is refused before any prompt, with the
// spec 9 fix, as an error (exit 1), and audited.
func TestK8sCredentialRefusesAnUnusableCA(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	e.approved(t, k8sConfig(e.pin.Server, e.pin.CASHA256))
	e.vault.lock("k8s-ca/hydra")
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	logins, shown := e.logins(), len(e.f.Shown())
	var c control.K8sCredential
	err := e.call(t, control.CmdK8sCredential, map[string]string{"name": "hydra", "execInfo": execInfo(t, e.pin.Server, e.clusterPEM)}, control.KindK8sCredential, &c)
	p := control.AsProblem(err)
	// ca create refuses a context set up already: forget comes before it.
	if p == nil || p.Code != control.CodeError || !strings.Contains(p.Message, "security delete-generic-password -s dev.nazar -a k8s-ca/hydra") ||
		!strings.Contains(p.Message, "then nazar k8s forget hydra (") || strings.Index(p.Message, "nazar k8s forget hydra") > strings.Index(p.Message, "nazar k8s ca create hydra") ||
		strings.Contains(p.Message, "k8s: the vault") || e.logins() != logins || len(e.f.Shown()) != shown {
		t.Fatalf("%+v", p)
	}
	if f := e.lastAudit(t); f["target"] != "k8s:hydra" || f["decision"] != "error" {
		t.Fatalf("audit %v", f)
	}
}
