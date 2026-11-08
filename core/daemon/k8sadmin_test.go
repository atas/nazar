package daemon

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/envpolicy"
)

// The k8s design: nazar k8s ca create (the CA and
// the config entry written as ssh-key create writes a key's, on one login
// prompt; no program is pinned), ca show, list and forget, on the control
// socket. nazar-agent never touches a kubeconfig or a cluster.

// lockedVault is the fake vault with items the Keychain refuses to return,
// and items it refuses to write.
type lockedVault struct {
	*fake.Vault
	mu      sync.Mutex
	locked  map[string]bool
	failPut map[string]bool
}

func (v *lockedVault) Get(name string) ([]byte, error) {
	v.mu.Lock()
	l := v.locked[name]
	v.mu.Unlock()
	if l {
		return nil, errors.New("errSecInteractionNotAllowed")
	}
	return v.Vault.Get(name)
}

func (v *lockedVault) Put(name string, data []byte) error {
	v.mu.Lock()
	f := v.failPut[name]
	v.mu.Unlock()
	if f {
		return errors.New("errSecInteractionNotAllowed")
	}
	return v.Vault.Put(name, data)
}

func (v *lockedVault) lock(name string) {
	v.mu.Lock()
	v.locked[name] = true
	v.mu.Unlock()
}

func (v *lockedVault) refusePut(name string) {
	v.mu.Lock()
	v.failPut[name] = true
	v.mu.Unlock()
}

const kubectlApps = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  kubectl: {signed: {team: KUBETEAM01, id: kubectl}}
`

// noKubectl is a config without apps.kubectl, which nothing needs (ca
// create adds none).
func (e *adminEnv) noKubectl() string {
	return "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n"
}

type adminEnv struct {
	*env
	vault      *lockedVault
	pin        cluster.Pin
	clusterPEM []byte
}

func startAdmin(t *testing.T) *adminEnv {
	t.Helper()
	lv := &lockedVault{Vault: fake.NewVault(), locked: map[string]bool{}, failPut: map[string]bool{}}
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		o.Vault = lv
		o.Pipes = f
		o.RunHost = func(int) (envpolicy.Host, error) { return envpolicy.Host{Home: "/Users/dev", User: "dev"}, nil }
	})
	clusterPEM := clusterCA(t, "hydra cluster CA")
	pin, err := cluster.PinOf(cluster.Info{Server: "https://hydra.example:16443", CAData: clusterPEM})
	if err != nil {
		t.Fatal(err)
	}
	e.approved(t, kubectlApps)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(cliProc("k8s"))
	return &adminEnv{env: e, vault: lv, pin: pin, clusterPEM: clusterPEM}
}

// createArgs are ca create's arguments for name on e's cluster.
func (e *adminEnv) createArgs(name string) map[string]string {
	return map[string]string{"name": name, "server": e.pin.Server, "caSHA256": e.pin.CASHA256, "tlsServerName": e.pin.TLSServerName,
		"proxyURL": e.pin.ProxyURL, "kubeconfig": "/Users/dev/.kube/config"}
}

func (e *adminEnv) create(t *testing.T, args map[string]string) (control.K8sContext, *control.Problem) {
	t.Helper()
	var c control.K8sContext
	err := e.call(t, control.CmdK8sCACreate, args, control.KindK8sContext, &c)
	return c, control.AsProblem(err)
}

func (e *adminEnv) caCreate(t *testing.T, name string) (control.K8sContext, *control.Problem) {
	t.Helper()
	return e.create(t, e.createArgs(name))
}

func (e *adminEnv) certFile(name string) string {
	return filepath.Join(layout.KeysDir(e.home), "k8s-ca-"+name+".crt")
}

// nothingMade fails unless name has no CA, no certificate file, no config
// entry, and config.yaml is as it was.
func (e *adminEnv) nothingMade(t *testing.T, name, cfg string) {
	t.Helper()
	if _, err := e.d.k8sCA.Get(name); !errors.Is(err, k8s.ErrNotFound) {
		t.Errorf("no CA for %s: %v", name, err)
	}
	if _, err := os.Stat(e.certFile(name)); !os.IsNotExist(err) {
		t.Errorf("no certificate file for %s", name)
	}
	if e.d.stager.Active().K8s[name] != nil || e.readConfig(t) != cfg {
		t.Errorf("config.yaml is as it was:\n%s", e.readConfig(t))
	}
}

func TestK8sCACreateSetsUpOnOnePrompt(t *testing.T) {
	e := startAdmin(t)
	e.approved(t, e.noKubectl())
	logins := e.logins()
	c, p := e.caCreate(t, "hydra")
	if p != nil {
		t.Fatal(p)
	}
	if e.logins() != logins+1 {
		t.Fatalf("one login prompt, got %d", e.logins()-logins)
	}
	// The prompt shows everything that is made.
	prompt := e.f.Shown()[len(e.f.Shown())-1].Prompt
	text := prompt.Title + "\n" + strings.Join(prompt.Lines, "\n")
	for _, want := range []string{`Set up Kubernetes context "hydra"?`, "Secure Enclave", "CN=dev-nazar (no groups", "https://hydra.example:16443",
		"server CA: sha256 Fingerprint=" + colonHex(e.pin.CASHA256), "the program that runs the plugin (kubectl, helm, k9s …) gets the credential",
		`app:"com.googlecode.iterm2"`, `"/Users/dev/.kube/config"`} {
		if !strings.Contains(text, want) {
			t.Errorf("the prompt must show %q:\n%s", want, text)
		}
	}
	for _, never := range []string{"clients", "trust ", "apps.kubectl"} {
		if strings.Contains(text, never) {
			t.Errorf("no program is pinned: the prompt must not show %q:\n%s", never, text)
		}
	}
	// The CA, its certificate file and the entry; no apps.kubectl, no pin.
	stored, err := e.d.k8sCA.Get("hydra")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(e.certFile("hydra")); err != nil || !bytes.Equal(b, stored.CertPEM()) {
		t.Fatalf("the certificate file: %v", err)
	}
	active := e.d.stager.Active()
	k := active.K8s["hydra"]
	if k == nil || k.Cluster != e.pin || k.Identity.User != "dev-nazar" || len(k.Identity.Groups) != 0 || k.Credential != "ca-cert" ||
		k.Own == nil || k.Own.Gate != "block" || len(k.Rules) != 1 || k.Rules[0].Apps[0].ID != "com.googlecode.iterm2" || k.LeftoverClients {
		t.Fatalf("the entry %+v", k)
	}
	if _, ok := active.Apps["kubectl"]; ok {
		t.Fatal("no apps.kubectl is added")
	}
	if cfg := e.readConfig(t); strings.Contains(cfg, "groups") || strings.Contains(cfg, "clients") {
		t.Fatalf("no groups, no clients:\n%s", cfg)
	}
	// The reply: the context, its CA with the certificate for the steps.
	if !c.Configured || c.State != control.K8sStateOK || c.Identity == nil || c.Identity.User != "dev-nazar" || len(c.Identity.Groups) != 0 ||
		c.CA == nil || c.CA.CertPEM != string(stored.CertPEM()) || c.CA.CertFile != e.certFile("hydra") {
		t.Fatalf("%+v", c)
	}
	if f := e.lastAudit(t); f["target"] != "k8s:hydra" {
		t.Fatalf("audit %v", f)
	}
	// Again, the same: set up already, answered at once (it finishes a run
	// whose kubeconfig write failed).
	logins = e.logins()
	if c, p := e.caCreate(t, "hydra"); p != nil || !c.Configured || c.CA == nil || c.CA.CertPEM == "" || e.logins() != logins {
		t.Fatalf("again: %+v %+v", c, p)
	}
}

// The minted certificates name <user>-nazar and no group (extends the
// mint test of k8s_test.go to the entry ca create writes).
func TestK8sCACreateMintsForUserNazarWithNoGroups(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), credCLI("hydra"))
	e.f.SetDefaultPeer(tab.Peer())
	var cred control.K8sCredential
	if err := e.call(t, control.CmdK8sCredential, map[string]string{"name": "hydra", "execInfo": execInfo(t, e.pin.Server, e.clusterPEM)}, control.KindK8sCredential, &cred); err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(cred.ClientCertificateData))
	if b == nil {
		t.Fatal("no certificate")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := e.d.k8sCA.Get("hydra")
	if cert.Subject.CommonName != "dev-nazar" || len(cert.Subject.Organization) != 0 || cert.CheckSignatureFrom(ca.Cert) != nil {
		t.Fatalf("subject %v", cert.Subject)
	}
}

func TestK8sCACreateDeniedMakesNothing(t *testing.T) {
	e := startAdmin(t)
	e.approved(t, e.noKubectl())
	cfg := e.readConfig(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	logins := e.logins()
	if _, p := e.caCreate(t, "hydra"); p == nil || p.Code != control.CodeRefused {
		t.Fatalf("denied: %+v", p)
	}
	if e.logins() != logins+1 {
		t.Fatal("one prompt")
	}
	e.nothingMade(t, "hydra", cfg)
}

func TestK8sCACreateConfigChangedDuringThePrompt(t *testing.T) {
	e := startAdmin(t)
	e.approved(t, e.noKubectl())
	release := e.holdLogin(t, true)
	var c control.K8sContext
	done := e.callInBackground(t, control.CmdK8sCACreate, e.createArgs("hydra"), control.KindK8sContext, &c)
	waitFor(t, func() bool { return e.isOpen() })
	e.writeConfig(t, e.noKubectl()+"# edited\n")
	release()
	if p := <-done; p == nil || p.Code != control.CodeStaged {
		t.Fatalf("changed meanwhile: %+v", p)
	}
	e.nothingMade(t, "hydra", e.noKubectl()+"# edited\n")
}

// A step that fails after the prompt undoes the ones before it: the CA is
// destroyed again, config.yaml restored, nothing else stays. (The step
// that fails here was the kubectl pin, which is gone: now it is saving
// the approved config.)
func TestK8sCACreateUndoesAFailedStep(t *testing.T) {
	e := startAdmin(t)
	e.approved(t, e.noKubectl())
	cfg := e.readConfig(t)
	e.vault.refusePut(configstage.ApprovedVaultItem)
	if _, p := e.caCreate(t, "hydra"); p == nil || p.Code != control.CodeError || !strings.Contains(p.Message, "could not be applied") {
		t.Fatalf("%+v", p)
	}
	e.nothingMade(t, "hydra", cfg)
}

// An apps.kubectl the user has is kept as it is.
func TestK8sCACreateKeepsAnAppsKubectl(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	if m := e.d.stager.Active().Apps["kubectl"]; m.Kind != config.MatchSigned {
		t.Fatalf("apps.kubectl %+v", m)
	}
}

// Security review: the prompt shows the whole CA fingerprint as openssl
// prints it, and the TLS server name and proxy each on a line of its own,
// whatever the length of the name; the client's user and groups are never
// the identity.
func TestK8sCACreatePromptShowsTheWholePin(t *testing.T) {
	e := startAdmin(t)
	e.approved(t, e.noKubectl())
	name := strings.Repeat("a", 128)
	a := e.createArgs(name)
	a["tlsServerName"], a["proxyURL"] = "hydra.internal", "socks5://127.0.0.1:1080"
	a["user"], a["groups"] = "root", "system:masters"
	if _, p := e.create(t, a); p != nil {
		t.Fatal(p)
	}
	lines := e.f.Shown()[len(e.f.Shown())-1].Prompt.Lines
	want := map[string]bool{"server: https://hydra.example:16443": false, "server CA: sha256 Fingerprint=" + colonHex(e.pin.CASHA256): false,
		"tls-server-name: hydra.internal": false, "proxy-url: socks5://127.0.0.1:1080": false}
	for _, l := range lines {
		if _, ok := want[l]; ok {
			want[l] = true
		}
	}
	for l, seen := range want {
		if !seen {
			t.Errorf("the prompt must have the line %q:\n%s", l, strings.Join(lines, "\n"))
		}
	}
	if fp := colonHex(e.pin.CASHA256); len(fp) != 95 || strings.ToUpper(fp) != fp {
		t.Fatalf("%q", fp)
	}
	k := e.d.stager.Active().K8s[name]
	if k == nil || k.Identity.User != "dev-nazar" || len(k.Identity.Groups) != 0 {
		t.Fatalf("%+v", k)
	}
}

func TestK8sCACreateRefusalsBeforeAnyPrompt(t *testing.T) {
	e := startAdmin(t)
	with := func(k, v string) map[string]string {
		a := e.createArgs("hydra2")
		a[k] = v
		return a
	}
	logins := e.logins()
	for name, a := range map[string]map[string]string{
		"name":       with("name", "a/b"),
		"no name":    with("name", ""),
		"server":     with("server", "http://x"),
		"unnormal":   with("server", "https://hydra.example:443"),
		"ca":         with("caSHA256", "xyz"),
		"tls name":   with("tlsServerName", "a b"),
		"kubeconfig": with("kubeconfig", "kube/config"),
	} {
		if _, p := e.create(t, a); p == nil || p.Code != control.CodeUsage {
			t.Errorf("%s: %+v", name, p)
		}
	}
	if e.logins() != logins {
		t.Fatal("no prompt for a refusal")
	}
	// A CA or an entry of that name already, another case of it.
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	logins = e.logins()
	other := e.createArgs("hydra")
	other["server"] = "https://evil.example"
	for name, a := range map[string]map[string]string{"another cluster": other, "another case": e.createArgs("HYDRA")} {
		if _, p := e.create(t, a); p == nil || p.Code != control.CodeError {
			t.Errorf("%s: %+v", name, p)
		}
	}
	if _, err := e.d.k8sCA.Create("loose", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	if _, p := e.caCreate(t, "loose"); p == nil || p.Code != control.CodeError || !strings.Contains(p.Message, "nazar k8s forget loose") {
		t.Errorf("a CA without an entry: %+v", p)
	}
	if e.logins() != logins {
		t.Fatal("no prompt for a refusal")
	}
	e.approved(t, e.readConfig(t)+"    byhand:\n      credential: ca-cert\n      identity: {user: dev-nazar}\n      cluster: {server: \""+e.pin.Server+"\", ca_sha256: "+e.pin.CASHA256+"}\n      gate: block\n")
	logins = e.logins()
	if _, p := e.caCreate(t, "byhand"); p == nil || p.Code != control.CodeError || !strings.Contains(p.Message, "nazar k8s forget byhand") {
		t.Errorf("an entry without a CA: %+v", p)
	}
	if e.logins() != logins {
		t.Fatal("no prompt for a refusal")
	}
	// A user name that can't be a Kubernetes user.
	e2 := startAdmin(t)
	e2.d.o.RunHost = func(int) (envpolicy.Host, error) { return envpolicy.Host{User: "a b"}, nil }
	if _, p := e2.caCreate(t, "hydra"); p == nil || p.Code != control.CodeError || !strings.Contains(p.Message, "user name") || e2.logins() != 0 {
		t.Fatalf("a bad user name: %+v", p)
	}
}

func TestK8sCACreateRefusesUnapprovedChanges(t *testing.T) {
	// A loosening whose background prompt is denied stays staged.
	e := startAdmin(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	denied := len(e.configAudit(t, audit.Denied))
	e.writeConfig(t, kubectlApps+"ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [iterm]\n          gate: dialog\n")
	// Wait for the background prompt's denial too, not just the staging:
	// until it is answered its claim is open, and a later answer could
	// still be taken by it.
	waitFor(t, func() bool { return e.stillStaged() && len(e.configAudit(t, audit.Denied)) > denied })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	logins := e.logins()
	if _, p := e.caCreate(t, "hydra"); p == nil || p.Code != control.CodeStaged || e.logins() != logins {
		t.Fatalf("pending: %+v", p)
	}
	if _, err := e.d.k8sCA.Get("hydra"); !errors.Is(err, k8s.ErrNotFound) {
		t.Fatal("no CA")
	}
}

func TestK8sCAShow(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	logins := e.logins()
	var ca control.K8sCA
	if err := e.call(t, control.CmdK8sCAShow, map[string]string{"name": "hydra"}, control.KindK8sCA, &ca); err != nil {
		t.Fatal(err)
	}
	stored, _ := e.d.k8sCA.Get("hydra")
	if ca.CertPEM != string(stored.CertPEM()) || e.logins() != logins {
		t.Fatal("show reads the Vault record, no prompt")
	}
	// The file is user-writable: show never reads it.
	_ = os.WriteFile(ca.CertFile, []byte("tampered"), 0o644)
	if err := e.call(t, control.CmdK8sCAShow, map[string]string{"name": "hydra"}, control.KindK8sCA, &ca); err != nil || !strings.HasPrefix(ca.CertPEM, "-----BEGIN CERTIFICATE-----") {
		t.Fatal("show reads the record, not the file")
	}
	if err := e.call(t, control.CmdK8sCAShow, map[string]string{"name": "nope"}, control.KindK8sCA, &ca); err == nil {
		t.Fatal("no CA")
	}
}

func TestK8sCACreateNeverFollowsAPlantedLink(t *testing.T) {
	e := startAdmin(t)
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("victim"), 0o600)
	_ = os.MkdirAll(filepath.Dir(e.certFile("hydra")), 0o700)
	if err := os.Symlink(victim, e.certFile("hydra")); err != nil {
		t.Fatal(err)
	}
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	if b, _ := os.ReadFile(victim); string(b) != "victim" {
		t.Fatal("the link's target was written")
	}
	if fi, err := os.Lstat(e.certFile("hydra")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the link is replaced by the certificate file")
	}
}

func TestK8sCACreateRefusesAnUnreadableItem(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	e.vault.lock("k8s-ca/hydra")
	logins := e.logins()
	if _, p := e.caCreate(t, "hydra"); p == nil || p.Code != control.CodeError {
		t.Fatalf("%+v", p)
	}
	var fp control.K8sContext
	if err := e.call(t, control.CmdK8sForget, map[string]string{"name": "hydra"}, control.KindK8sContext, &fp); err == nil ||
		!strings.Contains(err.Error(), "security delete-generic-password -s dev.nazar -a k8s-ca/hydra") {
		t.Fatalf("forget of an unreadable CA names the fix: %v", err)
	}
	if e.logins() != logins {
		t.Fatal("refused before any prompt")
	}
	e.vault.locked = map[string]bool{}
	if _, err := e.d.k8sCA.Get("hydra"); err != nil {
		t.Fatal("nothing was deleted")
	}
}

func TestK8sListAndAdvice(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	if _, err := e.d.k8sCA.Create("loose", platform.AccessWhenUnlocked); err != nil { // a CA with no entry (an old ca create)
		t.Fatal(err)
	}
	// A context configured by hand with no CA.
	body := e.readConfig(t) + "    nocas:\n      credential: ca-cert\n      identity:\n        user: dev\n      cluster:\n        server: https://n.example\n        ca_sha256: " + e.pin.CASHA256 + "\n      gate: block\n"
	e.approved(t, body)
	var l control.K8sContextList
	if err := e.call(t, control.CmdK8sList, nil, control.KindK8sContextList, &l); err != nil {
		t.Fatal(err)
	}
	got := map[string]control.K8sContext{}
	for _, c := range l.Items {
		got[c.Name] = c
	}
	if a := got["hydra"]; !a.Configured || a.CA == nil || a.Credential != "ca-cert" || a.TTLCert != "15m0s" || len(a.Rules) != 2 {
		t.Fatalf("hydra %+v", a)
	}
	if lo := got["loose"]; lo.Configured || lo.CA == nil || lo.State != control.K8sStateNoEntry || lo.Remedy != "nazar k8s forget loose, then nazar k8s ca create loose" {
		t.Fatalf("a CA without an entry: %+v", lo)
	}
	if n := got["nocas"]; !n.Configured || n.CA != nil || n.Remedy != "nazar k8s forget nocas, then nazar k8s ca create nocas" {
		t.Fatalf("an entry without a CA: %+v", n)
	}
	var cc control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &cc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pr := range cc.Problems {
		if strings.Contains(pr.Message, "nazar k8s forget nocas`, then `nazar k8s ca create nocas") {
			found = true
		}
	}
	if !found {
		t.Fatalf("config check warns about a context without a CA: %+v", cc.Problems)
	}
	// A CA the Keychain won't return is listed, with the fix.
	e.vault.lock("k8s-ca/loose")
	if err := e.call(t, control.CmdK8sList, nil, control.KindK8sContextList, &l); err != nil {
		t.Fatal(err)
	}
	for _, c := range l.Items {
		if c.Name == "loose" && (!c.CABroken || !strings.Contains(c.Remedy, "security delete-generic-password -s dev.nazar -a k8s-ca/loose")) {
			t.Fatalf("unreadable CA: %+v", c)
		}
	}
}

func TestK8sForget(t *testing.T) {
	e := startAdmin(t)
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	// A remembered approval for hydra: kubectl in an iTerm2 tab, the login
	// rule ca create wrote, allowed.
	tab := e.f.ITermTab(platform.ProcessRef{}, kubeProc("get", "pods"), credCLI("hydra"))
	e.f.SetDefaultPeer(tab.Peer())
	info := execInfo(t, e.pin.Server, e.clusterPEM)
	var cred control.K8sCredential
	if err := e.call(t, control.CmdK8sCredential, map[string]string{"name": "hydra", "execInfo": info}, control.KindK8sCredential, &cred); err != nil {
		t.Fatal(err)
	}
	if n := len(e.d.cache.List()); n != 1 {
		t.Fatalf("one remembered approval, got %d", n)
	}
	e.asCLI(cliProc("k8s", "forget", "hydra"))
	logins := e.logins()
	var c control.K8sContext
	if err := e.call(t, control.CmdK8sForget, map[string]string{"name": "hydra", "kubeconfig": "/Users/dev/.kube/config"}, control.KindK8sContext, &c); err != nil {
		t.Fatal(err)
	}
	if e.logins() != logins+1 || c.Configured || c.CA != nil {
		t.Fatalf("one prompt, nothing left: %+v", c)
	}
	// The prompt says what the CLI does to the kubeconfig after it.
	if lines := strings.Join(e.f.Shown()[len(e.f.Shown())-1].Prompt.Lines, "\n"); !strings.Contains(lines, `removes nazar's entries for hydra from "/Users/dev/.kube/config"`) {
		t.Fatalf("the prompt:\n%s", lines)
	}
	if _, err := e.d.k8sCA.Get("hydra"); !errors.Is(err, k8s.ErrNotFound) {
		t.Fatal("the CA is gone")
	}
	if _, err := os.Stat(e.certFile("hydra")); !os.IsNotExist(err) {
		t.Fatal("the .crt file is gone")
	}
	if e.d.stager.Active().K8s["hydra"] != nil || strings.Contains(e.readConfig(t), "hydra:") {
		t.Fatal("the config entry is gone")
	}
	if n := len(e.d.cache.List()); n != 0 {
		t.Fatalf("the approvals for hydra are gone: %d", n)
	}
	e.f.SetDefaultPeer(tab.Peer())
	if err := e.call(t, control.CmdK8sCredential, map[string]string{"name": "hydra", "execInfo": info}, control.KindK8sCredential, &cred); control.AsProblem(err) == nil || control.AsProblem(err).Code != control.CodeUsage {
		t.Fatalf("a forgotten context: %v", err)
	}
	// Unknown: an error before any prompt; denied: nothing deleted.
	logins = e.logins()
	if err := e.call(t, control.CmdK8sForget, map[string]string{"name": "hydra"}, control.KindK8sContext, &c); err == nil || e.logins() != logins {
		t.Fatalf("unknown: %v", err)
	}
	e.f.Advance(2 * time.Minute) // past the prompt cooldown of the refusal above
	if _, p := e.caCreate(t, "staging"); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	if err := e.call(t, control.CmdK8sForget, map[string]string{"name": "staging"}, control.KindK8sContext, &c); control.AsProblem(err) == nil || control.AsProblem(err).Code != control.CodeRefused {
		t.Fatalf("denied: %v", err)
	}
	if _, err := e.d.k8sCA.Get("staging"); err != nil {
		t.Fatal("a denied forget deletes nothing")
	}
}

// forget's two guards on config.yaml. Unapproved
// changes are not applied under forget's approval, and a file changed while
// the prompt was open changes nothing.
func TestK8sForgetGuards(t *testing.T) {
	ready := func(t *testing.T) *adminEnv {
		e := startAdmin(t)
		if _, p := e.caCreate(t, "hydra"); p != nil {
			t.Fatal(p)
		}
		return e
	}
	intact := func(t *testing.T, e *adminEnv) {
		t.Helper()
		if _, err := e.d.k8sCA.Get("hydra"); err != nil {
			t.Fatal("the CA must stay")
		}
		if e.d.stager.Active().K8s["hydra"] == nil {
			t.Fatal("the entry must stay")
		}
	}
	t.Run("unapproved changes", func(t *testing.T) {
		e := ready(t)
		e.f.SetDefaults(fake.Answer{}, fake.Answer{})
		denied := len(e.configAudit(t, audit.Denied))
		e.writeConfig(t, e.readConfig(t)+"ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [iterm]\n          gate: dialog\n")
		// Wait for the background prompt's denial too, not just the staging:
		// until it is answered its claim is open, and a later answer could
		// still be taken by it.
		waitFor(t, func() bool { return e.stillStaged() && len(e.configAudit(t, audit.Denied)) > denied })
		e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
		var c control.K8sContext
		err := e.call(t, control.CmdK8sForget, map[string]string{"name": "hydra"}, control.KindK8sContext, &c)
		if p := control.AsProblem(err); p == nil || p.Code != control.CodeStaged {
			t.Fatalf("%+v", p)
		}
		intact(t, e)
		if e.d.stager.Active().SSHAgent.Keys["k"] != nil {
			t.Fatal("the pending loosening must not be applied")
		}
	})
	t.Run("changed while the prompt is open", func(t *testing.T) {
		e := ready(t)
		release := e.holdLogin(t, true)
		var c control.K8sContext
		done := e.callInBackground(t, control.CmdK8sForget, map[string]string{"name": "hydra"}, control.KindK8sContext, &c)
		waitFor(t, func() bool { return e.isOpen() })
		e.writeConfig(t, e.readConfig(t)+"# edited\n")
		release()
		if p := <-done; p == nil || p.Code != control.CodeStaged {
			t.Fatalf("%+v", p)
		}
		intact(t, e)
	})
}

// A CA record that reads but is unusable (not one
// the Keychain refuses) is fixed by forget, which ca create says.
func TestK8sCACreateOverABrokenRecord(t *testing.T) {
	e := startAdmin(t)
	if err := e.vault.Vault.Put("k8s-ca/hydra", []byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, p := e.caCreate(t, "hydra"); p == nil || !strings.Contains(p.Message, "nazar k8s forget hydra") {
		t.Fatalf("%+v", p)
	}
	var c control.K8sContext
	if err := e.call(t, control.CmdK8sForget, map[string]string{"name": "hydra"}, control.KindK8sContext, &c); err != nil {
		t.Fatalf("forget of a broken record: %v", err)
	}
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatalf("after forget: %+v", p)
	}
}
