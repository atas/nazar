package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/policy"
)

// K8s design 2, 2.4: a request for a context's credential runs the
// shared pipeline. The approval key is (k8s:<ctx>, rule, scope, the
// client's identity, op k8s:<ctx>); checks 1 and 2 block without a prompt,
// audited, with the block warning.

var (
	kctlCode = platform.CodeIdentity{Signed: true, TeamID: "KUBETEAM01", SigningID: "kubectl", CDHash: []byte{0x0c}}
	k9Code   = platform.CodeIdentity{Signed: true, TeamID: "KUBETEAM01", SigningID: "k9s", CDHash: []byte{0x09}}
)

func kubectl(args ...string) fake.Proc {
	return fake.Proc{Path: "/usr/local/bin/kubectl", Args: append([]string{"kubectl"}, args...), Cwd: "/Users/u/projects/foo", Code: kctlCode}
}

func k9s() fake.Proc {
	return fake.Proc{Path: "/usr/local/bin/k9s", Args: []string{"k9s"}, Cwd: "/Users/u", Code: k9Code}
}

func testCA(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type k8sBroker struct {
	*env
	info cluster.Info
}

func newK8sBroker(t *testing.T) *k8sBroker {
	t.Helper()
	ca := testCA(t)
	info := cluster.Info{Server: "https://hydra.example:16443", CAData: ca}
	pin, err := cluster.PinOf(info)
	if err != nil {
		t.Fatal(err)
	}
	ctx := func(name string) string {
		return `    ` + name + `:
      credential: ca-cert
      identity: {user: admin}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + pin.CASHA256 + `}
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
`
	}
	src := strings.Replace(cfgSrc, "  iterm: {app: com.googlecode.iterm2}\n",
		"  iterm: {app: com.googlecode.iterm2}\n  kubectl: {signed: {team: KUBETEAM01, id: kubectl}}\n  k9s: {signed: {team: KUBETEAM01, id: k9s}}\n", 1) +
		"k8s:\n  contexts:\n" + ctx("hydra") + ctx("staging") +
		strings.Replace(ctx("old"), "      rules:", "      clients: [kubectl, helm, k9s]\n      rules:", 1)
	return &k8sBroker{env: newEnvWith(t, src, 200*time.Millisecond), info: info}
}

func (e *k8sBroker) k8sReq(name string, peer platform.ProcessRef) Request {
	info := e.info
	return Request{
		K8s: name, Cluster: &info, Chain: e.r.Resolve(peer),
		Summary: "kubectl get pods", Operation: "k8s credential", Destination: info.Server,
		Do: func(platform.ApprovalRef) error { e.calls.Add(1); return nil },
	}
}

func cred() fake.Proc { return cliProc() }

func TestK8sApprovalCoversOneContextAndOneClient(t *testing.T) {
	e := newK8sBroker(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, kubectl("get", "pods"), cred())
	first := e.k8sReq("hydra", tab.Peer())
	first.Op = approval.Op{ID: "login:SHA256:gh", Text: "github.com"} // a module can't choose what it covers
	if r := e.b.Handle(first); r.Decision != audit.Approved || r.Outcome.Target != "k8s:hydra" {
		t.Fatalf("first: %+v", r)
	}
	again := e.f.Launch(tab.Shell, kubectl("get", "svc"))
	if r := e.b.Handle(e.k8sReq("hydra", e.f.Launch(again, cred()))); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("another kubectl in the same tab, same context: %+v", r)
	}
	// The same tab and client, another context: asks again.
	if r := e.b.Handle(e.k8sReq("staging", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("staging: %+v", r)
	}
	// The same tab and context, another client: asks again.
	k := e.f.Launch(tab.Shell, k9s())
	if r := e.b.Handle(e.k8sReq("hydra", e.f.Launch(k, cred()))); r.Decision != audit.Approved {
		t.Fatalf("k9s: %+v", r)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 3 {
		t.Fatalf("one approval per (context, client): %d dialogs, want 3", n)
	}
	entries := e.cache.List()
	if len(entries) != 3 {
		t.Fatalf("approvals %+v", entries)
	}
	for _, en := range entries {
		ctx := strings.TrimPrefix(en.Key.Target, "k8s:")
		if en.Key.Op != "k8s:"+ctx || en.Covers != "the Kubernetes credential for "+ctx || en.Key.Receiver == "" {
			t.Fatalf("approval %+v", en)
		}
	}
}

func TestK8sPromptNamesTheClientCommand(t *testing.T) {
	e := newK8sBroker(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, kubectl("delete", "pod", "web-1", "-n", "prod"), cred())
	if r := e.b.Handle(e.k8sReq("hydra", tab.Peer())); r.Decision != audit.Approved {
		t.Fatal(r)
	}
	p := e.f.Shown()[0].Prompt
	text := promptText(p)
	if p.Title != `iTerm2 wants to use Kubernetes credential "hydra"` || !strings.Contains(text, "kubectl delete pod web-1 -n prod") ||
		!strings.Contains(text, "for the Kubernetes credential for hydra") {
		t.Fatalf("prompt %q:\n%s", p.Title, text)
	}
	f := e.lastLine(t)
	if f["target"] != "k8s:hydra" || f["operation"] != "k8s credential" || f["destination"] != "https://hydra.example:16443" ||
		!strings.HasPrefix(f["receiver"], "kubectl delete") || f["delivery"] != "" {
		t.Fatalf("audit %v", f)
	}
}

func TestK8sBlocksWarnAndAudit(t *testing.T) {
	e := newK8sBroker(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	// Check 1: the program that ran nazar exited, so it can't be told.
	tab := e.f.ITermTab(platform.ProcessRef{}, kubectl("get", "pods"), cred())
	e.f.Exit(tab.Procs[0])
	r := e.b.Handle(e.k8sReq("hydra", tab.Peer()))
	if r.Decision != audit.Blocked || r.Reason != policy.ReasonK8sCaller || e.calls.Load() != 0 || len(e.f.Shown()) != 0 {
		t.Fatalf("check 1: %+v", r)
	}
	f := e.lastLine(t)
	if f["decision"] != "blocked" || f["target"] != "k8s:hydra" || f["reason"] != policy.ReasonK8sCaller {
		t.Fatalf("audit %v", f)
	}
	w := e.f.Warnings()
	if len(w) != 1 || w[0].SuggestedRule != "" || !strings.Contains(strings.Join(w[0].Lines, "\n"), "can't be identified") ||
		strings.Contains(strings.Join(w[0].Lines, "\n"), "nazar trust") {
		t.Fatalf("warning %+v", w)
	}
	// Check 2: a look-alike server.
	tab = e.f.ITermTab(platform.ProcessRef{}, kubectl("get", "pods"), cred())
	req := e.k8sReq("hydra", tab.Peer())
	req.Cluster = &cluster.Info{Server: "https://10.0.0.9:16443", CAData: testCA(t)}
	r = e.b.Handle(req)
	if r.Decision != audit.Blocked || !strings.HasPrefix(r.Reason, policy.ReasonCluster) || e.calls.Load() != 0 || len(e.f.Shown()) != 0 {
		t.Fatalf("check 2: %+v", r)
	}
	if f := e.lastLine(t); !strings.HasPrefix(f["reason"], policy.ReasonCluster) || !strings.Contains(f["reason"], "10.0.0.9") {
		t.Fatalf("audit %v", f)
	}
	w = e.f.Warnings()
	if len(w) != 2 || w[1].SuggestedRule != "" || !strings.Contains(strings.Join(w[1].Lines, "\n"), "different server") ||
		!strings.Contains(strings.Join(w[1].Lines, "\n"), "kubeconfig may have been changed") {
		t.Fatalf("warning %+v", w)
	}
	// No spec.cluster at all.
	req = e.k8sReq("hydra", tab.Peer())
	req.Cluster = nil
	if r := e.b.Handle(req); r.Decision != audit.Blocked || r.Reason != policy.ReasonNoCluster {
		t.Fatalf("no cluster: %+v", r)
	}
	// A caller without a rule: the warning drafts a rule for the caller
	// of the client, never for kubectl or the CLI. (Spec review: in
	// an app's session, where a draft is made at all: Cursor ▸ zsh ▸
	// claude ▸ kubectl ▸ nazar, with rules for iTerm2 only.)
	cursor := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Cursor.app/Contents/MacOS/Cursor",
		Code: platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.todesktop.230313mzl4w4u92", CDHash: []byte{0xcc}},
		App:  &fake.App{BundleID: "com.todesktop.230313mzl4w4u92", Name: "Cursor"}})
	sh := e.f.Launch(cursor, fake.Proc{Path: "/bin/zsh", Args: []string{"-zsh"}, Code: fake.AppleCode("com.apple.zsh")})
	cl := e.f.Launch(sh, fake.ClaudeProc())
	kc := e.f.Launch(cl, kubectl("get", "secrets"))
	r = e.b.Handle(e.k8sReq("hydra", e.f.Launch(kc, cred())))
	if r.Decision != audit.Blocked || r.Reason != "no rule matched" {
		t.Fatalf("no rule: %+v", r)
	}
	w = e.f.Warnings()
	last := w[len(w)-1]
	if !strings.Contains(last.SuggestedRule, "Q6L2SF6YDW") || strings.Contains(last.SuggestedRule, "KUBETEAM01") || strings.Contains(last.SuggestedRule, "dev.nazar.cli") {
		t.Fatalf("the drafted rule must name the caller of the client (Claude Code): %q", last.SuggestedRule)
	}
	// A context with a leftover clients: line is off: no rule can allow
	// it, so no draft, and the warning names the fix.
	tab = e.f.ITermTab(platform.ProcessRef{}, kubectl("get", "pods"), cred())
	if r := e.b.Handle(e.k8sReq("old", tab.Peer())); r.Decision != audit.Blocked || r.Reason != policy.ReasonK8sLeftoverClients || e.calls.Load() != 0 {
		t.Fatalf("leftover clients: %+v", r)
	}
	w = e.f.Warnings()
	last = w[len(w)-1]
	if text := strings.Join(last.Lines, "\n"); last.SuggestedRule != "" || !strings.Contains(text, "k8s.contexts.old") || !strings.Contains(text, "remove the line") {
		t.Fatalf("leftover clients warning %+v", last)
	}
}

// No client list (k8s design 2.1): python3 or helm running the plugin in
// an iTerm2 tab is judged as iTerm2, and asks like kubectl does.
func TestK8sAnyProgramInTheTabAsks(t *testing.T) {
	e := newK8sBroker(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	py := scriptProc("/usr/bin/python3", "com.apple.python3", "python3", "deploy.py")
	helm := fake.Proc{Path: "/opt/homebrew/bin/helm", Args: []string{"helm", "list"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x4e}}}
	for _, p := range []fake.Proc{py, helm} {
		tab := e.f.ITermTab(platform.ProcessRef{}, p, cred())
		if r := e.b.Handle(e.k8sReq("hydra", tab.Peer())); r.Decision != audit.Approved || r.Outcome.Receiver == "" {
			t.Fatalf("%s: %+v", p.Path, r)
		}
	}
}
