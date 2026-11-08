package policy

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

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// K8s design 2: a request for a context's credential is decided
// by check 1 (the CLI's parent, whatever program it is, is identified),
// check 2 (the request's cluster is the recorded one) and check 3 (the
// first-match walk on whoever called that program), in that order. There
// is no client list: any program in a chain the rules allow receives it.

var (
	kubectlCode = platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0xc0, 0xde}}
	k9sCode     = platform.CodeIdentity{Signed: true, TeamID: "K9STEAM001", SigningID: "k9s", CDHash: []byte{0x99}}
)

func kubectlProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/opt/homebrew/bin/kubectl", Args: append([]string{"kubectl"}, args...), Cwd: "/Users/u/projects/foo", Code: kubectlCode}
}

func k9sProc() fake.Proc {
	return fake.Proc{Path: "/opt/homebrew/bin/k9s", Args: []string{"k9s"}, Code: k9sCode}
}

func helmProc() fake.Proc {
	return fake.Proc{Path: "/opt/homebrew/bin/helm", Args: []string{"helm", "list"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x4e, 0x1e}}}
}

func credProc(ctx string) fake.Proc { return cliProc("nazar", "k8s", "credential", ctx) }

func caPEM(t *testing.T, cn string) []byte {
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

type k8sEnv struct {
	*env
	ca   []byte       // the hydra cluster's CA
	info cluster.Info // what a request for hydra sends
}

func k8sSrc(hash string) string {
	return `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + hash + `}
      rules:
        - apps: [claude]
          gate: dialog
        - apps: [iterm]
          scope: session
          gate: login
          expire: 8h
    staging:
      credential: ca-cert
      identity: {user: admin}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + hash + `}
      rules:
        - apps: [iterm]
          scope: app
          gate: dialog
    anyone:
      credential: ca-cert
      identity: {user: viewer}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + hash + `}
      rules:
        - apps: [unknown]
          scope: session
          gate: dialog
    blocked:
      credential: ca-cert
      identity: {user: admin}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + hash + `}
      scope: session
      gate: login
`
}

func newK8sEnv(t *testing.T) *k8sEnv {
	t.Helper()
	ca := caPEM(t, "hydra cluster CA")
	info := cluster.Info{Server: "https://hydra.example:16443", CAData: ca}
	pin, err := cluster.PinOf(info)
	if err != nil {
		t.Fatal(err)
	}
	// No `nazar trust` of anything: no program is pinned for k8s.
	en := newEnvSrc(t, k8sSrc(pin.CASHA256))
	return &k8sEnv{env: en, ca: ca, info: info}
}

func (en *k8sEnv) k8s(name string, peer platform.ProcessRef, got *cluster.Info) Outcome {
	return en.e.EvaluateK8s(name, en.r.Resolve(peer), got)
}

func (en *k8sEnv) ok(name string, peer platform.ProcessRef) Outcome {
	info := en.info
	return en.k8s(name, peer, &info)
}

func TestEvaluateK8sAllowsThroughTheRules(t *testing.T) {
	en := newK8sEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc("get", "pods"), credProc("hydra"))
	out := en.ok("hydra", tab.Peer())
	if out.Target != "k8s:hydra" || out.Key != "hydra" || out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin || out.Reason != "rule 2 matched" {
		t.Fatalf("iTerm2 → bash → kubectl → nazar must get the iterm rule: %+v", out)
	}
	kubectl, _ := en.f.Process(tab.Procs[0])
	if out.Receiver == "" || out.Receiver != "path:/opt/homebrew/bin/kubectl#c0de" {
		t.Fatalf("the receiver is the client's identity: %q (want that of %s)", out.Receiver, kubectl.Path)
	}
	if out.OneShot || !strings.HasPrefix(out.ScopeID, "session:") || out.Root != tab.Shell {
		t.Fatalf("a session approval rooted at the tab's shell: %+v", out)
	}
}

func TestEvaluateK8sCheckOrder(t *testing.T) {
	en := newK8sEnv(t)
	// A parent that can't be identified AND the wrong cluster: check 1
	// speaks first.
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	other := cluster.Info{Server: "https://10.0.0.9:16443", CAData: caPEM(t, "evil")}
	pidOnly := *en.r.Resolve(tab.Peer())
	pidOnly.Procs = append(pidOnly.Procs[:0:0], pidOnly.Procs...)
	pidOnly.Procs[1].Ref.Generation = 0
	out := en.e.EvaluateK8s("hydra", &pidOnly, &other)
	if out.Policy.Gate != config.GateBlock || out.Reason != ReasonK8sCaller || out.RuleIndex != 0 {
		t.Fatalf("check 1 first: %+v", out)
	}
	check1 := out
	// An identified program, the wrong cluster, a matching rule: check 2 refuses.
	out = en.k8s("hydra", tab.Peer(), &other)
	if out.Policy.Gate != config.GateBlock || !strings.HasPrefix(out.Reason, ReasonCluster) || out.RuleIndex != 0 {
		t.Fatalf("check 2 before the rules: %+v", out)
	}
	check2 := out
	// An unknown context, whatever else.
	out = en.ok("nope", tab.Peer())
	if out.Policy.Gate != config.GateBlock || out.Reason != ReasonK8sContext || out.Target != "k8s:nope" {
		t.Fatalf("unknown context: %+v", out)
	}
	for _, o := range []Outcome{check1, check2, out} {
		if o.ScopeID != "" || !o.OneShot {
			t.Fatalf("a block is never remembered: %+v", o)
		}
	}
}

// The owner's decision (k8s design 2.1, "no client list"): whatever
// program runs the plugin receives the credential when the chain above it
// passes the rules, with no list and no `nazar trust`. Approvals stay per
// program (the receiver).
func TestEvaluateK8sAnyProgramInAnAllowedChain(t *testing.T) {
	en := newK8sEnv(t)
	changed := kubectlProc()
	changed.Code = platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0xba, 0xd0}} // after brew upgrade
	moved := kubectlProc()
	moved.Path = "/Users/u/bin/kubectl"
	tool := fake.Proc{Path: "/Users/u/go/bin/mytool", Args: []string{"mytool"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x70, 0x01}}}
	py := fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "deploy.py"}, Code: fake.AppleCode("com.apple.python3")}
	seen := map[string]string{}
	for name, p := range map[string]fake.Proc{
		"kubectl": kubectlProc(), "kubectl after an upgrade": changed, "kubectl elsewhere": moved,
		"helm": helmProc(), "k9s": k9sProc(), "a binary of the user's": tool, "python3": py,
	} {
		tab := en.f.ITermTab(platform.ProcessRef{}, p, credProc("hydra"))
		out := en.ok("hydra", tab.Peer())
		if out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin || out.Receiver == "" {
			t.Errorf("%s in an iTerm2 tab must get the iterm rule: %+v", name, out)
			continue
		}
		if prev, dup := seen[out.Receiver]; dup {
			t.Errorf("%s and %s share the receiver %q: one's approval would cover the other", name, prev, out.Receiver)
		}
		seen[out.Receiver] = name
	}
	// The shell itself runs the plugin: it is the program that receives
	// it, judged on who ran the shell (iTerm2).
	tab := en.f.ITermTab(platform.ProcessRef{}, credProc("hydra"))
	if out := en.ok("hydra", tab.Peer()); out.RuleIndex != 2 || out.Receiver == "" {
		t.Errorf("bash as the parent: %+v", out)
	}
	// The parent exited: the CLI is reparented to launchd, no chain[1].
	tab = en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	en.f.Exit(tab.Procs[0])
	if out := en.ok("hydra", tab.Peer()); out.Reason != ReasonK8sCaller || out.Policy.Gate != config.GateBlock || out.Receiver != "" {
		t.Errorf("parent exited: %+v", out)
	}
	// A parent whose code signature does not verify has no identity to
	// remember an approval under.
	unsigned := helmProc()
	unsigned.Code = platform.CodeIdentity{CDHash: []byte{0x01}}
	tab = en.f.ITermTab(platform.ProcessRef{}, unsigned, credProc("hydra"))
	if out := en.ok("hydra", tab.Peer()); out.Reason != ReasonK8sCaller || out.Receiver != "" {
		t.Errorf("unverified parent: %+v", out)
	}
}

// A chain whose parent record is PID-only, or a chain with nothing past
// the peer, never passes check 1 (k8s design 2.1: no "unknown" path for
// the program that receives the credential).
func TestEvaluateK8sClientNeedsAFullRecord(t *testing.T) {
	en := newK8sEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	c := en.r.Resolve(tab.Peer())
	if len(c.Procs) < 2 {
		t.Fatal("precondition")
	}
	pidOnly := *c
	pidOnly.Procs = append(pidOnly.Procs[:0:0], c.Procs...)
	pidOnly.Procs[1].Ref.Generation = 0
	info := en.info
	if out := en.e.EvaluateK8s("hydra", &pidOnly, &info); out.Reason != ReasonK8sCaller {
		t.Fatalf("PID-only parent: %+v", out)
	}
	alone := *c
	alone.Procs = c.Procs[:1]
	if out := en.e.EvaluateK8s("hydra", &alone, &info); out.Reason != ReasonK8sCaller {
		t.Fatalf("no parent: %+v", out)
	}
	if out := en.e.EvaluateK8s("hydra", nil, &info); out.Reason != ReasonK8sCaller || out.Policy.Gate != config.GateBlock {
		t.Fatalf("nil chain: %+v", out)
	}
}

func TestEvaluateK8sCluster(t *testing.T) {
	en := newK8sEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	if out := en.k8s("hydra", tab.Peer(), nil); out.Policy.Gate != config.GateBlock || out.Reason != ReasonNoCluster {
		t.Fatalf("no spec.cluster: %+v", out)
	}
	for name, got := range map[string]cluster.Info{
		"server":   {Server: "https://10.0.0.9:16443", CAData: en.ca},
		"ca":       {Server: en.info.Server, CAData: caPEM(t, "look-alike")},
		"no ca":    {Server: en.info.Server},
		"tls name": {Server: en.info.Server, CAData: en.ca, TLSServerName: "hydra"},
		"proxy":    {Server: en.info.Server, CAData: en.ca, ProxyURL: "http://proxy:3128"},
		"insecure": {Server: en.info.Server, CAData: en.ca, Insecure: true},
	} {
		got := got
		out := en.k8s("hydra", tab.Peer(), &got)
		if out.Policy.Gate != config.GateBlock || !strings.HasPrefix(out.Reason, ReasonCluster) || out.RuleIndex != 0 {
			t.Errorf("%s: %+v", name, out)
		}
	}
	// The same cluster written another way is the same cluster.
	same := cluster.Info{Server: "https://HYDRA.example:16443/", CAData: append([]byte("# ca\n"), en.ca...)}
	if out := en.k8s("hydra", tab.Peer(), &same); out.Policy.Gate != config.GateLogin {
		t.Fatalf("normalised server and CA: %+v", out)
	}
}

// Rules are judged on chain[2:]: never on the CLI or the program that
// runs it. Without a client list this is what keeps a program outside
// every allowed chain out, whatever it runs.
func TestEvaluateK8sRulesJudgeTheCallerOfTheClient(t *testing.T) {
	en := newK8sEnv(t)
	// Claude Code in the tab runs kubectl: Claude's rule (rule 1).
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), kubectlProc("delete", "pod", "web-1"), credProc("hydra"))
	if out := en.ok("hydra", tab.Peer()); out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog {
		t.Fatalf("claude ▸ kubectl ▸ nazar: %+v", out)
	}
	// Malware outside any app (started by launchd) runs the real kubectl.
	mal := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/mal", Code: platform.CodeIdentity{Signed: true, AdHoc: true}})
	k := en.f.Launch(mal, kubectlProc("get", "secrets"))
	cli := en.f.Launch(k, credProc("hydra"))
	out := en.ok("hydra", cli)
	if out.Policy.Gate != config.GateBlock || out.Reason != "no rule matched" || out.Receiver == "" {
		t.Fatalf("malware ▸ kubectl ▸ nazar must fall back to block: %+v", out)
	}
	for name, p := range map[string]fake.Proc{"helm": helmProc(), "k9s": k9sProc()} {
		c := en.f.Launch(en.f.Launch(mal, p), credProc("hydra"))
		if out := en.ok("hydra", c); out.Policy.Gate != config.GateBlock || out.Reason != "no rule matched" {
			t.Fatalf("malware ▸ %s ▸ nazar must fall back to block: %+v", name, out)
		}
	}
	// Malware running the plugin itself.
	if out := en.ok("hydra", en.f.Launch(mal, credProc("hydra"))); out.Policy.Gate != config.GateBlock {
		t.Fatalf("malware ▸ nazar must fall back to block: %+v", out)
	}
	// blocked: the context's own policy applies to every caller (key-gate).
	tab = en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("blocked"))
	if out := en.ok("blocked", tab.Peer()); !out.KeyGate || out.Policy.Gate != config.GateLogin || out.Policy.Scope != config.ScopeSession {
		t.Fatalf("own policy: %+v", out)
	}
}

func TestEvaluateK8sUnknownCallerIsOneShot(t *testing.T) {
	en := newK8sEnv(t)
	k := en.f.Launch(platform.ProcessRef{}, kubectlProc("get", "pods"))
	cli := en.f.Launch(k, credProc("anyone"))
	out := en.ok("anyone", cli)
	if !out.Unknown || out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog {
		t.Fatalf("kubectl from launchd: the unknown rule: %+v", out)
	}
	mustBeOneShot(t, "unknown caller", out)
	// hydra has no unknown rule: blocked.
	cli = en.f.Launch(k, credProc("hydra"))
	if out := en.ok("hydra", cli); out.Policy.Gate != config.GateBlock {
		t.Fatalf("unknown caller of hydra: %+v", out)
	}
}

func TestEvaluateK8sScopes(t *testing.T) {
	en := newK8sEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("staging"))
	out := en.ok("staging", tab.Peer())
	if out.OneShot || out.ScopeID != "app:H7V7XYVQ7D:com.googlecode.iterm2" || out.Receiver == "" {
		t.Fatalf("an app approval for staging: %+v", out)
	}
	// Two tabs, one session approval each; the scope id names the tab's shell.
	t1 := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	t2 := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	o1, o2 := en.ok("hydra", t1.Peer()), en.ok("hydra", t2.Peer())
	if o1.ScopeID == "" || o1.ScopeID == o2.ScopeID {
		t.Fatalf("one session per tab: %q %q", o1.ScopeID, o2.ScopeID)
	}
	// kubectl and k9s in one tab: one approval each (the receiver differs).
	t3 := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	k := en.ok("hydra", t3.Peer())
	n := en.f.Launch(t3.Shell, k9sProc())
	nn := en.f.Launch(n, credProc("hydra"))
	k9 := en.ok("hydra", nn)
	if k.ScopeID != k9.ScopeID || k.Receiver == k9.Receiver || k9.Receiver != "K9STEAM001:k9s" {
		t.Fatalf("same tab, two clients: %+v %+v", k, k9)
	}
}

// (Since a security review the ids carry the context's
// fingerprint, k8sRuleID; TestK8sRuleIDsTrackTheContext pins why.)
func TestLiveRuleIDsCoverK8s(t *testing.T) {
	en := newK8sEnv(t)
	live := LiveRuleIDs(en.e.Config())
	hydra := en.e.Config().K8s["hydra"]
	for _, r := range hydra.Rules {
		if !live["k8s:hydra|"+k8sRuleID(r.ID(), hydra)] {
			t.Fatalf("rule %d of hydra is not live: %v", r.Index, live)
		}
	}
	if !live["k8s:hydra|"+k8sRuleID(FallbackRuleID("k8s:hydra", en.e.Config().K8sFallback("hydra")), hydra)] {
		t.Fatal("the fallback of hydra is not live")
	}
	if !live["k8s:blocked|"+k8sRuleID(FallbackRuleID("k8s:blocked", en.e.Config().K8sFallback("blocked")), en.e.Config().K8s["blocked"])] {
		t.Fatal("the own policy of blocked is not live")
	}
	// An edited rule gets a new id: the old approvals are dropped.
	edited := strings.Replace(k8sSrc(hydra.Cluster.CASHA256), "          expire: 8h\n", "          expire: 9h\n", 1)
	live2 := LiveRuleIDs(parse(t, edited))
	if live2["k8s:hydra|"+k8sRuleID(hydra.Rules[1].ID(), hydra)] || !live2["k8s:hydra|"+k8sRuleID(hydra.Rules[0].ID(), hydra)] {
		t.Fatal("only the edited rule loses its approvals")
	}
}

// Spec review: rules see chain[2:] only. A rule that would match the
// nazar CLI (chain[0]) or the program that runs it (chain[1]) never
// applies.
func TestEvaluateK8sRulesNeverSeeTheCLIOrTheClient(t *testing.T) {
	en := newK8sEnv(t)
	hydra := en.e.Config().K8s["hydra"]
	cliRule := config.Rule{Index: 1, Apps: []config.Matcher{{Kind: config.MatchSigned, Team: nazarCLI.TeamID, ID: nazarCLI.SigningID}},
		Policy: config.Policy{Scope: config.ScopeUse, Gate: config.GateDialog}}
	clientRule := config.Rule{Index: 2, Apps: []config.Matcher{{Kind: config.MatchSigned, Team: k9sCode.TeamID, ID: "k9s"}},
		Policy: config.Policy{Scope: config.ScopeUse, Gate: config.GateDialog}}
	hydra.Rules = []config.Rule{cliRule, clientRule}
	tab := en.f.ITermTab(platform.ProcessRef{}, k9sProc(), credProc("hydra"))
	if out := en.ok("hydra", tab.Peer()); out.RuleIndex != 0 || out.Policy.Gate != config.GateBlock || out.Reason != "no rule matched" {
		t.Fatalf("iTerm2 ▸ bash ▸ k9s ▸ nazar must fall back: %+v", out)
	}
	// The same rule does match k9s when it calls another client.
	tab = en.f.ITermTab(platform.ProcessRef{}, k9sProc(), kubectlProc(), credProc("hydra"))
	if out := en.ok("hydra", tab.Peer()); out.RuleIndex != 2 {
		t.Fatalf("k9s ▸ kubectl ▸ nazar: k9s is a caller there: %+v", out)
	}
}

// Security review: a client the app runs directly (no shell between)
// is its own session root, so a scope: session approval is that run's, not
// the app's for as long as it runs.
func TestEvaluateK8sSessionOfAClientTheAppRunsDirectly(t *testing.T) {
	en := newK8sEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{})
	k1 := en.f.Launch(tab.App, kubectlProc("get", "pods"))
	k2 := en.f.Launch(tab.App, kubectlProc("get", "svc"))
	o1 := en.ok("hydra", en.f.Launch(k1, credProc("hydra")))
	o2 := en.ok("hydra", en.f.Launch(k2, credProc("hydra")))
	if o1.RuleIndex != 2 || o1.ScopeID == "" || o1.ScopeID == o2.ScopeID || o1.Root != k1 || o2.Root != k2 {
		t.Fatalf("one session per kubectl run: %+v\n%+v", o1, o2)
	}
}

// Security review: an approval is for what the context was when it
// was given. A change to its cluster, identity or ttl_cert (approved with
// Touch ID) gives every rule and the fallback a new id, so remembered
// approvals do not carry over to the new credential. (The receiver, the
// program that ran nazar, is a separate part of the approval key.)
func TestK8sRuleIDsTrackTheContext(t *testing.T) {
	en := newK8sEnv(t)
	src := k8sSrc(en.e.Config().K8s["hydra"].Cluster.CASHA256)
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("hydra"))
	before := en.ok("hydra", tab.Peer())
	if !LiveRuleIDs(en.e.Config())["k8s:hydra|"+before.RuleID] {
		t.Fatal("the outcome's rule id must be live")
	}
	for name, edited := range map[string]string{
		"identity": strings.Replace(src, "groups: [system:masters]", "groups: [system:masters, devs]", 1),
		"ttl_cert": strings.Replace(src, "      identity: {user: admin, groups: [system:masters]}\n", "      identity: {user: admin, groups: [system:masters]}\n      ttl_cert: 30m\n", 1),
		"cluster":  strings.Replace(src, "https://hydra.example:16443", "https://hydra.example:6443", 1),
	} {
		live := LiveRuleIDs(parse(t, edited))
		if live["k8s:hydra|"+before.RuleID] {
			t.Errorf("%s changed: the old approvals must not stay live", name)
		}
	}
	// An unrelated context's edit keeps hydra's ids.
	other := strings.Replace(src, "identity: {user: viewer}", "identity: {user: viewer2}", 1)
	if !LiveRuleIDs(parse(t, other))["k8s:hydra|"+before.RuleID] {
		t.Fatal("another context's change must not drop hydra's approvals")
	}
}

// A context that still has a clients: line (an older version's list) is
// off: refused before its rules, with the fix, while the config's other
// contexts work (config.K8sContext.LeftoverClients).
func TestEvaluateK8sLeftoverClientsLineIsOff(t *testing.T) {
	en := newK8sEnv(t)
	src := strings.Replace(k8sSrc(en.e.Config().K8s["hydra"].Cluster.CASHA256),
		"      identity: {user: admin}\n      cluster:", "      identity: {user: admin}\n      clients: [kubectl, helm, k9s]\n      cluster:", 1)
	en.e = New(parse(t, src), en.e.m)
	tab := en.f.ITermTab(platform.ProcessRef{}, kubectlProc(), credProc("staging"))
	out := en.ok("staging", tab.Peer())
	if out.Policy.Gate != config.GateBlock || out.Reason != ReasonK8sLeftoverClients || out.RuleIndex != 0 || out.ScopeID != "" {
		t.Fatalf("a context with clients: is off: %+v", out)
	}
	if out := en.ok("hydra", tab.Peer()); out.Policy.Gate != config.GateLogin {
		t.Fatalf("another context still works: %+v", out)
	}
}
