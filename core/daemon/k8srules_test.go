package daemon

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// What the Kubernetes tab needs from the agent: a context's rules
// as structured as a key's (k8s.list's policy and warnings, and a state
// with its remedy), and config.edit on k8s.contexts.<name>, staged and
// classified exactly as a key's or a secret's edit, with no to: and only
// for a context config.yaml has.

func k8sEditBase(caHash string) string {
	return `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  kubectl: {signed: {team: KUBETEAM01, id: kubectl}}
ssh_agent:
  keys:
    hydra:
      gate: block
secrets:
  hydra:
    gate: block
k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster: {server: "https://hydra.example:16443", ca_sha256: ` + caHash + `}
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
    hydra.prod:
      credential: ca-cert
      identity: {user: dev}
      cluster: {server: "https://hydra.eks.amazonaws.com", ca_sha256: ` + caHash + `}
      gate: block
`
}

type k8sEditEnv struct {
	*adminEnv
	body string
}

// startK8sEdit: hydra (configured, its CA made, one rule), hydra.prod
// (configured, no CA; its managed-cluster warning has a path that hydra's
// prefixes), loose (a CA, no entry), and a key and a secret named hydra.
// (If this base draws a parse warning for hydra, fix the base, never the
// assertions below.)
func startK8sEdit(t *testing.T) *k8sEditEnv {
	t.Helper()
	e := startAdmin(t)
	body := k8sEditBase(e.pin.CASHA256)
	e.approved(t, body)
	for _, n := range []string{"hydra", "loose"} {
		if _, err := e.d.k8sCA.Create(n, platform.AccessWhenUnlocked); err != nil {
			t.Fatal(err)
		}
	}
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	return &k8sEditEnv{adminEnv: e, body: body}
}

func (e *env) k8sList(t *testing.T) map[string]control.K8sContext {
	t.Helper()
	var l control.K8sContextList
	if err := e.call(t, control.CmdK8sList, nil, control.KindK8sContextList, &l); err != nil {
		t.Fatal(err)
	}
	m := map[string]control.K8sContext{}
	for _, c := range l.Items {
		m[c.Name] = c
	}
	return m
}

func TestK8sListCarriesPolicyStateAndWarnings(t *testing.T) {
	e := startK8sEdit(t)
	l := e.k8sList(t)
	a := l["hydra"]
	p := a.Policy
	if p == nil || p.Kind != control.KindSSHKeyRules || p.Name != "hydra" || !p.Configured || p.Staged || p.ConfigHash != contentHash([]byte(e.body)) ||
		p.FallbackSource != "context-gate" || p.Own == nil || p.Own.Gate != "block" || p.Fallback.Gate != "block" || len(p.Rules) != 1 {
		t.Fatalf("hydra policy: %+v", p)
	}
	r := p.Rules[0]
	if r.Index != 1 || r.Apps[0].Ref != "iterm" || r.To == nil || len(r.To) != 0 || r.Policy != (control.PolicyInfo{Scope: "session", Gate: "dialog"}) {
		t.Fatalf("rule 1: %+v", r)
	}
	// Warnings are the entry's own: hydra.prod's managed-cluster warning is
	// not hydra's, though hydra prefixes its path; never null.
	if a.State != control.K8sStateOK || a.Remedy != "" || a.Warnings == nil || len(a.Warnings) != 0 {
		t.Fatalf("hydra: state %q, remedy %q, warnings %q", a.State, a.Remedy, a.Warnings)
	}
	prod := l["hydra.prod"]
	if w := strings.Join(prod.Warnings, "\n"); !strings.Contains(w, "managed clusters") || prod.State != control.K8sStateNoCA ||
		prod.Remedy != "nazar k8s forget hydra.prod, then nazar k8s ca create hydra.prod" || prod.Policy == nil || len(prod.Policy.Rules) != 0 || prod.CA != nil {
		t.Fatalf("hydra.prod: %+v", prod)
	}
	// A CA with no entry (an old ca create); no policy (no entry: every
	// caller is refused, whatever defaults.fallback says).
	lo := l["loose"]
	if lo.State != control.K8sStateNoEntry || lo.Configured || lo.Policy != nil || lo.Warnings == nil || lo.CA == nil ||
		lo.Remedy != "nazar k8s forget loose, then nazar k8s ca create loose" {
		t.Fatalf("loose: %+v", lo)
	}
	// A CA the Keychain won't return (another signature of the agent): its
	// state and remedy, the very text nazar status prints for it.
	e.vault.lock("k8s-ca/loose")
	lo = e.k8sList(t)["loose"]
	if lo.State != control.K8sStateCAUnusable || !lo.CABroken || lo.CA != nil || !strings.Contains(lo.Remedy, "security delete-generic-password -s dev.nazar -a k8s-ca/loose") {
		t.Fatalf("unreadable CA: %+v", lo)
	}
	var st control.Status
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range st.Vault {
		if v.Item == "k8s-ca/loose" {
			found = v.Remedy == lo.Remedy && v.Reason == lo.UnusableReason && strings.Contains(v.Effect, "loose")
		}
	}
	if !found {
		t.Fatalf("nazar status must list the unusable CA with the same remedy: %+v", st.Vault)
	}
	// An item under k8s-ca/ whose name no context can have is nazar's to
	// list, never to use: quoted, with no effect.
	if err := e.vault.Put("k8s-ca/a:b", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	found = false
	for _, v := range st.Vault {
		if v.Item == `"k8s-ca/a:b"` {
			found = strings.HasPrefix(v.Effect, "none: ") && v.Remedy != ""
		}
	}
	if !found {
		t.Fatalf("a planted k8s-ca/ item: %+v", st.Vault)
	}
}

// Nothing in k8s list is a credential: no key, no minted certificate, no
// CA certificate (k8s ca show prints that, on request), and so nothing in
// status either.
func TestK8sListCarriesNoCredential(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	c, p := e.credential(t, "hydra", e.ok(t))
	if p != nil {
		t.Fatal(p)
	}
	ca, err := e.d.k8sCA.Get("hydra")
	if err != nil {
		t.Fatal(err)
	}
	var material []string
	for _, b := range [][]byte{[]byte(c.ClientCertificateData), []byte(c.ClientKeyData), ca.CertPEM()} {
		blk, _ := pem.Decode(b)
		if blk == nil {
			t.Fatal("not PEM")
		}
		enc := base64.StdEncoding.EncodeToString(blk.Bytes)
		material = append(material, enc[:64], enc[len(enc)-64:])
	}
	var l control.K8sContextList
	if err := e.call(t, control.CmdK8sList, nil, control.KindK8sContextList, &l); err != nil {
		t.Fatal(err)
	}
	var st control.Status
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"k8s list": l, "status": st} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		out := string(b)
		for _, s := range append(material, "-----BEGIN", "PRIVATE KEY", "certPEM", "clientKeyData", "clientCertificateData") {
			if strings.Contains(out, s) {
				t.Fatalf("%s carries credential material (%d bytes)", name, len(s))
			}
		}
	}
	if len(l.Items) != 1 || l.Items[0].State != control.K8sStateOK || l.Items[0].CA == nil || l.Items[0].CA.Fingerprint == "" {
		t.Fatalf("%+v", l.Items)
	}
}

// A context's new rule is a loosening: written and staged, no prompt, not
// in force until config apply; a stronger gate and a removed rule tighten
// at once. The key and the secret named hydra, and hydra.prod, are never
// touched.
func TestK8sRuleEditIsStagedLikeAKey(t *testing.T) {
	e := startK8sEdit(t)
	logins := e.logins()
	pol := e.k8sList(t)["hydra"].Policy
	if pol == nil {
		t.Fatal("hydra has no policy")
	}
	hash := pol.ConfigHash
	res, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "context": "hydra", "apps": refs("signed:TOOLTEAM01:dev.example.tool"),
		"scope": "session", "gate": "login", "expire": "8h", "at": "1", "ifHash": hash})
	if p != nil {
		t.Fatal(p)
	}
	if !res.Changed || res.Applied || res.Staged == nil || !res.Staged.Loosens || res.Context != "hydra" || res.Key != "" || res.Secret != "" {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(strings.Join(res.Staged.Loosening, "\n"), "k8s:hydra") {
		t.Fatalf("loosening %q", res.Staged.Loosening)
	}
	if len(e.d.stager.Active().K8s["hydra"].Rules) != 1 {
		t.Fatal("a loosening applied without approval")
	}
	time.Sleep(10 * e.o.PollInterval) // the poller would have prompted by now
	if e.logins() != logins {
		t.Fatal("an edit must not open a prompt of its own")
	}
	if lines := e.configAudit(t, audit.Blocked); len(lines) == 0 || !strings.Contains(lines[len(lines)-1]["reason"], "rule.add k8s:hydra") {
		t.Fatalf("audit %v", lines)
	}
	if shown := e.k8sList(t)["hydra"].Policy; shown == nil || !shown.Staged || len(shown.Rules) != 2 || shown.Rules[0].Apps[0].Ref != "signed:TOOLTEAM01:dev.example.tool" {
		t.Fatalf("shown after the edit: %+v", shown)
	}
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	c := e.d.stager.Active()
	if e.logins() != logins+1 || len(c.K8s["hydra"].Rules) != 2 {
		t.Fatal("config apply must show one prompt and apply the rule")
	}
	if len(c.K8s["hydra.prod"].Rules) != 0 || len(c.SSHAgent.Keys["hydra"].Rules) != 0 || len(c.Secrets["hydra"].Rules) != 0 {
		t.Fatalf("another entry was edited:\n%s", c.Raw)
	}
	// dialog → login on rule 2 (the iterm rule) tightens: in force at once.
	res, p = e.edit(t, map[string]string{"op": control.EditRuleSet, "context": "hydra", "index": "2", "gate": "login"})
	if p != nil || !res.Applied || res.Staged != nil || e.logins() != logins+1 {
		t.Fatalf("set: %+v %+v", res, p)
	}
	// Removing the iterm rule tightens (removing rule 1 would not: a tool
	// run in iTerm2 would fall through to rule 2, which has no expire).
	res, p = e.edit(t, map[string]string{"op": control.EditRuleRemove, "context": "hydra", "index": "2"})
	if p != nil || !res.Applied || res.Staged != nil || e.logins() != logins+1 {
		t.Fatalf("remove: %+v %+v", res, p)
	}
	if rs := e.d.stager.Active().K8s["hydra"].Rules; len(rs) != 1 || rs[0].Policy.Gate != "login" || rs[0].Apps[0].Team != "TOOLTEAM01" {
		t.Fatalf("not in force: %+v", rs)
	}
}

func TestK8sRuleEditRefusals(t *testing.T) {
	e := startK8sEdit(t)
	before := e.readConfig(t)
	add := func(kv ...string) map[string]string {
		m := map[string]string{"op": control.EditRuleAdd, "context": "hydra", "apps": refs("signed:TOOLTEAM01:dev.example.tool"), "gate": "login"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cases := []struct {
		name string
		args map[string]string
		code int
		msg  string
	}{
		{"key and context", add("key", "hydra"), control.ExitUsage, "not both"},
		{"secret and context", add("secret", "hydra"), control.ExitUsage, "not both"},
		{"bad name", add("context", "a/b"), control.ExitUsage, "invalid context name"},
		{"dots", add("context", "a..b"), control.ExitUsage, "invalid context name"},
		{"to on add", add("to", refs("kubectl")), control.ExitUsage, "take no to:"},
		{"empty to on add", add("to", ""), control.ExitUsage, "take no to:"},
		{"no-to on set", map[string]string{"op": control.EditRuleSet, "context": "hydra", "index": "1", "to": ""}, control.ExitUsage, "take no to:"},
		{"to on set", map[string]string{"op": control.EditRuleSet, "context": "hydra", "index": "1", "to": refs("kubectl")}, control.ExitUsage, "take no to:"},
		{"own gate", map[string]string{"op": control.EditKeySet, "context": "hydra", "gate": "login"}, control.ExitUsage, "SSH keys"},
		{"not configured", add("context", "nope"), control.ExitError, "there is no k8s context nope"},
		{"letter case", add("context", "Hydra"), control.ExitError, "there is no k8s context Hydra"},
		{"a CA, no entry", add("context", "loose"), control.ExitError, "nazar k8s ca create loose sets one up"},
		{"kubectl as the caller", add("apps", refs("kubectl")), control.ExitError, "would be invalid"},
		{"any under none", add("apps", refs("any"), "gate", "none"), control.ExitError, "would be invalid"},
		{"no such rule", map[string]string{"op": control.EditRuleRemove, "context": "hydra", "index": "9"}, control.ExitError, "k8s.contexts.hydra"},
		{"stale hash", add("ifHash", "0000"), control.ExitError, "nazar k8s list"},
	}
	for _, c := range cases {
		_, p := e.edit(t, c.args)
		if p.ExitCode() != c.code || !strings.Contains(p.Message, c.msg) {
			t.Errorf("%s: %+v, want exit %d with %q", c.name, p, c.code, c.msg)
		}
		if e.readConfig(t) != before {
			t.Fatalf("%s changed config.yaml", c.name)
		}
	}
	_, p := e.edit(t, add("apps", refs("kubectl")))
	if !strings.Contains(strings.Join(p.Details, "\n"), "names kubectl") {
		t.Fatalf("the parse error must be in the details: %+v", p)
	}
	// The name and to: are refused before config.yaml is read: an invalid
	// file does not change the answer.
	e.writeConfig(t, "this: [is not a config\n")
	for _, c := range cases {
		if c.code != control.ExitUsage {
			continue
		}
		if _, p := e.edit(t, c.args); p.ExitCode() != control.ExitUsage {
			t.Errorf("%s with an invalid config.yaml: %+v", c.name, p)
		}
	}
}

// Set up from a caller with no terminal (an app that runs the CLI), a
// context is blocked for everyone, and the prompt names the command that
// adds a rule.
func TestK8sCACreateWithoutATerminalNamesTheRuleCommand(t *testing.T) {
	e := startAdmin(t)
	uiCode := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "dev.nazar.ui", CDHash: []byte{0xd1}}
	ui := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Nazar UI.app/Contents/MacOS/NazarUI", Code: uiCode, App: &fake.App{BundleID: "dev.nazar.ui", Name: "Nazar UI"}})
	e.f.SetDefaultPeer(e.f.Launch(ui, cliProc("--json", "k8s", "ca", "create", "hydra", e.pin.Server)))
	if _, p := e.caCreate(t, "hydra"); p != nil {
		t.Fatal(p)
	}
	prompt := e.f.Shown()[len(e.f.Shown())-1].Prompt
	if lines := strings.Join(prompt.Lines, "\n"); !strings.Contains(lines, "no rule yet: every caller is blocked until one is added (nazar k8s rule add hydra …)") {
		t.Fatalf("prompt %q", lines)
	}
	if k := e.d.stager.Active().K8s["hydra"]; k == nil || len(k.Rules) != 0 || k.Own == nil || k.Own.Gate != "block" {
		t.Fatalf("%+v", k)
	}
}
