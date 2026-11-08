package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// K8s design 3, as built: the k8s section with credential: ca-cert,
// identity, ttl_cert and the recorded cluster; rules, scope, gate and
// expire as for ssh keys, judged on whoever called the program that runs
// the plugin. There is no clients: list (k8s design 2.1).

const caHash = "3f8c0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7"

const k8sApps = hdr + `apps:
  iterm: {app: com.googlecode.iterm2}
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  kubectl: {signed: {team: KUBETEAM01}}
  k9s: {signed: {team: K9STEAM001}}
  lens: {app: com.k8slens.lens, team: LENSTEAM01}
  perl: {signed: {team: apple, id: com.apple.perl}}
`

// k8sCtx is a valid hydra context; extra is added to its mapping (4 spaces
// deep), rules appended after it.
func k8sCtx(extra string) string {
	return k8sApps + `k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster:
        server: https://hydra.example:16443
        ca_sha256: ` + caHash + "\n" + extra
}

func TestK8sContextParses(t *testing.T) {
	c, probs := mustParse(t, k8sCtx(`      ttl_cert: 20m
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
          expire: 8h
        - apps: [claude]
          gate: dialog
`))
	if len(c.Unimplemented) != 0 || strings.Contains(probs.Error(), "not implemented") {
		t.Fatalf("k8s is implemented now: %v %v", c.Unimplemented, probs)
	}
	k := c.K8s["hydra"]
	if k == nil {
		t.Fatal("no hydra")
	}
	if k.Name != "hydra" || k.Credential != CredentialCACert || k.Identity.User != "admin" ||
		!slices.Equal(k.Identity.Groups, []string{"system:masters"}) || k.TTLCert != 20*time.Minute {
		t.Fatalf("%+v", k)
	}
	if k.Cluster.Server != "https://hydra.example:16443" || k.Cluster.CASHA256 != caHash || k.Cluster.TLSServerName != "" || k.Cluster.ProxyURL != "" {
		t.Fatalf("cluster %+v", k.Cluster)
	}
	if len(k.Rules) != 2 || k.Rules[0].Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) ||
		k.Rules[1].Policy.Gate != GateDialog {
		t.Fatalf("rules %+v", k.Rules)
	}
	if k.Own == nil || k.Own.Gate != GateBlock || c.K8sFallback("hydra") != *k.Own {
		t.Fatalf("own %+v", k.Own)
	}
	if c.K8sFallback("nope") != c.Defaults.Fallback {
		t.Fatal("an unknown context falls back to defaults.fallback")
	}
	if got := strings.Join(c.K8sNames(), ","); got != "hydra" {
		t.Fatal(got)
	}
}

func TestK8sContextDefaults(t *testing.T) {
	c, _ := mustParse(t, k8sApps+`k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin}
      cluster:
        server: https://HYDRA.example:443/
        ca_sha256: `+caHash+`
        tls_server_name: hydra.internal
        proxy_url: socks5://localhost:1080
`)
	k := c.K8s["hydra"]
	if k.TTLCert != DefaultTTLCert || DefaultTTLCert != 15*time.Minute {
		t.Fatalf("ttl_cert defaults to 15m: %v", k.TTLCert)
	}
	if k.Identity.Groups != nil && len(k.Identity.Groups) != 0 {
		t.Fatalf("groups %v", k.Identity.Groups)
	}
	if k.Cluster.Server != "https://hydra.example" || k.Cluster.TLSServerName != "hydra.internal" || k.Cluster.ProxyURL != "socks5://localhost:1080" {
		t.Fatalf("the server is kept normalised: %+v", k.Cluster)
	}
	if k.Own != nil || len(k.Rules) != 0 || c.K8sFallback("hydra") != c.Defaults.Fallback {
		t.Fatalf("no own policy: %+v", k.Own)
	}
	// credential, identity and cluster are required.
	wantError(t, k8sApps+"k8s:\n  contexts:\n    hydra:\n", "credential")
}

func TestK8sContextValidation(t *testing.T) {
	base := func(credential, identity, cluster string) string {
		return k8sApps + "k8s:\n  contexts:\n    hydra:\n" + credential + identity + cluster
	}
	cred := "      credential: ca-cert\n"
	id := "      identity: {user: admin}\n"
	cl := "      cluster: {server: \"https://hydra.example:16443\", ca_sha256: " + caHash + "}\n"
	for name, tc := range map[string]struct{ src, want string }{
		"stored":               {base("      credential: stored\n", id, cl), "stored is not in this version (ca-cert is)"},
		"jwt":                  {base("      credential: jwt\n", id, cl), "jwt is not planned; use ca-cert"},
		"unknown credential":   {base("      credential: magic\n", id, cl), "credential must be ca-cert"},
		"no credential":        {base("", id, cl), "credential"},
		"no identity":          {base(cred, "", cl), "identity"},
		"no user":              {base(cred, "      identity: {groups: [a]}\n", cl), "identity.user"},
		"empty user":           {base(cred, "      identity: {user: \"\"}\n", cl), "identity.user"},
		"user with space":      {base(cred, "      identity: {user: \"a b\"}\n", cl), "identity.user"},
		"user with newline":    {base(cred, "      identity: {user: \"a\\nb\"}\n", cl), "identity.user"},
		"user too long":        {base(cred, "      identity: {user: "+strings.Repeat("a", 129)+"}\n", cl), "identity.user"},
		"non-ascii user":       {base(cred, "      identity: {user: \"admín\"}\n", cl), "identity.user"},
		"group repeated":       {base(cred, "      identity: {user: a, groups: [x, x]}\n", cl), "listed twice"},
		"group bad":            {base(cred, "      identity: {user: a, groups: [\"x;y\"]}\n", cl), "identity.groups"},
		"groups not a list":    {base(cred, "      identity: {user: a, groups: x}\n", cl), "identity.groups"},
		"too many groups":      {base(cred, "      identity: {user: a, groups: [a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q]}\n", cl), "at most 16"},
		"identity unknown key": {base(cred, "      identity: {user: a, uid: \"1\"}\n", cl), "unknown field"},
		"no cluster":           {base(cred, id, ""), "cluster"},
		"http server":          {base(cred, id, "      cluster: {server: \"http://hydra.example\", ca_sha256: "+caHash+"}\n"), "cluster.server"},
		"server with query":    {base(cred, id, "      cluster: {server: \"https://hydra.example/?a=b\", ca_sha256: "+caHash+"}\n"), "cluster.server"},
		"server with user":     {base(cred, id, "      cluster: {server: \"https://u@hydra.example\", ca_sha256: "+caHash+"}\n"), "cluster.server"},
		"no server":            {base(cred, id, "      cluster: {ca_sha256: "+caHash+"}\n"), "cluster.server"},
		"no ca":                {base(cred, id, "      cluster: {server: \"https://hydra.example\"}\n"), "nazar k8s ca create hydra records it"},
		"short ca":             {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: abc}\n"), "cluster.ca_sha256"},
		"upper ca":             {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+strings.ToUpper(caHash)+"}\n"), "cluster.ca_sha256"},
		"cluster unknown key":  {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", insecure: true}\n"), "unknown field"},
		"ttl_cert too short":   {base(cred, id, cl) + "      ttl_cert: 30s\n", "ttl_cert"},
		"ttl_cert too long":    {base(cred, id, cl) + "      ttl_cert: 61m\n", "ttl_cert"},
		"ttl":                  {base(cred, id, cl) + "      ttl: 5m\n", "the ttl: field is not in this version"},
		"credential_ref":       {base(cred, id, cl) + "      credential_ref: x\n", "the credential_ref: field is not in this version"},
		"kubeconfig_context":   {base(cred, id, cl) + "      kubeconfig_context: x\n", "the kubeconfig_context: field is not in this version"},
		"issuer":               {base(cred, id, cl) + "      issuer: https://x\n", "the issuer: field is not in this version"},
		"unknown field":        {base(cred, id, cl) + "      colour: red\n", "unknown field"},
		"own gate none":        {base(cred, id, cl) + "      gate: none\n", "can't be none"},
		"rule to":              {base(cred, id, cl) + "      rules:\n        - apps: [iterm]\n          to: [kubectl]\n          gate: login\n", "k8s rules take no to:"},
		// No list, but a rule naming kubectl would match kubectl running
		// a plugin from its PATH (kubectl ▸ kubectl-x ▸ nazar): refused.
		"rule names kubectl":     {base(cred, id, cl) + "      rules:\n        - apps: [kubectl]\n          gate: login\n", "rule 1 names kubectl"},
		"rule inline kubectl":    {base(cred, id, cl) + "      rules:\n        - apps: [{path: /usr/local/bin/kubectl}]\n          gate: login\n", "rules are judged on who called it"},
		"rule kubectl of a team": {strings.Replace(base(cred, id, cl), "  perl:", "  kctl: {signed: {team: KUBETEAM01, id: kubectl}}\n  perl:", 1) + "      rules:\n        - apps: [kctl]\n          gate: login\n", "names kubectl"},
		"ttl_token":              {base(cred, id, cl) + "      ttl_token: 5m\n", "the ttl_token: field is not in this version"},
		"tls name with space":    {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", tls_server_name: \"a b\"}\n"), "cluster.tls_server_name"},
		"tls name with escape":   {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", tls_server_name: \"a\\e[2J\"}\n"), "cluster.tls_server_name"},
		"proxy with password":    {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", proxy_url: \"http://u:p@proxy:3128\"}\n"), "cluster.proxy_url"},
		"proxy not a url":        {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", proxy_url: \"proxy:3128\"}\n"), "cluster.proxy_url"},
		"proxy ftp":              {base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", proxy_url: \"ftp://proxy\"}\n"), "cluster.proxy_url"},
		"rule any none":          {base(cred, id, cl) + "      rules:\n        - apps: [any]\n          gate: none\n", "every program"},
		"rule unknown none":      {base(cred, id, cl) + "      rules:\n        - apps: [unknown]\n          gate: none\n", "every program"},
		"rule command":           {base(cred, id, cl) + "      rules:\n        - apps: [{command: [x]}]\n          gate: login\n", "command: matchers are only allowed in to:"},
		"contexts missing":       {k8sApps + "k8s: {}\n", "contexts"},
		"k8s unknown key":        {k8sApps + "k8s:\n  clusters: {}\n", "unknown field"},
		"context not a map":      {k8sApps + "k8s:\n  contexts:\n    hydra: [1]\n", "must be a mapping"},
	} {
		t.Run(name, func(t *testing.T) { wantError(t, tc.src, tc.want) })
	}
	// The clients: list is gone. A context that still has the line is off
	// (LeftoverClients) with a warning naming the fix, never read as if the
	// line were not there; the rest of the config stays valid (k8s design 2.1).
	for _, list := range []string{"[kubectl]", "[kubectl, helm, k9s]", "kubectl", "[]", "[nope]"} {
		src := strings.Replace(base(cred, id, cl)+"      clients: "+list+"\n", "apps:\n", "ssh_agent:\n  keys:\n    github: {gate: login}\napps:\n", 1)
		c, probs := Parse([]byte(src), env)
		if probs.HasErrors() {
			t.Fatalf("clients: %s must not make the file invalid: %v", list, probs)
		}
		want := "k8s.contexts.hydra.clients: " + K8sClientsGone
		if !strings.Contains(probs.Error(), want) || !strings.Contains(K8sClientsGone, "remove the line") {
			t.Fatalf("clients: %s: want the warning %q: %v", list, want, probs)
		}
		if k := c.K8s["hydra"]; k == nil || !k.LeftoverClients || c.SSHAgent.Keys["github"] == nil {
			t.Fatalf("clients: %s: the context is kept, off; the key stays: %+v", list, k)
		}
	}
	// A rule naming kubectl beside it was valid with clients: [helm]: not
	// an error while the context is off.
	if c, probs := Parse([]byte(base(cred, id, cl)+"      clients: [k9s]\n      rules:\n        - apps: [kubectl]\n          gate: login\n"), env); probs.HasErrors() || !c.K8s["hydra"].LeftoverClients {
		t.Fatalf("a leftover context is not checked for kubectl rules: %v", probs)
	}
	if c, _ := mustParse(t, base(cred, id, cl)); c.K8s["hydra"].LeftoverClients {
		t.Fatal("no clients: line, nothing left over")
	}
	// No apps.kubectl needed, and good names and URLs pass.
	noKubectl := strings.Replace(base(cred, id, "      cluster: {server: \"https://hydra.example\", ca_sha256: "+caHash+", tls_server_name: hydra.internal, proxy_url: \"socks5://localhost:1080\"}\n"), "  kubectl: {signed: {team: KUBETEAM01}}\n", "", 1)
	if c, _ := mustParse(t, noKubectl); c.K8s["hydra"] == nil {
		t.Fatal("a context needs no apps.kubectl")
	}
	// The terminal's app: rule, as ca create writes it, is fine.
	mustParse(t, base(cred, id, cl)+"      rules:\n        - apps: [iterm]\n          gate: login\n")
}

func TestK8sContextNames(t *testing.T) {
	for _, ok := range []string{"hydra", "admin@hydra", "a.b-c_d", "A1", strings.Repeat("a", 128)} {
		if !ValidK8sContextName(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"", "-a", ".a", "a/b", "a:b", "a b", "a..b", "ä", "a\n", strings.Repeat("a", 129), "default/api-x:6443/kube:admin"} {
		if ValidK8sContextName(bad) {
			t.Errorf("%q must be invalid", bad)
		}
	}
	src := k8sApps + "k8s:\n  contexts:\n"
	for _, n := range []string{"hydra", "HYDRA"} {
		src += "    " + n + ":\n      credential: ca-cert\n      identity: {user: a}\n      cluster: {server: \"https://hydra.example\", ca_sha256: " + caHash + "}\n"
	}
	wantError(t, src, "differ in more than letter case")
	wantError(t, k8sApps+"k8s:\n  contexts:\n    \"a:b\":\n      credential: ca-cert\n", "context names")
}

func TestK8sManagedServerWarns(t *testing.T) {
	for _, host := range []string{"ABC.gr7.us-east-1.eks.amazonaws.com", "x.gke.goog", "aks-1.hcp.westeurope.azmk8s.io"} {
		src := k8sApps + "k8s:\n  contexts:\n    m:\n      credential: ca-cert\n      identity: {user: a}\n      cluster: {server: \"https://" + host + "\", ca_sha256: " + caHash + "}\n"
		_, probs := mustParse(t, src)
		if !strings.Contains(probs.Error(), "managed clusters can't trust a nazar CA") {
			t.Errorf("%s: want the managed-cluster warning, got %v", host, probs)
		}
	}
}

// Rules of a context are checked for order like a key's.
func TestK8sRuleOrderWarnings(t *testing.T) {
	_, probs := mustParse(t, k8sCtx("      rules:\n        - apps: [any]\n          gate: dialog\n        - apps: [iterm]\n          gate: login\n"))
	if !strings.Contains(probs.Error(), "k8s.contexts.hydra.rules[2]") || !strings.Contains(probs.Error(), "can never match: rule 1") {
		t.Fatalf("want the shadowing warning: %v", probs)
	}
}
