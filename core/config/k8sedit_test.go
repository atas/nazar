package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/k8s/cluster"
)

// The context entry `nazar k8s ca create` writes (as `ssh-key create` does:
// its own gate block, plus a login rule for the terminal app it was typed
// in) and the removal `nazar k8s forget` makes. Comments and everything else are kept.

func k8sSpec(rule *RuleSpec) K8sContextSpec {
	return K8sContextSpec{
		Name:     "hydra",
		Identity: K8sIdentity{User: "admin", Groups: []string{"system:masters"}},
		Cluster:  cluster.Pin{Server: "https://hydra.example:16443", CASHA256: caHash, TLSServerName: "hydra.internal"},
		Rule:     rule,
	}
}

func TestAddK8sContext(t *testing.T) {
	src := "apiVersion: nazar/v1\nkind: Config\n# mine\napps:\n  kubectl: {path: /opt/homebrew/bin/kubectl}  # keep\n"
	rule := RuleSpec{Apps: []string{"app:com.googlecode.iterm2"}, Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}
	out, err := AddK8sContext([]byte(src), k8sSpec(&rule))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# mine") || !strings.Contains(string(out), "# keep") {
		t.Fatalf("comments lost:\n%s", out)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() {
		t.Fatalf("%s\n%s", probs.Error(), out)
	}
	k := c.K8s["hydra"]
	if k == nil || k.Credential != CredentialCACert || k.Identity.User != "admin" || !slices.Equal(k.Identity.Groups, []string{"system:masters"}) ||
		k.Cluster.Server != "https://hydra.example:16443" || k.Cluster.CASHA256 != caHash || k.Cluster.TLSServerName != "hydra.internal" || k.Cluster.ProxyURL != "" ||
		k.TTLCert != DefaultTTLCert || k.Own == nil || k.Own.Gate != GateBlock {
		t.Fatalf("%+v\n%s", k, out)
	}
	if len(k.Rules) != 1 || k.Rules[0].Apps[0].ID != "com.googlecode.iterm2" || k.Rules[0].Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) {
		t.Fatalf("rules %+v", k.Rules)
	}
	// Without a terminal: the block alone.
	out, err = AddK8sContext([]byte(src), k8sSpec(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c, probs := Parse(out, env); probs.HasErrors() || len(c.K8s["hydra"].Rules) != 0 {
		t.Fatalf("%v\n%s", probs, out)
	}
	// Into an existing k8s section beside another context.
	two, err := AddK8sContext(out, K8sContextSpec{Name: "staging", Identity: K8sIdentity{User: "dev"}, Cluster: cluster.Pin{Server: "https://s.example", CASHA256: caHash}})
	if err != nil {
		t.Fatal(err)
	}
	if c, probs := Parse(two, env); probs.HasErrors() || c.K8s["hydra"] == nil || c.K8s["staging"] == nil {
		t.Fatalf("%v\n%s", probs, two)
	}
}

func TestAddK8sContextRefusals(t *testing.T) {
	ok := "apiVersion: nazar/v1\nkind: Config\napps:\n  kubectl: {path: /opt/homebrew/bin/kubectl}\n"
	for name, tc := range map[string]struct {
		src  string
		spec K8sContextSpec
	}{
		"exists":         {ok + "k8s:\n  contexts:\n    HYDRA: {}\n", k8sSpec(nil)},
		"k8s a list":     {ok + "k8s: []\n", k8sSpec(nil)},
		"contexts list":  {ok + "k8s:\n  contexts: []\n", k8sSpec(nil)},
		"invalid name":   {ok, K8sContextSpec{Name: "a/b", Identity: K8sIdentity{User: "a"}, Cluster: k8sSpec(nil).Cluster}},
		"no identity":    {ok, K8sContextSpec{Name: "hydra", Cluster: k8sSpec(nil).Cluster}},
		"bad group":      {ok, K8sContextSpec{Name: "hydra", Identity: K8sIdentity{User: "a", Groups: []string{"a,b"}}, Cluster: k8sSpec(nil).Cluster}},
		"no cluster":     {ok, K8sContextSpec{Name: "hydra", Identity: K8sIdentity{User: "a"}}},
		"bad server":     {ok, K8sContextSpec{Name: "hydra", Identity: K8sIdentity{User: "a"}, Cluster: cluster.Pin{Server: "http://x", CASHA256: caHash}}},
		"not a document": {"- a\n", k8sSpec(nil)},
	} {
		if out, err := AddK8sContext([]byte(tc.src), tc.spec); err == nil {
			t.Errorf("%s: want an error, got\n%s", name, out)
		}
	}
}

func TestRemoveK8sContext(t *testing.T) {
	src := "apiVersion: nazar/v1\nkind: Config\n# top\napps:\n  kubectl: {path: /opt/homebrew/bin/kubectl}\nk8s:\n  contexts:\n    hydra:  # the node\n      credential: ca-cert\n      identity: {user: admin}\n      cluster: {server: \"https://hydra.example\", ca_sha256: " + caHash + "}\n    staging:\n      credential: ca-cert\n      identity: {user: dev}\n      cluster: {server: \"https://s.example\", ca_sha256: " + caHash + "}\n"
	out, err := RemoveK8sContext([]byte(src), "hydra")
	if err != nil {
		t.Fatal(err)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() || c.K8s["hydra"] != nil || c.K8s["staging"] == nil || !strings.Contains(string(out), "# top") {
		t.Fatalf("%v\n%s", probs, out)
	}
	if _, err := RemoveK8sContext([]byte(src), "nope"); err == nil {
		t.Fatal("removing an absent context is an error")
	}
	if _, err := RemoveK8sContext([]byte(src), "HYDRA"); err == nil {
		t.Fatal("names are exact")
	}
}
