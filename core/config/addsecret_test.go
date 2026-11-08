package config

import (
	"strings"
	"testing"
	"time"
)

// The entry `nazar secret add` writes for a name config.yaml has no
// entry for (as `ssh-key create` does for a key): the secret's own
// gate block, plus, when the command was typed in a terminal app, one rule
// for that app. Comments and everything already there are kept.
func TestAddSecret(t *testing.T) {
	src := "apiVersion: nazar/v1\nkind: Config\n# mine\nsecrets:\n  OTHER: {gate: block}  # keep\n"
	rule := RuleSpec{Apps: []string{"app:com.googlecode.iterm2"}, Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}
	out, err := AddSecret([]byte(src), "k8s/hydra", &rule)
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
	s := c.Secrets["k8s/hydra"]
	if s == nil || s.Own == nil || s.Own.Gate != GateBlock || len(s.Rules) != 1 || len(s.Deliver) != 2 {
		t.Fatalf("k8s/hydra = %+v\n%s", s, out)
	}
	if r := s.Rules[0]; r.Apps[0].Kind != MatchApp || r.Apps[0].ID != "com.googlecode.iterm2" || r.Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) || len(r.To) != 0 {
		t.Fatalf("rule %+v", r)
	}
	if c.Secrets["OTHER"] == nil {
		t.Fatal("existing entries changed")
	}

	for _, src := range []string{"", "apiVersion: nazar/v1\nkind: Config\n", "apiVersion: nazar/v1\nkind: Config\nsecrets:\n"} {
		out, err := AddSecret([]byte(src), "GH_TOKEN", nil)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		c, probs := Parse(out, env)
		if probs.HasErrors() || c.Secrets["GH_TOKEN"] == nil || c.Secrets["GH_TOKEN"].Own.Gate != GateBlock || len(c.Secrets["GH_TOKEN"].Rules) != 0 {
			t.Fatalf("%q → %s %v", src, out, probs)
		}
	}
	// Names YAML would read as something else stay strings.
	for _, n := range []string{"true", "123", "1e3", "null", "on"} {
		out, err := AddSecret(nil, n, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c, probs := Parse(out, env); probs.HasErrors() || c.Secrets[n] == nil {
			t.Fatalf("%q → %s %v", n, out, probs)
		}
	}
}

func TestAddSecretRefusals(t *testing.T) {
	src := []byte("apiVersion: nazar/v1\nkind: Config\nsecrets:\n  GH_TOKEN: {gate: block}\n")
	if _, err := AddSecret(src, "GH_TOKEN", nil); err == nil {
		t.Fatal("duplicate accepted")
	}
	for _, bad := range []string{"", "../x", "a b", "-x", "x/"} {
		if _, err := AddSecret(nil, bad, nil); err == nil {
			t.Errorf("bad name %q accepted", bad)
		}
	}
	for _, shape := range []string{"- a\n", "apiVersion: nazar/v1\nkind: Config\nsecrets: [a]\n", "apiVersion: nazar/v1\nkind: Config\nsecrets: x\n"} {
		if out, err := AddSecret([]byte(shape), "K", nil); err == nil {
			t.Errorf("%q: wrong shape accepted:\n%s", shape, out)
		}
	}
	if _, err := AddSecret(nil, "K", &RuleSpec{Apps: []string{"bad matcher!"}, Gate: GateLogin}); err == nil {
		t.Fatal("a bad matcher must be refused")
	}
}
