package config

import (
	"strings"
	"testing"
	"time"
)

func TestAddSSHKeyToSpecExample(t *testing.T) {
	out, err := AddSSHKey([]byte(specExample), "work", Policy{Scope: ScopeUse, Gate: GateLogin})
	if err != nil {
		t.Fatal(err)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() {
		t.Fatalf("%s\n%s", probs.Error(), out)
	}
	k := c.SSHAgent.Keys["work"]
	if k == nil || k.Own == nil || k.Own.Gate != GateLogin || len(k.Rules) != 0 {
		t.Fatalf("work = %+v", k)
	}
	if len(c.SSHAgent.Keys) != 4 || len(c.SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatal("existing keys changed")
	}
}

func TestAddSSHKeyKeepsComments(t *testing.T) {
	src := "apiVersion: nazar/v1\nkind: Config\n# my keys\nssh_agent:\n  keys:\n    a: {gate: login}  # important\n"
	out, err := AddSSHKey([]byte(src), "b", Policy{Scope: ScopeSession, Gate: GateDialog})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# my keys") || !strings.Contains(string(out), "# important") {
		t.Fatalf("comments lost:\n%s", out)
	}
	c, probs := Parse(out, env)
	if probs.HasErrors() || c.SSHAgent.Keys["b"].Own.Scope != ScopeSession {
		t.Fatalf("%v\n%s", probs, out)
	}
}

func TestAddSSHKeyCreatesSections(t *testing.T) {
	for _, src := range []string{"", "apiVersion: nazar/v1\nkind: Config\n", "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n"} {
		out, err := AddSSHKey([]byte(src), "k", Policy{Scope: ScopeUse, Gate: GateLogin})
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if c, probs := Parse(out, env); probs.HasErrors() || c.SSHAgent.Keys["k"] == nil {
			t.Fatalf("%q → %s %v", src, out, probs)
		}
	}
}

func TestAddSSHKeyRefusals(t *testing.T) {
	if _, err := AddSSHKey([]byte(specExample), "github", Policy{Gate: GateLogin}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := AddSSHKey(nil, "../x", Policy{Gate: GateLogin}); err == nil {
		t.Fatal("bad name accepted")
	}
	if _, err := AddSSHKey([]byte("- a\n- b\n"), "k", Policy{Gate: GateLogin}); err == nil {
		t.Fatal("non-mapping accepted")
	}
}

// Sections of the wrong shape are refused, never overwritten or panicked on:
// the edit must not silently drop what the user wrote.
func TestAddSSHKeyRefusesWrongShapes(t *testing.T) {
	for _, src := range []string{
		"apiVersion: nazar/v1\nkind: Config\nssh_agent: [a, b]\n",
		"apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys: [a]\n",
		"apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys: just a string\n",
		"apiVersion: nazar/v1\nkind: Config\nssh_agent: 3\n",
		"just a scalar\n",
		"{unterminated: [\n",
	} {
		out, err := AddSSHKey([]byte(src), "k", Policy{Scope: ScopeUse, Gate: GateLogin})
		if err == nil {
			t.Errorf("%q: accepted, gave\n%s", src, out)
		}
	}
}

// The new entry carries exactly the policy asked for: scope and expire for a
// prompting gate, neither for block (where Parse would warn that they are
// ignored and drop them).
func TestAddSSHKeyPolicyRoundTrip(t *testing.T) {
	cases := []Policy{
		{Scope: ScopeUse, Gate: GateLogin},
		{Scope: ScopeSession, Gate: GateDialog, Expire: 8 * time.Hour},
		{Scope: ScopeApp, Gate: GateLogin},
		{Scope: ScopeUse, Gate: GateBlock},
	}
	for _, pol := range cases {
		out, err := AddSSHKey(nil, "k", pol)
		if err != nil {
			t.Fatalf("%v: %v", pol, err)
		}
		c, probs := Parse(out, env)
		if probs.HasErrors() {
			t.Fatalf("%v: %s\n%s", pol, probs.Error(), out)
		}
		for _, p := range probs {
			if p.Severity == SevWarning && strings.Contains(p.Message, "ignored") {
				t.Errorf("%v: the written entry carries a field Parse ignores: %q:\n%s", pol, p.Message, out)
			}
		}
		k := c.SSHAgent.Keys["k"]
		if k == nil || k.Own == nil || *k.Own != pol {
			t.Errorf("%v: parsed back as %+v\n%s", pol, k, out)
		}
	}
}

// Every existing key keeps its rules, byte for byte in meaning, and the
// rest of the file (apps, defaults, socket) is untouched in meaning.
func TestAddSSHKeyKeepsEverythingElse(t *testing.T) {
	before, _ := mustParse(t, specExample)
	out, err := AddSSHKey([]byte(specExample), "work", Policy{Scope: ScopeUse, Gate: GateLogin})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := mustParse(t, string(out))
	for name, k := range before.SSHAgent.Keys {
		k2 := after.SSHAgent.Keys[name]
		if k2 == nil || len(k2.Rules) != len(k.Rules) {
			t.Fatalf("key %s changed: %+v", name, k2)
		}
		for i := range k.Rules {
			if k.Rules[i].Canonical() != k2.Rules[i].Canonical() {
				t.Errorf("key %s rule %d: %s became %s", name, i, k.Rules[i].Canonical(), k2.Rules[i].Canonical())
			}
		}
		if (k.Own == nil) != (k2.Own == nil) || (k.Own != nil && *k.Own != *k2.Own) {
			t.Errorf("key %s own policy changed", name)
		}
	}
	if after.SSHAgent.Socket != before.SSHAgent.Socket || after.Defaults.Timeout != before.Defaults.Timeout {
		t.Error("ssh_agent.socket or defaults changed")
	}
}

// Key names become file names (keys/<name>.pub) and config keys; anything
// that is not a valid key name is refused before the file is touched.
func TestAddSSHKeyRefusesHostileNames(t *testing.T) {
	for _, name := range []string{"", "a/b", "..", ".", "a\nb", "k: {gate: none}", "a b", strings.Repeat("x", 300)} {
		if out, err := AddSSHKey([]byte(specExample), name, Policy{Gate: GateLogin, Scope: ScopeUse}); err == nil {
			t.Errorf("name %q accepted:\n%s", name, out)
		}
	}
}
