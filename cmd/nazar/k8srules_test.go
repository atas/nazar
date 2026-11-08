package main

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

// k8s rule add|set|remove send config.edit with context (never key
// or secret), with exactly the args ssh-key rule sends; --to and --no-to
// are a usage error that says why; checks run before anything is sent.
func TestK8sRuleCommands(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Op: req.Args["op"], Context: req.Args["context"],
			Path: "/c.yaml", Changed: true, Applied: true, Problems: []control.ConfigProblem{}})
	})
	for _, c := range []struct {
		argv []string
		want map[string]string
	}{
		{[]string{"k8s", "rule", "add", "admin@hydra", "--apps", "iterm,signed:TOOLTEAM01:dev.example.tool", "--gate", "login", "--scope", "session", "--expire", "8h", "--at", "1", "--if-hash", "abc"},
			map[string]string{"op": "rule.add", "context": "admin@hydra", "apps": `["iterm","signed:TOOLTEAM01:dev.example.tool"]`, "gate": "login", "scope": "session", "expire": "8h", "at": "1", "ifHash": "abc"}},
		{[]string{"k8s", "rule", "set", "hydra", "2", "--gate", "dialog", "--no-expire"},
			map[string]string{"op": "rule.set", "context": "hydra", "index": "2", "gate": "dialog", "expire": ""}},
		{[]string{"k8s", "rule", "remove", "hydra.prod", "1", "--if-hash", "abc"}, map[string]string{"op": "rule.remove", "context": "hydra.prod", "index": "1", "ifHash": "abc"}},
	} {
		if code := h.run(append([]string{"--json"}, c.argv...)...); code != 0 {
			t.Fatalf("%q: exit %d %s", c.argv, code, h.errb)
		}
		r := h.requests()
		if got := r[len(r)-1]; got.Command != control.CmdConfigEdit || !maps.Equal(got.Args, c.want) {
			t.Fatalf("%q sent %s %v", c.argv, got.Command, got.Args)
		}
	}
	sent := len(h.requests())
	for _, bad := range [][]string{
		{"k8s", "rule", "add", "hydra", "--apps", "iterm", "--gate", "login", "--to", "kubectl"},
		{"k8s", "rule", "add", "hydra", "--apps", "iterm", "--gate", "login", "--no-to"},
		{"k8s", "rule", "set", "hydra", "1", "--to", "kubectl"},
		{"k8s", "rule", "set", "hydra", "1", "--no-to"},
		{"k8s", "rule", "set", "hydra", "1", "--gate", "login", "--no-to"},
	} {
		h.errb.Reset()
		if code := h.run(bad...); code != control.ExitUsage || !strings.Contains(h.errb.String(), "k8s rules take no --to") {
			t.Errorf("%q: exit %d %s", bad, code, h.errb)
		}
	}
	for _, bad := range [][]string{
		{"k8s", "rule"}, {"k8s", "rule", "move", "hydra"},
		{"k8s", "rule", "add", "a/b", "--apps", "iterm", "--gate", "login"},
		{"k8s", "rule", "add", "a:b", "--apps", "iterm", "--gate", "login"},
		{"k8s", "rule", "add", "a..b", "--apps", "iterm", "--gate", "login"},
		{"k8s", "rule", "remove", "-x", "1"},
		{"k8s", "rule", "add", "hydra", "--gate", "login"}, {"k8s", "rule", "add", "hydra", "--apps", "iterm", "--gate", "yes"},
		{"k8s", "rule", "set", "hydra", "0", "--gate", "login"}, {"k8s", "rule", "set", "hydra", "1"},
		{"k8s", "rule", "add", "hydra", "--apps", "iterm", "--gate", "login", "--no-expire"},
	} {
		if code := h.run(bad...); code != control.ExitUsage {
			t.Errorf("%q: exit %d", bad, code)
		}
	}
	if len(h.requests()) != sent {
		t.Fatal("a usage error sent a request")
	}
	if h.run("k8s", "rule", "set", "hydra", "1"); !strings.HasPrefix(h.errb.String(), "nazar: k8s rule set: give at least one of --apps, --scope") {
		t.Fatalf("k8s rule set's usage must not offer --to: %q", h.errb.String())
	}
	if !strings.HasSuffix(h.errb.String(), "nazar help k8s rule set: its flags and examples\n") {
		t.Fatalf("the usage error must point at k8s rule set's help: %s", h.errb)
	}
	if h.run("k8s"); !strings.Contains(h.errb.String(), "rule") {
		t.Fatalf("k8s's usage must list rule: %s", h.errb)
	}
}
