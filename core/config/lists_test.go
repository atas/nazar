package config

import (
	"reflect"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"
)

// apps: and to: take one shape: a list. One matcher on its own (a name, or
// one inline matcher, flow or block) is an error that says how to write it.
func TestAppsAndToAreListsOnly(t *testing.T) {
	head := "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n  git-https: {signed: {team: apple, id: com.apple.git-remote-http}}\n"
	for _, tc := range []struct{ name, src, want string }{
		{"key apps name", head + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: iterm\n          gate: login\n",
			"ssh_agent.keys.k.rules[1].apps: must be a list, e.g. apps: [iterm]"},
		{"key apps flow map", head + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: {app: com.x}\n          gate: login\n",
			"rules[1].apps: must be a list"},
		{"key apps block map", head + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps:\n            app: com.x\n          gate: login\n",
			"rules[1].apps: must be a list"},
		{"key apps any", head + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: any\n          gate: login\n",
			"rules[1].apps: must be a list"},
		{"key to", head + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [iterm]\n          to: {signed: {team: apple, id: com.apple.openssh}}\n          gate: login\n",
			"rules[1].to: must be a list, e.g. to: [iterm]"},
		{"secret to", head + "secrets:\n  T:\n    deliver: [helper]\n    helper: {git: {host: github.com}}\n    rules:\n      - apps: [iterm]\n        to: git-https\n        gate: dialog\n",
			"secrets.T.rules[1].to: must be a list"},
		{"secret apps", head + "secrets:\n  T:\n    rules:\n      - apps: iterm\n        to: [git-https]\n        gate: dialog\n",
			"secrets.T.rules[1].apps: must be a list"},
	} {
		t.Run(tc.name, func(t *testing.T) { wantError(t, tc.src, tc.want) })
	}
	// The list forms, flow and block, one matcher or several.
	c, _ := mustParse(t, head+`ssh_agent:
  keys:
    k:
      rules:
        - apps: [iterm]
          to: [{signed: {team: apple, id: com.apple.openssh}}]
          gate: login
        - apps:
            - app: com.x
            - iterm
          gate: dialog
`)
	r := c.SSHAgent.Keys["k"].Rules
	if len(r) != 2 || len(r[0].Apps) != 1 || len(r[0].To) != 1 || len(r[1].Apps) != 2 {
		t.Fatalf("%+v", r)
	}
}

// legacyConfig writes every rule's apps: and to: the way builds before
// list-only accepted: names, flow and block maps, with comments, in keys,
// secrets, a k8s context and an aws entry.
const legacyConfig = `apiVersion: nazar/v1
kind: Config
# my config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
  git-https: {signed: {team: apple, id: com.apple.git-remote-http}}
ssh_agent:
  keys:
    github:
      rules:
        - apps: claude # Claude Code
          scope: session
          gate: dialog
        - apps:
            app: com.mitchellh.ghostty
          gate: login
        - apps: [iterm]
          to: {signed: {team: apple, id: com.apple.openssh}}
          gate: none
        - apps: {path: /opt/homebrew/bin/tool}
          gate: login
      gate: block
secrets:
  GH_TOKEN:
    deliver: [helper]
    helper: {git: {host: github.com}}
    rules:
      - apps: iterm
        to: git-https
        scope: session
        gate: dialog
k8s:
  contexts:
    lab:
      credential: ca-cert
      identity: {user: me}
      cluster: {server: "https://10.0.0.1:6443", ca_sha256: 0000000000000000000000000000000000000000000000000000000000000000}
      rules:
        - apps: iterm
          gate: login
aws:
  dev:
    identity: {user: me}
    rules:
      - apps: {app: com.googlecode.iterm2}
        gate: login
`

// ruleShapes returns, for every rule in the file, whether its apps: and
// to: are YAML sequences.
func ruleShapes(t *testing.T, data []byte) (lists, singles int) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if k := n.Content[i].Value; (k == "apps" || k == "to") && lookup(n, "gate") != nil {
					if n.Content[i+1].Kind == yaml.SequenceNode {
						lists++
					} else {
						singles++
					}
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return lists, singles
}

// Migrate rewrites every single form as a list of one, keeps the
// comments, and the result parses (strictly) to exactly what the old file
// meant read the old way.
func TestMigrateKeepsTheMeaning(t *testing.T) {
	if _, probs := Parse([]byte(legacyConfig), env); !probs.HasErrors() {
		t.Fatal("the legacy config parses strictly: this test would prove nothing")
	}
	out, ok := Migrate([]byte(legacyConfig), env)
	if !ok {
		t.Fatal("not migrated")
	}
	nw, probs := Parse(out, env)
	if probs.HasErrors() {
		t.Fatalf("the rewrite does not parse:\n%s\n%s", out, probs.Error())
	}
	if _, singles := ruleShapes(t, out); singles != 0 {
		t.Fatalf("%d single forms left:\n%s", singles, out)
	}
	old := legacyParse(t, legacyConfig)
	old.Raw, old.Hash, nw.Raw, nw.Hash = nil, "", nil, ""
	if !reflect.DeepEqual(old, nw) {
		t.Fatalf("the rewrite means something else:\nold %+v\nnew %+v", old, nw)
	}
	for _, c := range []string{"# my config", "# Claude Code"} {
		if !strings.Contains(string(out), c) {
			t.Errorf("comment %q lost:\n%s", c, out)
		}
	}
	// Deterministic: the same bytes always give the same rewrite (the
	// approved config and a file equal to it end up equal).
	again, _ := Migrate([]byte(legacyConfig), env)
	if string(again) != string(out) {
		t.Fatal("two rewrites of the same bytes differ")
	}
	// Idempotent: nothing to do on the result.
	if _, ok := Migrate(out, env); ok {
		t.Fatal("the rewrite is rewritten again")
	}
}

func legacyParse(t *testing.T, src string) *Config {
	t.Helper()
	p := &parser{env: env, legacy: true}
	c := p.parse([]byte(src))
	if p.probs.HasErrors() {
		t.Fatalf("legacy parse: %s", p.probs.Error())
	}
	return c
}

// Nothing to rewrite: a strict file, a file invalid the old way too, and a
// file whose only problem is something else.
func TestMigrateLeavesOtherFilesAlone(t *testing.T) {
	for name, src := range map[string]string{
		"strict":    "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [any]\n          gate: login\n",
		"not yaml":  "apiVersion: nazar/v1\nkind: Config\nssh_agent: [",
		"other bad": "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: iterm\n          gate: maybe\n",
		"unknown":   "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: nosuchapp\n          gate: login\n",
		"empty":     "",
		"no lists":  "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: []\n          gate: login\n",
	} {
		if out, ok := Migrate([]byte(src), env); ok || out != nil {
			t.Errorf("%s: migrated to\n%s", name, out)
		}
	}
}

// Every rule nazar writes has list-form apps: and to:, one matcher too.
func TestWritersEmitLists(t *testing.T) {
	base := []byte("apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n")
	check := func(name string, out []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		lists, singles := ruleShapes(t, out)
		if singles != 0 || lists == 0 {
			t.Fatalf("%s: %d list(s), %d single form(s):\n%s", name, lists, singles, out)
		}
		if _, probs := Parse(out, env); probs.HasErrors() {
			t.Fatalf("%s: %s\n%s", name, probs.Error(), out)
		}
	}
	out, err := AddRule(base, KeyEntry("k"), RuleSpec{Apps: []string{"iterm"}, To: []string{"signed:apple:com.apple.openssh"}, Gate: GateLogin}, 0)
	check("add", out, err)
	out, err = SetRule(out, KeyEntry("k"), 1, RulePatch{Apps: []string{"app:com.x"}, To: &[]string{"iterm"}})
	check("set", out, err)
	out, err = AddSecret(base, "T", &RuleSpec{Apps: []string{"iterm"}, To: []string{"signed:apple:com.apple.git-remote-http"}, Gate: GateDialog, Scope: ScopeSession})
	check("secret add", out, err)
}
