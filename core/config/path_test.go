package config

import (
	"slices"
	"testing"
)

// pathSrc has a path: matcher in every place apps: matchers are accepted:
// an apps: entry, inline in a rule's apps: and to:, and in secret, k8s
// and aws rules.
const pathSrc = hdr + `apps:
  iterm: {app: com.googlecode.iterm2}
  mytool: {path: /opt/homebrew/opt/mytool/bin/mytool}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [mytool]
          gate: none
        - apps: [iterm, {path: /usr/local/bin/tool}]
          scope: session
          gate: login
        - apps: [{app: com.example.term}]
          to: [{path: /usr/local/bin/ssh}]
          gate: dialog
secrets:
  TOKEN:
    rules:
      - apps: [{path: /opt/homebrew/bin/gh}]
        to: [{path: /opt/homebrew/bin/gh}]
        gate: login
k8s:
  contexts:
    hydra:
      credential: ca-cert
      identity: {user: admin}
      cluster:
        server: https://hydra.example:16443
        ca_sha256: ` + caHash + `
      rules:
        - apps: [{path: /opt/homebrew/opt/mytool/bin/mytool}]
          gate: none
`

// path: is a matcher again (spec 4.2): valid everywhere apps: matchers
// are, with no warning (no pin, nothing to trust), under none too.
func TestPathMatcherParsesEverywhere(t *testing.T) {
	c, probs := Parse([]byte(pathSrc), env)
	if c == nil || len(probs) != 0 {
		t.Fatalf("want a valid config with no problem:\n%s", probs.Error())
	}
	if m := c.Apps["mytool"]; m.Kind != MatchPath || m.Path != "/opt/homebrew/opt/mytool/bin/mytool" {
		t.Fatalf("apps.mytool = %+v", m)
	}
	rules := c.SSHAgent.Keys["github"].Rules
	if len(rules) != 3 || rules[1].Apps[1].Kind != MatchPath || rules[2].To[0].Kind != MatchPath {
		t.Fatalf("rules: %+v", rules)
	}
	if c.K8s["hydra"].Rules[0].Policy.Gate != GateNone {
		t.Fatal("a k8s path: rule under none must parse")
	}
	got := c.PathMatchers()
	want := []PathUse{
		{"/opt/homebrew/opt/mytool/bin/mytool", "apps.mytool"},
		{"/usr/local/bin/tool", "ssh_agent.keys.github.rules[2].apps"},
		{"/usr/local/bin/ssh", "ssh_agent.keys.github.rules[3].to"},
		{"/opt/homebrew/bin/gh", "secrets.TOKEN.rules[1].apps"},
		{"/opt/homebrew/bin/gh", "secrets.TOKEN.rules[1].to"},
		{"/opt/homebrew/opt/mytool/bin/mytool", "k8s.contexts.hydra.rules[1].apps"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("PathMatchers:\n got %v\nwant %v", got, want)
	}
	if !c.HasPathMatchers() {
		t.Fatal("HasPathMatchers")
	}
	if Default(env).HasPathMatchers() {
		t.Fatal("the default has no path: matcher")
	}
}

// DropPathMatchers is what a path: matcher meant while it matched
// nothing: a rule with only path: matchers in apps:, or only path: in its
// to:, goes (it could match no request; an emptied to: must never open
// the rule to every receiver); a path: beside other matchers goes alone.
func TestDropPathMatchers(t *testing.T) {
	c, _ := mustParse(t, pathSrc)
	c.DropPathMatchers()
	rules := c.SSHAgent.Keys["github"].Rules
	if len(rules) != 1 || rules[0].Index != 2 || len(rules[0].Apps) != 1 || rules[0].Apps[0].Name != "iterm" {
		t.Fatalf("github rules: %+v", rules)
	}
	if len(c.Secrets["TOKEN"].Rules) != 0 || len(c.K8s["hydra"].Rules) != 0 {
		t.Fatal("rules with only path: matchers must go")
	}
	if c.HasPathMatchers() {
		t.Fatal("no path: matcher may be left")
	}
}

func TestSystemPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/bin/zsh": true, "/usr/bin/login": true, "/usr/libexec/x": true, "/System/Library/x": true, "/sbin/launchd": true, "/usr": true,
		"/usr/local/bin/x": false, "/usr/local": false, "/opt/homebrew/bin/x": false, "/Users/u/bin/x": false, "/binx/y": false, "/usrx": false,
	} {
		if SystemPath(p) != want {
			t.Errorf("SystemPath(%q) = %v", p, !want)
		}
	}
}
