package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var env = Env{Home: "/Users/u"}

// specExample is the config from spec 4.2, verbatim apart from comments.
const specExample = `apiVersion: nazar/v1
kind: Config

defaults:
  timeout: 60s
  fallback:
    gate: block

apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
  cursor:
    app: com.todesktop.230313mzl4w4u92
  ghostty:
    app: com.mitchellh.ghostty
  zed:
    app: dev.zed.Zed

ssh_agent:
  socket: ~/.nazar/run/agent.sock
  keys:
    github:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
        - apps: [iterm, cursor]
          scope: session
          gate: login
          expire: 8h
    myrepo-deploy:
      rules:
        - apps: [iterm, cursor]
          gate: none
    hydra:
      scope: use
      gate: login
`

func mustParse(t *testing.T, src string) (*Config, Problems) {
	t.Helper()
	c, probs := Parse([]byte(src), env)
	if probs.HasErrors() {
		t.Fatalf("unexpected errors:\n%s", probs.Error())
	}
	return c, probs
}

func wantError(t *testing.T, src, substr string) {
	t.Helper()
	c, probs := Parse([]byte(src), env)
	if c != nil || !probs.HasErrors() {
		t.Fatalf("want error containing %q, got config and %v", substr, probs)
	}
	if !strings.Contains(probs.Error(), substr) {
		t.Fatalf("want error containing %q, got:\n%s", substr, probs.Error())
	}
}

func TestSpecExampleParses(t *testing.T) {
	c, probs := mustParse(t, specExample)
	if len(probs) != 0 {
		t.Fatalf("the spec example must parse without a warning:\n%s", probs.Error())
	}
	if c.SSHAgent.Socket != "/Users/u/.nazar/run/agent.sock" {
		t.Fatalf("socket %q", c.SSHAgent.Socket)
	}
	if c.Defaults.Timeout != 60*time.Second || c.Defaults.Fallback.Gate != GateBlock {
		t.Fatalf("defaults %+v", c.Defaults)
	}
	gh := c.SSHAgent.Keys["github"]
	if len(gh.Rules) != 2 || gh.Own != nil {
		t.Fatalf("github %+v", gh)
	}
	r1, r2 := gh.Rules[0], gh.Rules[1]
	if r1.Apps[0].Kind != MatchSigned || r1.Apps[0].Team != "Q6L2SF6YDW" || r1.Apps[0].ID != "com.anthropic.claude-code" || r1.Apps[0].Name != "claude" {
		t.Fatalf("rule 1 apps %+v", r1.Apps)
	}
	if r1.Policy != (Policy{Scope: ScopeSession, Gate: GateDialog}) {
		t.Fatalf("rule 1 policy %+v", r1.Policy)
	}
	if len(r2.Apps) != 2 || r2.Policy.Expire != 8*time.Hour || r2.Policy.Gate != GateLogin || r2.Index != 2 {
		t.Fatalf("rule 2 %+v", r2)
	}
	if d := c.SSHAgent.Keys["myrepo-deploy"].Rules[0].Policy; d.Gate != GateNone || d.Scope != ScopeUse {
		t.Fatalf("deploy policy %+v", d)
	}
	if own := c.SSHAgent.Keys["hydra"].Own; own == nil || own.Gate != GateLogin || own.Scope != ScopeUse {
		t.Fatalf("hydra own %+v", own)
	}
	if c.Fallback("github").Gate != GateBlock || c.Fallback("hydra").Gate != GateLogin || c.Fallback("nope").Gate != GateBlock {
		t.Fatal("Fallback()")
	}
	if !c.NeedsUserPresence("hydra") || c.NeedsUserPresence("github") {
		t.Fatal("NeedsUserPresence")
	}
	if c.Audit.Args != ArgsRedacted || len(c.Hash) != 64 {
		t.Fatalf("audit %q hash %q", c.Audit.Args, c.Hash)
	}
}

func TestVersionAndKind(t *testing.T) {
	wantError(t, "kind: Config\n", "apiVersion")
	wantError(t, "apiVersion: nazar/v2\nkind: Config\n", `unknown apiVersion "nazar/v2"`)
	wantError(t, "apiVersion: nazar/v1\n", "kind")
	wantError(t, "apiVersion: nazar/v1\nkind: Secret\n", `unknown kind "Secret"`)
	wantError(t, "", "empty")
	// An unknown version is refused before anything else is looked at.
	_, probs := Parse([]byte("apiVersion: nazar/v9\nkind: Config\nbogus: 1\n"), env)
	if len(probs) != 1 {
		t.Fatalf("want exactly the version error, got %v", probs)
	}
}

func TestStrictness(t *testing.T) {
	h := "apiVersion: nazar/v1\nkind: Config\n"
	wantError(t, h+"sshagent: {}\n", `unknown field "sshagent"`)
	wantError(t, h+"ssh_agent:\n  keys:\n    a:\n      rules:\n        - apps: [any]\n          gate: login\n          gat: none\n", `unknown field "gat"`)
	wantError(t, h+"apps:\n  a: {app: x}\n  a: {app: y}\n", "already defined")
	wantError(t, h+"---\napiVersion: nazar/v1\n", "one YAML document")
	wantError(t, strings.Repeat("#", MaxFileSize+1), "larger than")
	wantError(t, h+"defaults:\n  timeout: 0s\n", "positive")
	wantError(t, h+"defaults:\n  timeout: 11m\n", "between 1s and 10m")
	wantError(t, h+"audit:\n  args: full\n", "redacted or none")
	wantError(t, h+"apps:\n  a: &x {app: x}\n  b:\n    <<: *x\n", "plain strings")
	wantError(t, h+"apps:\n  a: &x {app: x}\n  b: *x\n", "must be a mapping")
	wantError(t, h+"ssh_agent:\n  keys:\n    k: {gate: login}\n    k: {gate: block}\n", "already defined")
}

func TestRuleValidation(t *testing.T) {
	h := "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n  mcp: {command: [npx, -y, x]}\nssh_agent:\n  keys:\n    k:\n"
	wantError(t, h+"      rules:\n        - apps: [iterm]\n", "missing gate")
	wantError(t, h+"      rules:\n        - gate: login\n", "missing apps")
	wantError(t, h+"      rules:\n        - apps: [nosuch]\n          gate: login\n", `unknown app "nosuch"`)
	wantError(t, h+"      rules:\n        - apps: [iterm, {signed: {team: apple}}]\n          gate: none\n", "is refused under none")
	wantError(t, h+"      rules:\n        - apps: [mcp]\n          gate: login\n", "only allowed in to:")
	wantError(t, h+"      rules:\n        - apps: [iterm]\n          to: [mcp]\n          gate: login\n", "not to ssh keys")
	wantError(t, h+"      rules:\n        - apps: [iterm]\n          gate: maybe\n", "login, dialog, none or block")
	wantError(t, h+"      rules:\n        - apps: [iterm]\n          gate: login\n          scope: tab\n", "use, session or app")
	wantError(t, h+"      rules:\n        - apps: [iterm]\n          gate: login\n          expire: forever\n", "invalid duration")
	wantError(t, h+"      gate: none\n", "can't be none")
	wantError(t, h+"      scope: session\n", "without gate")
	wantError(t, "apiVersion: nazar/v1\nkind: Config\ndefaults:\n  fallback:\n    gate: none\n", "every caller")
}

func TestMatcherValidation(t *testing.T) {
	h := "apiVersion: nazar/v1\nkind: Config\napps:\n"
	wantError(t, h+"  a: {signed: {id: x}}\n", "team is required")
	wantError(t, h+"  a: {app: x, path: /x}\n", "exactly one")
	wantError(t, h+"  a: {team: X}\n", "exactly one")
	for _, p := range []string{"~/bin/x", "bin/x", "./x", "/opt/bin/", "//opt/x", "/opt/./x", "/opt/x/..", "\"\""} {
		wantError(t, h+"  a: {path: "+p+"}\n", "clean absolute path")
	}
	wantError(t, h+"  a: {signed: {team: X}, team: Y}\n", "team: belongs with app")
	wantError(t, h+"  any: {app: x}\n", "built in")
	wantError(t, h+"  Bad: {app: x}\n", "app names")
	wantError(t, h+"  a: {command: []}\n", "non-empty")
}

func TestKeyNames(t *testing.T) {
	for _, bad := range []string{"../x", "a/b", ".hidden", "", "a..b", strings.Repeat("a", 65)} {
		if ValidKeyName(bad) {
			t.Errorf("ValidKeyName(%q) = true", bad)
		}
	}
	for _, good := range []string{"github", "myrepo-deploy", "a.b_c", "K1"} {
		if !ValidKeyName(good) {
			t.Errorf("ValidKeyName(%q) = false", good)
		}
	}
	wantError(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    ../evil:\n      gate: login\n", "key names")
}

func TestInlineMatchersAndAppTeam(t *testing.T) {
	c, _ := mustParse(t, `apiVersion: nazar/v1
kind: Config
ssh_agent:
  keys:
    k:
      rules:
        - apps: [{app: com.googlecode.iterm2, team: H7V7XYVQ7D}]
          to: [{signed: {team: apple, id: com.apple.openssh}}]
          gate: dialog
          scope: app
`)
	r := c.SSHAgent.Keys["k"].Rules[0]
	if r.Apps[0].Kind != MatchApp || r.Apps[0].Team != "H7V7XYVQ7D" || r.Apps[0].Name != "" {
		t.Fatalf("apps %+v", r.Apps)
	}
	if r.To[0].Kind != MatchSigned || r.To[0].Team != "apple" {
		t.Fatalf("to %+v", r.To)
	}
}

func TestNormalisationAndWarnings(t *testing.T) {
	c, probs := mustParse(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    k:
      rules:
        - apps: [any]
          gate: login
        - apps: [iterm]
          gate: block
secrets:
  X: {}
k8s:
  contexts: {}
`)
	text := probs.Error()
	for _, want := range []string{"rules[2]", "can never match: rule 1"} {
		if !strings.Contains(text, want) {
			t.Errorf("warnings missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "secrets section") {
		t.Errorf("the secrets section is implemented now:\n%s", text)
	}
	// So is k8s (an empty contexts mapping is valid and says nothing).
	if strings.Contains(text, "k8s section") {
		t.Errorf("the k8s section is implemented now:\n%s", text)
	}
	if len(c.Unimplemented) != 0 || c.Secrets["X"] == nil || c.K8s == nil || len(c.K8s) != 0 {
		t.Fatalf("Unimplemented %v, secrets %v, k8s %v", c.Unimplemented, c.Secrets, c.K8s)
	}
}

func TestDefault(t *testing.T) {
	c := Default(env)
	if len(c.SSHAgent.Keys) != 0 || c.Defaults.Fallback.Gate != GateBlock || c.SSHAgent.Socket != "/Users/u/.nazar/run/agent.sock" {
		t.Fatalf("default %+v", c)
	}
}

func TestRuleIDChangesWithMeaning(t *testing.T) {
	a, _ := mustParse(t, specExample)
	b, _ := mustParse(t, strings.Replace(specExample, "gate: dialog", "gate: login", 1))
	if a.SSHAgent.Keys["github"].Rules[0].ID() == b.SSHAgent.Keys["github"].Rules[0].ID() {
		t.Fatal("rule ID must change when the rule changes")
	}
	if a.SSHAgent.Keys["github"].Rules[1].ID() != b.SSHAgent.Keys["github"].Rules[1].ID() {
		t.Fatal("unchanged rule must keep its ID")
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"8h": 8 * time.Hour, "90s": 90 * time.Second, "7d": 7 * 24 * time.Hour} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1h", "0d", "1w", "d"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) succeeded", bad)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(specExample))
	f.Add([]byte("apiVersion: nazar/v1\nkind: Config\napps: &a {x: *a}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, probs := Parse(data, env)
		if (c == nil) != probs.HasErrors() {
			t.Fatalf("config nil=%v but HasErrors=%v", c == nil, probs.HasErrors())
		}
	})
}

// ---------------------------------------------------------------------------
// Edge and attack cases implied by spec 4.2, 4.5 and 9. They check
// behaviour through the exported API only.
// ---------------------------------------------------------------------------

const hdr = "apiVersion: nazar/v1\nkind: Config\n"

// rulesHdr defines two named apps and opens the rules list of key k.
const rulesHdr = hdr + "apps:\n  iterm: {app: com.googlecode.iterm2}\n  mcp: {command: [npx, -y, x]}\nssh_agent:\n  keys:\n    k:\n      rules:\n"

// errorsOf returns only the error-severity problems.
func errorsOf(ps Problems) Problems {
	var out Problems
	for _, p := range ps {
		if p.Severity == SevError {
			out = append(out, p)
		}
	}
	return out
}

// Spec 4.2: nazar never guesses at a schema it doesn't know. apiVersion and
// kind are compared exactly, must be plain strings, and only the top-level
// fields count.
func TestVersionAndKindAreExact(t *testing.T) {
	for _, src := range []string{
		"apiVersion: Nazar/V1\nkind: Config\n",
		"apiVersion: \"nazar/v1 \"\nkind: Config\n",
		"apiVersion: nazar/v1beta1\nkind: Config\n",
		"apiVersion: v1\nkind: Config\n",
		"apiVersion: [nazar/v1]\nkind: Config\n",
		"apiVersion: {v: nazar/v1}\nkind: Config\n",
		"apiVersion: ~\nkind: Config\n",
		"apiVersion:\nkind: Config\n",
		// Only the top level counts.
		"defaults:\n  apiVersion: nazar/v1\n  kind: Config\n",
		// A repeated apiVersion must never let either value win silently.
		"apiVersion: nazar/v1\napiVersion: nazar/v2\nkind: Config\n",
		"apiVersion: nazar/v2\napiVersion: nazar/v1\nkind: Config\n",
	} {
		wantError(t, src, "apiVersion")
	}
	for _, src := range []string{
		"apiVersion: nazar/v1\nkind: config\n",
		"apiVersion: nazar/v1\nkind: \"Config \"\n",
		"apiVersion: nazar/v1\nkind: [Config]\n",
		"apiVersion: nazar/v1\nkind: ~\n",
		"apiVersion: nazar/v1\nkind: Secret\nkind: Config\n",
		"apiVersion: nazar/v1\nkind: Config\nkind: Secret\n",
	} {
		wantError(t, src, "kind")
	}
	// An unknown kind is refused before the rest of the file is looked at.
	_, probs := Parse([]byte("apiVersion: nazar/v1\nkind: Secret\nbogus: 1\n"), env)
	if len(probs) != 1 {
		t.Fatalf("want exactly the kind error, got %v", probs)
	}
	// A leading document marker is still one document.
	mustParse(t, "---\n"+hdr)
}

func TestMalformedYAML(t *testing.T) {
	for name, src := range map[string]string{
		"top-level sequence":  "- apiVersion: nazar/v1\n- kind: Config\n",
		"top-level scalar":    "nazar/v1\n",
		"only a comment":      "# nothing here\n",
		"unterminated flow":   hdr + "apps: [\n",
		"tab indentation":     hdr + "defaults:\n\ttimeout: 5s\n",
		"complex key":         hdr + "? [a, b]\n: c\n",
		"non-scalar app name": hdr + "apps:\n  ? {x: y}\n  : {app: x}\n",
		"binary garbage":      "\x00\x01\x02\xff\xfe",
		"second document":     hdr + "---\n" + hdr,
	} {
		c, probs := Parse([]byte(src), env)
		if c != nil || !probs.HasErrors() {
			t.Errorf("%s: want an error, got config %v and %v", name, c != nil, probs)
		}
	}
}

// Spec 4.2 / 9: `config check` shows details, so problems carry where they are.
func TestProblemsCarryLocation(t *testing.T) {
	_, probs := Parse([]byte(hdr+"defaults:\n  timeout: 5s\n  fallbak: {gate: login}\n"), env)
	var found *Problem
	for i := range probs {
		if strings.Contains(probs[i].Message, `unknown field "fallbak"`) {
			found = &probs[i]
		}
	}
	if found == nil {
		t.Fatalf("no unknown-field problem in %v", probs)
	}
	if found.Severity != SevError || found.Line != 5 || !strings.Contains(found.Path, "defaults") {
		t.Fatalf("problem %+v: want error at line 5 under defaults", *found)
	}
	if !strings.Contains(probs.Error(), "line 5") {
		t.Fatalf("Error() lacks the line: %s", probs.Error())
	}
}

// All independent errors are reported at once, not just the first.
func TestAllErrorsReported(t *testing.T) {
	_, probs := Parse([]byte(hdr+"defaults:\n  timeout: 0s\naudit:\n  args: full\n"), env)
	if n := len(errorsOf(probs)); n < 2 {
		t.Fatalf("want at least 2 errors, got %d: %v", n, probs)
	}
	for _, want := range []string{"positive", "redacted or none"} {
		if !strings.Contains(probs.Error(), want) {
			t.Errorf("errors missing %q:\n%s", want, probs.Error())
		}
	}
}

// A repeated key must never silently override the first, at any depth: a
// reviewer reading the top of a rule must see what nazar enforces.
// A check of the top level alone would miss secrets:/k8s:; this test (and
// the two below) need a whole-tree check.
func TestDuplicateKeysAnywhere(t *testing.T) {
	for name, src := range map[string]string{
		"rule gate":       rulesHdr + "        - apps: [iterm]\n          gate: login\n          gate: none\n",
		"rule apps":       rulesHdr + "        - apps: [iterm]\n          apps: [any]\n          gate: login\n",
		"inline matcher":  hdr + "apps:\n  a: {app: x, app: y}\n",
		"signed fields":   hdr + "apps:\n  a: {signed: {team: A, team: B}}\n",
		"defaults":        hdr + "defaults:\n  timeout: 5s\n  timeout: 9m\n",
		"top level":       hdr + "audit: {args: none}\naudit: {args: redacted}\n",
		"ssh_agent":       hdr + "ssh_agent:\n  socket: /tmp/a\n  socket: /tmp/b\n",
		"secrets section": hdr + "secrets:\n  A: {}\n  A: {}\n",
		"k8s section":     hdr + "k8s:\n  contexts: {}\n  contexts: {}\n",
	} {
		c, probs := Parse([]byte(src), env)
		if c != nil || !strings.Contains(probs.Error(), "already defined") {
			t.Errorf("%s: want an \"already defined\" error, got config=%v %v", name, c != nil, probs)
		}
	}
}

// Aliases and merge keys are refused everywhere, including the sections this
// version doesn't implement: the file is what gets approved, and what it
// means must be readable from the text.
func TestAliasesAndMergeKeysAnywhere(t *testing.T) {
	for name, src := range map[string]string{
		"scalar alias in matcher": hdr + "apps:\n  a: {app: &g x}\n  b: {app: *g}\n",
		"alias as gate":           hdr + "defaults:\n  fallback: {gate: &g login}\nssh_agent:\n  keys:\n    k:\n      gate: *g\n",
		"alias as apps list":      hdr + "apps:\n  iterm: {app: x}\nk8s: {l: &l [iterm]}\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: *l\n          gate: login\n",
		"alias as rule":           hdr + "apps:\n  iterm: {app: x}\nssh_agent:\n  keys:\n    a:\n      rules:\n        - &r {apps: [iterm], gate: login}\n    b:\n      rules:\n        - *r\n",
		"alias in secrets":        hdr + "secrets:\n  a: &x {v: 1}\n  b: *x\n",
		"merge key in k8s":        hdr + "k8s:\n  a: &x {v: 1}\n  b:\n    <<: *x\n",
		"merge key in rule":       hdr + "apps:\n  iterm: {app: x}\nk8s: {base: &b {gate: none}}\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [iterm]\n          <<: *b\n",
	} {
		c, probs := Parse([]byte(src), env)
		if c != nil || !probs.HasErrors() {
			t.Errorf("%s: want an error, got config=%v %v", name, c != nil, probs)
		}
	}
}

// A "billion laughs" alias bomb must be refused without expanding it.
func TestAliasBomb(t *testing.T) {
	for _, section := range []string{"apps", "secrets", "k8s"} {
		var b strings.Builder
		b.WriteString(hdr + section + ":\n  a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n")
		for i := 1; i < 40; i++ {
			p := fmt.Sprintf("*a%d", i-1)
			fmt.Fprintf(&b, "  a%d: &a%d [%s]\n", i, i, strings.Repeat(p+", ", 9)+p)
		}
		start := time.Now()
		c, probs := Parse([]byte(b.String()), env)
		if c != nil || !probs.HasErrors() {
			t.Errorf("%s: alias bomb accepted: %v", section, probs)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: alias bomb took %v", section, d)
		}
	}
}

// A null or non-string gate is an error, never "no gate" or a default.
func TestNullAndNonStringValues(t *testing.T) {
	for _, g := range []string{"gate:\n", "gate: ~\n", "gate: null\n", "gate: [none]\n", "gate: {none: 1}\n", "gate: \"\"\n", "gate: None\n", "gate: NONE\n"} {
		wantError(t, rulesHdr+"        - apps: [iterm]\n          "+g, "gate")
	}
	wantError(t, rulesHdr+"        - apps: [iterm]\n          gate: login\n          scope: ~\n", "scope")
	wantError(t, rulesHdr+"        - apps: [iterm]\n          gate: login\n          scope: session\n          expire: ~\n", "expire")
	wantError(t, rulesHdr+"        - apps: []\n          gate: login\n", "apps")
	wantError(t, rulesHdr+"        - apps: ~\n          gate: login\n", "apps")
	wantError(t, rulesHdr+"        - apps: [iterm, 7]\n          gate: login\n", "apps")
	wantError(t, rulesHdr+"        - apps: [iterm]\n          to: []\n          gate: login\n", "to")
	wantError(t, hdr+"ssh_agent:\n  keys:\n    k:\n      rules: {apps: [any], gate: login}\n", "rules")
	wantError(t, hdr+"ssh_agent:\n  keys: [a, b]\n", "ssh_agent.keys")
	wantError(t, hdr+"ssh_agent:\n  socket: ~\n", "socket")
	wantError(t, hdr+"audit:\n  args: ~\n", "audit.args")
}

func TestUnknownFieldsAtEveryLevel(t *testing.T) {
	for _, tc := range []struct{ src, field string }{
		{hdr + "ssh_agent:\n  key: {}\n", "key"},
		{hdr + "ssh_agent:\n  keys:\n    k:\n      gate: login\n      rule: []\n", "rule"},
		{hdr + "defaults:\n  fallback: {gate: login, apps: [any]}\n", "apps"},
		{hdr + "audit:\n  args: none\n  level: debug\n", "level"},
		{hdr + "apps:\n  a: {signed: {team: T, id: x, path: /bin/x}}\n", "path"},
		{rulesHdr + "        - apps: [iterm]\n          gate: login\n          comment: hi\n", "comment"},
		// Spec 4.2: there is no name: matcher; it could be faked.
		{hdr + "apps:\n  a: {name: ssh}\n", "name"},
		{rulesHdr + "        - apps: [{name: ssh}]\n          gate: login\n", "name"},
	} {
		wantError(t, tc.src, fmt.Sprintf("unknown field %q", tc.field))
	}
}

// Spec 4.2: gate: none refuses
// Apple-signed matchers (with or without id) by matcher kind, not
// by spelling; login and dialog still accept them. any and unknown are
// accepted, with a warning: they say "every program" outright. A path:
// is accepted under none unless it names one of Apple's programs (on the
// system volume): /bin/zsh is in almost every chain.
func TestGateNoneAcceptsOnlyAppOrThirdPartySigned(t *testing.T) {
	const refused = "is refused under none"
	// noneHdr names one matcher of every kind that rules may use.
	noneHdr := hdr + `apps:
  iterm: {app: com.googlecode.iterm2}
  pinned: {app: com.todesktop.230313mzl4w4u92, team: Q6L2SF6YDW}
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  vendor: {signed: {team: Q6L2SF6YDW}}
  zsh: {path: /bin/zsh}
  applesigned: {signed: {team: apple}}
  applezsh: {signed: {team: apple, id: com.apple.zsh}}
ssh_agent:
  keys:
    k:
      rules:
`
	// The cases name one matcher or a list; a rule always holds a list.
	list := func(apps string) string {
		if strings.HasPrefix(apps, "[") {
			return apps
		}
		return "[" + apps + "]"
	}
	rule := func(apps, gate string) string {
		return noneHdr + "        - apps: " + list(apps) + "\n          gate: " + gate + "\n"
	}

	// Accepted under none: app: (pinned or not) and third-party signed: (with or without id).
	for _, apps := range []string{
		"iterm", "pinned", "claude", "vendor",
		"[iterm, claude]", "[pinned, vendor, iterm]",
		"{app: com.googlecode.iterm2}",
		"{app: com.googlecode.iterm2, team: H7V7XYVQ7D}",
		"{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}",
		"{signed: {team: Q6L2SF6YDW}}",
	} {
		mustParse(t, rule(apps, "none"))
	}

	// any and unknown are the user's explicit "every program, no prompt"
	// (the user's choice, not nazar's). They are accepted
	// under none with a warning that says exactly that.
	for _, apps := range []string{"any", "unknown", "[any]", "[iterm, any]", "[unknown, iterm]"} {
		_, probs := mustParse(t, rule(apps, "none"))
		if !strings.Contains(probs.Error(), "use this key without asking") {
			t.Errorf("apps %s gate none: want the every-program warning, got:\n%s", apps, probs.Error())
		}
	}
	// A rule naming apps gets no such warning.
	if _, probs := mustParse(t, rule("[iterm, claude]", "none")); strings.Contains(probs.Error(), "every program") {
		t.Errorf("app rules must not get the every-program warning:\n%s", probs.Error())
	}

	// A path: outside the system volume is accepted under none, with no
	// warning from Parse (config check warns when the user can write it).
	for _, apps := range []string{"{path: /opt/homebrew/opt/mytool/bin/mytool}", "{path: /usr/local/bin/mytool}", "[iterm, {path: /Users/u/bin/tool}]"} {
		c, probs := mustParse(t, rule(apps, "none"))
		if len(probs) != 0 {
			t.Errorf("apps %s gate none: want no problem, got:\n%s", apps, probs.Error())
		}
		if len(c.SSHAgent.Keys["k"].Rules) != 1 {
			t.Fatalf("apps %s: rule dropped", apps)
		}
	}

	// Refused under none, whatever the spelling. The attack that motivated the
	// decision: a system binary (/bin/zsh, /usr/bin/login) is in almost every
	// chain, so none there means "anything, no prompt".
	refusedApps := []string{
		// Apple-signed, with or without an id.
		"applesigned", "applezsh",
		"{signed: {team: apple}}",
		"{signed: {team: apple, id: \"\"}}",
		"{signed: {team: apple, id: com.apple.zsh}}",
		"{signed: {team: apple, id: com.apple.bash}}",
		"{signed: {team: apple, id: com.apple.login}}",
		"{signed: {team: apple, id: com.apple.openssh}}",
		"{signed: {team: apple, id: com.anthropic.claude-code}}",
		// A path: of Apple's programs, named or inline.
		"zsh", "{path: /bin/zsh}", "{path: /usr/bin/login}", "{path: /bin/sh}", "{path: /usr/bin/ssh}",
		"{path: /System/Library/x}", "{path: /sbin/launchd}", "{path: /usr/libexec/x}",
		// One bad matcher poisons the list, wherever it sits.
		"[iterm, applezsh]", "[applezsh, iterm]", "[claude, applesigned]", "[zsh, applesigned]", "[iterm, {path: /bin/zsh}]",
		"[iterm, {signed: {team: apple, id: com.apple.zsh}}]", "[pinned, claude, applezsh]",
	}
	for _, apps := range refusedApps {
		wantError(t, rule(apps, "none"), refused)
		// A to: restriction doesn't change who may ask.
		wantError(t, noneHdr+"        - apps: "+list(apps)+"\n          to: [{signed: {team: apple, id: com.apple.openssh}}]\n          gate: none\n", refused)
		// The same apps: are fine with a gate that puts a person in the loop, or with block.
		for _, gate := range []string{"login", "dialog", "block"} {
			c, probs := mustParse(t, rule(apps, gate))
			if len(c.SSHAgent.Keys["k"].Rules) != 1 {
				t.Fatalf("apps %s gate %s: rule dropped: %v", apps, gate, probs)
			}
		}
	}

	// The refusal names the offending matcher and the gates that still accept it.
	for apps, want := range map[string]string{
		"applesigned": "applesigned is refused",
		"applezsh":    "applezsh is refused",
		"{signed: {team: apple, id: com.apple.zsh}}": `signed:"apple":"com.apple.zsh" is refused`,
		"[iterm, applezsh]":                          "applezsh is refused",
		"zsh":                                        "zsh is refused",
		"{path: /bin/zsh}":                           `path:"/bin/zsh" is refused`,
	} {
		_, probs := Parse([]byte(rule(apps, "none")), env)
		text := probs.Error()
		if !strings.Contains(text, want) || !strings.Contains(text, "login and dialog still accept it") {
			t.Errorf("apps %s: refusal should name the matcher and the gates that accept it:\n%s", apps, text)
		}
	}
	// Every refused matcher in a list is reported, so one fix doesn't reveal the next.
	_, probs := Parse([]byte(rule("[applezsh, applesigned, iterm, {signed: {team: apple}}]", "none")), env)
	text := probs.Error()
	for _, want := range []string{"applezsh is refused", "applesigned is refused", `signed:"apple":"" is refused`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "iterm is refused") {
		t.Errorf("iterm (app:) must not be refused:\n%s", text)
	}

	// No warning about Apple-signed matchers under login/dialog: the
	// decision is enforced only under none, not nagged about elsewhere.
	for _, apps := range []string{"applesigned", "applezsh", "{signed: {team: apple}}"} {
		for _, gate := range []string{"login", "dialog"} {
			_, probs := mustParse(t, rule(apps, gate))
			for _, pr := range probs {
				if strings.Contains(pr.Message, "Apple") || strings.Contains(pr.Message, "apple") {
					t.Errorf("apps %s gate %s: unexpected Apple-specific problem: %v", apps, gate, pr)
				}
			}
		}
	}

	// Catch-alls can never be none: a key's own gate and defaults.fallback
	// apply to every caller.
	wantError(t, hdr+"apps:\n  iterm: {app: x}\nssh_agent:\n  keys:\n    k:\n      gate: none\n      rules:\n        - apps: [iterm]\n          gate: login\n", "can't be none")
	wantError(t, hdr+"defaults:\n  fallback:\n    gate: none\n", "every caller")

	// Accepted matchers under none.
	c, _ := mustParse(t, hdr+`apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    k:
      rules:
        - apps: [iterm, {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}]
          gate: none
`)
	if got := c.SSHAgent.Keys["k"].Rules[0].Policy; got != (Policy{Scope: ScopeUse, Gate: GateNone}) {
		t.Fatalf("gate none policy: %+v", got)
	}
}

// Spec 4.2: command: only in to:, and never for ssh keys; unknown describes
// callers, not receivers.
func TestCommandAndUnknownPlacement(t *testing.T) {
	wantError(t, rulesHdr+"        - apps: [iterm, mcp]\n          gate: login\n", "only allowed in to:")
	wantError(t, rulesHdr+"        - apps: [{command: [npx, x]}]\n          gate: login\n", "only allowed in to:")
	wantError(t, rulesHdr+"        - apps: [iterm]\n          to: [{command: [printenv]}]\n          gate: login\n", "not to ssh keys")
	wantError(t, rulesHdr+"        - apps: [iterm]\n          to: [unknown]\n          gate: login\n", "to")
}

func TestMatcherEdgeCases(t *testing.T) {
	h := hdr + "apps:\n"
	wantError(t, h+"  a: {signed: {team: \"\", id: x}}\n", "team is required")
	wantError(t, h+"  a: {signed: com.anthropic.claude-code}\n", "must be a mapping")
	wantError(t, h+"  a: {app: \"\"}\n", "apps.a")
	wantError(t, h+"  a: {command: npx}\n", "non-empty")
	wantError(t, h+"  a: {command: [npx, [x]]}\n", "apps.a")
	wantError(t, h+"  a: {}\n", "exactly one")
	wantError(t, h+"  a: {signed: {team: T}, app: x}\n", "exactly one")
	wantError(t, h+"  a: {path: /x, command: [x]}\n", "exactly one")
	wantError(t, h+"  unknown: {app: x}\n", "built in")
	for _, n := range []string{"-x", "a b", "a/b", "\"\"", "ıterm", "it:erm"} {
		wantError(t, h+"  "+n+": {app: x}\n", "app names")
	}
	wantError(t, h+"  a: {app: x}\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [A]\n          gate: login\n", `unknown app "A"`)

	c, _ := mustParse(t, h+"  kubectl: {path: /opt/homebrew/bin/kubectl}\n  claude: {signed: {team: Q6L2SF6YDW}}\n  iterm: {app: com.googlecode.iterm2, team: H7V7XYVQ7D}\n  mcp: {command: [npx, -y, \"@brave/brave-search-mcp-server\"]}\n")
	want := map[string]Matcher{
		"kubectl": {Kind: MatchPath, Name: "kubectl", Path: "/opt/homebrew/bin/kubectl"},
		"claude":  {Kind: MatchSigned, Name: "claude", Team: "Q6L2SF6YDW"},
		"iterm":   {Kind: MatchApp, Name: "iterm", ID: "com.googlecode.iterm2", Team: "H7V7XYVQ7D"},
	}
	for n, m := range want {
		if got := c.Apps[n]; got.Kind != m.Kind || got.Name != m.Name || got.Team != m.Team || got.ID != m.ID || got.Path != m.Path {
			t.Errorf("apps.%s = %+v, want %+v", n, got, m)
		}
	}
	if got := c.Apps["mcp"]; got.Kind != MatchCommand || strings.Join(got.Command, "|") != "npx|-y|@brave/brave-search-mcp-server" {
		t.Errorf("apps.mcp = %+v", got)
	}
}

// Key names become file names (keys/<name>.pub) and Keychain item names.
func TestKeyNameAttacks(t *testing.T) {
	for _, bad := range []string{".", "..", "-rf", "--help", "a\x00b", "a\nb", "a b", `a\b`, "~", "$HOME", "*", "gіthub" /* Cyrillic і */, "ｇithub" /* fullwidth */, "a:b", "/etc/passwd"} {
		if ValidKeyName(bad) {
			t.Errorf("ValidKeyName(%q) = true", bad)
		}
	}
	if !ValidKeyName(strings.Repeat("a", 64)) {
		t.Error("64-character key name refused")
	}
	for _, bad := range []string{"gіthub", "-rf", "..", "\"a b\"", "\"x/../../y\""} {
		wantError(t, hdr+"ssh_agent:\n  keys:\n    "+bad+":\n      gate: login\n", "key names")
	}
	// keys/<name>.pub lives on a case-insensitive file system, so two keys
	// that differ only in case would share one .pub (last export wins) while
	// carrying different policies.
	for _, pair := range [][2]string{{"Github", "github"}, {"github", "GITHUB"}, {"K1", "k1"}} {
		wantError(t, hdr+"ssh_agent:\n  keys:\n    "+pair[0]+": {gate: login}\n    "+pair[1]+": {gate: dialog}\n", "more than letter case")
	}
	c, _ := mustParse(t, hdr+"ssh_agent:\n  keys:\n    github: {gate: login}\n    github2: {gate: dialog}\n")
	if len(c.SSHAgent.Keys) != 2 {
		t.Fatalf("distinct names rejected: %v", c.KeyNames())
	}
}

func TestSocketPath(t *testing.T) {
	for in, want := range map[string]string{
		"~/.nazar/agent.sock": "/Users/u/.nazar/agent.sock",
		"/tmp/nz1/agent.sock": "/tmp/nz1/agent.sock",
	} {
		c, _ := mustParse(t, hdr+"ssh_agent:\n  socket: "+in+"\n")
		if c.SSHAgent.Socket != want {
			t.Errorf("socket %q → %q, want %q", in, c.SSHAgent.Socket, want)
		}
	}
	c, _ := mustParse(t, hdr+"ssh_agent:\n  socket: ~/a/../b/./agent.sock\n")
	if s := c.SSHAgent.Socket; !filepath.IsAbs(s) || filepath.Clean(s) != s || !strings.HasPrefix(s, "/Users/u/") {
		t.Errorf("socket not a clean absolute path under home: %q", s)
	}
	for _, bad := range []string{"agent.sock", "./agent.sock", "~other/agent.sock", "\"\""} {
		wantError(t, hdr+"ssh_agent:\n  socket: "+bad+"\n", "socket")
	}
}

func TestTimeoutBounds(t *testing.T) {
	for in, want := range map[string]time.Duration{"1s": time.Second, "10m": 10 * time.Minute, "90s": 90 * time.Second} {
		c, _ := mustParse(t, hdr+"defaults:\n  timeout: "+in+"\n")
		if c.Defaults.Timeout != want {
			t.Errorf("timeout %s → %v", in, c.Defaults.Timeout)
		}
	}
	for _, bad := range []string{"999ms", "10m1s", "1d", "-5s", "5", "soon"} {
		c, probs := Parse([]byte(hdr+"defaults:\n  timeout: "+bad+"\n"), env)
		if c != nil || !strings.Contains(probs.Error(), "timeout") {
			t.Errorf("timeout %q accepted or error lacks location: %v", bad, probs)
		}
	}
}

// Durations must never wrap around into something short or negative.
func TestParseDurationEdges(t *testing.T) {
	for in, want := range map[string]time.Duration{"1h30m": 90 * time.Minute, "1d": 24 * time.Hour, "365d": 365 * 24 * time.Hour} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"0", "0s", "0h0m", " ", "1.5d", "-1d", "+-1d", "1d1h", "1D", "１d", "NaNd", "1e3d",
		"106752d", "9223372036854775807d", "99999999999999h", "9223372036854775808ns"} {
		if got, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) = %v, want error", bad, got)
		}
	}
	wantError(t, rulesHdr+"        - apps: [iterm]\n          gate: login\n          scope: session\n          expire: 9223372036854775807d\n", "expire")
}

func TestPolicyBasics(t *testing.T) {
	for g, want := range map[Gate]bool{GateLogin: true, GateDialog: true, GateNone: false, GateBlock: false} {
		if g.Prompts() != want {
			t.Errorf("%s.Prompts() = %v", g, !want)
		}
	}
	if s := (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}).String(); s != "gate=login scope=session expire=8h0m0s" {
		t.Errorf("Policy.String() = %q", s)
	}
	// The fallback may prompt; scope and expire are kept for prompting gates.
	c, _ := mustParse(t, hdr+"defaults:\n  fallback: {gate: login, scope: session, expire: 1h}\n")
	if want := (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: time.Hour}); c.Fallback("anything") != want {
		t.Errorf("Fallback = %+v, want %+v", c.Fallback("anything"), want)
	}
	wantError(t, hdr+"defaults:\n  fallback: {}\n", "missing gate")
	// block takes no scope or expire, there as everywhere.
	wantError(t, hdr+"defaults:\n  fallback: {gate: block, scope: app}\n", "defaults.fallback.scope: does nothing with gate: block")
}

func TestMinimalConfigAndDefault(t *testing.T) {
	c, probs := mustParse(t, hdr)
	if len(probs) != 0 {
		t.Errorf("minimal config has problems: %v", probs)
	}
	for name, got := range map[string]*Config{"minimal": c, "Default": Default(env)} {
		if got.APIVersion != APIVersion || got.Kind != KindConfig {
			t.Errorf("%s: version %q kind %q", name, got.APIVersion, got.Kind)
		}
		if got.Defaults.Timeout != DefaultTimeout || got.Defaults.Fallback != (Policy{Scope: ScopeUse, Gate: GateBlock}) {
			t.Errorf("%s: defaults %+v", name, got.Defaults)
		}
		if got.Audit.Args != ArgsRedacted || len(got.Apps) != 0 || len(got.SSHAgent.Keys) != 0 || len(got.Unimplemented) != 0 {
			t.Errorf("%s: %+v", name, got)
		}
		if got.SSHAgent.Socket != "/Users/u/.nazar/run/agent.sock" || len(got.KeyNames()) != 0 {
			t.Errorf("%s: socket %q keys %v", name, got.SSHAgent.Socket, got.KeyNames())
		}
		// Spec 4.2: keys without a config entry get defaults.fallback.
		if got.Fallback("unconfigured") != got.Defaults.Fallback {
			t.Errorf("%s: unconfigured key fallback %+v", name, got.Fallback("unconfigured"))
		}
	}
	if d := Default(env); d.Raw != nil || d.Hash != "" {
		t.Errorf("Default carries Raw/Hash: %q %q", d.Raw, d.Hash)
	}
	c, _ = mustParse(t, hdr+"audit:\n  args: none\n")
	if c.Audit.Args != ArgsNone {
		t.Errorf("audit.args none → %q", c.Audit.Args)
	}
}

// The hash identifies the approved bytes (spec 4.8); Raw must be nazar's own
// copy so a caller reusing its buffer can't change what was approved.
func TestRawAndHash(t *testing.T) {
	data := []byte(specExample)
	c, _ := Parse(data, env)
	if c == nil {
		t.Fatal("spec example refused")
	}
	sum := sha256.Sum256([]byte(specExample))
	if c.Hash != hex.EncodeToString(sum[:]) {
		t.Fatalf("Hash %q is not the SHA-256 of the file", c.Hash)
	}
	if !bytes.Equal(c.Raw, []byte(specExample)) {
		t.Fatal("Raw differs from the file")
	}
	for i := range data {
		data[i] = 'X'
	}
	if !bytes.Equal(c.Raw, []byte(specExample)) {
		t.Fatal("Raw aliases the caller's buffer")
	}
	c2, _ := mustParse(t, specExample+"# a comment\n")
	if c2.Hash == c.Hash {
		t.Fatal("different bytes, same hash")
	}
}

func TestSizeLimitBoundary(t *testing.T) {
	src := hdr + strings.Repeat("#", MaxFileSize-len(hdr)-1) + "\n"
	if len(src) != MaxFileSize {
		t.Fatalf("test setup: len %d", len(src))
	}
	mustParse(t, src)
	wantError(t, src+"#", "larger than")
	wantError(t, src+"\n", "larger than")
}

// Spec 4.5: a key carries Secure Enclave user presence only if every gate
// that can apply (all rules plus the key's own gate or defaults.fallback) is
// login or block, and `config check` says so for each other key.
func TestNeedsUserPresence(t *testing.T) {
	c, probs := mustParse(t, hdr+`defaults:
  fallback: {gate: dialog}
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    rules-login-fallback-dialog:
      rules:
        - apps: [iterm]
          gate: login
    own-login:
      gate: login
      rules:
        - apps: [iterm]
          gate: block
    rule-none:
      gate: login
      rules:
        - apps: [iterm]
          gate: none
    login-session:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
    own-login-app:
      scope: app
      gate: login
    bare:
`)
	// Spec 4.5 as amended (S1): login counts only with scope: use.
	want := map[string]bool{"rules-login-fallback-dialog": false, "own-login": true, "rule-none": false,
		"login-session": false, "own-login-app": false, "bare": false, "unconfigured": false}
	for k, w := range want {
		if got := c.NeedsUserPresence(k); got != w {
			t.Errorf("NeedsUserPresence(%q) = %v, want %v (gates %v)", k, got, w, c.Gates(k))
		}
	}
	gs := c.Gates("own-login")
	if len(gs) != 2 || !containsGate(gs, GateLogin) || !containsGate(gs, GateBlock) {
		t.Errorf("Gates(own-login) = %v", gs)
	}
	if gs := c.Gates("rules-login-fallback-dialog"); !containsGate(gs, GateDialog) {
		t.Errorf("Gates must include defaults.fallback: %v", gs)
	}
	if b := c.SSHAgent.Keys["bare"]; b == nil || len(b.Rules) != 0 || b.Own != nil {
		t.Errorf("bare key %+v", b)
	}
	// A dialog or none gate is a choice, not a problem: Parse never warns
	// about it (NeedsUserPresence above is what the key's protection uses).
	if warned := presenceWarnings(probs); len(warned) != 0 {
		t.Errorf("user-presence warnings %v; want none", warned)
	}
	_, probs = mustParse(t, specExample)
	if warned := presenceWarnings(probs); len(warned) != 0 {
		t.Errorf("spec example presence warnings %v; want none", warned)
	}
}

// Spec 4.5 as amended (S1), edge cases: every policy that can reach a key
// counts with its scope, not only its gate. A single login rule with scope
// session or app, or a defaults.fallback of login with scope session that a
// key without an own gate falls back to, takes chip-level presence away even
// when every gate is login. block always fits (Parse normalises its scope to
// use), and a key's own gate shadows defaults.fallback. None of these keys
// can be reached by dialog or none, so none of them gets a config-check
// warning (spec 4.2).
func TestNeedsUserPresenceCountsScope(t *testing.T) {
	c, probs := mustParse(t, hdr+`defaults:
  fallback: {scope: session, gate: login}
apps:
  iterm: {app: com.googlecode.iterm2}
  claude: {app: com.anthropic.claudefordesktop}
ssh_agent:
  keys:
    own-use-rule-app:
      scope: use
      gate: login
      rules:
        - apps: [iterm]
          scope: app
          gate: login
          expire: 8h
    own-use-rules-mixed:
      gate: login
      rules:
        - apps: [claude]
          gate: login
        - apps: [iterm]
          scope: session
          gate: login
    rules-use-fallback-session:
      rules:
        - apps: [iterm]
          gate: login
    own-block-shadows-fallback:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
    block-only:
      gate: block
    all-use:
      scope: use
      gate: login
      rules:
        - apps: [iterm]
          scope: use
          gate: login
        - apps: [claude]
          gate: block
`)
	want := map[string]bool{
		"own-use-rule-app":           false,
		"own-use-rules-mixed":        false,
		"rules-use-fallback-session": false, // every gate is login, but the fallback's scope is session
		"own-block-shadows-fallback": true,
		// An entry only block reaches is a key nobody may use yet; its
		// protection is decided by the rules added later, so no presence.
		"block-only":   false,
		"all-use":      true,
		"unconfigured": false, // defaults.fallback: login, scope session
	}
	for k, w := range want {
		if got := c.NeedsUserPresence(k); got != w {
			t.Errorf("NeedsUserPresence(%q) = %v, want %v (gates %v)", k, got, w, c.Gates(k))
		}
	}
	// The trap the amendment closes: the gates alone say "all login".
	for _, g := range c.Gates("rules-use-fallback-session") {
		if g != GateLogin {
			t.Fatalf("test setup: rules-use-fallback-session gates %v must all be login", c.Gates("rules-use-fallback-session"))
		}
	}
	if warned := presenceWarnings(probs); len(warned) != 0 {
		t.Errorf("no key here can be reached by dialog or none, so no user-presence warning: %v", warned)
	}
}

func containsGate(gs []Gate, g Gate) bool {
	for _, x := range gs {
		if x == g {
			return true
		}
	}
	return false
}

// presenceWarnings maps key name → whether a user-presence warning names it.
func presenceWarnings(ps Problems) map[string]bool {
	out := map[string]bool{}
	for _, p := range ps {
		if p.Severity != SevWarning || !strings.Contains(p.Message, "user presence") {
			continue
		}
		name := strings.TrimPrefix(p.Path, "ssh_agent.keys.")
		if i := strings.IndexAny(name, ".["); i >= 0 {
			name = name[:i]
		}
		out[name] = true
	}
	return out
}

// A rule with a to: restriction doesn't cover later rules without one, so
// they are not reported as unreachable.
func TestShadowingRespectsTo(t *testing.T) {
	_, probs := mustParse(t, hdr+`apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    k:
      rules:
        - apps: [any]
          to: [{signed: {team: apple, id: com.apple.openssh}}]
          gate: dialog
        - apps: [iterm]
          gate: login
        - apps: [iterm]
          gate: dialog
`)
	text := probs.Error()
	if strings.Contains(text, "rules[2]") {
		t.Errorf("rule 2 wrongly reported as shadowed:\n%s", text)
	}
	if !strings.Contains(text, "rules[3]") || !strings.Contains(text, "can never match: rule 2") {
		t.Errorf("rule 3 is shadowed by rule 2 but not reported:\n%s", text)
	}
}

var ruleIDRE = regexp.MustCompile(`^[1-9][0-9]*:[0-9a-f]{8}$`)

// Approvals are per rule (spec 4.2) and keyed by Rule.ID, so any change in
// what a rule means, including the definition of a named app it uses or its
// position under first-match, must give it a new ID.
func TestRuleIDTracksMeaning(t *testing.T) {
	base, _ := mustParse(t, specExample)
	gh := base.SSHAgent.Keys["github"].Rules
	for _, r := range gh {
		if !ruleIDRE.MatchString(r.ID()) {
			t.Fatalf("rule ID %q does not look like idx:hash8", r.ID())
		}
	}
	if gh[0].ID() == gh[1].ID() {
		t.Fatal("two rules share an ID")
	}
	edits := map[string][2]string{
		"named app's team redefined": {"team: Q6L2SF6YDW", "team: AAAAAAAAAA"},
		"named app's id redefined":   {"id: com.anthropic.claude-code", "id: com.evil.claude-code"},
		"scope changed":              {"          scope: session\n          gate: dialog", "          scope: app\n          gate: dialog"},
		"to: added":                  {"        - apps: [claude]\n", "        - apps: [claude]\n          to: [{signed: {team: apple, id: com.apple.openssh}}]\n"},
	}
	for name, e := range edits {
		if !strings.Contains(specExample, e[0]) {
			t.Fatalf("%s: test setup, %q not in spec example", name, e[0])
		}
		c, _ := mustParse(t, strings.Replace(specExample, e[0], e[1], 1))
		if c.SSHAgent.Keys["github"].Rules[0].ID() == gh[0].ID() {
			t.Errorf("%s: rule 1 kept its ID", name)
		}
		if c.SSHAgent.Keys["github"].Rules[1].ID() != gh[1].ID() {
			t.Errorf("%s: untouched rule 2 changed its ID", name)
		}
	}
	c, _ := mustParse(t, strings.Replace(specExample, "expire: 8h", "expire: 9h", 1))
	if c.SSHAgent.Keys["github"].Rules[1].ID() == gh[1].ID() {
		t.Error("expire change kept rule 2's ID")
	}
	// Swapping the two rules changes which one wins first: no ID survives.
	swapped := strings.Replace(specExample,
		"        - apps: [claude]\n          scope: session\n          gate: dialog\n        - apps: [iterm, cursor]\n          scope: session\n          gate: login\n          expire: 8h\n",
		"        - apps: [iterm, cursor]\n          scope: session\n          gate: login\n          expire: 8h\n        - apps: [claude]\n          scope: session\n          gate: dialog\n", 1)
	if swapped == specExample {
		t.Fatal("test setup: swap did not apply")
	}
	c, _ = mustParse(t, swapped)
	for _, r := range c.SSHAgent.Keys["github"].Rules {
		if r.ID() == gh[0].ID() || r.ID() == gh[1].ID() {
			t.Errorf("moved rule kept an old ID %s", r.ID())
		}
	}
}

// Parse is called from the config watcher and from control handlers at the
// same time; it must not share mutable state.
func TestParseConcurrently(t *testing.T) {
	want, _ := mustParse(t, specExample)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src := specExample
			if i%2 == 1 {
				src = "apiVersion: nazar/v2\nkind: Config\n"
			}
			c, probs := Parse([]byte(src), env)
			switch {
			case i%2 == 1 && c != nil:
				errs <- "bad version accepted"
			case i%2 == 0 && (c == nil || c.Hash != want.Hash || c.SSHAgent.Keys["github"].Rules[0].ID() != want.SSHAgent.Keys["github"].Rules[0].ID()):
				errs <- fmt.Sprintf("inconsistent parse: %v", probs)
			}
			_ = Default(env)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// A file at the size cap full of distinct rules must parse in bounded time:
// Parse runs on every reload inside the daemon and on nazar config check.
// (Pairwise Canonical() comparisons took over a minute for this input.)
func TestManyRulesParseQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString(hdr + "apps:\n  iterm: {app: com.googlecode.iterm2}\nssh_agent:\n  keys:\n    k:\n      rules:\n")
	lines := []string{
		"        - {apps: [{app: p.%d}], gate: login}\n",
		"        - {apps: [any], to: [{signed: {team: R%d}}], gate: login}\n",
		"        - {apps: [iterm], to: [{signed: {team: T%d}}], gate: dialog}\n",
	}
	for i := 0; b.Len()+80 < MaxFileSize; i++ {
		fmt.Fprintf(&b, lines[i%len(lines)], i)
	}
	start := time.Now()
	c, probs := Parse([]byte(b.String()), env)
	if c == nil {
		t.Fatalf("refused: %s", probs.Error())
	}
	if n := len(c.SSHAgent.Keys["k"].Rules); n < 10000 {
		t.Fatalf("test setup: only %d rules", n)
	}
	if d := time.Since(start); d > 10*time.Second*raceSlowdown {
		t.Fatalf("Parse took %v for %d bytes", d, b.Len())
	}
	if strings.Contains(probs.Error(), "can never match") {
		t.Fatal("distinct rules reported as shadowed")
	}
}

// PresenceFits is the first half of NeedsUserPresence (every policy
// that can reach the key is block or login with scope use): what a
// user-presence key can serve. It holds for an all-block key, which
// NeedsUserPresence does not (nothing to protect yet), so a tightening to
// block is never refused or warned about.
func TestPresenceFits(t *testing.T) {
	c, _ := mustParse(t, hdr+`apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    blockonly:
      gate: block
    loginuse:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
    sess:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
    dialog:
      gate: block
      rules:
        - apps: [iterm]
          gate: dialog
`)
	for k, w := range map[string][2]bool{ // fits, needs
		"blockonly": {true, false}, "loginuse": {true, true}, "sess": {false, false}, "dialog": {false, false}, "unconfigured": {true, false},
	} {
		if got := c.PresenceFits(k); got != w[0] {
			t.Errorf("PresenceFits(%q) = %v, want %v", k, got, w[0])
		}
		if got := c.NeedsUserPresence(k); got != w[1] {
			t.Errorf("NeedsUserPresence(%q) = %v, want %v", k, got, w[1])
		}
	}
}
