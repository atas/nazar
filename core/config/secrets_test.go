package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// The secrets section (secrets design 4): deliver, and rules, scope,
// gate and expire exactly as for ssh keys, with three stricter checks for a
// secret, whose value leaves nazar.

const secretsHdr = hdr + `apps:
  iterm: {app: com.googlecode.iterm2}
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  git-https: {signed: {team: apple, id: com.apple.git-remote-http}}
secrets:
`

func TestSecretsSectionParses(t *testing.T) {
	c, probs := mustParse(t, secretsHdr+`  GH_TOKEN:
    deliver: [helper]
    rules:
      - apps: [iterm]
        to: [git-https]
        scope: session
        gate: login
        expire: 8h
      - apps: [claude]
        to: [git-https]
        gate: block
  BRAVE_API_KEY:
    scope: use
    gate: login
  k8s/hydra:
`)
	if len(probs) != 0 {
		t.Fatalf("want no problems, got:\n%s", probs.Error())
	}
	if slices.Contains(c.Unimplemented, "secrets") {
		t.Fatal("the secrets section is implemented now")
	}
	gh := c.Secrets["GH_TOKEN"]
	if gh == nil || gh.Name != "GH_TOKEN" || !slices.Equal(gh.Deliver, []Delivery{DeliverHelper}) || len(gh.Rules) != 2 || gh.Own != nil {
		t.Fatalf("GH_TOKEN = %+v", gh)
	}
	r := gh.Rules[0]
	if r.Index != 1 || r.Apps[0].Name != "iterm" || r.To[0].Kind != MatchSigned || r.To[0].ID != "com.apple.git-remote-http" ||
		r.Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) {
		t.Fatalf("rule 1 = %+v", r)
	}
	brave := c.Secrets["BRAVE_API_KEY"]
	if brave == nil || brave.Own == nil || *brave.Own != (Policy{Scope: ScopeUse, Gate: GateLogin}) || len(brave.Rules) != 0 {
		t.Fatalf("BRAVE_API_KEY = %+v", brave)
	}
	if !slices.Equal(brave.Deliver, []Delivery{DeliverHelper, DeliverStdout}) {
		t.Fatalf("an entry without deliver: gets the default, got %v", brave.Deliver)
	}
	if hydra := c.Secrets["k8s/hydra"]; hydra == nil || hydra.Own != nil || len(hydra.Rules) != 0 || !slices.Equal(hydra.Deliver, DefaultDeliver()) {
		t.Fatalf("a bare entry has no rules, no own policy and the default deliver: %+v", hydra)
	}
	if got := strings.Join(c.SecretNames(), ","); got != "BRAVE_API_KEY,GH_TOKEN,k8s/hydra" {
		t.Fatalf("SecretNames = %s", got)
	}
	if c.SecretFallback("BRAVE_API_KEY") != *brave.Own || c.SecretFallback("GH_TOKEN") != c.Defaults.Fallback ||
		c.SecretFallback("NOT_CONFIGURED") != c.Defaults.Fallback {
		t.Fatal("SecretFallback: the entry's own policy, else defaults.fallback")
	}
	if !slices.Equal(c.Deliver("GH_TOKEN"), []Delivery{DeliverHelper}) || !slices.Equal(c.Deliver("NOT_CONFIGURED"), DefaultDeliver()) {
		t.Fatal("Deliver: the entry's list, else the default")
	}
}

// The default never grows: a method a later version builds must be listed
// to be used, so an approved entry never comes to mean more by itself.
func TestDefaultDeliverIsHelperAndStdout(t *testing.T) {
	d := DefaultDeliver()
	if !slices.Equal(d, []Delivery{DeliverHelper, DeliverStdout}) {
		t.Fatalf("DefaultDeliver = %v", d)
	}
	d[0] = DeliverEnv
	if DefaultDeliver()[0] != DeliverHelper {
		t.Fatal("DefaultDeliver must return a fresh slice")
	}
	for _, m := range []Delivery{DeliverHelper, DeliverStdout, DeliverLateEnv} { // late-env since M10
		if !m.Built() {
			t.Errorf("%s must be built", m)
		}
	}
	for _, m := range []Delivery{DeliverFile, DeliverEnv, "", "Helper", "stdout ", "Late-Env"} {
		if m.Built() {
			t.Errorf("%q must not be built in this version", m)
		}
	}
}

// What this version does not build is refused by name, never ignored, so
// nothing is approved now to work after an upgrade.
func TestDeliverValidation(t *testing.T) {
	// late-env is built since M10 (lateenv_test.go).
	for _, m := range []string{"file", "env"} {
		wantError(t, secretsHdr+"  X:\n    deliver: [helper, "+m+"]\n", m+" is not in this version")
	}
	wantError(t, secretsHdr+"  X:\n    deliver: [helper, helper]\n", "listed twice")
	wantError(t, secretsHdr+"  X:\n    deliver: []\n", "non-empty list")
	wantError(t, secretsHdr+"  X:\n    deliver: helper\n", "non-empty list")
	wantError(t, secretsHdr+"  X:\n    deliver: [Helper]\n", `unknown delivery "Helper"`)
	wantError(t, secretsHdr+"  X:\n    deliver: [~]\n", "secrets.X.deliver")
	// helper: is built since M8 (TestHelperGitValidation refuses its
	// unbuilt kinds by name), envAllow: since M10 (TestEnvAllow); file:
	// is still later.
	for _, f := range []string{"file: ~/.nazar/run/files/X"} {
		name := strings.SplitN(f, ":", 2)[0]
		wantError(t, secretsHdr+"  X:\n    "+f+"\n", "the "+name+": field is not in this version")
	}
	wantError(t, secretsHdr+"  X:\n    deliver: [helper]\n    color: red\n", `unknown field "color"`)
	wantError(t, secretsHdr+"  X: [helper]\n", "must be a mapping")
}

func TestSecretNamesInConfig(t *testing.T) {
	for _, bad := range []string{`".."`, `"a b"`, `"/x"`, `"x/"`, `"gіthub"`, `"a:b"`, `"-x"`} {
		wantError(t, secretsHdr+"  "+bad+": {}\n", "secret names")
	}
	wantError(t, secretsHdr+"  GH_TOKEN: {}\n  gh_token: {}\n", "differ in more than letter case")
}

func TestSecretRuleChecks(t *testing.T) {
	// The checks of ssh keys apply unchanged.
	wantError(t, secretsHdr+"  X:\n    deliver: [helper]\n    rules:\n      - apps: [{signed: {team: apple, id: com.apple.zsh}}]\n        to: [git-https]\n        gate: none\n", "is refused under none")
	wantError(t, secretsHdr+"  X:\n    gate: none\n", "own gate applies to every caller")
	wantError(t, secretsHdr+"  X:\n    scope: session\n", "scope/expire without gate")
	wantError(t, secretsHdr+"  X:\n    rules:\n      - apps: [iterm]\n        to: [unknown]\n        gate: login\n", "unknown describes callers")
	wantError(t, secretsHdr+"  X:\n    rules:\n      - apps: [iterm]\n        to: [{command: [npx, x]}]\n        gate: login\n", "command: receivers are for nazar run; add late-env to deliver")
	// Stricter than for ssh keys: a value leaves nazar, so "every program,
	// silently" is refused, not warned about...
	for _, m := range []string{"any", "unknown"} {
		wantError(t, secretsHdr+"  X:\n    deliver: [helper]\n    rules:\n      - apps: ["+m+"]\n        to: [git-https]\n        gate: none\n", "rule 1 would give this secret to")
	}
	// ...also with stdout as a method, whether deliver: lists it or the
	// default does...
	for _, m := range []string{"any", "unknown"} {
		wantError(t, secretsHdr+"  X:\n    rules:\n      - apps: ["+m+"]\n        gate: none\n", "rule 1 would give this secret")
		wantError(t, secretsHdr+"  X:\n    deliver: [stdout]\n    rules:\n      - apps: ["+m+"]\n        gate: none\n", "rule 1 would give this secret")
	}
	// ...while a rule naming an app may be silent for any child of it, with
	// stdout and with no to:.
	for _, deliver := range []string{"", "    deliver: [stdout]\n"} {
		c, probs := mustParse(t, secretsHdr+"  X:\n"+deliver+"    rules:\n      - apps: [iterm]\n        gate: none\n")
		if probs.HasErrors() || c.Secrets["X"].Rules[0].Policy.Gate != GateNone {
			t.Fatalf("a silent stdout rule for an app: matcher is valid (deliver %q): %v", deliver, probs)
		}
	}
	// helper alone may be silent for an app: matcher.
	c, probs := mustParse(t, secretsHdr+"  X:\n    deliver: [helper]\n    rules:\n      - apps: [iterm]\n        to: [git-https]\n        gate: none\n")
	if len(probs) != 0 || c.Secrets["X"].Rules[0].Policy.Gate != GateNone {
		t.Fatalf("a silent helper rule for an app: matcher is valid: %v", probs)
	}
}

// The rule-order warnings of ssh keys run per secret, and a rule without
// to: is a warning (secrets design 4).
func TestSecretRuleWarnings(t *testing.T) {
	_, probs := mustParse(t, secretsHdr+`  X:
    rules:
      - apps: [iterm]
        gate: login
      - apps: [iterm]
        to: [git-https]
        gate: dialog
      - apps: [claude]
        to: [git-https]
        gate: login
      - apps: [claude]
        to: [{signed: {team: apple}}]
        gate: dialog
`)
	text := probs.Error()
	for _, want := range []string{
		"secrets.X.rules[1].to: no to:",
		"secrets.X.rules[2]: can never match: rule 1",
		"secrets.X.rules[4]: to: of rule 3 only restricts its receivers",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("warnings missing %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, "no to:"); n != 1 {
		t.Errorf("only rule 1 lacks to:, got %d warnings:\n%s", n, text)
	}
}

// Review: a gate: block rule hands the value to nobody, so it never
// draws the "no to:" warning.
func TestBlockRuleWithoutToDoesNotWarn(t *testing.T) {
	_, probs := mustParse(t, secretsHdr+"  X:\n    rules:\n      - apps: [claude]\n        gate: block\n      - apps: [iterm]\n        to: [git-https]\n        gate: login\n")
	if strings.Contains(probs.Error(), "no to:") {
		t.Fatalf("a block rule needs no to::\n%s", probs.Error())
	}
}
