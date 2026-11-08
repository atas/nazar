package config

import (
	"strings"
	"testing"
	"time"
)

// One shape and one meaning per key: to: [any] (the same as no to:), a
// team spelled Apple (which matches nothing, where apple is Apple's), and
// scope or expire where they do nothing are config errors, each saying
// what to do.
func TestStrictRuleForms(t *testing.T) {
	head := hdr + "apps:\n  iterm: {app: com.googlecode.iterm2}\n"
	key := func(rule string) string { return head + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - " + rule }
	for _, tc := range []struct{ name, src, want string }{
		{"key to any", key("apps: [iterm]\n          to: [any]\n          gate: login\n"),
			"ssh_agent.keys.k.rules[1].to: any in to: is the same as no to:; leave to: out"},
		{"to any among others", key("apps: [iterm]\n          to: [iterm, any]\n          gate: login\n"),
			"rules[1].to: any in to: is the same as no to:; leave to: out"},
		{"secret to any", head + "secrets:\n  T:\n    rules:\n      - apps: [iterm]\n        to: [any]\n        gate: dialog\n",
			"secrets.T.rules[1].to: any in to: is the same as no to:; leave to: out"},
		{"signed Apple", key("apps: [{signed: {team: Apple, id: com.apple.ssh}}]\n          gate: login\n"),
			`rules[1].apps.signed.team: "Apple" matches nothing; Apple's team is written apple`},
		{"signed APPLE in to", key("apps: [iterm]\n          to: [{signed: {team: APPLE}}]\n          gate: login\n"),
			`rules[1].to.signed.team: "APPLE" matches nothing; Apple's team is written apple`},
		{"app team Apple", key("apps: [{app: com.x, team: Apple}]\n          gate: login\n"),
			`rules[1].apps.team: "Apple" matches nothing; Apple's team is written apple`},
		{"named app Apple", hdr + "apps:\n  ssh: {signed: {team: aPPle, id: com.apple.openssh}}\n",
			`apps.ssh.signed.team: "aPPle" matches nothing; Apple's team is written apple`},
		{"scope with block", key("apps: [iterm]\n          scope: session\n          gate: block\n"),
			"rules[1].scope: does nothing with gate: block; remove it"},
		{"expire with none", key("apps: [iterm]\n          gate: none\n          expire: 1h\n"),
			"rules[1].expire: does nothing with gate: none; remove it"},
		{"scope use with none", key("apps: [iterm]\n          scope: use\n          gate: none\n"),
			"rules[1].scope: does nothing with gate: none; remove it"},
		{"expire with scope use", key("apps: [iterm]\n          scope: use\n          gate: dialog\n          expire: 1h\n"),
			"rules[1].expire: does nothing with scope: use (nothing is remembered); remove it"},
		{"expire without scope", key("apps: [iterm]\n          gate: login\n          expire: 1h\n"),
			"rules[1].expire: does nothing with scope: use (nothing is remembered); remove it"},
		{"key's own gate block", head + "ssh_agent:\n  keys:\n    k:\n      scope: app\n      gate: block\n",
			"ssh_agent.keys.k.scope: does nothing with gate: block; remove it"},
		{"fallback", hdr + "defaults:\n  fallback: {gate: block, expire: 8h}\n",
			"defaults.fallback.expire: does nothing with gate: block; remove it"},
	} {
		t.Run(tc.name, func(t *testing.T) { wantError(t, tc.src, tc.want) })
	}
	// What stays: lower-case apple, scope and expire where they apply, a
	// team ID, no to:.
	mustParse(t, key("apps: [{signed: {team: apple, id: com.apple.ssh}}, {app: com.x, team: Q6L2SF6YDW}]\n          scope: session\n          gate: dialog\n          expire: 1h\n"))
	mustParse(t, key("apps: [iterm]\n          scope: use\n          gate: login\n"))
}

// strictForms has every old form Migrate turns into today's: a single
// matcher, to: [any] where it changes nothing (a secret's rule, a key's
// rule that remembers nothing), scope and expire that did nothing. With
// comments.
const strictForms = hdr + `# mine
apps:
  iterm: {app: com.googlecode.iterm2}
defaults:
  fallback: {scope: session, gate: block}
ssh_agent:
  keys:
    github:
      rules:
        - apps: iterm # my terminal
          to: [any]
          gate: none
          expire: 8h
        - apps: [iterm]
          to: [any]
          scope: use
          gate: dialog
          expire: 1h
        - apps: [any]
          gate: login
          expire: 2h
      scope: app
      gate: block
secrets:
  T:
    deliver: [helper]
    helper: {git: {host: github.com}}
    rules:
      - apps: [iterm]
        to: [iterm, any]
        scope: session
        gate: dialog
        expire: 1h
`

// Migrate drops what meant nothing: the rewrite parses strictly to exactly
// what the old file meant (read the old way, which reads a dropped to: as
// no to:: the same matching, the same approvals), keeps the comments, is
// deterministic and leaves nothing to do.
func TestMigrateDropsWhatMeantNothing(t *testing.T) {
	if _, probs := Parse([]byte(strictForms), env); !probs.HasErrors() {
		t.Fatal("the fixture parses strictly: this test would prove nothing")
	}
	out, ok := Migrate([]byte(strictForms), env)
	if !ok {
		t.Fatal("not migrated")
	}
	nw, probs := Parse(out, env)
	if probs.HasErrors() {
		t.Fatalf("the rewrite does not parse:\n%s\n%s", out, probs.Error())
	}
	for _, gone := range []string{"to: [any]", "any]", "expire: 8h", "expire: 2h", "scope: app", "scope: session, gate: block"} {
		if strings.Contains(string(out), gone) {
			t.Errorf("%q is still there:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"# mine", "# my terminal", "scope: session\n        gate: dialog"} {
		if !strings.Contains(string(out), kept) {
			t.Errorf("%q lost:\n%s", kept, out)
		}
	}
	old := legacyParse(t, strictForms)
	if !sameMeaning(old, nw) {
		t.Fatalf("the rewrite means something else:\nold %+v\nnew %+v", old, nw)
	}
	g := nw.SSHAgent.Keys["github"]
	if len(g.Rules) != 3 || g.Rules[0].To != nil || g.Rules[1].To != nil || g.Rules[2].Policy != (Policy{Scope: ScopeUse, Gate: GateLogin}) ||
		*g.Own != (Policy{Scope: ScopeUse, Gate: GateBlock}) || nw.Defaults.Fallback != (Policy{Scope: ScopeUse, Gate: GateBlock}) {
		t.Fatalf("github: %+v own %+v fallback %+v", g.Rules, g.Own, nw.Defaults.Fallback)
	}
	if r := nw.Secrets["T"].Rules[0]; r.To != nil || r.Policy != (Policy{Scope: ScopeSession, Gate: GateDialog, Expire: time.Hour}) {
		t.Fatalf("secret: %+v", r)
	}
	again, _ := Migrate([]byte(strictForms), env)
	if string(again) != string(out) {
		t.Fatal("two rewrites of the same bytes differ")
	}
	if _, ok := Migrate(out, env); ok {
		t.Fatal("the rewrite is rewritten again")
	}
}

// What has no rewrite of the same meaning is left as it is: a team spelled
// Apple matches nothing, and apple would match Apple's programs; to: [any]
// on a key's rule that remembers approvals ties each approval to the
// program that receives it, and no to: does not. Migrate leaves such a file
// alone; ParseApproved, the reader of the approved config in the vault,
// reads it as builds before did (with a warning), so the approved config
// keeps working while config.yaml shows the error.
func TestMigrateLeavesWhatItCannotRewrite(t *testing.T) {
	for name, rule := range map[string]string{
		"team Apple":           "        - apps: [{signed: {team: Apple, id: com.apple.ssh}}]\n          gate: dialog\n",
		"app team Apple":       "        - apps: [{app: com.x, team: APPLE}]\n          gate: dialog\n",
		"to any, remembered":   "        - apps: [any]\n          to: [any]\n          scope: session\n          gate: dialog\n",
		"to any, app scope":    "        - apps: [any]\n          to: [any]\n          scope: app\n          gate: login\n          expire: 1h\n",
		"named app team Apple": "        - apps: [old]\n          gate: dialog\n",
	} {
		t.Run(name, func(t *testing.T) {
			src := hdr + "apps:\n  old: {signed: {team: Apple}}\nssh_agent:\n  keys:\n    k:\n      rules:\n" + rule
			if _, probs := Parse([]byte(src), env); !probs.HasErrors() {
				t.Fatal("parses strictly")
			}
			if out, ok := Migrate([]byte(src), env); ok || out != nil {
				t.Fatalf("migrated to\n%s", out)
			}
			c, probs := ParseApproved([]byte(src), env)
			if probs.HasErrors() || c == nil || len(probs) == 0 {
				t.Fatalf("ParseApproved: %v\n%s", c, probs.Error())
			}
			if c.Hash == "" || string(c.Raw) != src {
				t.Fatal("Raw and Hash are the item's")
			}
			r := c.SSHAgent.Keys["k"].Rules[0]
			if strings.Contains(name, "to any") && (len(r.To) != 1 || r.To[0].Kind != MatchAny) {
				t.Fatalf("to: [any] must keep its meaning: %+v", r.To)
			}
			if strings.Contains(name, "Apple") && r.Apps[0].Team == "apple" {
				t.Fatalf("a team that matched nothing now matches Apple's programs: %+v", r.Apps)
			}
		})
	}
	// With other old forms too: those are rewritten, the rest kept.
	src := hdr + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: {signed: {team: Apple}}\n          gate: block\n          scope: app\n"
	out, ok := Migrate([]byte(src), env)
	if !ok || !strings.Contains(string(out), "team: Apple") || strings.Contains(string(out), "scope") {
		t.Fatalf("%v\n%s", ok, out)
	}
	if _, probs := Parse(out, env); !strings.Contains(probs.Error(), `"Apple" matches nothing`) {
		t.Fatalf("the rewrite must still say what is left:\n%s", probs.Error())
	}
	if c, probs := ParseApproved(out, env); c == nil || probs.HasErrors() {
		t.Fatal(probs.Error())
	}
	// ParseApproved refuses what no build accepted, and a gate: none
	// matcher spelled Apple (the check folds case).
	for _, bad := range []string{
		hdr + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [any]\n          gate: maybe\n",
		hdr + "ssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [{signed: {team: Apple}}]\n          gate: none\n",
	} {
		if c, probs := ParseApproved([]byte(bad), env); c != nil || !probs.HasErrors() {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

// The writers never write what Parse refuses: expire next to scope use
// (or no scope), any in to:.
func TestWritersWriteNoFormParseRefuses(t *testing.T) {
	base := []byte(hdr + "apps:\n  iterm: {app: com.googlecode.iterm2}\nssh_agent:\n  keys:\n    k:\n      rules:\n        - apps: [iterm]\n          scope: session\n          gate: dialog\n          expire: 8h\n")
	out, err := SetRule(base, KeyEntry("k"), 1, RulePatch{Scope: ptr(ScopeUse)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "expire") {
		t.Fatalf("expire kept with scope: use:\n%s", out)
	}
	mustParse(t, string(out))
	out, err = AddRule(base, KeyEntry("k"), RuleSpec{Apps: []string{"iterm"}, Gate: GateLogin, Expire: time.Hour}, 0)
	if err != nil {
		t.Fatal(err)
	}
	mustParse(t, string(out))
	if _, err := AddRule(base, KeyEntry("k"), RuleSpec{Apps: []string{"iterm"}, To: []string{"any"}, Gate: GateLogin}, 0); err == nil ||
		!strings.Contains(err.Error(), "any in to: is the same as no to:; leave to: out") {
		t.Fatalf("add --to any: %v", err)
	}
	if _, err := SetRule(base, KeyEntry("k"), 1, RulePatch{To: &[]string{"iterm", "any"}}); err == nil {
		t.Fatal("set --to any accepted")
	}
}
