package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The `to:` fall-through footgun. A rule matches only if both apps:
// and to: match; a request whose receiver is not in to: falls through to
// later rules (spec 4.2). So
//
//	- apps: [claude], to: [ssh], gate: dialog
//	- apps: [iterm], gate: none
//
// gives every OTHER client Claude Code starts inside iTerm the silent none
// rule. The config stays valid (risky-but-valid configs are the user's
// choice); config check warns on the later rule, naming the earlier one.

const ftApps = `apiVersion: nazar/v1
kind: Config
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
  cursor:
    app: com.todesktop.230313mzl4w4u92
  ssh:
    signed: { team: apple, id: com.apple.openssh }
  git:
    signed: { team: apple, id: com.apple.git }
ssh_agent:
  keys:
    github:
      rules:
`

// ftConfig builds a config whose key github has the given rules, one rule
// per string, each written as "apps: X[; to: Y]; gate: Z" flow fields.
func ftConfig(rules ...string) string {
	var b strings.Builder
	b.WriteString(ftApps)
	for _, r := range rules {
		b.WriteString("        - { " + r + " }\n")
	}
	return b.String()
}

var shadowRE = regexp.MustCompile(`can never match`)

// ruleWarnings parses body (which must be valid) and returns, per 1-based
// rule index of key, the warnings reported at that rule's path other than
// the existing "can never match" shadowing warning.
func ruleWarnings(t *testing.T, body, key string) map[int][]Problem {
	t.Helper()
	c, probs := Parse([]byte(body), Env{Home: "/Users/u"})
	if probs.HasErrors() || c == nil {
		t.Fatalf("config must stay valid (warnings never refuse a config):\n%s\n%s", probs.Error(), body)
	}
	re := regexp.MustCompile(`^ssh_agent\.keys\.` + regexp.QuoteMeta(key) + `\.rules\[(\d+)\]`)
	out := map[int][]Problem{}
	for _, p := range probs {
		m := re.FindStringSubmatch(p.Path)
		if m == nil || shadowRE.MatchString(p.Message) {
			continue
		}
		if p.Severity != SevWarning {
			t.Fatalf("rule problem must be a warning: %v", p)
		}
		var j int
		fmt.Sscan(m[1], &j)
		out[j] = append(out[j], p)
	}
	return out
}

func warnedRules(w map[int][]Problem) []int {
	var out []int
	for j := range w {
		out = append(out, j)
	}
	sort.Ints(out)
	return out
}

func TestToFallThroughWarning(t *testing.T) {
	cases := []struct {
		name  string
		rules []string
		want  map[int]int // later rule → earlier to:-restricted rule it must name
	}{
		// The documented footgun and its gate variants: later gate weaker.
		{"dialog then none", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], gate: none"}, map[int]int{2: 1}},
		{"login then dialog", []string{"apps: [claude], to: [ssh], gate: login", "apps: [iterm], gate: dialog"}, map[int]int{2: 1}},
		{"login then none", []string{"apps: [claude], to: [ssh], gate: login", "apps: [iterm], gate: none"}, map[int]int{2: 1}},
		{"block then login", []string{"apps: [claude], to: [ssh], gate: block", "apps: [iterm], gate: login"}, map[int]int{2: 1}},
		{"to: list", []string{"apps: [claude], to: [ssh, git], gate: login", "apps: [iterm], gate: none"}, map[int]int{2: 1}},
		{"inline to:", []string{"apps: [claude], to: [{signed: {team: apple, id: com.apple.openssh}}], gate: dialog", "apps: [iterm], gate: none"}, map[int]int{2: 1}},
		{"several later weaker rules", []string{"apps: [claude], to: [ssh], gate: login", "apps: [iterm], gate: dialog", "apps: [cursor], gate: none"}, map[int]int{2: 1, 3: 1}},
		{"earlier apps: [any]", []string{"apps: [any], to: [ssh], gate: login", "apps: [iterm], gate: none"}, map[int]int{2: 1}},
		{"later apps: [any]", []string{"apps: [claude], to: [ssh], gate: login", "apps: [any], gate: dialog"}, map[int]int{2: 1}},
		// A later rule with its own to: is reached by a fall-through only
		// through a receiver the earlier to: does not list.
		{"later to: outside the earlier one", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], to: [git], gate: none"}, map[int]int{2: 1}},
		{"later to: partly outside", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], to: [ssh, git], gate: none"}, map[int]int{2: 1}},

		// No warning: the later gate is not weaker.
		{"equal gate", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], gate: dialog"}, nil},
		{"stronger gate", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], gate: login"}, nil},
		{"none then none", []string{"apps: [claude], to: [ssh], gate: none", "apps: [iterm], gate: none"}, nil},
		{"later block", []string{"apps: [claude], to: [ssh], gate: login", "apps: [iterm], gate: block"}, nil},
		// No warning: nothing falls through because of to:.
		{"no to: (plain first-match order)", []string{"apps: [claude], gate: login", "apps: [iterm], gate: none"}, nil},
		{"weaker rule comes first", []string{"apps: [iterm], gate: none", "apps: [claude], to: [ssh], gate: dialog"}, nil},
		// No warning: what falls through can never reach the later rule.
		{"later to: within the earlier one", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], to: [ssh], gate: none"}, nil},
		{"later to: same receiver written inline", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [iterm], to: [{signed: {team: apple, id: com.apple.openssh}}], gate: none"}, nil},
		{"unknown chains match no app:", []string{"apps: [unknown], to: [ssh], gate: login", "apps: [iterm], gate: none"}, nil},
		{"app: never matches unknown chains", []string{"apps: [iterm], to: [ssh], gate: login", "apps: [unknown], gate: dialog"}, nil},
		// A signed: or path: process can be in an unknown chain
		// (spec 4.2): such a rule and unknown overlap, both ways.
		{"unknown then a signed: tool", []string{"apps: [unknown], to: [ssh], gate: login", "apps: [claude], gate: none"}, map[int]int{2: 1}},
		{"a signed: tool then unknown", []string{"apps: [claude], to: [ssh], gate: login", "apps: [unknown], gate: dialog"}, map[int]int{2: 1}},
		{"a path: tool then unknown", []string{"apps: [{path: /opt/homebrew/bin/kubectl}], to: [ssh], gate: login", "apps: [unknown], gate: dialog"}, map[int]int{2: 1}},
		{"fall-through caught by a stronger rule in between", []string{"apps: [claude], to: [ssh], gate: dialog", "apps: [claude], gate: login", "apps: [iterm], gate: none"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := ftConfig(c.rules...)
			got := ruleWarnings(t, body, "github")
			var want []int
			for j := range c.want {
				want = append(want, j)
			}
			sort.Ints(want)
			if fmt.Sprint(warnedRules(got)) != fmt.Sprint(want) {
				t.Fatalf("warned rules %v, want %v\nwarnings: %v\n%s", warnedRules(got), want, got, body)
			}
			for j, i := range c.want {
				ok := false
				ruleI := regexp.MustCompile(fmt.Sprintf(`\brule %d\b`, i))
				for _, p := range got[j] {
					if strings.Contains(p.Message, "to:") && ruleI.MatchString(p.Message) {
						ok = true
					}
				}
				if !ok {
					t.Errorf("the warning on rule %d must name to: and the earlier rule %d: %v", j, i, got[j])
				}
			}
		})
	}
}

// A signed: or path: rule matches an unknown chain its program is in
// (spec 4.2). A config approved before that matching changed, with such a
// rule above an `apps: unknown` rule of a stronger gate, got looser without
// an edit: a background process that runs the program now takes the earlier
// rule. config check warns on the earlier rule, naming the unknown rule.
func TestProcessRuleAboveStrongerUnknownRuleWarns(t *testing.T) {
	cases := []struct {
		name  string
		rules []string
		want  map[int]int // earlier process rule → the unknown rule it must name
	}{
		{"signed none above unknown block", []string{"apps: [claude], gate: none", "apps: [unknown], gate: block"}, map[int]int{1: 2}},
		{"signed dialog above unknown login", []string{"apps: [claude], gate: dialog", "apps: [iterm], gate: login", "apps: [unknown], gate: login"}, map[int]int{1: 3}},
		{"path dialog above unknown login", []string{"apps: [{path: /opt/homebrew/bin/kubectl}], gate: dialog", "apps: [unknown], gate: login"}, map[int]int{1: 2}},
		{"names the nearest stronger unknown rule", []string{"apps: [claude], gate: none", "apps: [unknown], to: [git], gate: dialog", "apps: [unknown], gate: block"}, map[int]int{1: 2}},
		// No warning.
		{"unknown first", []string{"apps: [unknown], gate: block", "apps: [claude], gate: none"}, nil},
		{"unknown rule not stronger", []string{"apps: [claude], gate: login", "apps: [unknown], gate: dialog"}, nil},
		{"app: never takes unknown chains", []string{"apps: [iterm], gate: none", "apps: [unknown], gate: block"}, nil},
		{"an example config: no unknown rule", []string{"apps: [claude], gate: none", "apps: [iterm], gate: login", "apps: [cursor], gate: login", "apps: [any], gate: login"}, nil},
	}
	re := regexp.MustCompile(`unknown`)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := ftConfig(c.rules...)
			got := ruleWarnings(t, body, "github")
			var warned []int
			for j, ps := range got {
				for _, p := range ps {
					if re.MatchString(p.Message) && !strings.Contains(p.Message, "to: of rule") {
						warned = append(warned, j)
						if want, ok := c.want[j]; !ok || !regexp.MustCompile(fmt.Sprintf(`\brule %d\b`, want)).MatchString(p.Message) {
							t.Errorf("rule %d: %q, want it to name rule %d", j, p.Message, c.want[j])
						}
					}
				}
			}
			sort.Ints(warned)
			var want []int
			for j := range c.want {
				want = append(want, j)
			}
			sort.Ints(want)
			if fmt.Sprint(warned) != fmt.Sprint(want) {
				t.Fatalf("warned rules %v, want %v: %v", warned, want, got)
			}
		})
	}
}

// Rules of different keys never interact: each key has its own first-match list.
func TestToFallThroughIsPerKey(t *testing.T) {
	body := ftApps + `        - { apps: [claude], to: [ssh], gate: dialog }
    deploy:
      rules:
        - { apps: [iterm], gate: none }
`
	for _, key := range []string{"github", "deploy"} {
		if w := ruleWarnings(t, body, key); len(w) != 0 {
			t.Errorf("key %s: %v", key, w)
		}
	}
}

// The spec's own example (section 4.2) is a clean config: it gets no
// fall-through warning, and no rule warning of any new kind.
func TestSpecExampleHasNoFallThroughWarning(t *testing.T) {
	body := `apiVersion: nazar/v1
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
ssh_agent:
  socket: ~/.nazar/agent.sock
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
	for _, key := range []string{"github", "myrepo-deploy", "hydra"} {
		if w := ruleWarnings(t, body, key); len(w) != 0 {
			t.Errorf("key %s: unexpected rule warnings %v", key, w)
		}
	}
}

// Spec 4.2: no warnings about terminal apps with gate none
// or scope app. Such rules get nothing beyond what they got before the
// fall-through warning.
func TestNoWarningForTerminalAppRules(t *testing.T) {
	appScope := `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    work:
      gate: block
      rules:
        - apps: [iterm]
          scope: app
          gate: login
          expire: 8h
`
	if _, probs := Parse([]byte(appScope), Env{Home: "/Users/u"}); len(probs) != 0 {
		t.Errorf("an iTerm scope: app login rule needs no warning:\n%s", probs.Error())
	}
	none := `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    deploy:
      rules:
        - apps: [iterm]
          gate: none
`
	_, probs := Parse([]byte(none), Env{Home: "/Users/u"})
	if probs.HasErrors() {
		t.Fatal(probs.Error())
	}
	if len(probs) != 0 {
		t.Errorf("an iTerm gate: none rule gets no warning:\n%s", probs.Error())
	}
}

// Regression (from a review): key() drops rules that fail to parse, so a rule's
// YAML Index and its position in key.Rules differ as soon as an earlier
// rule is invalid. The fall-through check must index by position: with
// one dropped rule it named the wrong rule's gate, with two it panicked
// (index out of range), crashing `nazar config check` and the daemon's
// reload, which never recover from Parse. The warning must keep naming the
// earlier rule by its YAML index, with its real gate.
func TestToFallThroughWarningAfterDroppedInvalidRules(t *testing.T) {
	cases := []struct {
		name    string
		dropped int
	}{
		{"one invalid rule before", 1},
		{"two invalid rules before", 2},
		{"three invalid rules before", 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var rules []string
			for i := 0; i < c.dropped; i++ {
				// An undefined app name: the rule errors and is left out of key.Rules.
				rules = append(rules, fmt.Sprintf("apps: [nosuchapp%d], gate: none", i))
			}
			rules = append(rules,
				"apps: [claude], to: [ssh], gate: login",
				"apps: [iterm], gate: dialog",
			)
			body := ftConfig(rules...)
			restricted, weaker := c.dropped+1, c.dropped+2

			var probs Problems
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Parse panicked on a config with %d invalid earlier rules: %v", c.dropped, r)
					}
				}()
				_, probs = Parse([]byte(body), Env{Home: "/Users/u"})
			}()
			if !probs.HasErrors() {
				t.Fatalf("the undefined apps must make the config invalid:\n%s", body)
			}
			path := fmt.Sprintf("ssh_agent.keys.github.rules[%d]", weaker)
			var warning *Problem
			for i := range probs {
				if probs[i].Path == path && probs[i].Severity == SevWarning && strings.Contains(probs[i].Message, "to:") {
					warning = &probs[i]
				}
			}
			if warning == nil {
				t.Fatalf("no fall-through warning at %s:\n%s", path, probs.Error())
			}
			want := fmt.Sprintf("weaker than rule %d's gate login", restricted)
			if !strings.Contains(warning.Message, want) {
				t.Errorf("the warning must name rule %d and its real gate (login), got: %s", restricted, warning.Message)
			}
			if !regexp.MustCompile(fmt.Sprintf(`to: of rule %d only restricts`, restricted)).MatchString(warning.Message) {
				t.Errorf("the warning must name the earlier rule by its YAML index %d, got: %s", restricted, warning.Message)
			}
			for i := 0; i < c.dropped; i++ {
				if strings.Contains(warning.Message, fmt.Sprintf("rule %d'", i+1)) {
					t.Errorf("the warning names a dropped rule %d: %s", i+1, warning.Message)
				}
			}
		})
	}
}
