package config

import "testing"

var (
	claude = Matcher{Kind: MatchSigned, Team: "Q6L2SF6YDW", ID: "com.anthropic.claude-code", Name: "claude"}
	iterm  = Matcher{Kind: MatchApp, ID: "com.googlecode.iterm2", Name: "iterm"}
	cursor = Matcher{Kind: MatchApp, ID: "com.todesktop.230313mzl4w4u92", Name: "cursor"}
	anyM   = Matcher{Kind: MatchAny, Name: "any"}
	unkM   = Matcher{Kind: MatchUnknown, Name: "unknown"}
	sshTo  = Matcher{Kind: MatchSigned, Team: "apple", ID: "com.apple.openssh"}
)

func rule(apps []Matcher, to []Matcher) Rule { return Rule{Apps: apps, To: to} }

func TestCovers(t *testing.T) {
	cases := []struct {
		name string
		a, b Rule
		want bool
	}{
		{"any covers anything", rule([]Matcher{anyM}, nil), rule([]Matcher{claude}, nil), true},
		{"any covers unknown", rule([]Matcher{anyM}, nil), rule([]Matcher{unkM}, nil), true},
		{"superset covers subset", rule([]Matcher{iterm, cursor}, nil), rule([]Matcher{iterm}, nil), true},
		{"subset does not cover superset", rule([]Matcher{iterm}, nil), rule([]Matcher{iterm, cursor}, nil), false},
		{"different matchers", rule([]Matcher{claude}, nil), rule([]Matcher{iterm}, nil), false},
		{"renamed matcher still covers", rule([]Matcher{{Kind: MatchApp, ID: "com.googlecode.iterm2", Name: "it2"}}, nil), rule([]Matcher{iterm}, nil), true},
		{"to-restricted does not cover unrestricted", rule([]Matcher{iterm}, []Matcher{sshTo}), rule([]Matcher{iterm}, nil), false},
		{"unrestricted covers to-restricted", rule([]Matcher{iterm}, nil), rule([]Matcher{iterm}, []Matcher{sshTo}), true},
		{"unknown does not cover known", rule([]Matcher{unkM}, nil), rule([]Matcher{iterm}, nil), false},
		{"empty apps never covered", rule([]Matcher{iterm}, nil), rule(nil, nil), false},
	}
	for _, c := range cases {
		if got := Covers(c.a, c.b); got != c.want {
			t.Errorf("%s: Covers = %v, want %v", c.name, got, c.want)
		}
	}
	if !CoversAll(rule([]Matcher{anyM}, nil)) || CoversAll(rule([]Matcher{anyM}, []Matcher{sshTo})) || CoversAll(rule([]Matcher{iterm}, nil)) {
		t.Fatal("CoversAll")
	}
}

// Edge and attack cases.
func TestCoversAttackCases(t *testing.T) {
	other := Matcher{Kind: MatchSigned, Team: "AAAAAAAAAA", ID: "com.anthropic.claude-code", Name: "claude"}
	toAny := Matcher{Kind: MatchAny, Name: "any"}
	gitTo := Matcher{Kind: MatchSigned, Team: "apple", ID: "com.apple.git"}
	cases := []struct {
		name string
		a, b Rule
		want bool
	}{
		// Same signing id and name, different team: a different publisher.
		{"same id other team", rule([]Matcher{claude}, nil), rule([]Matcher{other}, nil), false},
		{"pinned and unpinned app differ", rule([]Matcher{{Kind: MatchApp, ID: "com.googlecode.iterm2", Team: "H7V7XYVQ7D"}}, nil), rule([]Matcher{iterm}, nil), false},
		// Unknown chains are matched only by any/unknown (spec 4.2).
		{"known does not cover unknown", rule([]Matcher{iterm, claude}, nil), rule([]Matcher{unkM}, nil), false},
		{"unknown covers unknown", rule([]Matcher{unkM}, nil), rule([]Matcher{unkM}, nil), true},
		{"specific does not cover any", rule([]Matcher{iterm}, nil), rule([]Matcher{anyM}, nil), false},
		{"unknown does not cover any", rule([]Matcher{unkM}, nil), rule([]Matcher{anyM}, nil), false},
		{"same to covers", rule([]Matcher{iterm}, []Matcher{sshTo}), rule([]Matcher{iterm}, []Matcher{sshTo}), true},
		{"to subset does not cover to superset", rule([]Matcher{iterm}, []Matcher{sshTo}), rule([]Matcher{iterm}, []Matcher{sshTo, gitTo}), false},
		{"to any covers unrestricted", rule([]Matcher{iterm}, []Matcher{toAny}), rule([]Matcher{iterm}, nil), true},
		{"apps cover but to does not", rule([]Matcher{anyM}, []Matcher{gitTo}), rule([]Matcher{iterm}, []Matcher{sshTo}), false},
		{"command argv boundaries", rule([]Matcher{iterm}, []Matcher{{Kind: MatchCommand, Command: []string{"npx -y", "x"}}}), rule([]Matcher{iterm}, []Matcher{{Kind: MatchCommand, Command: []string{"npx", "-y x"}}}), false},
	}
	for _, c := range cases {
		if got := Covers(c.a, c.b); got != c.want {
			t.Errorf("%s: Covers = %v, want %v", c.name, got, c.want)
		}
	}
	if !CoversAll(rule([]Matcher{iterm, anyM}, nil)) || CoversAll(rule([]Matcher{unkM}, nil)) || CoversAll(rule(nil, nil)) {
		t.Fatal("CoversAll edge cases")
	}
}

// Canonical forms decide rule identity (approvals) and coverage (shadow
// warnings, tighten/loosen). Two different matchers or rules must never
// share one, however their fields are spelled.
// Fields joined with "/" and "," unescaped would collide here, so Canonical
// quotes each field.
func TestCanonicalIsUnambiguous(t *testing.T) {
	pairs := [][2]Matcher{
		{{Kind: MatchSigned, Team: "a/b", ID: "c"}, {Kind: MatchSigned, Team: "a", ID: "b/c"}},
		{{Kind: MatchApp, ID: "a/b", Team: "c"}, {Kind: MatchApp, ID: "a", Team: "b/c"}},
		{{Kind: MatchApp, ID: "x"}, {Kind: MatchApp, ID: "x", Team: "T"}},
		{{Kind: MatchSigned, Team: "T"}, {Kind: MatchSigned, Team: "T", ID: "x"}},
		{{Kind: MatchCommand, Command: []string{"a b"}}, {Kind: MatchCommand, Command: []string{"a", "b"}}},
		{{Kind: MatchCommand, Command: []string{"a", ""}}, {Kind: MatchCommand, Command: []string{"a"}}},
		{{Kind: MatchCommand, Command: []string{`a" "b`}}, {Kind: MatchCommand, Command: []string{"a", "b"}}},
		{{Kind: MatchPath, Path: "/x"}, {Kind: MatchPath, Path: "/x/"}},
	}
	for _, p := range pairs {
		if p[0].Canonical() == p[1].Canonical() {
			t.Errorf("%+v and %+v share Canonical %q", p[0], p[1], p[0].Canonical())
		}
		if Covers(rule([]Matcher{p[0]}, nil), rule([]Matcher{p[1]}, nil)) || Covers(rule([]Matcher{p[1]}, nil), rule([]Matcher{p[0]}, nil)) {
			t.Errorf("%+v and %+v cover each other", p[0], p[1])
		}
	}
	// Name never changes meaning; Label shows the name, or the meaning when inline.
	named := Matcher{Kind: MatchApp, ID: "com.googlecode.iterm2", Name: "iterm"}
	inline := Matcher{Kind: MatchApp, ID: "com.googlecode.iterm2"}
	if named.Canonical() != inline.Canonical() || named.Label() != "iterm" || inline.Label() != inline.Canonical() {
		t.Errorf("Canonical/Label: %q %q %q", named.Canonical(), named.Label(), inline.Label())
	}

	login := Policy{Scope: ScopeUse, Gate: GateLogin}
	two := Rule{Index: 1, Apps: []Matcher{{Kind: MatchPath, Path: "/a"}, {Kind: MatchPath, Path: "/b"}}, Policy: login}
	one := Rule{Index: 1, Apps: []Matcher{{Kind: MatchPath, Path: "/a,path:/b"}}, Policy: login}
	if two.Canonical() == one.Canonical() || two.ID() == one.ID() {
		t.Errorf("rules with different apps share Canonical %q / ID %s", two.Canonical(), two.ID())
	}
	split := Rule{Index: 1, Apps: []Matcher{{Kind: MatchPath, Path: "/a"}}, To: []Matcher{{Kind: MatchPath, Path: "/b"}}, Policy: login}
	moved := Rule{Index: 1, Apps: []Matcher{{Kind: MatchPath, Path: "/a] to=[path:/b"}}, Policy: login}
	if split.Canonical() == moved.Canonical() {
		t.Errorf("apps/to boundary is ambiguous: %q", split.Canonical())
	}
	// Order inside apps: does not change meaning; Index does change the ID.
	ab := Rule{Index: 2, Apps: []Matcher{iterm, cursor}, Policy: login}
	ba := Rule{Index: 2, Apps: []Matcher{cursor, iterm}, Policy: login}
	if ab.ID() != ba.ID() {
		t.Errorf("reordered apps list changed the ID: %s %s", ab.ID(), ba.ID())
	}
	ab3 := ab
	ab3.Index = 3
	if ab3.ID() == ab.ID() {
		t.Error("ID ignores the rule's position")
	}
}

// shadowedBy is what config check uses for "can never match" warnings; it
// must agree with Covers applied pairwise under first-match, for every mix
// of named, inline, any/unknown and to: matchers.
func TestShadowedByMatchesCovers(t *testing.T) {
	pool := []Matcher{claude, iterm, cursor, anyM, unkM, {Kind: MatchPath, Path: "/a"}, {Kind: MatchPath, Path: "/b"}}
	toPool := []Matcher{sshTo, {Kind: MatchSigned, Team: "apple", ID: "com.apple.git"}, {Kind: MatchAny, Name: "any"}, {Kind: MatchPath, Path: "/c"}}
	// A small deterministic generator (no shared state, no test flakiness).
	seed := uint32(2463534242)
	next := func(n int) int {
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5
		return int(seed % uint32(n))
	}
	pick := func(from []Matcher, max int) []Matcher {
		var out []Matcher
		for k := next(max + 1); k > 0; k-- {
			out = append(out, from[next(len(from))])
		}
		return out
	}
	for round := 0; round < 300; round++ {
		rules := make([]Rule, next(12)+1)
		for i := range rules {
			rules[i] = Rule{Index: i + 1, Apps: pick(pool, 3), To: pick(toPool, 2)}
		}
		got := shadowedBy(rules)
		for j := range rules {
			want := 0
			for i := 0; i < j; i++ {
				if Covers(rules[i], rules[j]) {
					want = rules[i].Index
					break
				}
			}
			if got[j] != want {
				t.Fatalf("round %d rule %d: shadowedBy=%d, pairwise Covers=%d\nrules=%+v", round, j+1, got[j], want, rules)
			}
		}
	}
}
