package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// parsed parses an edit's output and fails on errors.
func parsed(t *testing.T, out []byte) *Config {
	t.Helper()
	c, probs := Parse(out, env)
	if probs.HasErrors() {
		t.Fatalf("edited file does not parse: %s\n%s", probs.Error(), out)
	}
	return c
}

func ptr[T any](v T) *T { return &v }

func TestAddRuleAppendsAndInserts(t *testing.T) {
	out, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{"zed"}, Scope: ScopeUse, Gate: GateLogin}, 0)
	if err != nil {
		t.Fatal(err)
	}
	rules := parsed(t, out).SSHAgent.Keys["github"].Rules
	if len(rules) != 3 || rules[2].Apps[0].Name != "zed" || rules[2].Policy.Gate != GateLogin {
		t.Fatalf("appended: %+v", rules)
	}
	out, err = AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{"ghostty", "zed"}, To: []string{"signed:apple"}, Scope: ScopeSession, Gate: GateDialog, Expire: 90 * time.Minute}, 1)
	if err != nil {
		t.Fatal(err)
	}
	rules = parsed(t, out).SSHAgent.Keys["github"].Rules
	if len(rules) != 3 || len(rules[0].Apps) != 2 || len(rules[0].To) != 1 || rules[0].To[0].Team != "apple" ||
		rules[0].Policy != (Policy{Scope: ScopeSession, Gate: GateDialog, Expire: 90 * time.Minute}) || rules[1].Apps[0].Name != "claude" {
		t.Fatalf("inserted at 1: %+v\n%s", rules, out)
	}
	if !strings.Contains(string(out), "        - apps:\n            - ghostty\n            - zed\n") || !strings.Contains(string(out), "expire: 1h30m") {
		t.Fatalf("written form:\n%s", out)
	}
}

func TestAddRuleInlineMatchers(t *testing.T) {
	for ref, want := range map[string]Matcher{
		"app:com.googlecode.iterm2":                     {Kind: MatchApp, ID: "com.googlecode.iterm2"},
		"signed:Q6L2SF6YDW:com.anthropic.claude-code":   {Kind: MatchSigned, Team: "Q6L2SF6YDW", ID: "com.anthropic.claude-code"},
		"signed:Q6L2SF6YDW":                             {Kind: MatchSigned, Team: "Q6L2SF6YDW"},
		"path:/opt/homebrew/opt/mytool/bin/mytool":      {Kind: MatchPath, Path: "/opt/homebrew/opt/mytool/bin/mytool"},
		"path:/Applications/My App: v2 #1.app/x/y true": {Kind: MatchPath, Path: "/Applications/My App: v2 #1.app/x/y true"},
		"app:true": {Kind: MatchApp, ID: "true"},
		"app:1e3":  {Kind: MatchApp, ID: "1e3"},
		"any":      {Kind: MatchAny, Name: "any"},
		"unknown":  {Kind: MatchUnknown, Name: "unknown"},
	} {
		out, err := AddRule([]byte(specExample), KeyEntry("hydra"), RuleSpec{Apps: []string{ref}, Scope: ScopeUse, Gate: GateLogin}, 0)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		r := parsed(t, out).SSHAgent.Keys["hydra"].Rules
		if len(r) != 1 || len(r[0].Apps) != 1 || r[0].Apps[0].Canonical() != want.Canonical() {
			t.Errorf("%s: parsed back as %+v\n%s", ref, r, out)
		}
	}
}

// A reference that is not one of the forms is refused: nothing is written
// that would read as more than one matcher, a mapping key or a comment.
func TestAddRuleRefusesBadMatcherRefs(t *testing.T) {
	for _, ref := range []string{"", "Claude", "a b", "x: y", "app:", "signed:", "signed::id", "signed:T:", "path:relative/x", "path:/a/../b",
		"command:npx", "app:a\nb", "#c", "[a, b]", "{app: x}", strings.Repeat("a", 65)} {
		if out, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{ref}, Gate: GateLogin}, 0); err == nil {
			t.Errorf("%q accepted:\n%s", ref, out)
		}
	}
	if _, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Gate: GateLogin}, 0); err == nil {
		t.Error("a rule without apps accepted")
	}
	if _, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{"claude"}}, 0); err == nil {
		t.Error("a rule without a gate accepted")
	}
	for _, at := range []int{-1, 4, 99} {
		if _, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{"claude"}, Gate: GateLogin}, at); err == nil {
			t.Errorf("position %d accepted (github has 2 rules: 1..3)", at)
		}
	}
}

// A key without an entry, a bare `name:` and a key with only its own gate
// all get a rules list.
func TestAddRuleCreatesTheEntry(t *testing.T) {
	for name, src := range map[string]string{
		"missing file":  "",
		"missing entry": specExample,
		"bare name":     "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    work:\n",
		"own gate only": "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    work: {scope: use, gate: login}\n",
		"dotted name":   "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    work: {gate: login}\n",
	} {
		key := "work"
		if name == "dotted name" {
			key = "work.v2"
		}
		out, err := AddRule([]byte(src), KeyEntry(key), RuleSpec{Apps: []string{"app:com.googlecode.iterm2"}, Scope: ScopeSession, Gate: GateDialog}, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		k := parsed(t, out).SSHAgent.Keys[key]
		if k == nil || len(k.Rules) != 1 {
			t.Fatalf("%s: %+v\n%s", name, k, out)
		}
		if name == "own gate only" && (k.Own == nil || k.Own.Gate != GateLogin) {
			t.Fatalf("%s: the key's own gate was lost", name)
		}
		if name == "dotted name" && parsed(t, out).SSHAgent.Keys["work"] == nil {
			t.Fatalf("%s: the other key was lost:\n%s", name, out)
		}
	}
}

func TestSetRuleChangesOnlyWhatIsGiven(t *testing.T) {
	out, err := SetRule([]byte(specExample), KeyEntry("github"), 2, RulePatch{Gate: ptr(GateDialog), Expire: ptr(time.Duration(0))})
	if err != nil {
		t.Fatal(err)
	}
	r := parsed(t, out).SSHAgent.Keys["github"].Rules[1]
	if r.Policy != (Policy{Scope: ScopeSession, Gate: GateDialog}) || len(r.Apps) != 2 {
		t.Fatalf("rule 2: %+v\n%s", r, out)
	}
	out, err = SetRule([]byte(specExample), KeyEntry("github"), 1, RulePatch{Apps: []string{"iterm"}, To: ptr([]string{"signed:apple"})})
	if err != nil {
		t.Fatal(err)
	}
	r = parsed(t, out).SSHAgent.Keys["github"].Rules[0]
	if r.Apps[0].Name != "iterm" || len(r.To) != 1 || r.Policy.Gate != GateDialog {
		t.Fatalf("rule 1: %+v", r)
	}
	out, err = SetRule(out, KeyEntry("github"), 1, RulePatch{To: ptr([]string{})})
	if err != nil || len(parsed(t, out).SSHAgent.Keys["github"].Rules[0].To) != 0 {
		t.Fatalf("removing to: %v\n%s", err, out)
	}
	for _, c := range []struct {
		key   string
		index int
	}{{"github", 0}, {"github", 3}, {"hydra", 1}, {"nosuch", 1}} {
		if _, err := SetRule([]byte(specExample), KeyEntry(c.key), c.index, RulePatch{Gate: ptr(GateLogin)}); err == nil {
			t.Errorf("%s rule %d accepted", c.key, c.index)
		}
	}
	if _, err := SetRule([]byte(specExample), KeyEntry("github"), 1, RulePatch{}); err == nil {
		t.Error("an empty patch accepted")
	}
	if _, err := SetRule([]byte(specExample), KeyEntry("github"), 9, RulePatch{Gate: ptr(GateLogin)}); !errors.Is(err, ErrNoSuchRule) {
		t.Errorf("want ErrNoSuchRule, got %v", err)
	}
}

func TestRemoveRule(t *testing.T) {
	out, err := RemoveRule([]byte(specExample), KeyEntry("github"), 1)
	if err != nil {
		t.Fatal(err)
	}
	rules := parsed(t, out).SSHAgent.Keys["github"].Rules
	if len(rules) != 1 || rules[0].Apps[0].Name != "iterm" || rules[0].Index != 1 {
		t.Fatalf("%+v", rules)
	}
	out, err = RemoveRule([]byte(specExample), KeyEntry("myrepo-deploy"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "rules: []") || len(parsed(t, out).SSHAgent.Keys["myrepo-deploy"].Rules) != 0 {
		t.Fatalf("an emptied rules list must go:\n%s", out)
	}
	if _, err := RemoveRule([]byte(specExample), KeyEntry("github"), 3); !errors.Is(err, ErrNoSuchRule) {
		t.Fatalf("rule 3: %v", err)
	}
}

func TestSetKeyPolicy(t *testing.T) {
	out, err := SetKeyPolicy([]byte(specExample), "hydra", PolicyPatch{Scope: ptr(ScopeSession), Expire: ptr(8 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if own := parsed(t, out).SSHAgent.Keys["hydra"].Own; own == nil || *own != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) {
		t.Fatalf("hydra: %+v\n%s", own, out)
	}
	if _, err := SetKeyPolicy([]byte(specExample), "hydra", PolicyPatch{Gate: ptr(GateNone)}); err == nil {
		t.Fatal("a key's own gate none accepted")
	}
	// github has rules but no own gate: a scope alone would be refused by
	// Parse ("scope/expire without gate"), so the edit asks for a gate.
	if _, err := SetKeyPolicy([]byte(specExample), "github", PolicyPatch{Scope: ptr(ScopeUse)}); err == nil {
		t.Fatal("scope without a gate accepted")
	}
	out, err = SetKeyPolicy([]byte(specExample), "github", PolicyPatch{Gate: ptr(GateDialog)})
	if err != nil {
		t.Fatal(err)
	}
	if k := parsed(t, out).SSHAgent.Keys["github"]; k.Own == nil || k.Own.Gate != GateDialog || len(k.Rules) != 2 {
		t.Fatalf("github: %+v", k)
	}
}

// Comments and everything outside the edited key survive every edit.
func TestRuleEditsKeepCommentsAndTheRest(t *testing.T) {
	src := `apiVersion: nazar/v1
kind: Config
# who may sign
apps:
  iterm: {app: com.googlecode.iterm2} # my terminal
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm] # me
          scope: session
          gate: login
    other: {gate: block}
`
	edits := map[string]func([]byte) ([]byte, error){
		"add": func(b []byte) ([]byte, error) {
			return AddRule(b, KeyEntry("github"), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 0)
		},
		"set": func(b []byte) ([]byte, error) {
			return SetRule(b, KeyEntry("github"), 1, RulePatch{Gate: ptr(GateDialog)})
		},
		"remove": func(b []byte) ([]byte, error) { return RemoveRule(b, KeyEntry("github"), 1) },
		"policy": func(b []byte) ([]byte, error) { return SetKeyPolicy(b, "github", PolicyPatch{Gate: ptr(GateBlock)}) },
	}
	for name, edit := range edits {
		out, err := edit([]byte(src))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range []string{"# who may sign", "# my terminal"} {
			if !strings.Contains(string(out), c) {
				t.Errorf("%s lost %q:\n%s", name, c, out)
			}
		}
		if name != "remove" && !strings.Contains(string(out), "# me") {
			t.Errorf("%s lost the rule's comment:\n%s", name, out)
		}
		c := parsed(t, out)
		if o := c.SSHAgent.Keys["other"]; o == nil || o.Own == nil || o.Own.Gate != GateBlock {
			t.Errorf("%s changed another key", name)
		}
	}
}

// Sections of the wrong shape are refused, never overwritten.
func TestRuleEditsRefuseWrongShapes(t *testing.T) {
	for _, src := range []string{
		"apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github: [a]\n",
		"apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      rules: {a: b}\n",
		"apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      rules:\n        - just a string\n",
		"apiVersion: nazar/v1\nkind: Config\nssh_agent: [a]\n",
		"- a\n",
	} {
		if _, err := AddRule([]byte(src), KeyEntry("github"), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 0); err == nil &&
			!strings.Contains(src, "just a string") {
			t.Errorf("AddRule on %q accepted", src)
		}
		if _, err := SetRule([]byte(src), KeyEntry("github"), 1, RulePatch{Gate: ptr(GateBlock)}); err == nil {
			t.Errorf("SetRule on %q accepted", src)
		}
	}
	if _, err := RemoveRule([]byte(specExample), KeyEntry("../x"), 1); err == nil {
		t.Error("a bad key name accepted")
	}
}

func TestFormatDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		8 * time.Hour: "8h", 90 * time.Minute: "1h30m", 90 * time.Second: "1m30s", 30 * time.Second: "30s",
		24 * time.Hour: "1d", 7 * 24 * time.Hour: "7d", 25 * time.Hour: "25h", time.Hour + time.Second: "1h0m1s",
		// Whole days past what ParseDuration accepts as "Nd" fall back to hours.
		3650 * 24 * time.Hour: "3650d", 3651 * 24 * time.Hour: "87624h",
	} {
		if got := FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
		if back, err := ParseDuration(FormatDuration(d)); err != nil || back != d {
			t.Errorf("%v does not round-trip: %v %v", d, back, err)
		}
	}
}

// Values that YAML would read as something else (a comment, an alias, an
// anchor, a tag, null, a number, a flow collection, a document marker) are
// written quoted and read back as exactly the string that was asked for.
func TestAddRuleQuotesHostileValues(t *testing.T) {
	for ref, want := range map[string]Matcher{
		"app:a # b":                     {Kind: MatchApp, ID: "a # b"},
		"app:~":                         {Kind: MatchApp, ID: "~"},
		"app:null":                      {Kind: MatchApp, ID: "null"},
		"app:*x":                        {Kind: MatchApp, ID: "*x"},
		"app:&x":                        {Kind: MatchApp, ID: "&x"},
		"app:!!int 1":                   {Kind: MatchApp, ID: "!!int 1"},
		"app:0x10":                      {Kind: MatchApp, ID: "0x10"},
		"app:[a, b]":                    {Kind: MatchApp, ID: "[a, b]"},
		"app:{x: y}":                    {Kind: MatchApp, ID: "{x: y}"},
		"app:'q'":                       {Kind: MatchApp, ID: "'q'"},
		`app:"q"`:                       {Kind: MatchApp, ID: `"q"`},
		"app:--- x":                     {Kind: MatchApp, ID: "--- x"},
		"signed:yes:no":                 {Kind: MatchSigned, Team: "yes", ID: "no"},
		"signed:apple":                  {Kind: MatchSigned, Team: "apple"},
		"path:/tmp/x # not a comment":   {Kind: MatchPath, Path: "/tmp/x # not a comment"},
		"path:/tmp/{a}/[b]/*c/&d/!e/%f": {Kind: MatchPath, Path: "/tmp/{a}/[b]/*c/&d/!e/%f"},
	} {
		out, err := AddRule([]byte(specExample), KeyEntry("hydra"), RuleSpec{Apps: []string{ref}, Gate: GateLogin}, 0)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		r := parsed(t, out).SSHAgent.Keys["hydra"].Rules
		if len(r) != 1 || len(r[0].Apps) != 1 || r[0].Apps[0].Canonical() != want.Canonical() {
			t.Errorf("%s: parsed back as %+v\n%s", ref, r, out)
		}
		// The same value as a receiver (to:) reads back the same way.
		out, err = AddRule([]byte(specExample), KeyEntry("hydra"), RuleSpec{Apps: []string{"any"}, To: []string{ref}, Gate: GateLogin}, 0)
		if err != nil {
			t.Fatalf("to %s: %v", ref, err)
		}
		r = parsed(t, out).SSHAgent.Keys["hydra"].Rules
		if len(r) != 1 || len(r[0].To) != 1 || r[0].To[0].Canonical() != want.Canonical() {
			t.Errorf("to %s: parsed back as %+v\n%s", ref, r, out)
		}
	}
}

// Control characters (C0, DEL, C1) are refused in every matcher form: they
// could end the line, start a new key or rule, or reach a terminal as an
// escape sequence when the rule is shown.
func TestParseMatcherRefRefusesControlCharacters(t *testing.T) {
	for _, cc := range []string{"\x00", "\x01", "\t", "\n", "\r", "\x1b", "\x7f", "\u0085", "\u009b"} {
		for _, ref := range []string{"app:a" + cc + "b", "signed:T" + cc + "X", "signed:TEAM:id" + cc, "path:/a" + cc + "b"} {
			if n, err := ParseMatcherRef(ref); err == nil {
				t.Errorf("ParseMatcherRef(%q) accepted: %+v", ref, n)
			}
			if out, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{ref}, Gate: GateLogin}, 0); err == nil {
				t.Errorf("AddRule apps %q accepted:\n%s", ref, out)
			}
			if out, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{"any"}, To: []string{ref}, Gate: GateLogin}, 0); err == nil {
				t.Errorf("AddRule to %q accepted:\n%s", ref, out)
			}
		}
	}
}

func TestParseMatcherRefForms(t *testing.T) {
	for _, ref := range []string{"any", "unknown", "claude", "k9s", "a.b-c_d", "app:com.x", "signed:apple", "signed:T:id", "path:/x"} {
		if n, err := ParseMatcherRef(ref); err != nil || n == nil {
			t.Errorf("ParseMatcherRef(%q) = %v, %v", ref, n, err)
		}
	}
	// signed:T: and signed:apple: say an id is coming and give none; writing
	// the team-only form instead would widen the rule to every binary of
	// that team.
	for _, ref := range []string{"", "Any", "-x", ".x", "command:npx", "team:T", "app:", "signed:", "signed::id", "signed:T:", "signed:apple:", "path:", "path:x", "path:/a/", "path://a", "path:/a/./b"} {
		if n, err := ParseMatcherRef(ref); err == nil {
			t.Errorf("ParseMatcherRef(%q) accepted: %+v", ref, n)
		}
	}
}

// A bad receiver, an emptied apps: or a bad reference in a patch is
// refused like one in a new rule.
func TestRuleEditsRefuseBadPatches(t *testing.T) {
	if out, err := AddRule([]byte(specExample), KeyEntry("github"), RuleSpec{Apps: []string{"claude"}, To: []string{"Bad Name"}, Gate: GateLogin}, 0); err == nil {
		t.Errorf("a bad to: accepted:\n%s", out)
	}
	if out, err := SetRule([]byte(specExample), KeyEntry("github"), 1, RulePatch{Apps: []string{}}); err == nil {
		t.Errorf("an emptied apps: accepted:\n%s", out)
	}
	if out, err := SetRule([]byte(specExample), KeyEntry("github"), 1, RulePatch{Apps: []string{"x: y"}}); err == nil {
		t.Errorf("a bad apps: patch accepted:\n%s", out)
	}
	if out, err := SetRule([]byte(specExample), KeyEntry("github"), 1, RulePatch{To: ptr([]string{"path:rel"})}); err == nil {
		t.Errorf("a bad to: patch accepted:\n%s", out)
	}
	if out, err := SetRule([]byte(specExample), KeyEntry("github"), 1, RulePatch{Gate: ptr(Gate(""))}); err == nil {
		t.Errorf("an empty gate accepted:\n%s", out)
	}
	if out, err := SetKeyPolicy([]byte(specExample), "hydra", PolicyPatch{}); err == nil {
		t.Errorf("an empty policy patch accepted:\n%s", out)
	}
	for _, key := range []string{"", "a b", "x\ny", ".hidden", strings.Repeat("k", 65)} {
		if _, err := AddRule([]byte(specExample), KeyEntry(key), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 0); err == nil {
			t.Errorf("AddRule accepted key name %q", key)
		}
		if _, err := SetKeyPolicy([]byte(specExample), key, PolicyPatch{Gate: ptr(GateBlock)}); err == nil {
			t.Errorf("SetKeyPolicy accepted key name %q", key)
		}
	}
}

// Set and remove never create what they edit; a missing key or one without
// rules is ErrNoSuchRule or another error, never a fresh entry.
func TestSetAndRemoveNeedAnExistingRule(t *testing.T) {
	for name, src := range map[string]string{
		"empty file":     "",
		"no ssh_agent":   "apiVersion: nazar/v1\nkind: Config\n",
		"no keys":        "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  socket: ~/.nazar/agent.sock\n",
		"bare key":       "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n",
		"own gate only":  "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github: {gate: login}\n",
		"empty rules":    "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      rules: []\n",
		"other key only": "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    gitlab: {gate: login}\n",
	} {
		if out, err := SetRule([]byte(src), KeyEntry("github"), 1, RulePatch{Gate: ptr(GateBlock)}); err == nil {
			t.Errorf("%s: SetRule accepted:\n%s", name, out)
		}
		if out, err := RemoveRule([]byte(src), KeyEntry("github"), 1); err == nil {
			t.Errorf("%s: RemoveRule accepted:\n%s", name, out)
		}
	}
	// Key names are exact: "GitHub" and "github" are different entries.
	if out, err := RemoveRule([]byte(specExample), KeyEntry("GitHub"), 1); err == nil {
		t.Errorf("RemoveRule matched a key by folded case:\n%s", out)
	}
	if _, err := RemoveRule([]byte(specExample), KeyEntry("github"), 0); !errors.Is(err, ErrNoSuchRule) {
		t.Errorf("rule 0: want ErrNoSuchRule, got %v", err)
	}
	if _, err := RemoveRule([]byte(specExample), KeyEntry("github"), -1); !errors.Is(err, ErrNoSuchRule) {
		t.Errorf("rule -1: want ErrNoSuchRule, got %v", err)
	}
}

// A file with more than one YAML document is refused (Parse refuses it
// too): an edit must never drop the documents after the first.
func TestRuleEditsRefuseSeveralDocuments(t *testing.T) {
	src := specExample + "---\napiVersion: nazar/v1\nkind: Config\n"
	if out, err := AddRule([]byte(src), KeyEntry("github"), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 0); err == nil {
		t.Errorf("AddRule accepted:\n%s", out)
	}
	if out, err := SetRule([]byte(src), KeyEntry("github"), 1, RulePatch{Gate: ptr(GateBlock)}); err == nil {
		t.Errorf("SetRule accepted:\n%s", out)
	}
	if out, err := RemoveRule([]byte(src), KeyEntry("github"), 1); err == nil {
		t.Errorf("RemoveRule accepted:\n%s", out)
	}
	if out, err := SetKeyPolicy([]byte(src), "hydra", PolicyPatch{Gate: ptr(GateBlock)}); err == nil {
		t.Errorf("SetKeyPolicy accepted:\n%s", out)
	}
	if _, err := AddRule([]byte("apiVersion: nazar/v1\nkind: [unclosed\n"), KeyEntry("github"), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 0); err == nil {
		t.Error("AddRule accepted invalid YAML")
	}
}

// The edit is pure: the input bytes are never changed, and the rules of
// other keys and the order of a key's other rules are kept.
func TestRuleEditsArePure(t *testing.T) {
	src := []byte(specExample)
	before := string(src)
	if _, err := AddRule(src, KeyEntry("github"), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := SetRule(src, KeyEntry("github"), 2, RulePatch{Gate: ptr(GateBlock)}); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveRule(src, KeyEntry("github"), 1); err != nil {
		t.Fatal(err)
	}
	if string(src) != before {
		t.Fatal("an edit changed its input")
	}
	out, err := AddRule(src, KeyEntry("github"), RuleSpec{Apps: []string{"any"}, Gate: GateBlock}, 2)
	if err != nil {
		t.Fatal(err)
	}
	c := parsed(t, out)
	rules := c.SSHAgent.Keys["github"].Rules
	if len(rules) != 3 || rules[0].Apps[0].Name != "claude" || rules[1].Apps[0].Kind != MatchAny || rules[2].Apps[0].Name != "iterm" {
		t.Fatalf("inserted at 2: %+v", rules)
	}
	if len(c.SSHAgent.Keys["myrepo-deploy"].Rules) != 1 || c.SSHAgent.Keys["hydra"].Own == nil || len(c.Apps) != 5 || c.Defaults.Fallback.Gate != GateBlock {
		t.Fatalf("the rest of the file changed:\n%s", out)
	}
}

// A key's own policy: a missing key is created when a gate is given, and a
// zero expire removes the field.
func TestSetKeyPolicyCreatesAndRemovesExpire(t *testing.T) {
	out, err := SetKeyPolicy([]byte(specExample), "newkey", PolicyPatch{Gate: ptr(GateLogin), Scope: ptr(ScopeApp), Expire: ptr(7 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if k := parsed(t, out).SSHAgent.Keys["newkey"]; k == nil || k.Own == nil || *k.Own != (Policy{Scope: ScopeApp, Gate: GateLogin, Expire: 7 * 24 * time.Hour}) {
		t.Fatalf("newkey: %+v\n%s", k, out)
	}
	if !strings.Contains(string(out), "expire: 7d") {
		t.Fatalf("written form:\n%s", out)
	}
	out, err = SetKeyPolicy(out, "newkey", PolicyPatch{Expire: ptr(time.Duration(0))})
	if err != nil {
		t.Fatal(err)
	}
	if k := parsed(t, out).SSHAgent.Keys["newkey"]; k.Own == nil || k.Own.Expire != 0 || k.Own.Gate != GateLogin || strings.Contains(string(out), "expire: 7d") {
		t.Fatalf("expire not removed: %+v\n%s", k.Own, out)
	}
	if out, err := SetKeyPolicy([]byte(specExample), "newkey", PolicyPatch{Scope: ptr(ScopeUse)}); err == nil {
		t.Fatalf("a new key without a gate accepted:\n%s", out)
	}
}

// Every edit writes config.yaml in one format, block style: a file written
// in flow style (`keys: {a: {gate: dialog}}`, as a hand edit may leave it)
// comes out with one field per line and every list item on its own line,
// and what the edit adds is written the same way.
func TestEditsWriteOneFormat(t *testing.T) {
	src := []byte("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys: {t: {scope: use, gate: dialog}}\n")
	out, err := AddSSHKey(src, "github", Policy{Scope: ScopeUse, Gate: GateDialog})
	if err != nil {
		t.Fatal(err)
	}
	out, err = AddRule(out, KeyEntry("github"), RuleSpec{Apps: []string{"app:com.googlecode.iterm2"}, Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, err = AddRule(out, KeyEntry("github"), RuleSpec{Apps: []string{"app:com.github.GitHubClient"}, Scope: ScopeUse, Gate: GateNone}, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := `apiVersion: nazar/v1
kind: Config
ssh_agent:
  keys:
    t:
      scope: use
      gate: dialog
    github:
      scope: use
      gate: dialog
      rules:
        - apps:
            - app: com.googlecode.iterm2
          scope: session
          gate: login
          expire: 8h
        - apps:
            - app: com.github.GitHubClient
          gate: none
`
	if string(out) != want {
		t.Fatalf("written form:\n%s\nwant:\n%s", out, want)
	}
	if rules := parsed(t, out).SSHAgent.Keys["github"].Rules; len(rules) != 2 {
		t.Fatalf("rules: %+v", rules)
	}
	// A key-only edit rewrites the rest of the file the same way.
	out, err = SetKeyPolicy(src, "t", PolicyPatch{Gate: ptr(GateBlock)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "  keys:\n    t:") {
		t.Fatalf("keys still flow:\n%s", out)
	}
}

// scope and expire mean nothing with gate block or none (Parse warns about
// them), so an edit never writes them there, and drops them when it makes
// a gate non-prompting: nazar must not write what it then warns about.
func TestEditsWriteNoScopeForGatesThatDoNotPrompt(t *testing.T) {
	src := []byte("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      scope: session\n      gate: dialog\n      expire: 8h\n")
	out, err := SetKeyPolicy(src, "github", PolicyPatch{Gate: ptr(GateBlock)})
	if err != nil {
		t.Fatal(err)
	}
	out, err = AddRule(out, KeyEntry("github"), RuleSpec{Apps: []string{"app:com.github.GitHubClient"}, Scope: ScopeApp, Gate: GateNone, Expire: time.Hour}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "scope") || strings.Contains(string(out), "expire") {
		t.Fatalf("scope or expire written with a non-prompting gate:\n%s", out)
	}
	if _, probs := Parse(out, env); strings.Contains(probs.Error(), "ignored with gate") {
		t.Fatalf("the edit's own output warns: %s", probs.Error())
	}
}

// A secret's rules are edited by the same functions as a key's, in
// secrets.<name>, looked up by its exact name: a key of the same name, and a
// secret whose name is a prefix of it, are never touched.
const secretRulesDoc = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    GH.TOKEN:
      gate: block
secrets:
  GH:
    gate: block
  GH.TOKEN: # deliver and comments are kept
    deliver: [stdout]
    gate: block
`

func TestSecretRuleEdits(t *testing.T) {
	spec := RuleSpec{Apps: []string{"iterm"}, To: []string{"signed:apple:com.apple.git-remote-http"}, Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}
	out, err := AddRule([]byte(secretRulesDoc), SecretEntry("GH.TOKEN"), spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := parsed(t, out)
	s := c.Secrets["GH.TOKEN"]
	if s == nil || len(s.Rules) != 1 || s.Rules[0].Policy.Gate != GateLogin || len(s.Rules[0].To) != 1 || s.Own == nil || s.Own.Gate != GateBlock {
		t.Fatalf("GH.TOKEN: %+v\n%s", s, out)
	}
	if len(c.Secrets["GH"].Rules) != 0 || len(c.SSHAgent.Keys["GH.TOKEN"].Rules) != 0 {
		t.Fatalf("another entry was edited:\n%s", out)
	}
	if !strings.Contains(string(out), "# deliver and comments are kept") || len(s.Deliver) != 1 || s.Deliver[0] != DeliverStdout {
		t.Fatalf("deliver or comment lost:\n%s", out)
	}
	out, err = SetRule(out, SecretEntry("GH.TOKEN"), 1, RulePatch{Gate: ptr(GateDialog)})
	if err != nil {
		t.Fatal(err)
	}
	if r := parsed(t, out).Secrets["GH.TOKEN"].Rules[0]; r.Policy.Gate != GateDialog || len(r.To) != 1 {
		t.Fatalf("set: %+v", r)
	}
	out, err = RemoveRule(out, SecretEntry("GH.TOKEN"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if s := parsed(t, out).Secrets["GH.TOKEN"]; len(s.Rules) != 0 || strings.Contains(string(out), "rules:") {
		t.Fatalf("remove: %+v\n%s", s, out)
	}
	// A missing entry: rule add creates it (as for a key), with its exact
	// name; set and remove name the secret in their error.
	out, err = AddRule([]byte(secretRulesDoc), SecretEntry("team/NEW"), RuleSpec{Apps: []string{"iterm"}, Gate: GateLogin}, 0)
	if err != nil || len(parsed(t, out).Secrets["team/NEW"].Rules) != 1 {
		t.Fatalf("new entry: %v\n%s", err, out)
	}
	// A secret's entry made by rule add is blocked for every other caller,
	// as secret add writes it: never defaults.fallback.
	if own := parsed(t, out).Secrets["team/NEW"].Own; own == nil || own.Gate != GateBlock {
		t.Fatalf("new secret entry without gate: block:\n%s", out)
	}
	// A key's new entry is unchanged: its fallback stays defaults.fallback.
	if out, err := AddRule([]byte(secretRulesDoc), KeyEntry("NEWKEY"), RuleSpec{Apps: []string{"iterm"}, Gate: GateLogin}, 0); err != nil || parsed(t, out).SSHAgent.Keys["NEWKEY"].Own != nil {
		t.Fatalf("new key entry: %v\n%s", err, out)
	}
	if _, err := SetRule([]byte(secretRulesDoc), SecretEntry("NOPE"), 1, RulePatch{Gate: ptr(GateBlock)}); err == nil || !strings.Contains(err.Error(), "secrets.NOPE") {
		t.Fatalf("set on a missing secret: %v", err)
	}
	if _, err := RemoveRule([]byte(secretRulesDoc), SecretEntry("GH"), 1); err == nil || !strings.Contains(err.Error(), "secrets.GH has 0 rule(s)") {
		t.Fatalf("remove of a missing rule: %v", err)
	}
	for _, bad := range []string{"../x", "a b", "", "x\n"} {
		if _, err := AddRule([]byte(secretRulesDoc), SecretEntry(bad), spec, 0); err == nil {
			t.Errorf("secret name %q accepted", bad)
		}
	}
	if e := SecretEntry("GH"); e.String() != "secrets.GH" || KeyEntry("GH").String() != "ssh_agent.keys.GH" {
		t.Fatalf("%v %v", e, KeyEntry("GH"))
	}
}

// A k8s context's rules are edited by the same functions, in
// k8s.contexts.<name>, looked up by its exact name: a key and a secret of
// the same name, and a context whose name extends it, are never touched.
// An edit never creates a context (import does, with its cluster) and
// never writes to: (the program that runs the plugin receives it).
const k8sRulesDoc = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  kubectl: {signed: {team: KUBETEAM01, id: kubectl}}
ssh_agent:
  keys:
    hydra:
      gate: block
secrets:
  hydra:
    gate: block
k8s:
  contexts:
    hydra: # cluster, identity and comments are kept
      credential: ca-cert
      identity: {user: admin, groups: [system:masters]}
      cluster: {server: "https://hydra.example:16443", ca_sha256: 3f8c0000000000000000000000000000000000000000000000000000000000e1}
      gate: block
    hydra.prod:
      credential: ca-cert
      identity: {user: dev}
      cluster: {server: "https://prod.example:6443", ca_sha256: 3f8c0000000000000000000000000000000000000000000000000000000000e1}
      gate: block
`

func TestK8sRuleEdits(t *testing.T) {
	spec := RuleSpec{Apps: []string{"iterm"}, Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}
	out, err := AddRule([]byte(k8sRulesDoc), K8sEntry("hydra"), spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := parsed(t, out)
	k := c.K8s["hydra"]
	if k == nil || len(k.Rules) != 1 || k.Rules[0].Policy != (Policy{Scope: ScopeSession, Gate: GateLogin, Expire: 8 * time.Hour}) || len(k.Rules[0].To) != 0 ||
		k.Own == nil || k.Own.Gate != GateBlock || k.Identity.User != "admin" || k.Cluster.Server != "https://hydra.example:16443" {
		t.Fatalf("hydra: %+v\n%s", k, out)
	}
	if len(c.K8s["hydra.prod"].Rules) != 0 || len(c.SSHAgent.Keys["hydra"].Rules) != 0 || len(c.Secrets["hydra"].Rules) != 0 {
		t.Fatalf("another entry was edited:\n%s", out)
	}
	if !strings.Contains(string(out), "# cluster, identity and comments are kept") {
		t.Fatalf("comment lost:\n%s", out)
	}
	out, err = SetRule(out, K8sEntry("hydra"), 1, RulePatch{Gate: ptr(GateDialog), Apps: []string{"app:com.apple.Terminal"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := parsed(t, out).K8s["hydra"].Rules[0]; r.Policy.Gate != GateDialog || r.Apps[0].ID != "com.apple.Terminal" {
		t.Fatalf("set: %+v", r)
	}
	out, err = RemoveRule(out, K8sEntry("hydra"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if k := parsed(t, out).K8s["hydra"]; len(k.Rules) != 0 || strings.Contains(string(out), "rules:") {
		t.Fatalf("remove: %+v\n%s", k, out)
	}
	// No to:, by add or by set (an empty one, --no-to, included).
	for _, to := range [][]string{{"kubectl"}, {}} {
		if _, err := AddRule([]byte(k8sRulesDoc), K8sEntry("hydra"), RuleSpec{Apps: []string{"iterm"}, To: to, Gate: GateLogin}, 0); err == nil || !strings.Contains(err.Error(), "take no to:") {
			t.Fatalf("add with to %q: %v", to, err)
		}
	}
	withRule, err := AddRule([]byte(k8sRulesDoc), K8sEntry("hydra"), spec, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range [][]string{{"kubectl"}, {}} {
		if _, err := SetRule(withRule, K8sEntry("hydra"), 1, RulePatch{To: &to}); err == nil || !strings.Contains(err.Error(), "take no to:") {
			t.Fatalf("set to %q: %v", to, err)
		}
	}
	// A context that is not configured is never created; letter case counts.
	for _, name := range []string{"nope", "Hydra"} {
		if _, err := AddRule([]byte(k8sRulesDoc), K8sEntry(name), spec, 0); err == nil || !strings.Contains(err.Error(), "there is no k8s.contexts."+name) {
			t.Fatalf("add on %s: %v", name, err)
		}
	}
	if _, err := AddRule([]byte("apiVersion: nazar/v1\nkind: Config\n"), K8sEntry("hydra"), spec, 0); err == nil || !strings.Contains(err.Error(), "there is no k8s.contexts.hydra") {
		t.Fatalf("add with no k8s section: %v", err)
	}
	if _, err := RemoveRule([]byte(k8sRulesDoc), K8sEntry("hydra"), 1); err == nil || !strings.Contains(err.Error(), "k8s.contexts.hydra has 0 rule(s)") {
		t.Fatalf("remove of a missing rule: %v", err)
	}
	for _, bad := range []string{"a/b", "a:b", "x..y", ".x", "", "a b", "hydra\n"} {
		if _, err := AddRule([]byte(k8sRulesDoc), K8sEntry(bad), spec, 0); err == nil || !strings.Contains(err.Error(), "invalid context name") {
			t.Errorf("context name %q: %v", bad, err)
		}
	}
	if e := K8sEntry("hydra"); e.String() != "k8s.contexts.hydra" || !e.IsK8s() || e.IsSecret() || e.IsKey() || !KeyEntry("hydra").IsKey() || !SecretEntry("hydra").IsSecret() {
		t.Fatalf("%v", e)
	}
}
