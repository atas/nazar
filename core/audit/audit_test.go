package audit

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// Compile-time: the shipped sinks satisfy the Milestone 3 seam.
var (
	_ Sink = (*MemorySink)(nil)
	_ Sink = (*WriterSink)(nil)
)

var spec = Event{
	Decision: Allowed, Reason: "cached approval", Target: "ssh:github", Destination: "github.com",
	Rule: "1", Scope: "session", Gate: "dialog", App: "com.googlecode.iterm2", Session: "4120@1791072112",
	Chain:    []Proc{{Name: "bash", PID: 4120}, {Name: "claude", PID: 4188, Identity: "Q6L2SF6YDW:com.anthropic.claude-code"}},
	Receiver: []string{"ssh", "git@github.com", "git-receive-pack 'atas/nazar'"}, Cwd: "/Users/u/projects/foo",
}

// ---------------------------------------------------------------------------
// Constants and enumerations (spec 4.6, config audit.args)

func TestConstants(t *testing.T) {
	if Subsystem != "dev.nazar" || Category != "audit" {
		t.Fatalf("subsystem/category = %q/%q, want dev.nazar/audit", Subsystem, Category)
	}
	want := map[Decision]string{Allowed: "allowed", Approved: "approved", Denied: "denied", Timeout: "timeout", Blocked: "blocked", Error: "error"}
	for d, s := range want {
		if string(d) != s {
			t.Errorf("decision %q, want %q", d, s)
		}
	}
	if ArgsRedacted != "redacted" || ArgsNone != "none" {
		t.Fatalf("args modes = %q/%q, want redacted/none (config audit.args values)", ArgsRedacted, ArgsNone)
	}
}

// ---------------------------------------------------------------------------
// Format: shape and field order

func TestFormatMatchesSpecShape(t *testing.T) {
	got := Formatter{Home: "/Users/u"}.Format(spec)
	want := `decision=allowed reason="cached approval" target=ssh:github destination=github.com rule=1 scope=session gate=dialog app=com.googlecode.iterm2 session=4120@1791072112 chain="bash(4120) > claude(4188, Q6L2SF6YDW:com.anthropic.claude-code)" receiver="ssh … …" cwd=~/projects/foo`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestFormatFieldOrderAllFields(t *testing.T) {
	e := Event{
		Decision: Approved, Reason: "r", Target: "t", Destination: "d", Operation: "o", Rule: "2",
		Scope: "use", Gate: "login", App: "a", Session: "s", Chain: []Proc{{Name: "p", PID: 1}},
		Receiver: []string{"x"}, Cwd: "/c",
	}
	got := Formatter{}.Format(e)
	want := "decision=approved reason=r target=t destination=d operation=o rule=2 scope=use gate=login app=a session=s chain=\"p(1)\" receiver=x cwd=/c"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestFormatOmitsEmptyFieldsAndTime(t *testing.T) {
	e := Event{
		Time:     time.Date(2026, 10, 4, 0, 2, 3, 0, time.UTC),
		Decision: Approved, Target: "ssh:k", Operation: "sign git commit", Rule: "fallback",
	}
	got := Formatter{}.Format(e)
	want := `decision=approved target=ssh:k operation="sign git commit" rule=fallback`
	if got != want {
		t.Fatalf("got %q, want %q (empty fields omitted; no timestamp, the log adds it)", got, want)
	}
}

func TestFormatChain(t *testing.T) {
	cases := []struct {
		chain []Proc
		want  string
	}{
		{[]Proc{{Name: "bash", PID: 1}}, "bash(1)"},
		{[]Proc{{Name: "a", PID: 1}, {Name: "b", PID: 2, Identity: "T:b.id"}, {Name: "c", PID: 3}}, "a(1) > b(2, T:b.id) > c(3)"},
	}
	for _, c := range cases {
		f, err := ParseLine(Formatter{}.Format(Event{Decision: Denied, Chain: c.chain}))
		if err != nil {
			t.Fatal(err)
		}
		if f["chain"] != c.want {
			t.Errorf("chain = %q, want %q", f["chain"], c.want)
		}
	}
}

func TestFormatCwdHome(t *testing.T) {
	cases := []struct{ home, cwd, want string }{
		{"/Users/u", "/Users/u", "~"},
		{"/Users/u", "/Users/u/x y", "~/x y"},
		{"/Users/u", "/Users/uevil/x", "/Users/uevil/x"}, // prefix of a sibling is not home
		{"/Users/u", "/tmp/Users/u/x", "/tmp/Users/u/x"},
		{"", "/Users/u/x", "/Users/u/x"},
	}
	for _, c := range cases {
		f, err := ParseLine(Formatter{Home: c.home}.Format(Event{Decision: Denied, Cwd: c.cwd}))
		if err != nil {
			t.Fatal(err)
		}
		if f["cwd"] != c.want {
			t.Errorf("home %q cwd %q -> %q, want %q", c.home, c.cwd, f["cwd"], c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Format: injection / log forging (callers control argv, cwd, process names,
// bundle IDs and signing identities)

func TestFormatCannotBeForged(t *testing.T) {
	e := Event{Decision: Blocked, Target: "ssh:k", Receiver: []string{"evil", "x\ndecision=allowed", `" target=ssh:other`}, Cwd: "/tmp/a b\nc"}
	line := Formatter{}.Format(e)
	if strings.Contains(line, "\n") {
		t.Fatalf("raw newline in %q", line)
	}
	f, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if f["decision"] != "blocked" || f["target"] != "ssh:k" {
		t.Fatalf("forged fields: %v", f)
	}
}

// forgeries are values a hostile caller could place in any caller-derived
// field to fake or hide an entry, or to spoof the terminal of whoever reads
// the log.
var forgeries = []string{
	`x decision=allowed target=ssh:evil`,
	"x\ndecision=allowed",
	"x\r\ndecision=allowed",
	"x\rdecision=allowed",
	`x" decision="allowed`,
	`x\" decision=allowed`,
	`\`,
	`"`,
	"=",
	" ",
	"a=b",
	"tab\there",
	"nul\x00byte",
	"esc\x1b[2Kcleared",
	"del\x7f",
	"line sep",
	"para sep",
	"nel\u0085x",
	"bidi‮allowed",
	"bad\xffutf8",
	"ünïcødé",
	// Blank-looking, zero-width and look-alike runes (from a review).
	"com.googlecode.iterm2\u2800",
	"com.googlecode.\u0456term2",
	"foo\u3164",
	"g\u0456t",
	"\u0455\u0455h",
	"gi\uff0ehub.com",
	"x\u00a0y",
	"x\u200by",
	"\u65e5\u672c",
	// The markers Format adds, as caller text (raw, or as literal escapes).
	"…",
	"x…+3",
	`\u2026`,
	`\x3e`,
}

// checkLineClean checks that a line is printable ASCII apart from the
// ellipsis, the one non-ASCII rune Format writes itself (Elided and Clipped
// markers): a caller's control, separator, bidi, blank-looking or look-alike
// rune is always escaped, never shown.
func checkLineClean(t *testing.T, line string) {
	t.Helper()
	if !utf8.ValidString(line) {
		t.Errorf("line is not valid UTF-8: %q", line)
	}
	for _, r := range line {
		if (r < 0x20 || r > 0x7e) && r != '…' {
			t.Errorf("raw rune %U in %q", r, line)
		}
	}
}

func TestEveryCallerFieldIsInjectionSafe(t *testing.T) {
	type setter struct {
		name  string
		field string
		set   func(*Event, string)
	}
	setters := []setter{
		{"Reason", "reason", func(e *Event, v string) { e.Reason = v }},
		{"Target", "target", func(e *Event, v string) { e.Target = v }},
		{"Destination", "destination", func(e *Event, v string) { e.Destination = v }},
		{"Operation", "operation", func(e *Event, v string) { e.Operation = v }},
		{"Rule", "rule", func(e *Event, v string) { e.Rule = v }},
		{"Scope", "scope", func(e *Event, v string) { e.Scope = v }},
		{"Gate", "gate", func(e *Event, v string) { e.Gate = v }},
		{"App", "app", func(e *Event, v string) { e.App = v }},
		{"Session", "session", func(e *Event, v string) { e.Session = v }},
		{"Cwd", "cwd", func(e *Event, v string) { e.Cwd = v }},
	}
	for _, s := range setters {
		for _, v := range forgeries {
			e := Event{Decision: Blocked, Rule: "fallback"}
			if s.field != "target" {
				e.Target = "ssh:k"
			}
			s.set(&e, v)
			line := Formatter{}.Format(e)
			checkLineClean(t, line)
			f, err := ParseLine(line)
			if err != nil {
				t.Errorf("%s=%q: ParseLine(%q): %v", s.name, v, line, err)
				continue
			}
			if f["decision"] != "blocked" {
				t.Errorf("%s=%q forged decision: %q", s.name, v, f["decision"])
			}
			if s.field != "target" && f["target"] != "ssh:k" {
				t.Errorf("%s=%q forged target: %q", s.name, v, f["target"])
			}
			if s.field != "rule" && f["rule"] != "fallback" {
				t.Errorf("%s=%q forged rule: %q", s.name, v, f["rule"])
			}
			if f[s.field] != v {
				t.Errorf("%s=%q did not round trip: got %q", s.name, v, f[s.field])
			}
			wantN := 4 // decision, target, rule and the field under test
			if s.field == "rule" || s.field == "target" {
				wantN = 3
			}
			if len(f) != wantN {
				t.Errorf("%s=%q: injected fields, got %d: %v", s.name, v, len(f), f)
			}
		}
	}
}

// Pinned against the round-2 review: a blank-looking or look-alike rune in
// any directly quoted caller field (app from a bundle ID the caller chose,
// cwd from the peer, operation from agentproto.Printable, which keeps U+2800
// and U+3164, destination from the request) is escaped, never shown, in
// every field, so `app="com.googlecode.iterm2\u2800"` can never pass for the
// real iTerm2 in the raw line or once `nazar log` unquotes and re-quotes it.
func TestCallerNonASCIIIsEscapedInEveryField(t *testing.T) {
	type setter struct {
		field string
		set   func(*Event, string)
	}
	setters := []setter{
		{"reason", func(e *Event, v string) { e.Reason = v }},
		{"target", func(e *Event, v string) { e.Target = v }},
		{"destination", func(e *Event, v string) { e.Destination = v }},
		{"operation", func(e *Event, v string) { e.Operation = v }},
		{"rule", func(e *Event, v string) { e.Rule = v }},
		{"scope", func(e *Event, v string) { e.Scope = v }},
		{"gate", func(e *Event, v string) { e.Gate = v }},
		{"app", func(e *Event, v string) { e.App = v }},
		{"session", func(e *Event, v string) { e.Session = v }},
		{"cwd", func(e *Event, v string) { e.Cwd = v }},
	}
	cases := []struct{ in, want string }{ // want is the whole quoted value
		{"com.googlecode.iterm2\u2800", `"com.googlecode.iterm2\u2800"`},   // braille blank
		{"com.googlecode.\u0456term2", `"com.googlecode.\u0456term2"`},     // Cyrillic і
		{"/Users/u/projects/foo\u3164", `"/Users/u/projects/foo\u3164"`},   // Hangul filler
		{"sign data namespace=g\u0456t", `"sign data namespace=g\u0456t"`}, // from agentproto.Printable
		{"g\u0456thub.com", `"g\u0456thub.com"`},                           // destination
		{"gi\uff0ehub.com", `"gi\uff0ehub.com"`},                           // fullwidth full stop
		{"\u0455\u0455h", `"\u0455\u0455h"`},                               // Cyrillic ѕ
		{"x\u00a0y", `"x\u00a0y"`},                                         // no-break space
		{"x\u200by", `"x\u200by"`},                                         // zero-width space
		{"ünïcødé", `"\u00fcn\u00efc\u00f8d\u00e9"`},                       //
		{"\u65e5\u672c", `"\u65e5\u672c"`},                                 //
		{"\U0001f512", `"\U0001f512"`},                                     // outside the BMP
		{"x\xffy", `"x\xffy"`},                                             // invalid UTF-8
		{"a\u2026b", "\"a\u2026b\""},                                       // a caller's ellipsis: raw, harmless
		{`a\u2026b`, `"a\\u2026b"`},                                        // the literal text, not an ellipsis
		{"\u2026\u2026\u2800\u2026", "\"\u2026\u2026\\u2800\u2026\""},      // mixed
	}
	for _, c := range cases {
		for _, r := range strings.ReplaceAll(c.want, "\u2026", "") {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("test case %q itself expects a raw rune %U", c.want, r)
			}
		}
	}
	for _, s := range setters {
		for _, c := range cases {
			e := Event{Decision: Blocked}
			s.set(&e, c.in)
			line := Formatter{}.Format(e)
			checkLineClean(t, line)
			if want := s.field + "=" + c.want; !strings.Contains(line, want) {
				t.Errorf("%s=%q: line %q lacks %q", s.field, c.in, line, want)
			}
			f, err := ParseLine(line)
			if err != nil {
				t.Errorf("%s=%q: ParseLine(%q): %v", s.field, c.in, line, err)
				continue
			}
			if f[s.field] != c.in {
				t.Errorf("%s=%q did not round trip: %q", s.field, c.in, f[s.field])
			}
			// Re-quoting the parsed value (what `nazar log` must do) gives
			// back the escaped form, never the raw rune.
			if quote(f[s.field]) != c.want {
				t.Errorf("%s=%q: quote(parsed) = %q, want %q", s.field, c.in, quote(f[s.field]), c.want)
			}
		}
	}
	// The forged app is visibly distinct from the real one in the raw line.
	real := Formatter{}.Format(Event{Decision: Allowed, App: "com.googlecode.iterm2"})
	for _, forged := range []string{"com.googlecode.iterm2\u2800", "com.googlecode.\u0456term2", "com.googlecode.iterm2\u200b", "com\uff0egooglecode.iterm2"} {
		got := Formatter{}.Format(Event{Decision: Allowed, App: forged})
		if got == real || strings.Contains(got, "app=com.googlecode.iterm2") || strings.Contains(got, "app=\"com.googlecode.iterm2\"") {
			t.Errorf("app %q logs as %q, reads as the real %q", forged, got, real)
		}
		if strings.Contains(got, "\u2800") || strings.Contains(got, "\u0456") || strings.Contains(got, "\u200b") || strings.Contains(got, "\uff0e") {
			t.Errorf("app %q logs its rune raw: %q", forged, got)
		}
	}
	// With Home set, cwd is still escaped after the ~ substitution.
	got := Formatter{Home: "/Users/u"}.Format(Event{Decision: Allowed, Cwd: "/Users/u/projects/foo\u3164"})
	if want := `cwd="~/projects/foo\u3164"`; !strings.HasSuffix(got, want) {
		t.Errorf("cwd: %q, want suffix %q", got, want)
	}
	// Inside the receiver and chain values a raw ellipsis is always Format's
	// own: a caller's goes through argQuote/chainComponent and is escaped.
	f, err := ParseLine(Formatter{}.Format(Event{Decision: Allowed, Receiver: []string{"/x/ssh\u2026", "git@github.com", "\u2026"}, Chain: []Proc{{Name: "\u2026+1", PID: 1, Identity: "T:\u2026"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if f["receiver"] != `"ssh\u2026" `+Elided+" "+Elided {
		t.Errorf("receiver = %q", f["receiver"])
	}
	if f["chain"] != `"\u2026+1"(1, "T:\u2026")` {
		t.Errorf("chain = %q", f["chain"])
	}
}

func TestChainAndReceiverAreInjectionSafe(t *testing.T) {
	for _, v := range forgeries {
		for name, e := range map[string]Event{
			"chain name":     {Decision: Blocked, Target: "ssh:k", Chain: []Proc{{Name: v, PID: 7}}},
			"chain identity": {Decision: Blocked, Target: "ssh:k", Chain: []Proc{{Name: "p", PID: 7, Identity: v}}},
			"receiver argv0": {Decision: Blocked, Target: "ssh:k", Receiver: []string{v, "a"}},
			"receiver arg":   {Decision: Blocked, Target: "ssh:k", Receiver: []string{"prog", v}},
		} {
			for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
				line := Formatter{Args: mode}.Format(e)
				checkLineClean(t, line)
				f, err := ParseLine(line)
				if err != nil {
					t.Errorf("%s=%q mode %s: ParseLine(%q): %v", name, v, mode, line, err)
					continue
				}
				if f["decision"] != "blocked" || f["target"] != "ssh:k" {
					t.Errorf("%s=%q mode %s forged fields: %v", name, v, mode, f)
				}
				for k := range f {
					switch k {
					case "decision", "target", "chain", "receiver":
					default:
						t.Errorf("%s=%q mode %s injected field %q in %q", name, v, mode, k, line)
					}
				}
			}
		}
	}
}

// chainForgeries are process names and signing identities (both caller
// controlled: the executable's file name, or a self-signed identity) that try
// to read as extra chain elements, a PID, a signed identity or an elision.
var chainForgeries = []string{
	"a(1) > claude(2, T:x)",
	"claude(4188, Q6L2SF6YDW:com.anthropic.claude-code) > sh",
	"bash(4120) > claude(4188, Q6L2SF6YDW:com.anthropic.claude-code) > ssh",
	"T:a) > claude(2, Q6L2SF6YDW:com.anthropic.claude-code",
	"x) > y(1",
	"x(1)",
	"x, Q6L2SF6YDW:com.anthropic.claude-code",
	", Q6L2SF6YDW:com.anthropic.claude-code",
	"…+3",
	"a > …+1 > b",
	"(1)",
	")",
	"(",
	",",
	">",
	" > ",
}

// A forged name must never add, remove or sign a chain element: the chain
// value has exactly one " > "-separated element per Proc, and ParseChain
// returns the original chain.
func TestChainNamesCannotForgeElements(t *testing.T) {
	const signed = "Q6L2SF6YDW:com.anthropic.claude-code"
	vals := append(append([]string(nil), forgeries...), chainForgeries...)
	for _, v := range vals {
		for pos, chain := range map[string][]Proc{
			"name":     {{Name: "bash", PID: 4120}, {Name: v, PID: 7}, {Name: "ssh", PID: 9}},
			"identity": {{Name: "bash", PID: 4120}, {Name: "p", PID: 7, Identity: v}, {Name: "ssh", PID: 9}},
			"both":     {{Name: v, PID: 1, Identity: v}},
		} {
			line := Formatter{}.Format(Event{Decision: Blocked, Target: "ssh:k", Chain: chain})
			checkLineClean(t, line)
			f, err := ParseLine(line)
			if err != nil {
				t.Fatalf("%s=%q: ParseLine(%q): %v", pos, v, line, err)
			}
			elems := strings.Split(f["chain"], " > ")
			if len(elems) != len(chain) {
				t.Errorf("%s=%q: %d elements in chain %q, want %d", pos, v, len(elems), f["chain"], len(chain))
			}
			for i, el := range elems {
				if i < len(chain) && !strings.HasPrefix(el, `"`) && !strings.HasPrefix(el, chain[i].Name+"(") {
					t.Errorf("%s=%q: element %d %q is neither quoted nor %s(...)", pos, v, i, el, chain[i].Name)
				}
			}
			// The signed Claude element must appear only when it is real.
			if strings.Contains(f["chain"], "> claude(4188, "+signed+")") || strings.HasPrefix(f["chain"], "claude(4188, "+signed+")") {
				t.Errorf("%s=%q: forged signed element in chain %q", pos, v, f["chain"])
			}
			got, err := ParseChain(f["chain"])
			if err != nil {
				t.Fatalf("%s=%q: ParseChain(%q): %v", pos, v, f["chain"], err)
			}
			if len(got) != len(chain) {
				t.Fatalf("%s=%q: ParseChain = %v, want %v (chain %q)", pos, v, got, chain, f["chain"])
			}
			for i := range chain {
				if got[i].PID != chain[i].PID || !sameOrClipped(got[i].Name, chain[i].Name) || !sameOrClipped(got[i].Identity, chain[i].Identity) {
					t.Errorf("%s=%q: element %d = %v, want %v (chain %q)", pos, v, i, got[i], chain[i], f["chain"])
				}
			}
		}
	}
}

// sameOrClipped reports whether got is want, or want shortened by clip:
// a prefix of want plus "…+N" with N the bytes dropped.
func sameOrClipped(got, want string) bool {
	if got == want {
		return true
	}
	i := strings.LastIndex(got, Clipped)
	if i < 0 {
		return false
	}
	n, err := strconv.Atoi(got[i+len(Clipped):])
	return err == nil && strings.HasPrefix(want, got[:i]) && len(want)-i == n
}

func TestFormatChainQuotesUnsafeComponents(t *testing.T) {
	cases := []struct {
		chain []Proc
		want  string
	}{
		{[]Proc{{Name: "Code Helper (Plugin)", PID: 7}}, `"Code Helper (Plugin)"(7)`},
		{[]Proc{{Name: "a > b", PID: 7}}, `"a \x3e b"(7)`},
		{[]Proc{{Name: "bash", PID: 1}, {Name: "claude(4188, Q6L2SF6YDW:com.anthropic.claude-code) > sh", PID: 666}},
			`bash(1) > "claude(4188, Q6L2SF6YDW:com.anthropic.claude-code) \x3e sh"(666)`},
		{[]Proc{{Name: "p", PID: 7, Identity: "T:a) > claude(2, Q6L2SF6YDW:com.anthropic.claude-code"}},
			`p(7, "T:a) \x3e claude(2, Q6L2SF6YDW:com.anthropic.claude-code")`},
		{[]Proc{{Name: "p", PID: 7, Identity: "lower:case"}}, `p(7, "lower:case")`},
		{[]Proc{{Name: "", PID: 7}}, `""(7)`},
		{[]Proc{{Name: "my_tool-1.2+x", PID: 7, Identity: "ABC123:com.x-y_z.T"}}, `my_tool-1.2+x(7, ABC123:com.x-y_z.T)`},
		{[]Proc{{Name: "a b", PID: 7, Identity: "ABC123:com.x y"}}, `"a b"(7, "ABC123:com.x y")`},
		// Non-ASCII is escaped, never shown: a blank-looking or look-alike
		// rune cannot make a name read as another, nor two quoted names
		// read as one ("claudeㅤ" vs "claude").
		{[]Proc{{Name: "claude\u3164", PID: 1}}, `"claude\u3164"(1)`},
		{[]Proc{{Name: "claude\u2800", PID: 1, Identity: "Q6L2SF6YDW:com.anthropic.claude-code\u2800"}},
			`"claude\u2800"(1, "Q6L2SF6YDW:com.anthropic.claude-code\u2800")`},
		{[]Proc{{Name: "\u0441laude", PID: 1}}, `"\u0441laude"(1)`},
		{[]Proc{{Name: "caf\u00e9", PID: 1}}, `"caf\u00e9"(1)`},
		{[]Proc{{Name: "\xff", PID: 1}}, `"\xff"(1)`},
	}
	for _, c := range cases {
		for _, r := range strings.ReplaceAll(c.want, Clipped, "") {
			if r < 0x20 || r > 0x7e {
				t.Fatalf("test case %q itself expects a raw non-ASCII rune %U", c.want, r)
			}
		}
	}
	for _, c := range cases {
		f, err := ParseLine(Formatter{}.Format(Event{Decision: Denied, Chain: c.chain}))
		if err != nil {
			t.Fatal(err)
		}
		if f["chain"] != c.want {
			t.Errorf("chain %v = %q, want %q", c.chain, f["chain"], c.want)
		}
		got, err := ParseChain(f["chain"])
		if err != nil || fmt.Sprint(got) != fmt.Sprint(c.chain) {
			t.Errorf("ParseChain(%q) = %v, %v; want %v", f["chain"], got, err, c.chain)
		}
	}
}

func TestParseChain(t *testing.T) {
	f, err := ParseLine(Formatter{Home: "/Users/u"}.Format(spec))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseChain(f["chain"])
	if err != nil || fmt.Sprint(got) != fmt.Sprint(spec.Chain) {
		t.Fatalf("ParseChain(%q) = %v, %v", f["chain"], got, err)
	}
	if got, err := ParseChain(""); err != nil || len(got) != 0 {
		t.Fatalf("ParseChain(\"\") = %v, %v", got, err)
	}
	// Elided elements are skipped.
	got, err = ParseChain("bash(1) > …+3 > ssh(9)")
	if err != nil || fmt.Sprint(got) != fmt.Sprint([]Proc{{Name: "bash", PID: 1}, {Name: "ssh", PID: 9}}) {
		t.Fatalf("elided chain: %v, %v", got, err)
	}
	for _, bad := range []string{
		"x", "x(", "x()", "x(a)", "x(1", "x(1) >", "x(1)>y(2)", "x(1) > ", " > x(1)", "x(1) y(2)",
		"x(1, )", "x(1, t:x)", "x(1,T:x)", "x(1, T:x", "x(1)(2)", `"x(1)`, `"x"`, `"x"(1)z`, "x(-1)", "(1)", "…+x", "…+1x",
		"x(1, \"T:a\" )", `x(1, "T:a")y`, "ü(1)", "x y(1)",
	} {
		if got, err := ParseChain(bad); err == nil {
			t.Errorf("ParseChain(%q) = %v, want error", bad, got)
		}
	}
}

// The chain's drop order is fixed and attacker-independent: innermost and
// outermost first, then signed elements outermost first, then unsigned ones
// outermost first, with each dropped run marked in place. So an unsigned
// shell between the root and the signed caller goes before the signed
// caller, and a caller's own padding goes before anything outside it.
func TestFormatChainDropOrder(t *testing.T) {
	chain := []Proc{{Name: "bash", PID: 1}, {Name: "zsh", PID: 2}, {Name: "claude", PID: 3, Identity: "T:c"},
		{Name: "x", PID: 4}, {Name: "y", PID: 5}, {Name: "z", PID: 6}, {Name: "ssh", PID: 7}}
	full := "bash(1) > zsh(2) > claude(3, T:c) > x(4) > y(5) > z(6) > ssh(7)"
	for _, c := range []struct {
		limit int
		want  string
	}{
		{1000, full},
		{len(full) + 2, full},
		{len(full) + 1, "bash(1) > zsh(2) > claude(3, T:c) > x(4) > …+2 > ssh(7)"},
		{52, "bash(1) > zsh(2) > claude(3, T:c) > …+3 > ssh(7)"},
		{51, "bash(1) > …+1 > claude(3, T:c) > …+3 > ssh(7)"}, // the unsigned shell goes before the signed caller
		{26, "bash(1) > …+5 > ssh(7)"},
		{25, "…+6 > ssh(7)"},
		{15, "…+7"},
		{0, "…+7"},
	} {
		got := formatChain(chain, c.limit)
		if got != c.want {
			t.Errorf("formatChain(limit %d) = %q, want %q", c.limit, got, c.want)
		}
		if len(quote(got)) > c.limit && got != clipMarker(len(chain)) {
			t.Errorf("formatChain(limit %d) = %q: %d bytes quoted", c.limit, got, len(quote(got)))
		}
		if _, err := ParseChain(got); err != nil {
			t.Errorf("ParseChain(%q): %v", got, err)
		}
	}
	// A caller's own signed padding (inside the matched element) is dropped
	// before the matched element and before anything outside the caller.
	inner := []Proc{{Name: "bash", PID: 1}, {Name: "claude", PID: 3, Identity: "T:c"},
		{Name: "evil", PID: 4, Identity: "E:e"}, {Name: "evil", PID: 5, Identity: "E:e"}, {Name: "ssh", PID: 7}}
	if got, want := formatChain(inner, 43), "bash(1) > claude(3, T:c) > …+2 > ssh(7)"; got != want {
		t.Errorf("formatChain(inner, 43) = %q, want %q", got, want)
	}
	if got, want := formatChain(inner, 42), "bash(1) > …+3 > ssh(7)"; got != want {
		t.Errorf("formatChain(inner, 42) = %q, want %q", got, want)
	}
}

// Whatever the chain and the budget, the rendering fits (or is the bare
// marker), parses, keeps the elements in order, and keeps the innermost
// element whenever it keeps anything.
func TestFormatChainBudget(t *testing.T) {
	long := strings.Repeat("n", 100)
	chains := [][]Proc{
		{{Name: "a", PID: 1}},
		{{Name: "a", PID: 1}, {Name: "b", PID: 2}},
		{{Name: "a", PID: 1}, {Name: "b", PID: 2, Identity: "T:b"}, {Name: "c", PID: 3}},
		{{Name: long, PID: 1, Identity: "T:" + long}, {Name: "b", PID: 2}, {Name: long, PID: 3, Identity: "T:" + long}},
		{{Name: "a b", PID: 1}, {Name: `"`, PID: 2, Identity: "T:x > y"}, {Name: "…+1", PID: 3}, {Name: "d", PID: 4}},
	}
	for i := 0; i < 12; i++ {
		chains[2] = append(chains[2], Proc{Name: fmt.Sprintf("p%d", i), PID: 10 + i, Identity: map[bool]string{true: "T:s", false: ""}[i%3 == 0]})
	}
	for _, chain := range chains {
		full := formatChain(chain, 1<<20)
		for limit := len(full) + 4; limit >= 0; limit-- {
			got := formatChain(chain, limit)
			if len(quote(got)) > limit && got != clipMarker(len(chain)) {
				t.Fatalf("formatChain(%v, %d) = %q: %d bytes quoted", chain, limit, got, len(quote(got)))
			}
			procs, err := ParseChain(got)
			if err != nil {
				t.Fatalf("ParseChain(%q): %v", got, err)
			}
			j := 0
			for _, p := range procs {
				for j < len(chain) && chain[j].PID != p.PID {
					j++
				}
				if j == len(chain) {
					t.Fatalf("formatChain(%v, %d) = %q: elements out of order or invented", chain, limit, got)
				}
				j++
			}
			if len(procs) > 0 && procs[len(procs)-1].PID != chain[len(chain)-1].PID {
				t.Fatalf("formatChain(%v, %d) = %q: innermost element lost", chain, limit, got)
			}
			if n := strings.Count(got, Clipped); n > 0 {
				dropped := 0
				for _, el := range strings.Split(got, " > ") {
					if strings.HasPrefix(el, Clipped) {
						d, err := strconv.Atoi(el[len(Clipped):])
						if err != nil {
							t.Fatalf("formatChain(%v, %d) = %q: bad marker %q", chain, limit, got, el)
						}
						dropped += d
					}
				}
				if dropped+len(procs) != len(chain) {
					t.Fatalf("formatChain(%v, %d) = %q: %d kept + %d dropped != %d", chain, limit, got, len(procs), dropped, len(chain))
				}
			}
		}
	}
}

// Pinned against the round-1 review: a caller with code execution inside
// the approved session cannot make its own entry omit the signed element a
// rule matched on by padding the chain inside it with long, self-signed
// elements. The review's probe (one shell between the root and the signed
// caller, three 200-byte attacker elements, a long-named receiver) and a
// later 4 x (64-byte name + 64-byte identity) variant both keep
// claude(4188, Q6L2SF6YDW:com.anthropic.claude-code), the root and the
// innermost element, in both Args modes.
func TestChainKeepsMatchedSignedElementUnderPadding(t *testing.T) {
	claude := Proc{Name: "claude", PID: 4188, Identity: "Q6L2SF6YDW:com.anthropic.claude-code"}
	pad := func(n, size int, pid int) []Proc {
		var out []Proc
		for i := 0; i < n; i++ {
			out = append(out, Proc{Name: strings.Repeat("n", size), PID: pid + i, Identity: "ZZZZZZZZZZ:" + strings.Repeat("i", size)})
		}
		return out
	}
	for name, chain := range map[string][]Proc{
		"probe":  append(append([]Proc{{Name: "bash", PID: 4120}, {Name: "zsh", PID: 4121}, claude}, pad(3, 200, 5001)...), Proc{Name: strings.Repeat("s", 200), PID: 6000, Identity: "ZZZZZZZZZZ:" + strings.Repeat("s", 200)}),
		"review": append(append([]Proc{{Name: "bash", PID: 4120}, {Name: "zsh", PID: 4121}, claude}, pad(4, 64, 5001)...), Proc{Name: strings.Repeat("s", 300), PID: 6000}),
		"deep":   append(append([]Proc{{Name: "bash", PID: 4120}, {Name: "zsh", PID: 4121}, {Name: "tmux", PID: 4122}, {Name: "zsh", PID: 4123}, claude}, pad(40, 64, 5001)...), Proc{Name: "ssh", PID: 6000}),
	} {
		for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
			e := Event{Decision: Allowed, Reason: "cached approval", Target: "ssh:github", Destination: "github.com", Rule: "1",
				Scope: "session", Gate: "dialog", App: "com.googlecode.iterm2", Session: "4120@1791072112", Chain: chain,
				Receiver: []string{"/usr/bin/" + strings.Repeat("s", 200), "git@github.com"}, Cwd: "/Users/u/projects/foo"}
			line := Formatter{Args: mode, Home: "/Users/u"}.Format(e)
			if len(line) > MaxLine {
				t.Fatalf("%s/%s: line is %d bytes", name, mode, len(line))
			}
			f, err := ParseLine(line)
			if err != nil {
				t.Fatalf("%s/%s: ParseLine(%q): %v", name, mode, line, err)
			}
			if !strings.Contains(f["chain"], "> claude(4188, Q6L2SF6YDW:com.anthropic.claude-code) >") {
				t.Errorf("%s/%s: the matched signed element is missing from chain %q", name, mode, f["chain"])
			}
			procs, err := ParseChain(f["chain"])
			if err != nil {
				t.Fatalf("%s/%s: ParseChain(%q): %v", name, mode, f["chain"], err)
			}
			found := false
			for _, p := range procs {
				found = found || p == claude
			}
			if !found {
				t.Errorf("%s/%s: ParseChain(%q) = %v lacks %v", name, mode, f["chain"], procs, claude)
			}
			if procs[0].PID != 4120 || procs[len(procs)-1].PID != 6000 {
				t.Errorf("%s/%s: root or innermost element lost from %q", name, mode, f["chain"])
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Line length: the unified log keeps ~1015 bytes of a message, so a caller
// must not be able to make its own entry unparseable with a long argv, cwd
// or process name.

func TestFormatLineIsBounded(t *testing.T) {
	argv := []string{"/usr/bin/ssh", strings.Repeat("a", 1<<20), "git@github.com"}
	for i := 0; i < 2000; i++ {
		argv = append(argv, "x")
	}
	var chain []Proc
	for i := 0; i < 50; i++ {
		chain = append(chain, Proc{Name: strings.Repeat("n", 300) + fmt.Sprint(i), PID: 1000 + i, Identity: "T" + fmt.Sprint(i) + ":" + strings.Repeat("i", 300)})
	}
	e := Event{
		Decision: Blocked, Reason: "no rule matched", Target: "ssh:github", Destination: strings.Repeat("h", 5000),
		Operation: strings.Repeat("o", 5000), Rule: "fallback", Scope: "session", Gate: "block",
		App: "com.googlecode.iterm2", Session: "4120@1791072112", Chain: chain, Receiver: argv,
		Cwd: "/Users/u/" + strings.Repeat("d", 1015),
	}
	for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
		line := Formatter{Args: mode, Home: "/Users/u"}.Format(e)
		if len(line) > MaxLine {
			t.Fatalf("mode %s: line is %d bytes, want <= %d", mode, len(line), MaxLine)
		}
		checkLineClean(t, line)
		f, err := ParseLine(line)
		if err != nil {
			t.Fatalf("mode %s: ParseLine(%q): %v", mode, line, err)
		}
		for k, want := range map[string]string{
			"decision": "blocked", "reason": "no rule matched", "target": "ssh:github", "rule": "fallback",
			"scope": "session", "gate": "block", "app": "com.googlecode.iterm2", "session": "4120@1791072112",
		} {
			if f[k] != want {
				t.Errorf("mode %s: %s = %q, want %q", mode, k, f[k], want)
			}
		}
		for _, k := range []string{"destination", "operation", "chain", "receiver", "cwd"} {
			if f[k] == "" {
				t.Errorf("mode %s: %s missing from %q", mode, k, line)
			}
			if !strings.Contains(f[k], Clipped) {
				t.Errorf("mode %s: %s = %q has no clip marker", mode, k, f[k])
			}
		}
		if mode == ArgsNone && f["receiver"] != "ssh …+2002" {
			t.Errorf("mode none: receiver = %q, want %q", f["receiver"], "ssh …+2002")
		}
		if mode == ArgsRedacted && !strings.HasPrefix(f["receiver"], "ssh … … x x ") {
			t.Errorf("mode %s: receiver %q lost the program or kept a non-plain argument", mode, f["receiver"])
		}
		if !strings.HasPrefix(f["cwd"], "~/ddd") {
			t.Errorf("mode %s: cwd %q", mode, f["cwd"])
		}
		procs, err := ParseChain(f["chain"])
		if err != nil {
			t.Fatalf("mode %s: ParseChain(%q): %v", mode, f["chain"], err)
		}
		if len(procs) == 0 || procs[len(procs)-1].PID != 1049 {
			t.Errorf("mode %s: innermost caller lost from chain %q", mode, f["chain"])
		}
	}
	// A normal entry is never clipped.
	if line := (Formatter{Home: "/Users/u"}).Format(spec); strings.Contains(line, Clipped) {
		t.Fatalf("spec entry clipped: %q", line)
	}
}

func TestFormatClipsEachCallerField(t *testing.T) {
	long := strings.Repeat("ü", 2000)
	e := Event{Decision: Blocked, Reason: long, Target: long, Destination: long, Operation: long, Rule: long, Scope: long,
		Gate: long, App: long, Session: long, Chain: []Proc{{Name: long, PID: 1, Identity: long}}, Receiver: []string{long, long}, Cwd: long}
	line := Formatter{}.Format(e)
	if len(line) > MaxLine {
		t.Fatalf("line is %d bytes", len(line))
	}
	f, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range f {
		if k != "decision" && (!utf8.ValidString(v) || !strings.Contains(v, Clipped)) {
			t.Errorf("%s = %q: not clipped, or cut inside a rune", k, v)
		}
	}
	// Fields that are never shortened to fit the line keep their budget;
	// with every other field at its cap the squeezable ones may be reduced
	// to a bare marker, but they are still there.
	for _, k := range []string{"reason", "target", "rule", "scope", "gate", "app", "session"} {
		if !strings.HasPrefix(f[k], "üü") {
			t.Errorf("%s = %q: shortened below its budget", k, f[k])
		}
	}
	for _, k := range []string{"destination", "operation", "chain", "receiver", "cwd"} {
		if f[k] == "" {
			t.Errorf("%s dropped", k)
		}
	}
}

func TestReceiverDropsWholeArguments(t *testing.T) {
	argv := []string{"prog"}
	for i := 0; i < 300; i++ {
		argv = append(argv, fmt.Sprintf("arg%03d", i))
	}
	f, err := ParseLine(Formatter{}.Format(Event{Decision: Denied, Receiver: argv}))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(f["receiver"], " ")
	last := parts[len(parts)-1]
	if !strings.HasPrefix(last, Clipped) {
		t.Fatalf("receiver %q does not end with a marker", f["receiver"])
	}
	dropped, err := strconv.Atoi(strings.TrimPrefix(last, Clipped))
	if err != nil || len(parts)-1+dropped != len(argv) {
		t.Fatalf("kept %d + dropped %d != %d args (%v)", len(parts)-1, dropped, len(argv), err)
	}
	for i, p := range parts[:len(parts)-1] {
		if p != argv[i] {
			t.Fatalf("argument %d = %q, want %q", i, p, argv[i])
		}
	}
	if len(quote(f["receiver"])) > maxReceiver {
		t.Fatalf("receiver value is %d bytes", len(quote(f["receiver"])))
	}
}

func TestReceiverLongArgumentIsElidedLongProgramClipped(t *testing.T) {
	argv := []string{"ssh", strings.Repeat("a", 2000), "git@github.com", "-v"}
	f, err := ParseLine(Formatter{}.Format(Event{Decision: Blocked, Receiver: argv}))
	if err != nil {
		t.Fatal(err)
	}
	if f["receiver"] != "ssh … … -v" {
		t.Fatalf("receiver = %q: want every non-plain argument elided whole, never clipped", f["receiver"])
	}
	// A long program name (caller controlled) is clipped before it is
	// quoted, so the quoted text stays balanced and the arguments survive.
	for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
		argv = []string{"/x/a " + strings.Repeat("b", 2000), "-c", "x"}
		f, err = ParseLine(Formatter{Args: mode}.Format(Event{Decision: Blocked, Receiver: argv}))
		if err != nil {
			t.Fatal(err)
		}
		prog, err := strconv.QuotedPrefix(f["receiver"])
		if err != nil || !strings.HasPrefix(prog, `"a bbbb`) || len(prog) > maxArg {
			t.Fatalf("mode %s: receiver = %q: program not clipped and quoted (%v)", mode, f["receiver"], err)
		}
		if want := map[ArgsMode]string{ArgsRedacted: " -c x", ArgsNone: " …+2"}[mode]; f["receiver"] != prog+want {
			t.Fatalf("mode %s: receiver = %q, want %q", mode, f["receiver"], prog+want)
		}
	}
}

func TestClip(t *testing.T) {
	for _, c := range []struct {
		in    string
		limit int
		want  string
	}{
		{"short", 100, "short"},
		{"abcdefghij", 10, "abcdefghij"}, // bare values are not expanded by quoting
		{"abcde fghij", 13, "abcde fghij"},
		{"abcde fghij", 12, "abcde…+6"},
		// A non-ASCII rune costs its escape (ü, 6 bytes), the marker's
		// ellipsis stays raw (3 bytes).
		{"üüüüü", 32, "üüüüü"},
		{"üüüüü", 31, "üüüü…+2"},
		{"üüüüü", 13, "ü…+8"},
		{"üüüüü", 12, "…+10"},
		{"aüaüaüaü", 21, "aüaü…+6"},
		{"aüaüaüaü", 15, "aüa…+8"},
		{"aüaüaüaü", 14, "aü…+9"},
		{"aaaa\xc3\xa9bbbb", 11, "aaaa…+6"}, // é is 2 bytes; a half é would quote as \xc3
		{"a…b…c", 11, "a…b…c"},              // a caller's ellipsis is raw and costs 3
		{"a…b…cdef", 13, "a…b…+7"},
		{"a…b…c", 10, "a…+8"},
		{"\xff\xff\xff\xff\xff", 14, "\xff…+4"},
		{"abc", 0, "…+3"},
		{"abc", -5, "…+3"},
	} {
		got := clip(c.in, c.limit, quote)
		if got != c.want {
			t.Errorf("clip(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
		if len(quote(got)) > c.limit && got != clipMarker(len(c.in)) {
			t.Errorf("clip(%q, %d) = %q: %d bytes quoted", c.in, c.limit, got, len(quote(got)))
		}
		if !utf8.ValidString(got) && utf8.ValidString(c.in) {
			t.Errorf("clip(%q, %d) = %q: invalid UTF-8", c.in, c.limit, got)
		}
	}
}

// ---------------------------------------------------------------------------
// audit.args: redacted (default) or none; never a full command line

func TestArgsNoneKeepsOnlyProgramAndCount(t *testing.T) {
	line := Formatter{Args: ArgsNone}.Format(Event{Decision: Denied, Receiver: []string{"/usr/bin/curl", "-H", "X: 1", "https://x"}})
	if strings.Contains(line, "https") || strings.Contains(line, "X: 1") || strings.Contains(line, "-H") {
		t.Fatalf("got %q", line)
	}
	f, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if f["receiver"] != "curl …+3" {
		t.Fatalf("receiver = %q, want %q (base name plus argument count)", f["receiver"], "curl …+3")
	}
	// No arguments: no count.
	f, err = ParseLine(Formatter{Args: ArgsNone}.Format(Event{Decision: Denied, Receiver: []string{"/usr/bin/curl"}}))
	if err != nil || f["receiver"] != "curl" {
		t.Fatalf("receiver = %q, %v, want curl", f["receiver"], err)
	}
}

func TestArgsNoneProgramWithSpacesIsQuoted(t *testing.T) {
	f, err := ParseLine(Formatter{Args: ArgsNone}.Format(Event{Decision: Denied, Receiver: []string{"/Applications/My App.app/Contents/MacOS/My Tool", "--x"}}))
	if err != nil {
		t.Fatal(err)
	}
	if f["receiver"] != `"My Tool" …+1` {
		t.Fatalf("receiver = %q, want %q", f["receiver"], `"My Tool" …+1`)
	}
}

// A crafted argv[0] must never read as a different command line, to a
// parser or to a person reading Console.app: in every mode the program name
// is bare only when it is a plain word and otherwise quoted with every
// non-ASCII rune escaped, so what a real `ssh git@github.com` logs and what
// a program called "ssh git@github.com" (or "ssh …", "ssh …+1", "ssh⠀…+3"
// with a braille blank, or "ѕѕh" in Cyrillic) logs are visibly distinct.
func TestProgramNameCannotImpersonateACommand(t *testing.T) {
	for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
		recv := func(argv ...string) string {
			t.Helper()
			line := Formatter{Args: mode}.Format(Event{Decision: Allowed, Target: "ssh:k", Receiver: argv})
			checkLineClean(t, line)
			f, err := ParseLine(line)
			if err != nil {
				t.Fatalf("mode %s: ParseLine(%q): %v", mode, line, err)
			}
			checkReceiverASCII(t, f["receiver"])
			return f["receiver"]
		}
		reals := map[string]string{
			"ssh git@github.com": recv("ssh", "git@github.com"),
			"ssh a b c":          recv("ssh", "a", "b", "c"),
			"x a":                recv("x", "a"),
		}
		for _, forged := range [][]string{
			{"ssh git@github.com"},
			{"/usr/bin/ssh git@github.com"},
			{"ssh …"},
			{"ssh …+1"},
			{"ssh …"},
			{"ssh\tgit@github.com"},
			{"ssh git@github.com"},
			{"ssh git@github.com", "x"},
			{`ssh "git@github.com"`},
			{"ssh", "git@github.com", "…+1"},
			// Blank-looking and look-alike runes: U+2800 braille blank,
			// U+3164 Hangul filler, U+00A0 no-break space, Cyrillic ѕ,
			// fullwidth full stop, zero-width space.
			{"ssh⠀github.com"},
			{"sshㅤgithub.com"},
			{"ssh⠀…+3"},
			{"sshㅤ…+3"},
			{"ssh⠀a b c"},
			{"ѕѕh", "git@github.com"},
			{"ssh．git@github.com"},
			{"ssh​git@github.com"},
			// The markers Format adds, and separators, inside a program name.
			{"…", "x"},
			{"…+1"},
			{"x…+1", "a"},
			{"x …+1"},
			{"ssh=x", "a"},
			{"ssh:x", "a"},
			{"ssh@x", "a"},
			{"ssh+x", "a"},
			{"x…", "a"},
		} {
			got := recv(forged...)
			for name, real := range reals {
				if got == real {
					t.Errorf("mode %s: forged argv %q logs as %q, same as the real `%s`", mode, forged, got, name)
				}
			}
			// Every rendering is either a bare plain word or Go-quoted, and
			// a quoted program never contains an unescaped quote or a space
			// outside it.
			prog := got
			if strings.HasPrefix(got, `"`) {
				q, err := strconv.QuotedPrefix(got)
				if err != nil {
					t.Fatalf("mode %s: program %q not quoted as a prefix: %v", mode, got, err)
				}
				prog = q
			} else if i := strings.IndexByte(got, ' '); i >= 0 {
				prog = got[:i]
			}
			if !strings.HasPrefix(prog, `"`) && !PlainWord(prog) {
				t.Errorf("mode %s: program %q is neither quoted nor a plain word", mode, prog)
			}
			if !PlainWord(Program(forged[0])) && !strings.HasPrefix(prog, `"`) {
				t.Errorf("mode %s: program %q of %q is not a plain word but is bare", mode, prog, forged)
			}
		}
	}
}

// checkReceiverASCII checks that a receiver value is printable ASCII apart
// from the markers Format adds itself (Elided and Clipped): a caller's
// non-ASCII rune is always escaped, never shown.
func checkReceiverASCII(t *testing.T, recv string) {
	t.Helper()
	for _, r := range strings.ReplaceAll(recv, "…", "") {
		if r < 0x20 || r > 0x7e {
			t.Errorf("receiver %q shows a caller's rune %U unescaped", recv, r)
		}
	}
}

// Under both modes a program name with a non-ASCII rune is escaped
// (\uXXXX) rather than shown, so a look-alike cannot pass for ASCII.
func TestProgramNonASCIIIsEscaped(t *testing.T) {
	for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
		for _, c := range []struct{ argv0, want string }{
			{"ssh\u2800github.com", `"ssh\u2800github.com"`},
			{"\u0455\u0455h", `"\u0455\u0455h"`},
			{"ssh\u3164\u2026+3", `"ssh\u3164\u2026+3"`},
			{"caf\u00e9", `"caf\u00e9"`},
			{"\u65e5\u672c", `"\u65e5\u672c"`},
			{"\xff\xfe", `"\xff\xfe"`},
			{"my tool", `"my tool"`},
			{"ssh", "ssh"},
		} {
			f, err := ParseLine(Formatter{Args: mode}.Format(Event{Decision: Denied, Receiver: []string{"/x/" + c.argv0}}))
			if err != nil {
				t.Fatal(err)
			}
			if f["receiver"] != c.want {
				t.Errorf("mode %s: argv0 %q: receiver = %q, want %q", mode, c.argv0, f["receiver"], c.want)
			}
		}
	}
}

func TestReceiverIsAlwaysRedactedUnlessNone(t *testing.T) {
	const secret = "S3cr3t+Value/1234567890123456789012"
	argv := []string{"/usr/bin/tool", "--token=" + secret, "--password", secret, "https://u:" + secret + "@h/x", "-u", "alice:hunter2"}
	// Zero value, explicit redacted, and any unknown mode must all redact:
	// a full, unredacted command line is never logged.
	for _, mode := range []ArgsMode{"", ArgsRedacted, "full", "unredacted", "NONE"} {
		line := Formatter{Args: mode}.Format(Event{Decision: Approved, Receiver: argv})
		if strings.Contains(line, secret) || strings.Contains(line, "hunter2") || strings.Contains(line, "https") {
			t.Errorf("mode %q leaked the secret: %q", mode, line)
		}
		f, err := ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if f["receiver"] != "tool … --password … … -u …" {
			t.Errorf("mode %q: receiver = %q", mode, f["receiver"])
		}
	}
}

func TestReceiverEmptyArgumentIsElided(t *testing.T) {
	f, err := ParseLine(Formatter{}.Format(Event{Decision: Denied, Receiver: []string{"printf", ""}}))
	if err != nil {
		t.Fatal(err)
	}
	if f["receiver"] != "printf …" {
		t.Fatalf("receiver = %q, want %q", f["receiver"], "printf …")
	}
}

// ---------------------------------------------------------------------------
// RedactArgs: an allowlist of plain words (spec 4.6)

func TestConstantsRedaction(t *testing.T) {
	if Elided != "…" || MaxWord != 32 {
		t.Fatalf("Elided = %q, MaxWord = %d", Elided, MaxWord)
	}
	if PlainWord(Elided) || PlainWord(Clipped+"1") {
		t.Fatal("the markers must not be plain words, or a caller could forge them")
	}
}

func TestPlainWord(t *testing.T) {
	yes := []string{
		"a", "main", "origin", "pods", "prod", "2222", "8h", "v1.2.3", "file.txt", "/tmp", "/dev/null",
		"/usr/local/bin/kubectl", "path/to/x", "snake_case", "kebab-case", "a.b-c_d/e",
		"-v", "-n", "-1", "-T", "--", "--force", "--dry-run", "--no_color", "--j8", "--a-b_c-1",
		strings.Repeat("a", 32), "--" + strings.Repeat("a", 30),
	}
	no := []string{
		"", " ", "a b", " a", "a ", "a\tb", "a\nb",
		"--flag=value", "key=value", "=", "a=", "=a",
		"git@github.com", "@scope/pkg", "@",
		"alice:hunter2", "localhost:8080", "https://x.com", "ssh:github", ":",
		"https://x.com/?token=a", "a?b", "a&b", "?", "&",
		`"quoted"`, "'q'", `a"b`, "a'b", "`a`",
		"$HOME", "a;b", "a|b", "a>b", "a<b", "a*", "~", "~/x", "%41", "a\\b", "(a)", "[a]", "{a}", "a,b", "a+b", "#", "!",
		"-F/dev/null", "-ofile.txt", "--log.level", "-/", "--a/b",
		// A short option with anything glued to it may be a value: -pSECRET.
		"-la", "-rf", "-it", "-j8", "-p2222", "-pSup3rSecretValue", "-phunter2", "-race", "-count",
		"-", "---x", "--" + "-x", "--_x", "-_", "--.", "-" + strings.Repeat("a", 31),
		"ü", "é", "…", "…+1", " ", "​", "x\x00y", "\x1b[2K", "日本",
		strings.Repeat("a", 33), "--" + strings.Repeat("a", 31),
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	}
	for _, w := range yes {
		if !PlainWord(w) {
			t.Errorf("PlainWord(%q) = false, want true", w)
		}
	}
	for _, w := range no {
		if PlainWord(w) {
			t.Errorf("PlainWord(%q) = true, want false", w)
		}
	}
}

func TestRedactArgs(t *testing.T) {
	cases := []struct{ in, want []string }{
		// Readable commands stay readable (spec 4.6 examples).
		{[]string{"git", "push", "origin", "main"}, []string{"git", "push", "origin", "main"}},
		{[]string{"kubectl", "get", "pods", "-n", "prod"}, []string{"kubectl", "get", "pods", "-n", "prod"}},
		{[]string{"ls", "-l", "-a", "/tmp"}, []string{"ls", "-l", "-a", "/tmp"}},
		{[]string{"ls", "-la", "/tmp"}, []string{"ls", Elided, "/tmp"}}, // a cluster reads like -pSECRET
		{[]string{"/usr/bin/ssh", "-p", "2222", "git@github.com"}, []string{"ssh", "-p", "2222", Elided}},
		{[]string{"/opt/homebrew/bin/kubectl", "--context=prod", "get", "pods"}, []string{"kubectl", Elided, "get", "pods"}},
		// curl -u alice:… https://… keeps no secret.
		{[]string{"curl", "-u", "alice:hunter2", "https://api.example.com/v1"}, []string{"curl", "-u", Elided, Elided}},
		{[]string{"curl", "-H", "Authorization: Bearer abcdefghijkl", "https://x.com/?client_secret=abc"}, []string{"curl", "-H", Elided, Elided}},
		{[]string{"sh", "-c", "curl -u alice:hunter2 https://x"}, []string{"sh", "-c", Elided}},
		{[]string{"tool", "--token=ghp_abcdefghijklmnop"}, []string{"tool", Elided}},
		{[]string{"env", "GITHUB_TOKEN=abc123", "gh", "auth", "status"}, []string{"env", Elided, "gh", "auth", "status"}},
		{[]string{"git", "clone", "https://user:pa55word@github.com/x.git"}, []string{"git", "clone", Elided}},
		{[]string{"git", "clone", "git@github.com:atas/nazar.git"}, []string{"git", "clone", Elided}},
		{[]string{"npx", "-y", "@brave/brave-search-mcp-server"}, []string{"npx", "-y", Elided}},
		{[]string{"echo", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}, []string{"echo", Elided}},
		{[]string{"printf", "", "x"}, []string{"printf", Elided, "x"}},
		// Flags: bare ones stay, ones carrying a value go.
		{[]string{"ssh", "-F", "/dev/null", "-o", "IdentityAgent=/x", "host"}, []string{"ssh", "-F", "/dev/null", "-o", Elided, "host"}},
		{[]string{"ssh", "-F/dev/null", "host"}, []string{"ssh", Elided, "host"}},
		{[]string{"rm", "-r", "-f", "--", "-weird"}, []string{"rm", "-r", "-f", "--", Elided}},
		{[]string{"mysql", "-u", "root", "-pSup3rSecretValue"}, []string{"mysql", "-u", "root", Elided}},
		{[]string{"sshpass", "-phunter2", "ssh", "host"}, []string{"sshpass", Elided, "ssh", "host"}},
		// Length: 32 is kept, 33 is not.
		{[]string{"x", strings.Repeat("a", 32), strings.Repeat("a", 33)}, []string{"x", strings.Repeat("a", 32), Elided}},
		// The program is its base name, whatever it contains.
		{[]string{"/Applications/My App.app/Contents/MacOS/My Tool"}, []string{"My Tool"}},
		{[]string{"ssh git@github.com", "x"}, []string{"ssh git@github.com", "x"}},
		{[]string{""}, []string{"."}},
	}
	for _, c := range cases {
		got := RedactArgs(c.in)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("RedactArgs(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

// The shapes that defeated pattern-based redaction in review: whatever the
// secret looks like, the argument carrying it is not a plain word and is
// replaced whole. Each case names the secret and the element it rides in.
func TestRedactArgsAttackCases(t *testing.T) {
	const s = "Sup3rSecretValue"
	cases := [][]string{
		{"curl", "-u", "alice:" + s, "https://x.com"},
		{"curl", "--user", "alice:" + s},
		{"curl", "-u", "alice:" + s + "@x"},
		{"curl", "https://x.com/?client_secret=" + s},
		{"curl", "https://x.com/?a=1&token=" + s},
		{"curl", "https://alice:" + s + "@x.com/"},
		{"curl", "https://x.com/" + s + "/hook"},
		{"curl", "https://x.com/cb?next=%2Fapi%3Ftoken%3D" + s},
		{"curl", "-H", "Authorization: Bearer " + s},
		{"curl", "-H", "Authorization:" + s},
		{"curl", "-HAuthorization: " + s},
		{"curl", "--header=X-Api-Key: " + s},
		{"curl", "-H", "Cookie: sid=" + s},
		{"curl", "-d", "password=" + s},
		{"curl", "-d", `{"token":"` + s + `"}`},
		{"sh", "-c", "curl -u alice:" + s + " https://x"},
		{"sh", "-c", "export TOKEN=" + s + "; gh auth login"},
		{"bash", "-lc", "echo " + s + " | gh auth login --with-token"},
		{"zsh", "-c", s + ";"},
		{"tool", "--token=" + s},
		{"tool", "--TOKEN=" + s},
		{"tool", "--api-key=" + s},
		{"tool", "--password=" + s},
		{"tool", "-p" + s + "="},
		{"env", "AWS_SECRET_ACCESS_KEY=" + s, "aws", "s3", "ls"},
		{"env", "PGPASSWORD=" + s, "psql"},
		{"mysql", "-u", "root", "-p" + s},
		{"mysql", "-u", "root", "-p" + s + "!"},
		{"sshpass", "-p" + s, "ssh", "host"},
		{"tool", "-p" + s[:7]}, // a short glued value is still a glued value
		{"tool", "-" + s},
		{"echo", "ghp_" + s + "abcdefghijklmnopqrstuvwxyz"},
		{"echo", "sk-ant-api03-" + s + "-abcdefghijklmnopqrstuvwxyz"},
		{"echo", "AKIA" + s + "0123456789ABCDEFGHIJ"},
		{"echo", "xoxb-123456789012-" + s},
		{"echo", "github_pat_11ABCDEFG" + s},
		{"echo", "'" + s + "'"},
		{"echo", `"` + s + `"`},
		{"echo", s + " "},
		{"echo", " " + s},
		{"echo", s + "\n"},
		{"echo", "$" + s},
		{"echo", s + "@"},
		{"echo", s + "?"},
		{"echo", s + "&"},
		{"echo", s + "="},
		{"echo", s + ":"},
		{"echo", s + "ü"},
		{"echo", s + "…"},
		{"echo", "-" + s + "."},
		{"echo", "--" + s + "/"},
		{"echo", strings.Repeat(s, 3)},
	}
	for _, in := range cases {
		got := RedactArgs(in)
		if len(got) != len(in) {
			t.Errorf("RedactArgs(%q) changed length: %q", in, got)
			continue
		}
		for i := 1; i < len(in); i++ {
			if strings.Contains(in[i], s) && got[i] != Elided {
				t.Errorf("RedactArgs(%q) kept the secret-carrying argument %d: %q", in, i, got[i])
			}
		}
		if strings.Contains(strings.Join(got, "\x00"), s) {
			t.Errorf("RedactArgs(%q) leaked %q: %q", in, s, got)
		}
		line := Formatter{}.Format(Event{Decision: Approved, Receiver: in})
		if strings.Contains(line, s) {
			t.Errorf("Format(%q) leaked %q: %q", in, s, line)
		}
	}
}

// Decided trade-off, pinned so it is not mistaken for a bug: a value that is
// itself a short plain word is kept, flag or no flag, because the allowlist
// does not guess which words are secrets. Real tokens are longer than 32
// characters or carry other characters; a short plain password leaks.
func TestRedactArgsKeepsShortPlainValues(t *testing.T) {
	cases := []struct{ in, want []string }{
		{[]string{"tool", "--api-key", "s3cr3tvalue", "--verbose"}, []string{"tool", "--api-key", "s3cr3tvalue", "--verbose"}},
		{[]string{"tool", "--password", "hunter2"}, []string{"tool", "--password", "hunter2"}},
		{[]string{"tool", "--password", "hunter2!"}, []string{"tool", "--password", Elided}},
		{[]string{"tool", "--password", "correct-horse-battery-staple-1234"}, []string{"tool", "--password", Elided}},
	}
	for _, c := range cases {
		if got := RedactArgs(c.in); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("RedactArgs(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestRedactArgsLeavesPlainCommands(t *testing.T) {
	for _, in := range [][]string{
		{"git", "push", "origin", "main"},
		{"git", "status", "--short", "--branch"},
		{"kubectl", "get", "pods", "-n", "default"},
		{"ls", "-l", "-a", "/tmp"},
		{"make", "-j", "8", "all"},
		{"docker", "run", "--rm", "-i", "-t", "ubuntu"},
		{"tool", "view", "item-12345678"},
		{"open", "annual-report-2024.pdf"},
		{"ssh", "-F", "/dev/null", "-T", "host"},
		{"go", "test", "--race", "./..."},
	} {
		if got := RedactArgs(in); strings.Join(got, "\x00") != strings.Join(in, "\x00") {
			t.Errorf("RedactArgs(%q) = %q, want it unchanged", in, got)
		}
	}
	// Decided trade-off: a short option with anything glued to it is dropped,
	// clusters and Go-style long options included, because -pSECRET looks
	// the same.
	for _, c := range []struct{ in, want []string }{
		{[]string{"ls", "-la", "/tmp"}, []string{"ls", Elided, "/tmp"}},
		{[]string{"make", "-j8", "all"}, []string{"make", Elided, "all"}},
		{[]string{"docker", "run", "--rm", "-it", "ubuntu"}, []string{"docker", "run", "--rm", Elided, "ubuntu"}},
		{[]string{"go", "test", "-race", "-count=1", "./..."}, []string{"go", "test", Elided, Elided, "./..."}},
	} {
		if got := RedactArgs(c.in); strings.Join(got, "\x00") != strings.Join(c.want, "\x00") {
			t.Errorf("RedactArgs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactArgsEdgeCases(t *testing.T) {
	if got := RedactArgs(nil); got != nil {
		t.Fatalf("RedactArgs(nil) = %q", got)
	}
	if got := RedactArgs([]string{}); got != nil {
		t.Fatalf("RedactArgs(empty) = %q", got)
	}
	// Odd input must not panic and keeps argv's length.
	for _, in := range [][]string{{""}, {"", ""}, {"=", "=="}, {"--=", "-"}, {"\xff\xfe", "--token=\xff"}, {"://:@", "?token=", "&"}, {"/", "//", "/."}, {strings.Repeat("a", 1<<20), strings.Repeat("b", 1<<20)}} {
		if got := RedactArgs(in); len(got) != len(in) {
			t.Fatalf("RedactArgs(%q) has %d elements", in, len(got))
		}
	}
}

func TestRedactArgsDoesNotMutateInput(t *testing.T) {
	in := []string{"/usr/bin/tool", "--token=abcdef123", "--password", "abcdef123", "ghp_abcdefgh12345678", "x y"}
	orig := append([]string(nil), in...)
	_ = RedactArgs(in)
	_ = Formatter{}.Format(Event{Decision: Denied, Receiver: in})
	_ = Formatter{Args: ArgsNone}.Format(Event{Decision: Denied, Receiver: in})
	for i := range in {
		if in[i] != orig[i] {
			t.Fatalf("input mutated at %d: %q (was %q)", i, in[i], orig[i])
		}
	}
}

// plainWordRE is an independent statement of the allowlist for the fuzzer:
// 1..32 ASCII characters of [A-Za-z0-9._/-] not starting with '-', or a
// bare flag: one short option, "--", or a long option of at most 32 bytes.
var plainWordRE = regexp.MustCompile(`^(?:[A-Za-z0-9._/][A-Za-z0-9._/-]{0,31}|-[A-Za-z0-9]|--|--[A-Za-z0-9][A-Za-z0-9_-]{0,29})$`)

// Every element of RedactArgs' output is either the input element, which
// then matches the allowlist, or Elided; the program is argv[0]'s base name.
func checkRedacted(t *testing.T, in, got []string) {
	t.Helper()
	if len(got) != len(in) {
		t.Fatalf("RedactArgs(%q) = %q: length changed", in, got)
	}
	if len(in) == 0 {
		return
	}
	if got[0] != filepath.Base(in[0]) {
		t.Fatalf("RedactArgs(%q)[0] = %q, want base name %q", in, got[0], filepath.Base(in[0]))
	}
	for i := 1; i < len(in); i++ {
		switch {
		case got[i] == Elided && !plainWordRE.MatchString(in[i]):
		case got[i] == in[i] && plainWordRE.MatchString(in[i]):
		default:
			t.Fatalf("RedactArgs(%q)[%d] = %q (plain by regexp: %v)", in, i, got[i], plainWordRE.MatchString(in[i]))
		}
		if PlainWord(in[i]) != plainWordRE.MatchString(in[i]) {
			t.Fatalf("PlainWord(%q) = %v disagrees with the allowlist regexp", in[i], PlainWord(in[i]))
		}
	}
}

func FuzzRedactArgs(f *testing.F) {
	f.Add("curl", "-u", "alice:hunter2", "https://x.com/?client_secret=abc")
	f.Add("sh", "-c", "curl -u a:b https://x", "")
	f.Add("/usr/bin/ssh", "-p", "2222", "git@github.com")
	f.Add("git", "push", "origin", "main")
	f.Add("tool", "--token=x", "-F/dev/null", strings.Repeat("a", 33))
	f.Add("ssh git@github.com", "…", "…+1", "\xff")
	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		in := []string{a, b, c, d}
		checkRedacted(t, in, RedactArgs(in))
		for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
			line := Formatter{Args: mode}.Format(Event{Decision: Approved, Target: "ssh:k", Receiver: in})
			checkLineClean(t, line)
			fields, err := ParseLine(line)
			if err != nil || fields["decision"] != "approved" || fields["target"] != "ssh:k" {
				t.Fatalf("mode %s: %q: %v %v", mode, line, fields, err)
			}
			// Four arguments never exceed the receiver budget, so the value
			// is exactly the quoted program plus the allowlisted arguments
			// (redacted) or the argument count (none).
			prog := argQuote(clip(filepath.Base(a), maxArg, argQuote))
			want := prog + " " + clipMarker(3)
			if mode == ArgsRedacted {
				want = prog + " " + strings.Join(RedactArgs(in)[1:], " ")
			}
			if fields["receiver"] != want {
				t.Fatalf("mode %s: receiver %q, want %q", mode, fields["receiver"], want)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// ParseLine (nazar log reads the unified log back)

func TestParseLineRoundTrip(t *testing.T) {
	line := Formatter{Home: "/Users/u"}.Format(spec)
	f, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if f["reason"] != "cached approval" || f["chain"] != "bash(4120) > claude(4188, Q6L2SF6YDW:com.anthropic.claude-code)" || f["cwd"] != "~/projects/foo" {
		t.Fatalf("fields %v", f)
	}
	for _, bad := range []string{"", "nodecision=1", `decision="unterminated`, "decision=a decision=b", "=x decision=a"} {
		if _, err := ParseLine(bad); err == nil {
			t.Errorf("ParseLine(%q) succeeded", bad)
		}
	}
}

func TestParseLineAllFields(t *testing.T) {
	f, err := ParseLine(Formatter{Home: "/Users/u"}.Format(spec))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"decision": "allowed", "reason": "cached approval", "target": "ssh:github", "destination": "github.com",
		"rule": "1", "scope": "session", "gate": "dialog", "app": "com.googlecode.iterm2", "session": "4120@1791072112",
		"chain":    "bash(4120) > claude(4188, Q6L2SF6YDW:com.anthropic.claude-code)",
		"receiver": "ssh … …", "cwd": "~/projects/foo",
	}
	if len(f) != len(want) {
		t.Fatalf("got %d fields %v, want %d", len(f), f, len(want))
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %q, want %q", k, f[k], v)
		}
	}
}

func TestParseLineRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		" ",
		"decision",
		"decision=",
		"reason=x",
		`decision="a"b`,
		`decision=a "b"`,
		`"decision"=allowed`,
		`decision=allowed reason="x`,
		`decision=allowed reason="\q"`,
		"decision=allowed target",
		"decision=allowed =x",
		"decision=allowed target=a target=b",
		// Format never writes a raw non-ASCII rune other than the ellipsis,
		// so a quoted value carrying one is not an audit line.
		`decision=allowed app="ü"`,
		`decision=allowed app="com.googlecode.iterm2` + "⠀" + `"`,
		`decision=allowed app="com.googlecode.` + "і" + `term2"`,
		`decision=allowed cwd="~/foo` + "ㅤ" + `"`,
		`decision=allowed reason="x` + "​" + `"`,
		"decision=allowed app=\"x\u0085y\"",
		`decision=allowed app=ü`,
	} {
		if f, err := ParseLine(bad); err == nil {
			t.Errorf("ParseLine(%q) succeeded: %v", bad, f)
		}
	}
}

// ---------------------------------------------------------------------------
// Logger and sinks

type failSink struct{}

func (failSink) WriteAudit(time.Time, string) error { return errors.New("log down") }

func TestLogger(t *testing.T) {
	m := &MemorySink{}
	l := NewLogger(m, Formatter{}, nil)
	l.Log(Event{Decision: Blocked, Target: "ssh:x"})
	if lines := m.Lines(); len(lines) != 1 || lines[0] != "decision=blocked target=ssh:x" {
		t.Fatalf("lines %q", lines)
	}
	var got error
	NewLogger(failSink{}, Formatter{}, func(err error) { got = err }).Log(Event{Decision: Error})
	l.SetFormatter(Formatter{Args: ArgsNone})
	l.Log(Event{Decision: Denied, Receiver: []string{"/bin/x", "--token=1"}})
	if lines := m.Lines(); lines[1] != `decision=denied receiver="x …+1"` {
		t.Fatalf("SetFormatter not applied: %q", lines[1])
	}
	if got == nil {
		t.Fatal("sink error not reported")
	}
	var sb strings.Builder
	(&WriterSink{W: &sb}).WriteAudit(time.Date(2026, 10, 4, 0, 2, 3, 0, time.UTC), "decision=x")
	if sb.String() != "2026-10-04T00:02:03Z decision=x\n" {
		t.Fatalf("writer sink %q", sb.String())
	}
}

func TestLoggerFailingSinkWithoutHandler(t *testing.T) {
	// A nil onError must not panic: the decision is never blocked by logging.
	NewLogger(failSink{}, Formatter{}, nil).Log(Event{Decision: Denied})
}

type recSink struct {
	mu    sync.Mutex
	times []time.Time
	lines []string
}

func (r *recSink) WriteAudit(t time.Time, line string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.times = append(r.times, t)
	r.lines = append(r.lines, line)
	return nil
}

func TestLoggerPassesEventTime(t *testing.T) {
	r := &recSink{}
	at := time.Date(2026, 10, 4, 0, 30, 0, 0, time.UTC)
	NewLogger(r, Formatter{}, nil).Log(Event{Time: at, Decision: Approved, Target: "ssh:k"})
	if len(r.times) != 1 || !r.times[0].Equal(at) {
		t.Fatalf("sink got times %v, want %v", r.times, at)
	}
	if strings.Contains(r.lines[0], "2026") {
		t.Fatalf("time leaked into message text: %q", r.lines[0])
	}
}

func TestLoggerRedactsByDefault(t *testing.T) {
	m := &MemorySink{}
	NewLogger(m, Formatter{}, nil).Log(Event{Decision: Approved, Receiver: []string{"gh", "auth", "login", "--with-token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"}})
	if l := m.Lines(); len(l) != 1 || strings.Contains(l[0], "abcdefgh") || l[0] != `decision=approved receiver="gh auth login …"` {
		t.Fatalf("default logger leaked a token: %q", l)
	}
}

func TestMemorySinkLinesIsACopy(t *testing.T) {
	m := &MemorySink{}
	_ = m.WriteAudit(time.Time{}, "decision=a")
	l := m.Lines()
	l[0] = "decision=forged"
	if m.Lines()[0] != "decision=a" {
		t.Fatal("Lines exposes internal storage")
	}
}

func TestWriterSinkUsesUTC(t *testing.T) {
	var sb strings.Builder
	at := time.Date(2026, 10, 3, 17, 2, 3, 0, time.FixedZone("MST", -7*3600))
	if err := (&WriterSink{W: &sb}).WriteAudit(at, "decision=x"); err != nil {
		t.Fatal(err)
	}
	if sb.String() != "2026-10-04T00:02:03Z decision=x\n" {
		t.Fatalf("writer sink %q", sb.String())
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestWriterSinkReportsWriteError(t *testing.T) {
	if err := (&WriterSink{W: errWriter{}}).WriteAudit(time.Now(), "decision=x"); err == nil {
		t.Fatal("write error swallowed")
	}
	var got error
	NewLogger(&WriterSink{W: errWriter{}}, Formatter{}, func(err error) { got = err }).Log(Event{Decision: Denied})
	if got == nil {
		t.Fatal("logger did not report the writer error")
	}
}

// One request is one entry: a hostile event written through a WriterSink
// must still produce exactly one physical line.
func TestWriterSinkOneLinePerEvent(t *testing.T) {
	var sb strings.Builder
	l := NewLogger(&WriterSink{W: &sb}, Formatter{}, nil)
	for _, v := range forgeries {
		l.Log(Event{Decision: Blocked, Reason: v, Cwd: v, Receiver: []string{v, v}, Chain: []Proc{{Name: v, PID: 1, Identity: v}}})
	}
	lines := strings.Split(strings.TrimSuffix(sb.String(), "\n"), "\n")
	if len(lines) != len(forgeries) {
		t.Fatalf("%d events produced %d lines", len(forgeries), len(lines))
	}
	for _, ln := range lines {
		ts, msg, ok := strings.Cut(ln, " ")
		if !ok {
			t.Fatalf("no timestamp in %q", ln)
		}
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("bad timestamp %q: %v", ts, err)
		}
		if f, err := ParseLine(msg); err != nil || f["decision"] != "blocked" {
			t.Errorf("line %q: %v %v", msg, f, err)
		}
	}
}

func TestLoggerConcurrent(t *testing.T) {
	const secret = "C0ncurrentSecret99"
	const n = 64
	m := &MemorySink{}
	l := NewLogger(m, Formatter{}, nil)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			l.Log(Event{Decision: Approved, Target: fmt.Sprintf("ssh:k%d", i), Receiver: []string{"/bin/tool", "--token=" + secret}})
		}(i)
		go func(i int) {
			defer wg.Done()
			mode := ArgsRedacted
			if i%2 == 0 {
				mode = ArgsNone
			}
			l.SetFormatter(Formatter{Args: mode})
		}(i)
	}
	wg.Wait()
	lines := m.Lines()
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d", len(lines), n)
	}
	seen := map[string]bool{}
	for _, ln := range lines {
		if strings.Contains(ln, secret) {
			t.Errorf("secret leaked under concurrency: %q", ln)
		}
		f, err := ParseLine(ln)
		if err != nil {
			t.Errorf("unparseable %q: %v", ln, err)
			continue
		}
		seen[f["target"]] = true
	}
	if len(seen) != n {
		t.Fatalf("lost or duplicated entries: %d distinct targets", len(seen))
	}
}

func TestWriterSinkConcurrent(t *testing.T) {
	var sb strings.Builder
	w := &WriterSink{W: &sb}
	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = w.WriteAudit(time.Now(), fmt.Sprintf("decision=allowed target=ssh:k%d", i))
		}(i)
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(sb.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d", len(lines), n)
	}
	for _, ln := range lines {
		_, msg, _ := strings.Cut(ln, " ")
		if _, err := ParseLine(msg); err != nil {
			t.Errorf("interleaved line %q", ln)
		}
	}
}

// ---------------------------------------------------------------------------
// Fuzzing

func FuzzParseLine(f *testing.F) {
	f.Add(Formatter{}.Format(spec))
	f.Fuzz(func(t *testing.T, s string) {
		fields, err := ParseLine(s)
		if err != nil {
			return
		}
		// Whatever parses must survive a format/parse round trip of its values
		// (values within the clipping budgets; longer ones are clipped).
		e := Event{Decision: Decision(fields["decision"]), Reason: fields["reason"], Target: fields["target"]}
		g, err := ParseLine(Formatter{}.Format(e))
		if err != nil {
			t.Fatalf("round trip failed: %v (%v)", fields, err)
		}
		if len(quote(fields["decision"])) <= maxShort && g["decision"] != fields["decision"] {
			t.Fatalf("round trip lost decision: %q vs %q", fields, g)
		}
		if len(quote(fields["reason"])) <= maxField && g["reason"] != fields["reason"] {
			t.Fatalf("round trip lost reason: %q vs %q", fields, g)
		}
		for _, k := range []string{"decision", "reason"} {
			if g[k] != fields[k] && !strings.Contains(g[k], Clipped) {
				t.Fatalf("round trip changed %s: %q vs %q", k, fields, g)
			}
		}
	})
}

func FuzzFormat(f *testing.F) {
	for _, v := range forgeries {
		f.Add(v, v, v, v)
	}
	for _, v := range chainForgeries {
		f.Add(v, v, v, v)
	}
	big := strings.Repeat("a", 1<<16)
	f.Add(big, big, big, big)
	f.Add("r", "a", strings.Repeat("/ü", 512), strings.Repeat("\xff", 3000))
	f.Fuzz(func(t *testing.T, reason, app, cwd, arg string) {
		e := Event{
			Decision: Blocked, Target: "ssh:k", Reason: reason, App: app, Cwd: cwd,
			Chain: []Proc{{Name: arg, PID: 1, Identity: app}}, Receiver: []string{arg, arg, reason},
		}
		for _, mode := range []ArgsMode{ArgsRedacted, ArgsNone} {
			line := Formatter{Args: mode}.Format(e)
			checkLineClean(t, line)
			if len(line) > MaxLine {
				t.Fatalf("line of %d bytes > MaxLine", len(line))
			}
			g, err := ParseLine(line)
			if err != nil {
				t.Fatalf("ParseLine(%q): %v", line, err)
			}
			if g["decision"] != "blocked" || g["target"] != "ssh:k" {
				t.Fatalf("round trip/forgery: %v from %q", g, line)
			}
			for k, v := range map[string]string{"reason": reason, "app": app, "cwd": cwd} {
				if g[k] != v && !strings.Contains(g[k], Clipped) {
					t.Fatalf("%s round trip/forgery: %q from %q", k, g[k], line)
				}
			}
			if _, err := ParseChain(g["chain"]); err != nil {
				t.Fatalf("ParseChain(%q): %v", g["chain"], err)
			}
		}
	})
}

// Secrets design 8: envPassed names the envAllow variables the
// caller supplied, names only, right after delivery, as env_passed (the
// line's keys are lower case).
func TestEnvPassedField(t *testing.T) {
	line := Formatter{}.Format(Event{Decision: Approved, Target: "secret:X", Delivery: "late-env", EnvPassed: []string{"HTTPS_PROXY", "NODE_ENV"}})
	if !strings.Contains(line, "delivery=late-env env_passed=HTTPS_PROXY,NODE_ENV") {
		t.Fatalf("line %q", line)
	}
	if strings.Contains(Formatter{}.Format(Event{Decision: Approved, Target: "secret:X", Delivery: "late-env"}), "env_passed") {
		t.Fatal("an empty envPassed is omitted")
	}
}
