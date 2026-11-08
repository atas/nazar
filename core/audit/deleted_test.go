package audit

import (
	"strings"
	"testing"
)

// A process whose executable file is gone (Claude Code after its
// auto-update) is marked in the chain field OUTSIDE its name: the name is
// caller-chosen text, so a marker inside the quoted name can be forged by a
// binary literally named "claude-code (file deleted)". The element is
// name(pid[, team:id][, deleted]); "deleted" is bare, last, and only there
// (an identity always has a colon, and one that is not a plain identity is
// quoted, so no identity can read as the marker).

func TestChainMarksADeletedFileOutsideTheName(t *testing.T) {
	const signed = "Q6L2SF6YDW:com.anthropic.claude-code"
	cases := []struct {
		chain []Proc
		want  string
	}{
		{[]Proc{{Name: "claude-code", PID: 42, Identity: signed, Deleted: true}}, "claude-code(42, " + signed + ", deleted)"},
		{[]Proc{{Name: "claude-code", PID: 7, Deleted: true}}, "claude-code(7, deleted)"},
		{[]Proc{{Name: "a b", PID: 7, Deleted: true}}, `"a b"(7, deleted)`},
		{[]Proc{{Name: "bash", PID: 1}, {Name: "x", PID: 2, Deleted: true}, {Name: "ssh", PID: 3}}, "bash(1) > x(2, deleted) > ssh(3)"},
		// The literal names: quoted, and never marked.
		{[]Proc{{Name: "claude-code (file deleted)", PID: 7}}, `"claude-code (file deleted)"(7)`},
		{[]Proc{{Name: "claude-code(7, deleted)", PID: 8}}, `"claude-code(7, deleted)"(8)`},
		{[]Proc{{Name: "deleted", PID: 8}}, "deleted(8)"},
		// An identity that says "deleted" is quoted, so it is an identity.
		{[]Proc{{Name: "p", PID: 7, Identity: "deleted"}}, `p(7, "deleted")`},
		{[]Proc{{Name: "p", PID: 7, Identity: ", deleted"}}, `p(7, ", deleted")`},
	}
	for _, c := range cases {
		f, err := ParseLine(Formatter{}.Format(Event{Decision: Allowed, Chain: c.chain}))
		if err != nil {
			t.Fatal(err)
		}
		if f["chain"] != c.want {
			t.Errorf("chain %+v = %q, want %q", c.chain, f["chain"], c.want)
		}
		got, err := ParseChain(f["chain"])
		if err != nil || len(got) != len(c.chain) {
			t.Fatalf("ParseChain(%q) = %+v, %v", f["chain"], got, err)
		}
		for i := range got {
			if got[i] != c.chain[i] {
				t.Errorf("ParseChain(%q)[%d] = %+v, want %+v", f["chain"], i, got[i], c.chain[i])
			}
		}
	}
}

// A deleted "claude-code" and a live binary literally named
// "claude-code (file deleted)" never produce the same chain value, and each
// parses back as what it is.
func TestDeletedMarkCannotBeForgedByAName(t *testing.T) {
	deleted := Formatter{}.Format(Event{Decision: Allowed, Chain: []Proc{{Name: "claude-code", PID: 7, Deleted: true}}})
	for _, name := range []string{"claude-code (file deleted)", "claude-code, deleted", "claude-code(7, deleted)", "claude-code (file deleted)"} {
		literal := Formatter{}.Format(Event{Decision: Allowed, Chain: []Proc{{Name: name, PID: 7}}})
		fd, _ := ParseLine(deleted)
		fl, _ := ParseLine(literal)
		if fd["chain"] == fl["chain"] {
			t.Fatalf("%q reads as the deleted claude-code: %q", name, fl["chain"])
		}
		got, err := ParseChain(fl["chain"])
		if err != nil || len(got) != 1 || got[0].Deleted || got[0].Name != name {
			t.Fatalf("%q: ParseChain(%q) = %+v, %v", name, fl["chain"], got, err)
		}
	}
	// Every forgery as a name of a deleted or a live process round-trips
	// with the flag it had.
	for _, v := range append(append([]string(nil), forgeries...), chainForgeries...) {
		for _, del := range []bool{false, true} {
			chain := []Proc{{Name: "bash", PID: 1}, {Name: v, PID: 7, Deleted: del}, {Name: "ssh", PID: 9}}
			f, err := ParseLine(Formatter{}.Format(Event{Decision: Blocked, Chain: chain}))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseChain(f["chain"])
			if err != nil || len(got) != 3 {
				t.Fatalf("%q deleted=%v: ParseChain(%q) = %+v, %v", v, del, f["chain"], got, err)
			}
			for i := range chain {
				if got[i].Deleted != chain[i].Deleted || got[i].PID != chain[i].PID || !sameOrClipped(got[i].Name, chain[i].Name) {
					t.Errorf("%q deleted=%v: element %d = %+v, want %+v", v, del, i, got[i], chain[i])
				}
			}
		}
	}
}

// ParseChain accepts the marker only where Format writes it: bare, last,
// once.
func TestParseChainRejectsMisplacedDeletedMarks(t *testing.T) {
	for _, s := range []string{
		"x(1, deleted, deleted)",
		"x(1, deleted, T:a)",
		"x(1, T:a, deleted, deleted)",
		"x(1, Deleted)",
		"x(1,deleted)",
		"x(1, deleted )",
		"x(1, deleted",
		"x(deleted)",
		"x(1) deleted",
		"x(1), deleted",
	} {
		if got, err := ParseChain(s); err == nil {
			t.Errorf("ParseChain(%q) = %+v, want an error", s, got)
		}
	}
	got, err := ParseChain(`x(1, "deleted")`)
	if err != nil || len(got) != 1 || got[0].Deleted || got[0].Identity != "deleted" {
		t.Fatalf(`a quoted "deleted" is an identity: %+v, %v`, got, err)
	}
}

// FormatChain is the chain field's value exactly as Format writes it (and
// ParseLine returns it), so other views of a chain (the window's "last
// used") are built the same way: names quoted, the deleted mark outside,
// and the same bound and drop order for a long chain.
func TestFormatChainIsTheChainField(t *testing.T) {
	long := []Proc{{Name: "launchd-ish", PID: 1}}
	for i := 0; i < 60; i++ {
		long = append(long, Proc{Name: strings.Repeat("p", 20), PID: 100 + i})
	}
	long = append(long, Proc{Name: "claude-code", PID: 9, Identity: "Q6L2SF6YDW:com.anthropic.claude-code", Deleted: true}, Proc{Name: "ssh", PID: 10})
	for _, chain := range [][]Proc{
		nil,
		{{Name: "iTerm2", PID: 1}, {Name: "zsh", PID: 2}, {Name: "ssh", PID: 3}},
		{{Name: "a > b", PID: 7}, {Name: "claude-code", PID: 8, Deleted: true}},
		{{Name: "x\n‮", PID: 7, Identity: "T:a) > y(1"}},
		long,
	} {
		f, err := ParseLine(Formatter{}.Format(Event{Decision: Allowed, Chain: chain}))
		if err != nil {
			t.Fatal(err)
		}
		if got := FormatChain(chain); got != f["chain"] {
			t.Errorf("FormatChain = %q, the chain field is %q", got, f["chain"])
		}
	}
}
