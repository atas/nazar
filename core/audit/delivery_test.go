package audit

import (
	"strings"
	"testing"
)

// Secrets design 8: delivery= follows target=, is never shortened
// to fit the line, and is clipped at 16 bytes like any value it can't forge
// a field with.
func TestFormatDelivery(t *testing.T) {
	e := Event{Decision: Approved, Target: "secret:GH_TOKEN", Delivery: "helper", Rule: "1", Scope: "session", Gate: "dialog"}
	got := Formatter{}.Format(e)
	if want := "decision=approved target=secret:GH_TOKEN delivery=helper rule=1 scope=session gate=dialog"; got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	for _, v := range forgeries {
		line := Formatter{}.Format(Event{Decision: Blocked, Target: "secret:X", Rule: "fallback", Delivery: v})
		checkLineClean(t, line)
		f, err := ParseLine(line)
		if err != nil {
			t.Fatalf("delivery=%q: %v", v, err)
		}
		if f["decision"] != "blocked" || f["target"] != "secret:X" || f["rule"] != "fallback" || len(f) > 4 {
			t.Fatalf("delivery=%q forged a field: %v", v, f)
		}
	}
	line := Formatter{}.Format(Event{Decision: Blocked, Target: "secret:X", Delivery: strings.Repeat("x", 100)})
	if f, err := ParseLine(line); err != nil || !strings.Contains(f["delivery"], Clipped) || len(f["delivery"]) > 16 {
		t.Fatalf("a long delivery must be clipped to 16 bytes: %q %v", line, err)
	}
}
