package codesign

import (
	"strings"
	"testing"
)

// Secrets design 7.3: the code requirement nazar-agent holds the
// control peer of a value-returning command to, the twin of Nazar UI.app's
// CLIRequirement: a team build trusts dev.nazar.cli of its own team and
// ignores any pin; an ad-hoc build trusts exactly the CLI build whose
// cdhash `make agent` compiled into it; an ad-hoc build without a pin
// trusts no CLI.
func TestCLIRequirement(t *testing.T) {
	pin := strings.Repeat("0a", 20)
	team, err := CLIRequirement("ABCDE12345", pin)
	if want := `identifier "dev.nazar.cli" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"`; err != nil || team != want {
		t.Fatalf("team build: %q, %v; want %q", team, err, want)
	}
	if again, _ := CLIRequirement("ABCDE12345", ""); again != team {
		t.Fatal("the pin never changes a team build's rule")
	}
	dev, err := CLIRequirement("", pin)
	if want := `identifier "dev.nazar.cli" and cdhash H"` + pin + `"`; err != nil || dev != want {
		t.Fatalf("ad-hoc build: %q, %v; want %q", dev, err, want)
	}
	if r, err := CLIRequirement("", ""); err == nil {
		t.Fatalf("an ad-hoc build without a pin must trust no CLI, got %q", r)
	}
	for _, bad := range []string{
		strings.Repeat("0A", 20),        // upper case: not what codesign prints
		strings.Repeat("0a", 19),        // short
		strings.Repeat("0a", 21),        // long
		strings.Repeat("0a", 19) + `0"`, // closes the quote
		pin[:38] + `" or anchor apple or cdhash H"` + pin[:2],
		pin + "\n",
	} {
		if r, err := CLIRequirement("", bad); err == nil {
			t.Errorf("pin %q must be refused, got %q", bad, r)
		}
	}
	if r, err := CLIRequirement(`ABCDE1234"`, pin); err == nil {
		t.Errorf("a bad team must be refused, never fall back to the pin: %q", r)
	}
}
