package main

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

// A build with no hidden prompt (off macOS) never promises one in its help:
// `secret add` refuses at a terminal there (spec, "Weaker than macOS" 10). Its
// help says so and shows the piped form.
func TestHelpWithNoHiddenPrompt(t *testing.T) {
	for _, args := range [][]string{
		{"help"},
		{"--help"},
		{"secret", "--help"},
		{"secret", "add", "--help"},
		{"help", "secret", "add"},
	} {
		h := newHarness(t)
		h.a.noHiddenPrompt = true
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, h.errb.String())
		}
		got := strings.ReplaceAll(h.out.String(), "no hidden prompt", "")
		for _, bad := range []string{"hidden prompt", "The prompt takes", "typed at"} {
			if strings.Contains(got, bad) {
				t.Errorf("%v: help has %q:\n%s", args, bad, got)
			}
		}
	}

	h := newHarness(t)
	h.a.noHiddenPrompt = true
	if code := h.run("secret", "add", "--help"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	for _, want := range []string{
		"system has no hidden prompt",
		"refuses and reads nothing",
		`printf '%s' "$TOKEN" | nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN`,
	} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("secret add --help lacks %q:\n%s", want, h.out.String())
		}
	}

	// The usage nazar prints under no command at all is the same text.
	h = newHarness(t)
	h.a.noHiddenPrompt = true
	if code := h.run(); code != control.ExitUsage {
		t.Fatalf("no command: exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "(the value on stdin; never an argument)") {
		t.Errorf("the usage on stderr promises a hidden prompt:\n%s", h.errb.String())
	}

	// The one-line summary, which `secret --help` and completion show.
	h = newHarness(t)
	h.a.noHiddenPrompt = true
	if c, _ := find(h.a.commands(false), []string{"secret", "add"}); strings.Contains(c.Short, "hidden prompt") {
		t.Errorf("secret add's summary promises a hidden prompt: %q", c.Short)
	}
}

// macOS has the prompt, and its help stays as it was, byte for byte
// (clicontract_test.go pins the whole text).
func TestHelpWithHiddenPromptIsUnchanged(t *testing.T) {
	h := newHarness(t)
	if code := h.run("help"); code != 0 || h.out.String() != usage {
		t.Fatalf("exit %d, the usage changed:\n%s", code, h.out.String())
	}
	c, _ := find(newHarness(t).a.commands(false), []string{"secret", "add"})
	if want := "Store a secret, read from stdin or a hidden prompt (Touch ID once)"; c.Short != want {
		t.Errorf("summary %q, want %q", c.Short, want)
	}
	if want := "The value is read from stdin, or typed at a hidden prompt; it is never an argument (an argument\nis visible in ps). The prompt takes one line of at most about 1000 bytes; pipe anything longer\nor with several lines."; !strings.Contains(c.Long, want) {
		t.Errorf("help lost %q:\n%s", want, c.Long)
	}
	if want := "nazar secret add NOTES                  # typed at a hidden prompt"; !strings.Contains(c.Example, want) {
		t.Errorf("examples lost %q:\n%s", want, c.Example)
	}
}

func TestNoHiddenPromptOnlyOffMacOS(t *testing.T) {
	if noHiddenPromptOn("darwin") {
		t.Error("macOS has the hidden prompt")
	}
	for _, goos := range []string{"linux", "freebsd"} {
		if !noHiddenPromptOn(goos) {
			t.Errorf("%s has a hidden prompt, it should not", goos)
		}
	}
}

// On Linux the two rewrites meet: the help promises no hidden prompt and takes
// Linux's words, in the usage as in the command tree (main sets both).
func TestLinuxHelpHasNoHiddenPrompt(t *testing.T) {
	linuxHarness := func() *harness {
		h := newHarness(t)
		h.a.linux = true
		h.a.noHiddenPrompt = true
		return h
	}
	check := func(what, text string) {
		t.Helper()
		got := strings.ReplaceAll(text, "no hidden prompt", "")
		for _, bad := range []string{"hidden prompt", "The prompt takes", "typed at", "Touch ID"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: help has %q:\n%s", what, bad, text)
			}
		}
	}
	for _, args := range [][]string{
		{"help"},
		{"--help"},
		{"secret", "--help"},
		{"secret", "add", "--help"},
		{"help", "secret", "add"},
	} {
		h := linuxHarness()
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, h.errb.String())
		}
		check(strings.Join(args, " "), h.out.String())
	}

	h := linuxHarness()
	if code := h.run(); code != control.ExitUsage {
		t.Fatalf("no command: exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "(the value on stdin; never an argument)") {
		t.Errorf("the usage on stderr promises a hidden prompt:\n%s", h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "(not available on Linux yet)") {
		t.Errorf("the usage on stderr lost its Linux words:\n%s", h.errb.String())
	}
	check("no command", h.errb.String())

	h = linuxHarness()
	if c, _ := find(h.a.commands(false), []string{"secret", "add"}); c.Short != "Store a secret, read from stdin (your password once)" {
		t.Errorf("secret add's summary: %q", c.Short)
	}
}
