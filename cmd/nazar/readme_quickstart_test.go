package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
)

// The README's Quick start is what a new user types at a terminal. Its
// key-creation line and its rules block are run here, as written (a
// loosening edit carries --allow-loosen-access and asks at once, so there
// is no `config apply` line to copy), against the real core (fake
// platform; every Touch ID / Watch / password prompt approves), and must
// leave the github key with the example config's posture: the claude and
// iTerm2 rules in that order, and every other caller blocked. Ways the
// text went wrong before: two loosening edits in a row, which nazar-agent
// refuses after the first is staged; a bare `config apply`; a loosening
// line without the flag, which is refused (exit 2); and leaving the key's
// own gate at `dialog` from `ssh-key create`, so callers no rule matches
// got an Allow dialog instead of the example's block.

const readmePath = "../../docs/GUIDE.md"

// quickStartCommands returns the nazar command lines of the README's Quick
// start: its `ssh-key create` line and every line of the fenced block that
// adds the github rules, comments stripped, split on spaces (the commands
// use no quoting).
func quickStartCommands(t *testing.T) [][]string {
	t.Helper()
	b, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	start := strings.Index(text, "\n## Quick start\n")
	if start < 0 {
		t.Fatal("README has no Quick start section")
	}
	text = text[start+1:]
	if end := strings.Index(text, "\n## "); end >= 0 {
		text = text[:end]
	}
	fence := regexp.MustCompile("(?s)```bash\n(.*?)```")
	var create []string
	var rules [][]string
	for _, m := range fence.FindAllStringSubmatch(text, -1) {
		var lines [][]string
		for _, l := range strings.Split(m[1], "\n") {
			if i := strings.Index(l, "#"); i >= 0 {
				l = l[:i]
			}
			f := strings.Fields(l)
			if len(f) < 2 || f[0] != "nazar" {
				continue
			}
			if len(f) > 2 && f[1] == "ssh-key" && f[2] == "create" {
				create = f[1:]
			}
			lines = append(lines, f[1:])
		}
		if strings.Contains(m[1], "ssh-key rule add github") {
			if rules != nil {
				t.Fatal("more than one Quick start block adds github rules")
			}
			rules = lines
		}
	}
	if create == nil || rules == nil {
		t.Fatalf("Quick start: no `nazar ssh-key create` line (%v) or no github rules block (%v)", create, rules)
	}
	return append([][]string{create}, rules...)
}

func TestReadmeQuickStartRulesReachTheExamplePosture(t *testing.T) {
	w := newUIWorld(t)
	cmds := quickStartCommands(t)
	logins := w.f.CountShown(fake.KindAuthenticate)
	loosening := 0
	for _, c := range cmds {
		// A person at a terminal types no `config apply`: the edit before
		// it asked at once.
		if len(c) >= 2 && c[0] == "config" && c[1] == "apply" {
			t.Errorf("README Quick start: `nazar %s` is not needed at a terminal; the edit before it asks at once", strings.Join(c, " "))
		}
		if len(c) >= 2 && (c[1] == "create" || (len(c) >= 3 && c[1] == "rule" && c[2] == "add")) { // the lines that loosen, as the README writes them
			loosening++
		}
		if code := w.h.run(c...); code != 0 {
			t.Fatalf("README Quick start: `nazar %s` exits %d\nstdout %s\nstderr %s", strings.Join(c, " "), code, w.h.out, w.h.errb)
		}
		// Not one prompt inside another's cooldown: a user takes seconds per
		// line, not none.
		w.f.Advance(10 * time.Second)
	}
	// One Touch ID per loosening line, never a second for the same change.
	if n := w.f.CountShown(fake.KindAuthenticate) - logins; n != loosening {
		t.Fatalf("the Quick start showed %d login prompts for %d loosening lines", n, loosening)
	}
	// Nothing is left waiting for approval: config.yaml is the approved config.
	if _, code := w.cli(t, "config", "check"); code != 0 {
		t.Fatalf("after the Quick start, config check exits %d (a change still staged?)\n%s\n%s", code, w.h.out, w.h.errb)
	}
	data, err := os.ReadFile(layout.ConfigFile(w.h.home))
	if err != nil {
		t.Fatal(err)
	}
	cfg, probs := config.Parse(data, config.Env{Home: w.h.home})
	if probs.HasErrors() {
		t.Fatalf("config.yaml after the Quick start is invalid: %v", probs)
	}
	key, ok := cfg.SSHAgent.Keys["github"]
	if !ok {
		t.Fatal("no github key in config.yaml")
	}
	want := []struct {
		apps   string
		policy config.Policy
	}{
		{`signed:"Q6L2SF6YDW":"com.anthropic.claude-code"`, config.Policy{Scope: config.ScopeSession, Gate: config.GateDialog}},
		{`app:"com.googlecode.iterm2":""`, config.Policy{Scope: config.ScopeSession, Gate: config.GateLogin, Expire: 8 * time.Hour}},
	}
	if len(key.Rules) != len(want) {
		t.Fatalf("github has %d rules after the Quick start, want %d (the example's claude and iTerm2 rules): %+v", len(key.Rules), len(want), key.Rules)
	}
	for i, r := range key.Rules {
		if len(r.Apps) != 1 || r.Apps[0].Canonical() != want[i].apps || r.Policy != want[i].policy || len(r.To) != 0 {
			t.Errorf("github rule %d = %s, want apps=%s %s", i+1, r.Canonical(), want[i].apps, want[i].policy)
		}
	}
	// The example: "anything else → blocked". A dialog here would let any
	// process as the user put an Allow button for this key on screen.
	if fb := cfg.Fallback("github"); fb.Gate != config.GateBlock {
		t.Errorf("callers no github rule matches get %s; the example blocks them", fb)
	}
}
