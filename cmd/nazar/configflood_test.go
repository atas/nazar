package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform/fake"
)

// End to end: after the background config prompt is denied, rewriting
// config.yaml shows no new prompt, and `nazar config apply` during the
// cooldown is refused without a prompt: exit 4 (the change is staged and
// waiting for approval, spec 6), with the remaining cooldown in the
// message, on stderr for people and as a Problem object with --json.

// loosening gives key github a dialog fallback: looser than the built-in
// default (every key blocked), so it is staged and needs the login gate.
const loosening = "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      gate: dialog\n"

var cooldownLeft = regexp.MustCompile(`\b[1-6]?[0-9]\s*(s|sec|secs|second|seconds)\b`)

func configLines(sink *audit.MemorySink, dec audit.Decision) int {
	n := 0
	for _, l := range sink.Lines() {
		f, err := audit.ParseLine(l)
		if err == nil && f["target"] == "config" && f["decision"] == string(dec) {
			n++
		}
	}
	return n
}

// applyRefusals counts the blocked lines of `config apply` refusals under
// the throttle; each must name its caller.
func applyRefusals(t *testing.T, sink *audit.MemorySink) int {
	t.Helper()
	n := 0
	for _, l := range sink.Lines() {
		f, err := audit.ParseLine(l)
		if err != nil || f["target"] != "config" || f["decision"] != string(audit.Blocked) || !strings.HasPrefix(f["reason"], "config apply: not asked: ") {
			continue
		}
		if f["chain"] == "" && f["session"] == "" {
			t.Fatalf("a refused config apply must be audited with its caller: %s", l)
		}
		n++
	}
	return n
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestConfigApplyCooldownAgainstDaemon(t *testing.T) {
	h := newHarness(t)
	f, sink := startDaemon(t, h)

	writeConfig(t, h, loosening) // the fake's default login answer denies
	waitUntil(t, "the background prompt", func() bool { return f.CountShown(fake.KindAuthenticate) == 1 })
	waitUntil(t, "its denial in the audit log", func() bool { return configLines(sink, audit.Denied) == 1 })

	// Rewrites with a changed comment: no new prompt.
	for i := 1; i <= 4; i++ {
		writeConfig(t, h, loosening+fmt.Sprintf("# %d\n", i))
		waitUntil(t, "the rewrite to be observed", func() bool {
			return configLines(sink, audit.Blocked) == i || f.CountShown(fake.KindAuthenticate) > 1
		})
		if got := f.CountShown(fake.KindAuthenticate); got != 1 {
			t.Fatalf("rewrites after a denial must not prompt: %d login prompts after rewrite %d", got, i)
		}
	}

	// config apply during the cooldown: refused, no prompt, exit 4.
	if code := h.run("config", "apply"); code != control.ExitStaged {
		t.Fatalf("config apply during the cooldown: exit %d, want %d (stderr %q)", code, control.ExitStaged, h.errb.String())
	}
	if !cooldownLeft.MatchString(h.errb.String()) {
		t.Fatalf("stderr must say how long the cooldown still runs: %q", h.errb.String())
	}
	if code := h.run("--json", "config", "apply"); code != control.ExitStaged {
		t.Fatalf("--json config apply during the cooldown: exit %d, want %d", code, control.ExitStaged)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindProblem {
		t.Fatalf("--json must print exactly one Problem: %q", h.out.String())
	}
	if msg, _ := objs[0]["message"].(string); !cooldownLeft.MatchString(msg) {
		t.Fatalf("the Problem must carry the remaining cooldown: %q", h.out.String())
	}
	if h.errb.Len() != 0 {
		t.Fatalf("--json wrote to stderr: %q", h.errb.String())
	}
	if got := f.CountShown(fake.KindAuthenticate); got != 1 {
		t.Fatalf("config apply during the cooldown must not prompt: %d login prompts", got)
	}
	// Both refusals are in the audit log with the caller (regression: a
	// refused config apply left no trace of who asked), and neither added
	// a per-content blocked line.
	if got := applyRefusals(t, sink); got != 2 {
		t.Fatalf("2 refused config apply calls must leave 2 blocked lines with the caller, got %d:\n%s", got, strings.Join(sink.Lines(), "\n"))
	}
	if got := configLines(sink, audit.Blocked); got != 4+2 {
		t.Fatalf("want 4 per-content blocked lines plus 2 refusals, got %d", got)
	}

	// config check still reports the change as staged (exit 4).
	if code := h.run("config", "check"); code != control.ExitStaged || !strings.Contains(h.out.String(), "config apply") {
		t.Fatalf("config check: exit %d\n%s", code, h.out.String())
	}
	if got := f.CountShown(fake.KindAuthenticate); got != 1 {
		t.Fatalf("config check must not prompt: %d login prompts", got)
	}
}
