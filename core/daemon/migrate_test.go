package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
)

// backToOldLayout stops the daemon and puts what it has in ~/.nazar where
// an install before ~/.nazar/{config,keys,run} had it, with body as the
// config file.
func backToOldLayout(t *testing.T, e *env, body string) {
	t.Helper()
	e.halt()
	e.halt = nil
	old := layout.OldConfigDir(e.home)
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(layout.ConfigFile(e.home)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The approved config is kept by content (the vault's config/approved holds
// the file's bytes; spec 4.8), not by path: nazar-agent starting on an
// install of the old layout moves config.yaml and it is in force at once,
// with no prompt and nothing staged. A config that says something else
// after the move is still judged as a change.
func TestMigratedConfigStaysApproved(t *testing.T) {
	e := start(t)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	e.activate(t, rules)
	logins := e.logins()
	if logins == 0 {
		t.Fatal("the rules were not a loosening: this test would prove nothing")
	}
	approved, err := e.vault.Get("config/approved")
	if err != nil || string(approved) != rules {
		t.Fatalf("the vault holds %q (%v), want the file's bytes", approved, err)
	}

	backToOldLayout(t, e, rules)
	e.launch(t)
	if b, err := os.ReadFile(layout.ConfigFile(e.home)); err != nil || string(b) != rules {
		t.Fatalf("the config did not move: %q %v", b, err)
	}
	if _, err := os.Lstat(layout.OldConfigDir(e.home)); !os.IsNotExist(err) {
		t.Fatalf("~/.config/nazar is left: %v", err)
	}
	if got := string(e.d.stager.Active().Raw); got != rules {
		t.Fatalf("active config after the move:\n%s", got)
	}
	if e.stillStaged() {
		t.Fatal("the moved config is staged")
	}
	if n := e.logins(); n != logins {
		t.Fatalf("%d prompts after the move, want none", n-logins)
	}
	if lines := e.configAudit(t, audit.Blocked); len(lines) != 0 {
		t.Fatalf("config blocked after the move: %v", lines)
	}

	// Another content moved the same way goes through the gate.
	loosened := strings.Replace(rules, "scope: session\n          gate: dialog", "gate: none", 1)
	if loosened == rules {
		t.Fatal("the rules have no dialog gate to loosen")
	}
	backToOldLayout(t, e, loosened)
	e.launch(t)
	waitFor(t, func() bool { return e.logins() == logins+1 })
}
