package broker

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 5: Claude Code runs from a version-named file that its
// auto-update deletes. The audit chain and the dialog show "claude-code",
// marked "(file deleted)" once the file is gone, never "2.1.299" or ".";
// the rule still matches by code signature.
func TestAuditAndDialogUseDisplayNames(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	claude := fake.Proc{Path: "/Users/u/.local/share/claude/versions/2.1.299", Args: []string{"claude"}, Code: fake.ClaudeCode}
	tab := e.f.ITermTab(platform.ProcessRef{}, claude, fake.SSHProc("git@github.com"))
	info, _ := e.f.Process(tab.Procs[0])
	info.Path = "" // deleted by the update
	e.f.SetProcess(info)

	if r := e.b.Handle(e.req("github", tab.Peer())); !r.Allowed() || r.Outcome.RuleIndex != 1 {
		t.Fatalf("Claude Code's rule must still match by signature: %+v", r)
	}
	chain := e.lastLine(t)["chain"]
	// The mark is outside the name, so a binary literally named
	// "claude-code (file deleted)" can't pass for it.
	if !strings.Contains(chain, "claude-code(") || !strings.Contains(chain, ", Q6L2SF6YDW:com.anthropic.claude-code, deleted)") ||
		strings.Contains(chain, "(file deleted)") {
		t.Fatalf("audit chain %q", chain)
	}
	procs, err := audit.ParseChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	marked := 0
	for _, p := range procs {
		if p.Deleted {
			marked++
			if p.Name != "claude-code" || p.Identity != "Q6L2SF6YDW:com.anthropic.claude-code" || p.PID != tab.Procs[0].PID {
				t.Fatalf("deleted element %+v", p)
			}
		}
	}
	if marked != 1 {
		t.Fatalf("%d elements marked deleted in %q, want 1", marked, chain)
	}
	if strings.Contains(chain, "2.1.299") || strings.Contains(chain, ".(") {
		t.Fatalf("audit chain shows the file name: %q", chain)
	}
	shown := e.f.Shown()
	last := shown[len(shown)-1].Prompt
	joined := strings.Join(last.Lines, "\n")
	if !strings.Contains(joined, "chain: iTerm2 → bash → claude-code (file deleted) → ssh") {
		t.Fatalf("dialog lines:\n%s", joined)
	}
}

// The matched hop above the app (claude → Foo.app → ssh) is named the same
// way in the dialog's "matched:" line and the audit line's matched= field:
// "claude-code", marked once the file is gone.
func TestMatchedHopUsesDisplayName(t *testing.T) {
	e := newEnv(t)
	claude := fake.Proc{Path: "/Users/u/.local/share/claude/versions/2.1.299", Args: []string{"claude"}, Code: fake.ClaudeCode}
	tab := e.f.ITermTab(platform.ProcessRef{}, claude, fooApp(), fake.SSHProc("git@github.com"))

	check := func(wantLine, wantName string, wantDeleted bool) {
		t.Helper()
		e.cache.RevokeAll("test")
		p, f := e.handleShown(t, e.req("github", tab.Peer()))
		if f["rule"] != "1" {
			t.Fatalf("want rule 1 (apps: claude), got %v", f)
		}
		if !strings.Contains(promptText(p), wantLine) {
			t.Errorf("want %q in the dialog:\n%s", wantLine, promptText(p))
		}
		if strings.Contains(promptText(p), "2.1.299") {
			t.Errorf("the dialog shows the version-named file:\n%s", promptText(p))
		}
		procs, err := audit.ParseChain(f["matched"])
		if err != nil || len(procs) != 1 || procs[0].Name != wantName || procs[0].Identity != "Q6L2SF6YDW:com.anthropic.claude-code" ||
			procs[0].Deleted != wantDeleted {
			t.Fatalf("matched = %q (%v): want one element %s(pid, Q6L2SF6YDW:com.anthropic.claude-code), deleted=%v", f["matched"], err, wantName, wantDeleted)
		}
	}
	check("matched: claude-code (rule 1, above Foo)", "claude-code", false)

	info, _ := e.f.Process(tab.Procs[0])
	info.Path = "" // deleted by the update
	e.f.SetProcess(info)
	check("matched: claude-code (file deleted) (rule 1, above Foo)", "claude-code", true)
}

// Attack: a deleted, unsigned program that renamed itself after a trusted
// one ("claude-code" as p_comm) shows that name only with the deleted mark,
// carries no identity in the audit chain, and matches no signed: rule.
func TestDeletedImpostorGetsNoIdentity(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/claude-code", Args: []string{"claude"}, Code: fake.Unsigned},
		fake.SSHProc("git@github.com"))
	info, _ := e.f.Process(tab.Procs[0])
	info.Path = ""
	e.f.SetProcess(info)
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Allowed() || r.Outcome.RuleIndex == 1 {
		t.Fatalf("an unsigned impostor must not match Claude Code's rule: %+v", r)
	}
	procs, err := audit.ParseChain(e.lastLine(t)["chain"])
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range procs {
		if p.PID == tab.Procs[0].PID {
			found = true
			if p.Name != "claude-code" || !p.Deleted || p.Identity != "" {
				t.Errorf("impostor in the audit chain: %+v; want name \"claude-code\" marked deleted, no identity", p)
			}
		}
	}
	if !found {
		t.Fatalf("impostor missing from the audit chain %q", e.lastLine(t)["chain"])
	}
}

// Attack: a live, unsigned binary literally named
// "claude-code (file deleted)" is logged under that name, quoted and NOT
// marked deleted, so the audit line of a deleted Claude Code can't be
// forged by a file name (and the reverse); in the dialog it is one quoted
// name.
func TestLiteralDeletedNameIsNotMarked(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	const name = "claude-code (file deleted)"
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/" + name, Args: []string{"claude"}, Code: fake.Unsigned},
		fake.SSHProc("git@github.com"))
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Allowed() {
		t.Fatalf("an unsigned look-alike must not be allowed: %+v", r)
	}
	chain := e.lastLine(t)["chain"]
	if strings.Contains(chain, ", deleted)") || !strings.Contains(chain, `"claude-code (file deleted)"(`) {
		t.Fatalf("want the literal name as one quoted name, not marked deleted: %q", chain)
	}
	procs, err := audit.ParseChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range procs {
		if p.PID == tab.Procs[0].PID {
			found = true
			if p.Name != name || p.Deleted || p.Identity != "" {
				t.Errorf("look-alike in the audit chain: %+v; want name %q, not deleted, no identity", p, name)
			}
		}
	}
	if !found {
		t.Fatalf("look-alike missing from the audit chain %q", chain)
	}
}
