package broker

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 7: a session approval given to a tool the rule names
// (Claude Code) is that tool's run. It ends when the process exits, not
// when the tab's shell does hours later; everything the run starts shares
// it; the dialog's Scope line names the run; the audit line's session= and
// the remembered approval's scope id are the run's, so `nazar status` and
// `nazar revoke --session` agree.

// runID is the session id of a process's run, as `nazar status` shows it.
func runID(t *testing.T, e *env, ref platform.ProcessRef) string {
	t.Helper()
	info, err := e.f.Process(ref)
	if err != nil {
		t.Fatal(err)
	}
	return caller.SessionID{PID: ref.PID, Start: info.StartTime}.String()
}

func TestApprovalEndsWithTheRun(t *testing.T) {
	e := newEnv(t)
	ch, cancel := e.cache.Subscribe()
	defer cancel()
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
	claude := tab.Procs[0]
	run := runID(t, e, claude)
	p, f := e.handleShown(t, e.req("github", tab.Peer()))
	if f["rule"] != "1" || f["scope"] != "session" || f["session"] != run {
		t.Fatalf("audit %v, want rule 1 in the claude run %s", f, run)
	}
	if want := "Scope: this claude run, for github.com only"; !containsLine(p.Lines, want) {
		t.Fatalf("dialog lines %q, want %q", p.Lines, want)
	}
	if l := e.cache.List(); len(l) != 1 || l[0].Key.ScopeID != "session:"+run || l[0].Scope != "session" {
		t.Fatalf("remembered %+v, want one session approval keyed by the run", l)
	}
	if e.f.ExitWatchers(claude) != 1 || e.f.ExitWatchers(tab.Shell) != 0 {
		t.Fatalf("exit watchers: claude %d, shell %d; want the run watched, not the tab", e.f.ExitWatchers(claude), e.f.ExitWatchers(tab.Shell))
	}
	// Anything the run starts is covered, and a new kind of request in it
	// says what the run already has.
	again := e.f.Launch(claude, fake.SSHProc("git@github.com"))
	if r := e.b.Handle(e.req("github", again)); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("second request in the run: %+v", r)
	}
	git := e.req("github", again)
	git.Op = approval.Op{ID: "sign:git", Text: "git commits and tags"}
	if p, _ := e.handleShown(t, git); !containsLine(p.Lines, "Already approved for this claude run: github.com") {
		t.Fatalf("dialog lines %q, want the run's earlier approval listed", p.Lines)
	}
	if len(e.cache.List()) != 2 {
		t.Fatalf("remembered %+v, want two approvals of the run", e.cache.List())
	}
	// The run ends: both approvals go, as `nazar status --follow` reports.
	e.f.Exit(claude)
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("approvals outlived the run: %+v", l)
	}
	removed := 0
	for drained := false; !drained; {
		select {
		case ev := <-ch:
			if ev.Type == approval.Removed {
				removed++
				if ev.Reason != "session ended" {
					t.Fatalf("removal reason %q, want %q", ev.Reason, "session ended")
				}
			}
		default:
			drained = true
		}
	}
	if removed != 2 {
		t.Fatalf("%d removals reported, want 2", removed)
	}
	// The tab is still open; a new claude in it asks again.
	next := e.f.Launch(tab.Shell, fake.ClaudeProc())
	before := e.f.CountShown(fake.KindConfirm)
	r := e.b.Handle(e.req("github", e.f.Launch(next, fake.SSHProc("git@github.com"))))
	if r.Decision != audit.Approved || e.f.CountShown(fake.KindConfirm) != before+1 {
		t.Fatalf("a new run in the tab: %+v, %d dialogs", r, e.f.CountShown(fake.KindConfirm)-before)
	}
	shown := e.f.Shown()
	if text := strings.Join(shown[len(shown)-1].Prompt.Lines, "\n"); strings.Contains(text, "Already approved") {
		t.Fatalf("a new run is a first prompt:\n%s", text)
	}
}

// THREAT-MODEL 5.12's first case, closed: a script in the tab, outside the
// approved run, starts its own `claude -p "git push …"`. It has claude in
// its chain and the tab holds an approval for the claude rule, but it is
// another run: a prompt, with no "Already approved" line. The approved
// run's own nested claude still shares its approval (5.2). Each run's
// approval ends with its own process, and `nazar revoke --session` takes
// the id the audit line shows.
func TestAnotherRunInTheTabIsNotCovered(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
	claude := tab.Procs[0]
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("the user's run: %+v", r)
	}
	first := e.lastLine(t)
	bash := fake.Proc{Path: "/bin/bash", Args: []string{"bash", "evil.sh"}, Code: fake.AppleCode("com.apple.bash")}
	stray := e.f.Launch(e.f.Launch(tab.Shell, bash), fake.ClaudeProc())
	r := e.b.Handle(e.req("github", e.f.Launch(stray, fake.SSHProc("git@github.com"))))
	if r.Decision != audit.Approved || r.Outcome.RuleIndex != 1 || e.f.CountShown(fake.KindConfirm) != 2 {
		t.Fatalf("a claude the tab's script started rode on the first run's approval: %+v, %d dialogs", r, e.f.CountShown(fake.KindConfirm))
	}
	if text := strings.Join(e.f.Shown()[1].Prompt.Lines, "\n"); strings.Contains(text, "Already approved") {
		t.Fatalf("a new run is a first prompt:\n%s", text)
	}
	if f := e.lastLine(t); f["session"] == first["session"] || f["session"] != runID(t, e, stray) {
		t.Fatalf("audit session %q, want the stray run %s (the first run is %s)", f["session"], runID(t, e, stray), first["session"])
	}
	inner := e.f.Launch(e.f.Launch(claude, bash), fake.ClaudeProc())
	if r := e.b.Handle(e.req("github", e.f.Launch(inner, fake.SSHProc("git@github.com")))); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("a claude the approved run started: %+v, want the run's approval", r)
	}
	if n := len(e.cache.List()); n != 2 {
		t.Fatalf("%d approvals, want one per run", n)
	}
	e.f.Exit(stray)
	l := e.cache.List()
	if len(l) != 1 || l[0].Key.ScopeID != "session:"+first["session"] {
		t.Fatalf("after the stray run exited: %+v, want the user's run's approval only", l)
	}
	if n := e.cache.RevokeScope("session:"+first["session"], "revoked"); n != 1 || len(e.cache.List()) != 0 {
		t.Fatalf("revoke --session with the audit line's id revoked %d", n)
	}
}

// A run that exits while its dialog is open leaves no approval behind, as
// a tab closed during a prompt does not.
func TestRunEndsDuringPrompt(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	e.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer {
		e.f.Exit(tab.Procs[0])
		return fake.Answer{Allow: true}
	})
	e.b.Handle(e.req("github", tab.Peer()))
	waitFor(t, "an approval for a run that already ended was kept", func() bool {
		return len(e.cache.List()) == 0 && e.f.LiveApprovals() == 0
	})
}

// The run's name in the Scope line is the tool's executable name, which the
// tool's author chose: it is rendered like a program name (quoted unless a
// plain word) and the line is cleaned, so it cannot read as another scope.
func TestRunNounIsRenderedLikeAProgramName(t *testing.T) {
	e := newEnv(t)
	evil := fake.Proc{Path: "/Users/u/bin/terminal session\x1b[2J", Args: []string{"claude"}, Code: fake.ClaudeCode}
	tab := e.f.ITermTab(platform.ProcessRef{}, evil, fake.SSHProc("h"))
	p, _ := e.handleShown(t, e.req("github", tab.Peer()))
	n := 0
	for _, l := range p.Lines {
		noControl(t, "line", l)
		if strings.HasPrefix(strings.TrimSpace(l), "Scope:") {
			n++
			if !strings.HasPrefix(l, `Scope: this "terminal session`) || !strings.Contains(l, `" run, for github.com only`) {
				t.Errorf("scope line %q", l)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d Scope lines in %q", n, p.Lines)
	}
}
