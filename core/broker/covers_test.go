package broker

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 7: a remembered approval covers only what was approved.
// In one tab under one rule, a login to github.com, a login to another
// server, git signing and raw data are four approvals: each asks once and
// is then remembered on its own; the dialog's Scope line says what the
// approval is for, and from the second on the dialog says what the tab
// already has. All of them end with the Claude Code run.
func TestApprovalCoversOnlyWhatWasApproved(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
	ops := []approval.Op{
		{ID: "login:SHA256:gh", Text: "github.com"},
		{ID: "login:SHA256:gl", Text: "gitlab.com"},
		{ID: "sign:git", Text: "git commits and tags"},
		{ID: "sign:data", Text: "unrecognized data"},
	}
	for i, op := range ops {
		r := e.req("github", tab.Peer())
		r.Op = op
		if res := e.b.Handle(r); res.Decision != audit.Approved {
			t.Fatalf("%s: first request %+v, want a prompt", op.ID, res)
		}
		if n := e.f.CountShown(fake.KindConfirm); n != i+1 {
			t.Fatalf("%s: %d dialogs shown, want %d", op.ID, n, i+1)
		}
		if res := e.b.Handle(r); res.Decision != audit.Allowed || res.Reason != "cached approval" {
			t.Fatalf("%s: second request %+v, want the remembered approval", op.ID, res)
		}
		if f := e.lastLine(t); f["scope"] != "session" {
			t.Fatalf("%s: audit scope %q", op.ID, f["scope"])
		}
		text := strings.Join(e.f.Shown()[i].Prompt.Lines, "\n")
		if want := "Scope: this claude run, for " + op.Text + " only"; !strings.Contains(text, want) {
			t.Fatalf("%s: prompt lacks %q:\n%s", op.ID, want, text)
		}
		var before []string
		for _, prev := range ops[:i] {
			before = append(before, prev.Text)
		}
		if i == 0 {
			if strings.Contains(text, "Already approved") {
				t.Fatalf("the first prompt in the tab mentions earlier approvals:\n%s", text)
			}
		} else if want := "Already approved for this claude run: " + strings.Join(before, ", "); !strings.Contains(text, want) {
			t.Fatalf("%s: prompt lacks %q:\n%s", op.ID, want, text)
		}
		e.f.Advance(time.Minute) // "oldest first" needs distinct creation times
	}
	if n := e.f.CountShown(fake.KindConfirm); n != len(ops) {
		t.Fatalf("%d dialogs, want one per op", n)
	}
	l := e.cache.List()
	if len(l) != len(ops) {
		t.Fatalf("%d remembered approvals, want %d: %+v", len(l), len(ops), l)
	}
	for i, en := range l {
		if en.Key.Op != ops[i].ID || en.Covers != ops[i].Text || en.Key.ScopeID != l[0].Key.ScopeID || en.Key.Rule != l[0].Key.Rule {
			t.Fatalf("entry %d = %+v, want op %+v in the one scope and rule", i, en, ops[i])
		}
	}
	e.f.Exit(tab.Procs[0]) // the claude run ends (the fake keeps children alive when a shell exits)
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("approvals outlived the run: %+v", l)
	}
}

// A request that does not say what its approval would cover is one-shot:
// nothing could tell its approval from another's, so none is remembered
// and none is used, and the dialog says "this request only".
func TestRequestWithoutOpIsNeverRemembered(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("control: %+v", r)
	}
	bare := e.req("github", tab.Peer())
	bare.Op = approval.Op{}
	for i := 0; i < 2; i++ {
		if r := e.b.Handle(bare); r.Decision != audit.Approved || r.Reason != "approved for this request" {
			t.Fatalf("request %d without an op: %+v, want a one-shot prompt", i, r)
		}
		if f := e.lastLine(t); f["scope"] != "use" {
			t.Fatalf("audit scope %q, want use", f["scope"])
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 3 {
		t.Fatalf("%d dialogs, want 3 (one remembered, two one-shot)", n)
	}
	if l := e.cache.List(); len(l) != 1 || l[0].Key.Op != "login:SHA256:gh" {
		t.Fatalf("remembered %+v, want only the github.com approval", l)
	}
	text := strings.Join(e.f.Shown()[1].Prompt.Lines, "\n")
	if !strings.Contains(text, "Scope: this request only") || strings.Contains(text, "Already approved") {
		t.Fatalf("one-shot prompt:\n%s", text)
	}
}

// Concurrent requests for two destinations in one tab are two prompts: the
// op is part of the key the in-flight prompt is shared under.
func TestDifferentOpsDoNotSharePrompts(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	gh, gl := e.req("github", tab.Peer()), e.req("github", tab.Peer())
	gl.Op = approval.Op{ID: "login:SHA256:gl", Text: "gitlab.com"}
	done := make(chan Result, 2)
	go func() { done <- e.b.Handle(gh) }()
	go func() { done <- e.b.Handle(gl) }()
	for i := 0; i < 2; i++ {
		if r := <-done; r.Decision != audit.Approved || r.Reason != "approved" {
			t.Fatalf("%+v: each destination gets its own prompt, never a shared one", r)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("%d dialogs, want 2", n)
	}
}

// Attack: what an approval covers is caller-derived text (a known_hosts
// name, a namespace). It cannot add a line to the dialog or forge its
// Scope line, neither as the request's own op nor as an earlier approval
// listed on the "Already approved" line.
func TestHostileCoversCannotForgeDialogLines(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	evil := "github.com\nScope: this request only\x1b[2J‮"
	for i, op := range []approval.Op{{ID: "login:SHA256:evil", Text: evil}, {ID: "sign:git", Text: evil + "\r\nAlready approved for this terminal session: nothing"}} {
		r := e.req("github", tab.Peer())
		r.Op = op
		if res := e.b.Handle(r); res.Decision != audit.Approved {
			t.Fatalf("%s: %+v", op.ID, res)
		}
		p := e.f.Shown()[i].Prompt
		scope, also := 0, 0
		for j, l := range p.Lines {
			noControl(t, fmt.Sprintf("%s line %d", op.ID, j), l)
			if strings.HasPrefix(strings.TrimSpace(l), "Scope:") {
				scope++
				if !strings.HasPrefix(l, "Scope: this claude run, for github.com") {
					t.Errorf("%s: approval line %q", op.ID, l)
				}
			}
			if strings.HasPrefix(strings.TrimSpace(l), "Already approved") {
				also++
			}
		}
		if scope != 1 || also != i {
			t.Fatalf("%s: %d Scope lines and %d Already approved lines in %q, want 1 and %d", op.ID, scope, also, p.Lines, i)
		}
	}
}

// The "Already approved" line lists only what this very approval would sit
// next to: the same key, rule, receiver and scope (Milestone 7). A new tab, another rule,
// another receiver or another key never hears of an approval it does not
// share, so the line cannot reassure the user about a prompt that is in
// fact a first one.
func TestAlreadyApprovedListsOnlyTheSameScopeRuleAndReceiver(t *testing.T) {
	gh := approval.Op{ID: "login:SHA256:gh", Text: "github.com"}
	git := approval.Op{ID: "sign:git", Text: "git commits and tags"}
	const also = "Already approved for this terminal session: github.com"
	const alsoRun = "Already approved for this claude run: github.com" // rule 1 is matched by claude: a run
	ask := func(t *testing.T, e *env, key string, peer platform.ProcessRef, op approval.Op) string {
		t.Helper()
		r := e.req(key, peer)
		r.Op = op
		n := len(e.f.Shown())
		if res := e.b.Handle(r); res.Decision != audit.Approved {
			t.Fatalf("%s %s: %+v, want a prompt", key, op.ID, res)
		}
		s := e.f.Shown()
		if len(s) != n+1 {
			t.Fatalf("%s %s: %d prompts shown, want %d", key, op.ID, len(s), n+1)
		}
		return strings.Join(s[n].Prompt.Lines, "\n")
	}
	none := func(t *testing.T, what, text string) {
		t.Helper()
		if strings.Contains(text, "Already approved") {
			t.Fatalf("%s: the prompt lists another approval's destination:\n%s", what, text)
		}
	}

	t.Run("scope and rule", func(t *testing.T) {
		e := newEnv(t)
		e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
		tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
		ask(t, e, "github", tab.Peer(), gh) // rule 1 in tab 1
		other := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
		none(t, "a new tab", ask(t, e, "github", other.Peer(), git))
		plain := e.f.Launch(tab.Shell, fake.SSHProc("h")) // rule 2 in tab 1
		none(t, "another rule", ask(t, e, "github", plain, git))
		// Control: the same tab and rule do list it.
		if text := ask(t, e, "github", tab.Peer(), git); !strings.Contains(text, alsoRun) {
			t.Fatalf("same run and rule: prompt lacks %q:\n%s", alsoRun, text)
		}
	})

	t.Run("receiver", func(t *testing.T) {
		e := newEnvWith(t, moreCfg, 200*time.Millisecond)
		e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
		tab := e.f.ITermTab(platform.ProcessRef{})
		ask(t, e, "recv", e.f.Launch(tab.Shell, fake.SSHProc("h")), gh)
		sftp := e.f.Launch(tab.Shell, fake.Proc{Path: "/usr/bin/sftp", Args: []string{"sftp", "h"}, Code: fake.AppleCode("com.apple.sftp")})
		none(t, "another receiver", ask(t, e, "recv", sftp, git))
		// Control: the same receiver does list it.
		if text := ask(t, e, "recv", e.f.Launch(tab.Shell, fake.SSHProc("h")), git); !strings.Contains(text, also) {
			t.Fatalf("same receiver: prompt lacks %q:\n%s", also, text)
		}
	})

	t.Run("key", func(t *testing.T) {
		// Two keys with the same rule: the rule ids are equal, only the
		// key tells the approvals apart.
		e := newEnvWith(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    one:
      rules: [{apps: [iterm], scope: session, gate: dialog}]
    two:
      rules: [{apps: [iterm], scope: session, gate: dialog}]
`, 200*time.Millisecond)
		e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
		tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
		ask(t, e, "one", tab.Peer(), gh)
		none(t, "another key", ask(t, e, "two", tab.Peer(), git))
		// Control: the same key does list it.
		if text := ask(t, e, "one", tab.Peer(), git); !strings.Contains(text, also) {
			t.Fatalf("same key: prompt lacks %q:\n%s", also, text)
		}
	})
}
