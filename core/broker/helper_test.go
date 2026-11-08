package broker

import (
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// A tab whose iTermServer was orphaned before nazar-agent saw it
// below iTerm2 stays unknown, but the Claude Code in it is still Claude
// Code: the claude rule matches. The dialog keeps its Unknown app header and
// names claude as the process that matched; the audit line has no app= and
// names claude in matched=; nothing is remembered, so each request asks.
func TestUnwitnessedOrphanedTabGetsTheToolRule(t *testing.T) {
	e := newEnv(t)
	tab := e.f.OrphanedClaudeTab()
	claude := tab.Procs[0]
	for i := 0; i < 2; i++ {
		p, f := e.handleShown(t, e.req("github", tab.Peer()))
		if !p.Unknown || !strings.HasPrefix(p.Lines[0], "Unknown app:") || !strings.HasPrefix(p.Title, "Unknown app wants") {
			t.Fatalf("request %d: the dialog must stay an Unknown app's:\n%s", i, promptText(p))
		}
		if want := "matched: claude (rule 1, in the chain)"; !containsLine(p.Lines, want) {
			t.Fatalf("request %d: no %q line:\n%s", i, want, promptText(p))
		}
		if f["rule"] != "1" || f["app"] != "" || f["scope"] != "use" || f["session"] != "" || f["decision"] != "approved" {
			t.Fatalf("request %d: audit rule=%q app=%q scope=%q session=%q decision=%q", i, f["rule"], f["app"], f["scope"], f["session"], f["decision"])
		}
		procs, err := audit.ParseChain(f["matched"])
		if err != nil || len(procs) != 1 || procs[0].Name != "claude" || procs[0].PID != claude.PID || procs[0].Identity != "Q6L2SF6YDW:com.anthropic.claude-code" {
			t.Fatalf("request %d: matched = %q (%v), want claude(%d, Q6L2SF6YDW:com.anthropic.claude-code)", i, f["matched"], err, claude.PID)
		}
	}
	if len(e.cache.List()) != 0 {
		t.Fatalf("an unknown chain was remembered: %+v", e.cache.List())
	}
}

// Milestone 7: iTerm2 restarted (an update); its tabs live on under
// the orphaned iTermServer. Their requests still get iTerm2's rules, the
// dialog names iTerm2 and the helper it came through, the audit line
// records the app and the helper, a session approval covers the tab and
// only the tab, and a silent app: rule stays silent (an earlier bug:
// `gate: none` refused, because the chain had become unknown).
func TestOrphanedTabKeepsItsAppRules(t *testing.T) {
	e := newEnv(t)
	tabA := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), gitSSH("/Users/u/projects/foo"))
	tabB := e.f.ITermTab(tabA.App, fake.ClaudeProc(), gitSSH("/Users/u/projects/foo"))
	e.r.Resolve(tabA.Peer()) // nazar-agent sees each tab's server below iTerm2 …
	e.r.Resolve(tabB.Peer())
	e.f.Exit(tabA.App)                  // … then the update restarted iTerm2 …
	e.f.ITermTab(platform.ProcessRef{}) // … which runs again, with a new server and tab

	prompt, f := e.handleShown(t, e.req("github", tabA.Peer()))
	if prompt.Unknown || prompt.Title != `iTerm2 wants to use key "github"` {
		t.Fatalf("prompt %+v", prompt)
	}
	if want := "chain: iTerm2 (via iTermServer-3.6) → bash → claude → ssh"; !containsLine(prompt.Lines, want) {
		t.Fatalf("lines %q, want %q", prompt.Lines, want)
	}
	for _, l := range prompt.Lines {
		if len(l) >= 11 && l[:11] == "Unknown app" {
			t.Fatalf("an orphaned tab is not an unknown chain: %q", prompt.Lines)
		}
	}
	if f["app"] != "com.googlecode.iterm2" || f["rule"] != "1" || f["scope"] != "session" || f["session"] == "" {
		t.Fatalf("audit app=%q rule=%q scope=%q session=%q", f["app"], f["rule"], f["scope"], f["session"])
	}
	procs, err := audit.ParseChain(f["chain"])
	if err != nil || len(procs) != 4 || procs[0].Name != "iTermServer-3.6" || procs[0].Identity != "H7V7XYVQ7D:com.googlecode.iterm2" || procs[1].Name != "bash" || procs[3].Name != "ssh" {
		t.Fatalf("chain %q (%v): want the helper first, then the tab's shell down", f["chain"], err)
	}

	// The approval is the tab's: tab A asks no more, tab B still does.
	before := len(e.f.Shown())
	if r := e.b.Handle(e.req("github", tabA.Peer())); r.Decision != audit.Allowed || len(e.f.Shown()) != before {
		t.Fatalf("second request from the tab: %+v, %d prompts", r, len(e.f.Shown())-before)
	}
	if _, f := e.handleShown(t, e.req("github", tabB.Peer())); f["app"] != "com.googlecode.iterm2" {
		t.Fatalf("tab B audit app=%q", f["app"])
	}

	// A silent app: rule is silent for an orphaned tab too.
	if r := e.b.Handle(e.req("deploy", tabA.Peer())); r.Decision != audit.Allowed {
		t.Fatalf("gate none through the orphaned helper: %+v", r)
	}
	if l := e.lastLine(t); l["app"] != "com.googlecode.iterm2" || l["gate"] != "none" || l["decision"] != "allowed" {
		t.Fatalf("audit %+v", l)
	}
}

// A scope: app approval given to an orphaned tab is iTerm2's: it is
// remembered under the app's bundle ID (so `nazar revoke --app` finds it),
// covers the next request without a prompt, and ends when the iTerm2 it
// was given under quits (THREAT-MODEL 4.2 "Approvals end").
func TestOrphanedTabAppScopeEndsWhenTheAppQuits(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	old := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.r.Resolve(old.Peer())
	e.f.Exit(old.App)
	fresh := e.f.ITermTab(platform.ProcessRef{}).App

	req := e.req("appkey", old.Peer())
	if req.Chain.Unknown || req.Chain.App.Ref != fresh {
		t.Fatalf("control: the orphaned tab is not the new iTerm2's: %+v", req.Chain)
	}
	if r := e.b.Handle(req); r.Decision != audit.Approved {
		t.Fatalf("first request: %+v", r)
	}
	l := e.cache.List()
	if len(l) != 1 || l[0].Scope != "app" || l[0].App != "com.googlecode.iterm2" {
		t.Fatalf("approvals %+v, want one scope: app approval under iTerm2", l)
	}
	before := len(e.f.Shown())
	if r := e.b.Handle(e.req("appkey", old.Peer())); r.Decision != audit.Allowed || len(e.f.Shown()) != before {
		t.Fatalf("second request: %+v, %d prompts", r, len(e.f.Shown())-before)
	}
	e.f.Exit(fresh)
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("approvals left after iTerm2 quit: %+v", l)
	}
}
