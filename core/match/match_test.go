package match

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/trust"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

var (
	claudeM = config.Matcher{Kind: config.MatchSigned, Team: "Q6L2SF6YDW", ID: "com.anthropic.claude-code"}
	itermM  = config.Matcher{Kind: config.MatchApp, ID: "com.googlecode.iterm2"}
	sshM    = config.Matcher{Kind: config.MatchSigned, Team: "apple", ID: "com.apple.openssh"}
	kubectl = config.Matcher{Kind: config.MatchPath, Path: "/opt/homebrew/bin/kubectl"}
	anyM    = config.Matcher{Kind: config.MatchAny}
	unknown = config.Matcher{Kind: config.MatchUnknown}
)

type env struct {
	f     *fake.Fake
	r     *caller.Resolver
	store *trust.Store
	e     *Evaluator
	notes []string
}

// newEnv is the usual state after the config was approved: iTerm2's team
// was pinned from the installed app at approval (spec 4.2). Tests of
// unpinned apps use newUnpinnedEnv.
func newEnv(t *testing.T) *env {
	en := newUnpinnedEnv(t)
	if _, err := en.store.Pin("com.googlecode.iterm2", "H7V7XYVQ7D"); err != nil {
		t.Fatal(err)
	}
	return en
}

func newUnpinnedEnv(t *testing.T) *env {
	f := fake.New(t0)
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	en := &env{f: f, r: &caller.Resolver{P: f}, store: st}
	en.e = &Evaluator{Trust: st, Note: func(m string) { en.notes = append(en.notes, m) }}
	return en
}

func TestSignedMatchesAnyProcessInChain(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.Proc{Path: "/usr/bin/python3", Code: fake.AppleCode("com.apple.python3")}, fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	if !en.e.Apps([]config.Matcher{claudeM}, c) {
		t.Fatal("claude deep in the chain must match")
	}
	plain := en.f.ITermTab(tab.App, fake.SSHProc("h"))
	if en.e.Apps([]config.Matcher{claudeM}, en.r.Resolve(plain.Peer())) {
		t.Fatal("claude must not match a chain without it")
	}
}

func TestSignedRejectsAdHocAndWrongID(t *testing.T) {
	en := newEnv(t)
	fakeClaude := fake.Proc{Path: "/tmp/claude", Code: platform.CodeIdentity{Signed: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"}}
	tab := en.f.ITermTab(platform.ProcessRef{}, fakeClaude, fake.SSHProc("h"))
	if en.e.Apps([]config.Matcher{claudeM}, en.r.Resolve(tab.Peer())) {
		t.Fatal("ad-hoc code must never match signed:")
	}
	other := fake.Proc{Path: "/x", Code: platform.CodeIdentity{Signed: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.other"}}
	tab2 := en.f.ITermTab(tab.App, other, fake.SSHProc("h"))
	if en.e.Apps([]config.Matcher{claudeM}, en.r.Resolve(tab2.Peer())) {
		t.Fatal("wrong signing id must not match")
	}
	teamOnly := config.Matcher{Kind: config.MatchSigned, Team: "Q6L2SF6YDW"}
	if !en.e.Apps([]config.Matcher{teamOnly}, en.r.Resolve(tab2.Peer())) {
		t.Fatal("team-only matcher must match any id of that team")
	}
}

func TestAppMatchesOnlyThePinnedTeamAndRejectsImpostor(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if !en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(tab.Peer())) {
		t.Fatal("iterm with the pinned team must match")
	}
	evil := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/Evil.app/x", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "com.googlecode.iterm2"}, App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"}})
	peer := en.f.Launch(evil, fake.SSHProc("h"))
	if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(peer)) {
		t.Fatal("same bundle id with another team must not match the pin")
	}
	if !strings.Contains(strings.Join(en.notes, "\n"), "EVILTEAM00 but H7V7XYVQ7D is pinned") {
		t.Fatalf("mismatch not noted: %v", en.notes)
	}
	if team, _ := en.store.PinnedTeam("com.googlecode.iterm2"); team != "H7V7XYVQ7D" {
		t.Fatalf("pin changed to %q", team)
	}
}

func TestAppRequiresValidSignature(t *testing.T) {
	en := newEnv(t)
	// Forged fields claiming the pinned team: ad-hoc and unsigned code has no
	// team at all (CodeIdentity.Team), so it never matches the pin.
	for name, code := range map[string]platform.CodeIdentity{
		"adhoc":    {Signed: true, AdHoc: true, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2"},
		"unsigned": {TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2"},
	} {
		app := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/i", Code: code, App: &fake.App{BundleID: "com.googlecode.iterm2"}})
		peer := en.f.Launch(app, fake.SSHProc("h"))
		if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(peer)) {
			t.Fatalf("%s app must not match", name)
		}
	}
	if team, _ := en.store.PinnedTeam("com.googlecode.iterm2"); team != "H7V7XYVQ7D" {
		t.Fatalf("pin changed to %q", team)
	}
	un := newUnpinnedEnv(t)
	adhoc := un.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/i", Code: platform.CodeIdentity{Signed: true, AdHoc: true}, App: &fake.App{BundleID: "com.googlecode.iterm2"}})
	if un.e.Apps([]config.Matcher{itermM}, un.r.Resolve(un.f.Launch(adhoc, fake.SSHProc("h")))) {
		t.Fatal("ad-hoc app must not match")
	}
	if _, ok := un.store.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatal("ad-hoc app must not create a pin")
	}
}

func TestAppExplicitTeam(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	wrong := config.Matcher{Kind: config.MatchApp, ID: "com.googlecode.iterm2", Team: "OTHER"}
	if en.e.Apps([]config.Matcher{wrong}, en.r.Resolve(tab.Peer())) {
		t.Fatal("explicit team mismatch must not match")
	}
}

// An unknown chain has no app, but its processes are still the kernel's
// parent links, each verified: signed: matches a process that is in
// it, app: never does (spec 4.2).
func TestUnknownChainMatchesItsProcessesNotAnApp(t *testing.T) {
	en := newEnv(t)
	cl := en.f.Launch(platform.ProcessRef{}, fake.ClaudeProc())
	peer := en.f.Launch(cl, fake.SSHProc("h"))
	c := en.r.Resolve(peer)
	if !c.Unknown || c.Truncated {
		t.Fatal("setup: chain must be unknown and whole")
	}
	if ref, ok := en.e.Matched([]config.Matcher{claudeM}, c); !ok || ref != cl {
		t.Fatalf("signed: must match claude in an unknown chain: %v %v, want %v", ref, ok, cl)
	}
	if en.e.Apps([]config.Matcher{itermM}, c) {
		t.Fatal("app: must not match an unknown chain")
	}
	if !en.e.Apps([]config.Matcher{anyM}, c) || !en.e.Apps([]config.Matcher{unknown}, c) {
		t.Fatal("any and unknown must match an unknown chain")
	}
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if en.e.Apps([]config.Matcher{unknown}, en.r.Resolve(tab.Peer())) {
		t.Fatal("unknown must not match a known chain")
	}
}

// A chain attributed to an app only through the responsible process is
// unknown (spec 4.1 step 5): app: and signed: for that app must not match,
// and the attribution stays in the summary. The ssh in the chain is its own
// process, so signed: for it matches.
func TestResponsibleAppIsNoIdentity(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{})
	mux := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	en.f.SetResponsible(mux, tab.App)
	c := en.r.Resolve(mux)
	if c.AppSource != caller.AppFromResponsible || c.Summary() != "iTerm2 (responsible) → ssh" {
		t.Fatalf("setup: want responsible attribution, got source %v summary %q", c.AppSource, c.Summary())
	}
	if en.e.Apps([]config.Matcher{itermM}, c) {
		t.Fatal("app: must not match a responsible-only app")
	}
	if en.e.Apps([]config.Matcher{{Kind: config.MatchSigned, Team: "H7V7XYVQ7D"}}, c) {
		t.Fatal("signed: must not match a responsible-only app's signature")
	}
	if ref, ok := en.e.Matched([]config.Matcher{sshM}, c); !ok || ref != mux {
		t.Fatalf("signed: for the ssh that is in the chain: %v %v", ref, ok)
	}
	if !en.e.Apps([]config.Matcher{anyM}, c) || !en.e.Apps([]config.Matcher{unknown}, c) {
		t.Fatal("any and unknown must match")
	}
	if len(en.notes) != 0 {
		t.Fatalf("no pin or note for an unknown chain, got %q", en.notes)
	}
}

// Chain shedding. Config intent, spec 4.2 and threat model
// 8 ("per-caller rules are how you narrow"):
//
//   - apps: claude   gate: login   # Claude Code must get Touch ID
//   - apps: iterm    gate: none    # me in my terminal: silent
//
// A process Claude Code started leaves its chain, by double-forking so it
// is re-parented to launchd, or by nesting past the depth limit, and is
// still "responsible to" the tab's app (responsibility is inherited). It
// must not then match the iterm rule: the chain is unknown, so neither
// rule matches and the request falls to the fallback or an unknown rule.
// The ssh is still in its own chain: signed: for it matches a whole chain
// (spec 4.2), never a truncated one.
func TestShedChainCannotTakeTheAppRule(t *testing.T) {
	bash := fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}
	itermSigned := config.Matcher{Kind: config.MatchSigned, Team: "H7V7XYVQ7D"}

	check := func(t *testing.T, en *env, c *caller.Chain) {
		t.Helper()
		if !c.Unknown {
			t.Fatalf("shed chain must be unknown, got %+v", c)
		}
		if en.e.Apps([]config.Matcher{claudeM}, c) {
			t.Fatal("claude rule must not match a chain Claude is no longer in")
		}
		if en.e.Apps([]config.Matcher{itermM}, c) || en.e.Apps([]config.Matcher{itermSigned}, c) {
			t.Fatal("BYPASS: shed chain took the app's rule through the responsible process")
		}
		if got := en.e.Apps([]config.Matcher{sshM}, c); got == c.Truncated {
			t.Fatalf("signed: for the ssh in the chain matched=%v, truncated=%v", got, c.Truncated)
		}
		if !en.e.Apps([]config.Matcher{unknown}, c) {
			t.Fatal("unknown must match")
		}
	}

	t.Run("double fork", func(t *testing.T) {
		en := newEnv(t)
		tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), bash)
		helper := en.f.Launch(tab.Peer(), bash)
		ssh := en.f.Launch(helper, fake.SSHProc("prod"))
		en.f.SetResponsible(ssh, tab.App)
		c := en.r.Resolve(ssh)
		if !en.e.Apps([]config.Matcher{claudeM}, c) || !en.e.Apps([]config.Matcher{itermM}, c) {
			t.Fatal("setup: the full chain must match both claude and iterm")
		}
		en.f.Exit(helper)
		check(t, en, en.r.Resolve(ssh))
	})

	t.Run("deep nesting", func(t *testing.T) {
		en := newEnv(t)
		tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
		parent := tab.Peer()
		for i := 0; i < caller.DefaultMaxDepth; i++ {
			parent = en.f.Launch(parent, bash)
		}
		ssh := en.f.Launch(parent, fake.SSHProc("prod"))
		en.f.SetResponsible(ssh, tab.App)
		c := en.r.Resolve(ssh)
		if !c.Truncated {
			t.Fatal("setup: chain must be truncated")
		}
		check(t, en, c)
	})

	t.Run("control: no responsible process", func(t *testing.T) {
		en := newEnv(t)
		tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
		helper := en.f.Launch(tab.Peer(), bash)
		ssh := en.f.Launch(helper, fake.SSHProc("prod"))
		en.f.Exit(helper)
		en.f.SetResponsible(ssh, platform.ProcessRef{})
		c := en.r.Resolve(ssh)
		if c.AppSource != caller.AppNone {
			t.Fatalf("setup: no responsible app, got %v", c.AppSource)
		}
		check(t, en, c)
	})
}

func TestReceiverIsThePeerOnly(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	if !en.e.Receiver([]config.Matcher{sshM}, c) {
		t.Fatal("ssh peer must match to: [ssh]")
	}
	if en.e.Receiver([]config.Matcher{claudeM}, c) {
		t.Fatal("to: checks only the receiver, not the chain")
	}
	if !en.e.Receiver([]config.Matcher{anyM}, c) {
		t.Fatal("to: [any]")
	}
	empty := &caller.Chain{Unknown: true}
	if en.e.Receiver([]config.Matcher{sshM}, empty) {
		t.Fatal("no peer, no receiver match")
	}
}

func TestIdentity(t *testing.T) {
	if got := Identity(platform.ProcessInfo{Code: fake.AppleCode("com.apple.openssh")}); got != "apple:com.apple.openssh" {
		t.Fatal(got)
	}
	if got := Identity(platform.ProcessInfo{Path: "/x", Code: platform.CodeIdentity{CDHash: []byte{1}}}); got != "path:/x#01" {
		t.Fatal(got)
	}
}

// ---- Additional behaviour, edge and attack cases (spec 4.2) ----

// Code that is not validly signed can't claim a team: unsigned code with a
// team ID, or ad-hoc code claiming to be Apple's, never matches signed:.
func TestForgedSignatureFieldsNeverMatchSigned(t *testing.T) {
	en := newEnv(t)
	forged := []platform.CodeIdentity{
		{Signed: false, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
		{Signed: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
		{Signed: false, Apple: true, SigningID: "com.anthropic.claude-code"},
	}
	appleSSH := []platform.CodeIdentity{
		{Signed: false, Apple: true, SigningID: "com.apple.openssh"},
		{Signed: true, AdHoc: true, Apple: true, SigningID: "com.apple.openssh"},
	}
	for i, code := range forged {
		tab := en.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/claude", Code: code}, fake.SSHProc("h"))
		if en.e.Apps([]config.Matcher{claudeM, {Kind: config.MatchSigned, Team: "Q6L2SF6YDW"}}, en.r.Resolve(tab.Peer())) {
			t.Fatalf("forged identity %d matched signed:", i)
		}
	}
	for i, code := range appleSSH {
		app := en.f.ITermTab(platform.ProcessRef{}).App
		// Chain without any genuine Apple-signed process: the app itself is the parent.
		peer := en.f.Launch(app, fake.Proc{Path: "/tmp/ssh", Code: code})
		c := en.r.Resolve(peer)
		if en.e.Receiver([]config.Matcher{sshM}, c) {
			t.Fatalf("forged Apple identity %d matched to: signed apple", i)
		}
		if en.e.Apps([]config.Matcher{sshM}, c) {
			t.Fatalf("forged Apple identity %d matched apps: signed apple", i)
		}
	}
}

// signed: with team apple matches Apple-signed code only, and a Developer ID
// team never matches an Apple matcher (or the other way round).
func TestSignedAppleTeam(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	if !en.e.Apps([]config.Matcher{sshM}, c) {
		t.Fatal("Apple ssh in the chain must match signed: {team: apple, id: com.apple.openssh}")
	}
	devID := fake.Proc{Path: "/usr/local/bin/ssh", Code: platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "com.apple.openssh"}}
	app := en.f.ITermTab(platform.ProcessRef{}).App
	peer := en.f.Launch(app, devID)
	if en.e.Receiver([]config.Matcher{sshM}, en.r.Resolve(peer)) {
		t.Fatal("a Developer ID binary using Apple's signing id must not match team apple")
	}
}

func TestEmptyMatcherListNeverMatches(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	if en.e.Apps(nil, c) || en.e.Apps([]config.Matcher{}, c) {
		t.Fatal("no matchers, no match")
	}
	if en.e.Receiver(nil, c) {
		t.Fatal("no receiver matchers, no match")
	}
}

// A list matches if any of its matchers does ([iterm, cursor]).
func TestListMatchesIfAnyMatches(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	cursorM := config.Matcher{Kind: config.MatchApp, ID: "com.todesktop.230313mzl4w4u92"}
	if !en.e.Apps([]config.Matcher{cursorM, itermM}, c) {
		t.Fatal("[cursor, iterm] must match an iTerm chain")
	}
	if en.e.Apps([]config.Matcher{cursorM, claudeM}, c) {
		t.Fatal("[cursor, claude] must not match a plain iTerm chain")
	}
}

// In an unknown chain signed: matches a process that is in it,
// verified as in any chain. app: never
// matches one (spec 4.2 "Unknown chains").
func TestUnknownChainMatchesVerifiedProcessesOnly(t *testing.T) {
	en := newEnv(t)
	resolved := "/opt/homebrew/Cellar/kubernetes-cli/1.34.0/bin/kubectl"
	kc := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: resolved, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0xaa}}})
	peer := en.f.Launch(kc, fake.SSHProc("h"))
	c := en.r.Resolve(peer)
	if !c.Unknown || c.Truncated {
		t.Fatal("setup: chain must be unknown and whole")
	}
	for _, m := range []config.Matcher{sshM, {Kind: config.MatchSigned, Team: "apple"}} {
		if !en.e.Apps([]config.Matcher{m}, c) {
			t.Fatalf("%s did not match its process in an unknown chain", m.Canonical())
		}
	}
	if en.e.Apps([]config.Matcher{itermM}, c) {
		t.Fatal("app: matched an unknown chain")
	}
	// An unknown chain whose walk was cut short (recycled parent PID) may be
	// missing processes: nothing but any and unknown matches it, even though
	// the app is still running above it.
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	cl, _ := en.f.Process(tab.Procs[0])
	cl.StartTime = t0.Add(24 * time.Hour)
	en.f.SetProcess(cl)
	tc := en.r.Resolve(tab.Peer())
	if !tc.Unknown || !tc.Truncated {
		t.Fatalf("setup: want truncated unknown chain, got unknown=%v truncated=%v", tc.Unknown, tc.Truncated)
	}
	for _, m := range []config.Matcher{itermM, claudeM, sshM, {Kind: config.MatchSigned, Team: "apple"}} {
		if en.e.Apps([]config.Matcher{m}, tc) {
			t.Fatalf("%s matched a truncated unknown chain", m.Canonical())
		}
	}
	if !en.e.Apps([]config.Matcher{unknown}, tc) {
		t.Fatal("unknown must match a truncated unknown chain")
	}
}

// An example: a Claude Code session in an iTerm2 tab whose
// iTermServer was orphaned by an iTerm2 update before nazar-agent ever saw
// it below iTerm2. The chain is unknown, but claude is in it, validly
// signed: the claude rule matches, naming claude; app: does not.
func TestOrphanedUnwitnessedTabMatchesItsTool(t *testing.T) {
	en := newEnv(t)
	tab := en.f.OrphanedClaudeTab()
	c := en.r.Resolve(tab.Peer())
	if !c.Unknown || c.Truncated || c.AppSource == caller.AppFromHelper || len(c.Procs) != 7 {
		t.Fatalf("setup: want the whole unknown chain of 7, got unknown=%v truncated=%v source=%v procs=%d", c.Unknown, c.Truncated, c.AppSource, len(c.Procs))
	}
	ref, ok := en.e.Matched([]config.Matcher{itermM, claudeM}, c)
	if !ok || ref != tab.Procs[0] {
		t.Fatalf("claude rule: matched %v %v, want claude %v", ref, ok, tab.Procs[0])
	}
	if en.e.Apps([]config.Matcher{itermM}, c) || en.e.Apps([]config.Matcher{{Kind: config.MatchApp, ID: "com.googlecode.iterm2", Team: "H7V7XYVQ7D"}}, c) {
		t.Fatal("app: matched an unknown chain")
	}
	// The same tab without claude in it: only any and unknown.
	bare := en.f.OrphanedITermTab(fake.SSHProc("git@github.com"))
	bc := en.r.Resolve(bare.Peer())
	if !bc.Unknown || en.e.Apps([]config.Matcher{claudeM}, bc) || en.e.Apps([]config.Matcher{itermM}, bc) {
		t.Fatalf("bare orphaned tab: unknown=%v", bc.Unknown)
	}
}

// Impostors in an unknown chain: code that claims Claude Code's team and
// signing identifier but is ad hoc, unsigned, or of another team is not
// Claude Code, wherever it sits.
func TestUnknownChainRejectsImpostors(t *testing.T) {
	for name, code := range map[string]platform.CodeIdentity{
		"adhoc":      {Signed: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
		"unsigned":   {TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
		"other team": {Signed: true, TeamID: "EVILTEAM00", SigningID: "com.anthropic.claude-code"},
		"apple flag": {Signed: true, Apple: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
	} {
		t.Run(name, func(t *testing.T) {
			en := newEnv(t)
			tab := en.f.OrphanedITermTab(fake.Proc{Path: "/Users/u/.local/bin/claude", Args: []string{"claude"}, Code: code}, fake.SSHProc("h"))
			detached := en.f.Launch(en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/claude", Code: code}), fake.SSHProc("h"))
			for _, peer := range []platform.ProcessRef{tab.Peer(), detached} {
				c := en.r.Resolve(peer)
				if !c.Unknown {
					t.Fatal("setup: chain must be unknown")
				}
				if en.e.Apps([]config.Matcher{claudeM}, c) {
					t.Fatalf("an impostor (%+v) matched signed: claude", code)
				}
			}
		})
	}
}

// An unknown chain cut off by the depth limit may be missing what is above
// the cut (the processes a stricter rule names): it matches no signed:,
// even for a validly signed process below the cut.
func TestTruncatedUnknownChainMatchesNoProcess(t *testing.T) {
	en := newEnv(t)
	bash := fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}
	parent := en.f.Launch(platform.ProcessRef{}, bash)
	for i := 0; i < caller.DefaultMaxDepth; i++ {
		parent = en.f.Launch(parent, bash)
	}
	cl := en.f.Launch(parent, fake.ClaudeProc())
	peer := en.f.Launch(cl, fake.SSHProc("h"))
	c := en.r.Resolve(peer)
	if !c.Unknown || !c.Truncated || c.Procs[1].Ref != cl {
		t.Fatalf("setup: want a truncated unknown chain with claude in it, got unknown=%v truncated=%v", c.Unknown, c.Truncated)
	}
	if en.e.Apps([]config.Matcher{claudeM}, c) || en.e.Apps([]config.Matcher{sshM}, c) {
		t.Fatal("signed: matched a truncated unknown chain")
	}
	if !en.e.Apps([]config.Matcher{unknown}, c) || !en.e.Apps([]config.Matcher{anyM}, c) {
		t.Fatal("any and unknown must still match")
	}
}

// app: is about the GUI app of the chain. A CLI process carrying the app's
// signature, or a different app, does not make the chain "that app".
func TestAppMatchesTheChainAppOnly(t *testing.T) {
	en := newEnv(t)
	term := en.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
		Code: fake.AppleCode("com.apple.Terminal"),
		App:  &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"},
	})
	sh := en.f.Launch(term, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	itermBin := en.f.Launch(sh, fake.Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode})
	peer := en.f.Launch(itermBin, fake.SSHProc("h"))
	c := en.r.Resolve(peer)
	if en.e.Apps([]config.Matcher{itermM}, c) {
		t.Fatal("an iTerm2-signed CLI process inside Terminal.app must not match app: iterm")
	}
	if team, _ := en.store.PinnedTeam("com.googlecode.iterm2"); team != "H7V7XYVQ7D" {
		t.Fatalf("pin changed to %q", team)
	}
	if en.e.Apps([]config.Matcher{{Kind: config.MatchApp, ID: "com.apple.Terminal"}}, c) {
		t.Fatal("app: com.apple.Terminal must not match before its team is pinned")
	}
	if _, ok := en.store.PinnedTeam("com.apple.Terminal"); ok {
		t.Fatal("matching must never create a pin")
	}
	en.store.Pin("com.apple.Terminal", "apple") // as config approval would
	if !en.e.Apps([]config.Matcher{{Kind: config.MatchApp, ID: "com.apple.Terminal"}}, c) {
		t.Fatal("app: com.apple.Terminal must match once pinned to apple")
	}
}

// Pins live in the trust store (the Vault): a restarted daemon with a new
// evaluator still rejects an impostor of a pinned app.
func TestAppPinSurvivesRestart(t *testing.T) {
	f := fake.New(t0)
	v := fake.NewVault()
	r := &caller.Resolver{P: f}
	st1, _ := trust.Open(v)
	if _, err := st1.Pin("com.googlecode.iterm2", "H7V7XYVQ7D"); err != nil { // config approval
		t.Fatal(err)
	}
	e1 := &Evaluator{Trust: st1}
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if !e1.Apps([]config.Matcher{itermM}, r.Resolve(tab.Peer())) {
		t.Fatal("iterm must match")
	}
	st2, err := trust.Open(v)
	if err != nil {
		t.Fatal(err)
	}
	e2 := &Evaluator{Trust: st2} // nil Note must be fine
	evil := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/Evil.app/x", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "com.googlecode.iterm2"}, App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"}})
	if e2.Apps([]config.Matcher{itermM}, r.Resolve(f.Launch(evil, fake.SSHProc("h")))) {
		t.Fatal("impostor matched after restart")
	}
	if !e2.Apps([]config.Matcher{itermM}, r.Resolve(tab.Peer())) {
		t.Fatal("genuine iTerm2 must still match after restart")
	}
}

// Matching reads pins only, so a locked Keychain changes nothing: a pinned
// app still matches and an unpinned one still matches nothing.
func TestAppMatchingNeedsNoVaultWrites(t *testing.T) {
	f := fake.New(t0)
	v := fake.NewVault()
	st, _ := trust.Open(v)
	st.Pin("com.googlecode.iterm2", "H7V7XYVQ7D")
	v.FailPut = errors.New("keychain locked")
	e := &Evaluator{Trust: st}
	r := &caller.Resolver{P: f}
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if !e.Apps([]config.Matcher{itermM}, r.Resolve(tab.Peer())) {
		t.Fatal("a pinned app must match without writing anything")
	}
	cursorTab := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Cursor.app/Contents/MacOS/Cursor", Code: platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.todesktop.230313mzl4w4u92"}, App: &fake.App{BundleID: "com.todesktop.230313mzl4w4u92", Name: "Cursor"}})
	cursorM := config.Matcher{Kind: config.MatchApp, ID: "com.todesktop.230313mzl4w4u92"}
	if e.Apps([]config.Matcher{cursorM}, r.Resolve(f.Launch(cursorTab, fake.SSHProc("h")))) {
		t.Fatal("an unpinned app must not match")
	}
}

func TestAppExplicitTeamMatches(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	right := config.Matcher{Kind: config.MatchApp, ID: "com.googlecode.iterm2", Team: "H7V7XYVQ7D"}
	if !en.e.Apps([]config.Matcher{right}, en.r.Resolve(tab.Peer())) {
		t.Fatal("explicit matching team must match")
	}
	evil := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/Evil.app/x", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "com.googlecode.iterm2"}, App: &fake.App{BundleID: "com.googlecode.iterm2"}})
	if en.e.Apps([]config.Matcher{right}, en.r.Resolve(en.f.Launch(evil, fake.SSHProc("h")))) {
		t.Fatal("explicit team must reject another team")
	}
}

// to: checks the receiver (the socket peer) only, for every matcher kind.
func TestReceiverKinds(t *testing.T) {
	en := newEnv(t)
	resolved := "/opt/homebrew/Cellar/kubernetes-cli/1.34.0/bin/kubectl"
	kc := fake.Proc{Path: resolved, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0xaa}}}

	inChain := en.f.ITermTab(platform.ProcessRef{}, kc, fake.SSHProc("h"))
	c := en.r.Resolve(inChain.Peer())
	if en.e.Receiver([]config.Matcher{itermM}, c) {
		t.Fatal("to: app must not match when the receiver is a command in the app's tab")
	}
	if en.e.Receiver([]config.Matcher{{Kind: config.MatchSigned, Team: "H7V7XYVQ7D"}}, c) {
		t.Fatal("to: signed must not match the app above the peer")
	}
}

// The receiver is identified by its own signature even when the chain is
// unknown (a ControlPersist master is still Apple's ssh), but a forged
// receiver never matches.
func TestReceiverOnUnknownChain(t *testing.T) {
	en := newEnv(t)
	mux := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	c := en.r.Resolve(mux)
	if !c.Unknown {
		t.Fatal("setup: chain must be unknown")
	}
	if !en.e.Receiver([]config.Matcher{sshM}, c) {
		t.Fatal("Apple ssh receiver must match to: signed apple ssh on an unknown chain")
	}
	if en.e.Receiver([]config.Matcher{claudeM}, c) {
		t.Fatal("to: claude must not match an ssh receiver")
	}
}

// Identity is a cache key: unsigned or ad-hoc code must never get a team
// identity, whatever its claimed fields, and different binaries differ.
func TestIdentityCannotBeForged(t *testing.T) {
	forged := platform.ProcessInfo{Path: "/tmp/claude", Code: platform.CodeIdentity{Signed: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code", CDHash: []byte{0xde, 0xad}}}
	if got := Identity(forged); got != "path:/tmp/claude#dead" {
		t.Fatalf("ad-hoc identity %q", got)
	}
	unsignedApple := platform.ProcessInfo{Path: "/tmp/ssh", Code: platform.CodeIdentity{Apple: true, SigningID: "com.apple.openssh", CDHash: []byte{0x01}}}
	if got := Identity(unsignedApple); strings.HasPrefix(got, "apple:") {
		t.Fatalf("unsigned code got an Apple identity %q", got)
	}
	if got := Identity(platform.ProcessInfo{Code: fake.ClaudeCode}); got != "Q6L2SF6YDW:com.anthropic.claude-code" {
		t.Fatalf("claude identity %q", got)
	}
	a := Identity(platform.ProcessInfo{Path: "/opt/homebrew/bin/k9s", Code: platform.CodeIdentity{CDHash: []byte{1}}})
	b := Identity(platform.ProcessInfo{Path: "/opt/homebrew/bin/k9s", Code: platform.CodeIdentity{CDHash: []byte{2}}})
	if a == b {
		t.Fatal("different code at the same path must have different identities")
	}
}

// A nil Note callback is allowed for every noting path.
func TestNilNoteIsSafe(t *testing.T) {
	f := fake.New(t0)
	st, _ := trust.Open(fake.NewVault())
	e := &Evaluator{Trust: st}
	r := &caller.Resolver{P: f}
	tab := f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: kubectl.Path, Code: platform.CodeIdentity{CDHash: []byte{1}}}, fake.SSHProc("h"))
	c := r.Resolve(tab.Peer())
	e.Apps([]config.Matcher{itermM, kubectl}, c) // notes "not pinned"
	adhoc := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/i", Code: platform.CodeIdentity{Signed: true, AdHoc: true}, App: &fake.App{BundleID: "com.googlecode.iterm2"}})
	e.Apps([]config.Matcher{itermM}, r.Resolve(f.Launch(adhoc, fake.SSHProc("h"))))
}

// Milestone 7: for a signed: matcher, the process that
// satisfied it is the outermost one in the session (from the session root
// down to the peer): a session approval is bound to that process's run, so
// a claude a claude started shares the run of the one the user started.
// Above the session the order is as before: the first such process, peer
// first.
func TestMatchedIsTheOutermostInTheSession(t *testing.T) {
	en := newEnv(t)
	sh := fake.Proc{Path: "/bin/sh", Code: fake.AppleCode("com.apple.sh")}
	nested := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), sh, fake.ClaudeProc(), fake.SSHProc("h"))
	if ref, ok := en.e.Matched([]config.Matcher{claudeM}, en.r.Resolve(nested.Peer())); !ok || ref != nested.Procs[0] {
		t.Fatalf("nested claude: matched %v, want the outer claude %v", ref, nested.Procs[0])
	}
	// claude → Foo.app → zsh → claude → ssh: the app is Foo, the session is
	// zsh's, and the claude in it wins over the one above the app.
	foo := fake.Proc{Path: "/Applications/Foo.app/Contents/MacOS/Foo", Code: platform.CodeIdentity{Signed: true, TeamID: "FOOTEAM001", SigningID: "com.foo.app", CDHash: []byte{0xf0}}, App: &fake.App{BundleID: "com.foo.app", Name: "Foo"}}
	zsh := fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")}
	both := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), foo, zsh, fake.ClaudeProc(), fake.SSHProc("h"))
	c := en.r.Resolve(both.Peer())
	if c.App.BundleID != "com.foo.app" || c.SessionRoot != both.Procs[2] {
		t.Fatalf("control: app %q root %v, want Foo and zsh %v", c.App.BundleID, c.SessionRoot, both.Procs[2])
	}
	if ref, ok := en.e.Matched([]config.Matcher{claudeM}, c); !ok || ref != both.Procs[3] {
		t.Fatalf("matched %v, want the claude in the session %v", ref, both.Procs[3])
	}
	above := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), foo, fake.SSHProc("h"))
	if ref, ok := en.e.Matched([]config.Matcher{claudeM}, en.r.Resolve(above.Peer())); !ok || ref != above.Procs[0] {
		t.Fatalf("claude only above the app: matched %v, want %v", ref, above.Procs[0])
	}
}
