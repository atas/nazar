package caller

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

func TestITermChainAppAndSession(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}, fake.Proc{Path: "/usr/bin/git", Code: fake.AppleCode("com.apple.git")}, fake.SSHProc("git@github.com"))
	r := &Resolver{P: f}
	c := r.Resolve(tab.Peer())
	if c.Unknown || c.AppSource != AppFromChain || c.App.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("app: %+v source %v", c.App, c.AppSource)
	}
	if c.SessionRoot != tab.Shell {
		t.Fatalf("session root %v, want login shell %v (iTermServer and root-owned login are skipped)", c.SessionRoot, tab.Shell)
	}
	shell, _ := f.Process(tab.Shell)
	if c.Session.String() != fmt.Sprintf("%d@%d", tab.Shell.PID, shell.StartTime.Unix()) {
		t.Fatalf("session id %q", c.Session)
	}
	if got := c.Summary(); got != "iTerm2 → bash → claude → bash → git → ssh" {
		t.Fatalf("summary %q", got)
	}
	if below := c.Below(); len(below) != 5 || below[0].Ref != tab.Shell || below[4].Ref != tab.Peer() {
		t.Fatalf("Below() = %d procs", len(below))
	}
	if c.AppIdentity() != "H7V7XYVQ7D:com.googlecode.iterm2" {
		t.Fatalf("app identity %q", c.AppIdentity())
	}
	if len(c.Procs) != 8 || c.Truncated {
		t.Fatalf("procs %d truncated %v", len(c.Procs), c.Truncated)
	}
}

func TestTwoTabsHaveDifferentSessions(t *testing.T) {
	f := fake.New(t0)
	a := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	b := f.ITermTab(a.App, fake.SSHProc("h"))
	r := &Resolver{P: f}
	ca, cb := r.Resolve(a.Peer()), r.Resolve(b.Peer())
	if ca.Session == cb.Session || ca.AppIdentity() != cb.AppIdentity() {
		t.Fatalf("sessions %v %v apps %q %q", ca.Session, cb.Session, ca.AppIdentity(), cb.AppIdentity())
	}
}

func TestUnknownChainEndsAtLaunchd(t *testing.T) {
	f := fake.New(t0)
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("-S", "/tmp/cm", "[mux]"))
	c := (&Resolver{P: f}).Resolve(mux)
	if !c.Unknown || c.AppSource != AppNone || !c.Session.IsZero() || c.AppName() != "Unknown app" {
		t.Fatalf("want unknown chain, got %+v", c)
	}
	if c.Summary() != "ssh" {
		t.Fatalf("summary %q", c.Summary())
	}
}

// A chain that ends at launchd without an app is unknown (spec 4.1 step 5)
// even when the responsible process names an app: the app is kept for the
// summary only. It is not an identity, so AppName and AppIdentity report no
// app and nothing can be remembered under it.
func TestResponsibleProcessFallback(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	f.SetResponsible(mux, tab.App)
	c := (&Resolver{P: f}).Resolve(mux)
	if !c.Unknown || c.AppSource != AppFromResponsible || c.App.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("want unknown chain shown as responsible iTerm2, got %+v", c)
	}
	if !c.Session.IsZero() || !c.SessionRoot.IsZero() {
		t.Fatal("responsible attribution must not invent a session")
	}
	if c.Summary() != "iTerm2 (responsible) → ssh" {
		t.Fatalf("summary %q", c.Summary())
	}
	if c.AppName() != "Unknown app" || c.AppIdentity() != "" {
		t.Fatalf("a responsible app is not an identity: name %q identity %q", c.AppName(), c.AppIdentity())
	}
	if b := c.Below(); len(b) != 1 || b[0].Path != "/usr/bin/ssh" {
		t.Fatalf("below %+v", b)
	}
}

// Chain shedding: macOS responsibility is inherited by
// every process a tab starts, so a process can leave its chain (double-fork
// and be re-parented to launchd, or nest past the depth limit) and still be
// "responsible to" the tab's app. Such a chain must be unknown, never an
// attributed app with its rules.
func TestShedChainIsUnknownDespiteResponsibleApp(t *testing.T) {
	bash := fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}

	t.Run("double fork", func(t *testing.T) {
		f := fake.New(t0)
		tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), bash)
		helper := f.Launch(tab.Peer(), bash)
		ssh := f.Launch(helper, fake.SSHProc("prod"))
		f.SetResponsible(ssh, tab.App)
		r := &Resolver{P: f}
		if c := r.Resolve(ssh); c.Unknown || c.AppSource != AppFromChain {
			t.Fatalf("setup: full chain must find iTerm2, got %+v", c)
		}
		f.Exit(helper) // ssh is re-parented to launchd
		c := r.Resolve(ssh)
		if !c.Unknown || c.AppSource != AppFromResponsible || c.AppIdentity() != "" || !c.Session.IsZero() {
			t.Fatalf("shed chain must be unknown: unknown=%v source=%v identity=%q session=%v",
				c.Unknown, c.AppSource, c.AppIdentity(), c.Session)
		}
		if c.Summary() != "iTerm2 (responsible) → ssh" {
			t.Fatalf("summary %q", c.Summary())
		}
	})

	t.Run("deep nesting", func(t *testing.T) {
		f := fake.New(t0)
		tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
		parent := tab.Peer()
		for i := 0; i < DefaultMaxDepth; i++ {
			parent = f.Launch(parent, bash)
		}
		ssh := f.Launch(parent, fake.SSHProc("prod"))
		f.SetResponsible(ssh, tab.App)
		c := (&Resolver{P: f}).Resolve(ssh)
		if !c.Truncated || len(c.Procs) != DefaultMaxDepth {
			t.Fatalf("setup: want truncation at %d, got truncated=%v procs=%d", DefaultMaxDepth, c.Truncated, len(c.Procs))
		}
		if !c.Unknown || c.AppSource != AppFromResponsible || c.AppIdentity() != "" {
			t.Fatalf("deep chain must be unknown: unknown=%v source=%v identity=%q", c.Unknown, c.AppSource, c.AppIdentity())
		}
	})
}

func TestResponsibleThatIsNotAnAppStaysUnknown(t *testing.T) {
	f := fake.New(t0)
	d := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/local/bin/daemon"})
	peer := f.Launch(d, fake.SSHProc("h"))
	f.SetResponsible(peer, d)
	if c := (&Resolver{P: f}).Resolve(peer); !c.Unknown {
		t.Fatal("a responsible process that is not an app must not attribute")
	}
}

func TestPIDReuseTruncates(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	shell, _ := f.Process(tab.Shell)
	shell.StartTime = t0.Add(time.Hour) // "parent" started after the child: recycled PID
	f.SetProcess(shell)
	c := (&Resolver{P: f}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || len(c.Procs) != 1 {
		t.Fatalf("want truncated unknown chain of 1, got truncated=%v unknown=%v procs=%d", c.Truncated, c.Unknown, len(c.Procs))
	}
	if !strings.HasPrefix(c.Summary(), "… → ") {
		t.Fatalf("summary %q", c.Summary())
	}
}

func TestLoopAndDepthLimit(t *testing.T) {
	f := fake.New(t0)
	a := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/a"})
	b := f.Launch(a, fake.Proc{Path: "/b"})
	ai, _ := f.Process(a)
	ai.Parent = b
	ai.StartTime = t0.Add(-time.Hour)
	f.SetProcess(ai)
	if c := (&Resolver{P: f}).Resolve(b); !c.Truncated || len(c.Procs) != 2 {
		t.Fatalf("loop: truncated=%v procs=%d", c.Truncated, len(c.Procs))
	}
	parent := platform.ProcessRef{}
	for i := 0; i < 10; i++ {
		parent = f.Launch(parent, fake.Proc{Path: "/x"})
	}
	if c := (&Resolver{P: f, MaxDepth: 4}).Resolve(parent); !c.Truncated || len(c.Procs) != 4 {
		t.Fatalf("depth: truncated=%v procs=%d", c.Truncated, len(c.Procs))
	}
}

func TestVanishedPeerIsUnknown(t *testing.T) {
	f := fake.New(t0)
	c := (&Resolver{P: f}).ResolveFD(9)
	if !c.Unknown || len(c.Procs) != 0 {
		t.Fatalf("got %+v", c)
	}
	if _, ok := c.Peer(); ok {
		t.Fatal("no peer expected")
	}
}

func TestPeerIsTheAppHasNoSession(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	c := (&Resolver{P: f}).Resolve(tab.App)
	if c.AppSource != AppFromChain || !c.Session.IsZero() {
		t.Fatalf("got %+v", c)
	}
}

// ---- Additional behaviour, edge and attack cases (spec 4.1) ----

// terminalApp launches an Apple-signed GUI terminal (Terminal.app) whose tabs
// run /usr/bin/login (root) → zsh, like iTerm2 without the helper.
func terminalApp(f *fake.Fake) platform.ProcessRef {
	return f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
		Code: fake.AppleCode("com.apple.Terminal"),
		App:  &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"},
	})
}

func terminalTab(f *fake.Fake, app platform.ProcessRef, extra ...fake.Proc) (shell, peer platform.ProcessRef) {
	login := f.Launch(app, fake.Proc{Path: "/usr/bin/login", Root: true, Code: fake.AppleCode("com.apple.login")})
	shell = f.Launch(login, fake.Proc{Path: "/bin/zsh", Args: []string{"-zsh"}, Code: fake.AppleCode("com.apple.zsh")})
	peer = shell
	for _, p := range extra {
		peer = f.Launch(peer, p)
	}
	return shell, peer
}

// An Apple-signed app's shells are Apple-signed too: the "skip the app's own
// helpers" rule must not treat every Apple binary as a helper of an Apple app,
// or Terminal.app tabs would have no session (or one shared session).
func TestAppleAppSessionIsTheTabShell(t *testing.T) {
	f := fake.New(t0)
	app := terminalApp(f)
	shellA, peerA := terminalTab(f, app, fake.SSHProc("h"))
	shellB, peerB := terminalTab(f, app, fake.SSHProc("h"))
	r := &Resolver{P: f}
	ca, cb := r.Resolve(peerA), r.Resolve(peerB)
	if ca.Unknown || ca.AppSource != AppFromChain || ca.App.BundleID != "com.apple.Terminal" {
		t.Fatalf("app %+v source %v", ca.App, ca.AppSource)
	}
	if ca.SessionRoot != shellA || cb.SessionRoot != shellB {
		t.Fatalf("session roots %v %v, want tab shells %v %v", ca.SessionRoot, cb.SessionRoot, shellA, shellB)
	}
	if ca.Session == cb.Session || ca.Session.IsZero() {
		t.Fatalf("tabs must have distinct, non-zero sessions: %v %v", ca.Session, cb.Session)
	}
	if ca.AppIdentity() != "apple:com.apple.Terminal" || ca.AppIdentity() != cb.AppIdentity() {
		t.Fatalf("app identities %q %q", ca.AppIdentity(), cb.AppIdentity())
	}
	if got := ca.Summary(); got != "Terminal → zsh → ssh" {
		t.Fatalf("summary %q", got)
	}
}

// An app whose shell is its direct child (no login, no helper): the session
// root is that child (spec 4.1 step 4).
func TestDirectChildShellIsTheSessionRoot(t *testing.T) {
	f := fake.New(t0)
	code := platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.example.editor", CDHash: []byte{0xed}}
	app := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Editor.app/Contents/MacOS/Editor", Code: code, App: &fake.App{BundleID: "com.example.editor", Name: "Editor"}})
	helper := f.Launch(app, fake.Proc{Path: "/Applications/Editor.app/Contents/Frameworks/Editor Helper", Code: platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.example.editor.helper"}})
	shell := f.Launch(helper, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	peer := f.Launch(shell, fake.SSHProc("h"))
	c := (&Resolver{P: f}).Resolve(peer)
	if c.SessionRoot != shell {
		t.Fatalf("session root %v, want shell %v below the app's same-team helper", c.SessionRoot, shell)
	}
	sh, _ := f.Process(shell)
	if c.Session.PID != shell.PID || !c.Session.Start.Equal(sh.StartTime) {
		t.Fatalf("session %+v, want (%d, %v)", c.Session, shell.PID, sh.StartTime)
	}

	f2 := fake.New(t0)
	app2 := f2.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Editor.app/Contents/MacOS/Editor", Code: code, App: &fake.App{BundleID: "com.example.editor", Name: "Editor"}})
	shell2 := f2.Launch(app2, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	peer2 := f2.Launch(shell2, fake.SSHProc("h"))
	if c2 := (&Resolver{P: f2}).Resolve(peer2); c2.SessionRoot != shell2 {
		t.Fatalf("session root %v, want direct child %v", c2.SessionRoot, shell2)
	}
}

// Every command in one tab shares the tab's session; different commands in
// the same tab must not get different sessions.
func TestCommandsInOneTabShareTheSession(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/git", Code: fake.AppleCode("com.apple.git")}, fake.SSHProc("git@github.com"))
	second := f.Launch(tab.Shell, fake.SSHProc("prod"))
	r := &Resolver{P: f}
	a, b := r.Resolve(tab.Peer()), r.Resolve(second)
	if a.Session.IsZero() || a.Session != b.Session || a.SessionRoot != b.SessionRoot {
		t.Fatalf("same tab, sessions %v vs %v", a.Session, b.Session)
	}
}

// A GUI app started inside another app's tab: the app is the innermost one
// (the first GUI app walking up from the peer), and its session is its own.
func TestInnermostAppWins(t *testing.T) {
	f := fake.New(t0)
	cursorCode := platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.todesktop.230313mzl4w4u92", CDHash: []byte{0xcc}}
	tab := f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Cursor.app/Contents/MacOS/Cursor", Code: cursorCode, App: &fake.App{BundleID: "com.todesktop.230313mzl4w4u92", Name: "Cursor"}})
	cursor := tab.Peer()
	zsh := f.Launch(cursor, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	peer := f.Launch(zsh, fake.SSHProc("h"))
	c := (&Resolver{P: f}).Resolve(peer)
	if c.AppSource != AppFromChain || c.App.Ref != cursor || c.App.BundleID != "com.todesktop.230313mzl4w4u92" {
		t.Fatalf("app %+v, want Cursor", c.App)
	}
	if c.SessionRoot != zsh {
		t.Fatalf("session root %v, want zsh %v under Cursor", c.SessionRoot, zsh)
	}
	if c.Summary() != "Cursor → zsh → ssh" {
		t.Fatalf("summary %q", c.Summary())
	}
}

// A request from the app's own helper (same team) has no session root, so a
// session approval can never span all of the app's tabs.
func TestAppHelperPeerHasNoSession(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	c := (&Resolver{P: f}).Resolve(tab.Server)
	if c.Unknown || c.AppSource != AppFromChain {
		t.Fatalf("helper should still be attributed to the app: %+v", c)
	}
	if !c.Session.IsZero() || !c.SessionRoot.IsZero() {
		t.Fatalf("helper got session %v root %v", c.Session, c.SessionRoot)
	}
}

// ResolveFD uses the platform's peer identity for the socket and resolves
// exactly like Resolve.
func TestResolveFDUsesThePeer(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	f.SetPeer(7, tab.Peer())
	r := &Resolver{P: f}
	c := r.ResolveFD(7)
	want := r.Resolve(tab.Peer())
	if c.Unknown || c.Session != want.Session || c.AppIdentity() != want.AppIdentity() || len(c.Procs) != len(want.Procs) {
		t.Fatalf("ResolveFD %+v, Resolve %+v", c, want)
	}
	if p, ok := c.Peer(); !ok || p.Ref != tab.Peer() {
		t.Fatalf("peer %v %v", p.Ref, ok)
	}
}

// A peer ref that no longer exists (the process exited, or the PID was
// recycled so the generation differs) is unknown, never another process.
func TestStaleOrRecycledPeerRefIsUnknown(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	stale := platform.ProcessRef{PID: tab.Peer().PID, Generation: tab.Peer().Generation + 7}
	r := &Resolver{P: f}
	for name, ref := range map[string]platform.ProcessRef{"recycled pid": stale, "never existed": {PID: 4242, Generation: 1}} {
		c := r.Resolve(ref)
		if !c.Unknown || len(c.Procs) != 0 || c.AppSource != AppNone || !c.Session.IsZero() {
			t.Fatalf("%s: got %+v", name, c)
		}
		if _, ok := c.Peer(); ok {
			t.Fatalf("%s: no peer expected", name)
		}
		// Accessors must be safe on an empty chain.
		if c.AppName() != "Unknown app" || c.AppIdentity() != "" || len(c.Below()) != 0 {
			t.Fatalf("%s: accessors %q %q %d", name, c.AppName(), c.AppIdentity(), len(c.Below()))
		}
		_ = c.Summary()
	}
	f.Exit(tab.Peer())
	if c := r.Resolve(tab.Peer()); !c.Unknown || len(c.Procs) != 0 {
		t.Fatalf("exited peer: %+v", c)
	}
}

// A parent ref with the right PID but the wrong generation (the parent died
// and its PID was reused) must stop the walk: the chain is truncated and,
// without the app above it, unknown. It must never attach the new process.
func TestParentGenerationMismatchTruncates(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	peer, _ := f.Process(tab.Peer())
	peer.Parent = platform.ProcessRef{PID: tab.Shell.PID, Generation: tab.Shell.Generation + 1}
	f.SetProcess(peer)
	f.SetResponsible(tab.Peer(), platform.ProcessRef{}) // no responsible app to show either
	c := (&Resolver{P: f}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || len(c.Procs) != 1 || c.AppSource != AppNone {
		t.Fatalf("truncated=%v unknown=%v procs=%d source=%v", c.Truncated, c.Unknown, len(c.Procs), c.AppSource)
	}
}

// A parent that vanished mid-walk truncates the chain; with no app reached,
// it is unknown.
func TestMissingParentTruncates(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	peer, _ := f.Process(tab.Peer())
	peer.Parent = platform.ProcessRef{PID: 31337, Generation: 31337001}
	f.SetProcess(peer)
	c := (&Resolver{P: f}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || len(c.Procs) != 1 {
		t.Fatalf("truncated=%v unknown=%v procs=%d", c.Truncated, c.Unknown, len(c.Procs))
	}
}

// A process listed as its own parent is a loop of one.
func TestSelfParentLoopTerminates(t *testing.T) {
	f := fake.New(t0)
	p := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/x"})
	info, _ := f.Process(p)
	info.Parent = p
	f.SetProcess(info)
	done := make(chan *Chain, 1)
	go func() { done <- (&Resolver{P: f}).Resolve(p) }()
	select {
	case c := <-done:
		if !c.Truncated || len(c.Procs) != 1 || !c.Unknown {
			t.Fatalf("truncated=%v procs=%d unknown=%v", c.Truncated, len(c.Procs), c.Unknown)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve did not terminate on a self-parent loop")
	}
}

// Without an explicit MaxDepth, DefaultMaxDepth (64) bounds the walk; a chain
// cut off before it reaches the app is unknown, never guessed.
func TestDefaultDepthLimitAndAppBeyondLimit(t *testing.T) {
	if DefaultMaxDepth != 64 {
		t.Fatalf("DefaultMaxDepth = %d", DefaultMaxDepth)
	}
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	parent := tab.Shell
	for i := 0; i < 100; i++ {
		parent = f.Launch(parent, fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")})
	}
	f.SetResponsible(parent, platform.ProcessRef{}) // no responsible app to show either
	c := (&Resolver{P: f}).Resolve(parent)
	if !c.Truncated || len(c.Procs) != DefaultMaxDepth {
		t.Fatalf("truncated=%v procs=%d", c.Truncated, len(c.Procs))
	}
	if !c.Unknown || c.AppSource != AppNone || !c.Session.IsZero() {
		t.Fatalf("app beyond the depth limit must not be attributed: %+v source %v", c.App, c.AppSource)
	}
}

// The walk stops at launchd and does not include it.
func TestChainExcludesLaunchd(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := (&Resolver{P: f}).Resolve(tab.Peer())
	for _, p := range c.Procs {
		if p.Ref == f.Launchd || p.Ref.PID == 1 {
			t.Fatal("launchd must not be part of the chain")
		}
	}
	if top := c.Procs[len(c.Procs)-1]; top.Ref != tab.App {
		t.Fatalf("outermost process %v, want the app %v", top.Ref, tab.App)
	}
	if c.Procs[0].Ref != tab.Peer() {
		t.Fatal("Procs must be peer first")
	}
}

// The responsible-process fallback must not be fooled: a responsible process
// that has exited, or a peer named as its own responsible process, gives an
// unknown chain.
func TestResponsibleFallbackFailsClosed(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	f.SetResponsible(mux, tab.App)
	f.Exit(tab.App)
	if c := (&Resolver{P: f}).Resolve(mux); !c.Unknown || c.AppSource != AppNone {
		t.Fatalf("exited responsible app attributed: %+v", c)
	}

	self := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	f.SetResponsible(self, self)
	if c := (&Resolver{P: f}).Resolve(self); !c.Unknown {
		t.Fatalf("self-responsible non-app attributed: %+v", c)
	}

	stale := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	app := f.ITermTab(platform.ProcessRef{}).App
	f.SetResponsible(stale, platform.ProcessRef{PID: app.PID, Generation: app.Generation + 1})
	if c := (&Resolver{P: f}).Resolve(stale); !c.Unknown {
		t.Fatalf("responsible ref with a recycled PID attributed: %+v", c)
	}
}

// When the app is in the chain, the chain decides; the responsible process is
// only a fallback and never overrides it.
func TestChainAppBeatsResponsible(t *testing.T) {
	f := fake.New(t0)
	other := terminalApp(f)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	f.SetResponsible(tab.Peer(), other)
	c := (&Resolver{P: f}).Resolve(tab.Peer())
	if c.AppSource != AppFromChain || c.App.BundleID != "com.googlecode.iterm2" || c.Session.IsZero() {
		t.Fatalf("got %+v source %v", c.App, c.AppSource)
	}
}

func TestSessionIDFormat(t *testing.T) {
	var z SessionID
	if !z.IsZero() {
		t.Fatal("zero SessionID must be IsZero")
	}
	s := SessionID{PID: 4242, Start: time.Unix(1791072000, 123456789)}
	if s.IsZero() || s.String() != "4242@1791072000" {
		t.Fatalf("String() = %q", s.String())
	}
}

// ---- PID-reuse guard on the peer, display forgery, app identity ----

// byPID wraps the fake with a Process() that, like a KERN_PROC_PID sysctl,
// looks a process up by PID only and returns the live occupant of that PID
// whatever generation the caller asked for. The Resolver must not rely on
// the platform to refuse a generation mismatch.
type byPID struct {
	*fake.Fake
	live map[int]platform.ProcessRef
}

func newByPID(f *fake.Fake, refs ...platform.ProcessRef) *byPID {
	b := &byPID{Fake: f, live: map[int]platform.ProcessRef{f.Launchd.PID: f.Launchd}}
	for _, r := range refs {
		b.live[r.PID] = r
	}
	return b
}

func (b *byPID) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	live, ok := b.live[ref.PID]
	if !ok {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	return b.Fake.Process(live)
}

func tabRefs(tab fake.Chain) []platform.ProcessRef {
	return append([]platform.ProcessRef{tab.App, tab.Server, tab.Login, tab.Shell}, tab.Procs...)
}

// A peer ref whose generation no longer matches (the audit token names a
// process that exited and whose PID was recycled) must be unknown even when
// the platform answers with the PID's new occupant. The new occupant must
// never inherit the chain, app or session.
func TestPeerGenerationMismatchIsUnknownOnByPIDPlatform(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	p := newByPID(f, tabRefs(tab)...)
	r := &Resolver{P: p}

	// Control: the live ref resolves normally through the wrapper.
	if c := r.Resolve(tab.Peer()); c.Unknown || c.AppSource != AppFromChain || len(c.Procs) != 5 {
		t.Fatalf("control: live peer through by-PID platform: unknown=%v source=%v procs=%d", c.Unknown, c.AppSource, len(c.Procs))
	}

	stale := platform.ProcessRef{PID: tab.Peer().PID, Generation: tab.Peer().Generation - 1}
	c := r.Resolve(stale)
	if !c.Unknown || !c.Truncated || len(c.Procs) != 0 || c.AppSource != AppNone || !c.Session.IsZero() {
		t.Fatalf("stale peer resolved as the PID's new occupant: unknown=%v truncated=%v procs=%d source=%v session=%v", c.Unknown, c.Truncated, len(c.Procs), c.AppSource, c.Session)
	}
	if _, ok := c.Peer(); ok || c.AppIdentity() != "" {
		t.Fatalf("stale peer must have no peer and no app identity: %q", c.AppIdentity())
	}
	f.SetPeer(3, stale)
	if c := r.ResolveFD(3); !c.Unknown || len(c.Procs) != 0 {
		t.Fatalf("ResolveFD with a stale peer: %+v", c)
	}
}

// The same by-PID platform must not get a recycled parent attached: the walk
// stops at the generation mismatch and the chain is truncated and unknown.
func TestParentGenerationMismatchTruncatesOnByPIDPlatform(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	peer, _ := f.Process(tab.Peer())
	peer.Parent = platform.ProcessRef{PID: tab.Shell.PID, Generation: tab.Shell.Generation + 1}
	f.SetProcess(peer)
	f.SetResponsible(tab.Peer(), platform.ProcessRef{}) // no responsible app to show either
	c := (&Resolver{P: newByPID(f, tabRefs(tab)...)}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || len(c.Procs) != 1 || c.AppSource != AppNone {
		t.Fatalf("truncated=%v unknown=%v procs=%d source=%v", c.Truncated, c.Unknown, len(c.Procs), c.AppSource)
	}
}

// And a responsible-process ref with a recycled PID must not attribute to
// the PID's new occupant.
func TestResponsibleGenerationMismatchIsUnknownOnByPIDPlatform(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	p := newByPID(f, append(tabRefs(tab), mux)...)
	r := &Resolver{P: p}

	f.SetResponsible(mux, tab.App)
	if c := r.Resolve(mux); !c.Unknown || c.AppSource != AppFromResponsible {
		t.Fatalf("control: live responsible app shown through by-PID platform: %+v", c)
	}
	f.SetResponsible(mux, platform.ProcessRef{PID: tab.App.PID, Generation: tab.App.Generation + 1})
	if c := r.Resolve(mux); !c.Unknown || c.AppSource != AppNone {
		t.Fatalf("responsible ref with a recycled PID attributed to the new occupant: %+v", c)
	}
}

// Executable file names and app display names are attacker-chosen. Summary()
// must render them so they can't forge hops, the separator, "(responsible)"
// or the truncation mark: anything but a short plain name is quoted.
func TestSummaryCannotBeForgedByNames(t *testing.T) {
	f := fake.New(t0)
	genuine := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	forged := f.ITermTab(genuine.App, fake.Proc{Path: "/tmp/x/claude → ssh", Args: []string{"claude → ssh"}})
	r := &Resolver{P: f}
	g, fc := r.Resolve(genuine.Peer()), r.Resolve(forged.Peer())
	if g.Summary() != "iTerm2 → bash → claude → ssh" {
		t.Fatalf("genuine summary %q", g.Summary())
	}
	if want := `iTerm2 → bash → "claude → ssh"`; fc.Summary() != want {
		t.Fatalf("forged summary %q, want %q", fc.Summary(), want)
	}
	if fc.Summary() == g.Summary() {
		t.Fatal("a crafted file name impersonated the genuine chain")
	}

	// A process named like the truncation mark, and an app whose display
	// name contains hops, are quoted too.
	dots := f.ITermTab(genuine.App, fake.Proc{Path: "/tmp/…"}, fake.Proc{Path: "/tmp/(responsible)"})
	if got, want := r.Resolve(dots.Peer()).Summary(), `iTerm2 → bash → "…" → "(responsible)"`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
	evil := f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Evil.app/Contents/MacOS/Evil",
		Code: platform.CodeIdentity{Signed: true, TeamID: "EVIL000000", SigningID: "com.evil.app", CDHash: []byte{0xee}},
		App:  &fake.App{BundleID: "com.evil.app", Name: "iTerm2 → bash → claude"},
	})
	zsh := f.Launch(evil, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	peer := f.Launch(zsh, fake.SSHProc("h"))
	if got, want := r.Resolve(peer).Summary(), `"iTerm2 → bash → claude" → zsh → ssh`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	f.SetResponsible(mux, evil)
	if got, want := r.Resolve(mux).Summary(), `"iTerm2 → bash → claude" (responsible) → ssh`; got != want {
		t.Fatalf("summary %q, want %q", got, want)
	}
}

func TestSafeName(t *testing.T) {
	long := strings.Repeat("a", maxNameLen)
	cases := map[string]string{
		"ssh": "ssh", "iTerm2": "iTerm2", "python3.12": "python3.12", "g++": "g++", "my-tool_v2": "my-tool_v2",
		long:            long,
		"":              `""`,
		"claude → ssh":  `"claude → ssh"`,
		"Editor Helper": `"Editor Helper"`,
		"…":             `"…"`,
		"(responsible)": `"(responsible)"`,
		`a"b`:           `"a\"b"`,
		"ssh\x00\n":     `"ssh\x00\n"`,
		"ßash":          `"ßash"`,
		long + "b":      `"` + long[:maxNameLen-1] + `…"`,
		"a=b":           `"a=b"`,
		"a/b":           `"a/b"`,
	}
	for in, want := range cases {
		if got := safeName(in); got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := safeName(strings.Repeat("→", 100)); len([]rune(got)) > maxNameLen+3 {
		t.Errorf("long non-plain name not truncated: %d runes", len([]rune(got)))
	}
}

// An app whose code can't be verified (ad-hoc or unsigned) is still the
// chain's app for display, but has no identity: a scope: app approval must
// never be remembered for it, or an impostor with the same bundle ID would
// inherit the approval (spec 4.2).
func TestUnverifiableAppHasNoIdentity(t *testing.T) {
	cases := map[string]platform.CodeIdentity{
		"ad-hoc with a team id": {Signed: true, AdHoc: true, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2", CDHash: []byte{0xad}},
		"ad-hoc claiming apple": {Signed: true, AdHoc: true, Apple: true, SigningID: "com.googlecode.iterm2"},
		"unsigned":              {Signed: false, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2"},
	}
	for name, code := range cases {
		f := fake.New(t0)
		app := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/iTerm.app/Contents/MacOS/iTerm2", Code: code, App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"}})
		zsh := f.Launch(app, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
		peer := f.Launch(zsh, fake.SSHProc("h"))
		c := (&Resolver{P: f}).Resolve(peer)
		if c.Unknown || c.AppSource != AppFromChain || c.App.BundleID != "com.googlecode.iterm2" {
			t.Fatalf("%s: app %+v source %v unknown %v", name, c.App, c.AppSource, c.Unknown)
		}
		if id := c.AppIdentity(); id != "" {
			t.Fatalf("%s: AppIdentity() = %q, want \"\" for an unverifiable app", name, id)
		}
		// Display still names the app; nothing is hidden from the user.
		if c.AppName() != "iTerm2" || c.Summary() != "iTerm2 → zsh → ssh" {
			t.Fatalf("%s: name %q summary %q", name, c.AppName(), c.Summary())
		}
	}
	// The genuine, Developer-ID-signed app keeps its identity.
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if id := (&Resolver{P: f}).Resolve(tab.Peer()).AppIdentity(); id != "H7V7XYVQ7D:com.googlecode.iterm2" {
		t.Fatalf("genuine app identity %q", id)
	}
}

// One iTermServer hosts every tab, so it must never be the session root:
// every third-party-signed process right below the app is skipped, whatever
// the app's own signature says. Here iTerm2's running code no longer
// verifies (it updated itself on disk and was not restarted), so its team
// is unknown; two tabs under the one server still get their own sessions,
// each rooted at the tab's login shell.
func TestStaleAppTabsUnderOneServerGetTheirOwnSessions(t *testing.T) {
	f := fake.New(t0)
	stale := fake.ITermCode
	stale.Signed = false
	app := f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: stale,
		App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	server := f.Launch(app, fake.Proc{Path: "/Users/u/Library/Application Support/iTerm2/iTermServer-3.7.3",
		Code: platform.CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D", SigningID: "iTermServer", CDHash: []byte{0x5e}}})
	tab := func() (shell, peer platform.ProcessRef) {
		login := f.Launch(server, fake.Proc{Path: "/usr/bin/login", Root: true, Code: fake.AppleCode("com.apple.login")})
		shell = f.Launch(login, fake.Proc{Path: "/bin/bash", Args: []string{"-bash"}, Code: fake.AppleCode("com.apple.bash")})
		claude := f.Launch(shell, fake.ClaudeProc())
		peer = f.Launch(claude, fake.SSHProc("git@github.com"))
		return shell, peer
	}
	shell1, peer1 := tab()
	shell2, peer2 := tab()
	r := &Resolver{P: f}
	c1, c2 := r.Resolve(peer1), r.Resolve(peer2)
	if c1.SessionRoot != shell1 || c2.SessionRoot != shell2 {
		t.Fatalf("session roots %v %v, want the tabs' shells %v %v", c1.SessionRoot, c2.SessionRoot, shell1, shell2)
	}
	if c1.Session == c2.Session {
		t.Fatalf("two tabs share session %v", c1.Session)
	}
}

// A third-party-signed process between the app and the shell, of any team,
// is skipped: the root can only move deeper (a narrower session), never up
// to a process that more than one tab runs under.
func TestThirdPartyHelpersAboveTheShellAreSkipped(t *testing.T) {
	f := fake.New(t0)
	app := f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Editor.app/Contents/MacOS/Editor", Code: platform.CodeIdentity{Signed: true, TeamID: "EDITORTEAM", SigningID: "com.example.editor", CDHash: []byte{1}},
		App: &fake.App{BundleID: "com.example.editor", Name: "Editor"},
	})
	host := f.Launch(app, fake.Proc{Path: "/opt/host", Code: platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM1", SigningID: "host", CDHash: []byte{2}}})
	shell := f.Launch(host, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	peer := f.Launch(shell, fake.SSHProc("git@github.com"))
	if c := (&Resolver{P: f}).Resolve(peer); c.SessionRoot != shell {
		t.Fatalf("session root %v, want the shell %v (the other team's host is shared)", c.SessionRoot, shell)
	}
}

// A helper inside the app's own bundle is skipped whatever its signature:
// one that stopped verifying with its app (VS Code's terminal host after
// the running app was upgraded on disk) has no team, and kept as the root
// it would make one session of every terminal it hosts.
func TestStaleInBundleHelperIsSkipped(t *testing.T) {
	f := fake.New(t0)
	team := platform.CodeIdentity{Signed: true, TeamID: "UBF8T346G9", SigningID: "com.microsoft.VSCode", CDHash: []byte{1}}
	app := f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", Code: team,
		App: &fake.App{BundleID: "com.microsoft.VSCode", Name: "Code"},
	})
	stale := platform.CodeIdentity{TeamID: "UBF8T346G9", SigningID: "com.github.Electron.helper"} // no longer validly signed
	host := f.Launch(app, fake.Proc{Path: "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper", Code: stale})
	term := func() (shell, peer platform.ProcessRef) {
		shell = f.Launch(host, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
		return shell, f.Launch(shell, fake.SSHProc("git@github.com"))
	}
	s1, p1 := term()
	s2, p2 := term()
	r := &Resolver{P: f}
	if c1, c2 := r.Resolve(p1), r.Resolve(p2); c1.SessionRoot != s1 || c2.SessionRoot != s2 {
		t.Fatalf("roots %v %v, want the shells %v %v (the stale helper hosts both)", c1.SessionRoot, c2.SessionRoot, s1, s2)
	}
}

// A helper whose file an update deleted has no path (the kernel has none),
// so the bundle check can't place it; it is skipped like one.
func TestHelperWithADeletedFileIsSkipped(t *testing.T) {
	f := fake.New(t0)
	app := f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", Code: platform.CodeIdentity{Signed: true, TeamID: "UBF8T346G9", SigningID: "com.microsoft.VSCode", CDHash: []byte{1}},
		App: &fake.App{BundleID: "com.microsoft.VSCode", Name: "Code"},
	})
	host := f.Launch(app, fake.Proc{Path: "", Code: platform.CodeIdentity{}})
	shell := f.Launch(host, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
	peer := f.Launch(shell, fake.SSHProc("git@github.com"))
	if c := (&Resolver{P: f}).Resolve(peer); c.SessionRoot != shell {
		t.Fatalf("session root %v, want the shell %v (the helper's file is gone)", c.SessionRoot, shell)
	}
}

// orphanServer is iTermServer as iTerm2 runs it since 3.4: copied to
// Application Support, signed by iTerm2's team under its own identifier.
var orphanServer = fake.Proc{
	Path: "/Users/u/Library/Application Support/iTerm2/iTermServer-3.7.4",
	Code: platform.CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D", SigningID: "iTermServer", CDHash: []byte{0x5e}},
}

// orphanedTab is the shape of an orphaned tab: iTerm2 updated and restarted;
// the tab's processes live on under the old server, which launchd now
// parents. Before the restart r resolves the tab once, as nazar-agent
// resolves every connection, and so sees the server directly below iTerm2
// (witness). It returns the orphaned server, the tab's login shell and its
// peer (claude → ssh under the shell), and leaves no iTerm2 running.
func orphanedTab(f *fake.Fake, r *Resolver) (server, shell, peer platform.ProcessRef) {
	app := f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode,
		App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	server = f.Launch(app, orphanServer)
	login := f.Launch(server, fake.Proc{Path: "/usr/bin/login", Root: true, Code: fake.AppleCode("com.apple.login")})
	shell = f.Launch(login, fake.Proc{Path: "/bin/bash", Args: []string{"-bash"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.bash")})
	claude := f.Launch(shell, fake.ClaudeProc())
	peer = f.Launch(claude, fake.SSHProc("git@github.com"))
	if c := r.Resolve(peer); c.AppSource != AppFromChain || c.App.Ref != app {
		panic("orphanedTab: the tab is not iTerm2's before the restart")
	}
	f.Exit(app) // the update restarted iTerm2: the server and the tab are re-parented to launchd
	return server, shell, peer
}

// Milestone 7: iTerm2 keeps a tab's processes alive across its own
// restart under its helper iTermServer, which launchd then parents. The
// helper heads the chain, is signed by iTerm2's team, is not an app, answers
// for itself (its iTerm2 is gone), and the one running iTerm2 of that team
// started after it: it stands for the app, with the tab's login shell as the
// session root, as before the restart (spec 4.1 step 3).
func TestOrphanedHelperStandsForItsApp(t *testing.T) {
	f := fake.New(t0)
	r := &Resolver{P: f}
	server, shell, peer := orphanedTab(f, r)
	fresh := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")) // the new iTerm2, with its own server and tab
	c := r.Resolve(peer)
	if c.Unknown || c.AppSource != AppFromHelper || c.App.Ref != fresh.App || c.App.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("want iTerm2 through its orphaned helper, got unknown=%v source=%v app=%+v", c.Unknown, c.AppSource, c.App)
	}
	if c.SessionRoot != shell {
		t.Fatalf("session root %v, want the tab's login shell %v", c.SessionRoot, shell)
	}
	if c.AppIdentity() != "H7V7XYVQ7D:com.googlecode.iterm2" || c.AppName() != "iTerm2" || !c.HasApp() {
		t.Fatalf("identity %q name %q", c.AppIdentity(), c.AppName())
	}
	if got := c.Summary(); got != "iTerm2 (via iTermServer-3.7.4) → bash → claude → ssh" {
		t.Fatalf("summary %q", got)
	}
	if h, ok := c.Helper(); !ok || h.Ref != server {
		t.Fatalf("Helper() = %v, %v; want %v", h.Ref, ok, server)
	}
	if below := c.Below(); len(below) != 3 || below[0].Ref != shell || below[2].Ref != peer {
		t.Fatalf("Below() = %d procs, want the shell down", len(below))
	}
	if c.Truncated || len(c.Procs) != 5 || c.Procs[4].Ref != server {
		t.Fatalf("procs %d truncated %v", len(c.Procs), c.Truncated)
	}
	// The new iTerm2's own tab is an ordinary chain, and a second orphaned
	// tab under the same server is its own session.
	if c2 := r.Resolve(fresh.Peer()); c2.AppSource != AppFromChain || c2.SessionRoot != fresh.Shell {
		t.Fatalf("the new tab: source=%v root=%v", c2.AppSource, c2.SessionRoot)
	}
	login2 := f.Launch(server, fake.Proc{Path: "/usr/bin/login", Root: true, Code: fake.AppleCode("com.apple.login")})
	shell2 := f.Launch(login2, fake.Proc{Path: "/bin/bash", Args: []string{"-bash"}, Code: fake.AppleCode("com.apple.bash")})
	peer2 := f.Launch(shell2, fake.SSHProc("h"))
	if c3 := r.Resolve(peer2); c3.AppSource != AppFromHelper || c3.SessionRoot != shell2 || c3.Session == c.Session {
		t.Fatalf("the other orphaned tab: source=%v root=%v session=%v", c3.AppSource, c3.SessionRoot, c3.Session)
	}
	// The peer being the helper itself: iTerm2's, no session.
	if c4 := r.Resolve(server); c4.AppSource != AppFromHelper || !c4.Session.IsZero() || c4.Summary() != "iTerm2 (via iTermServer-3.7.4)" {
		t.Fatalf("the helper as the peer: source=%v session=%v summary=%q", c4.AppSource, c4.Session, c4.Summary())
	}
}

// What an orphaned helper may not do (spec 4.1 step 3, THREAT-MODEL 5.14).
// Each case is a chain that reaches launchd under a process that is not an
// app; none may take an app's identity or a session. The control case
// (the first) is the one that may.
func TestOrphanedHelperFailsClosed(t *testing.T) {
	bash := fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}
	newITerm := func(f *fake.Fake) platform.ProcessRef { return f.ITermTab(platform.ProcessRef{}).App }
	cases := []struct {
		name   string
		build  func(f *fake.Fake) (peer platform.ProcessRef, r *Resolver)
		helper bool // may stand for the app
	}{
		{"control: orphaned tab, iTerm2 restarted", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			newITerm(f)
			return peer, r
		}, true},
		{"the app is not running", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			return peer, r
		}, false},
		{"a LaunchAgent runs the app's own helper binary (never seen below the app)", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// iTerm2 is running; something launchd started (a LaunchAgent)
			// runs iTerm2's own server binary and a shell under it.
			newITerm(f)
			server := f.Launch(platform.ProcessRef{}, orphanServer)
			sh := f.Launch(server, bash)
			return f.Launch(sh, fake.SSHProc("h")), &Resolver{P: f}
		}, false},
		{"the app is older than the seen helper (a second copy of the app outlived the tab's)", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// A second copy of iTerm2 (open -n) has run since before the
			// tab's iTerm2 started its server. The tab's iTerm2 quits: the
			// older copy is the only app of the bundle ID, but the helper
			// is not an orphan of a restart of it.
			newITerm(f)
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			return peer, r
		}, false},
		{"the seen helper is still responsible to a live process", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// The seen server was started by the new iTerm2 (it answers to
			// it), not orphaned by the old one: it stays where it is, in
			// no app's chain.
			r := &Resolver{P: f}
			server, _, peer := orphanedTab(f, r)
			f.SetResponsible(server, newITerm(f))
			return peer, r
		}, false},
		{"the seen helper's code changed under its ref (it execed another team's program)", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// exec keeps the PID and the start time, so the ref the agent
			// saw below iTerm2 now runs code of another team. The process
			// is no longer the helper that was seen.
			r := &Resolver{P: f}
			server, _, peer := orphanedTab(f, r)
			info, _ := f.Process(server)
			info.Path, info.Code = "/usr/local/bin/other", platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM1", SigningID: "com.example.other", CDHash: []byte{2}}
			f.SetProcess(info)
			newITerm(f)
			return peer, r
		}, false},
		{"an Apple app's own child shell, the app quits and comes back", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// Terminal's tab shell is Apple-signed like Terminal itself.
			// Apple's team is not an app's own: no Apple process is ever
			// remembered as a helper, so the shell heads an unknown chain
			// once Terminal quits, whatever Terminal opens later.
			r := &Resolver{P: f}
			app := terminalApp(f)
			shell := f.Launch(app, fake.Proc{Path: "/bin/zsh", Args: []string{"-zsh"}, Code: fake.AppleCode("com.apple.zsh")})
			peer := f.Launch(shell, fake.SSHProc("h"))
			if c := r.Resolve(peer); c.AppSource != AppFromChain || c.SessionRoot != shell {
				panic("the shell is not Terminal's tab")
			}
			f.Exit(app)
			terminalApp(f)
			return peer, r
		}, false},
		{"another team's tool directly below the app, an app of the tool's team takes the bundle ID", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// An editor runs claude directly; claude is right below the
			// app but not the app's own team, so it is no helper. Bundle
			// IDs are not unique across teams: an app of claude's team
			// carrying the editor's bundle ID would otherwise be its app.
			r := &Resolver{P: f}
			code := platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.example.editor", CDHash: []byte{0xed}}
			app := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Editor.app/Contents/MacOS/Editor", Code: code, App: &fake.App{BundleID: "com.example.editor", Name: "Editor"}})
			claude := f.Launch(app, fake.ClaudeProc())
			peer := f.Launch(claude, fake.SSHProc("h"))
			if c := r.Resolve(peer); c.AppSource != AppFromChain {
				panic("claude is not the editor's")
			}
			f.Exit(app)
			f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Editor.app/Contents/MacOS/Editor", Code: fake.ClaudeCode, App: &fake.App{BundleID: "com.example.editor", Name: "Editor"}})
			return peer, r
		}, false},
		{"the helper is still responsible to a live app (detached from a tab)", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// A tab of a live iTerm2 started claude; claude double-forked a
			// claude of its own. Claude.app (the same team as claude) opens
			// later: the detached claude is not its process.
			tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
			helper := f.Launch(tab.Peer(), bash)
			detached := f.Launch(helper, fake.ClaudeProc())
			peer := f.Launch(detached, fake.SSHProc("h"))
			f.Exit(helper) // detached is re-parented to launchd; it still answers to iTerm2
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/Claude.app/Contents/MacOS/Claude", Code: fake.ClaudeCode,
				App: &fake.App{BundleID: "com.anthropic.claudefordesktop", Name: "Claude"},
			})
			return peer, &Resolver{P: f}
		}, false},
		{"never seen below its app (nazar-agent started after the app restarted)", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			_, _, peer := orphanedTab(f, &Resolver{P: f}) // another agent saw it
			newITerm(f)
			return peer, &Resolver{P: f}
		}, false},
		{"seen below another app of the team", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/iTerm2 Nightly.app/Contents/MacOS/iTerm2", Code: fake.ITermCode,
				App: &fake.App{BundleID: "com.googlecode.iterm2.nightly", Name: "iTerm2 Nightly"},
			})
			return peer, r
		}, false},
		{"a detached copy of the app's own helper, and the app restarts", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// Under claude in a live tab, a script detaches iTerm2's own
			// signed server and runs a shell under it; the agent resolves
			// both chains while iTerm2 runs. iTerm2 then quits and comes
			// back: the detached server answers for itself, is iTerm2's
			// team and is older than the new iTerm2, but was never seen
			// below an app, so claude's rules are not shed.
			r := &Resolver{P: f}
			tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), bash)
			mid := f.Launch(tab.Peer(), bash)
			server := f.Launch(mid, orphanServer)
			sh := f.Launch(server, bash)
			peer := f.Launch(sh, fake.SSHProc("prod"))
			f.Exit(mid)
			if c := r.Resolve(tab.Peer()); c.AppSource != AppFromChain {
				panic("the tab is not iTerm2's")
			}
			if c := r.Resolve(peer); !c.Unknown {
				panic("the detached chain is not unknown while iTerm2 runs")
			}
			f.Exit(tab.App)
			newITerm(f)
			return peer, r
		}, false},
		{"a copy of the app's own helper used while still attached, then detached, and the app restarts", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// The same copy, but the script uses ssh through it while it
			// is still in the tab's chain (iTerm2 is that chain's app),
			// and only then detaches. Only the process directly below
			// iTerm2 is remembered, never one further down, so the copy
			// does not stand for the next iTerm2.
			r := &Resolver{P: f}
			tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), bash)
			mid := f.Launch(tab.Peer(), bash)
			server := f.Launch(mid, orphanServer)
			sh := f.Launch(server, bash)
			peer := f.Launch(sh, fake.SSHProc("prod"))
			if c := r.Resolve(peer); c.AppSource != AppFromChain || indexOf(c.Procs, server) < 0 {
				panic("the attached copy's chain is not iTerm2's")
			}
			f.Exit(mid)
			f.Exit(tab.App)
			newITerm(f)
			return peer, r
		}, false},
		{"a detached claude, the tab's app quits, Claude.app opens", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
			h := f.Launch(tab.Peer(), bash)
			detached := f.Launch(h, fake.ClaudeProc())
			peer := f.Launch(detached, fake.SSHProc("h"))
			r.Resolve(tab.Peer())
			f.Exit(h)
			r.Resolve(peer)
			f.Exit(tab.App)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/Claude.app/Contents/MacOS/Claude", Code: fake.ClaudeCode,
				App: &fake.App{BundleID: "com.anthropic.claudefordesktop", Name: "Claude"},
			})
			return peer, r
		}, false},
		{"another team's tool started directly by the app, the app quits, its own app opens", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// iTerm2 runs claude as a tab's command; claude is seen right
			// below iTerm2 but is not iTerm2's team, so it is no helper.
			r := &Resolver{P: f}
			app := newITerm(f)
			claude := f.Launch(app, fake.ClaudeProc())
			peer := f.Launch(claude, fake.SSHProc("h"))
			if c := r.Resolve(peer); c.AppSource != AppFromChain {
				panic("claude is not iTerm2's")
			}
			f.Exit(app)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/Claude.app/Contents/MacOS/Claude", Code: fake.ClaudeCode,
				App: &fake.App{BundleID: "com.anthropic.claudefordesktop", Name: "Claude"},
			})
			return peer, r
		}, false},
		{"the seen helper's PID was recycled", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// The seen server exited; a process of the same team now holds
			// its PID under another generation, launchd's child, answering
			// for itself.
			r := &Resolver{P: f}
			server, _, _ := orphanedTab(f, r)
			info, _ := f.Process(server)
			f.Exit(server)
			impostor := platform.ProcessRef{PID: server.PID, Generation: server.Generation + 1}
			info.Ref, info.Parent, info.StartTime = impostor, f.Launchd, info.StartTime.Add(time.Millisecond)
			f.SetProcess(info)
			f.SetResponsible(impostor, impostor)
			peer := f.Launch(impostor, fake.SSHProc("h"))
			newITerm(f)
			return peer, r
		}, false},
		{"the top is Apple-signed (a double-forked ssh), an Apple app opened after it", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// The ssh heads its own chain and answers for itself once
			// iTerm2 is gone; Terminal (Apple's team, the only one
			// running, younger) would otherwise be its app.
			tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), bash)
			helper := f.Launch(tab.Peer(), bash)
			peer := f.Launch(helper, fake.SSHProc("h"))
			f.Exit(helper)
			f.Exit(tab.App)
			newITerm(f)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Code: fake.AppleCode("com.apple.Terminal"),
				App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"},
			})
			return peer, &Resolver{P: f}
		}, false},
		{"the top is unsigned", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			d := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/local/bin/daemon"})
			peer := f.Launch(d, fake.SSHProc("h"))
			newITerm(f)
			return peer, &Resolver{P: f}
		}, false},
		{"the top is ad-hoc signed with the app's team id", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			adhoc := orphanServer
			adhoc.Code = platform.CodeIdentity{Signed: true, AdHoc: true, TeamID: "H7V7XYVQ7D", SigningID: "iTermServer"}
			d := f.Launch(platform.ProcessRef{}, adhoc)
			peer := f.Launch(d, fake.SSHProc("h"))
			newITerm(f)
			return peer, &Resolver{P: f}
		}, false},
		{"the running app is another team's", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/Other.app/Contents/MacOS/Other",
				Code: platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM1", SigningID: "com.example.other", CDHash: []byte{1}},
				App:  &fake.App{BundleID: "com.example.other", Name: "Other"},
			})
			return peer, r
		}, false},
		{"the running app carries the bundle ID under another team", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// Bundle IDs are not unique across teams: the identity is
			// team:bundle, and the helper binds only to the pair it was
			// seen under.
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2",
				Code: platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM1", SigningID: "com.googlecode.iterm2", CDHash: []byte{3}},
				App:  &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
			})
			return peer, r
		}, false},
		{"two running apps of the team", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			newITerm(f)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/iTerm Beta.app/Contents/MacOS/iTerm2", Code: fake.ITermCode,
				App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
			})
			return peer, r
		}, false},
		{"the running app is another user's", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			f.Launch(platform.ProcessRef{}, fake.Proc{
				Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode, Root: true,
				App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
			})
			return peer, r
		}, false},
		{"the chain is truncated", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			r := &Resolver{P: f}
			_, _, peer := orphanedTab(f, r)
			newITerm(f)
			r.MaxDepth = 3 // ssh, claude, bash: the helper is never reached
			return peer, r
		}, false},
		{"the chain is truncated at the helper (its parent vanished mid-walk)", func(f *fake.Fake) (platform.ProcessRef, *Resolver) {
			// The helper is the last process the walk reached, but not
			// the top: what is above it is unknown.
			r := &Resolver{P: f}
			server, _, peer := orphanedTab(f, r)
			newITerm(f)
			info, _ := f.Process(server)
			info.Parent = platform.ProcessRef{PID: 31337, Generation: 31337001}
			f.SetProcess(info)
			return peer, r
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer, r := tc.build(fake.New(t0))
			c := r.Resolve(peer)
			if tc.helper {
				if c.AppSource != AppFromHelper || c.Unknown || c.AppIdentity() == "" || c.Session.IsZero() {
					t.Fatalf("control: source=%v unknown=%v identity=%q session=%v", c.AppSource, c.Unknown, c.AppIdentity(), c.Session)
				}
				return
			}
			// Unknown, with no identity and no session; a responsible app
			// may still be shown (AppFromResponsible), as before.
			if c.AppSource == AppFromHelper || !c.Unknown || c.AppIdentity() != "" || !c.Session.IsZero() || c.HasApp() {
				t.Fatalf("not fail-closed: source=%v unknown=%v identity=%q session=%v app=%+v", c.AppSource, c.Unknown, c.AppIdentity(), c.Session, c.App)
			}
		})
	}
}

// staleApps lists the running apps under a ref whose generation is not the
// live one (the app's PID was recycled, or the platform's list is stale).
type staleApps struct{ *fake.Fake }

func (s staleApps) Apps() []platform.AppInfo {
	apps := s.Fake.Apps()
	for i := range apps {
		apps[i].Ref.Generation++
	}
	return apps
}

// claimsApps lists, next to the real apps, a process the platform does not
// call an app (here the new iTerm2's own server, with the app's bundle id:
// younger than the orphaned helper, of its team and user, so only AppFor's
// verdict on its live record keeps it out).
type claimsApps struct {
	*fake.Fake
	extra platform.ProcessRef
}

func (c claimsApps) Apps() []platform.AppInfo {
	return append(c.Fake.Apps(), platform.AppInfo{Ref: c.extra, BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: orphanServer.Code})
}

// Apps is a list of candidates, never an answer: an entry is the app only
// when Process answers it under exactly that full ref and AppFor calls its
// live record an app. A stale ref and a non-app claimed as an app are both
// skipped, and the helper stays unknown.
func TestHelperAppCandidatesAreRechecked(t *testing.T) {
	f := fake.New(t0)
	r := &Resolver{P: f}
	_, _, peer := orphanedTab(f, r)
	freshTab := f.ITermTab(platform.ProcessRef{})
	fresh := freshTab.App
	if c := r.Resolve(peer); c.AppSource != AppFromHelper || c.App.Ref != fresh {
		t.Fatalf("control: %v %+v", c.AppSource, c.App)
	}
	r.P = staleApps{f}
	if c := r.Resolve(peer); c.AppSource != AppNone || !c.Unknown {
		t.Fatalf("a stale app ref was taken: source=%v app=%+v", c.AppSource, c.App)
	}
	f.Exit(fresh)
	r.P = claimsApps{f, freshTab.Server}
	if c := r.Resolve(peer); c.AppSource != AppNone || !c.Unknown {
		t.Fatalf("a non-app listed as an app was taken: source=%v app=%+v", c.AppSource, c.App)
	}
	// With the real app running again, the claimed extra makes two
	// candidates of the team only if it passes; it does not.
	again := f.ITermTab(platform.ProcessRef{}).App
	if c := r.Resolve(peer); c.AppSource != AppFromHelper || c.App.Ref != again {
		t.Fatalf("the claimed non-app disturbed the real app: source=%v app=%+v", c.AppSource, c.App)
	}
}

// witness keeps at most maxSeen helpers and drops those no longer running
// first, so an agent that saw many helpers come and go still knows the
// live one (a forgotten helper would only stay unknown once orphaned).
func TestSeenHelpersAreBounded(t *testing.T) {
	f := fake.New(t0)
	r := &Resolver{P: f}
	server, _, peer := orphanedTab(f, r)
	app := platform.AppInfo{BundleID: "com.googlecode.iterm2", Code: fake.ITermCode}
	for i := 0; i < 3*maxSeen; i++ {
		r.witness(platform.ProcessInfo{Ref: platform.ProcessRef{PID: 90000 + i, Generation: 1}, Code: orphanServer.Code}, app)
	}
	if n := len(r.seen); n > maxSeen {
		t.Fatalf("%d helpers kept, want at most %d", n, maxSeen)
	}
	if _, ok := r.seen[server]; !ok {
		t.Fatal("the live helper was dropped before the dead ones")
	}
	f.ITermTab(platform.ProcessRef{})
	if c := r.Resolve(peer); c.AppSource != AppFromHelper {
		t.Fatalf("source=%v", c.AppSource)
	}
}

// Milestone 7: Tool says whether a process is a tool running inside
// the session, the run a session approval for a rule it satisfied is bound
// to: strictly below the session root and not Apple's.
func TestToolIsInsideTheSession(t *testing.T) {
	f := fake.New(t0)
	sh := fake.Proc{Path: "/bin/sh", Code: fake.AppleCode("com.apple.sh")}
	tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), sh, fake.ClaudeProc(), fake.SSHProc("h"))
	r := &Resolver{P: f}
	c := r.Resolve(tab.Peer())
	for i, want := range []bool{true, false, true, false} { // claude, sh, claude, ssh
		p, ok := c.Tool(tab.Procs[i])
		if ok != want || (ok && p.Ref != tab.Procs[i]) {
			t.Errorf("Tool(procs[%d]) = %+v %v, want %v", i, p, ok, want)
		}
	}
	for name, ref := range map[string]platform.ProcessRef{"the root": tab.Shell, "login": tab.Login, "the helper": tab.Server, "the app": tab.App, "zero": {}, "a stranger": {PID: 99999, Generation: 7}} {
		if _, ok := c.Tool(ref); ok {
			t.Errorf("%s is a tool in the session", name)
		}
	}
	// A tool the app started directly sits above the root (spec 4.1 step
	// 4): not a run in the session, which is the shell below it.
	direct := f.Launch(tab.App, fake.ClaudeProc())
	bash := f.Launch(direct, fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")})
	dc := r.Resolve(f.Launch(bash, fake.SSHProc("h")))
	if dc.SessionRoot != bash {
		t.Fatalf("control: root %v, want bash %v", dc.SessionRoot, bash)
	}
	if _, ok := dc.Tool(direct); ok {
		t.Error("a tool above the session root is a tool in the session")
	}
	// An unknown chain has no session and no tool.
	stray := f.Launch(platform.ProcessRef{}, fake.ClaudeProc())
	uc := r.Resolve(f.Launch(stray, fake.SSHProc("h")))
	if !uc.Unknown {
		t.Fatal("control: a chain from launchd is unknown")
	}
	if _, ok := uc.Tool(stray); ok {
		t.Error("a tool in an unknown chain is a tool in a session")
	}
}
