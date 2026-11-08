package fake

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// The fake must satisfy the interfaces the core consumes (spec 4.7).
var (
	_ platform.Platform = (*Fake)(nil)
	_ platform.Vault    = (*Vault)(nil)
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

// waitFor polls cond until it holds or two seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// within fails the test if fn does not return within two seconds (a deadlock
// in the fake would otherwise hang the whole test binary).
func within(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("deadlock: %s never returned", what)
	}
}

// walk returns the chain from ref up to (not including) launchd, peer first.
func walk(t *testing.T, f *Fake, ref platform.ProcessRef) []platform.ProcessInfo {
	t.Helper()
	var chain []platform.ProcessInfo
	for ref != f.Launchd {
		info, err := f.Process(ref)
		if err != nil {
			t.Fatalf("Process(%v): %v", ref, err)
		}
		chain = append(chain, info)
		if len(chain) > 64 {
			t.Fatal("parent chain does not terminate at launchd")
		}
		ref = info.Parent
	}
	return chain
}

// ---------------------------------------------------------------------------
// Core behaviour.

func TestLaunchAndWalk(t *testing.T) {
	f := New(t0)
	c := f.ITermTab(platform.ProcessRef{}, Proc{Path: "/usr/bin/git"}, SSHProc("git@github.com"))
	p, err := f.Process(c.Peer())
	if err != nil || p.Path != "/usr/bin/ssh" {
		t.Fatalf("peer %+v %v", p, err)
	}
	var chain []platform.ProcessInfo
	for ref := c.Peer(); ref != f.Launchd; {
		info, err := f.Process(ref)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, info)
		ref = info.Parent
	}
	if len(chain) != 6 {
		t.Fatalf("chain length %d, want 6", len(chain))
	}
	app, ok := f.AppFor(chain)
	if !ok || app.BundleID != "com.googlecode.iterm2" || app.Ref != c.App {
		t.Fatalf("AppFor = %+v %v", app, ok)
	}
	login, _ := f.Process(c.Login)
	if login.UID != 0 {
		t.Fatalf("login uid %d, want 0", login.UID)
	}
}

func TestExitFiresWatchersAndReparents(t *testing.T) {
	f := New(t0)
	c := f.ITermTab(platform.ProcessRef{}, Proc{Path: "/usr/bin/git"})
	fired := 0
	f.OnProcessExit(c.Shell, func() { fired++ })
	f.Exit(c.Shell)
	if fired != 1 {
		t.Fatalf("fired %d", fired)
	}
	if _, err := f.Process(c.Shell); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("want ErrNoProcess, got %v", err)
	}
	git, _ := f.Process(c.Procs[0])
	if git.Parent != f.Launchd {
		t.Fatalf("orphan parent %v, want launchd", git.Parent)
	}
	done := make(chan struct{})
	f.OnProcessExit(c.Shell, func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watcher on dead process never ran")
	}
}

func TestGateScripting(t *testing.T) {
	f := New(t0)
	f.ScriptAuth(Answer{Allow: true}, Answer{Allow: false})
	ref, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{Title: "a"})
	if err != nil || ref == 0 {
		t.Fatalf("first auth: %v %v", ref, err)
	}
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{Title: "b"}); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("second auth: want ErrDenied, got %v", err)
	}
	if ok, _ := f.Confirm(platform.Prompt{}); ok {
		t.Fatal("default confirm must deny")
	}
	f.ScriptConfirm(Answer{Allow: true})
	if ok, _ := f.Confirm(platform.Prompt{}); !ok {
		t.Fatal("scripted confirm must allow")
	}
	if f.CountShown(KindAuthenticate) != 2 || f.CountShown(KindConfirm) != 2 {
		t.Fatalf("shown %+v", f.Shown())
	}
	if f.LiveApprovals() != 1 {
		t.Fatal("one live approval expected")
	}
	f.ReleaseApproval(ref)
	f.ReleaseApproval(ref)
	if f.LiveApprovals() != 0 || len(f.Released()) != 1 {
		t.Fatal("release must be idempotent")
	}
}

func TestEnclaveSignVerifiesAndEnforcesPresence(t *testing.T) {
	f := New(t0)
	h, pub, err := f.CreateKey(platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Sign(h, []byte("x"), 0); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("want ErrAuthRequired, got %v", err)
	}
	f.ScriptAuth(Answer{Allow: true})
	ref, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	der, err := f.Sign(h, []byte("data"), ref)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("data"))
	if !ecdsa.VerifyASN1(pk, sum[:], der) {
		t.Fatal("signature does not verify")
	}
	f.ReleaseApproval(ref)
	if _, err := f.Sign(h, []byte("x"), ref); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatal("released ref must not sign")
	}
	if err := f.DeleteKey(h); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Sign(h, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("deleted key must be gone")
	}
}

func TestNoPresenceKeySignsWithoutRef(t *testing.T) {
	f := New(t0)
	h, _, _ := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	if _, err := f.Sign(h, []byte("x"), 0); err != nil {
		t.Fatal(err)
	}
	if f.SignCalls() != 1 {
		t.Fatal("SignCalls")
	}
}

func TestPeerOf(t *testing.T) {
	f := New(t0)
	if _, err := f.PeerOf(3); err == nil {
		t.Fatal("unscripted peer must fail")
	}
	a := f.Launch(platform.ProcessRef{}, Proc{Path: "/a"})
	b := f.Launch(platform.ProcessRef{}, Proc{Path: "/b"})
	f.SetDefaultPeer(a)
	f.SetPeer(7, b)
	if r, _ := f.PeerOf(3); r != a {
		t.Fatal("default peer")
	}
	if r, _ := f.PeerOf(7); r != b {
		t.Fatal("scripted peer")
	}
}

func TestVault(t *testing.T) {
	v := NewVault()
	if _, err := v.Get("x"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatal("missing item")
	}
	v.Put("ssh-key/a", []byte("1"))
	v.Put("ssh-key/b", []byte("2"))
	v.Put("state", []byte("3"))
	names, _ := v.List("ssh-key/")
	if len(names) != 2 || names[0] != "ssh-key/a" {
		t.Fatalf("List = %v", names)
	}
	if err := v.Delete("ssh-key/a"); err != nil {
		t.Fatal(err)
	}
}

func TestBlockingAnswer(t *testing.T) {
	f := New(t0)
	release := make(chan struct{})
	f.ScriptConfirm(Answer{Allow: true, Wait: release})
	got := make(chan bool)
	go func() { ok, _ := f.Confirm(platform.Prompt{}); got <- ok }()
	select {
	case <-got:
		t.Fatal("answered before release")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if !<-got {
		t.Fatal("want allow")
	}
}

// ---------------------------------------------------------------------------
// Clock.

func TestClockStartsAtStartAndAdvances(t *testing.T) {
	f := New(t0)
	if got := f.Now(); !got.Equal(t0) {
		t.Fatalf("Now() = %v, want %v", got, t0)
	}
	f.Advance(90 * time.Minute)
	if got := f.Now(); !got.Equal(t0.Add(90 * time.Minute)) {
		t.Fatalf("after Advance, Now() = %v, want %v", got, t0.Add(90*time.Minute))
	}
}

// Session IDs are (pid, start time) (spec 4.1 step 4), so start times must be
// realistic: never before the clock started, never in the future, never
// before the parent's, and unaffected by later clock moves.
func TestLaunchStartTimes(t *testing.T) {
	f := New(t0)
	a := f.Launch(platform.ProcessRef{}, Proc{Path: "/a"})
	b := f.Launch(a, Proc{Path: "/b"})
	pa, _ := f.Process(a)
	pb, _ := f.Process(b)
	if pa.StartTime.Before(t0) {
		t.Fatalf("process started %v, before the clock start %v", pa.StartTime, t0)
	}
	if pb.StartTime.Before(pa.StartTime) {
		t.Fatalf("child started %v, before its parent %v", pb.StartTime, pa.StartTime)
	}
	if pb.StartTime.Equal(pa.StartTime) {
		t.Fatal("two launches share a start time")
	}
	if pb.StartTime.After(f.Now()) {
		t.Fatalf("process start %v is after Now() %v", pb.StartTime, f.Now())
	}
	f.Advance(time.Hour)
	c := f.Launch(platform.ProcessRef{}, Proc{Path: "/c"})
	pc, _ := f.Process(c)
	if pc.StartTime.Before(t0.Add(time.Hour)) {
		t.Fatalf("launch after Advance started at %v", pc.StartTime)
	}
	if again, _ := f.Process(a); !again.StartTime.Equal(pa.StartTime) {
		t.Fatal("Advance changed an existing process's start time")
	}
}

// ---------------------------------------------------------------------------
// Processes.

func TestLaunchdIsTheAppleSignedRoot(t *testing.T) {
	f := New(t0)
	if f.Launchd.IsZero() {
		t.Fatal("Launchd ref is zero")
	}
	p, err := f.Process(f.Launchd)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref != f.Launchd || p.UID != 0 || !p.Parent.IsZero() || p.Path != "/sbin/launchd" {
		t.Fatalf("launchd record %+v", p)
	}
	if p.Code.Team() != "apple" {
		t.Fatalf("launchd team %q, want apple", p.Code.Team())
	}
	if _, ok := f.AppFor([]platform.ProcessInfo{p}); ok {
		t.Fatal("launchd must not be a GUI app")
	}
}

func TestLaunchRecordsProcessFields(t *testing.T) {
	f := New(t0)
	code := platform.CodeIdentity{Signed: true, TeamID: "ABCDE12345", SigningID: "com.example.tool", CDHash: []byte{0xab}}
	args := []string{"tool", "--flag"}
	ref := f.Launch(platform.ProcessRef{}, Proc{Path: "/opt/tool", Args: args, Cwd: "/tmp/w", Code: code})
	args[0] = "evil" // the caller's slice must not alias the record
	p, err := f.Process(ref)
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref != ref || p.Parent != f.Launchd || p.Path != "/opt/tool" || p.Cwd != "/tmp/w" {
		t.Fatalf("record %+v", p)
	}
	if !slices.Equal(p.Args, []string{"tool", "--flag"}) {
		t.Fatalf("Args = %q", p.Args)
	}
	if p.Code.TeamID != "ABCDE12345" || p.Code.SigningID != "com.example.tool" || p.Code.Team() != "ABCDE12345" {
		t.Fatalf("Code = %+v", p.Code)
	}
	if p.UID == 0 {
		t.Fatal("a process launched without Root must not run as root")
	}
	p.Args[1] = "mutated" // nor may the returned record alias it
	if again, _ := f.Process(ref); again.Args[1] != "--flag" {
		t.Fatalf("Process returned an aliased Args slice: %q", again.Args)
	}

	d := f.Launch(platform.ProcessRef{}, Proc{Path: "/bin/sleep"})
	if pd, _ := f.Process(d); !slices.Equal(pd.Args, []string{"/bin/sleep"}) {
		t.Fatalf("default Args = %q, want [/bin/sleep]", pd.Args)
	}
	r := f.Launch(platform.ProcessRef{}, Proc{Path: "/usr/bin/login", Root: true})
	if pr, _ := f.Process(r); pr.UID != 0 {
		t.Fatalf("Root process uid %d", pr.UID)
	}
}

// A recycled ref would let a new process inherit a dead one's approvals and
// exit watches, so refs are never handed out twice.
func TestLaunchGivesEveryProcessADistinctRef(t *testing.T) {
	f := New(t0)
	seen := map[platform.ProcessRef]bool{f.Launchd: true}
	var dead []platform.ProcessRef
	for i := range 50 {
		ref := f.Launch(platform.ProcessRef{}, Proc{Path: "/bin/true"})
		if ref.IsZero() {
			t.Fatal("Launch returned the zero ref")
		}
		if seen[ref] {
			t.Fatalf("launch %d reused ref %v", i, ref)
		}
		seen[ref] = true
		if i%2 == 0 {
			f.Exit(ref)
			dead = append(dead, ref)
		}
	}
	for _, ref := range dead {
		if _, err := f.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Fatalf("exited %v still resolves: %v", ref, err)
		}
	}
}

// Building a chain under a parent that does not exist is a test bug; the fake
// must say so rather than silently invent a chain.
func TestLaunchUnderUnknownParentPanics(t *testing.T) {
	f := New(t0)
	gone := f.Launch(platform.ProcessRef{}, Proc{Path: "/a"})
	f.Exit(gone)
	for _, parent := range []platform.ProcessRef{{PID: 99999, Generation: 1}, gone} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Launch under %v did not panic", parent)
				}
			}()
			f.Launch(parent, Proc{Path: "/b"})
		}()
	}
}

func TestSetProcessScriptsOddRecords(t *testing.T) {
	f := New(t0)
	parent := f.Launch(platform.ProcessRef{}, Proc{Path: "/p"})
	child := f.Launch(parent, Proc{Path: "/c"})
	ci, _ := f.Process(child)
	pi, _ := f.Process(parent)
	pi.StartTime = ci.StartTime.Add(time.Second) // a parent that started after its child
	f.SetProcess(pi)
	if got, _ := f.Process(parent); !got.StartTime.Equal(pi.StartTime) {
		t.Fatalf("SetProcess not applied: %v", got.StartTime)
	}

	ghost := platform.ProcessRef{PID: 4242, Generation: 9}
	f.SetProcess(platform.ProcessInfo{Ref: ghost, Parent: f.Launchd, UID: 501, Path: "/tmp/x", Args: []string{"x"}})
	if got, err := f.Process(ghost); err != nil || got.Path != "/tmp/x" || got.Parent != f.Launchd {
		t.Fatalf("scripted process %+v %v", got, err)
	}
	fired := 0
	f.OnProcessExit(ghost, func() { fired++ })
	f.Exit(ghost)
	if fired != 1 {
		t.Fatalf("watcher on a scripted process fired %d times", fired)
	}
	if _, err := f.Process(ghost); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("exited scripted process: %v", err)
	}
}

// The audit token's pidversion exists so a recycled PID can't impersonate
// the original (spec 4.1 step 1): same PID, different generation = different
// process, for lookups and for exit watches.
func TestRecycledPIDIsADifferentProcess(t *testing.T) {
	f := New(t0)
	alive := f.Launch(platform.ProcessRef{}, Proc{Path: "/usr/bin/ssh"})
	twin := platform.ProcessRef{PID: alive.PID, Generation: alive.Generation + 1}
	f.SetProcess(platform.ProcessInfo{Ref: twin, Parent: f.Launchd, UID: 501, StartTime: f.Now(), Path: "/tmp/evil"})
	aliveFired, twinFired := 0, 0
	f.OnProcessExit(alive, func() { aliveFired++ })
	f.OnProcessExit(twin, func() { twinFired++ })

	f.Exit(twin)
	if twinFired != 1 || aliveFired != 0 {
		t.Fatalf("exit of the twin fired alive=%d twin=%d", aliveFired, twinFired)
	}
	if p, err := f.Process(alive); err != nil || p.Path != "/usr/bin/ssh" {
		t.Fatalf("original process after its twin exited: %+v %v", p, err)
	}

	f.Exit(alive)
	recycled := platform.ProcessRef{PID: alive.PID, Generation: alive.Generation + 2}
	f.SetProcess(platform.ProcessInfo{Ref: recycled, Parent: f.Launchd, UID: 501, StartTime: f.Now(), Path: "/tmp/evil"})
	if _, err := f.Process(alive); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("dead ref resolves through a recycled PID: %v", err)
	}
	done := make(chan struct{})
	f.OnProcessExit(alive, func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watch on a dead ref waited for the recycled PID")
	}
	if aliveFired != 1 {
		t.Fatalf("alive watcher fired %d", aliveFired)
	}
}

func TestExitRunsEachWatcherOnceInOrder(t *testing.T) {
	f := New(t0)
	p := f.Launch(platform.ProcessRef{}, Proc{Path: "/a"})
	var order []int
	f.OnProcessExit(p, func() { order = append(order, 1) })
	f.OnProcessExit(p, func() { order = append(order, 2) })
	if n := f.ExitWatchers(p); n != 2 {
		t.Fatalf("ExitWatchers = %d, want 2", n)
	}
	f.Exit(p) // watchers have run by the time Exit returns
	if !slices.Equal(order, []int{1, 2}) {
		t.Fatalf("watchers ran %v, want [1 2]", order)
	}
	if n := f.ExitWatchers(p); n != 0 {
		t.Fatalf("ExitWatchers after exit = %d", n)
	}
	f.Exit(p)
	if len(order) != 2 {
		t.Fatalf("second Exit re-fired watchers: %v", order)
	}
	f.Exit(platform.ProcessRef{PID: 77777, Generation: 3}) // never existed: no-op
}

func TestWatchOnNeverLaunchedProcessRunsPromptly(t *testing.T) {
	f := New(t0)
	done := make(chan struct{})
	f.OnProcessExit(platform.ProcessRef{PID: 31337, Generation: 1}, func() { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watch on an unknown process never ran")
	}
}

// OnProcessExit racing Exit: whichever wins, the watcher runs exactly once
// (a missed exit would keep a session approval alive forever).
func TestExitWatcherRunsExactlyOnceUnderRaces(t *testing.T) {
	f := New(t0)
	const n = 200
	var fired [n]atomic.Int32
	var wg sync.WaitGroup
	for i := range n {
		p := f.Launch(platform.ProcessRef{}, Proc{Path: "/bin/sleep"})
		wg.Add(2)
		go func() { defer wg.Done(); f.OnProcessExit(p, func() { fired[i].Add(1) }) }()
		go func() { defer wg.Done(); f.Exit(p) }()
	}
	wg.Wait()
	waitFor(t, "every watcher to run", func() bool {
		for i := range n {
			if fired[i].Load() == 0 {
				return false
			}
		}
		return true
	})
	time.Sleep(20 * time.Millisecond)
	for i := range n {
		if got := fired[i].Load(); got != 1 {
			t.Fatalf("watcher %d ran %d times", i, got)
		}
	}
}

// Callbacks run outside the fake's lock: an exit or lock handler that looks
// up processes or registers more watches must not deadlock.
func TestEventCallbacksMayCallBackIntoTheFake(t *testing.T) {
	f := New(t0)
	p := f.Launch(platform.ProcessRef{}, Proc{Path: "/a"})
	q := f.Launch(platform.ProcessRef{}, Proc{Path: "/b"})
	within(t, "Exit with a re-entrant watcher", func() {
		f.OnProcessExit(p, func() {
			_, _ = f.Process(q)
			f.OnProcessExit(q, func() {})
			_ = f.ExitWatchers(q)
			_ = f.Now()
		})
		f.Exit(p)
	})
	within(t, "LockScreen with a re-entrant callback", func() {
		f.OnScreenLock(func() {
			f.OnScreenLock(func() {})
			_ = f.Now()
			_ = f.Warnings()
		})
		f.LockScreen()
	})
}

// A gate func that moves the fake clock (the user took two minutes to
// answer) or inspects recorded prompts must not deadlock.
func TestGateFuncsMayCallBackIntoTheFake(t *testing.T) {
	f := New(t0)
	f.SetGateFuncs(
		func(platform.Prompt) Answer {
			f.Advance(2 * time.Minute)
			_ = f.CountShown(KindAuthenticate)
			return Answer{Allow: true}
		},
		func(platform.Prompt) Answer {
			_ = f.Shown()
			_ = f.LiveApprovals()
			return Answer{Allow: true}
		},
	)
	within(t, "Authenticate with a re-entrant gate func", func() {
		if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); err != nil {
			t.Errorf("Authenticate: %v", err)
		}
	})
	within(t, "Confirm with a re-entrant gate func", func() {
		if ok, _ := f.Confirm(platform.Prompt{}); !ok {
			t.Error("Confirm denied")
		}
	})
	if got := f.Now(); !got.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("Now() = %v after the gate func advanced the clock", got)
	}
}

// ---------------------------------------------------------------------------
// Apps.

func TestAppForReturnsTheInnermostApp(t *testing.T) {
	f := New(t0)
	c := f.ITermTab(platform.ProcessRef{})
	cursorCode := platform.CodeIdentity{Signed: true, TeamID: "TEAMCURSR1", SigningID: "com.example.cursor"}
	cursor := f.Launch(c.Shell, Proc{
		Path: "/Applications/Cursor.app/Contents/MacOS/Cursor", Code: cursorCode,
		App: &App{BundleID: "com.example.cursor", Name: "Cursor"},
	})
	ssh := f.Launch(cursor, SSHProc("host"))
	app, ok := f.AppFor(walk(t, f, ssh))
	if !ok || app.Ref != cursor || app.BundleID != "com.example.cursor" || app.Name != "Cursor" {
		t.Fatalf("AppFor = %+v %v, want Cursor", app, ok)
	}
	if app.Code.Team() != "TEAMCURSR1" {
		t.Fatalf("app code %+v", app.Code)
	}
}

// A process can copy iTerm2's path, arguments and code identity, or reuse
// its PID, but that does not make it the app (spec 4.1 step 3).
func TestAppForCannotBeSpoofed(t *testing.T) {
	f := New(t0)
	c := f.ITermTab(platform.ProcessRef{})
	if _, ok := f.AppFor(nil); ok {
		t.Fatal("AppFor(nil) found an app")
	}
	if _, ok := f.AppFor([]platform.ProcessInfo{}); ok {
		t.Fatal("AppFor(empty) found an app")
	}
	impostor := f.Launch(platform.ProcessRef{}, Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: ITermCode})
	ip, _ := f.Process(impostor)
	if a, ok := f.AppFor([]platform.ProcessInfo{ip}); ok {
		t.Fatalf("look-alike process without an app bundle resolved as %+v", a)
	}
	real, _ := f.Process(c.App)
	forged := real
	forged.Ref.Generation++
	if a, ok := f.AppFor([]platform.ProcessInfo{forged}); ok {
		t.Fatalf("recycled-PID record resolved as app %+v", a)
	}
	for _, ref := range []platform.ProcessRef{c.Server, c.Login, c.Shell} {
		p, _ := f.Process(ref)
		if a, ok := f.AppFor([]platform.ProcessInfo{p}); ok {
			t.Fatalf("%s resolved as app %+v", p.Path, a)
		}
	}
}

// ---------------------------------------------------------------------------
// Scenario helpers: the iTerm2 chain spike S3 observed.

func TestITermTabMatchesSpikeS3Chain(t *testing.T) {
	f := New(t0)
	c := f.ITermTab(platform.ProcessRef{})
	if c.Peer() != c.Shell || len(c.Procs) != 0 {
		t.Fatalf("tab without extras: Peer %v Shell %v Procs %v", c.Peer(), c.Shell, c.Procs)
	}
	app, _ := f.Process(c.App)
	server, _ := f.Process(c.Server)
	login, _ := f.Process(c.Login)
	shell, _ := f.Process(c.Shell)
	if app.Parent != f.Launchd || app.Code.Team() != "H7V7XYVQ7D" {
		t.Fatalf("app %+v", app)
	}
	if server.Parent != c.App || server.Code.Team() != "H7V7XYVQ7D" || server.UID == 0 {
		t.Fatalf("iTermServer %+v", server)
	}
	if login.Parent != c.Server || login.UID != 0 || login.Path != "/usr/bin/login" || login.Code.Team() != "apple" {
		t.Fatalf("login %+v", login)
	}
	if shell.Parent != c.Login || shell.UID == 0 || filepath.Base(shell.Path) != "bash" || shell.Code.Team() != "apple" {
		t.Fatalf("shell %+v", shell)
	}
	if len(shell.Args) == 0 || !strings.HasPrefix(shell.Args[0], "-") {
		t.Fatalf("shell is not a login shell: args %q", shell.Args)
	}
	a, ok := f.AppFor(walk(t, f, c.Shell))
	if !ok || a.Ref != c.App || a.BundleID != "com.googlecode.iterm2" || a.Name != "iTerm2" || a.Code.Team() != "H7V7XYVQ7D" {
		t.Fatalf("AppFor = %+v %v", a, ok)
	}
}

func TestITermTabsShareTheAppButNotTheSession(t *testing.T) {
	f := New(t0)
	c1 := f.ITermTab(platform.ProcessRef{})
	c2 := f.ITermTab(c1.App, ClaudeProc(), Proc{Path: "/bin/bash"}, SSHProc("-T", "git@github.com"))
	if c2.App != c1.App {
		t.Fatal("tab on an existing app launched a new app")
	}
	if c2.Shell == c1.Shell || c2.Login == c1.Login {
		t.Fatal("two tabs share a login shell")
	}
	s1, _ := f.Process(c1.Shell)
	s2, _ := f.Process(c2.Shell)
	if s1.StartTime.Equal(s2.StartTime) {
		t.Fatal("two tabs' shells share a start time (session IDs would collide)")
	}
	if len(c2.Procs) != 3 || c2.Peer() != c2.Procs[2] {
		t.Fatalf("Procs %v Peer %v", c2.Procs, c2.Peer())
	}
	parent := c2.Shell
	for i, ref := range c2.Procs {
		p, _ := f.Process(ref)
		if p.Parent != parent {
			t.Fatalf("Procs[%d] parent %v, want %v (outermost first)", i, p.Parent, parent)
		}
		parent = ref
	}
	// spike S3: Claude Code's Bash tool resolves to iTerm2, not to claude.
	if a, ok := f.AppFor(walk(t, f, c2.Peer())); !ok || a.Ref != c1.App {
		t.Fatalf("AppFor through claude = %+v %v, want iTerm2", a, ok)
	}
	c3 := f.ITermTab(platform.ProcessRef{})
	if c3.App == c1.App {
		t.Fatal("zero app must launch a new iTerm2")
	}
}

func TestScenarioIdentities(t *testing.T) {
	if ITermCode.Team() != "H7V7XYVQ7D" || ITermCode.SigningID != "com.googlecode.iterm2" {
		t.Fatalf("ITermCode %+v", ITermCode)
	}
	if ClaudeCode.Team() != "Q6L2SF6YDW" || ClaudeCode.SigningID != "com.anthropic.claude-code" {
		t.Fatalf("ClaudeCode %+v", ClaudeCode)
	}
	if Unsigned.Signed || Unsigned.Team() != "" {
		t.Fatalf("Unsigned %+v", Unsigned)
	}
	a := AppleCode("com.apple.openssh")
	if a.Team() != "apple" || a.SigningID != "com.apple.openssh" {
		t.Fatalf("AppleCode %+v", a)
	}
	if bytes.Equal(AppleCode("com.apple.x").CDHash, AppleCode("com.apple.y").CDHash) {
		t.Fatal("different Apple binaries share a cdhash")
	}

	s := SSHProc("-T", "git@github.com")
	if s.Path != "/usr/bin/ssh" || !slices.Equal(s.Args, []string{"ssh", "-T", "git@github.com"}) || s.Code.Team() != "apple" || s.App != nil {
		t.Fatalf("SSHProc %+v", s)
	}
	if bare := SSHProc(); !slices.Equal(bare.Args, []string{"ssh"}) {
		t.Fatalf("SSHProc() args %q", bare.Args)
	}
	s.Args[0] = "mutated"
	if SSHProc("x").Args[0] != "ssh" {
		t.Fatal("SSHProc results share an Args slice")
	}
	cl := ClaudeProc()
	if cl.Code.Team() != "Q6L2SF6YDW" || cl.App != nil {
		t.Fatalf("ClaudeProc %+v (Claude Code's CLI is not a GUI app)", cl)
	}
}

// ---------------------------------------------------------------------------
// Callers: PeerOf, ResponsibleFor, CodeHash.

func TestPeerOfFailsClosedWithoutAScriptedPeer(t *testing.T) {
	f := New(t0)
	for _, fd := range []int{3, 0, -1} {
		ref, err := f.PeerOf(fd)
		if err == nil || !ref.IsZero() {
			t.Fatalf("PeerOf(%d) = %v, %v; want zero ref and an error", fd, ref, err)
		}
	}
}

func TestPeerFuncOverridesThePeerTable(t *testing.T) {
	f := New(t0)
	a := f.Launch(platform.ProcessRef{}, Proc{Path: "/a"})
	b := f.Launch(platform.ProcessRef{}, Proc{Path: "/b"})
	f.SetPeer(5, a)
	f.SetPeer(6, a)
	f.SetPeer(6, b) // re-scripting replaces
	if r, _ := f.PeerOf(6); r != b {
		t.Fatalf("re-scripted peer %v, want %v", r, b)
	}
	boom := errors.New("no peer token")
	f.PeerFunc = func(fd int) (platform.ProcessRef, error) {
		if fd == 5 {
			return b, nil
		}
		return platform.ProcessRef{}, boom
	}
	if r, err := f.PeerOf(5); err != nil || r != b {
		t.Fatalf("PeerFunc ignored: %v %v", r, err)
	}
	if _, err := f.PeerOf(6); !errors.Is(err, boom) {
		t.Fatalf("PeerFunc error not returned: %v", err)
	}
	f.PeerFunc = nil
	if r, _ := f.PeerOf(5); r != a {
		t.Fatalf("after clearing PeerFunc: %v, want %v", r, a)
	}
}

// Spike S3 and Milestone 7: responsibility as macOS assigns it. A process launchd
// starts answers for itself, a tab's processes answer to their app, and
// once the app has exited they answer for themselves (observed
// on an orphaned iTermServer); SetResponsible overrides, for one process.
func TestResponsibleFor(t *testing.T) {
	f := New(t0)
	c := f.ITermTab(platform.ProcessRef{})
	mux := f.Launch(platform.ProcessRef{}, SSHProc("-M", "-S", "/tmp/cm", "host"))
	other := f.Launch(platform.ProcessRef{}, Proc{Path: "/bin/other"})
	if r, ok := f.ResponsibleFor(mux); !ok || r != mux {
		t.Fatalf("a process launchd started: ResponsibleFor = %v %v, want itself", r, ok)
	}
	for _, p := range []platform.ProcessRef{c.Server, c.Login, c.Shell} {
		if r, ok := f.ResponsibleFor(p); !ok || r != c.App {
			t.Fatalf("%v: ResponsibleFor = %v %v, want the app %v", p, r, ok, c.App)
		}
	}
	f.SetResponsible(mux, c.App)
	if r, ok := f.ResponsibleFor(mux); !ok || r != c.App {
		t.Fatalf("ResponsibleFor = %v %v", r, ok)
	}
	if r, ok := f.ResponsibleFor(other); !ok || r != other {
		t.Fatalf("scripting one process leaked to another: %v %v", r, ok)
	}
	f.Exit(c.App)
	for _, p := range []platform.ProcessRef{c.Server, c.Login, c.Shell, mux} {
		if r, ok := f.ResponsibleFor(p); !ok || r != p {
			t.Fatalf("%v after the app exited: ResponsibleFor = %v %v, want itself", p, r, ok)
		}
	}
	if _, ok := f.ResponsibleFor(c.App); ok {
		t.Fatal("an exited process has a responsible process")
	}
	if _, ok := f.ResponsibleFor(platform.ProcessRef{PID: 424242, Generation: 1}); ok {
		t.Fatal("a process never launched has a responsible process")
	}
}

// Apps lists the live GUI apps and nothing else; an exited app is gone.
func TestApps(t *testing.T) {
	f := New(t0)
	if got := f.Apps(); len(got) != 0 {
		t.Fatalf("Apps() of an empty tree = %+v", got)
	}
	a := f.ITermTab(platform.ProcessRef{})
	b := f.Launch(platform.ProcessRef{}, Proc{Path: "/Applications/Foo.app/Contents/MacOS/Foo", App: &App{BundleID: "com.foo.app", Name: "Foo"}})
	f.Launch(platform.ProcessRef{}, Proc{Path: "/usr/local/bin/daemon"})
	got := f.Apps()
	if len(got) != 2 || got[0].Ref != a.App || got[0].BundleID != "com.googlecode.iterm2" || got[1].Ref != b || got[1].BundleID != "com.foo.app" {
		t.Fatalf("Apps() = %+v", got)
	}
	f.Exit(a.App)
	if got := f.Apps(); len(got) != 1 || got[0].Ref != b {
		t.Fatalf("Apps() after the app exited = %+v", got)
	}
}

func TestCodeHash(t *testing.T) {
	f := New(t0)
	if _, err := f.CodeHash("/usr/local/bin/tool"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("unscripted CodeHash: %v", err)
	}
	h := []byte{1, 2, 3}
	f.SetCodeHash("/usr/local/bin/tool", h)
	h[0] = 9
	got, err := f.CodeHash("/usr/local/bin/tool")
	if err != nil || !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("CodeHash = %x %v", got, err)
	}
	got[1] = 9
	if again, _ := f.CodeHash("/usr/local/bin/tool"); !bytes.Equal(again, []byte{1, 2, 3}) {
		t.Fatalf("CodeHash returned an aliased slice: %x", again)
	}
	boom := errors.New("not a Mach-O")
	f.CodeHashFunc = func(p string) ([]byte, error) {
		if p == "/opt/x" {
			return []byte{7}, nil
		}
		return nil, boom
	}
	if got, _ := f.CodeHash("/opt/x"); !bytes.Equal(got, []byte{7}) {
		t.Fatalf("CodeHashFunc not used: %x", got)
	}
	if got, _ := f.CodeHash("/usr/local/bin/tool"); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Fatalf("scripted hash must win over CodeHashFunc: %x", got)
	}
	if _, err := f.CodeHash("/nope"); !errors.Is(err, boom) {
		t.Fatalf("CodeHashFunc error not returned: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Gates.

func TestUnscriptedGatesDeny(t *testing.T) {
	f := New(t0)
	ref, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	if !errors.Is(err, platform.ErrDenied) || ref != 0 {
		t.Fatalf("unscripted Authenticate = %v, %v; want 0, ErrDenied", ref, err)
	}
	if ok, _ := f.Confirm(platform.Prompt{}); ok {
		t.Fatal("unscripted Confirm allowed")
	}
	if f.LiveApprovals() != 0 {
		t.Fatal("a denial issued an approval")
	}
}

// Err is a prompt failure (timeout, dismissed): it wins over Allow and never
// yields an approval.
func TestAnswerErrFailsClosed(t *testing.T) {
	f := New(t0)
	boom := errors.New("prompt timed out")
	f.ScriptAuth(Answer{Allow: true, Err: boom})
	f.ScriptConfirm(Answer{Allow: true, Err: boom})
	ref, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	if !errors.Is(err, boom) || ref != 0 {
		t.Fatalf("Authenticate = %v, %v; want 0, %v", ref, err, boom)
	}
	ok, err := f.Confirm(platform.Prompt{})
	if !errors.Is(err, boom) || ok {
		t.Fatalf("Confirm = %v, %v; want false, %v", ok, err, boom)
	}
	if f.LiveApprovals() != 0 {
		t.Fatal("an errored prompt issued an approval")
	}
	if f.CountShown(KindAuthenticate) != 1 || f.CountShown(KindConfirm) != 1 {
		t.Fatalf("errored prompts must still be recorded as shown: %+v", f.Shown())
	}
}

func TestScriptQueuesAreFIFOPerGateThenDefaults(t *testing.T) {
	f := New(t0)
	f.SetDefaults(Answer{Allow: true}, Answer{Allow: true})
	f.ScriptConfirm(Answer{Allow: false}, Answer{Allow: false})
	var got []bool
	for range 4 {
		ok, _ := f.Confirm(platform.Prompt{})
		got = append(got, ok)
	}
	if !slices.Equal(got, []bool{false, false, true, true}) {
		t.Fatalf("confirm answers %v", got)
	}
	f.ScriptAuth(Answer{Allow: false})
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("queued denial: %v", err)
	}
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); err != nil {
		t.Fatalf("default allow after the queue drained: %v", err)
	}

	f.SetDefaults(Answer{}, Answer{})
	f.ScriptAuth(Answer{Allow: true})
	if ok, _ := f.Confirm(platform.Prompt{}); ok {
		t.Fatal("Confirm consumed an answer scripted for Authenticate")
	}
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); err != nil {
		t.Fatalf("scripted auth answer lost: %v", err)
	}
}

func TestGateFuncsOverrideQueuesAndSeeThePrompt(t *testing.T) {
	f := New(t0)
	f.ScriptAuth(Answer{Allow: false})
	f.ScriptConfirm(Answer{Allow: false})
	var gotAuth platform.Prompt
	f.SetGateFuncs(
		func(p platform.Prompt) Answer { gotAuth = p; return Answer{Allow: true} },
		func(p platform.Prompt) Answer { return Answer{Allow: p.Title == "ok"} },
	)
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{Title: "login", Lines: []string{"a"}}); err != nil {
		t.Fatalf("AuthFunc ignored: %v", err)
	}
	if gotAuth.Title != "login" || !slices.Equal(gotAuth.Lines, []string{"a"}) {
		t.Fatalf("AuthFunc saw %+v", gotAuth)
	}
	if ok, _ := f.Confirm(platform.Prompt{Title: "ok"}); !ok {
		t.Fatal("ConfirmFunc ignored")
	}
	if ok, _ := f.Confirm(platform.Prompt{Title: "no"}); ok {
		t.Fatal("ConfirmFunc answer not used")
	}
	f.SetGateFuncs(nil, nil)
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("queue not used after clearing funcs: %v", err)
	}
	if ok, _ := f.Confirm(platform.Prompt{}); ok {
		t.Fatal("confirm queue not used after clearing funcs")
	}
}

func TestShownRecordsEveryPromptInOrder(t *testing.T) {
	f := New(t0)
	lines := []string{"chain: bash > ssh", "key: github"}
	f.Authenticate(platform.AuthUserPresence, platform.Prompt{
		Title: "t1", Lines: lines, Unknown: true, Reason: "use key github", Timeout: time.Minute,
	})
	f.Confirm(platform.Prompt{Title: "t2"})
	f.Authenticate(platform.AuthNone, platform.Prompt{Title: "t3"})
	lines[0] = "mutated"
	s := f.Shown()
	if len(s) != 3 {
		t.Fatalf("Shown = %+v", s)
	}
	p := s[0]
	if p.Kind != KindAuthenticate || p.Policy != platform.AuthUserPresence || p.Prompt.Title != "t1" ||
		!p.Prompt.Unknown || p.Prompt.Reason != "use key github" || p.Prompt.Timeout != time.Minute {
		t.Fatalf("Shown[0] = %+v", p)
	}
	if !slices.Equal(p.Prompt.Lines, []string{"chain: bash > ssh", "key: github"}) {
		t.Fatalf("recorded Lines alias the caller's slice: %q", p.Prompt.Lines)
	}
	if s[1].Kind != KindConfirm || s[1].Prompt.Title != "t2" {
		t.Fatalf("Shown[1] = %+v", s[1])
	}
	if s[2].Kind != KindAuthenticate || s[2].Policy != platform.AuthNone || s[2].Prompt.Title != "t3" {
		t.Fatalf("Shown[2] = %+v", s[2])
	}
	s[0].Prompt.Title = "x"
	if f.Shown()[0].Prompt.Title != "t1" {
		t.Fatal("Shown returned the internal slice")
	}
	if f.CountShown(KindAuthenticate) != 2 || f.CountShown(KindConfirm) != 1 {
		t.Fatal("CountShown")
	}
}

// While one prompt waits for the user, the prompt is already visible to
// tests, no approval exists yet, and every other call keeps working
// ("blocking methods block only the calling goroutine", spec 4.7).
func TestBlockedPromptIsVisibleAndDoesNotStallTheFake(t *testing.T) {
	f := New(t0)
	release := make(chan struct{})
	f.ScriptAuth(Answer{Allow: true, Wait: release})
	type result struct {
		ref platform.ApprovalRef
		err error
	}
	got := make(chan result, 1)
	go func() {
		r, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{Title: "slow"})
		got <- result{r, err}
	}()
	waitFor(t, "the blocked prompt to be recorded", func() bool { return f.CountShown(KindAuthenticate) == 1 })
	within(t, "other fake calls while a prompt is blocked", func() {
		f.ScriptConfirm(Answer{Allow: true})
		if ok, _ := f.Confirm(platform.Prompt{}); !ok {
			t.Error("Confirm while Authenticate blocked")
		}
		if _, err := f.Process(f.Launchd); err != nil {
			t.Error(err)
		}
		f.Launch(platform.ProcessRef{}, Proc{Path: "/x"})
		h, _, err := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := f.Sign(h, []byte("y"), 0); err != nil {
			t.Error(err)
		}
	})
	select {
	case r := <-got:
		t.Fatalf("answered before release: %+v", r)
	default:
	}
	if f.LiveApprovals() != 0 {
		t.Fatal("approval issued before the user answered")
	}
	close(release)
	r := <-got
	if r.err != nil || r.ref == 0 {
		t.Fatalf("after release: %+v", r)
	}
	if f.LiveApprovals() != 1 {
		t.Fatal("LiveApprovals after release")
	}
}

func TestAnswerDelay(t *testing.T) {
	f := New(t0)
	f.ScriptConfirm(Answer{Allow: true, Delay: 40 * time.Millisecond})
	start := time.Now()
	ok, _ := f.Confirm(platform.Prompt{})
	if el := time.Since(start); el < 40*time.Millisecond {
		t.Fatalf("answered after %v, want >= 40ms", el)
	}
	if !ok {
		t.Fatal("delayed answer lost")
	}
}

func TestApprovalRefsAreDistinctAndReleasedInOrder(t *testing.T) {
	f := New(t0)
	f.SetDefaults(Answer{Allow: true}, Answer{Allow: true})
	if ok, _ := f.Confirm(platform.Prompt{}); !ok || f.LiveApprovals() != 0 {
		t.Fatal("a confirm dialog must not create an approval ref")
	}
	var refs []platform.ApprovalRef
	for range 5 {
		r, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
		if err != nil || r == 0 {
			t.Fatalf("Authenticate = %v %v", r, err)
		}
		if slices.Contains(refs, r) {
			t.Fatalf("ref %v issued twice", r)
		}
		refs = append(refs, r)
	}
	if f.LiveApprovals() != 5 {
		t.Fatalf("LiveApprovals = %d", f.LiveApprovals())
	}
	f.ReleaseApproval(refs[3])
	f.ReleaseApproval(refs[1])
	f.ReleaseApproval(refs[4])
	f.ReleaseApproval(0)
	f.ReleaseApproval(platform.ApprovalRef(^uint64(0))) // never issued
	if got := f.Released(); !slices.Equal(got, []platform.ApprovalRef{refs[3], refs[1], refs[4]}) {
		t.Fatalf("Released = %v", got)
	}
	if f.LiveApprovals() != 2 {
		t.Fatalf("LiveApprovals = %d, want 2", f.LiveApprovals())
	}
}

func TestConcurrentAuthenticateIssuesUniqueRefs(t *testing.T) {
	f := New(t0)
	f.SetDefaults(Answer{Allow: true}, Answer{Allow: true})
	const n = 64
	refs := make(chan platform.ApprovalRef, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			r, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
			if err != nil {
				t.Error(err)
			}
			refs <- r
			f.Confirm(platform.Prompt{})
		})
	}
	wg.Wait()
	close(refs)
	seen := map[platform.ApprovalRef]bool{}
	for r := range refs {
		if r == 0 || seen[r] {
			t.Fatalf("ref %v zero or duplicated", r)
		}
		seen[r] = true
	}
	if f.LiveApprovals() != n || f.CountShown(KindAuthenticate) != n || f.CountShown(KindConfirm) != n {
		t.Fatalf("live %d shown auth %d confirm %d", f.LiveApprovals(), f.CountShown(KindAuthenticate), f.CountShown(KindConfirm))
	}
}

// ---------------------------------------------------------------------------
// Enclave.

func TestCreateKeyReturnsDistinctP256Keys(t *testing.T) {
	f := New(t0)
	handles := map[string]bool{}
	pubs := map[string]bool{}
	for _, purpose := range []platform.Purpose{platform.PurposeSign, platform.PurposeKeyAgreement} {
		for _, auth := range []platform.AuthPolicy{platform.AuthNone, platform.AuthUserPresence} {
			h, pub, err := f.CreateKey(purpose, auth, platform.AccessWhenUnlocked)
			if err != nil {
				t.Fatalf("CreateKey(%v, %v): %v", purpose, auth, err)
			}
			if len(h) == 0 {
				t.Fatal("empty handle")
			}
			if len(pub) != 65 || pub[0] != 0x04 {
				t.Fatalf("public key is not an X9.63 uncompressed point: %x", pub)
			}
			if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub); err != nil {
				t.Fatalf("public key not on P-256: %v", err)
			}
			if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
				t.Fatalf("public key rejected by ecdh: %v", err)
			}
			if handles[hex.EncodeToString(h)] || pubs[hex.EncodeToString(pub)] {
				t.Fatal("CreateKey returned a duplicate handle or public key")
			}
			handles[hex.EncodeToString(h)] = true
			pubs[hex.EncodeToString(pub)] = true
		}
	}
}

// An out-of-range AuthPolicy must not quietly become "no presence needed"
// (fail open); an out-of-range Purpose is equally a caller bug.
func TestCreateKeyRefusesUnknownPurposeOrPolicy(t *testing.T) {
	f := New(t0)
	cases := []struct {
		purpose platform.Purpose
		auth    platform.AuthPolicy
	}{
		{platform.Purpose(0), platform.AuthNone},
		{platform.Purpose(3), platform.AuthNone},
		{platform.Purpose(-1), platform.AuthUserPresence},
		{platform.PurposeSign, platform.AuthPolicy(2)},
		{platform.PurposeSign, platform.AuthPolicy(-1)},
		{platform.PurposeKeyAgreement, platform.AuthPolicy(99)},
	}
	for _, c := range cases {
		h, pub, err := f.CreateKey(c.purpose, c.auth, platform.AccessWhenUnlocked)
		if err == nil || len(h) != 0 || len(pub) != 0 {
			t.Errorf("CreateKey(%v, %v) = %x, %x, %v; want an error", c.purpose, c.auth, h, pub, err)
		}
	}
}

// An out-of-range Access must not quietly become "works while locked".
func TestCreateKeyRefusesUnknownAccess(t *testing.T) {
	f := New(t0)
	for _, a := range []platform.Access{2, -1, 99} {
		h, pub, err := f.CreateKey(platform.PurposeSign, platform.AuthNone, a)
		if err == nil || len(h) != 0 || len(pub) != 0 {
			t.Errorf("CreateKey(sign, none, %v) = %x, %x, %v; want an error", a, h, pub, err)
		}
	}
}

// A key that asks for the user on every use can't work while the Mac is
// locked, so it is never made to: user presence with after-first-unlock
// is refused.
func TestCreateKeyRefusesPresenceWhileLocked(t *testing.T) {
	f := New(t0)
	for _, p := range []platform.Purpose{platform.PurposeSign, platform.PurposeKeyAgreement} {
		if h, pub, err := f.CreateKey(p, platform.AuthUserPresence, platform.AccessAfterFirstUnlock); err == nil || len(h) != 0 || len(pub) != 0 {
			t.Errorf("CreateKey(%v, user-presence, after-first-unlock) = %x, %x, %v; want an error", p, h, pub, err)
		}
	}
}

// Like the Secure Enclave: while the Mac is locked no when-unlocked key
// can be made (ErrLocked); an after-first-unlock one can.
func TestCreateWhenUnlockedKeyFailsWhileLocked(t *testing.T) {
	f := New(t0)
	f.SetLocked(true)
	for _, auth := range []platform.AuthPolicy{platform.AuthNone, platform.AuthUserPresence} {
		if h, pub, err := f.CreateKey(platform.PurposeSign, auth, platform.AccessWhenUnlocked); !errors.Is(err, platform.ErrLocked) || len(h) != 0 || len(pub) != 0 {
			t.Errorf("CreateKey(sign, %v, when-unlocked) while locked = %x, %x, %v; want ErrLocked", auth, h, pub, err)
		}
	}
	if _, _, err := f.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessAfterFirstUnlock); err != nil {
		t.Fatalf("after-first-unlock key while locked: %v", err)
	}
}

// Like the Secure Enclave: while the Mac is locked a when-unlocked key
// fails with ErrLocked, for signing and key agreement, and an
// after-first-unlock key keeps working; unlocking makes the first work again.
func TestWhenUnlockedKeyFailsWhileLocked(t *testing.T) {
	f := New(t0)
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	keys := map[platform.Access][2][]byte{}
	for _, a := range []platform.Access{platform.AccessWhenUnlocked, platform.AccessAfterFirstUnlock} {
		sh, _, err := f.CreateKey(platform.PurposeSign, platform.AuthNone, a)
		if err != nil {
			t.Fatal(err)
		}
		kh, _, err := f.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, a)
		if err != nil {
			t.Fatal(err)
		}
		keys[a] = [2][]byte{sh, kh}
	}
	use := func(a platform.Access) (error, error) {
		_, serr := f.Sign(keys[a][0], []byte("x"), 0)
		_, kerr := f.KeyAgreement(keys[a][1], peer.PublicKey().Bytes(), 0)
		return serr, kerr
	}
	f.SetLocked(true)
	if serr, kerr := use(platform.AccessWhenUnlocked); !errors.Is(serr, platform.ErrLocked) || !errors.Is(kerr, platform.ErrLocked) {
		t.Fatalf("when-unlocked key while locked: sign %v, agree %v; want ErrLocked", serr, kerr)
	}
	if serr, kerr := use(platform.AccessAfterFirstUnlock); serr != nil || kerr != nil {
		t.Fatalf("after-first-unlock key while locked: sign %v, agree %v; want both to work", serr, kerr)
	}
	f.SetLocked(false)
	if serr, kerr := use(platform.AccessWhenUnlocked); serr != nil || kerr != nil {
		t.Fatalf("when-unlocked key after unlocking: sign %v, agree %v; want both to work", serr, kerr)
	}
}

// Like the Secure Enclave, a presence key signs only with an approval ref the
// fake itself issued and has not released: not zero, not a guessed number,
// not a ref from another platform instance, not a dialog confirmation.
func TestPresenceKeyRefusesForgedAndForeignRefs(t *testing.T) {
	f := New(t0)
	h, pub, _ := f.CreateKey(platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	f.SetDefaults(Answer{}, Answer{Allow: true})
	if ok, _ := f.Confirm(platform.Prompt{}); !ok {
		t.Fatal("confirm")
	}
	other := New(t0)
	other.ScriptAuth(Answer{Allow: true})
	foreign, _ := other.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	f.ScriptAuth(Answer{Allow: false})
	denied, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	for _, ref := range []platform.ApprovalRef{0, 1, 1000, 1001, foreign, denied, platform.ApprovalRef(^uint64(0))} {
		if _, err := f.Sign(h, []byte("x"), ref); !errors.Is(err, platform.ErrAuthRequired) {
			t.Fatalf("Sign with unissued ref %v: %v, want ErrAuthRequired", ref, err)
		}
	}
	if f.SignCalls() != 0 {
		t.Fatalf("SignCalls = %d after refused signs", f.SignCalls())
	}
	// One authentication is reused for later signs until released (spike S1).
	f.ScriptAuth(Answer{Allow: true})
	ref, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	for _, msg := range []string{"one", "two"} {
		der, err := f.Sign(h, []byte(msg), ref)
		if err != nil {
			t.Fatalf("Sign with live ref: %v", err)
		}
		sum := sha256.Sum256([]byte(msg))
		if !ecdsa.VerifyASN1(pk, sum[:], der) {
			t.Fatal("signature does not verify")
		}
	}
	if f.SignCalls() != 2 {
		t.Fatalf("SignCalls = %d, want 2", f.SignCalls())
	}
}

func TestSignaturesBindDataAndKey(t *testing.T) {
	f := New(t0)
	h1, pub1, _ := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	_, pub2, _ := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	pk1, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub1)
	pk2, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub2)
	der, err := f.Sign(h1, []byte("payload"), 0)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("payload"))
	other := sha256.Sum256([]byte("payload2"))
	if !ecdsa.VerifyASN1(pk1, sum[:], der) {
		t.Fatal("signature does not verify over SHA-256(input)")
	}
	if ecdsa.VerifyASN1(pk1, other[:], der) {
		t.Fatal("signature verifies over different data")
	}
	if ecdsa.VerifyASN1(pk2, sum[:], der) {
		t.Fatal("signature verifies under another key")
	}
	empty, err := f.Sign(h1, nil, 0)
	if err != nil {
		t.Fatalf("Sign(empty): %v", err)
	}
	esum := sha256.Sum256(nil)
	if !ecdsa.VerifyASN1(pk1, esum[:], empty) {
		t.Fatal("signature over empty input does not verify")
	}
}

// Handles are opaque: anything other than an exact handle this enclave issued
// is not found. A handle from another Fake is another Mac's Secure Enclave.
func TestUnknownHandlesAreNotFound(t *testing.T) {
	f := New(t0)
	h, _, _ := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	kept := bytes.Clone(h)
	other := New(t0)
	oh, _, _ := other.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	random := make([]byte, len(h))
	rand.Read(random)
	flipped := bytes.Clone(h)
	flipped[0] ^= 1
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	bad := map[string][]byte{
		"nil": nil, "empty": {}, "truncated": h[:len(h)-1], "extended": append(bytes.Clone(h), 0),
		"random": random, "bit-flipped": flipped, "other enclave": oh,
	}
	for name, b := range bad {
		if _, err := f.Sign(b, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("Sign(%s handle): %v, want ErrNotFound", name, err)
		}
		if _, err := f.KeyAgreement(b, peer.PublicKey().Bytes(), 0); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("KeyAgreement(%s handle): %v, want ErrNotFound", name, err)
		}
		if err := f.DeleteKey(b); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("DeleteKey(%s handle): %v, want ErrNotFound", name, err)
		}
	}
	h[0] ^= 0xff // mutating the caller's copy of the handle must not matter
	if _, err := f.Sign(kept, []byte("x"), 0); err != nil {
		t.Fatalf("original handle stopped working: %v", err)
	}
	if f.SignCalls() != 1 {
		t.Fatalf("SignCalls = %d, want 1", f.SignCalls())
	}
}

func TestDeleteKeyRemovesOnlyThatKey(t *testing.T) {
	f := New(t0)
	h1, _, _ := f.CreateKey(platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	h2, _, _ := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	f.ScriptAuth(Answer{Allow: true})
	ref, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	if err := f.DeleteKey(h1); err != nil {
		t.Fatal(err)
	}
	if err := f.DeleteKey(h1); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("second DeleteKey: %v", err)
	}
	if _, err := f.Sign(h1, []byte("x"), ref); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("deleted key with a live ref: %v", err)
	}
	if _, err := f.Sign(h2, []byte("x"), 0); err != nil {
		t.Fatalf("other key: %v", err)
	}
}

// A CryptoKit signing key cannot do key agreement and vice versa; the fake
// must not let a test pass that the real enclave would fail.
func TestKeysAreUsableOnlyForTheirPurpose(t *testing.T) {
	f := New(t0)
	sh, _, _ := f.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	kh, _, _ := f.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessWhenUnlocked)
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := f.Sign(kh, []byte("x"), 0); err == nil {
		t.Fatal("a key-agreement key signed")
	}
	if _, err := f.KeyAgreement(sh, peer.PublicKey().Bytes(), 0); err == nil {
		t.Fatal("a signing key did key agreement")
	}
	if f.SignCalls() != 0 {
		t.Fatalf("SignCalls = %d", f.SignCalls())
	}
}

func TestKeyAgreementDerivesTheSharedSecret(t *testing.T) {
	f := New(t0)
	h, pub, err := f.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	secret, err := f.KeyAgreement(h, peer.PublicKey().Bytes(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := peer.ECDH(ours)
	if len(secret) != 32 || !bytes.Equal(secret, want) {
		t.Fatalf("shared secret %x, want %x", secret, want)
	}
}

func TestKeyAgreementEnforcesPresence(t *testing.T) {
	f := New(t0)
	h, _, _ := f.CreateKey(platform.PurposeKeyAgreement, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	pp := peer.PublicKey().Bytes()
	if _, err := f.KeyAgreement(h, pp, 0); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("without a ref: %v", err)
	}
	f.ScriptAuth(Answer{Allow: true})
	ref, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	if _, err := f.KeyAgreement(h, pp, ref); err != nil {
		t.Fatalf("with a live ref: %v", err)
	}
	f.ReleaseApproval(ref)
	if _, err := f.KeyAgreement(h, pp, ref); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("with a released ref: %v", err)
	}
}

// Peer keys come from outside (Phase 2 secrets); garbage must be an error,
// never a panic or a secret.
func TestKeyAgreementRejectsMalformedPeerKeys(t *testing.T) {
	f := New(t0)
	h, _, _ := f.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, platform.AccessWhenUnlocked)
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	valid := peer.PublicKey().Bytes()
	offCurve := bytes.Clone(valid)
	offCurve[64] ^= 1
	compressed := append([]byte{0x02 | (valid[64] & 1)}, valid[1:33]...)
	p384, _ := ecdh.P384().GenerateKey(rand.Reader)
	cases := map[string][]byte{
		"nil": nil, "empty": {}, "short": valid[:64], "long": append(bytes.Clone(valid), 0),
		"compressed": compressed, "infinity": {0x00}, "zero point": append([]byte{0x04}, make([]byte, 64)...),
		"off curve": offCurve, "P-384": p384.PublicKey().Bytes(),
	}
	for name, key := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s peer key panicked: %v", name, r)
				}
			}()
			if s, err := f.KeyAgreement(h, key, 0); err == nil {
				t.Errorf("%s peer key accepted, secret %x", name, s)
			}
		}()
	}
}

func TestConcurrentSigning(t *testing.T) {
	f := New(t0)
	h, pub, _ := f.CreateKey(platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	f.ScriptAuth(Answer{Allow: true})
	ref, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	pk, _ := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	const n = 32
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			msg := []byte{byte(i)}
			der, err := f.Sign(h, msg, ref)
			if err != nil {
				t.Error(err)
				return
			}
			sum := sha256.Sum256(msg)
			if !ecdsa.VerifyASN1(pk, sum[:], der) {
				t.Errorf("signature %d does not verify", i)
			}
		})
	}
	wg.Wait()
	if f.SignCalls() != n {
		t.Fatalf("SignCalls = %d, want %d", f.SignCalls(), n)
	}
}

// ---------------------------------------------------------------------------
// Warnings and screen lock.

func TestWarningsAreRecordedInOrder(t *testing.T) {
	f := New(t0)
	if len(f.Warnings()) != 0 {
		t.Fatal("new fake has warnings")
	}
	lines := []string{"unknown caller", "chain: ssh"}
	f.ShowWarning(platform.Warning{ID: "w1", Title: "Blocked", Lines: lines, Count: 1, SuggestedRule: "apps: [unknown]"})
	lines[0] = "mutated"
	f.ShowWarning(platform.Warning{ID: "w1", Title: "Blocked", Count: 2})
	f.ShowWarning(platform.Warning{ID: "w2", Title: "Blocked", Count: 1})
	w := f.Warnings()
	if len(w) != 3 {
		t.Fatalf("Warnings = %+v", w)
	}
	if w[0].ID != "w1" || w[1].ID != "w1" || w[2].ID != "w2" || w[0].Count != 1 || w[1].Count != 2 || w[2].Count != 1 {
		t.Fatalf("Warnings = %+v", w)
	}
	if w[0].Lines[0] != "unknown caller" || w[0].SuggestedRule != "apps: [unknown]" || w[0].Title != "Blocked" {
		t.Fatalf("Warnings[0] = %+v (Lines must not alias the caller's slice)", w[0])
	}
}

func TestLockScreenFiresEveryCallbackEachTime(t *testing.T) {
	f := New(t0)
	f.LockScreen() // no callbacks: no-op
	var a, b atomic.Int32
	f.OnScreenLock(func() { a.Add(1) })
	f.OnScreenLock(func() { b.Add(1) })
	f.LockScreen()
	f.LockScreen()
	if a.Load() != 2 || b.Load() != 2 {
		t.Fatalf("callbacks fired a=%d b=%d, want 2 each", a.Load(), b.Load())
	}
}

// ---------------------------------------------------------------------------
// Vault.

func TestVaultRoundTripCopiesAndDelete(t *testing.T) {
	v := NewVault()
	val := []byte("handle-bytes")
	if err := v.Put("ssh-key/github", val); err != nil {
		t.Fatal(err)
	}
	val[0] = 'X'
	got, err := v.Get("ssh-key/github")
	if err != nil || string(got) != "handle-bytes" {
		t.Fatalf("Get = %q %v (Put must copy)", got, err)
	}
	got[0] = 'Y'
	if again, _ := v.Get("ssh-key/github"); string(again) != "handle-bytes" {
		t.Fatalf("Get returned an aliased slice: %q", again)
	}
	v.Put("ssh-key/github", []byte("v2"))
	if got, _ := v.Get("ssh-key/github"); string(got) != "v2" {
		t.Fatalf("overwrite: %q", got)
	}
	if err := v.Put("empty", []byte{}); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get("empty"); err != nil || len(got) != 0 {
		t.Fatalf("empty value: %q %v", got, err)
	}
	if err := v.Delete("ssh-key/github"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("ssh-key/github"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("Get after Delete: %v", err)
	}
	if err := v.Delete("ssh-key/github"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("second Delete: %v", err)
	}
	if err := v.Delete("never"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("Delete missing: %v", err)
	}
}

func TestVaultListIsSortedAndPrefixExact(t *testing.T) {
	v := NewVault()
	for _, n := range []string{"ssh-key/b", "state/trust", "ssh-key/a", "ssh-keyring", "config/approved", "ssh-key/c"} {
		v.Put(n, []byte("x"))
	}
	if got, _ := v.List("ssh-key/"); !slices.Equal(got, []string{"ssh-key/a", "ssh-key/b", "ssh-key/c"}) {
		t.Fatalf("List(ssh-key/) = %v", got)
	}
	want := []string{"config/approved", "ssh-key/a", "ssh-key/b", "ssh-key/c", "ssh-keyring", "state/trust"}
	if got, _ := v.List(""); !slices.Equal(got, want) {
		t.Fatalf("List(\"\") = %v", got)
	}
	if got, err := v.List("nothing/"); err != nil || len(got) != 0 {
		t.Fatalf("List(nothing/) = %v %v", got, err)
	}
	if got, _ := v.List("ssh-key/a"); !slices.Equal(got, []string{"ssh-key/a"}) {
		t.Fatalf("List(ssh-key/a) = %v", got)
	}
}

// A locked Keychain: Put fails, and nothing (new or overwritten) is stored.
func TestVaultFailPut(t *testing.T) {
	v := NewVault()
	v.Put("config/approved", []byte("old"))
	boom := errors.New("keychain locked")
	v.FailPut = boom
	if err := v.Put("config/approved", []byte("new")); !errors.Is(err, boom) {
		t.Fatalf("Put = %v, want %v", err, boom)
	}
	if err := v.Put("new-item", []byte("x")); !errors.Is(err, boom) {
		t.Fatalf("Put = %v, want %v", err, boom)
	}
	if got, _ := v.Get("config/approved"); string(got) != "old" {
		t.Fatalf("failed Put overwrote the item: %q", got)
	}
	if _, err := v.Get("new-item"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("failed Put stored a new item: %v", err)
	}
	v.FailPut = nil
	if err := v.Put("new-item", []byte("x")); err != nil {
		t.Fatalf("Put after clearing FailPut: %v", err)
	}
}

func TestVaultsAreIndependent(t *testing.T) {
	a, b := NewVault(), NewVault()
	a.Put("k", []byte("v"))
	if _, err := b.Get("k"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("item leaked across vaults: %v", err)
	}
}

func TestVaultConcurrentUse(t *testing.T) {
	v := NewVault()
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			name := "ssh-key/" + string(rune('a'+i%26)) + hex.EncodeToString([]byte{byte(i)})
			if err := v.Put(name, []byte{byte(i)}); err != nil {
				t.Error(err)
			}
			if _, err := v.Get(name); err != nil {
				t.Error(err)
			}
			if _, err := v.List("ssh-key/"); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if names, _ := v.List("ssh-key/"); len(names) != 32 {
		t.Fatalf("List = %d names, want 32", len(names))
	}
}

// A PID-only ref (generation 0) is what KERN_PROC_PID's ppid and the
// responsible-process lookup give on macOS: Process answers the
// live occupant of the PID with its full ref, the newest record when a test
// scripted a recycled PID, and ErrNoProcess once the PID is free. A full ref
// still matches only its exact instance.
func TestPIDOnlyRefResolvesToTheLiveOccupant(t *testing.T) {
	f := New(t0)
	ssh := f.Launch(platform.ProcessRef{}, SSHProc("h"))
	pidOnly := platform.ProcessRef{PID: ssh.PID}
	if !pidOnly.IsPIDOnly() || pidOnly.IsZero() {
		t.Fatalf("%v: IsPIDOnly=%v IsZero=%v", pidOnly, pidOnly.IsPIDOnly(), pidOnly.IsZero())
	}
	got, err := f.Process(pidOnly)
	if err != nil || got.Ref != ssh || got.Path != "/usr/bin/ssh" {
		t.Fatalf("Process(PID-only) = %v %q, %v; want %v", got.Ref, got.Path, err, ssh)
	}
	if _, err := f.Process(platform.ProcessRef{PID: ssh.PID, Generation: ssh.Generation + 1}); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("full ref with another generation resolved: %v", err)
	}

	newer := platform.ProcessRef{PID: ssh.PID, Generation: ssh.Generation + 9}
	f.SetProcess(platform.ProcessInfo{Ref: newer, Parent: f.Launchd, UID: 501, StartTime: f.Now().Add(time.Minute), Path: "/tmp/newer"})
	if got, err := f.Process(pidOnly); err != nil || got.Ref != newer {
		t.Fatalf("Process(PID-only) with a recycled PID = %v, %v; want the newest %v", got.Ref, err, newer)
	}
	f.Exit(newer)
	if got, err := f.Process(pidOnly); err != nil || got.Ref != ssh {
		t.Fatalf("Process(PID-only) after the newer exited = %v, %v; want %v", got.Ref, err, ssh)
	}
	f.Exit(ssh)
	if _, err := f.Process(pidOnly); !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("Process(PID-only) of a free PID: %v, want ErrNoProcess", err)
	}
	for _, ref := range []platform.ProcessRef{{}, {PID: -1}, {PID: 1 << 30}} {
		if _, err := f.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Fatalf("Process(%v): %v, want ErrNoProcess", ref, err)
		}
	}
}
