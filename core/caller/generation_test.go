package caller

// ProcessRef.Generation as the macOS platform can provide it
// (spike S3). The peer's audit token (LOCAL_PEERTOKEN) identifies the peer
// exactly, but the parent walk uses sysctl KERN_PROC_PID, whose record
// names the parent by PID only (ppid), and the responsible-process lookup
// (responsibility_get_pid_responsible_for_pid) also returns a bare PID. So
// ProcessInfo.Parent and ResponsibleFor may return PID-only refs
// (Generation 0), and Process({PID, 0}) answers whatever process now holds
// the PID. The Resolver must work with that, and must keep refusing a
// recycled PID: a PID-only ref is accepted only for a process that started
// no later than the process that pointed at it, and never for the peer.

import (
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// darwinLike wraps the fake with the lookups macOS can actually make.
//   - Process(ref) looks ref.PID up (KERN_PROC_PID). A ref with a non-zero
//     generation must match the live occupant exactly, else ErrNoProcess;
//     a PID-only ref answers the live occupant.
//   - Every record's Parent is PID-only (kinfo_proc gives ppid, nothing more).
//   - ResponsibleFor returns a PID-only ref.
//
// The broken-platform knobs (redirect, noGen) model a buggy implementation
// the Resolver must not trust.
type darwinLike struct {
	*fake.Fake
	mu       sync.Mutex
	live     map[int]platform.ProcessRef // PID → current occupant
	resp     map[platform.ProcessRef]int // responsible PID by full ref
	redirect map[int]int                 // broken: a lookup of PID k answers PID v's record
	noGen    map[int]bool                // broken: the record for this PID comes back without a generation
}

func newDarwinLike(f *fake.Fake, refs ...platform.ProcessRef) *darwinLike {
	d := &darwinLike{
		Fake: f, live: map[int]platform.ProcessRef{f.Launchd.PID: f.Launchd},
		resp: map[platform.ProcessRef]int{}, redirect: map[int]int{}, noGen: map[int]bool{},
	}
	for _, r := range refs {
		d.live[r.PID] = r
	}
	return d
}

// occupy makes ref the live occupant of its PID (the previous holder's PID
// was recycled).
func (d *darwinLike) occupy(ref platform.ProcessRef) {
	d.mu.Lock()
	d.live[ref.PID] = ref
	d.mu.Unlock()
}

func (d *darwinLike) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	d.mu.Lock()
	pid := ref.PID
	if to, ok := d.redirect[pid]; ok {
		pid = to
	}
	occ, ok := d.live[pid]
	strip := d.noGen[pid]
	d.mu.Unlock()
	if !ok || (ref.Generation != 0 && occ != ref && pid == ref.PID) {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	info, err := d.Fake.Process(occ)
	if err != nil {
		return info, err
	}
	if !info.Parent.IsZero() {
		info.Parent = platform.ProcessRef{PID: info.Parent.PID}
	}
	if strip {
		info.Ref = platform.ProcessRef{PID: info.Ref.PID}
	}
	return info, nil
}

func (d *darwinLike) ResponsibleFor(ref platform.ProcessRef) (platform.ProcessRef, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	pid, ok := d.resp[ref]
	return platform.ProcessRef{PID: pid}, ok
}

func (d *darwinLike) setResponsible(ref platform.ProcessRef, pid int) {
	d.mu.Lock()
	d.resp[ref] = pid
	d.mu.Unlock()
}

func noDuplicates(t *testing.T, c *Chain) {
	t.Helper()
	seen := map[int]bool{}
	for _, p := range c.Procs {
		if seen[p.Ref.PID] {
			t.Fatalf("process %v appears twice in the chain", p.Ref)
		}
		seen[p.Ref.PID] = true
	}
}

// The iTerm chain from spike S3 resolves the same on a platform whose parent
// refs are PID-only as on the fake with exact refs: same processes (full
// refs), same app, same session. Without this every real chain would be cut
// off after the peer and come out unknown.
func TestPIDOnlyParentRefsResolveTheFullChain(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.Proc{Path: "/usr/bin/git", Code: fake.AppleCode("com.apple.git")}, fake.SSHProc("git@github.com"))
	want := (&Resolver{P: f}).Resolve(tab.Peer())
	if want.Unknown || want.Truncated {
		t.Fatalf("control: exact-ref fake chain unknown=%v truncated=%v", want.Unknown, want.Truncated)
	}

	d := newDarwinLike(f, tabRefs(tab)...)
	c := (&Resolver{P: d}).Resolve(tab.Peer())
	if c.Unknown || c.Truncated || c.AppSource != AppFromChain || c.App.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("PID-only parents: unknown=%v truncated=%v source=%v app=%q procs=%d",
			c.Unknown, c.Truncated, c.AppSource, c.App.BundleID, len(c.Procs))
	}
	if len(c.Procs) != len(want.Procs) {
		t.Fatalf("procs %d, want %d", len(c.Procs), len(want.Procs))
	}
	for i := range want.Procs {
		if c.Procs[i].Ref != want.Procs[i].Ref {
			t.Fatalf("proc %d: ref %v, want %v", i, c.Procs[i].Ref, want.Procs[i].Ref)
		}
		if c.Procs[i].Ref.Generation == 0 {
			t.Fatalf("proc %d recorded with a PID-only ref %v", i, c.Procs[i].Ref)
		}
	}
	if c.SessionRoot != tab.Shell || c.Session != want.Session {
		t.Fatalf("session root %v (%v), want %v (%v)", c.SessionRoot, c.Session, tab.Shell, want.Session)
	}
	if c.AppIdentity() != want.AppIdentity() || c.Summary() != want.Summary() {
		t.Fatalf("identity %q summary %q, want %q %q", c.AppIdentity(), c.Summary(), want.AppIdentity(), want.Summary())
	}
}

// Attack: the peer's parent shell exited and its PID now belongs to a newer
// process that claims to sit under the tab's login. A PID-only parent ref
// resolves to that impostor, which started after the peer, so the walk must
// stop there: truncated, unknown, the impostor never in the chain, and the
// tab's app and session never attached.
func TestPIDOnlyParentWhosePIDWasRecycledTruncates(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	peer, _ := f.Process(tab.Peer())
	impostor := platform.ProcessRef{PID: tab.Shell.PID, Generation: tab.Shell.Generation + 5}
	f.SetProcess(platform.ProcessInfo{
		Ref: impostor, Parent: tab.Login, UID: 501, StartTime: peer.StartTime.Add(time.Hour),
		Path: "/bin/bash", Args: []string{"-bash"}, Code: fake.AppleCode("com.apple.bash"),
	})
	d := newDarwinLike(f, tabRefs(tab)...)
	d.occupy(impostor)

	c := (&Resolver{P: d}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || len(c.Procs) != 1 || c.AppSource != AppNone || !c.Session.IsZero() {
		t.Fatalf("recycled parent PID attached: truncated=%v unknown=%v procs=%d source=%v session=%v",
			c.Truncated, c.Unknown, len(c.Procs), c.AppSource, c.Session)
	}
	for _, p := range c.Procs {
		if p.Ref == impostor {
			t.Fatal("impostor is part of the chain")
		}
	}
}

// Attack: a buggy platform answers a PID-only lookup with another PID's
// record (here the iTerm2 app itself, which started early enough to pass
// the start-time check). The Resolver must check the PID it got back and
// stop, never jump straight to the app.
func TestPIDOnlyLookupAnsweringAnotherPIDTruncates(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	d := newDarwinLike(f, tabRefs(tab)...)
	d.redirect[tab.Shell.PID] = tab.App.PID

	c := (&Resolver{P: d}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || len(c.Procs) != 1 || c.AppSource != AppNone {
		t.Fatalf("record for another PID accepted as the parent: truncated=%v unknown=%v procs=%d source=%v",
			c.Truncated, c.Unknown, len(c.Procs), c.AppSource)
	}
}

// A record that comes back without a generation can't be told from a later
// occupant of its PID (session roots and exit watches are keyed by the
// full ref), so it is never part of the chain: the walk stops before it.
func TestRecordWithoutGenerationIsNotChained(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	d := newDarwinLike(f, tabRefs(tab)...)
	d.noGen[tab.Login.PID] = true

	c := (&Resolver{P: d}).Resolve(tab.Peer())
	if !c.Truncated || !c.Unknown || c.AppSource != AppNone || len(c.Procs) != 2 {
		t.Fatalf("truncated=%v unknown=%v source=%v procs=%d (want ssh, bash then stop)",
			c.Truncated, c.Unknown, c.AppSource, len(c.Procs))
	}
	for _, p := range c.Procs {
		if p.Ref.Generation == 0 {
			t.Fatalf("PID-only record %v in the chain", p.Ref)
		}
	}
}

// The peer is identified by its audit token, so its ref always has a
// generation. A PID-only peer ref is exactly the PID-reuse hole the audit
// token closes: it is unknown, even though the platform would answer it with
// the PID's live occupant.
func TestPIDOnlyPeerRefIsUnknown(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	d := newDarwinLike(f, tabRefs(tab)...)
	r := &Resolver{P: d}

	pidOnly := platform.ProcessRef{PID: tab.Peer().PID}
	c := r.Resolve(pidOnly)
	if !c.Unknown || len(c.Procs) != 0 || c.AppSource != AppNone || !c.Session.IsZero() {
		t.Fatalf("PID-only peer resolved: unknown=%v procs=%d source=%v", c.Unknown, len(c.Procs), c.AppSource)
	}
	f.SetPeer(7, pidOnly)
	if c := r.ResolveFD(7); !c.Unknown || len(c.Procs) != 0 {
		t.Fatalf("ResolveFD with a PID-only peer: unknown=%v procs=%d", c.Unknown, len(c.Procs))
	}
}

// The responsible-process lookup returns a bare PID on macOS. For a live
// app that started before the peer it is still shown (display only): the
// chain stays unknown, has no session and no identity, and the app is
// recorded under its full ref.
func TestPIDOnlyResponsibleRefIsShownForDisplay(t *testing.T) {
	f := fake.New(t0)
	tab := f.ITermTab(platform.ProcessRef{})
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	d := newDarwinLike(f, append(tabRefs(tab), mux)...)
	d.setResponsible(mux, tab.App.PID)

	c := (&Resolver{P: d}).Resolve(mux)
	if !c.Unknown || c.AppSource != AppFromResponsible || c.App.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("want unknown chain shown as responsible iTerm2, got unknown=%v source=%v app=%q", c.Unknown, c.AppSource, c.App.BundleID)
	}
	if c.App.Ref != tab.App {
		t.Fatalf("responsible app ref %v, want the full ref %v", c.App.Ref, tab.App)
	}
	if !c.Session.IsZero() || c.AppIdentity() != "" || c.AppName() != "Unknown app" {
		t.Fatalf("responsible app must stay display-only: session=%v identity=%q name=%q", c.Session, c.AppIdentity(), c.AppName())
	}
}

// Attack: the responsible app exited and its PID now belongs to another GUI
// app launched after the peer. A PID-only responsible ref must not attribute
// the chain (even for display) to a process younger than the peer.
func TestPIDOnlyResponsibleYoungerThanThePeerIsNotShown(t *testing.T) {
	f := fake.New(t0)
	mux := f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	later := f.ITermTab(platform.ProcessRef{}) // launched after the mux
	d := newDarwinLike(f, append(tabRefs(later), mux)...)
	d.setResponsible(mux, later.App.PID)

	c := (&Resolver{P: d}).Resolve(mux)
	if !c.Unknown || c.AppSource != AppNone {
		t.Fatalf("responsible PID now held by a younger app was shown: source=%v app=%q", c.AppSource, c.App.BundleID)
	}
	if got := c.Summary(); got != "ssh" {
		t.Fatalf("summary %q, want just the peer", got)
	}
}

// Attack: two processes that name each other as parent with the same start
// time pass the start-time check. With PID-only parent refs the loop must
// still be caught: no process appears twice and the chain is truncated.
func TestPIDOnlyParentLoopIsDetected(t *testing.T) {
	f := fake.New(t0)
	a := f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/a"})
	b := f.Launch(a, fake.Proc{Path: "/b"})
	ai, _ := f.Process(a)
	bi, _ := f.Process(b)
	ai.Parent, ai.StartTime = b, t0
	bi.StartTime = t0
	f.SetProcess(ai)
	f.SetProcess(bi)
	d := newDarwinLike(f, a, b)

	done := make(chan *Chain, 1)
	go func() { done <- (&Resolver{P: d}).Resolve(b) }()
	select {
	case c := <-done:
		noDuplicates(t, c)
		if !c.Truncated || !c.Unknown || len(c.Procs) != 2 {
			t.Fatalf("loop: truncated=%v unknown=%v procs=%d (want b, a then stop)", c.Truncated, c.Unknown, len(c.Procs))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Resolve did not terminate on a PID-only loop")
	}
}

// Milestone 7 on the lookups macOS can make: PID-only parents, a
// PID-only responsible ref (the orphaned helper answers for itself, as the
// kernel does once its app has exited), and app candidates re-read by their
// full ref. The orphaned tab resolves as on the exact-ref fake.
func TestOrphanedHelperOnPIDOnlyPlatform(t *testing.T) {
	f := fake.New(t0)
	r := &Resolver{P: f}
	server, shell, peer := orphanedTab(f, r)
	fresh := f.ITermTab(platform.ProcessRef{})
	want := r.Resolve(peer)
	if want.AppSource != AppFromHelper {
		t.Fatalf("control: %v", want.AppSource)
	}
	proc := func(ref platform.ProcessRef) platform.ProcessInfo {
		info, err := f.Process(ref)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	login := proc(shell).Parent
	claude := proc(peer).Parent
	d := newDarwinLike(f, append(tabRefs(fresh), server, login, shell, claude, peer)...)
	d.setResponsible(server, server.PID)

	r.P = d
	c := r.Resolve(peer)
	if c.Unknown || c.Truncated || c.AppSource != AppFromHelper || c.App.Ref != fresh.App || c.SessionRoot != shell {
		t.Fatalf("PID-only platform: unknown=%v truncated=%v source=%v app=%v root=%v",
			c.Unknown, c.Truncated, c.AppSource, c.App.Ref, c.SessionRoot)
	}
	if c.Summary() != want.Summary() || c.AppIdentity() != want.AppIdentity() || c.Session != want.Session {
		t.Fatalf("summary %q identity %q session %v, want %q %q %v",
			c.Summary(), c.AppIdentity(), c.Session, want.Summary(), want.AppIdentity(), want.Session)
	}

	// The helper's responsible process is a PID the kernel answers for a
	// live process that is not the helper: not orphaned, unknown.
	d.setResponsible(server, fresh.App.PID)
	if c := r.Resolve(peer); !c.Unknown || c.AppSource == AppFromHelper {
		t.Fatalf("helper responsible to a live process attributed: source=%v", c.AppSource)
	}
	d.setResponsible(server, server.PID)

	// The app's PID was recycled: the candidate's full ref no longer names
	// the live occupant, so there is no app.
	impostor := platform.ProcessRef{PID: fresh.App.PID, Generation: fresh.App.Generation + 7}
	f.SetProcess(platform.ProcessInfo{
		Ref: impostor, Parent: f.Launchd, UID: 501, StartTime: proc(fresh.App).StartTime.Add(time.Hour),
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode,
	})
	d.occupy(impostor)
	if c := r.Resolve(peer); !c.Unknown || c.AppSource != AppNone {
		t.Fatalf("recycled app PID attributed: source=%v app=%+v", c.AppSource, c.App)
	}
}

// listsApps replaces the platform's list of running apps.
type listsApps struct {
	*darwinLike
	apps []platform.AppInfo
}

func (l listsApps) Apps() []platform.AppInfo { return l.apps }

// A broken platform answers a listed candidate with another process's
// record (the redirect knob): the new iTerm2's server is listed as the app,
// and a lookup of its PID answers the new iTerm2. The record is not the
// candidate's, so the candidate is skipped and the helper stays unknown;
// the app it was mistaken for is not listed, so nothing else can make it
// the helper's app.
func TestHelperAppCandidateAnsweredForAnotherProcess(t *testing.T) {
	f := fake.New(t0)
	r := &Resolver{P: f}
	server, shell, peer := orphanedTab(f, r)
	fresh := f.ITermTab(platform.ProcessRef{})
	proc := func(ref platform.ProcessRef) platform.ProcessInfo {
		info, err := f.Process(ref)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	login := proc(shell).Parent
	claude := proc(peer).Parent
	d := newDarwinLike(f, append(tabRefs(fresh), server, login, shell, claude, peer)...)
	d.setResponsible(server, server.PID)
	listed := platform.AppInfo{Ref: fresh.Server, BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: fake.ITermCode}
	r.P = listsApps{d, []platform.AppInfo{{Ref: fresh.App, BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: fake.ITermCode}}}
	if c := r.Resolve(peer); c.AppSource != AppFromHelper || c.App.Ref != fresh.App {
		t.Fatalf("control: source=%v app=%+v", c.AppSource, c.App)
	}
	d.redirect[fresh.Server.PID] = fresh.App.PID
	r.P = listsApps{d, []platform.AppInfo{listed}}
	if c := r.Resolve(peer); !c.Unknown || c.AppSource != AppNone || c.HasApp() {
		t.Fatalf("a candidate answered with another process's record was taken: source=%v app=%+v", c.AppSource, c.App)
	}
}
