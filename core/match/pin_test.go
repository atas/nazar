package match

import (
	"strings"
	"sync"
	"testing"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/trust"
)

// Security fix (spec 4.2 "pinned on first load", 4.8). An app:
// matcher without team: matches only a process whose bundle ID AND team
// equal a pin that already exists in the trust store. Pins are created when
// a config is approved (from the INSTALLED app, shown in the approval diff)
// or by `nazar trust --app` behind the login gate; matching never writes a
// pin. Before the fix, the first process to present a configured bundle ID
// pinned its own team: a Developer-ID-signed impostor (/tmp/Evil.app with
// CFBundleIdentifier com.googlecode.iterm2) that asked first became "iTerm2"
// for good, even under gate: none.

// readOnlyTrust has only the read side of the trust store. It satisfying
// Trust is the compile-time guarantee that the evaluator cannot write pins.
type readOnlyTrust struct{ pins map[string]string }

func (r readOnlyTrust) PinnedTeam(id string) (string, bool) { t, ok := r.pins[id]; return t, ok }

var _ Trust = readOnlyTrust{}

// countingVault counts writes, so a test can prove matching wrote nothing.
type countingVault struct {
	*fake.Vault
	mu   sync.Mutex
	puts int
}

func (v *countingVault) Put(name string, value []byte) error {
	v.mu.Lock()
	v.puts++
	v.mu.Unlock()
	return v.Vault.Put(name, value)
}

func (v *countingVault) Puts() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.puts
}

var evilITerm = fake.Proc{
	Path: "/tmp/Evil.app/Contents/MacOS/Evil",
	Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "com.googlecode.iterm2", CDHash: []byte{0xee}},
	App:  &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
}

func joined(notes []string) string { return strings.Join(notes, "\n") }

// Attack: the impostor is the first process ever to ask for an app: matcher
// with no pin yet. It must not match and must not pin itself; when the
// config approval later pins the real team, the impostor still fails and
// the real app matches.
func TestImpostorFirstContactDoesNotPinItself(t *testing.T) {
	en := newUnpinnedEnv(t)
	evil := en.f.Launch(platform.ProcessRef{}, evilITerm)
	peer := en.f.Launch(evil, fake.SSHProc("h"))
	for i := 0; i < 3; i++ {
		if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(peer)) {
			t.Fatal("BYPASS: impostor matched app: iterm on first contact")
		}
	}
	if team, ok := en.store.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatalf("BYPASS: first contact pinned team %q", team)
	}
	if len(en.store.Pins()) != 0 {
		t.Fatalf("matching wrote pins: %v", en.store.Pins())
	}

	en.store.Pin("com.googlecode.iterm2", "H7V7XYVQ7D") // config approval, from the installed app
	if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(peer)) {
		t.Fatal("impostor must not match once the real team is pinned")
	}
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if !en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(tab.Peer())) {
		t.Fatal("the real app must match its pin")
	}
}

// Attack: the real app has never run; the impostor runs, then the real
// app. Neither creates a pin, and the real app does not match either until
// a pin exists (it is inactive, not "first come").
func TestImpostorBeforeRealAppEverRan(t *testing.T) {
	en := newUnpinnedEnv(t)
	evil := en.f.Launch(platform.ProcessRef{}, evilITerm)
	if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(en.f.Launch(evil, fake.SSHProc("h")))) {
		t.Fatal("BYPASS: impostor matched")
	}
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(tab.Peer())) {
		t.Fatal("an unpinned app: matcher must match nothing, not even the real app")
	}
	if _, ok := en.store.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatal("matching must never create a pin")
	}
	if !strings.Contains(joined(en.notes), "nazar trust --app com.googlecode.iterm2") {
		t.Fatalf("an unpinned app must be noted with the fix, got %q", en.notes)
	}
}

// Attack via to:. A receiver app: matcher must not pin either.
func TestReceiverAppDoesNotPin(t *testing.T) {
	en := newUnpinnedEnv(t)
	evil := en.f.Launch(platform.ProcessRef{}, evilITerm)
	c := en.r.Resolve(evil)
	if en.e.Receiver([]config.Matcher{itermM}, c) {
		t.Fatal("BYPASS: unpinned to: app matched")
	}
	if _, ok := en.store.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatal("Receiver must never create a pin")
	}
}

// After an update the real app is signed by another team. That is a
// mismatch: logged, not matched, and never re-pinned (only `nazar trust
// --app` behind the login gate changes a pin), however often it asks.
func TestTeamChangeAfterUpdateNeverRepins(t *testing.T) {
	en := newEnv(t)
	updated := fake.ITermCode
	updated.TeamID = "NEWTEAM000"
	app := en.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: updated,
		App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	tab := en.f.ITermTab(app, fake.SSHProc("h"))
	for i := 0; i < 3; i++ {
		if en.e.Apps([]config.Matcher{itermM}, en.r.Resolve(tab.Peer())) {
			t.Fatal("an app whose team changed must not match the old pin")
		}
	}
	if team, _ := en.store.PinnedTeam("com.googlecode.iterm2"); team != "H7V7XYVQ7D" {
		t.Fatalf("BYPASS: mismatch re-pinned to %q", team)
	}
	if !strings.Contains(joined(en.notes), "NEWTEAM000 but H7V7XYVQ7D is pinned") {
		t.Fatalf("mismatch must be logged, got %q", en.notes)
	}
}

// Matching never writes to the vault, for any matcher kind, matching or not,
// pinned or not.
func TestMatchingNeverWritesTheVault(t *testing.T) {
	f := fake.New(t0)
	v := &countingVault{Vault: fake.NewVault()}
	st, err := trust.Open(v)
	if err != nil {
		t.Fatal(err)
	}
	st.Pin("com.apple.Terminal", "apple")
	base := v.Puts()
	var notes []string
	e := &Evaluator{Trust: st, Note: func(m string) { notes = append(notes, m) }}
	r := &caller.Resolver{P: f}

	tab := f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	evil := f.Launch(platform.ProcessRef{}, evilITerm)
	chains := []*caller.Chain{
		r.Resolve(tab.Peer()),
		r.Resolve(f.Launch(evil, fake.SSHProc("h"))),
		r.Resolve(evil),
	}
	ms := []config.Matcher{itermM, claudeM, sshM, kubectl, anyM, unknown,
		{Kind: config.MatchApp, ID: "com.todesktop.230313mzl4w4u92"},
		{Kind: config.MatchApp, ID: "com.apple.Terminal"}}
	for _, c := range chains {
		for _, m := range ms {
			e.Apps([]config.Matcher{m}, c)
			e.Receiver([]config.Matcher{m}, c)
		}
	}
	if v.Puts() != base {
		t.Fatalf("BYPASS: matching wrote the vault %d times", v.Puts()-base)
	}
	if pins := st.Pins(); len(pins) != 1 || pins["com.apple.Terminal"] != "apple" {
		t.Fatalf("pins changed by matching: %v", pins)
	}
}

// The evaluator works with a read-only trust view: it never needs Pin.
func TestEvaluatorWorksWithReadOnlyTrust(t *testing.T) {
	f := fake.New(t0)
	r := &caller.Resolver{P: f}
	e := &Evaluator{Trust: readOnlyTrust{pins: map[string]string{"com.googlecode.iterm2": "H7V7XYVQ7D"}}}
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if !e.Apps([]config.Matcher{itermM}, r.Resolve(tab.Peer())) {
		t.Fatal("pinned iterm must match through a read-only trust view")
	}
	evil := f.Launch(platform.ProcessRef{}, evilITerm)
	if e.Apps([]config.Matcher{itermM}, r.Resolve(f.Launch(evil, fake.SSHProc("h")))) {
		t.Fatal("impostor must not match")
	}
	empty := &Evaluator{Trust: readOnlyTrust{}}
	if empty.Apps([]config.Matcher{itermM}, r.Resolve(tab.Peer())) {
		t.Fatal("no pin: must not match")
	}
}

// An explicit team: in the config needs no pin and ignores the store: it
// matches that team only, and writes nothing.
func TestExplicitTeamNeedsNoPin(t *testing.T) {
	en := newUnpinnedEnv(t)
	right := config.Matcher{Kind: config.MatchApp, ID: "com.googlecode.iterm2", Team: "H7V7XYVQ7D"}
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if !en.e.Apps([]config.Matcher{right}, en.r.Resolve(tab.Peer())) {
		t.Fatal("explicit team must match without a pin")
	}
	evil := en.f.Launch(platform.ProcessRef{}, evilITerm)
	if en.e.Apps([]config.Matcher{right}, en.r.Resolve(en.f.Launch(evil, fake.SSHProc("h")))) {
		t.Fatal("explicit team must reject another team")
	}
	if len(en.store.Pins()) != 0 {
		t.Fatal("explicit team must not create a pin")
	}
}

// The pin is per bundle ID: a process of the pinned team presenting a
// different, unpinned bundle ID does not match that bundle's matcher.
func TestPinIsPerBundleID(t *testing.T) {
	en := newEnv(t)
	other := en.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Other.app/Contents/MacOS/Other",
		Code: platform.CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.other"},
		App:  &fake.App{BundleID: "com.googlecode.other", Name: "Other"},
	})
	c := en.r.Resolve(en.f.Launch(other, fake.SSHProc("h")))
	if en.e.Apps([]config.Matcher{{Kind: config.MatchApp, ID: "com.googlecode.other"}}, c) {
		t.Fatal("an unpinned bundle id must not match because its team is pinned for another bundle")
	}
	if en.e.Apps([]config.Matcher{itermM}, c) {
		t.Fatal("a different bundle id must not match app: iterm")
	}
}
