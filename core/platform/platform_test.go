package platform

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestProcessRef(t *testing.T) {
	if !(ProcessRef{}).IsZero() {
		t.Fatal("zero ref must be zero")
	}
	r := ProcessRef{PID: 42, Generation: 7}
	if r.IsZero() || r.String() != "42/7" {
		t.Fatalf("got %v %q", r.IsZero(), r.String())
	}
}

// A ref is zero only when both fields are zero: PID 0 with a generation, or a
// PID with generation 0, still names a process instance.
func TestProcessRefZeroNeedsBothFieldsZero(t *testing.T) {
	for _, r := range []ProcessRef{{PID: 0, Generation: 1}, {PID: 1, Generation: 0}} {
		if r.IsZero() {
			t.Errorf("%+v reported as zero", r)
		}
	}
	if got := (ProcessRef{}).String(); got != "0/0" {
		t.Errorf("zero ref String()=%q want %q", got, "0/0")
	}
	max := ProcessRef{PID: math.MaxInt32, Generation: math.MaxUint64}
	if got, want := max.String(), fmt.Sprintf("%d/%d", math.MaxInt32, uint64(math.MaxUint64)); got != want {
		t.Errorf("String()=%q want %q", got, want)
	}
}

// A recycled PID is a different process: refs with the same PID and a
// different generation must never compare equal or share a map slot
// (approvals and exit watches are keyed by ProcessRef).
func TestProcessRefGenerationDistinguishesRecycledPID(t *testing.T) {
	a := ProcessRef{PID: 500, Generation: 1}
	b := ProcessRef{PID: 500, Generation: 2}
	if a == b {
		t.Fatal("refs with different generations compare equal")
	}
	if a.String() == b.String() {
		t.Fatalf("refs with different generations print the same: %q", a.String())
	}
	m := map[ProcessRef]string{a: "old"}
	if _, ok := m[b]; ok {
		t.Fatal("recycled PID found the old process's entry")
	}
}

func TestCodeIdentityTeam(t *testing.T) {
	cases := []struct {
		c    CodeIdentity
		want string
	}{
		{CodeIdentity{Signed: true, TeamID: "Q6L2SF6YDW"}, "Q6L2SF6YDW"},
		{CodeIdentity{Signed: true, Apple: true}, "apple"},
		{CodeIdentity{Signed: true, AdHoc: true, TeamID: "X"}, ""},
		{CodeIdentity{TeamID: "Q6L2SF6YDW"}, ""},
	}
	for i, c := range cases {
		if got := c.c.Team(); got != c.want {
			t.Errorf("case %d: Team()=%q want %q", i, got, c.want)
		}
	}
}

// Team() feeds the `signed:` and `app:` matchers, which are trusted because
// they can't be faked. Anything that is not a valid, non-ad-hoc signature
// must yield "" so it can never match a team or "apple".
func TestCodeIdentityTeamCannotBeFaked(t *testing.T) {
	cases := []struct {
		name string
		c    CodeIdentity
		want string
	}{
		{"zero value", CodeIdentity{}, ""},
		{"unsigned claiming apple", CodeIdentity{Apple: true}, ""},
		{"unsigned claiming apple and team", CodeIdentity{Apple: true, TeamID: "Q6L2SF6YDW", SigningID: "com.apple.Terminal"}, ""},
		{"ad-hoc claiming apple", CodeIdentity{Signed: true, AdHoc: true, Apple: true}, ""},
		{"ad-hoc with signing id", CodeIdentity{Signed: true, AdHoc: true, SigningID: "com.anthropic.claude-code"}, ""},
		{"signed, no team, not apple", CodeIdentity{Signed: true, SigningID: "x"}, ""},
		{"unsigned with cdhash", CodeIdentity{CDHash: []byte{1, 2, 3}}, ""},
		{"apple wins over a team id", CodeIdentity{Signed: true, Apple: true, TeamID: "Q6L2SF6YDW"}, "apple"},
	}
	for _, c := range cases {
		if got := c.c.Team(); got != c.want {
			t.Errorf("%s: Team()=%q want %q", c.name, got, c.want)
		}
	}
}

func TestStrings(t *testing.T) {
	if PurposeSign.String() != "sign" || AuthUserPresence.String() != "user-presence" || AuthNone.String() != "none" {
		t.Fatal("unexpected String() output")
	}
	if AccessWhenUnlocked.String() != "when-unlocked" || AccessAfterFirstUnlock.String() != "after-first-unlock" || Access(7).String() != "access(7)" {
		t.Fatal("unexpected Access String() output")
	}
	if !AccessWhenUnlocked.Valid() || !AccessAfterFirstUnlock.Valid() || Access(2).Valid() || Access(-1).Valid() {
		t.Fatal("unexpected Access Valid() output")
	}
}

// The numeric values cross the C bridge to Swift (Milestone 3), so they are
// part of the contract.
func TestEnumValues(t *testing.T) {
	if PurposeSign != 1 || PurposeKeyAgreement != 2 {
		t.Errorf("Purpose values: sign=%d key-agreement=%d, want 1 and 2", PurposeSign, PurposeKeyAgreement)
	}
	// The zero value is the stricter access: a record or handle written
	// before Access existed reads as AccessWhenUnlocked.
	if AccessWhenUnlocked != 0 || AccessAfterFirstUnlock != 1 {
		t.Errorf("Access values: when-unlocked=%d after-first-unlock=%d, want 0 and 1", AccessWhenUnlocked, AccessAfterFirstUnlock)
	}
	if AuthNone != 0 || AuthUserPresence != 1 {
		t.Errorf("AuthPolicy values: none=%d user-presence=%d, want 0 and 1", AuthNone, AuthUserPresence)
	}
	var none ApprovalRef
	if none != 0 {
		t.Error("zero ApprovalRef must be 0 (no approval)")
	}
	if got := PurposeKeyAgreement.String(); got != "key-agreement" {
		t.Errorf("PurposeKeyAgreement.String()=%q", got)
	}
}

// Out-of-range values (a corrupt Vault record, a bad bridge value) must not
// masquerade as a valid one in logs or prompts.
func TestStringsOfUnknownValues(t *testing.T) {
	known := map[string]bool{"sign": true, "key-agreement": true, "none": true, "user-presence": true, "": true}
	for _, p := range []Purpose{0, -1, 3, 99} {
		if s := p.String(); known[s] {
			t.Errorf("Purpose(%d).String()=%q looks like a valid value", int(p), s)
		}
	}
	for _, a := range []AuthPolicy{-1, 2, 99} {
		if s := a.String(); known[s] {
			t.Errorf("AuthPolicy(%d).String()=%q looks like a valid value", int(a), s)
		}
	}
}

// The sentinel errors are distinct and survive wrapping, so callers can tell
// a cancelled prompt from a missing key from a vanished process.
func TestSentinelErrors(t *testing.T) {
	errs := map[string]error{
		"ErrNotFound":     ErrNotFound,
		"ErrNoProcess":    ErrNoProcess,
		"ErrDenied":       ErrDenied,
		"ErrAuthRequired": ErrAuthRequired,
		"ErrAmbiguous":    ErrAmbiguous,
	}
	for name, e := range errs {
		if e == nil {
			t.Fatalf("%s is nil", name)
		}
		if e.Error() == "" {
			t.Errorf("%s has an empty message", name)
		}
		wrapped := fmt.Errorf("context: %w", e)
		for other, o := range errs {
			if got := errors.Is(wrapped, o); got != (other == name) {
				t.Errorf("errors.Is(wrapped %s, %s)=%v", name, other, got)
			}
		}
	}
}

// stubPlatform and stubVault pin the exact method sets of the seams that
// Milestone 3's Swift layer implements: changing a signature breaks this
// test at compile time.
type stubPlatform struct{}

func (stubPlatform) CreateKey(purpose Purpose, auth AuthPolicy, access Access) (handle, publicKey []byte, err error) {
	return nil, nil, ErrNotFound
}
func (stubPlatform) Sign(handle, digestInput []byte, approval ApprovalRef) ([]byte, error) {
	return nil, ErrAuthRequired
}
func (stubPlatform) KeyAgreement(handle, peerPublicKey []byte, approval ApprovalRef) ([]byte, error) {
	return nil, ErrAuthRequired
}
func (stubPlatform) DeleteKey(handle []byte) error { return ErrNotFound }
func (stubPlatform) Authenticate(policy AuthPolicy, prompt Prompt) (ApprovalRef, error) {
	return 0, ErrDenied
}
func (stubPlatform) Confirm(prompt Prompt) (bool, error)              { return false, nil }
func (stubPlatform) ReleaseApproval(ref ApprovalRef)                  {}
func (stubPlatform) PeerOf(socketFD int) (ProcessRef, error)          { return ProcessRef{}, ErrNoProcess }
func (stubPlatform) Process(ref ProcessRef) (ProcessInfo, error)      { return ProcessInfo{}, ErrNoProcess }
func (stubPlatform) AppFor(chain []ProcessInfo) (AppInfo, bool)       { return AppInfo{}, false }
func (stubPlatform) Apps() []AppInfo                                  { return nil }
func (stubPlatform) CodeHash(path string) ([]byte, error)             { return nil, ErrNotFound }
func (stubPlatform) ResponsibleFor(ref ProcessRef) (ProcessRef, bool) { return ProcessRef{}, false }
func (stubPlatform) OnProcessExit(ref ProcessRef, fn func())          {}
func (stubPlatform) OnScreenLock(fn func())                           {}
func (stubPlatform) ShowWarning(w Warning)                            {}
func (stubPlatform) InstalledApp(bundleID string) (AppBundle, error) {
	return AppBundle{}, ErrNotFound
}

type stubVault struct{}

func (stubVault) Get(name string) ([]byte, error)      { return nil, ErrNotFound }
func (stubVault) Put(name string, value []byte) error  { return nil }
func (stubVault) Delete(name string) error             { return nil }
func (stubVault) List(prefix string) ([]string, error) { return nil, nil }

var (
	_ Platform = stubPlatform{}
	_ Vault    = stubVault{}
)

// The shared value types carry the fields the core and the Swift layer
// exchange (spec 4.1, 4.4, 4.7).
func TestSharedTypesFields(t *testing.T) {
	ref := ProcessRef{PID: 10, Generation: 3}
	code := CodeIdentity{Signed: true, TeamID: "T", SigningID: "s", Apple: false, AdHoc: false, CDHash: []byte{9}}
	pi := ProcessInfo{
		Ref: ref, Parent: ProcessRef{PID: 1, Generation: 1}, UID: 501,
		StartTime: time.Unix(1, 0), Path: "/bin/sh", Args: []string{"sh", "-c", "x"}, Cwd: "/", Code: code,
	}
	ai := AppInfo{Ref: ref, BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: code}
	p := Prompt{Title: "t", Lines: []string{"l"}, Unknown: true, Reason: "r", Timeout: 60 * time.Second}
	w := Warning{ID: "id", Title: "t", Lines: []string{"l"}, Count: 2, SuggestedRule: "rule"}
	if pi.Code.Team() != "T" || ai.Code.Team() != "T" || p.Timeout != time.Minute || w.Count != 2 {
		t.Fatal("field round trip failed")
	}
	var plat Platform = stubPlatform{}
	if _, err := plat.Authenticate(AuthUserPresence, p); !errors.Is(err, ErrDenied) {
		t.Fatalf("stub Authenticate: %v", err)
	}
	var v Vault = stubVault{}
	if _, err := v.Get("ssh-key/github"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stub Get: %v", err)
	}
}

// App: team pins are taken from the INSTALLED app when a config is
// approved (spec 4.2 "pinned on first load"), never from whatever process
// first asks. The platform resolves the installed bundle for a bundle ID
// (macOS, Milestone 3: LaunchServices + the static code signature of the
// bundle in /Applications or ~/Applications). It is part of Platform, so
// calling it through the interface pins the method set at compile time.
func TestInstalledAppIsPartOfThePlatform(t *testing.T) {
	var plat Platform = stubPlatform{}
	b, err := plat.InstalledApp("com.googlecode.iterm2")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("stub InstalledApp: %v", err)
	}
	b = AppBundle{
		BundleID: "com.googlecode.iterm2",
		Path:     "/Applications/iTerm.app",
		Code:     CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2"},
	}
	if b.Code.Team() != "H7V7XYVQ7D" || b.Path == "" || b.BundleID == "" {
		t.Fatal("AppBundle field round trip failed")
	}
	// The team a pin records is CodeIdentity.Team(): an ad-hoc or unsigned
	// bundle has none, whatever TeamID claims.
	b.Code.AdHoc = true
	if b.Code.Team() != "" {
		t.Fatal("an ad-hoc installed bundle must have no team")
	}
}
