package configstage

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/trust"
)

// Security fix (spec 4.2 "team ID pinned on first load", 4.8, 6).
//
// An app: matcher without team: matches only the team pinned for its bundle
// ID (core/match never writes pins). Pins are created here, never while
// matching:
//
//   - When a loosening config change is staged, every app: matcher without
//     team: (in rules' apps: and to:) whose bundle ID has no pin yet is
//     resolved to the INSTALLED app through Platform.InstalledApp. Each
//     resolvable one becomes a PinChange in the staged Diff (Diff.Pins) and
//     a Loosening finding with Target "app:<bundle id>" naming the team and
//     the bundle path, so the login prompt shows which team is trusted.
//     Approving records exactly the pins that were shown; staging, denying
//     or a failed approval records none.
//   - A bundle ID that is not installed, ambiguous (installed bundles with
//     different teams) or not validly signed gets no pin: its matcher stays
//     inactive (matches nothing). AppProblems reports it, for `nazar config
//     check` and `nazar status`, with Fix "nazar trust --app <bundle id>".
//   - An existing pin is never changed by a config change. A later team
//     mismatch with the installed app is reported by AppProblems; only
//     TrustApp (`nazar trust --app`, behind the login gate) re-pins.
//   - Nothing pins without the login gate: not a tightening applied at
//     once, not a cosmetic edit, not loading the approved config at start.
//
// API this file pins down (configstage):
//
//	type AppResolver interface{ InstalledApp(bundleID string) (platform.AppBundle, error) } // *fake.Fake, the macOS platform
//	type PinStore interface {                                                              // *trust.Store
//		PinnedTeam(bundleID string) (string, bool)
//		Pin(bundleID, team string) (string, error) // first writer wins
//		SetPin(bundleID, team string) error        // replace
//	}
//	type PinChange struct{ BundleID, Team, Old, Path string } // Old: the pin replaced ("" for a new pin)
//	type AppProblem struct{ BundleID, Reason, Fix string }
//	Diff.Pins []PinChange
//	func OpenWithTrust(env config.Env, v platform.Vault, pins PinStore, apps AppResolver, onApply func(*config.Config)) (*Stager, error)
//	func AppProblems(c *config.Config, pins PinStore, apps AppResolver) []AppProblem
//	func TrustApp(bundleID string, pins PinStore, apps AppResolver, approve func(PinChange) (bool, error)) (PinChange, error)

const (
	itermID  = "com.googlecode.iterm2"
	cursorID = "com.todesktop.230313mzl4w4u92"
	itermApp = "/Applications/iTerm.app"
	itermTm  = "H7V7XYVQ7D"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

var (
	evilCode    = platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: itermID, CDHash: []byte{0xee}}
	newTeamCode = platform.CodeIdentity{Signed: true, TeamID: "NEWTEAM000", SigningID: itermID, CDHash: []byte{0x18}}
)

type pinEnv struct {
	s     *Stager
	f     *fake.Fake
	v     *fake.Vault // the stager's vault
	tv    *fake.Vault // the trust store's vault
	store *trust.Store
}

func openPinning(t *testing.T) *pinEnv {
	t.Helper()
	pe := &pinEnv{f: fake.New(t0), v: fake.NewVault(), tv: fake.NewVault()}
	var err error
	if pe.store, err = trust.Open(pe.tv); err != nil {
		t.Fatal(err)
	}
	if pe.s, err = OpenWithTrust(env, pe.v, pe.store, pe.f, nil); err != nil {
		t.Fatal(err)
	}
	return pe
}

func (pe *pinEnv) pin(id string) (string, bool) { return pe.store.PinnedTeam(id) }

func pinFor(d Diff, id string) (PinChange, bool) {
	for _, p := range d.Pins {
		if p.BundleID == id {
			return p, true
		}
	}
	return PinChange{}, false
}

func findingFor(d Diff, target string) (Finding, bool) {
	for _, f := range d.Loosening {
		if f.Target == target {
			return f, true
		}
	}
	return Finding{}, false
}

func problemFor(ps []AppProblem, id string) (AppProblem, bool) {
	for _, p := range ps {
		if p.BundleID == id {
			return p, true
		}
	}
	return AppProblem{}, false
}

func TestStagedChangeShowsThePinItWillCreate(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	r := pe.s.Observe(src(base))
	if !r.Staged {
		t.Fatalf("adding rules must be staged: %+v", r)
	}
	p, ok := pinFor(r.Diff, itermID)
	if !ok || p.Team != itermTm || p.Path != itermApp || p.Old != "" {
		t.Fatalf("diff must show the new pin from the installed app, got %+v (all: %+v)", p, r.Diff.Pins)
	}
	f, ok := findingFor(r.Diff, appTarget(itermID))
	if !ok || !strings.Contains(f.Why, itermTm) || !strings.Contains(f.Why, itermApp) {
		t.Fatalf("a new pin is a loosening the prompt shows (team and bundle), got %+v\n%s", f, findingsText(r.Diff))
	}
	if pend, _ := pe.s.Pending(); len(pend.Diff.Pins) != len(r.Diff.Pins) {
		t.Fatal("Pending must carry the pins shown to the approver")
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("staging must not pin")
	}
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if team, ok := pe.pin(itermID); !ok || team != itermTm {
		t.Fatalf("approval must record the pin shown, got %q %v", team, ok)
	}
	// The pin is in the trust store's vault: it survives a restart.
	st2, _ := trust.Open(pe.tv)
	if team, _ := st2.PinnedTeam(itermID); team != itermTm {
		t.Fatalf("pin not persisted: %q", team)
	}
}

// Rules' to: and inline app: matchers are pinned the same way.
func TestInlineAndReceiverAppMatchersArePinned(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp("/Applications/Cursor.app", cursorID, platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: cursorID})
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	r := pe.s.Observe(src(`ssh_agent:
  keys:
    github:
      rules:
        - apps: [{app: com.googlecode.iterm2}]
          to: [{app: com.todesktop.230313mzl4w4u92}]
          gate: login
`))
	if !r.Staged {
		t.Fatalf("staged: %+v", r)
	}
	if p, ok := pinFor(r.Diff, itermID); !ok || p.Team != itermTm {
		t.Fatalf("inline apps: app matcher must be pinned: %+v", r.Diff.Pins)
	}
	if p, ok := pinFor(r.Diff, cursorID); !ok || p.Team != "VDXQ22DGB9" {
		t.Fatalf("to: app matcher must be pinned: %+v", r.Diff.Pins)
	}
}

func TestDeniedOrFailedApprovalPinsNothing(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	pe.s.Observe(src(base))
	pe.s.Approve("", func(Pending) (bool, error) { return false, nil })
	pe.s.Approve("", func(Pending) (bool, error) { return true, errors.New("gate timed out") })
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("a denied or failed approval must not pin")
	}
}

// TOCTOU: the installed bundle is swapped while the prompt is open. What is
// pinned is what the user approved, never a re-resolution.
func TestApprovalPinsWhatWasShownNotWhatIsInstalledNow(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	pe.s.Observe(src(base))
	ok, err := pe.s.Approve("", func(p Pending) (bool, error) {
		if c, _ := pinFor(p.Diff, itermID); c.Team != itermTm {
			t.Errorf("approver shown %+v", c)
		}
		pe.f.InstallApp(itermApp, itermID, evilCode) // swapped during the prompt
		return true, nil
	})
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if team, _ := pe.pin(itermID); team != itermTm {
		t.Fatalf("BYPASS: pinned %q, not the team the user approved", team)
	}
}

// Attack: an app not installed (or uninstalled) gets no pin, so a later
// impostor can't take its place; the matcher is inactive and reported with
// the fix.
func TestUninstalledAppIsNotPinnedAndIsReported(t *testing.T) {
	pe := openPinning(t)
	r := pe.s.Observe(src(base))
	if _, ok := pinFor(r.Diff, itermID); ok {
		t.Fatalf("an app that isn't installed can't be pinned: %+v", r.Diff.Pins)
	}
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal("the rest of the config still applies:", ok, err)
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("no pin for an app that isn't installed")
	}
	probs := AppProblems(pe.s.Active(), pe.store, pe.f)
	p, ok := problemFor(probs, itermID)
	if !ok || p.Reason == "" || p.Fix != "nazar trust --app "+itermID {
		t.Fatalf("config check/status must report the inactive matcher with the fix, got %+v", probs)
	}
	if _, ok := problemFor(probs, cursorID); !ok {
		t.Fatalf("every inactive app: matcher is reported: %+v", probs)
	}
	if _, ok := problemFor(probs, "com.anthropic.claude-code"); ok {
		t.Fatal("signed: matchers have no pin to report")
	}
}

// Attack: an impostor copying the bundle ID next to the real app (e.g. in
// ~/Applications, which the user can write). The bundle ID is ambiguous:
// nothing is pinned or shown as a pin, and the matcher is reported.
func TestAmbiguousInstallIsNotPinned(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	pe.f.InstallApp("/Users/u/Applications/iTerm.app", itermID, evilCode)
	r := pe.s.Observe(src(base))
	if p, ok := pinFor(r.Diff, itermID); ok {
		t.Fatalf("ambiguous install must not be offered as a pin: %+v", p)
	}
	pe.s.Approve("", yes)
	if team, ok := pe.pin(itermID); ok {
		t.Fatalf("BYPASS: ambiguous install pinned %q", team)
	}
	if p, ok := problemFor(AppProblems(pe.s.Active(), pe.store, pe.f), itermID); !ok || p.Fix != "nazar trust --app "+itermID {
		t.Fatalf("ambiguous app must be reported with the fix: %+v", p)
	}
}

// An installed bundle that isn't validly signed has no team to pin.
func TestUnsignedInstallIsNotPinned(t *testing.T) {
	for name, code := range map[string]platform.CodeIdentity{
		"adhoc":    {Signed: true, AdHoc: true, TeamID: itermTm, SigningID: itermID},
		"unsigned": {TeamID: itermTm, SigningID: itermID},
	} {
		t.Run(name, func(t *testing.T) {
			pe := openPinning(t)
			pe.f.InstallApp(itermApp, itermID, code)
			r := pe.s.Observe(src(base))
			if p, ok := pinFor(r.Diff, itermID); ok {
				t.Fatalf("offered pin for %s bundle: %+v", name, p)
			}
			pe.s.Approve("", yes)
			if team, ok := pe.pin(itermID); ok {
				t.Fatalf("pinned %q for a %s bundle", team, name)
			}
			if _, ok := problemFor(AppProblems(pe.s.Active(), pe.store, pe.f), itermID); !ok {
				t.Fatal("must be reported")
			}
		})
	}
}

// Attack: the app updated to another team (or an impostor replaced it).
// A config change never re-pins: the old pin stays, no PinChange is shown
// for it, and AppProblems reports the mismatch with the fix.
func TestConfigChangeNeverRepins(t *testing.T) {
	pe := openPinning(t)
	pe.store.Pin(itermID, itermTm)
	pe.f.InstallApp(itermApp, itermID, newTeamCode)
	r := pe.s.Observe(src(base))
	if p, ok := pinFor(r.Diff, itermID); ok {
		t.Fatalf("a config change must not offer to re-pin: %+v", p)
	}
	pe.s.Approve("", yes)
	if team, _ := pe.pin(itermID); team != itermTm {
		t.Fatalf("BYPASS: config approval re-pinned to %q", team)
	}
	p, ok := problemFor(AppProblems(pe.s.Active(), pe.store, pe.f), itermID)
	if !ok || p.Fix != "nazar trust --app "+itermID || !strings.Contains(p.Reason, "NEWTEAM000") {
		t.Fatalf("team mismatch must be reported with the fix: %+v", p)
	}
}

func TestExistingPinAndExplicitTeamAreNotShownAgain(t *testing.T) {
	pe := openPinning(t)
	pe.store.Pin(itermID, itermTm)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	pe.f.InstallApp("/Applications/Cursor.app", cursorID, platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: cursorID})
	r := pe.s.Observe([]byte(`apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: login
        - apps: [{app: com.todesktop.230313mzl4w4u92, team: VDXQ22DGB9}]
          gate: login
`))
	if len(r.Diff.Pins) != 0 {
		t.Fatalf("nothing new to pin, got %+v", r.Diff.Pins)
	}
	if _, ok := findingFor(r.Diff, appTarget(itermID)); ok {
		t.Fatal("an unchanged pin is not a loosening")
	}
	pe.s.Approve("", yes)
	if _, ok := pe.pin(cursorID); ok {
		t.Fatal("an explicit team: needs no pin")
	}
	probs := AppProblems(pe.s.Active(), pe.store, pe.f)
	if len(probs) != 0 {
		t.Fatalf("pinned and explicit-team matchers are fine: %+v", probs)
	}
}

// The login gate is the only way to a pin: a tightening (applied at once,
// spec 4.8) and loading the approved config at start never pin, even when
// the app is installed now.
func TestNoPinWithoutTheLoginGate(t *testing.T) {
	pe := openPinning(t)
	pe.s.Observe(src(base)) // iTerm not installed yet
	pe.s.Approve("", yes)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)

	tight := src(strings.Replace(base, "scope: session\n          gate: dialog", "gate: block", 1))
	if r := pe.s.Observe(tight); !r.Applied {
		t.Fatalf("a tightening must still apply at once: %+v", r)
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("a tightening applied without the gate must not pin")
	}
	cosmetic := append(append([]byte(nil), tight...), []byte("# a comment\n")...)
	pe.s.Observe(cosmetic)
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("a cosmetic edit must not pin without the gate")
	}

	s2, err := OpenWithTrust(env, pe.v, pe.store, pe.f, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Active() == nil {
		t.Fatal("no active config")
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("loading the approved config at start must not pin")
	}
	if _, ok := problemFor(AppProblems(s2.Active(), pe.store, pe.f), itermID); !ok {
		t.Fatal("the unpinned matcher must be reported")
	}
}

// A new pin is new trust, so a change whose only loosening is a bundle ID
// new to the config goes to the gate even when Classify calls the rules a
// tightening: a `gate: block` rule on an unpinned app: matcher matches
// nothing, so applying it at once without the pin would let the real app
// fall through to later, more permissive rules instead of being blocked.
func TestNewBundleIDForcesTheGateEvenWhenRulesOnlyTighten(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	pe.s.Observe(src(`ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          gate: dialog
`))
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("the approved config has no app: matcher, so nothing to pin yet")
	}

	block := src(`ssh_agent:
  keys:
    github:
      rules:
        - apps: [{app: com.googlecode.iterm2}]
          gate: block
        - apps: [claude]
          gate: dialog
`)
	nw := cfgFull(t, string(block))
	if d := Classify(pe.s.Active(), nw); d.Loosens() {
		t.Fatalf("precondition: the rules alone must classify as a tightening, got\n%s", findingsText(d))
	}
	r := pe.s.Observe(block)
	if !r.Staged || r.Applied {
		t.Fatalf("a bundle id new to the config must be staged for the gate, not applied: %+v", r)
	}
	p, ok := pinFor(r.Diff, itermID)
	if !ok || p.Team != itermTm || p.Path != itermApp || p.Old != "" {
		t.Fatalf("diff must show the pin the gate is for, got %+v (all: %+v)", p, r.Diff.Pins)
	}
	f, ok := findingFor(r.Diff, appTarget(itermID))
	if !ok || !strings.Contains(f.Why, itermTm) || !strings.Contains(f.Why, itermApp) {
		t.Fatalf("the new pin must be the loosening shown (team and bundle), got %+v\n%s", f, findingsText(r.Diff))
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("staging must not pin")
	}
	if len(pe.s.Active().SSHAgent.Keys["github"].Rules) != 1 {
		t.Fatal("the block rule must not be active before the gate")
	}
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if team, ok := pe.pin(itermID); !ok || team != itermTm {
		t.Fatalf("approval must record the pin shown, got %q %v", team, ok)
	}
	if len(pe.s.Active().SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatal("the approved change must be active")
	}
}

// Without a pin store and resolver (Open), nothing is ever pinned and the
// behaviour of the stager is unchanged.
func TestOpenWithoutTrustNeverPins(t *testing.T) {
	s, _, _ := open(t)
	r := s.Observe(src(base))
	if !r.Staged || len(r.Diff.Pins) != 0 {
		t.Fatalf("got %+v", r)
	}
}

// --- nazar trust --app <bundle id> ---------------------------------------

func trustEnv(t *testing.T) (*fake.Fake, *fake.Vault, *trust.Store) {
	t.Helper()
	f := fake.New(t0)
	v := fake.NewVault()
	st, err := trust.Open(v)
	if err != nil {
		t.Fatal(err)
	}
	return f, v, st
}

func TestTrustAppPinsTheInstalledAppBehindTheGate(t *testing.T) {
	f, v, st := trustEnv(t)
	f.InstallApp(itermApp, itermID, fake.ITermCode)
	var shown []PinChange
	approve := func(c PinChange) (bool, error) { shown = append(shown, c); return true, nil }
	c, err := TrustApp(itermID, st, f, approve)
	if err != nil {
		t.Fatal(err)
	}
	want := PinChange{BundleID: itermID, Team: itermTm, Path: itermApp}
	if c != want || len(shown) != 1 || shown[0] != want {
		t.Fatalf("got %+v, shown %+v; want %+v", c, shown, want)
	}
	st2, _ := trust.Open(v)
	if team, _ := st2.PinnedTeam(itermID); team != itermTm {
		t.Fatalf("pin not persisted: %q", team)
	}
}

func TestTrustAppDeniedOrFailedPinsNothing(t *testing.T) {
	f, _, st := trustEnv(t)
	f.InstallApp(itermApp, itermID, fake.ITermCode)
	if _, err := TrustApp(itermID, st, f, func(PinChange) (bool, error) { return false, nil }); err == nil {
		t.Fatal("a denied trust must be reported as not done")
	}
	boom := errors.New("gate timed out")
	if _, err := TrustApp(itermID, st, f, func(PinChange) (bool, error) { return true, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := st.PinnedTeam(itermID); ok {
		t.Fatal("pinned without passing the gate")
	}
}

// The re-pin path after an app update that changed team: the prompt shows
// the old and the new team, and only an approval replaces the pin.
func TestTrustAppRepinsAfterTeamChange(t *testing.T) {
	f, _, st := trustEnv(t)
	st.Pin(itermID, itermTm)
	f.InstallApp(itermApp, itermID, newTeamCode)
	var shown PinChange
	if _, err := TrustApp(itermID, st, f, func(c PinChange) (bool, error) { shown = c; return false, nil }); err == nil {
		t.Fatal("denied must be an error")
	}
	if shown.Old != itermTm || shown.Team != "NEWTEAM000" || shown.Path != itermApp {
		t.Fatalf("prompt must show old and new team: %+v", shown)
	}
	if team, _ := st.PinnedTeam(itermID); team != itermTm {
		t.Fatalf("denied re-pin changed the pin to %q", team)
	}
	if _, err := TrustApp(itermID, st, f, func(PinChange) (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	if team, _ := st.PinnedTeam(itermID); team != "NEWTEAM000" {
		t.Fatalf("approved re-pin not recorded: %q", team)
	}
}

// The gate is never shown for something that can't be pinned.
func TestTrustAppRefusesWhatCantBePinned(t *testing.T) {
	cases := map[string]struct {
		install func(f *fake.Fake)
		is      error
	}{
		"not installed": {func(*fake.Fake) {}, platform.ErrNotFound},
		"ambiguous": {func(f *fake.Fake) {
			f.InstallApp(itermApp, itermID, fake.ITermCode)
			f.InstallApp("/Users/u/Applications/iTerm.app", itermID, evilCode)
		}, platform.ErrAmbiguous},
		"adhoc": {func(f *fake.Fake) {
			f.InstallApp(itermApp, itermID, platform.CodeIdentity{Signed: true, AdHoc: true, TeamID: itermTm, SigningID: itermID})
		}, nil},
		"unsigned": {func(f *fake.Fake) {
			f.InstallApp(itermApp, itermID, platform.CodeIdentity{TeamID: itermTm, SigningID: itermID})
		}, nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f, _, st := trustEnv(t)
			tc.install(f)
			asked := false
			_, err := TrustApp(itermID, st, f, func(PinChange) (bool, error) { asked = true; return true, nil })
			if err == nil {
				t.Fatal("must fail")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
			if asked {
				t.Fatal("the gate must not be shown for an app that can't be pinned")
			}
			if _, ok := st.PinnedTeam(itermID); ok {
				t.Fatal("pinned anyway")
			}
		})
	}
}

// TOCTOU on `nazar trust --app`: the bundle is swapped while the prompt is
// open; the pin written is the one the user approved.
func TestTrustAppPinsWhatWasShown(t *testing.T) {
	f, _, st := trustEnv(t)
	f.InstallApp(itermApp, itermID, fake.ITermCode)
	_, err := TrustApp(itermID, st, f, func(PinChange) (bool, error) {
		f.InstallApp(itermApp, itermID, evilCode)
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if team, _ := st.PinnedTeam(itermID); team != itermTm {
		t.Fatalf("BYPASS: pinned %q, not the approved team", team)
	}
}

// The trust store and the fake satisfy the seams.
var (
	_ PinStore    = (*trust.Store)(nil)
	_ AppResolver = (*fake.Fake)(nil)
)

// Attack: the user-facing strings are forgeable. The
// attacker, as the user, names directories under ~/Applications, which is
// where InstalledApp looks; a bundle path (or a team, pin or bundle id)
// carrying a newline, a carriage return, a terminal escape or a bidi
// override could write a second, legitimate-looking pin line into the
// approval diff, overwrite the real line in a terminal, or reverse how it
// reads. Every untrusted value must be quoted ASCII-only: no raw control
// character or non-ASCII rune may reach a Changes entry, a Finding, an
// AppProblem reason or a TrustApp error, and a crafted path must not add a
// pin line.
func TestApprovalStringsQuoteUntrustedValues(t *testing.T) {
	forged := "app:" + itermID + ": team " + itermTm + " pinned from " + itermApp
	evilPath := "/Users/u/Applications/x\n" + forged + "\r\x1b[2K‮.app"
	evilTeam := "EVIL\nTEAM0"
	evil := platform.CodeIdentity{Signed: true, TeamID: evilTeam, SigningID: itermID, CDHash: []byte{0xee}}

	clean := func(t *testing.T, what, s string) {
		t.Helper()
		for _, r := range s {
			if r < 0x20 || r == 0x7f || r > 0x7e {
				t.Fatalf("FORGEABLE: %s carries the raw rune %U: %q", what, r, s)
			}
		}
	}
	// Entries carry no raw newline (clean), so each is one line of the
	// rendered diff: a pin line is an entry that starts with "app:".
	pinLines := func(ss []string) (n int) {
		for _, s := range ss {
			if strings.HasPrefix(s, "app:") {
				n++
			}
		}
		return n
	}

	// 1. The staged diff of a new pin.
	pe := openPinning(t)
	pe.f.InstallApp(evilPath, itermID, evil)
	r := pe.s.Observe(src(base))
	if !r.Staged {
		t.Fatalf("must be staged: %+v", r)
	}
	if p, ok := pinFor(r.Diff, itermID); !ok || p.Path != evilPath || p.Team != evilTeam {
		t.Fatalf("PinChange keeps the raw values for the store, got %+v", p)
	}
	for _, c := range r.Diff.Changes {
		clean(t, "Changes entry", c)
	}
	if n := pinLines(r.Diff.Changes); n != 1 {
		t.Fatalf("FORGEABLE: %d pin lines in the diff for one pin: %q", n, r.Diff.Changes)
	}
	f, ok := findingFor(r.Diff, appTarget(itermID))
	if !ok {
		t.Fatalf("finding %q missing: %s", appTarget(itermID), findingsText(r.Diff))
	}
	for _, f := range r.Diff.Loosening {
		clean(t, "Finding.Target", f.Target)
		clean(t, "Finding.Why", f.Why)
	}
	if !strings.Contains(f.Why, strconv.QuoteToASCII(evilPath)) || !strings.Contains(f.Why, strconv.QuoteToASCII(evilTeam)) {
		t.Fatalf("the finding must show the quoted path and team: %q", f.Why)
	}
	for _, line := range strings.Split(strings.Join(r.Diff.Changes, "\n")+"\n"+findingsText(r.Diff), "\n") {
		if line == forged || strings.HasPrefix(line, "app:"+itermID+":") {
			t.Fatalf("FORGEABLE: the forged line reads as a real one: %q", line)
		}
	}

	// 2. AppProblems, on an active config whose app: matcher has no pin:
	// not pinned yet, then unsigned, then a resolver error; then, pinned,
	// a team mismatch. Every reason is quoted.
	pe2 := openPinning(t)
	pe2.s.Observe(src(base))
	pe2.s.Approve("", yes) // nothing installed: nothing pinned
	check := func(t *testing.T, pe *pinEnv, want ...string) {
		t.Helper()
		p, ok := problemFor(AppProblems(pe.s.Active(), pe.store, pe.f), itermID)
		if !ok {
			t.Fatal("must be reported")
		}
		clean(t, "AppProblem.Reason", p.Reason)
		clean(t, "AppProblem.Fix", p.Fix)
		for _, w := range want {
			if !strings.Contains(p.Reason, w) {
				t.Fatalf("reason %q must carry %q", p.Reason, w)
			}
		}
	}
	pe2.f.InstallApp(evilPath, itermID, evil)
	check(t, pe2, "not pinned yet", strconv.QuoteToASCII(evilPath), strconv.QuoteToASCII(evilTeam))
	pe2.f.InstallApp(evilPath, itermID, platform.CodeIdentity{SigningID: itermID})
	check(t, pe2, "not validly signed", strconv.QuoteToASCII(evilPath))
	boom := errors.New("codesign: " + forged + "\n" + forged)
	pe2.f.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, boom }
	check(t, pe2, "could not be checked", strconv.QuoteToASCII(boom.Error()))
	pe2.f.InstalledAppFunc = nil
	// pe approved the evil pin above (the user chose to); the installed app
	// then changes to the real team, so the pin no longer matches.
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if team, _ := pe.pin(itermID); team != evilTeam {
		t.Fatalf("the raw team is what gets pinned, got %q", team)
	}
	pe.f.InstallApp(evilPath, itermID, fake.ITermCode)
	check(t, pe, "does not match", strconv.QuoteToASCII(evilPath), strconv.QuoteToASCII(evilTeam), itermTm)

	// 3. TrustApp's errors: an unsigned bundle at the evil path, and a
	// bundle id (from the config file) that is itself crafted.
	tf, _, st := trustEnv(t)
	tf.InstallApp(evilPath, itermID, platform.CodeIdentity{SigningID: itermID})
	_, err := TrustApp(itermID, st, tf, func(PinChange) (bool, error) { return true, nil })
	if err == nil || !strings.Contains(err.Error(), strconv.QuoteToASCII(evilPath)) {
		t.Fatalf("err = %v", err)
	}
	clean(t, "TrustApp error", err.Error())
	evilID := "com.x\n" + forged
	_, err = TrustApp(evilID, st, tf, func(PinChange) (bool, error) { return true, nil })
	if err == nil || !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), strconv.QuoteToASCII(evilID)) {
		t.Fatalf("err = %v", err)
	}
	clean(t, "TrustApp error", err.Error())
}

// The fix is a shell command: a plain bundle id is bare, any other is
// single-quoted so it is one word, whatever it carries.
func TestFixTrustAppIsOneShellWord(t *testing.T) {
	if got := FixTrustApp(itermID); got != "nazar trust --app "+itermID {
		t.Fatalf("got %q", got)
	}
	if got, want := FixTrustApp("com.x y'z"), `nazar trust --app 'com.x y'\''z'`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := FixTrustApp(""), "nazar trust --app ''"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// `nazar ssh-key create` shows its change on the login gate before
// writing the file. Preview classifies the bytes against the active config
// exactly as Observe would, pins included, and stages nothing; the
// ApplyAuthenticated that follows the gate records exactly the pins
// previewed, as Approve records the pins shown.
func TestPreviewShowsPinsAndStagesNothing(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	p, err := pe.s.Preview(src(base))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Diff.Loosens() || p.Config == nil || p.Config.Hash == "" {
		t.Fatalf("preview of a loosening: %+v", p.Diff)
	}
	pin, ok := pinFor(p.Diff, itermID)
	if !ok || pin.Team != itermTm || pin.Path != itermApp {
		t.Fatalf("preview must show the pin an approval records, got %+v", p.Diff.Pins)
	}
	if _, ok := findingFor(p.Diff, appTarget(itermID)); !ok {
		t.Fatalf("the pin is a loosening the prompt shows:\n%s", findingsText(p.Diff))
	}
	if _, staged := pe.s.Pending(); staged {
		t.Fatal("Preview must stage nothing")
	}
	if _, ok := pe.pin(itermID); ok {
		t.Fatal("Preview must pin nothing")
	}
	if len(pe.s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("Preview must apply nothing")
	}
	if err := pe.s.ApplyAuthenticated(p); err != nil {
		t.Fatal(err)
	}
	if team, ok := pe.pin(itermID); !ok || team != itermTm {
		t.Fatalf("ApplyAuthenticated must record the pins previewed, got %q %v", team, ok)
	}
	if len(pe.s.Active().SSHAgent.Keys) != 1 {
		t.Fatal("not applied")
	}
	// A pin that appeared meanwhile for another team is not what was
	// approved: nothing applies (first writer wins, as Approve).
	pe2 := openPinning(t)
	pe2.f.InstallApp(itermApp, itermID, fake.ITermCode)
	p2 := mustPreview(t, pe2.s, src(base))
	if _, err := pe2.store.Pin(itermID, "EVILTEAM00"); err != nil {
		t.Fatal(err)
	}
	if err := pe2.s.ApplyAuthenticated(p2); !errors.Is(err, ErrStale) || len(pe2.s.Active().SSHAgent.Keys) != 0 {
		t.Fatalf("a pin of another team must make the apply stale, got %v", err)
	}
}
