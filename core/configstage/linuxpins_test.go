package configstage

import (
	"errors"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/trust"
)

// On Linux an app: pin records the hash of the app's executable, not a
// signing team (spec "app: on Linux"): every pin text says so, and the
// approval names the fix for the hash an update changes. Portable: these
// run on every OS, with the fake describing itself as Linux.

// linuxApps is the fake platform describing itself as Linux.
type linuxApps struct{ *fake.Fake }

func (linuxApps) Traits() platform.Traits { return platform.LinuxTraits }

const (
	termID   = "org.gnome.Terminal"
	termExe  = "/usr/bin/gnome-terminal"
	termHash = "sha256:0a0b"
)

var (
	termCode    = platform.CodeIdentity{Signed: true, TeamID: termHash, SigningID: termID}
	termUpdated = platform.CodeIdentity{Signed: true, TeamID: "sha256:0c0d", SigningID: termID}
	linuxEnv    = config.Env{Home: "/home/u", NoCodeSigning: true}
)

const linuxSrc = `apiVersion: nazar/v1
kind: Config
apps:
  term: {app: org.gnome.Terminal}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [term]
          scope: session
          gate: login
`

// openLinuxPinning is openPinning on the Linux-described fake.
func openLinuxPinning(t *testing.T) (*Stager, linuxApps, *trust.Store) {
	t.Helper()
	apps := linuxApps{fake.New(t0)}
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithTrust(linuxEnv, fake.NewVault(), st, apps, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, apps, st
}

func hasString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// The approval prompt of a config change shows the executable and its
// hash, and that an update needs nazar trust --app; never a team or a
// signer.
func TestLinuxStagedPinWording(t *testing.T) {
	s, apps, st := openLinuxPinning(t)
	apps.InstallApp(termExe, termID, termCode)
	r := s.Observe([]byte(linuxSrc))
	if !r.Staged {
		t.Fatalf("adding rules must be staged: %+v", r)
	}
	want := `app:"org.gnome.Terminal": executable hash "sha256:0a0b" pinned from "/usr/bin/gnome-terminal"`
	if !hasString(r.Diff.Changes, want) {
		t.Errorf("changes %q, want %q", r.Diff.Changes, want)
	}
	f, ok := findingFor(r.Diff, appTarget(termID))
	wantWhy := `trusts the executable at "/usr/bin/gnome-terminal" (hash "sha256:0a0b") as this app from now on; ` +
		"an update of the app changes the hash, and then `nazar trust --app org.gnome.Terminal` pins the new one"
	if !ok || f.Why != wantWhy {
		t.Errorf("finding %+v, want %q", f, wantWhy)
	}
	if ok, err := s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if got, _ := st.PinnedTeam(termID); got != termHash {
		t.Fatalf("pinned %q", got)
	}
}

// macOS keeps its words: a team, the signer of the installed app.
func TestMacStagedPinWording(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	r := pe.s.Observe(src(base))
	want := `app:"com.googlecode.iterm2": team "H7V7XYVQ7D" pinned from "/Applications/iTerm.app"`
	if !hasString(r.Diff.Changes, want) {
		t.Errorf("changes %q, want %q", r.Diff.Changes, want)
	}
	f, _ := findingFor(r.Diff, appTarget(itermID))
	if wantWhy := `trusts team "H7V7XYVQ7D", the signer of the installed app at "/Applications/iTerm.app", as this app from now on`; f.Why != wantWhy {
		t.Errorf("finding %q, want %q", f.Why, wantWhy)
	}
}

// nazar apps list on Linux: an unpinned, a changed and a missing app are
// worded by executable and hash, each with the trust --app fix.
func TestLinuxAppProblemsWording(t *testing.T) {
	c, probs := config.Parse([]byte(linuxSrc), linuxEnv)
	if c == nil {
		t.Fatal(probs.Error())
	}
	apps := linuxApps{fake.New(t0)}
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	reason := func() string {
		t.Helper()
		p, ok := problemFor(AppProblems(c, st, apps), termID)
		if !ok || p.Fix != "nazar trust --app org.gnome.Terminal" {
			t.Fatalf("no problem with the fix: %+v", p)
		}
		return p.Reason
	}
	if got, want := reason(), "no app with this app id is installed; the matcher matches nothing"; got != want {
		t.Errorf("missing: %q, want %q", got, want)
	}
	apps.InstallApp(termExe, termID, termCode)
	if got, want := reason(), `executable hash "sha256:0a0b" of the installed app at "/usr/bin/gnome-terminal" is not pinned yet, so the matcher matches nothing`; got != want {
		t.Errorf("unpinned: %q, want %q", got, want)
	}
	if _, err := st.Pin(termID, termHash); err != nil {
		t.Fatal(err)
	}
	if _, ok := problemFor(AppProblems(c, st, apps), termID); ok {
		t.Fatal("a matching pin is no problem")
	}
	apps.UninstallApp(termExe)
	apps.InstallApp(termExe, termID, termUpdated)
	want := `the installed app's executable at "/usr/bin/gnome-terminal" has hash "sha256:0c0d" but "sha256:0a0b" is pinned, so it does not match ` +
		"(an update of the app replaces its executable; find out why it changed before you run the fix)"
	if got := reason(); got != want {
		t.Errorf("changed: %q, want %q", got, want)
	}
	apps.InstallApp("/opt/term/gnome-terminal", termID, termCode)
	if st, err = trust.Open(fake.NewVault()); err != nil { // no pin yet
		t.Fatal(err)
	}
	if got, want := reason(), "several installed apps have this app id, with different executables; the matcher matches nothing"; got != want {
		t.Errorf("ambiguous: %q, want %q", got, want)
	}
}

// The macOS mismatch keeps its words.
func TestMacAppProblemMismatchWording(t *testing.T) {
	pe := openPinning(t)
	pe.f.InstallApp(itermApp, itermID, fake.ITermCode)
	pe.s.Observe(src(base))
	if ok, err := pe.s.Approve("", yes); !ok || err != nil {
		t.Fatal(ok, err)
	}
	pe.f.UninstallApp(itermApp)
	pe.f.InstallApp(itermApp, itermID, newTeamCode)
	p, _ := problemFor(AppProblems(pe.s.Active(), pe.store, pe.f), itermID)
	if want := `the installed app at "/Applications/iTerm.app" is signed by team "NEWTEAM000" but "H7V7XYVQ7D" is pinned, so it does not match`; p.Reason != want {
		t.Errorf("%q, want %q", p.Reason, want)
	}
}

// A pin that appeared while the prompt was open names what it is.
func TestRecordPinsStaleWording(t *testing.T) {
	for _, tc := range []struct {
		w    pinWords
		want string
	}{
		{pinWords{}, `configstage: the staged change is no longer what the file says: app "org.gnome.Terminal" is now pinned to team "sha256:0c0d", not the "sha256:0a0b" that was approved`},
		{pinWords{hash: true}, `configstage: the staged change is no longer what the file says: app "org.gnome.Terminal" is now pinned to executable hash "sha256:0c0d", not the "sha256:0a0b" that was approved`},
	} {
		st, err := trust.Open(fake.NewVault())
		if err != nil {
			t.Fatal(err)
		}
		st.Pin(termID, "sha256:0c0d")
		err = recordPins(st, tc.w, []PinChange{{BundleID: termID, Team: termHash, Path: termExe}})
		if !errors.Is(err, ErrStale) || err.Error() != tc.want {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
}

// platformNotFound is the shape of the Linux platform's error for an
// entry that is no app: its own text names the platform and the id, and
// it unwraps to a platform.NotFoundError with the bare reason.
type platformNotFound struct{ id, why string }

func (e *platformNotFound) Error() string { return "desktop: " + e.id + ": " + e.why }
func (e *platformNotFound) Unwrap() error { return &platform.NotFoundError{Reason: e.why} }

// An entry that exists but can never be matched (on Linux: it runs a
// launcher or a script, or another id owns its program) is reported with
// the platform's reason, not as "not installed", by config check and by
// trust --app alike, and with no fix: `nazar trust --app` would refuse it
// with the same reason. The error stays ErrNotFound for every other
// caller, and TrustApp's text carries the reason once, not the platform's
// own prefix as well.
func TestLinuxNotFoundReasonShown(t *testing.T) {
	c, probs := config.Parse([]byte(linuxSrc), linuxEnv)
	if c == nil {
		t.Fatal(probs.Error())
	}
	apps := linuxApps{fake.New(t0)}
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	const why = `its program "/usr/bin/flatpak" is a shell, interpreter or launcher that starts some other program, so no process can match app:"org.gnome.Terminal"`
	apps.InstalledAppFunc = func(id string) (platform.AppBundle, error) {
		if id != termID {
			t.Errorf("InstalledApp(%q)", id)
		}
		return platform.AppBundle{}, &platformNotFound{id: id, why: why}
	}
	p, ok := problemFor(AppProblems(c, st, apps), termID)
	if !ok || p.Reason != why+"; the matcher matches nothing" || p.Fix != "" {
		t.Errorf("AppProblems = %+v, %v; want the reason %q and no fix", p, ok, why)
	}
	_, err = TrustApp(termID, st, apps, func(PinChange) (bool, error) { t.Fatal("no prompt"); return false, nil })
	if want := `configstage: app "org.gnome.Terminal" can't be pinned: ` + why; err == nil || err.Error() != want || !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("TrustApp = %v, want %q (and ErrNotFound)", err, want)
	}
	if _, got, unpinnable := resolve(apps, termID); got != why || !unpinnable {
		t.Errorf("resolve: %q, %v", got, unpinnable)
	}
	// The bare ErrNotFound keeps its words: no app is installed.
	apps.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, platform.ErrNotFound }
	if _, got, unpinnable := resolve(apps, termID); got != "no app with this app id is installed" || unpinnable {
		t.Errorf("resolve(bare ErrNotFound): %q, %v", got, unpinnable)
	}
}

// A pinned app whose entry stops being an app (an upgrade turned its
// program into a wrapper script, Terminal=true was set, a user's entry
// under a lower id took its program over) is reported with the platform's
// reason too: the pin cannot help, AppFor never answers the id, so
// without this config check and apps list would be silent about a rule
// that matches nothing.
func TestLinuxPinnedNotFoundReasonShown(t *testing.T) {
	c, probs := config.Parse([]byte(linuxSrc), linuxEnv)
	if c == nil {
		t.Fatal(probs.Error())
	}
	apps := linuxApps{fake.New(t0)}
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	apps.InstallApp(termExe, termID, termCode)
	if _, err := st.Pin(termID, termHash); err != nil {
		t.Fatal(err)
	}
	if p, ok := problemFor(AppProblems(c, st, apps), termID); ok {
		t.Fatalf("a matching pin is no problem: %+v", p)
	}
	const why = `its program "/usr/bin/gnome-terminal" is a script, not a native executable; the process that runs it is its interpreter, so no process can match app:"org.gnome.Terminal"`
	apps.InstalledAppFunc = func(string) (platform.AppBundle, error) {
		return platform.AppBundle{}, &platformNotFound{id: termID, why: why}
	}
	p, ok := problemFor(AppProblems(c, st, apps), termID)
	if !ok || p.Reason != why+"; the matcher matches nothing" || p.Fix != "" {
		t.Errorf("AppProblems(pinned, no longer an app) = %+v, %v; want the reason %q and no fix", p, ok, why)
	}
	// The pin is untouched: only trust --app replaces one.
	if got, _ := st.PinnedTeam(termID); got != termHash {
		t.Errorf("pin = %q, want %q", got, termHash)
	}
}

// What can't be pinned says so in the platform's words.
func TestLinuxUnpinnableWording(t *testing.T) {
	apps := linuxApps{fake.New(t0)}
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	apps.InstallApp(termExe, termID, platform.CodeIdentity{SigningID: termID})
	_, err = TrustApp(termID, st, apps, func(PinChange) (bool, error) { t.Fatal("no prompt"); return false, nil })
	if want := `configstage: app "org.gnome.Terminal" can't be pinned: the executable at "/usr/bin/gnome-terminal" has no hash to pin`; err == nil || err.Error() != want {
		t.Errorf("%v, want %q", err, want)
	}
	if _, why, unpinnable := resolve(apps, termID); why != `the installed app at "/usr/bin/gnome-terminal" has no executable hash to pin` || unpinnable {
		t.Errorf("resolve: %q, %v", why, unpinnable)
	}
}
