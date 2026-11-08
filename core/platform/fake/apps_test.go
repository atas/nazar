package fake

import (
	"errors"
	"sync"
	"testing"

	"github.com/atas/nazar/core/platform"
)

// The fake scripts installed app bundles for Platform.InstalledApp, the
// call config approval and `nazar trust --app` use to pin an app's team
// (spec 4.2). InstallApp puts a bundle at a path (replacing what was there),
// UninstallApp removes it, and InstalledApp resolves a bundle ID:
//   - none installed            → platform.ErrNotFound
//   - every bundle shares a team → one of them (deterministically)
//   - bundles with different teams (CodeIdentity.Team()) → platform.ErrAmbiguous
// InstalledAppFunc, when set, answers instead (error injection).

var evilCode = platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "com.googlecode.iterm2", CDHash: []byte{0xee}}

func TestInstalledAppNotInstalled(t *testing.T) {
	f := New(t0)
	if _, err := f.InstalledApp("com.googlecode.iterm2"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("nothing installed: err = %v, want ErrNotFound", err)
	}
	// A running app is not an installed one: the platform answers from the
	// bundles on disk, not from whatever process claims the bundle ID.
	f.ITermTab(platform.ProcessRef{})
	if _, err := f.InstalledApp("com.googlecode.iterm2"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("running but not installed: err = %v, want ErrNotFound", err)
	}
}

func TestInstalledAppResolvesTheBundle(t *testing.T) {
	f := New(t0)
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
	b, err := f.InstalledApp("com.googlecode.iterm2")
	if err != nil {
		t.Fatal(err)
	}
	if b.BundleID != "com.googlecode.iterm2" || b.Path != "/Applications/iTerm.app" || b.Code.Team() != "H7V7XYVQ7D" {
		t.Fatalf("got %+v", b)
	}
	if _, err := f.InstalledApp("com.todesktop.230313mzl4w4u92"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("other bundle id: err = %v, want ErrNotFound", err)
	}
	// Returned values are copies.
	b.Code.CDHash[0] ^= 0xff
	if b2, _ := f.InstalledApp("com.googlecode.iterm2"); b2.Code.CDHash[0] != ITermCode.CDHash[0] {
		t.Fatal("InstalledApp must return a copy of the code identity")
	}
}

// Two copies with the same team (an old one in ~/Applications) are not
// ambiguous: either one pins the same team.
func TestInstalledAppSameTeamTwiceIsNotAmbiguous(t *testing.T) {
	f := New(t0)
	f.InstallApp("/Users/u/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
	b, err := f.InstalledApp("com.googlecode.iterm2")
	if err != nil || b.Code.Team() != "H7V7XYVQ7D" {
		t.Fatalf("got %+v, %v", b, err)
	}
	for i := 0; i < 5; i++ {
		if b2, _ := f.InstalledApp("com.googlecode.iterm2"); b2.Path != b.Path {
			t.Fatal("the answer must be deterministic")
		}
	}
}

// An impostor bundle copying the bundle ID with another team, installed
// next to the real one (e.g. dropped into ~/Applications, which the user
// can write), makes the bundle ID ambiguous: nothing is resolved.
func TestInstalledAppDifferentTeamsAreAmbiguous(t *testing.T) {
	f := New(t0)
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
	f.InstallApp("/Users/u/Applications/iTerm.app", "com.googlecode.iterm2", evilCode)
	if b, err := f.InstalledApp("com.googlecode.iterm2"); !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("got %+v, %v; want ErrAmbiguous", b, err)
	}
	f.UninstallApp("/Users/u/Applications/iTerm.app")
	if b, err := f.InstalledApp("com.googlecode.iterm2"); err != nil || b.Code.Team() != "H7V7XYVQ7D" {
		t.Fatalf("after removing the impostor: %+v, %v", b, err)
	}
}

// Re-installing at the same path replaces the bundle (an app update that
// changed its signing team).
func TestInstallAppReplacesAndUninstallRemoves(t *testing.T) {
	f := New(t0)
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
	newTeam := ITermCode
	newTeam.TeamID = "NEWTEAM000"
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", newTeam)
	if b, err := f.InstalledApp("com.googlecode.iterm2"); err != nil || b.Code.Team() != "NEWTEAM000" {
		t.Fatalf("after update: %+v, %v", b, err)
	}
	f.UninstallApp("/Applications/iTerm.app")
	if _, err := f.InstalledApp("com.googlecode.iterm2"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("after uninstall: %v", err)
	}
	f.UninstallApp("/Applications/never-installed.app") // no-op
}

func TestInstalledAppFuncOverrides(t *testing.T) {
	f := New(t0)
	f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
	boom := errors.New("launchservices unavailable")
	f.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, boom }
	if _, err := f.InstalledApp("com.googlecode.iterm2"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the scripted error", err)
	}
}

func TestInstalledAppConcurrentUse(t *testing.T) {
	f := New(t0)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			f.InstallApp("/Applications/iTerm.app", "com.googlecode.iterm2", ITermCode)
		}()
		go func() {
			defer wg.Done()
			f.InstalledApp("com.googlecode.iterm2")
		}()
	}
	wg.Wait()
}
