package testd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

func TestScenarioFollowsScriptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script.json")
	f := fake.New(time.Now())
	New(f, path)
	r := &caller.Resolver{P: f}
	if c := r.ResolveFD(3); c.App.BundleID != "com.googlecode.iterm2" {
		t.Fatalf("default chain: %+v", c.App)
	}
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); err == nil {
		t.Fatal("default auth must deny")
	}
	os.WriteFile(path, []byte(`{"chain":"unknown","auth":"allow","confirm":"allow"}`), 0o600)
	if c := r.ResolveFD(3); !c.Unknown {
		t.Fatal("chain not re-read")
	}
	if _, err := f.Authenticate(platform.AuthUserPresence, platform.Prompt{}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.Confirm(platform.Prompt{}); !ok {
		t.Fatal("confirm not re-read")
	}
	a, b := r.ResolveFD(3), r.ResolveFD(4)
	if a.Procs[0].Ref != b.Procs[0].Ref {
		t.Fatal("the same chain name must give the same peer")
	}
}

// app: team pins come from the INSTALLED app at config approval, so
// the apps of the scripted chains are installed with their real teams:
// integration tests that approve a config with `app: com.googlecode.iterm2`
// get a working matcher, as on a typical Mac.
func TestScenarioInstallsChainApps(t *testing.T) {
	f := fake.New(time.Now())
	New(f, filepath.Join(t.TempDir(), "script.json"))
	b, err := f.InstalledApp("com.googlecode.iterm2")
	if err != nil || b.Code.Team() != fake.ITermCode.Team() {
		t.Fatalf("iTerm2 must be installed with its team: %+v %v", b, err)
	}
	r := &caller.Resolver{P: f}
	if c := r.ResolveFD(3); c.App.Code.Team() != b.Code.Team() {
		t.Fatalf("the running iTerm2 (%q) and the installed one (%q) must agree", c.App.Code.Team(), b.Code.Team())
	}
}
