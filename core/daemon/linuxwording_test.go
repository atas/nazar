package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The daemon on a platform that describes itself as Linux: the same fake,
// with Linux's traits. Portable: these run on every OS.

type linuxFake struct{ *fake.Fake }

func (linuxFake) Traits() platform.Traits { return platform.LinuxTraits }

func onLinux(f *fake.Fake, o *Options) { o.Platform = linuxFake{f} }

func onLinuxWithClock(f *fake.Fake, o *Options) { onLinux(f, o); withClock(f, o) }

// An always-ask key on Linux is guarded by nazar, not by a chip, and the
// refusal of a looser rule says so.
func TestLinuxAlwaysAskRefusalSaysNazar(t *testing.T) {
	e := startWith(t, onLinuxWithClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github", "alwaysAsk": "true"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	lines := e.f.Shown()[0].Prompt.Lines
	if last, want := lines[len(lines)-1], "your password on every use, enforced by nazar: this key can never get a session, dialog or no-prompt rule"; last != want {
		t.Errorf("the create prompt's last line is %q, want %q", last, want)
	}
	e.f.Advance(2 * time.Minute)
	before := e.readConfig(t)
	_, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("any"), "gate": "dialog"})
	want := `SSH key "github" asks on every use (enforced by nazar); create another key for a looser rule (nothing was changed)`
	if p == nil || p.ExitCode() != control.ExitError || p.Message != want {
		t.Fatalf("want %q, got %+v", want, p)
	}
	if e.readConfig(t) != before {
		t.Fatal("config.yaml was written")
	}
}

const linuxApproved = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: dialog
`

// A config.yaml with a signed: matcher is invalid on Linux: config check
// says why, and the approved config stays in force.
func TestLinuxConfigWithSignedIsInvalid(t *testing.T) {
	e := startWith(t, onLinux)
	e.approved(t, linuxApproved)
	active := e.d.stager.Active().Hash
	e.writeConfig(t, strings.Replace(linuxApproved, "{app: com.googlecode.iterm2}", "{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}", 1))
	var res control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &res); err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatalf("a signed: matcher must be invalid on Linux: %+v", res)
	}
	found := false
	for _, p := range res.Problems {
		if p.Message == "signed: needs macOS code signatures; on Linux name the program's file with path: or a desktop app with app:" {
			found = p.Severity == string(config.SevError) && p.Path == "apps.iterm"
		}
	}
	if !found {
		t.Fatalf("no error for signed: at apps.iterm: %+v", res.Problems)
	}
	if got := e.d.stager.Active().Hash; got != active || res.ActiveHash != active {
		t.Fatalf("active config changed: %s (reply %s), want %s", got, res.ActiveHash, active)
	}
	if _, pending := e.d.stager.Pending(); pending {
		t.Fatal("an invalid config must not be staged")
	}
}

// `nazar trust --app` for an app whose entry exists but can never be
// matched (on Linux: it runs a launcher or a script) says why, in the
// platform's words, instead of "no app with this app id is installed";
// no prompt is shown and nothing is pinned. The bare ErrNotFound and
// ErrAmbiguous are worded for Linux (an app id, an executable), as config
// check words them; macOS keeps its words.
func TestLinuxTrustAppSaysWhy(t *testing.T) {
	e := startWith(t, onLinux)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	const why = `its program "/usr/bin/flatpak" is a shell, interpreter or launcher that starts some other program, so no process can match app:"org.x.Y"`
	e.f.InstalledAppFunc = func(string) (platform.AppBundle, error) {
		return platform.AppBundle{}, &platform.NotFoundError{Reason: why}
	}
	shown := len(e.f.Shown())
	_, p := e.trustApp(t, "org.x.Y")
	if want := `app "org.x.Y" can't be pinned: ` + why; p == nil || p.ExitCode() != control.ExitError || p.Message != want {
		t.Fatalf("want exit %d %q, got %+v", control.ExitError, want, p)
	}
	if len(e.f.Shown()) != shown {
		t.Fatal("an app that can't be pinned must be refused before any prompt")
	}
	if pins := e.status(t).Pins; len(pins) != 0 {
		t.Fatalf("nothing may be pinned: %v", pins)
	}
	e.f.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, platform.ErrNotFound }
	if _, p := e.trustApp(t, "org.x.Y"); p == nil || p.Message != `app "org.x.Y" can't be pinned: no app with this app id is installed` {
		t.Fatalf("bare ErrNotFound on Linux: %+v", p)
	}
	e.f.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, platform.ErrAmbiguous }
	if _, p := e.trustApp(t, "org.x.Y"); p == nil || p.Message != `app "org.x.Y" can't be pinned: several installed apps have this app id, with different executables` {
		t.Fatalf("ErrAmbiguous on Linux: %+v", p)
	}
	// macOS keeps its words.
	mac := startWith(t, nil)
	mac.f.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, platform.ErrNotFound }
	if _, p := mac.trustApp(t, "org.x.Y"); p == nil || p.Message != `app "org.x.Y" can't be pinned: no app with this bundle id is installed` {
		t.Fatalf("bare ErrNotFound on macOS: %+v", p)
	}
	mac.f.InstalledAppFunc = func(string) (platform.AppBundle, error) { return platform.AppBundle{}, platform.ErrAmbiguous }
	if _, p := mac.trustApp(t, "org.x.Y"); p == nil || p.Message != `app "org.x.Y" can't be pinned: several installed apps have this bundle id and they are signed by different teams` {
		t.Fatalf("ErrAmbiguous on macOS: %+v", p)
	}
}

// pinMismatch approves a config with app: iterm (pinning iTerm2's team from
// the installed app), then asks the daemon's evaluator about a tab of an
// iTerm2 whose identity changed, and returns the match: lines it logged.
func pinMismatch(t *testing.T, mod func(f *fake.Fake, o *Options)) []string {
	t.Helper()
	logs := &logBuf{}
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Logf = logs.Printf
		if mod != nil {
			mod(f, o)
		}
	})
	e.approved(t, linuxApproved)
	updated := fake.ITermCode
	updated.TeamID = "NEWTEAM000"
	app := e.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: updated,
		App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	tab := e.f.ITermTab(app, fake.SSHProc("h"))
	m, ok := e.d.stager.Active().Apps["iterm"]
	if !ok {
		t.Fatal("the approved config has no app iterm")
	}
	if e.d.eval.Apps([]config.Matcher{m}, e.d.resolver.Resolve(tab.Peer())) {
		t.Fatal("an app whose identity changed must not match the old pin")
	}
	var out []string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.HasPrefix(l, "match: ") {
			out = append(out, strings.TrimPrefix(l, "match: "))
		}
	}
	return out
}

// On Linux the pin is the executable's hash, and a mismatch names the fix:
// a package upgrade replaces the file, and nazar trust --app pins the new
// one once the user knows why it changed.
func TestLinuxPinMismatchNote(t *testing.T) {
	linux := pinMismatch(t, onLinux)
	want := "app com.googlecode.iterm2 has executable hash NEWTEAM000 but H7V7XYVQ7D is pinned; not matching; run nazar trust --app com.googlecode.iterm2 once you know why it changed"
	if !containsLine(linux, want) {
		t.Errorf("Linux notes %q, want %q", linux, want)
	}
	mac := pinMismatch(t, nil)
	want = "app com.googlecode.iterm2 has team NEWTEAM000 but H7V7XYVQ7D is pinned; not matching"
	if !containsLine(mac, want) {
		t.Errorf("macOS notes %q, want exactly %q", mac, want)
	}
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

type stubPipes struct {
	ok  bool
	err error
}

func (s stubPipes) StdoutReadBy(_, _ platform.ProcessRef) (bool, error) { return s.ok, s.err }

// On Linux a stdout check that could not tell (a process whose fds can't be
// read started after the plugin) says so and says to try again: nothing
// wrapped the plugin. A client that is gone, a plain no, and every error on
// macOS keep the refusal.
func TestLinuxStdoutCheckUnknownSaysTryAgain(t *testing.T) {
	chain := &caller.Chain{Procs: []platform.ProcessInfo{
		{Ref: platform.ProcessRef{PID: 20, Generation: 2}},
		{Ref: platform.ProcessRef{PID: 10, Generation: 1}},
	}}
	cannotTell := errors.New("pipes: cannot tell who holds the pipe: process 7 started after the program that asked and its fds cannot be read")
	for _, tc := range []struct {
		name     string
		traits   platform.Traits
		ok       bool
		err      error
		k8s, aws string
	}{
		{"Linux, can't tell", platform.LinuxTraits, false, cannotTell, "can't tell who reads the plugin's output; try again", "can't tell who reads the credential's output; try again"},
		{"Linux, the client exited", platform.LinuxTraits, false, platform.ErrNoProcess, errStdout, errAWSStdout},
		{"Linux, a plain no", platform.LinuxTraits, false, nil, errStdout, errAWSStdout},
		{"Linux, yes", platform.LinuxTraits, true, nil, "", ""},
		{"macOS, can't tell", platform.MacTraits, false, errors.New("proc_pidfdinfo: EPERM"), errStdout, errAWSStdout},
		{"macOS, the client exited", platform.MacTraits, false, platform.ErrNoProcess, errStdout, errAWSStdout},
		{"macOS, yes", platform.MacTraits, true, nil, "", ""},
	} {
		d := &Daemon{o: Options{Pipes: stubPipes{tc.ok, tc.err}, Logf: func(string, ...any) {}}, traits: tc.traits}
		if got := d.k8sStdout(chain); got != tc.k8s {
			t.Errorf("%s: k8sStdout = %q, want %q", tc.name, got, tc.k8s)
		}
		if got := d.awsStdout(chain); got != tc.aws {
			t.Errorf("%s: awsStdout = %q, want %q", tc.name, got, tc.aws)
		}
	}
}

// On Linux a delete prompt never says the key or CA is destroyed: nazar
// deletes its file, and an earlier copy of the vault folder still works on
// the same TPM. macOS keeps its line word for word.
func TestLinuxDeletePromptPromisesNothing(t *testing.T) {
	mac := "The key is destroyed in the Secure Enclave. This can't be undone."
	if got := (&Daemon{traits: platform.MacTraits}).deleted(mac, "key"); got != mac {
		t.Errorf("macOS: %q", got)
	}
	got := (&Daemon{traits: platform.LinuxTraits}).deleted(mac, "key")
	if strings.Contains(got, "destroyed") || strings.Contains(got, "undone") || !strings.Contains(got, "backup") || !strings.Contains(got, "~/.nazar/vault") {
		t.Errorf("Linux: %q", got)
	}
}

// The remedy names the file the vault really uses: hex of the name, or
// the sha256 of a name too long for a file name (vault.stem).
func TestItemFileMatchesTheVaultsName(t *testing.T) {
	if got := itemFile("ab"); got != "~/.nazar/vault/6162.item" {
		t.Errorf("short name: %q", got)
	}
	atLimit, over := strings.Repeat("a", 116), strings.Repeat("a", 117)
	if got := itemFile(atLimit); got != "~/.nazar/vault/"+strings.Repeat("61", 116)+".item" {
		t.Errorf("116 bytes is still hex: %q", got)
	}
	// sha256 of 117 "a"s, in hex.
	if got := itemFile(over); len(got) != len("~/.nazar/vault/")+64+len(".item") {
		t.Errorf("a long name is filed by its sha256: %q", got)
	}
}
