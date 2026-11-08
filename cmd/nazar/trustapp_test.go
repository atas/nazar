package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// `nazar trust --app <bundle id>` (spec 4.2, 4.8, 6): the fix every
// unpinned or mismatched app: matcher message names
// (configstage.FixTrustApp, core/match notes).

const appID = "com.example.tool"

var appCode = platform.CodeIdentity{Signed: true, TeamID: "TOOLTEAM01", SigningID: appID, CDHash: []byte{0x70}}

func appPinReply(req control.Request, out control.Emitter) {
	switch req.Command {
	case control.CmdTrustApp:
		out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: req.Args["app"], Team: "TOOLTEAM01",
			Path: "/Applications/Tool.app", Changed: true})
	default:
		replyFor(req, out)
	}
}

func TestTrustAppMapsToControlRequest(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { appPinReply(req, out) })
	for i, args := range [][]string{
		{"--json", "trust", "--app", appID},
		{"--json", "trust", "--app=" + appID},
		{"trust", "--json", "--app", appID},
	} {
		if code := h.run(args...); code != control.ExitOK {
			t.Fatalf("%v: exit %d stdout %q stderr %q", args, code, h.out, h.errb)
		}
		reqs := h.requests()
		if len(reqs) != i+1 {
			t.Fatalf("%v: %d requests", args, len(reqs))
		}
		r := reqs[i]
		if r.Command != control.CmdTrustApp || r.APIVersion != control.APIVersion || r.Args["app"] != appID {
			t.Fatalf("%v: request %+v", args, r)
		}
		if _, ok := r.Args["path"]; ok {
			t.Fatalf("%v: --app must not send a path: %+v", args, r.Args)
		}
		objs := jsonLines(t, h.out.String())
		if len(objs) != 1 || objs[0]["kind"] != control.KindAppPin || objs[0]["bundleId"] != appID || objs[0]["team"] != "TOOLTEAM01" {
			t.Fatalf("%v: stdout %q", args, h.out)
		}
	}
	// There is no path form (a path: rule needs no trust, spec 4.2): a
	// usage error decided locally; nothing is sent.
	if code := h.run("trust", "/opt/homebrew/bin/kubectl"); code != control.ExitUsage || !strings.Contains(h.errb.String(), "a path: rule needs no trust") {
		t.Fatalf("trust <path>: exit %d %q", code, h.errb)
	}
	if n := len(h.requests()); n != 3 {
		t.Fatalf("trust <path> reached Nazar.app: %d requests", n)
	}
}

func TestTrustAppHumanOutput(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { appPinReply(req, out) })
	if code := h.run("trust", "--app", appID); code != 0 {
		t.Fatalf("exit %d %q", code, h.errb)
	}
	for _, want := range []string{appID, "TOOLTEAM01"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("human output lacks %q: %q", want, h.out)
		}
	}
}

// Usage errors are decided locally and send nothing.
func TestTrustAppUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { appPinReply(req, out) })
	for _, args := range [][]string{
		{"trust", "--app"},
		{"trust", "--app", ""},
		{"trust", "--app=", "x"},
		{"trust", "--app", appID, "/bin/ls"},
		{"trust", "/bin/ls", "--app", appID},
		{"trust", "--app", appID, "--app", "com.other"},
		{"trust"},
		{"trust", "/bin/ls"},
		{"trust", "bin/kubectl"},
	} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%v: exit %d, want 2 (stderr %q)", args, code, h.errb)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("usage errors reached Nazar.app: %+v", r)
	}
	if code := h.run("--json", "trust", "--app"); code != control.ExitUsage {
		t.Fatal(code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindProblem {
		t.Fatalf("--json usage error: %q", h.out)
	}
}

func TestTrustAppExitCodes(t *testing.T) {
	h := newHarness(t)
	if code := h.run("trust", "--app", appID); code != control.ExitUnavailable {
		t.Fatalf("not running: exit %d", code)
	}
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Args["app"] {
		case "denied":
			out.Emit(control.NewProblem(control.CodeRefused, "not pinned: user denied"))
		default:
			out.Emit(control.NewProblem(control.CodeError, "app %q can't be pinned: not installed", req.Args["app"]))
		}
	})
	if code := h.run("trust", "--app", "denied"); code != control.ExitRefused {
		t.Fatalf("denied: exit %d", code)
	}
	if code := h.run("--json", "trust", "--app", "missing"); code != control.ExitError {
		t.Fatalf("missing: exit %d", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindProblem {
		t.Fatalf("%q", h.out)
	}
}

func TestHelpMentionsTrustApp(t *testing.T) {
	h := newHarness(t)
	h.run("help")
	for _, l := range strings.Split(h.out.String(), "\n") {
		if strings.Contains(l, "trust") && strings.Contains(l, "--app <") {
			return
		}
	}
	t.Fatalf("help lacks `trust --app <bundle id>`:\n%s", h.out)
}

// Hostile reply fields are escaped in the human view.
func TestTrustAppEscapesHostileReply(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: hostile, Team: hostile, OldTeam: hostile, Path: hostile, Changed: true})
	})
	h.run("trust", "--app", appID)
	assertEscaped(t, "trust --app", h, false)
}

// startDaemon runs the real daemon on the fake platform behind the
// harness's control socket, so the CLI is tested end to end.
func startDaemon(t *testing.T, h *harness) (*fake.Fake, *audit.MemorySink) {
	t.Helper()
	f := fake.New(time.Now())
	tab := f.ITermTab(platform.ProcessRef{})
	f.SetDefaultPeer(tab.Peer())
	sink := &audit.MemorySink{}
	// The daemon runs on the fake's clock, so a test can cross the cooldown
	// that follows a denied prompt without sleeping.
	d, err := daemon.New(daemon.Options{Platform: f, Vault: fake.NewVault(), AuditSink: sink, Home: h.home,
		ControlSocket: h.env["NAZAR_CONTROL_SOCKET"], PollInterval: 20 * time.Millisecond, Now: f.Now,
		GateTimeout: func() time.Duration { return 2 * time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(h.env["NAZAR_CONTROL_SOCKET"]); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not listen")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return f, sink
}

// End to end: the CLI against the real daemon with the fake platform.
// The command FixTrustApp prints is run exactly as written.
func TestTrustAppAgainstDaemon(t *testing.T) {
	h := newHarness(t)
	f, _ := startDaemon(t, h)

	// Not installed: exit 1, no prompt.
	if code := h.run("--json", "trust", "--app", appID); code != control.ExitError {
		t.Fatalf("not installed: exit %d %q", code, h.out)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindProblem {
		t.Fatalf("%q", h.out)
	}
	// Ambiguous: two bundles with the id, signed by different teams.
	f.InstallApp("/Applications/Two.app", "com.example.two", appCode)
	f.InstallApp("/Users/u/Applications/Two.app", "com.example.two", platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM9", SigningID: "com.example.two"})
	if code := h.run("trust", "--app", "com.example.two"); code != control.ExitError {
		t.Fatalf("ambiguous: exit %d", code)
	}
	if len(f.Shown()) != 0 {
		t.Fatal("unpinnable apps must be refused before any prompt")
	}

	f.InstallApp("/Applications/Tool.app", appID, appCode)
	// Denied: exit 3.
	if code := h.run("trust", "--app", appID); code != control.ExitRefused {
		t.Fatalf("denied: exit %d %q", code, h.errb)
	}
	// Right after a denial the prompt is not shown again: exit 3 with
	// the cooldown left, and no second prompt.
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if code := h.run("trust", "--app", appID); code != control.ExitRefused || !cooldownLeft.MatchString(h.errb.String()) {
		t.Fatalf("trust --app during the cooldown: exit %d %q", code, h.errb)
	}
	if n := f.CountShown(fake.KindAuthenticate); n != 1 {
		t.Fatalf("trust --app during the cooldown must not prompt: %d login prompts", n)
	}
	f.Advance(daemon.ConfigApplyCooldown)
	// Approved, run exactly as the fix message spells it.
	words := strings.Fields(configstage.FixTrustApp(appID))
	if len(words) < 2 || words[0] != "nazar" {
		t.Fatalf("fix %q", configstage.FixTrustApp(appID))
	}
	if code := h.run(append([]string{"--json"}, words[1:]...)...); code != control.ExitOK {
		t.Fatalf("%v: exit %d %q %q", words, code, h.out, h.errb)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindAppPin || objs[0]["team"] != "TOOLTEAM01" || objs[0]["bundleId"] != appID {
		t.Fatalf("%q", h.out)
	}
	// status shows the pin.
	if code := h.run("--json", "status"); code != 0 {
		t.Fatal(code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || !strings.Contains(h.out.String(), `"`+appID+`":"TOOLTEAM01"`) {
		t.Fatalf("status lacks the pin: %q", h.out)
	}
}
