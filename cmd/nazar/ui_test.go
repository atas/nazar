package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

// Milestone 6 (spec 6.1): `nazar ui` opens Nazar UI.app through Launch
// Services by bundle id. It needs no agent and sends no control request.

// uiHarness records what openUI was asked to open and serves a control
// socket that must stay unused.
func uiHarness(t *testing.T, path string, err error) (*harness, *[]string) {
	t.Helper()
	h := newHarness(t)
	var opened []string
	h.a.openUI = func(id string) (string, error) { opened = append(opened, id); return path, err }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	return h, &opened
}

func TestUIOpensNazarUIByBundleID(t *testing.T) {
	h, opened := uiHarness(t, "/Applications/Nazar UI.app", nil)
	if code := h.run("--json", "ui"); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.out, h.errb)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindUI || objs[0]["app"] != "/Applications/Nazar UI.app" || objs[0]["opened"] != true {
		t.Fatalf("stdout %q", h.out)
	}
	if code := h.run("ui"); code != 0 || h.out.String() != "opened /Applications/Nazar UI.app\n" {
		t.Fatalf("human view: exit %d %q", code, h.out)
	}
	if strings.Join(*opened, ",") != "dev.nazar.ui,dev.nazar.ui" {
		t.Fatalf("opened %q", *opened)
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("nazar ui talked to the agent: %+v", r)
	}
}

// Not installed: exit 1 with how to install it (the app is optional), as
// a Problem object under --json.
func TestUINotInstalled(t *testing.T) {
	h, _ := uiHarness(t, "", errUINotInstalled)
	if code := h.run("ui"); code != control.ExitError || !strings.Contains(h.errb.String(), "brew install --cask atas/tap/nazar-ui") {
		t.Fatalf("exit %d %q", code, h.errb)
	}
	if code := h.run("--json", "ui"); code != control.ExitError {
		t.Fatalf("--json: exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindProblem || !strings.Contains(objs[0]["message"].(string), "not installed") {
		t.Fatalf("stdout %q", h.out)
	}
}

// Any other failure is exit 1 with the reason, escaped for the terminal;
// extra arguments are a usage error and open nothing.
func TestUIRefusals(t *testing.T) {
	h, opened := uiHarness(t, "", errors.New("LSOpen failed\x1b[2J"))
	if code := h.run("ui"); code != control.ExitError || !strings.Contains(h.errb.String(), "LSOpen failed") {
		t.Fatalf("exit %d %q", code, h.errb)
	}
	if strings.Contains(h.errb.String(), "\x1b") {
		t.Fatalf("unescaped error text: %q", h.errb)
	}
	*opened = nil
	if code := h.run("ui", "extra"); code != control.ExitUsage || len(*opened) != 0 {
		t.Fatalf("extra argument: exit %d, opened %q", code, *opened)
	}
	h.a.openUI = nil
	if code := h.run("ui"); code != control.ExitError {
		t.Fatalf("no seam: exit %d", code)
	}
}

// The only program the CLI opens through Launch Services is Nazar UI.app,
// by bundle id: /usr/bin/open appears in one source file, as `open -b`.
func TestCLIOpensOnlyNazarUI(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{`exec.Command("open"`, "LSOpen", "NSWorkspace"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q", f, bad)
			}
		}
		n := strings.Count(src, `"/usr/bin/open"`)
		switch {
		case f == "ui_darwin.go" && (n != 1 || !strings.Contains(src, `exec.Command("/usr/bin/open", "-b", id)`)):
			t.Errorf("ui_darwin.go must run /usr/bin/open exactly once, as open -b <bundle id>")
		case f != "ui_darwin.go" && n != 0:
			t.Errorf("%s runs /usr/bin/open", f)
		}
	}
}

// `nazar ui` needs no agent and no bundle: with no control socket at all
// and a CLI outside any nazar bundle (a Homebrew link, a copy), it still
// opens Nazar UI.app, and it reads no LaunchAgent to do it.
func TestUINeedsNoAgent(t *testing.T) {
	h := newHarness(t)
	var opened []string
	h.a.openUI = func(id string) (string, error) { opened = append(opened, id); return "/Applications/Nazar UI.app", nil }
	h.a.executable = func() (string, error) { return filepath.Join(h.home, "bin", "nazar"), nil }
	h.a.plistProgram = func(string) (string, error) {
		t.Fatal("nazar ui read a LaunchAgent")
		return "", nil
	}
	h.env["NAZAR_CONTROL_SOCKET"] = filepath.Join(h.home, "nothing-listens-here.sock")
	if code := h.run("ui"); code != 0 || h.out.String() != "opened /Applications/Nazar UI.app\n" {
		t.Fatalf("exit %d %q %q", code, h.out, h.errb)
	}
	if strings.Join(opened, ",") != uiBundleID || uiBundleID != "dev.nazar.ui" {
		t.Fatalf("opened %q", opened)
	}
}

// The path Launch Services reports is whatever app registered the bundle
// id (THREAT-MODEL 5.13): it is shown escaped for the terminal, and kept
// verbatim (JSON-escaped) under --json.
func TestUIEscapesTheAppPath(t *testing.T) {
	hostile := "/Users/x/Nazar\x1b]8;;http://evil\x07 UI.app\n"
	h, _ := uiHarness(t, hostile, nil)
	if code := h.run("ui"); code != 0 {
		t.Fatalf("exit %d %q", code, h.errb)
	}
	if s := h.out.String(); strings.ContainsAny(s, "\x1b\x07") || strings.Count(s, "\n") != 1 || !strings.HasPrefix(s, "opened ") || !strings.Contains(s, "/Users/x/Nazar") {
		t.Fatalf("unescaped path: %q", s)
	}
	if code := h.run("--json", "ui"); code != 0 {
		t.Fatalf("--json: exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["app"] != hostile {
		t.Fatalf("stdout %q", h.out)
	}
}

// Flags `nazar ui` does not have are usage errors, and open nothing.
func TestUIFlagsAreUsageErrors(t *testing.T) {
	h, opened := uiHarness(t, "/Applications/Nazar UI.app", nil)
	for _, args := range [][]string{{"ui", "--bin-dir", "/tmp"}, {"ui", "-b", "com.example.other"}, {"ui", "--", "dev.nazar.ui"}} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
	if len(*opened) != 0 {
		t.Fatalf("opened %q", *opened)
	}
}
