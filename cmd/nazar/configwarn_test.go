package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

// `nazar config check` shows Nazar.app's problems too (unpinned
// app: matchers, keys whose Secure Enclave policy no longer fits their
// gates), not only what the local parse found. A problem both report is
// shown once. Warnings never change the exit code.

const cleanCfg = "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    hydra:\n      scope: use\n      gate: login\n"

const (
	appProblemMsg = `app: "com.example.tool": team "TOOLTEAM01" of the installed app at "/Applications/Tool.app" is not pinned yet, so the matcher matches nothing; run ` + "`nazar trust --app com.example.tool`"
	keyProblemMsg = `SSH key "hydra" was created with Secure Enclave user presence, but rule 2 (gate dialog) can reach it, so those requests fail; re-create the key without user presence`
)

func cfgPath(h *harness) string { return layout.ConfigFile(h.home) }

// serveCheck answers config check with problems (and staged, if given) for
// the harness's own config file; every other command gets replyFor.
func serveCheck(t *testing.T, h *harness, staged *control.ConfigDiff, problems ...control.ConfigProblem) {
	t.Helper()
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if req.Command != control.CmdConfigCheck {
			replyFor(req, out)
			return
		}
		out.Emit(control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Path: cfgPath(h), Valid: true,
			Problems: append([]control.ConfigProblem{}, problems...), Staged: staged})
	})
}

func jsonCheck(t *testing.T, h *harness) control.ConfigCheck {
	t.Helper()
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindConfigCheck {
		t.Fatalf("want one ConfigCheck object: %s", h.out)
	}
	var c control.ConfigCheck
	if err := json.Unmarshal([]byte(strings.TrimSpace(h.out.String())), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func countMessages(ps []control.ConfigProblem, msg string) int {
	n := 0
	for _, p := range ps {
		if p.Message == msg {
			n++
		}
	}
	return n
}

func TestConfigCheckShowsDaemonProblems(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, cleanCfg)
	serveCheck(t, h, nil,
		control.ConfigProblem{Severity: "warning", Message: appProblemMsg},
		control.ConfigProblem{Severity: "warning", Path: "ssh_agent.keys.hydra", Line: 4, Message: keyProblemMsg},
	)
	if code := h.run("config", "check"); code != control.ExitOK {
		t.Fatalf("warnings never change the exit code: exit %d\n%s", code, h.out)
	}
	out := h.out.String()
	for _, want := range []string{
		"warning: " + appProblemMsg,
		"warning: line 4: ssh_agent.keys.hydra: " + keyProblemMsg,
		"is valid",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config check must print %q:\n%s", want, out)
		}
	}

	if code := h.run("--json", "config", "check"); code != control.ExitOK {
		t.Fatalf("--json: exit %d\n%s", code, h.out)
	}
	c := jsonCheck(t, h)
	if !c.Valid || countMessages(c.Problems, appProblemMsg) != 1 || countMessages(c.Problems, keyProblemMsg) != 1 {
		t.Fatalf("--json must carry Nazar.app's problems once each: %+v", c.Problems)
	}
}

// Nazar.app parses the same file and reports the same parse warnings: they
// are shown once, not twice.
func TestConfigCheckShowsEachProblemOnce(t *testing.T) {
	h := newHarness(t)
	// A rule that can never match only warns.
	body := cleanCfg + "    other:\n      rules:\n        - apps: [any]\n          gate: login\n        - apps: [any]\n          gate: dialog\n"
	writeConfig(t, h, body)
	_, local := config.Parse([]byte(body), config.Env{Home: h.home})
	if len(local) == 0 || local.HasErrors() {
		t.Fatalf("fixture: want local warnings only: %v", local)
	}
	var remote []control.ConfigProblem
	for _, p := range local {
		remote = append(remote, control.ConfigProblem{Severity: string(p.Severity), Path: p.Path, Line: p.Line, Message: p.Message})
	}
	remote = append(remote, control.ConfigProblem{Severity: "warning", Message: appProblemMsg})
	serveCheck(t, h, nil, remote...)

	if code := h.run("config", "check"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	out := h.out.String()
	for _, p := range local {
		if n := strings.Count(out, p.Message); n != 1 {
			t.Errorf("%q printed %d times, want once:\n%s", p.Message, n, out)
		}
	}
	if n := strings.Count(out, appProblemMsg); n != 1 {
		t.Errorf("Nazar.app's own problem printed %d times, want once:\n%s", n, out)
	}

	if code := h.run("--json", "config", "check"); code != control.ExitOK {
		t.Fatalf("--json: exit %d\n%s", code, h.out)
	}
	c := jsonCheck(t, h)
	for _, p := range local {
		if n := countMessages(c.Problems, p.Message); n != 1 {
			t.Errorf("--json: %q appears %d times, want once: %+v", p.Message, n, c.Problems)
		}
	}
	if countMessages(c.Problems, appProblemMsg) != 1 {
		t.Errorf("--json: Nazar.app's own problem missing or repeated: %+v", c.Problems)
	}
}

// A staged change still exits 4, and Nazar.app's problems are shown with it.
func TestConfigCheckShowsDaemonProblemsWhileStaged(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, cleanCfg)
	serveCheck(t, h, &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Loosens: true, Changes: []string{"ssh:hydra: added rule 2"}},
		control.ConfigProblem{Severity: "warning", Path: "ssh_agent.keys.hydra", Message: keyProblemMsg})
	if code := h.run("config", "check"); code != control.ExitStaged {
		t.Fatalf("exit %d, want %d\n%s", code, control.ExitStaged, h.out)
	}
	if !strings.Contains(h.out.String(), keyProblemMsg) || !strings.Contains(h.out.String(), "ssh:hydra: added rule 2") {
		t.Fatalf("staged diff and Nazar.app's problem must both show:\n%s", h.out)
	}
}

// Nazar.app's problems carry config-derived names; the human view escapes
// them like everything else it prints (the local file is clean here, so
// only the remote problem can carry the hostile string).
func TestConfigCheckEscapesDaemonProblems(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, cleanCfg)
	serveCheck(t, h, nil, control.ConfigProblem{Severity: "warning", Path: hostile, Message: "app: " + hostile + " matches nothing"})
	h.run("config", "check")
	assertEscaped(t, "config check with a hostile remote problem", h, false)
	if strings.Contains(h.out.String(), "\x1b") || strings.Contains(h.out.String(), "\u202e") {
		t.Fatalf("raw control runes reached the terminal: %q", h.out)
	}
	h.run("--json", "config", "check")
	if !json.Valid([]byte(strings.TrimSpace(h.out.String()))) {
		t.Fatalf("--json output is not valid JSON: %q", h.out)
	}
}

// A clean config with a clean Nazar.app prints no warning at all.
func TestConfigCheckCleanPrintsNoWarning(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, cleanCfg)
	serveCheck(t, h, nil)
	if code := h.run("config", "check"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	if strings.Contains(h.out.String(), "warning") || strings.Contains(h.out.String(), "error") {
		t.Fatalf("clean config: %s", h.out)
	}
	h.run("--json", "config", "check")
	if c := jsonCheck(t, h); len(c.Problems) != 0 {
		t.Fatalf("clean config: %+v", c.Problems)
	}
}

// status prints Nazar.app's key advice so the user can tell which key it is
// about (the message names it).
func TestStatusShowsKeyAdvice(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{},
			Problems: []control.ConfigProblem{{Severity: "warning", Path: "ssh_agent.keys.hydra", Message: keyProblemMsg}}})
	})
	if code := h.run("status"); code != control.ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.out.String(), keyProblemMsg) {
		t.Fatalf("status must show the advice:\n%s", h.out)
	}
}
