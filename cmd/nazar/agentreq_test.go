package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

// Milestone 6 (spec 4): the CLI names the agent it trusts by signature.

// A CLI signed by a team trusts dev.nazar.agent of that team, wherever
// either runs from: no bundle is read and no path is consulted, so it can
// never fall back to a weaker, build-pinned rule either.
func TestAgentRequirementOfATeamCLI(t *testing.T) {
	h := newHarness(t)
	h.a.selfTeam = func() (string, error) { return "ABCDE12345", nil }
	h.a.designated = func(string) (string, error) { t.Fatal("a team CLI read a bundle's requirement"); return "", nil }
	h.a.plistProgram = func(string) (string, error) { t.Fatal("a team CLI read the LaunchAgent"); return "", nil }
	for _, exe := range []string{h.app.CLI, "/opt/homebrew/bin/nazar"} {
		h.a.executable = func() (string, error) { return exe, nil }
		req, err := h.a.agentRequirement()
		want := `identifier "dev.nazar.agent" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"`
		if err != nil || req != want {
			t.Fatalf("CLI at %s: agentRequirement = %q, %v; want %q", exe, req, err, want)
		}
	}
}

// An ad-hoc CLI trusts exactly the agent bundle it ships in.
func TestAgentRequirementOfAnAdHocCLIIsItsOwnBundle(t *testing.T) {
	h := newHarness(t)
	h.a.selfTeam = func() (string, error) { return "", nil }
	var asked []string
	h.a.designated = func(p string) (string, error) { asked = append(asked, p); return `cdhash H"1234"`, nil }
	h.a.plistProgram = func(string) (string, error) { t.Fatal("the LaunchAgent was read"); return "", nil }
	req, err := h.a.agentRequirement()
	if err != nil || req != `cdhash H"1234"` || len(asked) != 1 || asked[0] != h.app.Bundle {
		t.Fatalf("agentRequirement = %q, %v; asked %q, want %q", req, err, asked, h.app.Bundle)
	}
}

// What an ad-hoc CLI refuses to trust, and what makes any CLI trust
// nothing: no request is ever sent then.
func TestAgentRequirementRefuses(t *testing.T) {
	for name, set := range map[string]func(h *harness){
		"ad hoc, outside a bundle (even with a LaunchAgent naming one)": func(h *harness) {
			h.a.selfTeam = func() (string, error) { return "", nil }
			h.a.executable = func() (string, error) { return "/usr/local/bin/nazar", nil }
			h.a.plistProgram = func(string) (string, error) { return h.app.MainExe, nil }
		},
		"ad hoc, the agent's own executable, not the CLI": func(h *harness) {
			h.a.selfTeam = func() (string, error) { return "", nil }
			h.a.executable = func() (string, error) { return h.app.MainExe, nil }
		},
		"ad hoc, bundle without the agent executable": func(h *harness) {
			h.a.selfTeam = func() (string, error) { return "", nil }
			h.a.executable = func() (string, error) { return h.home + "/Gone.app/Contents/MacOS/nazar", nil }
		},
		"ad hoc, no designated requirement": func(h *harness) {
			h.a.selfTeam = func() (string, error) { return "", nil }
			h.a.designated = func(string) (string, error) { return "", errors.New("unsigned") }
		},
		"own signature unreadable": func(h *harness) {
			h.a.selfTeam = func() (string, error) { return "", errors.New("invalid signature") }
		},
		"a team id that would inject a clause": func(h *harness) {
			h.a.selfTeam = func() (string, error) { return `ABCDE12345" or anchor apple or identifier "x`, nil }
		},
		"no seams": func(h *harness) { h.a.selfTeam = nil },
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.a.designated = func(string) (string, error) { return `cdhash H"1234"`, nil }
			set(h)
			if req, err := h.a.agentRequirement(); err == nil {
				t.Fatalf("agentRequirement = %q, want an error", req)
			}
			h.a.verifier = nil
			h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
			if code := h.run("status"); code == 0 {
				t.Fatalf("status passed: %q", h.out)
			}
			if r := h.requests(); len(r) != 0 {
				t.Fatalf("requests reached an unverified peer: %+v", r)
			}
		})
	}
}

// End to end: a team CLI refuses the harness's ad-hoc stub server (this
// test binary) before sending anything.
func TestTeamCLIRefusesAnAdHocPeer(t *testing.T) {
	h := newHarness(t)
	h.a.verifier = nil
	h.a.selfTeam = func() (string, error) { return "ABCDE12345", nil }
	h.a.designated = designatedRequirement
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("status"); code == 0 {
		t.Fatalf("a team CLI accepted an ad-hoc peer: %q", h.out)
	}
	if !strings.Contains(h.errb.String(), "is not") {
		t.Fatalf("stderr %q", h.errb)
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("requests reached the peer: %+v", r)
	}
}
