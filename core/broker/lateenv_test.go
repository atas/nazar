package broker

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Secrets design 5.1, 8: a late-env request runs the same
// pipeline. Its op is deliver:late-env ("nazar run"), its receiver the
// synthetic chain of the agent's resolution, and a refusal after the exec
// (a DeniedError from Do) is decision=denied, not error, in the one line.

const runCfg = cfgSrc + `secrets:
  BRAVE_API_KEY:
    deliver: [late-env]
    envAllow: [HTTPS_PROXY]
    rules:
      - apps: [iterm]
        to: [{command: [npx, -y, "@brave/brave-search-mcp-server"]}]
        scope: session
        gate: dialog
`

const npxReal = "/opt/node/lib/node_modules/npm/bin/npx-cli.js"

func runEnv(t *testing.T) *env {
	e := newEnvWith(t, runCfg, 200*time.Millisecond)
	e.m.Command = func(a0 string) (string, error) {
		if a0 == "npx" {
			return npxReal, nil
		}
		return "", errors.New("not found")
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	return e
}

func (e *env) runReq(peer platform.ProcessRef, digest byte, do func(platform.ApprovalRef) error) Request {
	argv := []string{"npx", "-y", "@brave/brave-search-mcp-server"}
	return Request{
		Secret: "BRAVE_API_KEY", Delivery: config.DeliverLateEnv, Chain: e.r.Resolve(peer),
		Receiver:  caller.Synthetic(platform.ProcessInfo{Path: npxReal, Args: argv, Cwd: "/", Code: platform.CodeIdentity{CDHash: []byte{digest}}}),
		Summary:   "nazar run npx -y @brave/brave-search-mcp-server",
		Operation: "nazar run", EnvPassed: []string{"HTTPS_PROXY"},
		Do: do,
	}
}

func TestLateEnvRequestIsApprovedRememberedAndAudited(t *testing.T) {
	e := runEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, cliProc())
	ok := func(platform.ApprovalRef) error { e.calls.Add(1); return nil }
	if r := e.b.Handle(e.runReq(tab.Peer(), 1, ok)); r.Decision != audit.Approved {
		t.Fatalf("first: %+v", r)
	}
	shown := e.f.Shown()
	if len(shown) != 1 || !strings.Contains(promptText(shown[0].Prompt), "Scope: this terminal session, for nazar run only") {
		t.Fatalf("prompt:\n%s", promptText(shown[0].Prompt))
	}
	f := e.lastLine(t)
	if f["delivery"] != "late-env" || f["env_passed"] != "HTTPS_PROXY" || f["operation"] != "nazar run" || !strings.HasPrefix(f["receiver"], "npx-cli.js -y") {
		t.Fatalf("audit %v", f)
	}
	if r := e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, ok)); r.Reason != "cached approval" {
		t.Fatalf("the same receiver in the same tab: %+v", r)
	}
	// Other pinned bytes: another receiver, another dialog.
	if r := e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 2, ok)); r.Decision != audit.Approved || e.f.CountShown(fake.KindConfirm) != 2 {
		t.Fatalf("changed bytes must ask again: %+v (%d dialogs)", r, e.f.CountShown(fake.KindConfirm))
	}
	for _, en := range e.cache.List() {
		if en.Key.Op != "deliver:late-env" || en.Covers != "nazar run" {
			t.Fatalf("approval %+v", en)
		}
	}
}

func TestDeniedAfterExecIsOneDeniedLine(t *testing.T) {
	e := runEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, cliProc())
	before := len(e.sink.Lines())
	r := e.b.Handle(e.runReq(tab.Peer(), 1, func(platform.ApprovalRef) error {
		return &DeniedError{Reason: "unexpected environment: npm_config_script_shell"}
	}))
	if r.Decision != audit.Denied || r.Reason != "unexpected environment: npm_config_script_shell" {
		t.Fatalf("result %+v", r)
	}
	if n := len(e.sink.Lines()) - before; n != 1 {
		t.Fatalf("one audit line, got %d", n)
	}
	if f := e.lastLine(t); f["decision"] != "denied" || f["reason"] != "unexpected environment: npm_config_script_shell" {
		t.Fatalf("audit %v", f)
	}
	// A wrapped DeniedError is a denial too; any other error stays an error.
	r = e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, func(platform.ApprovalRef) error {
		return fmt.Errorf("handover: %w", &DeniedError{Reason: "receiver changed at exec"})
	}))
	if r.Decision != audit.Denied || r.Reason != "receiver changed at exec" {
		t.Fatalf("wrapped: %+v", r)
	}
	r = e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, func(platform.ApprovalRef) error { return errors.New("target never exec'd") }))
	if r.Decision != audit.Error || r.Reason != "target never exec'd" {
		t.Fatalf("plain error: %+v", r)
	}
}

// Review findings.

// The dialog and the audit line name what runs (the pinned realpath and
// the tail), never the caller-chosen argv[0], and cwd= stays the caller's
// directory (secrets design 6.3.3, 8).
func TestRunReceiverIsShownByItsRealpath(t *testing.T) {
	e := runEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, scriptProc("/opt/claude/bin/claude", "com.example.claude", "claude"), cliProc())
	req := e.runReq(tab.Peer(), 1, func(platform.ApprovalRef) error { return nil })
	req.Receiver = caller.Synthetic(platform.ProcessInfo{Path: npxReal, Args: []string{"git", "-y", "@brave/brave-search-mcp-server"}, Cwd: "/", Code: platform.CodeIdentity{CDHash: []byte{1}}})
	e.b.Handle(req)
	text := promptText(e.f.Shown()[0].Prompt)
	if !strings.Contains(text, npxReal+" -y") || strings.Contains(text, "git -y") {
		t.Fatalf("the dialog must show the realpath, not argv[0]:\n%s", text)
	}
	f := e.lastLine(t)
	if !strings.HasPrefix(f["receiver"], "npx-cli.js -y") || f["cwd"] != "~/projects/foo" || !strings.HasPrefix(f["command"], "claude") {
		t.Fatalf("audit %v", f)
	}
}

// A refusal after the exec drops the approval it ran under: the next run
// of that receiver asks again (a caller racing a file swap gets no silent
// retries).
func TestDeniedAfterExecDropsTheApproval(t *testing.T) {
	e := runEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, cliProc())
	ok := func(platform.ApprovalRef) error { return nil }
	if r := e.b.Handle(e.runReq(tab.Peer(), 1, ok)); r.Decision != audit.Approved {
		t.Fatal(r)
	}
	r := e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, func(platform.ApprovalRef) error {
		return &DeniedError{Reason: "receiver changed at exec"}
	}))
	if r.Decision != audit.Denied {
		t.Fatalf("%+v", r)
	}
	if r := e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, ok)); r.Decision != audit.Approved || e.f.CountShown(fake.KindConfirm) != 2 {
		t.Fatalf("must ask again: %+v (%d dialogs)", r, e.f.CountShown(fake.KindConfirm))
	}
	// A nil or empty DeniedError is still a denial, with a reason.
	for _, err := range []error{(*DeniedError)(nil), &DeniedError{}} {
		r := e.b.Handle(e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, func(platform.ApprovalRef) error { return err }))
		if r.Decision != audit.Denied || r.Reason != "denied after approval" {
			t.Fatalf("%v: %+v", err, r)
		}
	}
}

// One method's approval never serves another, and another tail is another
// receiver even with the same digest.
func TestRunApprovalCoversOnlyLateEnvAndOneCommandLine(t *testing.T) {
	e := newEnvWith(t, strings.Replace(strings.Replace(runCfg, "[late-env]", "[late-env, stdout]", 1), "    envAllow: [HTTPS_PROXY]\n", "    envAllow: [HTTPS_PROXY]\n", 1), 200*time.Millisecond)
	e.m.Command = func(a0 string) (string, error) { return npxReal, nil }
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, cliProc())
	ok := func(platform.ApprovalRef) error { return nil }
	e.b.Handle(e.runReq(tab.Peer(), 1, ok))
	stdout := e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, ok)
	stdout.Delivery = config.DeliverStdout
	if r := e.b.Handle(stdout); r.Reason == "cached approval" {
		t.Fatalf("a late-env approval served stdout: %+v", r)
	}
	other := e.runReq(e.f.Launch(tab.Shell, cliProc()), 1, ok)
	other.Receiver.Procs[0].Args = []string{npxReal, "-y", "@brave/brave-search-mcp-server", "--x"}
	if r := e.b.Handle(other); r.Reason == "cached approval" {
		t.Fatalf("another tail rode the approval: %+v", r)
	}
}
