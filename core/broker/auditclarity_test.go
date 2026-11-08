package broker

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/policy"
)

// Milestone 5: rule=key-gate when the key's own gate applied,
// rule=fallback only for defaults.fallback.
func TestRuleFieldTellsKeyGateFromFallback(t *testing.T) {
	e := newEnvWith(t, moreCfg, 0)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	cases := []struct{ key, rule string }{
		{"userkey", RuleKeyGate},    // no rules, own scope/gate
		{"guarded", "2"},            // iTerm matches rule 2
		{"nosuchkey", RuleFallback}, // not configured: defaults.fallback (block)
	}
	for _, c := range cases {
		e.b.Handle(e.req(c.key, tab.Peer()))
		if got := e.lastLine(t)["rule"]; got != c.rule {
			t.Errorf("%s: rule=%q, want %q", c.key, got, c.rule)
		}
	}
	// A configured key whose rules don't match and that has no own gate
	// falls to defaults.fallback.
	other := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("appkey", other))
	if f := e.lastLine(t); f["rule"] != RuleFallback || f["decision"] != string(audit.Blocked) {
		t.Fatalf("appkey from an unknown caller: %v", f)
	}
}

// Milestone 5: a denied dialog says how it ended.
func TestDeniedDialogSaysHow(t *testing.T) {
	cases := []struct {
		how      platform.DialogHow
		decision audit.Decision
		reason   string
	}{
		{platform.DialogDenyButton, audit.Denied, "user denied (Deny button)"},
		{platform.DialogEscape, audit.Denied, "user denied (Esc)"},
		{platform.DialogClosed, audit.Denied, "the dialog closed without an answer"},
		{platform.DialogTimedOut, audit.Timeout, "no answer within 200ms"},
		{platform.DialogNoReason, audit.Denied, "user denied"},
		{platform.DialogHow(99), audit.Denied, "user denied"}, // unknown: a plain denial
	}
	for _, c := range cases {
		e := newEnv(t)
		e.f.ScriptConfirm(fake.Answer{How: c.how})
		tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
		r := e.b.Handle(e.req("github", tab.Peer()))
		if r.Allowed() || r.Decision != c.decision || r.Reason != c.reason {
			t.Errorf("%v: %s %q, want %s %q", c.how, r.Decision, r.Reason, c.decision, c.reason)
		}
		if f := e.lastLine(t); f["decision"] != string(c.decision) || f["reason"] != c.reason {
			t.Errorf("%v: audit %v", c.how, f)
		}
		if e.calls.Load() != 0 {
			t.Errorf("%v: signed after a denial", c.how)
		}
	}
}

// keyGateCfg has a key with both rules and its own gate (mixed), a key with
// rules only (bare: defaults.fallback for other callers) and a
// defaults.fallback that prompts, so key-gate vs fallback is not just
// "blocked or not".
const keyGateCfg = `apiVersion: nazar/v1
kind: Config
defaults:
  fallback: {scope: use, gate: dialog}
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    mixed:
      scope: use
      gate: dialog
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
    bare:
      rules:
        - apps: [iterm]
          gate: dialog
`

// Milestone 5, edge cases: the key's own gate is key-gate even when
// the key has rules that did not match; defaults.fallback is fallback even
// when it prompts; a matched rule is its number. rule=key-gate is only the
// audit label: the approval cache's rule id stays fallback:<hash>, so no
// approval made before Milestone 5 is dropped.
func TestKeyGateIsTheKeysOwnPolicyOnly(t *testing.T) {
	e := newEnvWith(t, keyGateCfg, 0)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	other := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	cases := []struct {
		key     string
		peer    platform.ProcessRef
		rule    string
		keyGate bool
	}{
		{"mixed", tab.Peer(), "1", false},
		{"mixed", other, RuleKeyGate, true},
		{"bare", tab.Peer(), "1", false},
		{"bare", other, RuleFallback, false},
		{"ghost", other, RuleFallback, false}, // not configured at all
	}
	for _, c := range cases {
		r := e.b.Handle(e.req(c.key, c.peer))
		f := e.lastLine(t)
		if f["rule"] != c.rule || r.Outcome.KeyGate != c.keyGate {
			t.Errorf("%s: rule=%q KeyGate=%v, want %q %v (audit %v)", c.key, f["rule"], r.Outcome.KeyGate, c.rule, c.keyGate, f)
		}
		if c.rule == "1" {
			continue
		}
		if !strings.HasPrefix(r.Outcome.RuleID, "fallback:") || r.Outcome.RuleID != policy.FallbackRuleID(r.Outcome.Target, r.Outcome.Policy) {
			t.Errorf("%s: approval rule id %q changed (want fallback:<hash>)", c.key, r.Outcome.RuleID)
		}
		if f["gate"] != "dialog" {
			t.Errorf("%s: gate=%q, want dialog (the fallback/own gate applied)", c.key, f["gate"])
		}
	}
	if f := e.lastLine(t); f["rule"] == RuleKeyGate {
		t.Fatalf("an unconfigured key must never be labelled key-gate: %v", f)
	}
}

// classifyDialog fails closed: a platform that says both "yes" and "denied"
// is not an approval; a wrapped DialogDenied keeps its way; any other error
// stays an error; a plain denial is "user denied"; the dialog's own
// countdown is a timeout with the broker's wording and the prompt's timeout.
func TestClassifyDialog(t *testing.T) {
	const to = 30 * time.Second
	deny := platform.DialogDenied{How: platform.DialogDenyButton}
	cases := []struct {
		name     string
		ok       bool
		err      error
		approved bool
		decision audit.Decision
		reason   string
	}{
		{"allow", true, nil, true, "", ""},
		{"plain denial", false, nil, false, audit.Denied, "user denied"},
		{"ErrDenied", false, platform.ErrDenied, false, audit.Denied, "user denied"},
		{"Deny button", false, deny, false, audit.Denied, "user denied (Deny button)"},
		{"wrapped Esc", false, fmt.Errorf("ui: %w", platform.DialogDenied{How: platform.DialogEscape}), false, audit.Denied, "user denied (Esc)"},
		{"closed", false, platform.DialogDenied{How: platform.DialogClosed}, false, audit.Denied, "the dialog closed without an answer"},
		{"own countdown", false, platform.DialogDenied{How: platform.DialogTimedOut}, false, audit.Timeout, "no answer within 30s"},
		{"how 1 is not allow", false, platform.DialogDenied{How: 1}, false, audit.Denied, "user denied"},
		{"unknown how", false, platform.DialogDenied{How: 42}, false, audit.Denied, "user denied"},
		{"yes and denied", true, deny, false, audit.Denied, ""},
		{"yes and an error", true, errors.New("boom"), false, audit.Error, "boom"},
		{"other error", false, errors.New("ui stuck"), false, audit.Error, "ui stuck"},
	}
	for _, c := range cases {
		r := classifyDialog(c.ok, c.err, to)
		if r.ok != c.approved || r.ref != 0 {
			t.Errorf("%s: ok=%v ref=%d, want ok=%v and no ref", c.name, r.ok, r.ref, c.approved)
			continue
		}
		if c.approved {
			continue
		}
		if r.decision != c.decision || (c.reason != "" && r.reason != c.reason) {
			t.Errorf("%s: %s %q, want %s %q", c.name, r.decision, r.reason, c.decision, c.reason)
		}
	}
}

// The dialog's own countdown and the broker's timer read the same in the
// audit log, and a late DialogTimedOut after the broker gave up changes
// nothing: one line, decision=timeout, nothing signed.
func TestDialogCountdownReadsLikeTheBrokersTimeout(t *testing.T) {
	e := newEnv(t)
	e.f.ScriptConfirm(fake.Answer{How: platform.DialogTimedOut, Delay: 400 * time.Millisecond})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
	r := e.b.Handle(e.req("github", tab.Peer()))
	if r.Decision != audit.Timeout || r.Reason != "no answer within 200ms" {
		t.Fatalf("broker timer: %s %q", r.Decision, r.Reason)
	}
	time.Sleep(500 * time.Millisecond) // the late answer arrives
	if n := len(e.sink.Lines()); n != 1 {
		t.Errorf("%d audit lines, want 1", n)
	}
	if f := e.lastLine(t); f["decision"] != string(audit.Timeout) || e.calls.Load() != 0 {
		t.Errorf("audit %v, signed %d", f, e.calls.Load())
	}
}
