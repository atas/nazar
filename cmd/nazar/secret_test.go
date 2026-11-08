package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/control"
)

// Secrets design 7.1: nazar secret add, list and rm. The value is
// read from stdin or a hidden terminal prompt, never from an argument, and
// is never printed.

const cliValue = "nazar-m8-03-cli-value-77b2"

// secretServer answers secret.add, secret.list and secret.delete like
// nazar-agent would.
func (h *harness) secretServer(t *testing.T) {
	t.Helper()
	created := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	h.serve(t, func(ctx context.Context, req control.Request, out control.Emitter) {
		s := control.Secret{TypeMeta: control.Meta(control.KindSecret), Name: req.Args["name"], Configured: true,
			Deliver: []string{"helper", "stdout"}, Rules: []string{`1: apps=[app:"com.googlecode.iterm2":""] to=[] gate=login scope=session expire=8h0m0s`, "fallback: gate=block"}}
		switch req.Command {
		case control.CmdSecretAdd:
			s.Stored, s.Created, s.WhileLocked = true, &created, req.Args["onlyWhenUnlocked"] != "true"
			out.Emit(s)
		case control.CmdSecretDelete:
			out.Emit(s)
		case control.CmdSecretList:
			s.Name, s.Stored, s.Created = "GH_TOKEN", true, &created
			broken := control.Secret{TypeMeta: control.Meta(control.KindSecret), Name: "OLD", Stored: true, Broken: true, Rules: []string{"fallback: gate=block"},
				UnusableReason: "Keychain item secret/OLD can't be read", Remedy: "security delete-generic-password -s dev.nazar -a secret/OLD, then nazar secret add OLD"}
			out.Emit(control.SecretList{TypeMeta: control.Meta(control.KindSecretList), Items: []control.Secret{s, broken}})
		default:
			out.Emit(control.NewProblem(control.CodeUsage, "unexpected %s", req.Command))
		}
	})
}

func (h *harness) pipeIn(s string) {
	h.a.stdin = strings.NewReader(s)
	h.a.stdinTerminal = func() bool { return false }
	h.a.readHidden = func() ([]byte, error) { panic("not a terminal") }
}

func TestSecretAddReadsTheValueFromStdin(t *testing.T) {
	h := newHarness(t)
	h.secretServer(t)
	for _, c := range []struct{ in, want string }{
		{cliValue + "\n", cliValue},            // echo $X | nazar secret add
		{cliValue, cliValue},                   // printf %s
		{cliValue + "\n\n", cliValue + "\n"},   // exactly one newline is stripped
		{"line1\nline2\n", "line1\nline2"},     // a multi-line value stays whole
		{"\x00\xff bytes\n", "\x00\xff bytes"}, // bytes, not text
	} {
		h.pipeIn(c.in)
		if code := h.run("secret", "add", "GH_TOKEN"); code != 0 {
			t.Fatalf("exit %d: %s", code, h.errb.String())
		}
		reqs := h.requests()
		got, err := base64.StdEncoding.DecodeString(reqs[len(reqs)-1].Args["valueBase64"])
		if err != nil || string(got) != c.want || reqs[len(reqs)-1].Args["name"] != "GH_TOKEN" {
			t.Fatalf("sent %d bytes (%v), want %d", len(got), err, len(c.want))
		}
		if !strings.Contains(h.out.String(), "added secret GH_TOKEN") {
			t.Fatalf("output %q", h.out.String())
		}
		if strings.Contains(h.out.String()+h.errb.String(), cliValue) {
			t.Fatal("the value must never be printed")
		}
	}
	h.pipeIn(cliValue + "\n")
	h.a.json = true
	h.out.Reset()
	if code := h.a.run([]string{"--json", "secret", "add", "GH_TOKEN"}); code != 0 {
		t.Fatalf("--json exit %d", code)
	}
	var s control.Secret
	if err := json.Unmarshal(h.out.Bytes(), &s); err != nil || s.Kind != control.KindSecret || !s.Stored || strings.Contains(h.out.String(), cliValue) {
		t.Fatalf("--json %q %v", h.out.String(), err)
	}
}

// A terminal gets one hidden line; the prompt goes to stderr and stdin is
// not read any other way.
func TestSecretAddPromptsHiddenOnATerminal(t *testing.T) {
	h := newHarness(t)
	h.secretServer(t)
	h.a.stdin = strings.NewReader("must not be read")
	h.a.stdinTerminal = func() bool { return true }
	asked := 0
	h.a.readHidden = func() ([]byte, error) { asked++; return []byte(cliValue), nil }
	if code := h.run("secret", "add", "GH_TOKEN"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	reqs := h.requests()
	if asked != 1 || reqs[0].Args["valueBase64"] != base64.StdEncoding.EncodeToString([]byte(cliValue)) {
		t.Fatalf("asked %d times", asked)
	}
	if !strings.Contains(h.errb.String(), "value for GH_TOKEN (typing is hidden): ") || strings.Contains(h.out.String()+h.errb.String(), cliValue) {
		t.Fatalf("stderr %q", h.errb.String())
	}
}

// The value never comes from an argument, and nothing is sent for a bad
// name, an empty value or one over the size bound.
func TestSecretAddRefusals(t *testing.T) {
	h := newHarness(t)
	h.secretServer(t)
	for _, c := range []struct {
		args []string
		in   string
		want string
	}{
		{[]string{"secret", "add", "GH_TOKEN", cliValue}, cliValue, "expected 1 argument"},
		{[]string{"secret", "add", "--value", cliValue, "GH_TOKEN"}, cliValue, "flag provided but not defined"},
		{[]string{"secret", "add", "a b"}, cliValue, `invalid secret name "a b"`},
		{[]string{"secret", "add", "GH_TOKEN"}, "", "the value is empty"},
		{[]string{"secret", "add", "GH_TOKEN"}, "\n", "the value is empty"},
		{[]string{"secret", "add", "GH_TOKEN"}, strings.Repeat("v", 32<<10+1), "larger than 32 KiB"},
	} {
		h.pipeIn(c.in)
		if code := h.run(c.args...); code != control.ExitUsage || !strings.Contains(h.errb.String(), c.want) {
			t.Errorf("%q: exit %d, stderr %q, want %q", c.args, code, h.errb.String(), c.want)
		}
		if strings.Contains(h.out.String()+h.errb.String(), cliValue) {
			t.Errorf("%q: the value was echoed", c.args)
		}
	}
	if n := len(h.requests()); n != 0 {
		t.Fatalf("%d requests sent", n)
	}
	// 32 KiB exactly is accepted.
	h.pipeIn(strings.Repeat("v", 32<<10))
	if code := h.run("secret", "add", "BIG"); code != 0 {
		t.Fatalf("32 KiB: exit %d %s", code, h.errb.String())
	}
}

func TestSecretListAndRm(t *testing.T) {
	h := newHarness(t)
	h.secretServer(t)
	if code := h.run("secret", "list"); code != 0 {
		t.Fatalf("list exit %d %s", code, h.errb.String())
	}
	out := h.out.String()
	for _, want := range []string{"NAME", "CREATED", "RULES", "GH_TOKEN", "2026-10-18", "OLD", "broken", "fix: security delete-generic-password -s dev.nazar -a secret/OLD, then nazar secret add OLD"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if code := h.run("secret", "rm", "GH_TOKEN"); code != 0 || !strings.Contains(h.out.String(), "deleted secret GH_TOKEN") {
		t.Fatalf("rm exit %d %q %s", code, h.out.String(), h.errb.String())
	}
	if r := h.requests(); r[len(r)-1].Command != control.CmdSecretDelete || r[len(r)-1].Args["name"] != "GH_TOKEN" {
		t.Fatalf("%+v", r[len(r)-1])
	}
	for _, bad := range [][]string{{"secret"}, {"secret", "rm"}, {"secret", "delete", "X"}, {"secret", "list", "x"}} {
		if code := h.run(bad...); code != control.ExitUsage {
			t.Errorf("%q: exit %d", bad, code)
		}
	}
}

// Security review: a value typed at the hidden prompt is refused when
// more input is pending (a multi-line paste: the rest would reach the shell
// as commands), when it reaches the terminal's line limit (it may have been
// cut short), or when it holds an escape sequence (a terminal's paste
// markers).
func TestHiddenLineChecks(t *testing.T) {
	if err := checkHiddenLine([]byte(cliValue), 0); err != nil {
		t.Fatalf("a plain line: %v", err)
	}
	for _, c := range []struct {
		line    []byte
		pending int
		want    string
	}{
		{[]byte("-----BEGIN KEY-----"), 31, "pipe it"},
		{[]byte(strings.Repeat("v", 1023)), 0, "pipe it"},
		{[]byte("\x1b[200~token\x1b[201~"), 0, "escape"},
	} {
		err := checkHiddenLine(c.line, c.pending)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), string(c.line)) {
			t.Errorf("%d bytes, %d pending: %v", len(c.line), c.pending, err)
		}
	}
	if err := checkHiddenLine([]byte(strings.Repeat("v", 1022)), 0); err != nil {
		t.Fatalf("1022 bytes fit the terminal's line: %v", err)
	}
}

// The test hook that skips the agent's signature check never carries a
// value to a listener nobody checked.
func TestSecretAddRefusedUnderTheTestPeerHook(t *testing.T) {
	h := newHarness(t)
	h.secretServer(t)
	h.env["NAZAR_TEST_PEER"] = "same-user"
	h.a.verifier = nil
	h.pipeIn(cliValue)
	if code := h.run("secret", "add", "X"); code != control.ExitUsage || !strings.Contains(h.errb.String(), "NAZAR_TEST_PEER") {
		t.Fatalf("exit %d %q", code, h.errb.String())
	}
	if n := len(h.requests()); n != 0 {
		t.Fatalf("%d requests", n)
	}
}

// secret rule add|set|remove send config.edit with secret (never
// key), with exactly the args ssh-key rule sends; checks run before
// anything is sent.
func TestSecretRuleCommands(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Op: req.Args["op"], Secret: req.Args["secret"],
			Path: "/c.yaml", Changed: true, Applied: true, Problems: []control.ConfigProblem{}})
	})
	for _, c := range []struct {
		argv []string
		want map[string]string
	}{
		{[]string{"secret", "rule", "add", "team/GH_TOKEN", "--apps", "iterm", "--to", "git-https", "--gate", "login", "--scope", "session", "--expire", "8h", "--at", "1", "--if-hash", "abc"},
			map[string]string{"op": "rule.add", "secret": "team/GH_TOKEN", "apps": `["iterm"]`, "to": `["git-https"]`, "gate": "login", "scope": "session", "expire": "8h", "at": "1", "ifHash": "abc"}},
		{[]string{"secret", "rule", "set", "GH_TOKEN", "2", "--no-to", "--gate", "dialog", "--no-expire"},
			map[string]string{"op": "rule.set", "secret": "GH_TOKEN", "index": "2", "to": "", "gate": "dialog", "expire": ""}},
		{[]string{"secret", "rule", "remove", "GH_TOKEN", "1"}, map[string]string{"op": "rule.remove", "secret": "GH_TOKEN", "index": "1"}},
	} {
		if code := h.run(append([]string{"--json"}, c.argv...)...); code != 0 {
			t.Fatalf("%q: exit %d %s", c.argv, code, h.errb)
		}
		r := h.requests()
		if got := r[len(r)-1]; got.Command != control.CmdConfigEdit || !maps.Equal(got.Args, c.want) {
			t.Fatalf("%q sent %s %v", c.argv, got.Command, got.Args)
		}
	}
	sent := len(h.requests())
	for _, bad := range [][]string{
		{"secret", "rule"}, {"secret", "rule", "move", "X"}, {"secret", "rule", "add", "../x", "--apps", "iterm", "--gate", "login"},
		{"secret", "rule", "add", "X", "--gate", "login"}, {"secret", "rule", "add", "X", "--apps", "iterm", "--gate", "yes"},
		{"secret", "rule", "set", "X", "0", "--gate", "login"}, {"secret", "rule", "set", "X", "1"}, {"secret", "rule", "add", "X", "--apps", "iterm", "--gate", "login", "--no-expire"},
	} {
		if code := h.run(bad...); code != control.ExitUsage {
			t.Errorf("%q: exit %d", bad, code)
		}
	}
	if len(h.requests()) != sent {
		t.Fatal("a usage error sent a request")
	}
	if h.run("secret"); !strings.Contains(h.errb.String(), "add, list, rm, rule") {
		t.Fatalf("secret's usage must list rule: %s", h.errb)
	}
}
