package main

import (
	"context"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

// `ssh-key create <name> --always-ask` sends the request argument
// alwaysAsk=true and nothing else besides the name (the agent decides the
// entry); without the flag the argument is not sent at all.
func TestCreateAlwaysAskSendsTheRequestArg(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	for i, args := range [][]string{
		{"--json", "ssh-key", "create", "prod", "--always-ask"},
		{"--json", "ssh-key", "create", "--always-ask", "prod"},
	} {
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d %s %s", args, code, h.out, h.errb)
		}
		r := h.requests()[i]
		if r.Command != control.CmdSSHKeyCreate || len(r.Args) != 2 || r.Args["name"] != "prod" || r.Args["alwaysAsk"] != "true" {
			t.Fatalf("%v: request %+v", args, r)
		}
	}
	if code := h.run("--json", "ssh-key", "create", "work"); code != 0 {
		t.Fatal(code)
	}
	if r := h.requests()[2]; len(r.Args) != 1 || r.Args["name"] != "work" {
		t.Fatalf("without the flag only the name is sent: %+v", r.Args)
	}
}

// The CLI checks the reply: a key created without chip protection when
// --always-ask was asked for (an older nazar-agent that does not know the
// argument) is an error, never a quiet success, and says how to undo it.
func TestCreateAlwaysAskRefusesAKeyWithoutIt(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: req.Args["name"], Type: "ecdsa-sha2-nistp256",
			Fingerprint: "SHA256:abc", Configured: true, Rules: []string{"fallback: gate=block"}})
	})
	if code := h.run("ssh-key", "create", "prod", "--always-ask"); code != control.ExitError {
		t.Fatalf("exit %d, want 1: %s %s", code, h.out, h.errb)
	}
	for _, want := range []string{"without", "nazar ssh-key delete prod"} {
		if !strings.Contains(h.errb.String(), want) {
			t.Errorf("stderr lacks %q: %s", want, h.errb)
		}
	}
	if strings.Contains(h.out.String(), "created SSH key") {
		t.Fatalf("reported as created: %s", h.out)
	}
}

// `ssh-key list` marks the keys the chip asks for on every use; the human
// create output says so too.
func TestKeyListMarksAlwaysAskKeys(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyList:
			out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{
				{TypeMeta: control.Meta(control.KindSSHKey), Name: "github", Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:gh", Configured: true, Rules: []string{"1: x", "fallback: gate=block"}},
				{TypeMeta: control.Meta(control.KindSSHKey), Name: "prod", Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:pr", Configured: true, UserPresence: true, Rules: []string{"1: y", "fallback: gate=block"}},
			}})
		default:
			replyFor(req, out)
		}
	})
	if code := h.run("ssh-key", "list"); code != 0 {
		t.Fatal(code)
	}
	for _, line := range strings.Split(h.out.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "prod"):
			if !strings.Contains(line, "asks every time (chip)") {
				t.Errorf("prod is not marked: %q", line)
			}
		case strings.Contains(line, "asks every time"):
			t.Errorf("only prod is marked: %q", line)
		}
	}
	if code := h.run("ssh-key", "create", "prod", "--always-ask"); code != 0 || !strings.Contains(h.out.String(), "asks every time (chip)") {
		t.Fatalf("create: %d %s %s", code, h.out, h.errb)
	}
}
