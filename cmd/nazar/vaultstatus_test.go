package main

import (
	"context"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

const otherBuild = "Keychain item ssh-key/github can't be read by this build of Nazar.app: it belongs to another build of Nazar.app"

// `nazar status` and `nazar ssh-key list` name every
// unreadable vault item with its effect and the command that fixes it,
// escaped like every other reply field.
func TestStatusAndListShowUnreadableItems(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdStatus:
			out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{}, Vault: []control.VaultProblem{
				{Item: "config/prompts", Reason: "Keychain item config/prompts can't be read", Effect: "no approval prompt can open",
					Remedy: "security delete-generic-password -s dev.nazar -a config/prompts"},
				{Item: "ssh-key/github", Reason: otherBuild, Effect: "SSH key github can't sign", Remedy: "security delete-generic-password -s dev.nazar -a ssh-key/github, then nazar ssh-key create github\x1b[2J"},
			}})
		case control.CmdSSHKeyList:
			out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{
				{TypeMeta: control.Meta(control.KindSSHKey), Name: "github", Broken: true, Configured: true, Rules: []string{"fallback: gate=login scope=use"},
					UnusableReason: otherBuild, Remedy: "security delete-generic-password -s dev.nazar -a ssh-key/github, then nazar ssh-key create github"},
			}})
		default:
			replyFor(req, out)
		}
	})
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	for _, want := range []string{"vault: config/prompts", "fix: security delete-generic-password -s dev.nazar -a config/prompts",
		"vault: ssh-key/github", "effect: SSH key github can't sign"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Fatal("an escape sequence reached the terminal")
	}
	if code := h.run("ssh-key", "list"); code != 0 {
		t.Fatal(code)
	}
	if out := h.out.String(); !strings.Contains(out, "broken") || !strings.Contains(out, otherBuild) ||
		!strings.Contains(out, "fix: security delete-generic-password -s dev.nazar -a ssh-key/github, then nazar ssh-key create github") {
		t.Fatalf("ssh-key list:\n%s", out)
	}
	if code := h.run("--json", "status"); code != 0 {
		t.Fatal(code)
	}
	objs := jsonLines(t, h.out.String())
	if v, _ := objs[0]["vault"].([]any); len(v) != 2 {
		t.Fatalf("--json status vault: %v", objs[0]["vault"])
	}
}

// create sends the name and nothing else; a flag is a usage error
// that never reaches Nazar.app.
func TestCreateSendsOnlyGivenFlags(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("ssh-key", "create", "github"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if r := h.requests()[0]; len(r.Args) != 1 || r.Args["name"] != "github" {
		t.Fatalf("args %v", r.Args)
	}
	for _, bad := range [][]string{{"ssh-key", "create", "k", "--gate", "dialog", "--gate", "login"}, {"ssh-key", "create", "k", "--scope="}} {
		if code := h.run(bad...); code != control.ExitUsage {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
}
