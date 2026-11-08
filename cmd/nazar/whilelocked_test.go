package main

import (
	"context"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
)

// --only-when-unlocked sends the request argument onlyWhenUnlocked=true
// on ssh-key create, secret add and k8s ca create; without it nothing is
// sent (the agent's default: a key that works while the Mac is locked).
func TestOnlyWhenUnlockedSendsTheRequestArg(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	for i, c := range []struct {
		args []string
		says string
	}{
		{[]string{"ssh-key", "create", "github", "--only-when-unlocked"}, "only when unlocked: the chip refuses it while the Mac is locked"},
		{[]string{"ssh-key", "create", "--only-when-unlocked", "--always-ask", "prod"}, "only when unlocked: the chip refuses it while the Mac is locked"},
		{[]string{"ssh-key", "create", "bot"}, "works while the Mac is locked too"},
		{[]string{"ssh-key", "create", "prod2", "--always-ask"}, "only when unlocked: the chip refuses it while the Mac is locked"},
	} {
		if code := h.run(c.args...); code != 0 {
			t.Fatalf("%v: exit %d %s", c.args, code, h.errb)
		}
		r := h.requests()[i]
		if want := strings.Contains(strings.Join(c.args, " "), "--only-when-unlocked"); (r.Args["onlyWhenUnlocked"] == "true") != want || (!want && len(r.Args) > 2) {
			t.Fatalf("%v: request %+v", c.args, r.Args)
		}
		if !strings.Contains(h.out.String(), c.says) {
			t.Errorf("%v: output lacks %q:\n%s", c.args, c.says, h.out)
		}
	}

	s := newHarness(t)
	s.secretServer(t)
	s.pipeIn(cliValue + "\n")
	if code := s.run("secret", "add", "GH_TOKEN", "--only-when-unlocked"); code != 0 {
		t.Fatalf("secret add: %d %s", code, s.errb)
	}
	if r := s.requests()[0]; r.Args["onlyWhenUnlocked"] != "true" {
		t.Fatalf("secret add request %v", r.Args["onlyWhenUnlocked"])
	}
	if !strings.Contains(s.out.String(), "only when unlocked") {
		t.Fatalf("secret add output:\n%s", s.out)
	}
	s.pipeIn(cliValue + "\n")
	if code := s.run("secret", "add", "BOT"); code != 0 {
		t.Fatalf("secret add: %d %s", code, s.errb)
	}
	if r := s.requests()[1]; len(r.Args) != 2 {
		t.Fatalf("without the flag only name and value are sent: %v", len(r.Args))
	}

	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		c := setUpReply(t, req.Args["name"])
		c.CA.WhileLocked = req.Args["onlyWhenUnlocked"] != "true"
		_ = out.Emit(c)
	})
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443", "--only-when-unlocked"); code != control.ExitOK {
		t.Fatalf("k8s ca create: %d %s", code, w.errb)
	}
	if r := w.requests()[0]; r.Args["onlyWhenUnlocked"] != "true" {
		t.Fatalf("k8s ca create request %+v", r.Args)
	}
	if !strings.Contains(w.out.String(), "only while the Mac is unlocked") {
		t.Fatalf("k8s ca create output:\n%s", w.out)
	}
}

// The CLI checks the reply: a key, secret or CA that works while the Mac is
// locked when --only-when-unlocked asked otherwise is an error, never a
// quiet success, and says how to undo it.
func TestOnlyWhenUnlockedRefusesAReplyWithoutIt(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyCreate:
			out.Emit(control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: req.Args["name"], Type: "ecdsa-sha2-nistp256",
				Fingerprint: "SHA256:abc", Configured: true, WhileLocked: true, Rules: []string{"fallback: gate=block"}})
		case control.CmdSecretAdd:
			out.Emit(control.Secret{TypeMeta: control.Meta(control.KindSecret), Name: req.Args["name"], Stored: true, WhileLocked: true,
				Deliver: []string{"stdout"}, Rules: []string{"fallback: gate=block"}})
		}
	})
	if code := h.run("ssh-key", "create", "github", "--only-when-unlocked"); code != control.ExitError ||
		!strings.Contains(h.errb.String(), "nazar ssh-key delete github") || strings.Contains(h.out.String(), "created SSH key") {
		t.Fatalf("ssh-key create: %d %s %s", code, h.out, h.errb)
	}
	h.pipeIn(cliValue + "\n")
	if code := h.run("secret", "add", "GH", "--only-when-unlocked"); code != control.ExitError ||
		!strings.Contains(h.errb.String(), "nazar secret rm GH") || strings.Contains(h.out.String(), "added secret") {
		t.Fatalf("secret add: %d %s %s", code, h.out, h.errb)
	}
	w := kubeHarness(t)
	w.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		_ = out.Emit(setUpReply(t, req.Args["name"]))
	})
	if code := w.run("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443", "--only-when-unlocked"); code != control.ExitError ||
		!strings.Contains(w.errb.String(), "nazar k8s forget hydra-nazar") {
		t.Fatalf("k8s ca create: %d %s %s", code, w.out, w.errb)
	}
}

// The lists mark what works only while the Mac is unlocked: keys made with
// --only-when-unlocked or --always-ask and every key made before nazar
// knew the difference. A broken key is not marked (its record can't say).
func TestListsMarkOnlyWhenUnlocked(t *testing.T) {
	h := newHarness(t)
	key := func(name string, whileLocked, broken bool) control.SSHKey {
		return control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: name, Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:" + name,
			Configured: true, WhileLocked: whileLocked, Broken: broken, Rules: []string{"1: x", "fallback: gate=block"}}
	}
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyList:
			out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{
				key("bot", true, false), key("github", false, false), key("gone", false, true)}})
		case control.CmdSecretList:
			out.Emit(control.SecretList{TypeMeta: control.Meta(control.KindSecretList), Items: []control.Secret{
				{TypeMeta: control.Meta(control.KindSecret), Name: "BOT", Stored: true, WhileLocked: true, Rules: []string{"fallback: gate=block"}},
				{TypeMeta: control.Meta(control.KindSecret), Name: "GH", Stored: true, Rules: []string{"fallback: gate=block"}},
				{TypeMeta: control.Meta(control.KindSecret), Name: "NEW", Configured: true, Rules: []string{"fallback: gate=block"}},
			}})
		case control.CmdK8sList:
			out.Emit(control.K8sContextList{TypeMeta: control.Meta(control.KindK8sContextList), Items: []control.K8sContext{
				{TypeMeta: control.Meta(control.KindK8sContext), Name: "bot", State: control.K8sStateNoEntry, Remedy: "r",
					CA: &control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: "bot", Fingerprint: "aa", WhileLocked: true}},
				{TypeMeta: control.Meta(control.KindK8sContext), Name: "hydra", State: control.K8sStateNoEntry, Remedy: "r",
					CA: &control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: "hydra", Fingerprint: "bb"}},
			}})
		}
	})
	marked := func(cmd ...string) map[string]bool {
		h.out.Reset()
		if code := h.run(cmd...); code != 0 {
			t.Fatalf("%v: %d %s", cmd, code, h.errb)
		}
		m := map[string]bool{}
		name := ""
		for _, line := range strings.Split(h.out.String(), "\n") {
			if f := strings.Fields(line); len(f) > 0 && !strings.HasPrefix(line, " ") {
				name = f[0]
			}
			if strings.Contains(line, "only when unlocked") {
				m[name] = true
			}
		}
		return m
	}
	if m := marked("ssh-key", "list"); !m["github"] || m["bot"] || m["gone"] || len(m) != 1 {
		t.Errorf("ssh-key list marks %v:\n%s", m, h.out)
	}
	if m := marked("secret", "list"); !m["GH"] || m["BOT"] || m["NEW"] || len(m) != 1 {
		t.Errorf("secret list marks %v:\n%s", m, h.out)
	}
	if m := marked("k8s", "list"); !m["hydra"] || m["bot"] || len(m) != 1 {
		t.Errorf("k8s list marks %v:\n%s", m, h.out)
	}
}
