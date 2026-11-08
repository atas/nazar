package sshagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/atas/nazar/core/audit"
)

// Spec 4.6: every request is logged: who asked, for what, and what
// happened. A SIGN_REQUEST the agent refuses before it reaches the broker
// (after a refused session-bind, or with a userauth that contradicts the
// connection's binding or names another key) is one audit line with
// decision=blocked and a fixed reason: never a prompt, never a signature,
// and never client-chosen bytes in the reason.

// refusedAudited checks the audit lines written so far: want of them
// (want < 0: at least one), each a blocked line for ssh:github from the
// test's iTerm2 tab, with a fixed, printable reason.
func refusedAudited(t *testing.T, e *env, want int) []map[string]string {
	t.Helper()
	lines := e.sink.Lines()
	if want >= 0 && len(lines) != want {
		t.Fatalf("want %d audit lines for the refused requests, got %d:\n%s", want, len(lines), strings.Join(lines, "\n"))
	}
	if want < 0 && len(lines) == 0 {
		t.Fatal("a refused SIGN_REQUEST must be audited (spec 4.6: every request is logged)")
	}
	var out []map[string]string
	for _, l := range lines {
		if hasControl(l) {
			t.Fatalf("audit line carries control characters: %q", l)
		}
		f, err := audit.ParseLine(l)
		if err != nil {
			t.Fatalf("unparseable audit line %q: %v", l, err)
		}
		if f["decision"] != "blocked" || f["target"] != "ssh:github" {
			t.Fatalf("refused request audited as %v", f)
		}
		if f["reason"] == "" || strings.Contains(f["reason"], "SHA256") {
			t.Fatalf("refusal reason must be a fixed message: %q", f["reason"])
		}
		if f["app"] != "com.googlecode.iterm2" || f["chain"] == "" {
			t.Fatalf("who asked must be logged: %v", f)
		}
		out = append(out, f)
	}
	return out
}

type refusal struct {
	name string
	// run makes one refused SIGN_REQUEST on c; v varies the client-chosen
	// bytes (session IDs, keys) between runs of the same refusal.
	run func(t *testing.T, e *env, c agent.ExtendedAgent, v byte)
}

func otherClientKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustFail(t *testing.T, c agent.ExtendedAgent, e *env, data []byte) {
	t.Helper()
	if _, err := c.Sign(e.pub, data); err == nil {
		t.Fatal("the request must be refused")
	}
}

var refusals = []refusal{
	{"after a refused session-bind", func(t *testing.T, e *env, c agent.ExtendedAgent, v byte) {
		sid := bytes.Repeat([]byte{v}, 32)
		sig, _ := e.signer.Sign(rand.Reader, []byte("another session"))
		if _, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
			HostKey, SessionID, Signature []byte
			Fwd                           bool
		}{e.signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), false})); err == nil {
			t.Fatal("forged bind accepted")
		}
		mustFail(t, c, e, sshsig("git"))
	}},
	{"userauth for another session", func(t *testing.T, e *env, c agent.ExtendedAgent, v byte) {
		if err := e.bind(t, c, bytes.Repeat([]byte{v}, 32), false); err != nil {
			t.Fatal(err)
		}
		mustFail(t, c, e, userauth(bytes.Repeat([]byte{v + 1}, 32), e.pub.Marshal(), nil))
	}},
	{"userauth host key differs from the bind", func(t *testing.T, e *env, c agent.ExtendedAgent, v byte) {
		sid := bytes.Repeat([]byte{v}, 32)
		if err := e.bind(t, c, sid, false); err != nil {
			t.Fatal(err)
		}
		mustFail(t, c, e, userauth(sid, e.pub.Marshal(), otherHostSigner(t).PublicKey()))
	}},
	{"userauth names another key", func(t *testing.T, e *env, c agent.ExtendedAgent, v byte) {
		mustFail(t, c, e, userauth(bytes.Repeat([]byte{v}, 32), otherClientKey(t).Marshal(), nil))
	}},
	{"userauth on a forwarding hop", func(t *testing.T, e *env, c agent.ExtendedAgent, v byte) {
		hop := bytes.Repeat([]byte{v}, 32)
		if err := e.bind(t, c, hop, true); err != nil {
			t.Fatal(err)
		}
		mustFail(t, c, e, userauth(hop, e.pub.Marshal(), e.signer.PublicKey()))
	}},
	{"forwarded userauth without host key", func(t *testing.T, e *env, c agent.ExtendedAgent, v byte) {
		if err := e.bind(t, c, bytes.Repeat([]byte{v}, 32), true); err != nil {
			t.Fatal(err)
		}
		sid := bytes.Repeat([]byte{v + 1}, 32)
		if err := e.bind(t, c, sid, false); err != nil {
			t.Fatal(err)
		}
		mustFail(t, c, e, userauth(sid, e.pub.Marshal(), nil))
	}},
}

// Each refusal class is one blocked audit line; the same class gives the
// same reason whatever bytes the client sent, and none of those bytes
// reach the line.
func TestRefusedSignRequestsAreAudited(t *testing.T) {
	reasons := map[string]string{}
	for _, r := range refusals {
		t.Run(r.name, func(t *testing.T) {
			e := newEnv(t)
			var got []string
			for i, v := range []byte{0x11, 0x5a} {
				c, _ := e.client(t, e.peer)
				r.run(t, e, c, v)
				lines := refusedAudited(t, e, i+1)
				got = append(got, lines[i]["reason"])
				for _, l := range e.sink.Lines() {
					for _, b := range [][]byte{bytes.Repeat([]byte{v}, 32), bytes.Repeat([]byte{v + 1}, 32)} {
						if strings.Contains(strings.ToLower(l), hex.EncodeToString(b)[:16]) {
							t.Fatalf("client bytes reached the audit line: %q", l)
						}
					}
				}
			}
			if got[0] != got[1] {
				t.Fatalf("the reason must be fixed per refusal, got %q and %q", got[0], got[1])
			}
			if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
				t.Fatal("refused before any prompt or signature")
			}
			reasons[r.name] = got[0]
		})
	}
	// "What touched my key?" must tell a refused bind from a contradictory
	// userauth.
	if a, b := reasons["after a refused session-bind"], reasons["userauth names another key"]; a != "" && a == b {
		t.Fatalf("a refused bind and a userauth for another key share the reason %q", a)
	}
}

// A refusal is logged once, by the agent, and does not turn later requests
// into double lines: a valid request afterwards is exactly one more line.
func TestRefusalThenValidRequestAuditsOnceEach(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	mustFail(t, c, e, userauth(bytes.Repeat([]byte{3}, 32), otherClientKey(t).Marshal(), nil))
	refusedAudited(t, e, 1)
	if _, err := c.Sign(e.pub, sshsig("git")); err != nil {
		t.Fatal(err)
	}
	lines := e.sink.Lines()
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	f, _ := audit.ParseLine(lines[1])
	if f["decision"] != "approved" || f["operation"] != "sign git commit" {
		t.Fatalf("%v", f)
	}
}
