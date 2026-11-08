package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

// sign-git must not take the agent socket from config.yaml on disk:
// that file is not approved (spec 4.8), so anything that can write it could
// point git's signing at its own agent. The socket is $NAZAR_AGENT_SOCK if
// set, else the approved socket the running app reports (Status.AgentPath
// over the control socket), else ~/.nazar/run/agent.sock. Spec 4.8, 5, 6.

// execSock returns the SSH_AUTH_SOCK sign-git passed to ssh-keygen; it must
// be set exactly once.
func execSock(t *testing.T, h *harness) string {
	t.Helper()
	if len(h.execed) < 2 || h.execed[0] != sshKeygen {
		t.Fatalf("ssh-keygen not executed: %q", h.execed)
	}
	var socks []string
	for _, kv := range h.execed {
		if v, ok := strings.CutPrefix(kv, "SSH_AUTH_SOCK="); ok {
			socks = append(socks, v)
		}
	}
	if len(socks) != 1 {
		t.Fatalf("SSH_AUTH_SOCK set %d times: %q", len(socks), h.execed)
	}
	return socks[0]
}

// signGitOnce runs sign-git as git does and returns the socket it chose.
// Nothing may be written to stdout: git reads ssh-keygen's stdout for the
// signature, and the wrapper shares it.
func signGitOnce(t *testing.T, h *harness) string {
	t.Helper()
	h.execed = nil
	h.out.Reset()
	h.errb.Reset()
	done := make(chan struct{})
	go func() { defer close(done); h.a.signGit([]string{"-Y", "sign", "-n", "git", "-f", "/k.pub"}) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("sign-git hung: a git commit would never finish")
	}
	if h.out.Len() != 0 {
		t.Fatalf("sign-git wrote to stdout (git reads the signature from it): %q", h.out)
	}
	return execSock(t, h)
}

func statusWith(path string) handlerFunc {
	return func(_ context.Context, req control.Request, out control.Emitter) {
		if req.Command != control.CmdStatus {
			out.Emit(control.NewProblem(control.CodeError, "unexpected %s", req.Command))
			return
		}
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{}, AgentPath: path})
	}
}

const evilCfg = "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  socket: ~/evil.sock\n"

func defaultSock(h *harness) string { return layout.AgentSocket(h.home) }

// The running app's approved socket wins over a valid but unapproved
// config.yaml naming another one; sign-git only asks for status.
func TestSignGitUsesApprovedSocketFromApp(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, evilCfg)
	approved := filepath.Join(h.home, "approved", "agent.sock")
	h.serve(t, statusWith(approved))
	if got := signGitOnce(t, h); got != approved {
		t.Fatalf("SSH_AUTH_SOCK=%q, want the app's approved socket %q", got, approved)
	}
	reqs := h.requests()
	if len(reqs) == 0 {
		t.Fatal("sign-git did not ask the app for its socket")
	}
	for _, r := range reqs {
		if r.Command != control.CmdStatus || r.Follow {
			t.Fatalf("sign-git sent %q (follow=%v); only a one-shot status is needed", r.Command, r.Follow)
		}
	}
	// The same through `nazar sign-git`.
	h.execed = nil
	h.a.run([]string{"sign-git", "-Y", "sign"})
	if got := execSock(t, h); got != approved {
		t.Fatalf("nazar sign-git: SSH_AUTH_SOCK=%q, want %q", got, approved)
	}
}

// NAZAR_AGENT_SOCK overrides everything and needs no round trip.
func TestSignGitEnvOverrideWins(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, evilCfg)
	h.serve(t, statusWith(filepath.Join(h.home, "approved.sock")))
	h.env["NAZAR_AGENT_SOCK"] = "/tmp/override.sock"
	if got := signGitOnce(t, h); got != "/tmp/override.sock" {
		t.Fatalf("SSH_AUTH_SOCK=%q, want the override", got)
	}
	if n := len(h.requests()); n != 0 {
		t.Fatalf("%d control requests sent although NAZAR_AGENT_SOCK is set", n)
	}
}

// Without an answer from the app, the default socket is used: never a
// socket named in the config file on disk, valid or not, wherever
// NAZAR_CONFIG points.
func TestSignGitFallsBackToDefaultNotConfigFile(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, h *harness)
	}{
		{"app not running", func(*testing.T, *harness) {}},
		{"app not running, NAZAR_CONFIG", func(t *testing.T, h *harness) {
			p := filepath.Join(h.home, "other.yaml")
			writeFile(t, p, evilCfg)
			h.env["NAZAR_CONFIG"] = p
		}},
		{"app reports no socket", func(t *testing.T, h *harness) { h.serve(t, statusWith("")) }},
		{"app reports a relative socket", func(t *testing.T, h *harness) { h.serve(t, statusWith("evil.sock")) }},
		{"app answers with a problem", func(t *testing.T, h *harness) {
			h.serve(t, func(_ context.Context, _ control.Request, out control.Emitter) {
				out.Emit(control.NewProblem(control.CodeError, "busy"))
			})
		}},
		{"app answers garbage", func(t *testing.T, h *harness) {
			h.serve(t, func(_ context.Context, _ control.Request, out control.Emitter) {
				out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList)})
			})
		}},
		{"control peer fails verification", func(t *testing.T, h *harness) {
			h.serve(t, statusWith(filepath.Join(h.home, "impostor.sock")))
			h.a.verifier = control.VerifierFunc(func(*net.UnixConn) error { return errors.New("not nazar-agent") })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			writeConfig(t, h, evilCfg)
			tc.setup(t, h)
			got := signGitOnce(t, h)
			if got != defaultSock(h) {
				t.Fatalf("SSH_AUTH_SOCK=%q, want the default %q", got, defaultSock(h))
			}
		})
	}
}

// An app that accepts the connection but never answers must not hang git:
// sign-git gives up within a bounded time and uses the default socket.
func TestSignGitStalledAppFallsBackToDefault(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, evilCfg)
	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	h.serve(t, func(ctx context.Context, _ control.Request, _ control.Emitter) {
		select {
		case <-stall:
		case <-ctx.Done():
		}
	})
	if got := signGitOnce(t, h); got != defaultSock(h) {
		t.Fatalf("SSH_AUTH_SOCK=%q, want the default %q", got, defaultSock(h))
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
