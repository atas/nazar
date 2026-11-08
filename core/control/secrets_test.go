package control

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/platform"
)

// Secrets design 7.2, 7.3: the secrets commands and kinds, and the
// genuine-CLI check of the peer of every command that returns a value.

func TestSecretConstants(t *testing.T) {
	for got, want := range map[string]string{
		KindSecret: "Secret", KindSecretList: "SecretList", KindSecretValue: "SecretValue",
		CmdSecretAdd: "secret.add", CmdSecretList: "secret.list", CmdSecretDelete: "secret.delete",
		CmdSecretGet: "secret.get", CmdSecretHelper: "secret.helper",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
	for _, c := range []string{CmdSecretGet, CmdSecretHelper} {
		if !ValueCommand(c) {
			t.Errorf("%s returns a value", c)
		}
	}
	for _, c := range []string{CmdSecretAdd, CmdSecretList, CmdSecretDelete, CmdStatus, CmdSSHKeyCreate, "", "secret.get ", "Secret.get"} {
		if ValueCommand(c) {
			t.Errorf("%q returns no value", c)
		}
	}
}

// The server runs VerifyCLI on the connection of a value command only, and
// tells the handler what it found through the context; a handler that
// never asks, a server without VerifyCLI and ServeConn all fail closed.
func TestPeerIsNazarCLIOnlyWhenTheCheckAccepts(t *testing.T) {
	var verdict error
	var checks atomic.Int32
	var fdType atomic.Int32
	seen := make(chan bool, 1)
	h := &stubHandler{fn: func(ctx context.Context, req Request, out Emitter) {
		seen <- PeerIsNazarCLI(ctx)
		_ = out.Emit(NewProblem(CodeError, "done"))
	}}
	cliRef := platform.ProcessRef{PID: 4201, Generation: 7}
	ts := serveWith(t, h, func(s *Server) {
		s.VerifyCLI = func(fd int) (platform.ProcessRef, error) {
			checks.Add(1)
			typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
			if err != nil {
				typ = -1
			}
			fdType.Store(int32(typ))
			return cliRef, verdict
		}
	})
	ask := func(cmd string) bool {
		t.Helper()
		_ = client(ts.path).Do(context.Background(), NewRequest(cmd, nil), ignore)
		select {
		case v := <-seen:
			return v
		case <-time.After(3 * time.Second):
			t.Fatal("handler not called")
		}
		return false
	}
	ts.chain = &caller.Chain{Procs: []platform.ProcessInfo{{Ref: cliRef}}}
	if !ask(CmdSecretGet) || checks.Load() != 1 || fdType.Load() != syscall.SOCK_STREAM {
		t.Fatalf("a genuine CLI asking for a value: checks %d, fd type %d", checks.Load(), fdType.Load())
	}
	verdict = errors.New("peer is not the nazar CLI")
	if ask(CmdSecretHelper) || checks.Load() != 2 {
		t.Fatal("a peer the check refuses is never the CLI")
	}
	verdict = nil
	if ask(CmdSecretList) || checks.Load() != 2 {
		t.Fatal("a command that returns no value is never checked and never marked")
	}

	noCheck := make(chan bool, 1)
	plain := serve(t, &stubHandler{fn: func(ctx context.Context, req Request, out Emitter) {
		noCheck <- PeerIsNazarCLI(ctx)
		_ = out.Emit(NewProblem(CodeError, "done"))
	}})
	_ = client(plain.path).Do(context.Background(), NewRequest(CmdSecretGet, nil), ignore)
	if <-noCheck {
		t.Fatal("a server without VerifyCLI must treat no peer as the CLI")
	}

	a, b := net.Pipe()
	defer a.Close()
	srv := &Server{Handler: &stubHandler{fn: func(ctx context.Context, req Request, out Emitter) {
		noCheck <- PeerIsNazarCLI(ctx)
	}}, VerifyCLI: func(int) (platform.ProcessRef, error) { return platform.ProcessRef{}, nil }}
	go srv.ServeConn(b, &caller.Chain{Unknown: true})
	asyncWrite(t, a, []byte(mustJSON(t, NewRequest(CmdSecretGet, nil))+"\n"))
	select {
	case v := <-noCheck:
		if v {
			t.Fatal("ServeConn has no socket to check, so its peer is never the CLI")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler not called")
	}
	if PeerIsNazarCLI(context.Background()) {
		t.Fatal("a plain context is not the CLI")
	}
}

// Security review: the check and the caller chain must name the same
// process. The audit token names whoever last touched the client socket, so
// two reads can name two processes: a genuine CLI made to touch the socket
// between them would vouch for a chain that is not its own.
func TestPeerIsNazarCLIOnlyForTheResolvedPeer(t *testing.T) {
	seen := make(chan bool, 1)
	h := &stubHandler{fn: func(ctx context.Context, req Request, out Emitter) {
		seen <- PeerIsNazarCLI(ctx)
		_ = out.Emit(NewProblem(CodeError, "done"))
	}}
	verified := platform.ProcessRef{PID: 4201, Generation: 7}
	ts := serveWith(t, h, func(s *Server) {
		s.VerifyCLI = func(int) (platform.ProcessRef, error) { return verified, nil }
	})
	for _, c := range []struct {
		chain *caller.Chain
		want  bool
	}{
		{&caller.Chain{Procs: []platform.ProcessInfo{{Ref: verified}}}, true},
		{&caller.Chain{Procs: []platform.ProcessInfo{{Ref: platform.ProcessRef{PID: 100, Generation: 3}}}}, false},
		{&caller.Chain{Procs: []platform.ProcessInfo{{Ref: platform.ProcessRef{PID: 4201, Generation: 8}}}}, false},
		{&caller.Chain{Unknown: true}, false},
	} {
		ts.chain = c.chain
		_ = client(ts.path).Do(context.Background(), NewRequest(CmdSecretGet, nil), ignore)
		select {
		case got := <-seen:
			if got != c.want {
				t.Errorf("chain %+v: PeerIsNazarCLI = %v, want %v", c.chain.Procs, got, c.want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("handler not called")
		}
	}
}
