package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/unixsock"
)

// MaxRequestSize bounds one request line, newline included.
const MaxRequestSize = 64 * 1024

// MaxLargeRequestSize bounds a secret.run request line, which carries the
// caller's candidate environment (secrets design 7.3); every other command
// keeps MaxRequestSize.
const MaxLargeRequestSize = 128 * 1024

const (
	// requestReadTimeout bounds reading the request line, not the life of
	// a --follow stream.
	requestReadTimeout = 5 * time.Second
	// replyWriteTimeout bounds one Emit, so a client that stops reading
	// cannot pin a handler forever.
	replyWriteTimeout = 30 * time.Second
)

// Emitter writes one reply object as one line.
type Emitter interface {
	Emit(v any) error
}

// Handler serves one request. It emits zero or more objects; a Problem, if
// any, must be last. ctx is cancelled when the client goes away. peer is
// the resolved caller (the CLI and its chain), for the audit log.
type Handler interface {
	Serve(ctx context.Context, req Request, peer *caller.Chain, out Emitter)
}

const (
	// acceptRetryMin and acceptRetryMax bound the back-off between retries
	// of a failed accept (fd exhaustion, an aborted connection, ...), as in
	// net/http. The listener stays bound, so giving up would leave every
	// later `nazar` command hanging instead of being answered.
	acceptRetryMin = 5 * time.Millisecond
	acceptRetryMax = time.Second
)

// Server accepts control connections.
type Server struct {
	Handler Handler
	// Resolve turns the connected socket's fd into the peer's caller chain.
	// It runs once per valid request, after the request line was accepted.
	// nil leaves the peer nil.
	Resolve func(fd int) *caller.Chain
	Logf    func(format string, args ...any)
	// VerifyCLI checks that the connection's peer is the genuine nazar CLI
	// (secrets design 7.3) and returns the process it checked; an
	// error when it is not. It runs only for a value command
	// (ValueCommand), after the request line was read and the caller chain
	// resolved, and the peer counts as the CLI (PeerIsNazarCLI) only when
	// the process it vouched for is that chain's peer: the audit token
	// names whoever last touched the client socket, so two reads of it can
	// name two processes. nil means no peer is ever the CLI: no value is
	// returned to anyone.
	//
	// KNOWN LIMIT (THREAT-MODEL 4.10): a pass means "the process the token
	// names is the genuine CLI", not "the genuine CLI wrote this request".
	// A same-user process that shares the connection with a genuine CLI
	// (an inherited descriptor, or the CLI exec'd over the process that
	// connected) can make it the one the token names and read the reply.
	VerifyCLI func(fd int) (platform.ProcessRef, error)

	// peerCheck gates every accepted connection before a byte is read; nil
	// means unixsock.RequireSameUser. Tests swap it to prove the gate is
	// wired and fails closed.
	peerCheck func(c *net.UnixConn) error

	// conns holds every accepted connection whose goroutine is still
	// running, so Serve can close them when the listener goes away; wg
	// counts those goroutines so Serve returns only once they are gone.
	mu    sync.Mutex
	conns map[*net.UnixConn]struct{}
	wg    sync.WaitGroup
}

// track registers an accepted connection and its goroutine. It is called
// from Serve's own goroutine, before the connection goroutine starts, so
// the WaitGroup is never grown concurrently with the Wait in Serve.
func (s *Server) track(c *net.UnixConn) {
	s.mu.Lock()
	if s.conns == nil {
		s.conns = make(map[*net.UnixConn]struct{})
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	s.wg.Add(1)
}

// untrack is the connection goroutine's last act: it closes the connection
// (whether or not it was closed already), forgets it and releases Serve.
func (s *Server) untrack(c *net.UnixConn) {
	_ = c.Close()
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	s.wg.Done()
}

// closeConns closes every connection still being served. Closing it ends
// the drain in serveConn, which cancels the handler's ctx.
func (s *Server) closeConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Server) checkPeer(c *net.UnixConn) error {
	if s.peerCheck != nil {
		return s.peerCheck(c)
	}
	return unixsock.RequireSameUser(c)
}

// Serve accepts connections until l is closed; that is the only way it
// returns. It then closes every connection it is still serving, which
// cancels the running handlers' ctx, waits for their goroutines to finish
// and returns nil: after Serve returns nothing it started is still running,
// so a handler must return once its ctx is cancelled. Any other accept
// error (EMFILE, ECONNABORTED, ...) is logged and retried with back-off,
// because the socket stays bound while Serve is not accepting and clients
// would hang on it. Peers running as another user are dropped before
// anything is read. Serve must not run twice at once on one Server.
func (s *Server) Serve(l *net.UnixListener) error {
	var delay time.Duration
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.closeConns()
				s.wg.Wait()
				return nil
			}
			if delay == 0 {
				delay = acceptRetryMin
			} else {
				delay = min(delay*2, acceptRetryMax)
			}
			s.logf("control: accept: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		s.track(c)
		go func() {
			defer s.untrack(c)
			if err := s.checkPeer(c); err != nil {
				s.logf("control: refusing connection: %v", err)
				return
			}
			s.serveConn(c, func(req Request, peer *caller.Chain) bool { return s.isCLI(c, req, peer) }, func() *caller.Chain {
				if s.Resolve == nil {
					return nil
				}
				var peer *caller.Chain
				if err := unixsock.WithFD(c, func(fd int) error {
					peer = s.Resolve(fd)
					return nil
				}); err != nil {
					s.logf("control: resolving peer: %v", err)
				}
				return peer
			})
		}()
	}
}

// ServeConn reads one request from c and serves it with the given peer. It
// returns when the handler does and does not close c.
// A peer served this way is never the nazar CLI (PeerIsNazarCLI): there
// is no socket to check.
func (s *Server) ServeConn(c net.Conn, peer *caller.Chain) {
	s.serveConn(c, func(Request, *caller.Chain) bool { return false }, func() *caller.Chain { return peer })
}

// peerIsCLIKey marks a handler's context when VerifyCLI accepted the peer.
type peerIsCLIKey struct{}

// PeerIsNazarCLI reports whether the server checked the peer of this
// request and found the genuine nazar CLI. Only the server sets it, only
// for a value command, and only when VerifyCLI accepted the peer.
func PeerIsNazarCLI(ctx context.Context) bool {
	v, _ := ctx.Value(peerIsCLIKey{}).(bool)
	return v
}

// isCLI runs VerifyCLI on c for a value command, and holds it to the peer
// of the resolved chain.
func (s *Server) isCLI(c *net.UnixConn, req Request, peer *caller.Chain) bool {
	if !ValueCommand(req.Command) || s.VerifyCLI == nil || peer == nil {
		return false
	}
	p, ok := peer.Peer()
	if !ok || p.Ref.IsZero() {
		return false
	}
	var verr error
	var checked platform.ProcessRef
	if err := unixsock.WithFD(c, func(fd int) error {
		checked, verr = s.VerifyCLI(fd)
		return nil
	}); err != nil {
		s.logf("control: checking the peer: %v", err)
		return false
	}
	if verr != nil {
		s.logf("control: %s from a peer that is not the nazar CLI: %v", req.Command, verr)
		return false
	}
	if checked != p.Ref {
		s.logf("control: %s: the process checked (%s) is not the caller (%s)", req.Command, checked, p.Ref)
		return false
	}
	return true
}

type emitter struct {
	mu   sync.Mutex
	conn net.Conn
	enc  *json.Encoder
}

func (e *emitter) Emit(v any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.conn.SetWriteDeadline(time.Now().Add(replyWriteTimeout))
	return e.enc.Encode(v)
}

func (s *Server) serveConn(c net.Conn, isCLI func(Request, *caller.Chain) bool, resolve func() *caller.Chain) {
	out := &emitter{conn: c, enc: json.NewEncoder(c)}
	req, p := readRequest(c)
	if p != nil {
		s.logf("control: %s", p.Message)
		_ = out.Emit(p)
		return
	}
	if s.Handler == nil {
		_ = out.Emit(NewProblem(CodeError, "control: no handler"))
		return
	}
	peer := resolve()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if isCLI(req, peer) {
		ctx = context.WithValue(ctx, peerIsCLIKey{}, true)
	}
	// Anything the client sends after its request is discarded; the read
	// ending (the client closed or misbehaved, or Serve closed c) cancels
	// the handler. When the handler returns, an expired deadline ends the
	// drain in turn, and serveConn returns only once it has.
	_ = c.SetReadDeadline(time.Time{})
	drained := make(chan struct{})
	defer func() {
		_ = c.SetReadDeadline(time.Now())
		<-drained
	}()
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, c)
		cancel()
	}()
	s.Handler.Serve(ctx, req, peer, out)
}

// readRequest reads and validates the one request line. Any failure is a
// usage Problem; nothing of the offending input is echoed.
func readRequest(c net.Conn) (Request, *Problem) {
	var req Request
	_ = c.SetReadDeadline(time.Now().Add(requestReadTimeout))
	br := bufio.NewReader(io.LimitReader(c, MaxLargeRequestSize+1))
	line, err := br.ReadBytes('\n')
	if len(line) > MaxLargeRequestSize {
		return req, NewProblem(CodeUsage, "control: request too large (max %d bytes)", MaxLargeRequestSize)
	}
	if err != nil {
		return req, NewProblem(CodeUsage, "control: no complete request line within %v (max %d bytes)", requestReadTimeout, MaxRequestSize)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, NewProblem(CodeUsage, "control: bad request: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return req, NewProblem(CodeUsage, "control: bad request: data after the request object")
	}
	if req.APIVersion != APIVersion || req.Kind != KindRequest {
		return req, NewProblem(CodeUsage, "control: bad request: expected apiVersion %q and kind %q", APIVersion, KindRequest)
	}
	if len(line) > MaxRequestSize && req.Command != CmdSecretRun {
		return req, NewProblem(CodeUsage, "control: request too large (max %d bytes)", MaxRequestSize)
	}
	return req, nil
}
