package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/atas/nazar/core/unixsock"
)

const (
	dialTimeout      = 3 * time.Second
	defaultMaxObject = 4 << 20
)

// PeerVerifier checks that the process listening on the control socket is
// Nazar.app before the CLI sends anything. Milestone 3 adds a code-signature
// check; SameUserVerifier is the baseline every build runs.
type PeerVerifier interface {
	VerifyPeer(c *net.UnixConn) error
}

// SameUserVerifier accepts a peer running as the current user.
type SameUserVerifier struct{}

func (SameUserVerifier) VerifyPeer(c *net.UnixConn) error { return unixsock.RequireSameUser(c) }

// SelfError is a PeerVerifier's refusal that is about this CLI, not about
// the peer: Do reports Err as it is, without saying the peer is not
// nazar-agent.
type SelfError struct{ Err error }

func (e *SelfError) Error() string { return e.Err.Error() }
func (e *SelfError) Unwrap() error { return e.Err }

// VerifierFunc adapts a function to PeerVerifier.
type VerifierFunc func(c *net.UnixConn) error

func (f VerifierFunc) VerifyPeer(c *net.UnixConn) error { return f(c) }

// Client talks to the control socket.
type Client struct {
	Socket string
	// Verifier must accept the listening process before the request is
	// sent; a Client without one refuses to talk at all.
	Verifier PeerVerifier
	// MaxObject bounds one reply line (default 4 MiB).
	MaxObject int
}

// Do sends req and calls fn for every reply object except a trailing
// Problem, which is returned as a *Problem error; an error from fn stops
// the stream and is returned as is. Connection failures are a *Problem with
// code "unavailable", a peer the Verifier rejects or a malformed reply a
// *Problem with code "error". Do returns nil once ctx ends (the user left a
// --follow stream).
func (c *Client) Do(ctx context.Context, req Request, fn func(kind string, raw json.RawMessage) error) error {
	if c.Verifier == nil {
		return NewProblem(CodeError, "control: no peer verifier configured")
	}
	if fn == nil {
		fn = func(string, json.RawMessage) error { return nil }
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return NewProblem(CodeUnavailable, "nazar-agent isn't running (cannot connect to %s: %v); run `nazar install`", c.Socket, err)
	}
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return NewProblem(CodeError, "control: %s is not a unix socket", c.Socket)
	}
	if err := c.Verifier.VerifyPeer(uc); err != nil {
		var self *SelfError
		if errors.As(err, &self) {
			return NewProblem(CodeError, "%v", self.Err)
		}
		return NewProblem(CodeError, "the process listening on %s is not nazar-agent: %v", c.Socket, err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	req.TypeMeta = Meta(KindRequest)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return NewProblem(CodeUnavailable, "control: sending request: %v", err)
	}

	max := c.MaxObject
	if max <= 0 {
		max = defaultMaxObject
	}
	br := bufio.NewReaderSize(conn, 64*1024)
	for {
		raw, err := readLine(br, max)
		if err != nil {
			switch {
			case errors.Is(err, io.EOF) && len(raw) == 0:
				return nil // the server is done
			case errors.Is(err, io.EOF):
				return NewProblem(CodeError, "control: reply ended in the middle of an object")
			case errors.Is(err, errLineTooLong):
				return NewProblem(CodeError, "control: reply object exceeds %d bytes", max)
			case ctx.Err() != nil:
				return nil
			}
			return NewProblem(CodeError, "control: reading reply: %v", err)
		}
		var meta TypeMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			return NewProblem(CodeError, "control: bad reply: %v", err)
		}
		if meta.APIVersion != APIVersion {
			return NewProblem(CodeError, "control: reply has apiVersion %q; this CLI understands %s", meta.APIVersion, APIVersion)
		}
		if meta.Kind == "" {
			return NewProblem(CodeError, "control: reply object has no kind")
		}
		if meta.Kind == KindProblem {
			var p Problem
			if err := json.Unmarshal(raw, &p); err != nil {
				return NewProblem(CodeError, "control: bad problem: %v", err)
			}
			return &p
		}
		if err := fn(meta.Kind, raw); err != nil {
			return err
		}
	}
}

var errLineTooLong = errors.New("line too long")

// readLine returns the next newline-terminated line (newline included) of
// at most max bytes. At EOF it returns what was read with io.EOF; a line
// beyond max is errLineTooLong.
func readLine(br *bufio.Reader, max int) (json.RawMessage, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > max {
			return nil, errLineTooLong
		}
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

// Call sends req and decodes the one reply object, which must be of the
// given kind, into out (a pointer to that kind's struct). No object, more
// than one, or one of another kind is an error.
func (c *Client) Call(ctx context.Context, req Request, kind string, out any) error {
	got := false
	err := c.Do(ctx, req, func(k string, raw json.RawMessage) error {
		if k != kind {
			return NewProblem(CodeError, "control: expected a %s reply, got %s", kind, k)
		}
		if got {
			return NewProblem(CodeError, "control: more than one %s in reply", kind)
		}
		got = true
		if err := json.Unmarshal(raw, out); err != nil {
			return NewProblem(CodeError, "control: bad %s reply: %v", kind, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !got {
		return NewProblem(CodeError, "control: no %s in reply", kind)
	}
	return nil
}
