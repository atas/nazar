// Package sshagent serves the SSH agent protocol on nazar's agent socket
// (spec 5): REQUEST_IDENTITIES (the keys the caller may use), SIGN_REQUEST
// through the broker, the session-bind@openssh.com extension, and
// SSH_AGENT_FAILURE for everything else (adding/removing keys, lock/unlock,
// other extensions).
package sshagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/ssh/agentproto"
	"github.com/atas/nazar/core/ssh/knownhosts"
	"github.com/atas/nazar/core/unixsock"
)

// MaxBinds bounds session-bind requests per connection (as OpenSSH does).
const MaxBinds = 16

const (
	// acceptRetryMin and acceptRetryMax bound the back-off between retries
	// of a failed accept (fd exhaustion, an aborted connection, ...), as in
	// net/http and core/control. The listener stays bound, so giving up
	// would leave every later ssh and git hanging instead of being answered.
	acceptRetryMin = 5 * time.Millisecond
	acceptRetryMax = time.Second
)

// Server is the agent. All fields are required except Logf.
type Server struct {
	Keys       *keys.Registry
	Broker     *broker.Broker
	Resolver   *caller.Resolver
	KnownHosts func() string // path of known_hosts
	Logf       func(format string, args ...any)

	// peerCheck gates every accepted connection before a byte is read; nil
	// means unixsock.RequireSameUser. Tests swap it to prove the gate is
	// wired and fails closed (as core/control does).
	peerCheck func(c *net.UnixConn) error
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// errText renders an error for the log. Errors on the request path wrap
// x/crypto errors that embed client-chosen bytes raw (a key algorithm, for
// one), so the text is reduced to printable runes and bounded before it is
// interpolated: a client never gets to write its own log lines.
func errText(err error) string {
	return agentproto.Printable(err.Error(), 200)
}

// checkPeer runs the UID gate: peerCheck when set, else
// unixsock.RequireSameUser, which refuses a peer whose UID cannot be read.
func (s *Server) checkPeer(c *net.UnixConn) error {
	if s.peerCheck != nil {
		return s.peerCheck(c)
	}
	return unixsock.RequireSameUser(c)
}

// Serve accepts connections until l is closed, each on its own goroutine;
// that is the only way it returns, and it then returns nil. Any other
// accept error (EMFILE, ECONNABORTED, ...) is logged and retried with
// back-off, as core/control does: the socket stays bound while Serve is
// not accepting, so giving up would leave every later ssh and git hanging
// on REQUEST_IDENTITIES instead of failing, and the daemon (which runs
// Serve on a goroutine and discards its result) would never notice. The
// trigger is reachable from a forwarded peer, which can open as many agent
// channels, hence local connections, as it likes.
func (s *Server) Serve(l *net.UnixListener) error {
	var delay time.Duration
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if delay == 0 {
				delay = acceptRetryMin
			} else {
				delay = min(delay*2, acceptRetryMax)
			}
			s.logf("agent: accept: %s; retrying in %v", errText(err), delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go s.handle(c)
	}
}

// handle serves one accepted connection: peers of another UID are dropped
// before a byte is read, and the caller chain is resolved once from the
// socket peer. A peer that cannot be identified gets an unknown chain, so
// it is judged by the fallback rule and never by someone else's.
func (s *Server) handle(c *net.UnixConn) {
	defer c.Close()
	if err := s.checkPeer(c); err != nil {
		s.logf("agent: refusing connection: %s", errText(err))
		return
	}
	chain := &caller.Chain{Unknown: true, Truncated: true}
	err := unixsock.WithFD(c, func(fd int) error {
		chain = s.Resolver.ResolveFD(fd)
		return nil
	})
	if err != nil {
		s.logf("agent: cannot identify peer: %s", errText(err))
		chain = &caller.Chain{Unknown: true, Truncated: true}
	}
	s.ServeConn(c, chain)
}

// conn is per-connection protocol state.
type conn struct {
	binds []agentproto.SessionBind
	// bindFailed is set once a session-bind on this connection was refused.
	// OpenSSH keeps forwarding the agent after a failed bind, so a bind
	// nazar cannot parse or verify (a host-key algorithm x/crypto does not
	// know yet, for one) would otherwise leave a forwarded connection looking
	// local: judged by the local tab's rules and riding on its remembered
	// approvals. As ssh-agent does for constrained keys ("previous session
	// bind failed on socket"), the connection then signs nothing. A later
	// successful bind does not lift it: that is exactly what the remote
	// ssh's own bind would look like.
	bindFailed bool
}

// forwarded reports whether any bind on the connection came through a
// forwarded agent. Once the local ssh has bound with is_forwarding, every
// later request on the connection comes from the remote side, whatever
// binds the remote ssh adds afterwards.
func (c *conn) forwarded() bool {
	for _, b := range c.binds {
		if b.Forwarding {
			return true
		}
	}
	return false
}

// ServeConn speaks the protocol on rw for a caller already resolved to
// chain (nil is an unknown caller). It returns when the peer disconnects
// or sends a malformed frame (empty or over agentproto.MaxMessageLen).
func (s *Server) ServeConn(rw io.ReadWriter, chain *caller.Chain) {
	if chain == nil {
		chain = &caller.Chain{Unknown: true, Truncated: true}
	}
	st := &conn{}
	for {
		body, err := agentproto.ReadMessage(rw)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logf("agent: closing connection: %s", errText(err))
			}
			return
		}
		if err := agentproto.WriteMessage(rw, s.dispatch(body, chain, st)); err != nil {
			return
		}
	}
}

// dispatch answers one request. body is never empty: ReadMessage refuses
// empty frames.
func (s *Server) dispatch(body []byte, chain *caller.Chain, st *conn) []byte {
	switch body[0] {
	case agentproto.MsgRequestIdentities:
		if len(body) != 1 {
			return agentproto.Failure()
		}
		return s.identities(chain)
	case agentproto.MsgSignRequest:
		return s.sign(body, chain, st)
	case agentproto.MsgExtension:
		return s.extension(body, st)
	}
	// ADD_IDENTITY, REMOVE_*, LOCK/UNLOCK, smartcard and unknown messages:
	// nazar never accepts keys from clients and has no lock state.
	return agentproto.Failure()
}

// extension handles session-bind@openssh.com; every other extension fails.
// A bind that does not verify is not recorded, so a client cannot make the
// connection claim a host key it cannot prove; and it marks the connection,
// so a bind nazar could not judge never lets requests pass as unbound.
func (s *Server) extension(body []byte, st *conn) []byte {
	ext, err := agentproto.ParseExtension(body)
	if err != nil || ext.Name != agentproto.SessionBindName {
		return agentproto.Failure()
	}
	if len(st.binds) >= MaxBinds {
		st.bindFailed = true
		s.logf("agent: refusing session-bind beyond %d per connection", MaxBinds)
		return agentproto.Failure()
	}
	b, err := agentproto.ParseSessionBind(ext.Contents)
	if err != nil {
		st.bindFailed = true
		s.logf("agent: refusing session-bind: %s", errText(err))
		return agentproto.Failure()
	}
	// The same rules as OpenSSH's process_ext_session_bind, checked against
	// every recorded bind. An authentication bind (is_forwarding false) is
	// final: ssh sends it right before userauth and never binds again on
	// that connection, so a later bind is someone else's. And a session ID
	// is recorded once: were it bound again under another key, the latest
	// bind would rename the destination of a session already proved to
	// belong to a different host (OpenSSH: "session ID recorded against
	// different key"). The same key again is refused too (OpenSSH treats it
	// as a no-op); no ssh sends it, and refusing keeps the rule simple.
	for _, prev := range st.binds {
		if !prev.Forwarding {
			st.bindFailed = true
			s.logf("agent: refusing session-bind: the connection is already bound for authentication")
			return agentproto.Failure()
		}
		if bytes.Equal(prev.SessionID, b.SessionID) {
			st.bindFailed = true
			s.logf("agent: refusing session-bind: session ID already recorded on this connection")
			return agentproto.Failure()
		}
	}
	st.binds = append(st.binds, b)
	return agentproto.Success()
}

// identities answers REQUEST_IDENTITIES (spec 5) with the keys nazar holds
// that this caller may use, as the broker decides and reports
// (Broker.Offer): the keys of the active (approved) config whose policy for
// the chain is not block. A key whose record cannot be read is not offered
// either, and without an active config nothing is.
func (s *Server) identities(chain *caller.Chain) []byte {
	list, err := s.Keys.List()
	if err != nil {
		s.logf("agent: listing keys: %s", errText(err))
		return agentproto.Failure()
	}
	var held []keys.Info
	var names []string
	for _, k := range list {
		if !k.Broken {
			held, names = append(held, k), append(names, k.Name)
		}
	}
	ids := make([]agentproto.Identity, 0, len(held))
	for i, ok := range s.Broker.Offer(chain, names) {
		if ok {
			ids = append(ids, agentproto.Identity{Blob: held[i].Blob, Comment: held[i].Name})
		}
	}
	return agentproto.MarshalIdentities(ids)
}

// Refusal reasons for a SIGN_REQUEST the agent refuses before it reaches
// the broker. Each is a fixed message (spec 4.6: it is written to the audit
// log, so it never carries client-chosen bytes) and distinct per class, so
// "what touched my key?" tells a refused bind from a contradictory userauth.
var (
	errBindRefused       = errors.New("an earlier session-bind on this connection was refused")
	errOtherKey          = errors.New("userauth names a different key than the one asked to sign")
	errSessionMismatch   = errors.New("userauth session does not match the session-bind")
	errForwardingHop     = errors.New("userauth on a forwarding hop")
	errNoForwardedHostKy = errors.New("userauth carries no host key on a forwarded connection")
	errHostKeyMismatch   = errors.New("userauth host key does not match the session-bind")
)

// sign runs a SIGN_REQUEST through the broker. A key nazar does not hold
// fails at once (there is no target to log). A connection on which a
// session-bind was refused, or a userauth that contradicts the request or
// the connection's binding, is refused before any prompt and still logged
// through Broker.Refuse: every request for a key is audited (spec 4.6).
func (s *Server) sign(body []byte, chain *caller.Chain, st *conn) []byte {
	req, err := agentproto.ParseSignRequest(body)
	if err != nil {
		return agentproto.Failure()
	}
	key, ok := s.Keys.ByBlob(req.KeyBlob)
	if !ok {
		return agentproto.Failure()
	}
	p := agentproto.ParsePayload(req.Data)
	refuse := func(why error) []byte {
		s.logf("agent: refusing to sign with %s: %s", agentproto.Printable(key.Name, 64), why.Error())
		s.Broker.Refuse(broker.Request{
			Key: key.Name, Chain: chain, Operation: operation(p), Forwarded: st.forwarded(),
		}, why.Error())
		return agentproto.Failure()
	}
	if st.bindFailed {
		return refuse(errBindRefused)
	}
	dest, bound, err := s.destination(p, req.KeyBlob, chain, st)
	if err != nil {
		return refuse(err)
	}
	var sig *ssh.Signature
	res := s.Broker.Handle(broker.Request{
		Key: key.Name, Chain: chain, Summary: agentproto.Describe(p, dest),
		Destination: dest, Operation: operation(p), Op: covers(p, bound, dest), Forwarded: st.forwarded(),
		Do: func(ref platform.ApprovalRef) error {
			var err error
			sig, err = s.Keys.Sign(key.Name, req.Data, ref)
			return err
		},
	})
	if !res.Allowed() || sig == nil {
		return agentproto.Failure()
	}
	return agentproto.MarshalSignResponse(sig)
}

// operation names what a non-login payload signs, for the audit log ("" for
// a userauth, whose destination says what it is). It only ever carries
// printable text.
func operation(p agentproto.Payload) string {
	switch p.Kind {
	case agentproto.PayloadSSHSig:
		if p.SSHSig.Namespace == "git" {
			return "sign git commit"
		}
		return fmt.Sprintf("sign data namespace=%s", agentproto.Printable(p.SSHSig.Namespace, 64))
	case agentproto.PayloadUnknown:
		return "sign unrecognized data"
	}
	return ""
}

// covers is what an approval for this request would cover, as the approval
// cache keys and shows it (spec 4.3, Milestone 7): a login by the host key
// the session-bind proved, never by the name known_hosts gives it (a file
// anything running as the user can edit); a login nothing proved, as one
// kind of its own; a signature by its exact namespace, under a prefix of its
// own so no namespace can name a fixed kind ("data", or "git\x00" printing
// as "git"), and by its SHA-256 under another when what the dialog shows of
// it is not all of it (a dropped rune, or past 64 characters), so two
// namespaces that print alike are never one approval; anything else as
// unrecognised data. dest is the destination as shown, for the text of a
// proved login.
func covers(p agentproto.Payload, bound ssh.PublicKey, dest string) approval.Op {
	switch p.Kind {
	case agentproto.PayloadUserAuth:
		if bound == nil {
			return approval.Op{ID: "login:unbound", Text: "unidentified servers"}
		}
		return approval.Op{ID: "login:" + ssh.FingerprintSHA256(bound), Text: dest}
	case agentproto.PayloadSSHSig:
		if p.SSHSig.Namespace == "git" {
			return approval.Op{ID: "sign:git", Text: "git commits and tags"}
		}
		ns := p.SSHSig.Namespace
		shown := agentproto.Printable(ns, 64)
		id := "sign:ns:" + ns
		if shown != ns {
			sum := sha256.Sum256([]byte(ns))
			id = "sign:nsx:" + hex.EncodeToString(sum[:])
		}
		return approval.Op{ID: id, Text: fmt.Sprintf("data in namespace %q", shown)}
	}
	return approval.Op{ID: "sign:data", Text: "unrecognized data"}
}

// destination names the destination of a login after checking the userauth
// against the connection's session binding, and returns the host key that
// binding proved; a non-login payload, and a login on a connection with no
// bind, have neither. The destination only ever carries printable text: it
// reaches the dialog and the audit log. An error is one of the fixed
// refusal reasons above.
func (s *Server) destination(p agentproto.Payload, keyBlob []byte, chain *caller.Chain, st *conn) (dest string, bound ssh.PublicKey, err error) {
	if p.Kind != agentproto.PayloadUserAuth {
		return "", nil, nil
	}
	ua := p.UserAuth
	if !bytes.Equal(ua.PubKey, keyBlob) {
		return "", nil, errOtherKey
	}
	// As OpenSSH's process_sign_request2 and identity_permitted do for a
	// destination-constrained key, a userauth is checked against the most
	// recent bind, which must be an authentication bind: the local ssh has
	// already authenticated to a forwarding hop, so a userauth for that
	// session can only come from the far side ("tried to sign on forwarding
	// hop"). Past the first hop the userauth must carry the host key, so
	// the destination named is the one the signature itself is bound to
	// ("no hostkey recorded in signature for forwarded connection").
	if n := len(st.binds); n > 0 {
		last := st.binds[n-1]
		if !bytes.Equal(ua.SessionID, last.SessionID) {
			return "", nil, errSessionMismatch
		}
		if last.Forwarding {
			return "", nil, errForwardingHop
		}
		if n > 1 && ua.HostKey == nil {
			return "", nil, errNoForwardedHostKy
		}
		if ua.HostKey != nil && !bytes.Equal(ua.HostKey.Marshal(), last.HostKey.Marshal()) {
			return "", nil, errHostKeyMismatch
		}
		bound = last.HostKey
	}
	if bound == nil {
		// Unbound: nothing proved who the server is. A host key the userauth
		// itself carries (publickey-hostbound) is the client's own word, so
		// it names nothing either: a client in an approved tab could put
		// github.com's host key into a userauth for a session with any
		// server that skips the hostbound check (Milestone 7, THREAT-MODEL
		// 4.11). Real ssh always binds before its first signature.
		return "", nil, nil
	}
	var args []string
	if peer, ok := chain.Peer(); ok {
		args = peer.Args
	}
	res, err := knownhosts.Lookup(s.KnownHosts(), bound, knownhosts.CandidatesFromArgs(args))
	if err != nil {
		s.logf("agent: known_hosts: %s", errText(err))
	}
	dest = res.Display()
	if st.forwarded() {
		dest += " (via a forwarded agent)"
	}
	return dest, bound, nil
}
