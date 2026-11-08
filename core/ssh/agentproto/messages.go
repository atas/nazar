package agentproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ssh"
)

// Identity is one entry of an IDENTITIES_ANSWER.
type Identity struct {
	Blob    []byte // SSH wire public key
	Comment string
}

// MarshalIdentities builds an IDENTITIES_ANSWER body (type byte included).
func MarshalIdentities(ids []Identity) []byte {
	b := binary.BigEndian.AppendUint32([]byte{MsgIdentitiesAnswer}, uint32(len(ids)))
	for _, id := range ids {
		b = appendBytes(b, id.Blob)
		b = appendBytes(b, []byte(id.Comment))
	}
	return b
}

// ParseIdentities parses an IDENTITIES_ANSWER body (type byte included):
// what another agent answers the CLI's REQUEST_IDENTITIES. A body
// of another type, a count the body cannot hold, a truncated entry or
// trailing bytes is an error; nothing is allocated for a count before the
// bytes for it are known to be there.
func ParseIdentities(body []byte) ([]Identity, error) {
	if len(body) == 0 || body[0] != MsgIdentitiesAnswer {
		return nil, errors.New("agentproto: not an identities answer")
	}
	r := &reader{b: body[1:]}
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(r.b))/8 { // each entry is at least two length prefixes
		return nil, errShort
	}
	ids := make([]Identity, 0, n)
	for i := uint32(0); i < n; i++ {
		var id Identity
		if id.Blob, err = r.bytes(); err != nil {
			return nil, err
		}
		if id.Comment, err = r.string(); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return ids, nil
}

// SignRequest is a parsed SIGN_REQUEST.
type SignRequest struct {
	KeyBlob []byte
	Data    []byte
	Flags   uint32
}

// ParseSignRequest parses a SIGN_REQUEST body (type byte included). A body
// of another type, a truncated body or one with trailing bytes is an error.
func ParseSignRequest(body []byte) (SignRequest, error) {
	if len(body) == 0 || body[0] != MsgSignRequest {
		return SignRequest{}, errors.New("agentproto: not a sign request")
	}
	r := &reader{b: body[1:]}
	var req SignRequest
	var err error
	if req.KeyBlob, err = r.bytes(); err != nil {
		return SignRequest{}, err
	}
	if req.Data, err = r.bytes(); err != nil {
		return SignRequest{}, err
	}
	if req.Flags, err = r.uint32(); err != nil {
		return SignRequest{}, err
	}
	if err := r.done(); err != nil {
		return SignRequest{}, err
	}
	return req, nil
}

// MarshalSignResponse builds a SIGN_RESPONSE body (type byte included).
func MarshalSignResponse(sig *ssh.Signature) []byte {
	return appendBytes([]byte{MsgSignResponse}, ssh.Marshal(sig))
}

// Extension is a parsed EXTENSION request.
type Extension struct {
	Name     string
	Contents []byte // extension-specific, parsed by the extension's own parser
}

// ParseExtension parses an EXTENSION body (type byte included).
func ParseExtension(body []byte) (Extension, error) {
	if len(body) == 0 || body[0] != MsgExtension {
		return Extension{}, errors.New("agentproto: not an extension")
	}
	r := &reader{b: body[1:]}
	name, err := r.string()
	if err != nil {
		return Extension{}, err
	}
	return Extension{Name: name, Contents: r.b}, nil
}

// SessionBindName is the OpenSSH extension that binds a connection to a
// host key (OpenSSH PROTOCOL.agent section 3.3).
const SessionBindName = "session-bind@openssh.com"

// MaxSessionIDLen bounds session identifiers (OpenSSH: SSH_DIGEST_MAX_LENGTH).
const MaxSessionIDLen = 64

// SessionBind is a verified session-bind@openssh.com request.
type SessionBind struct {
	HostKey    ssh.PublicKey
	SessionID  []byte
	Forwarding bool
}

// ParseSessionBind parses the extension contents and verifies that the host
// key signed the session ID; an unverifiable bind is an error, so a client
// cannot claim a host key it does not hold. The result does not alias
// contents.
func ParseSessionBind(contents []byte) (SessionBind, error) {
	r := &reader{b: contents}
	hk, err := r.bytes()
	if err != nil {
		return SessionBind{}, err
	}
	sid, err := r.bytes()
	if err != nil {
		return SessionBind{}, err
	}
	sigBlob, err := r.bytes()
	if err != nil {
		return SessionBind{}, err
	}
	fwd, err := r.bool()
	if err != nil {
		return SessionBind{}, err
	}
	if err := r.done(); err != nil {
		return SessionBind{}, err
	}
	if len(sid) == 0 || len(sid) > MaxSessionIDLen {
		return SessionBind{}, fmt.Errorf("agentproto: session id length %d", len(sid))
	}
	// Parsed keys may keep a reference to their wire bytes; parse a copy so
	// the host key stays valid after the request buffer is reused.
	key, err := ssh.ParsePublicKey(bytes.Clone(hk))
	if err != nil {
		return SessionBind{}, fmt.Errorf("agentproto: bad host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(sigBlob, &sig); err != nil {
		return SessionBind{}, fmt.Errorf("agentproto: bad signature: %w", err)
	}
	if err := key.Verify(sid, &sig); err != nil {
		return SessionBind{}, fmt.Errorf("agentproto: session-bind signature does not verify: %w", err)
	}
	return SessionBind{HostKey: key, SessionID: bytes.Clone(sid), Forwarding: fwd}, nil
}

// p256OrderBits is the size of the P-256 group order; r and s are below it.
const p256OrderBits = 256

// ECDSASignatureFromDER converts the platform's ASN.1 DER ECDSA signature
// (SEQUENCE { r INTEGER, s INTEGER }, exactly, as crypto/ecdsa parses it)
// into an ecdsa-sha2-nistp256 SSH signature.
func ECDSASignatureFromDER(der []byte) (*ssh.Signature, error) {
	rs := struct{ R, S *big.Int }{new(big.Int), new(big.Int)}
	var inner cryptobyte.String
	input := cryptobyte.String(der)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) || !input.Empty() ||
		!inner.ReadASN1Integer(rs.R) || !inner.ReadASN1Integer(rs.S) || !inner.Empty() {
		return nil, errors.New("agentproto: bad DER signature")
	}
	if rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.R.BitLen() > p256OrderBits || rs.S.BitLen() > p256OrderBits {
		return nil, errors.New("agentproto: bad DER signature: r or s out of range")
	}
	return &ssh.Signature{Format: ssh.KeyAlgoECDSA256, Blob: ssh.Marshal(rs)}, nil
}
