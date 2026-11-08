package agentproto

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// PayloadKind classifies the data of a SIGN_REQUEST.
type PayloadKind int

const (
	PayloadUnknown  PayloadKind = iota
	PayloadUserAuth             // SSH_MSG_USERAUTH_REQUEST (a login)
	PayloadSSHSig               // SSHSIG (ssh-keygen -Y sign, git signing)
)

// Method names a userauth payload may carry.
const (
	MethodPublicKey          = "publickey"
	MethodPublicKeyHostbound = "publickey-hostbound-v00@openssh.com"
)

// UserAuth is a parsed SSH_MSG_USERAUTH_REQUEST signature payload
// (RFC 4252 section 7, OpenSSH PROTOCOL section 3.10 for hostbound).
type UserAuth struct {
	SessionID []byte
	User      string
	Service   string
	Method    string
	Algo      string
	PubKey    []byte
	HostKey   ssh.PublicKey // only for publickey-hostbound-v00@openssh.com
}

// SSHSig is a parsed SSHSIG signed-data blob (OpenSSH PROTOCOL.sshsig).
type SSHSig struct {
	Namespace string
	HashAlg   string
}

// Payload is what a SIGN_REQUEST asks to sign.
type Payload struct {
	Kind     PayloadKind
	UserAuth *UserAuth // set iff Kind == PayloadUserAuth
	SSHSig   *SSHSig   // set iff Kind == PayloadSSHSig
	Len      int       // length of the data in bytes, whatever its kind
}

var sshsigMagic = []byte("SSHSIG")

const msgUserAuthRequest = 50

// maxShown bounds client-supplied strings in the dialog line.
const maxShown = 64

// ParsePayload classifies data. Anything that is not a well-formed userauth
// request or SSHSIG blob (including one with trailing bytes) is
// PayloadUnknown; a half-parsed payload is never reported.
func ParsePayload(data []byte) Payload {
	p := Payload{Len: len(data)}
	if bytes.HasPrefix(data, sshsigMagic) {
		if s, ok := parseSSHSig(data[len(sshsigMagic):]); ok {
			p.Kind, p.SSHSig = PayloadSSHSig, s
		}
		return p
	}
	if u, ok := parseUserAuth(data); ok {
		p.Kind, p.UserAuth = PayloadUserAuth, u
	}
	return p
}

// parseSSHSig parses the signed data after the magic:
// string namespace, string reserved, string hash_algorithm, string H(message).
func parseSSHSig(b []byte) (*SSHSig, bool) {
	r := &reader{b: b}
	ns, err := r.string()
	if err != nil || ns == "" { // PROTOCOL.sshsig: namespace MUST NOT be empty
		return nil, false
	}
	if _, err := r.bytes(); err != nil { // reserved
		return nil, false
	}
	alg, err := r.string()
	if err != nil {
		return nil, false
	}
	if _, err := r.bytes(); err != nil { // H(message)
		return nil, false
	}
	if r.done() != nil {
		return nil, false
	}
	return &SSHSig{Namespace: ns, HashAlg: alg}, true
}

// parseUserAuth parses the publickey signature payload: string session id,
// byte SSH_MSG_USERAUTH_REQUEST, string user, string service, string
// method, bool has_signature (true), string algorithm, string public key
// and, for the hostbound method only, string server host key.
func parseUserAuth(b []byte) (*UserAuth, bool) {
	r := &reader{b: b}
	u := &UserAuth{}
	var err error
	if u.SessionID, err = r.bytes(); err != nil || len(u.SessionID) == 0 || len(u.SessionID) > MaxSessionIDLen {
		return nil, false
	}
	if t, err := r.byte(); err != nil || t != msgUserAuthRequest {
		return nil, false
	}
	if u.User, err = r.string(); err != nil {
		return nil, false
	}
	if u.Service, err = r.string(); err != nil {
		return nil, false
	}
	if u.Method, err = r.string(); err != nil {
		return nil, false
	}
	if u.Method != MethodPublicKey && u.Method != MethodPublicKeyHostbound {
		return nil, false
	}
	if has, err := r.bool(); err != nil || !has {
		return nil, false
	}
	if u.Algo, err = r.string(); err != nil {
		return nil, false
	}
	if u.PubKey, err = r.bytes(); err != nil {
		return nil, false
	}
	if u.Method == MethodPublicKeyHostbound {
		hk, err := r.bytes()
		if err != nil {
			return nil, false
		}
		if u.HostKey, err = ssh.ParsePublicKey(bytes.Clone(hk)); err != nil {
			return nil, false
		}
	}
	if r.done() != nil {
		return nil, false
	}
	u.SessionID = bytes.Clone(u.SessionID)
	u.PubKey = bytes.Clone(u.PubKey)
	return u, true
}

// Describe is the "what for" line of the approval dialog (spec 5).
// destination is the known_hosts name or host key fingerprint, "" if none.
// Client-supplied strings are sanitised and bounded before they are shown.
func Describe(p Payload, destination string) string {
	switch p.Kind {
	case PayloadUserAuth:
		if destination == "" {
			destination = "an unidentified server"
		}
		return fmt.Sprintf("login to %s as %s", Printable(destination, 128), Printable(p.UserAuth.User, maxShown))
	case PayloadSSHSig:
		if p.SSHSig.Namespace == "git" {
			return "sign a git commit/tag"
		}
		return fmt.Sprintf("sign data (namespace %q)", Printable(p.SSHSig.Namespace, maxShown))
	}
	return fmt.Sprintf("sign unrecognized data (%d bytes)", p.Len)
}

// Printable strips non-printable runes (controls, escapes, bidi overrides,
// zero-width characters) and truncates to max runes with an ellipsis, for
// showing attacker-controlled strings in dialogs and logs. Invalid UTF-8
// becomes U+FFFD, so the result is always valid UTF-8.
func Printable(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue
		}
		if n == max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
