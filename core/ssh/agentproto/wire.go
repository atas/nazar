// Package agentproto encodes and decodes the SSH agent protocol
// (draft-miller-ssh-agent) and classifies what a client asks to sign.
// Everything here parses untrusted input from the agent socket.
package agentproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Message numbers (draft-miller-ssh-agent section 5.1).
const (
	MsgFailure                 = 5
	MsgSuccess                 = 6
	MsgRequestIdentities       = 11
	MsgIdentitiesAnswer        = 12
	MsgSignRequest             = 13
	MsgSignResponse            = 14
	MsgAddIdentity             = 17
	MsgRemoveIdentity          = 18
	MsgRemoveAllIdentities     = 19
	MsgAddSmartcardKey         = 20
	MsgRemoveSmartcardKey      = 21
	MsgLock                    = 22
	MsgUnlock                  = 23
	MsgAddIDConstrained        = 25
	MsgAddSmartcardConstrained = 26
	MsgExtension               = 27
)

// MaxMessageLen is the largest message accepted (OpenSSH's AGENT_MAX_LEN).
const MaxMessageLen = 256 * 1024

// ErrTooLarge is returned for a message longer than MaxMessageLen.
var ErrTooLarge = errors.New("agentproto: message too large")

var errShort = errors.New("agentproto: truncated message")

// ReadMessage reads one length-prefixed message and returns its body
// (message type byte first). Empty and oversized messages are errors; the
// length is checked before any body is read, so a hostile header never
// causes an allocation. A stream that ends cleanly between messages
// returns io.EOF.
func ReadMessage(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, errors.New("agentproto: empty message")
	}
	if n > MaxMessageLen {
		return nil, ErrTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

// WriteMessage writes body with its length prefix. An oversized body is
// refused before anything is written.
func WriteMessage(w io.Writer, body []byte) error {
	if len(body) > MaxMessageLen {
		return ErrTooLarge
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err := w.Write(buf)
	return err
}

// Failure is the SSH_AGENT_FAILURE reply. Each call returns a fresh slice.
func Failure() []byte { return []byte{MsgFailure} }

// Success is the SSH_AGENT_SUCCESS reply. Each call returns a fresh slice.
func Success() []byte { return []byte{MsgSuccess} }

// reader decodes SSH wire types (RFC 4251 section 5) from a byte slice.
// Every accessor fails on a short buffer instead of reading past it.
type reader struct{ b []byte }

func (r *reader) uint32() (uint32, error) {
	if len(r.b) < 4 {
		return 0, errShort
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, nil
}

func (r *reader) byte() (byte, error) {
	if len(r.b) < 1 {
		return 0, errShort
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, nil
}

func (r *reader) bool() (bool, error) {
	v, err := r.byte()
	return v != 0, err
}

// bytes reads a length-prefixed string. The result aliases the input.
func (r *reader) bytes() ([]byte, error) {
	n, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(r.b)) {
		return nil, errShort
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, nil
}

func (r *reader) string() (string, error) {
	b, err := r.bytes()
	return string(b), err
}

// done fails unless every byte was consumed: trailing data is a malformed
// message, never silently ignored.
func (r *reader) done() error {
	if len(r.b) != 0 {
		return fmt.Errorf("agentproto: %d trailing bytes", len(r.b))
	}
	return nil
}

// appendBytes appends b as an SSH wire string (uint32 length + bytes).
func appendBytes(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}
