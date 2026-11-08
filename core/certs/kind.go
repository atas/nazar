// Package certs is the certificate engine (aws design 2): a CA whose key is
// in the Secure Enclave, kept in the Vault, issuing short-lived client
// certificates. It knows nothing of Kubernetes or AWS; each adapter names
// its own kind of CA record.
//
// The CA key signs only certificates built here: the CA's own in Create,
// a leaf from a LeafSpec in Issue (aws design 2.3).
package certs

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// Kind is one adapter's CA records: the Vault prefix, the words its
// messages use, and which names it accepts.
type Kind struct {
	tag     string // starts every message: "k8s"
	prefix  string // the Vault item prefix: "k8s-ca/"
	noun    string // names an entry: "context"
	subject string // the CA's CN before the name: "nazar k8s CA "
	valid   func(string) bool

	errExists, errNotFound, errInvalidName, errUnreadable, errBroken error
}

// NewKind makes a kind and its errors. tag starts every message ("k8s: …"),
// noun names an entry ("names another context", "invalid context name"),
// subject is the CA's CN before the name ("nazar k8s CA "). valid says
// which names the kind makes and reads; prefix ends in "/".
func NewKind(tag, prefix, noun, subject string, valid func(string) bool) *Kind {
	if tag == "" || noun == "" || subject == "" || valid == nil || len(prefix) < 2 || !strings.HasSuffix(prefix, "/") {
		panic("certs: an incomplete kind")
	}
	return &Kind{
		tag: tag, prefix: prefix, noun: noun, subject: subject, valid: valid,
		errExists:      errors.New(tag + ": a CA of that name exists"),
		errNotFound:    errors.New(tag + ": no CA of that name"),
		errInvalidName: errors.New(tag + ": invalid " + noun + " name"),
		// The Vault refused to return the record (an item of another
		// signature of the agent, a locked keychain; main spec 9). Such a
		// record is never deleted by the store.
		errUnreadable: errors.New(tag + ": the vault refused to return the CA record"),
		// The record reads but can't be used (it names another entry, its
		// certificate does not parse, is not a CA, or is not its key's).
		errBroken: errors.New(tag + ": the CA record is unusable"),
	}
}

// ErrExists: a CA of that name, ignoring letter case, exists or can't be
// read.
func (k *Kind) ErrExists() error { return k.errExists }

// ErrNotFound: no CA of that name.
func (k *Kind) ErrNotFound() error { return k.errNotFound }

// ErrInvalidName: a name the kind never makes.
func (k *Kind) ErrInvalidName() error { return k.errInvalidName }

// ErrUnreadable: the Vault refused to return the record.
func (k *Kind) ErrUnreadable() error { return k.errUnreadable }

// ErrBroken: the record reads but can't be used.
func (k *Kind) ErrBroken() error { return k.errBroken }

// article is "a" or "an" before the kind's noun.
func (k *Kind) article() string {
	if strings.ContainsRune("aeiou", rune(k.noun[0])) {
		return "an"
	}
	return "a"
}

// Serial is a positive 127-bit serial; only NewSerial makes one.
type Serial struct{ n *big.Int }

// NewSerial is a random serial: positive, and a full 127 bits.
func NewSerial() (Serial, error) {
	n, err := randomSerial()
	if err != nil {
		return Serial{}, err
	}
	return Serial{n}, nil
}

// Hex is the serial as 32 hex digits: the AWS role session name. The zero
// Serial's is empty.
func (s Serial) Hex() string {
	if s.n == nil {
		return ""
	}
	b := make([]byte, 16)
	return hex.EncodeToString(s.n.FillBytes(b))
}

// Decimal is the serial in decimal: the Credential= of an X509 SigV4
// header. The zero Serial's is empty.
func (s Serial) Decimal() string {
	if s.n == nil {
		return ""
	}
	return s.n.String()
}
