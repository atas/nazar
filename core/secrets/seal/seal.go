// Package seal encrypts a secret to a P-256 key-agreement key with HPKE
// (RFC 9180, base mode) through the standard library's crypto/hpke:
// DHKEM(P-256, HKDF-SHA256) 0x0010, HKDF-SHA256 0x0001, AES-256-GCM 0x0002
// (secrets design 3.2). Sealing needs only the public key. Opening needs the
// key agreement with the sender's ephemeral key, which the caller supplies as
// an Agree function: in nazar it is Platform.KeyAgreement, so the Secure
// Enclave does the ECDH and Go never holds the private key.
//
// The secret's name is in the HPKE info string, so a value sealed for one
// name never opens under another. One message per context, a fresh
// ephemeral key per Seal.
package seal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"fmt"
)

// MaxValue is the largest secret: its Vault record (the value sealed, in
// base64 inside JSON, beside the enclave handle) stays under the 64 KiB a
// Keychain item is tested with, and a secret.add request under
// control.MaxRequestSize (secrets design 3.2).
const MaxValue = 32 << 10

var (
	ErrEmpty    = errors.New("seal: the secret is empty")
	ErrTooLarge = fmt.Errorf("seal: a secret is at most %d bytes", MaxValue)
	// ErrOpen: the sealed value does not open with this key under this name
	// (another key, another name, or damaged bytes). It never says which.
	ErrOpen = errors.New("seal: the sealed value does not open")
)

// Agree returns the ECDH shared secret (the 32-byte X coordinate, as
// Platform.KeyAgreement does) of the recipient's private key with peer, an
// X9.63 uncompressed P-256 point.
type Agree func(peer []byte) ([]byte, error)

// Check reports whether value can be sealed: not empty, at most MaxValue.
func Check(value []byte) error {
	switch {
	case len(value) == 0:
		return ErrEmpty
	case len(value) > MaxValue:
		return ErrTooLarge
	}
	return nil
}

func info(name string) []byte { return []byte("nazar/v1 secret\x00" + name) }

// Seal encrypts value for name to pub, an X9.63 uncompressed P-256 point.
// enc is the 65-byte ephemeral public key; ct the ciphertext and its tag.
func Seal(pub []byte, name string, value []byte) (enc, ct []byte, err error) {
	if err := Check(value); err != nil {
		return nil, nil, err
	}
	pk, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("seal: recipient key: %w", err)
	}
	hp, err := hpke.NewDHKEMPublicKey(pk)
	if err != nil {
		return nil, nil, err
	}
	enc, s, err := hpke.NewSender(hp, hpke.HKDFSHA256(), hpke.AES256GCM(), info(name))
	if err != nil {
		return nil, nil, err
	}
	ct, err = s.Seal(nil, value)
	if err != nil {
		return nil, nil, err
	}
	return enc, ct, nil
}

// Open decrypts what Seal made for name to pub, doing the key agreement
// through agree. agree's own error is returned unchanged (an enclave that
// needs an approval, a deleted key); anything else that keeps the value
// shut is ErrOpen.
func Open(pub []byte, agree Agree, name string, enc, ct []byte) ([]byte, error) {
	return open(pub, agree, hpke.AES256GCM(), info(name), nil, enc, ct)
}

// open is Open with the AEAD, info and aad as parameters, so the RFC 9180
// vectors (AES-128-GCM) run through the same adapter.
func open(pub []byte, agree Agree, aead hpke.AEAD, info, aad, enc, ct []byte) ([]byte, error) {
	pk, err := ecdh.P256().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("seal: recipient key: %w", err)
	}
	x := &exchanger{pub: pk, agree: agree}
	priv, err := hpke.NewDHKEMPrivateKey(x)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, priv, hpke.HKDFSHA256(), aead, info)
	if x.err != nil {
		return nil, x.err
	}
	if err != nil {
		return nil, ErrOpen // enc is not a P-256 point: the enclave was never asked
	}
	pt, err := r.Open(aad, ct)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// exchanger is the recipient's key as crypto/hpke sees it: the public key
// from the record, the ECDH done by agree. It keeps agree's error, so Open
// can return it whatever crypto/hpke makes of it.
type exchanger struct {
	pub   *ecdh.PublicKey
	agree Agree
	err   error
}

func (x *exchanger) PublicKey() *ecdh.PublicKey { return x.pub }
func (x *exchanger) Curve() ecdh.Curve          { return ecdh.P256() }

func (x *exchanger) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	z, err := x.agree(peer.Bytes())
	if err == nil && len(z) != 32 {
		err = fmt.Errorf("seal: key agreement returned %d bytes, want 32", len(z))
	}
	if err != nil {
		x.err = err
		return nil, err
	}
	return z, nil
}
