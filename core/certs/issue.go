package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"time"

	"github.com/atas/nazar/core/platform"
)

// LeafSpec is everything a caller chooses about a leaf. Its profile is
// fixed: digital signature, client auth, not a CA, no names but the subject.
type LeafSpec struct {
	CN        string
	O         []string  // one O= each; empty for AWS
	NotBefore time.Time // the caller's; cut to whole seconds
	NotAfter  time.Time // the caller's; cut to whole seconds and to the CA's end
	Serial    Serial    // zero: a new random one
}

// Leaf is a minted certificate and its key. The key never leaves the
// process; the caller drops it once used.
type Leaf struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Issue mints a leaf for spec: a fresh P-256 key made here, signed by the
// CA key through Platform.Sign with ref, read back and checked (check)
// before it is returned. The CA must be valid at now.
func (ca *CA) Issue(p platform.Platform, spec LeafSpec, now time.Time, ref platform.ApprovalRef) (Leaf, error) {
	k := ca.kind
	if k == nil || ca.pub == nil || ca.Cert == nil {
		return Leaf{}, errors.New("certs: a CA that no store returned")
	}
	now = now.UTC()
	if now.Before(ca.Cert.NotBefore) || !now.Before(ca.Cert.NotAfter) {
		return Leaf{}, fmt.Errorf("%s: the CA of %s is not valid now (valid %s to %s)", k.tag, ca.Name,
			ca.Cert.NotBefore.Format(time.RFC3339), ca.Cert.NotAfter.Format(time.RFC3339))
	}
	spec.O = slices.Clone(spec.O)
	spec.NotBefore = spec.NotBefore.UTC().Truncate(time.Second)
	spec.NotAfter = spec.NotAfter.UTC().Truncate(time.Second) // whole seconds, never past the caller's end
	if spec.NotAfter.After(ca.Cert.NotAfter) {
		spec.NotAfter = ca.Cert.NotAfter
	}
	if spec.CN == "" {
		return Leaf{}, errors.New(k.tag + ": a certificate needs a subject")
	}
	if spec.NotBefore.IsZero() || !spec.NotBefore.Before(spec.NotAfter) {
		return Leaf{}, errors.New(k.tag + ": a certificate needs a lifetime")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Leaf{}, err
	}
	if spec.Serial.n == nil {
		if spec.Serial, err = NewSerial(); err != nil {
			return Leaf{}, err
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).Set(spec.Serial.n),
		Subject:               pkix.Name{CommonName: spec.CN, Organization: spec.O},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	sg := &signer{p: p, handle: ca.Handle, pub: ca.pub, ref: ref, tag: k.tag}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, sg)
	if err != nil {
		err = unwrapPlatform(err)
		if errors.Is(err, platform.ErrLocked) && ca.Access == platform.AccessWhenUnlocked {
			return Leaf{}, platform.Locked(fmt.Sprintf("%s: %s is locked; the CA of %s signs only while it's unlocked", k.tag, platform.TraitsOf(p).Machine, ca.Name))
		}
		return Leaf{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Leaf{}, err
	}
	if err := check(cert, ca, spec, &key.PublicKey); err != nil {
		return Leaf{}, err
	}
	return Leaf{Cert: cert, Key: key}, nil
}

// check is the minted certificate read back: signed by the CA, issued by
// its subject and key id, with spec's serial, subject and lifetime (spec as
// Issue settled it), for the key just made, a client certificate and
// nothing else. Nothing leaves that fails it.
func check(cert *x509.Certificate, ca *CA, spec LeafSpec, pub *ecdsa.PublicKey) error {
	tag := ca.kind.tag
	certPub, _ := cert.PublicKey.(*ecdsa.PublicKey)
	switch {
	case cert.CheckSignatureFrom(ca.Cert) != nil:
		return errors.New(tag + ": the minted certificate does not verify against the CA")
	case !bytes.Equal(cert.RawIssuer, ca.Cert.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, ca.Cert.SubjectKeyId):
		return errors.New(tag + ": the minted certificate names another issuer")
	case cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(cert.UnknownExtKeyUsage) != 0:
		return errors.New(tag + ": the minted certificate has the wrong usages")
	case !cert.NotAfter.Equal(spec.NotAfter) || !cert.NotBefore.Equal(spec.NotBefore):
		return errors.New(tag + ": the minted certificate has the wrong lifetime")
	case certPub == nil || !certPub.Equal(pub):
		return errors.New(tag + ": the minted certificate is for another key")
	case cert.Subject.CommonName != spec.CN || !sameSet(cert.Subject.Organization, spec.O) ||
		len(cert.Subject.Names) != 1+len(spec.O):
		return errors.New(tag + ": the minted certificate names another identity")
	case len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0:
		return errors.New(tag + ": the minted certificate names a host")
	case spec.Serial.n == nil || cert.SerialNumber.Cmp(spec.Serial.n) != 0:
		return errors.New(tag + ": the minted certificate has another serial")
	}
	return nil
}

// sameSet reports whether a and b hold the same strings (Go writes the O=
// values as one DER SET, in its own order).
func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// errDigest refuses Sign(digest): the enclave hashes what it signs, so it
// is only ever handed the message (SignMessage).
var errDigest = errors.New("the CA signs messages, never digests")

// signer is a crypto.Signer and crypto.MessageSigner over the platform's
// key: x509.CreateCertificate hands SignMessage the TBS bytes, and
// Platform.Sign hashes them with SHA-256 and signs (ecdsa-with-SHA256).
// Only Create and Issue make one (aws design 2.3; TestSignerOnlyInCreateAndIssue).
type signer struct {
	p      platform.Platform
	handle []byte
	pub    *ecdsa.PublicKey
	ref    platform.ApprovalRef
	tag    string
}

func (s *signer) Public() crypto.PublicKey { return s.pub }

func (s *signer) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("%s: %w", s.tag, errDigest)
}

func (s *signer) SignMessage(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New(s.tag + ": the CA signs with SHA-256 only")
	}
	sig, err := s.p.Sign(s.handle, msg, s.ref)
	if err != nil {
		return nil, &platformError{err}
	}
	return sig, nil
}

// platformError carries the platform's error through x509 so errors.Is
// still finds platform.ErrNotFound and ErrAuthRequired.
type platformError struct{ err error }

func (e *platformError) Error() string { return e.err.Error() }
func (e *platformError) Unwrap() error { return e.err }

func unwrapPlatform(err error) error {
	var pe *platformError
	if errors.As(err, &pe) {
		return pe.err
	}
	return err
}
