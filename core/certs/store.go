package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atas/nazar/core/platform"
)

// caYears is how long a CA certificate is valid (k8s design 6.1).
const caYears = 10

// caRecord is the Vault item <prefix><name>: the enclave key's handle and
// public key, and the CA certificate itself, so that issuing reads nothing
// a same-user process can write.
type caRecord struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	Handle    []byte    `json:"handle"`
	PublicKey []byte    `json:"publicKey"`
	Created   time.Time `json:"created"`
	CertDER   []byte    `json:"certDER"`
	// Access is absent (AccessWhenUnlocked) in every record written
	// before it existed, which is what those CAs are.
	Access platform.Access `json:"access,omitempty"`
}

// CA is an entry's certificate authority: an enclave signing key and its
// self-signed certificate.
type CA struct {
	Name      string
	Handle    []byte
	PublicKey []byte // X9.63 uncompressed point
	Created   time.Time
	Cert      *x509.Certificate
	Access    platform.Access
	kind      *Kind
	pub       *ecdsa.PublicKey
}

// CAInfo describes a CA record for listings; never key material.
type CAInfo struct {
	Name        string
	Created     time.Time
	Fingerprint string // SHA-256 of the certificate's DER, hex
	NotAfter    time.Time
	Access      platform.Access
	Broken      bool
	Unreadable  bool
	Problem     string
}

// Store keeps one kind's CA records in the Vault. Names are compared
// ignoring letter case, as the entry names in config are.
type Store struct {
	k   *Kind
	p   platform.Platform
	v   platform.Vault
	now func() time.Time
	// mu serialises Create and Delete, so two creates of one name (or of
	// names equal ignoring case) can't both pass the free-name check.
	mu sync.Mutex
}

// NewStore returns a store of k's records over p and v.
func NewStore(k *Kind, p platform.Platform, v platform.Vault, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{k: k, p: p, v: v, now: now}
}

// CertPEM is the CA certificate as PEM: what the relying party trusts.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// Info describes ca.
func (ca *CA) Info() CAInfo {
	sum := sha256.Sum256(ca.Cert.Raw)
	return CAInfo{Name: ca.Name, Created: ca.Created, Fingerprint: hex.EncodeToString(sum[:]), NotAfter: ca.Cert.NotAfter, Access: ca.Access}
}

// Create makes a CA named name: a new enclave signing key (AuthNone:
// nazar's gate is the check, k8s design 6.1; access says when the chip lets
// it sign), its self-signed certificate signed through the platform,
// checked, and the Vault record. On any failure the new key is deleted and
// nothing is stored. A name taken ignoring letter case, or whose record
// can't be read, is ErrExists.
func (s *Store) Create(name string, access platform.Access) (ca *CA, err error) {
	k := s.k
	if !k.valid(name) {
		return nil, k.errInvalidName
	}
	if !access.Valid() {
		return nil, fmt.Errorf("%s: unknown access %v", k.tag, access)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	names, err := s.v.List(k.prefix)
	if err != nil {
		return nil, fmt.Errorf("%s: listing CA records: %w", k.tag, err)
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimPrefix(n, k.prefix), name) {
			return nil, k.errExists
		}
	}
	handle, pubRaw, err := s.p.CreateKey(platform.PurposeSign, platform.AuthNone, access)
	if errors.Is(err, platform.ErrLocked) {
		return nil, platform.Locked(k.tag + ": the Mac is locked; a CA that signs only while it's unlocked can't be made now")
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = s.p.DeleteKey(handle)
		}
	}()
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pubRaw)
	if err != nil {
		return nil, fmt.Errorf("%s: the enclave returned an unusable public key: %w", k.tag, err)
	}
	now := s.now().UTC()
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ski := sha256.Sum256(pubRaw)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: k.subject + name},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(caYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          ski[:20],
	}
	sg := &signer{p: s.p, handle: handle, pub: pub, tag: k.tag}
	// CreateCertificate checks the signature against sg.Public(), so a
	// platform whose key is not the public key it returned fails here.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, sg)
	if err != nil {
		return nil, fmt.Errorf("%s: making the CA certificate: %w", k.tag, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return nil, fmt.Errorf("%s: the CA certificate does not verify: %w", k.tag, err)
	}
	rec := caRecord{Version: 1, Name: name, Handle: handle, PublicKey: pubRaw, Created: now, CertDER: der, Access: access}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if err := s.v.Put(k.prefix+name, b); err != nil {
		return nil, err
	}
	return &CA{Name: name, Handle: handle, PublicKey: pubRaw, Created: now, Cert: cert, Access: access, kind: k, pub: pub}, nil
}

// Get returns the CA named name: ErrNotFound, ErrUnreadable or ErrBroken
// (wrapped, saying why) when it can't be used; ErrInvalidName for a name
// the kind can't make (never read).
func (s *Store) Get(name string) (*CA, error) {
	k := s.k
	if !k.valid(name) {
		return nil, k.errInvalidName
	}
	raw, err := s.v.Get(k.prefix + name)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, k.errNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s%s: %v", k.errUnreadable, k.prefix, name, err)
	}
	return k.decode(name, raw)
}

func (k *Kind) decode(name string, raw []byte) (*CA, error) {
	broken := func(why string) (*CA, error) {
		return nil, fmt.Errorf("%w: %s%s %s", k.errBroken, k.prefix, name, why)
	}
	var rec caRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return broken("does not decode")
	}
	if rec.Version != 1 {
		return broken(fmt.Sprintf("has format version %d", rec.Version))
	}
	if rec.Name != name {
		return broken("names another " + k.noun)
	}
	if len(rec.Handle) == 0 {
		return broken("has no key handle")
	}
	if !rec.Access.Valid() {
		return broken("has unknown access " + rec.Access.String())
	}
	cert, err := x509.ParseCertificate(rec.CertDER)
	if err != nil {
		return broken("holds a certificate that does not parse")
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return broken("holds a certificate that is not a CA")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return broken("holds a certificate that is not a P-256 key's")
	}
	if b, err := pub.Bytes(); err != nil || !bytes.Equal(b, rec.PublicKey) {
		return broken("holds a certificate of another key")
	}
	return &CA{Name: name, Handle: rec.Handle, PublicKey: rec.PublicKey, Created: rec.Created, Cert: cert, Access: rec.Access, kind: k, pub: pub}, nil
}

// List describes every item under the kind's prefix in name order: broken
// and unreadable records, and items under a name the kind can't make
// (listed, never used; main spec 9), included.
func (s *Store) List() ([]CAInfo, error) {
	k := s.k
	names, err := s.v.List(k.prefix)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	out := make([]CAInfo, 0, len(names))
	for _, item := range names {
		name := strings.TrimPrefix(item, k.prefix)
		ca, err := s.Get(name)
		switch {
		case errors.Is(err, k.errNotFound):
			continue // gone meanwhile
		case errors.Is(err, k.errInvalidName):
			out = append(out, CAInfo{Name: name, Broken: true, Problem: "not a CA nazar made: its name is not " + k.article() + " " + k.noun + " name"})
		case err != nil:
			out = append(out, CAInfo{Name: name, Broken: true, Unreadable: errors.Is(err, k.errUnreadable), Problem: err.Error()})
		default:
			out = append(out, ca.Info())
		}
	}
	return out, nil
}

// Delete removes the CA named name: its enclave key, then its Vault item.
// A record the Vault refuses to return is never deleted (ErrUnreadable;
// main spec 9: a locked keychain reads like a lost item). The key goes
// only for a record that reads in full and whose handle no other CA record
// of the kind carries (a restored duplicate); a broken record loses its
// item only. ErrNotFound from either step is no error, so a second delete
// finishes a half-done one.
func (s *Store) Delete(name string) error {
	k := s.k
	if !k.valid(name) {
		return k.errNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.v.Get(k.prefix + name)
	if errors.Is(err, platform.ErrNotFound) {
		return k.errNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: %s%s: %v", k.errUnreadable, k.prefix, name, err)
	}
	if ca, err := k.decode(name, raw); err == nil {
		shared, err := s.handleShared(name, ca.Handle)
		if err != nil {
			return err
		}
		if !shared {
			if err := s.p.DeleteKey(ca.Handle); err != nil && !errors.Is(err, platform.ErrNotFound) {
				return err
			}
		}
	}
	if err := s.v.Delete(k.prefix + name); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return err
	}
	return nil
}

// handleShared reports whether another CA record of the kind carries
// handle. A record the Vault won't return counts as sharing it: nazar
// can't tell, and an orphaned enclave key is harmless where a deleted one
// is not.
func (s *Store) handleShared(name string, handle []byte) (bool, error) {
	k := s.k
	names, err := s.v.List(k.prefix)
	if err != nil {
		return false, err
	}
	for _, item := range names {
		if item == k.prefix+name {
			continue
		}
		raw, err := s.v.Get(item)
		if errors.Is(err, platform.ErrNotFound) {
			continue
		}
		if err != nil {
			return true, nil
		}
		var rec caRecord
		if json.Unmarshal(raw, &rec) == nil && bytes.Equal(rec.Handle, handle) {
			return true, nil
		}
	}
	return false, nil
}

// randomSerial is a positive 128-bit serial number with its top bit clear:
// a full 127 bits.
func randomSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = b[0]&0x7f | 0x40 // positive, and a full 127 bits
	return new(big.Int).SetBytes(b), nil
}
