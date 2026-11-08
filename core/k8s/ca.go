package k8s

import (
	"time"

	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// VaultPrefix is the Vault item prefix of the CA records: k8s-ca/<context>.
const VaultPrefix = "k8s-ca/"

// kind is the k8s contexts' CA records in the certificate engine
// (aws design 2).
var kind = certs.NewKind("k8s", VaultPrefix, "context", "nazar k8s CA ", config.ValidK8sContextName)

var (
	ErrExists      = kind.ErrExists()
	ErrNotFound    = kind.ErrNotFound()
	ErrInvalidName = kind.ErrInvalidName()
	// ErrUnreadable: the Vault refused to return the record (an item of
	// another signature of the agent, a locked keychain; spec 9). Such a
	// record is never deleted by the store.
	ErrUnreadable = kind.ErrUnreadable()
	// ErrBroken: the record reads but can't be used (it names another
	// context, its certificate does not parse, is not a CA, or is not its
	// key's).
	ErrBroken = kind.ErrBroken()
)

// CA is a context's certificate authority: an enclave signing key and its
// self-signed certificate.
type CA struct {
	*certs.CA
}

// CAInfo describes a CA record for listings; never key material.
type CAInfo = certs.CAInfo

// CAStore keeps the CA records in the Vault. Names are compared ignoring
// letter case, as the context names in config are.
type CAStore struct {
	s *certs.Store
}

// NewCAStore returns a store over p and v.
func NewCAStore(p platform.Platform, v platform.Vault, now func() time.Time) *CAStore {
	return &CAStore{s: certs.NewStore(kind, p, v, now)}
}

func wrap(ca *certs.CA, err error) (*CA, error) {
	if err != nil {
		return nil, err
	}
	return &CA{ca}, nil
}

// Create makes a CA for context name: a new enclave signing key (AuthNone:
// nazar's gate is the check, k8s design 6.1; access says when the chip lets
// it sign), its self-signed certificate signed through the platform,
// checked, and the Vault record. On any failure the new key is deleted and
// nothing is stored. A name taken ignoring letter case, or whose record
// can't be read, is ErrExists.
func (s *CAStore) Create(name string, access platform.Access) (*CA, error) {
	return wrap(s.s.Create(name, access))
}

// Get returns the CA of context name: ErrNotFound, ErrUnreadable or
// ErrBroken (wrapped, saying why) when it can't be used; ErrInvalidName for
// a name nazar can't make (never read).
func (s *CAStore) Get(name string) (*CA, error) {
	return wrap(s.s.Get(name))
}

// List describes every k8s-ca/ item in name order: broken and unreadable
// records, and items under a name nazar can't make (listed, never used;
// main spec 9), included.
func (s *CAStore) List() ([]CAInfo, error) { return s.s.List() }

// Delete removes the CA of context name: its enclave key, then its Vault
// item. A record the Vault refuses to return is never deleted
// (ErrUnreadable; spec 9: a locked keychain reads like a lost item). The
// key goes only for a record that reads in full and whose handle no other
// CA record carries (a restored duplicate); a broken record loses its
// item only. ErrNotFound from either step is no error, so a second delete
// finishes a half-done one.
func (s *CAStore) Delete(name string) error { return s.s.Delete(name) }
