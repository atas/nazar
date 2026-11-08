// Package secrets stores nazar's secrets (secrets design 3.1–3.4, Milestone
// 8): each secret is sealed with HPKE (core/secrets/seal) to its own Secure
// Enclave key-agreement key, and one Vault item, secret/<name>, holds the
// key's handle, its public key and the sealed value. Nothing is written to
// disk.
//
// The platform is not trusted blindly: a value is opened again through the
// enclave before it is stored, so a key that cannot open what was sealed to
// it never holds a secret. A record the Vault refuses to return is never
// deleted (spec 9): a locked keychain reads the same as a lost item.
package secrets

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/secrets/seal"
)

// VaultPrefix is the Vault name prefix of secret records: secret/<name>.
const VaultPrefix = "secret/"

// recordVersion is the shape of record; any other version is refused as
// broken, never guessed.
const recordVersion = 1

var (
	ErrExists      = errors.New("secrets: a secret with that name already exists")
	ErrNotFound    = errors.New("secrets: no such secret")
	ErrInvalidName = errors.New("secrets: invalid secret name")
	// ErrUnreadable: the Vault refused to return the record (an item of
	// another build of nazar-agent, a locked keychain).
	ErrUnreadable = errors.New("secrets: the vault refused to return the record")
	// ErrBroken: the record was read but is not a usable secret.
	ErrBroken = errors.New("secrets: the secret's record is unusable")
)

// record is what the Vault holds for one secret: the only place its enclave
// handle and its sealed value are ever written.
type record struct {
	Version   int                 `json:"version"`
	Name      string              `json:"name"`
	Handle    []byte              `json:"handle"`
	PublicKey []byte              `json:"publicKey"` // X9.63 uncompressed P-256
	Auth      platform.AuthPolicy `json:"auth"`
	// Access is absent (AccessWhenUnlocked) in every record written before
	// it existed, which is what those keys are.
	Access  platform.Access `json:"access,omitempty"`
	Created time.Time       `json:"created"`
	Enc     []byte          `json:"enc"`    // HPKE encapsulated key
	Sealed  []byte          `json:"sealed"` // HPKE ciphertext of the value
}

// Info describes a secret without its handle or value.
type Info struct {
	Name       string
	Auth       platform.AuthPolicy
	Access     platform.Access
	Created    time.Time
	Broken     bool   // unusable record; only Name, Unreadable and Problem are set
	Unreadable bool   // the Vault refused to return it (spec 9)
	Problem    string // what failed; never a value
}

// Store is safe for concurrent use. Add, Replace and Delete are serialised;
// Open and the listings go straight to the Vault and the platform.
type Store struct {
	mu  sync.Mutex
	p   platform.Platform
	v   platform.Vault
	now func() time.Time
}

// NewStore returns a store over p and v. A nil now means time.Now.
func NewStore(p platform.Platform, v platform.Vault, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{p: p, v: v, now: now}
}

// Add stores a new secret: a new key-agreement key without Secure Enclave
// user presence (secrets design 3.5), made with access, the value sealed to
// it and opened again through the enclave, then the record. Nothing is left
// behind on failure.
func (s *Store) Add(name string, value []byte, access platform.Access) (Info, error) {
	if !config.ValidSecretName(name) {
		return Info{}, ErrInvalidName
	}
	if !access.Valid() {
		return Info{}, fmt.Errorf("secrets: unknown access %v", access)
	}
	if err := seal.Check(value); err != nil {
		return Info{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkFree(name); err != nil {
		return Info{}, err
	}
	handle, pub, err := s.p.CreateKey(platform.PurposeKeyAgreement, platform.AuthNone, access)
	if errors.Is(err, platform.ErrLocked) {
		return Info{}, platform.Locked("secrets: the Mac is locked; a secret that opens only while it's unlocked can't be added now")
	}
	if err != nil {
		return Info{}, fmt.Errorf("secrets: create enclave key: %w", err)
	}
	rec := record{Version: recordVersion, Name: name, Handle: handle, PublicKey: pub,
		Auth: platform.AuthNone, Access: access, Created: s.now().UTC()}
	if err := s.sealTo(&rec, value); err != nil {
		return Info{}, s.discard(handle, err)
	}
	if err := s.put(rec); err != nil {
		return Info{}, s.discard(handle, err)
	}
	return infoOf(rec), nil
}

// Replace seals a new value to the secret's existing key (secrets design
// 3.4: not a delete). The old record stays as it was on any failure.
func (s *Store) Replace(name string, value []byte) (Info, error) {
	if err := seal.Check(value); err != nil {
		return Info{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.load(name)
	if err != nil {
		return Info{}, err
	}
	if err := s.sealTo(&rec, value); err != nil {
		return Info{}, err
	}
	if err := s.put(rec); err != nil {
		return Info{}, err
	}
	return infoOf(rec), nil
}

// Open returns the secret's value, doing the key agreement under approval
// ref. The caller zeroes it when done.
func (s *Store) Open(name string, ref platform.ApprovalRef) ([]byte, error) {
	rec, err := s.load(name)
	if err != nil {
		return nil, err
	}
	v, err := seal.Open(rec.PublicKey, s.agree(rec.Handle, ref), name, rec.Enc, rec.Sealed)
	if errors.Is(err, platform.ErrLocked) && rec.Access == platform.AccessWhenUnlocked {
		return nil, platform.Locked(fmt.Sprintf("secrets: the Mac is locked; %s opens only while it's unlocked", name))
	}
	if err != nil {
		return nil, fmt.Errorf("secrets: open %s: %w", name, err)
	}
	return v, nil
}

// Get returns one secret. A record the Vault refuses or that does not decode
// is returned with Broken set and no error (spec 9): one bad item degrades
// only its own secret.
func (s *Store) Get(name string) (Info, error) {
	rec, err := s.load(name)
	switch {
	case err == nil:
		return infoOf(rec), nil
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrInvalidName):
		return Info{}, err
	default:
		return Info{Name: name, Broken: true, Unreadable: errors.Is(err, ErrUnreadable), Problem: err.Error()}, nil
	}
}

// List returns every secret record in the Vault, sorted by name; items whose
// name is not a valid secret name are listed as broken. Only a Vault whose
// listing fails is an error.
func (s *Store) List() ([]Info, error) {
	names, err := s.v.List(VaultPrefix)
	if err != nil {
		return nil, fmt.Errorf("secrets: list vault: %w", err)
	}
	out := make([]Info, 0, len(names))
	for _, n := range names {
		if !strings.HasPrefix(n, VaultPrefix) {
			continue
		}
		name := strings.TrimPrefix(n, VaultPrefix)
		info, err := s.Get(name)
		switch {
		case errors.Is(err, ErrNotFound):
			continue // deleted between List and Get
		case err != nil:
			info = Info{Name: name, Broken: true, Problem: err.Error()}
		}
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b Info) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Delete erases the secret (secrets design 3.4): the enclave key first, then
// the Vault item, so a failure in between leaves a record whose key is dead,
// never a live key without its record, and a second Delete finishes. The key
// is freed only when the record names this secret and no other record
// carries the same handle. A record the Vault refuses to return is never
// deleted: ErrUnreadable, and nothing is called.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, err := s.load(name)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidName) || errors.Is(err, ErrUnreadable) {
		return err
	}
	if rec.Name == name && len(rec.Handle) > 0 {
		shared, err := s.handleShared(name, rec.Handle)
		if err != nil {
			return err
		}
		if !shared {
			if err := s.p.DeleteKey(rec.Handle); err != nil && !errors.Is(err, platform.ErrNotFound) {
				return fmt.Errorf("secrets: delete enclave key: %w", err)
			}
		}
	}
	if err := s.v.Delete(VaultPrefix + name); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return fmt.Errorf("secrets: delete vault item: %w", err)
	}
	return nil
}

// sealTo seals value to rec's key and opens it again through the enclave
// before rec may be stored: a platform whose public key is not its handle's,
// or a dead handle, would otherwise lose the value for good. Slice 1 keys
// are AuthNone, so the check needs no approval.
func (s *Store) sealTo(rec *record, value []byte) error {
	enc, ct, err := seal.Seal(rec.PublicKey, rec.Name, value)
	if err != nil {
		return fmt.Errorf("secrets: seal %s: %w", rec.Name, err)
	}
	got, err := seal.Open(rec.PublicKey, s.agree(rec.Handle, 0), rec.Name, enc, ct)
	if err != nil {
		return fmt.Errorf("secrets: the enclave key of %s does not open what was sealed to it: %w", rec.Name, err)
	}
	same := bytes.Equal(got, value)
	clear(got)
	if !same {
		return fmt.Errorf("secrets: the enclave key of %s opened something else", rec.Name)
	}
	rec.Enc, rec.Sealed = enc, ct
	return nil
}

func (s *Store) agree(handle []byte, ref platform.ApprovalRef) seal.Agree {
	return func(peer []byte) ([]byte, error) { return s.p.KeyAgreement(handle, peer, ref) }
}

func (s *Store) put(rec record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := s.v.Put(VaultPrefix+rec.Name, b); err != nil {
		return fmt.Errorf("secrets: store %s: %w", rec.Name, err)
	}
	return nil
}

// checkFree reports ErrExists when name, or a name differing only in letter
// case, is taken (FIFO paths live on a case-insensitive volume, 3.3). A
// Vault that cannot be read is an error: Add must not guess.
func (s *Store) checkFree(name string) error {
	if _, err := s.v.Get(VaultPrefix + name); err == nil {
		return ErrExists
	} else if !errors.Is(err, platform.ErrNotFound) {
		return fmt.Errorf("secrets: read vault: %w", err)
	}
	names, err := s.v.List(VaultPrefix)
	if err != nil {
		return fmt.Errorf("secrets: list vault: %w", err)
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimPrefix(n, VaultPrefix), name) {
			return ErrExists
		}
	}
	return nil
}

// discard deletes a freshly created enclave key after a failed Add and
// returns cause, joined with the delete error if that fails too.
func (s *Store) discard(handle []byte, cause error) error {
	if err := s.p.DeleteKey(handle); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return errors.Join(cause, fmt.Errorf("secrets: delete orphaned enclave key: %w", err))
	}
	return cause
}

// handleShared reports whether a Vault record other than name's carries the
// same enclave handle. Any record whose JSON parses counts, broken or not: a
// duplicated Keychain item (a restore) must never let one delete wipe
// another secret's key. A Vault that cannot be read is an error.
func (s *Store) handleShared(name string, handle []byte) (bool, error) {
	names, err := s.v.List(VaultPrefix)
	if err != nil {
		return false, fmt.Errorf("secrets: list vault: %w", err)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, VaultPrefix) || n == VaultPrefix+name {
			continue
		}
		b, err := s.v.Get(n)
		if errors.Is(err, platform.ErrNotFound) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("secrets: read vault item %s: %w", n, err)
		}
		var other record
		if json.Unmarshal(b, &other) == nil && bytes.Equal(other.Handle, handle) {
			return true, nil
		}
	}
	return false, nil
}

// load reads and decodes the record for name: ErrInvalidName, ErrNotFound,
// ErrUnreadable (wrapped, with the Vault's error), or ErrBroken (wrapped,
// with whatever parsed, so Delete can still free the key).
func (s *Store) load(name string) (record, error) {
	if !config.ValidSecretName(name) {
		return record{}, ErrInvalidName
	}
	b, err := s.v.Get(VaultPrefix + name)
	if errors.Is(err, platform.ErrNotFound) {
		return record{}, ErrNotFound
	}
	if err != nil {
		return record{}, fmt.Errorf("%w: %s%s: %v", ErrUnreadable, VaultPrefix, name, err)
	}
	return decode(name, b)
}

func decode(name string, b []byte) (record, error) {
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return record{}, fmt.Errorf("%w: %s: %v", ErrBroken, name, err)
	}
	why := ""
	switch {
	case rec.Version != recordVersion:
		why = fmt.Sprintf("record version %d (this nazar reads %d)", rec.Version, recordVersion)
	case rec.Name != name:
		why = "record name does not match"
	case len(rec.Handle) == 0:
		why = "no enclave handle"
	case rec.Auth != platform.AuthNone && rec.Auth != platform.AuthUserPresence:
		why = "unknown auth policy " + rec.Auth.String()
	case !rec.Access.Valid():
		why = "unknown access " + rec.Access.String()
	case !isP256(rec.PublicKey):
		why = "bad public key"
	case len(rec.Enc) == 0 || len(rec.Sealed) == 0:
		why = "no sealed value"
	}
	if why != "" {
		return rec, fmt.Errorf("%w: %s: %s", ErrBroken, name, why)
	}
	return rec, nil
}

func isP256(pub []byte) bool {
	_, err := ecdh.P256().NewPublicKey(pub)
	return err == nil
}

func infoOf(rec record) Info {
	return Info{Name: rec.Name, Auth: rec.Auth, Access: rec.Access, Created: rec.Created}
}
