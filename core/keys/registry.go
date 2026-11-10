// Package keys manages nazar's SSH keys: Secure Enclave handles kept in the
// platform Vault (never in plain files, spec 4.5) and public keys exported
// to ~/.nazar/keys/<name>.pub in OpenSSH format.
//
// The platform layer is not trusted blindly: the public key it returns on
// creation must be a well-formed P-256 point, and every signature it
// produces is verified against the stored public key before it is handed
// out (spec 9: a wiped or unusable handle fails instead of "signing").
package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/ssh/agentproto"
)

// VaultPrefix is the Vault name prefix for key records: ssh-key/<name>.
const VaultPrefix = "ssh-key/"

var (
	ErrExists      = errors.New("keys: a key with that name already exists")
	ErrNotFound    = errors.New("keys: no such key")
	ErrInvalidName = errors.New("keys: invalid key name")

	// errBroken marks a Vault record that exists but cannot be used (spec 9).
	errBroken = errors.New("keys: key record is unreadable")
)

// record is what the Vault holds for one key. It is the only place the
// enclave handle is ever written.
type record struct {
	Name      string              `json:"name"`
	Handle    []byte              `json:"handle"`
	PublicKey []byte              `json:"publicKey"` // SSH wire format
	Auth      platform.AuthPolicy `json:"auth"`
	// Access is absent (AccessWhenUnlocked) in every record written before
	// it existed, which is what those keys are.
	Access  platform.Access `json:"access,omitempty"`
	Created time.Time       `json:"created"`
}

// Info describes a key without its handle.
type Info struct {
	Name          string
	Type          string // "ecdsa-sha2-nistp256"
	Fingerprint   string // "SHA256:..."
	AuthorizedKey string // "ecdsa-sha2-nistp256 AAAA... name"
	Blob          []byte // SSH wire public key
	Auth          platform.AuthPolicy
	Access        platform.Access
	Created       time.Time
	Broken        bool // the record could not be read; only Name and the fields below are set
	// Unreadable: the Vault refused to return the record (an item of
	// another build of Nazar.app, a locked keychain), as opposed to a
	// record that was read but does not decode. Problem says what failed.
	Unreadable bool
	Problem    string
}

// Registry is safe for concurrent use. Create and Delete are serialised;
// reads and signing go straight to the Vault and the platform.
type Registry struct {
	mu     sync.Mutex
	p      platform.Platform
	v      platform.Vault
	pubDir string
	now    func() time.Time
	tr     platform.Traits // p's, for the words of its errors
}

// NewRegistry returns a registry over p and v that exports public keys to
// pubDir. A nil now means time.Now.
func NewRegistry(p platform.Platform, v platform.Vault, pubDir string, now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{p: p, v: v, pubDir: pubDir, now: now, tr: platform.TraitsOf(p)}
}

// Create makes a new Secure Enclave signing key protected by auth and access, stores
// its handle in the Vault and writes <pubDir>/<name>.pub (0644). Nothing is
// left behind when any step fails: the enclave key is deleted again and the
// Vault item removed, so the name stays free.
func (r *Registry) Create(name string, auth platform.AuthPolicy, access platform.Access) (Info, error) {
	if !config.ValidKeyName(name) {
		return Info{}, ErrInvalidName
	}
	if auth != platform.AuthNone && auth != platform.AuthUserPresence {
		return Info{}, fmt.Errorf("keys: unknown auth policy %v", auth)
	}
	if !access.Fits(auth) {
		return Info{}, fmt.Errorf("keys: access %v for auth policy %v", access, auth)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkFree(name); err != nil {
		return Info{}, err
	}

	handle, raw, err := r.p.CreateKey(platform.PurposeSign, auth, access)
	if errors.Is(err, platform.ErrLocked) {
		return Info{}, platform.Locked(fmt.Sprintf("keys: %s is locked; a key that works only while it's unlocked can't be made now", r.tr.Machine))
	}
	if err != nil {
		return Info{}, fmt.Errorf("keys: create %s key: %w", r.tr.KeyChip(), err)
	}
	ecpub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return Info{}, r.discard(handle, fmt.Errorf("keys: platform returned a bad public key: %w", err))
	}
	pub, err := ssh.NewPublicKey(ecpub)
	if err != nil {
		return Info{}, r.discard(handle, err)
	}
	rec := record{Name: name, Handle: handle, PublicKey: pub.Marshal(), Auth: auth, Access: access, Created: r.now()}
	b, err := json.Marshal(rec)
	if err != nil {
		return Info{}, r.discard(handle, err)
	}
	if err := r.v.Put(VaultPrefix+name, b); err != nil {
		return Info{}, r.discard(handle, fmt.Errorf("keys: store key handle: %w", err))
	}
	info := infoOf(rec, pub)
	if err := r.writePub(name, info.AuthorizedKey); err != nil {
		err = fmt.Errorf("keys: export %s.pub: %w", name, err)
		if derr := r.v.Delete(VaultPrefix + name); derr != nil {
			err = errors.Join(err, fmt.Errorf("keys: roll back key handle: %w", derr))
		}
		return Info{}, r.discard(handle, err)
	}
	return info, nil
}

// checkFree reports ErrExists when name, or a name differing only in letter
// case (keys/<name>.pub lives on a case-insensitive file system), is already
// taken. A Vault that cannot be read is an error: Create must not guess.
func (r *Registry) checkFree(name string) error {
	if _, err := r.v.Get(VaultPrefix + name); err == nil {
		return ErrExists
	} else if !errors.Is(err, platform.ErrNotFound) {
		return fmt.Errorf("keys: read vault: %w", err)
	}
	names, err := r.v.List(VaultPrefix)
	if err != nil {
		return fmt.Errorf("keys: list vault: %w", err)
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimPrefix(n, VaultPrefix), name) {
			return ErrExists
		}
	}
	return nil
}

// discard deletes a freshly created enclave key after a failed Create and
// returns cause, joined with the delete error if that fails too.
func (r *Registry) discard(handle []byte, cause error) error {
	if err := r.p.DeleteKey(handle); err != nil && !errors.Is(err, platform.ErrNotFound) {
		return errors.Join(cause, fmt.Errorf("keys: delete orphaned %s key: %w", r.tr.KeyChip(), err))
	}
	return cause
}

// writePub atomically writes <pubDir>/<name>.pub with mode 0644 whatever
// the umask. The file is written next to its final place and renamed over
// it, so a planted symlink is replaced, never written through, and a stale
// .pub is replaced whole.
func (r *Registry) writePub(name, authorizedKey string) error {
	if err := os.MkdirAll(r.pubDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(r.pubDir, "."+name+".pub.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(authorizedKey + "\n"); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, r.pubPath(name)); err != nil {
		return err
	}
	done = true
	return nil
}

// pubPath is the .pub file for a name that passed config.ValidKeyName.
func (r *Registry) pubPath(name string) string {
	return filepath.Join(r.pubDir, name+".pub")
}

func infoOf(rec record, pub ssh.PublicKey) Info {
	blob := append([]byte(nil), rec.PublicKey...)
	return Info{
		Name:          rec.Name,
		Type:          pub.Type(),
		Fingerprint:   ssh.FingerprintSHA256(pub),
		AuthorizedKey: pub.Type() + " " + base64.StdEncoding.EncodeToString(blob) + " " + rec.Name,
		Blob:          blob,
		Auth:          rec.Auth,
		Access:        rec.Access,
		Created:       rec.Created,
	}
}

// decode parses a Vault record for name. Anything that is not a complete,
// self-consistent ecdsa-sha2-nistp256 record is errBroken; whatever did
// parse is still returned so Delete can try to free the enclave key.
func decode(name string, b []byte, chip string) (record, ssh.PublicKey, error) {
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return record{}, nil, fmt.Errorf("%w: %s: %v", errBroken, name, err)
	}
	broken := func(why string) (record, ssh.PublicKey, error) {
		return rec, nil, fmt.Errorf("%w: %s: %s", errBroken, name, why)
	}
	if rec.Name != name {
		return broken("record name does not match")
	}
	if len(rec.Handle) == 0 {
		return broken("no " + chip + " handle")
	}
	if rec.Auth != platform.AuthNone && rec.Auth != platform.AuthUserPresence {
		return broken("unknown auth policy " + rec.Auth.String())
	}
	if !rec.Access.Valid() {
		return broken("unknown access " + rec.Access.String())
	}
	pub, err := ssh.ParsePublicKey(rec.PublicKey)
	if err != nil {
		return broken("bad public key: " + err.Error())
	}
	if pub.Type() != ssh.KeyAlgoECDSA256 {
		return broken("unexpected key type " + pub.Type())
	}
	return rec, pub, nil
}

// load reads and decodes the record for name. It returns ErrInvalidName,
// ErrNotFound, a wrapped Vault error, or an errBroken error (with whatever
// parsed) for an unusable record.
func (r *Registry) load(name string) (record, ssh.PublicKey, error) {
	if !config.ValidKeyName(name) {
		return record{}, nil, ErrInvalidName
	}
	b, err := r.v.Get(VaultPrefix + name)
	if errors.Is(err, platform.ErrNotFound) {
		return record{}, nil, ErrNotFound
	}
	if err != nil {
		return record{}, nil, fmt.Errorf("keys: read vault item %s%s: %w", VaultPrefix, name, err)
	}
	return decode(name, b, r.tr.KeyChip())
}

// Get returns one key. A record that is in the Vault but cannot be read
// (the Keychain refuses or fails to decode that one item) or cannot be
// decoded is returned with Broken set and no error (spec 9): one bad item
// degrades only its own key, which stays visible and can be deleted.
func (r *Registry) Get(name string) (Info, error) {
	rec, pub, err := r.load(name)
	switch {
	case err == nil:
		return infoOf(rec, pub), nil
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrInvalidName):
		return Info{}, err
	default:
		return Info{Name: name, Broken: true, Unreadable: !errors.Is(err, errBroken), Problem: err.Error()}, nil
	}
}

// List returns every key record in the Vault, sorted by name. Records that
// cannot be read or decoded, and records under names that are not valid
// key names, are listed with Broken set; the other keys are unaffected.
// Only a Vault whose listing fails is an error.
func (r *Registry) List() ([]Info, error) {
	names, err := r.v.List(VaultPrefix)
	if err != nil {
		return nil, fmt.Errorf("keys: list vault: %w", err)
	}
	out := make([]Info, 0, len(names))
	for _, n := range names {
		if !strings.HasPrefix(n, VaultPrefix) {
			continue
		}
		name := strings.TrimPrefix(n, VaultPrefix)
		info, err := r.Get(name)
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

// ByBlob finds a usable key by its exact SSH wire public key.
func (r *Registry) ByBlob(blob []byte) (Info, bool) {
	if len(blob) == 0 {
		return Info{}, false
	}
	all, err := r.List()
	if err != nil {
		return Info{}, false
	}
	for _, k := range all {
		if !k.Broken && bytes.Equal(k.Blob, blob) {
			return k, true
		}
	}
	return Info{}, false
}

// Delete removes the key from the enclave, the Vault and the key folder.
// A broken record is removed too; a missing .pub or an already wiped
// enclave handle is not an error. The name is validated before it is ever
// used as a file name, so a tampered Vault cannot make Delete touch a file
// outside the key folder.
//
// Destroying a Secure Enclave key cannot be undone, so the handle in the
// record is freed only when it is unmistakably this key's: the record names
// this key (a record that carries another key's name is a stray copy of
// that key) and no other Vault record points at the same handle. Otherwise
// only the Vault item and the .pub go; the enclave key is freed when the
// last record referring to it is deleted.
//
// A record the Vault cannot read at all (spec 9: listed as broken) has no
// handle to free: Delete removes the Vault item and the .pub so the name
// is usable again and the broken entry stops being listed, and reports the
// Vault's delete error if that fails too.
func (r *Registry) Delete(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, _, err := r.load(name)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalidName) {
		return err
	}
	if rec.Name == name && len(rec.Handle) > 0 {
		shared, err := r.handleShared(name, rec.Handle)
		if err != nil {
			return err
		}
		if !shared {
			if err := r.p.DeleteKey(rec.Handle); err != nil && !errors.Is(err, platform.ErrNotFound) {
				return fmt.Errorf("keys: delete %s key: %w", r.tr.KeyChip(), err)
			}
		}
	}
	if err := r.v.Delete(VaultPrefix + name); err != nil {
		return fmt.Errorf("keys: delete key handle: %w", err)
	}
	// os.Remove unlinks the entry itself, never a symlink's target.
	if err := os.Remove(r.pubPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("keys: remove %s.pub: %w", name, err)
	}
	return nil
}

// handleShared reports whether a Vault record other than name's carries the
// same enclave handle. Any record whose JSON parses counts, broken or not: a
// duplicated or corrupted Keychain item (restore, migration) must never let
// deleting it wipe a different, working key. A Vault that cannot be read is
// an error, so Delete never guesses.
func (r *Registry) handleShared(name string, handle []byte) (bool, error) {
	names, err := r.v.List(VaultPrefix)
	if err != nil {
		return false, fmt.Errorf("keys: list vault: %w", err)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, VaultPrefix) || n == VaultPrefix+name {
			continue
		}
		b, err := r.v.Get(n)
		if errors.Is(err, platform.ErrNotFound) {
			continue // deleted between List and Get
		}
		if err != nil {
			return false, fmt.Errorf("keys: read vault item %s: %w", n, err)
		}
		var other record
		if json.Unmarshal(b, &other) == nil && bytes.Equal(other.Handle, handle) {
			return true, nil
		}
	}
	return false, nil
}

// Sign signs data with the named key under approval ref and returns an SSH
// signature. The platform's DER signature is converted and verified against
// the stored public key before it is returned, so garbage from the platform
// or a signature by some other key is an error, never a reply.
func (r *Registry) Sign(name string, data []byte, ref platform.ApprovalRef) (*ssh.Signature, error) {
	rec, pub, err := r.load(name)
	if err != nil {
		return nil, err
	}
	der, err := r.p.Sign(rec.Handle, data, ref)
	if errors.Is(err, platform.ErrLocked) && rec.Access == platform.AccessWhenUnlocked {
		return nil, platform.Locked(fmt.Sprintf("keys: %s is locked; %s signs only while it's unlocked", r.tr.Machine, name))
	}
	if err != nil {
		return nil, fmt.Errorf("keys: sign with %s: %w", name, err)
	}
	sig, err := agentproto.ECDSASignatureFromDER(der)
	if err != nil {
		return nil, fmt.Errorf("keys: sign with %s: %w", name, err)
	}
	if err := pub.Verify(data, sig); err != nil {
		return nil, fmt.Errorf("keys: %s signature for %s does not verify (key broken?): %w", r.tr.KeyChip(), name, err)
	}
	return sig, nil
}
