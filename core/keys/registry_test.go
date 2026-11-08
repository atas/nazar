package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

// spyPlatform is the fake platform with a window onto the enclave: it tracks
// which issued handles are still alive (created and not deleted), records
// what CreateKey was asked for, and can be scripted to misbehave the way a
// broken or hostile platform layer might.
type spyPlatform struct {
	*fake.Fake

	mu       sync.Mutex
	live     map[string]bool // hex(handle) -> alive
	handles  [][]byte        // every handle CreateKey returned, in order
	purposes []platform.Purpose
	auths    []platform.AuthPolicy

	createErr error                                                               // CreateKey fails with this
	pubFunc   func(real []byte) []byte                                            // rewrites the public key CreateKey returns
	signFunc  func(handle, data []byte, ref platform.ApprovalRef) ([]byte, error) // replaces Sign
	deleteErr error                                                               // DeleteKey fails with this
}

func newSpy() *spyPlatform {
	return &spyPlatform{Fake: fake.New(t0), live: map[string]bool{}}
}

func (s *spyPlatform) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	s.mu.Lock()
	s.purposes = append(s.purposes, purpose)
	s.auths = append(s.auths, auth)
	createErr, pubFunc := s.createErr, s.pubFunc
	s.mu.Unlock()
	if createErr != nil {
		return nil, nil, createErr
	}
	h, pub, err := s.Fake.CreateKey(purpose, auth, access)
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	s.live[hex.EncodeToString(h)] = true
	s.handles = append(s.handles, append([]byte(nil), h...))
	s.mu.Unlock()
	if pubFunc != nil {
		pub = pubFunc(pub)
	}
	return h, pub, nil
}

func (s *spyPlatform) Sign(handle, data []byte, ref platform.ApprovalRef) ([]byte, error) {
	s.mu.Lock()
	fn := s.signFunc
	s.mu.Unlock()
	if fn != nil {
		return fn(handle, data, ref)
	}
	return s.Fake.Sign(handle, data, ref)
}

func (s *spyPlatform) DeleteKey(handle []byte) error {
	s.mu.Lock()
	derr := s.deleteErr
	s.mu.Unlock()
	if derr != nil {
		return derr
	}
	err := s.Fake.DeleteKey(handle)
	if err == nil {
		s.mu.Lock()
		delete(s.live, hex.EncodeToString(handle))
		s.mu.Unlock()
	}
	return err
}

// Live is the number of enclave keys created and not yet deleted.
func (s *spyPlatform) Live() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

func (s *spyPlatform) Handles() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.handles...)
}

// spyVault is the in-memory vault with scriptable read/list/delete failures
// (Put failures come from fake.Vault.FailPut).
type spyVault struct {
	*fake.Vault
	FailGet    error            // every Get fails with this
	FailGetOf  map[string]error // Get of these names (with prefix) fails; the rest work
	FailList   error
	FailDelete error
}

func (v *spyVault) Get(name string) ([]byte, error) {
	if v.FailGet != nil {
		return nil, v.FailGet
	}
	if err := v.FailGetOf[name]; err != nil {
		return nil, err
	}
	return v.Vault.Get(name)
}

func (v *spyVault) List(prefix string) ([]string, error) {
	if v.FailList != nil {
		return nil, v.FailList
	}
	return v.Vault.List(prefix)
}

func (v *spyVault) Delete(name string) error {
	if v.FailDelete != nil {
		return v.FailDelete
	}
	return v.Vault.Delete(name)
}

func newReg(t *testing.T) (*Registry, *spyPlatform, *spyVault, string) {
	t.Helper()
	f := newSpy()
	v := &spyVault{Vault: fake.NewVault()}
	dir := filepath.Join(t.TempDir(), "keys")
	return NewRegistry(f, v, dir, f.Now), f, v, dir
}

func mustCreate(t *testing.T, r *Registry, name string, auth platform.AuthPolicy) Info {
	t.Helper()
	info, err := r.Create(name, auth, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatalf("Create(%q): %v", name, err)
	}
	return info
}

func vaultNames(t *testing.T, v *spyVault) []string {
	t.Helper()
	names, err := v.Vault.List("")
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// assertNothingLeft checks that a failed Create left no trace: no live
// enclave key, no Vault item, no file in the key folder, nothing listed.
func assertNothingLeft(t *testing.T, r *Registry, f *spyPlatform, v *spyVault, dir string) {
	t.Helper()
	if n := f.Live(); n != 0 {
		t.Errorf("%d enclave key(s) leaked", n)
	}
	if names := vaultNames(t, v); len(names) != 0 {
		t.Errorf("vault items left: %q", names)
	}
	if es := dirEntries(t, dir); len(es) != 0 {
		t.Errorf("files left in key folder: %q", es)
	}
	if list, err := r.List(); err != nil || len(list) != 0 {
		t.Errorf("List = %+v, %v; want empty", list, err)
	}
}

func signAndVerify(t *testing.T, r *Registry, info Info, ref platform.ApprovalRef) {
	t.Helper()
	data := []byte("payload for " + info.Name)
	sig, err := r.Sign(info.Name, data, ref)
	if err != nil {
		t.Fatalf("Sign(%q): %v", info.Name, err)
	}
	pub, err := ssh.ParsePublicKey(info.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(data, sig); err != nil {
		t.Fatalf("Sign(%q) does not verify: %v", info.Name, err)
	}
}

// ------------------------------------------------------------ core behaviour

func TestCreateWritesPubAndHidesHandle(t *testing.T) {
	r, _, v, dir := newReg(t)
	info, err := r.Create("github", platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if info.Type != "ecdsa-sha2-nistp256" || !strings.HasPrefix(info.Fingerprint, "SHA256:") || !strings.HasSuffix(info.AuthorizedKey, " github") {
		t.Fatalf("%+v", info)
	}
	b, err := os.ReadFile(filepath.Join(dir, "github.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(b); err != nil {
		t.Fatalf(".pub does not parse: %v", err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "github.pub"))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	if _, err := v.Get(VaultPrefix + "github"); err != nil {
		t.Fatal("handle must be in the vault")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("only the .pub may be on disk, found %d files", len(entries))
	}
	if _, err := r.Create("github", platform.AuthNone, platform.AccessWhenUnlocked); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := r.Create("../evil", platform.AuthNone, platform.AccessWhenUnlocked); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("bad name: %v", err)
	}
}

func TestSignVerifies(t *testing.T) {
	r, _, _, _ := newReg(t)
	info, _ := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked)
	sig, err := r.Sign("k", []byte("data"), 0)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.ParsePublicKey(info.Blob)
	if err := pub.Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.ByBlob(info.Blob); !ok {
		t.Fatal("ByBlob")
	}
	if _, ok := r.ByBlob([]byte("nope")); ok {
		t.Fatal("ByBlob matched garbage")
	}
}

func TestUserPresenceKeyNeedsApproval(t *testing.T) {
	r, f, _, _ := newReg(t)
	r.Create("k", platform.AuthUserPresence, platform.AccessWhenUnlocked)
	if _, err := r.Sign("k", []byte("d"), 0); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("want ErrAuthRequired, got %v", err)
	}
	f.ScriptAuth(fake.Answer{Allow: true})
	ref, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	if _, err := r.Sign("k", []byte("d"), ref); err != nil {
		t.Fatal(err)
	}
}

// A key's Access is kept in its record and reported as it was made;
// out-of-range access is refused before anything is made.
func TestCreateKeepsAccess(t *testing.T) {
	r, _, _, _ := newReg(t)
	for name, a := range map[string]platform.Access{"locked-ok": platform.AccessAfterFirstUnlock, "unlocked-only": platform.AccessWhenUnlocked} {
		if info, err := r.Create(name, platform.AuthNone, a); err != nil || info.Access != a {
			t.Fatalf("Create(%s, %v) = %+v, %v", name, a, info, err)
		}
		if got, err := r.Get(name); err != nil || got.Access != a {
			t.Fatalf("Get(%s) = %+v, %v; want access %v", name, got, err, a)
		}
	}
	r2, f2, v2, dir2 := newReg(t)
	if _, err := r2.Create("k", platform.AuthNone, platform.Access(2)); err == nil {
		t.Fatal("unknown access accepted")
	}
	assertNothingLeft(t, r2, f2, v2, dir2)
}

// While the Mac is locked no when-unlocked key can be made: Create says
// so and leaves nothing behind; a while-locked key is made.
func TestCreateWhileLockedSaysSo(t *testing.T) {
	r, f, v, dir := newReg(t)
	f.SetLocked(true)
	_, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked)
	if !errors.Is(err, platform.ErrLocked) || err.Error() != "keys: the Mac is locked; a key that works only while it's unlocked can't be made now" {
		t.Fatalf("Create while locked = %v", err)
	}
	assertNothingLeft(t, r, f, v, dir)
	if _, err := r.Create("bot", platform.AuthNone, platform.AccessAfterFirstUnlock); err != nil {
		t.Fatal(err)
	}
}

// A key with user presence works only while the Mac is unlocked: the
// registry refuses the other access before any key is made.
func TestCreateRefusesPresenceWhileLocked(t *testing.T) {
	r, f, v, dir := newReg(t)
	if _, err := r.Create("k", platform.AuthUserPresence, platform.AccessAfterFirstUnlock); err == nil {
		t.Fatal("user presence with after-first-unlock accepted")
	}
	assertNothingLeft(t, r, f, v, dir)
}

// A record written before Access existed has no access field: it is a
// when-unlocked key (the only kind nazar made then), never reported as one
// that works while the Mac is locked. An access value nazar never writes
// makes the record broken.
func TestRecordWithoutAccessIsWhenUnlocked(t *testing.T) {
	r, _, v, _ := newReg(t)
	mustCreate(t, r, "old", platform.AuthNone)
	b, _ := v.Get(VaultPrefix + "old")
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["access"]; ok {
		t.Fatalf("a when-unlocked record carries an access field: %s", b)
	}
	if got, err := r.Get("old"); err != nil || got.Broken || got.Access != platform.AccessWhenUnlocked {
		t.Fatalf("Get(old) = %+v, %v; want a usable when-unlocked key", got, err)
	}
	m["access"] = 5
	b, _ = json.Marshal(m)
	if err := v.Put(VaultPrefix+"old", b); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Get("old"); err != nil || !got.Broken {
		t.Fatalf("Get(old) with access 5 = %+v, %v; want broken", got, err)
	}
}

// A when-unlocked key used while the Mac is locked fails with an error that
// says so, by the key's name, and still matches platform.ErrLocked.
func TestSignWhileLockedSaysSo(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "github", platform.AuthNone)
	if _, err := r.Create("bot", platform.AuthNone, platform.AccessAfterFirstUnlock); err != nil {
		t.Fatal(err)
	}
	f.SetLocked(true)
	_, err := r.Sign("github", []byte("d"), 0)
	if !errors.Is(err, platform.ErrLocked) || err.Error() != "keys: the Mac is locked; github signs only while it's unlocked" {
		t.Fatalf("Sign while locked = %v", err)
	}
	if _, err := r.Sign("bot", []byte("d"), 0); err != nil {
		t.Fatalf("after-first-unlock key while locked: %v", err)
	}
	// A platform that says "locked" for a key that works while locked is
	// passed through as it is, never worded as that key's rule.
	f.signFunc = func([]byte, []byte, platform.ApprovalRef) ([]byte, error) { return nil, platform.ErrLocked }
	if _, err := r.Sign("bot", []byte("d"), 0); !errors.Is(err, platform.ErrLocked) || err.Error() != "keys: sign with bot: platform: the Mac is locked" {
		t.Fatalf("after-first-unlock key, platform says locked: %v", err)
	}
}

func TestDelete(t *testing.T) {
	r, _, _, dir := newReg(t)
	r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked)
	if err := r.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "k.pub")); !os.IsNotExist(err) {
		t.Fatal(".pub not removed")
	}
	if _, err := r.Sign("k", []byte("d"), 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key signed: %v", err)
	}
	if err := r.Delete("k"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestBrokenRecordIsListed(t *testing.T) {
	r, _, v, _ := newReg(t)
	r.Create("good", platform.AuthNone, platform.AccessWhenUnlocked)
	v.Put(VaultPrefix+"bad", []byte("{"))
	list, err := r.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", list, err)
	}
	if !list[0].Broken || list[0].Name != "bad" || list[1].Broken {
		t.Fatalf("%+v", list)
	}
	if _, err := r.Sign("bad", []byte("d"), 0); err == nil {
		t.Fatal("broken key signed")
	}
}

func TestVaultFailureLeavesNoKey(t *testing.T) {
	r, _, v, _ := newReg(t)
	v.FailPut = errors.New("keychain locked")
	if _, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Fatal("want error")
	}
	if list, _ := r.List(); len(list) != 0 {
		t.Fatal("no key may remain")
	}
}

// ------------------------------------------------------------------ Create

// The returned Info, the .pub file and the parsed public key all describe
// the same enclave key, in the exact OpenSSH format ssh and git read.
func TestCreateInfoMatchesPubFileAndEnclaveKey(t *testing.T) {
	r, f, _, dir := newReg(t)
	info := mustCreate(t, r, "a.b_c-1", platform.AuthNone)

	if info.Name != "a.b_c-1" || info.Auth != platform.AuthNone || !info.Created.Equal(t0) || info.Broken {
		t.Fatalf("info = %+v", info)
	}
	pub, err := ssh.ParsePublicKey(info.Blob)
	if err != nil {
		t.Fatalf("Blob is not an SSH public key: %v", err)
	}
	if pub.Type() != ssh.KeyAlgoECDSA256 || info.Type != ssh.KeyAlgoECDSA256 {
		t.Fatalf("type %q / %q, want %q", pub.Type(), info.Type, ssh.KeyAlgoECDSA256)
	}
	if info.Fingerprint != ssh.FingerprintSHA256(pub) {
		t.Fatalf("fingerprint %q, want %q", info.Fingerprint, ssh.FingerprintSHA256(pub))
	}
	fields := strings.Fields(info.AuthorizedKey)
	if len(fields) != 3 || fields[0] != ssh.KeyAlgoECDSA256 || fields[2] != "a.b_c-1" ||
		fields[1] != base64.StdEncoding.EncodeToString(info.Blob) {
		t.Fatalf("AuthorizedKey = %q", info.AuthorizedKey)
	}

	b, err := os.ReadFile(filepath.Join(dir, "a.b_c-1.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != info.AuthorizedKey+"\n" {
		t.Fatalf(".pub = %q, want %q", b, info.AuthorizedKey+"\n")
	}
	filePub, comment, _, rest, err := ssh.ParseAuthorizedKey(b)
	if err != nil || comment != "a.b_c-1" || len(rest) != 0 || !bytes.Equal(filePub.Marshal(), info.Blob) {
		t.Fatalf("ParseAuthorizedKey(.pub) = %v, %q, rest %q, %v", filePub, comment, rest, err)
	}

	// The key really is the enclave key: the enclave's own signature over
	// some data verifies against the exported key.
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d, want 1", f.Live())
	}
	signAndVerify(t, r, info, 0)
}

// Keys are created as signing keys with exactly the auth policy asked for:
// a presence key must never be silently created without presence.
func TestCreatePassesPurposeAndAuthToThePlatform(t *testing.T) {
	r, f, _, _ := newReg(t)
	a := mustCreate(t, r, "a", platform.AuthNone)
	b := mustCreate(t, r, "b", platform.AuthUserPresence)
	if a.Auth != platform.AuthNone || b.Auth != platform.AuthUserPresence {
		t.Fatalf("Auth: a=%v b=%v", a.Auth, b.Auth)
	}
	f.mu.Lock()
	purposes, auths := append([]platform.Purpose(nil), f.purposes...), append([]platform.AuthPolicy(nil), f.auths...)
	f.mu.Unlock()
	if len(purposes) != 2 || purposes[0] != platform.PurposeSign || purposes[1] != platform.PurposeSign {
		t.Fatalf("purposes = %v, want [sign sign]", purposes)
	}
	if len(auths) != 2 || auths[0] != platform.AuthNone || auths[1] != platform.AuthUserPresence {
		t.Fatalf("auths = %v", auths)
	}
	if got, err := r.Get("b"); err != nil || got.Auth != platform.AuthUserPresence {
		t.Fatalf("Get(b) = %+v, %v", got, err)
	}
}

func TestCreateRefusesUnknownAuthPolicy(t *testing.T) {
	r, f, v, dir := newReg(t)
	if _, err := r.Create("k", platform.AuthPolicy(7), platform.AccessWhenUnlocked); err == nil {
		t.Fatal("unknown auth policy accepted")
	}
	assertNothingLeft(t, r, f, v, dir)
}

func TestCreateRefusesInvalidNamesBeforeTouchingAnything(t *testing.T) {
	bad := []string{
		"", ".", "..", "../evil", "a/b", "/abs", "a\\b", ".hidden", "-rf", "_x",
		"a b", "a\x00b", "a\nb", "k.pub/../x", "x..y", "gіthub", // Cyrillic і
		"ключ", strings.Repeat("a", 65), "a:b", "~root", "$HOME",
	}
	for _, name := range bad {
		r, f, v, dir := newReg(t)
		if _, err := r.Create(name, platform.AuthNone, platform.AccessWhenUnlocked); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Create(%q) = %v, want ErrInvalidName", name, err)
		}
		f.mu.Lock()
		calls := len(f.purposes)
		f.mu.Unlock()
		if calls != 0 {
			t.Errorf("Create(%q) reached the enclave", name)
		}
		assertNothingLeft(t, r, f, v, dir)
		// Nothing was written next to (or above) the key folder either.
		if es := dirEntries(t, filepath.Dir(dir)); len(es) != 0 {
			t.Errorf("Create(%q) wrote %q next to the key folder", name, es)
		}
	}
	r, _, _, _ := newReg(t)
	mustCreate(t, r, strings.Repeat("a", 64), platform.AuthNone)
}

func TestCreateDuplicateKeepsTheOriginalKey(t *testing.T) {
	r, f, _, dir := newReg(t)
	orig := mustCreate(t, r, "k", platform.AuthNone)
	before, _ := os.ReadFile(filepath.Join(dir, "k.pub"))
	for _, auth := range []platform.AuthPolicy{platform.AuthNone, platform.AuthUserPresence} {
		if _, err := r.Create("k", auth, platform.AccessWhenUnlocked); !errors.Is(err, ErrExists) {
			t.Fatalf("duplicate Create(k, %v) = %v, want ErrExists", auth, err)
		}
	}
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d after refused duplicates, want 1", f.Live())
	}
	after, _ := os.ReadFile(filepath.Join(dir, "k.pub"))
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate Create rewrote the .pub")
	}
	got, err := r.Get("k")
	if err != nil || !bytes.Equal(got.Blob, orig.Blob) || got.Auth != platform.AuthNone {
		t.Fatalf("Get(k) = %+v, %v", got, err)
	}
	signAndVerify(t, r, orig, 0)
}

// ~/.nazar/keys lives on a case-insensitive file system (APFS
// default), so "GitHub" and "github" would share one .pub file: creating
// the second must not overwrite the first key's public key.
func TestCreateRefusesNamesDifferingOnlyInCase(t *testing.T) {
	r, f, _, dir := newReg(t)
	orig := mustCreate(t, r, "github", platform.AuthNone)
	for _, name := range []string{"GitHub", "GITHUB", "gitHub"} {
		if _, err := r.Create(name, platform.AuthNone, platform.AccessWhenUnlocked); !errors.Is(err, ErrExists) {
			t.Fatalf("Create(%q) after github = %v, want ErrExists", name, err)
		}
	}
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d, want 1", f.Live())
	}
	b, err := os.ReadFile(filepath.Join(dir, "github.pub"))
	if err != nil || string(b) != orig.AuthorizedKey+"\n" {
		t.Fatalf("github.pub = %q, %v; want the original key", b, err)
	}
	list, _ := r.List()
	if len(list) != 1 || list[0].Name != "github" {
		t.Fatalf("List = %+v", list)
	}
}

// A stale .pub left behind (key deleted on another Mac, restored dotfiles)
// is replaced by the new key's public key.
func TestCreateReplacesStalePubFile(t *testing.T) {
	r, _, _, dir := newReg(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k.pub"), []byte("ssh-ed25519 AAAAstale old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info := mustCreate(t, r, "k", platform.AuthNone)
	b, _ := os.ReadFile(filepath.Join(dir, "k.pub"))
	if string(b) != info.AuthorizedKey+"\n" {
		t.Fatalf(".pub = %q", b)
	}
	fi, _ := os.Stat(filepath.Join(dir, "k.pub"))
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o, want 644", fi.Mode().Perm())
	}
}

// A symlink planted at keys/<name>.pub must not make nazar write through it
// into another file (e.g. ~/.ssh/authorized_keys).
func TestCreateDoesNotWriteThroughPlantedSymlink(t *testing.T) {
	r, _, _, dir := newReg(t)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(filepath.Dir(dir), "authorized_keys")
	if err := os.WriteFile(victim, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "k.pub")); err != nil {
		t.Fatal(err)
	}
	info := mustCreate(t, r, "k", platform.AuthNone)
	if b, _ := os.ReadFile(victim); string(b) != "precious\n" {
		t.Fatalf("symlink target was written: %q", b)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o600 {
		t.Fatalf("symlink target mode changed to %o", fi.Mode().Perm())
	}
	fi, err := os.Lstat(filepath.Join(dir, "k.pub"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("k.pub is not a regular file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "k.pub")); string(b) != info.AuthorizedKey+"\n" {
		t.Fatalf(".pub = %q", b)
	}
}

// The .pub is world-readable (0644) whatever the process umask is, and the
// write leaves no temporary files behind.
func TestPubModeIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	r, _, _, dir := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	fi, err := os.Stat(filepath.Join(dir, "k.pub"))
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("k.pub mode %v, %v; want 0644", fi, err)
	}
	if es := dirEntries(t, dir); len(es) != 1 {
		t.Fatalf("key folder holds %q, want only k.pub", es)
	}
}

// The enclave handle never reaches a file or the returned Info, in any
// common encoding. Only the Vault holds it (spec 4.5).
func TestHandleNeverOnDiskOrInInfo(t *testing.T) {
	r, f, _, dir := newReg(t)
	infos := []Info{
		mustCreate(t, r, "one", platform.AuthNone),
		mustCreate(t, r, "two", platform.AuthUserPresence),
	}
	list, _ := r.List()
	infos = append(infos, list...)
	got, _ := r.Get("one")
	infos = append(infos, got)
	byBlob, _ := r.ByBlob(infos[0].Blob)
	infos = append(infos, byBlob)

	root := filepath.Dir(dir)
	for _, h := range f.Handles() {
		needles := [][]byte{
			h,
			[]byte(hex.EncodeToString(h)),
			[]byte(strings.ToUpper(hex.EncodeToString(h))),
			[]byte(base64.StdEncoding.EncodeToString(h)),
			[]byte(base64.RawStdEncoding.EncodeToString(h)),
			[]byte(base64.URLEncoding.EncodeToString(h)),
			[]byte(base64.RawURLEncoding.EncodeToString(h)),
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, n := range needles {
				if bytes.Contains(b, n) {
					t.Errorf("enclave handle found in %s", p)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, info := range infos {
			dump := []byte(fmt.Sprintf("%+v %#v", info, info))
			dump = append(dump, info.Blob...)
			for _, n := range needles {
				if bytes.Contains(dump, n) {
					t.Errorf("enclave handle exposed through Info %q", info.Name)
				}
			}
		}
	}
}

func TestCreatePlatformFailureLeavesNothing(t *testing.T) {
	r, f, v, dir := newReg(t)
	f.createErr = errors.New("secure enclave unavailable")
	if _, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Fatal("want error")
	}
	assertNothingLeft(t, r, f, v, dir)
}

// The platform layer is not trusted to return a well-formed P-256 point: a
// malformed public key is refused and the enclave key it came with is
// deleted rather than kept around unexported.
func TestCreateRefusesBadPublicKeyFromPlatform(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384Bytes, _ := p384.PublicKey.Bytes()
	cases := map[string]func(real []byte) []byte{
		"empty":        func([]byte) []byte { return nil },
		"truncated":    func(r []byte) []byte { return r[:len(r)-1] },
		"extended":     func(r []byte) []byte { return append(append([]byte(nil), r...), 0) },
		"compressed":   func(r []byte) []byte { return append([]byte{0x02 | (r[64] & 1)}, r[1:33]...) },
		"not on curve": func(r []byte) []byte { b := bytes.Repeat([]byte{1}, 65); b[0] = 4; return b },
		"zero point":   func(r []byte) []byte { b := make([]byte, 65); b[0] = 4; return b },
		"bad prefix":   func(r []byte) []byte { b := append([]byte(nil), r...); b[0] = 0x05; return b },
		"P-384":        func([]byte) []byte { return p384Bytes },
		"ssh blob":     func(r []byte) []byte { return []byte("ecdsa-sha2-nistp256 AAAA") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, f, v, dir := newReg(t)
			f.pubFunc = mutate
			if _, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
				t.Fatal("bad public key accepted")
			}
			assertNothingLeft(t, r, f, v, dir)
		})
	}
}

// The Vault write is the commit point: if it fails, the enclave key is
// deleted and no .pub is exported for a key nazar cannot use.
func TestCreateVaultPutFailureLeavesNothing(t *testing.T) {
	r, f, v, dir := newReg(t)
	v.FailPut = errors.New("keychain locked")
	if _, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Fatal("want error")
	}
	v.FailPut = nil
	assertNothingLeft(t, r, f, v, dir)
	// The name is free again once the Vault works.
	info := mustCreate(t, r, "k", platform.AuthNone)
	signAndVerify(t, r, info, 0)
}

// If the Vault can't be read, Create can't know whether the name is taken:
// it must fail instead of creating (and possibly overwriting) a key.
func TestCreateVaultReadFailureCreatesNothing(t *testing.T) {
	r, f, v, dir := newReg(t)
	v.FailGet = errors.New("keychain locked")
	if _, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Fatal("want error")
	}
	v.FailGet = nil
	assertNothingLeft(t, r, f, v, dir)
}

// The .pub export is the last step of Create; when it fails, the enclave key
// and the Vault item made just before are rolled back, so nothing reports
// the key as existing and the name is free for a retry.
func TestCreateFailsWhenPubCannotBeWritten(t *testing.T) {
	r, f, v, dir := newReg(t)
	// The key folder path is taken by a regular file.
	if err := os.WriteFile(dir, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create("k", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Fatal("Create reported success without exporting the .pub")
	}
	if n := f.Live(); n != 0 {
		t.Errorf("%d enclave key(s) leaked after the .pub export failed", n)
	}
	if names := vaultNames(t, v); len(names) != 0 {
		t.Errorf("vault items left after the .pub export failed: %q", names)
	}
	if list, err := r.List(); err != nil || len(list) != 0 {
		t.Errorf("List = %+v, %v; want empty", list, err)
	}
	if _, err := r.Get("k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get(k) = %v, want ErrNotFound", err)
	}
	if b, err := os.ReadFile(dir); err != nil || string(b) != "not a folder" {
		t.Errorf("the file in the key folder's place was changed: %q, %v", b, err)
	}
	// With the obstacle gone the name is free and a retry works.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	info := mustCreate(t, r, "k", platform.AuthNone)
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d after retry, want 1", f.Live())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "k.pub")); string(b) != info.AuthorizedKey+"\n" {
		t.Fatalf("k.pub = %q after retry", b)
	}
	signAndVerify(t, r, info, 0)
}

func TestCreateMakesMissingKeyFolder(t *testing.T) {
	f := newSpy()
	dir := filepath.Join(t.TempDir(), "config", "nazar", "keys")
	r := NewRegistry(f, fake.NewVault(), dir, f.Now)
	mustCreate(t, r, "k", platform.AuthNone)
	if _, err := os.Stat(filepath.Join(dir, "k.pub")); err != nil {
		t.Fatal(err)
	}
}

func TestCreateUsesInjectedClock(t *testing.T) {
	r, f, _, _ := newReg(t)
	a := mustCreate(t, r, "a", platform.AuthNone)
	f.Advance(90 * time.Minute)
	b := mustCreate(t, r, "b", platform.AuthNone)
	if !a.Created.Equal(t0) || !b.Created.Equal(t0.Add(90*time.Minute)) {
		t.Fatalf("Created a=%v b=%v", a.Created, b.Created)
	}
	f.Advance(time.Hour)
	if got, _ := r.Get("a"); !got.Created.Equal(t0) {
		t.Fatalf("Get(a).Created = %v, want %v", got.Created, t0)
	}
}

func TestEachKeyIsDistinct(t *testing.T) {
	r, f, _, _ := newReg(t)
	seen := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d"} {
		info := mustCreate(t, r, n, platform.AuthNone)
		if prev, dup := seen[info.Fingerprint]; dup {
			t.Fatalf("%s and %s share a key", prev, n)
		}
		seen[info.Fingerprint] = n
	}
	if f.Live() != 4 {
		t.Fatalf("live = %d", f.Live())
	}
}

// ---------------------------------------------------------------- Get/List

func TestGetUnknownAndInvalidNames(t *testing.T) {
	r, _, _, _ := newReg(t)
	mustCreate(t, r, "github", platform.AuthNone)
	if _, err := r.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(nope) = %v, want ErrNotFound", err)
	}
	for _, name := range []string{"", "../github", "github/", "github.pub"} {
		info, err := r.Get(name)
		if err == nil && !info.Broken {
			t.Errorf("Get(%q) = %+v, want an error", name, info)
		}
	}
}

func TestListIsSortedAndOnlyKeys(t *testing.T) {
	r, _, v, _ := newReg(t)
	for _, n := range []string{"zeta", "alpha", "mid"} {
		mustCreate(t, r, n, platform.AuthNone)
	}
	// Other Vault items (trust state, approved config) are not keys.
	v.Put("state/trust", []byte("{}"))
	v.Put("config/approved", []byte("apiVersion: nazar/v1\n"))
	v.Put("ssh-keys", []byte("x"))
	list, err := r.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, k := range list {
		names = append(names, k.Name)
		if k.Broken {
			t.Errorf("%s listed as broken", k.Name)
		}
		if got, err := r.Get(k.Name); err != nil || !bytes.Equal(got.Blob, k.Blob) || got.Fingerprint != k.Fingerprint {
			t.Errorf("List entry %s disagrees with Get: %+v / %+v, %v", k.Name, k, got, err)
		}
	}
	if strings.Join(names, ",") != "alpha,mid,zeta" {
		t.Fatalf("names = %v", names)
	}
}

func TestListEmpty(t *testing.T) {
	r, _, _, _ := newReg(t)
	list, err := r.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("List = %+v, %v", list, err)
	}
}

func TestListVaultFailureIsAnError(t *testing.T) {
	r, _, v, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	v.FailList = errors.New("keychain locked")
	if _, err := r.List(); err == nil {
		t.Fatal("List hid a Vault failure")
	}
	if _, ok := r.ByBlob([]byte("x")); ok {
		t.Fatal("ByBlob matched while the Vault is unreadable")
	}
}

// vaultRecord reads and parses the stored record of a key, for tests that
// plant modified copies of a real record.
func vaultRecord(t *testing.T, v *spyVault, name string) record {
	t.Helper()
	b, err := v.Vault.Get(VaultPrefix + name)
	if err != nil {
		t.Fatal(err)
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func mustJSON(t *testing.T, rec record) []byte {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Spec 9: a key whose record can't be read is listed as broken and never
// signs; every kind of garbage record is handled without a panic. The
// records that do parse but fail a consistency check (no handle, another
// key's name, a key that is not ecdsa-sha2-nistp256, an unknown auth
// policy) are just as broken: none may be offered to ssh through ByBlob.
func TestBrokenRecordsOfEveryShape(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSSH, _ := ssh.NewPublicKey(edPub)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384SSH, _ := ssh.NewPublicKey(&p384.PublicKey)

	static := func(b []byte) func(record) []byte { return func(record) []byte { return b } }
	cases := []struct {
		name string
		make func(good record) []byte // the bytes stored under ssh-key/bad
	}{
		{"nil", static(nil)},
		{"empty", static([]byte{})},
		{"open brace", static([]byte("{"))},
		{"null", static([]byte("null"))},
		{"empty object", static([]byte("{}"))},
		{"array", static([]byte("[]"))},
		{"string", static([]byte(`"x"`))},
		{"name only", static([]byte(`{"name":"bad"}`))},
		{"0xff", static(bytes.Repeat([]byte{0xff}, 300))},
		{"binary", static([]byte("\x00\x01\x02"))},
		// Structurally valid records built from a real one.
		{"no handle", func(g record) []byte {
			g.Name, g.Handle = "bad", nil
			return mustJSON(t, g)
		}},
		{"empty handle", func(g record) []byte {
			g.Name, g.Handle = "bad", []byte{}
			return mustJSON(t, g)
		}},
		{"another key's name", func(g record) []byte {
			return mustJSON(t, g) // still says "good", stored under "bad"
		}},
		{"ed25519 public key", func(g record) []byte {
			g.Name, g.PublicKey = "bad", edSSH.Marshal()
			return mustJSON(t, g)
		}},
		{"P-384 public key", func(g record) []byte {
			g.Name, g.PublicKey = "bad", p384SSH.Marshal()
			return mustJSON(t, g)
		}},
		{"no public key", func(g record) []byte {
			g.Name, g.PublicKey = "bad", nil
			return mustJSON(t, g)
		}},
		{"unknown auth policy", func(g record) []byte {
			g.Name, g.Auth = "bad", platform.AuthPolicy(7)
			return mustJSON(t, g)
		}},
		{"negative auth policy", func(g record) []byte {
			g.Name, g.Auth = "bad", platform.AuthPolicy(-1)
			return mustJSON(t, g)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, f, v, _ := newReg(t)
			good := mustCreate(t, r, "good", platform.AuthNone)
			stored := tc.make(vaultRecord(t, v, "good"))
			v.Put(VaultPrefix+"bad", stored)
			var badRec record
			_ = json.Unmarshal(stored, &badRec)

			list, err := r.List()
			if err != nil || len(list) != 2 {
				t.Fatalf("List = %+v, %v", list, err)
			}
			if list[0].Name != "bad" || !list[0].Broken || list[1].Name != "good" || list[1].Broken {
				t.Fatalf("List = %+v", list)
			}
			if info, err := r.Get("bad"); err != nil || !info.Broken {
				t.Fatalf("Get(bad) = %+v, %v; want Broken", info, err)
			}
			if sig, err := r.Sign("bad", []byte("d"), 0); err == nil || sig != nil {
				t.Fatalf("broken key signed: %v, %v", sig, err)
			}
			if k, ok := r.ByBlob(good.Blob); !ok || k.Name != "good" || !bytes.Equal(k.Blob, good.Blob) {
				t.Fatalf("ByBlob(good) = %+v, %v", k, ok)
			}
			// The broken record's own public key never resolves to the
			// broken record: either it is good's key (and good is
			// returned) or it is some other key and nothing matches.
			if k, ok := r.ByBlob(badRec.PublicKey); ok && (k.Name != "good" || !bytes.Equal(k.Blob, good.Blob)) {
				t.Fatalf("ByBlob(broken record's key) = %+v", k)
			}
			if !bytes.Equal(badRec.PublicKey, good.Blob) {
				if k, ok := r.ByBlob(badRec.PublicKey); ok {
					t.Fatalf("ByBlob(broken record's key) matched %q", k.Name)
				}
			}
			for _, blob := range [][]byte{nil, {}} {
				if k, ok := r.ByBlob(blob); ok {
					t.Fatalf("ByBlob(%v) matched %q", blob, k.Name)
				}
			}
			// A broken key can be cleaned up, and cleaning it up never
			// touches good's enclave key, whose handle every one of these
			// records either lacks or shares with good.
			if err := r.Delete("bad"); err != nil {
				t.Fatalf("Delete(bad) = %v", err)
			}
			if f.Live() != 1 {
				t.Fatalf("live enclave keys = %d after Delete(bad), want 1", f.Live())
			}
			if list, _ := r.List(); len(list) != 1 || list[0].Name != "good" {
				t.Fatalf("after delete List = %+v", list)
			}
			if _, err := r.Get("bad"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Get(bad) after delete = %v", err)
			}
			signAndVerify(t, r, good, 0)
		})
	}
}

// Handles live only in the Vault, so a fresh Registry (nazar restarted)
// over the same Vault and enclave finds and uses every key, even without
// the .pub files.
func TestKeysSurviveRestart(t *testing.T) {
	f := newSpy()
	v := fake.NewVault()
	dir := filepath.Join(t.TempDir(), "keys")
	r1 := NewRegistry(f, v, dir, f.Now)
	a := mustCreate(t, r1, "a", platform.AuthNone)
	b := mustCreate(t, r1, "b", platform.AuthUserPresence)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	f.Advance(24 * time.Hour)

	r2 := NewRegistry(f, v, dir, f.Now)
	list, err := r2.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("List after restart = %+v, %v", list, err)
	}
	for i, want := range []Info{a, b} {
		got := list[i]
		if got.Name != want.Name || !bytes.Equal(got.Blob, want.Blob) || got.Fingerprint != want.Fingerprint ||
			got.AuthorizedKey != want.AuthorizedKey || got.Auth != want.Auth || !got.Created.Equal(want.Created) || got.Broken {
			t.Fatalf("after restart %+v, want %+v", got, want)
		}
	}
	signAndVerify(t, r2, a, 0)
	if _, err := r2.Sign("b", []byte("d"), 0); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("presence key after restart: %v", err)
	}
}

// Info is a snapshot: mutating a returned Blob doesn't corrupt the registry.
func TestInfoBlobIsACopy(t *testing.T) {
	r, _, _, _ := newReg(t)
	info := mustCreate(t, r, "k", platform.AuthNone)
	orig := append([]byte(nil), info.Blob...)
	for i := range info.Blob {
		info.Blob[i] ^= 0xff
	}
	if got, _ := r.Get("k"); !bytes.Equal(got.Blob, orig) {
		t.Fatal("Get changed after mutating Create's Blob")
	}
	got, _ := r.ByBlob(orig)
	for i := range got.Blob {
		got.Blob[i] = 0
	}
	list, _ := r.List()
	for i := range list[0].Blob {
		list[0].Blob[i] = 0
	}
	if k, ok := r.ByBlob(orig); !ok || k.Name != "k" {
		t.Fatal("ByBlob broken after mutating returned Blobs")
	}
	signAndVerify(t, r, Info{Name: "k", Blob: orig}, 0)
}

// ------------------------------------------------------------------ ByBlob

func TestByBlobExactMatchOnly(t *testing.T) {
	r, _, _, _ := newReg(t)
	a := mustCreate(t, r, "a", platform.AuthNone)
	b := mustCreate(t, r, "b", platform.AuthUserPresence)
	for _, want := range []Info{a, b} {
		got, ok := r.ByBlob(want.Blob)
		if !ok || got.Name != want.Name || !bytes.Equal(got.Blob, want.Blob) || got.Auth != want.Auth {
			t.Fatalf("ByBlob(%s) = %+v, %v", want.Name, got, ok)
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := ssh.NewPublicKey(&other.PublicKey)
	near := append([]byte(nil), a.Blob...)
	near[len(near)-1] ^= 1
	for name, blob := range map[string][]byte{
		"nil":            nil,
		"empty":          {},
		"prefix":         a.Blob[:len(a.Blob)-1],
		"extended":       append(append([]byte(nil), a.Blob...), 0),
		"one bit off":    near,
		"other P-256":    otherPub.Marshal(),
		"authorized_key": []byte(a.AuthorizedKey),
		"fingerprint":    []byte(a.Fingerprint),
		"name":           []byte("a"),
	} {
		if got, ok := r.ByBlob(blob); ok {
			t.Errorf("ByBlob(%s) matched %q", name, got.Name)
		}
	}
}

// ------------------------------------------------------------------- Sign

func TestSignProducesSSHSignatureBoundToData(t *testing.T) {
	r, _, _, _ := newReg(t)
	info := mustCreate(t, r, "k", platform.AuthNone)
	other := mustCreate(t, r, "other", platform.AuthNone)
	pub, _ := ssh.ParsePublicKey(info.Blob)
	otherPub, _ := ssh.ParsePublicKey(other.Blob)
	for _, data := range [][]byte{nil, {}, []byte("x"), bytes.Repeat([]byte("big"), 100000)} {
		sig, err := r.Sign("k", data, 0)
		if err != nil {
			t.Fatalf("Sign(%d bytes): %v", len(data), err)
		}
		if sig.Format != ssh.KeyAlgoECDSA256 || len(sig.Rest) != 0 {
			t.Fatalf("signature format %q rest %x", sig.Format, sig.Rest)
		}
		if err := pub.Verify(data, sig); err != nil {
			t.Fatalf("Sign(%d bytes) does not verify: %v", len(data), err)
		}
		if err := pub.Verify(append(append([]byte(nil), data...), '!'), sig); err == nil {
			t.Fatal("signature verifies for other data")
		}
		if err := otherPub.Verify(data, sig); err == nil {
			t.Fatal("signature verifies under another key")
		}
	}
}

func TestSignUnknownOrInvalidName(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	if _, err := r.Sign("nope", []byte("d"), 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Sign(nope) = %v, want ErrNotFound", err)
	}
	before := f.SignCalls()
	for _, name := range []string{"", "K", "../k", "k/", "k.pub", "k\x00"} {
		if sig, err := r.Sign(name, []byte("d"), 0); err == nil || sig != nil {
			t.Errorf("Sign(%q) = %v, %v; want an error", name, sig, err)
		}
	}
	if f.SignCalls() != before {
		t.Fatal("a sign with an unknown name reached the enclave")
	}
}

func TestSignPresenceKeyRefusesBadRefs(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthUserPresence)
	other := fake.New(t0)
	other.ScriptAuth(fake.Answer{Allow: true})
	foreign, _ := other.Authenticate(platform.AuthUserPresence, platform.Prompt{})

	f.ScriptAuth(fake.Answer{Allow: true})
	ref, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	f.ReleaseApproval(ref)
	for _, bad := range []platform.ApprovalRef{0, 1, foreign, ref, platform.ApprovalRef(^uint64(0))} {
		if sig, err := r.Sign("k", []byte("d"), bad); !errors.Is(err, platform.ErrAuthRequired) || sig != nil {
			t.Fatalf("Sign with ref %v = %v, %v; want ErrAuthRequired", bad, sig, err)
		}
	}
	// A dialog confirmation is not an approval ref.
	f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	if ok, _ := f.Confirm(platform.Prompt{}); !ok {
		t.Fatal("confirm")
	}
	if _, err := r.Sign("k", []byte("d"), 0); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("after Confirm: %v", err)
	}
	// One live approval signs repeatedly until released.
	f.ScriptAuth(fake.Answer{Allow: true})
	live, _ := f.Authenticate(platform.AuthUserPresence, platform.Prompt{})
	info, _ := r.Get("k")
	signAndVerify(t, r, info, live)
	signAndVerify(t, r, info, live)
	f.ReleaseApproval(live)
	if _, err := r.Sign("k", []byte("d"), live); !errors.Is(err, platform.ErrAuthRequired) {
		t.Fatalf("after release: %v", err)
	}
}

func TestSignPassesPlatformErrorsThrough(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	for _, want := range []error{platform.ErrDenied, platform.ErrAuthRequired, errors.New("enclave busy")} {
		f.signFunc = func([]byte, []byte, platform.ApprovalRef) ([]byte, error) { return nil, want }
		if sig, err := r.Sign("k", []byte("d"), 0); !errors.Is(err, want) || sig != nil {
			t.Fatalf("Sign = %v, %v; want %v", sig, err, want)
		}
	}
}

// Every signature is verified against the stored public key before it is
// returned: a platform that returns garbage, a signature by another key or
// over other data must not produce a "valid-looking" reply.
func TestSignVerifiesPlatformOutput(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	strangerH, _, err := f.Fake.CreateKey(platform.PurposeSign, platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(handle, data []byte, ref platform.ApprovalRef) ([]byte, error){
		"nil":   func([]byte, []byte, platform.ApprovalRef) ([]byte, error) { return nil, nil },
		"empty": func([]byte, []byte, platform.ApprovalRef) ([]byte, error) { return []byte{}, nil },
		"garbage": func([]byte, []byte, platform.ApprovalRef) ([]byte, error) {
			return []byte("definitely not DER"), nil
		},
		"raw r||s": func(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
			return bytes.Repeat([]byte{0x42}, 64), nil
		},
		"other key": func(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
			return f.Fake.Sign(strangerH, d, ref)
		},
		"other data": func(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
			return f.Fake.Sign(h, append([]byte("x"), d...), ref)
		},
		"trailing bytes": func(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
			der, err := f.Fake.Sign(h, d, ref)
			return append(der, 0), err
		},
		"flipped bit": func(h, d []byte, ref platform.ApprovalRef) ([]byte, error) {
			der, err := f.Fake.Sign(h, d, ref)
			if err == nil {
				der[len(der)-1] ^= 1
			}
			return der, err
		},
	}
	for name, fn := range cases {
		f.signFunc = fn
		if sig, err := r.Sign("k", []byte("data"), 0); err == nil || sig != nil {
			t.Errorf("%s: Sign = %v, %v; want an error", name, sig, err)
		}
	}
	f.signFunc = nil
	info, _ := r.Get("k")
	signAndVerify(t, r, info, 0)
}

// Spec 9: a key whose enclave handle is gone (wiped, restored on another
// Mac) fails to sign instead of returning something.
func TestSignWithWipedHandleFails(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	if err := f.Fake.DeleteKey(f.Handles()[0]); err != nil {
		t.Fatal(err)
	}
	if sig, err := r.Sign("k", []byte("d"), 0); err == nil || sig != nil {
		t.Fatalf("Sign with wiped handle = %v, %v", sig, err)
	}
}

// ------------------------------------------------------------------ Delete

func TestDeleteRemovesEnclaveKeyVaultItemAndPub(t *testing.T) {
	r, f, v, dir := newReg(t)
	keep := mustCreate(t, r, "keep", platform.AuthNone)
	gone := mustCreate(t, r, "gone", platform.AuthUserPresence)
	if err := r.Delete("gone"); err != nil {
		t.Fatal(err)
	}
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d, want 1 (the enclave key must be deleted)", f.Live())
	}
	if _, err := v.Vault.Get(VaultPrefix + "gone"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("vault item still there: %v", err)
	}
	if es := dirEntries(t, dir); len(es) != 1 || es[0] != "keep.pub" {
		t.Fatalf("key folder = %q", es)
	}
	if _, err := r.Get("gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(gone) = %v", err)
	}
	if _, ok := r.ByBlob(gone.Blob); ok {
		t.Fatal("ByBlob found a deleted key")
	}
	if list, _ := r.List(); len(list) != 1 || list[0].Name != "keep" {
		t.Fatalf("List = %+v", list)
	}
	signAndVerify(t, r, keep, 0)

	// The name can be reused; it is a new key.
	again := mustCreate(t, r, "gone", platform.AuthNone)
	if bytes.Equal(again.Blob, gone.Blob) {
		t.Fatal("re-created key reuses the deleted key")
	}
	signAndVerify(t, r, again, 0)
}

func TestDeleteToleratesMissingPubAndWipedHandle(t *testing.T) {
	r, f, v, dir := newReg(t)
	mustCreate(t, r, "nopub", platform.AuthNone)
	mustCreate(t, r, "wiped", platform.AuthNone)
	if err := os.Remove(filepath.Join(dir, "nopub.pub")); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete("nopub"); err != nil {
		t.Fatalf("Delete with missing .pub: %v", err)
	}
	if err := f.Fake.DeleteKey(f.Handles()[1]); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete("wiped"); err != nil {
		t.Fatalf("Delete with wiped enclave handle: %v", err)
	}
	if names := vaultNames(t, v); len(names) != 0 {
		t.Fatalf("vault items left: %q", names)
	}
	if es := dirEntries(t, dir); len(es) != 0 {
		t.Fatalf("files left: %q", es)
	}
}

func TestDeleteUnknownTouchesNothing(t *testing.T) {
	r, f, _, dir := newReg(t)
	mustCreate(t, r, "github", platform.AuthNone)
	// A stray .pub without a key is not ours to delete through another name.
	if err := os.WriteFile(filepath.Join(dir, "stray.pub"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nope", "GITHUB", "GitHub", "github.pub", "github/", ""} {
		if err := r.Delete(name); err == nil {
			t.Errorf("Delete(%q) succeeded", name)
		}
	}
	if f.Live() != 1 {
		t.Fatalf("live = %d", f.Live())
	}
	if _, err := os.Stat(filepath.Join(dir, "github.pub")); err != nil {
		t.Fatalf("github.pub removed through another name: %v", err)
	}
	if info, err := r.Get("github"); err != nil || info.Broken {
		t.Fatalf("Get(github) = %+v, %v", info, err)
	}
}

// A name is a file name only after validation: Delete with a traversal name
// must never remove a file outside the key folder, even if the Vault holds
// an item under that name (corrupt or tampered Vault).
func TestDeleteNeverEscapesKeyFolder(t *testing.T) {
	for _, name := range []string{"../victim", "../../victim", "/tmp/victim", "sub/../../victim"} {
		r, _, v, dir := newReg(t)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		root := filepath.Dir(dir)
		victims := []string{
			filepath.Join(root, "victim.pub"),
			filepath.Join(filepath.Dir(root), "victim.pub"),
		}
		for _, p := range victims {
			if err := os.WriteFile(p, []byte("precious\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(p)
		}
		v.Put(VaultPrefix+name, []byte("{"))
		_ = r.Delete(name)
		for _, p := range victims {
			if b, err := os.ReadFile(p); err != nil || string(b) != "precious\n" {
				t.Errorf("Delete(%q) touched %s: %q, %v", name, p, b, err)
			}
		}
	}
}

// A symlink at keys/<name>.pub is removed, never its target.
func TestDeleteRemovesSymlinkNotTarget(t *testing.T) {
	r, _, _, dir := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	victim := filepath.Join(filepath.Dir(dir), "authorized_keys")
	if err := os.WriteFile(victim, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "k.pub")
	if err := os.Remove(pubPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, pubPath); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "precious\n" {
		t.Fatalf("symlink target touched: %q, %v", b, err)
	}
	if _, err := os.Lstat(pubPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("k.pub link still there: %v", err)
	}
}

// A Keychain item duplicated by a restore or migration still points at the
// original key's enclave handle. Deleting the duplicate (listed as broken:
// its record carries the other key's name) must not destroy that key.
func TestDeleteBrokenDuplicateKeepsTheOriginalKey(t *testing.T) {
	r, f, v, dir := newReg(t)
	good := mustCreate(t, r, "good", platform.AuthNone)
	raw, err := v.Vault.Get(VaultPrefix + "good")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(VaultPrefix+"copy", raw); err != nil {
		t.Fatal(err)
	}
	if list, _ := r.List(); len(list) != 2 || list[0].Name != "copy" || !list[0].Broken || list[1].Broken {
		t.Fatalf("List = %+v", list)
	}

	if err := r.Delete("copy"); err != nil {
		t.Fatalf("Delete(copy) = %v", err)
	}
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d after deleting the duplicate, want 1", f.Live())
	}
	if names := vaultNames(t, v); len(names) != 1 || names[0] != VaultPrefix+"good" {
		t.Fatalf("vault = %q", names)
	}
	if es := dirEntries(t, dir); len(es) != 1 || es[0] != "good.pub" {
		t.Fatalf("key folder = %q", es)
	}
	if info, err := r.Get("good"); err != nil || info.Broken || !bytes.Equal(info.Blob, good.Blob) {
		t.Fatalf("Get(good) = %+v, %v", info, err)
	}
	if k, ok := r.ByBlob(good.Blob); !ok || k.Name != "good" {
		t.Fatalf("ByBlob(good) = %+v, %v", k, ok)
	}
	signAndVerify(t, r, good, 0)

	// Once the last record is deleted the enclave key is freed.
	if err := r.Delete("good"); err != nil {
		t.Fatal(err)
	}
	if f.Live() != 0 {
		t.Fatalf("live enclave keys = %d after deleting the last record, want 0", f.Live())
	}
}

// Deleting one of two records that both decode cleanly and both point at
// one enclave handle keeps the key alive for the other; it is freed with
// the last record.
func TestDeleteSharedHandleIsFreedWithTheLastRecord(t *testing.T) {
	r, f, v, _ := newReg(t)
	a := mustCreate(t, r, "a", platform.AuthNone)
	rec := vaultRecord(t, v, "a")
	rec.Name = "b"
	if err := v.Put(VaultPrefix+"b", mustJSON(t, rec)); err != nil {
		t.Fatal(err)
	}
	if list, _ := r.List(); len(list) != 2 || list[0].Broken || list[1].Broken {
		t.Fatalf("List = %+v", list)
	}
	if err := r.Delete("b"); err != nil {
		t.Fatal(err)
	}
	if f.Live() != 1 {
		t.Fatalf("live = %d after Delete(b), want 1", f.Live())
	}
	signAndVerify(t, r, a, 0)
	if err := r.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if f.Live() != 0 {
		t.Fatalf("live = %d after Delete(a), want 0", f.Live())
	}
}

// A record that is broken but unmistakably this key's own (right name, a
// handle nobody else refers to) does free its enclave key on delete, so a
// corrupted record does not leave an orphaned Secure Enclave key behind.
func TestDeleteBrokenOwnRecordFreesItsEnclaveKey(t *testing.T) {
	corrupt := map[string]func(rec *record){
		"unknown auth":   func(rec *record) { rec.Auth = platform.AuthPolicy(7) },
		"bad public key": func(rec *record) { rec.PublicKey = []byte("not a key") },
		"no public key":  func(rec *record) { rec.PublicKey = nil },
		"wrong key type": func(rec *record) {
			edPub, _, _ := ed25519.GenerateKey(rand.Reader)
			edSSH, _ := ssh.NewPublicKey(edPub)
			rec.PublicKey = edSSH.Marshal()
		},
	}
	for name, mutate := range corrupt {
		t.Run(name, func(t *testing.T) {
			r, f, v, dir := newReg(t)
			other := mustCreate(t, r, "other", platform.AuthNone)
			mustCreate(t, r, "k", platform.AuthNone)
			rec := vaultRecord(t, v, "k")
			mutate(&rec)
			if err := v.Put(VaultPrefix+"k", mustJSON(t, rec)); err != nil {
				t.Fatal(err)
			}
			if info, err := r.Get("k"); err != nil || !info.Broken {
				t.Fatalf("Get(k) = %+v, %v; want Broken", info, err)
			}
			if f.Live() != 2 {
				t.Fatalf("live = %d before delete, want 2", f.Live())
			}
			if err := r.Delete("k"); err != nil {
				t.Fatalf("Delete(k) = %v", err)
			}
			if f.Live() != 1 {
				t.Fatalf("live = %d after Delete(k), want 1 (k's enclave key must be freed)", f.Live())
			}
			if names := vaultNames(t, v); len(names) != 1 || names[0] != VaultPrefix+"other" {
				t.Fatalf("vault = %q", names)
			}
			if es := dirEntries(t, dir); len(es) != 1 || es[0] != "other.pub" {
				t.Fatalf("key folder = %q", es)
			}
			signAndVerify(t, r, other, 0)
		})
	}
}

// Delete never guesses whether a handle is shared: if the Vault cannot be
// read while checking, nothing is deleted.
func TestDeleteBrokenRecordVaultReadFailureDeletesNothing(t *testing.T) {
	r, f, v, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	rec := vaultRecord(t, v, "k")
	rec.Auth = platform.AuthPolicy(7)
	if err := v.Put(VaultPrefix+"k", mustJSON(t, rec)); err != nil {
		t.Fatal(err)
	}
	v.FailList = errors.New("keychain locked")
	if err := r.Delete("k"); err == nil {
		t.Fatal("Delete hid a Vault failure")
	}
	v.FailList = nil
	if f.Live() != 1 {
		t.Fatalf("live = %d, want 1", f.Live())
	}
	if names := vaultNames(t, v); len(names) != 1 {
		t.Fatalf("vault = %q", names)
	}
}

func TestDeleteReportsVaultFailure(t *testing.T) {
	r, _, v, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	v.FailDelete = errors.New("keychain locked")
	if err := r.Delete("k"); err == nil {
		t.Fatal("Delete hid a Vault failure")
	}
}

// Spec 9: a key whose Keychain item cannot be read (errSecDecode, an ACL
// that no longer matches after re-signing, a migrated item) is listed as
// broken and fails to sign, and only that key degrades: the other keys are
// still listed, found by blob and sign, and the bad item can be deleted so
// the name is usable again. Deleting it frees no enclave key, since the
// handle is unknowable, so no other key's enclave key is at risk.
func TestOneUnreadableItemDegradesOnlyThatKey(t *testing.T) {
	r, f, v, dir := newReg(t)
	good := mustCreate(t, r, "good", platform.AuthNone)
	mustCreate(t, r, "bad", platform.AuthNone)
	v.FailGetOf = map[string]error{VaultPrefix + "bad": errors.New("errSecDecode")}

	list, err := r.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %+v, %v; want good and bad", list, err)
	}
	if list[0].Name != "bad" || !list[0].Broken || list[1].Name != "good" || list[1].Broken {
		t.Fatalf("List = %+v; want bad Broken, good usable", list)
	}
	if !bytes.Equal(list[1].Blob, good.Blob) {
		t.Fatalf("good's listed blob changed")
	}
	if info, err := r.Get("bad"); err != nil || !info.Broken || info.Name != "bad" {
		t.Fatalf("Get(bad) = %+v, %v; want Broken", info, err)
	}
	if _, err := r.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(nope) = %v, want ErrNotFound", err)
	}
	if got, ok := r.ByBlob(good.Blob); !ok || got.Name != "good" {
		t.Fatalf("ByBlob(good) = %+v, %v", got, ok)
	}
	if _, err := r.Sign("bad", []byte("d"), 0); err == nil {
		t.Fatal("unreadable key signed")
	}
	signAndVerify(t, r, good, 0)
	if _, err := r.Create("bad", platform.AuthNone, platform.AccessWhenUnlocked); err == nil {
		t.Fatal("Create reused a name whose item is unreadable")
	}
	if f.Live() != 2 {
		t.Fatalf("live = %d, want 2", f.Live())
	}

	if err := r.Delete("bad"); err != nil {
		t.Fatalf("Delete(bad) = %v", err)
	}
	if f.Live() != 2 {
		t.Fatalf("live = %d after Delete(bad), want 2 (no handle was readable, so none may be freed)", f.Live())
	}
	if names := vaultNames(t, v); len(names) != 1 || names[0] != VaultPrefix+"good" {
		t.Fatalf("vault = %q, want only good", names)
	}
	if es := dirEntries(t, dir); len(es) != 1 || es[0] != "good.pub" {
		t.Fatalf("key folder = %q, want only good.pub", es)
	}
	if list, err := r.List(); err != nil || len(list) != 1 || list[0].Name != "good" || list[0].Broken {
		t.Fatalf("List = %+v, %v after Delete(bad)", list, err)
	}
	signAndVerify(t, r, good, 0)
	v.FailGetOf = nil // the item is gone; a real Vault now reports not found
	if err := r.Delete("bad"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete(bad) = %v, want ErrNotFound", err)
	}
	again := mustCreate(t, r, "bad", platform.AuthNone)
	signAndVerify(t, r, again, 0)
}

// Deleting an unreadable item whose Vault delete also fails reports that,
// and still touches no enclave key.
func TestDeleteUnreadableItemReportsVaultDeleteFailure(t *testing.T) {
	r, f, v, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	v.FailGetOf = map[string]error{VaultPrefix + "k": errors.New("errSecInteractionNotAllowed")}
	v.FailDelete = errors.New("errSecInteractionNotAllowed")
	if err := r.Delete("k"); err == nil {
		t.Fatal("Delete hid a Vault failure")
	}
	if f.Live() != 1 {
		t.Fatalf("live = %d, want 1", f.Live())
	}
	if names := vaultNames(t, v); len(names) != 1 {
		t.Fatalf("vault = %q", names)
	}
}

// Delete checks every other record before freeing a handle, and fails
// closed when one of them cannot be read: it could be the record that
// shares the handle. Setup: key a; a stray record b carrying a's handle;
// only a's item unreadable. Delete(b) must error, free nothing and leave b
// in the Vault; a keeps working. (Changing handleShared's Get-error branch
// to `continue` would make this test destroy a.)
func TestDeleteFailsClosedWhenAnotherRecordIsUnreadable(t *testing.T) {
	r, f, v, dir := newReg(t)
	a := mustCreate(t, r, "a", platform.AuthNone)
	rec := vaultRecord(t, v, "a")
	rec.Name = "b"
	if err := v.Put(VaultPrefix+"b", mustJSON(t, rec)); err != nil {
		t.Fatal(err)
	}
	v.FailGetOf = map[string]error{VaultPrefix + "a": errors.New("errSecInteractionNotAllowed")}

	err := r.Delete("b")
	if err == nil {
		t.Fatal("Delete(b) succeeded while a's record was unreadable")
	}
	if !strings.Contains(err.Error(), VaultPrefix+"a") {
		t.Errorf("Delete(b) = %v; want the unreadable item named", err)
	}
	if f.Live() != 1 {
		t.Fatalf("live = %d after Delete(b), want 1 (a's enclave key must survive)", f.Live())
	}
	names := vaultNames(t, v)
	if len(names) != 2 || names[0] != VaultPrefix+"a" || names[1] != VaultPrefix+"b" {
		t.Fatalf("vault = %q, want a and b untouched", names)
	}
	if es := dirEntries(t, dir); len(es) != 1 || es[0] != "a.pub" {
		t.Fatalf("key folder = %q", es)
	}

	v.FailGetOf = nil
	signAndVerify(t, r, a, 0)
	if err := r.Delete("b"); err != nil {
		t.Fatalf("Delete(b) once readable = %v", err)
	}
	if f.Live() != 1 {
		t.Fatalf("live = %d, want 1", f.Live())
	}
	signAndVerify(t, r, a, 0)
}

func TestDeleteReportsEnclaveFailure(t *testing.T) {
	r, f, _, _ := newReg(t)
	mustCreate(t, r, "k", platform.AuthNone)
	f.deleteErr = errors.New("enclave busy")
	if err := r.Delete("k"); err == nil {
		t.Fatal("Delete hid an enclave failure")
	}
}

// -------------------------------------------------------------- concurrency

// Racing creates of one name produce exactly one key and no orphaned
// enclave keys; distinct names, lists, lookups and signs run concurrently.
func TestConcurrentUse(t *testing.T) {
	r, f, _, dir := newReg(t)
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins, exists := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Create("same", platform.AuthNone, platform.AccessWhenUnlocked)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrExists):
				exists++
			default:
				t.Errorf("Create(same): %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || exists != n-1 {
		t.Fatalf("wins=%d exists=%d", wins, exists)
	}
	if f.Live() != 1 {
		t.Fatalf("live enclave keys = %d, want 1", f.Live())
	}
	same, err := r.Get("same")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "same.pub")); string(b) != same.AuthorizedKey+"\n" {
		t.Fatalf("same.pub = %q does not match the surviving key", b)
	}

	for i := 0; i < n; i++ {
		wg.Add(3)
		name := fmt.Sprintf("k%02d", i)
		go func() {
			defer wg.Done()
			info, err := r.Create(name, platform.AuthNone, platform.AccessWhenUnlocked)
			if err != nil {
				t.Errorf("Create(%s): %v", name, err)
				return
			}
			if _, err := r.Sign(name, []byte(name), 0); err != nil {
				t.Errorf("Sign(%s): %v", name, err)
			}
			if k, ok := r.ByBlob(info.Blob); !ok || k.Name != name {
				t.Errorf("ByBlob(%s) = %+v, %v", name, k, ok)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := r.List(); err != nil {
				t.Errorf("List: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := r.Sign("same", []byte("x"), 0); err != nil {
				t.Errorf("Sign(same): %v", err)
			}
		}()
	}
	wg.Wait()
	list, _ := r.List()
	if len(list) != n+1 || f.Live() != n+1 {
		t.Fatalf("list=%d live=%d, want %d", len(list), f.Live(), n+1)
	}
	if es := dirEntries(t, dir); len(es) != n+1 {
		t.Fatalf("key folder holds %d files, want %d: %q", len(es), n+1, es)
	}
}
