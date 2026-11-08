package secrets

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/seal"
)

var t0 = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)

// spyPlatform is the fake platform with the calls the store makes written to
// a trace it shares with spyVault (so tests can check their order), and with
// the failures a broken platform layer could produce.
type spyPlatform struct {
	*fake.Fake
	trace     *[]string
	creates   []string                // "<purpose>/<auth>" of every CreateKey
	handles   [][]byte                // every handle CreateKey returned
	pubFunc   func(pub []byte) []byte // rewrites the public key CreateKey returns
	deleteErr error                   // DeleteKey fails with this
}

func (s *spyPlatform) CreateKey(p platform.Purpose, a platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	*s.trace = append(*s.trace, "CreateKey")
	s.creates = append(s.creates, p.String()+"/"+a.String())
	h, pub, err := s.Fake.CreateKey(p, a, access)
	if err != nil {
		return nil, nil, err
	}
	s.handles = append(s.handles, h)
	if s.pubFunc != nil {
		pub = s.pubFunc(pub)
	}
	return h, pub, nil
}

func (s *spyPlatform) DeleteKey(h []byte) error {
	*s.trace = append(*s.trace, "DeleteKey")
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.Fake.DeleteKey(h)
}

type spyVault struct {
	*fake.Vault
	trace      *[]string
	FailGetOf  map[string]error // Get of these names (with prefix) fails; the rest work
	FailDelete error
}

func (v *spyVault) Get(name string) ([]byte, error) {
	if err := v.FailGetOf[name]; err != nil {
		return nil, err
	}
	return v.Vault.Get(name)
}

func (v *spyVault) Put(name string, b []byte) error {
	*v.trace = append(*v.trace, "Put "+name)
	return v.Vault.Put(name, b)
}

func (v *spyVault) Delete(name string) error {
	*v.trace = append(*v.trace, "Delete "+name)
	if v.FailDelete != nil {
		return v.FailDelete
	}
	return v.Vault.Delete(name)
}

func newStore(t *testing.T) (*Store, *spyPlatform, *spyVault) {
	t.Helper()
	trace := &[]string{}
	f := fake.New(t0)
	p := &spyPlatform{Fake: f, trace: trace}
	v := &spyVault{Vault: fake.NewVault(), trace: trace}
	return NewStore(p, v, f.Now), p, v
}

func mustAdd(t *testing.T, s *Store, name, value string) Info {
	t.Helper()
	info, err := s.Add(name, []byte(value), platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatalf("Add(%q): %v", name, err)
	}
	return info
}

func mustOpen(t *testing.T, s *Store, name string) string {
	t.Helper()
	v, err := s.Open(name, 0)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	return string(v)
}

// alive reports whether the enclave still knows handle.
func alive(t *testing.T, p platform.Platform, h []byte) bool {
	t.Helper()
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.KeyAgreement(h, peer.PublicKey().Bytes(), 0)
	if err != nil && !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("KeyAgreement: %v", err)
	}
	return err == nil
}

func record0(t *testing.T, v *spyVault, name string) record {
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

func TestAddSealsToANewKeyAndOpens(t *testing.T) {
	s, p, v := newStore(t)
	const value = "ghp_secret_value_123"
	info := mustAdd(t, s, "GITHUB_PERSONAL_ACCESS_TOKEN", value)
	if info.Name != "GITHUB_PERSONAL_ACCESS_TOKEN" || info.Auth != platform.AuthNone || !info.Created.Equal(t0) || info.Broken {
		t.Fatalf("Info = %+v", info)
	}
	// Slice 1: a key-agreement key, never Secure Enclave user presence (3.5).
	if len(p.creates) != 1 || p.creates[0] != "key-agreement/none" {
		t.Fatalf("CreateKey calls = %v, want [key-agreement/none]", p.creates)
	}
	if got := mustOpen(t, s, "GITHUB_PERSONAL_ACCESS_TOKEN"); got != value {
		t.Fatal("Open did not return the value that was added")
	}
	item, err := v.Vault.Get("secret/GITHUB_PERSONAL_ACCESS_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{value, base64.StdEncoding.EncodeToString([]byte(value)), "ghp_"} {
		if bytes.Contains(item, []byte(leak)) {
			t.Fatal("the Vault record holds the value in the clear")
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"version", "name", "handle", "publicKey", "auth", "created", "enc", "sealed"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("record has no %q", k)
		}
	}
	if len(fields) != 8 || string(fields["version"]) != "1" {
		t.Fatalf("record fields = %d, version %s; want exactly the 8 of secrets design 3.1, version 1", len(fields), fields["version"])
	}
}

func TestNamesAreValidatedBeforeAnyKeyIsMade(t *testing.T) {
	s, p, _ := newStore(t)
	mustAdd(t, s, "k8s/hydra", "kubeconfig")
	if got := mustOpen(t, s, "k8s/hydra"); got != "kubeconfig" {
		t.Fatal("k8s/hydra did not round-trip")
	}
	for _, n := range []string{"", "-x", "a/../b", "x\n", "a b"} {
		if _, err := s.Add(n, []byte("v"), platform.AccessWhenUnlocked); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Add(%q) = %v, want ErrInvalidName", n, err)
		}
		if _, err := s.Open(n, 0); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Open(%q) = %v, want ErrInvalidName", n, err)
		}
	}
	if len(p.creates) != 1 {
		t.Fatalf("a refused name made an enclave key: %v", p.creates)
	}
}

func TestAddRefusesTakenNames(t *testing.T) {
	s, p, _ := newStore(t)
	mustAdd(t, s, "GH_TOKEN", "one")
	for _, n := range []string{"GH_TOKEN", "gh_token", "Gh_Token"} {
		if _, err := s.Add(n, []byte("two"), platform.AccessWhenUnlocked); !errors.Is(err, ErrExists) {
			t.Errorf("Add(%q) = %v, want ErrExists", n, err)
		}
	}
	if len(p.creates) != 1 {
		t.Fatalf("a refused add made an enclave key: %v", p.creates)
	}
	if mustOpen(t, s, "GH_TOKEN") != "one" {
		t.Fatal("a refused add changed the stored value")
	}
}

func TestAddRefusesWhenTheVaultCannotBeRead(t *testing.T) {
	s, p, v := newStore(t)
	v.FailGetOf = map[string]error{"secret/GH": errors.New("errSecInteractionNotAllowed")}
	if _, err := s.Add("GH", []byte("v"), platform.AccessWhenUnlocked); err == nil || errors.Is(err, ErrExists) {
		t.Fatalf("Add with an unreadable Vault = %v, want a read error", err)
	}
	if len(p.creates) != 0 {
		t.Fatal("Add guessed the name was free and made a key")
	}
}

func TestValueLimits(t *testing.T) {
	s, p, v := newStore(t)
	if _, err := s.Add("E", nil, platform.AccessWhenUnlocked); !errors.Is(err, seal.ErrEmpty) {
		t.Fatalf("Add(empty) = %v, want seal.ErrEmpty", err)
	}
	if _, err := s.Add("E", make([]byte, seal.MaxValue+1), platform.AccessWhenUnlocked); !errors.Is(err, seal.ErrTooLarge) {
		t.Fatalf("Add(MaxValue+1) = %v, want seal.ErrTooLarge", err)
	}
	if len(p.creates) != 0 {
		t.Fatal("a key was made for a value that cannot be stored")
	}
	big := bytes.Repeat([]byte{0xa5}, seal.MaxValue)
	if _, err := s.Add("BIG", big, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	item, err := v.Vault.Get("secret/BIG")
	if err != nil {
		t.Fatal(err)
	}
	// A Keychain item round-trips up to 64 KiB in KeychainVaultTests; leave
	// room for the largest handle the Swift platform makes (KeyHandle: a
	// 6-byte prefix and at most 4096 bytes of Secure Enclave blob).
	if n := len(item) + base64.StdEncoding.EncodedLen(6+4096); n > 64<<10 {
		t.Fatalf("the largest record would be %d bytes, over 64 KiB", n)
	}
	if got, err := s.Open("BIG", 0); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("a MaxValue secret did not round-trip: %v", err)
	}
}

func TestAddLeavesNothingBehindOnFailure(t *testing.T) {
	other, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(p *spyPlatform, v *spyVault){
		"the vault write fails": func(p *spyPlatform, v *spyVault) { v.FailPut = errors.New("keychain locked") },
		"the public key is another key's": func(p *spyPlatform, v *spyVault) {
			p.pubFunc = func([]byte) []byte { return other.PublicKey().Bytes() }
		},
		"the public key is not a point": func(p *spyPlatform, v *spyVault) { p.pubFunc = func([]byte) []byte { return []byte{4, 1, 2} } },
	} {
		t.Run(name, func(t *testing.T) {
			s, p, v := newStore(t)
			setup(p, v)
			if _, err := s.Add("GH", []byte("v"), platform.AccessWhenUnlocked); err == nil {
				t.Fatal("Add succeeded; the value would be lost for good")
			}
			if len(p.handles) != 1 || alive(t, p, p.handles[0]) {
				t.Fatal("the enclave key of a failed Add must be deleted")
			}
			if _, err := v.Vault.Get("secret/GH"); !errors.Is(err, platform.ErrNotFound) {
				t.Fatalf("a failed Add left a record: %v", err)
			}
		})
	}
}

func TestReplaceReSealsToTheSameKey(t *testing.T) {
	s, p, v := newStore(t)
	mustAdd(t, s, "GH", "old")
	before := record0(t, v, "GH")
	if _, err := s.Replace("GH", []byte("new")); err != nil {
		t.Fatal(err)
	}
	after := record0(t, v, "GH")
	if !bytes.Equal(after.Handle, before.Handle) || !bytes.Equal(after.PublicKey, before.PublicKey) || !after.Created.Equal(before.Created) {
		t.Fatal("Replace must keep the key and the creation time")
	}
	if bytes.Equal(after.Enc, before.Enc) || bytes.Equal(after.Sealed, before.Sealed) {
		t.Fatal("Replace must seal afresh")
	}
	if len(p.creates) != 1 {
		t.Fatalf("Replace made a key: %v", p.creates)
	}
	if mustOpen(t, s, "GH") != "new" {
		t.Fatal("Replace did not store the new value")
	}
	if _, err := s.Replace("NOPE", []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Replace(missing) = %v, want ErrNotFound", err)
	}
	if _, err := s.Replace("GH", nil); !errors.Is(err, seal.ErrEmpty) {
		t.Fatalf("Replace(empty) = %v, want seal.ErrEmpty", err)
	}
}

func TestReplaceRefusesADeadKey(t *testing.T) {
	s, p, v := newStore(t)
	mustAdd(t, s, "GH", "old")
	before, _ := v.Vault.Get("secret/GH")
	if err := p.Fake.DeleteKey(p.handles[0]); err != nil { // the handle died (a wiped enclave, another Mac)
		t.Fatal(err)
	}
	if _, err := s.Replace("GH", []byte("new")); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("Replace onto a dead key = %v, want platform.ErrNotFound", err)
	}
	if after, _ := v.Vault.Get("secret/GH"); !bytes.Equal(after, before) {
		t.Fatal("a refused Replace changed the record")
	}
}

func TestARecordOpensOnlyUnderItsOwnName(t *testing.T) {
	s, _, v := newStore(t)
	mustAdd(t, s, "A", "value-a")
	item, _ := v.Vault.Get("secret/A")
	v.Vault.Put("secret/B", item) // copied as is: the record says it is A's
	if info, err := s.Get("B"); err != nil || !info.Broken || !strings.Contains(info.Problem, "name") {
		t.Fatalf("Get(B) = %+v, %v; want broken (record name)", info, err)
	}
	if _, err := s.Open("B", 0); !errors.Is(err, ErrBroken) {
		t.Fatalf("Open(B) = %v, want ErrBroken", err)
	}
	rec := record0(t, v, "A")
	rec.Name = "C" // copied with its name rewritten: the seal is bound to A
	b, _ := json.Marshal(rec)
	v.Vault.Put("secret/C", b)
	if _, err := s.Open("C", 0); !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("Open(C) = %v, want seal.ErrOpen", err)
	}
}

func TestBrokenAndUnreadableRecords(t *testing.T) {
	s, _, v := newStore(t)
	mustAdd(t, s, "GOOD", "v")
	mustAdd(t, s, "LOCKED", "v")
	v.FailGetOf = map[string]error{"secret/LOCKED": errors.New("vault get failed (status -25308)")}
	v.Vault.Put("secret/CORRUPT", []byte("{not json"))
	future := record0(t, v, "GOOD")
	future.Version, future.Name = 2, "FUTURE"
	b, _ := json.Marshal(future)
	v.Vault.Put("secret/FUTURE", b)
	odd := record0(t, v, "GOOD")
	odd.Name, odd.Auth = "ODDAUTH", 7
	b, _ = json.Marshal(odd)
	v.Vault.Put("secret/ODDAUTH", b)
	v.Vault.Put("secret/bad name", []byte("{}")) // any same-user process can add one
	v.Vault.Put("ssh-key/github", []byte("{}"))  // not a secret at all

	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		broken, unreadable bool
		problem            string
	}
	wants := []struct {
		name string
		want
	}{
		{"CORRUPT", want{true, false, "CORRUPT"}},
		{"FUTURE", want{true, false, "version 2"}},
		{"GOOD", want{false, false, ""}},
		{"LOCKED", want{true, true, "-25308"}},
		{"ODDAUTH", want{true, false, "auth"}},
		{"bad name", want{true, false, "invalid secret name"}},
	}
	if len(list) != len(wants) {
		t.Fatalf("List = %+v, want %d entries", list, len(wants))
	}
	for i, w := range wants {
		got := list[i]
		if got.Name != w.name || got.Broken != w.broken || got.Unreadable != w.unreadable ||
			(w.problem == "") != (got.Problem == "") || !strings.Contains(got.Problem, w.problem) {
			t.Errorf("List[%d] = %+v, want %s %+v", i, got, w.name, w.want)
		}
	}
	if mustOpen(t, s, "GOOD") != "v" {
		t.Fatal("a good secret stopped opening beside broken ones")
	}
	for name, want := range map[string]error{
		"LOCKED": ErrUnreadable, "CORRUPT": ErrBroken, "FUTURE": ErrBroken, "ODDAUTH": ErrBroken,
		"bad name": ErrInvalidName, "MISSING": ErrNotFound,
	} {
		if got, err := s.Open(name, 0); !errors.Is(err, want) || got != nil {
			t.Errorf("Open(%q) = %v, want %v", name, err, want)
		}
	}
}

func TestDeleteErasesTheKeyThenTheRecord(t *testing.T) {
	s, p, v := newStore(t)
	mustAdd(t, s, "GH", "v")
	h := p.handles[0]
	*p.trace = nil
	if err := s.Delete("GH"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*p.trace, ","); got != "DeleteKey,Delete secret/GH" {
		t.Fatalf("Delete calls = %s; want the key first, then the record", got)
	}
	if alive(t, p, h) {
		t.Fatal("the enclave key survived Delete")
	}
	if _, err := v.Vault.Get("secret/GH"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("the record survived Delete: %v", err)
	}
	if _, err := s.Open("GH", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open after Delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete("GH"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete = %v, want ErrNotFound", err)
	}
	mustAdd(t, s, "GH", "v2") // the name is free again
}

func TestDeleteStopsWhenTheEnclaveRefuses(t *testing.T) {
	s, p, v := newStore(t)
	mustAdd(t, s, "GH", "v")
	p.deleteErr = errors.New("enclave busy")
	if err := s.Delete("GH"); err == nil {
		t.Fatal("Delete succeeded although DeleteKey failed")
	}
	if _, err := v.Vault.Get("secret/GH"); err != nil {
		t.Fatalf("the record must be untouched when DeleteKey fails: %v", err)
	}
	if mustOpen(t, s, "GH") != "v" {
		t.Fatal("the secret must still open")
	}
}

func TestDeleteFinishesAfterAHalfDoneDelete(t *testing.T) {
	s, _, v := newStore(t)
	mustAdd(t, s, "GH", "v")
	v.FailDelete = errors.New("keychain write failed")
	if err := s.Delete("GH"); err == nil {
		t.Fatal("Delete succeeded although the Vault refused")
	}
	// Key gone, record kept: the secret is unusable, never a live key
	// without its record.
	if _, err := s.Open("GH", 0); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("Open after a half-done Delete = %v, want platform.ErrNotFound", err)
	}
	v.FailDelete = nil
	if err := s.Delete("GH"); err != nil {
		t.Fatalf("the second Delete must finish the job: %v", err)
	}
	if _, err := s.Get("GH"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after the second Delete = %v, want ErrNotFound", err)
	}
}

func TestDeleteKeepsAKeyAnotherRecordUses(t *testing.T) {
	s, p, v := newStore(t)
	mustAdd(t, s, "A", "v")
	rec := record0(t, v, "A")
	rec.Name = "B" // a duplicated item (a restore) under another name
	b, _ := json.Marshal(rec)
	v.Vault.Put("secret/B", b)
	*p.trace = nil
	if err := s.Delete("B"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(*p.trace, ","), "DeleteKey") {
		t.Fatal("deleting B destroyed the key A still uses")
	}
	if mustOpen(t, s, "A") != "v" {
		t.Fatal("A stopped opening")
	}
}

func TestDeleteNeverTouchesAnUnreadableRecord(t *testing.T) {
	s, p, v := newStore(t)
	mustAdd(t, s, "GH", "v")
	v.FailGetOf = map[string]error{"secret/GH": errors.New("errSecInteractionNotAllowed")}
	*p.trace = nil
	if err := s.Delete("GH"); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Delete of an unreadable record = %v, want ErrUnreadable", err)
	}
	if len(*p.trace) != 0 {
		t.Fatalf("an unreadable record (a locked keychain reads the same as a lost one) must never be deleted: %v", *p.trace)
	}
	v.FailGetOf = nil
	if mustOpen(t, s, "GH") != "v" {
		t.Fatal("the secret must still open")
	}
}

func TestDeleteRemovesACorruptRecord(t *testing.T) {
	s, _, v := newStore(t)
	v.Vault.Put("secret/BAD", []byte("{not json"))
	if err := s.Delete("BAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("BAD"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

// A secret's key Access is kept in its record and shown in its info; a
// record written before Access existed is a when-unlocked secret; an
// access value nazar never writes makes the record broken; an unknown
// access is refused before any key is made.
func TestAddKeepsAccess(t *testing.T) {
	s, p, v := newStore(t)
	if info, err := s.Add("BOT", []byte("v"), platform.AccessAfterFirstUnlock); err != nil || info.Access != platform.AccessAfterFirstUnlock {
		t.Fatalf("Add(BOT) = %+v, %v", info, err)
	}
	mustAdd(t, s, "GH", "v")
	for name, want := range map[string]platform.Access{"BOT": platform.AccessAfterFirstUnlock, "GH": platform.AccessWhenUnlocked} {
		if got, err := s.Get(name); err != nil || got.Broken || got.Access != want {
			t.Fatalf("Get(%s) = %+v, %v; want access %v", name, got, err, want)
		}
	}
	raw, _ := v.Get(VaultPrefix + "GH")
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["access"]; ok {
		t.Fatal("a when-unlocked record carries an access field")
	}
	m["access"] = 4
	raw, _ = json.Marshal(m)
	if err := v.Put(VaultPrefix+"GH", raw); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get("GH"); err != nil || !got.Broken {
		t.Fatalf("Get(GH) with access 4 = %+v, %v; want broken", got, err)
	}
	before := len(p.creates)
	if _, err := s.Add("ODD", []byte("v"), platform.Access(2)); err == nil || len(p.creates) != before {
		t.Fatalf("unknown access: %v, %d keys made", err, len(p.creates)-before)
	}
}

// Opening a when-unlocked secret while the Mac is locked fails with an
// error that says so, by the secret's name; an after-first-unlock secret
// opens.
func TestOpenWhileLockedSaysSo(t *testing.T) {
	s, p, _ := newStore(t)
	mustAdd(t, s, "GH", "v")
	if _, err := s.Add("BOT", []byte("w"), platform.AccessAfterFirstUnlock); err != nil {
		t.Fatal(err)
	}
	p.SetLocked(true)
	_, err := s.Open("GH", 0)
	if !errors.Is(err, platform.ErrLocked) || err.Error() != "secrets: the Mac is locked; GH opens only while it's unlocked" {
		t.Fatalf("Open while locked = %v", err)
	}
	if v, err := s.Open("BOT", 0); err != nil || string(v) != "w" {
		t.Fatalf("after-first-unlock secret while locked = %q, %v", v, err)
	}
}
