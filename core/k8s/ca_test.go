package k8s

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// K8s design 6.1: one Secure Enclave CA key per context, its
// handle and its self-signed CA certificate kept together in the Vault item
// k8s-ca/<name>, which only nazar-agent can write.

var t0 = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)

// spyVault is a fake vault whose Get can fail per item (a locked keychain,
// another build's item) and which counts writes.
type spyVault struct {
	*fake.Vault
	mu        sync.Mutex
	FailGetOf map[string]error
	deletes   []string
}

func (v *spyVault) Get(name string) ([]byte, error) {
	v.mu.Lock()
	err := v.FailGetOf[name]
	v.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return v.Vault.Get(name)
}

func (v *spyVault) Delete(name string) error {
	v.mu.Lock()
	v.deletes = append(v.deletes, name)
	v.mu.Unlock()
	return v.Vault.Delete(name)
}

// spyPlatform records what reaches the enclave and can misbehave.
type spyPlatform struct {
	*fake.Fake
	mu        sync.Mutex
	refs      []platform.ApprovalRef
	signed    [][]byte
	deleted   [][]byte
	wrongPub  bool // CreateKey returns another key's public key
	wrongSig  bool // Sign signs with another key
	otherPriv *ecdsa.PrivateKey
}

func newSpy(t *testing.T) *spyPlatform {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &spyPlatform{Fake: fake.New(t0), otherPriv: k}
}

func (p *spyPlatform) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	h, pub, err := p.Fake.CreateKey(purpose, auth, access)
	if err == nil && p.wrongPub {
		pub, _ = p.otherPriv.PublicKey.Bytes()
	}
	return h, pub, err
}

func (p *spyPlatform) Sign(handle, data []byte, ref platform.ApprovalRef) ([]byte, error) {
	p.mu.Lock()
	p.refs = append(p.refs, ref)
	p.signed = append(p.signed, append([]byte(nil), data...))
	bad := p.wrongSig
	p.mu.Unlock()
	if bad {
		sum := sha256.Sum256(data)
		return ecdsa.SignASN1(rand.Reader, p.otherPriv, sum[:])
	}
	return p.Fake.Sign(handle, data, ref)
}

func (p *spyPlatform) DeleteKey(handle []byte) error {
	p.mu.Lock()
	p.deleted = append(p.deleted, append([]byte(nil), handle...))
	p.mu.Unlock()
	return p.Fake.DeleteKey(handle)
}

func newStore(t *testing.T) (*CAStore, *spyPlatform, *spyVault) {
	t.Helper()
	p := newSpy(t)
	v := &spyVault{Vault: fake.NewVault()}
	return NewCAStore(p, v, func() time.Time { return t0 }), p, v
}

func TestCAStoreCreateGetDelete(t *testing.T) {
	s, p, v := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Cert
	if c.Subject.CommonName != "nazar k8s CA hydra" || !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero ||
		c.KeyUsage != x509.KeyUsageCertSign || len(c.ExtKeyUsage) != 0 || len(c.SubjectKeyId) == 0 {
		t.Fatalf("CA profile: %+v", c)
	}
	if !c.NotBefore.Equal(t0.Add(-time.Minute)) || !c.NotAfter.Equal(t0.AddDate(10, 0, 0)) {
		t.Fatalf("validity %v – %v", c.NotBefore, c.NotAfter)
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Fatalf("self-signed through the platform: %v", err)
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if raw, _ := pub.Bytes(); !ok || !bytes.Equal(raw, ca.PublicKey) {
		t.Fatal("the certificate's key is the enclave key")
	}
	if c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() < 100 {
		t.Fatalf("serial %v", c.SerialNumber)
	}
	// The PEM is the certificate.
	b, _ := pem.Decode(ca.CertPEM())
	if b == nil || b.Type != "CERTIFICATE" || !bytes.Equal(b.Bytes, c.Raw) {
		t.Fatal("CertPEM")
	}
	if names, _ := v.List(VaultPrefix); len(names) != 1 || names[0] != "k8s-ca/hydra" {
		t.Fatalf("vault %v", names)
	}
	got, err := s.Get("hydra")
	if err != nil || !bytes.Equal(got.Cert.Raw, c.Raw) || !bytes.Equal(got.Handle, ca.Handle) {
		t.Fatalf("get: %v", err)
	}
	list, err := s.List()
	sum := sha256.Sum256(c.Raw)
	if err != nil || len(list) != 1 || list[0].Name != "hydra" || list[0].Broken || list[0].Fingerprint != hex.EncodeToString(sum[:]) || !list[0].Created.Equal(t0) {
		t.Fatalf("list %+v %v", list, err)
	}
	for _, again := range []string{"hydra", "HYDRA"} {
		if _, err := s.Create(again, platform.AccessWhenUnlocked); !errors.Is(err, ErrExists) {
			t.Fatalf("create %s again: %v", again, err)
		}
	}
	if _, err := s.Create("a/b", platform.AccessWhenUnlocked); err == nil {
		t.Fatal("an invalid name must be refused")
	}
	if err := s.Delete("hydra"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("hydra"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if _, err := p.Fake.Sign(ca.Handle, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("the enclave key must be gone: %v", err)
	}
	if err := s.Delete("hydra"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second delete: %v", err)
	}
}

func TestCAStoreCreateRollsBack(t *testing.T) {
	s, p, v := newStore(t)
	v.FailPut = errors.New("the keychain is locked")
	if _, err := s.Create("hydra", platform.AccessWhenUnlocked); err == nil {
		t.Fatal("a failed vault write must fail the create")
	}
	if len(p.deleted) != 1 {
		t.Fatalf("the new key must be deleted: %d deletes", len(p.deleted))
	}
	v.FailPut = nil
	p.wrongPub = true
	if _, err := s.Create("hydra", platform.AccessWhenUnlocked); err == nil {
		t.Fatal("a platform whose public key is not its handle's must fail the create")
	}
	if len(p.deleted) != 2 {
		t.Fatalf("the new key must be deleted: %d deletes", len(p.deleted))
	}
	if names, _ := v.List(VaultPrefix); len(names) != 0 {
		t.Fatalf("nothing stored: %v", names)
	}
	p.wrongPub = false
	if _, err := s.Create("hydra", platform.AccessWhenUnlocked); err != nil {
		t.Fatalf("the name stays free: %v", err)
	}
}

func record(t *testing.T, v *spyVault, item string) map[string]any {
	t.Helper()
	b, err := v.Vault.Get(item)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func put(t *testing.T, v *spyVault, item string, m map[string]any) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Vault.Put(item, b); err != nil {
		t.Fatal(err)
	}
}

func TestCAStoreBrokenAndUnreadableRecords(t *testing.T) {
	s, p, v := newStore(t)
	hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.Create("other", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	m := record(t, v, "k8s-ca/hydra")
	// Copied as is to another name: the name inside says hydra.
	put(t, v, "k8s-ca/copy", m)
	// Its certificate swapped for another CA's (key mismatch).
	swapped := record(t, v, "k8s-ca/hydra")
	swapped["name"] = "swapped"
	swapped["certDER"] = record(t, v, "k8s-ca/other")["certDER"]
	put(t, v, "k8s-ca/swapped", swapped)
	// A future format, and junk.
	future := record(t, v, "k8s-ca/hydra")
	future["name"], future["version"] = "future", 2
	put(t, v, "k8s-ca/future", future)
	if err := v.Vault.Put("k8s-ca/junk", []byte("{")); err != nil {
		t.Fatal(err)
	}
	// A leaf certificate (not a CA) with the right key.
	leaf := record(t, v, "k8s-ca/hydra")
	leaf["name"] = "leaf"
	leafCred, err := hydra.Issue(p, identity("x"), 15*time.Minute, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := pem.Decode(leafCred.CertPEM)
	leaf["certDER"] = lb.Bytes
	put(t, v, "k8s-ca/leaf", leaf)
	for _, name := range []string{"copy", "swapped", "future", "junk", "leaf"} {
		if _, err := s.Get(name); !errors.Is(err, ErrBroken) {
			t.Errorf("%s: want ErrBroken, got %v", name, err)
		}
	}
	// Unreadable: the vault refuses the item.
	v.FailGetOf = map[string]error{"k8s-ca/other": errors.New("errSecInteractionNotAllowed")}
	if _, err := s.Get("other"); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("unreadable: %v", err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, i := range list {
		switch {
		case i.Unreadable:
			states[i.Name] = "unreadable"
		case i.Broken:
			states[i.Name] = "broken"
		default:
			states[i.Name] = "ok"
		}
		if i.Problem != "" && strings.Contains(i.Problem, "PRIVATE") {
			t.Fatal("problem text")
		}
	}
	want := map[string]string{"hydra": "ok", "other": "unreadable", "copy": "broken", "swapped": "broken", "future": "broken", "junk": "broken", "leaf": "broken"}
	for n, st := range want {
		if states[n] != st {
			t.Errorf("%s: %s, want %s (%v)", n, states[n], st, states)
		}
	}
	// An unreadable record is never deleted: nothing reaches the platform or the vault.
	nd, nv := len(p.deleted), len(v.deletes)
	if err := s.Delete("other"); !errors.Is(err, ErrUnreadable) || len(p.deleted) != nd || len(v.deletes) != nv {
		t.Fatalf("delete of unreadable: %v (%d key deletes, %d vault deletes)", err, len(p.deleted)-nd, len(v.deletes)-nv)
	}
	v.FailGetOf = nil
	_ = other
	// A broken record that names another handle in use (the copy) is
	// removed without destroying hydra's key.
	if err := s.Delete("copy"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("hydra"); err != nil {
		t.Fatalf("hydra must survive the copy's delete: %v", err)
	}
	if _, err := hydra.Issue(p, identity("x"), 15*time.Minute, t0, 0); err != nil {
		t.Fatalf("hydra's key must still sign: %v", err)
	}
}

// A record duplicated with its own name (a Keychain restore) shares the
// handle: deleting one keeps the key for the other.
func TestCAStoreDeleteKeepsASharedKey(t *testing.T) {
	s, p, v := newStore(t)
	hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	dup := record(t, v, "k8s-ca/hydra")
	dup["name"] = "dup"
	put(t, v, "k8s-ca/dup", dup)
	if _, err := s.Get("dup"); err != nil {
		t.Fatalf("precondition: the duplicate reads: %v", err)
	}
	if err := s.Delete("dup"); err != nil {
		t.Fatal(err)
	}
	if len(p.deleted) != 0 {
		t.Fatal("the key hydra uses must not be deleted")
	}
	if _, err := hydra.Issue(p, identity("x"), 15*time.Minute, t0, 0); err != nil {
		t.Fatalf("hydra must still sign: %v", err)
	}
}

// A CA's Access is kept in its record and shown in its info; a record
// written before Access existed is a when-unlocked CA; an access value
// nazar never writes makes the record broken; an unknown access is refused
// before any key is made.
func TestCAStoreKeepsAccess(t *testing.T) {
	s, _, v := newStore(t)
	if _, err := s.Create("bot", platform.AccessAfterFirstUnlock); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("hydra", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]platform.Access{"bot": platform.AccessAfterFirstUnlock, "hydra": platform.AccessWhenUnlocked} {
		ca, err := s.Get(name)
		if err != nil || ca.Access != want || ca.Info().Access != want {
			t.Fatalf("Get(%s) = %+v, %v; want access %v", name, ca, err, want)
		}
	}
	raw, _ := v.Get(VaultPrefix + "hydra")
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["access"]; ok {
		t.Fatalf("a when-unlocked record carries an access field: %s", raw)
	}
	m["access"] = 9
	raw, _ = json.Marshal(m)
	if err := v.Put(VaultPrefix+"hydra", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("hydra"); !errors.Is(err, ErrBroken) {
		t.Fatalf("Get with access 9 = %v; want ErrBroken", err)
	}
	if _, err := s.Create("odd", platform.Access(3)); err == nil {
		t.Fatal("unknown access accepted")
	}
	if _, err := v.Get(VaultPrefix + "odd"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("a refused create left a record: %v", err)
	}
}

// Issuing with a when-unlocked CA while the Mac is locked fails with an
// error that says so, by the context's name; an after-first-unlock CA
// issues.
func TestIssueWhileLockedSaysSo(t *testing.T) {
	s, p, _ := newStore(t)
	hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	bot, err := s.Create("bot", platform.AccessAfterFirstUnlock)
	if err != nil {
		t.Fatal(err)
	}
	p.SetLocked(true)
	_, err = hydra.Issue(p, identity("admin"), 15*time.Minute, t0.Add(time.Hour), 0)
	if !errors.Is(err, platform.ErrLocked) || err.Error() != "k8s: the Mac is locked; the CA of hydra signs only while it's unlocked" {
		t.Fatalf("Issue while locked = %v", err)
	}
	if _, err := bot.Issue(p, identity("admin"), 15*time.Minute, t0.Add(time.Hour), 0); err != nil {
		t.Fatalf("after-first-unlock CA while locked: %v", err)
	}
}
