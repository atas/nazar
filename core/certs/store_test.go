package certs

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
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The engine's store and issuer, each test run for two kinds (aws design
// 11.1): the k8s one, and a test kind with other words, another prefix and
// another name rule, so nothing of one kind shows in the other.

var t0 = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)

var testNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func k8sKind() *Kind {
	return NewKind("k8s", "k8s-ca/", "context", "nazar k8s CA ", config.ValidK8sContextName)
}

func testKind() *Kind {
	return NewKind("test", "test-ca/", "entry", "nazar test CA ", testNameRE.MatchString)
}

// kinds runs f once per kind.
func kinds(t *testing.T, f func(t *testing.T, k *Kind)) {
	for name, k := range map[string]*Kind{"k8s": k8sKind(), "test": testKind()} {
		t.Run(name, func(t *testing.T) { f(t, k) })
	}
}

// spyVault is a fake vault whose Get can fail per item (a locked keychain,
// another build's item) and which counts deletes.
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

func newStore(t *testing.T, k *Kind) (*Store, *spyPlatform, *spyVault) {
	t.Helper()
	p := newSpy(t)
	v := &spyVault{Vault: fake.NewVault()}
	return NewStore(k, p, v, func() time.Time { return t0 }), p, v
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

// leafFor is a 15-minute leaf for cn from now.
func leafFor(cn string, now time.Time, o ...string) LeafSpec {
	return LeafSpec{CN: cn, O: o, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(15 * time.Minute)}
}

func TestNewKindRefusesAnIncompleteKind(t *testing.T) {
	ok := func(string) bool { return true }
	for name, f := range map[string]func(){
		"no tag":        func() { NewKind("", "x-ca/", "entry", "nazar x CA ", ok) },
		"no slash":      func() { NewKind("x", "x-ca", "entry", "nazar x CA ", ok) },
		"empty prefix":  func() { NewKind("x", "/", "entry", "nazar x CA ", ok) },
		"no noun":       func() { NewKind("x", "x-ca/", "", "nazar x CA ", ok) },
		"no subject":    func() { NewKind("x", "x-ca/", "entry", "", ok) },
		"no name check": func() { NewKind("x", "x-ca/", "entry", "nazar x CA ", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: NewKind must panic", name)
				}
			}()
			f()
		}()
	}
}

func TestKindErrorTexts(t *testing.T) {
	for k, want := range map[*Kind][5]string{
		k8sKind(): {"k8s: a CA of that name exists", "k8s: no CA of that name", "k8s: invalid context name",
			"k8s: the vault refused to return the CA record", "k8s: the CA record is unusable"},
		testKind(): {"test: a CA of that name exists", "test: no CA of that name", "test: invalid entry name",
			"test: the vault refused to return the CA record", "test: the CA record is unusable"},
	} {
		got := [5]string{k.ErrExists().Error(), k.ErrNotFound().Error(), k.ErrInvalidName().Error(), k.ErrUnreadable().Error(), k.ErrBroken().Error()}
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
		if k.ErrNotFound() != k.ErrNotFound() {
			t.Error("a kind's errors are values: errors.Is matches them")
		}
	}
	if k8sKind().ErrNotFound() == k8sKind().ErrNotFound() {
		t.Error("each kind has its own errors")
	}
}

func TestStoreCreateGetDelete(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, v := newStore(t, k)
		ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		c := ca.Cert
		if c.Subject.CommonName != k.subject+"hydra" || !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero ||
			c.KeyUsage != x509.KeyUsageCertSign || len(c.ExtKeyUsage) != 0 {
			t.Fatalf("CA profile: %+v", c)
		}
		ski := sha256.Sum256(ca.PublicKey)
		if !bytes.Equal(c.SubjectKeyId, ski[:20]) || len(c.AuthorityKeyId) != 0 || c.SerialNumber.BitLen() != 127 {
			t.Fatalf("SKI %x, AKI %x, serial %d bits", c.SubjectKeyId, c.AuthorityKeyId, c.SerialNumber.BitLen())
		}
		if !c.NotBefore.Equal(t0.Add(-time.Minute)) || !c.NotAfter.Equal(t0.AddDate(10, 0, 0)) {
			t.Fatalf("validity %v – %v", c.NotBefore, c.NotAfter)
		}
		if err := c.CheckSignatureFrom(c); err != nil {
			t.Fatalf("self-signed through the platform: %v", err)
		}
		b, _ := pem.Decode(ca.CertPEM())
		if b == nil || b.Type != "CERTIFICATE" || !bytes.Equal(b.Bytes, c.Raw) {
			t.Fatal("CertPEM")
		}
		if names, _ := v.List(""); len(names) != 1 || names[0] != k.prefix+"hydra" {
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
			if _, err := s.Create(again, platform.AccessWhenUnlocked); !errors.Is(err, k.ErrExists()) && !errors.Is(err, k.ErrInvalidName()) {
				t.Fatalf("create %s again: %v", again, err)
			}
		}
		if _, err := s.Create("a/b", platform.AccessWhenUnlocked); !errors.Is(err, k.ErrInvalidName()) {
			t.Fatalf("an invalid name: %v", err)
		}
		if err := s.Delete("hydra"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("hydra"); !errors.Is(err, k.ErrNotFound()) {
			t.Fatalf("after delete: %v", err)
		}
		if _, err := p.Fake.Sign(ca.Handle, []byte("x"), 0); !errors.Is(err, platform.ErrNotFound) {
			t.Fatalf("the enclave key must be gone: %v", err)
		}
		if err := s.Delete("hydra"); !errors.Is(err, k.ErrNotFound()) {
			t.Fatalf("a second delete: %v", err)
		}
	})
}

func TestStoreCreateRollsBack(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, v := newStore(t, k)
		v.FailPut = errors.New("the keychain is locked")
		if _, err := s.Create("hydra", platform.AccessWhenUnlocked); err == nil {
			t.Fatal("a failed vault write must fail the create")
		}
		v.FailPut = nil
		p.wrongPub = true
		_, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err == nil || !strings.HasPrefix(err.Error(), k.tag+": making the CA certificate: ") {
			t.Fatalf("a platform whose public key is not its handle's: %v", err)
		}
		if len(p.deleted) != 2 {
			t.Fatalf("the new keys must be deleted: %d deletes", len(p.deleted))
		}
		if names, _ := v.List(""); len(names) != 0 {
			t.Fatalf("nothing stored: %v", names)
		}
		p.wrongPub = false
		p.SetLocked(true)
		if _, err := s.Create("hydra", platform.AccessWhenUnlocked); !errors.Is(err, platform.ErrLocked) ||
			err.Error() != k.tag+": the Mac is locked; a CA that signs only while it's unlocked can't be made now" {
			t.Fatalf("locked: %v", err)
		}
		p.SetLocked(false)
		if _, err := s.Create("hydra", platform.Access(3)); err == nil || err.Error() != k.tag+": unknown access access(3)" {
			t.Fatalf("unknown access: %v", err)
		}
		if _, err := s.Create("hydra", platform.AccessWhenUnlocked); err != nil {
			t.Fatalf("the name stays free: %v", err)
		}
	})
}

func TestStoreBrokenAndUnreadableRecords(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, v := newStore(t, k)
		hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Create("other", platform.AccessWhenUnlocked); err != nil {
			t.Fatal(err)
		}
		put(t, v, k.prefix+"copy", record(t, v, k.prefix+"hydra"))
		swapped := record(t, v, k.prefix+"hydra")
		swapped["name"] = "swapped"
		swapped["certDER"] = record(t, v, k.prefix+"other")["certDER"]
		put(t, v, k.prefix+"swapped", swapped)
		future := record(t, v, k.prefix+"hydra")
		future["name"], future["version"] = "future", 2
		put(t, v, k.prefix+"future", future)
		if err := v.Vault.Put(k.prefix+"junk", []byte("{")); err != nil {
			t.Fatal(err)
		}
		leaf, err := hydra.Issue(p, leafFor("x", t0), t0, 0)
		if err != nil {
			t.Fatal(err)
		}
		lr := record(t, v, k.prefix+"hydra")
		lr["name"] = "leaf"
		lr["certDER"] = leaf.Cert.Raw
		put(t, v, k.prefix+"leaf", lr)
		for name, why := range map[string]string{
			"copy":    "names another " + k.noun,
			"swapped": "holds a certificate of another key",
			"future":  "has format version 2",
			"junk":    "does not decode",
			"leaf":    "holds a certificate that is not a CA",
		} {
			_, err := s.Get(name)
			if want := k.tag + ": the CA record is unusable: " + k.prefix + name + " " + why; !errors.Is(err, k.ErrBroken()) || err.Error() != want {
				t.Errorf("%s: %v, want %q", name, err, want)
			}
		}
		v.FailGetOf = map[string]error{k.prefix + "other": errors.New("errSecInteractionNotAllowed")}
		_, err = s.Get("other")
		if want := k.tag + ": the vault refused to return the CA record: " + k.prefix + "other: errSecInteractionNotAllowed"; !errors.Is(err, k.ErrUnreadable()) || err.Error() != want {
			t.Fatalf("unreadable: %v", err)
		}
		_ = v.Vault.Put(k.prefix+"a:b", []byte("{}"))
		list, err := s.List()
		if err != nil {
			t.Fatal(err)
		}
		states := map[string]string{}
		var names []string
		for _, i := range list {
			names = append(names, i.Name)
			switch {
			case i.Unreadable:
				states[i.Name] = "unreadable"
			case i.Broken:
				states[i.Name] = "broken"
			default:
				states[i.Name] = "ok"
			}
			if i.Name == "a:b" && i.Problem != "not a CA nazar made: its name is not "+k.article()+" "+k.noun+" name" {
				t.Errorf("foreign item: %q", i.Problem)
			}
		}
		if !slices.IsSorted(names) {
			t.Errorf("listed in name order: %v", names)
		}
		want := map[string]string{"a:b": "broken", "hydra": "ok", "other": "unreadable", "copy": "broken", "swapped": "broken", "future": "broken", "junk": "broken", "leaf": "broken"}
		if len(states) != len(want) {
			t.Errorf("states %v", states)
		}
		for n, st := range want {
			if states[n] != st {
				t.Errorf("%s: %s, want %s", n, states[n], st)
			}
		}
		nd, nv := len(p.deleted), len(v.deletes)
		if err := s.Delete("other"); !errors.Is(err, k.ErrUnreadable()) || len(p.deleted) != nd || len(v.deletes) != nv {
			t.Fatalf("delete of unreadable: %v", err)
		}
		v.FailGetOf = nil
		// The copy shares hydra's handle: its delete keeps hydra's key.
		if err := s.Delete("copy"); err != nil {
			t.Fatal(err)
		}
		if _, err := hydra.Issue(p, leafFor("x", t0), t0, 0); err != nil {
			t.Fatalf("hydra's key must still sign: %v", err)
		}
	})
}

func TestStoreDeleteKeepsASharedKey(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, v := newStore(t, k)
		hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		dup := record(t, v, k.prefix+"hydra")
		dup["name"] = "dup"
		put(t, v, k.prefix+"dup", dup)
		if _, err := s.Get("dup"); err != nil {
			t.Fatalf("precondition: the duplicate reads: %v", err)
		}
		if err := s.Delete("dup"); err != nil {
			t.Fatal(err)
		}
		if len(p.deleted) != 0 {
			t.Fatal("the key hydra uses must not be deleted")
		}
		if _, err := hydra.Issue(p, leafFor("x", t0), t0, 0); err != nil {
			t.Fatalf("hydra must still sign: %v", err)
		}
	})
}

func TestStoreKeepsAccess(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, _, v := newStore(t, k)
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
		if _, ok := record(t, v, k.prefix+"hydra")["access"]; ok {
			t.Fatal("a when-unlocked record carries no access field")
		}
		m := record(t, v, k.prefix+"hydra")
		m["access"] = 9
		put(t, v, k.prefix+"hydra", m)
		if _, err := s.Get("hydra"); !errors.Is(err, k.ErrBroken()) {
			t.Fatalf("access 9: %v", err)
		}
	})
}

func TestStoreCreateIsSerialised(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, _, v := newStore(t, k)
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, n := range []string{"hydra", "hydra"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.Create(n, platform.AccessWhenUnlocked)
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, k.ErrExists()):
				t.Fatal(err)
			}
		}
		if names, _ := v.List(""); ok != 1 || len(names) != 1 {
			t.Fatalf("one CA: %d made, %v", ok, names)
		}
	})
}

// Two kinds over one Vault: neither lists, reads, deletes nor counts the
// other's records, and a name taken in one (ignoring case) is free in the
// other.
func TestKindsNeverCross(t *testing.T) {
	p := newSpy(t)
	v := &spyVault{Vault: fake.NewVault()}
	kk, tk := k8sKind(), testKind()
	ks, ts := NewStore(kk, p, v, func() time.Time { return t0 }), NewStore(tk, p, v, func() time.Time { return t0 })
	kc, err := ks.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Get("hydra"); !errors.Is(err, tk.ErrNotFound()) {
		t.Fatalf("the test kind reads k8s's record: %v", err)
	}
	if err := ts.Delete("hydra"); !errors.Is(err, tk.ErrNotFound()) {
		t.Fatalf("the test kind deletes k8s's record: %v", err)
	}
	tc, err := ts.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatalf("a name of another kind is free: %v", err)
	}
	if _, err := ks.Create("HYDRA", platform.AccessWhenUnlocked); !errors.Is(err, kk.ErrExists()) {
		t.Fatalf("case-folded within a kind: %v", err)
	}
	if tc.Cert.Subject.CommonName != "nazar test CA hydra" || kc.Cert.Subject.CommonName != "nazar k8s CA hydra" || bytes.Equal(tc.Handle, kc.Handle) {
		t.Fatal("each kind's CA has its own subject and key")
	}
	// An item of a third adapter, a copy of k8s's record, is nobody's here.
	raw, err := v.Vault.Get("k8s-ca/hydra")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Vault.Put("aws-ca/hydra", raw); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{ks, ts} {
		list, err := s.List()
		if err != nil || len(list) != 1 || list[0].Name != "hydra" || list[0].Broken {
			t.Fatalf("%s lists %+v %v", s.k.tag, list, err)
		}
	}
	if err := ts.Delete("hydra"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Get("hydra"); err != nil {
		t.Fatalf("k8s's CA survives the test kind's delete: %v", err)
	}
	if _, err := kc.Issue(p, leafFor("x", t0), t0, 0); err != nil {
		t.Fatalf("k8s's key survives the test kind's delete: %v", err)
	}
	if _, err := v.Vault.Get("aws-ca/hydra"); err != nil {
		t.Fatal("another adapter's item is never deleted")
	}
	if names, _ := v.List(""); len(names) != 2 {
		t.Fatalf("left: %v", names)
	}
}
