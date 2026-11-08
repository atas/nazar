package k8s

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Pins of what a k8s CA looks like from outside (aws design 2.4, 11.1):
// the Vault record, records written by earlier builds, the CA and leaf
// certificates' profiles, and every error text. They hold the CA code to
// what it does, whichever package it lives in.

// recordShape is a k8s-ca/ record as its keys in order, with every byte
// field shown as <base64> (they are random) after checking it decodes.
func recordShape(t *testing.T, raw []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var parts []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		switch k {
		case "handle", "publicKey", "certDER":
			var b []byte
			if err := json.Unmarshal(v, &b); err != nil || len(b) == 0 {
				t.Fatalf("%s is not base64 bytes: %s", k, v)
			}
			v = json.RawMessage(`"<base64>"`)
		}
		parts = append(parts, `"`+k.(string)+`":`+string(v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func TestPinCARecordJSON(t *testing.T) {
	s, _, v := newStore(t)
	for _, c := range []struct {
		name   string
		access platform.Access
		want   string
	}{
		{"hydra", platform.AccessWhenUnlocked,
			`{"version":1,"name":"hydra","handle":"<base64>","publicKey":"<base64>","created":"2026-10-18T00:00:00Z","certDER":"<base64>"}`},
		{"bot", platform.AccessAfterFirstUnlock,
			`{"version":1,"name":"bot","handle":"<base64>","publicKey":"<base64>","created":"2026-10-18T00:00:00Z","certDER":"<base64>","access":1}`},
	} {
		ca, err := s.Create(c.name, c.access)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := v.Vault.Get("k8s-ca/" + c.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := recordShape(t, raw); got != c.want {
			t.Errorf("record of %s:\n got %s\nwant %s", c.name, got, c.want)
		}
		var rec struct{ Handle, PublicKey, CertDER []byte }
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rec.Handle, ca.Handle) || !bytes.Equal(rec.PublicKey, ca.PublicKey) || !bytes.Equal(rec.CertDER, ca.Cert.Raw) {
			t.Errorf("record of %s holds another key or certificate", c.name)
		}
		if len(rec.PublicKey) != 65 || rec.PublicKey[0] != 4 {
			t.Errorf("publicKey is an X9.63 uncompressed point: %x", rec.PublicKey)
		}
	}
}

// Records written by the code before core/certs existed
// (testdata/k8s-ca-*.json) read the same, field by field.
func TestPinOldRecordsDecode(t *testing.T) {
	cases := []struct {
		name, handle, pub, fingerprint string
		access                         platform.Access
	}{
		{"hydra", "26f96ae89a7ac271677724624de7558f4ab35026c764a80298b3c318a90da5d6",
			"04ddbb6020dd406e96fec5bd7bdcb4780be49f940fbfd24362c73779f7afc7499f4ddafbdb1e66a34f1a7d96f0c691c08dc38b6faeccf9852f42d3688093eaab60",
			"72a5ded4c930d0dd7cac7a51159039e278d3fd981e01b3cb6c459cba0ab9f906", platform.AccessWhenUnlocked},
		{"bot", "af63ef3f8d90e5787db51037f172c1cb4b35ad02eb157238b60c8f4f7ccdf7bb",
			"04eea0a71766d20b389a6aa38520b69d2299dee570d3620bab953ddabf163a1649ab6cbe513beb3f4425ffdbaa216bf5285b91a06dcb3d76141d8efaf3fe5aada5",
			"ef4b7324b013b474958bf85d04ca121faf904bb09905cd7191bb42b204d16815", platform.AccessAfterFirstUnlock},
	}
	s, _, v := newStore(t)
	for _, c := range cases {
		raw, err := os.ReadFile("testdata/k8s-ca-" + c.name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Vault.Put("k8s-ca/"+c.name, bytes.TrimSpace(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range cases {
		ca, err := s.Get(c.name)
		if err != nil {
			t.Fatalf("Get(%s): %v", c.name, err)
		}
		i := ca.Info()
		if ca.Name != c.name || hex.EncodeToString(ca.Handle) != c.handle || hex.EncodeToString(ca.PublicKey) != c.pub ||
			!ca.Created.Equal(t0) || ca.Access != c.access {
			t.Errorf("%s decodes as %+v", c.name, ca)
		}
		if i.Name != c.name || i.Fingerprint != c.fingerprint || !i.Created.Equal(t0) || !i.NotAfter.Equal(t0.AddDate(10, 0, 0)) ||
			i.Access != c.access || i.Broken || i.Unreadable || i.Problem != "" {
			t.Errorf("%s info %+v", c.name, i)
		}
		if ca.Cert.Subject.CommonName != "nazar k8s CA "+c.name || !ca.Cert.NotBefore.Equal(t0.Add(-time.Minute)) {
			t.Errorf("%s certificate %v %v", c.name, ca.Cert.Subject, ca.Cert.NotBefore)
		}
	}
	list, err := s.List()
	if err != nil || len(list) != 2 || list[0].Name != "bot" || list[1].Name != "hydra" || list[0].Broken || list[1].Broken {
		t.Fatalf("list %+v %v", list, err)
	}
}

type ext struct {
	id       string
	critical bool
}

func exts(c *x509.Certificate) []ext {
	var out []ext
	for _, e := range c.Extensions {
		out = append(out, ext{e.Id.String(), e.Critical})
	}
	return out
}

func sameExts(a, b []ext) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The CA certificate's template, field by field, and the leaf's.
func TestPinCertificateProfiles(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	c := ca.Cert
	subject, _ := asn1.Marshal(pkix.Name{CommonName: "nazar k8s CA hydra"}.ToRDNSequence())
	ski := sha256.Sum256(ca.PublicKey)
	if c.Version != 3 || !bytes.Equal(c.RawSubject, subject) || !bytes.Equal(c.RawIssuer, subject) ||
		c.SignatureAlgorithm != x509.ECDSAWithSHA256 || c.PublicKeyAlgorithm != x509.ECDSA ||
		!bytes.Equal(c.SubjectKeyId, ski[:20]) || len(c.AuthorityKeyId) != 0 || c.SerialNumber.BitLen() != 127 {
		t.Fatalf("CA certificate: v%d subject %x ski %x aki %x serial %d bits", c.Version, c.RawSubject, c.SubjectKeyId, c.AuthorityKeyId, c.SerialNumber.BitLen())
	}
	if want := []ext{{"2.5.29.15", true}, {"2.5.29.19", true}, {"2.5.29.14", false}}; !sameExts(exts(c), want) {
		t.Fatalf("CA extensions %v, want %v", exts(c), want)
	}
	if !c.NotBefore.Equal(t0.Add(-time.Minute)) || !c.NotAfter.Equal(t0.AddDate(10, 0, 0)) {
		t.Fatalf("CA validity %v – %v", c.NotBefore, c.NotAfter)
	}
	now := t0.Add(90*time.Minute + 700*time.Millisecond)
	cred, err := ca.Issue(p, identity("admin", "system:masters"), 15*time.Minute, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := parseCred(t, cred)
	leafSubject, _ := asn1.Marshal(pkix.Name{CommonName: "admin", Organization: []string{"system:masters"}}.ToRDNSequence())
	if leaf.Version != 3 || !bytes.Equal(leaf.RawSubject, leafSubject) || !bytes.Equal(leaf.RawIssuer, subject) ||
		leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(leaf.SubjectKeyId) != 0 ||
		!bytes.Equal(leaf.AuthorityKeyId, c.SubjectKeyId) || leaf.SerialNumber.BitLen() != 127 {
		t.Fatalf("leaf: v%d subject %x ski %x aki %x serial %d bits", leaf.Version, leaf.RawSubject, leaf.SubjectKeyId, leaf.AuthorityKeyId, leaf.SerialNumber.BitLen())
	}
	if want := []ext{{"2.5.29.15", true}, {"2.5.29.37", false}, {"2.5.29.19", true}, {"2.5.29.35", false}}; !sameExts(exts(leaf), want) {
		t.Fatalf("leaf extensions %v, want %v", exts(leaf), want)
	}
	if !leaf.NotBefore.Equal(t0.Add(89*time.Minute)) || !leaf.NotAfter.Equal(t0.Add(105*time.Minute)) || !cred.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("leaf validity %v – %v", leaf.NotBefore, leaf.NotAfter)
	}
	if !bytes.HasPrefix(cred.KeyPEM, []byte("-----BEGIN EC PRIVATE KEY-----\n")) || !bytes.HasPrefix(cred.CertPEM, []byte("-----BEGIN CERTIFICATE-----\n")) {
		t.Fatal("PEM block types")
	}
}

// listFailVault fails every List.
type listFailVault struct{ *fake.Vault }

func (listFailVault) List(string) ([]string, error) { return nil, errors.New("boom") }

// pubPlatform returns pub from CreateKey in place of the key's.
type pubPlatform struct {
	*fake.Fake
	pub []byte
}

func (p *pubPlatform) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	h, _, err := p.Fake.CreateKey(purpose, auth, access)
	return h, p.pub, err
}

// Every error text core/k8s's CA code returns, by the path that returns it.
func TestPinErrorTexts(t *testing.T) {
	for err, want := range map[error]string{
		ErrExists:      "k8s: a CA of that name exists",
		ErrNotFound:    "k8s: no CA of that name",
		ErrInvalidName: "k8s: invalid context name",
		ErrUnreadable:  "k8s: the vault refused to return the CA record",
		ErrBroken:      "k8s: the CA record is unusable",
	} {
		if err.Error() != want {
			t.Errorf("%q, want %q", err, want)
		}
	}
	type got struct {
		err    error
		want   string
		prefix bool // want is the text's start; the rest is the platform's or x509's
		is     error
	}
	var cases []got
	add := func(err error, want string, is error) { cases = append(cases, got{err, want, false, is}) }
	addPrefix := func(err error, want string) { cases = append(cases, got{err, want, true, nil}) }

	s, p, v := newStore(t)
	hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("other", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	_, err = s.Create("a/b", platform.AccessWhenUnlocked)
	add(err, "k8s: invalid context name", ErrInvalidName)
	_, err = s.Create("x", platform.Access(3))
	add(err, "k8s: unknown access access(3)", nil)
	_, err = s.Create("Hydra", platform.AccessWhenUnlocked)
	add(err, "k8s: a CA of that name exists", ErrExists)
	_, err = NewCAStore(p, listFailVault{fake.NewVault()}, nil).Create("x", platform.AccessWhenUnlocked)
	add(err, "k8s: listing CA records: boom", nil)
	_, err = NewCAStore(&pubPlatform{Fake: fake.New(t0), pub: []byte{4, 1, 2}}, fake.NewVault(), nil).Create("x", platform.AccessWhenUnlocked)
	addPrefix(err, "k8s: the enclave returned an unusable public key: ")
	p.wrongPub = true
	_, err = s.Create("x", platform.AccessWhenUnlocked)
	addPrefix(err, "k8s: making the CA certificate: ")
	p.wrongPub = false
	locked := fake.New(t0)
	locked.SetLocked(true)
	_, err = NewCAStore(locked, fake.NewVault(), nil).Create("x", platform.AccessWhenUnlocked)
	add(err, "k8s: the Mac is locked; a CA that signs only while it's unlocked can't be made now", platform.ErrLocked)

	_, err = s.Get("a:b")
	add(err, "k8s: invalid context name", ErrInvalidName)
	_, err = s.Get("nope")
	add(err, "k8s: no CA of that name", ErrNotFound)
	v.FailGetOf = map[string]error{"k8s-ca/other": errors.New("errSecInteractionNotAllowed")}
	_, err = s.Get("other")
	add(err, "k8s: the vault refused to return the CA record: k8s-ca/other: errSecInteractionNotAllowed", ErrUnreadable)
	err = s.Delete("other")
	add(err, "k8s: the vault refused to return the CA record: k8s-ca/other: errSecInteractionNotAllowed", ErrUnreadable)
	v.FailGetOf = nil
	add(s.Delete("a:b"), "k8s: no CA of that name", ErrNotFound)
	add(s.Delete("nope"), "k8s: no CA of that name", ErrNotFound)

	// Broken records, one per reason.
	edCA := func() []byte {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ed"}, NotBefore: t0, NotAfter: t0.Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}()
	leafCred, err := hydra.Issue(p, identity("x"), 15*time.Minute, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := parseCred(t, leafCred)
	broken := map[string]func(m map[string]any){
		"version":  func(m map[string]any) { m["version"] = 2 },
		"another":  func(m map[string]any) { m["name"] = "hydra" },
		"nohandle": func(m map[string]any) { delete(m, "handle") },
		"access":   func(m map[string]any) { m["access"] = 9 },
		"noparse":  func(m map[string]any) { m["certDER"] = base64.StdEncoding.EncodeToString([]byte("junk")) },
		"leaf":     func(m map[string]any) { m["certDER"] = leafCert.Raw },
		"ed":       func(m map[string]any) { m["certDER"] = edCA },
		"swapped":  func(m map[string]any) { m["certDER"] = record(t, v, "k8s-ca/other")["certDER"] },
	}
	for name, edit := range broken {
		m := record(t, v, "k8s-ca/hydra")
		m["name"] = name
		edit(m)
		put(t, v, "k8s-ca/"+name, m)
	}
	if err := v.Vault.Put("k8s-ca/junk", []byte("{")); err != nil {
		t.Fatal(err)
	}
	for name, why := range map[string]string{
		"junk":     "does not decode",
		"version":  "has format version 2",
		"another":  "names another context",
		"nohandle": "has no key handle",
		"access":   "has unknown access access(9)",
		"noparse":  "holds a certificate that does not parse",
		"leaf":     "holds a certificate that is not a CA",
		"ed":       "holds a certificate that is not a P-256 key's",
		"swapped":  "holds a certificate of another key",
	} {
		_, err := s.Get(name)
		add(err, "k8s: the CA record is unusable: k8s-ca/"+name+" "+why, ErrBroken)
	}
	_ = v.Vault.Put("k8s-ca/a:b", []byte("{}"))
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	problems := map[string]string{}
	for _, i := range list {
		problems[i.Name] = i.Problem
	}
	if problems["a:b"] != "not a CA nazar made: its name is not a context name" || problems["junk"] != "k8s: the CA record is unusable: k8s-ca/junk does not decode" ||
		problems["hydra"] != "" {
		t.Errorf("list problems %q", problems)
	}

	// Issue.
	_, err = hydra.Issue(p, identity("a"), 0, t0, 0)
	add(err, "k8s: ttl_cert 0s is outside 1m0s..1h0m0s", nil)
	_, err = hydra.Issue(p, identity("a"), 2*time.Hour, t0, 0)
	add(err, "k8s: ttl_cert 2h0m0s is outside 1m0s..1h0m0s", nil)
	_, err = hydra.Issue(p, identity("a b"), 15*time.Minute, t0, 0)
	add(err, "k8s: invalid identity user", nil)
	_, err = hydra.Issue(p, identity("a", "x\ny"), 15*time.Minute, t0, 0)
	add(err, "k8s: invalid identity group", nil)
	_, err = hydra.Issue(p, identity("a"), 15*time.Minute, t0.AddDate(11, 0, 0), 0)
	add(err, "k8s: the CA of hydra is not valid now (valid 2026-10-17T23:59:00Z to 2036-10-18T00:00:00Z)", nil)
	_, err = hydra.Issue(p, identity("a"), 15*time.Minute, t0.Add(-time.Hour), 0)
	add(err, "k8s: the CA of hydra is not valid now (valid 2026-10-17T23:59:00Z to 2036-10-18T00:00:00Z)", nil)
	p.SetLocked(true)
	_, err = hydra.Issue(p, identity("a"), 15*time.Minute, t0, 0)
	add(err, "k8s: the Mac is locked; the CA of hydra signs only while it's unlocked", platform.ErrLocked)
	p.SetLocked(false)

	// The provider.
	pr := CACertProvider(s, p)
	_, err = pr.Issue(IssueInput{Context: &config.K8sContext{Name: "hydra", Credential: "stored"}, Now: t0})
	add(err, "k8s: not a ca-cert context", nil)
	_, err = pr.Issue(IssueInput{Now: t0})
	add(err, "k8s: not a ca-cert context", nil)
	_, err = pr.Issue(IssueInput{Context: &config.K8sContext{Name: "nope", Credential: config.CredentialCACert}, Now: t0})
	add(err, "k8s: no CA of that name", ErrNotFound)

	for i, c := range cases {
		switch {
		case c.err == nil:
			t.Errorf("case %d (%q): no error", i, c.want)
		case c.prefix && !strings.HasPrefix(c.err.Error(), c.want):
			t.Errorf("case %d: %q does not start with %q", i, c.err, c.want)
		case !c.prefix && c.err.Error() != c.want:
			t.Errorf("case %d: %q, want %q", i, c.err, c.want)
		case c.is != nil && !errors.Is(c.err, c.is):
			t.Errorf("case %d: %q is not %v", i, c.err, c.is)
		}
	}
}
