package certs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// A leaf for a throwaway key, signed through the platform on the CA key,
// with the client profile and nothing more, lasting what the caller asked
// (or to the CA's end, if sooner).

func TestIssueProfile(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, _ := newStore(t, k)
		ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		now := t0.Add(90*time.Minute + 700*time.Millisecond)
		leaf, err := ca.Issue(p, LeafSpec{CN: "admin", O: []string{"system:masters", "devs"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(15 * time.Minute)}, now, 0)
		if err != nil {
			t.Fatal(err)
		}
		cert, key := leaf.Cert, leaf.Key
		if cert.Subject.CommonName != "admin" || !slices.Equal(slices.Sorted(slices.Values(cert.Subject.Organization)), []string{"devs", "system:masters"}) ||
			len(cert.Subject.Names) != 3 {
			t.Fatalf("subject %v", cert.Subject)
		}
		if !bytes.Equal(cert.RawIssuer, ca.Cert.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, ca.Cert.SubjectKeyId) {
			t.Fatal("issuer and authority key id are the CA's")
		}
		if !cert.NotBefore.Equal(t0.Add(89*time.Minute)) || !cert.NotAfter.Equal(t0.Add(105*time.Minute)) {
			t.Fatalf("whole seconds: %v – %v", cert.NotBefore, cert.NotAfter)
		}
		if cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
			!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(cert.UnknownExtKeyUsage) != 0 {
			t.Fatalf("usages: CA=%v ku=%v eku=%v", cert.IsCA, cert.KeyUsage, cert.ExtKeyUsage)
		}
		if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 || len(cert.SubjectKeyId) != 0 {
			t.Fatal("no names, no key id of its own")
		}
		if cert.SerialNumber.BitLen() != 127 || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 || cert.CheckSignatureFrom(ca.Cert) != nil {
			t.Fatal("a 127-bit serial, signed by the CA with ecdsa-with-SHA256")
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.Cert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Fatalf("a client chain to the CA: %v", err)
		}
		pub, _ := cert.PublicKey.(*ecdsa.PublicKey)
		if pub == nil || !pub.Equal(&key.PublicKey) || key.Curve != elliptic.P256() {
			t.Fatal("the key is the certificate's P-256 key")
		}
		if len(p.signed) == 0 || !bytes.Equal(p.signed[len(p.signed)-1], cert.RawTBSCertificate) {
			t.Fatal("Platform.Sign must receive the TBS bytes")
		}
		// No O=, as for AWS: the subject is the CN alone.
		bare, err := ca.Issue(p, leafFor("me-nazar", now), now, 0)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := asnSubject(pkix.Name{CommonName: "me-nazar"})
		if !bytes.Equal(bare.Cert.RawSubject, want) || bare.Key.Equal(key) || bare.Cert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			t.Fatal("a subject of one CN; every issue has its own key and serial")
		}
	})
}

func TestIssueTakesTheCallersSerial(t *testing.T) {
	s, p, _ := newStore(t, testKind())
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := NewSerial()
	if err != nil {
		t.Fatal(err)
	}
	spec := leafFor("me-nazar", t0)
	spec.Serial = sn
	leaf, err := ca.Issue(p, spec, t0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Cert.SerialNumber.String() != sn.Decimal() || leaf.Cert.SerialNumber.Text(16) != strings.TrimLeft(sn.Hex(), "0") {
		t.Fatalf("serial %v, want %s", leaf.Cert.SerialNumber, sn.Decimal())
	}
}

func TestIssueLifetime(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, _ := newStore(t, k)
		ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		// The CA's end cuts a later one.
		near := ca.Cert.NotAfter.Add(-5 * time.Minute)
		leaf, err := ca.Issue(p, leafFor("a", near), near, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !leaf.Cert.NotAfter.Equal(ca.Cert.NotAfter) {
			t.Fatalf("a leaf never outlives its CA: %v", leaf.Cert.NotAfter)
		}
		// The CA must be valid now.
		for _, now := range []time.Time{ca.Cert.NotAfter, ca.Cert.NotAfter.Add(time.Second), ca.Cert.NotBefore.Add(-time.Second)} {
			_, err := ca.Issue(p, leafFor("a", now), now, 0)
			if want := k.tag + ": the CA of hydra is not valid now (valid 2026-10-17T23:59:00Z to 2036-10-18T00:00:00Z)"; err == nil || err.Error() != want {
				t.Errorf("at %v: %v", now, err)
			}
		}
		// A spec with no subject or no lifetime mints nothing.
		for name, spec := range map[string]LeafSpec{
			"no CN":       {NotBefore: t0, NotAfter: t0.Add(time.Minute)},
			"no start":    {CN: "a", NotAfter: t0.Add(time.Minute)},
			"empty":       {CN: "a", NotBefore: t0, NotAfter: t0.Add(999 * time.Millisecond)},
			"backwards":   {CN: "a", NotBefore: t0, NotAfter: t0.Add(-time.Minute)},
			"past the CA": {CN: "a", NotBefore: ca.Cert.NotAfter, NotAfter: ca.Cert.NotAfter.Add(time.Hour)},
		} {
			if _, err := ca.Issue(p, spec, t0, 0); err == nil || !strings.HasPrefix(err.Error(), k.tag+": a certificate needs a ") {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
}

func TestIssueWhileLockedSaysSo(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, _ := newStore(t, k)
		hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		bot, err := s.Create("bot", platform.AccessAfterFirstUnlock)
		if err != nil {
			t.Fatal(err)
		}
		p.SetLocked(true)
		_, err = hydra.Issue(p, leafFor("a", t0), t0, 0)
		if !errors.Is(err, platform.ErrLocked) || err.Error() != k.tag+": the Mac is locked; the CA of hydra signs only while it's unlocked" {
			t.Fatalf("Issue while locked = %v", err)
		}
		if _, err := bot.Issue(p, leafFor("a", t0), t0, 0); err != nil {
			t.Fatalf("after-first-unlock CA while locked: %v", err)
		}
	})
}

func TestIssueRefusesABadSignature(t *testing.T) {
	s, p, _ := newStore(t, testKind())
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	p.wrongSig = true
	if leaf, err := ca.Issue(p, leafFor("a", t0), t0, 0); err == nil || leaf.Cert != nil || leaf.Key != nil {
		t.Fatal("a signature that does not verify against the CA key mints nothing")
	}
	p.wrongSig = false
	if _, err := ca.Issue(p, leafFor("a", t0), t0, 42); err != nil || p.refs[len(p.refs)-1] != 42 {
		t.Fatalf("the approval ref reaches Platform.Sign: %v %v", err, p.refs)
	}
	if err := p.Fake.DeleteKey(ca.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(p, leafFor("a", t0), t0, 0); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("a dead CA key: %v", err)
	}
}

// A CA no store returned (built by hand) has no kind and no key: it mints
// nothing.
func TestIssueNeedsAStoresCA(t *testing.T) {
	s, p, _ := newStore(t, testKind())
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	forged := &CA{Name: ca.Name, Handle: ca.Handle, PublicKey: ca.PublicKey, Created: ca.Created, Cert: ca.Cert, Access: ca.Access}
	if _, err := forged.Issue(p, leafFor("a", t0), t0, 0); err == nil {
		t.Fatal("a hand-built CA must not issue")
	}
}

func TestSerial(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		sn, err := NewSerial()
		if err != nil {
			t.Fatal(err)
		}
		h, d := sn.Hex(), sn.Decimal()
		n, ok := new(big.Int).SetString(d, 10)
		if !ok || n.Sign() <= 0 || n.BitLen() != 127 {
			t.Fatalf("serial %s: positive, 127 bits", d)
		}
		if len(h) != 32 || len(h)%2 != 0 || strings.ToLower(h) != h || n.Text(16) != strings.TrimLeft(h, "0") {
			t.Fatalf("hex %q of %s", h, d)
		}
		if seen[h] {
			t.Fatal("a repeated serial")
		}
		seen[h] = true
	}
	var zero Serial
	if zero.Hex() != "" || zero.Decimal() != "" {
		t.Fatal("the zero serial has no text")
	}
}

// Moved from core/k8s with its case table: the signer is handed messages,
// never digests, hashes with SHA-256 only, and passes the approval on.
func TestSignerSignsOnlyMessages(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, _ := newStore(t, k)
		ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		sg := &signer{p: p, handle: ca.Handle, pub: ca.pub, ref: 7, tag: k.tag}
		sum := sha256.Sum256([]byte("tbs"))
		if _, err := sg.Sign(rand.Reader, sum[:], crypto.SHA256); err == nil || err.Error() != k.tag+": the CA signs messages, never digests" {
			t.Fatalf("Sign(digest) must be refused: the enclave signs what it hashes: %v", err)
		}
		if _, err := sg.SignMessage(rand.Reader, []byte("tbs"), crypto.SHA384); err == nil || err.Error() != k.tag+": the CA signs with SHA-256 only" {
			t.Fatalf("only SHA-256: %v", err)
		}
		sig, err := sg.SignMessage(rand.Reader, []byte("tbs"), crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		pub := sg.Public().(*ecdsa.PublicKey)
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			t.Fatal("the signature verifies with the CA key over SHA-256(msg)")
		}
		if p.refs[len(p.refs)-1] != 7 {
			t.Fatal("the approval ref reaches Platform.Sign")
		}
	})
}

// Moved from core/k8s with its case table. Reviews: check is the last
// gate before a certificate leaves; it is tested on its own, on
// certificates CreateCertificate would accept.
func TestIssueCheck(t *testing.T) {
	kinds(t, func(t *testing.T, k *Kind) {
		s, p, _ := newStore(t, k)
		ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		other, err := s.Create("other", platform.AccessWhenUnlocked)
		if err != nil {
			t.Fatal(err)
		}
		now := t0.Add(time.Hour)
		nb, na := now.Add(-time.Minute), now.Add(15*time.Minute)
		spec := LeafSpec{CN: "admin", O: []string{"system:masters"}, NotBefore: nb, NotAfter: na, Serial: Serial{big.NewInt(99)}}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		good := func() *x509.Certificate {
			return &x509.Certificate{SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: "admin", Organization: []string{"system:masters"}},
				NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				BasicConstraintsValid: true}
		}
		mint := func(tmpl *x509.Certificate, by *CA, pub *ecdsa.PublicKey) *x509.Certificate {
			t.Helper()
			der, err := x509.CreateCertificate(rand.Reader, tmpl, by.Cert, pub, &signer{p: p, handle: by.Handle, pub: by.pub, tag: k.tag})
			if err != nil {
				t.Fatal(err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		if err := check(mint(good(), ca, &key.PublicKey), ca, spec, &key.PublicKey); err != nil {
			t.Fatalf("a good certificate: %v", err)
		}
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		cases := map[string]*x509.Certificate{
			"another CA":  mint(good(), other, &key.PublicKey),
			"another key": mint(good(), ca, &otherKey.PublicKey),
			"another subject": func() *x509.Certificate {
				c := good()
				c.Subject.CommonName = "root"
				return mint(c, ca, &key.PublicKey)
			}(),
			"another group": func() *x509.Certificate {
				c := good()
				c.Subject.Organization = []string{"evil"}
				return mint(c, ca, &key.PublicKey)
			}(),
			"a CA": func() *x509.Certificate {
				c := good()
				c.IsCA = true
				c.KeyUsage |= x509.KeyUsageCertSign
				return mint(c, ca, &key.PublicKey)
			}(),
			"server auth too": func() *x509.Certificate {
				c := good()
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
				return mint(c, ca, &key.PublicKey)
			}(),
			"another key usage": func() *x509.Certificate {
				c := good()
				c.KeyUsage |= x509.KeyUsageKeyEncipherment
				return mint(c, ca, &key.PublicKey)
			}(),
			"a later end": func() *x509.Certificate {
				c := good()
				c.NotAfter = na.Add(time.Hour)
				return mint(c, ca, &key.PublicKey)
			}(),
			"an earlier start": func() *x509.Certificate {
				c := good()
				c.NotBefore = nb.Add(-time.Hour)
				return mint(c, ca, &key.PublicKey)
			}(),
			"a DNS name": func() *x509.Certificate {
				c := good()
				c.DNSNames = []string{"evil.example"}
				return mint(c, ca, &key.PublicKey)
			}(),
			"another serial": func() *x509.Certificate {
				c := good()
				c.SerialNumber = big.NewInt(100)
				return mint(c, ca, &key.PublicKey)
			}(),
		}
		for name, c := range cases {
			if err := check(c, ca, spec, &key.PublicKey); err == nil || !strings.HasPrefix(err.Error(), k.tag+": the minted certificate ") {
				t.Errorf("%s: check must refuse it: %v", name, err)
			}
		}
	})
}

func asnSubject(n pkix.Name) ([]byte, error) { return asn1.Marshal(n.ToRDNSequence()) }
