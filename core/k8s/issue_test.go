package k8s

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
)

// K8s design 6.1: a client certificate for a throwaway key, signed
// through the platform on the context's CA key, with the client profile and
// nothing more, ending at ttl_cert (or the CA's end, if sooner).

func identity(user string, groups ...string) config.K8sIdentity {
	return config.K8sIdentity{User: user, Groups: groups}
}

func parseCred(t *testing.T, c Credential) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	cb, rest := pem.Decode(c.CertPEM)
	if cb == nil || cb.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("CertPEM is one certificate: %q", c.CertPEM)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	kb, rest := pem.Decode(c.KeyPEM)
	if kb == nil || kb.Type != "EC PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("KeyPEM is one EC key: %v", kb)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestIssueProfile(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	now := t0.Add(90 * time.Minute)
	c, err := ca.Issue(p, identity("admin", "system:masters", "devs"), 15*time.Minute, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := parseCred(t, c)
	// Go writes every O= in one multi-valued RDN, a DER SET, so their order
	// is the encoding's; Kubernetes reads them as a set of groups.
	orgs := slices.Sorted(slices.Values(cert.Subject.Organization))
	if cert.Subject.CommonName != "admin" || !slices.Equal(orgs, []string{"devs", "system:masters"}) ||
		len(cert.Subject.OrganizationalUnit) != 0 || len(cert.Subject.Country) != 0 {
		t.Fatalf("subject %v", cert.Subject)
	}
	if !bytes.Equal(cert.RawIssuer, ca.Cert.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, ca.Cert.SubjectKeyId) {
		t.Fatal("issuer and authority key id are the CA's")
	}
	if !cert.NotBefore.Equal(now.Add(-time.Minute)) || !cert.NotAfter.Equal(now.Add(15*time.Minute)) || !c.NotAfter.Equal(cert.NotAfter) {
		t.Fatalf("validity %v – %v (NotAfter %v)", cert.NotBefore, cert.NotAfter, c.NotAfter)
	}
	if cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) || len(cert.UnknownExtKeyUsage) != 0 {
		t.Fatalf("usages: CA=%v ku=%v eku=%v", cert.IsCA, cert.KeyUsage, cert.ExtKeyUsage)
	}
	if len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 || len(cert.CRLDistributionPoints) != 0 || len(cert.OCSPServer) != 0 {
		t.Fatal("no names, no CRL or OCSP")
	}
	if cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() < 100 {
		t.Fatalf("serial %v", cert.SerialNumber)
	}
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 || cert.CheckSignatureFrom(ca.Cert) != nil {
		t.Fatal("signed by the CA with ecdsa-with-SHA256")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("a client chain to the CA: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("not a server certificate")
	}
	pub, _ := cert.PublicKey.(*ecdsa.PublicKey)
	if pub == nil || !pub.Equal(&key.PublicKey) || key.Curve.Params().Name != "P-256" {
		t.Fatal("the key is the certificate's P-256 key")
	}
	// The platform signed the TBS itself (SHA-256 inside), with the CA key.
	if len(p.signed) == 0 || !bytes.Equal(p.signed[len(p.signed)-1], cert.RawTBSCertificate) {
		t.Fatal("Platform.Sign must receive the TBS bytes")
	}
	// A second issue: a fresh key and serial.
	c2, err := ca.Issue(p, identity("admin"), 15*time.Minute, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	cert2, key2 := parseCred(t, c2)
	if key2.Equal(key) || cert2.SerialNumber.Cmp(cert.SerialNumber) == 0 || len(cert2.Subject.Organization) != 0 {
		t.Fatal("every issue has its own key and serial")
	}
}

func TestIssueLifetime(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{config.MinTTLCert, time.Hour} {
		c, err := ca.Issue(p, identity("a"), ttl, t0, 0)
		if err != nil {
			t.Fatal(err)
		}
		if cert, _ := parseCred(t, c); !cert.NotAfter.Equal(t0.Add(ttl)) {
			t.Fatalf("ttl %v: %v", ttl, cert.NotAfter)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Minute, 59 * time.Second, time.Hour + time.Second} {
		if _, err := ca.Issue(p, identity("a"), ttl, t0, 0); err == nil {
			t.Fatalf("ttl %v must be refused", ttl)
		}
	}
	// Sub-second now: the certificate's whole seconds never pass now+ttl.
	odd := t0.Add(1500 * time.Millisecond)
	c, err := ca.Issue(p, identity("a"), 15*time.Minute, odd, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cert, _ := parseCred(t, c); cert.NotAfter.After(odd.Add(15*time.Minute)) || !c.NotAfter.Equal(cert.NotAfter) {
		t.Fatalf("NotAfter %v past %v", cert.NotAfter, odd.Add(15*time.Minute))
	}
}

func TestIssueStopsAtTheCAEnd(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	near := ca.Cert.NotAfter.Add(-5 * time.Minute)
	c, err := ca.Issue(p, identity("a"), 15*time.Minute, near, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cert, _ := parseCred(t, c); !cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("a certificate never outlives its CA: %v vs %v", cert.NotAfter, ca.Cert.NotAfter)
	}
	if _, err := ca.Issue(p, identity("a"), 15*time.Minute, ca.Cert.NotAfter.Add(time.Second), 0); err == nil {
		t.Fatal("an expired CA must not issue")
	}
	if _, err := ca.Issue(p, identity("a"), 15*time.Minute, ca.Cert.NotBefore.Add(-time.Hour), 0); err == nil {
		t.Fatal("a CA not yet valid must not issue")
	}
}

func TestIssueRefusesBadIdentities(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []config.K8sIdentity{identity(""), identity("a b"), identity("a", "x\ny"), identity("a\x00")} {
		if _, err := ca.Issue(p, id, 15*time.Minute, t0, 0); err == nil {
			t.Errorf("%+v must be refused", id)
		}
	}
}

func TestIssuePassesTheApprovalRef(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(p, identity("a"), 15*time.Minute, t0, platform.ApprovalRef(42)); err != nil {
		t.Fatal(err)
	}
	if p.refs[len(p.refs)-1] != 42 {
		t.Fatalf("refs %v", p.refs)
	}
}

func TestIssueRefusesABadSignature(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	p.wrongSig = true
	if c, err := ca.Issue(p, identity("a"), 15*time.Minute, t0, 0); err == nil || c.CertPEM != nil || c.KeyPEM != nil {
		t.Fatal("a signature that does not verify against the CA key mints nothing")
	}
	// An enclave error is returned as it is.
	p.wrongSig = false
	if err := p.Fake.DeleteKey(ca.Handle); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(p, identity("a"), 15*time.Minute, t0, 0); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("a dead CA key: %v", err)
	}
}

func TestCACertProvider(t *testing.T) {
	s, p, _ := newStore(t)
	ca, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	pr := CACertProvider(s, p)
	if pr.Kind() != config.CredentialCACert {
		t.Fatal(pr.Kind())
	}
	ctx := &config.K8sContext{Name: "hydra", Credential: config.CredentialCACert, Identity: identity("admin", "system:masters"),
		TTLCert: 20 * time.Minute, Cluster: cluster.Pin{Server: "https://hydra.example"}}
	c, err := pr.Issue(IssueInput{Context: ctx, Approval: 9, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := parseCred(t, c)
	if cert.Subject.CommonName != "admin" || !cert.NotAfter.Equal(t0.Add(20*time.Minute)) || cert.CheckSignatureFrom(ca.Cert) != nil || p.refs[len(p.refs)-1] != 9 {
		t.Fatalf("%v %v", cert.Subject, cert.NotAfter)
	}
	ctx.Name = "nope"
	if _, err := pr.Issue(IssueInput{Context: ctx, Now: t0}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no CA: %v", err)
	}
	ctx.Name, ctx.Credential = "hydra", "stored"
	if _, err := pr.Issue(IssueInput{Context: ctx, Now: t0}); err == nil {
		t.Fatal("another kind's context must be refused")
	}
}

// Security review: two creates of one name (or of two names
// equal ignoring case) at once make one CA; the other is refused and its
// key deleted.
func TestCAStoreCreateIsSerialised(t *testing.T) {
	s, p, v := newStore(t)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, n := range []string{"hydra", "HYDRA"} {
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
		case !errors.Is(err, ErrExists):
			t.Fatal(err)
		}
	}
	names, _ := v.List(VaultPrefix)
	if ok != 1 || len(names) != 1 {
		t.Fatalf("one CA: %d made, %v", ok, names)
	}
	_ = p
}

// Spec review: an item under k8s-ca/ whose name nazar can't make
// is listed as broken (main spec 9: listed, never used), in name order.
func TestCAStoreListsForeignItems(t *testing.T) {
	s, _, v := newStore(t)
	if _, err := s.Create("zeta", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	_ = v.Vault.Put("k8s-ca/a:b", []byte("{}"))
	if _, err := s.Create("alpha", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, i := range list {
		names = append(names, i.Name)
		if i.Name == "a:b" && !i.Broken {
			t.Fatal("a foreign item is broken")
		}
	}
	if strings.Join(names, ",") != "a:b,alpha,zeta" {
		t.Fatalf("listed in order, foreign items included: %v", names)
	}
	if _, err := s.Get("a:b"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Get of a foreign name: %v", err)
	}
}

func FuzzParseExecInfo(f *testing.F) {
	f.Add(`{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"cluster":{"server":"https://a","certificate-authority-data":"QUJD"}}}`)
	f.Add(`{"apiVersion":"client.authentication.k8s.io/v1beta1","kind":"ExecCredential"}`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, raw string) {
		info, err := ParseExecInfo(raw)
		var u *UsageError
		if err != nil && (!errors.As(err, &u) || info != nil) {
			t.Fatalf("an error is a usage error with no info: %v", err)
		}
		if err != nil && strings.Contains(err.Error(), raw) && len(raw) > 8 {
			t.Fatal("the error echoes the input")
		}
	})
}
