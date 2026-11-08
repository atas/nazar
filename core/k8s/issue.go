package k8s

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// backdate is how far before the request a certificate starts, for clocks
// a little behind (k8s design 6.1).
const backdate = time.Minute

// Credential is what a provider returns (k8s design 4): a certificate and
// its key as PEM, and the certificate's own end. The caller clears KeyPEM
// once it is sent.
type Credential struct {
	CertPEM  []byte
	KeyPEM   []byte
	NotAfter time.Time
}

// Issue mints a client certificate for id (k8s design 6.1): a fresh P-256
// key made here, CN=id.User and one O= per group, issued by the CA's
// certificate, valid from now-1m to min(now+ttl, the CA's end), digital
// signature and client auth only, not a CA. The certificate engine signs it
// by Platform.Sign on the CA key with ref and checks it against the CA
// before it is returned. ttl must be within config's ttl_cert range; the CA
// must be valid at now.
func (ca *CA) Issue(p platform.Platform, id config.K8sIdentity, ttl time.Duration, now time.Time, ref platform.ApprovalRef) (Credential, error) {
	if ttl < config.MinTTLCert || ttl > config.MaxTTLCert {
		return Credential{}, fmt.Errorf("k8s: ttl_cert %s is outside %s..%s", ttl, config.MinTTLCert, config.MaxTTLCert)
	}
	if !config.ValidK8sSubject(id.User) {
		return Credential{}, errors.New("k8s: invalid identity user")
	}
	for _, g := range id.Groups {
		if !config.ValidK8sSubject(g) {
			return Credential{}, errors.New("k8s: invalid identity group")
		}
	}
	now = now.UTC()
	leaf, err := ca.CA.Issue(p, certs.LeafSpec{
		CN:        id.User,
		O:         id.Groups,
		NotBefore: now.Add(-backdate),
		NotAfter:  now.Add(ttl),
	}, now, ref)
	if err != nil {
		return Credential{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leaf.Key)
	if err != nil {
		return Credential{}, err
	}
	defer clear(keyDER)
	return Credential{
		CertPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Cert.Raw}),
		KeyPEM:   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		NotAfter: leaf.Cert.NotAfter,
	}, nil
}
