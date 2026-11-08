// Package k8stest is a fake Kubernetes API server for tests (k8s design 11):
// TLS from a CA of its own, client certificates checked against the client
// CA a test gives it, and a record of every certificate it saw, so a test
// can prove a credential reached the server only when nazar said so.
package k8stest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Seen is one request the server received.
type Seen struct {
	Path string
	// CN and O are the verified client certificate's subject; Verified is
	// false when the request carried no certificate the client CA accepts.
	CN       string
	O        []string
	Verified bool
	// Presented is true when the client sent any certificate at all.
	Presented bool
}

// Server is a running fake API server.
type Server struct {
	URL   string
	CAPEM []byte // the CA that signed the serving certificate: the kubeconfig's certificate-authority-data

	srv  *httptest.Server
	mu   sync.Mutex
	seen []Seen
	pool *x509.CertPool // the client CAs, guarded by mu
}

// Start runs a server whose serving certificate (for 127.0.0.1) comes from a
// fresh CA, and which accepts client certificates that chain to clientCA
// (nil: none). Every request with a verified client certificate gets 200 and
// a pod list naming who it saw; the rest get 401. It stops at test cleanup.
func Start(t *testing.T, clientCA *x509.Certificate) *Server {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "k8stest serving CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "kube-apiserver"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool: x509.NewCertPool()}
	if clientCA != nil {
		s.pool.AddCert(clientCA)
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.srv.TLS = base.Clone()
	s.srv.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		s.mu.Lock()
		c.ClientCAs = s.pool.Clone()
		s.mu.Unlock()
		return c, nil
	}
	s.srv.StartTLS()
	s.URL = s.srv.URL
	t.Cleanup(s.srv.Close)
	return s
}

// TrustClientCA adds a client CA from the next connection on: a cluster
// whose client CA bundle gained a nazar CA (the node steps).
func (s *Server) TrustClientCA(ca *x509.Certificate) {
	s.mu.Lock()
	s.pool.AddCert(ca)
	s.mu.Unlock()
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	seen := Seen{Path: r.URL.Path}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		seen.Presented = true
		if len(r.TLS.VerifiedChains) > 0 {
			c := r.TLS.PeerCertificates[0]
			seen.Verified, seen.CN, seen.O = true, c.Subject.CommonName, c.Subject.Organization
		}
	}
	s.mu.Lock()
	s.seen = append(s.seen, seen)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !seen.Verified {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Unauthorized", "code": 401})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"kind": "PodList", "apiVersion": "v1",
		"items": []any{map[string]any{"metadata": map[string]any{"name": "web-1", "namespace": "default",
			"annotations": map[string]string{"k8stest/user": seen.CN}}}},
	})
}

// Seen returns every request so far.
func (s *Server) Seen() []Seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Seen(nil), s.seen...)
}
