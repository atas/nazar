package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// K8s design 2.2: check 2 compares the cluster a request names
// with the one config recorded, one canonical way.

func TestNormalizeServer(t *testing.T) {
	for in, want := range map[string]string{
		"https://hydra.example:16443":             "https://hydra.example:16443",
		"https://HYDRA.Example:16443/":            "https://hydra.example:16443",
		"HTTPS://hydra.example":                   "https://hydra.example",
		"https://hydra.example:443":               "https://hydra.example",
		"https://hydra.example:443/":              "https://hydra.example",
		"https://rancher.example/k8s/clusters/c1": "https://rancher.example/k8s/clusters/c1",
		"https://rancher.example/k8s/Clusters/c1": "https://rancher.example/k8s/Clusters/c1", // the path is byte for byte
		"https://10.0.0.9:6443":                   "https://10.0.0.9:6443",
		"https://[::1]:6443":                      "https://[::1]:6443",
	} {
		got, err := NormalizeServer(in)
		if err != nil || got != want {
			t.Errorf("NormalizeServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "hydra.example", "http://hydra.example", "https://", "https://user@hydra.example",
		"https://user:pw@hydra.example", "https://hydra.example/?x=1", "https://hydra.example/#f",
		"https://hydra.example?", "ftp://hydra.example", "https://hydra example", "https://hydra.example:99999",
		"https://hydra.example:port", "https://hydra.example\n", "//hydra.example",
		// Security review: a host that is not ASCII (a homoglyph,
		// a bidi override) is refused; IDNs are written in punycode.
		"https://hydr\u0430.example", "https://hydra.example\u202e", "https://hydra.ex\u00e4mple/",
	} {
		if got, err := NormalizeServer(bad); err == nil {
			t.Errorf("NormalizeServer(%q) = %q, want an error", bad, got)
		}
	}
}

func testCert(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }

func TestCAHash(t *testing.T) {
	a, b := testCert(t, "a"), testCert(t, "b")
	one, err := CAHash(pemOf(a))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(a)
	if one != hex.EncodeToString(sum[:]) {
		t.Fatalf("one certificate: the hash is SHA-256 of its DER, got %s", one)
	}
	ab, err := CAHash(append(pemOf(a), pemOf(b)...))
	if err != nil {
		t.Fatal(err)
	}
	ba, err := CAHash(append(pemOf(b), pemOf(a)...))
	if err != nil || ab != ba {
		t.Fatalf("block order must not matter: %s %s %v", ab, ba, err)
	}
	if ab == one {
		t.Fatal("a two-CA bundle must not hash like one of its CAs")
	}
	messy := "# the cluster CA\n\n" + strings.ReplaceAll(string(pemOf(b)), "\n", "\r\n") + "comment between blocks\n" + string(pemOf(a)) + "\n\n"
	if got, err := CAHash([]byte(messy)); err != nil || got != ab {
		t.Fatalf("whitespace and comments must not matter: %s %v", got, err)
	}
	for name, bad := range map[string][]byte{
		"empty":             nil,
		"no block":          []byte("not a certificate"),
		"a key block":       pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
		"junk certificate":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x03, 1, 2, 3}}),
		"trailing DER":      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: append(append([]byte{}, a...), 0)}),
		"a good and a junk": append(pemOf(a), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})...),
		"headers":           pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a}),
	} {
		if got, err := CAHash(bad); err == nil {
			t.Errorf("%s: CAHash = %s, want an error", name, got)
		}
	}
}

func TestPinOfAndMatch(t *testing.T) {
	ca := pemOf(testCert(t, "ca"))
	other := pemOf(testCert(t, "other"))
	info := Info{Server: "https://Hydra.example:16443/", CAData: ca, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"}
	pin, err := PinOf(info)
	if err != nil {
		t.Fatal(err)
	}
	if pin.Server != "https://hydra.example:16443" || len(pin.CASHA256) != 64 || pin.TLSServerName != "hydra" || pin.ProxyURL != "socks5://localhost:1080" {
		t.Fatalf("%+v", pin)
	}
	if err := pin.Match(info); err != nil {
		t.Fatalf("the request it was recorded from must match: %v", err)
	}
	for name, got := range map[string]Info{
		"server":          {Server: "https://10.0.0.9:16443", CAData: ca, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
		"port":            {Server: "https://hydra.example:6443", CAData: ca, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
		"path":            {Server: "https://hydra.example:16443/x", CAData: ca, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
		"ca":              {Server: info.Server, CAData: other, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
		"ca bundle":       {Server: info.Server, CAData: append(append([]byte{}, ca...), other...), TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
		"no ca":           {Server: info.Server, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
		"tls server name": {Server: info.Server, CAData: ca, ProxyURL: "socks5://localhost:1080"},
		"proxy":           {Server: info.Server, CAData: ca, TLSServerName: "hydra"},
		"insecure":        {Server: info.Server, CAData: ca, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080", Insecure: true},
		"bad server":      {Server: "http://hydra.example:16443", CAData: ca, TLSServerName: "hydra", ProxyURL: "socks5://localhost:1080"},
	} {
		if err := pin.Match(got); err == nil {
			t.Errorf("%s: a different cluster matched", name)
		}
	}
	if _, err := PinOf(Info{Server: info.Server, CAData: ca, Insecure: true}); err == nil {
		t.Error("an insecure cluster must not be recorded")
	}
	if _, err := PinOf(Info{Server: info.Server}); err == nil {
		t.Error("a cluster without a CA must not be recorded")
	}
}

// The values a mismatch names come from KUBERNETES_EXEC_INFO, which any
// kubeconfig writer controls: they are quoted and cut, never raw.
func TestMismatchTextIsQuotedAndShort(t *testing.T) {
	ca := pemOf(testCert(t, "ca"))
	pin, err := PinOf(Info{Server: "https://hydra.example:16443", CAData: ca})
	if err != nil {
		t.Fatal(err)
	}
	hostile := "https://evil.example/\x1b[2J‮" + strings.Repeat("a", 600)
	err = pin.Match(Info{Server: hostile, CAData: ca})
	if err == nil {
		t.Fatal("matched")
	}
	msg := err.Error()
	if strings.ContainsAny(msg, "\x1b‮") || len(msg) > 700 {
		t.Fatalf("raw or unbounded: %q (%d bytes)", msg, len(msg))
	}
	if !strings.Contains(msg, "https://hydra.example:16443") {
		t.Fatalf("the expected server must be named: %q", msg)
	}
	if d := Display(strings.Repeat("x", 1000)); len(d) > 260 {
		t.Fatalf("Display must cut to 256 bytes: %d", len(d))
	}
}
