package awstest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The fake must not share code with nazar's signer (aws design 11.2): it
// imports nothing of nazar at all.
func TestFakeIsIndependent(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, imp := range strings.Fields(string(out)) {
		if strings.Contains(imp, "nazar") {
			t.Fatalf("awstest imports %s", imp)
		}
	}
}

// A CA and a leaf made here with the standard library, and a request
// signed by the steps of the AWS guide, written out in this test.

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) ca {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return ca{c, k, CertPEM(der)}
}

func (c ca) leaf(t *testing.T, notBefore, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{SerialNumber: serial.Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "you-nazar"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &k.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, k
}

type signed struct {
	method, path, query string
	headers             map[string]string // sent, by canonical name
	body                []byte
}

const (
	anchorArn  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
	profileArn = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
	roleArn    = "arn:aws:iam::123456789012:role/dev"
)

// sign builds a request as the guide's steps say, signing names (sorted),
// with alg in the Authorization header.
func sign(t *testing.T, host string, cert *x509.Certificate, key *ecdsa.PrivateKey, at time.Time, body []byte, query string, names []string, alg string) signed {
	t.Helper()
	date := at.UTC().Format("20060102T150405Z")
	h := map[string]string{
		"Content-Type": "application/json",
		"Host":         host,
		"X-Amz-Date":   date,
		"X-Amz-X509":   base64.StdEncoding.EncodeToString(cert.Raw),
	}
	canon := "POST\n/sessions\n" + query + "\n"
	for _, n := range names {
		canon += n + ":" + h[http.CanonicalHeaderKey(n)] + "\n"
	}
	sum := sha256.Sum256(body)
	canon += "\n" + strings.Join(names, ";") + "\n" + hex.EncodeToString(sum[:])
	creq := sha256.Sum256([]byte(canon))
	scope := date[:8] + "/us-east-1/rolesanywhere/aws4_request"
	sts := alg + "\n" + date + "\n" + scope + "\n" + hex.EncodeToString(creq[:])
	d := sha256.Sum256([]byte(sts))
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	h["Authorization"] = alg + " Credential=" + cert.SerialNumber.String() + "/" + scope + ", SignedHeaders=" + strings.Join(names, ";") + ", Signature=" + hex.EncodeToString(sig)
	delete(h, "Host")
	return signed{method: "POST", path: "/sessions", query: query, headers: h, body: body}
}

func (s *Server) send(t *testing.T, r signed) (int, map[string]any) {
	t.Helper()
	u := s.URL + r.path
	if r.query != "" {
		u += "?" + r.query
	}
	req, _ := http.NewRequest(r.method, u, bytes.NewReader(r.body))
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

var allHeaders = []string{"content-type", "host", "x-amz-date", "x-amz-x509"}

func body(t *testing.T) []byte {
	b, _ := json.Marshal(Params{DurationSeconds: 3600, ProfileArn: profileArn, RoleArn: roleArn, TrustAnchorArn: anchorArn})
	return b
}

func TestFakeAcceptsAGuideRequest(t *testing.T) {
	c := newCA(t, "nazar aws CA dev")
	s := Start(t, "us-east-1", c.pem)
	cert, key := c.leaf(t, time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute))
	host := strings.TrimPrefix(s.URL, "https://")
	code, out := s.send(t, sign(t, host, cert, key, time.Now(), body(t), "", allHeaders, algorithm))
	if code != http.StatusCreated {
		t.Fatalf("%d %v", code, out)
	}
	seen := s.Seen()[0]
	if !seen.InBody || seen.Params.RoleArn != roleArn || seen.Serial != cert.SerialNumber.String() || seen.CN != "you-nazar" || seen.Issuer != "nazar aws CA dev" {
		t.Fatalf("%+v", seen)
	}
	cs := out["credentialSet"].([]any)[0].(map[string]any)
	creds := cs["credentials"].(map[string]any)
	if creds["accessKeyId"] != AccessKeyID || creds["secretAccessKey"] != SecretAccessKey || creds["sessionToken"] != SessionToken || cs["roleArn"] != roleArn {
		t.Fatalf("%v", cs)
	}
	if !strings.HasSuffix(cs["assumedRoleUser"].(map[string]any)["arn"].(string), "assumed-role/dev/"+seen.SerialHex) {
		t.Fatalf("the session is named for the serial: %v", cs)
	}
	// The parameters in the query, as AWS's helper sends them, are accepted too.
	q := "durationSeconds=900&profileArn=" + uriEncode(profileArn) + "&roleArn=" + uriEncode(roleArn) + "&trustAnchorArn=" + uriEncode(anchorArn)
	if code, out := s.send(t, sign(t, host, cert, key, time.Now(), nil, q, allHeaders, algorithm)); code != http.StatusCreated {
		t.Fatalf("query: %d %v", code, out)
	}
	if seen := s.Seen()[1]; seen.InBody || seen.Params.DurationSeconds != 900 {
		t.Fatalf("query: %+v", seen)
	}
}

func TestFakeRefuses(t *testing.T) {
	c := newCA(t, "nazar aws CA dev")
	other := newCA(t, "nazar aws CA dev")
	s := Start(t, "us-east-1", c.pem)
	host := strings.TrimPrefix(s.URL, "https://")
	now := time.Now()
	cert, key := c.leaf(t, now.Add(-5*time.Minute), now.Add(5*time.Minute))
	good := func() signed { return sign(t, host, cert, key, now, body(t), "", allHeaders, algorithm) }
	rsaAlg := "AWS4-X509-RSA-SHA256"
	ocert, okey := other.leaf(t, now.Add(-5*time.Minute), now.Add(5*time.Minute))
	ecert, ekey := c.leaf(t, now.Add(-20*time.Minute), now.Add(-10*time.Minute))
	cases := map[string]func() signed{
		"content-type changed": func() signed { r := good(); r.headers["Content-Type"] = "application/x-amz-json-1.1"; return r },
		"x-amz-date changed": func() signed {
			r := good()
			r.headers["X-Amz-Date"] = now.Add(time.Second).UTC().Format("20060102T150405Z")
			return r
		},
		"x-amz-x509 changed": func() signed {
			r := good()
			r.headers["X-Amz-X509"] = base64.StdEncoding.EncodeToString(ocert.Raw)
			return r
		},
		"host changed": func() signed {
			return sign(t, "rolesanywhere.us-east-1.amazonaws.com", cert, key, now, body(t), "", allHeaders, algorithm)
		},
		"body changed": func() signed {
			r := good()
			r.body = bytes.Replace(r.body, []byte("role/dev"), []byte("role/admin"), 1)
			return r
		},
		"date 6 minutes off": func() signed {
			return sign(t, host, cert, key, now.Add(-6*time.Minute), body(t), "", allHeaders, algorithm)
		},
		"a leaf of another CA": func() signed { return sign(t, host, ocert, okey, now, body(t), "", allHeaders, algorithm) },
		"an expired leaf":      func() signed { return sign(t, host, ecert, ekey, now, body(t), "", allHeaders, algorithm) },
		"RSA algorithm":        func() signed { return sign(t, host, cert, key, now, body(t), "", allHeaders, rsaAlg) },
		"content-type unsigned": func() signed {
			return sign(t, host, cert, key, now, body(t), "", []string{"host", "x-amz-date", "x-amz-x509"}, algorithm)
		},
		"x-amz-x509 unsigned": func() signed {
			return sign(t, host, cert, key, now, body(t), "", []string{"content-type", "host", "x-amz-date"}, algorithm)
		},
		"another serial in Credential": func() signed {
			r := good()
			r.headers["Authorization"] = strings.Replace(r.headers["Authorization"], "Credential="+cert.SerialNumber.String(), "Credential=1", 1)
			return r
		},
		"no Authorization": func() signed { r := good(); delete(r.headers, "Authorization"); return r },
	}
	for name, mk := range cases {
		if code, out := s.send(t, mk()); code != http.StatusForbidden {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if s.Accepted() != 0 {
		t.Fatalf("accepted %d", s.Accepted())
	}
	// An RSA key with the ECDSA algorithm string.
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "you-nazar"}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Minute), KeyUsage: x509.KeyUsageDigitalSignature}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &rk.PublicKey, c.key)
	rc, _ := x509.ParseCertificate(der)
	r := good()
	r.headers["X-Amz-X509"] = base64.StdEncoding.EncodeToString(rc.Raw)
	if code, _ := s.send(t, r); code != http.StatusForbidden {
		t.Fatalf("RSA key: %d", code)
	}
	// And the good request still passes: the cases above failed for their change.
	if code, out := s.send(t, good()); code != http.StatusCreated {
		t.Fatalf("good: %d %v", code, out)
	}
}

func TestFakeErrorShapes(t *testing.T) {
	c := newCA(t, "nazar aws CA dev")
	s := Start(t, "us-east-1", c.pem)
	s.Fail(http.StatusTooManyRequests, "ThrottlingException", "Rate exceeded")
	cert, key := c.leaf(t, time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute))
	code, out := s.send(t, sign(t, strings.TrimPrefix(s.URL, "https://"), cert, key, time.Now(), body(t), "", allHeaders, algorithm))
	if code != http.StatusTooManyRequests || out["message"] != "Rate exceeded" {
		t.Fatalf("%d %v", code, out)
	}
}
