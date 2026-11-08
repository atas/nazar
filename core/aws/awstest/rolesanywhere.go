// Package awstest is a fake IAM Roles Anywhere endpoint for tests (aws
// design 11.2): an httptest TLS server that checks CreateSession requests
// as AWS documents it and answers with fixed fake credentials, or with
// AWS's error shapes on demand.
//
// It is written from AWS's signing guide
// (https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html),
// not from nazar's signer, and never imports it (TestFakeIsIndependent):
// a fake that shared the signer's code would accept the signer's mistakes.
package awstest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fake credentials every accepted request gets. Tests scan audit lines,
// logs and problems for them: none may ever appear there.
const (
	AccessKeyID     = "ASIAFAKEAWSTESTKEY01"
	SecretAccessKey = "fake/Secret+Access+Key/awstest0000000000"
	SessionToken    = "FakeSessionTokenAwstest//Zm9vYmFyYmF6+FakeSessionTokenAwstest="
)

const algorithm = "AWS4-X509-ECDSA-SHA256"

// Seen is one request the fake received.
type Seen struct {
	// Err is why the request was refused; nil when it was accepted.
	Err error
	// Serial is the decimal serial of the X-Amz-X509 certificate, and
	// SerialHex the same as 32 hex digits (the role session name).
	Serial, SerialHex string
	// CN is the certificate's subject CN; Issuer its issuer's.
	CN, Issuer string
	// InBody reports whether the parameters came in the body (else the
	// query); Params are the parameters, from wherever they came.
	InBody bool
	Params Params
	// Signed is the request's SignedHeaders; UserAgent its user-agent.
	Signed    []string
	UserAgent string
}

// Params are CreateSession's parameters.
type Params struct {
	DurationSeconds int    `json:"durationSeconds,omitempty"`
	ProfileArn      string `json:"profileArn"`
	RoleArn         string `json:"roleArn"`
	TrustAnchorArn  string `json:"trustAnchorArn"`
	RoleSessionName string `json:"roleSessionName,omitempty"`
}

// Server is a running fake.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	anchors  *x509.CertPool
	now      func() time.Time
	region   string
	profile  time.Duration // the profile's durationSeconds
	reply    func(w http.ResponseWriter, s Seen) bool
	seen     []Seen
	accepted int
}

// Start runs a fake for region whose trust anchor bundle is anchorPEM (one
// or two PEM certificates, as a trust anchor holds). It stops at test
// cleanup.
func Start(t *testing.T, region string, anchorPEM []byte) *Server {
	t.Helper()
	s := &Server{now: time.Now, region: region, profile: time.Hour}
	s.SetAnchors(anchorPEM)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// SetAnchors replaces the trust anchor bundle.
func (s *Server) SetAnchors(anchorPEM []byte) {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(anchorPEM)
	s.mu.Lock()
	s.anchors = pool
	s.mu.Unlock()
}

// SetClock sets the fake's clock (default time.Now).
func (s *Server) SetClock(now func() time.Time) {
	s.mu.Lock()
	s.now = now
	s.mu.Unlock()
}

// SetProfileDuration sets the profile's durationSeconds: the session lasts
// the smaller of it and the request's.
func (s *Server) SetProfileDuration(d time.Duration) {
	s.mu.Lock()
	s.profile = d
	s.mu.Unlock()
}

// SetReply makes the fake answer an accepted request with fn instead of
// its credentials, when fn returns true (an error shape, a slow or odd
// reply). nil restores the default.
func (s *Server) SetReply(fn func(w http.ResponseWriter, s Seen) bool) {
	s.mu.Lock()
	s.reply = fn
	s.mu.Unlock()
}

// Fail makes the fake answer every accepted request with AWS's error shape:
// status, the x-amzn-ErrorType code and a JSON message.
func (s *Server) Fail(status int, code, message string) {
	s.SetReply(func(w http.ResponseWriter, _ Seen) bool {
		WriteError(w, status, code, message)
		return true
	})
}

// WriteError writes an error as Roles Anywhere does (restJson1).
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amzn-Errortype", code+":http://internal.amazon.com/coral/com.amazonaws.rolesanywhere/")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

// Seen returns every request received, in order.
func (s *Server) Seen() []Seen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Seen(nil), s.seen...)
}

// Accepted is how many requests passed every check.
func (s *Server) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// RootCAs is a pool with the fake's serving certificate.
func (s *Server) RootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return pool
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	anchors, now, region, profile, reply := s.anchors, s.now(), s.region, s.profile, s.reply
	s.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	seen := Seen{UserAgent: r.Header.Get("User-Agent")}
	if err == nil {
		err = verify(r, body, anchors, now, region, &seen)
	}
	s.mu.Lock()
	seen.Err = err
	s.seen = append(s.seen, seen)
	if err == nil {
		s.accepted++
	}
	s.mu.Unlock()
	if err != nil {
		WriteError(w, http.StatusForbidden, "AccessDeniedException", err.Error())
		return
	}
	if reply != nil && reply(w, seen) {
		return
	}
	d := profile
	if rd := time.Duration(seen.Params.DurationSeconds) * time.Second; rd > 0 && rd < d {
		d = rd
	}
	name := seen.SerialHex
	if seen.Params.RoleSessionName != "" {
		name = seen.Params.RoleSessionName
	}
	role := seen.Params.RoleArn
	account, roleName := "", role
	if p := strings.SplitN(role, ":", 6); len(p) == 6 {
		account, roleName = p[4], strings.TrimPrefix(p[5], "role/")
	}
	out := map[string]any{
		"credentialSet": []any{map[string]any{
			"assumedRoleUser": map[string]string{
				"arn":           "arn:aws:sts::" + account + ":assumed-role/" + roleName + "/" + name,
				"assumedRoleId": "AROAFAKEAWSTEST:" + name,
			},
			"credentials": map[string]string{
				"accessKeyId":     AccessKeyID,
				"secretAccessKey": SecretAccessKey,
				"sessionToken":    SessionToken,
				"expiration":      now.Add(d).UTC().Format(time.RFC3339),
			},
			"packedPolicySize": 0,
			"roleArn":          role,
			"sourceIdentity":   "CN=" + seen.CN,
		}},
		"subjectArn": "arn:aws:rolesanywhere:" + region + ":" + account + ":subject/41cl0bae-6783-40d4-ab20-65dc5d922e45",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}

// required are the headers every request must sign: the ones CloudTrail's
// missingSignedHeaders names.
var required = []string{"content-type", "host", "x-amz-date", "x-amz-x509"}

// verify checks r as Roles Anywhere does, filling seen as it goes.
func verify(r *http.Request, body []byte, anchors *x509.CertPool, now time.Time, region string, seen *Seen) error {
	if r.Method != http.MethodPost || r.URL.Path != "/sessions" {
		return fmt.Errorf("not POST /sessions: %s %s", r.Method, r.URL.Path)
	}
	// The Authorization header: algorithm, Credential, SignedHeaders, Signature.
	auth := r.Header.Get("Authorization")
	alg, rest, ok := strings.Cut(auth, " ")
	if !ok || alg != algorithm {
		return fmt.Errorf("algorithm %q, want %s", alg, algorithm)
	}
	fields := map[string]string{}
	for _, f := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(f), "=")
		if !ok {
			return fmt.Errorf("malformed Authorization field %q", f)
		}
		if _, dup := fields[k]; dup {
			return fmt.Errorf("Authorization repeats %s", k)
		}
		fields[k] = v
	}
	cred, signedList, sigHex := fields["Credential"], fields["SignedHeaders"], fields["Signature"]
	if cred == "" || signedList == "" || sigHex == "" || len(fields) != 3 {
		return errors.New("Authorization needs exactly Credential, SignedHeaders and Signature")
	}
	signed := strings.Split(signedList, ";")
	seen.Signed = signed
	if !sort.StringsAreSorted(signed) {
		return errors.New("SignedHeaders is not sorted")
	}
	for _, h := range required {
		if !contains(signed, h) {
			return fmt.Errorf("header %s is not signed", h)
		}
	}
	// The certificate, from X-Amz-X509.
	der, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Amz-X509"))
	if err != nil {
		return fmt.Errorf("X-Amz-X509 is not base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("X-Amz-X509 is not a certificate: %v", err)
	}
	seen.Serial = cert.SerialNumber.String()
	seen.SerialHex = fmt.Sprintf("%032x", cert.SerialNumber)
	seen.CN, seen.Issuer = cert.Subject.CommonName, cert.Issuer.CommonName
	if r.Header.Get("X-Amz-X509-Chain") != "" {
		return errors.New("a chain was sent, and the fake's anchors are the issuers themselves")
	}
	// The credential scope: <serial>/<date>/<region>/rolesanywhere/aws4_request.
	scope := strings.Split(cred, "/")
	if len(scope) != 5 {
		return fmt.Errorf("Credential %q is not serial/date/region/service/aws4_request", cred)
	}
	if scope[0] != seen.Serial {
		return fmt.Errorf("Credential names serial %s, the certificate has %s", scope[0], seen.Serial)
	}
	amzDate := r.Header.Get("X-Amz-Date")
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return fmt.Errorf("X-Amz-Date %q: %v", amzDate, err)
	}
	if d := now.Sub(t); d > 5*time.Minute || d < -5*time.Minute {
		return fmt.Errorf("X-Amz-Date %s is %s from the server's clock", amzDate, d)
	}
	if scope[1] != t.Format("20060102") || scope[2] != region || scope[3] != "rolesanywhere" || scope[4] != "aws4_request" {
		return fmt.Errorf("credential scope %s does not match %s/%s/rolesanywhere/aws4_request", strings.Join(scope[1:], "/"), t.Format("20060102"), region)
	}
	// The canonical request, rebuilt from what arrived.
	var canon strings.Builder
	canon.WriteString(r.Method + "\n")
	canon.WriteString(r.URL.EscapedPath() + "\n")
	canon.WriteString(canonicalQuery(r.URL.Query()) + "\n")
	for _, h := range signed {
		var v string
		if h == "host" {
			v = r.Host
		} else {
			vs := r.Header.Values(h)
			if len(vs) == 0 {
				return fmt.Errorf("signed header %s is missing", h)
			}
			trimmed := make([]string, len(vs))
			for i, x := range vs {
				trimmed[i] = strings.Join(strings.Fields(x), " ")
			}
			v = strings.Join(trimmed, ",")
		}
		canon.WriteString(h + ":" + v + "\n")
	}
	canon.WriteString("\n" + signedList + "\n")
	sum := sha256.Sum256(body)
	canon.WriteString(hex.EncodeToString(sum[:]))
	creq := sha256.Sum256([]byte(canon.String()))
	sts := algorithm + "\n" + amzDate + "\n" + strings.Join(scope[1:], "/") + "\n" + hex.EncodeToString(creq[:])
	// The signature: ECDSA over SHA-256 of the string to sign, DER, hex.
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("Signature is not hex")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("the certificate's key is not ECDSA, and the algorithm is " + algorithm)
	}
	digest := sha256.Sum256([]byte(sts))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("the signature does not verify")
	}
	// The certificate, against the trust anchor at the fake's clock.
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 && cert.SignatureAlgorithm != x509.ECDSAWithSHA384 &&
		cert.SignatureAlgorithm != x509.SHA256WithRSA && cert.SignatureAlgorithm != x509.SHA384WithRSA {
		return fmt.Errorf("the certificate is signed with %s", cert.SignatureAlgorithm)
	}
	if cert.IsCA {
		return errors.New("the certificate is a CA")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("the certificate's key usage has no digital signature")
	}
	if cert.Subject.String() == "" {
		return errors.New("the certificate has no subject")
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: anchors, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("the certificate does not chain to the trust anchor: %v", err)
	}
	// The parameters: in the body or in the query.
	if len(body) > 0 {
		seen.InBody = true
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&seen.Params); err != nil {
			return fmt.Errorf("ValidationException: the body: %v", err)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			return errors.New("a JSON body needs content-type application/json")
		}
	} else {
		q := r.URL.Query()
		seen.Params = Params{ProfileArn: q.Get("profileArn"), RoleArn: q.Get("roleArn"), TrustAnchorArn: q.Get("trustAnchorArn"), RoleSessionName: q.Get("roleSessionName")}
		if v := q.Get("durationSeconds"); v != "" {
			if seen.Params.DurationSeconds, err = strconv.Atoi(v); err != nil {
				return fmt.Errorf("ValidationException: durationSeconds %q", v)
			}
		}
	}
	if seen.Params.ProfileArn == "" || seen.Params.RoleArn == "" || seen.Params.TrustAnchorArn == "" {
		return errors.New("ValidationException: profileArn, roleArn and trustAnchorArn are required")
	}
	if d := seen.Params.DurationSeconds; d != 0 && (d < 900 || d > 43200) {
		return fmt.Errorf("ValidationException: durationSeconds %d", d)
	}
	return nil
}

// canonicalQuery is SigV4's: names and values URI-encoded, sorted by name
// then value, joined with &.
func canonicalQuery(q url.Values) string {
	var parts []string
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// uriEncode encodes every byte but the unreserved A-Z a-z 0-9 - _ . ~, as
// %XX with upper-case hex.
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// CertPEM is der as PEM, for tests that build a bundle.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
