package aws

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/aws/awstest"
	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

const (
	anchor  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
	profile = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
	role    = "arn:aws:iam::123456789012:role/dev"
)

func entry() *config.AWSEntry {
	return &config.AWSEntry{Name: "dev", Identity: config.AWSIdentity{User: "you-nazar"}, TrustAnchorArn: anchor, ProfileArn: profile,
		RoleArn: role, Region: "us-east-1", Account: "123456789012", Duration: time.Hour}
}

type rig struct {
	p    *fake.Fake
	ca   *certs.CA
	fake *awstest.Server
	c    *Client
}

func newRig(t *testing.T) *rig {
	t.Helper()
	p := fake.New(time.Now())
	s := NewCAStore(p, fake.NewVault(), time.Now)
	ca, err := s.Create("dev", platform.AccessAfterFirstUnlock)
	if err != nil {
		t.Fatal(err)
	}
	f := awstest.Start(t, "us-east-1", ca.CertPEM())
	return &rig{p: p, ca: ca, fake: f, c: &Client{Endpoint: f.URL, RootCAs: f.RootCAs(), UserAgent: "nazar/test"}}
}

func (r *rig) leaf(t *testing.T, now time.Time) certs.Leaf {
	t.Helper()
	serial, err := certs.NewSerial()
	if err != nil {
		t.Fatal(err)
	}
	l, err := Issue(r.ca, r.p, "you-nazar", serial, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// The fixed inputs of the guide's shape: no query, the four headers, the
// body's hash (aws design 11.3).
func TestCanonicalRequestAndStringToSign(t *testing.T) {
	b, err := requestBody(entry())
	if err != nil {
		t.Fatal(err)
	}
	wantBody := `{"durationSeconds":3600,"profileArn":"` + profile + `","roleArn":"` + role + `","trustAnchorArn":"` + anchor + `"}`
	if string(b) != wantBody {
		t.Fatalf("body %s", b)
	}
	sum := sha256.Sum256(b)
	canon := canonicalRequest("rolesanywhere.us-east-1.amazonaws.com", "20261031T120000Z", "MIIB", b)
	want := "POST\n/sessions\n\n" +
		"content-type:application/json\nhost:rolesanywhere.us-east-1.amazonaws.com\nx-amz-date:20261031T120000Z\nx-amz-x509:MIIB\n" +
		"\ncontent-type;host;x-amz-date;x-amz-x509\n" + hex.EncodeToString(sum[:])
	if canon != want {
		t.Fatalf("canonical request:\n%s\nwant:\n%s", canon, want)
	}
	creq := sha256.Sum256([]byte(want))
	sts := stringToSign("20261031T120000Z", "us-east-1", canon)
	if sts != "AWS4-X509-ECDSA-SHA256\n20261031T120000Z\n20261031/us-east-1/rolesanywhere/aws4_request\n"+hex.EncodeToString(creq[:]) {
		t.Fatalf("string to sign:\n%s", sts)
	}
	if a := authorization("123", "20261031T120000Z", "us-east-1", "ab"); a != "AWS4-X509-ECDSA-SHA256 Credential=123/20261031/us-east-1/rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=ab" {
		t.Fatal(a)
	}
}

func TestEverySessionPassesTheFake(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 5; i++ {
		now := time.Now()
		leaf := r.leaf(t, now)
		s, err := r.c.CreateSession(context.Background(), entry(), leaf, now)
		if err != nil {
			t.Fatal(err, r.fake.Seen())
		}
		if s.AccessKeyID != awstest.AccessKeyID || s.SecretAccessKey != awstest.SecretAccessKey || s.SessionToken != awstest.SessionToken ||
			s.AccountID != "123456789012" || s.Expiration.Location() != time.UTC || s.Expiration.Before(now.Add(59*time.Minute)) {
			t.Fatalf("%+v", s)
		}
		seen := r.fake.Seen()[i]
		if !seen.InBody || seen.Params.RoleArn != role || seen.Params.ProfileArn != profile || seen.Params.TrustAnchorArn != anchor ||
			seen.Params.DurationSeconds != 3600 || seen.Params.RoleSessionName != "" || seen.Serial != leaf.Cert.SerialNumber.String() ||
			seen.CN != "you-nazar" || seen.Issuer != "nazar aws CA dev" || seen.UserAgent != "nazar/test" {
			t.Fatalf("%+v", seen)
		}
		if strings.Join(seen.Signed, ";") != "content-type;host;x-amz-date;x-amz-x509" {
			t.Fatalf("signed %v", seen.Signed)
		}
	}
	// A 15-minute entry asks for 900 seconds.
	e := entry()
	e.Duration = 15 * time.Minute
	if _, err := r.c.CreateSession(context.Background(), e, r.leaf(t, time.Now()), time.Now()); err != nil {
		t.Fatal(err)
	}
	if d := r.fake.Seen()[5].Params.DurationSeconds; d != 900 {
		t.Fatalf("durationSeconds %d", d)
	}
}

// The clock window: a request signed 6 minutes off is refused by AWS (the
// fake), as AWS's error.
func TestClockSkew(t *testing.T) {
	r := newRig(t)
	now := time.Now()
	r.fake.SetClock(func() time.Time { return now.Add(6 * time.Minute) })
	_, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, now), now)
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != "AccessDeniedException" || ae.Status != 403 {
		t.Fatalf("%v", err)
	}
	// 4 minutes: the leaf and the date are both still good.
	r.fake.SetClock(func() time.Time { return now.Add(4 * time.Minute) })
	if _, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, now), now); err != nil {
		t.Fatal(err)
	}
}

func TestLeafProfile(t *testing.T) {
	r := newRig(t)
	now := time.Now()
	l := r.leaf(t, now)
	c := l.Cert
	if c.Subject.CommonName != "you-nazar" || len(c.Subject.Organization) != 0 || c.Issuer.CommonName != "nazar aws CA dev" || c.IsCA ||
		!c.NotBefore.Equal(now.UTC().Add(-Skew).Truncate(time.Second)) || !c.NotAfter.Equal(now.UTC().Add(Skew).Truncate(time.Second)) {
		t.Fatalf("leaf %v %v %v..%v", c.Subject, c.Issuer, c.NotBefore, c.NotAfter)
	}
	if _, err := Issue(r.ca, r.p, "bad user", certs.Serial{}, now, 0); err == nil {
		t.Fatal("an invalid user must be refused")
	}
	s, _ := certs.NewSerial()
	if _, err := Issue(r.ca, r.p, "you-nazar", certs.Serial{}, now, 0); err == nil {
		t.Fatal("a leaf needs its serial")
	}
	if l, err := Issue(r.ca, r.p, "you-nazar", s, now, 0); err != nil || l.Cert.SerialNumber.String() != s.Decimal() {
		t.Fatal(err)
	}
}

// The aws kind's records are aws-ca/ items and never a k8s context's.
func TestKindIsItsOwn(t *testing.T) {
	p := fake.New(time.Now())
	v := fake.NewVault()
	as := NewCAStore(p, v, time.Now)
	ks := k8s.NewCAStore(p, v, time.Now)
	if _, err := as.Create("hydra", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Get("hydra"); !errors.Is(err, k8s.ErrNotFound) {
		t.Fatalf("a k8s store reads an aws CA: %v", err)
	}
	if l, _ := ks.List(); len(l) != 0 {
		t.Fatalf("a k8s store lists an aws CA: %v", l)
	}
	if _, err := v.Get(VaultPrefix + "hydra"); err != nil {
		t.Fatal(err)
	}
	ca, _ := as.Get("hydra")
	if ca.Cert.Subject.CommonName != "nazar aws CA hydra" || ca.Access != platform.AccessWhenUnlocked {
		t.Fatal(ca.Cert.Subject)
	}
	if _, err := as.Get("Hydra"); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrBroken) {
		t.Fatalf("Hydra: %v", err)
	}
	if _, err := as.Get("bad/name"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("bad/name: %v", err)
	}
}

// Each reply check of aws design 6.3 has a failing case.
func TestReplyChecks(t *testing.T) {
	r := newRig(t)
	creds := func(edit func(m map[string]any)) func(w http.ResponseWriter, s awstest.Seen) bool {
		return func(w http.ResponseWriter, s awstest.Seen) bool {
			c := map[string]any{"accessKeyId": awstest.AccessKeyID, "secretAccessKey": awstest.SecretAccessKey, "sessionToken": awstest.SessionToken,
				"expiration": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
			cs := map[string]any{"credentials": c, "roleArn": role}
			out := map[string]any{"credentialSet": []any{cs}}
			edit(map[string]any{"out": out, "cs": cs, "c": c})
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(out)
			return true
		}
	}
	set := func(where, k string, v any) func(m map[string]any) {
		return func(m map[string]any) { m[where].(map[string]any)[k] = v }
	}
	cases := map[string]struct {
		reply func(w http.ResponseWriter, s awstest.Seen) bool
		want  string
	}{
		"status 200": {func(w http.ResponseWriter, _ awstest.Seen) bool {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{}`))
			return true
		}, "HTTP 200"},
		"too large": {func(w http.ResponseWriter, _ awstest.Seen) bool {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", 70<<10) + `"}`))
			return true
		}, "larger than 64 KiB"},
		"not JSON": {func(w http.ResponseWriter, _ awstest.Seen) bool {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`nope`))
			return true
		}, "not a JSON object"},
		"two objects":  {creds(func(m map[string]any) {}), ""},
		"no set":       {creds(func(m map[string]any) { m["out"].(map[string]any)["credentialSet"] = []any{} }), "has no credentials"},
		"key shape":    {creds(set("c", "accessKeyId", "asia-lower")), "access key id"},
		"key short":    {creds(set("c", "accessKeyId", "ASIA1")), "access key id"},
		"no secret":    {creds(set("c", "secretAccessKey", "")), "secret access key"},
		"secret ctl":   {creds(set("c", "secretAccessKey", "a\x1bb")), "secret access key"},
		"secret big":   {creds(set("c", "secretAccessKey", strings.Repeat("a", 17<<10))), "secret access key"},
		"no token":     {creds(set("c", "sessionToken", "")), "session token"},
		"no expiry":    {creds(set("c", "expiration", "")), "RFC 3339"},
		"bad expiry":   {creds(set("c", "expiration", "1 hour")), "RFC 3339"},
		"past":         {creds(set("c", "expiration", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))), "expired"},
		"too long":     {creds(set("c", "expiration", time.Now().Add(time.Hour+6*time.Minute).UTC().Format(time.RFC3339))), "longer than"},
		"another role": {creds(set("cs", "roleArn", "arn:aws:iam::123456789012:role/admin")), "another role"},
	}
	for name, tc := range cases {
		if name == "two objects" {
			tc.reply = func(w http.ResponseWriter, s awstest.Seen) bool {
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"credentialSet":[]} {}`))
				return true
			}
			tc.want = "data after"
		}
		r.fake.SetReply(tc.reply)
		_, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now())
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), awstest.SecretAccessKey) {
			t.Errorf("%s: the error holds the secret", name)
		}
	}
	// A secret is accepted up to 16 KiB.
	r.fake.SetReply(creds(set("c", "secretAccessKey", strings.Repeat("a", 16<<10+1))))
	if _, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now()); err == nil || !strings.Contains(err.Error(), "secret access key") {
		t.Fatalf("secret over 16 KiB: %v", err)
	}
	r.fake.SetReply(creds(func(m map[string]any) { delete(m["cs"].(map[string]any), "roleArn") }))
	if _, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now()); err != nil {
		t.Fatalf("no roleArn in the reply is fine: %v", err)
	}
}

func TestAWSErrors(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct {
		status     int
		code, msg  string
		wantInText string
	}{
		{403, "AccessDeniedException", "Unable to assume role for arn:aws:iam::123456789012:role/dev", "aws: AccessDeniedException: Unable to assume role"},
		{400, "ValidationException", "durationSeconds exceeds MaxSessionDuration", "aws: ValidationException: durationSeconds"},
		{404, "ResourceNotFoundException", "trust anchor not found", "aws: ResourceNotFoundException: trust anchor"},
		{429, "ThrottlingException", "Rate exceeded", "aws: ThrottlingException: Rate exceeded"},
		{403, "AccessDeniedException", "evil\x1b[2Jtext", `evil\x1b[2Jtext`},
	} {
		r.fake.Fail(tc.status, tc.code, tc.msg)
		_, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now())
		var ae *Error
		if !errors.As(err, &ae) || ae.Status != tc.status || ae.Code != tc.code || !strings.Contains(err.Error(), tc.wantInText) {
			t.Errorf("%d %s: %v", tc.status, tc.code, err)
		}
	}
}

func TestTransport(t *testing.T) {
	c := &Client{}
	tr := c.transport()
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion < 0x0303 || tr.TLSClientConfig.InsecureSkipVerify || !tr.DisableKeepAlives {
		t.Fatalf("%+v", tr)
	}
	if c.url("eu-west-2") != "https://rolesanywhere.eu-west-2.amazonaws.com/sessions" || c.timeout() != 10*time.Second {
		t.Fatal(c.url("eu-west-2"))
	}
	r := newRig(t)
	// A redirect is never followed.
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(201) }))
	defer other.Close()
	r.fake.SetReply(func(w http.ResponseWriter, _ awstest.Seen) bool {
		http.Redirect(w, &http.Request{}, other.URL+"/sessions", http.StatusTemporaryRedirect)
		return true
	})
	if _, err := r.c.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now()); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect: %v", err)
	}
	// A slow server meets the deadline.
	r.fake.SetReply(func(w http.ResponseWriter, _ awstest.Seen) bool { time.Sleep(time.Second); return false })
	slow := *r.c
	slow.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := slow.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now()); err == nil || !strings.Contains(err.Error(), "did not answer within") {
		t.Fatalf("slow: %v", err)
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("the deadline took %s", d)
	}
	// A server the roots don't trust.
	r.fake.SetReply(nil)
	untrusted := *r.c
	untrusted.RootCAs = nil
	if _, err := untrusted.CreateSession(context.Background(), entry(), r.leaf(t, time.Now()), time.Now()); err == nil || !strings.Contains(err.Error(), "can't reach") {
		t.Fatalf("untrusted: %v", err)
	}
	// An entry not connected is never sent.
	n := len(r.fake.Seen())
	if _, err := r.c.CreateSession(context.Background(), &config.AWSEntry{Name: "x"}, r.leaf(t, time.Now()), time.Now()); err == nil || len(r.fake.Seen()) != n {
		t.Fatal("not connected")
	}
}

// The signer only signs nazar's own request.
func TestSignRefusesOtherRequests(t *testing.T) {
	r := newRig(t)
	l := r.leaf(t, time.Now())
	for _, u := range []string{"https://h/sessions?x=1", "https://h/other"} {
		req, _ := http.NewRequest(http.MethodPost, u, nil)
		if err := sign(req, nil, l.Cert, l.Key, "us-east-1", time.Now()); err == nil {
			t.Errorf("%s signed", u)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://h/sessions", nil)
	if err := sign(req, nil, l.Cert, l.Key, "us-east-1", time.Now()); err == nil {
		t.Error("GET signed")
	}
	req, _ = http.NewRequest(http.MethodPost, "https://h/sessions", nil)
	if err := sign(req, nil, nil, nil, "us-east-1", time.Now()); err == nil {
		t.Error("no leaf")
	}
}
