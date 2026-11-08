package aws

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
)

// The limits of the one call (aws design 6.3, 9.4).
const (
	Timeout  = 10 * time.Second
	maxReply = 64 << 10
	maxField = 16 << 10
)

// Client calls CreateSession. Its zero value is what nazar-agent uses: the
// host rolesanywhere.<region>.amazonaws.com, the system's roots, a
// 10-second deadline. Endpoint and RootCAs are set only by tests (the
// daemon's AWS option, pointed at core/aws/awstest), never by config, the
// environment or nazar-testd, which leaves the option unset.
type Client struct {
	Endpoint  string         // "https://host:port" in place of the region's host
	RootCAs   *x509.CertPool // nil: the system's
	Timeout   time.Duration  // 0: Timeout
	UserAgent string         // sent unsigned; "": nazar
}

// Session is what CreateSession gave: the credential_process fields.
type Session struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	AccountID       string
}

// Error is AWS's refusal: the status, its error code (AccessDeniedException,
// ValidationException, …) and its message. Its text names the code and
// the message, quoted and cut: never a credential, which a refusal has none of.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return "aws: " + display(e.Code) + ": " + display(e.Message)
}

// display renders text from AWS for a message: cut to 256 bytes and
// printable ASCII only, so nothing reaches a terminal or the audit log raw.
func display(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

// URL is where the session is asked for: Roles Anywhere's host in the
// trust anchor's region, from the config in force, never from a request.
func (c *Client) url(region string) string {
	if c.Endpoint != "" {
		return c.Endpoint + "/sessions"
	}
	return "https://rolesanywhere." + region + ".amazonaws.com/sessions"
}

// transport has no proxy, TLS 1.2 or later and no connection kept: one
// request per run.
func (c *Client) transport() *http.Transport {
	return &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: c.timeout()}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.RootCAs},
		TLSHandshakeTimeout: c.timeout(),
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
	}
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return Timeout
}

// errRedirect: a redirect is never followed.
var errRedirect = errors.New("redirected")

// body is CreateSession's: every parameter in the body (aws design 4.1).
type body struct {
	DurationSeconds int    `json:"durationSeconds"`
	ProfileArn      string `json:"profileArn"`
	RoleArn         string `json:"roleArn"`
	TrustAnchorArn  string `json:"trustAnchorArn"`
}

// requestBody is the JSON nazar sends for e.
func requestBody(e *config.AWSEntry) ([]byte, error) {
	return json.Marshal(body{DurationSeconds: int(e.Duration / time.Second), ProfileArn: e.ProfileArn, RoleArn: e.RoleArn, TrustAnchorArn: e.TrustAnchorArn})
}

// accessKeyRE is an access key id: 16 to 128 of A-Z and 0-9.
var accessKeyRE = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)

// CreateSession signs one CreateSession for entry e with leaf and sends it
// (aws design 3.3, 4): one attempt, no redirect, no proxy, the deadline.
// The reply is checked (6.3) before anything is returned; AWS's refusal is
// an *Error.
func (c *Client) CreateSession(ctx context.Context, e *config.AWSEntry, leaf certs.Leaf, now time.Time) (Session, error) {
	if e == nil || !e.Connected() || e.Region == "" || e.Account == "" {
		return Session{}, errors.New("aws: the entry is not connected")
	}
	b, err := requestBody(e)
	if err != nil {
		return Session{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(e.Region), bytes.NewReader(b))
	if err != nil {
		return Session{}, err
	}
	if err := sign(req, b, leaf.Cert, leaf.Key, e.Region, now); err != nil {
		return Session{}, err
	}
	ua := c.UserAgent
	if ua == "" {
		ua = "nazar"
	}
	req.Header.Set("User-Agent", ua)
	hc := &http.Client{Transport: c.transport(), CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect }}
	host := req.URL.Host
	resp, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		switch {
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ue) && ue.Timeout()):
			return Session{}, fmt.Errorf("aws: %s did not answer within %s", host, c.timeout())
		case errors.Is(err, errRedirect):
			return Session{}, fmt.Errorf("aws: %s answered with a redirect, which nazar never follows", host)
		}
		return Session{}, fmt.Errorf("aws: can't reach %s: %s", host, display(errText(err)))
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxReply+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Session{}, fmt.Errorf("aws: %s did not answer within %s", host, c.timeout())
		}
		return Session{}, fmt.Errorf("aws: reading the reply of %s: %s", host, display(errText(err)))
	}
	if len(data) > maxReply {
		return Session{}, errors.New("aws: the reply is larger than 64 KiB")
	}
	if resp.StatusCode != http.StatusCreated {
		return Session{}, awsError(resp, data)
	}
	return checkReply(data, e, now)
}

// errText is err's message without the URL net/http puts in front.
func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// awsError reads AWS's error shape: the code from x-amzn-ErrorType (up to
// its ':'), else the body's __type or code; the body's message.
func awsError(resp *http.Response, data []byte) error {
	var b struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(data, &b)
	code, _, _ := strings.Cut(resp.Header.Get("X-Amzn-Errortype"), ":")
	if code == "" {
		code = b.Type
		if i := strings.LastIndexByte(code, '#'); i >= 0 {
			code = code[i+1:]
		}
	}
	if code == "" {
		code = b.Code
	}
	if code == "" {
		code = "HTTP " + strconv.Itoa(resp.StatusCode)
	}
	msg := b.Message
	if msg == "" {
		msg = b.Msg
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return &Error{Status: resp.StatusCode, Code: code, Message: msg}
}

type reply struct {
	CredentialSet []struct {
		Credentials struct {
			AccessKeyID     string `json:"accessKeyId"`
			SecretAccessKey string `json:"secretAccessKey"`
			SessionToken    string `json:"sessionToken"`
			Expiration      string `json:"expiration"`
		} `json:"credentials"`
		RoleArn string `json:"roleArn"`
	} `json:"credentialSet"`
}

// checkReply accepts a 201's body only as aws design 6.3 says: one JSON
// object, a credential set, an access key id of its shape, a secret and a
// token of printable ASCII at most 16 KiB each, an expiration after now and
// at most duration + Skew away (AWS's clock may be ahead of the Mac's by as
// much as the leaf allows), and the configured role when one is named.
func checkReply(data []byte, e *config.AWSEntry, now time.Time) (Session, error) {
	bad := func(what string) (Session, error) {
		return Session{}, errors.New("aws: CreateSession's reply " + what)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var r reply
	if err := dec.Decode(&r); err != nil {
		return bad("is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad("has data after its JSON object")
	}
	if len(r.CredentialSet) == 0 {
		return bad("has no credentials")
	}
	cs := r.CredentialSet[0]
	c := cs.Credentials
	switch {
	case !accessKeyRE.MatchString(c.AccessKeyID):
		return bad("has an access key id of another shape")
	case !printable(c.SecretAccessKey):
		return bad("has no usable secret access key")
	case !printable(c.SessionToken):
		return bad("has no usable session token")
	case cs.RoleArn != "" && cs.RoleArn != e.RoleArn:
		return bad("is for another role")
	}
	exp, err := time.Parse(time.RFC3339, c.Expiration)
	if err != nil {
		return bad("has no RFC 3339 expiration")
	}
	if !exp.After(now) {
		return bad("has expired already")
	}
	if exp.After(now.Add(e.Duration + Skew)) {
		return bad("lasts longer than the entry's duration")
	}
	return Session{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken,
		Expiration: exp.UTC(), AccountID: e.Account}, nil
}

// printable: non-empty, at most 16 KiB, printable ASCII without spaces.
func printable(s string) bool {
	if s == "" || len(s) > maxField {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
