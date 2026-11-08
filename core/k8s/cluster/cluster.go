// Package cluster is check 2 of the k8s module (k8s design 2.2): what a
// request's spec.cluster says (Info), what config recorded at import (Pin),
// and the one canonical comparison of the two. It imports nothing of
// nazar's, so config, policy and the module all compare clusters the same
// way.
package cluster

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Info is a cluster as client-go describes it in KUBERNETES_EXEC_INFO
// (spec.cluster). Every field comes from a kubeconfig, which any process
// of the user can write.
type Info struct {
	Server        string
	CAData        []byte // PEM: certificate-authority-data
	TLSServerName string
	ProxyURL      string
	Insecure      bool // insecure-skip-tls-verify
}

// Pin is a cluster as config.yaml records it (k8s.contexts.NAME.cluster):
// the normalised server, the canonical CA hash and the two names, compared
// exactly.
type Pin struct {
	Server        string
	CASHA256      string
	TLSServerName string
	ProxyURL      string
}

// NormalizeServer returns the canonical form of an API server URL: https
// only, scheme and host lower-cased, an explicit :443 dropped, one trailing
// "/" removed; user info, a query or a fragment is refused, and the rest (a
// path prefix behind Rancher, a port) must match byte for byte.
func NormalizeServer(s string) (string, error) {
	bad := func(why string) (string, error) {
		return "", fmt.Errorf("server %s: %s", Display(s), why)
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
		// Non-ASCII too: a homoglyph host would read like the real one on a
		// prompt; an internationalised name is written in punycode.
		return bad("contains spaces, control or non-ASCII characters")
	}
	u, err := url.Parse(s)
	if err != nil {
		return bad("is not a URL")
	}
	switch {
	case !strings.EqualFold(u.Scheme, "https"):
		return bad("must start with https://")
	case u.Opaque != "":
		return bad("is not a URL")
	case u.User != nil:
		return bad("must not carry a user or password")
	case u.RawQuery != "" || u.ForceQuery:
		return bad("must not have a query")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return bad("must not have a fragment")
	case u.Hostname() == "":
		return bad("has no host")
	}
	host := strings.ToLower(u.Hostname())
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return bad("has an invalid port")
		}
		if n != 443 {
			host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	path = strings.TrimSuffix(path, "/")
	return "https://" + host + path, nil
}

// CAHash is the canonical hash of a CA bundle (k8s design 2.2): every PEM
// block must be a certificate (no headers) that parses with nothing after
// it; their DER encodings are sorted and concatenated, then hashed with
// SHA-256. Block order, whitespace and text between blocks don't count;
// the exact set of trust anchors does.
func CAHash(pemData []byte) (string, error) {
	var ders [][]byte
	rest := pemData
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return "", errors.New("the CA data holds a PEM block that is not a certificate")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return "", errors.New("the CA data holds a certificate that does not parse")
		}
		ders = append(ders, c.Raw)
	}
	if len(ders) == 0 {
		return "", errors.New("the CA data holds no certificate")
	}
	slices.SortFunc(ders, bytes.Compare)
	h := sha256.New()
	for _, d := range ders {
		h.Write(d)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PinOf is what import records for a cluster: refused when TLS is not
// checked or there is no CA to pin (k8s design 5.2 step 5).
func PinOf(i Info) (Pin, error) {
	if i.Insecure {
		return Pin{}, errors.New("insecure-skip-tls-verify is set: nazar cannot protect a cluster whose server certificate is not checked; add certificate-authority-data")
	}
	server, err := NormalizeServer(i.Server)
	if err != nil {
		return Pin{}, err
	}
	if len(i.CAData) == 0 {
		return Pin{}, errors.New("the cluster has no certificate-authority-data: nazar pins the cluster's CA; add it to the kubeconfig")
	}
	ca, err := CAHash(i.CAData)
	if err != nil {
		return Pin{}, err
	}
	return Pin{Server: server, CASHA256: ca, TLSServerName: i.TLSServerName, ProxyURL: i.ProxyURL}, nil
}

// Match reports whether got is the recorded cluster: nil, or an error that
// names what was expected and what came (got's values quoted and cut,
// Display). A cluster whose TLS is not checked never matches.
func (p Pin) Match(got Info) error {
	mismatch := func(field, want, have string) error {
		return fmt.Errorf("%s: expected %s, got %s", field, Display(want), Display(have))
	}
	if got.Insecure {
		return errors.New("insecure-skip-tls-verify is set")
	}
	server, err := NormalizeServer(got.Server)
	if err != nil {
		return mismatch("server", p.Server, got.Server)
	}
	if server != p.Server {
		return mismatch("server", p.Server, server)
	}
	ca := "none"
	if len(got.CAData) > 0 {
		if ca, err = CAHash(got.CAData); err != nil {
			ca = "unreadable"
		}
	}
	if ca != p.CASHA256 {
		return mismatch("ca", "sha256:"+short(p.CASHA256), "sha256:"+short(ca))
	}
	if got.TLSServerName != p.TLSServerName {
		return mismatch("tls-server-name", p.TLSServerName, got.TLSServerName)
	}
	if got.ProxyURL != p.ProxyURL {
		return mismatch("proxy-url", p.ProxyURL, got.ProxyURL)
	}
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12] + "…"
	}
	return h
}

// maxDisplay bounds a value taken from a kubeconfig in a message.
const maxDisplay = 256

// Display renders a value from a kubeconfig or KUBERNETES_EXEC_INFO for a
// message: cut to 256 bytes, then Go-quoted in ASCII, so no control, ESC or
// bidi rune reaches a terminal, a dialog or the audit log raw.
func Display(s string) string {
	if len(s) > maxDisplay {
		s = s[:maxDisplay]
	}
	return strconv.QuoteToASCII(s)
}
