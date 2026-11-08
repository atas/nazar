package aws

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

// Algorithm is the SigV4 variant of Roles Anywhere for an ECDSA key (aws
// design 4.2).
const Algorithm = "AWS4-X509-ECDSA-SHA256"

// signedHeaders are the headers nazar sends and signs, sorted: the ones
// CloudTrail's missingSignedHeaders checks. user-agent is sent unsigned.
const signedHeaders = "content-type;host;x-amz-date;x-amz-x509"

const amzDateFormat = "20060102T150405Z"

// canonicalRequest is step 2 of the signing process for nazar's one
// request: POST /sessions, no query, the four headers, the body's hash.
func canonicalRequest(host, amzDate, x509b64 string, body []byte) string {
	sum := sha256.Sum256(body)
	return "POST\n/sessions\n\n" +
		"content-type:application/json\n" +
		"host:" + host + "\n" +
		"x-amz-date:" + amzDate + "\n" +
		"x-amz-x509:" + x509b64 + "\n" +
		"\n" + signedHeaders + "\n" + hex.EncodeToString(sum[:])
}

// scope is the credential scope: <date>/<region>/rolesanywhere/aws4_request.
func scope(amzDate, region string) string {
	return amzDate[:8] + "/" + region + "/rolesanywhere/aws4_request"
}

// stringToSign is step 3.
func stringToSign(amzDate, region, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return Algorithm + "\n" + amzDate + "\n" + scope(amzDate, region) + "\n" + hex.EncodeToString(sum[:])
}

// authorization is step 5: the certificate's serial in decimal names the
// credential.
func authorization(serial, amzDate, region, sigHex string) string {
	return Algorithm + " Credential=" + serial + "/" + scope(amzDate, region) + ", SignedHeaders=" + signedHeaders + ", Signature=" + sigHex
}

// sign sets the signed headers and Authorization of req, a POST of body to
// /sessions, with the leaf cert and its key (step 4: ECDSA over SHA-256 of
// the string to sign, ASN.1 DER, hex). The host signed is req.URL's, which
// is what the client sends.
func sign(req *http.Request, body []byte, cert *x509.Certificate, key *ecdsa.PrivateKey, region string, now time.Time) error {
	if cert == nil || key == nil || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		return errors.New("aws: no leaf to sign with")
	}
	if req.Method != http.MethodPost || req.URL.Path != "/sessions" || req.URL.RawQuery != "" {
		return errors.New("aws: nazar signs only its own POST /sessions")
	}
	amzDate := now.UTC().Format(amzDateFormat)
	x5 := base64.StdEncoding.EncodeToString(cert.Raw)
	sts := stringToSign(amzDate, region, canonicalRequest(req.URL.Host, amzDate, x5, body))
	digest := sha256.Sum256([]byte(sts))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return err
	}
	req.Host = req.URL.Host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-X509", x5)
	req.Header.Set("Authorization", authorization(cert.SerialNumber.String(), amzDate, region, hex.EncodeToString(sig)))
	return nil
}
