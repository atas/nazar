// Package k8s is the k8s module's ca-cert provider (k8s design 6.1, as
// built in Milestone 12): the exec plugin's wire format, a Secure Enclave
// CA per context, and the short-lived client certificates it mints.
package k8s

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/atas/nazar/core/k8s/cluster"
)

// ExecAPIVersion is the only exec credential version nazar speaks (k8s
// design 1.1): GA since Kubernetes 1.22.
const ExecAPIVersion = "client.authentication.k8s.io/v1"

// MaxExecInfo bounds KUBERNETES_EXEC_INFO; a CA bundle of a few
// certificates fits many times over. (A value near the bound can still
// make the control request too large once escaped; that too is refused.)
const MaxExecInfo = 48 << 10

// NoExecInfo is the refusal of a plugin run without KUBERNETES_EXEC_INFO,
// which client-go always sets: something other than kubectl ran it.
const NoExecInfo = "no KUBERNETES_EXEC_INFO: nazar k8s credential is run by kubectl's exec plugin"

// UsageError is exec info nazar does not accept: the plugin's exit 2.
// Its message never echoes the input.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usage(msg string) error { return &UsageError{Msg: msg} }

// execInfo is the part of KUBERNETES_EXEC_INFO nazar reads.
type execInfo struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Cluster *struct {
			Server                   string `json:"server"`
			TLSServerName            string `json:"tls-server-name"`
			InsecureSkipTLSVerify    bool   `json:"insecure-skip-tls-verify"`
			CertificateAuthorityData []byte `json:"certificate-authority-data"`
			ProxyURL                 string `json:"proxy-url"`
		} `json:"cluster"`
	} `json:"spec"`
}

// ParseExecInfo reads KUBERNETES_EXEC_INFO, which whoever wrote the
// kubeconfig controls: one JSON object, kind ExecCredential, apiVersion
// client.authentication.k8s.io/v1, at most MaxExecInfo bytes. It returns
// spec.cluster, or nil when there is none (provideClusterInfo: false; the
// policy refuses that, k8s design 1.1). Anything else is a UsageError.
func ParseExecInfo(raw string) (*cluster.Info, error) {
	if raw == "" {
		return nil, usage(NoExecInfo)
	}
	if len(raw) > MaxExecInfo {
		return nil, usage("KUBERNETES_EXEC_INFO is larger than 48 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	var in execInfo
	if err := dec.Decode(&in); err != nil {
		return nil, usage("KUBERNETES_EXEC_INFO is not an ExecCredential")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, usage("KUBERNETES_EXEC_INFO is not one ExecCredential")
	}
	if in.Kind != "ExecCredential" {
		return nil, usage("KUBERNETES_EXEC_INFO is not an ExecCredential")
	}
	if in.APIVersion != ExecAPIVersion {
		return nil, usage("nazar needs exec.apiVersion " + ExecAPIVersion + "; set it in the kubeconfig user entry that runs nazar (nazar k8s ca create writes it so)")
	}
	c := in.Spec.Cluster
	if c == nil {
		return nil, nil
	}
	return &cluster.Info{Server: c.Server, CAData: c.CertificateAuthorityData, TLSServerName: c.TLSServerName,
		ProxyURL: c.ProxyURL, Insecure: c.InsecureSkipTLSVerify}, nil
}

// execCredential is the reply (k8s design 1.3): no spec, no token.
type execCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		ClientCertificateData string `json:"clientCertificateData"`
		ClientKeyData         string `json:"clientKeyData"`
		ExpirationTimestamp   string `json:"expirationTimestamp"`
	} `json:"status"`
}

// execDocStart is the YAML document-start marker nazar's reply begins with,
// on a line of its own (THREAT-MODEL 5.16). client-go reads the plugin's
// stdout as YAML or JSON, and a wrapper that keeps kubectl the plugin's
// parent can write before the CLI runs (the stdout check refuses any
// co-writer while it runs). Without a marker, a prefix such as
// `status:\n  token: >-\n    ` makes a YAML folded scalar that captures
// nazar's whole reply as the value of status.token, which kubectl then
// sends to the server as a bearer token, key included. `---` is a marker
// only at column 0, so the line break before it comes first, whatever line
// a prefix left open: the marker then ends any block scalar a prefix
// opened, and inside a flow or quoted scalar it is an error, so the reply
// decodes as nazar's own document or not at all. kubectl accepts it (YAML
// is read when the stream is not valid JSON, which `---` makes it).
const execDocStart = "\n---\n"

// EncodeExecCredential is the plugin's stdout: the v1 ExecCredential with
// the certificate, its key and the expiration (RFC 3339, UTC), one YAML
// document that starts with execDocStart (see there) and is JSON after it.
// The caller clears the returned bytes once written.
func EncodeExecCredential(certPEM, keyPEM []byte, exp time.Time) ([]byte, error) {
	if len(certPEM) == 0 || len(keyPEM) == 0 || exp.IsZero() {
		return nil, errors.New("k8s: an ExecCredential needs a certificate, a key and an expiration")
	}
	var c execCredential
	c.APIVersion, c.Kind = ExecAPIVersion, "ExecCredential"
	c.Status.ClientCertificateData = string(certPEM)
	c.Status.ClientKeyData = string(keyPEM)
	c.Status.ExpirationTimestamp = exp.UTC().Format(time.RFC3339)
	b := bytes.NewBufferString(execDocStart)
	if err := json.NewEncoder(b).Encode(c); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
