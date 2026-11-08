package k8s

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// K8s design 1.1, 1.3: KUBERNETES_EXEC_INFO is untrusted input,
// parsed by nazar-agent (v1 only); the reply is the v1 ExecCredential with
// a certificate, a key and an expiration, and nothing else.

func execJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseExecInfo(t *testing.T) {
	ca := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	raw := execJSON(t, map[string]any{
		"apiVersion": ExecAPIVersion, "kind": "ExecCredential",
		"spec": map[string]any{"interactive": false, "cluster": map[string]any{
			"server": "https://hydra.example:16443", "tls-server-name": "hydra", "insecure-skip-tls-verify": true,
			"certificate-authority-data": ca, "proxy-url": "socks5://localhost:1080", "disable-compression": true,
			"config": map[string]any{"anything": 1},
		}},
	})
	info, err := ParseExecInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if info == nil || info.Server != "https://hydra.example:16443" || info.TLSServerName != "hydra" || !info.Insecure ||
		string(info.CAData) != string(ca) || info.ProxyURL != "socks5://localhost:1080" {
		t.Fatalf("%+v", info)
	}
	// No spec.cluster (provideClusterInfo: false): no info, no error; the
	// policy refuses it (check 2 can't run).
	info, err = ParseExecInfo(execJSON(t, map[string]any{"apiVersion": ExecAPIVersion, "kind": "ExecCredential", "spec": map[string]any{"interactive": false}}))
	if err != nil || info != nil {
		t.Fatalf("no cluster: %+v %v", info, err)
	}
	for name, bad := range map[string]string{
		"empty":       "",
		"junk":        "not json",
		"array":       "[]",
		"v1beta1":     execJSON(t, map[string]any{"apiVersion": "client.authentication.k8s.io/v1beta1", "kind": "ExecCredential", "spec": map[string]any{}}),
		"no version":  execJSON(t, map[string]any{"kind": "ExecCredential", "spec": map[string]any{}}),
		"other kind":  execJSON(t, map[string]any{"apiVersion": ExecAPIVersion, "kind": "Secret", "spec": map[string]any{}}),
		"two objects": execJSON(t, map[string]any{"apiVersion": ExecAPIVersion, "kind": "ExecCredential"}) + "{}",
		"bad ca":      `{"apiVersion":"` + ExecAPIVersion + `","kind":"ExecCredential","spec":{"cluster":{"server":"https://a","certificate-authority-data":"!!"}}}`,
		"too large":   `{"apiVersion":"` + ExecAPIVersion + `","kind":"ExecCredential","spec":{"cluster":{"server":"https://a","tls-server-name":"` + strings.Repeat("a", MaxExecInfo) + `"}}}`,
	} {
		info, err := ParseExecInfo(bad)
		var u *UsageError
		if err == nil || !errors.As(err, &u) || info != nil {
			t.Errorf("%s: want a usage error, got %+v %v", name, info, err)
		}
		if name == "v1beta1" && (!strings.Contains(err.Error(), ExecAPIVersion) || !strings.Contains(err.Error(), "nazar k8s ca create")) {
			t.Errorf("v1beta1: the message must name the version and the fix: %v", err)
		}
		if strings.ContainsAny(err.Error(), "\x00\x1b") || len(err.Error()) > 400 {
			t.Errorf("%s: the error must be short and plain: %q", name, err)
		}
	}
}

func TestEncodeExecCredential(t *testing.T) {
	exp := time.Date(2026, 10, 17, 17, 15, 0, 0, time.FixedZone("MST", -7*3600))
	b, err := EncodeExecCredential([]byte("CERT"), []byte("KEY"), exp)
	if err != nil {
		t.Fatal(err)
	}
	// The reply starts with a YAML document-start marker on a line of its
	// own (THREAT-MODEL 5.16): `---` is a marker only at column 0, so a
	// line break comes first whatever a prepended prefix left the line at,
	// and a prepended YAML scalar, block or flow, cannot then take nazar's
	// bytes into a field kubectl would send. After the marker it is the
	// JSON object.
	if execDocStart != "\n---\n" || !strings.HasPrefix(string(b), execDocStart) {
		t.Fatalf("reply does not start with a line break and the document marker: %q", b[:min(len(b), 8)])
	}
	var m map[string]any
	if err := json.Unmarshal(b[len(execDocStart):], &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 || m["apiVersion"] != ExecAPIVersion || m["kind"] != "ExecCredential" {
		t.Fatalf("top level %v", m)
	}
	st, _ := m["status"].(map[string]any)
	if len(st) != 3 || st["clientCertificateData"] != "CERT" || st["clientKeyData"] != "KEY" || st["expirationTimestamp"] != "2026-10-18T00:15:00Z" {
		t.Fatalf("status %v", st)
	}
	if strings.Contains(string(b), "token") || strings.Contains(string(b), "spec") || !strings.HasSuffix(string(b), "\n") {
		t.Fatalf("exactly the certificate pair: %s", b)
	}
	if _, err := EncodeExecCredential(nil, []byte("KEY"), exp); err == nil {
		t.Fatal("a reply without a certificate must be refused")
	}
	if _, err := EncodeExecCredential([]byte("C"), []byte("K"), time.Time{}); err == nil {
		t.Fatal("a reply without an expiration must be refused")
	}
}
