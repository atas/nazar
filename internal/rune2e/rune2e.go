// Package rune2e is what the end-to-end tests of nazar run share (on
// Linux and on the Mac): the value, a local npm registry and the
// probe programs. Test support only: imported by core/daemon's Linux test
// and by the conformance host, never by a shipped binary.
package rune2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Value is the secret every end-to-end run hands over.
const Value = "BSA-e2e-7f3c1a9d2b6e4f08a5c7"

// B64 is the value as it crosses the run socket.
var B64 = base64.StdEncoding.EncodeToString([]byte(Value))

// Holds reports whether b holds the value or its base64.
func Holds(b []byte) bool {
	return bytes.Contains(b, []byte(Value)) || bytes.Contains(b, []byte(B64))
}

// Report is what a probe writes once it started.
type Report struct {
	PID      int      `json:"pid"`
	Hash     *string  `json:"hash"`
	Leftover []string `json:"leftover"`
}

// Got reports whether the probe had the value in its environment.
func (r Report) Got() bool {
	sum := sha256.Sum256([]byte(Value))
	return r.Hash != nil && *r.Hash == hex.EncodeToString(sum[:])
}

// File is one file of a package tarball.
type File struct {
	Name, Body string
	Mode       int64
}

// tgz packs files under package/, as npm pack does.
func tgz(t testing.TB, files []File) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + f.Name, Mode: f.Mode, Size: int64(len(f.Body)), ModTime: time.Unix(1700000000, 0), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(f.Body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// Registry serves packages as an npm registry does, on 127.0.0.1: the
// packument at /<name> (a scoped name with its slash escaped) and the
// tarball. Every package is built by the test from strings.
type Registry struct {
	srv  *httptest.Server
	docs map[string][]byte
	tars map[string][]byte

	mu     sync.Mutex
	served []string // tarballs served
}

// NewRegistry starts an empty registry, closed at t's cleanup.
func NewRegistry(t testing.TB) *Registry {
	r := &Registry{docs: map[string][]byte{}, tars: map[string][]byte{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		p := strings.Replace(strings.TrimPrefix(q.URL.EscapedPath(), "/"), "%2f", "/", 1)
		p = strings.Replace(p, "%2F", "/", 1)
		if b, ok := r.tars[p]; ok {
			r.mu.Lock()
			r.served = append(r.served, p)
			r.mu.Unlock()
			w.Write(b)
			return
		}
		if b, ok := r.docs[p]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
			return
		}
		http.NotFound(w, q)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// URL is the registry's address, http://127.0.0.1:<port>.
func (r *Registry) URL() string { return r.srv.URL }

// Tarballs is every tarball served so far, in order.
func (r *Registry) Tarballs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.served)
}

// Publish adds name at version 1.0.0 with manifest and files. Call it
// before anything asks the registry.
func (r *Registry) Publish(t testing.TB, name string, manifest map[string]any, files []File) {
	t.Helper()
	manifest["name"], manifest["version"] = name, "1.0.0"
	pj, _ := json.Marshal(manifest)
	tar := tgz(t, append([]File{{"package.json", string(pj), 0o644}}, files...))
	tarPath := name + "/-/" + filepath.Base(name) + "-1.0.0.tgz"
	r.tars[tarPath] = tar
	s1 := sha1.Sum(tar)
	s512 := sha512.Sum512(tar)
	v := map[string]any{}
	for k, x := range manifest {
		v[k] = x
	}
	v["dist"] = map[string]any{"tarball": r.srv.URL + "/" + tarPath, "shasum": hex.EncodeToString(s1[:]),
		"integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:])}
	doc, _ := json.Marshal(map[string]any{"name": name, "dist-tags": map[string]string{"latest": "1.0.0"}, "versions": map[string]any{"1.0.0": v}})
	r.docs[name] = doc
}

// ProbeServer is the Node target, a package's bin as an MCP server is
// one: it reports what it has and waits on stdin.
const ProbeServer = `#!/usr/bin/env node
const fs = require('fs'), crypto = require('crypto');
const v = process.env.BRAVE_API_KEY;
const report = {pid: process.pid, hash: v === undefined ? null : crypto.createHash('sha256').update(v).digest('hex'),
  leftover: Object.keys(process.env).filter(k => k.startsWith('NAZAR_') || k === 'NODE_OPTIONS')};
fs.writeFileSync(process.env.E2E_REPORT + '.tmp', JSON.stringify(report));
fs.renameSync(process.env.E2E_REPORT + '.tmp', process.env.E2E_REPORT);
process.stdin.resume();
process.stdin.on('end', () => process.exit(0));
`

// ProbePy is the Python target: a script run by python3 itself (an
// interpreter: the exec'd process is the target).
const ProbePy = `import hashlib, json, os, sys
v = os.environ.get("BRAVE_API_KEY")
rep = {"pid": os.getpid(), "hash": None if v is None else hashlib.sha256(v.encode()).hexdigest(),
       "leftover": [k for k in os.environ if k.startswith("NAZAR_") or k == "PYTHONPATH"]}
with open(os.environ["E2E_REPORT"] + ".tmp", "w") as f:
    json.dump(rep, f)
os.rename(os.environ["E2E_REPORT"] + ".tmp", os.environ["E2E_REPORT"])
sys.stdin.read()
`

// SyncBuf is a bytes.Buffer a command's copy goroutine and the test share.
type SyncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *SyncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *SyncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
