// Package peertrust is how the nazar CLI and nazar-agent recognize each
// other on Linux, where no code signature names a program: by the SHA-256
// of each other's binary, recorded by `nazar install` in
// ~/.nazar/install.json. The agent accepts a control connection only from
// a process of its user whose running image hashes to the record's CLI
// (CLIVerifier, peer_linux.go); the CLI sends nothing until the process
// listening on the control socket hashes to the record's agent
// (CheckAgent) and its own running image hashes to the record's CLI
// (CheckSelf). The record is read on every check, so a re-run `nazar
// install` applies at once, and the CLI says "run nazar install" when an
// upgrade left the agent or the CLI differing from the record without it.
// The agent says it only in its log, to whatever connects. The record
// is the user's own file in a 0700 folder: it is same-user trust, as the
// design's "Weaker than macOS" list says (item 2), not an escalation.
package peertrust

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/unixsock"
)

// Binary is one recorded program: where it was at install and what it
// hashed to. Only the hash is checked; the path is for `nazar status` and
// people reading the file.
type Binary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Record is what `nazar install` writes: the CLI and the agent it installed.
type Record struct {
	CLI   Binary `json:"cli"`
	Agent Binary `json:"agent"`
}

// ErrNotInstalled: there is no record, so neither side can trust the other.
var ErrNotInstalled = errors.New("nazar install has not recorded this nazar's binaries; run nazar install")

// fileName is the record's name under ~/.nazar.
const fileName = "install.json"

// File is the record's path, ~/.nazar/install.json.
func File(home string) string { return filepath.Join(layout.Root(home), fileName) }

// Read returns the record, ErrNotInstalled when there is none, and an
// error naming the file when it cannot be read or does not hold two
// SHA-256 hashes.
func Read(home string) (Record, error) {
	path := File(home)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return Record{}, ErrNotInstalled
		}
		return Record{}, fmt.Errorf("peertrust: %s: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Record{}, fmt.Errorf("peertrust: %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return Record{}, fmt.Errorf("peertrust: %s is not a regular file; run nazar install", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return Record{}, fmt.Errorf("peertrust: %s: %w", path, err)
	}
	if len(data) > maxRecord {
		return Record{}, fmt.Errorf("peertrust: %s is larger than %d bytes; run nazar install", path, maxRecord)
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return Record{}, fmt.Errorf("peertrust: %s: %v; run nazar install", path, err)
	}
	for _, b := range []struct{ what, hash string }{{"cli", r.CLI.SHA256}, {"agent", r.Agent.SHA256}} {
		if !validHash(b.hash) {
			return Record{}, fmt.Errorf("peertrust: %s: %s.sha256 is not a SHA-256 hash; run nazar install", path, b.what)
		}
	}
	return r, nil
}

// maxRecord bounds the file: two paths and two hashes fit in far less.
const maxRecord = 64 << 10

// validHash: 64 lower-case hex digits, what HashFile gives.
func validHash(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Write replaces the record atomically: ~/.nazar is made 0700 when it is
// missing and must be a private folder of this user, the file is written
// 0600 next to the record and renamed over it, so a reader sees the old
// record or the new one and never a part. Both hashes must be ones
// HashFile could have given.
func Write(home string, r Record) error {
	for _, b := range []struct{ what, hash string }{{"cli", r.CLI.SHA256}, {"agent", r.Agent.SHA256}} {
		if !validHash(b.hash) {
			return fmt.Errorf("peertrust: %s.sha256 %q is not a SHA-256 hash", b.what, b.hash)
		}
	}
	dir := layout.Root(home)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("peertrust: %w", err)
	}
	if err := unixsock.CheckPrivateDir(dir); err != nil {
		return fmt.Errorf("peertrust: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("peertrust: %w", err)
	}
	data = append(data, '\n')
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("peertrust: %w", err)
	}
	tmp := filepath.Join(dir, "."+fileName+".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("peertrust: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("peertrust: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("peertrust: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("peertrust: %w", err)
	}
	if err := os.Rename(tmp, File(home)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("peertrust: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// HashFile is the SHA-256 of the regular file at path, as lower-case hex:
// what the record holds and what a running image is compared with.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("peertrust: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("peertrust: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("peertrust: %s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("peertrust: %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
