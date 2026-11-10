//go:build linux

// Package vault is the Linux platform.Vault: a folder of files under the
// user's home (layout.VaultDir, ~/.nazar/vault), holding the TPM-wrapped
// key blobs and the sealed secrets. Linux has no per-app keychain ACL, so
// the folder's mode is the whole protection: 0700, every item 0600, and
// Open refuses a folder that is a link, another user's, or open to the
// group or others (the agent fails to start rather than serve from it).
//
// One item is one file, <hex(name)>.item. A name longer than fits a file
// name (116 bytes; NAME_MAX is 255) is filed as <hex(sha256(name))>.item.
// Every item starts with a small header that repeats the name, so Get
// checks it and List reads it instead of decoding file names. Put writes
// .<stem>.tmp-<random> (O_EXCL, O_NOFOLLOW), fsyncs it, renames it over
// the item and fsyncs the folder: a reader sees the old item or the new
// one, never a torn one, and a crash leaves at most a temp file, which
// nothing reads. Items are opened with O_NOFOLLOW, so an item replaced by
// a link is an error, not the link's target. An advisory lock on the
// folder serialises writers across processes; the mutex, within one.
package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/unixsock"
)

var _ platform.Vault = (*Vault)(nil)

const (
	itemSuffix = ".item"
	// maxHexName is the longest name filed as its hex: its temp file name,
	// "." + 2*116 + ".tmp-" + 16 random hex digits, is 254 bytes.
	maxHexName = 116
	// magic starts every item file, before the name and the value.
	magic = "nzv1"
)

// Vault is a platform.Vault in one folder. Open makes it.
type Vault struct {
	dir string
	mu  sync.Mutex
}

// Open opens the vault in dir, making it 0700 when it is missing. It
// refuses a dir that is a link, not a folder, another user's or has any
// group or other bit; it never changes the mode of what exists.
func Open(dir string) (*Vault, error) {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("vault: %w", err)
	}
	if err := unixsock.CheckPrivateDir(dir); err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	return &Vault{dir: dir}, nil
}

// Get returns a copy of the item, or platform.ErrNotFound.
func (v *Vault) Get(name string) ([]byte, error) {
	stem, err := stem(name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(v.dir, stem+itemSuffix)
	got, value, err := readItem(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, platform.ErrNotFound
		}
		return nil, err
	}
	if got != name {
		return nil, fmt.Errorf("vault: %s holds another item's name", path)
	}
	return value, nil
}

// Put stores a copy of value under name, replacing any previous item.
func (v *Vault) Put(name string, value []byte) error {
	stem, err := stem(name)
	if err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	dir, err := v.lock()
	if err != nil {
		return err
	}
	defer dir.Close()
	tmp := filepath.Join(v.dir, "."+stem+".tmp-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	if err := writeItem(f, name, value); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("vault: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("vault: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(v.dir, stem+itemSuffix)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("vault: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

// Delete removes the item, or returns platform.ErrNotFound.
func (v *Vault) Delete(name string) error {
	stem, err := stem(name)
	if err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	dir, err := v.lock()
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := os.Remove(filepath.Join(v.dir, stem+itemSuffix)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return platform.ErrNotFound
		}
		return fmt.Errorf("vault: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

// List returns the names starting with prefix, sorted. Temp files, links
// and files that are not items are not listed; a damaged item is an
// error that names it.
func (v *Vault) List(prefix string) ([]string, error) {
	ents, err := os.ReadDir(v.dir)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, itemSuffix) {
			continue
		}
		name, _, err := readItem(filepath.Join(v.dir, n))
		if errors.Is(err, fs.ErrNotExist) {
			continue // deleted since ReadDir
		}
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// lock opens the folder (never through a link) and takes its advisory
// lock; closing the file releases it.
func (v *Vault) lock() (*os.File, error) {
	dir, err := os.OpenFile(v.dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX); err != nil {
		dir.Close()
		return nil, fmt.Errorf("vault: lock %s: %w", v.dir, err)
	}
	return dir, nil
}

// stem is the item's file name without its suffix: the name in hex, or
// its sha256 in hex when the name is too long for a file name.
func stem(name string) (string, error) {
	if name == "" {
		return "", errors.New("vault: empty name")
	}
	if len(name) > maxHexName {
		sum := sha256.Sum256([]byte(name))
		return hex.EncodeToString(sum[:]), nil
	}
	return hex.EncodeToString([]byte(name)), nil
}

// writeItem writes the header and the value and fsyncs the file.
func writeItem(f *os.File, name string, value []byte) error {
	var b bytes.Buffer
	b.WriteString(magic)
	b.Write(binary.AppendUvarint(nil, uint64(len(name))))
	b.WriteString(name)
	b.Write(value)
	if _, err := f.Write(b.Bytes()); err != nil {
		return err
	}
	return f.Sync()
}

// readItem reads one item file, never through a link, and returns the
// name its header holds and a fresh copy of its value.
func readItem(path string) (name string, value []byte, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return "", nil, fmt.Errorf("vault: %s is a link, not an item", path)
		}
		return "", nil, fmt.Errorf("vault: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", nil, fmt.Errorf("vault: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", nil, fmt.Errorf("vault: %s is not a file", path)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", nil, fmt.Errorf("vault: %w", err)
	}
	if !bytes.HasPrefix(b, []byte(magic)) {
		return "", nil, fmt.Errorf("vault: %s is not an item", path)
	}
	b = b[len(magic):]
	n, k := binary.Uvarint(b)
	if k <= 0 || n > uint64(len(b)-k) {
		return "", nil, fmt.Errorf("vault: %s is damaged", path)
	}
	b = b[k:]
	return string(b[:n]), b[n:], nil
}
