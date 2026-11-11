package peertrust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestFile(t *testing.T) {
	if got, want := File("/home/u"), "/home/u/.nazar/install.json"; got != want {
		t.Fatalf("File = %q, want %q", got, want)
	}
}

// Write makes ~/.nazar 0700 when it is missing, writes the record 0600,
// and Read gives it back; a second Write replaces it and leaves no
// temporary file behind.
func TestRecordRoundTrip(t *testing.T) {
	home := t.TempDir()
	r := Record{CLI: Binary{Path: "/usr/local/bin/nazar", SHA256: hashA}, Agent: Binary{Path: "/usr/local/bin/nazar-agent", SHA256: hashB}}
	if err := Write(home, r); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(filepath.Join(home, ".nazar"))
	if err != nil {
		t.Fatal(err)
	}
	if !dir.IsDir() || dir.Mode().Perm() != 0o700 {
		t.Fatalf("~/.nazar mode %v, want a 0700 folder", dir.Mode())
	}
	fi, err := os.Stat(File(home))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v, want 0600", fi.Mode().Perm())
	}
	got, err := Read(home)
	if err != nil {
		t.Fatal(err)
	}
	if got != r {
		t.Fatalf("Read = %+v, want %+v", got, r)
	}
	r2 := Record{CLI: Binary{Path: "/opt/nazar/bin/nazar", SHA256: hashB}, Agent: Binary{Path: "/opt/nazar/bin/nazar-agent", SHA256: hashA}}
	if err := Write(home, r2); err != nil {
		t.Fatal(err)
	}
	if got, err := Read(home); err != nil || got != r2 {
		t.Fatalf("after the second Write: %+v, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Join(home, ".nazar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "install.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("~/.nazar holds %v, want install.json alone", names)
	}
}

// Without a record, Read is ErrNotInstalled: with no ~/.nazar at all, and
// with the folder but no file.
func TestReadMissing(t *testing.T) {
	home := t.TempDir()
	if _, err := Read(home); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("no ~/.nazar: %v, want ErrNotInstalled", err)
	}
	if err := os.Mkdir(filepath.Join(home, ".nazar"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(home); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("no file: %v, want ErrNotInstalled", err)
	}
	if !strings.Contains(ErrNotInstalled.Error(), "run nazar install") {
		t.Fatalf("ErrNotInstalled %q does not say what to do", ErrNotInstalled)
	}
}

// A record that is not two SHA-256 hashes is an error that names the file
// and the fix, never a record that could pass a check; and Write refuses
// to make one.
func TestDamagedRecord(t *testing.T) {
	for name, body := range map[string]string{
		"not json":   "{",
		"empty":      "{}",
		"short hash": `{"cli":{"path":"/a","sha256":"abc"},"agent":{"path":"/b","sha256":"` + hashB + `"}}`,
		"upper hex":  `{"cli":{"path":"/a","sha256":"` + strings.ToUpper(hashA) + `"},"agent":{"path":"/b","sha256":"` + hashB + `"}}`,
		"not hex":    `{"cli":{"path":"/a","sha256":"` + hashA + `"},"agent":{"path":"/b","sha256":"` + strings.Repeat("zz", 32) + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, ".nazar"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(File(home), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := Read(home)
			if err == nil || errors.Is(err, ErrNotInstalled) {
				t.Fatalf("Read = %+v, %v; want an error that is not ErrNotInstalled", r, err)
			}
			if r != (Record{}) {
				t.Fatalf("a damaged record came back as %+v", r)
			}
			if !strings.Contains(err.Error(), File(home)) || !strings.Contains(err.Error(), "run nazar install") {
				t.Fatalf("error %q names neither the file nor the fix", err)
			}
		})
	}
	if err := Write(t.TempDir(), Record{CLI: Binary{SHA256: "abc"}, Agent: Binary{SHA256: hashB}}); err == nil {
		t.Fatal("Write accepted a record that is not a hash")
	}
}

// The record is never read through a link: a user's own link in ~/.nazar
// would make the check about some other file.
func TestReadRefusesLink(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".nazar"), 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(home, "elsewhere.json")
	if err := os.WriteFile(real, []byte(`{"cli":{"sha256":"`+hashA+`"},"agent":{"sha256":"`+hashB+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, File(home)); err != nil {
		t.Fatal(err)
	}
	if r, err := Read(home); err == nil || errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Read through a link = %+v, %v", r, err)
	}
}

// HashFile is the lower-case hex SHA-256 of the file's bytes, and an error
// for a missing file or a folder.
func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "abc")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("HashFile = %q, want %q", got, want)
	}
	if !validHash(got) {
		t.Fatalf("HashFile gave %q, which Read would refuse", got)
	}
	if h, err := HashFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatalf("HashFile(missing) = %q, nil", h)
	}
	if h, err := HashFile(dir); err == nil {
		t.Fatalf("HashFile(folder) = %q, nil", h)
	}
}
