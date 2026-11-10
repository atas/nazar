//go:build linux

package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/atas/nazar/core/platform"
)

var _ platform.Vault = (*Vault)(nil)

func open(t *testing.T) (*Vault, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return v, dir
}

func TestRoundTrip(t *testing.T) {
	v, _ := open(t)
	in := []byte("value one")
	if err := v.Put("key", in); err != nil {
		t.Fatal(err)
	}
	in[0] = 'X' // the vault keeps its own copy
	got, err := v.Get("key")
	if err != nil || string(got) != "value one" {
		t.Fatalf("Get: %q, %v", got, err)
	}
	got[0] = 'Y'
	if again, _ := v.Get("key"); string(again) != "value one" {
		t.Errorf("Get shares memory with the caller: %q", again)
	}
	// A second Put replaces; an empty value is a value.
	if err := v.Put("key", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get("key"); err != nil || len(got) != 0 {
		t.Errorf("after Put(nil): %q, %v", got, err)
	}
	if err := v.Delete("key"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("key"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Get after Delete: %v, want ErrNotFound", err)
	}
	if err := v.Delete("key"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Delete missing: %v, want ErrNotFound", err)
	}
	if _, err := v.Get("never"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Get missing: %v, want ErrNotFound", err)
	}
}

func TestList(t *testing.T) {
	v, dir := open(t)
	for _, n := range []string{"ssh/b", "ssh/a", "secret/x", "ssh", "sshd"} {
		if err := v.Put(n, []byte(n)); err != nil {
			t.Fatal(err)
		}
	}
	// A temp file a crashed writer left behind is never an item.
	if err := os.WriteFile(filepath.Join(dir, ".7373682f7a.tmp-deadbeef"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	for prefix, want := range map[string][]string{
		"":        {"secret/x", "ssh", "ssh/a", "ssh/b", "sshd"},
		"ssh":     {"ssh", "ssh/a", "ssh/b", "sshd"},
		"ssh/":    {"ssh/a", "ssh/b"},
		"secret/": {"secret/x"},
		"zzz":     nil,
	} {
		got, err := v.List(prefix)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("List(%q) = %v, want %v", prefix, got, want)
		}
	}
	if err := v.Delete("ssh/a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.List("ssh/"); strings.Join(got, ",") != "ssh/b" {
		t.Errorf("List after Delete: %v", got)
	}
}

func TestNames(t *testing.T) {
	v, dir := open(t)
	names := []string{"a/b", "..", ".", "tpm/0a", "ключ/ÿ€𝄞", "with space", "a\nb", strings.Repeat("n", 200), "x"}
	for i, n := range names {
		if err := v.Put(n, []byte(fmt.Sprint(i))); err != nil {
			t.Fatalf("Put(%q): %v", n, err)
		}
	}
	for i, n := range names {
		if got, err := v.Get(n); err != nil || string(got) != fmt.Sprint(i) {
			t.Errorf("Get(%q): %q, %v", n, got, err)
		}
	}
	got, err := v.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(names) {
		t.Errorf("List: %d names, want %d: %q", len(got), len(names), got)
	}
	for _, n := range names {
		if err := v.Delete(n); err != nil {
			t.Errorf("Delete(%q): %v", n, err)
		}
	}
	// Nothing escaped the folder, and nothing is left in it.
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("left in the vault: %v", ents)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(dir), "b")); err == nil {
		t.Error("a/b made a file outside the vault")
	}
	// The empty name is an error, not an item.
	if err := v.Put("", []byte("x")); err == nil {
		t.Error("Put(\"\") succeeded")
	}
	if _, err := v.Get(""); err == nil || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Get(\"\"): %v, want an error other than ErrNotFound", err)
	}
	if err := v.Delete(""); err == nil || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Delete(\"\"): %v, want an error other than ErrNotFound", err)
	}
}

func TestModes(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	v, dir := open(t)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("folder: %v %v, want 0700", fi, err)
	}
	if err := v.Put("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 1 {
		t.Fatalf("items: %v %v", ents, err)
	}
	fi, err := ents[0].Info()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Errorf("item %s: %v %v, want a 0600 file", ents[0].Name(), fi.Mode(), err)
	}
	if !strings.HasSuffix(ents[0].Name(), ".item") {
		t.Errorf("item file %s, want <hex>.item", ents[0].Name())
	}
}

func TestRefusesLooseFolder(t *testing.T) {
	base := t.TempDir()
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(loose); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Errorf("0755 folder: %v, want a mode error", err)
	}
	if fi, _ := os.Lstat(loose); fi.Mode().Perm() != 0o755 {
		t.Errorf("the loose folder was changed to %o", fi.Mode().Perm())
	}
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Error("a symlinked folder was accepted")
	}
	// A file where the folder should be.
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); err == nil {
		t.Error("a file was accepted as the folder")
	}
}

func TestItemSymlinkNotFollowed(t *testing.T) {
	v, dir := open(t)
	if err := v.Put("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	item := filepath.Join(dir, ents[0].Name())
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("elsewhere"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(item); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, item); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get("k"); err == nil {
		t.Errorf("Get through a symlink: %q", got)
	} else if errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Get through a symlink: %v, want an error other than ErrNotFound", err)
	}
	if got, _ := v.List(""); len(got) != 0 {
		t.Errorf("List names a symlink: %v", got)
	}
	// Put writes a new file in the link's place; the target is never touched.
	if err := v.Put("k", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "elsewhere" {
		t.Errorf("the target changed: %q, %v", got, err)
	}
	if fi, err := os.Lstat(item); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("after Put: %v %v, want a regular file", fi, err)
	}
	if got, err := v.Get("k"); err != nil || string(got) != "new" {
		t.Errorf("Get after Put: %q, %v", got, err)
	}
}

func TestLeftoverTempIgnored(t *testing.T) {
	v, dir := open(t)
	if err := v.Put("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	stem := strings.TrimSuffix(ents[0].Name(), ".item")
	for _, junk := range []string{"." + stem + ".tmp-0123456789abcdef", ".6f74686572.tmp-ffffffffffffffff", "notes.txt", stem} {
		if err := os.WriteFile(filepath.Join(dir, junk), []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := v.List(""); err != nil || strings.Join(got, ",") != "k" {
		t.Errorf("List: %v, %v, want [k]", got, err)
	}
	if got, err := v.Get("k"); err != nil || string(got) != "v" {
		t.Errorf("Get: %q, %v", got, err)
	}
	if _, err := v.Get("other"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Get of a name with only a temp file: %v, want ErrNotFound", err)
	}
	// A Put next to the leftover works, and leaves it alone.
	if err := v.Put("k", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if got, err := v.Get("k"); err != nil || string(got) != "v2" {
		t.Errorf("Get after Put: %q, %v", got, err)
	}
}

func TestConcurrentPuts(t *testing.T) {
	v, dir := open(t)
	const writers, names = 64, 8
	value := func(w int) []byte {
		return bytes.Repeat([]byte(fmt.Sprintf("writer %02d|", w)), 512)
	}
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			name := fmt.Sprintf("n%d", w%names)
			for i := 0; i < 4; i++ {
				if err := v.Put(name, value(w)); err != nil {
					errs <- err
					return
				}
				if got, err := v.Get(name); err != nil {
					errs <- err
					return
				} else if !torn(got, value) {
					errs <- fmt.Errorf("torn read of %s: %d bytes", name, len(got))
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	got, err := v.List("")
	if err != nil || len(got) != names {
		t.Fatalf("List: %v, %v", got, err)
	}
	for _, n := range got {
		b, err := v.Get(n)
		if err != nil || !torn(b, value) {
			t.Errorf("%s: %d bytes, %v", n, len(b), err)
		}
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != names {
		t.Errorf("%d files in the vault, want %d (no temp files left)", len(ents), names)
	}
	// The last Put wins.
	if err := v.Put("n0", []byte("last")); err != nil {
		t.Fatal(err)
	}
	if b, err := v.Get("n0"); err != nil || string(b) != "last" {
		t.Errorf("after the last Put: %q, %v", b, err)
	}
}

// torn reports whether b is one whole value of value(w), for some w.
func torn(b []byte, value func(int) []byte) bool {
	for w := 0; w < 64; w++ {
		if bytes.Equal(b, value(w)) {
			return true
		}
	}
	return false
}

func TestPersistsAcrossOpen(t *testing.T) {
	v, dir := open(t)
	if err := v.Put("ssh/one", []byte("blob")); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(strings.Repeat("l", 200), []byte("long")); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := again.Get("ssh/one"); err != nil || string(got) != "blob" {
		t.Errorf("Get after reopen: %q, %v", got, err)
	}
	if got, err := again.Get(strings.Repeat("l", 200)); err != nil || string(got) != "long" {
		t.Errorf("Get of the long name after reopen: %q, %v", got, err)
	}
	if got, err := again.List(""); err != nil || len(got) != 2 || got[0] != strings.Repeat("l", 200) || got[1] != "ssh/one" {
		t.Errorf("List after reopen: %v, %v", got, err)
	}
	if err := again.Delete("ssh/one"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("ssh/one"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("the first handle still sees the item: %v", err)
	}
}
