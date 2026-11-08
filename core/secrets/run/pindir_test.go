package run

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The pins of nazar run's loader and of its folder.

func realTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// tick lets the file clock move on after a fixture was written (Linux's is
// coarse), as an installed bundle's files are long written.
func tick() { time.Sleep(20 * time.Millisecond) }

func TestPinHashesARegularFile(t *testing.T) {
	d := realTemp(t)
	p := write(t, filepath.Join(d, "env.cjs"), "loader", 0o644)
	sum := sha256.Sum256([]byte("loader"))
	f, err := Pin(p)
	if err != nil || f.Dir || f.Path != p || f.SHA256 != hex.EncodeToString(sum[:]) || f.Ino == 0 {
		t.Fatalf("Pin = %+v, %v", f, err)
	}
	if err := Repin(f); err != nil {
		t.Fatalf("an unchanged file: %v", err)
	}
}

func TestPinRefusesALink(t *testing.T) {
	d := realTemp(t)
	write(t, filepath.Join(d, "copy.cjs"), "loader", 0o644)
	link(t, "copy.cjs", filepath.Join(d, "env.cjs"))
	if _, err := Pin(filepath.Join(d, "env.cjs")); err == nil {
		t.Fatal("a link must be refused")
	}
}

func TestPinDirHoldsExactlyItsEntries(t *testing.T) {
	t.Run("exactly its entry", func(t *testing.T) {
		dir := filepath.Join(realTemp(t), "python")
		write(t, filepath.Join(dir, "sitecustomize.py"), "loader", 0o644)
		f, err := PinDir(dir, "sitecustomize.py")
		if err != nil || !f.Dir || f.Path != dir || f.Ino == 0 || f.SHA256 != "" {
			t.Fatalf("PinDir = %+v, %v", f, err)
		}
		if err := Repin(f); err != nil {
			t.Fatalf("an unchanged folder: %v", err)
		}
	})
	for _, tc := range []struct {
		name string
		prep func(t *testing.T, dir string)
	}{
		{"a module beside it", func(t *testing.T, dir string) { write(t, filepath.Join(dir, "socket.py"), "x", 0o644) }},
		{"an extension beside it", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "sitecustomize.cpython-314-darwin.so"), "x", 0o644)
		}},
		{"cached bytecode", func(t *testing.T, dir string) {
			write(t, filepath.Join(dir, "__pycache__", "sitecustomize.cpython-314.pyc"), "x", 0o644)
		}},
		{"an empty folder beside it", func(t *testing.T, dir string) { os.Mkdir(filepath.Join(dir, "sitecustomize"), 0o755) }},
		{"the entry missing", func(t *testing.T, dir string) { os.Remove(filepath.Join(dir, "sitecustomize.py")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(realTemp(t), "python")
			write(t, filepath.Join(dir, "sitecustomize.py"), "loader", 0o644)
			tc.prep(t, dir)
			if _, err := PinDir(dir, "sitecustomize.py"); err == nil || !strings.Contains(err.Error(), "must hold only") {
				t.Fatalf("PinDir = %v, want a refusal", err)
			}
		})
	}
	t.Run("a link to a folder", func(t *testing.T) {
		d := realTemp(t)
		write(t, filepath.Join(d, "real", "sitecustomize.py"), "loader", 0o644)
		link(t, "real", filepath.Join(d, "python"))
		if _, err := PinDir(filepath.Join(d, "python"), "sitecustomize.py"); err == nil {
			t.Fatal("a link must be refused")
		}
	})
	t.Run("a file", func(t *testing.T) {
		p := write(t, filepath.Join(realTemp(t), "python"), "x", 0o644)
		if _, err := PinDir(p); err == nil {
			t.Fatal("a file is not a folder")
		}
	})
}

// Any change to the folder after it was pinned is seen, even when undone:
// its mtime and ctime moved, which no user process can set back.
func TestRepinSeesAFolderChangedAndPutBack(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, parent, dir string)
	}{
		{"a file added and removed", func(t *testing.T, _, dir string) {
			write(t, filepath.Join(dir, "socket.py"), "x", 0o644)
			os.Remove(filepath.Join(dir, "socket.py"))
		}},
		{"the entry renamed aside and back", func(t *testing.T, _, dir string) {
			p := filepath.Join(dir, "sitecustomize.py")
			os.Rename(p, p+".x")
			os.Rename(p+".x", p)
		}},
		{"the folder moved aside, a fake in its place, and moved back", func(t *testing.T, parent, dir string) {
			os.Rename(dir, filepath.Join(parent, "aside"))
			write(t, filepath.Join(dir, "sitecustomize.py"), "evil", 0o644)
			os.RemoveAll(dir)
			os.Rename(filepath.Join(parent, "aside"), dir)
		}},
		{"its mode changed and put back", func(t *testing.T, _, dir string) {
			os.Chmod(dir, 0o777)
			os.Chmod(dir, 0o755)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := realTemp(t)
			dir := filepath.Join(parent, "python")
			write(t, filepath.Join(dir, "sitecustomize.py"), "loader", 0o644)
			os.Chmod(dir, 0o755)
			f, err := PinDir(dir, "sitecustomize.py")
			if err != nil {
				t.Fatal(err)
			}
			tick()
			tc.change(t, parent, dir)
			if err := Repin(f); err == nil {
				t.Fatal("a folder changed after its pin was not seen")
			}
		})
	}
}

// PinAbove pins every folder above a path that a process of this user can
// move aside and back: one in a folder it can write, or owns and so can
// make writable. Moving a folder changes its own ctime only, so the pins
// of the loader's folder and file alone still match a tree put back.
func TestPinAboveSeesAFolderAboveMovedAsideAndBack(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "nzp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(base, "app"), 0o755); os.RemoveAll(base) })
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "app", "Contents", "loaders", "node")
	write(t, filepath.Join(dir, "env.cjs"), "loader", 0o644)
	// app is the user's own but not writable: Contents can still be moved
	// once the user makes it writable again.
	if err := os.Chmod(filepath.Join(base, "app"), 0o555); err != nil {
		t.Fatal(err)
	}
	pins, err := PinAbove(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range pins {
		if !f.Dir {
			t.Fatalf("%s pinned as a file", f.Path)
		}
		got = append(got, f.Path)
	}
	// /tmp's (or /private/tmp's) parent belongs to root: it and the folders
	// above it can't be moved by the user, and change all the time.
	want := []string{filepath.Join(base, "app", "Contents", "loaders"), filepath.Join(base, "app", "Contents"), filepath.Join(base, "app"), base}
	if strings.Join(got, ":") != strings.Join(want, ":") {
		t.Fatalf("PinAbove = %q, want %q", got, want)
	}
	for _, f := range pins {
		if err := Repin(f); err != nil {
			t.Fatalf("an unchanged folder: %v", err)
		}
	}
	tick()
	os.Chmod(filepath.Join(base, "app"), 0o755)
	c := filepath.Join(base, "app", "Contents")
	if err := os.Rename(c, c+".aside"); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "env.cjs"), "evil", 0o644)
	os.RemoveAll(c)
	if err := os.Rename(c+".aside", c); err != nil {
		t.Fatal(err)
	}
	if err := Repin(pins[1]); err == nil {
		t.Fatal("Contents moved aside and back was not seen")
	}
}
