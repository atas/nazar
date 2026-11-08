package run

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A file or folder on a volume a process of the user mounted (a
// disk image, a share, a file-system extension; statfs f_owner is the
// user's uid) is never pinned, and one that comes to be on such a volume
// is a change: a share's server can give nazar and the interpreter
// different bytes. The volumes macOS mounts itself are root's (measured on
// macOS 27). mountedBy is the seam: no test mounts anything.
func TestPinRefusesAVolumeYouMounted(t *testing.T) {
	dir := realTemp(t)
	vol := filepath.Join(dir, "vol")
	if err := os.MkdirAll(filepath.Join(vol, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(vol, "sub", "env.cjs")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	userMounted, broken := "", false
	old := mountedBy
	t.Cleanup(func() { mountedBy = old })
	mountedBy = func(f *os.File) (uint32, error) {
		mu.Lock()
		defer mu.Unlock()
		if broken {
			return 0, errors.New("statfs failed")
		}
		if userMounted != "" && (f.Name() == userMounted || strings.HasPrefix(f.Name(), userMounted+"/")) {
			return 501, nil
		}
		return 0, nil
	}
	set := func(path string, fail bool) { mu.Lock(); userMounted, broken = path, fail; mu.Unlock() }

	pinned, err := Pin(file)
	if err != nil {
		t.Fatal(err)
	}
	folder, err := PinDir(filepath.Join(vol, "sub"), "env.cjs")
	if err != nil {
		t.Fatal(err)
	}
	above, err := PinAbove(folder.Path)
	if err != nil || len(above) == 0 {
		t.Fatalf("PinAbove: %v %v", above, err)
	}

	set(vol, false)
	if _, err := Pin(file); err == nil || !strings.Contains(err.Error(), "on a volume you mounted") {
		t.Fatalf("Pin on a volume you mounted: %v", err)
	}
	if _, err := PinDir(filepath.Join(vol, "sub"), "env.cjs"); err == nil {
		t.Fatal("PinDir on a volume you mounted must refuse")
	}
	for _, f := range []File{pinned, folder} {
		if Repin(f) == nil {
			t.Fatalf("Repin of %s, now on a volume you mounted, must refuse", f.Path)
		}
	}
	set(dir, false) // a folder above the loader's
	if _, err := PinAbove(folder.Path); err == nil {
		t.Fatal("PinAbove through a volume you mounted must refuse")
	}
	set("", true)
	if _, err := Pin(file); err == nil {
		t.Fatal("a volume whose owner can't be read must refuse")
	}
	set("", false)
	if Repin(pinned) != nil || Repin(folder) != nil {
		t.Fatal("unchanged on macOS's own volume: Repin must pass")
	}
}
