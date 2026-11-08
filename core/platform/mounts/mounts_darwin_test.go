//go:build darwin

package mounts

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The kqueue watch with nothing mounted: no change through file
// writes, a rename and a process; a change once stopped (fail closed). The
// mount itself is checked by the conformance suite in NazarConformanceHost
// (make conformance), which attaches a disk image in a temp dir.
func TestWatchWithNothingMounted(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("no mount watch on macOS: late-env would be refused")
	}
	changed, stop, err := m.WatchMounts()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "f"), filepath.Join(dir, "g")); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("/usr/bin/true").Run(); err != nil {
		t.Fatal(err)
	}
	if changed() {
		t.Fatal("a change with nothing mounted (a volume the system mounted meanwhile fails this too: run again)")
	}
	stop()
	stop()
	if !changed() {
		t.Fatal("after stop, changed must report a change")
	}
}
