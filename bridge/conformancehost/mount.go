//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// mountScratch mounts a 1 MiB disk image over a folder of a temp dir and
// unmounts it again (D12): the conformance suite's Mount on macOS, and a
// mount during a real run in the end-to-end test. -nobrowse keeps it out of
// the Finder. Nothing on the volume is ever opened: a disk image is a
// removable volume, which macOS may ask about before a program reads one.
// Never a folder of the user's.
func mountScratch(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	img, mnt := filepath.Join(dir, "nz.dmg"), filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	hdiutil := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("/usr/bin/hdiutil", args...).CombinedOutput(); err != nil {
			t.Fatalf("hdiutil %s: %v\n%s", args[0], err, out)
		}
	}
	hdiutil("create", "-size", "1m", "-fs", "HFS+", "-layout", "NONE", "-volname", "nazar-test", img)
	// Registered after TempDir, so it runs before the folder is removed.
	t.Cleanup(func() { _ = exec.Command("/usr/bin/hdiutil", "detach", "-force", mnt).Run() })
	hdiutil("attach", "-nobrowse", "-noverify", "-noautoopen", "-mountpoint", mnt, img)
	hdiutil("detach", mnt)
}
