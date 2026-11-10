package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unsetEnv removes the variable for this test and restores it after.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
}

// withReady points Check at path for this test.
func withReady(t *testing.T, path string) {
	t.Helper()
	old := readyPath
	readyPath = path
	t.Cleanup(func() { readyPath = old })
}

func TestCheckRefusesOutsideTheContainer(t *testing.T) {
	unsetEnv(t, envVar)
	err := Check()
	if err == nil {
		t.Fatal("Check() = nil with NAZAR_LINUX_TEST_CONTAINER unset")
	}
	if !strings.Contains(err.Error(), envVar) {
		t.Fatalf("error does not name the variable: %v", err)
	}
}

func TestCheckRefusesOtherValues(t *testing.T) {
	for _, v := range []string{"", "0", "true", "yes", " 1"} {
		t.Setenv(envVar, v)
		if err := Check(); err == nil {
			t.Fatalf("Check() = nil with %s=%q", envVar, v)
		}
	}
}

func TestCheckRefusesWithoutTheReadyFile(t *testing.T) {
	t.Setenv(envVar, "1")
	withReady(t, filepath.Join(t.TempDir(), "ready"))
	err := Check()
	if err == nil {
		t.Fatal("Check() = nil with no ready file")
	}
	if !strings.Contains(err.Error(), "ready") {
		t.Fatalf("error does not name the ready file: %v", err)
	}
}

// The ready file is touched by the container's entrypoint as root; one the
// test user made itself (a variable set by hand on a real machine) is refused.
func TestCheckRefusesAReadyFileNotOwnedByRoot(t *testing.T) {
	t.Setenv(envVar, "1")
	path := filepath.Join(t.TempDir(), "ready")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// Root made it: hand it to nobody so it is not root's.
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	withReady(t, path)
	err := Check()
	if err == nil {
		t.Fatal("Check() = nil with a ready file the user owns")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Fatalf("error does not say root: %v", err)
	}
}

func TestCheckRefusesAReadySymlink(t *testing.T) {
	t.Setenv(envVar, "1")
	dir := t.TempDir()
	path := filepath.Join(dir, "ready")
	// "/" is owned by root everywhere; a link to it must still be refused.
	if err := os.Symlink("/", path); err != nil {
		t.Fatal(err)
	}
	withReady(t, path)
	if err := Check(); err == nil {
		t.Fatal("Check() = nil with the ready path a symlink")
	}
}

// The positive case on any host: /etc/passwd is a regular file root owns.
func TestCheckAcceptsTheVariableAndARootReadyFile(t *testing.T) {
	t.Setenv(envVar, "1")
	withReady(t, "/etc/passwd")
	if err := Check(); err != nil {
		t.Fatalf("Check() = %v, want nil", err)
	}
}

func TestRequireDoesNotRunOutsideTheContainer(t *testing.T) {
	unsetEnv(t, envVar)
	// A nil *testing.M would panic in m.Run: Require must return before it.
	if code := Require(nil); code != 1 {
		t.Fatalf("Require outside the container = %d, want 1", code)
	}
}
