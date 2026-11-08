package layout

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/atas/nazar/core/unixsock"
)

func TestTildeFormsAreTheFunctions(t *testing.T) {
	for got, want := range map[string]string{
		ConfigFile("~"):  ConfigFileTilde,
		KeysDir("~"):     KeysDirTilde,
		AgentSocket("~"): AgentSocketTilde,
	} {
		if got != want {
			t.Errorf("%s, want %s", got, want)
		}
	}
}

func TestPrepare(t *testing.T) {
	home := fakeHome(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	if err := Prepare(home); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{Root(home), ConfigDir(home), RunDir(home)} {
		if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v, want a folder, mode 700", dir, fi, err)
		}
	}
	if err := Prepare(home); err != nil {
		t.Errorf("second run: %v", err)
	}
	// A deleted run/ comes back.
	if err := os.Remove(RunDir(home)); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(home); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(RunDir(home)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("run/ after a delete: %v %v", fi, err)
	}
	// A ~/.nazar or a run/ open to others is refused, not fixed.
	for _, dir := range []string{RunDir(home), Root(home)} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := Prepare(home); err == nil || !strings.Contains(err.Error(), "mode") {
			t.Errorf("%s 0755: %v, want a mode error", dir, err)
		}
		if fi, _ := os.Lstat(dir); fi.Mode().Perm() != 0o755 {
			t.Errorf("%s was changed to %o", dir, fi.Mode().Perm())
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A link for ~/.nazar is refused: the sockets would be reached through it.
	moved := filepath.Join(home, "elsewhere")
	if err := os.Rename(Root(home), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, Root(home)); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(home); err == nil {
		t.Error("a link at ~/.nazar was accepted")
	}
}

// A real-length home keeps the sockets within sun_path (macOS: 103 bytes, unixsock checks it).
func TestSocketsFitSunPath(t *testing.T) {
	home := "/Users/" + strings.Repeat("u", 32)
	for _, p := range []string{AgentSocket(home), ControlSocket(home), filepath.Join(RunDir(home), strings.Repeat("a", 32)+".sock")} {
		if len(p) > unixsock.MaxPathLen {
			t.Errorf("%s is %d bytes", p, len(p))
		}
	}
}

// fakeHome is a temp home short enough for a socket.
func fakeHome(t *testing.T) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "nzl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	return home
}
