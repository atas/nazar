package layout

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func write(t *testing.T, p, body string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func wantFile(t *testing.T, p, body string, mode fs.FileMode) {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != mode {
		t.Errorf("%s: mode %v, want a regular file %o", p, fi.Mode(), mode)
	}
	if b, _ := os.ReadFile(p); string(b) != body {
		t.Errorf("%s holds %q, want %q", p, b, body)
	}
}

func wantGone(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s still exists (%v)", p, err)
	}
}

func wantLine(t *testing.T, lines []string, sub string) {
	t.Helper()
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return
		}
	}
	t.Errorf("no line says %q:\n%s", sub, strings.Join(lines, "\n"))
}

// oldInstall lays out what an install of the old layout left: its config
// with a backup, keys and a CA, each in its own mode.
func oldInstall(t *testing.T, home string) (old string) {
	t.Helper()
	old = OldConfigDir(home)
	write(t, filepath.Join(old, "config.yaml"), "config\n", 0o600)
	write(t, filepath.Join(old, "config.yaml.bak"), "backup\n", 0o640)
	write(t, filepath.Join(old, "keys", "github.pub"), "ecdsa github\n", 0o644)
	write(t, filepath.Join(old, "keys", "k8s-ca-hydra.crt"), "ca\n", 0o600)
	return old
}

func TestMigrateNothingToDo(t *testing.T) {
	home := fakeHome(t)
	if l := Migrate(home); l != nil {
		t.Fatalf("empty home: %q", l)
	}
	if ents, _ := os.ReadDir(home); len(ents) != 0 {
		t.Fatalf("Migrate made %v in an empty home", ents)
	}
	// Already in the new layout: nothing moves, nothing is said.
	write(t, ConfigFile(home), "config\n", 0o600)
	write(t, filepath.Join(KeysDir(home), "github.pub"), "ecdsa\n", 0o644)
	if l := Migrate(home); l != nil {
		t.Fatalf("new layout: %q", l)
	}
	wantFile(t, ConfigFile(home), "config\n", 0o600)
}

func TestMigrateMovesAll(t *testing.T) {
	home := fakeHome(t)
	old := oldInstall(t, home)
	before, err := os.Lstat(filepath.Join(old, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	lines := Migrate(home)
	wantFile(t, ConfigFile(home), "config\n", 0o600)
	wantFile(t, filepath.Join(ConfigDir(home), "config.yaml.bak"), "backup\n", 0o640)
	wantFile(t, filepath.Join(KeysDir(home), "github.pub"), "ecdsa github\n", 0o644)
	wantFile(t, filepath.Join(KeysDir(home), "k8s-ca-hydra.crt"), "ca\n", 0o600)
	wantGone(t, old)
	wantLine(t, lines, "removed the empty "+old)
	for _, dir := range []string{Root(home), ConfigDir(home)} {
		if fi, err := os.Lstat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v, want mode 700", dir, fi, err)
		}
	}
	// rename(2): the same file, not a copy.
	after, err := os.Lstat(ConfigFile(home))
	if err != nil || !os.SameFile(before, after) {
		t.Errorf("config.yaml is not the same file after the move (%v)", err)
	}
	// ~/.config itself is not nazar's.
	if _, err := os.Lstat(filepath.Join(home, ".config")); err != nil {
		t.Errorf("~/.config: %v", err)
	}
	if l := Migrate(home); l != nil {
		t.Errorf("second run: %q", l)
	}
}

// Keys never existed (a config made by hand): the config still moves and
// no keys folder is made.
func TestMigrateKeysDirMissing(t *testing.T) {
	home := fakeHome(t)
	write(t, filepath.Join(OldConfigDir(home), "config.yaml"), "config\n", 0o600)
	Migrate(home)
	wantFile(t, ConfigFile(home), "config\n", 0o600)
	wantGone(t, KeysDir(home))
	wantGone(t, OldConfigDir(home))
}

// A config in both places: both stay, it is said, and nothing else moves.
func TestMigrateConfigInBothPlaces(t *testing.T) {
	home := fakeHome(t)
	old := oldInstall(t, home)
	write(t, ConfigFile(home), "new\n", 0o600)
	lines := Migrate(home)
	wantFile(t, ConfigFile(home), "new\n", 0o600)
	wantFile(t, filepath.Join(old, "config.yaml"), "config\n", 0o600)
	wantFile(t, filepath.Join(old, "keys", "github.pub"), "ecdsa github\n", 0o644)
	wantGone(t, filepath.Join(KeysDir(home), "github.pub"))
	wantLine(t, lines, "both ")
}

// A key already at the destination: neither copy changes, it is said, the
// rest moves and the old folder stays because it is not empty.
func TestMigrateNeverOverwritesAFile(t *testing.T) {
	home := fakeHome(t)
	old := oldInstall(t, home)
	write(t, filepath.Join(KeysDir(home), "github.pub"), "other\n", 0o644)
	write(t, filepath.Join(ConfigDir(home), "config.yaml.bak"), "other\n", 0o600)
	lines := Migrate(home)
	wantFile(t, filepath.Join(KeysDir(home), "github.pub"), "other\n", 0o644)
	wantFile(t, filepath.Join(old, "keys", "github.pub"), "ecdsa github\n", 0o644)
	wantFile(t, filepath.Join(ConfigDir(home), "config.yaml.bak"), "other\n", 0o600)
	wantFile(t, filepath.Join(old, "config.yaml.bak"), "backup\n", 0o640)
	wantFile(t, filepath.Join(KeysDir(home), "k8s-ca-hydra.crt"), "ca\n", 0o600)
	wantFile(t, ConfigFile(home), "config\n", 0o600)
	wantLine(t, lines, "left "+filepath.Join(old, "keys", "github.pub"))
	wantLine(t, lines, "left "+filepath.Join(old, "config.yaml.bak"))
	wantLine(t, lines, "left "+old+": it still holds")
}

// A link at any old path is neither followed nor moved: it stays, its target
// is unchanged, and it is said.
func TestMigrateLeavesLinks(t *testing.T) {
	outside := func(t *testing.T, home string) string {
		p := filepath.Join(home, "elsewhere", "target")
		write(t, p, "target\n", 0o600)
		return p
	}
	wantLink := func(t *testing.T, p string) {
		t.Helper()
		if fi, err := os.Lstat(p); err != nil || fi.Mode().Type() != fs.ModeSymlink {
			t.Errorf("%s is no longer a link (%v, %v)", p, fi, err)
		}
	}

	t.Run("config.yaml", func(t *testing.T) {
		home := fakeHome(t)
		old := oldInstall(t, home)
		target := outside(t, home)
		cfg := filepath.Join(old, "config.yaml")
		os.Remove(cfg)
		if err := os.Symlink(target, cfg); err != nil {
			t.Fatal(err)
		}
		lines := Migrate(home)
		wantLink(t, cfg)
		wantFile(t, target, "target\n", 0o600)
		wantGone(t, ConfigFile(home))
		wantLine(t, lines, cfg)
	})

	t.Run("a key", func(t *testing.T) {
		home := fakeHome(t)
		old := oldInstall(t, home)
		target := outside(t, home)
		link := filepath.Join(old, "keys", "evil.pub")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		lines := Migrate(home)
		wantLink(t, link)
		wantFile(t, target, "target\n", 0o600)
		wantGone(t, filepath.Join(KeysDir(home), "evil.pub"))
		wantFile(t, filepath.Join(KeysDir(home), "github.pub"), "ecdsa github\n", 0o644)
		wantFile(t, ConfigFile(home), "config\n", 0o600)
		wantLine(t, lines, "left "+link)
	})

	t.Run("keys/", func(t *testing.T) {
		home := fakeHome(t)
		write(t, filepath.Join(OldConfigDir(home), "config.yaml"), "config\n", 0o600)
		target := outside(t, home)
		link := filepath.Join(OldConfigDir(home), "keys")
		if err := os.Symlink(filepath.Dir(target), link); err != nil {
			t.Fatal(err)
		}
		lines := Migrate(home)
		wantLink(t, link)
		wantFile(t, target, "target\n", 0o600)
		wantGone(t, filepath.Join(KeysDir(home), "target"))
		wantFile(t, ConfigFile(home), "config\n", 0o600)
		wantLine(t, lines, link)
	})

	t.Run("~/.config/nazar", func(t *testing.T) {
		home := fakeHome(t)
		real := filepath.Join(home, "dotfiles", "nazar")
		write(t, filepath.Join(real, "config.yaml"), "config\n", 0o600)
		if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, OldConfigDir(home)); err != nil {
			t.Fatal(err)
		}
		lines := Migrate(home)
		wantLink(t, OldConfigDir(home))
		wantFile(t, filepath.Join(real, "config.yaml"), "config\n", 0o600)
		wantGone(t, ConfigFile(home))
		wantLine(t, lines, OldConfigDir(home))
	})
}

// The old sockets go only when they are sockets nobody listens on; a file
// or a link of that name stays, and a link's target is not touched.
func TestMigrateOldSockets(t *testing.T) {
	home := fakeHome(t)
	if err := os.Mkdir(Root(home), 0o700); err != nil {
		t.Fatal(err)
	}
	agent, ctl := filepath.Join(Root(home), "agent.sock"), filepath.Join(Root(home), "control.sock")
	stale := func(p string) {
		t.Helper()
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		l.SetUnlinkOnClose(false)
		l.Close()
	}
	stale(agent)
	stale(ctl)
	lines := Migrate(home)
	wantGone(t, agent)
	wantGone(t, ctl)
	wantLine(t, lines, "removed the old socket "+agent)

	// A socket someone still listens on stays.
	live, err := net.ListenUnix("unix", &net.UnixAddr{Name: agent, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	lines = Migrate(home)
	if fi, err := os.Lstat(agent); err != nil || fi.Mode().Type() != fs.ModeSocket {
		t.Errorf("the live socket is gone (%v)", err)
	}
	wantLine(t, lines, "left the old socket "+agent)

	// A link named control.sock, to a socket: not followed, not removed.
	target := filepath.Join(home, "t.sock")
	stale(target)
	if err := os.Symlink(target, ctl); err != nil {
		t.Fatal(err)
	}
	Migrate(home)
	if fi, err := os.Lstat(ctl); err != nil || fi.Mode().Type() != fs.ModeSymlink {
		t.Errorf("the link is gone (%v)", err)
	}
	if fi, err := os.Lstat(target); err != nil || fi.Mode().Type() != fs.ModeSocket {
		t.Errorf("the link's target is gone (%v)", err)
	}
	os.Remove(ctl)
	// A regular file of that name stays.
	write(t, ctl, "not a socket\n", 0o600)
	Migrate(home)
	wantFile(t, ctl, "not a socket\n", 0o600)
}

// renameNoReplace refuses an existing destination with EEXIST, atomically,
// whatever it is.
func TestRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	write(t, a, "a\n", 0o600)
	write(t, b, "b\n", 0o600)
	if err := renameNoReplace(a, b); !errors.Is(err, syscall.EEXIST) || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err %v, want EEXIST", err)
	}
	wantFile(t, a, "a\n", 0o600)
	wantFile(t, b, "b\n", 0o600)
	os.Remove(b)
	if err := renameNoReplace(a, b); err != nil {
		t.Fatal(err)
	}
	wantGone(t, a)
	wantFile(t, b, "a\n", 0o600)
}
