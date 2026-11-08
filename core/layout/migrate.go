package layout

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/atas/nazar/core/unixsock"
)

// OldConfigDir is ~/.config/nazar, where config.yaml and keys/ were before
// this layout.
func OldConfigDir(home string) string { return filepath.Join(home, ".config", "nazar") }

// Migrate moves an install of the old layout into this one; nazar-agent
// runs it at start, before it reads the config. When ~/.nazar/config/
// config.yaml does not exist and ~/.config/nazar/config.yaml does, the
// files of ~/.config/nazar/keys move to ~/.nazar/keys, then config.yaml.bak*
// and config.yaml (last, so an interrupted move is finished at the next
// start) to ~/.nazar/config, each by rename(2): same inode, same mode, same
// bytes, so the approved config (kept by content) still matches. Only
// regular files move, and never over an existing one; a link, a folder or a
// clash stays where it is and is reported. ~/.config/nazar and its keys/
// are removed once empty. The old sockets ~/.nazar/agent.sock and
// control.sock are removed when they are sockets nobody listens on. It
// returns one line per thing done or left; nothing to do is nil.
func Migrate(home string) []string {
	m := &migration{}
	m.config(home)
	for _, n := range []string{"agent.sock", "control.sock"} {
		p := filepath.Join(Root(home), n)
		if fi, err := os.Lstat(p); err == nil && fi.Mode().Type() == fs.ModeSocket {
			if err := unixsock.RemoveStale(p); err != nil {
				m.say("left the old socket %s: %v", p, err)
			} else {
				m.say("removed the old socket %s (sockets are in %s now)", p, RunDir(home))
			}
		}
	}
	return m.lines
}

type migration struct{ lines []string }

func (m *migration) say(format string, args ...any) {
	m.lines = append(m.lines, fmt.Sprintf(format, args...))
}

func (m *migration) config(home string) {
	old, oldCfg, newCfg := OldConfigDir(home), filepath.Join(OldConfigDir(home), "config.yaml"), ConfigFile(home)
	if _, err := os.Lstat(oldCfg); err != nil {
		return // nothing to move (or ~/.config/nazar is not readable: left alone)
	}
	if _, err := os.Lstat(newCfg); err == nil {
		m.say("both %s and %s exist; nazar reads %s: compare them and remove the old one", oldCfg, newCfg, newCfg)
		return
	}
	if fi, err := os.Lstat(old); err != nil || !fi.IsDir() {
		m.say("%s is not a folder (a link?); move its files into %s by hand", old, Root(home))
		return
	}
	if fi, err := os.Lstat(oldCfg); err != nil || !fi.Mode().IsRegular() {
		m.say("%s is not a regular file (a link?); move it to %s by hand", oldCfg, newCfg)
		return
	}
	if err := mkdirs(0o700, Root(home), ConfigDir(home)); err != nil {
		m.say("cannot make %s: %v", ConfigDir(home), err)
		return
	}
	if m.moveAll(filepath.Join(old, "keys"), KeysDir(home), 0o755, func(string) bool { return true }) {
		_ = os.Remove(filepath.Join(old, "keys")) // only when empty
	}
	m.moveAll(old, ConfigDir(home), 0o700, func(n string) bool { return strings.HasPrefix(n, "config.yaml.bak") })
	if m.move(oldCfg, newCfg) {
		m.say("moved %s to %s", oldCfg, newCfg)
	}
	if err := os.Remove(old); err == nil {
		m.say("removed the empty %s", old)
	} else if ents, _ := os.ReadDir(old); len(ents) > 0 {
		names := make([]string, len(ents))
		for i, e := range ents {
			names[i] = e.Name()
		}
		m.say("left %s: it still holds %s", old, strings.Join(names, ", "))
	}
}

// moveAll moves the regular files of dir that want names into to (made with
// mode if missing) and reports whether dir is a real folder. A missing dir
// moves nothing.
func (m *migration) moveAll(dir, to string, mode fs.FileMode, want func(string) bool) bool {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil || !fi.IsDir() {
		m.say("%s is not a folder (a link?); move its files into %s by hand", dir, to)
		return false
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		m.say("cannot read %s: %v", dir, err)
		return true
	}
	n := 0
	for _, e := range ents {
		if !want(e.Name()) {
			continue
		}
		if n == 0 {
			if err := mkdirs(mode, to); err != nil {
				m.say("cannot make %s: %v", to, err)
				return true
			}
		}
		if m.move(filepath.Join(dir, e.Name()), filepath.Join(to, e.Name())) {
			n++
		}
	}
	if n > 0 {
		m.say("moved %d file(s) from %s to %s", n, dir, to)
	}
	return true
}

// move renames a regular file from to to, never over an existing file, and
// reports whether it moved; anything else is reported and left.
func (m *migration) move(from, to string) bool {
	fi, err := os.Lstat(from)
	if err != nil || !fi.Mode().IsRegular() {
		m.say("left %s: not a regular file (a link?); move it to %s by hand", from, to)
		return false
	}
	if err := renameNoReplace(from, to); err != nil {
		if errors.Is(err, fs.ErrExist) {
			m.say("left %s: %s exists; compare them and remove the old one", from, to)
		} else {
			m.say("left %s: %v", from, err)
		}
		return false
	}
	return true
}

// mkdirs makes each missing folder, in order, with mode. An existing one is
// kept as it is: unixsock and the readers check it.
func mkdirs(mode fs.FileMode, dirs ...string) error {
	for _, p := range dirs {
		if err := os.Mkdir(p, mode); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	return nil
}
