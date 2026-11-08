package daemon

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

// pathAdvice warns, once per file, about each path: matcher of c whose
// file, or a folder above it, this user can write (spec 4.2): any program
// of theirs can put its own code there and get the rule's access. Under
// /opt/homebrew that is every path. A warning, not an error: the user
// chose the rule, and it is still narrower than unknown.
func (d *Daemon) pathAdvice(c *config.Config) []control.ConfigProblem {
	if c == nil {
		return nil
	}
	var out []control.ConfigProblem
	seen := map[string]bool{}
	for _, u := range c.PathMatchers() {
		if seen[u.Path] {
			continue
		}
		seen[u.Path] = true
		if !userWritable(u.Path) {
			continue
		}
		shown := u.Path
		if q := strconv.QuoteToASCII(u.Path); q != `"`+u.Path+`"` {
			shown = q
		}
		out = append(out, control.ConfigProblem{Severity: string(config.SevWarning), Path: u.Where,
			Message: "path:" + shown + " is writable by your user; any program of yours can replace it and get this rule's access"})
	}
	return out
}

// userWritable reports whether this user can change what path p runs:
// write or own (and so chmod) the file or any folder above it, along p as
// written and along its resolved path. A file that does not exist yet is
// as writable as the folder it would be made in.
func userWritable(p string) bool {
	paths := []string{p}
	if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
		paths = append(paths, r)
	}
	for _, q := range paths {
		for x := q; ; x = filepath.Dir(x) {
			if canChange(x) {
				return true
			}
			if x == filepath.Dir(x) {
				break
			}
		}
	}
	return false
}

func canChange(p string) bool {
	if unix.Access(p, unix.W_OK) == nil {
		return true
	}
	var st unix.Stat_t
	return unix.Stat(p, &st) == nil && int(st.Uid) == os.Geteuid()
}
