package match

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

func fakeProc(path string, args ...string) fake.Proc {
	return fake.Proc{Path: path, Args: args, Code: adhoc}
}

func fakeSSH() fake.Proc { return fake.SSHProc("h") }

// realDir is a fresh temporary directory with its symlinks resolved (on
// macOS the temp dir is under /var, a symlink to /private/var): the kernel
// reports an executable's resolved path.
func realDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func pathM(p string) config.Matcher { return config.Matcher{Kind: config.MatchPath, Path: p} }

// adhoc is a Homebrew binary's code identity: linker-signed, no team.
var adhoc = platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "a.out", CDHash: []byte{0xaa}}

// A launchd-started unsigned program (no app above it) asking directly:
// the chain is unknown, the program is its only process.
func (en *env) launchd(path string, args ...string) platform.ProcessRef {
	return en.f.Launch(platform.ProcessRef{}, fakeProc(path, args...))
}

// path: is resolved at every match (spec 4.2): a rule through a Homebrew
// opt/ symlink matches the process at its current target, and after an
// upgrade repoints the link, the new target and no longer the old one.
func TestPathResolvesSymlinkAtMatchTime(t *testing.T) {
	en := newEnv(t)
	d := realDir(t)
	v1 := filepath.Join(d, "Cellar/mytool/1.0/bin/mytool")
	v2 := filepath.Join(d, "Cellar/mytool/1.1/bin/mytool")
	touch(t, v1)
	touch(t, v2)
	opt := filepath.Join(d, "opt/mytool")
	if err := os.MkdirAll(filepath.Dir(opt), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(d, "Cellar/mytool/1.0"), opt); err != nil {
		t.Fatal(err)
	}
	m := []config.Matcher{pathM(filepath.Join(opt, "bin/mytool"))}
	if !en.e.Apps(m, en.r.Resolve(en.launchd(v1))) {
		t.Fatal("the process at the symlink's target must match")
	}
	if en.e.Apps(m, en.r.Resolve(en.launchd(v2))) {
		t.Fatal("another version must not match while the link names 1.0")
	}
	// brew upgrade: the opt/ link now names 1.1.
	if err := os.Remove(opt); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(d, "Cellar/mytool/1.1"), opt); err != nil {
		t.Fatal(err)
	}
	if !en.e.Apps(m, en.r.Resolve(en.launchd(v2))) {
		t.Fatal("after the upgrade the new target must match")
	}
	if en.e.Apps(m, en.r.Resolve(en.launchd(v1))) {
		t.Fatal("after the upgrade the old target must no longer match")
	}
}

// The literal rule path matches too (it is the file); a path that does
// not exist matches nothing, not even a process reporting that very path.
func TestPathLiteralAndMissing(t *testing.T) {
	en := newEnv(t)
	tmp := t.TempDir() // on macOS under /var, a symlink: literal and resolved differ
	tool := filepath.Join(tmp, "bin/tool")
	touch(t, tool)
	resolved, err := filepath.EvalSymlinks(tool)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{tool, resolved} {
		if !en.e.Apps([]config.Matcher{pathM(tool)}, en.r.Resolve(en.launchd(p))) {
			t.Fatalf("a process at %s must match path:%s", p, tool)
		}
	}
	gone := filepath.Join(tmp, "bin/gone")
	if en.e.Apps([]config.Matcher{pathM(gone)}, en.r.Resolve(en.launchd(gone))) {
		t.Fatal("a path that does not exist must match nothing")
	}
}

// Exact file only: no directory, prefix or sibling matches.
func TestPathIsExactFile(t *testing.T) {
	en := newEnv(t)
	d := realDir(t)
	tool := filepath.Join(d, "bin/tool")
	touch(t, tool)
	touch(t, tool+"2")
	touch(t, filepath.Join(d, "bin/sub/tool"))
	for _, rule := range []string{filepath.Join(d, "bin"), d, filepath.Join(d, "bin/too")} {
		for _, p := range []string{tool, tool + "2", filepath.Join(d, "bin/sub/tool")} {
			if en.e.Apps([]config.Matcher{pathM(rule)}, en.r.Resolve(en.launchd(p))) {
				t.Fatalf("path:%s matched %s", rule, p)
			}
		}
	}
	if en.e.Apps([]config.Matcher{pathM(tool)}, en.r.Resolve(en.launchd(tool+"2"))) {
		t.Fatal("a sibling with a longer name must not match")
	}
}

// argv[0] is the caller's to choose: only the path the kernel reports
// counts.
func TestPathIgnoresArgv0(t *testing.T) {
	en := newEnv(t)
	d := realDir(t)
	tool := filepath.Join(d, "bin/tool")
	other := filepath.Join(d, "bin/other")
	touch(t, tool)
	touch(t, other)
	if en.e.Apps([]config.Matcher{pathM(tool)}, en.r.Resolve(en.launchd(other, tool, "--flag"))) {
		t.Fatal("argv[0] naming the rule's path must not match")
	}
}

// Like signed:, path: matches any process in the chain, in a known or an
// unknown chain, but not in a truncated one; as a receiver, only the peer.
func TestPathChainAndReceiver(t *testing.T) {
	en := newEnv(t)
	d := realDir(t)
	tool := filepath.Join(d, "bin/tool")
	touch(t, tool)
	m := []config.Matcher{pathM(tool)}
	tab := en.f.ITermTab(platform.ProcessRef{}, fakeProc(tool), fakeSSH())
	if !en.e.Apps(m, en.r.Resolve(tab.Peer())) {
		t.Fatal("path: must match its process in an iTerm2 tab")
	}
	c := en.r.Resolve(en.f.Launch(en.launchd(tool), fakeSSH()))
	if !c.Unknown || !en.e.Apps(m, c) {
		t.Fatal("path: must match its process in an unknown chain")
	}
	if en.e.Receiver(m, c) {
		t.Fatal("to: path: must not match a process above the receiver")
	}
	if !en.e.Receiver(m, en.r.Resolve(en.launchd(tool))) {
		t.Fatal("to: path: must match the receiver itself")
	}
}
