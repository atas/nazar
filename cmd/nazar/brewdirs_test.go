package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests never read this Mac's Homebrew folders: a developer who installed
// nazar with Homebrew has /opt/homebrew/bin/nazar-sign-git, which changed
// the setup advice (and broke TestUIFixtures) on that Mac only.
func TestMain(m *testing.M) {
	brewBinDirs = nil
	os.Exit(m.Run())
}

// The setup advice names Homebrew's nazar-sign-git link when it exists.
func TestProgramFixFindsHomebrewsLink(t *testing.T) {
	brew := t.TempDir()
	defer func(d []string) { brewBinDirs = d }(brewBinDirs)
	h := newHarness(t)
	s := &setup{a: h.a}
	if got := s.programFix(); !strings.HasPrefix(got, "run `nazar install`") {
		t.Fatalf("no link anywhere: %q", got)
	}
	link := filepath.Join(brew, signGitName)
	if err := os.WriteFile(link, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	brewBinDirs = []string{brew}
	if got, want := s.programFix(), "set it with `git config --global gpg.ssh.program "+link+"`"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
