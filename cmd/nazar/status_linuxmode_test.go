package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// shippedLinuxBrewBinDirs is the value main runs with: TestMain clears the
// variable so that no test reads a real Homebrew folder.
var shippedLinuxBrewBinDirs = linuxBrewBinDirs

const linuxGitLine = "/usr/bin/git config --global --includes --get-regexp " + gitKeys

// On Linux git is /usr/bin/git itself: there is no xcode-select and no
// developer directory, and a Mac must never run its /usr/bin/git shim.
func TestLinuxStatusGit(t *testing.T) {
	sshLine := sshGText("github.com", "", "no", "false", "~/.ssh/id_ed25519")
	h := linuxHarness(t)
	h.serve(t, statusWith(defaultSock(h)))
	var ran []string
	h.a.output = recording(fakeOutput(t, map[string]string{
		linuxGitLine:                       "gpg.format ssh\ngpg.ssh.program /usr/bin/ssh-keygen\nuser.signingkey ~/.nazar/keys/github.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshLine,
	}), &ran)
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if !slices.Contains(ran, "/usr/bin/git") || slices.Contains(ran, "/usr/bin/xcode-select") {
		t.Fatalf("ran %q", ran)
	}
	if out := h.out.String(); !strings.Contains(out, "setup: error: git config --global: git signs with nazar's key github but gpg.ssh.program is `/usr/bin/ssh-keygen`, not a link named nazar-sign-git") {
		t.Fatalf("the check did not see git's settings:\n%s", out)
	}
	// No settings at all (git exits 1): silence, as on macOS.
	h = linuxHarness(t)
	h.serve(t, statusWith(defaultSock(h)))
	ran = nil
	h.a.output = recording(fakeOutput(t, map[string]string{"/usr/bin/ssh -T -G -- github.com": sshLine}), &ran)
	if code := h.run("status"); code != 0 || strings.Contains(h.out.String(), "setup:") {
		t.Fatalf("no settings: exit %d\n%s", code, h.out)
	}
	if slices.Contains(ran, "/usr/bin/xcode-select") {
		t.Fatalf("ran %q", ran)
	}
	// macOS asks xcode-select first and never runs the shim.
	h = newHarness(t)
	h.serve(t, statusWith(defaultSock(h)))
	ran = nil
	h.a.output = recording(fakeOutput(t, map[string]string{"/usr/bin/ssh -T -G -- github.com": sshLine}), &ran)
	if code := h.run("status"); code != 0 {
		t.Fatalf("macOS: exit %d %s", code, h.errb)
	}
	if !slices.Contains(ran, "/usr/bin/xcode-select") || slices.Contains(ran, "/usr/bin/git") {
		t.Fatalf("macOS ran %q", ran)
	}
}

func TestLinuxBrewLink(t *testing.T) {
	if !slices.Equal(shippedLinuxBrewBinDirs, []string{"/home/linuxbrew/.linuxbrew/bin"}) {
		t.Fatalf("Homebrew's folder on Linux: %q", shippedLinuxBrewBinDirs)
	}
	defer func(mac, linux []string) { brewBinDirs, linuxBrewBinDirs = mac, linux }(brewBinDirs, linuxBrewBinDirs)
	macBrew, linuxBrew := t.TempDir(), t.TempDir()
	brewBinDirs, linuxBrewBinDirs = []string{macBrew}, []string{linuxBrew}

	link := func(dir string) string {
		p := filepath.Join(dir, signGitName)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	fix := func(p string) string { return "set it with `git config --global gpg.ssh.program " + p + "`" }

	h := linuxHarness(t)
	s := &setup{a: h.a}
	macLink := link(macBrew)
	if got := s.programFix(); !strings.HasPrefix(got, "run `nazar install`") {
		t.Fatalf("Linux looked in the Mac's folders: %q", got)
	}
	linuxLink := link(linuxBrew)
	if got := s.programFix(); got != fix(linuxLink) {
		t.Fatalf("Linux: %q", got)
	}
	// macOS looks where it always did.
	h.a.linux = false
	if got := s.programFix(); got != fix(macLink) {
		t.Fatalf("macOS: %q", got)
	}
}
