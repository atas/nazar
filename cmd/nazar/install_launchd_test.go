//go:build launchd && darwin

package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestInstallWithRealLaunchd (make check-launchd; opt-in because launchd
// may show a "Background Items Added" notification): the bundled CLI of a
// fake Nazar.app installs a LaunchAgent under a random dev.nazar.test.*
// label in a temporary HOME, launchd runs it, and uninstall stops it. The
// real dev.nazar label and the real HOME are never touched.
func TestInstallWithRealLaunchd(t *testing.T) {
	home, err := os.MkdirTemp("/tmp", "nzld")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	var n [4]byte
	rand.Read(n[:])
	label := "dev.nazar.test." + hex.EncodeToString(n[:])
	uid := strconv.Itoa(os.Getuid())
	defer exec.Command("/bin/launchctl", "bootout", "gui/"+uid+"/"+label).Run() // whatever happens

	macos := filepath.Join(home, "Nazar.app", "Contents", "MacOS")
	os.MkdirAll(macos, 0o755)
	if err := os.WriteFile(filepath.Join(macos, appExeName), []byte("#!/bin/sh\nexec /bin/sleep 600\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(macos, "nazar")
	if out, err := exec.Command("go", "build", "-o", cli, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	env := []string{"HOME=" + home, "PATH=/usr/bin:/bin", "NAZAR_LAUNCH_LABEL=" + label}
	run := func(args ...string) string {
		cmd := exec.Command(cli, args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("nazar %v: %v %s", args, err, out)
		}
		return string(out)
	}
	run("install", "--bin-dir", filepath.Join(home, "bin"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		out, _ := exec.Command("/bin/launchctl", "print", "gui/"+uid+"/"+label).CombinedOutput()
		if strings.Contains(string(out), "state = running") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent not running:\n%s", out)
		}
		time.Sleep(200 * time.Millisecond)
	}
	run("uninstall", "--bin-dir", filepath.Join(home, "bin"))
	if err := exec.Command("/bin/launchctl", "print", "gui/"+uid+"/"+label).Run(); err == nil {
		t.Fatal("agent still loaded after uninstall")
	}
}
