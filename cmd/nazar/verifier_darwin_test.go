//go:build darwin && cgo

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/codesign"
	"github.com/atas/nazar/core/unixsock"
)

// signedBundle makes <dir>/Nazar.app with a real, ad-hoc-signed executable
// (a copy of /usr/bin/true, never a real identity) and a minimal
// Info.plist, so codesign.DesignatedRequirement succeeds on it. It returns
// the bundle path.
func signedBundle(t *testing.T, dir string) string {
	t.Helper()
	app := filepath.Join(dir, "Nazar.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, appExeName), src, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>` +
		`<key>CFBundleIdentifier</key><string>dev.nazar.test</string><key>CFBundleExecutable</key><string>` + appExeName + `</string>` +
		`<key>CFBundlePackageType</key><string>APPL</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", app).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v\n%s", err, out)
	}
	return app
}

// checkAgentPeer must actually run codesign.CheckPeer. With the designated
// requirement of a VALIDLY signed bundle and a live peer token, the only
// thing that can refuse this test binary — which is not that bundle — is
// CheckPeer. A checkAgentPeer that skipped or ignored CheckPeer would accept
// us (guards against a `return codesign.CheckPeer(...)` → `return nil`
// regression).
func TestCheckAgentPeerReachesCheckPeer(t *testing.T) {
	bundle := signedBundle(t, t.TempDir())
	req, err := codesign.DesignatedRequirement(bundle)
	if err != nil {
		t.Fatal(err)
	}

	// Socket served by this test binary; sun_path is 104 bytes, so keep the
	// directory short.
	short, err := os.MkdirTemp("/tmp", "nzcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	sock := filepath.Join(short, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	err = unixsock.WithFD(c.(*net.UnixConn), func(fd int) error { return checkAgentPeer(fd, req) })
	if err == nil {
		t.Fatal("checkAgentPeer accepted this test binary against a signed bundle's requirement: CheckPeer was not reached")
	}
	// The refusal must come from CheckPeer (peer does not satisfy the
	// requirement), not from an earlier token failure.
	if !strings.Contains(err.Error(), "does not satisfy") {
		t.Fatalf("checkAgentPeer refused before reaching CheckPeer: %v", err)
	}
}
