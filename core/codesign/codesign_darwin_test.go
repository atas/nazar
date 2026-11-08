//go:build darwin && cgo

package codesign

import (
	"bufio"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// bundle builds testdata/peerlistener into <dir>/<name>.app as NazarApp
// with the given bundle id, ad-hoc signed (never a real identity).
func bundle(t *testing.T, dir, name, id string) string {
	t.Helper()
	app := filepath.Join(dir, name+".app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", filepath.Join(macos, "NazarApp"), "./testdata/peerlistener").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>` +
		`<key>CFBundleIdentifier</key><string>` + id + `</string><key>CFBundleExecutable</key><string>NazarApp</string>` +
		`<key>CFBundlePackageType</key><string>APPL</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", app).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v\n%s", err, out)
	}
	return app
}

// shortDir is a fresh folder under /tmp (sun_path is 104 bytes), removed
// after the test.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// dial connects to sock, waiting up to 10 s for the listener to come up.
func dial(t *testing.T, sock string) *net.UnixConn {
	t.Helper()
	var c net.Conn
	var err error
	for end := time.Now().Add(10 * time.Second); ; {
		if c, err = net.Dial("unix", sock); err == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("listener never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*net.UnixConn)
}

// listen runs app's executable on a fresh socket and returns a connection
// to it and the process.
func listen(t *testing.T, app string) (*net.UnixConn, *exec.Cmd) {
	t.Helper()
	sock := filepath.Join(shortDir(t), "s")
	cmd := exec.Command(filepath.Join(app, "Contents", "MacOS", "NazarApp"), sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return dial(t, sock), cmd
}

func token(t *testing.T, c *net.UnixConn) AuditToken {
	t.Helper()
	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tok, err := PeerAuditToken(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestPeerMustBeTheTrustedApp(t *testing.T) {
	dir := t.TempDir()
	nazar := bundle(t, dir, "Nazar", "dev.nazar.test")
	other := bundle(t, dir, "Other", "dev.nazar.test.other")
	req, err := DesignatedRequirement(nazar)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req, `cdhash H"`) {
		t.Fatalf("ad-hoc designated requirement %q, want an exact cdhash", req)
	}
	c, cmd := listen(t, nazar)
	tok := token(t, c)
	if tok.PID() != cmd.Process.Pid {
		t.Fatalf("token pid %d, listener %d", tok.PID(), cmd.Process.Pid)
	}
	if err := CheckPeer(tok, req); err != nil {
		t.Fatalf("the trusted app was refused: %v", err)
	}
	oc, _ := listen(t, other)
	if err := CheckPeer(token(t, oc), req); err == nil {
		t.Fatal("another app satisfied Nazar's requirement")
	}
	// The peer is gone: its token names no process any more.
	cmd.Process.Kill()
	cmd.Wait()
	if err := CheckPeer(tok, req); err == nil {
		t.Fatal("a dead peer's token passed")
	}
}

// Two bundles that differ only in their identifier have different ad-hoc
// requirements, and neither satisfies the other's.
func TestRequirementsAreNotInterchangeable(t *testing.T) {
	dir := t.TempDir()
	nazar := bundle(t, dir, "Nazar", "dev.nazar.test")
	other := bundle(t, dir, "Other", "dev.nazar.test.other")
	nreq, err := DesignatedRequirement(nazar)
	if err != nil {
		t.Fatal(err)
	}
	oreq, err := DesignatedRequirement(other)
	if err != nil {
		t.Fatal(err)
	}
	if nreq == oreq {
		t.Fatalf("two different bundles share the requirement %q", nreq)
	}
	again, err := DesignatedRequirement(nazar)
	if err != nil || again != nreq {
		t.Fatalf("requirement not stable for the same bundle: %q vs %q (%v)", again, nreq, err)
	}
	oc, _ := listen(t, other)
	otok := token(t, oc)
	if err := CheckPeer(otok, oreq); err != nil {
		t.Fatalf("Other refused against its own requirement: %v", err)
	}
	nc, _ := listen(t, nazar)
	if err := CheckPeer(token(t, nc), oreq); err == nil {
		t.Fatal("Nazar satisfied Other's requirement")
	}
}

// A process that is not the bundle (here: this test binary, ad-hoc signed
// by the Go linker) is refused, and its token names this process.
func TestThisProcessIsNotTheApp(t *testing.T) {
	nazar := bundle(t, t.TempDir(), "Nazar", "dev.nazar.test")
	req, err := DesignatedRequirement(nazar)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortDir(t), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c := dial(t, sock)
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	tok := token(t, c)
	if tok.PID() != os.Getpid() {
		t.Fatalf("token pid %d, want this process %d", tok.PID(), os.Getpid())
	}
	if err := CheckPeer(tok, req); err == nil {
		t.Fatal("this test binary satisfied Nazar.app's requirement")
	}
}

// A token is the whole audit token, not its PID: a live, trusted peer's
// token with the PID or the PID version changed names no process (or a
// different one) and never passes (spike S3: PIDs are recycled).
func TestForgedTokensFail(t *testing.T) {
	nazar := bundle(t, t.TempDir(), "Nazar", "dev.nazar.test")
	req, err := DesignatedRequirement(nazar)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := listen(t, nazar)
	tok := token(t, c)
	if err := CheckPeer(tok, req); err != nil {
		t.Fatalf("the trusted app was refused: %v", err)
	}
	version := tok
	version[7]++ // the PID version: a later process with the same PID
	if err := CheckPeer(version, req); err == nil {
		t.Fatal("a token with another PID version passed")
	}
	pid := tok
	pid[5] = uint32(os.Getpid()) // another live process's PID
	if err := CheckPeer(pid, req); err == nil {
		t.Fatal("a token with another PID passed")
	}
}

// A requirement that is not the bundle's own (a different cdhash, or an
// unrelated identifier) is not satisfied by the trusted app either.
func TestWrongRequirementFails(t *testing.T) {
	nazar := bundle(t, t.TempDir(), "Nazar", "dev.nazar.test")
	c, _ := listen(t, nazar)
	tok := token(t, c)
	for _, req := range []string{
		`cdhash H"0000000000000000000000000000000000000000"`,
		`identifier "dev.nazar.test.other"`,
		`anchor apple`,
	} {
		if err := CheckPeer(tok, req); err == nil {
			t.Errorf("the app satisfied the foreign requirement %q", req)
		}
	}
}

func TestBadInputs(t *testing.T) {
	if _, err := DesignatedRequirement("/nonexistent/Nazar.app"); err == nil {
		t.Error("requirement of a missing path")
	}
	if _, err := DesignatedRequirement(""); err == nil {
		t.Error("requirement of an empty path")
	}
	if err := CheckPeer(AuditToken{}, `anchor apple`); err == nil {
		t.Error("the zero token passed")
	}
	if err := CheckPeer(AuditToken{}, `not a requirement (`); err == nil {
		t.Error("a malformed requirement passed")
	}
	if _, err := PeerAuditToken(-1); err == nil {
		t.Error("token of fd -1")
	}
}

// Unsigned code has no designated requirement: a bundle-shaped folder of
// shell scripts (what an attacker could drop in place) and a plain file.
func TestUnsignedHasNoRequirement(t *testing.T) {
	dir := t.TempDir()
	macos := filepath.Join(dir, "Nazar.app", "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macos, "NazarApp"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if req, err := DesignatedRequirement(filepath.Join(dir, "Nazar.app")); err == nil {
		t.Errorf("unsigned bundle has requirement %q", req)
	}
	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if req, err := DesignatedRequirement(plain); err == nil {
		t.Errorf("a plain file has requirement %q", req)
	}
}

// PeerAuditToken needs a connected Unix socket: a listening socket and a
// regular file have no peer.
func TestPeerAuditTokenNeedsAPeer(t *testing.T) {
	l, err := net.Listen("unix", filepath.Join(shortDir(t), "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	lf, err := l.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if _, err := PeerAuditToken(int(lf.Fd())); err == nil {
		t.Error("a listening socket has a peer token")
	}
	f, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := PeerAuditToken(int(f.Fd())); err == nil {
		t.Error("a regular file has a peer token")
	}
}

// startOwner starts app's executable as `-own-fd3` with l's descriptor as
// fd 3 and returns once it has called listen() on it.
func startOwner(t *testing.T, app string, l *net.UnixListener) *exec.Cmd {
	t.Helper()
	f, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() // the child has its own copy now
	cmd := exec.Command(filepath.Join(app, "Contents", "MacOS", "NazarApp"), "-own-fd3")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || strings.TrimSpace(line) != "owned" {
		t.Fatalf("owner said %q, %v", line, err)
	}
	return cmd
}

// peerTokenErr is PeerAuditToken's error for c.
func peerTokenErr(t *testing.T, c *net.UnixConn) error {
	t.Helper()
	f, err := c.File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = PeerAuditToken(int(f.Fd()))
	return err
}

// The kernel facts behind the known limit in the package doc (XNU
// uipc_usrreq.c: LOCAL_PEERTOKEN is proc_find(peer socket's last_pid)),
// pinned so a macOS change, or a fix that relies on them, is noticed:
//
//  1. Read right after connect(), before the server has touched the
//     connection, the token names the process that last did
//     bind/listen/accept/connect/send/recv/poll/kevent on the LISTENING
//     socket, not the one that will service accept(). Any process holding
//     the descriptor can become that by calling listen() again.
//  2. Once a process has accept()ed and written on the connection, the
//     token names that process instead.
//  3. When the named process has exited, the read fails with EINVAL: fail
//     closed, never the servicer and never a stale token.
//
// Together, 1 is the spoof the CLI's check cannot see: the token names a
// genuine code-signed Nazar.app process, the bytes come from this test.
func TestTokenNamesTheLastTouchingProcessNotTheServicer(t *testing.T) {
	nazar := bundle(t, t.TempDir(), "Nazar", "dev.nazar.test")
	req, err := DesignatedRequirement(nazar)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortDir(t), "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// 1. This test made the socket; a Nazar.app process listen()s on it
	// last. Before anyone accepts, the token names Nazar.app and the
	// check passes — the spoof.
	owner := startOwner(t, nazar, l)
	c := dial(t, sock)
	tok := token(t, c)
	if tok.PID() != owner.Process.Pid {
		t.Fatalf("token names pid %d; want the re-listen()er %d (this test is %d)", tok.PID(), owner.Process.Pid, os.Getpid())
	}
	if err := CheckPeer(tok, req); err != nil {
		t.Fatalf("the Nazar.app listen-owner was refused: %v (the known limit assumes it passes)", err)
	}

	// 2. This test (not Nazar.app) services the connection; read after the
	// reply, the token names this test and the check fails.
	s, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Write([]byte("FORGED\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "FORGED\n" {
		t.Fatalf("read %q, %v", line, err)
	}
	after := token(t, c)
	if after.PID() != os.Getpid() {
		t.Fatalf("after the reply the token names pid %d; want the servicer %d", after.PID(), os.Getpid())
	}
	if err := CheckPeer(after, req); err == nil {
		t.Fatal("this test binary passed as Nazar.app")
	}

	// 3. The named process is gone: a new connection's token read fails
	// with EINVAL, although this test still serves the socket.
	owner.Process.Kill()
	owner.Wait()
	c2 := dial(t, sock)
	err = peerTokenErr(t, c2)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("dead listen-owner: PeerAuditToken = %v, want EINVAL", err)
	}
	if !strings.Contains(err.Error(), "listen-owner") {
		t.Fatalf("the error should explain itself: %v", err)
	}

	// And another listen() names a live process again.
	owner2 := startOwner(t, nazar, l)
	c3 := dial(t, sock)
	if tok3 := token(t, c3); tok3.PID() != owner2.Process.Pid {
		t.Fatalf("token names pid %d after re-listen; want %d", tok3.PID(), owner2.Process.Pid)
	}
}

// PeerAuditToken's errors tell a bad descriptor from a dead listen-owner:
// EBADF and ENOTSOCK are not EINVAL.
func TestPeerAuditTokenErrnos(t *testing.T) {
	_, err := PeerAuditToken(-1)
	if !errors.Is(err, syscall.EBADF) {
		t.Errorf("fd -1: %v, want EBADF", err)
	}
	f, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = PeerAuditToken(int(f.Fd()))
	if !errors.Is(err, syscall.ENOTSOCK) {
		t.Errorf("regular file: %v, want ENOTSOCK", err)
	}
	if errors.Is(err, syscall.EINVAL) {
		t.Errorf("a regular file must not look like a dead listen-owner: %v", err)
	}
}

// Both forms of the CLI requirement compile in Security.framework (a
// malformed one would refuse every genuine CLI), and this test binary,
// which is not dev.nazar.cli, satisfies neither.
func TestCLIRequirementCompiles(t *testing.T) {
	team, err := CLIRequirement("ABCDE12345", "")
	if err != nil {
		t.Fatal(err)
	}
	dev, err := CLIRequirement("", strings.Repeat("0a", 20))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortDir(t), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c := dial(t, sock)
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	tok := token(t, c)
	for _, req := range []string{team, dev} {
		if err := ParseRequirement(req); err != nil {
			t.Fatalf("%q: %v", req, err)
		}
		if err := CheckPeer(tok, req); err == nil {
			t.Fatalf("this test binary satisfied %q", req)
		}
	}
}
