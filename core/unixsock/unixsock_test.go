package unixsock

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// shortDir returns a temp dir short enough for sun_path (macOS: 104 bytes).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "nzs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// privateDir returns a short temp dir that already is 0700.
func privateDir(t *testing.T) string {
	t.Helper()
	d := shortDir(t)
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func mustNotExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s must not exist (Lstat err=%v)", p, err)
	}
}

// acceptOne accepts a single connection on l in the background.
func acceptOne(l *net.UnixListener) <-chan error {
	done := make(chan error, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err == nil {
			c.Close()
		}
		done <- err
	}()
	return done
}

func TestMaxPathLen(t *testing.T) {
	if MaxPathLen != 103 {
		t.Fatalf("MaxPathLen=%d want 103 (macOS sun_path is 104 bytes with the NUL)", MaxPathLen)
	}
}

func TestListenCreatesPrivateSocket(t *testing.T) {
	dir := filepath.Join(shortDir(t), "sock")
	path := filepath.Join(dir, "a.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o, want 600", fi.Mode().Perm())
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o, want 700", di.Mode().Perm())
	}
}

func TestListenSocketIsUsable(t *testing.T) {
	p := filepath.Join(privateDir(t), "a.sock")
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		t.Fatalf("%s is %v, want a socket", p, fi.Mode().Type())
	}
	done := acceptOne(l)
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Missing folders (including intermediate ones, e.g. a fresh ~/.nazar) are
// created 0700, and the socket ends up 0600, even under a permissive umask.
func TestListenPermissionsIgnoreUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	base := shortDir(t)
	dir := filepath.Join(base, "x", "y")
	p := filepath.Join(dir, "a.sock")
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, d := range []string{filepath.Join(base, "x"), dir} {
		fi, err := os.Lstat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %o, want 700", d, fi.Mode().Perm())
		}
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %o, want 600", fi.Mode().Perm())
	}
}

func TestListenRefusesLooseDir(t *testing.T) {
	dir := shortDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(dir, "a.sock")); err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("want mode error, got %v", err)
	}
}

// Any group or other bit on an existing folder is refused, and Listen must not
// "fix" a folder someone else prepared by chmod-ing it: it refuses, creates
// nothing and leaves the mode alone.
func TestListenRefusesAnyGroupOrOtherBit(t *testing.T) {
	for _, mode := range []fs.FileMode{0o710, 0o701, 0o720, 0o702, 0o740, 0o704, 0o750, 0o770, 0o707, 0o777, 0o777 | fs.ModeSticky} {
		dir := shortDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, "a.sock")
		l, err := Listen(p)
		if err == nil {
			l.Close()
			t.Errorf("mode %v: Listen succeeded", mode)
			continue
		}
		if !strings.Contains(err.Error(), "mode") {
			t.Errorf("mode %v: want mode error, got %v", mode, err)
		}
		mustNotExist(t, p)
		fi, _ := os.Lstat(dir)
		if fi.Mode().Perm() != mode.Perm() {
			t.Errorf("mode %v: Listen changed the folder mode to %v", mode, fi.Mode().Perm())
		}
	}
}

func TestListenRefusesSymlinkDir(t *testing.T) {
	base := shortDir(t)
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	os.Symlink(real, link)
	if _, err := Listen(filepath.Join(link, "a.sock")); err == nil {
		t.Fatal("want error for symlinked socket dir")
	}
	// Nothing may be created through the link either.
	mustNotExist(t, filepath.Join(real, "a.sock"))
}

// A socket straight in a shared folder (/tmp: root-owned, world-writable, and
// a symlink on macOS) is refused.
func TestListenRefusesSharedSystemDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	for _, dir := range []string{"/tmp", "/private/tmp", "/var/tmp"} {
		if _, err := os.Lstat(dir); err != nil {
			continue
		}
		p := filepath.Join(dir, "nz-unixsock-test-shared.sock")
		os.Remove(p)
		l, err := Listen(p)
		if err == nil {
			l.Close()
			os.Remove(p)
			t.Errorf("Listen in shared folder %s succeeded", dir)
			continue
		}
		mustNotExist(t, p)
	}
}

func TestListenRefusesNonSocketFile(t *testing.T) {
	dir := shortDir(t)
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "a.sock")
	os.WriteFile(p, []byte("x"), 0o600)
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("want not-a-socket error, got %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Fatal("regular file was modified")
	}
}

// A planted symlink at the socket path is never followed, removed or
// replaced, whatever it points to (a victim file, a live socket, nothing).
func TestListenRefusesSymlinkAtSocketPath(t *testing.T) {
	dir := privateDir(t)
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := privateDir(t)
	live := filepath.Join(other, "live.sock")
	ll, err := net.ListenUnix("unix", &net.UnixAddr{Name: live, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ll.Close()

	for name, target := range map[string]string{
		"to-file":     victim,
		"to-socket":   live,
		"dangling":    filepath.Join(dir, "missing"),
		"to-dir-self": dir,
	} {
		p := filepath.Join(dir, name+".sock")
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		l, err := Listen(p)
		if err == nil {
			l.Close()
			t.Errorf("%s: Listen accepted a symlink at the socket path", name)
			continue
		}
		if dst, err := os.Readlink(p); err != nil || dst != target {
			t.Errorf("%s: symlink was replaced or removed (readlink=%q, %v)", name, dst, err)
		}
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("symlink target was modified")
	}
	if fi, err := os.Lstat(live); err != nil || fi.Mode().Type() != fs.ModeSocket {
		t.Fatalf("live socket behind the symlink was disturbed: %v", err)
	}
}

func TestListenRefusesOtherFileTypes(t *testing.T) {
	dir := privateDir(t)
	sub := filepath.Join(dir, "d.sock")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(sub); err == nil {
		t.Fatal("Listen accepted a directory at the socket path")
	}
	if _, err := os.Stat(filepath.Join(sub, "f")); err != nil {
		t.Fatalf("directory at the socket path was disturbed: %v", err)
	}
	fifo := filepath.Join(dir, "f.sock")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(fifo); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("want not-a-socket error for a FIFO, got %v", err)
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode().Type() != fs.ModeNamedPipe {
		t.Fatalf("FIFO was disturbed: %v", err)
	}
}

func TestListenRefusesParentThatIsAFile(t *testing.T) {
	dir := privateDir(t)
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(f, "a.sock")); err == nil {
		t.Fatal("want error when the socket folder is a regular file")
	}
	if b, _ := os.ReadFile(f); string(b) != "x" {
		t.Fatal("file was modified")
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	dir := shortDir(t)
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "a.sock")
	l1, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	l1.SetUnlinkOnClose(false)
	l1.Close()
	l2, err := Listen(p)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	defer l2.Close()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("replacement socket mode %o, want 600", fi.Mode().Perm())
	}
	done := acceptOne(l2)
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatalf("replacement socket not reachable: %v", err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestListenRefusesLiveSocket(t *testing.T) {
	dir := shortDir(t)
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "a.sock")
	l1, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a second instance must not steal a live socket, got %v", err)
	}
	if c, err := net.Dial("unix", p); err != nil {
		t.Fatalf("the first listener lost its socket: %v", err)
	} else {
		c.Close()
	}
}

// A live socket created by someone else (not through Listen) is not stolen
// either, and the connection made to probe it doesn't break the owner.
func TestListenRefusesForeignLiveSocket(t *testing.T) {
	p := filepath.Join(privateDir(t), "a.sock")
	owner, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	before, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("want in-use error, got %v", err)
	}
	after, err := os.Lstat(p)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the owner's socket file was replaced (err=%v)", err)
	}
	// The owner still receives new connections.
	owner.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 1)
	go func() {
		for {
			c, err := owner.AcceptUnix()
			if err != nil {
				done <- err
				return
			}
			// Skip the probe connection, if it is still queued.
			buf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := c.Read(buf)
			c.Close()
			if n == 1 && buf[0] == 'k' {
				done <- nil
				return
			}
		}
	}()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("k"))
	c.Close()
	if err := <-done; err != nil {
		t.Fatalf("owner stopped receiving connections: %v", err)
	}
}

// Nazar started twice at the same moment (LaunchAgent plus a manual start):
// exactly one instance may own the socket, and the socket on disk must lead to
// that winner. Run with a fresh path and with a stale socket left behind.
func TestListenConcurrentStartsHaveOneWinner(t *testing.T) {
	const rounds = 200
	n := 2 * runtime.GOMAXPROCS(0)
	if n < 4 {
		n = 4
	}
	for _, stale := range []bool{false, true} {
		for r := 0; r < rounds; r++ {
			p := filepath.Join(privateDir(t), "a.sock")
			if stale {
				old, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				old.SetUnlinkOnClose(false)
				old.Close()
			}
			var (
				wg      sync.WaitGroup
				mu      sync.Mutex
				winners []*net.UnixListener
				start   = make(chan struct{})
			)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					l, err := Listen(p)
					if err == nil {
						mu.Lock()
						winners = append(winners, l)
						mu.Unlock()
					}
				}()
			}
			close(start)
			wg.Wait()
			if len(winners) != 1 {
				for _, l := range winners {
					l.Close()
				}
				t.Fatalf("stale=%v round %d: %d concurrent Listen calls succeeded, want exactly 1", stale, r, len(winners))
			}
			w := winners[0]
			w.SetDeadline(time.Now().Add(5 * time.Second))
			done := acceptOne(w)
			c, err := net.Dial("unix", p)
			if err != nil {
				w.Close()
				t.Fatalf("stale=%v round %d: winner's socket not reachable: %v", stale, r, err)
			}
			c.Close()
			if err := <-done; err != nil {
				w.Close()
				t.Fatalf("stale=%v round %d: the socket on disk does not lead to the winner: %v", stale, r, err)
			}
			w.Close()
		}
	}
}

// Closing the listener (clean shutdown) removes the socket file.
func TestCloseRemovesSocket(t *testing.T) {
	p := filepath.Join(privateDir(t), "a.sock")
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, p)
}

func TestListenRejectsLongPath(t *testing.T) {
	if _, err := Listen("/tmp/" + strings.Repeat("x", 120)); err == nil {
		t.Fatal("want error for long path")
	}
}

// The limit is exact: MaxPathLen bytes work, one more is refused before
// anything is created on disk (no folder, no file).
func TestListenPathLengthBoundary(t *testing.T) {
	base := privateDir(t)
	pad := func(n int, sub string) string {
		prefix := filepath.Join(base, sub) + "/"
		if len(prefix) >= n {
			t.Fatalf("temp dir %q too long for the boundary test", prefix)
		}
		return prefix + strings.Repeat("s", n-len(prefix))
	}
	ok := pad(MaxPathLen, "ok")
	if len(ok) != MaxPathLen {
		t.Fatalf("built %d bytes", len(ok))
	}
	l, err := Listen(ok)
	if err != nil {
		t.Fatalf("path of exactly %d bytes refused: %v", MaxPathLen, err)
	}
	l.Close()

	long := pad(MaxPathLen+1, "long")
	if _, err := Listen(long); err == nil {
		t.Fatalf("path of %d bytes accepted", MaxPathLen+1)
	}
	mustNotExist(t, filepath.Join(base, "long"))
}

func TestListenRejectsRelativePath(t *testing.T) {
	dir := privateDir(t)
	t.Chdir(dir)
	for _, p := range []string{"a.sock", "./a.sock", "sub/a.sock", ""} {
		if l, err := Listen(p); err == nil {
			l.Close()
			t.Errorf("relative path %q accepted", p)
		}
	}
	mustNotExist(t, filepath.Join(dir, "a.sock"))
	mustNotExist(t, filepath.Join(dir, "sub"))
}

func TestCheckPrivateDir(t *testing.T) {
	dir := privateDir(t)
	if err := CheckPrivateDir(dir); err != nil {
		t.Fatalf("0700 dir refused: %v", err)
	}

	loose := shortDir(t)
	os.Chmod(loose, 0o750)
	if err := CheckPrivateDir(loose); err == nil {
		t.Error("0750 dir accepted")
	}

	link := filepath.Join(shortDir(t), "link")
	os.Symlink(dir, link)
	if err := CheckPrivateDir(link); err == nil {
		t.Error("symlink to a private dir accepted")
	}

	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o600)
	if err := CheckPrivateDir(f); err == nil {
		t.Error("regular file accepted")
	}

	if err := CheckPrivateDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing dir accepted")
	}
}

// A folder owned by someone else is refused even when its mode is 0700, so
// the mode check alone can't be what refuses it.
func TestCheckPrivateDirRefusesOtherOwner(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root")
	}
	// Root-owned 0700 folders: macOS, then Linux.
	for _, dir := range []string{"/private/var/audit", "/private/var/backups", "/root"} {
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) == os.Getuid() {
			continue
		}
		err = CheckPrivateDir(dir)
		if err == nil || !strings.Contains(err.Error(), "owned") {
			t.Fatalf("want ownership error for %s, got %v", dir, err)
		}
		if l, err := Listen(filepath.Join(dir, "nz.sock")); err == nil {
			l.Close()
			t.Fatalf("Listen in %s succeeded", dir)
		}
		return
	}
	t.Skip("no folder owned by another user with mode 0700 found")
}

func TestPeerUIDIsCurrentUser(t *testing.T) {
	dir := shortDir(t)
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "a.sock")
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, err := l.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		done <- RequireSameUser(c)
	}()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// connPair returns both ends of a connection made through Listen.
func connPair(t *testing.T) (server, client *net.UnixConn) {
	t.Helper()
	p := filepath.Join(privateDir(t), "a.sock")
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	type res struct {
		c   *net.UnixConn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := l.AcceptUnix()
		ch <- res{c, err}
	}()
	cc, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: p, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		cc.Close()
		t.Fatal(r.err)
	}
	t.Cleanup(func() { r.c.Close(); cc.Close() })
	return r.c, cc
}

// The UID comes from the kernel, not from anything the peer sends: a client
// that writes a claim of being root first is still reported as itself.
func TestPeerUIDIsKernelVerified(t *testing.T) {
	srv, cli := connPair(t)
	if _, err := cli.Write([]byte("uid=0\nUSER=root\n")); err != nil {
		t.Fatal(err)
	}
	uid, err := PeerUID(srv)
	if err != nil {
		t.Fatal(err)
	}
	if uid != os.Getuid() {
		t.Fatalf("PeerUID=%d want %d", uid, os.Getuid())
	}
	// The client side can check the server the same way.
	if uid, err := PeerUID(cli); err != nil || uid != os.Getuid() {
		t.Fatalf("client-side PeerUID=%d, %v", uid, err)
	}
	if err := RequireSameUser(cli); err != nil {
		t.Fatal(err)
	}
}

// Failing to read the peer must fail closed: an error, never a UID that could
// pass a check (0 = root, or the current user).
func TestPeerUIDFailsClosedOnClosedConn(t *testing.T) {
	srv, _ := connPair(t)
	srv.Close()
	uid, err := PeerUID(srv)
	if err == nil {
		t.Fatalf("PeerUID on a closed conn returned %d and no error", uid)
	}
	if uid == 0 || uid == os.Getuid() {
		t.Fatalf("PeerUID returned a usable uid %d together with error %v", uid, err)
	}
	if err := RequireSameUser(srv); err == nil {
		t.Fatal("RequireSameUser passed on a closed conn")
	}
}

// After the peer hangs up, the credentials recorded at connect time are still
// the peer's; nothing falls back to "current user" or root by default.
func TestPeerUIDAfterPeerHangsUp(t *testing.T) {
	srv, cli := connPair(t)
	cli.Close()
	uid, err := PeerUID(srv)
	if err == nil && uid != os.Getuid() {
		t.Fatalf("PeerUID=%d want %d", uid, os.Getuid())
	}
	if err != nil && (uid == 0 || uid == os.Getuid()) {
		t.Fatalf("PeerUID returned a usable uid %d together with error %v", uid, err)
	}
}

func TestWithFD(t *testing.T) {
	srv, _ := connPair(t)
	called := false
	err := WithFD(srv, func(fd int) error {
		called = true
		if fd < 0 {
			t.Errorf("fd=%d", fd)
		}
		// The fd is a live socket for the duration of fn.
		if _, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil {
			t.Errorf("fd %d is not a valid socket inside fn: %v", fd, err)
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("WithFD err=%v called=%v", err, called)
	}

	sentinel := errors.New("from fn")
	if err := WithFD(srv, func(int) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("WithFD did not return fn's error: %v", err)
	}

	srv.Close()
	called = false
	if err := WithFD(srv, func(int) error { called = true; return nil }); err == nil {
		t.Fatal("WithFD on a closed conn returned nil")
	}
	if called {
		t.Fatal("fn ran on a closed conn")
	}
}
