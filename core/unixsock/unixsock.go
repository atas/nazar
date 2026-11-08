// Package unixsock creates the agent and control sockets safely and reads the
// kernel-verified UID of a connected peer.
package unixsock

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// MaxPathLen is the sun_path limit on macOS (104 including the NUL).
const MaxPathLen = 103

// probeTimeout bounds the connect() used to tell a live socket from a stale one.
const probeTimeout = 5 * time.Second

// Listen creates a Unix socket at path. The parent folder is created 0700 if
// missing and must be a real directory (not a symlink) owned by the current
// user with no group/other access. A stale socket at path (nobody listens)
// is replaced; a socket that accepts connections, or any other existing
// file, is an error. The socket itself is chmod 0600.
//
// Two instances starting at once (LaunchAgent plus a manual start) are
// serialized with an advisory lock on the folder, so exactly one of them
// binds and the other sees the winner's live socket instead of a window in
// which it looks stale.
func Listen(path string) (*net.UnixListener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("unixsock: %q is not an absolute path", path)
	}
	if len(path) > MaxPathLen {
		return nil, fmt.Errorf("unixsock: %s is longer than %d bytes", path, MaxPathLen)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("unixsock: %w", err)
	}
	if err := CheckPrivateDir(dir); err != nil {
		return nil, err
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := RemoveStale(path); err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("unixsock: %w", err)
	}
	l.SetUnlinkOnClose(true)
	// Between bind and this chmod the node carries the umask-derived mode;
	// the 0700 folder keeps it out of reach of other users meanwhile.
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("unixsock: %w", err)
	}
	return l, nil
}

// RemoveStale unlinks path if it is a socket nobody listens on. It
// never touches a non-socket (regular file, symlink, directory, FIFO) and
// never removes a socket whose state it cannot establish.
func RemoveStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unixsock: %w", err)
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("unixsock: %s exists and is not a socket", path)
	}
	// A socket someone still listens on belongs to a running instance:
	// never steal it. Only a stale socket (connection refused) is removed;
	// any other outcome of the probe fails closed.
	c, err := net.DialTimeout("unix", path, probeTimeout)
	switch {
	case err == nil:
		c.Close()
		return fmt.Errorf("unixsock: %s is in use by another process", path)
	case errors.Is(err, syscall.ECONNREFUSED):
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("unixsock: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unixsock: cannot tell whether %s is in use: %w", path, err)
	}
}

// lockDir takes an exclusive advisory lock on the folder itself (no lock
// file is left behind) and returns the function that releases it. The folder
// is opened without following a final symlink and must be the one that
// CheckPrivateDir just approved.
func lockDir(dir string) (unlock func(), err error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("unixsock: open %s: %w", dir, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unixsock: fstat %s: %w", dir, err)
	}
	if int(st.Uid) != os.Getuid() || st.Mode&0o077 != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("unixsock: %s changed while opening it", dir)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("unixsock: lock %s: %w", dir, err)
	}
	return func() { unix.Close(fd) }, nil
}

// CheckPrivateDir fails unless dir is a real directory (not a symlink) owned
// by the current user with mode bits 0700 or stricter.
func CheckPrivateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("unixsock: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("unixsock: %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unixsock: cannot read owner of %s", dir)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("unixsock: %s is owned by uid %d, not %d", dir, st.Uid, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("unixsock: %s has mode %o; want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// WithFD runs fn with the connection's file descriptor, which stays valid
// for the duration of fn. On a closed connection fn does not run.
func WithFD(c *net.UnixConn, fn func(fd int) error) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := rc.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

// PeerUID returns the effective UID of the process at the other end of c,
// as recorded by the kernel when it connected. On error the returned UID is
// -1, never a value that could pass a check.
func PeerUID(c *net.UnixConn) (int, error) {
	uid := -1
	err := WithFD(c, func(fd int) error {
		u, err := peerUID(fd)
		if err != nil {
			return err
		}
		uid = u
		return nil
	})
	if err != nil {
		return -1, err
	}
	return uid, nil
}

// RequireSameUser closes nothing; it returns an error unless the peer runs
// as the current user.
func RequireSameUser(c *net.UnixConn) error {
	uid, err := PeerUID(c)
	if err != nil {
		return err
	}
	if uid != os.Getuid() {
		return fmt.Errorf("unixsock: peer uid %d is not %d", uid, os.Getuid())
	}
	return nil
}
