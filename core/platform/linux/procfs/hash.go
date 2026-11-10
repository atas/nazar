//go:build linux

package procfs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// hashKey identifies a file's content as far as the file system tells
// without reading it: a replace changes the inode, and a write(2) changes
// the size, the mtime or the ctime. A write through a shared mapping does
// not (the kernel updates the times on the first write to a clean page
// only), so the cache holds only files nobody but root can map for
// writing: cacheable.
type hashKey struct {
	dev, ino uint64
	size     int64
	mtime    unix.Timespec
	ctime    unix.Timespec
}

// fileID names a file on this machine: its device and inode.
type fileID struct{ dev, ino uint64 }

// maxCache bounds the hash cache; past it the cache starts over.
const maxCache = 1024

// maxImage is the largest file CodeHash and ExeHash read: a program's
// file is far smaller, and a sparse or remote file of any size must not
// hold a request for its whole length. Beyond it the hash is an error.
// The cap bounds the work, not the file system's time: a read of a file
// on a stalled mount (a hung NFS or SSHFS, a FUSE server that stopped
// answering, which may be any process of the user; an AppImage runs from
// one) waits as long as the mount does, as every process that touches it
// does, and the request whose chain holds such a program waits with it.
// Nothing here bounds that wait.
const maxImage = 1 << 30

// settle is how old a file's last change must be before its hash is
// cached. A same-size in-place write in the same timestamp as the change
// that was hashed would keep the cache key and the stale hash, and file
// timestamps are coarse: one tick of the kernel's clock (up to 10 ms) on
// most file systems and a whole second on some (ext3, ext4 with 128-byte
// inodes). settle is longer than any of them, so the next write to a
// settled file lands in a later timestamp. A file changed more recently
// than this is hashed from its bytes every time.
const settle = 2 * time.Second

// CodeHash is the SHA-256 of the regular file at the absolute path, and
// ErrNotFound when there is no such file. A relative path is refused: it
// would name a file against the agent's own working directory. A FIFO, a
// device, a socket or a directory is refused without being opened, so the
// call never waits on a writer, reads without end, or has the side effect
// an open of a device can have (an exclusive device such as the TPM is
// busy for every other user while it is open).
func (p *Procs) CodeHash(path string) ([]byte, error) {
	if path == "" {
		return nil, platform.ErrNotFound
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("procfs: %q is not an absolute path", path)
	}
	h, _, err := p.hashPath(path)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
		return nil, platform.ErrNotFound
	}
	return h, err
}

// ExeHash is the SHA-256 of the file the process ref names was started
// from (/proc/<pid>/exe opens that file, even once it is deleted or
// replaced on disk). It is the hash of that file, not of the code the
// process runs: a library loaded through LD_PRELOAD, a same-user debugger
// or a script run by an allowed interpreter runs other code under the same
// file and hash (item 1 of the design's "Weaker than macOS" list). The
// ref must be full, and the process must be the same instance before and
// after the read; otherwise ErrNoProcess. A PID-only ref is refused: the
// hash is an identity check, and the PID's occupant of the moment, which
// such a ref would name, is nobody in particular (a recycled PID would be
// pinned or trusted as the process that held it).
func (p *Procs) ExeHash(ref platform.ProcessRef) ([]byte, error) {
	if ref.Generation == 0 {
		return nil, platform.ErrNoProcess
	}
	st, err := check(ref)
	if err != nil {
		return nil, err
	}
	h, _, err := p.hashPath(procPath(ref.PID, "exe"))
	if err != nil {
		if again, err2 := ReadStat(ref.PID); err2 != nil || !st.same(again) {
			return nil, platform.ErrNoProcess
		}
		return nil, fmt.Errorf("procfs: executable of %d: %w", ref.PID, err)
	}
	p.pause()
	again, err := ReadStat(ref.PID)
	if err != nil || !st.same(again) {
		return nil, platform.ErrNoProcess
	}
	return h, nil
}

// hashPath hashes the regular file at path through the cache and names
// the file that was hashed. The result is the caller's own copy. The name
// is resolved once, to a descriptor that holds the file without opening
// it (O_PATH: no device is woken, no FIFO rendezvous happens); the file's
// type and size are checked on that descriptor, and the file is then
// opened for reading through the descriptor itself (/proc/self/fd), not
// through the name again, which could have come to mean another file in
// between. So nothing but a regular file is ever opened or read, and the
// file read is the file checked.
func (p *Procs) hashPath(path string) ([]byte, fileID, error) {
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fileID{}, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, fileID{}, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if err := regular(path, &st); err != nil {
		return nil, fileID{}, err
	}
	if p.beforeRead != nil {
		p.beforeRead()
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pfd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fileID{}, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return nil, fileID{}, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	if opened.Dev != st.Dev || opened.Ino != st.Ino {
		return nil, fileID{}, fmt.Errorf("procfs: %s is not the file that was checked", path)
	}
	st = opened
	if err := regular(path, &st); err != nil {
		return nil, fileID{}, err
	}
	var fsys unix.Statfs_t
	if err := unix.Fstatfs(fd, &fsys); err != nil {
		return nil, fileID{}, &fs.PathError{Op: "statfs", Path: path, Err: err}
	}
	id := fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}
	key := hashKey{dev: id.dev, ino: id.ino, size: st.Size, mtime: st.Mtim, ctime: st.Ctim}
	cacheable := cacheable(&st, int64(fsys.Type), p.uid, p.cacheOwner, p.now())
	if cacheable {
		p.mu.Lock()
		h, hit := p.cache[key]
		p.mu.Unlock()
		if hit {
			return append([]byte(nil), h...), id, nil
		}
	}
	sum := sha256.New()
	n, err := io.Copy(sum, io.LimitReader(f, maxImage+1))
	if err != nil {
		return nil, fileID{}, err
	}
	if n > maxImage {
		return nil, fileID{}, fmt.Errorf("procfs: %s is larger than %d bytes", path, maxImage)
	}
	h := sum.Sum(nil)
	if cacheable {
		p.mu.Lock()
		if len(p.cache) >= maxCache {
			p.cache = map[hashKey][]byte{}
		}
		p.cache[key] = h
		p.mu.Unlock()
	}
	return append([]byte(nil), h...), id, nil
}

// regular refuses, with the error CodeHash reports, a file that is not a
// regular file of a size CodeHash reads.
func regular(path string, st *unix.Stat_t) error {
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		return fmt.Errorf("procfs: %s is a directory", path)
	default:
		return fmt.Errorf("procfs: %s is not a regular file", path)
	}
	if st.Size > maxImage {
		return fmt.Errorf("procfs: %s is larger than %d bytes", path, maxImage)
	}
	return nil
}

// cacheable reports whether the hash of the file behind st, on a file
// system of type fsType, may be kept under its hashKey by an agent running
// as uid at the time now. It may when nobody but root can change the
// file's bytes under an unchanged key: the file belongs to owner (root,
// but for a test's seam) and neither its group nor others may write it
// (so no process of any other user can map it for writing; a replace by
// root changes the inode, a write(2) the times), the agent's user is
// neither root nor the owner, the file system is not FUSE (its server,
// which may be any process of this user, answers stat as it likes), and
// the last change is older than settle (a same-size rewrite in the same
// timestamp would keep the key). A file another unprivileged user owns is
// not cached either: its owner could change its bytes through a shared
// mapping under an unchanged key, as TestMappedRewriteIsNotCached shows
// for this user, and the cache would serve the old hash for the new code.
//
// Two consequences, accepted. A program this user owns (Claude Code's own
// build under ~/.local, a node under ~/.nvm, an app under ~/.local: often
// 100 MB and more) is read and hashed in full on every CodeHash, ExeHash
// and Process. The chain is walked on every request, with one Process per
// process in it, so a request from such a program hashes its file at
// least once per request, more when the chain holds more than one such
// program (node under Claude Code). SHA-256 of 200 MB takes about 100 ms
// on a CPU with SHA instructions and several times that without them, so
// a request from such a caller costs on the order of 100 ms to 500 ms in
// hashing: the price of never serving a stale hash for a file the caller
// can write. And the stat is trusted for a root-owned file only as far as
// the file system behind it is out of the user's hands: on a mount whose
// backing store the user owns (a loop mount of a user-owned image through
// udisks, removable media) the bytes can change under unchanged times, as
// on FUSE, and a stale hash can be served until the cache starts over.
// Item 2 of the design's "Weaker than macOS" list bounds what that gains
// an attacker.
func cacheable(st *unix.Stat_t, fsType int64, uid, owner int, now time.Time) bool {
	if uid == 0 || uid == owner || int(st.Uid) != owner || st.Mode&0o022 != 0 || fsType == unix.FUSE_SUPER_MAGIC {
		return false
	}
	return now.Sub(time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))) >= settle
}

// sameFile reports whether the file at path, as this process sees it, is
// the file id names.
func sameFile(path string, id fileID) bool {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return false
	}
	return uint64(st.Dev) == id.dev && uint64(st.Ino) == id.ino
}

// imageID names the file the process pid runs, as /proc/<pid>/exe resolves
// it, in whatever mount namespace the process lives; false when the kernel
// won't say (another user's process, or gone).
func imageID(pid int) (fileID, bool) {
	var st unix.Stat_t
	if err := unix.Stat(procPath(pid, "exe"), &st); err != nil {
		return fileID{}, false
	}
	return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}
