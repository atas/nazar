//go:build linux

// Package procfs answers the caller questions of platform.Platform on Linux
// from /proc and the socket's peer credentials: who is at the other end of
// a socket, what a process is and who its parent is, when it exits, and the
// hash of a program's file or of the file a process was started from.
//
// A process instance is its PID plus its start ticks (/proc/<pid>/stat field
// 22) plus one, so a recycled PID is told from the process that held it
// before. Linux has no code signatures: Code is never Signed and CDHash is
// the SHA-256 of the file the process was started from (/proc/<pid>/exe).
// That names the file, not the code that runs: a library loaded through
// LD_PRELOAD, a same-user debugger or a script run by an allowed
// interpreter runs other code under the same path and hash (item 1 of the
// design's "Weaker than macOS" list).
//
// Two things macOS tells apart that this package can't (items 7 and 8 of
// that list, which the docs state; only same-user processes can reach the
// agent's sockets, which the design accepts for v1): a peer that execs
// another program after it connected keeps its PID, start ticks and pidfd,
// so it is reported as the program it became (on macOS the audit token's
// pidversion changes on exec, and a connection opened before the exec is
// refused); and before Linux 6.5 (no SO_PEERPIDFD: the
// stock kernels of Debian 12 and Ubuntu 22.04) a peer that exited and was
// reaped between connecting and being looked up can have its PID reused,
// and the new holder is reported as the peer, unless it started after the
// lookup began (PeerOf).
package procfs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// Procs reads processes from /proc. The zero value is not usable: New.
type Procs struct {
	mu    sync.Mutex
	cache map[hashKey][]byte // file hashes keyed by dev, ino, size, mtime, ctime
	// uid is the user the agent runs as, and cacheOwner the one user whose
	// files may be served from the hash cache (root; a file anyone else
	// can write is hashed from its bytes every time). now is the clock the
	// cache's settle time is measured by. Tests set all three.
	uid        int
	cacheOwner int
	now        func() time.Time

	// managerExes are the executables of the user's service manager: a
	// process whose parent is one of them, running `--user` as the same
	// user, is at the top of its chain, as a process under launchd is on
	// macOS. Tests override it.
	managerExes []string
	// noPidfd makes OnProcessExit poll instead of waiting on a pidfd, as
	// it does on a kernel without them; noPeerPidfd makes PeerOf go by
	// SO_PEERCRED alone, as it does before Linux 6.5. Tests set them.
	noPidfd     bool
	noPeerPidfd bool
	// pidfdWaits counts the exits waited on through a pidfd and peerPidfds
	// the peers identified through SO_PEERPIDFD, so tests can tell those
	// paths were taken and not their fallbacks.
	pidfdWaits atomic.Int64
	peerPidfds atomic.Int64
	// between runs between a record's first read and its last check, in
	// Process, ExeHash and PeerOf; nil in use. Tests set it to change the
	// process in between. beforeRead runs in hashPath once the file's type
	// is checked and before it is opened for reading; nil in use. Tests
	// set it to make the name mean another file in between.
	between    func()
	beforeRead func()
	// imageOf names the file a process runs, as the kernel resolves
	// /proc/<pid>/exe in the process's own mount namespace; nil means
	// imageID. Tests set it to answer as the kernel does for a process in
	// another mount namespace: a file other than the one its name means
	// here.
	imageOf func(pid int) (fileID, bool)
	// ticksNow is the clock the peer's start is compared with in PeerOf;
	// nil means bootTicks. Tests set it.
	ticksNow func() (uint64, bool)
}

// systemdExes are where distributions install the systemd binary.
var systemdExes = []string{"/usr/lib/systemd/systemd", "/lib/systemd/systemd"}

// New returns a Procs with an empty hash cache.
func New() *Procs {
	return &Procs{cache: map[hashKey][]byte{}, uid: os.Geteuid(), now: time.Now, managerExes: systemdExes}
}

// Process answers the platform.Platform contract: given a full ref only
// that instance (a tampered generation, an exited or zombie process, the
// zero ref and a negative or absent PID are ErrNoProcess); given a PID-only
// ref the live occupant of the PID with its full ref. /proc/<pid>/stat is
// read first and last, and a record whose identity changed between the
// two reads (another start, parent or uid, or exited) is ErrNoProcess.
//
// Path is the file the process runs only when that name, as the agent
// sees it, is the file whose image was hashed: a process in another mount
// namespace (a Flatpak or Snap app, a container, a bind mount) sees other
// files under the same names, and a path: rule must not match one of
// those. When they differ, or the image can't be read, Path is "".
func (p *Procs) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	st, err := check(ref)
	if err != nil {
		return platform.ProcessInfo{}, err
	}
	pid := ref.PID
	info := platform.ProcessInfo{
		Ref:  platform.ProcessRef{PID: pid, Generation: Generation(st.StartTicks)},
		UID:  st.EUID,
		Path: exePath(pid),
		Args: cmdline(pid),
		Cwd:  readLink(procPath(pid, "cwd")),
		Comm: comm(pid),
	}
	boot, err := btime()
	if err != nil {
		return platform.ProcessInfo{}, err
	}
	info.StartTime = startTime(boot, st.StartTicks)
	p.pause()
	// The hash of the file the process was started from; nil when it can't
	// be read (another user's process): there is no identity to match then,
	// and no Path either.
	h, id, err := p.hashPath(procPath(pid, "exe"))
	if err != nil {
		info.Path = ""
	} else {
		info.Code = platform.CodeIdentity{CDHash: h}
		if info.Path != "" && !sameFile(info.Path, id) {
			info.Path = ""
		}
	}
	info.Parent = p.parent(st)
	again, err := ReadStat(pid)
	if err != nil || !st.same(again) {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	return info, nil
}

// pause runs the between hook when a test set one.
func (p *Procs) pause() {
	if p.between != nil {
		p.between()
	}
}

// startTime is the wall-clock time at which a process that started ticks
// after the boot at boot (seconds since the epoch) started. The ticks are
// split into whole seconds and a remainder, so the value can't overflow a
// Duration (ticks times a second does after about 2.9 years of uptime).
func startTime(boot int64, ticks uint64) time.Time {
	return time.Unix(boot+int64(ticks/clockTicks), 0).Add(time.Duration(ticks%clockTicks) * (time.Second / clockTicks))
}

// check reads the stat of the process ref names and refuses a ref that
// names no live instance.
func check(ref platform.ProcessRef) (Stat, error) {
	if ref.PID <= 0 {
		return Stat{}, platform.ErrNoProcess
	}
	st, err := ReadStat(ref.PID)
	if err != nil {
		return Stat{}, err
	}
	if !st.live() || (ref.Generation != 0 && ref.Generation != Generation(st.StartTicks)) {
		return Stat{}, platform.ErrNoProcess
	}
	return st, nil
}

// parent names the parent of the process behind st: PID-only, as the
// kernel gives only its PID; zero at the top of the tree; {PID: 1} when
// the parent is this user's service manager (`systemd --user`), so the
// chain ends there as it ends at launchd on macOS. A parent that can't be
// read (gone, or another user's) is named by its PID anyway: core/caller
// resolves and checks it.
func (p *Procs) parent(st Stat) platform.ProcessRef {
	if st.PPID <= 0 {
		return platform.ProcessRef{}
	}
	if p.isUserManager(st.PPID, st.EUID) {
		return platform.ProcessRef{PID: 1}
	}
	return platform.ProcessRef{PID: st.PPID}
}

// isUserManager reports whether pid is the service manager of the user
// uid: one of the manager executables, run with `--user`, as that user.
// The executable is matched by the file it is, as Process ties Path to
// the hashed image: the name /proc/<pid>/exe reads means another file to
// a process in its own mount namespace, so a program bind-mounted over
// the manager's name is not the manager. The other side of that: once a
// package upgrade has replaced the systemd binary, a `systemd --user`
// still running the old file is not matched until it re-execs or the
// user logs in again; its children's chains then carry it and end at the
// system's PID 1, which fails closed for a rule that relies on the chain
// ending at the manager (as an app: pin fails closed after an upgrade).
func (p *Procs) isUserManager(pid, uid int) bool {
	st, err := ReadStat(pid)
	if err != nil || !st.live() || st.EUID != uid {
		return false
	}
	imageOf := p.imageOf
	if imageOf == nil {
		imageOf = imageID
	}
	id, ok := imageOf(pid)
	if !ok {
		return false
	}
	known := false
	for _, m := range p.managerExes {
		if sameFile(m, id) {
			known = true
		}
	}
	if !known {
		return false
	}
	args := cmdline(pid)
	return len(args) >= 2 && args[1] == "--user"
}

// PeerOf identifies the process at the other end of the connected Unix
// socket fd, with a full ref. The PID is the peer's as the kernel recorded
// it at connect time (SO_PEERCRED). With SO_PEERPIDFD (Linux 6.5) the
// kernel hands out its pidfd of that process, which names that process
// and no later holder of its PID; a signal check on it once the stat was
// read (ESRCH only when that process is gone) proves the stat was the
// peer's own, so its PID could not have been recycled before the read.
// Without the option (an older kernel, or a seccomp filter that refuses
// it), the stat of the PID is what there is, and one check narrows what
// it can be: the peer connected before this call began, and it started
// before it connected, so a holder of the PID whose start ticks are later
// than the boot clock's at entry is a new process in a recycled PID, not
// the peer (the kernel floors both to the same tick, so a peer that
// started in the tick this call began in still passes). A PID recycled
// before the call began is item 8 of the design's "Weaker than macOS"
// list. A peer that has exited is ErrNoProcess; an fd that is not a
// connected Unix socket, or a pidfd the kernel could not make for another
// reason (the agent's file table is full), is a plain error that says so.
func (p *Procs) PeerOf(fd int) (platform.ProcessRef, error) {
	if fd < 0 {
		return platform.ProcessRef{}, errors.New("procfs: bad socket")
	}
	ticksNow := p.ticksNow
	if ticksNow == nil {
		ticksNow = bootTicks
	}
	entry, haveEntry := ticksNow()
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return platform.ProcessRef{}, fmt.Errorf("procfs: peer credentials: %w", err)
	}
	if cred.Pid <= 0 {
		return platform.ProcessRef{}, fmt.Errorf("procfs: peer pid %d: %w", cred.Pid, platform.ErrNoProcess)
	}
	pidfd, perr := -1, error(unix.ENOPROTOOPT)
	if !p.noPeerPidfd {
		pidfd, perr = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	}
	switch {
	case perr == nil:
		defer unix.Close(pidfd)
		p.peerPidfds.Add(1)
	case errors.Is(perr, unix.ENOPROTOOPT), errors.Is(perr, unix.ENOSYS), errors.Is(perr, unix.EPERM):
		// Before Linux 6.5 the kernel has no pidfd for a peer; a seccomp
		// filter may refuse the option. SO_PEERCRED's pid is what there is,
		// as OnProcessExit polls when pidfd_open is refused.
	case errors.Is(perr, unix.ESRCH), errors.Is(perr, unix.EINVAL):
		// The kernel knows the option but makes no pidfd for a peer that
		// has exited and been reaped. A kernel that hands one out for a
		// reaped peer too is caught below: the stat read, of nobody or of
		// a new holder of the PID, is refused by the signal check.
		return platform.ProcessRef{}, fmt.Errorf("procfs: peer pidfd: %v: %w", perr, platform.ErrNoProcess)
	default:
		// EMFILE and the like: the agent's fault, not the peer's.
		return platform.ProcessRef{}, fmt.Errorf("procfs: peer pidfd: %w", perr)
	}
	st, err := ReadStat(int(cred.Pid))
	if err != nil {
		return platform.ProcessRef{}, err
	}
	if !st.live() {
		return platform.ProcessRef{}, platform.ErrNoProcess
	}
	if haveEntry && st.StartTicks > entry {
		return platform.ProcessRef{}, fmt.Errorf("procfs: pid %d started after the lookup began: %w", cred.Pid, platform.ErrNoProcess)
	}
	p.pause()
	// The process the pidfd names is still there after the read, so the
	// read was of the peer, not of a later holder of its PID. EPERM would
	// mean "exists, not yours".
	if perr == nil && errors.Is(unix.PidfdSendSignal(pidfd, 0, nil, 0), unix.ESRCH) {
		return platform.ProcessRef{}, platform.ErrNoProcess
	}
	return platform.ProcessRef{PID: int(cred.Pid), Generation: Generation(st.StartTicks)}, nil
}

// ResponsibleFor is always unknown: Linux has no responsible-process link.
func (p *Procs) ResponsibleFor(platform.ProcessRef) (platform.ProcessRef, bool) {
	return platform.ProcessRef{}, false
}

// exePath is the file a process runs, or "" when the kernel won't say
// (another user's process) or the file is gone (deleted by an upgrade
// while the process runs: the link ends in " (deleted)").
func exePath(pid int) string {
	path := readLink(procPath(pid, "exe"))
	if strings.HasSuffix(path, " (deleted)") {
		return ""
	}
	return path
}

func readLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

// cmdline is the process's arguments: NUL-separated in /proc/<pid>/cmdline.
func cmdline(pid int) []string {
	data, err := os.ReadFile(procPath(pid, "cmdline"))
	if err != nil || len(data) == 0 {
		return nil
	}
	data = bytes.TrimSuffix(data, []byte{0})
	parts := bytes.Split(data, []byte{0})
	args := make([]string, len(parts))
	for i, part := range parts {
		args[i] = string(part)
	}
	return args
}

// comm is the kernel's short name for the process (at most 15 bytes).
func comm(pid int) string {
	data, err := os.ReadFile(procPath(pid, "comm"))
	if err != nil {
		return ""
	}
	return string(bytes.TrimRight(data, "\n"))
}
