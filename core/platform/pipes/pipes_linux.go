//go:build linux

package pipes

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"golang.org/x/sys/unix"
)

// pfKernelThread is PF_KTHREAD (include/linux/sched.h): the flags bit of a
// kernel thread, in field 9 of /proc/<pid>/stat.
const pfKernelThread = 0x00200000

// A task whose fds cannot be read and that the check cannot skip is read
// again for this long before the check fails closed. A process part way
// through exit has dropped its memory, which makes its /proc files root's,
// and still holds its fds until the kernel has freed that memory, so an
// ordinary process of this user looks unreadable for a moment. A program
// that stays unreadable waits this long once and is an error: the wait is
// one budget for the whole scan.
const (
	unreadableWait = 2 * time.Second
	unreadablePoll = 10 * time.Millisecond
)

type procPipes struct{}

// New is the Linux stdout check (see doc.go).
func New() platform.Pipes { return procPipes{} }

// fdLink is one open fd of a task: its number and what
// /proc/<pid>/task/<tid>/fd/<fd> points at ("pipe:[1234]", "socket:[99]",
// a path).
type fdLink struct {
	fd     int
	target string
}

// holder is one reference to the pipe: an fd of a process.
type holder struct{ pid, fd int }

// readFDs lists the open fds of one task of a process, as listFDs does. A
// variable so the tests can make one process's fds unreadable, as another
// user's are.
var readFDs = listFDs

// readStatFile reads /proc/<pid>/stat. A variable so the tests can show the
// check a kernel thread's record, which a container does not list.
var readStatFile = func(pid int) ([]byte, error) { return os.ReadFile(procPath(pid, "stat")) }

// StdoutReadBy: both refs are checked live before and after the reads, so
// the answer is about the instances they name, never a recycled PID's.
// The writer's fd 1 must be a pipe's write end. Then every fd of every
// thread of every process in /proc is read for a link to that pipe: the
// only references allowed are the writer's fd 1 and one fd of the reader,
// open for reading and close-on-exec (one the reader opened itself: exec
// closes every fd that is, Go never sets it on an fd it inherited, and the
// pipe os/exec makes for an exec plugin is close-on-exec from the start).
// Any other reference, in the writer, the reader or a third process, is a
// co-writer or a co-reader, and the answer is false. A process whose fds
// cannot be read (another user's, or a non-dumpable one) is skipped when it
// started before the writer, as it cannot have inherited a pipe the reader
// made for the writer, and is an error otherwise, after a short wait for one on its
// way out: the check fails closed. Weaker than macOS, which counts a pipe
// end's references in the kernel. This is a snapshot: a reference in flight
// over a socket is invisible here, and so is one in a process whose fds are
// hidden, and any same-user process can open either end through
// /proc/<pid>/fd after the scan, including between the mint-time check and
// the CLI's write. So it stops a relay (tee), not a same-user reader
// (doc.go, THREAT-MODEL Linux).
func (procPipes) StdoutReadBy(writer, reader platform.ProcessRef) (bool, error) {
	return readByLive(writer, 0, reader)
}

// StdoutReadByThrough (platform.StdoutThrough): as StdoutReadBy, with via's
// fd 1 the one more reference the pipe may have, and that one a write end
// (checked by its flags), so via passed the pipe on and cannot read it.
// via is checked live with the other two.
func (procPipes) StdoutReadByThrough(writer, via, reader platform.ProcessRef) (bool, error) {
	if _, err := live(via); err != nil {
		return false, err
	}
	ok, err := readByLive(writer, via.PID, reader)
	if _, err := live(via); err != nil {
		return false, err
	}
	return ok, err
}

// readByLive checks writer and reader live before and after readBy; via is
// 0 for no process between them.
func readByLive(writer platform.ProcessRef, via int, reader platform.ProcessRef) (bool, error) {
	ws, err := live(writer)
	if err != nil {
		return false, err
	}
	if _, err := live(reader); err != nil {
		return false, err
	}
	cutoff := ws.StartTicks
	if via != 0 {
		// via started the writer, so it is the older of the two.
		vs, err := procfs.ReadStat(via)
		if err != nil {
			if errors.Is(err, platform.ErrNoProcess) {
				return false, err
			}
			return false, fmt.Errorf("pipes: %w", err)
		}
		cutoff = min(cutoff, vs.StartTicks)
	}
	ok, err := readBy(writer.PID, via, reader.PID, cutoff)
	if _, err := live(writer); err != nil {
		return false, err
	}
	if _, err := live(reader); err != nil {
		return false, err
	}
	return ok, err
}

// readBy answers for the live processes writer and reader; cutoff is
// unreadable's. via, when not 0, is the one process
// whose fd 1 may hold the pipe's write end as well.
func readBy(writer, via, reader int, cutoff uint64) (bool, error) {
	target, err := os.Readlink(fdPath(writer, 1))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // fd 1 is closed
		}
		return false, fmt.Errorf("pipes: read fd 1 of %d: %w", writer, err)
	}
	if !strings.HasPrefix(target, "pipe:[") {
		return false, nil
	}
	flags, err := fdFlags(writer, 1)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if flags&unix.O_ACCMODE != unix.O_WRONLY {
		return false, nil
	}
	hs, err := holders(target, cutoff)
	if err != nil {
		return false, err
	}
	want := 2
	if via != 0 {
		want = 3
	}
	if len(hs) != want {
		return false, nil
	}
	readerFD, viaSeen := -1, false
	for _, h := range hs {
		switch {
		case h.pid == writer && h.fd == 1:
		case via != 0 && h.pid == via && h.fd == 1 && !viaSeen:
			viaSeen = true
		case h.pid == reader && readerFD < 0:
			readerFD = h.fd
		default:
			return false, nil
		}
	}
	if readerFD < 0 || (via != 0 && !viaSeen) {
		return false, nil
	}
	if via != 0 {
		// via's fd 1 is the write end it passed on: open for writing
		// only, so via cannot read what writer writes.
		flags, err := fdFlags(via, 1)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		if flags&unix.O_ACCMODE != unix.O_WRONLY {
			return false, nil
		}
	}
	flags, err = fdFlags(reader, readerFD)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // closed since the scan
		}
		return false, err
	}
	return flags&unix.O_ACCMODE == unix.O_RDONLY && flags&unix.O_CLOEXEC != 0, nil
}

// holders finds every fd of every process in /proc that links to target,
// reading the fd table of each of its threads: a process whose main thread
// has exited shows no fds of its own, and a thread that unshared its table
// shows its fds only there. Threads usually share one table, so an fd number
// already seen in the process is not a second reference.
func holders(target string, cutoff uint64) ([]holder, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("pipes: list /proc: %w", err)
	}
	var hs []holder
	var deadline time.Time // of the wait in readTask, set when first needed
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		tids, err := tasks(pid)
		if err != nil {
			if err := unreadable(pid, pid, err, cutoff); err != nil {
				return nil, err
			}
			continue
		}
		seen := map[int]bool{}
		for _, tid := range tids {
			fds, err := readTask(pid, tid, cutoff, &deadline)
			if err != nil {
				return nil, err
			}
			for _, f := range fds {
				if f.target == target && !seen[f.fd] {
					seen[f.fd] = true
					hs = append(hs, holder{pid, f.fd})
				}
			}
		}
	}
	return hs, nil
}

// readTask lists the fds of one thread. One the check may skip gives none.
// One that cannot be read and cannot be skipped is read again until it can
// be either or deadline passes (set here on first use), then fails the check.
func readTask(pid, tid int, cutoff uint64, deadline *time.Time) ([]fdLink, error) {
	for {
		fds, err := readFDs(pid, tid)
		if err == nil {
			return fds, nil
		}
		judged := unreadable(pid, tid, err, cutoff)
		if judged == nil {
			return nil, nil
		}
		if !errors.Is(err, fs.ErrPermission) {
			return nil, judged
		}
		now := time.Now()
		if deadline.IsZero() {
			*deadline = now.Add(unreadableWait)
		}
		if now.After(*deadline) {
			return nil, judged
		}
		time.Sleep(unreadablePoll)
	}
}

// unreadable decides about a thread of pid whose fds could not be listed:
// nil skips it, an error fails the check. A thread that is gone or has
// exited (a zombie: its table is closed, though a zombie main thread can
// have live threads, each judged on its own) holds no pipe, nor does a
// kernel thread (no user fds). One in a process that started before cutoff
// is skipped. cutoff is the start, in boot ticks, of the writer, or of the
// shell between it and the reader: the reader makes the pipe for the program
// it then starts, so no older process has it by inheritance, and everything
// that program forks, a wrapper's background job included, is newer (exec
// keeps a process's start). The reader's own start would refuse too much: a
// reader that lives long (k9s, a port-forward, an SDK refreshing its
// credential) is older than much of the machine, and any sudo, ssh or root
// service started after it (not dumpable) would fail every check for as
// long as it lived. Any other could hold the pipe, so the
// check fails closed.
func unreadable(pid, tid int, err error, cutoff uint64) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if !errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("pipes: list fds of %d: %w", pid, err)
	}
	st, serr := procfs.ReadStat(pid)
	if errors.Is(serr, platform.ErrNoProcess) {
		return nil
	}
	if serr != nil {
		return fmt.Errorf("pipes: %w", serr)
	}
	if st.StartTicks < cutoff {
		return nil
	}
	if kt, kerr := kernelThread(pid); kerr == nil && kt {
		return nil
	}
	state, serr := taskState(pid, tid)
	if errors.Is(serr, fs.ErrNotExist) || errors.Is(serr, unix.ESRCH) {
		return nil
	}
	if serr == nil && (state == 'Z' || state == 'X') {
		return nil
	}
	return fmt.Errorf("pipes: cannot tell who holds the pipe: process %d started after the program that asked and its fds cannot be read: %w", pid, err)
}

// tasks lists the thread ids of pid from /proc/<pid>/task.
func tasks(pid int) ([]int, error) {
	ents, err := os.ReadDir(procPath(pid, "task"))
	if err != nil {
		return nil, err
	}
	tids := make([]int, 0, len(ents))
	for _, e := range ents {
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			tids = append(tids, tid)
		}
	}
	return tids, nil
}

// taskState is the state letter of one thread, from its own stat record:
// /proc/<pid>/stat answers for the main thread alone.
func taskState(pid, tid int) (byte, error) {
	data, err := os.ReadFile(taskPath(pid, tid, "stat"))
	if err != nil {
		return 0, err
	}
	fields, err := statFields(data)
	if err != nil {
		return 0, err
	}
	return fields[0][0], nil
}

// listFDs reads /proc/<pid>/task/<tid>/fd. An fd closed between the listing
// and its readlink is left out; any other failure is the caller's to judge.
func listFDs(pid, tid int) ([]fdLink, error) {
	dir := taskPath(pid, tid, "fd")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	links := make([]fdLink, 0, len(ents))
	for _, e := range ents {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		target, err := os.Readlink(dir + "/" + e.Name())
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, err
		}
		links = append(links, fdLink{fd: fd, target: target})
	}
	return links, nil
}

// fdFlags is the open flags of fd in pid, from the flags line of
// /proc/<pid>/fdinfo/<fd> (octal). A missing file is fs.ErrNotExist.
func fdFlags(pid, fd int) (uint64, error) {
	data, err := os.ReadFile(procPath(pid, "fdinfo/"+strconv.Itoa(fd)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, err
		}
		return 0, fmt.Errorf("pipes: read fd %d of %d: %w", fd, pid, err)
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("flags:")) {
			continue
		}
		flags, err := strconv.ParseUint(string(bytes.TrimSpace(line[len("flags:"):])), 8, 64)
		if err != nil {
			return 0, fmt.Errorf("pipes: fdinfo of fd %d of %d: %w", fd, pid, err)
		}
		return flags, nil
	}
	return 0, fmt.Errorf("pipes: fdinfo of fd %d of %d has no flags line", fd, pid)
}

// kernelThread reports whether pid is a kernel thread.
func kernelThread(pid int) (bool, error) {
	data, err := readStatFile(pid)
	if err != nil {
		return false, err
	}
	return kernelThreadStat(data)
}

// statFields are the fields of a stat record after the comm: state(3)
// ppid(4) pgrp(5) session(6) tty_nr(7) tpgid(8) flags(9) and on. The comm
// (field 2) is in parentheses and may hold spaces and parentheses itself,
// so they are counted from the last ')'.
func statFields(data []byte) ([][]byte, error) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return nil, errors.New("pipes: malformed stat")
	}
	fields := bytes.Fields(data[end+1:])
	if len(fields) < 7 || len(fields[0]) != 1 {
		return nil, errors.New("pipes: malformed stat")
	}
	return fields, nil
}

// kernelThreadStat reads PF_KTHREAD from the flags field (9) of a
// /proc/<pid>/stat record.
func kernelThreadStat(data []byte) (bool, error) {
	fields, err := statFields(data)
	if err != nil {
		return false, err
	}
	flags, err := strconv.ParseUint(string(fields[6]), 10, 64)
	if err != nil {
		return false, fmt.Errorf("pipes: stat flags: %w", err)
	}
	return flags&pfKernelThread != 0, nil
}

// live checks that ref names a live process: a full ref (never PID-only
// or zero) whose PID holds the instance with that start, not a zombie.
func live(ref platform.ProcessRef) (procfs.Stat, error) {
	if ref.PID <= 0 || ref.Generation == 0 {
		return procfs.Stat{}, platform.ErrNoProcess
	}
	st, err := procfs.ReadStat(ref.PID)
	if err != nil {
		if errors.Is(err, platform.ErrNoProcess) {
			return st, err
		}
		return st, fmt.Errorf("pipes: %w", err)
	}
	if procfs.Generation(st.StartTicks) != ref.Generation || st.State == 'Z' || st.State == 'X' {
		return st, platform.ErrNoProcess
	}
	return st, nil
}

func procPath(pid int, file string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + file
}

func taskPath(pid, tid int, file string) string {
	return procPath(pid, "task/"+strconv.Itoa(tid)+"/"+file)
}

func fdPath(pid, fd int) string {
	return procPath(pid, "fd/"+strconv.Itoa(fd))
}
