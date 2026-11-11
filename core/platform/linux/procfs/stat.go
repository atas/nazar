//go:build linux

package procfs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"sync"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// Stat is what identifies one process instance in /proc/<pid>/stat (and
// its effective uid from /proc/<pid>/status).
type Stat struct {
	PPID       int
	StartTicks uint64 // field 22: clock ticks after boot when the process started
	State      byte   // R, S, D, T, t, Z (zombie), X (dead), ...
	EUID       int
}

// Generation is the ProcessRef generation of a process that started at
// startTicks: the ticks plus one, so it is never zero (a PID-only ref) even
// for a process started in the boot's first tick.
func Generation(startTicks uint64) uint64 { return startTicks + 1 }

// ReadStat reads the identity of pid from /proc. A pid that is not
// positive, or that no process holds, is platform.ErrNoProcess; a zombie
// is still reported, with State 'Z' (Process maps it to ErrNoProcess). A
// thread's id is ErrNoProcess too: /proc/<tid>/ answers for any thread,
// but only a thread group leader is a process.
func ReadStat(pid int) (Stat, error) {
	if pid <= 0 {
		return Stat{}, platform.ErrNoProcess
	}
	data, err := os.ReadFile(procPath(pid, "stat"))
	if err != nil {
		return Stat{}, noProcess(err)
	}
	st, err := parseStat(data)
	if err != nil {
		return Stat{}, err
	}
	status, err := os.ReadFile(procPath(pid, "status"))
	if err != nil {
		return Stat{}, noProcess(err)
	}
	tgid, err := parseStatus(status, "Tgid:")
	if err != nil {
		return Stat{}, err
	}
	if tgid != pid {
		return Stat{}, platform.ErrNoProcess
	}
	st.EUID, err = parseEUID(status)
	if err != nil {
		return Stat{}, err
	}
	return st, nil
}

// live reports whether st is a process that can still act: a zombie or a
// dead process has exited, whatever else /proc still says about it. The
// state is the thread group leader's, so a process whose main thread has
// exited while its other threads run on (a pthread_exit from the main
// thread; no Go program does it) reads as a zombie too and is treated as
// gone: Process and ExeHash refuse it, PeerOf refuses it as a peer and
// OnProcessExit fires for it. That fails closed, for a rare case; the
// Threads line of /proc/<pid>/status could tell the two apart.
func (st Stat) live() bool { return st.State != 'Z' && st.State != 'X' }

// same reports whether the process behind st2 is the one behind st: the
// same start, parent and uid, and still live. A flip between running and
// sleeping is not a change. A new parent is one, though the instance is
// the same: a process whose parent exits between the two reads is
// reparented (to PID 1 or a subreaper), and the record read in between
// named the old parent, which the chain would then be judged by. Such a
// caller is reported as ErrNoProcess for that one request (a false
// refusal, logged as the caller being gone; the next request sees the
// settled record), never matched by a parent it no longer has.
func (st Stat) same(st2 Stat) bool {
	return st.StartTicks == st2.StartTicks && st.PPID == st2.PPID && st.EUID == st2.EUID && st.live() && st2.live()
}

func procPath(pid int, file string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + file
}

// noProcess maps a /proc read error to ErrNoProcess when the process is
// gone (ENOENT: the directory vanished; ESRCH: it exited mid-read).
func noProcess(err error) error {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return platform.ErrNoProcess
	}
	return fmt.Errorf("procfs: %w", err)
}

// parseStat parses /proc/<pid>/stat. The comm (field 2) is in parentheses
// and may hold spaces and parentheses itself, so the fields are counted
// from the last ')'.
func parseStat(data []byte) (Stat, error) {
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return Stat{}, errors.New("procfs: malformed stat")
	}
	// After the comm: state(3) ppid(4) ... starttime(22).
	fields := bytes.Fields(data[end+1:])
	if len(fields) < 20 || len(fields[0]) != 1 {
		return Stat{}, errors.New("procfs: malformed stat")
	}
	ppid, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return Stat{}, fmt.Errorf("procfs: stat ppid: %w", err)
	}
	start, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return Stat{}, fmt.Errorf("procfs: stat starttime: %w", err)
	}
	return Stat{PPID: ppid, StartTicks: start, State: fields[0][0]}, nil
}

// parseEUID takes the effective uid from the "Uid:" line of
// /proc/<pid>/status (real, effective, saved, filesystem).
func parseEUID(status []byte) (int, error) {
	f, err := statusFields(status, "Uid:")
	if err != nil {
		return 0, err
	}
	if len(f) < 2 {
		return 0, errors.New("procfs: short Uid line in status")
	}
	return strconv.Atoi(string(f[1]))
}

// parseStatus takes the one number on the status line with the given
// prefix ("Tgid:", say).
func parseStatus(status []byte, prefix string) (int, error) {
	f, err := statusFields(status, prefix)
	if err != nil {
		return 0, err
	}
	if len(f) < 1 {
		return 0, fmt.Errorf("procfs: short %s line in status", prefix)
	}
	return strconv.Atoi(string(f[0]))
}

// statusFields returns the fields after the prefix on the first line of
// /proc/<pid>/status that starts with it.
func statusFields(status []byte, prefix string) ([][]byte, error) {
	for _, line := range bytes.Split(status, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(prefix)) {
			return bytes.Fields(line[len(prefix):]), nil
		}
	}
	return nil, fmt.Errorf("procfs: no %s line in status", prefix)
}

// clockTicks is the kernel's USER_HZ, in which /proc reports times: 100 on
// every Linux architecture Go runs on.
const clockTicks = 100

// bootTicks is the boot clock now, in the ticks /proc/<pid>/stat counts a
// process's start in: both are the kernel's boottime clock, and both are
// floored to the tick, so a process that started in this tick has at most
// this value. False when the clock can't be read.
func bootTicks() (uint64, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil || ts.Sec < 0 {
		return 0, false
	}
	return uint64(ts.Sec)*clockTicks + uint64(ts.Nsec)/(1e9/clockTicks), true
}

var (
	bootMu   sync.Mutex
	bootTime int64 // seconds since the epoch; 0 until read
)

// btime is the boot time from /proc/stat, read once.
func btime() (int64, error) {
	bootMu.Lock()
	defer bootMu.Unlock()
	if bootTime != 0 {
		return bootTime, nil
	}
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("procfs: %w", err)
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("btime ")) {
			continue
		}
		t, err := strconv.ParseInt(string(bytes.TrimSpace(line[6:])), 10, 64)
		if err != nil || t <= 0 {
			return 0, fmt.Errorf("procfs: /proc/stat btime %q", line)
		}
		bootTime = t
		return t, nil
	}
	return 0, errors.New("procfs: no btime in /proc/stat")
}
