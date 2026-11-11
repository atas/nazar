//go:build linux

package pipes

// THREAT-MODEL 5.16 on Linux: the stdout check over real processes. This
// test process is the reader, as kubectl is for its exec plugin, and each
// writer is its child set up by internal/linuxtest/stdoutcase. No /dev/tpm,
// bus or desktop is touched; the children are /bin/sleep, /bin/cat and the
// shells that exec them, and this test binary run again as a process whose
// main thread has exited. The tests share the readFDs seam, so none runs in
// parallel.

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/internal/linuxtest/stdoutcase"
	"golang.org/x/sys/unix"
)

// hiddenHolderEnv runs this test binary as hiddenHolder instead of the tests.
const hiddenHolderEnv = "NAZAR_PIPES_TEST_HIDDEN_HOLDER"

func init() {
	if os.Getenv(hiddenHolderEnv) != "" {
		runtime.LockOSThread() // the main goroutine stays on the main thread
	}
}

func TestMain(m *testing.M) {
	if os.Getenv(hiddenHolderEnv) != "" {
		hiddenHolder()
	}
	os.Exit(m.Run())
}

// hiddenHolder keeps fd 3 open in a thread and exits the main thread alone:
// /proc/<pid>/stat then says zombie and /proc/<pid>/fd shows no fds, though
// the process lives on and holds fd 3.
func hiddenHolder() {
	go func() {
		runtime.LockOSThread()
		var b [1]byte
		unix.Read(3, b[:])
		for {
			unix.Nanosleep(&unix.Timespec{Sec: 3600}, nil)
		}
	}()
	unix.Syscall(unix.SYS_EXIT, 0, 0, 0)
}

func TestNewOnLinux(t *testing.T) {
	if New() == nil {
		t.Fatal("pipes.New() is nil on Linux: nazar-agent would refuse every k8s credential")
	}
}

// The one yes, asked three times: the answer is read from /proc each time
// and nothing in the check changes it.
func TestPiped(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	for i := range 3 {
		if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
			t.Fatalf("StdoutReadBy of a pipe the parent reads (call %d) = %v, %v; want true", i+1, ok, err)
		}
	}
}

// Every other fd 1 is a plain no with no error: the pipe is matched by its
// inode, a read end someone else holds as well is no pipe to the reader
// alone, a write end someone else holds as well is no pipe from the writer
// alone, one the reader inherited is no pipe it opened, and a file, a
// terminal, a socket, the wrong end or a closed fd is no pipe to it.
func TestOtherCases(t *testing.T) {
	for _, c := range []conformance.StdoutCase{
		conformance.StdoutPipedElsewhere, conformance.StdoutSharedReadEnd, conformance.StdoutSharedWriteEnd,
		conformance.StdoutInheritedReadEnd, conformance.StdoutRelayed, conformance.StdoutFile,
		conformance.StdoutTerminal, conformance.StdoutSocket, conformance.StdoutReadEnd, conformance.StdoutClosed,
	} {
		t.Run(string(c), func(t *testing.T) {
			w, r := stdoutcase.Start(t, c)
			if ok, err := New().StdoutReadBy(w, r); ok || err != nil {
				t.Fatalf("StdoutReadBy with fd 1 %s = %v, %v; want false and no error", c, ok, err)
			}
		})
	}
}

// A writer that has exited is ErrNoProcess, never an answer.
func TestGone(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutGone)
	if ok, err := New().StdoutReadBy(w, r); ok || !errors.Is(err, platform.ErrNoProcess) {
		t.Fatalf("StdoutReadBy of an exited writer = %v, %v; want ErrNoProcess", ok, err)
	}
}

// Only the live instances the full refs name are asked about: a stale
// generation, a PID-only ref or the zero ref of either side is
// ErrNoProcess, and the question is not symmetric.
func TestRefs(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	stale := func(ref platform.ProcessRef) platform.ProcessRef {
		return platform.ProcessRef{PID: ref.PID, Generation: ref.Generation + 1}
	}
	for name, refs := range map[string][2]platform.ProcessRef{
		"writer's generation tampered": {stale(w), r},
		"reader's generation tampered": {w, stale(r)},
		"writer PID-only":              {{PID: w.PID}, r},
		"reader PID-only":              {w, {PID: r.PID}},
		"zero writer":                  {{}, r},
		"zero reader":                  {w, {}},
		"negative writer":              {{PID: -1, Generation: 1}, r},
	} {
		if ok, err := New().StdoutReadBy(refs[0], refs[1]); ok || !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("StdoutReadBy(%s) = %v, %v; want ErrNoProcess", name, ok, err)
		}
	}
	if ok, err := New().StdoutReadBy(r, w); ok || err != nil {
		t.Errorf("StdoutReadBy(reader, writer) = %v, %v; want false and no error", ok, err)
	}
	// The refusals left the true answer as it was.
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy after the refusals = %v, %v; want true", ok, err)
	}
}

// denied is what /proc answers for another user's process or a non-dumpable
// one.
func denied(pid int) error {
	return &fs.PathError{Op: "open", Path: "/proc/" + strconv.Itoa(pid) + "/fd", Err: unix.EACCES}
}

// denyFDs makes readFDs answer EACCES for pid, in every thread, and reports
// whether it was asked.
func denyFDs(t *testing.T, pid int) *atomic.Bool {
	t.Helper()
	real := readFDs
	var asked atomic.Bool
	readFDs = func(p, tid int) ([]fdLink, error) {
		if p == pid {
			asked.Store(true)
			return nil, denied(p)
		}
		return real(p, tid)
	}
	t.Cleanup(func() { readFDs = real })
	return &asked
}

// denyFDsOnce makes readFDs answer EACCES the first time it is asked for
// pid, and the real answer after that, and counts the times it was asked.
func denyFDsOnce(t *testing.T, pid int) *atomic.Int32 {
	t.Helper()
	real := readFDs
	var asked atomic.Int32
	readFDs = func(p, tid int) ([]fdLink, error) {
		if p == pid && asked.Add(1) == 1 {
			return nil, denied(p)
		}
		return real(p, tid)
	}
	t.Cleanup(func() { readFDs = real })
	return &asked
}

// startChild starts cmd and has it killed and reaped when the test ends.
func startChild(t *testing.T, cmd *exec.Cmd) *exec.Cmd {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	return cmd
}

// waitState waits until pid's stat shows state.
func waitState(t *testing.T, pid int, state byte) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if st, err := procfs.ReadStat(pid); err == nil && st.State == state {
			return
		}
	}
	t.Fatalf("process %d did not reach state %c", pid, state)
}

// pipeWithWriter makes a pipe this process reads, whose write end only a new
// child holds on fd 1, and returns the read end and the two full refs.
func pipeWithWriter(t *testing.T) (r *os.File, writer, reader platform.ProcessRef) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	cmd := exec.Command("/bin/sleep", "600")
	cmd.Stdout = w
	startChild(t, cmd)
	w.Close()
	return r, fullRef(t, cmd.Process.Pid), fullRef(t, os.Getpid())
}

func fullRef(t *testing.T, pid int) platform.ProcessRef {
	t.Helper()
	return platform.ProcessRef{PID: pid, Generation: procfs.Generation(startTicks(t, pid))}
}

// startHiddenHolder starts a process that holds a copy of f on fd 3 and whose
// main thread has exited, with a thread still running.
func startHiddenHolder(t *testing.T, f *os.File) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), hiddenHolderEnv+"=1")
	cmd.ExtraFiles = []*os.File{f}
	startChild(t, cmd)
	pid := cmd.Process.Pid
	waitState(t, pid, 'Z')
	if tids, err := tasks(pid); err != nil || len(tids) < 2 {
		t.Fatalf("threads of the hidden holder: %v, %v; want the zombie main thread and others", tids, err)
	}
	return pid
}

func startTicks(t *testing.T, pid int) uint64 {
	t.Helper()
	st, err := procfs.ReadStat(pid)
	if err != nil {
		t.Fatalf("stat of %d: %v", pid, err)
	}
	return st.StartTicks
}

// A process whose fds can't be read but that started before the reader
// can't hold a pipe the reader made later: it is skipped and the answer
// stands. PID 1 is older than this process wherever the test runs.
func TestUnreadableOlderSkipped(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	if startTicks(t, 1) >= startTicks(t, r.PID) {
		t.Fatal("PID 1 did not start before this process")
	}
	asked := denyFDs(t, 1)
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy with PID 1 unreadable = %v, %v; want true", ok, err)
	}
	if !asked.Load() {
		t.Fatal("the check never looked at PID 1's fds")
	}
}

// A process whose fds can't be read and that started after the reader but
// before the writer is skipped too: the pipe was made for the writer, after
// that process was forked. A long-lived reader (k9s, a port-forward) is
// older than every sudo or ssh on the machine started since.
func TestUnreadableOlderThanWriterSkipped(t *testing.T) {
	other := startChild(t, exec.Command("/bin/sleep", "600"))
	time.Sleep(50 * time.Millisecond) // start times count in ticks of 10 ms
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	if o := startTicks(t, other.Process.Pid); o < startTicks(t, r.PID) || o >= startTicks(t, w.PID) {
		t.Fatal("the child did not start after the reader and before the writer")
	}
	asked := denyFDs(t, other.Process.Pid)
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy with an unreadable process older than the writer = %v, %v; want true", ok, err)
	}
	if !asked.Load() {
		t.Fatal("the check never looked at the child's fds")
	}
}

// A process whose fds can't be read and that started after the writer
// could hold the pipe: the check fails closed with an error that names it,
// not ErrNoProcess (the writer is alive) and not a plain no.
func TestUnreadableNewerIsAnError(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	other := exec.Command("/bin/sleep", "600")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		other.Process.Kill()
		other.Wait()
	})
	if startTicks(t, other.Process.Pid) < startTicks(t, r.PID) {
		t.Fatal("the child started before this process")
	}
	asked := denyFDs(t, other.Process.Pid)
	ok, err := New().StdoutReadBy(w, r)
	if ok || err == nil || errors.Is(err, platform.ErrNoProcess) || !strings.Contains(err.Error(), strconv.Itoa(other.Process.Pid)) {
		t.Fatalf("StdoutReadBy with a newer process unreadable = %v, %v; want false and an error naming %d", ok, err, other.Process.Pid)
	}
	if !asked.Load() {
		t.Fatal("the check never looked at the child's fds")
	}
}

// A process on its way out has dropped its memory, so its /proc files are
// root's and answer EACCES while it still holds its fds, as an ordinary
// same-user program does for a moment on a busy machine. That is no refusal:
// it is read again, and its real answer counts.
func TestUnreadableForAMomentIsReadAgain(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	other := startChild(t, exec.Command("/bin/sleep", "600"))
	asked := denyFDsOnce(t, other.Process.Pid)
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy with a process unreadable for a moment = %v, %v; want true", ok, err)
	}
	if asked.Load() < 2 {
		t.Fatalf("the child's fds were asked for %d times; want it read again", asked.Load())
	}
}

// The second read is a real read, not a pass: if it shows a copy of the read
// end, the answer is no.
func TestUnreadableForAMomentThenHoldsThePipe(t *testing.T) {
	pipe, w, r := pipeWithWriter(t)
	holder := exec.Command("/bin/sleep", "600")
	holder.Stdin = pipe
	startChild(t, holder)
	denyFDsOnce(t, holder.Process.Pid)
	if ok, err := New().StdoutReadBy(w, r); ok || err != nil {
		t.Fatalf("StdoutReadBy with a co-reader unreadable for a moment = %v, %v; want false and no error", ok, err)
	}
}

// One that never reads again but finishes exiting while the check waits is
// skipped as the zombie it has become.
func TestUnreadableThenExits(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	other := startChild(t, exec.Command("/bin/sleep", "600"))
	denyFDs(t, other.Process.Pid)
	timer := time.AfterFunc(100*time.Millisecond, func() { other.Process.Kill() })
	defer timer.Stop()
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy with an unreadable process that exits = %v, %v; want true", ok, err)
	}
}

// The wait is bounded: one that stays unreadable fails the check soon.
func TestUnreadableWaitIsBounded(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	other := startChild(t, exec.Command("/bin/sleep", "600"))
	denyFDs(t, other.Process.Pid)
	start := time.Now()
	if ok, err := New().StdoutReadBy(w, r); ok || err == nil {
		t.Fatalf("StdoutReadBy with a process that stays unreadable = %v, %v; want an error", ok, err)
	}
	if took := time.Since(start); took < unreadableWait || took > unreadableWait+5*time.Second {
		t.Fatalf("the check took %v; want about %v", took, unreadableWait)
	}
}

// A zombie has closed its fds, however new it is and whatever /proc says
// about reading them.
func TestUnreadableZombieSkipped(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	zombie := startChild(t, exec.Command("/bin/true")) // not reaped until the end
	waitState(t, zombie.Process.Pid, 'Z')
	asked := denyFDs(t, zombie.Process.Pid)
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy with an unreadable zombie = %v, %v; want true", ok, err)
	}
	if !asked.Load() {
		t.Fatal("the check never looked at the zombie's fds")
	}
}

// A kernel thread holds no user fds, so a new one that cannot be read is
// skipped. A container lists none, so the stat record is a kernel thread's.
func TestUnreadableKernelThreadSkipped(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	other := startChild(t, exec.Command("/bin/sleep", "600"))
	pid := other.Process.Pid
	denyFDs(t, pid)
	real := readStatFile
	readStatFile = func(p int) ([]byte, error) {
		if p == pid {
			return []byte(strconv.Itoa(p) + " (kworker/u8:3) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 20 0 1 0 5000 0 0\n"), nil
		}
		return real(p)
	}
	t.Cleanup(func() { readStatFile = real })
	if ok, err := New().StdoutReadBy(w, r); !ok || err != nil {
		t.Fatalf("StdoutReadBy with an unreadable kernel thread = %v, %v; want true", ok, err)
	}
}

// A process whose main thread has exited shows as a zombie with no fds, and
// its other threads still hold them: a co-reader there, reading the
// credential, is a plain no.
func TestHiddenCoReaderZombieLeader(t *testing.T) {
	pipe, w, r := pipeWithWriter(t)
	startHiddenHolder(t, pipe)
	if ok, err := New().StdoutReadBy(w, r); ok || err != nil {
		t.Fatalf("StdoutReadBy with a co-reader behind a zombie main thread = %v, %v; want false and no error", ok, err)
	}
}

// The same with a co-writer: fd 3 is a copy of the write end.
func TestHiddenCoWriterZombieLeader(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pr.Close() })
	t.Cleanup(func() { pw.Close() })
	startHiddenHolder(t, pw)
	cmd := exec.Command("/bin/sleep", "600")
	cmd.Stdout = pw
	startChild(t, cmd)
	pw.Close()
	if ok, err := New().StdoutReadBy(fullRef(t, cmd.Process.Pid), fullRef(t, os.Getpid())); ok || err != nil {
		t.Fatalf("StdoutReadBy with a co-writer behind a zombie main thread = %v, %v; want false and no error", ok, err)
	}
}

// Where the zombie main thread answers EACCES it is skipped alone, since it
// has no table, and its live threads are still read.
func TestHiddenCoReaderZombieLeaderUnreadable(t *testing.T) {
	pipe, w, r := pipeWithWriter(t)
	pid := startHiddenHolder(t, pipe)
	real := readFDs
	readFDs = func(p, tid int) ([]fdLink, error) {
		if p == pid && tid == pid {
			return nil, denied(p)
		}
		return real(p, tid)
	}
	t.Cleanup(func() { readFDs = real })
	if ok, err := New().StdoutReadBy(w, r); ok || err != nil {
		t.Fatalf("StdoutReadBy with a co-reader behind an unreadable zombie main thread = %v, %v; want false and no error", ok, err)
	}
}

// A zombie main thread does not excuse live threads that cannot be read:
// they could hold the pipe, so the check fails closed.
func TestZombieLeaderWithUnreadableThreadsIsAnError(t *testing.T) {
	pipe, w, r := pipeWithWriter(t)
	pid := startHiddenHolder(t, pipe)
	denyFDs(t, pid)
	ok, err := New().StdoutReadBy(w, r)
	if ok || err == nil || errors.Is(err, platform.ErrNoProcess) || !strings.Contains(err.Error(), strconv.Itoa(pid)) {
		t.Fatalf("StdoutReadBy with unreadable threads behind a zombie main thread = %v, %v; want false and an error naming %d", ok, err, pid)
	}
}

// A thread with an fd table of its own is read too, and a reference only
// there counts. The seam stands in for unshare(CLONE_FILES), which a
// container's seccomp profile refuses: a thread of the reader, not its main
// one, has a second fd on the pipe, and the same fd number in every thread
// (TestPiped) is one reference.
func TestReferenceInAThreadTableCounts(t *testing.T) {
	w, r := stdoutcase.Start(t, conformance.StdoutPiped)
	target, err := os.Readlink(fdPath(w.PID, 1))
	if err != nil {
		t.Fatal(err)
	}
	tids, err := tasks(r.PID)
	if err != nil || len(tids) < 2 {
		t.Fatalf("threads of this process: %v, %v; want several", tids, err)
	}
	real := readFDs
	var asked atomic.Bool
	readFDs = func(p, tid int) ([]fdLink, error) {
		fds, err := real(p, tid)
		if p == r.PID && tid != r.PID && err == nil {
			asked.Store(true)
			fds = append(fds, fdLink{fd: 977, target: target})
		}
		return fds, err
	}
	t.Cleanup(func() { readFDs = real })
	if ok, err := New().StdoutReadBy(w, r); ok || err != nil {
		t.Fatalf("StdoutReadBy with a reference in a thread's own table = %v, %v; want false and no error", ok, err)
	}
	if !asked.Load() {
		t.Fatal("the check never read a thread's table")
	}
}

// A kernel thread has no user fds, so one that started after the reader
// is skipped like an older process; it is told by PF_KTHREAD in the flags
// field of /proc/<pid>/stat, after the comm in parentheses, which may hold
// spaces and parentheses itself.
func TestKernelThreadStat(t *testing.T) {
	for _, tc := range []struct {
		name string
		stat string
		want bool
	}{
		{"kthreadd", "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 2 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0", true},
		{"kworker", "1234 (kworker/u8:3) I 2 0 0 0 -1 69238880 0 0 0 0 0 0 0 0 20 0 1 0 5000 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0", true},
		{"sleep", "4321 (sleep) S 4300 4321 4300 0 -1 1077936128 0 0 0 0 0 0 0 0 20 0 1 0 6000 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0", false},
		{"a comm with the fields in it", "4322 (x) S 0 0 0 0 -1 2129984 1) S 0 0 0 0 -1 1077936128 0 0 0 0 0 0 0 0 20 0 1 0 6000 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0", false},
	} {
		got, err := kernelThreadStat([]byte(tc.stat + "\n"))
		if err != nil || got != tc.want {
			t.Errorf("%s: kernelThreadStat = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := kernelThreadStat([]byte("garbage\n")); err == nil {
		t.Error("kernelThreadStat of garbage: no error")
	}
	if got, err := kernelThreadStat(readSelfStat(t)); err != nil || got {
		t.Errorf("kernelThreadStat of this process = %v, %v; want false", got, err)
	}
}

func readSelfStat(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
