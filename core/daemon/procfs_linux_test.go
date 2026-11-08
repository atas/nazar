package daemon

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// procPlatform is the fake platform with real processes: the
// seams nazar run uses (PeerOf, Process, CodeHash, OnProcessExit and
// platform.Exec) read Linux's /proc, so the daemon judges the real CLI,
// npx and node. Everything else (vault, enclave, dialogs) stays the fake.
// TEST ONLY: polling stands in for kqueue's NOTE_EXEC (the Mac's exec watch);
// it sees an exec as a change of the image (image: the file and the stack
// the exec laid out).
type procPlatform struct {
	*fake.Fake

	mu     sync.Mutex
	hashes map[[5]int64][]byte // by dev, ino, size, mtime, ctime
	peers  []int               // every pid PeerOf named on a run socket, in order
}

func newProcPlatform(f *fake.Fake) *procPlatform {
	return &procPlatform{Fake: f, hashes: map[[5]int64][]byte{}}
}

// procStat reads the fields of /proc/<pid>/stat a ref needs: the parent, the
// start time in clock ticks (the generation: a recycled pid has another)
// and the state.
func procStat(pid int) (ppid int, start uint64, state byte, err error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, 0, platform.ErrNoProcess
	}
	i := bytes.LastIndexByte(b, ')')
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, 0, 0, platform.ErrNoProcess
	}
	ppid, _ = strconv.Atoi(f[1])
	start, _ = strconv.ParseUint(f[19], 10, 64)
	return ppid, start, f[0][0], nil
}

// live reports whether ref names a running process. A zombie may be a
// leader mid-exec, not gone: when a thread other than the main one calls
// execve, the leader shows as Z until the kernel has moved that thread
// into its place, milliseconds under load. A real zombie stays Z until it
// is reaped, so only one that is still Z (or gone) after zombieGrace is.
func live(ref platform.ProcessRef) bool {
	deadline := time.Now().Add(zombieGrace)
	for {
		_, start, state, err := procStat(ref.PID)
		if err != nil || (ref.Generation != 0 && start != ref.Generation) {
			return false
		}
		if state != 'Z' {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
}

// zombieGrace is how long live waits for a zombie leader to finish an exec.
const zombieGrace = 200 * time.Millisecond

func (p *procPlatform) PeerOf(fd int) (platform.ProcessRef, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return platform.ProcessRef{}, err
	}
	_, start, _, err := procStat(int(cred.Pid))
	if err != nil {
		return platform.ProcessRef{}, err
	}
	if sa, err := unix.Getsockname(fd); err == nil {
		if u, ok := sa.(*unix.SockaddrUnix); ok && strings.Contains(u.Name, "/.nazar/run/") && len(filepath.Base(u.Name)) == 37 { // <32 hex>.sock, not the agent's own
			p.mu.Lock()
			p.peers = append(p.peers, int(cred.Pid))
			p.mu.Unlock()
		}
	}
	return platform.ProcessRef{PID: int(cred.Pid), Generation: start}, nil
}

// peerPIDs is every pid that connected to a run socket so far.
func (p *procPlatform) peerPIDs() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.peers...)
}

func (p *procPlatform) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	if ref.PID <= 0 {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	if !live(ref) {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	ppid, start, _, err := procStat(ref.PID)
	if err != nil {
		return platform.ProcessInfo{}, platform.ErrNoProcess
	}
	dir := "/proc/" + strconv.Itoa(ref.PID) + "/"
	// StartTime: clock ticks since boot at 100 Hz (10 ms): enough for
	// caller.Resolver's "a parent started no later than its child".
	info := platform.ProcessInfo{Ref: platform.ProcessRef{PID: ref.PID, Generation: start}, StartTime: time.Unix(0, int64(start)*int64(10*time.Millisecond))}
	info.Path, _ = os.Readlink(dir + "exe")
	info.Code.CDHash, _ = p.CodeHash(dir + "exe") // the running image itself
	info.Cwd, _ = os.Readlink(dir + "cwd")
	if b, err := os.ReadFile(dir + "cmdline"); err == nil {
		info.Args = splitNUL(b)
	}
	if b, err := os.ReadFile(dir + "comm"); err == nil {
		info.Comm = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(dir + "status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) > 1 && f[0] == "Uid:" {
				info.UID, _ = strconv.Atoi(f[1])
			}
		}
	}
	if ppid > 0 {
		if _, pstart, _, err := procStat(ppid); err == nil {
			info.Parent = platform.ProcessRef{PID: ppid, Generation: pstart}
		}
	}
	return info, nil
}

func splitNUL(b []byte) []string {
	b = bytes.TrimSuffix(b, []byte{0})
	if len(b) == 0 {
		return []string{}
	}
	return strings.Split(string(b), "\x00")
}

// CodeHash is the SHA-256 of the file (its first 20 bytes, a cdhash's
// size), cached by identity: node is over 100 MB.
func (p *procPlatform) CodeHash(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	key := [5]int64{int64(st.Dev), int64(st.Ino), st.Size, st.Mtim.Nano(), st.Ctim.Nano()}
	p.mu.Lock()
	h, ok := p.hashes[key]
	p.mu.Unlock()
	if ok {
		return h, nil
	}
	s := sha256.New()
	if _, err := io.Copy(s, f); err != nil {
		return nil, err
	}
	h = s.Sum(nil)[:20]
	p.mu.Lock()
	p.hashes[key] = h
	p.mu.Unlock()
	return h, nil
}

// pollEvery is how often the exit and exec watches look.
const pollEvery = 500 * time.Microsecond

func (p *procPlatform) OnProcessExit(ref platform.ProcessRef, fn func()) {
	go func() {
		for live(ref) {
			time.Sleep(pollEvery)
		}
		fn()
	}()
}

// image identifies the image a process runs now: the file
// /proc/<pid>/exe names, and the start of its stack (/proc/<pid>/stat
// field 28), which every exec lays out anew, so an exec of the same file
// again is seen too.
func image(pid int) ([3]uint64, bool) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(pid)+"/exe", &st); err != nil {
		return [3]uint64{}, false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return [3]uint64{}, false
	}
	f := strings.Fields(string(b[bytes.LastIndexByte(b, ')')+1:]))
	if len(f) < 26 {
		return [3]uint64{}, false
	}
	stack, _ := strconv.ParseUint(f[25], 10, 64)
	return [3]uint64{st.Dev, st.Ino, stack}, true
}

// OnProcessExec polls the image of ref (image) and calls fn with the process read
// right after it changed (argv included: npm rewrites its own about 40 ms
// later, spike S12).
func (p *procPlatform) OnProcessExec(ref platform.ProcessRef, fn func(platform.ProcessInfo)) (func(), error) {
	if !live(ref) {
		return nil, platform.ErrNoProcess
	}
	last, _ := image(ref.PID)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if !live(ref) {
				return
			}
			now, ok := image(ref.PID)
			if ok && now != last {
				last = now
				info, err := p.Process(ref)
				// exe switches before the kernel sets up the new argv:
				// read again until it is there (an exec has an argv).
				for tries := 0; err == nil && len(info.Args) == 0 && tries < 1000; tries++ {
					time.Sleep(20 * time.Microsecond)
					info, err = p.Process(ref)
				}
				if err != nil {
					return
				}
				// The exec is done once argv is there: take the image as
				// it settled (the stack moves during the exec).
				if settled, ok := image(ref.PID); ok {
					last = settled
				}
				fn(info)
			}
			time.Sleep(pollEvery)
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stop); <-done }) }, nil
}

func (p *procPlatform) Environment(ref platform.ProcessRef) ([]string, error) {
	if !live(ref) {
		return nil, platform.ErrNoProcess
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(ref.PID) + "/environ")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, platform.ErrUnreadable
		}
		return nil, platform.ErrNoProcess
	}
	return splitNUL(b), nil
}

var _ platform.Exec = (*procPlatform)(nil)

// The seam sees every exec, an exec of the same file again included
// (polling: execs further apart than a poll).
func TestProcPlatformSeesEveryExec(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip(err)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip(err)
	}
	sleep, _ = filepath.EvalSymlinks(sleep)
	cmd := exec.Command("/bin/sh", "-c", "read x; exec /bin/sh -c 'read x; exec "+sleep+" 5'")
	in, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	p := newProcPlatform(fake.New(time.Now()))
	_, start, _, err := procStat(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	cancel, err := p.OnProcessExec(platform.ProcessRef{PID: cmd.Process.Pid, Generation: start}, func(info platform.ProcessInfo) {
		mu.Lock()
		seen = append(seen, info.Path)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	time.Sleep(50 * time.Millisecond)
	in.Write([]byte("\n")) // sh execs sh: the same file again
	time.Sleep(100 * time.Millisecond)
	in.Write([]byte("\n")) // sh execs sleep
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		got := slices.Clone(seen)
		mu.Unlock()
		if len(got) == 2 {
			if got[0] != sh || got[1] != sleep {
				t.Fatalf("execs %q, want %q then %q", got, sh, sleep)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("execs seen: %q, want two", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
