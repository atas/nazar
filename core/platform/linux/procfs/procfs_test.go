//go:build linux

package procfs

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"golang.org/x/sys/unix"
)

// The test binary doubles as the child processes the tests need. The mode
// is chosen by NAZAR_PROCFS_CHILD; a child prints what the test must know
// on stdout and then blocks on stdin until the test kills it.
const childEnv = "NAZAR_PROCFS_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "hold":
		// Connect to the test's socket when it names one, then wait.
		if path := os.Getenv("NAZAR_PROCFS_SOCK"); path != "" {
			c, err := net.Dial("unix", path)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer c.Close()
		}
		fmt.Println("ok")
		io.Copy(io.Discard, os.Stdin)
	case "manager":
		// Stand in for `systemd --user`: parent a sleep and report its pid.
		sleep := exec.Command(sleepPath(), "600")
		if err := sleep.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(sleep.Process.Pid)
		io.Copy(io.Discard, os.Stdin)
		sleep.Process.Kill()
	case "exec":
		// Become the program NAZAR_PROCFS_EXEC names (run as `<it> 600`)
		// once the test writes a byte to stdin.
		fmt.Println("ok")
		io.ReadFull(os.Stdin, make([]byte, 1))
		prog := os.Getenv("NAZAR_PROCFS_EXEC")
		err := unix.Exec(prog, []string{prog, "600"}, os.Environ())
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "unknown child mode")
		os.Exit(2)
	}
}

func sleepPath() string {
	p, err := exec.LookPath("sleep")
	if err != nil {
		return "/bin/sleep"
	}
	return p
}

// startChild re-executes the test binary (or the copy at exe) in mode with
// extra environment, and returns the command, its first stdout line and
// the pipe that ends it. Cleanup kills it and reaps it.
func startChild(t *testing.T, exe, mode string, args []string, env ...string) (*exec.Cmd, string) {
	t.Helper()
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), append([]string{childEnv + "=" + mode}, env...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("child %s: no first line: %v", mode, err)
	}
	return cmd, strings.TrimSpace(line)
}

// startSleep starts a sleep from exe (a copy of the system's sleep, or
// the system's when exe is empty) and returns it, reaped at cleanup.
func startSleep(t *testing.T, exe string) *exec.Cmd {
	t.Helper()
	if exe == "" {
		exe = sleepPath()
	}
	cmd := exec.Command(exe, "600")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	// Under a binfmt_misc emulator (Rosetta in an amd64 container on a
	// Mac) the child first runs the emulator's stub, which then re-execs
	// the program: the same pid and start, another exe link for a moment.
	// On a real Linux the first look is the program.
	want, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if got := readLink(procPath(cmd.Process.Pid, "exe")); got == want {
			return cmd
		} else if time.Now().After(deadline) {
			t.Fatalf("child %d runs %q, want %q", cmd.Process.Pid, got, want)
		}
	}
}

func fullRef(t *testing.T, pid int) platform.ProcessRef {
	t.Helper()
	st, err := ReadStat(pid)
	if err != nil {
		t.Fatalf("ReadStat(%d): %v", pid, err)
	}
	return platform.ProcessRef{PID: pid, Generation: Generation(st.StartTicks)}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func TestProcessSelf(t *testing.T) {
	p := New()
	self := fullRef(t, os.Getpid())
	info, err := p.Process(self)
	if err != nil {
		t.Fatalf("Process(self %v): %v", self, err)
	}
	if info.Ref != self {
		t.Errorf("Ref = %v, want %v", info.Ref, self)
	}
	if info.Ref.Generation == 0 || info.Ref.Generation != Generation(mustStat(t, os.Getpid()).StartTicks) {
		t.Errorf("Generation = %d, want the start ticks plus one", info.Ref.Generation)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	if info.Path != exe {
		t.Errorf("Path = %q, want %q", info.Path, exe)
	}
	if len(info.Args) == 0 || info.Args[0] != os.Args[0] || len(info.Args) != len(os.Args) {
		t.Errorf("Args = %q, want %q", info.Args, os.Args)
	}
	wd, _ := os.Getwd()
	if wd, err = filepath.EvalSymlinks(wd); err != nil {
		t.Fatal(err)
	}
	if info.Cwd != wd {
		t.Errorf("Cwd = %q, want %q", info.Cwd, wd)
	}
	if info.UID != os.Geteuid() {
		t.Errorf("UID = %d, want %d", info.UID, os.Geteuid())
	}
	if info.Comm == "" || len(info.Comm) > 15 || info.Comm != filepath.Base(exe)[:len(info.Comm)] {
		t.Errorf("Comm = %q, want the first 15 bytes of %q", info.Comm, filepath.Base(exe))
	}
	if info.Code.Signed || info.Code.AdHoc || info.Code.Apple || info.Code.TeamID != "" || info.Code.SigningID != "" {
		t.Errorf("Code = %+v, want unsigned", info.Code)
	}
	want, err := p.CodeHash(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Code.CDHash) != sha256.Size || !bytes.Equal(info.Code.CDHash, want) {
		t.Errorf("CDHash = %x, want CodeHash(Path) %x", info.Code.CDHash, want)
	}
	if info.StartTime.IsZero() || info.StartTime.After(time.Now()) || time.Since(info.StartTime) > 24*time.Hour {
		t.Errorf("StartTime = %v, want recent", info.StartTime)
	}
	if info.Parent != (platform.ProcessRef{PID: os.Getppid()}) {
		t.Errorf("Parent = %v, want the PID-only ref of %d", info.Parent, os.Getppid())
	}
	again, err := p.Process(self)
	if err != nil || again.Ref != self || !again.StartTime.Equal(info.StartTime) {
		t.Errorf("Process(self) again = %v %v, %v; want the same record", again.Ref, again.StartTime, err)
	}
}

func mustStat(t *testing.T, pid int) Stat {
	t.Helper()
	st, err := ReadStat(pid)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestTamperedGeneration(t *testing.T) {
	p := New()
	self := fullRef(t, os.Getpid())
	for name, bad := range map[string]platform.ProcessRef{
		"generation+1": {PID: self.PID, Generation: self.Generation + 1},
		"generation-1": {PID: self.PID, Generation: self.Generation - 1},
		"generation^1": {PID: self.PID, Generation: self.Generation ^ 1},
	} {
		if bad.Generation == 0 {
			continue
		}
		if info, err := p.Process(bad); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Process(%s %v) = %v, %v; want ErrNoProcess", name, bad, info.Ref, err)
		}
		if _, err := p.ExeHash(bad); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("ExeHash(%s %v) = %v; want ErrNoProcess", name, bad, err)
		}
	}
}

func TestPIDOnlyAnswersOccupant(t *testing.T) {
	p := New()
	self := fullRef(t, os.Getpid())
	info, err := p.Process(platform.ProcessRef{PID: os.Getpid()})
	if err != nil || info.Ref != self {
		t.Fatalf("Process(PID-only %d) = %v, %v; want %v", os.Getpid(), info.Ref, err, self)
	}
	child := startSleep(t, "")
	ref := fullRef(t, child.Process.Pid)
	info, err = p.Process(platform.ProcessRef{PID: ref.PID})
	if err != nil || info.Ref != ref {
		t.Fatalf("Process(PID-only child %d) = %v, %v; want %v", ref.PID, info.Ref, err, ref)
	}
	if info.Parent != (platform.ProcessRef{PID: os.Getpid()}) {
		t.Errorf("child's Parent = %v, want PID-only %d", info.Parent, os.Getpid())
	}
}

// TestExeHashRefusesPIDOnly: ExeHash is an identity check, so a PID-only
// ref, which names whoever holds the PID now, is ErrNoProcess; the full
// ref of the same process is hashed.
func TestExeHashRefusesPIDOnly(t *testing.T) {
	p := New()
	for _, pid := range []int{os.Getpid(), startSleep(t, "").Process.Pid} {
		if h, err := p.ExeHash(platform.ProcessRef{PID: pid}); !errors.Is(err, platform.ErrNoProcess) || h != nil {
			t.Errorf("ExeHash(PID-only %d) = %x, %v; want ErrNoProcess", pid, h, err)
		}
		if h, err := p.ExeHash(fullRef(t, pid)); err != nil || len(h) != sha256.Size {
			t.Errorf("ExeHash(full ref of %d) = %x, %v; want a hash", pid, h, err)
		}
	}
}

func TestZombieIsNoProcess(t *testing.T) {
	p := New()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ref := fullRef(t, cmd.Process.Pid)
	defer cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st, err := ReadStat(ref.PID)
		if err != nil {
			t.Fatalf("ReadStat(child): %v", err)
		}
		if st.State == 'Z' || st.State == 'X' {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child %d still %c after 5s", ref.PID, st.State)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if info, err := p.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Process(zombie %v) = %v, %v; want ErrNoProcess", ref, info.Ref, err)
	}
	if info, err := p.Process(platform.ProcessRef{PID: ref.PID}); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("Process(PID-only zombie %d) = %v, %v; want ErrNoProcess", ref.PID, info.Ref, err)
	}
	if _, err := p.ExeHash(ref); !errors.Is(err, platform.ErrNoProcess) {
		t.Errorf("ExeHash(zombie %v) = %v; want ErrNoProcess", ref, err)
	}
}

func TestBadRefs(t *testing.T) {
	p := New()
	for name, ref := range map[string]platform.ProcessRef{
		"zero":                {},
		"negative":            {PID: -1},
		"negative with gen":   {PID: -1, Generation: 1},
		"absent":              {PID: math.MaxInt32},
		"absent with gen":     {PID: math.MaxInt32, Generation: 1},
		"pid 0 with gen":      {PID: 0, Generation: 1},
		"very negative":       {PID: math.MinInt32},
		"max pid max gen":     {PID: math.MaxInt32, Generation: math.MaxUint64},
		"absent pid-only odd": {PID: math.MaxInt32 - 1},
	} {
		if info, err := p.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Process(%s %v) = %v, %v; want ErrNoProcess", name, ref, info.Ref, err)
		}
		if _, err := p.ExeHash(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("ExeHash(%s %v) = %v; want ErrNoProcess", name, ref, err)
		}
		if _, err := ReadStat(ref.PID); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("ReadStat(%s %d) = %v; want ErrNoProcess", name, ref.PID, err)
		}
	}
	if ref, ok := p.ResponsibleFor(fullRef(t, os.Getpid())); ok || !ref.IsZero() {
		t.Errorf("ResponsibleFor(self) = %v, %v; want zero, false", ref, ok)
	}
}

func TestDeletedExecutable(t *testing.T) {
	p := New()
	exe := filepath.Join(t.TempDir(), "sleep")
	copyFile(t, sleepPath(), exe)
	cmd := startSleep(t, exe)
	ref := fullRef(t, cmd.Process.Pid)
	if info, err := p.Process(ref); err != nil || info.Path != exe {
		t.Fatalf("Process(copy) = %q, %v; want Path %q", info.Path, err, exe)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	info, err := p.Process(ref)
	if err != nil {
		t.Fatalf("Process(deleted): %v", err)
	}
	if info.Path != "" {
		t.Errorf("Path = %q, want \"\" once the file is deleted", info.Path)
	}
	if info.Comm != "sleep" {
		t.Errorf("Comm = %q, want \"sleep\"", info.Comm)
	}
	if info.Ref != ref {
		t.Errorf("Ref = %v, want %v", info.Ref, ref)
	}
	if len(info.Code.CDHash) != sha256.Size {
		t.Errorf("CDHash = %x, want the running image's hash", info.Code.CDHash)
	}
}

func TestUserManagerIsTheTop(t *testing.T) {
	dir := t.TempDir()
	manager := filepath.Join(dir, "systemd")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, self, manager)
	cmd, line := startChild(t, manager, "manager", []string{"--user"})
	sleepPID, err := strconv.Atoi(line)
	if err != nil {
		t.Fatalf("manager printed %q", line)
	}
	t.Cleanup(func() { unix.Kill(sleepPID, unix.SIGKILL) })
	ref := fullRef(t, sleepPID)

	p := New()
	p.managerExes = []string{manager}
	info, err := p.Process(ref)
	if err != nil {
		t.Fatal(err)
	}
	if info.Parent != (platform.ProcessRef{PID: 1}) {
		t.Errorf("Parent under the user's manager = %v, want {PID: 1}", info.Parent)
	}

	// Without the seam the copy is just another program, so the real
	// parent is named; and `--user` is part of what makes a manager.
	plain := New()
	if info, err := plain.Process(ref); err != nil || info.Parent != (platform.ProcessRef{PID: cmd.Process.Pid}) {
		t.Errorf("Parent with the default manager paths = %v, %v; want PID-only %d", info.Parent, err, cmd.Process.Pid)
	}
	system, line := startChild(t, manager, "manager", []string{"--system"})
	sysSleep, err := strconv.Atoi(line)
	if err != nil {
		t.Fatalf("manager printed %q", line)
	}
	t.Cleanup(func() { unix.Kill(sysSleep, unix.SIGKILL) })
	if info, err := p.Process(fullRef(t, sysSleep)); err != nil || info.Parent != (platform.ProcessRef{PID: system.Process.Pid}) {
		t.Errorf("Parent under `systemd --system` = %v, %v; want PID-only %d", info.Parent, err, system.Process.Pid)
	}
}

// TestUserManagerIsTheFileNotTheName: the manager is matched by the file
// it runs, not by the name /proc/<pid>/exe reads. Both directions, with
// no mount namespace (TestBindMountedManagerIsNotTheTop needs one, which
// a container's seccomp profile may forbid): a manager path that is a
// hard link to the running file matches under another name; and a
// process whose name is the manager's but whose image, as the kernel
// resolves it in the process's own mount namespace, is another file does
// not. The kernel's answer for the image is a seam, set to what it gives
// for a program bind-mounted over the manager's name.
func TestUserManagerIsTheFileNotTheName(t *testing.T) {
	dir := t.TempDir()
	manager := filepath.Join(dir, "systemd")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, self, manager)
	cmd, line := startChild(t, manager, "manager", []string{"--user"})
	sleepPID, err := strconv.Atoi(line)
	if err != nil {
		t.Fatalf("manager printed %q", line)
	}
	t.Cleanup(func() { unix.Kill(sleepPID, unix.SIGKILL) })
	ref := fullRef(t, sleepPID)
	if got := readLink(procPath(cmd.Process.Pid, "exe")); got != manager {
		t.Fatalf("the manager's exe reads %q, want %q", got, manager)
	}

	// Another name for the same file: the manager, though its exe reads
	// the other name.
	link := filepath.Join(dir, "link")
	if err := os.Link(manager, link); err != nil {
		t.Fatal(err)
	}
	p := New()
	p.managerExes = []string{link}
	if info, err := p.Process(ref); err != nil || info.Parent != (platform.ProcessRef{PID: 1}) {
		t.Errorf("Parent with the manager named by a hard link = %v, %v; want {PID: 1}: the same file", info.Parent, err)
	}

	// The manager's name, another file: not the manager.
	other := filepath.Join(dir, "other")
	copyFile(t, self, other)
	var st unix.Stat_t
	if err := unix.Stat(other, &st); err != nil {
		t.Fatal(err)
	}
	p = New()
	p.managerExes = []string{manager}
	p.imageOf = func(pid int) (fileID, bool) {
		if pid == cmd.Process.Pid {
			return fileID{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
		}
		return imageID(pid)
	}
	if info, err := p.Process(ref); err != nil || info.Parent != (platform.ProcessRef{PID: cmd.Process.Pid}) {
		t.Errorf("Parent under a program whose name is the manager's but whose file is not = %v, %v; want PID-only %d", info.Parent, err, cmd.Process.Pid)
	}
	// The seam answering as the kernel does, the match holds.
	p.imageOf = imageID
	if info, err := p.Process(ref); err != nil || info.Parent != (platform.ProcessRef{PID: 1}) {
		t.Errorf("Parent under the manager = %v, %v; want {PID: 1}", info.Parent, err)
	}
}

// peerModes runs fn with the kernel's peer pidfd and with SO_PEERCRED
// alone (before Linux 6.5).
func peerModes(t *testing.T, fn func(t *testing.T, p *Procs)) {
	t.Run("pidfd", func(t *testing.T) { fn(t, New()) })
	t.Run("peercred", func(t *testing.T) {
		p := New()
		p.noPeerPidfd = true
		fn(t, p)
	})
}

func TestPeerOf(t *testing.T) { peerModes(t, testPeerOf) }

func testPeerOf(t *testing.T, p *Procs) {
	// A socketpair's ends both carry the creator's credentials (the kernel
	// records them at socketpair time), so the peer of each end is this
	// process.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	self := fullRef(t, os.Getpid())
	if ref, err := p.PeerOf(fds[0]); err != nil || ref != self {
		t.Errorf("PeerOf(socketpair end) = %v, %v; want %v", ref, err, self)
	}

	// A child that connects to a listening socket is the peer of the
	// accepted connection.
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd, _ := startChild(t, "", "hold", nil, "NAZAR_PROCFS_SOCK="+sock)
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ref platform.ProcessRef
	var perr error
	if err := raw.Control(func(fd uintptr) { ref, perr = p.PeerOf(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if perr != nil {
		t.Fatalf("PeerOf(accepted): %v", perr)
	}
	want := fullRef(t, cmd.Process.Pid)
	if ref != want {
		t.Errorf("PeerOf(accepted) = %v, want the child's %v", ref, want)
	}
	if info, err := p.Process(ref); err != nil || info.Ref != ref {
		t.Errorf("Process(peer %v) = %v, %v", ref, info.Ref, err)
	}

	if _, err := p.PeerOf(-1); err == nil {
		t.Error("PeerOf(-1) succeeded")
	}
	f, err := os.Open("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := p.PeerOf(int(f.Fd())); err == nil {
		t.Error("PeerOf(a file) succeeded")
	}
}

func TestPeerOfExitedPeer(t *testing.T) { peerModes(t, testPeerOfExitedPeer) }

func testPeerOfExitedPeer(t *testing.T, p *Procs) {
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd, _ := startChild(t, "", "hold", nil, "NAZAR_PROCFS_SOCK="+sock)
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cmd.Process.Kill()
	cmd.Wait()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var perr error
	var ref platform.ProcessRef
	if err := raw.Control(func(fd uintptr) { ref, perr = p.PeerOf(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(perr, platform.ErrNoProcess) {
		t.Errorf("PeerOf(exited peer) = %v, %v; want ErrNoProcess", ref, perr)
	}
}

// exitModes runs fn with pidfds and with the polling fallback.
func exitModes(t *testing.T, fn func(t *testing.T, p *Procs)) {
	t.Run("pidfd", func(t *testing.T) { fn(t, New()) })
	t.Run("poll", func(t *testing.T) {
		p := New()
		p.noPidfd = true
		fn(t, p)
	})
}

func waitFired(t *testing.T, fired chan struct{}, what string) {
	t.Helper()
	select {
	case <-fired:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not run within 5s", what)
	}
}

func TestExitOnce(t *testing.T) {
	exitModes(t, func(t *testing.T, p *Procs) {
		cmd := startSleep(t, "")
		ref := fullRef(t, cmd.Process.Pid)
		fired := make(chan struct{}, 16)
		p.OnProcessExit(ref, func() { fired <- struct{}{} })
		select {
		case <-fired:
			t.Fatalf("exit callback for live %v ran before it exited", ref)
		case <-time.After(300 * time.Millisecond):
		}
		cmd.Process.Kill()
		waitFired(t, fired, "exit callback after kill")
		select {
		case <-fired:
			t.Fatal("exit callback ran twice")
		case <-time.After(300 * time.Millisecond):
		}
		cmd.Wait()
	})
}

func TestExitGonePromptly(t *testing.T) {
	exitModes(t, func(t *testing.T, p *Procs) {
		cmd := startSleep(t, "")
		ref := fullRef(t, cmd.Process.Pid)
		cmd.Process.Kill()
		cmd.Wait()
		fired := make(chan struct{}, 16)
		p.OnProcessExit(ref, func() { fired <- struct{}{} })
		waitFired(t, fired, "exit callback registered on an exited process")
		select {
		case <-fired:
			t.Fatal("exit callback ran twice")
		case <-time.After(300 * time.Millisecond):
		}
	})
}

func TestExitNeverExisted(t *testing.T) {
	exitModes(t, func(t *testing.T, p *Procs) {
		live := fullRef(t, os.Getpid())
		for _, ref := range []platform.ProcessRef{
			{PID: math.MaxInt32, Generation: 1},
			{PID: live.PID, Generation: live.Generation + 1},
			{},
			{PID: live.PID}, // PID-only: names no instance
		} {
			fired := make(chan struct{}, 16)
			p.OnProcessExit(ref, func() { fired <- struct{}{} })
			waitFired(t, fired, fmt.Sprintf("exit callback for %v", ref))
		}
	})
}

func TestExeHashIsTheRunningImage(t *testing.T) {
	p := New()
	dir := t.TempDir()
	exe := filepath.Join(dir, "sleep")
	copyFile(t, sleepPath(), exe)
	old, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	cmd := startSleep(t, exe)
	ref := fullRef(t, cmd.Process.Pid)
	h, err := p.ExeHash(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h, sum(old)) {
		t.Errorf("ExeHash = %x, want %x", h, sum(old))
	}
	// A package upgrade: the file is replaced (the running image can't be
	// written in place: ETXTBSY).
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	fresh := append(append([]byte{}, old...), []byte("\nnew build\n")...)
	if err := os.WriteFile(exe, fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	if h, err := p.ExeHash(ref); err != nil || !bytes.Equal(h, sum(old)) {
		t.Errorf("ExeHash after the replace = %x, %v; want the running image's %x", h, err, sum(old))
	}
	if h, err := p.CodeHash(exe); err != nil || !bytes.Equal(h, sum(fresh)) {
		t.Errorf("CodeHash after the replace = %x, %v; want the new file's %x", h, err, sum(fresh))
	}
	if info, err := p.Process(ref); err != nil || !bytes.Equal(info.Code.CDHash, sum(old)) || info.Path != "" {
		t.Errorf("Process after the replace: Path %q CDHash %x, %v; want \"\" and %x", info.Path, info.Code.CDHash, err, sum(old))
	}
}

// TestHashCacheSeesRewrite: a cached file rewritten in place (same inode,
// same size, new content) is hashed anew, because the key holds the times
// and a write(2) to a settled file lands in a later timestamp. The file is
// this user's own, which is never cached, so the cache's owner is set to
// this user, the agent's uid moved off it and the clock past settle, as
// TestHashCacheHolds does, and the test checks that the first hash was in
// fact cached: with a key of the inode alone the stale hash would be
// served.
func TestHashCacheSeesRewrite(t *testing.T) {
	p := New()
	p.cacheOwner = os.Geteuid()
	p.uid++
	p.now = func() time.Time { return time.Now().Add(settle) }
	path := filepath.Join(t.TempDir(), "f")
	a := bytes.Repeat([]byte("a"), 4096)
	b := bytes.Repeat([]byte("b"), 4096)
	if err := os.WriteFile(path, a, 0o644); err != nil {
		t.Fatal(err)
	}
	var was unix.Stat_t
	if err := unix.Stat(path, &was); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, sum(a)) {
			t.Fatalf("CodeHash(a) = %x, %v; want %x", h, err, sum(a))
		}
	}
	if n := len(p.cache); n != 1 {
		t.Fatalf("the file was not cached (%d entries): the test needs a cached hash to see past", n)
	}
	// The rewrite keeps the inode and the size. A write to a file settled
	// for real lands in a later timestamp (settle outlasts the coarsest
	// one); here the clock is moved instead of waited for, so the write is
	// repeated until the file system's clock has moved on.
	var is unix.Stat_t
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := unix.Stat(path, &is); err != nil {
			t.Fatal(err)
		}
		if is.Ctim != was.Ctim || is.Mtim != was.Mtim {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rewrite kept the file's timestamps for 5s")
		}
	}
	if is.Ino != was.Ino || is.Size != was.Size {
		t.Fatalf("the rewrite changed the inode (%d to %d) or the size (%d to %d); the test needs an in-place rewrite", was.Ino, is.Ino, was.Size, is.Size)
	}
	if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, sum(b)) {
		t.Errorf("CodeHash(b) = %x, %v; want %x (same inode and size, new content, new times)", h, err, sum(b))
	}
	// The hash is the caller's to keep: changing it changes no later answer.
	h, _ := p.CodeHash(path)
	h[0] ^= 0xff
	if h2, err := p.CodeHash(path); err != nil || !bytes.Equal(h2, sum(b)) {
		t.Errorf("CodeHash(b) after the caller wrote to its copy = %x, %v; want %x", h2, err, sum(b))
	}
}

func TestCodeHashMissing(t *testing.T) {
	p := New()
	dir := t.TempDir()
	for _, path := range []string{filepath.Join(dir, "missing"), filepath.Join(dir, "missing", "deeper"), ""} {
		if h, err := p.CodeHash(path); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("CodeHash(%q) = %x, %v; want ErrNotFound", path, h, err)
		}
	}
	if h, err := p.CodeHash(dir); err == nil || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("CodeHash(a directory) = %x, %v; want another error", h, err)
	}
}

func TestReadStat(t *testing.T) {
	st, err := ReadStat(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if st.PPID != os.Getppid() || st.EUID != os.Geteuid() || st.StartTicks == 0 || st.State == 0 {
		t.Errorf("ReadStat(self) = %+v", st)
	}
	if Generation(st.StartTicks) != st.StartTicks+1 || Generation(0) != 1 {
		t.Error("Generation is not start ticks plus one")
	}
	// A comm with spaces and parentheses does not shift the fields.
	data := []byte("42 (a (b) c) R 7 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 123456 1000 10 18446744073709551615\n")
	if got, err := parseStat(data); err != nil || got.PPID != 7 || got.State != 'R' || got.StartTicks != 123456 {
		t.Errorf("parseStat(odd comm) = %+v, %v", got, err)
	}
	if _, err := parseStat([]byte("42 (x) R 7\n")); err == nil {
		t.Error("parseStat(short line) succeeded")
	}
}

// hashWithin runs CodeHash(path) and fails the test when it has not
// returned within two seconds: a FIFO waits for a writer and a device
// never ends, and neither may hold the caller.
func hashWithin(t *testing.T, p *Procs, path string) ([]byte, error) {
	t.Helper()
	type result struct {
		h   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		h, err := p.CodeHash(path)
		done <- result{h, err}
	}()
	select {
	case r := <-done:
		return r.h, r.err
	case <-time.After(2 * time.Second):
		t.Fatalf("CodeHash(%q) did not return within 2s", path)
		return nil, nil
	}
}

func TestCodeHashRefusesSpecialFiles(t *testing.T) {
	p := New()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, path := range []string{fifo, "/dev/zero", "/dev/null", sock} {
		h, err := hashWithin(t, p, path)
		if err == nil || errors.Is(err, platform.ErrNotFound) || h != nil {
			t.Errorf("CodeHash(%q) = %x, %v; want an error other than ErrNotFound", path, h, err)
		}
	}
	// A link to such a file is refused the same way.
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	if h, err := hashWithin(t, p, link); err == nil || errors.Is(err, platform.ErrNotFound) || h != nil {
		t.Errorf("CodeHash(link to /dev/zero) = %x, %v; want an error other than ErrNotFound", h, err)
	}
}

func TestCodeHashRefusesRelativePath(t *testing.T) {
	p := New()
	// procfs.go is in the test's working directory, so a relative lookup
	// would find a file; the path is refused before any lookup.
	if _, err := os.Stat("procfs.go"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"procfs.go", "./procfs.go", ".", "../procfs/procfs.go", "dev/zero"} {
		h, err := p.CodeHash(path)
		if err == nil || errors.Is(err, platform.ErrNotFound) || h != nil {
			t.Errorf("CodeHash(%q) = %x, %v; want an error other than ErrNotFound", path, h, err)
		}
	}
	if h, err := p.CodeHash("/dev/\x00null"); err == nil || h != nil {
		t.Errorf("CodeHash(path with NUL) = %x, %v; want an error", h, err)
	}
}

func TestThreadIsNoProcess(t *testing.T) {
	p := New()
	pid := os.Getpid()
	// A goroutine pinned to a thread other than the main one: /proc/<tid>/
	// answers for it, with the process's exe, parent and uid, but it is
	// not a process.
	done := make(chan struct{})
	var started func(depth int)
	started = func(depth int) {
		runtime.LockOSThread()
		tid := unix.Gettid()
		if tid == pid {
			if depth > 8 {
				t.Error("every goroutine landed on the main thread")
				close(done)
				return
			}
			// Keep this thread busy so the next goroutine gets another.
			inner := make(chan struct{})
			go func() { defer close(inner); started(depth + 1) }()
			<-inner
			return
		}
		defer close(done)
		if _, err := ReadStat(tid); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("ReadStat(thread %d) = %v; want ErrNoProcess", tid, err)
		}
		if info, err := p.Process(platform.ProcessRef{PID: tid}); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Process(PID-only thread %d) = %v, %v; want ErrNoProcess", tid, info.Ref, err)
		}
		data, err := os.ReadFile(procPath(tid, "stat"))
		if err != nil {
			t.Error(err)
			return
		}
		st, err := parseStat(data)
		if err != nil {
			t.Error(err)
			return
		}
		full := platform.ProcessRef{PID: tid, Generation: Generation(st.StartTicks)}
		if info, err := p.Process(full); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Process(thread %v) = %v, %v; want ErrNoProcess", full, info.Ref, err)
		}
		if _, err := p.ExeHash(full); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("ExeHash(thread %v) = %v; want ErrNoProcess", full, err)
		}
	}
	go started(0)
	<-done
	status := []byte("Name:\tx\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t42\nNgid:\t0\nPid:\t43\nUid:\t1000\t1001\t1000\t1000\n")
	if tgid, err := parseStatus(status, "Tgid:"); err != nil || tgid != 42 {
		t.Errorf("parseStatus(Tgid) = %d, %v; want 42", tgid, err)
	}
	if uid, err := parseEUID(status); err != nil || uid != 1001 {
		t.Errorf("parseEUID = %d, %v; want 1001", uid, err)
	}
	if _, err := parseStatus(status, "Threads:"); err == nil {
		t.Error("parseStatus(a missing line) succeeded")
	}
}

func TestStartTime(t *testing.T) {
	const boot = 1_700_000_000
	for _, tc := range []struct {
		ticks uint64
		want  time.Time
	}{
		{0, time.Unix(boot, 0)},
		{1, time.Unix(boot, 0).Add(10 * time.Millisecond)},
		{150, time.Unix(boot, 0).Add(1500 * time.Millisecond)},
		// About 2.95 years of uptime: ticks times a second overflows a
		// Duration here.
		{9_300_000_000, time.Unix(boot+93_000_000, 0)},
		{9_300_000_042, time.Unix(boot+93_000_000, 0).Add(420 * time.Millisecond)},
		{math.MaxUint64, time.Unix(boot+int64(math.MaxUint64/100), 0).Add(150 * time.Millisecond)},
	} {
		if got := startTime(boot, tc.ticks); !got.Equal(tc.want) {
			t.Errorf("startTime(%d, %d) = %v, want %v", boot, tc.ticks, got, tc.want)
		}
	}
	// A later start is a later time, across the overflow point.
	if !startTime(boot, 9_300_000_000).After(startTime(boot, 9_200_000_000)) {
		t.Error("startTime does not grow with the ticks past 2.9 years")
	}
	bt, err := btime()
	if err != nil {
		t.Fatal(err)
	}
	st := mustStat(t, os.Getpid())
	info, err := New().Process(fullRef(t, os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if !info.StartTime.Equal(startTime(bt, st.StartTicks)) {
		t.Errorf("Process(self).StartTime = %v, want %v", info.StartTime, startTime(bt, st.StartTicks))
	}
}

// TestHashCacheHolds: a file root owns and nobody else can write is cached
// once its last change is settle old, and not before. The clock, the
// agent's uid and the cache's owner are seams, so the test turns on
// neither timing nor a file this user cannot make; the system's sleep then
// shows a Procs as made caching a real root-owned program.
func TestHashCacheHolds(t *testing.T) {
	p := New()
	p.cacheOwner = os.Geteuid() // the test's file stands in for root's
	p.uid++                     // from the cache's point of view: not the owner, not root
	path := filepath.Join(t.TempDir(), "f")
	a := bytes.Repeat([]byte("a"), 4096)
	if err := os.WriteFile(path, a, 0o644); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	changed := time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec))
	// Changed less than settle ago: hashed from its bytes, not cached,
	// because a same-size rewrite in the same timestamp would keep the key.
	p.now = func() time.Time { return changed.Add(settle - time.Nanosecond) }
	if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, sum(a)) {
		t.Fatalf("CodeHash(a) = %x, %v; want %x", h, err, sum(a))
	}
	if n := len(p.cache); n != 0 {
		t.Errorf("a file changed just now was cached (%d entries)", n)
	}
	p.now = func() time.Time { return changed.Add(settle) }
	for i := 0; i < 2; i++ {
		if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, sum(a)) {
			t.Fatalf("CodeHash(a) = %x, %v; want %x", h, err, sum(a))
		}
	}
	if n := len(p.cache); n != 1 {
		t.Errorf("a settled file was not cached (%d entries)", n)
	}

	sleep := sleepPath()
	if err := unix.Stat(sleep, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		t.Fatalf("%s is owned by uid %d with mode %o: the test needs a root-owned program nobody else can write", sleep, st.Uid, st.Mode&0o777)
	}
	want := 1
	if os.Geteuid() == 0 {
		want = 0 // root writes anything: nothing is cached for it
	}
	real := New()
	for i := 0; i < 2; i++ {
		if _, err := real.CodeHash(sleep); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(real.cache); n != want {
		t.Errorf("CodeHash(%s) as uid %d cached %d entries, want %d", sleep, os.Geteuid(), n, want)
	}
}

func TestHashCacheSameTickRewrite(t *testing.T) {
	p := New()
	path := filepath.Join(t.TempDir(), "f")
	// Same-size rewrites back to back land in one coarse clock tick more
	// often than not: the hash must be the new content's every time.
	for i := 0; i < 200; i++ {
		a := []byte(fmt.Sprintf("a%04d", i) + strings.Repeat("a", 4091))
		b := []byte(fmt.Sprintf("b%04d", i) + strings.Repeat("b", 4091))
		if err := os.WriteFile(path, a, 0o644); err != nil {
			t.Fatal(err)
		}
		if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, sum(a)) {
			t.Fatalf("round %d: CodeHash(a) = %x, %v; want %x", i, h, err, sum(a))
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, sum(b)) {
			t.Fatalf("round %d: CodeHash(b) = %x, %v; want %x (same size, same tick)", i, h, err, sum(b))
		}
	}
}

func TestExitWaitsOnPidfd(t *testing.T) {
	for _, tc := range []struct {
		name    string
		noPidfd bool
		want    int64
	}{{"pidfd", false, 1}, {"poll", true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			p.noPidfd = tc.noPidfd
			cmd := startSleep(t, "")
			ref := fullRef(t, cmd.Process.Pid)
			fired := make(chan struct{}, 16)
			p.OnProcessExit(ref, func() { fired <- struct{}{} })
			cmd.Process.Kill()
			waitFired(t, fired, "exit callback after kill")
			// Counted only once a wait on the pidfd returned, so a pidfd
			// the poller refused (the exit then comes from the poll) does
			// not count.
			if got := p.pidfdWaits.Load(); got != tc.want {
				t.Errorf("exits waited on through a pidfd = %d, want %d (pidfd_open needs Linux 5.3)", got, tc.want)
			}
			cmd.Wait()
		})
	}
}

// peerPidfdHere reports whether this kernel has SO_PEERPIDFD (Linux 6.5):
// the package supports kernels without it (Debian 12, Ubuntu 22.04), going
// by SO_PEERCRED alone, and the tests of that path hold on both.
func peerPidfdHere(t *testing.T) bool {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	pidfd, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PEERPIDFD)
	switch {
	case err == nil:
		unix.Close(pidfd)
		return true
	case errors.Is(err, unix.ENOPROTOOPT):
		t.Logf("kernel %s has no SO_PEERPIDFD (Linux 6.5): peers go by SO_PEERCRED alone", kernelRelease())
		return false
	default:
		t.Fatalf("SO_PEERPIDFD on a socketpair: %v", err)
		return false
	}
}

func TestPeerOfUsesPidfd(t *testing.T) {
	var withPidfd int64
	if peerPidfdHere(t) {
		withPidfd = 1
	}
	for _, tc := range []struct {
		name        string
		noPeerPidfd bool
		want        int64
	}{{"pidfd", false, withPidfd}, {"peercred", true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			p := New()
			p.noPeerPidfd = tc.noPeerPidfd
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])
			if ref, err := p.PeerOf(fds[0]); err != nil || ref != fullRef(t, os.Getpid()) {
				t.Fatalf("PeerOf = %v, %v", ref, err)
			}
			if got := p.peerPidfds.Load(); got != tc.want {
				t.Errorf("peers identified through SO_PEERPIDFD = %d, want %d (it needs Linux 6.5; this kernel: %s)", got, tc.want, kernelRelease())
			}
		})
	}
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "?"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// TestRecheckSeesExit: a process that exits between a record's first read
// and its last check is ErrNoProcess, not a record of what it was.
func TestRecheckSeesExit(t *testing.T) {
	t.Run("Process", func(t *testing.T) {
		p := New()
		cmd := startSleep(t, "")
		ref := fullRef(t, cmd.Process.Pid)
		p.between = func() { cmd.Process.Kill(); cmd.Wait() }
		if info, err := p.Process(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("Process(exited between the reads) = %v, %v; want ErrNoProcess", info.Ref, err)
		}
	})
	t.Run("ExeHash", func(t *testing.T) {
		p := New()
		cmd := startSleep(t, "")
		ref := fullRef(t, cmd.Process.Pid)
		p.between = func() { cmd.Process.Kill(); cmd.Wait() }
		if h, err := p.ExeHash(ref); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("ExeHash(exited between the reads) = %x, %v; want ErrNoProcess", h, err)
		}
	})
	peerModes(t, func(t *testing.T, p *Procs) {
		sock := filepath.Join(t.TempDir(), "s")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		cmd, _ := startChild(t, "", "hold", nil, "NAZAR_PROCFS_SOCK="+sock)
		conn, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		child := fullRef(t, cmd.Process.Pid)
		p.between = func() { cmd.Process.Kill(); cmd.Wait() }
		raw, err := conn.(*net.UnixConn).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var ref platform.ProcessRef
		var perr error
		if err := raw.Control(func(fd uintptr) { ref, perr = p.PeerOf(int(fd)) }); err != nil {
			t.Fatal(err)
		}
		if p.noPeerPidfd || !peerPidfdHere(t) {
			// Before Linux 6.5 (or with the seam) there is nothing to
			// recheck against: the stat that was read is the answer (the
			// design's "Weaker than macOS" 8, which the docs state).
			if perr != nil || ref != child {
				t.Errorf("PeerOf by SO_PEERCRED alone = %v, %v; want the stat read before the exit, %v", ref, perr, child)
			}
			return
		}
		if !errors.Is(perr, platform.ErrNoProcess) {
			t.Errorf("PeerOf(exited between the reads) = %v, %v; want ErrNoProcess", ref, perr)
		}
	})
}

// TestExecBetweenReadlinkAndHash: a process that becomes another program
// between the readlink of its exe and the read of its image gets no Path:
// the name read and the image hashed are two different files.
func TestExecBetweenReadlinkAndHash(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, self, a)
	// Still called sleep: a multi-call sleep (Ubuntu 26.04) goes by the
	// name it is run as and refuses any other.
	if err := os.Mkdir(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	b := filepath.Join(dir, "b", "sleep")
	copyFile(t, sleepPath(), b)
	bytesOfB, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(a)
	cmd.Env = append(os.Environ(), childEnv+"=exec", "NAZAR_PROCFS_EXEC="+b)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ok" {
		t.Fatalf("child: %q, %v", line, err)
	}
	ref := fullRef(t, cmd.Process.Pid)
	if info, err := New().Process(ref); err != nil || info.Path != a {
		t.Fatalf("Process(before the exec) = %q, %v; want Path %q", info.Path, err, a)
	}
	p := New()
	p.between = func() {
		if _, err := stdin.Write([]byte{'\n'}); err != nil {
			t.Error(err)
		}
		for deadline := time.Now().Add(5 * time.Second); readLink(procPath(ref.PID, "exe")) != b; time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("child %d did not exec %q", ref.PID, b)
			}
		}
	}
	info, err := p.Process(ref)
	if err != nil {
		t.Fatalf("Process(exec'd between the reads): %v", err)
	}
	if info.Path != "" {
		t.Errorf("Path = %q, want \"\": the name read was %q but the image hashed is %q", info.Path, a, b)
	}
	if !bytes.Equal(info.Code.CDHash, sum(bytesOfB)) {
		t.Errorf("CDHash = %x, want the new image's %x", info.Code.CDHash, sum(bytesOfB))
	}
	if info.Ref != ref {
		t.Errorf("Ref = %v, want %v (an exec keeps the instance)", info.Ref, ref)
	}
	// Settled, the new program is named, and the name and the image agree.
	p.between = nil
	if info, err := p.Process(ref); err != nil || info.Path != b || !bytes.Equal(info.Code.CDHash, sum(bytesOfB)) {
		t.Errorf("Process(after the exec) = %q %x, %v; want %q and %x", info.Path, info.Code.CDHash, err, b, sum(bytesOfB))
	}
}

// userNamespaces returns the unshare program when an unprivileged user
// and mount namespace can be made here. Elsewhere the test is skipped (a
// developer's machine that forbids them), except in the Linux test image,
// where it fails: that image is where these tests must run, and a
// container's default seccomp profile forbids unshare unless the run
// allows it (notHere says how). TestExecBetweenReadlinkAndHash and
// TestUserManagerIsTheFileNotTheName cover the name-against-image check
// without a namespace, through seams.
func userNamespaces(t *testing.T) string {
	t.Helper()
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		notHere(t, "no unshare")
	}
	if out, err := exec.Command(unshare, "-rm", "true").CombinedOutput(); err != nil {
		notHere(t, fmt.Sprintf("unshare -rm is not permitted here: %v: %s", err, strings.TrimSpace(string(out))))
	}
	return unshare
}

// notHere skips the test for the reason given, except inside the Linux
// test image (test/linux sets NAZAR_LINUX_TEST_CONTAINER=1), where no test
// is ever skipped: there it fails, naming what the container run must
// allow.
func notHere(t *testing.T, reason string) {
	t.Helper()
	if os.Getenv("NAZAR_LINUX_TEST_CONTAINER") == "1" {
		t.Fatalf("%s; in the test image this test must run: the container must allow unprivileged user and mount namespaces (docker run --security-opt seccomp=unconfined, and --security-opt apparmor=unconfined where AppArmor confines containers)", reason)
	}
	t.Skip(reason)
}

// TestBindMountedPathIsNotReported: a process in its own mount namespace
// runs tail under the name of sleep; the name means another file here,
// so no Path is reported for it (a path: rule for sleep must not match).
func TestBindMountedPathIsNotReported(t *testing.T) {
	unshare := userNamespaces(t)
	tail, err := exec.LookPath("tail")
	if err != nil {
		notHere(t, "no tail")
	}
	sleep := sleepPath()
	cmd := exec.Command(unshare, "-rm", "sh", "-c", "mount --bind "+tail+" "+sleep+" && exec "+sleep+" -f /dev/null")
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for deadline := time.Now().Add(5 * time.Second); readLink(procPath(cmd.Process.Pid, "exe")) != sleep; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("child %d runs %q, want %q", cmd.Process.Pid, readLink(procPath(cmd.Process.Pid, "exe")), sleep)
		}
	}
	p := New()
	info, err := p.Process(fullRef(t, cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := p.CodeHash(tail)
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != "" {
		t.Errorf("Path = %q, want \"\": that name is another file in the process's mount namespace", info.Path)
	}
	if !bytes.Equal(info.Code.CDHash, wantHash) {
		t.Errorf("CDHash = %x, want tail's %x", info.Code.CDHash, wantHash)
	}
	if info.Comm != "sleep" {
		t.Errorf("Comm = %q, want \"sleep\"", info.Comm)
	}
}

// TestBindMountedManagerIsNotTheTop: a process in its own mount namespace
// runs the test binary, as `--user`, under the name of tail; with tail as
// the manager's executable, the name matches but the file does not, so
// its child's Parent is the real one, not the chain's top {PID: 1}.
func TestBindMountedManagerIsNotTheTop(t *testing.T) {
	unshare := userNamespaces(t)
	tail, err := exec.LookPath("tail")
	if err != nil {
		notHere(t, "no tail")
	}
	manager := filepath.Join(t.TempDir(), "manager")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copyFile(t, self, manager)
	cmd := exec.Command(unshare, "-rm", "sh", "-c", "mount --bind "+manager+" "+tail+" && exec "+tail+" --user")
	cmd.Env = append(os.Environ(), childEnv+"=manager")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("manager: no first line: %v", err)
	}
	sleepPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("manager printed %q", line)
	}
	t.Cleanup(func() { unix.Kill(sleepPID, unix.SIGKILL) })
	if got := readLink(procPath(cmd.Process.Pid, "exe")); got != tail {
		t.Fatalf("the manager's exe reads %q, want %q", got, tail)
	}
	p := New()
	p.managerExes = []string{tail}
	info, err := p.Process(fullRef(t, sleepPID))
	if err != nil {
		t.Fatal(err)
	}
	if info.Parent != (platform.ProcessRef{PID: cmd.Process.Pid}) {
		t.Errorf("Parent under a program bind-mounted over the manager's name = %v, want PID-only %d: that name is another file here", info.Parent, cmd.Process.Pid)
	}
}

// TestCacheable: the decision to keep a file's hash under its key, case
// by case.
func TestCacheable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	old := unix.NsecToTimespec(now.Add(-settle).UnixNano())
	fresh := unix.NsecToTimespec(now.Add(-settle + time.Millisecond).UnixNano())
	const ext4 = unix.EXT4_SUPER_MAGIC
	for name, tc := range map[string]struct {
		st    unix.Stat_t
		fs    int64
		uid   int
		owner int
		want  bool
	}{
		"root's program, settled":     {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o755, Ctim: old}, ext4, 1000, 0, true},
		"setuid root, no write bits":  {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o4755, Ctim: old}, ext4, 1000, 0, true},
		"another user's, settled":     {unix.Stat_t{Uid: 2000, Mode: unix.S_IFREG | 0o644, Ctim: old}, ext4, 1000, 0, false},
		"another user's, read-only":   {unix.Stat_t{Uid: 2000, Mode: unix.S_IFREG | 0o444, Ctim: old}, ext4, 1000, 0, false},
		"changed within settle":       {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o755, Ctim: fresh}, ext4, 1000, 0, false},
		"this user's own file":        {unix.Stat_t{Uid: 1000, Mode: unix.S_IFREG | 0o644, Ctim: old}, ext4, 1000, 0, false},
		"this user's, read-only mode": {unix.Stat_t{Uid: 1000, Mode: unix.S_IFREG | 0o444, Ctim: old}, ext4, 1000, 0, false},
		"root's, group-writable":      {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o775, Ctim: old}, ext4, 1000, 0, false},
		"root's, world-writable":      {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o777, Ctim: old}, ext4, 1000, 0, false},
		"the agent as root":           {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o755, Ctim: old}, ext4, 0, 0, false},
		"on FUSE":                     {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o755, Ctim: old}, unix.FUSE_SUPER_MAGIC, 1000, 0, false},
		// The seam: the tests' own files stand in for root's.
		"the seam's owner, settled":  {unix.Stat_t{Uid: 1000, Mode: unix.S_IFREG | 0o644, Ctim: old}, ext4, 1001, 1000, true},
		"the seam's owner, as agent": {unix.Stat_t{Uid: 1000, Mode: unix.S_IFREG | 0o644, Ctim: old}, ext4, 1000, 1000, false},
		"root's, the seam elsewhere": {unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o755, Ctim: old}, ext4, 1001, 1000, false},
	} {
		if got := cacheable(&tc.st, tc.fs, tc.uid, tc.owner, now); got != tc.want {
			t.Errorf("%s: cacheable = %v, want %v", name, got, tc.want)
		}
	}
	if New().cacheOwner != 0 {
		t.Errorf("New().cacheOwner = %d, want root", New().cacheOwner)
	}
}

// mapShared maps the whole file at path, shared and writable, and returns
// the mapping and a release of it (idempotent; also run at cleanup).
func mapShared(t *testing.T, path string) ([]byte, func()) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	m, err := unix.Mmap(int(f.Fd()), 0, int(fi.Size()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if err := unix.Munmap(m); err != nil {
			t.Error(err)
		}
		f.Close()
	}
	t.Cleanup(release)
	return m, release
}

// fileSum is the SHA-256 of the file's bytes as they are now.
func fileSum(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sum(data)
}

// TestMappedRewriteIsNotCached: a write through a shared mapping changes
// a file's bytes and, once the page is dirty, none of its timestamps, so
// the cache key does not change with the content. A file this user can
// write is therefore never served from the cache: CodeHash of the file,
// and ExeHash of a process started from it after the tamper, are the hash
// of the bytes as they are. The attacker waits out settle; the test moves
// the clock instead.
func TestMappedRewriteIsNotCached(t *testing.T) {
	dir := t.TempDir()
	t.Run("CodeHash", func(t *testing.T) {
		p := New()
		p.now = func() time.Time { return time.Now().Add(settle) }
		path := filepath.Join(dir, "f")
		if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 4096), 0o644); err != nil {
			t.Fatal(err)
		}
		m, _ := mapShared(t, path)
		m[0] = 'b' // the first write: the page is dirty now and the times are updated
		before := fileSum(t, path)
		if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, before) {
			t.Fatalf("CodeHash = %x, %v; want %x", h, err, before)
		}
		m[1] = 'c' // the second: the bytes change, no timestamp does
		want := fileSum(t, path)
		if bytes.Equal(want, before) {
			t.Fatal("the write through the mapping changed nothing")
		}
		if h, err := p.CodeHash(path); err != nil || !bytes.Equal(h, want) {
			t.Errorf("CodeHash after a write through the mapping = %x, %v; want %x (the hash before the write was %x)", h, err, want, before)
		}
	})
	t.Run("ExeHash", func(t *testing.T) {
		p := New()
		p.now = func() time.Time { return time.Now().Add(settle) }
		exe := filepath.Join(dir, "sleep")
		copyFile(t, sleepPath(), exe)
		m, release := mapShared(t, exe)
		// The file's last byte ends the section header table, which exec
		// does not read.
		m[len(m)-1] ^= 1
		before, err := p.CodeHash(exe) // hashed while the mapping is dirty
		if err != nil {
			t.Fatal(err)
		}
		m[len(m)-1] ^= 2
		want := fileSum(t, exe)
		if bytes.Equal(want, before) {
			t.Fatal("the write through the mapping changed nothing")
		}
		release() // no writer left: exec gets no ETXTBSY
		cmd := startSleep(t, exe)
		ref := fullRef(t, cmd.Process.Pid)
		if h, err := p.ExeHash(ref); err != nil || !bytes.Equal(h, want) {
			t.Errorf("ExeHash of the tampered program = %x, %v; want %x (the hash before the tamper was %x)", h, err, want, before)
		}
		if info, err := p.Process(ref); err != nil || !bytes.Equal(info.Code.CDHash, want) {
			t.Errorf("Process(tampered program).CDHash = %x, %v; want %x", info.Code.CDHash, err, want)
		}
		if h, err := p.CodeHash(exe); err != nil || !bytes.Equal(h, want) {
			t.Errorf("CodeHash of the tampered program = %x, %v; want %x", h, err, want)
		}
	})
}

// TestCodeHashDoesNotOpenSpecialFiles: a FIFO is refused without being
// opened. Opening it would release a writer waiting for a reader, as an
// open of a device has effects of its own (an exclusive one, such as the
// TPM, is busy for everyone else while it is open).
func TestCodeHashDoesNotOpenSpecialFiles(t *testing.T) {
	p := New()
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	opened := make(chan error, 1)
	go func() {
		// Blocks until some reader opens the FIFO.
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
		}
		opened <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the writer reach its open
	if h, err := hashWithin(t, p, fifo); err == nil || errors.Is(err, platform.ErrNotFound) || h != nil {
		t.Errorf("CodeHash(fifo) = %x, %v; want an error other than ErrNotFound", h, err)
	}
	select {
	case err := <-opened:
		t.Errorf("CodeHash opened the FIFO: the writer waiting for a reader was released (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	// Release the writer ourselves.
	fd, err := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer did not wake once a reader opened the FIFO")
	}
}

// TestCodeHashRefusesHugeFile: a file larger than maxImage (sparse here)
// is an error at once, not a read that holds the caller.
func TestCodeHashRefusesHugeFile(t *testing.T) {
	p := New()
	path := filepath.Join(t.TempDir(), "huge")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxImage + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if h, err := hashWithin(t, p, path); err == nil || errors.Is(err, platform.ErrNotFound) || h != nil {
		t.Errorf("CodeHash(a %d-byte file) = %x, %v; want an error other than ErrNotFound", maxImage+1, h, err)
	}
}

// TestPeerOfPidfdFailureIsNotThePeers: a failure of the agent's own (its
// file table is full) is an error that names that reason, not "the peer
// has exited", whether the descriptor refused was the peer's pidfd or, on
// a kernel without SO_PEERPIDFD (the peercred mode here, and either mode
// before Linux 6.5), the open of the peer's /proc/<pid>/stat.
func TestPeerOfPidfdFailureIsNotThePeers(t *testing.T) {
	peerModes(t, func(t *testing.T, p *Procs) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		self := fullRef(t, os.Getpid())
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
			t.Fatal(err)
		}
		// The lowest free descriptor: a limit at it makes the next one fail.
		probe, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(probe)
		full := lim
		full.Cur = uint64(probe)
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &full); err != nil {
			t.Fatal(err)
		}
		ref, perr := p.PeerOf(fds[0])
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
			t.Fatal(err)
		}
		if perr == nil || errors.Is(perr, platform.ErrNoProcess) || !errors.Is(perr, unix.EMFILE) {
			t.Errorf("PeerOf with a full file table = %v, %v; want an EMFILE error that is not ErrNoProcess", ref, perr)
		}
		if ref, err := p.PeerOf(fds[0]); err != nil || ref != self {
			t.Errorf("PeerOf with the file table free again = %v, %v; want %v", ref, err, self)
		}
	})
}

// TestCodeHashReadsTheFileItChecked: the file read is the file whose type
// was checked, though the name comes to mean another file in between: a
// symlink is swapped from a regular file to a FIFO with a writer waiting
// on it. The hash is the regular file's and the FIFO is never opened (the
// writer stays blocked). A stat of the name followed by an open of the
// name would open the FIFO, releasing the writer, before refusing it.
func TestCodeHashReadsTheFileItChecked(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	a := bytes.Repeat([]byte("a"), 4096)
	if err := os.WriteFile(file, a, 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	opened := make(chan error, 1)
	go func() {
		// Blocks until some reader opens the FIFO.
		fd, err := unix.Open(fifo, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(fd)
		}
		opened <- err
	}()
	time.Sleep(100 * time.Millisecond) // let the writer reach its open
	p := New()
	p.beforeRead = func() {
		if err := os.Remove(link); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(fifo, link); err != nil {
			t.Error(err)
		}
	}
	if h, err := hashWithin(t, p, link); err != nil || !bytes.Equal(h, sum(a)) {
		t.Errorf("CodeHash(link swapped to a FIFO after the check) = %x, %v; want the checked file's %x", h, err, sum(a))
	}
	select {
	case err := <-opened:
		t.Errorf("CodeHash opened the FIFO: the writer waiting for a reader was released (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	// Settled, the name means the FIFO, which is refused without being
	// opened: the writer still waits.
	p.beforeRead = nil
	if h, err := hashWithin(t, p, link); err == nil || errors.Is(err, platform.ErrNotFound) || h != nil {
		t.Errorf("CodeHash(link to a FIFO) = %x, %v; want an error other than ErrNotFound", h, err)
	}
	select {
	case err := <-opened:
		t.Errorf("CodeHash opened the FIFO it refused: the writer was released (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}
	// Release the writer ourselves.
	fd, err := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	select {
	case <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("the writer did not wake once a reader opened the FIFO")
	}
}

// TestPeerOfRefusesHolderStartedAfterEntry: the holder of the peer's PID
// is refused when its start ticks are later than the boot clock's at the
// start of the call: the peer connected before the call and started
// before that, so such a holder is a new process in a recycled PID. The
// clock is a seam; a holder that started in the call's own tick passes
// (the kernel floors both to the tick), as does any peer when the clock
// can't be read, and the live clock refuses no real peer (TestPeerOf and
// this test's last check).
func TestPeerOfRefusesHolderStartedAfterEntry(t *testing.T) {
	peerModes(t, func(t *testing.T, p *Procs) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fds[0])
		defer unix.Close(fds[1])
		self := fullRef(t, os.Getpid())
		start := mustStat(t, os.Getpid()).StartTicks
		p.ticksNow = func() (uint64, bool) { return start - 1, true }
		if ref, err := p.PeerOf(fds[0]); !errors.Is(err, platform.ErrNoProcess) {
			t.Errorf("PeerOf with the holder started a tick after the call began = %v, %v; want ErrNoProcess", ref, err)
		}
		p.ticksNow = func() (uint64, bool) { return start, true }
		if ref, err := p.PeerOf(fds[0]); err != nil || ref != self {
			t.Errorf("PeerOf with the holder started in the call's tick = %v, %v; want %v", ref, err, self)
		}
		p.ticksNow = func() (uint64, bool) { return 0, false }
		if ref, err := p.PeerOf(fds[0]); err != nil || ref != self {
			t.Errorf("PeerOf with no clock = %v, %v; want %v", ref, err, self)
		}
		p.ticksNow = nil
		if ref, err := p.PeerOf(fds[0]); err != nil || ref != self {
			t.Errorf("PeerOf with the live clock = %v, %v; want %v", ref, err, self)
		}
		now, ok := bootTicks()
		if !ok || now < start {
			t.Errorf("bootTicks() = %d, %v; want at least this process's start %d", now, ok, start)
		}
	})
}
