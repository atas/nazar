//go:build linux

package peertrust

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/core/unixsock"
)

// The test binary doubles as the peer: a copy of it, started in the mode
// NAZAR_PEERTRUST_CHILD names, connects to the test's socket, says so on
// stdout and holds the connection until the test kills it. A socketpair
// would not do: both its ends carry the creator's credentials, so the
// peer would be the test itself; a connect names the child.
const (
	childEnv = "NAZAR_PEERTRUST_CHILD"
	sockEnv  = "NAZAR_PEERTRUST_SOCK"
)

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "hold":
		c, err := net.Dial("unix", os.Getenv(sockEnv))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer c.Close()
		fmt.Println("ok")
		io.Copy(io.Discard, os.Stdin)
	default:
		fmt.Fprintln(os.Stderr, "unknown child mode")
		os.Exit(2)
	}
}

// peer is a child holding a connection to the test: the test's end of it,
// the child's pid, and the file the child runs.
type peer struct {
	conn *net.UnixConn
	pid  int
	exe  string
}

// startPeer copies the test binary to dir, starts the copy and accepts
// its connection.
func startPeer(t *testing.T, dir string) peer {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "nazar-peer")
	copyFile(t, self, exe, nil)
	sock := filepath.Join(dir, "p.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), childEnv+"=hold", sockEnv+"="+sock)
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
	l.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatalf("the child did not connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ok" {
		t.Fatalf("child: %q, %v", line, err)
	}
	return peer{conn: conn, pid: cmd.Process.Pid, exe: exe}
}

// copyFile copies from to to as an executable, with extra appended.
func copyFile(t *testing.T, from, to string, extra []byte) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, append(data, extra...), 0o755); err != nil {
		t.Fatal(err)
	}
}

// tmpDir is a short folder under /tmp: a socket path is bounded.
func tmpDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzpt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// record writes a record whose CLI and agent are the given files.
func record(t *testing.T, home, cli, agent string) {
	t.Helper()
	ch, err := HashFile(cli)
	if err != nil {
		t.Fatal(err)
	}
	ah, err := HashFile(agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(home, Record{CLI: Binary{Path: cli, SHA256: ch}, Agent: Binary{Path: agent, SHA256: ah}}); err != nil {
		t.Fatal(err)
	}
}

// other is a file that is not the peer's: the peer's bytes and one more.
func other(t *testing.T, dir, exe string) string {
	t.Helper()
	p := filepath.Join(dir, "nazar-other")
	copyFile(t, exe, p, []byte{'\n'})
	return p
}

func fullRef(t *testing.T, pid int) platform.ProcessRef {
	t.Helper()
	st, err := procfs.ReadStat(pid)
	if err != nil {
		t.Fatal(err)
	}
	return platform.ProcessRef{PID: pid, Generation: procfs.Generation(st.StartTicks)}
}

// verifyPeer runs the verifier on the test's end of the connection.
func verifyPeer(t *testing.T, p peer, v func(fd int) (platform.ProcessRef, error)) (platform.ProcessRef, error) {
	t.Helper()
	var ref platform.ProcessRef
	var verr error
	if err := unixsock.WithFD(p.conn, func(fd int) error { ref, verr = v(fd); return nil }); err != nil {
		t.Fatal(err)
	}
	return ref, verr
}

func TestCLIVerifierAcceptsRecordedBinary(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	record(t, home, p.exe, other(t, dir, p.exe))
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	ref, err := verifyPeer(t, p, CLIVerifier(home, procfs.New(), os.Getuid(), logf))
	if err != nil {
		t.Fatalf("the recorded CLI was refused: %v", err)
	}
	if want := fullRef(t, p.pid); ref != want {
		t.Fatalf("ref %+v, want the child's full ref %+v", ref, want)
	}
	if len(logged) != 0 {
		t.Fatalf("an accepted peer was logged: %q", logged)
	}
}

func TestCLIVerifierRefusesOtherBinary(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	record(t, home, other(t, dir, p.exe), p.exe) // the peer is recorded as the agent, not the CLI
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	ref, err := verifyPeer(t, p, CLIVerifier(home, procfs.New(), os.Getuid(), logf))
	if !errors.Is(err, ErrCLIMismatch) {
		t.Fatalf("err %v, want ErrCLIMismatch", err)
	}
	if ref != (platform.ProcessRef{}) {
		t.Fatalf("a refused peer came back with a ref: %+v", ref)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "run nazar install") {
		t.Fatalf("logged %q", logged)
	}
}

func TestCLIVerifierRefusesOtherUID(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	record(t, home, p.exe, other(t, dir, p.exe))
	ref, err := verifyPeer(t, p, CLIVerifier(home, procfs.New(), os.Getuid()+1, nil))
	if err == nil || !strings.Contains(err.Error(), "uid") {
		t.Fatalf("a peer of another uid: %v", err)
	}
	if ref != (platform.ProcessRef{}) {
		t.Fatalf("a refused peer came back with a ref: %+v", ref)
	}
}

func TestCLIVerifierRefusesWithoutRecord(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	ref, err := verifyPeer(t, p, CLIVerifier(home, procfs.New(), os.Getuid(), nil))
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err %v, want ErrNotInstalled", err)
	}
	if ref != (platform.ProcessRef{}) {
		t.Fatalf("a refused peer came back with a ref: %+v", ref)
	}
}

// The record is read on every check: a re-run nazar install applies to
// the next connection, and so does the record's loss.
func TestCLIVerifierReadsTheRecordEveryTime(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	o := other(t, dir, p.exe)
	v := CLIVerifier(home, procfs.New(), os.Getuid(), nil)
	record(t, home, o, p.exe)
	if _, err := verifyPeer(t, p, v); !errors.Is(err, ErrCLIMismatch) {
		t.Fatalf("before the re-install: %v", err)
	}
	record(t, home, p.exe, o)
	if _, err := verifyPeer(t, p, v); err != nil {
		t.Fatalf("after the re-install: %v", err)
	}
	if err := os.Remove(File(home)); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPeer(t, p, v); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("after the record went: %v", err)
	}
}

func TestCLIVerifierBadSocket(t *testing.T) {
	home := t.TempDir()
	v := CLIVerifier(home, procfs.New(), os.Getuid(), nil)
	if ref, err := v(-1); err == nil || ref != (platform.ProcessRef{}) {
		t.Fatalf("fd -1: %+v, %v", ref, err)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if ref, err := v(int(f.Fd())); err == nil || ref != (platform.ProcessRef{}) {
		t.Fatalf("a file that is not a socket: %+v, %v", ref, err)
	}
}

func TestCheckAgentAcceptsRecordedAgent(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	record(t, home, other(t, dir, p.exe), p.exe)
	if err := unixsock.WithFD(p.conn, func(fd int) error { return CheckAgent(fd, home, procfs.New()) }); err != nil {
		t.Fatalf("the recorded agent was refused: %v", err)
	}
}

func TestCheckAgentMismatchNamesInstall(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	record(t, home, p.exe, other(t, dir, p.exe)) // the peer is recorded as the CLI, not the agent
	err := unixsock.WithFD(p.conn, func(fd int) error { return CheckAgent(fd, home, procfs.New()) })
	const want = "the agent on the control socket is not the nazar-agent nazar install recorded (it was upgraded or replaced); run nazar install"
	if err == nil || err.Error() != want {
		t.Fatalf("err %v, want %q", err, want)
	}
	if !errors.Is(err, ErrAgentMismatch) {
		t.Fatalf("err %v is not ErrAgentMismatch", err)
	}
}

func TestCheckAgentWithoutRecord(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	p := startPeer(t, dir)
	err := unixsock.WithFD(p.conn, func(fd int) error { return CheckAgent(fd, home, procfs.New()) })
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err %v, want ErrNotInstalled", err)
	}
	if err := CheckAgent(-1, home, procfs.New()); err == nil {
		t.Fatal("CheckAgent(-1) passed")
	}
}

// The CLI's check of itself: the image it runs is this test binary.
func TestCheckSelfAcceptsRecordedCLI(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	record(t, home, self, other(t, dir, self))
	if err := CheckSelf(home); err != nil {
		t.Fatalf("the recorded CLI was refused: %v", err)
	}
}

// An upgrade the record has not seen: this CLI differs from the record's,
// whatever the agent is.
func TestCheckSelfMismatchNamesInstall(t *testing.T) {
	dir, home := tmpDir(t), t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	record(t, home, other(t, dir, self), self) // this binary is recorded as the agent, not the CLI
	err = CheckSelf(home)
	const want = "this nazar is not the nazar that nazar install recorded (it was upgraded or replaced); run nazar install"
	if err == nil || err.Error() != want {
		t.Fatalf("err %v, want %q", err, want)
	}
	if !errors.Is(err, ErrSelfMismatch) {
		t.Fatalf("err %v is not ErrSelfMismatch", err)
	}
}

func TestCheckSelfWithoutRecord(t *testing.T) {
	if err := CheckSelf(t.TempDir()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err %v, want ErrNotInstalled", err)
	}
}
