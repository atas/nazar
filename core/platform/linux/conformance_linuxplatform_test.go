//go:build linux && linuxplatform

// The platform contract (core/platform/conformance) run against the
// Linux Platform in the test image: a fresh swtpm and file vault per
// subtest, the container's polkitd with the test agent answering for this
// process, fakedialog in place of zenity, and fakelogind and fakenotify on
// a private bus. Every gate is driven by one answers queue, so Answer
// scripts the next Authenticate or Confirm whichever gate it is. Nothing
// here reaches the host's TPM, its buses or a desktop.
package linux_test

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"github.com/atas/nazar/core/platform/linux"
	"github.com/atas/nazar/core/platform/linux/dialog"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/core/platform/linux/vault"
	"github.com/atas/nazar/core/platform/pipes"
	"github.com/atas/nazar/internal/linuxtest/answers"
	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/dbustest"
	"github.com/atas/nazar/internal/linuxtest/fakelogind"
	"github.com/atas/nazar/internal/linuxtest/fakenotify"
	"github.com/atas/nazar/internal/linuxtest/polkitagent"
	"github.com/atas/nazar/internal/linuxtest/stdoutcase"
	"github.com/atas/nazar/internal/linuxtest/swtpm"
)

// The image's test user (test/linux/Dockerfile), whose password the test
// agent gives PAM on an allow.
const (
	testUser     = "nazartest"
	testPassword = "nazar-test-password"
)

// childEnv names the socket the test binary, re-executed as the Peer
// hook's child, connects to and then holds until its stdin closes.
const childEnv = "NAZAR_LINUX_CONFORMANCE_CHILD"

// fakePath is the fakedialog binary, built once in TestMain.
var fakePath string

func TestMain(m *testing.M) {
	if sock := os.Getenv(childEnv); sock != "" {
		c, err := net.Dial("unix", sock)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer c.Close()
		fmt.Println("ok")
		io.Copy(io.Discard, os.Stdin)
		return
	}
	if err := container.Check(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	dir, err := os.MkdirTemp("", "nzconf")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fakePath = filepath.Join(dir, "fakedialog")
	build := exec.Command(goTool(), "build", "-o", fakePath, "github.com/atas/nazar/internal/linuxtest/fakedialog")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build fakedialog:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := container.Require(m)
	os.RemoveAll(dir)
	os.Exit(code)
}

func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go")
}

func TestLinuxConforms(t *testing.T) {
	conformance.Run(t, newEnv)
}

// newEnv builds one Platform with every part real but the person: the
// test agent and fakedialog answer from q. Exec and Mounts stay nil
// (nazar run is not in Linux v1), so only those two groups are skipped.
func newEnv(t *testing.T) conformance.Env {
	t.Helper()
	q := answers.NewQueue(t)

	tr, err := linuxudstpm.Open(swtpm.Start(t))
	if err != nil {
		t.Fatalf("open swtpm: %v", err)
	}
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}

	// polkit: the container's system bus, this process as the subject, and
	// the test agent registered for it.
	system, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatalf("system bus: %v", err)
	}
	t.Cleanup(func() { system.Close() })
	self := fullRef(t, os.Getpid())
	subject := polkit.ProcessSubject(self.PID, self.Generation-1, os.Getuid())
	polkitagent.Register(t, system, subject, testUser, testPassword, q)

	// logind and the notification server: fakes on one private bus, each
	// part of the platform on its own connection, as on the real buses.
	address := dbustest.Start(t)
	uid := os.Getuid()
	fakelogind.Serve(t, connect(t, address), uid)
	fakenotify.Serve(t, connect(t, address))

	p, err := linux.New(linux.Options{
		Home:    t.TempDir(),
		TPM:     tr,
		Vault:   v,
		Polkit:  system,
		Logind:  connect(t, address),
		Notify:  connect(t, address),
		Subject: func() (polkit.Subject, error) { return subject, nil },
		Dialog:  fakeDialog(t, q),
		UID:     uid,
	})
	if err != nil {
		t.Fatalf("linux.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	procs := &children{t: t}
	t.Cleanup(procs.killAll)
	return conformance.Env{
		P:      p,
		Answer: q.Push,
		Spawn:  procs.spawn,
		Exit:   procs.exit,
		Peer:   procs.peer,
		Pipes:  pipes.New(),
		Stdout: stdoutcase.Start,
	}
}

// connect opens one connection to the private bus at address, closed at cleanup.
func connect(t *testing.T, address string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatalf("connect %s: %v", address, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// fakeDialog is a zenity stand-in: a wrapper that gives fakedialog the
// queue's socket (the allowlist would strip it from the environment) and
// execs it, so the exit code is the fake's: 0 allow, 1 deny, 5 timed out.
func fakeDialog(t *testing.T, q *answers.Queue) dialog.Dialog {
	t.Helper()
	program := filepath.Join(t.TempDir(), "dialog")
	script := "#!/bin/sh\nexport NAZAR_TEST_ANSWERS='" + q.Socket() + "'\nexec '" + fakePath + "' \"$@\"\n"
	if err := os.WriteFile(program, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return dialog.Dialog{
		Program: program,
		Kind:    dialog.Zenity,
		Env:     func() []string { return []string{"DISPLAY=:0"} },
	}
}

// fullRef is pid's full ref as the Linux platform forms it.
func fullRef(t *testing.T, pid int) platform.ProcessRef {
	t.Helper()
	st, err := procfs.ReadStat(pid)
	if err != nil {
		t.Fatalf("stat %d: %v", pid, err)
	}
	return platform.ProcessRef{PID: pid, Generation: procfs.Generation(st.StartTicks)}
}

// children starts and ends real processes for the suite: /bin/sleep for
// Spawn, this test binary connected to a socket of ours for Peer.
type children struct {
	t     *testing.T
	mu    sync.Mutex
	cmds  map[int]*exec.Cmd
	close []io.Closer
}

func (c *children) start(cmd *exec.Cmd) *exec.Cmd {
	if err := cmd.Start(); err != nil {
		c.t.Fatalf("start %s: %v", cmd.Path, err)
	}
	c.mu.Lock()
	if c.cmds == nil {
		c.cmds = map[int]*exec.Cmd{}
	}
	c.cmds[cmd.Process.Pid] = cmd
	c.mu.Unlock()
	return cmd
}

func (c *children) spawn() platform.ProcessRef {
	cmd := c.start(exec.Command("/bin/sleep", "3600"))
	return fullRef(c.t, cmd.Process.Pid)
}

func (c *children) exit(ref platform.ProcessRef) {
	c.mu.Lock()
	cmd := c.cmds[ref.PID]
	delete(c.cmds, ref.PID)
	c.mu.Unlock()
	if cmd == nil {
		c.t.Fatalf("Exit of %v, which the suite did not spawn", ref)
	}
	cmd.Process.Kill()
	cmd.Wait() // reaped: gone for the platform too
}

// peer listens on a socket, starts a child that connects to it and holds
// the connection, and returns our end of that connection with the child's
// PID. The kernel records the connecting process as the peer, so PeerOf
// of our end names the child (a socketpair would name this process, which
// made both ends).
func (c *children) peer() (int, int) {
	dir, err := os.MkdirTemp("/tmp", "nzcf") // short: sun_path is 108 bytes
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		c.t.Fatal(err)
	}
	defer l.Close()

	exe, err := os.Executable()
	if err != nil {
		c.t.Fatal(err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), childEnv+"="+sock)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		c.t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	c.start(cmd)
	c.mu.Lock()
	c.close = append(c.close, stdin)
	c.mu.Unlock()

	conn, err := l.Accept()
	if err != nil {
		c.t.Fatalf("accept the child's connection: %v", err)
	}
	// The child says ok once connected, so the connection is its own and
	// it is holding it.
	if _, err := io.ReadFull(stdout, make([]byte, 3)); err != nil {
		c.t.Fatalf("child did not report its connection: %v", err)
	}
	f, err := conn.(*net.UnixConn).File()
	if err != nil {
		c.t.Fatal(err)
	}
	conn.Close()
	c.t.Cleanup(func() { f.Close() })
	return int(f.Fd()), cmd.Process.Pid
}

// killAll ends every child still running when the subtest ends.
func (c *children) killAll() {
	c.mu.Lock()
	cmds := c.cmds
	c.cmds = nil
	closers := c.close
	c.close = nil
	c.mu.Unlock()
	for _, cl := range closers {
		cl.Close()
	}
	for _, cmd := range cmds {
		cmd.Process.Kill()
		cmd.Wait()
	}
}
