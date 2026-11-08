//go:build darwin

// Command conformancehost runs core/platform/conformance against the Swift
// platform. It is built as a C archive and linked by the Swift
// executable NazarConformanceHost; never by Nazar.app:
//
//	go build -buildmode=c-archive -o build/libnazar-conformance.a ./bridge/conformancehost
//	NazarConformanceHost real   [-test.v] [-test.run …]   # real Secure Enclave (AuthNone keys only), real processes
//	NazarConformanceHost seamed [-test.v] [-test.run …]   # software keys + scripted gates: the approval subtests too
//
// Nothing here needs a person: the real run never creates a user-presence
// key and has no Answer hook, so no login or dialog gate is ever called.
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../macos/Sources/CNazarBridge/include
#include "nazar_bridge.h"
#include "nazar_host_hooks.h"
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/atas/nazar/bridge/cbridge"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/conformance"
	"github.com/atas/nazar/core/platform/mounts"
	"github.com/atas/nazar/core/platform/pipes"
	"golang.org/x/sys/unix"
)

const (
	modeReal   = 1
	modeSeamed = 2
)

//export NazarRunConformance
func NazarRunConformance(cb *C.NazarCallbacks, mode C.int32_t, hooks *C.NazarHostHooks) C.int32_t {
	b, err := cbridge.New(unsafe.Pointer(cb))
	if err != nil {
		fmt.Fprintln(os.Stderr, "conformance host:", err)
		return 2
	}
	h := newHooks(unsafe.Pointer(hooks))
	// argv is "NazarConformanceHost <mode> [test flags]": drop the mode so
	// the testing package sees only its own flags.
	if len(os.Args) > 1 {
		os.Args = append(os.Args[:1:1], os.Args[2:]...)
	}
	testing.Init()
	tests := []testing.InternalTest{
		{Name: "TestSwiftPlatformConforms", F: func(t *testing.T) {
			conformance.Run(t, func(t *testing.T) conformance.Env { return newEnv(t, b, h, int(mode)) })
		}},
		// A missing exec seam is a failure here, never a skip of
		// the exec group.
		{Name: "TestSwiftPlatformHasExec", F: func(t *testing.T) {
			if b.Exec() == nil {
				t.Fatal("the Swift layer offers no exec seam: the exec group would be skipped")
			}
		}},
		// The same for the stdout check (package pipes, which
		// nazar-agent wires): a missing one would skip the pipes group.
		{Name: "TestPlatformHasPipes", F: func(t *testing.T) {
			if pipes.New() == nil {
				t.Fatal("no stdout check on macOS: the pipes group would be skipped and nazar-agent would refuse every k8s credential")
			}
		}},
		// nazar run end to end on these seams (make integration-run;
		// make conformance skips them: they need the bundle make agent built).
		{Name: "TestNazarRunThroughRealNpx", F: func(t *testing.T) { testRunThroughRealNpx(t, b) }},
		{Name: "TestNazarRunPython", F: func(t *testing.T) { testRunPython(t, b) }},
		{Name: "TestNazarRunRefusesChangedPinnedFiles", F: func(t *testing.T) { testRunRefusesChangedPinnedFiles(t, b) }},
		// Check 0, check 1 and the stdout check on real chains with
		// the real kubectl (make integration-run; make conformance skips it:
		// it needs the nazartest CLI).
		{Name: "TestNazarK8sRealKubectl", F: func(t *testing.T) { testK8sRealKubectl(t, b) }},
		{Name: "TestNoBoundaryLeaks", F: func(t *testing.T) {
			time.Sleep(200 * time.Millisecond) // let late exit callbacks finish
			if live, bad := h.liveBuffers(), h.badFrees(); live != 0 || bad != 0 {
				t.Fatalf("Swift buffers: %d never freed, %d bad frees", live, bad)
			}
		}},
	}
	testing.Main(func(pat, s string) (bool, error) { return regexp.MatchString(pat, s) }, tests, nil, nil)
	return 0 // not reached: testing.Main exits
}

//export NazarProcessExited
func NazarProcessExited(token C.uint64_t) { cbridge.ProcessExited(uint64(token)) }

//export NazarScreenLocked
func NazarScreenLocked(token C.uint64_t) { cbridge.ScreenLocked(uint64(token)) }

//export NazarProcessExecd
func NazarProcessExecd(token C.uint64_t, record *C.uint8_t, n C.size_t) {
	cbridge.ExecEvent(uint64(token), unsafe.Pointer(record), uint64(n))
}

func main() {}

// newEnv gives one subtest the platform and hooks over real processes.
func newEnv(t *testing.T, b *cbridge.Bridge, h hostHooks, mode int) conformance.Env {
	procs := &children{t: t}
	t.Cleanup(procs.killAll)
	env := conformance.Env{P: b, Spawn: procs.spawn, Exit: procs.exit, Peer: procs.peer,
		Exec: b.Exec(), Execer: procs.execer, Mounts: mounts.New(), Mount: mountScratch,
		Pipes: pipes.New(), Stdout: procs.stdout}
	if mode == modeSeamed {
		env.Answer = h.answer
	} else {
		env.SkipUserPresenceKeys = true
	}
	return env
}

// children starts and ends real processes for the suite: /bin/sleep for
// Spawn, /usr/bin/nc -U connected to a socket of ours for Peer.
type children struct {
	t     *testing.T
	mu    sync.Mutex
	cmds  map[int]*exec.Cmd
	close []func()
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
	cmd := c.start(exec.Command("/bin/sleep", "600"))
	return platform.ProcessRef{PID: cmd.Process.Pid, Generation: generation(c.t, cmd.Process.Pid)}
}

// execer starts NazarExecProbe (built next to this host by `swift build`)
// as the exec group's Execer: in "/", with exactly env, its
// command line the script probe probe probe /bin/sleep 600, so each line
// on its stdin makes it exec the rest of its argv.
func (c *children) execer(env []string) conformance.Execer {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(filepath.Join(filepath.Dir(exe), "NazarExecProbe"))
	}
	if err != nil {
		c.t.Fatalf("NazarExecProbe (make swift-build builds it next to this host): %v", err)
	}
	p := exe
	cmd := exec.Command(p, p, p, "/bin/sleep", "600")
	cmd.Env, cmd.Dir = env, "/"
	in, err := cmd.StdinPipe()
	if err != nil {
		c.t.Fatal(err)
	}
	c.start(cmd)
	c.mu.Lock()
	c.close = append(c.close, func() { in.Close() })
	c.mu.Unlock()
	steps := []conformance.Image{
		{Path: p, Args: []string{p, p, "/bin/sleep", "600"}},
		{Path: p, Args: []string{p, "/bin/sleep", "600"}},
		{Path: "/bin/sleep", Args: []string{"/bin/sleep", "600"}, Hidden: true},
	}
	return conformance.Execer{
		Ref: platform.ProcessRef{PID: cmd.Process.Pid, Generation: generation(c.t, cmd.Process.Pid)},
		Next: func() conformance.Image {
			s := steps[0]
			steps = steps[1:]
			in.Write([]byte("\n"))
			return s
		},
	}
}

// generation is the macOS ProcessRef generation: the start time in
// microseconds from sysctl KERN_PROC_PID (core/platform ProcessRef).
func generation(t *testing.T, pid int) uint64 {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		t.Fatalf("kinfo %d: %v", pid, err)
	}
	st := k.Proc.P_starttime
	return uint64(st.Sec)*1_000_000 + uint64(st.Usec)
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

func (c *children) peer() (int, int) {
	dir, err := os.MkdirTemp("/tmp", "nzcf") // short: sun_path is 104 bytes
	if err != nil {
		c.t.Fatal(err)
	}
	path := filepath.Join(dir, "p.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		c.t.Fatal(err)
	}
	nc := exec.Command("/usr/bin/nc", "-U", path)
	stdin, _ := nc.StdinPipe() // held open: nc stays connected until cleanup
	c.start(nc)
	l.SetDeadline(time.Now().Add(10 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		c.t.Fatalf("accept: %v", err)
	}
	f, err := conn.File()
	if err != nil {
		c.t.Fatal(err)
	}
	c.mu.Lock()
	c.close = append(c.close, func() { stdin.Close(); f.Close(); conn.Close(); l.Close(); os.RemoveAll(dir) })
	c.mu.Unlock()
	return int(f.Fd()), nc.Process.Pid
}

func (c *children) killAll() {
	c.mu.Lock()
	cmds, closers := c.cmds, c.close
	c.cmds, c.close = nil, nil
	c.mu.Unlock()
	for _, cmd := range cmds {
		cmd.Process.Kill()
		cmd.Wait()
	}
	for _, f := range closers {
		f()
	}
}
