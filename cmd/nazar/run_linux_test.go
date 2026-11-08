//go:build linux

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/control"
)

// On Linux, the reset nazar run makes before exec, read back from
// /proc by the exec'd program. macOS has its own reset and test
// (run_darwin_test.go).

// The real reset, in a child process that execs a probe which reports
// what it inherited from /proc (no shell in between: a shell resets its
// own signal mask). The child starts as a careless caller would: fds
// without close-on-exec, signals ignored and blocked, umask 077, core
// dumps allowed, in another folder.
func TestRunResetsTheProcessBeforeExec(t *testing.T) {
	for _, p := range []string{"cat", "ls", "pwd"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Skip(p + " not installed")
		}
	}
	h := newHarness(t)
	dev, ino := rootIdentity(t)
	var mu sync.Mutex // probe is read by the server's goroutine
	var probe []string
	h.serveRun(t, func() control.RunPlan {
		mu.Lock()
		probe := probe
		mu.Unlock()
		path, err := exec.LookPath(probe[0])
		if err == nil {
			path, err = filepath.EvalSymlinks(path)
		}
		if err != nil {
			t.Error(err)
		}
		return control.RunPlan{TypeMeta: control.Meta(control.KindRunPlan), ExecPath: path, ExecArgv: probe,
			Env: []string{"PATH=/usr/bin:/bin"}, Cwd: "/", CwdDev: dev, CwdIno: ino, Files: []control.RunFile{fileOf(t, path)}}
	}, nil)
	run := func(argv ...string) string {
		mu.Lock()
		probe = argv
		mu.Unlock()
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "NAZAR_TEST_RUN_CHILD="+h.env["NAZAR_CONTROL_SOCKET"], "NAZAR_TEST_RUN_DIR="+h.home)
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, b)
		}
		return string(b)
	}
	fields := map[string]string{}
	for _, l := range strings.Split(run("cat", "/proc/self/status", "/proc/self/limits"), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
		if strings.HasPrefix(l, "Max core file size") {
			fields["core"] = strings.Join(strings.Fields(l)[4:6], " ")
		}
	}
	var lim unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_CORE, &lim)
	want := map[string]string{"SigBlk": "0000000000000000", "SigIgn": "0000000000000000", "Umask": "0022", "core": "0 0"}
	if lim.Max == 0 {
		delete(want, "core") // nothing to reset from here
	}
	for k, want := range want {
		if fields[k] != want {
			t.Errorf("%s = %q, want %q", k, fields[k], want)
		}
	}
	if got := strings.Fields(run("ls", "/proc/self/fd")); !slices.Equal(got, []string{"0", "1", "2", "3"}) {
		t.Errorf("fds %q: only 0-2 (and ls's own 3) may reach the receiver", got)
	}
	if cwd := run("pwd", "-P"); strings.TrimSpace(cwd) != "/" {
		t.Errorf("cwd %q", cwd)
	}
}

// TestRunChild is the child of TestRunResetsTheProcessBeforeExec.
func TestRunChild(t *testing.T) {
	sock := os.Getenv("NAZAR_TEST_RUN_CHILD")
	if sock == "" {
		t.Skip("child of TestRunResetsTheProcessBeforeExec")
	}
	dir := os.Getenv("NAZAR_TEST_RUN_DIR")
	for i := 0; i < 3; i++ { // fds a careless caller leaves open across exec
		if _, err := unix.Open(filepath.Join(dir, "report"), unix.O_RDONLY|unix.O_CREAT, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ignoreSignals(unix.SIGTERM, unix.SIGPIPE, unix.SIGHUP, unix.SIGUSR2)
	// Signals Go's signal package never handles (glibc's 32 and 33, 34 =
	// SIGRTMIN): ignored through the kernel directly.
	for _, sig := range []unix.Signal{32, 33, 34} {
		rawIgnore(t, sig)
	}
	unix.Umask(0o077)
	var lim unix.Rlimit
	unix.Getrlimit(unix.RLIMIT_CORE, &lim)
	lim.Cur = lim.Max
	unix.Setrlimit(unix.RLIMIT_CORE, &lim)
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	blockSignalsOnThisThread(t, unix.SIGUSR1, unix.SIGWINCH)
	a := &app{stdout: os.Stdout, stderr: os.Stderr, getenv: func(k string) string {
		if k == "NAZAR_CONTROL_SOCKET" {
			return sock
		}
		return ""
	}, environ: os.Environ, exec: unix.Exec, verifier: control.SameUserVerifier{}, resetForExec: resetForExec}
	code := a.run([]string{"run", "--secret", "API_KEY", "--", "node", "x"})
	t.Fatalf("exec returned: exit %d", code) // unreachable on success
}

func ignoreSignals(sigs ...os.Signal) { signal.Ignore(sigs...) }

// blockSignalsOnThisThread blocks sigs on the calling goroutine's thread,
// which it locks for good: the CLI then runs, and execs, on it.
func blockSignalsOnThisThread(t *testing.T, sigs ...unix.Signal) {
	runtime.LockOSThread()
	var set unix.Sigset_t
	for _, s := range sigs {
		set.Val[(s-1)/64] |= 1 << ((s - 1) % 64)
	}
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &set, nil); err != nil {
		t.Fatal(err)
	}
}

// rawIgnore sets SIG_IGN on sig with rt_sigaction itself, past Go's
// signal package.
func rawIgnore(t *testing.T, sig unix.Signal) {
	act := [4]uint64{1} // sa_handler = SIG_IGN, no flags, empty mask
	if _, _, e := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(sig), uintptr(unsafe.Pointer(&act)), 0, 8, 0, 0); e != 0 {
		t.Fatal(e)
	}
}
