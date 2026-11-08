//go:build darwin && cgo

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/control"
)

// nazar run's reset on macOS (runreset_darwin.go), read back from
// inside the program it execs. testdata/runprobe.c is the careless caller
// (`spawn`), a plain execve with the task's exception port put on the
// exec thread too (`exec`) and the probe (`report`).
// The CLI is the real binary, signed as `make agent` signs it (ad hoc, the
// hardened runtime), talking to this test's stub agent: the plan it gets
// execs `<image> report`, for an ad-hoc and a hardened image.

// compileProbe builds testdata/runprobe.c into dir (clang signs it ad hoc).
func compileProbe(t *testing.T, dir string) string {
	t.Helper()
	bin := filepath.Join(dir, "runprobe")
	if out, err := exec.Command("cc", "-Wall", "-Werror", "-o", bin, "testdata/runprobe.c").CombinedOutput(); err != nil {
		t.Fatalf("cc: %v\n%s", err, out)
	}
	real, err := filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

// signHardened signs bin ad hoc with the hardened runtime (never a real
// identity).
func signHardened(t *testing.T, bin string, args ...string) {
	t.Helper()
	argv := append(append([]string{"--force", "--sign", "-", "--options", "runtime"}, args...), bin)
	if out, err := exec.Command("/usr/bin/codesign", argv...).CombinedOutput(); err != nil {
		t.Fatalf("codesign: %v\n%s", err, out)
	}
}

// probeReport runs argv in dir and returns the probe's key=value lines.
func probeReport(t *testing.T, dir string, env []string, argv ...string) map[string]string {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = dir, env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	r := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			r[k] = v
		}
	}
	if _, ok := r["cwd"]; err != nil || !ok {
		t.Fatalf("%q: %v\n%s%s", argv, err, out, stderr.String())
	}
	return r
}

// sigList is "1,2,…" for the signals below 32 that keep(sig) accepts.
func sigList(keep func(unix.Signal) bool) string {
	var l []string
	for s := unix.Signal(1); s < 32; s++ {
		if keep(s) {
			l = append(l, strconv.Itoa(int(s)))
		}
	}
	return strings.Join(l, ",")
}

func TestRunResetsTheProcessBeforeExecOnMacOS(t *testing.T) {
	h := newHarness(t)
	nazar := buildNazar(t, h.home)
	signHardened(t, nazar, "--identifier", "dev.nazar.cli") // as make agent signs it
	probe := compileProbe(t, h.home)
	hardened := filepath.Join(filepath.Dir(probe), "runprobe-hardened")
	b, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hardened, b, 0o755); err != nil {
		t.Fatal(err)
	}
	signHardened(t, hardened)
	dev, ino := rootIdentity(t)
	var mu sync.Mutex // plan is read by the server's goroutine
	var plan control.RunPlan
	h.serveRun(t, func() control.RunPlan {
		mu.Lock()
		defer mu.Unlock()
		return plan
	}, nil)
	env := []string{"HOME=" + h.home, "PATH=/usr/bin:/bin", "NAZAR_CONTROL_SOCKET=" + h.env["NAZAR_CONTROL_SOCKET"], "NAZAR_TEST_PEER=same-user"}
	ignored := sigList(func(s unix.Signal) bool { return s != unix.SIGKILL && s != unix.SIGSTOP && s != unix.SIGCHLD })
	var mask uint32
	for _, s := range []unix.Signal{unix.SIGHUP, unix.SIGINT, unix.SIGPIPE, unix.SIGALRM, unix.SIGTERM, unix.SIGUSR1, unix.SIGUSR2, unix.SIGWINCH} {
		mask |= 1 << (s - 1)
	}
	for _, img := range []string{probe, hardened} {
		t.Run(filepath.Base(img), func(t *testing.T) {
			f := fileOf(t, img)
			mu.Lock()
			plan = control.RunPlan{TypeMeta: control.Meta(control.KindRunPlan), ExecPath: img, ExecArgv: []string{img, "report"},
				Env: []string{"PATH=/usr/bin:/bin"}, Cwd: "/", CwdDev: dev, CwdIno: ino, Files: []control.RunFile{f}}
			mu.Unlock()

			// The control: a plain execve hands the careless state on.
			before := probeReport(t, h.home, env, probe, "spawn", probe, "exec", img, "report")
			if before["blocked"] != fmt.Sprintf("%08x", mask) || before["ignored"] != ignored || before["umask"] != "077" ||
				!slices.Contains(strings.Split(before["fds"], ","), "100") || before["cwd"] == "/" {
				t.Fatalf("the careless caller's state did not reach the program: %q", before)
			}
			// Spike S14: what a plain execve passes on (measured on macOS 27:
			// the task port into both images, the thread port into neither).
			t.Logf("plain execve into %s: taskports=%s threadports=%s; nazar run must leave none", filepath.Base(img), before["taskports"], before["threadports"])

			// The CLI is exec'd the same way: a thread port, if a later macOS
			// kept it across execve, would be on the CLI's first thread.
			got := probeReport(t, h.home, env, probe, "spawn", probe, "exec", nazar, "run", "--secret", "API_KEY", "--", "node", "x")
			want := map[string]string{"fds": "0,1,2", "blocked": "00000000", "ignored": "", "umask": "022", "core": "0/0",
				"taskports": "0", "threadports": "0", "cwd": "/"}
			for k, w := range want {
				if g, ok := got[k]; !ok || g != w {
					t.Errorf("%s = %q, want %q (before nazar run: %q)", k, g, w, before[k])
				}
			}
		})
	}
	if n := len(h.requests()); n != 2 {
		t.Errorf("%d secret.run requests, want one per image", n)
	}
}

// A macOS build without cgo has no reset (runreset_darwin_nocgo.go): its
// nazar run refuses before it asks nazar-agent anything. The guard that
// replaces the stub's: TestRunWithoutTheResetRefuses checks the same of a
// nil reset inside the test binary.
func TestRunWithoutCgoRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	h := newHarness(t)
	bin := filepath.Join(h.home, "nazar-nocgo")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	h.serveRun(t, func() control.RunPlan { t.Error("no request expected"); return control.RunPlan{} }, nil)
	cmd := exec.Command(bin, "run", "--secret", "API_KEY", "--", "node", "x")
	cmd.Env = []string{"HOME=" + h.home, "PATH=/usr/bin:/bin", "NAZAR_CONTROL_SOCKET=" + h.env["NAZAR_CONTROL_SOCKET"], "NAZAR_TEST_PEER=same-user"}
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != control.ExitError || !strings.Contains(string(out), "run: not available in this build yet") {
		t.Fatalf("err %v, output %q", err, out)
	}
	if n := len(h.requests()); n != 0 {
		t.Fatalf("%d requests: a CLI that can't exec must not ask the agent", n)
	}
}
