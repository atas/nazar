package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/control"
)

// followRole makes this test binary one of the processes of
// TestFollowEndsWithItsParent: "parent" starts the follow command and
// exits when its stdin closes; "child" is the follow command.
const followRole = "NAZAR_TEST_FOLLOW_ROLE"

// A --follow stream ends (exit 0, nothing more printed) as soon as the
// process that started it is gone, though no event ever comes to write:
// Nazar UI.app quitting, or killed, must never leave `nazar status
// --follow` or `nazar log --follow` running for ever under launchd.
func TestFollowEndsWithItsParent(t *testing.T) {
	switch os.Getenv(followRole) {
	case "parent":
		followParent()
	case "child":
		followChild(t)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"status", "log"} {
		t.Run(cmd, func(t *testing.T) {
			outR, outW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer outR.Close()
			errR, errW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer errR.Close()
			p := exec.Command(exe, "-test.run=^TestFollowEndsWithItsParent$")
			// Under -race a process sleeps 1s before it exits
			// (atexit_sleep_ms): the bound is for the CLI, not for that.
			p.Env = append(os.Environ(), followRole+"=parent", "NAZAR_TEST_FOLLOW_CMD="+cmd,
				"GORACE="+os.Getenv("GORACE")+" atexit_sleep_ms=0")
			p.Stdout, p.Stderr = outW, errW
			stdin, err := p.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			outW.Close()
			errW.Close()
			errs := bufio.NewReader(errR)
			errR.SetReadDeadline(time.Now().Add(10 * time.Second))
			first, err := errs.ReadString('\n')
			pid, perr := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(first), "child "))
			if err != nil || perr != nil {
				stdin.Close()
				p.Wait()
				t.Fatalf("parent did not start the follow command: %q %v", first, err)
			}
			// The child holds the pipes until it exits: a failure kills it,
			// never leaving it behind as the bug did (SIGTERM, so it cleans up).
			alive := true
			defer func() {
				if alive {
					syscall.Kill(pid, syscall.SIGTERM)
				}
			}()
			out := bufio.NewReader(outR)
			outR.SetReadDeadline(time.Now().Add(10 * time.Second))
			if l, err := out.ReadString('\n'); err != nil {
				t.Fatalf("the follow command printed nothing: %q %v", l, err)
			}
			// The stream is running; its parent now exits.
			stdin.Close()
			if err := p.Wait(); err != nil {
				t.Fatalf("parent: %v", err)
			}
			deadline := time.Now().Add(2 * time.Second)
			outR.SetReadDeadline(deadline)
			errR.SetReadDeadline(deadline)
			rest, err := io.ReadAll(out)
			if err != nil {
				t.Fatalf("nazar --json %s --follow still runs 2s after its parent exited (%v)", cmd, err)
			}
			tail, err := io.ReadAll(errs)
			if err != nil {
				t.Fatalf("stderr: %v", err)
			}
			alive = false
			if len(rest) != 0 {
				t.Errorf("printed after its parent exited: %q", rest)
			}
			if strings.TrimSpace(string(tail)) != "exit 0" {
				t.Errorf("ended with %q, want exit 0", tail)
			}
		})
	}
}

// followParent starts the follow command with this process's stdout and
// stderr, says its pid, and exits (without waiting for it) once stdin
// closes.
func followParent() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}
	c := exec.Command(exe, "-test.run=^TestFollowEndsWithItsParent$")
	c.Env = append(os.Environ(), followRole+"=child")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "child %d\n", c.Process.Pid)
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// followChild runs `nazar --json <cmd> --follow` against a stub agent
// whose stream (or a log whose `log stream`) sends one line and then
// nothing, and reports its exit code on stderr.
func followChild(t *testing.T) {
	h := newHarness(t)
	h.a.stdout = os.Stdout
	h.serve(t, func(ctx context.Context, _ control.Request, out control.Emitter) {
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus)})
		<-ctx.Done()
	})
	h.a.runLog = func(ctx context.Context, _ []string, _ func([]byte)) error {
		fmt.Fprintln(os.Stdout, `{"started":true}`)
		<-ctx.Done()
		return nil
	}
	code := h.a.run([]string{"--json", os.Getenv("NAZAR_TEST_FOLLOW_CMD"), "--follow"})
	os.RemoveAll(h.home)
	fmt.Fprintf(os.Stderr, "exit %d\n", code)
	os.Exit(0)
}
