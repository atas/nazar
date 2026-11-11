//go:build linux && linuxplatform

package main

// The release build against a machine with no TPM device. It runs only in
// the test image (container.Require): the test starts the real release
// binary, which opens /dev/tpmrm0, and the image is the one place known to
// have no such device, so a real TPM is never touched. A TPM-equipped
// machine is refused, not skipped: the test must never pass by running
// nothing, and must never let the binary reach a real device.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/swtpm"
)

func TestMain(m *testing.M) { os.Exit(container.Require(m)) }

// Without /dev/tpmrm0 the release build ends at once with exit 1 and the
// one line that says what to run, and the NAZAR_TEST_* variables of the
// nazartest build change nothing: a running swtpm and a temp home are
// offered through them, and the binary still goes for the device.
func TestAgentWithoutTPMExplains(t *testing.T) {
	if _, err := os.Stat(tpmDevice); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s is present (%v): this test runs only where there is no TPM device", tpmDevice, err)
	}
	dir, err := os.MkdirTemp("/tmp", "nzag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(dir, "nazar-agent")
	build := exec.Command("go", "build", "-o", agent, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the release nazar-agent: %v\n%s", err, out)
	}

	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(agent)
	cmd.Env = []string{
		"HOME=" + home, "PATH=/usr/bin:/bin",
		"NAZAR_TEST_HOME=" + home,
		"NAZAR_TEST_SWTPM=" + swtpm.Start(t),
		"NAZAR_TEST_LOGIND_BUS=unix:path=" + filepath.Join(dir, "nobus"),
		"NAZAR_TEST_SESSION_BUS=unix:path=" + filepath.Join(dir, "nobus"),
		"NAZAR_TEST_DIALOG=" + filepath.Join(dir, "nodialog"),
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("nazar-agent: %v, want exit 1\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	got := strings.TrimSuffix(stderr.String(), "\n")
	wantPrefix := "nazar-agent: can't open " + tpmDevice + ": "
	wantSuffix := fmt.Sprintf("; run once, then log out and back in: sudo %s install --system", filepath.Join(dir, "nazar"))
	if !strings.HasPrefix(got, wantPrefix) || !strings.HasSuffix(got, wantSuffix) || strings.Count(got, "\n") != 0 {
		t.Fatalf("stderr %q\nwant one line %q…%q", got, wantPrefix, wantSuffix)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout %q, want nothing", stdout.String())
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("the agent wrote %v into the test home it was offered: the release build must ignore NAZAR_TEST_HOME", entries)
	}
}
