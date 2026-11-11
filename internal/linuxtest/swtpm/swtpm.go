//go:build linux

// Package swtpm starts a software TPM 2.0 for one test, so no test ever
// opens /dev/tpm0 or /dev/tpmrm0. The swtpm program is in the Linux test
// image (test/linux). Test-only code; nothing in it ships.
package swtpm

import (
	"bytes"
	"net"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// startTimeout bounds how long swtpm may take to listen.
const startTimeout = 10 * time.Second

// Start runs its own swtpm with its state in t.TempDir() and returns the
// path of its TPM command socket (raw TPM 2.0 commands; TPM2_Startup is
// done). It is stopped at cleanup. Each call is a fresh TPM.
func Start(t testing.TB) (socket string) {
	t.Helper()
	dir := t.TempDir()
	socket = filepath.Join(dir, "tpm.sock")
	ctrl := filepath.Join(dir, "ctrl.sock")
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+socket,
		"--ctrl", "type=unixio,path="+ctrl,
		"--flags", "not-need-init,startup-clear")
	// Read only once Wait has returned: exec copies into it until then.
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// Its own process group, so a terminal's signals reach the test, not it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("swtpm: %v", err)
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	stop := func() {
		select {
		case <-exited:
			return
		default:
		}
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-exited
		}
	}
	t.Cleanup(stop)

	deadline := time.Now().Add(startTimeout)
	for {
		select {
		case <-exited:
			t.Fatalf("swtpm exited before it listened (%v): %s", waitErr, out.String())
		default:
		}
		if c, err := net.Dial("unix", socket); err == nil {
			c.Close()
			return socket
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("swtpm did not listen on %s within %v: %s", socket, startTimeout, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
