//go:build linux

// Package dbustest starts a private dbus-daemon for one test, where the
// test may own any name (org.freedesktop.login1, org.freedesktop.Notifications)
// to stand in for logind or a notification server. No test talks to the
// host's system or session bus. Test-only code; nothing in it ships.
package dbustest

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startTimeout bounds how long dbus-daemon may take to listen.
const startTimeout = 10 * time.Second

// ConfigFile is test/linux/dbus-private.conf in this source tree.
func ConfigFile() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "test", "linux", "dbus-private.conf")
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}

// Start runs a private dbus-daemon with test/linux/dbus-private.conf,
// listening on a socket in t.TempDir(), and returns its address. It is
// stopped at cleanup.
func Start(t testing.TB) (address string) {
	t.Helper()
	conf, err := ConfigFile()
	if err != nil {
		t.Fatalf("dbustest: the bus configuration test/linux/dbus-private.conf: %v", err)
	}
	dir := t.TempDir()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("dbustest: %v", err)
	}
	defer r.Close()
	cmd := exec.Command("dbus-daemon",
		"--config-file="+conf,
		"--address=unix:path="+filepath.Join(dir, "bus"),
		"--nofork", "--nopidfile", "--nosyslog", "--print-address=1")
	// Read only once Wait has returned: exec copies into it until then.
	var stderr bytes.Buffer
	cmd.Stdout = w
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = cmd.Start()
	w.Close()
	if err != nil {
		t.Fatalf("dbustest: dbus-daemon: %v", err)
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

	// dbus-daemon prints the address once it listens.
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(r).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	select {
	case address = <-line:
		if address != "" {
			return address
		}
		stop()
		t.Fatalf("dbustest: dbus-daemon printed no address (%v): %s", waitErr, stderr.String())
	case <-time.After(startTimeout):
		stop()
		t.Fatalf("dbustest: dbus-daemon did not listen within %v: %s", startTimeout, stderr.String())
	}
	return ""
}
