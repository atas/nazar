//go:build linux

package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/peertrust"
)

// startControlChild runs the test binary as a stub control server on the
// harness's control socket (controlchild_test.go) and waits until it
// listens. Its image is this test binary: never the one a record made for
// another file names.
func startControlChild(t *testing.T, h *harness) {
	t.Helper()
	startControlChildAt(t, h.env["NAZAR_CONTROL_SOCKET"])
}

// startControlChildAt is startControlChild on the socket sock.
func startControlChildAt(t *testing.T, sock string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), controlChildEnv+"="+sock)
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
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ok" {
		t.Fatalf("control child: %q, %v", line, err)
	}
}

// childRequests is what the stub server in the child was sent.
func childRequests(t *testing.T, h *harness) string {
	t.Helper()
	return childRequestsAt(t, h.env["NAZAR_CONTROL_SOCKET"])
}

// childRequestsAt is childRequests for the child on the socket sock.
func childRequestsAt(t *testing.T, sock string) string {
	t.Helper()
	data, err := os.ReadFile(controlChildRequests(sock))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(data)
}

// otherBinary is a file that is not the child's image: a tiny script.
func otherBinary(t *testing.T, h *harness) string {
	t.Helper()
	p := filepath.Join(h.home, "other")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// recordBinaries writes a record naming cli and agent in the harness's home.
func recordBinaries(t *testing.T, h *harness, cli, agent string) {
	t.Helper()
	recordBinariesIn(t, h.home, cli, agent)
}

// recordBinariesIn writes a record naming cli and agent in home.
func recordBinariesIn(t *testing.T, home, cli, agent string) {
	t.Helper()
	ch, err := peertrust.HashFile(cli)
	if err != nil {
		t.Fatal(err)
	}
	ah, err := peertrust.HashFile(agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := peertrust.Write(home, peertrust.Record{CLI: peertrust.Binary{Path: cli, SHA256: ch}, Agent: peertrust.Binary{Path: agent, SHA256: ah}}); err != nil {
		t.Fatal(err)
	}
}

// On Linux, with no verifier set (what main() does), the CLI checks the
// control socket's peer against the agent `nazar install` recorded. A
// server whose image is not that agent (nazar upgraded without a new
// `nazar install`, or an impostor) is refused with the message that names
// the fix, every control command exits 1, and nothing is sent to it.
func TestLinuxCLIRefusesUnrecordedAgent(t *testing.T) {
	h := linuxHarness(t)
	h.a.verifier = nil
	startControlChild(t, h)
	recordBinaries(t, h, otherBinary(t, h), otherBinary(t, h))
	for _, args := range [][]string{
		{"status"}, {"ssh-key", "list"}, {"ssh-key", "create", "work"}, {"revoke", "--all"}, {"config", "apply"}, {"trust", "--app", "code"},
	} {
		code := h.run(args...)
		if code != control.ExitError {
			t.Errorf("%v: exit %d, want %d; stderr %q", args, code, control.ExitError, h.errb)
		}
		if !strings.Contains(h.errb.String(), peertrust.ErrAgentMismatch.Error()) || !strings.Contains(h.errb.String(), "not nazar-agent") {
			t.Errorf("%v: stderr %q, want the mismatch message", args, h.errb)
		}
	}
	if got := childRequests(t, h); got != "" {
		t.Fatalf("requests reached an unverified peer: %q", got)
	}
	// --json: the same refusal as one Problem on stdout.
	if code := h.run("--json", "status"); code != control.ExitError {
		t.Fatalf("--json: exit %d %q", code, h.errb)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindProblem {
		t.Fatalf("--json stdout %q", h.out)
	}
	if msg, _ := objs[0]["message"].(string); !strings.Contains(msg, peertrust.ErrAgentMismatch.Error()) {
		t.Fatalf("--json problem message %q", msg)
	}
	if got := childRequests(t, h); got != "" {
		t.Fatalf("requests reached an unverified peer: %q", got)
	}
}

// With no record at all (nazar install never ran), the CLI refuses with
// ErrNotInstalled's words and sends nothing.
func TestLinuxCLIRefusesWithoutRecord(t *testing.T) {
	h := linuxHarness(t)
	h.a.verifier = nil
	startControlChild(t, h)
	if code := h.run("status"); code != control.ExitError || !strings.Contains(h.errb.String(), peertrust.ErrNotInstalled.Error()) {
		t.Fatalf("exit %d, stderr %q", code, h.errb)
	}
	if got := childRequests(t, h); got != "" {
		t.Fatalf("requests reached an unverified peer: %q", got)
	}
}

// A record that names the server's image is accepted and the request
// goes through. The record is read on every run: one that no longer
// names the server refuses the next run.
func TestLinuxCLIAcceptsRecordedAgent(t *testing.T) {
	h := linuxHarness(t)
	h.a.verifier = nil
	startControlChild(t, h)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	recordBinaries(t, h, self, self) // the test binary is this CLI and the child's image
	if code := h.run("status"); code != 0 {
		t.Fatalf("the recorded agent was refused: exit %d %q", code, h.errb)
	}
	if got := childRequests(t, h); !strings.Contains(got, control.CmdStatus) {
		t.Fatalf("child saw %q", got)
	}
	recordBinaries(t, h, otherBinary(t, h), otherBinary(t, h))
	if code := h.run("status"); code != control.ExitError || !strings.Contains(h.errb.String(), peertrust.ErrAgentMismatch.Error()) {
		t.Fatalf("after the record changed: exit %d %q", code, h.errb)
	}
}

// NAZAR_TEST_PEER=same-user drops the hash check on Linux as it drops the
// signature check on macOS, with the same warning: the integration suite
// runs a test daemon that is not nazar-agent there too.
func TestLinuxTestPeerOverride(t *testing.T) {
	h := linuxHarness(t)
	h.a.verifier = nil
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("status"); code == 0 {
		t.Fatalf("an unrecorded peer was accepted: %q", h.out)
	}
	h.env["NAZAR_TEST_PEER"] = "same-user"
	if code := h.run("status"); code != 0 || !strings.Contains(h.errb.String(), "NAZAR_TEST_PEER=same-user") {
		t.Fatalf("override: exit %d, stderr %q", code, h.errb)
	}
}

// A package upgrade replaced both binaries and the old agent still runs:
// the agent matches the record, this CLI does not, and the agent would
// refuse it with a reason only its log sees. The CLI says what to do,
// exits 1 (not the 3 of a user's decision) and sends nothing. A re-run
// `nazar install` applies at once.
func TestLinuxUpgradedCLINamesInstall(t *testing.T) {
	h := linuxHarness(t)
	h.a.verifier = nil
	startControlChild(t, h)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	recordBinaries(t, h, otherBinary(t, h), self)
	for _, args := range [][]string{{"status"}, {"ssh-key", "list"}, {"get", "API"}} {
		code := h.run(args...)
		if code != control.ExitError {
			t.Errorf("%v: exit %d, want %d; stderr %q", args, code, control.ExitError, h.errb)
		}
		if got := h.errb.String(); !strings.Contains(got, peertrust.ErrSelfMismatch.Error()) || strings.Contains(got, "not nazar-agent") {
			t.Errorf("%v: stderr %q, want the self mismatch and nothing about the agent", args, got)
		}
	}
	if got := childRequests(t, h); got != "" {
		t.Fatalf("requests were sent: %q", got)
	}
	recordBinaries(t, h, self, self)
	if code := h.run("status"); code != 0 {
		t.Fatalf("after nazar install: exit %d %q", code, h.errb)
	}
}

// credentialCommands are the two commands whose environment a kubeconfig
// or an AWS profile writes, and the request each sends.
var credentialCommands = []struct {
	args []string
	cmd  string
}{
	{[]string{"k8s", "credential", "prod"}, control.CmdK8sCredential},
	{[]string{"aws", "credential", "prod"}, control.CmdAWSCredential},
}

// credentialHarness is a Linux CLI with no verifier set and a stub control
// server, whose image is this test binary, on the socket in the user
// database's home. It returns that socket and a second folder, for $HOME
// to name.
func credentialHarness(t *testing.T) (h *harness, sock, forged string) {
	t.Helper()
	h = linuxHarness(t)
	h.a.verifier = nil
	h.env["KUBERNETES_EXEC_INFO"] = execInfoJSON
	sock = layout.ControlSocket(h.home)
	startControlChildAt(t, sock)
	return h, sock, tmpHome(t)
}

// tmpHome is a short folder of its own, not the harness's.
func tmpHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzhome")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// The environment of k8s credential and aws credential is attacker-writable,
// so $HOME must not choose which hash is trusted: the account's record does
// not name the listener, a forged one in $HOME does, and nothing is sent.
func TestLinuxCredentialIgnoresForgedHomeRecord(t *testing.T) {
	h, sock, forged := credentialHarness(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	recordBinaries(t, h, self, otherBinary(t, h))
	recordBinariesIn(t, forged, self, self)
	h.env["HOME"] = forged
	for _, c := range credentialCommands {
		if code := h.run(c.args...); code != control.ExitError || !strings.Contains(h.errb.String(), peertrust.ErrAgentMismatch.Error()) {
			t.Errorf("%v: exit %d, stderr %q", c.args, code, h.errb)
		}
	}
	if got := childRequestsAt(t, sock); got != "" {
		t.Fatalf("a request reached a listener only the forged record names: %q", got)
	}
}

// The same holds for the CLI's check of itself: $HOME can not vouch for a
// CLI the account's record does not name.
func TestLinuxCredentialSelfCheckIgnoresForgedHomeRecord(t *testing.T) {
	h, sock, forged := credentialHarness(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	recordBinaries(t, h, otherBinary(t, h), self)
	recordBinariesIn(t, forged, self, self)
	h.env["HOME"] = forged
	for _, c := range credentialCommands {
		if code := h.run(c.args...); code != control.ExitError || !strings.Contains(h.errb.String(), peertrust.ErrSelfMismatch.Error()) {
			t.Errorf("%v: exit %d, stderr %q", c.args, code, h.errb)
		}
	}
	if got := childRequestsAt(t, sock); got != "" {
		t.Fatalf("requests were sent: %q", got)
	}
}

// And a genuine run is not hurt by what its environment says: the account's
// record names the listener, $HOME holds another record, none, or is unset.
func TestLinuxCredentialUsesAccountRecord(t *testing.T) {
	h, sock, forged := credentialHarness(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	recordBinaries(t, h, self, self)
	recordBinariesIn(t, forged, otherBinary(t, h), otherBinary(t, h))
	empty := tmpHome(t)
	sent := 0
	for _, home := range []string{forged, empty, ""} {
		h.env["HOME"] = home
		for _, c := range credentialCommands {
			h.run(c.args...)
			sent++
			if got := childRequestsAt(t, sock); strings.Count(got, "\n") != sent || !strings.HasSuffix(got, c.cmd+"\n") {
				t.Fatalf("HOME=%q %v: child saw %q; stderr %q", home, c.args, got, h.errb)
			}
		}
	}
}
