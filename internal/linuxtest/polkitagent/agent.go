//go:build linux

// Package polkitagent is a polkit authentication agent for the Linux
// platform tests: the desktop's agent, played by the test. It registers
// on the container's system bus for one subject and answers polkit's
// prompts from the answers queue the way a person would: an allow runs
// polkit's own setuid helper with the test user's password, so polkitd
// sees a real PAM authentication; a deny, or no answer in time, cancels
// the prompt. Test-only code; nothing in it ships. It must never be
// registered on a real desktop's bus: the test image is the only place
// it runs (internal/linuxtest/container).
package polkitagent

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/internal/linuxtest/answers"
)

const (
	authorityName = "org.freedesktop.PolicyKit1"
	authorityPath = dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority")
	authorityIfc  = "org.freedesktop.PolicyKit1.Authority"
	agentIface    = "org.freedesktop.PolicyKit1.AuthenticationAgent"
	// agentPath is passed as a string: polkit's interface types the
	// agent's object path `s`, not `o`.
	agentPath    = dbus.ObjectPath("/dev/nazar/test/PolkitAgent")
	errCancelled = "org.freedesktop.PolicyKit1.Error.Cancelled"

	// helper is polkit's setuid PAM helper (Debian's polkitd package). It
	// reads the cookie and the PAM answers on stdin and reports the
	// authentication to polkitd itself.
	helper = "/usr/lib/polkit-1/polkit-agent-helper-1"

	// answerWait is how long a prompt waits for the test's answer before
	// the agent cancels it, as a person who walked away would.
	answerWait = 10 * time.Second
	// pollSlice is how often a waiting prompt checks for a cancellation.
	pollSlice = 100 * time.Millisecond
	// helperWait bounds one PAM authentication.
	helperWait = 30 * time.Second
)

// Agent is the registered test agent.
type Agent struct {
	t        testing.TB
	user     string
	password string
	q        *answers.Queue

	mu        sync.Mutex
	messages  []string
	cancelled int
	prompts   map[string]chan struct{} // cookie: closed by CancelAuthentication
}

// Register exports the agent on system and registers it with polkit for
// subject. An allow from q authenticates as user with password; it is
// unregistered at cleanup.
func Register(t testing.TB, system *dbus.Conn, subject polkit.Subject, user, password string, q *answers.Queue) *Agent {
	t.Helper()
	a := &Agent{t: t, user: user, password: password, q: q, prompts: map[string]chan struct{}{}}
	if err := system.Export(a, agentPath, agentIface); err != nil {
		t.Fatalf("polkitagent: export: %v", err)
	}
	authority := system.Object(authorityName, authorityPath)
	if err := authority.Call(authorityIfc+".RegisterAuthenticationAgent", 0, subject, "C", string(agentPath)).Err; err != nil {
		system.Export(nil, agentPath, agentIface)
		t.Fatalf("polkitagent: RegisterAuthenticationAgent: %v", err)
	}
	t.Cleanup(func() {
		authority.Call(authorityIfc+".UnregisterAuthenticationAgent", 0, subject, string(agentPath))
		system.Export(nil, agentPath, agentIface)
	})
	return a
}

// Messages is the message of every BeginAuthentication, in order.
func (a *Agent) Messages() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.messages...)
}

// Cancelled is how many CancelAuthentication calls polkit made.
func (a *Agent) Cancelled() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cancelled
}

func cancelledError() *dbus.Error {
	return dbus.NewError(errCancelled, []any{"the test user cancelled"})
}

// BeginAuthentication is polkit's prompt. It returns once the user
// answered: nil after a successful authentication (the helper has told
// polkitd), Cancelled on a deny, no answer in answerWait, or a
// CancelAuthentication for the cookie.
func (a *Agent) BeginAuthentication(actionID, message, iconName string, details map[string]string, cookie string, identities []polkit.Subject) *dbus.Error {
	cancel := make(chan struct{})
	a.mu.Lock()
	a.messages = append(a.messages, message)
	a.prompts[cookie] = cancel
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.prompts, cookie)
		a.mu.Unlock()
	}()

	deadline := time.Now().Add(answerWait)
	for {
		select {
		case <-cancel:
			return cancelledError()
		default:
		}
		allow, ok := a.q.Pop(pollSlice)
		if ok {
			if !allow {
				return cancelledError()
			}
			if err := a.authenticate(cookie); err != nil {
				a.t.Errorf("polkitagent: %v", err)
				return dbus.NewError("org.freedesktop.PolicyKit1.Error.Failed", []any{err.Error()})
			}
			return nil
		}
		if time.Now().After(deadline) {
			return cancelledError()
		}
	}
}

// CancelAuthentication is polkit closing the prompt for cookie.
func (a *Agent) CancelAuthentication(cookie string) *dbus.Error {
	a.mu.Lock()
	a.cancelled++
	ch, ok := a.prompts[cookie]
	if ok {
		delete(a.prompts, cookie)
		close(ch)
	}
	a.mu.Unlock()
	return nil
}

// authenticate runs polkit's helper for the cookie and answers PAM's
// prompts with the password. The helper's protocol is one line each way
// on its stdin and stdout: the cookie first, then "PAM_PROMPT_ECHO_OFF
// <text>" or "PAM_PROMPT_ECHO_ON <text>" wants an answer, "PAM_ERROR_MSG
// <text>" and "PAM_TEXT_INFO <text>" do not, and "SUCCESS" or "FAILURE"
// ends it. On success the helper reports to polkitd before it exits, so
// waiting for its exit is waiting for polkitd to know.
func (a *Agent) authenticate(cookie string) error {
	cmd := exec.Command(helper, a.user)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", helper, err)
	}
	done := make(chan error, 1)
	go func() { done <- a.converse(stdin, stdout, cookie) }()

	var convErr error
	select {
	case convErr = <-done:
	case <-time.After(helperWait):
		cmd.Process.Kill()
		convErr = fmt.Errorf("the helper did not finish in %v", helperWait)
	}
	waitErr := cmd.Wait()
	if convErr != nil {
		return fmt.Errorf("%s: %v (stderr: %q)", helper, convErr, stderr.String())
	}
	if waitErr != nil {
		return fmt.Errorf("%s: %v (stderr: %q)", helper, waitErr, stderr.String())
	}
	return nil
}

func (a *Agent) converse(stdin io.WriteCloser, stdout io.Reader, cookie string) error {
	defer stdin.Close()
	if _, err := fmt.Fprintf(stdin, "%s\n", cookie); err != nil {
		return fmt.Errorf("write cookie: %w", err)
	}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		line := lines.Text()
		switch {
		case strings.HasPrefix(line, "PAM_PROMPT_ECHO_OFF "), strings.HasPrefix(line, "PAM_PROMPT_ECHO_ON "):
			if _, err := fmt.Fprintf(stdin, "%s\n", a.password); err != nil {
				return fmt.Errorf("write password: %w", err)
			}
		case line == "SUCCESS":
			return nil
		case line == "FAILURE":
			return fmt.Errorf("PAM refused user %q", a.user)
		}
	}
	if err := lines.Err(); err != nil {
		return err
	}
	return fmt.Errorf("the helper ended without SUCCESS or FAILURE")
}
