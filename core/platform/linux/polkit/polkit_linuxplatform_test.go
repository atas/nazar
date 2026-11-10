//go:build linux && linuxplatform

// The login gate against the container's own polkitd (test/linux): a test
// polkit agent registered for this process answers the prompt from the
// answers queue, the way a person would, with the test user's password
// through PAM. Nothing here reaches the host's polkit, buses or TPM.
package polkit_test

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/internal/linuxtest/answers"
	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/polkitagent"
)

// The test image's user (test/linux/Dockerfile).
const (
	testUser     = "nazartest"
	testPassword = "nazar-test-password"
)

func TestMain(m *testing.M) { os.Exit(container.Require(m)) }

func systemBus(t *testing.T) *dbus.Conn {
	t.Helper()
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatalf("system bus: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// selfSubject is this test process, as polkit identifies it.
func selfSubject(t *testing.T) polkit.Subject {
	t.Helper()
	st, err := procfs.ReadStat(os.Getpid())
	if err != nil {
		t.Fatalf("own stat: %v", err)
	}
	return polkit.ProcessSubject(os.Getpid(), st.StartTicks, os.Getuid())
}

// gate is an Authority for this process with the test agent answering
// for it from q.
func gate(t *testing.T) (*polkit.Authority, *polkitagent.Agent, *answers.Queue) {
	t.Helper()
	conn := systemBus(t)
	subject := selfSubject(t)
	q := answers.NewQueue(t)
	agent := polkitagent.Register(t, conn, subject, testUser, testPassword, q)
	auth := polkit.New(conn, func() (polkit.Subject, error) { return subject, nil })
	return auth, agent, q
}

func prompt(timeout time.Duration) platform.Prompt {
	return platform.Prompt{
		Title:   `iTerm2 wants to use key "github"`,
		Lines:   []string{"git push origin main", "app: iTerm2 (com.googlecode.iterm2)"},
		Timeout: timeout,
	}
}

func TestAllowed(t *testing.T) {
	auth, _, q := gate(t)
	q.Push(true)
	if err := auth.Check(prompt(30 * time.Second)); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
}

func TestCancelled(t *testing.T) {
	auth, _, q := gate(t)
	q.Push(false)
	err := auth.Check(prompt(30 * time.Second))
	if !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Check = %v, want ErrDenied", err)
	}
}

func TestTimesOut(t *testing.T) {
	auth, agent, _ := gate(t)
	start := time.Now()
	err := auth.Check(prompt(2 * time.Second))
	took := time.Since(start)
	if !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Check = %v, want ErrDenied", err)
	}
	if took > 3*time.Second {
		t.Fatalf("Check took %v, want under 3 s", took)
	}
	if took < 2*time.Second {
		t.Fatalf("Check returned after %v, before its 2 s timeout", took)
	}
	// polkit answers the cancelled check and tells the agent to close its
	// prompt on two separate paths, so the agent may see the
	// CancelAuthentication a moment after Check has returned.
	deadline := time.Now().Add(time.Second)
	for agent.Cancelled() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := agent.Cancelled(); n != 1 {
		t.Fatalf("the agent saw %d CancelAuthentication calls, want 1", n)
	}
}

// auth_self keeps nothing: the second check asks again.
func TestEveryCheckPrompts(t *testing.T) {
	auth, agent, q := gate(t)
	q.Push(true)
	q.Push(true)
	for i := 0; i < 2; i++ {
		if err := auth.Check(prompt(30 * time.Second)); err != nil {
			t.Fatalf("Check %d = %v, want nil", i+1, err)
		}
	}
	if n := len(agent.Messages()); n != 2 {
		t.Fatalf("the agent was asked %d times, want 2: %q", n, agent.Messages())
	}
}

// The prompt polkit hands the agent is the request itself: polkit expands
// $(nazar.prompt) in the action's message from the details Check passes.
func TestPromptShowsTheRequest(t *testing.T) {
	auth, agent, q := gate(t)
	q.Push(true)
	p := prompt(30 * time.Second)
	if err := auth.Check(p); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
	msgs := agent.Messages()
	if len(msgs) != 1 {
		t.Fatalf("the agent was asked %d times, want 1", len(msgs))
	}
	if !strings.Contains(msgs[0], p.Title) {
		t.Errorf("message %q does not contain the title %q", msgs[0], p.Title)
	}
	if !strings.Contains(msgs[0], p.Lines[0]) {
		t.Errorf("message %q does not contain the first line %q", msgs[0], p.Lines[0])
	}
}

// A subject with no agent (a child of ours; the agent is registered for
// this process only) is an error, not an approval, and does not hang.
func TestNoAgentIsAnError(t *testing.T) {
	conn := systemBus(t)
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { child.Process.Kill(); child.Wait() })
	st, err := procfs.ReadStat(child.Process.Pid)
	if err != nil {
		t.Fatalf("child stat: %v", err)
	}
	subject := polkit.ProcessSubject(child.Process.Pid, st.StartTicks, os.Getuid())
	auth := polkit.New(conn, func() (polkit.Subject, error) { return subject, nil })

	start := time.Now()
	err = auth.Check(prompt(5 * time.Second))
	if err == nil {
		t.Fatal("Check = nil with no agent, want an error")
	}
	if errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Check = %v, want an error other than ErrDenied", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Check took %v with no agent, want a quick error", took)
	}
	if !strings.Contains(err.Error(), "no polkit authentication agent") {
		t.Fatalf("Check = %v, want the no-agent message", err)
	}
}

// The real polkitd approves a root subject with no agent and no answer,
// which is why Check does not ask it.
func TestRootSubjectIsRefused(t *testing.T) {
	st, err := procfs.ReadStat(1)
	if err != nil {
		t.Fatalf("pid 1 stat: %v", err)
	}
	subject := polkit.ProcessSubject(1, st.StartTicks, 0)
	auth := polkit.New(systemBus(t), func() (polkit.Subject, error) { return subject, nil })
	err = auth.Check(prompt(5 * time.Second))
	if err == nil || errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Check = %v, want an error other than ErrDenied", err)
	}
}

// A process subject that names this user but is really root's process is
// not approved: the uid passes Check's guard, and polkitd must not take it.
func TestSubjectLyingAboutItsUIDIsNotApproved(t *testing.T) {
	st, err := procfs.ReadStat(1)
	if err != nil {
		t.Fatalf("pid 1 stat: %v", err)
	}
	subject := polkit.ProcessSubject(1, st.StartTicks, os.Getuid())
	auth := polkit.New(systemBus(t), func() (polkit.Subject, error) { return subject, nil })
	err = auth.Check(prompt(5 * time.Second))
	if err == nil {
		t.Fatal("Check = nil for pid 1 named as this user, want a refusal")
	}
	t.Logf("polkitd: %v", err)
}

// A subject that cannot be determined fails closed before polkit is asked.
func TestSubjectErrorFailsClosed(t *testing.T) {
	conn := systemBus(t)
	boom := errors.New("no session")
	auth := polkit.New(conn, func() (polkit.Subject, error) { return polkit.Subject{}, boom })
	err := auth.Check(prompt(5 * time.Second))
	if !errors.Is(err, boom) {
		t.Fatalf("Check = %v, want the subject's error", err)
	}
}
