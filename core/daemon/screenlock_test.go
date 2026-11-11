package daemon

import (
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform/fake"
)

// ScreenLocked ends every remembered approval, as a host that wants
// approvals to end at the screen lock calls it (nazar-agent on Linux):
// the next request in the same session is asked again, and the audit log
// says why. The platform's own lock event does nothing on its own: the
// daemon registers no callback for it, so a host that does not call
// ScreenLocked (the macOS app) keeps its sessions across a lock.
func TestScreenLockedEndsApprovals(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{})
	e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      gate: dialog\n      rules:\n        - apps: [{app: com.googlecode.iterm2}]\n          scope: session\n          gate: dialog\n")
	e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &control.ConfigDiff{})
	waitFor(t, func() bool { k := e.d.stager.Active().SSHAgent.Keys["github"]; return k != nil && len(k.Rules) == 1 })

	conn, err := net.Dial("unix", e.d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ag := agent.NewClient(conn)
	ks, err := ag.List()
	if err != nil || len(ks) != 1 {
		t.Fatalf("%v %v", ks, err)
	}
	pub, _ := ssh.ParsePublicKey(ks[0].Blob)
	sign := func() {
		t.Helper()
		if _, err := ag.Sign(pub, sshsig()); err != nil {
			t.Fatal(err)
		}
	}
	approvals := func() int {
		t.Helper()
		var st control.Status
		e.call(t, control.CmdStatus, nil, control.KindStatus, &st)
		return len(st.Approvals)
	}
	sign()
	if n := approvals(); n != 1 {
		t.Fatalf("%d approvals after the first signature, want 1", n)
	}
	// The platform's lock event alone changes nothing.
	e.f.LockScreen()
	sign()
	if dialogs := e.f.CountShown(fake.KindConfirm); dialogs != 1 {
		t.Fatalf("%d dialogs after a lock the host did not pass on, want 1 (the approval is remembered)", dialogs)
	}
	if n := approvals(); n != 1 {
		t.Fatalf("%d approvals after the platform's lock event, want still 1", n)
	}

	e.d.ScreenLocked()
	if n := approvals(); n != 0 {
		t.Fatalf("%d approvals after ScreenLocked, want 0", n)
	}
	sign()
	if dialogs := e.f.CountShown(fake.KindConfirm); dialogs != 2 {
		t.Fatalf("%d dialogs after ScreenLocked, want 2 (asked again)", dialogs)
	}
	found := false
	for _, line := range e.sink.Lines() {
		f, err := audit.ParseLine(line)
		if err == nil && f["target"] == "approvals" && strings.HasPrefix(f["reason"], "screen locked") {
			if f["reason"] != "screen locked: 1 approval ended" || f["decision"] != "allowed" {
				t.Fatalf("audit %v", f)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit line for the lock:\n%s", strings.Join(e.sink.Lines(), "\n"))
	}
	// The third signature was remembered again; a lock with nothing left to
	// end is still written down.
	e.d.ScreenLocked()
	if last := e.lastAudit(t); last["target"] != "approvals" || last["reason"] != "screen locked: 1 approval ended" {
		t.Fatalf("audit %v", last)
	}
	e.d.ScreenLocked()
	if last := e.lastAudit(t); last["target"] != "approvals" || last["reason"] != "screen locked: 0 approvals ended" {
		t.Fatalf("audit %v", last)
	}
}
