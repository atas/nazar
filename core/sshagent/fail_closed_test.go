package sshagent

import (
	"sort"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// ---------------------------------------------------------------------------
// Spec 5 "Session-bind and forwarding": under gate: none a forwarded
// connection (ssh -A) gets a one-time dialog instead of being silent, so a
// remote host can't sign quietly.
// ---------------------------------------------------------------------------

const noneCfg = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: none
`

// Locally, gate none signs without a prompt.
func TestLocalGateNoneIsSilent(t *testing.T) {
	e := newEnvWith(t, noneCfg)
	c, _ := e.client(t, e.peer)
	for _, data := range [][]byte{sshsig("git"), userauth([]byte("sid"), e.pub.Marshal(), nil)} {
		sig, err := c.Sign(e.pub, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := e.pub.Verify(data, sig); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(e.f.Shown()); n != 0 {
		t.Fatalf("gate none prompted %d times locally", n)
	}
}

// On a forwarded connection the same key and caller need the dialog for
// every request, for logins and for git signing alike.
func TestForwardedGateNoneAsksEveryTime(t *testing.T) {
	e := newEnvWith(t, noneCfg)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	c, _ := e.client(t, e.peer)
	sid := e.forward(t, c)
	reqs := [][]byte{
		userauth(sid, e.pub.Marshal(), e.signer.PublicKey()),
		userauth(sid, e.pub.Marshal(), e.signer.PublicKey()),
		sshsig("git"),
	}
	for i, data := range reqs {
		sig, err := c.Sign(e.pub, data)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if err := e.pub.Verify(data, sig); err != nil {
			t.Fatal(err)
		}
		if n := e.f.CountShown(fake.KindConfirm); n != i+1 {
			t.Fatalf("request %d: %d dialogs, want %d: a forwarded gate-none request must never be silent", i, n, i+1)
		}
		f := lastAudit(t, e)
		if f["decision"] != "approved" || f["gate"] != "dialog" {
			t.Fatalf("request %d: audit %v, want decision=approved gate=dialog", i, f)
		}
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 0 {
		t.Fatalf("forwarded gate none must use the dialog, not the login prompt (%d)", n)
	}
}

// Denying the forwarded dialog refuses the signature; nothing is signed.
func TestForwardedGateNoneDeniedSignsNothing(t *testing.T) {
	e := newEnvWith(t, noneCfg)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: false})
	c, _ := e.client(t, e.peer)
	sid := e.forward(t, c)
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err == nil {
		t.Fatal("a denied forwarded request must fail")
	}
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("a denied forwarded git signature must fail")
	}
	if e.f.SignCalls() != 0 {
		t.Fatalf("signed %d times without approval", e.f.SignCalls())
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("dialogs %d, want 2", n)
	}
	if f := lastAudit(t, e); f["decision"] != "denied" {
		t.Fatalf("audit %v", f)
	}
	// A plain local connection from the same caller is still silent.
	local, _ := e.client(t, e.peer)
	if _, err := local.Sign(e.pub, sshsig("git")); err != nil {
		t.Fatal(err)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("local gate none prompted (dialogs %d)", n)
	}
}

func lastAudit(t *testing.T, e *env) map[string]string {
	t.Helper()
	lines := e.sink.Lines()
	if len(lines) == 0 {
		t.Fatal("no audit line")
	}
	f, err := audit.ParseLine(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// ---------------------------------------------------------------------------
// Spec 5: REQUEST_IDENTITIES returns the configured keys, i.e. the
// keys in the ACTIVE (approved) config's ssh_agent.keys that nazar holds. A
// key that exists in the enclave store but is not (or no longer) configured
// is not offered. The active config is the one requests are judged by: the
// broker's current policy engine, swapped on every approved change.
// ---------------------------------------------------------------------------

func (e *env) listNames(t *testing.T, peer platform.ProcessRef) []string {
	t.Helper()
	c, _ := e.client(t, peer)
	ks, err := c.List()
	if err != nil {
		t.Fatalf("REQUEST_IDENTITIES: %v", err)
	}
	names := make([]string, 0, len(ks))
	for _, k := range ks {
		names = append(names, k.Comment)
	}
	sort.Strings(names)
	return names
}

func equalNames(a []string, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A key held in the store but absent from the active config is not offered.
func TestIdentitiesOnlyConfiguredKeys(t *testing.T) {
	e := newEnv(t) // configures github only
	if _, err := e.reg.Create("stale", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	if got := e.listNames(t, e.peer); !equalNames(got, "github") {
		t.Fatalf("identities %v, want [github]: an unconfigured key must not be offered", got)
	}
}

// Removing a key from the config (an approved change) stops offering it,
// on new connections and on connections already open; adding it back
// offers it again. A key the config names but nazar does not hold is never
// invented.
func TestIdentitiesFollowActiveConfig(t *testing.T) {
	e := newEnv(t)
	if _, err := e.reg.Create("work", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	open, _ := e.client(t, e.peer)

	e.reload(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    work:
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
    ghost:
      rules:
        - apps: [iterm]
          gate: dialog
`)
	if got := e.listNames(t, e.peer); !equalNames(got, "work") {
		t.Fatalf("after removing github: identities %v, want [work]", got)
	}
	ks, err := open.List()
	if err != nil || len(ks) != 1 || ks[0].Comment != "work" {
		t.Fatalf("connection opened before the change: %v %v, want [work]", ks, err)
	}

	e.reload(t, "apiVersion: nazar/v1\nkind: Config\n")
	if got := e.listNames(t, e.peer); len(got) != 0 {
		t.Fatalf("no keys configured: identities %v, want none", got)
	}

	e.reload(t, cfgSrc)
	if got := e.listNames(t, e.peer); !equalNames(got, "github") {
		t.Fatalf("after adding github back: identities %v", got)
	}
}

// A configured key whose record cannot be read is still left out.
func TestIdentitiesConfiguredButBrokenKeyNotOffered(t *testing.T) {
	e := newEnv(t)
	if err := e.kv.Put("ssh-key/broken", []byte("not a key record")); err != nil {
		t.Fatal(err)
	}
	e.reload(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: dialog
    broken:
      rules:
        - apps: [iterm]
          gate: dialog
`)
	if got := e.listNames(t, e.peer); !equalNames(got, "github") {
		t.Fatalf("identities %v, want [github]", got)
	}
}
