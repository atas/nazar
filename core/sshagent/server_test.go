package sshagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/policy"
	"github.com/atas/nazar/core/ssh/knownhosts"
	"github.com/atas/nazar/core/trust"
	"github.com/atas/nazar/core/unixsock"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

const cfgSrc = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
`

type env struct {
	f      *fake.Fake
	srv    *Server
	reg    *keys.Registry
	kv     *fake.Vault // the registry's Vault
	sink   *audit.MemorySink
	pub    ssh.PublicKey
	cache  *approval.Cache
	kh     string
	peer   platform.ProcessRef
	signer ssh.Signer                     // the server's host key, for session-bind
	eng    *atomic.Pointer[policy.Engine] // the active (approved) policy
	m      *match.Evaluator
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, cfgSrc)
}

// parseCfg parses src as an approved config.
func parseCfg(t *testing.T, src string) *config.Config {
	t.Helper()
	cfg, probs := config.Parse([]byte(src), config.Env{Home: "/Users/u"})
	if probs.HasErrors() {
		t.Fatal(probs.Error())
	}
	return cfg
}

// reload makes src the active config, as the daemon does when a config
// change is approved: the broker's policy engine is swapped.
func (e *env) reload(t *testing.T, src string) {
	t.Helper()
	e.eng.Store(policy.New(parseCfg(t, src), e.m))
}

// newEnvWith is newEnv over the config src. The registry holds one key,
// "github", whatever src configures.
func newEnvWith(t *testing.T, src string) *env {
	t.Helper()
	cfg := parseCfg(t, src)
	f := fake.New(t0)
	f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	// As config approval does (spec 4.2): iTerm2's team is pinned from
	// the installed app when the config is approved, never while matching.
	if _, err := st.Pin("com.googlecode.iterm2", fake.ITermCode.Team()); err != nil {
		t.Fatal(err)
	}
	m := &match.Evaluator{Trust: st}
	eng := &atomic.Pointer[policy.Engine]{}
	eng.Store(policy.New(cfg, m))
	sink := &audit.MemorySink{}
	kv := fake.NewVault()
	reg := keys.NewRegistry(f, kv, t.TempDir(), f.Now)
	info, err := reg.Create("github", platform.AuthNone, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.ParsePublicKey(info.Blob)
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hostPriv)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	os.WriteFile(kh, []byte("github.com "+string(ssh.MarshalAuthorizedKey(hs.PublicKey()))), 0o600)
	cache := approval.New(f.Now, f.ReleaseApproval)
	b := broker.New(broker.Options{
		Platform: f, Cache: cache, Audit: audit.NewLogger(sink, audit.Formatter{}, nil),
		Engine: eng.Load, Now: f.Now,
		Timeout: func() time.Duration { return time.Second },
	})
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	return &env{f: f, reg: reg, kv: kv, sink: sink, pub: pub, cache: cache, kh: kh, peer: tab.Peer(), signer: hs, eng: eng, m: m,
		srv: &Server{Keys: reg, Broker: b, Resolver: &caller.Resolver{P: f}, KnownHosts: func() string { return kh }}}
}

// client starts ServeConn on one end of a pipe for chain and returns an
// x/crypto agent client on the other.
func (e *env) client(t *testing.T, peer platform.ProcessRef) (agent.ExtendedAgent, net.Conn) {
	a, b := net.Pipe()
	chain := e.srv.Resolver.Resolve(peer)
	go func() { e.srv.ServeConn(a, chain); a.Close() }()
	t.Cleanup(func() { b.Close() })
	return agent.NewClient(b), b
}

// rawConn starts ServeConn on one end of a pipe for peer and returns the
// other end with no agent client attached (x/crypto's client reads the
// connection in the background, which would steal raw replies).
func (e *env) rawConn(t *testing.T, peer platform.ProcessRef) net.Conn {
	a, b := net.Pipe()
	chain := e.srv.Resolver.Resolve(peer)
	go func() { e.srv.ServeConn(a, chain); a.Close() }()
	t.Cleanup(func() { b.Close() })
	return b
}

func TestListIdentities(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	ks, err := c.List()
	if err != nil || len(ks) != 1 || ks[0].Comment != "github" || !bytes.Equal(ks[0].Blob, e.pub.Marshal()) {
		t.Fatalf("%v %v", ks, err)
	}
}

func TestSignGoesThroughBroker(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	data := sshsig("git")
	sig, err := c.Sign(e.pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.pub.Verify(data, sig); err != nil {
		t.Fatal(err)
	}
	f, _ := audit.ParseLine(e.sink.Lines()[0])
	if f["operation"] != "sign git commit" || f["decision"] != "approved" {
		t.Fatalf("audit %v", f)
	}
	if p := e.f.Shown()[0].Prompt; p.Lines[0] != "sign a git commit/tag" {
		t.Fatalf("prompt %v", p.Lines)
	}
}

func TestDeniedSignIsFailure(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: false})
	c, _ := e.client(t, e.peer)
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("denied request must fail")
	}
	unknown := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	c2, _ := e.client(t, unknown)
	if _, err := c2.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("blocked request must fail")
	}
	if e.f.SignCalls() != 0 {
		t.Fatal("nothing may be signed")
	}
}

func TestUnknownKeyIsFailure(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ssh.NewPublicKey(&k.PublicKey)
	if _, err := c.Sign(other, sshsig("git")); err == nil {
		t.Fatal("signing with a key nazar doesn't hold must fail")
	}
	if len(e.f.Shown()) != 0 {
		t.Fatal("no prompt for a foreign key")
	}
}

func TestRefusesKeyManagement(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := c.Add(agent.AddedKey{PrivateKey: k}); err == nil {
		t.Fatal("ADD_IDENTITY must fail")
	}
	if err := c.Remove(e.pub); err == nil {
		t.Fatal("REMOVE_IDENTITY must fail")
	}
	if err := c.RemoveAll(); err == nil {
		t.Fatal("REMOVE_ALL must fail")
	}
	if err := c.Lock([]byte("p")); err == nil {
		t.Fatal("LOCK must fail")
	}
	if err := c.Unlock([]byte("p")); err == nil {
		t.Fatal("UNLOCK must fail")
	}
	if _, err := c.Extension("query", nil); err == nil {
		t.Fatal("unknown extension must fail")
	}
	if ks, _ := c.List(); len(ks) != 1 {
		t.Fatal("key set must be unchanged")
	}
}

func (e *env) bind(t *testing.T, c agent.ExtendedAgent, sid []byte, fwd bool) error {
	return bindWith(c, e.signer, sid, fwd)
}

// bindWith sends a correctly signed session-bind for sid under signer's
// host key.
func bindWith(c agent.ExtendedAgent, signer ssh.Signer, sid []byte, fwd bool) error {
	sig, _ := signer.Sign(rand.Reader, sid)
	_, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
		HostKey   []byte
		SessionID []byte
		Signature []byte
		Fwd       bool
	}{signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), fwd}))
	return err
}

// otherHostSigner is a host key nazar has never seen: an attacker's.
func otherHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func userauth(sid, pub []byte, hostKey ssh.PublicKey) []byte {
	method := "publickey"
	if hostKey != nil {
		method = "publickey-hostbound-v00@openssh.com"
	}
	b := wireString(nil, sid)
	b = append(b, 50)
	for _, s := range []string{"git", "ssh-connection", method} {
		b = wireString(b, []byte(s))
	}
	b = append(b, 1)
	b = wireString(b, []byte("ecdsa-sha2-nistp256"))
	b = wireString(b, pub)
	if hostKey != nil {
		b = wireString(b, hostKey.Marshal())
	}
	return b
}

func wireString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func sshsig(ns string) []byte {
	b := []byte("SSHSIG")
	b = wireString(b, []byte(ns))
	b = wireString(b, nil)
	b = wireString(b, []byte("sha512"))
	return wireString(b, bytes.Repeat([]byte{1}, 64))
}

func TestLoginNamesDestinationFromSessionBind(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	sid := bytes.Repeat([]byte{9}, 32)
	if err := e.bind(t, c, sid, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; got != "login to github.com as git" {
		t.Fatalf("summary %q", got)
	}
	f, _ := audit.ParseLine(e.sink.Lines()[0])
	if f["destination"] != "github.com" {
		t.Fatalf("audit %v", f)
	}
}

// A server known under several names is shown under all of them, the
// name the caller's ssh was given first, in the dialog, the approval it
// would remember and the audit log; still only names known_hosts gives
// the key the session-bind proved. Through a forwarded agent the whole
// line still fits the dialog's first line.
func TestLoginShowsEveryKnownHostsName(t *testing.T) {
	e := newEnv(t)
	hk := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.signer.PublicKey())))
	other := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherHostSigner(t).PublicKey())))
	kh := "[old.example]:2222,[hydra.example]:2222 " + hk + "\n" +
		"[evil.example]:2222 " + other + "\n" +
		"[hydra.tail0a1b2.ts.net]:2222,[192.0.2.7]:2222 " + hk + "\n"
	if err := os.WriteFile(e.kh, []byte(kh), 0o600); err != nil {
		t.Fatal(err)
	}
	const dest = "[hydra.tail0a1b2.ts.net]:2222 (also [old.example]:2222, [hydra.example]:2222, [192.0.2.7]:2222)"
	login := func(args ...string) (platform.Prompt, map[string]string) {
		t.Helper()
		c, _ := e.client(t, e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc(args...)).Peer())
		sid := bytes.Repeat([]byte{byte(len(e.sink.Lines()) + 1)}, 32)
		if err := e.bind(t, c, sid, false); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
			t.Fatal(err)
		}
		shown, lines := e.f.Shown(), e.sink.Lines()
		f, err := audit.ParseLine(lines[len(lines)-1])
		if err != nil {
			t.Fatal(err)
		}
		return shown[len(shown)-1].Prompt, f
	}
	p, f := login("-p", "2222", "u@hydra.tail0a1b2.ts.net")
	if p.Lines[0] != "login to "+dest+" as git" {
		t.Fatalf("summary %q", p.Lines[0])
	}
	if text := strings.Join(p.Lines, "\n"); !strings.Contains(text, "Scope: this terminal session, for "+dest+" only") {
		t.Fatalf("dialog:\n%s", text)
	}
	if !strings.HasPrefix(p.Reason, `use key "github" for login to [hydra.tail0a1b2.ts.net]:2222 (also [old.example]:2222`) {
		t.Fatalf("reason %q", p.Reason)
	}
	if f["destination"] != dest {
		t.Fatalf("audit destination %q", f["destination"])
	}
	fp := ssh.FingerprintSHA256(e.signer.PublicKey())
	if en := e.cache.List(); len(en) != 1 || en[0].Key.Op != "login:"+fp || en[0].Covers != dest {
		t.Fatalf("remembered %+v, want one approval by host key shown with every name", en)
	}

	// Another key's name on the command line neither shows nor reorders.
	e.cache.RevokeAll("test")
	p, f = login("-p", "2222", "evil.example")
	const fileOrder = "[old.example]:2222 (also [hydra.example]:2222, [hydra.tail0a1b2.ts.net]:2222, [192.0.2.7]:2222)"
	if p.Lines[0] != "login to "+fileOrder+" as git" || f["destination"] != fileOrder {
		t.Fatalf("summary %q, audit %q", p.Lines[0], f["destination"])
	}

	// Through a forwarded agent nothing of the line is cut.
	e2 := newEnv(t)
	if err := os.WriteFile(e2.kh, []byte(strings.ReplaceAll(kh, hk, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e2.signer.PublicKey()))))), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := e2.client(t, e2.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("-p", "2222", "u@hydra.tail0a1b2.ts.net")).Peer())
	if err := e2.bind(t, c, bytes.Repeat([]byte{1}, 32), true); err != nil {
		t.Fatal(err)
	}
	sid := bytes.Repeat([]byte{2}, 32)
	if err := e2.bind(t, c, sid, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(e2.pub, userauth(sid, e2.pub.Marshal(), e2.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if got := e2.f.Shown()[0].Prompt.Lines[0]; got != "login to "+dest+" (via a forwarded agent) as git" {
		t.Fatalf("forwarded summary %q", got)
	}
}

// A hashed known_hosts entry (HashKnownHosts yes) can only be named through
// the host the caller's ssh was invoked for: the server hands the peer's
// argv to knownhosts as candidates. The host is deliberately not in
// knownhosts.WellKnown, so nothing but the argv can name it.
func TestHashedKnownHostNamedFromCallerArgs(t *testing.T) {
	e := newEnv(t)
	for _, wk := range knownhosts.WellKnown {
		if wk == "example.org" {
			t.Fatal("test host must not be well known")
		}
	}
	salt := []byte("0123456789abcdefghij")
	entry := knownhosts.HashName("example.org", salt) + " " + string(ssh.MarshalAuthorizedKey(e.signer.PublicKey()))
	if err := os.WriteFile(e.kh, []byte(entry), 0o600); err != nil {
		t.Fatal(err)
	}
	peer := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@example.org")).Peer()
	c, _ := e.client(t, peer)
	sid := bytes.Repeat([]byte{9}, 32)
	if err := e.bind(t, c, sid, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; got != "login to example.org as git" {
		t.Fatalf("summary %q, want the hashed host named from the caller's argv", got)
	}
	f, err := audit.ParseLine(e.sink.Lines()[0])
	if err != nil {
		t.Fatal(err)
	}
	if f["destination"] != "example.org" {
		t.Fatalf("audit destination %q, want example.org", f["destination"])
	}

	// Contrast: a caller whose argv names another host cannot name the
	// hashed entry, so only the fingerprint is shown and recorded.
	c2, _ := e.client(t, e.peer) // ssh git@github.com
	sid2 := bytes.Repeat([]byte{8}, 32)
	if err := e.bind(t, c2, sid2, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Sign(e.pub, userauth(sid2, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	shown := e.f.Shown()
	if got := shown[len(shown)-1].Prompt.Lines[0]; !strings.HasPrefix(got, "login to host key SHA256:") || strings.Contains(got, "example.org") {
		t.Fatalf("summary %q, want only the fingerprint when argv names another host", got)
	}
	lines := e.sink.Lines()
	f, err = audit.ParseLine(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	if d := f["destination"]; !strings.HasPrefix(d, "host key SHA256:") || strings.Contains(d, "example.org") {
		t.Fatalf("audit destination %q, want only the fingerprint", d)
	}
}

// A correctly signed session-bind body is accepted only under the exact
// extension name (spec 5: unknown extensions are SSH_AGENT_FAILURE). Under
// any other name it fails and, above all, is not recorded as a bind: a
// later userauth for another session is not refused as a mismatch, and the
// bound host is never named.
func TestSessionBindUnderOtherExtensionNameIsNotRecorded(t *testing.T) {
	for _, name := range []string{"query", "session-bind@openssh.com\x00", "session-bind@openssh.co", "Session-bind@openssh.com", "session-bind@openssh.com "} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			e := newEnv(t)
			c, _ := e.client(t, e.peer)
			sid := bytes.Repeat([]byte{9}, 32)
			sig, _ := e.signer.Sign(rand.Reader, sid)
			body := ssh.Marshal(struct {
				HostKey, SessionID, Signature []byte
				Fwd                           bool
			}{e.signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), false})
			if _, err := c.Extension(name, body); err == nil {
				t.Fatalf("a valid session-bind under extension name %q must fail", name)
			}
			// Still unbound: a userauth for a different session, and one for the
			// same session without a host key, both pass as unbound logins.
			for _, s := range [][]byte{bytes.Repeat([]byte{4}, 32), sid} {
				if _, err := c.Sign(e.pub, userauth(s, e.pub.Marshal(), nil)); err != nil {
					t.Fatalf("userauth after a refused bind must be judged as unbound: %v", err)
				}
			}
			for _, s := range e.f.Shown() {
				if got := s.Prompt.Lines[0]; got != "login to an unidentified server as git" {
					t.Fatalf("a refused bind must not name a destination: %q", got)
				}
			}
			for _, l := range e.sink.Lines() {
				f, err := audit.ParseLine(l)
				if err != nil {
					t.Fatal(err)
				}
				if d := f["destination"]; d != "" {
					t.Fatalf("a refused bind must not reach the audit destination: %q", d)
				}
			}
		})
	}
}

func TestSessionBindMismatchIsRefused(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	e.bind(t, c, bytes.Repeat([]byte{9}, 32), false)
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{8}, 32), e.pub.Marshal(), nil)); err == nil {
		t.Fatal("userauth for another session must be refused")
	}
	_, otherHost, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherHost)
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{9}, 32), e.pub.Marshal(), otherSigner.PublicKey())); err == nil {
		t.Fatal("hostbound key different from the bound host key must be refused")
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := ssh.NewPublicKey(&k.PublicKey)
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{9}, 32), otherPub.Marshal(), nil)); err == nil {
		t.Fatal("userauth naming another key must be refused")
	}
	if len(e.f.Shown()) != 0 {
		t.Fatal("refused before any prompt")
	}
}

func TestForgedSessionBindIsRefused(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	sid := bytes.Repeat([]byte{9}, 32)
	sig, _ := e.signer.Sign(rand.Reader, []byte("another session"))
	_, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
		HostKey, SessionID, Signature []byte
		Fwd                           bool
	}{e.signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), false}))
	if err == nil {
		t.Fatal("session-bind with a bad signature must fail")
	}
}

// The shape of a forwarded connection: the local ssh binds the session to
// the first hop with is_forwarding, then the remote ssh binds its own
// session (without it) and authenticates to that one, host-bound.
func (e *env) forward(t *testing.T, c agent.ExtendedAgent) (sid []byte) {
	t.Helper()
	if err := e.bind(t, c, bytes.Repeat([]byte{1}, 32), true); err != nil {
		t.Fatal(err)
	}
	sid = bytes.Repeat([]byte{9}, 32)
	if err := e.bind(t, c, sid, false); err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestForwardedAndUnknownHost(t *testing.T) {
	e := newEnv(t)
	os.WriteFile(e.kh, nil, 0o600)
	c, _ := e.client(t, e.peer)
	sid := e.forward(t, c)
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	got := e.f.Shown()[0].Prompt.Lines[0]
	if !strings.HasPrefix(got, "login to host key SHA256:") || !strings.HasSuffix(got, "(via a forwarded agent) as git") {
		t.Fatalf("summary %q", got)
	}
}

func TestForwardedConnectionPromptsEveryTime(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	sid := e.forward(t, c)
	for i := 0; i < 2; i++ {
		if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("forwarded requests must prompt every time; shown %d", n)
	}
}

// Only forwarding binds stack (nested hops); the limit is counted on them.
func TestTooManyBinds(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	for i := 0; i < MaxBinds; i++ {
		if err := e.bind(t, c, bytes.Repeat([]byte{byte(i + 1)}, 32), true); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.bind(t, c, bytes.Repeat([]byte{99}, 32), false); err == nil {
		t.Fatal("bind beyond the limit must fail")
	}
	// A bind refused for the limit marks the connection like any other
	// refused bind: nothing on it is signed, not even for the latest
	// recorded session.
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{MaxBinds}, 32), e.pub.Marshal(), nil)); err == nil {
		t.Fatal("sign after a bind refused for the limit must fail")
	}
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("SSHSIG after a bind refused for the limit must fail")
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatal("refused before any prompt or signature")
	}
}

func TestOversizedFrameClosesConnection(t *testing.T) {
	e := newEnv(t)
	raw := e.rawConn(t, e.peer)
	hdr := binary.BigEndian.AppendUint32(nil, 1<<30)
	raw.Write(hdr)
	raw.SetReadDeadline(time.Now().Add(time.Second))
	// Only EOF proves the server closed the connection: a deadline
	// timeout would mean it ignored the bad header and kept reading.
	if _, err := raw.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server must close the connection on an oversized frame; want EOF, got %v", err)
	}
}

func TestServeOverUnixSocket(t *testing.T) {
	e := newEnv(t)
	dir, _ := os.MkdirTemp("/tmp", "nzag")
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "agent.sock")
	l, err := unixsock.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	e.f.SetDefaultPeer(e.peer)
	go e.srv.Serve(l)
	defer l.Close()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := agent.NewClient(conn).Sign(e.pub, sshsig("git")); err != nil {
		t.Fatal(err)
	}
}

// --- Additional behaviour, edge and attack cases ---

// frame prefixes body with its uint32 length, as the agent protocol does.
func frame(body []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}

// roundTrip writes one raw message and returns the reply body.
func roundTrip(t *testing.T, conn net.Conn, body []byte) []byte {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if _, err := conn.Write(frame(body)); err != nil {
		t.Fatalf("write %x: %v", body, err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("reply to %x: %v", body, err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		t.Fatalf("reply to %x: bad length %d", body, n)
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reply to %x: %v", body, err)
	}
	return reply
}

const (
	msgFailure            = 5
	msgRequestIdentities  = 11
	msgIdentitiesAnswer   = 12
	msgExtension          = 27
	sshAgentFailureReason = "SSH_AGENT_FAILURE"
)

func extensionBody(name string, contents []byte) []byte {
	b := wireString([]byte{msgExtension}, []byte(name))
	return append(b, contents...)
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == '‮' }) >= 0
}

// Every message nazar does not implement is answered with SSH_AGENT_FAILURE
// and the connection stays usable (spec 5: "Everything else").
func TestRawUnsupportedMessagesFail(t *testing.T) {
	e := newEnv(t)
	raw := e.rawConn(t, e.peer)
	cases := map[string][]byte{
		"ADD_SMARTCARD_KEY":             {20, 0, 0, 0, 1, 'x', 0, 0, 0, 1, 'y'},
		"REMOVE_SMARTCARD_KEY":          {21, 0, 0, 0, 1, 'x', 0, 0, 0, 1, 'y'},
		"ADD_ID_CONSTRAINED":            {25, 0, 0, 0, 0},
		"ADD_SMARTCARD_KEY_CONSTRAINED": {26, 0, 0, 0, 0},
		"REMOVE_IDENTITY garbage":       {18},
		"LOCK no body":                  {22},
		"type 0":                        {0},
		"type 1 (SSH1)":                 {1},
		"type 200":                      {200},
		"type 255":                      {255},
		"SIGN_REQUEST no body":          {13},
		"SIGN_REQUEST truncated":        {13, 0, 0, 0, 9, 1, 2},
		"SIGN_REQUEST huge string len":  {13, 0xff, 0xff, 0xff, 0xff},
		"EXTENSION no name":             {msgExtension},
		"EXTENSION truncated name":      {msgExtension, 0, 0, 0, 40, 's'},
		"unknown extension":             extensionBody("query", nil),
		"session-bind garbage":          extensionBody("session-bind@openssh.com", []byte{1, 2, 3}),
		"session-bind empty":            extensionBody("session-bind@openssh.com", nil),
		"near-name extension":           extensionBody("session-bind@openssh.com\x00", nil),
	}
	for name, body := range cases {
		if r := roundTrip(t, raw, body); len(r) != 1 || r[0] != msgFailure {
			t.Errorf("%s: want %s, got %x", name, sshAgentFailureReason, r)
		}
	}
	if r := roundTrip(t, raw, []byte{msgRequestIdentities}); len(r) == 0 || r[0] != msgIdentitiesAnswer {
		t.Fatalf("connection must stay usable after failures; got %x", r)
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatal("malformed requests must never prompt or sign")
	}
}

// A zero-length frame is malformed. The server must not crash (a panic in
// the connection goroutine would take the whole agent down); it may answer
// SSH_AGENT_FAILURE or close the connection, nothing else.
func TestEmptyFrameDoesNotCrash(t *testing.T) {
	e := newEnv(t)
	raw := e.rawConn(t, e.peer)
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := raw.Write([]byte{0, 0, 0, 0}); err != nil {
		return // already closed: acceptable
	}
	var hdr [5]byte
	n, err := io.ReadFull(raw, hdr[:])
	if err == nil && !(binary.BigEndian.Uint32(hdr[:4]) == 1 && hdr[4] == msgFailure) {
		t.Fatalf("empty frame must be refused or close the connection; got %x", hdr[:n])
	}
}

// Oversized frames just above OpenSSH's 256 KiB limit also close the
// connection, without the server reading (or allocating) the body.
func TestFrameJustOverLimitClosesConnection(t *testing.T) {
	e := newEnv(t)
	raw := e.rawConn(t, e.peer)
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	raw.Write(binary.BigEndian.AppendUint32(nil, 256*1024+1))
	// Only EOF proves the server closed the connection: a deadline
	// timeout would mean it ignored the bad header and kept reading.
	if _, err := raw.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("server must close the connection on a frame over 256 KiB; want EOF, got %v", err)
	}
}

func TestSessionBindWithOverlongSessionIDFails(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	if err := e.bind(t, c, bytes.Repeat([]byte{7}, 65), false); err == nil {
		t.Fatal("a session id over 64 bytes must be refused")
	}
}

// A session-bind signed by a key other than the one it names is refused,
// and a refused bind does not bind: the forged host is never named. Nor is
// the connection then served as unbound: a refused bind marks it, and no
// userauth on it (for that session or any other) is signed or prompted.
func TestForgedBindDoesNotBind(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	sid := bytes.Repeat([]byte{9}, 32)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(otherPriv)
	sig, _ := otherSigner.Sign(rand.Reader, sid)
	_, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
		HostKey, SessionID, Signature []byte
		Fwd                           bool
	}{e.signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), false}))
	if err == nil {
		t.Fatal("session-bind signed by another key must fail")
	}
	for _, s := range [][]byte{bytes.Repeat([]byte{4}, 32), sid} {
		if _, err := c.Sign(e.pub, userauth(s, e.pub.Marshal(), nil)); err == nil {
			t.Fatal("userauth after a refused bind must be refused")
		}
		if _, err := c.Sign(e.pub, userauth(s, e.pub.Marshal(), e.signer.PublicKey())); err == nil {
			t.Fatal("hostbound userauth after a refused bind must be refused")
		}
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatalf("refused before any prompt or signature; shown %d signs %d",
			len(e.f.Shown()), e.f.SignCalls())
	}
	// Spec 4.6: every request is logged, refused ones included.
	refusedAudited(t, e, 4)
}

// Refused binds fail closed. OpenSSH's ssh keeps forwarding
// the agent after its is_forwarding bind failed, so a bind nazar cannot
// parse (here a host-key algorithm x/crypto does not know, as happens
// whenever OpenSSH ships one first) must not leave the connection looking
// local; as ssh-agent does for constrained keys, nothing on it is signed.
func TestRefusedBindFailsClosed(t *testing.T) {
	e := newEnv(t)
	logs := captureLog(e)
	c, _ := e.client(t, e.peer)
	sid := bytes.Repeat([]byte{9}, 32)
	hostKey := wireString(wireString(nil, []byte("ssh-xmss@openssh.com")), bytes.Repeat([]byte{1}, 32))
	sig, _ := e.signer.Sign(rand.Reader, sid)
	_, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
		HostKey, SessionID, Signature []byte
		Fwd                           bool
	}{hostKey, sid, ssh.Marshal(sig), true}))
	if err == nil {
		t.Fatal("session-bind with an unparseable host key must fail")
	}
	// The remote ssh's own bind afterwards verifies fine; it must not lift
	// the mark, since that is the exact shape of a forwarded connection.
	if err := e.bind(t, c, bytes.Repeat([]byte{2}, 32), false); err != nil {
		t.Fatalf("a later valid bind is still recorded: %v", err)
	}
	// Three userauths (bound session, other session, hostbound) and an
	// SSHSIG: on a forwarded connection each would prompt; here none may.
	for name, data := range map[string][]byte{
		"userauth bound session": userauth(bytes.Repeat([]byte{2}, 32), e.pub.Marshal(), nil),
		"userauth other session": userauth(sid, e.pub.Marshal(), nil),
		"userauth hostbound":     userauth(bytes.Repeat([]byte{2}, 32), e.pub.Marshal(), e.signer.PublicKey()),
		"sshsig git":             sshsig("git"),
		"unrecognized payload":   []byte("hello"),
		"sshsig other namespace": sshsig("file"),
	} {
		if _, err := c.Sign(e.pub, data); err == nil {
			t.Fatalf("%s: sign after a refused bind must fail", name)
		}
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatalf("a marked connection must neither prompt nor sign; shown %d signs %d",
			len(e.f.Shown()), e.f.SignCalls())
	}
	// Spec 4.6: every request is logged; each refused SIGN_REQUEST is one
	// blocked audit line.
	refusedAudited(t, e, 6)
	// Listing keys stays answered: refusing it would hide nothing (public
	// keys) and ssh would only report the gap differently.
	if ids, err := c.List(); err != nil || len(ids) != 1 {
		t.Fatalf("identities on a marked connection: %v, %d", err, len(ids))
	}
	var refused int
	for _, l := range logs() {
		if strings.HasPrefix(l, "agent: refusing to sign with github: an earlier session-bind") {
			refused++
		}
		if strings.ContainsAny(l, "\n\r\x1b") || hasControl(l) {
			t.Fatalf("log line carries control characters: %q", l)
		}
	}
	if refused != 6 {
		t.Fatalf("want 6 refusal log lines, got %d: %q", refused, logs())
	}
	// The mark is per connection: a fresh one from the same peer is served,
	// prompted and remembered as an ordinary local connection.
	c2, _ := e.client(t, e.peer)
	if err := e.bind(t, c2, sid, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c2.Sign(e.pub, userauth(sid, e.pub.Marshal(), nil)); err != nil {
			t.Fatalf("sign on a fresh connection: %v", err)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 || e.f.SignCalls() != 2 {
		t.Fatalf("fresh connection: shown %d (want 1), signs %d (want 2)", n, e.f.SignCalls())
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; got != "login to github.com as git" {
		t.Fatalf("fresh connection prompt %q", got)
	}
}

// OpenSSH checks userauth against the most recent bind on the connection.
func TestUserauthMustMatchLatestBind(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	sid1, sid2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := e.bind(t, c, sid1, true); err != nil {
		t.Fatal(err)
	}
	if err := e.bind(t, c, sid2, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign(e.pub, userauth(sid1, e.pub.Marshal(), e.signer.PublicKey())); err == nil {
		t.Fatal("userauth for an earlier session must be refused")
	}
	if len(e.f.Shown()) != 0 {
		t.Fatal("refused before any prompt")
	}
	if _, err := c.Sign(e.pub, userauth(sid2, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatalf("userauth for the latest bind: %v", err)
	}
}

// Binds are per connection: a bind (and its forwarding flag) on one
// connection never constrains or taints another.
func TestBindsArePerConnection(t *testing.T) {
	e := newEnv(t)
	c1, _ := e.client(t, e.peer)
	c2, _ := e.client(t, e.peer)
	if err := e.bind(t, c1, bytes.Repeat([]byte{1}, 32), true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c2.Sign(e.pub, userauth(bytes.Repeat([]byte{2}, 32), e.pub.Marshal(), nil)); err != nil {
			t.Fatalf("sign on the other connection: %v", err)
		}
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; strings.Contains(got, "forwarded") {
		t.Fatalf("connection 2 is not forwarded: %q", got)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("an unforwarded session-scoped approval is remembered; shown %d", n)
	}
}

// Agent forwarding: the local ssh binds with is_forwarding,
// then the remote ssh binds its own session without it. Every request on
// that connection comes from the remote host and must still prompt every
// time and say so.
func TestForwardedStaysForwardedAfterLaterBind(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	if err := e.bind(t, c, bytes.Repeat([]byte{1}, 32), true); err != nil {
		t.Fatal(err)
	}
	sid := bytes.Repeat([]byte{2}, 32)
	if err := e.bind(t, c, sid, false); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("forwarded connection must prompt every time; shown %d", n)
	}
	for _, s := range e.f.Shown() {
		if !strings.Contains(s.Prompt.Lines[0], "via a forwarded agent") {
			t.Fatalf("prompt must say the request is forwarded: %q", s.Prompt.Lines[0])
		}
	}
}

// A remote host holding a forwarded agent must not ride on a remembered
// approval for git signing either.
func TestForwardedGitSigningPromptsEveryTime(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	if err := e.bind(t, c, bytes.Repeat([]byte{1}, 32), true); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Sign(e.pub, sshsig("git")); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 3 {
		t.Fatalf("forwarded git signing must prompt every time; shown %d", n)
	}
}

// Contrast: on a plain connection a session-scoped approval is remembered.
func TestUnforwardedApprovalIsRemembered(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	for i := 0; i < 3; i++ {
		if _, err := c.Sign(e.pub, sshsig("git")); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("session approval should be remembered; shown %d", n)
	}
}

func TestOtherNamespaceShownVerbatimAndSanitised(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	if _, err := c.Sign(e.pub, sshsig("file")); err != nil {
		t.Fatal(err)
	}
	got := e.f.Shown()[0].Prompt.Lines[0]
	if !strings.Contains(got, "file") || strings.Contains(got, "git commit") {
		t.Fatalf("namespace must be shown verbatim: %q", got)
	}
	// The audit line is the only record of what the key signed (spec 4.6):
	// a file signature must never be recorded as a git commit.
	f, err := audit.ParseLine(e.sink.Lines()[0])
	if err != nil {
		t.Fatal(err)
	}
	if f["operation"] != "sign data namespace=file" {
		t.Fatalf("audit operation %q, want %q", f["operation"], "sign data namespace=file")
	}
	evil := "git\n\x1b[2Jlogin to github.com‮"
	data := sshsig(evil)
	if _, err := c.Sign(e.pub, data); err != nil {
		t.Fatal(err)
	}
	shown := e.f.Shown()
	got = shown[len(shown)-1].Prompt.Lines[0]
	if hasControl(got) || got == "sign a git commit/tag" {
		t.Fatalf("hostile namespace must be sanitised and never pass as git: %q", got)
	}
	lines := e.sink.Lines()
	for _, l := range lines {
		if hasControl(l) {
			t.Fatalf("audit line carries control characters: %q", l)
		}
	}
	// A namespace that merely starts with "git" is not git: the audit
	// operation must say what it is, sanitised, and never read as a commit.
	f, err = audit.ParseLine(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	if op := f["operation"]; op == "sign git commit" || !strings.HasPrefix(op, "sign data namespace=") || hasControl(op) {
		t.Fatalf("hostile namespace audited as %q", op)
	}
}

func TestUnrecognizedPayload(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	data := []byte("NAZAR-SECRET-PAYLOAD-MARKER-0123456789")
	sig, err := c.Sign(e.pub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.pub.Verify(data, sig); err != nil {
		t.Fatal(err)
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; got != "sign unrecognized data (38 bytes)" {
		t.Fatalf("summary %q", got)
	}
	// The audit record must say the payload was unrecognized, not a commit.
	f, err := audit.ParseLine(e.sink.Lines()[0])
	if err != nil {
		t.Fatal(err)
	}
	if f["operation"] != "sign unrecognized data" {
		t.Fatalf("audit operation %q, want %q", f["operation"], "sign unrecognized data")
	}
	// Audit never logs payloads or signatures (spec 4.6).
	b64 := base64.StdEncoding.EncodeToString(sig.Blob)
	for _, l := range e.sink.Lines() {
		if strings.Contains(l, "NAZAR-SECRET") || strings.Contains(l, b64) || strings.Contains(l, b64[:16]) {
			t.Fatalf("audit line leaks payload or signature: %q", l)
		}
	}
}

func TestUnboundLoginHasNoInventedDestination(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{3}, 32), e.pub.Marshal(), nil)); err != nil {
		t.Fatal(err)
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; got != "login to an unidentified server as git" {
		t.Fatalf("summary %q", got)
	}
}

// A userauth naming another key is refused even without any bind.
func TestUserauthForOtherKeyRefusedWithoutBind(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherPub, _ := ssh.NewPublicKey(&k.PublicKey)
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{3}, 32), otherPub.Marshal(), nil)); err == nil {
		t.Fatal("userauth naming another key must be refused")
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatal("refused before any prompt or signature")
	}
}

func TestConnectionUsableAfterDenial(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: false})
	c, _ := e.client(t, e.peer)
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("denied request must fail")
	}
	if ks, err := c.List(); err != nil || len(ks) != 1 {
		t.Fatalf("connection must stay usable: %v %v", ks, err)
	}
	f, _ := audit.ParseLine(e.sink.Lines()[0])
	if f["decision"] == "approved" || f["decision"] == "allowed" {
		t.Fatalf("denial audited as %v", f)
	}
}

func listenAgent(t *testing.T, e *env) (string, *net.UnixListener, chan error) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	l, err := unixsock.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.srv.Serve(l) }()
	t.Cleanup(func() {
		l.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after the listener closed")
		}
	})
	return path, l, done
}

func TestServeReturnsNilWhenListenerClosed(t *testing.T) {
	e := newEnv(t)
	dir, _ := os.MkdirTemp("/tmp", "nzag")
	defer os.RemoveAll(dir)
	l, err := unixsock.Listen(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e.srv.Serve(l) }()
	time.Sleep(20 * time.Millisecond)
	l.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// Over the real socket the caller comes from the socket peer: a process
// outside any configured app falls to the block fallback: it is offered no
// key (Milestone 7), and a sign request with the key's blob (public, on
// disk) gets no prompt and no signature.
func TestServeResolvesCallerFromSocketPeer(t *testing.T) {
	e := newEnv(t)
	stranger := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	e.f.SetDefaultPeer(stranger)
	path, _, _ := listenAgent(t, e)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := agent.NewClient(conn)
	if ks, err := c.List(); err != nil || len(ks) != 0 {
		t.Fatalf("identities for a caller outside the rules: %v %v, want none", ks, err)
	}
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("a caller outside the rules must be blocked")
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatal("blocked caller: no prompt, no signature")
	}
}

// When the peer of a connection cannot be identified the request fails
// closed: never signed, never approved.
func TestServeUnidentifiedPeerFailsClosed(t *testing.T) {
	e := newEnv(t) // no peer scripted: the fake's PeerOf fails
	path, _, _ := listenAgent(t, e)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := agent.NewClient(conn).Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("an unidentified peer must not get a signature")
	}
	if e.f.SignCalls() != 0 {
		t.Fatal("nothing may be signed")
	}
}

// Many connections at once each get their own state and answers.
func TestConcurrentConnections(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaultPeer(e.peer)
	path, _, _ := listenAgent(t, e)
	const n = 8
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			conn, err := net.Dial("unix", path)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			c := agent.NewClient(conn)
			sid := bytes.Repeat([]byte{byte(i + 1)}, 32)
			sig, _ := e.signer.Sign(rand.Reader, sid)
			if _, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
				HostKey, SessionID, Signature []byte
				Fwd                           bool
			}{e.signer.PublicKey().Marshal(), sid, ssh.Marshal(sig), false})); err != nil {
				errs <- err
				return
			}
			data := userauth(sid, e.pub.Marshal(), nil)
			s, err := c.Sign(e.pub, data)
			if err == nil {
				err = e.pub.Verify(data, s)
			}
			errs <- err
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// Only usable keys are offered: a Vault record that cannot be read is not
// listed, and the healthy key is unaffected.
func TestBrokenKeyIsNotListed(t *testing.T) {
	e := newEnv(t)
	if err := e.kv.Put(keys.VaultPrefix+"broken", []byte("not a key record")); err != nil {
		t.Fatal(err)
	}
	c, _ := e.client(t, e.peer)
	ks, err := c.List()
	if err != nil || len(ks) != 1 || ks[0].Comment != "github" {
		t.Fatalf("%v %v", ks, err)
	}
}

// --- Peer-UID gate (spec 5, Phase 0 S6): proven through the peerCheck seam ---

// A peer the UID check rejects is dropped before a byte is read: no reply
// ever comes back, the fake's PeerOf is never asked (so no chain is
// resolved), and nothing is prompted or signed. The connection must close
// (EOF, or a reset because the request was still unread), never time out.
func TestServeDropsPeerTheCheckRejects(t *testing.T) {
	e := newEnv(t)
	var checked, peered atomic.Int32
	e.f.PeerFunc = func(fd int) (platform.ProcessRef, error) {
		peered.Add(1)
		return e.peer, nil
	}
	e.srv.peerCheck = func(c *net.UnixConn) error {
		checked.Add(1)
		return errors.New("unixsock: peer uid 0 is not 501")
	}
	path, _, _ := listenAgent(t, e)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A write may fail if the server already closed its end; that is fine.
	conn.Write(frame([]byte{msgRequestIdentities}))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the server did not close a refused peer's connection promptly: %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("the server answered a refused peer: %x", b)
	}
	// handle closes the connection only on return, after the check ran, so
	// seeing it closed means the counters are final.
	if n := checked.Load(); n != 1 {
		t.Fatalf("peer check ran %d times, want 1", n)
	}
	if n := peered.Load(); n != 0 {
		t.Fatalf("PeerOf ran %d times for a refused peer; the chain must not be resolved", n)
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatal("a refused peer must never prompt or sign")
	}
}

// The gate is wired on the default path: handle runs the check exactly once
// per connection, on a same-user conn, and only then resolves the peer.
func TestServeRunsPeerCheckBeforeResolving(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var events []string
	e.f.PeerFunc = func(fd int) (platform.ProcessRef, error) {
		mu.Lock()
		events = append(events, "peer")
		mu.Unlock()
		return e.peer, nil
	}
	e.srv.peerCheck = func(c *net.UnixConn) error {
		uid, err := unixsock.PeerUID(c)
		if err != nil {
			return err
		}
		if uid != os.Getuid() {
			return fmt.Errorf("check got a connection whose peer is uid %d", uid)
		}
		mu.Lock()
		events = append(events, "check")
		mu.Unlock()
		return nil
	}
	path, _, _ := listenAgent(t, e)
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := agent.NewClient(conn).Sign(e.pub, sshsig("git")); err != nil {
		t.Fatalf("a same-user peer passing the check must be served: %v", err)
	}
	mu.Lock()
	got := strings.Join(events, ",")
	mu.Unlock()
	if got != "check,peer" {
		t.Fatalf("events %q, want the peer check once, then the peer lookup", got)
	}
	if e.f.SignCalls() != 1 {
		t.Fatalf("sign calls %d, want 1", e.f.SignCalls())
	}
}

// Without a check of its own, a Server uses unixsock.RequireSameUser, which
// passes a live same-user conn and fails closed on one whose peer cannot be
// read, never letting it in.
func TestServerDefaultPeerCheckFailsClosed(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "nzag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	l, err := unixsock.Listen(path) // never accepted: the conn sits in the backlog
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Server{}).checkPeer(conn); err != nil {
		t.Fatalf("a same-user peer was refused: %v", err)
	}
	conn.Close()
	if err := (&Server{}).checkPeer(conn); err == nil {
		t.Fatal("the default peer check passed a closed conn")
	}
}

// captureLog routes the server's log through a slice; it returns a snapshot
// function that is safe to call while the connection goroutine runs.
func captureLog(e *env) func() []string {
	var mu sync.Mutex
	var lines []string
	e.srv.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

// A client controls the key algorithm string of the host key it sends in a
// session-bind, and x/crypto embeds that string raw in its parse error. The
// daemon log must still get exactly one line, with no newline, escape or
// other control character, so a client cannot forge log lines of its own.
func TestHostileSessionBindCannotForgeLogLines(t *testing.T) {
	e := newEnv(t)
	logs := captureLog(e)
	c, _ := e.client(t, e.peer)
	algo := "ssh-ed25519\n2026-10-04 agent: signed with github \x1b[2J"
	hostKey := wireString(wireString(nil, []byte(algo)), bytes.Repeat([]byte{1}, 32))
	sid := bytes.Repeat([]byte{9}, 32)
	sig, _ := e.signer.Sign(rand.Reader, sid)
	_, err := c.Extension("session-bind@openssh.com", ssh.Marshal(struct {
		HostKey, SessionID, Signature []byte
		Fwd                           bool
	}{hostKey, sid, ssh.Marshal(sig), false}))
	if err == nil {
		t.Fatal("session-bind with an unparseable host key must fail")
	}
	lines := logs()
	if len(lines) != 1 {
		t.Fatalf("want exactly one log line, got %d: %q", len(lines), lines)
	}
	if strings.ContainsAny(lines[0], "\n\r\x1b") || hasControl(lines[0]) {
		t.Fatalf("log line carries client-chosen control characters: %q", lines[0])
	}
	if !strings.HasPrefix(lines[0], "agent: refusing session-bind") {
		t.Fatalf("log line must start with the fixed message: %q", lines[0])
	}
}

// A hostile key algorithm in the userauth's host key (sign path) and in
// the SSHSIG namespace must not reach the log raw either; the sign path
// logs a fixed message with an internal reason only.
func TestHostileSignRequestDoesNotForgeLogLines(t *testing.T) {
	e := newEnv(t)
	logs := captureLog(e)
	c, _ := e.client(t, e.peer)
	if err := e.bind(t, c, bytes.Repeat([]byte{9}, 32), false); err != nil {
		t.Fatal(err)
	}
	// A userauth for another session, with a namespace-looking control
	// payload, is refused and logged once.
	data := userauth(bytes.Repeat([]byte{8}, 32), e.pub.Marshal(), nil)
	if _, err := c.Sign(e.pub, data); err == nil {
		t.Fatal("userauth for a session other than the bound one must fail")
	}
	// SSHSIG namespace with control characters is allowed through the
	// broker (it is shown sanitised) and must not log raw either.
	if _, err := c.Sign(e.pub, sshsig("x\n\x1b[2Jagent: forged")); err != nil {
		t.Fatal(err)
	}
	for _, l := range logs() {
		if strings.ContainsAny(l, "\n\r\x1b") || hasControl(l) {
			t.Fatalf("log line carries control characters: %q", l)
		}
	}
	for _, l := range e.sink.Lines() {
		if hasControl(l) {
			t.Fatalf("audit line carries control characters: %q", l)
		}
	}
}

// quiet asserts that nothing on the connection was prompted or signed,
// that every refused SIGN_REQUEST so far was audited as blocked (spec 4.6:
// every request is logged) and that every captured log line is a fixed
// message.
func quiet(t *testing.T, e *env, logs func() []string, prefix string) {
	t.Helper()
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatalf("must neither prompt nor sign; shown %d signs %d",
			len(e.f.Shown()), e.f.SignCalls())
	}
	refusedAudited(t, e, -1)
	for _, l := range logs() {
		if strings.ContainsAny(l, "\n\r\x1b") || hasControl(l) {
			t.Fatalf("log line carries control characters: %q", l)
		}
		if !strings.HasPrefix(l, "agent: refusing ") {
			t.Fatalf("unexpected log line %q", l)
		}
	}
	if prefix != "" {
		for _, l := range logs() {
			if strings.HasPrefix(l, prefix) {
				return
			}
		}
		t.Fatalf("no log line starts with %q: %q", prefix, logs())
	}
}

// Destination spoofing through a duplicate session-bind. On a forwarded
// connection the remote ssh (which an attacker on that host controls)
// binds the genuine session to github.com, then re-binds the same session
// ID under a key of its own. OpenSSH's ssh-agent refuses to record a
// session ID twice ("session ID recorded against different key"); nazar
// used to append it and judge the userauth by the latest bind, so the
// prompt and the audit line said "host key SHA256:…" instead of
// github.com. The re-bind must fail and mark the connection.
func TestRebindingSessionUnderAnotherKeyIsRefused(t *testing.T) {
	e := newEnv(t)
	logs := captureLog(e)
	c, _ := e.client(t, e.peer)
	sid := e.forward(t, c)
	attacker := otherHostSigner(t)
	for _, fwd := range []bool{false, true} {
		if err := bindWith(c, attacker, sid, fwd); err == nil {
			t.Fatalf("re-binding a recorded session ID under another key (fwd=%v) must fail", fwd)
		}
	}
	for name, hk := range map[string]ssh.PublicKey{
		"plain publickey":    nil,
		"hostbound genuine":  e.signer.PublicKey(),
		"hostbound attacker": attacker.PublicKey(),
	} {
		if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), hk)); err == nil {
			t.Fatalf("%s: sign for the re-bound session must fail", name)
		}
	}
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("SSHSIG after a refused bind must fail")
	}
	quiet(t, e, logs, "agent: refusing session-bind: ")
	for _, l := range logs() {
		if strings.Contains(l, "SHA256") {
			t.Fatalf("the refusal names no key: %q", l)
		}
	}
}

// The duplicate check is its own rule, not a side effect of the
// authentication bind being final: among stacked forwarding binds a
// session ID is recorded once, whether the second bind carries another
// key or the very same one (OpenSSH tolerates the latter as a no-op;
// nazar refuses it, since no ssh sends it).
func TestDuplicateSessionBindIsRefused(t *testing.T) {
	sid := bytes.Repeat([]byte{5}, 32)
	for name, second := range map[string]func(t *testing.T, e *env, c agent.ExtendedAgent) error{
		"another key": func(t *testing.T, e *env, c agent.ExtendedAgent) error {
			return bindWith(c, otherHostSigner(t), sid, true)
		},
		"same key": func(t *testing.T, e *env, c agent.ExtendedAgent) error { return e.bind(t, c, sid, true) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			logs := captureLog(e)
			c, _ := e.client(t, e.peer)
			if err := e.bind(t, c, sid, true); err != nil {
				t.Fatal(err)
			}
			if err := second(t, e, c); err == nil {
				t.Fatal("a session ID already recorded on the connection must not bind again")
			}
			// A later, genuine authentication bind does not lift the mark.
			if err := e.bind(t, c, bytes.Repeat([]byte{6}, 32), false); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{6}, 32), e.pub.Marshal(), e.signer.PublicKey())); err == nil {
				t.Fatal("sign after a refused duplicate bind must fail")
			}
			if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
				t.Fatal("SSHSIG after a refused duplicate bind must fail")
			}
			quiet(t, e, logs, "agent: refusing session-bind: session ID already recorded")
		})
	}
}

// As OpenSSH ("attempt to bind session ID to socket previously bound for
// authentication attempt"): once a connection is bound for authentication
// (is_forwarding false) nothing else binds on it, forwarding or not.
func TestBindAfterAuthenticationBindIsRefused(t *testing.T) {
	for name, fwd := range map[string]bool{"authentication": false, "forwarding": true} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			logs := captureLog(e)
			c, _ := e.client(t, e.peer)
			sid1, sid2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
			if err := e.bind(t, c, sid1, false); err != nil {
				t.Fatal(err)
			}
			if err := e.bind(t, c, sid2, fwd); err == nil {
				t.Fatal("a bind after the authentication bind must fail")
			}
			for _, sid := range [][]byte{sid1, sid2} {
				for _, hk := range []ssh.PublicKey{nil, e.signer.PublicKey()} {
					if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), hk)); err == nil {
						t.Fatal("sign after a refused bind must fail")
					}
				}
			}
			if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
				t.Fatal("SSHSIG after a refused bind must fail")
			}
			quiet(t, e, logs, "agent: refusing session-bind: the connection is already bound for authentication")
		})
	}
}

// As OpenSSH ("tried to sign on forwarding hop"): a userauth for the
// session of a forwarding bind is never signed. The local ssh has already
// authenticated to that hop; only the remote side could ask for it. The
// connection itself stays usable: the remote ssh's own bind and git
// signing through the forwarded agent still work.
func TestUserauthOnForwardingHopIsRefused(t *testing.T) {
	e := newEnv(t)
	logs := captureLog(e)
	c, _ := e.client(t, e.peer)
	hop := bytes.Repeat([]byte{1}, 32)
	if err := e.bind(t, c, hop, true); err != nil {
		t.Fatal(err)
	}
	for _, hk := range []ssh.PublicKey{nil, e.signer.PublicKey()} {
		if _, err := c.Sign(e.pub, userauth(hop, e.pub.Marshal(), hk)); err == nil {
			t.Fatal("userauth on the forwarding hop must fail")
		}
	}
	quiet(t, e, logs, "agent: refusing to sign with github: userauth on a forwarding hop")
	if _, err := c.Sign(e.pub, sshsig("git")); err != nil {
		t.Fatalf("git signing through the forwarded agent: %v", err)
	}
	sid := bytes.Repeat([]byte{2}, 32)
	if err := e.bind(t, c, sid, false); err != nil {
		t.Fatalf("the remote ssh's own bind: %v", err)
	}
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatalf("userauth for the remote ssh's session: %v", err)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 || e.f.SignCalls() != 2 {
		t.Fatalf("shown %d signs %d, want 2 and 2", n, e.f.SignCalls())
	}
	if got := e.f.Shown()[1].Prompt.Lines[0]; got != "login to github.com (via a forwarded agent) as git" {
		t.Fatalf("summary %q", got)
	}
}

// As OpenSSH ("no hostkey recorded in signature for forwarded connection"):
// on a forwarded connection the userauth must carry the host key, so the
// destination shown is the one the signature itself is bound to, not only
// the one a bind claimed for that session ID. A direct connection keeps
// accepting plain publickey, for servers without hostbound userauth.
func TestForwardedUserauthMustCarryHostKey(t *testing.T) {
	e := newEnv(t)
	logs := captureLog(e)
	c, _ := e.client(t, e.peer)
	sid := e.forward(t, c)
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), nil)); err == nil {
		t.Fatal("plain publickey userauth on a forwarded connection must fail")
	}
	quiet(t, e, logs, "agent: refusing to sign with github: userauth carries no host key on a forwarded connection")
	if _, err := c.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatalf("hostbound userauth on a forwarded connection: %v", err)
	}
	// Contrast: a direct connection, plain publickey.
	c2, _ := e.client(t, e.peer)
	if err := e.bind(t, c2, sid, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Sign(e.pub, userauth(sid, e.pub.Marshal(), nil)); err != nil {
		t.Fatalf("plain publickey userauth on a direct connection: %v", err)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 || e.f.SignCalls() != 2 {
		t.Fatalf("shown %d signs %d, want 2 and 2", n, e.f.SignCalls())
	}
}

// --- Accept loop resilience (adversarial review) ---

// TestServeSurvivesAcceptFailure: a transient accept error must not end
// Serve. The daemon runs Serve on a goroutine and discards its result, and
// the socket stays bound while nobody accepts, so a dead loop would leave
// every later ssh and git hanging on REQUEST_IDENTITIES instead of failing,
// silently and for good. Plain fd pressure provokes it, and so can a
// forwarded peer, which turns every agent channel it opens into one local
// connection. Here accept fails with EMFILE: every fd number below a
// lowered RLIMIT_NOFILE is used up except one, which the client's socket()
// takes, so the server's accept() has none left. Once descriptors are
// freed Serve must still be accepting, and it must end only when the
// listener is closed.
func TestServeSurvivesAcceptFailure(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaultPeer(e.peer)
	acceptErr := make(chan string, 16)
	e.srv.Logf = func(format string, args ...any) {
		if strings.HasPrefix(format, "agent: accept:") {
			select {
			case acceptErr <- fmt.Sprintf(format, args...):
			default:
			}
		}
	}
	path, _, serveDone := listenAgent(t, e)

	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		t.Fatal(err)
	}
	probe, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Close(probe)
	low := orig
	low.Cur = uint64(probe) + 8 // the lowest free fd number plus a few
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Fatal(err)
	}
	var fill []int
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			for _, fd := range fill {
				syscall.Close(fd)
			}
			if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
				t.Errorf("restoring RLIMIT_NOFILE: %v", err)
			}
		})
	}
	defer restore()
	for {
		fd, err := syscall.Open("/dev/null", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			if !errors.Is(err, syscall.EMFILE) {
				restore()
				t.Fatal(err)
			}
			break
		}
		fill = append(fill, fd)
	}
	if len(fill) == 0 {
		restore()
		t.Fatal("could not use up the fd table")
	}
	// Exactly one fd number is free now: the client's socket.
	syscall.Close(fill[len(fill)-1])
	fill = fill[:len(fill)-1]

	list := func() ([]*agent.Key, error) {
		conn, err := net.Dial("unix", path)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(20 * time.Second))
		return agent.NewClient(conn).List()
	}
	type outcome struct {
		keys []*agent.Key
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		keys, err := list()
		done <- outcome{keys, err}
	}()
	select {
	case msg := <-acceptErr:
		if !strings.Contains(msg, "too many open files") {
			t.Logf("accept failed with %q (expected EMFILE, but any transient error will do)", msg)
		}
	case <-time.After(5 * time.Second):
		restore()
		t.Fatal("the server never reported an accept failure (or does not log one)")
	}
	restore()
	// The triggering client is either served once the loop recovers (Linux
	// leaves it queued) or told so at once (XNU closes the connection whose
	// accept failed); it must not hang either way.
	select {
	case o := <-done:
		if o.err != nil {
			t.Logf("the client that hit the failure got: %v", o.err)
		} else if len(o.keys) != 1 {
			t.Fatalf("got %d keys, want 1", len(o.keys))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the client that hit the accept failure hangs")
	}
	// Serve is still running and accepting: the next client is served.
	// listenAgent's cleanup then closes the listener and checks that Serve
	// returns.
	select {
	case err := <-serveDone:
		t.Fatalf("Serve returned %v on a transient accept error; it must keep accepting", err)
	default:
	}
	keys, err := list()
	if err != nil {
		t.Fatalf("Serve stopped accepting after a transient accept error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
}

// Milestone 7: a session approval covers one destination, the
// server whose host key the session-bind proved. A login to another server
// from the same tab asks again (and the dialog says what the tab already
// has); a second login to either does not. What is remembered is keyed by
// the host key's fingerprint and shown by the known_hosts name.
func TestApprovalCoversOneDestination(t *testing.T) {
	e := newEnv(t)
	other := otherHostSigner(t)
	login := func(signer ssh.Signer, sid byte) {
		t.Helper()
		c, _ := e.client(t, e.peer)
		s := bytes.Repeat([]byte{sid}, 32)
		if err := bindWith(c, signer, s, false); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Sign(e.pub, userauth(s, e.pub.Marshal(), signer.PublicKey())); err != nil {
			t.Fatal(err)
		}
	}
	login(e.signer, 1)
	login(other, 2)
	login(e.signer, 3)
	login(other, 4)
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("%d dialogs, want one per server", n)
	}
	lines := e.sink.Lines()
	if len(lines) != 4 {
		t.Fatalf("%d audit lines, want 4", len(lines))
	}
	for i, want := range []string{"approved", "approved", "allowed", "allowed"} {
		f, err := audit.ParseLine(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		if f["decision"] != want {
			t.Fatalf("login %d: decision %q, want %q (%v)", i+1, f["decision"], want, f)
		}
	}
	ghFP, otherFP := ssh.FingerprintSHA256(e.signer.PublicKey()), ssh.FingerprintSHA256(other.PublicKey())
	got := map[string]string{}
	for _, en := range e.cache.List() {
		got[en.Key.Op] = en.Covers
	}
	if len(got) != 2 || got["login:"+ghFP] != "github.com" || got["login:"+otherFP] != "host key "+otherFP {
		t.Fatalf("remembered %+v, want the two servers by host key", got)
	}
	shown := e.f.Shown()
	if text := strings.Join(shown[0].Prompt.Lines, "\n"); !strings.Contains(text, "Scope: this terminal session, for github.com only") || strings.Contains(text, "Already approved") {
		t.Fatalf("first dialog:\n%s", text)
	}
	if text := strings.Join(shown[1].Prompt.Lines, "\n"); !strings.Contains(text, "Scope: this terminal session, for host key "+otherFP+" only") || !strings.Contains(text, "Already approved for this terminal session: github.com") {
		t.Fatalf("second dialog:\n%s", text)
	}
}

// A login approval does not cover signing, nor one namespace another, nor
// an unbound login a proved one: each kind asks once and is then remembered
// on its own.
func TestLoginApprovalDoesNotCoverSigning(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	sid := bytes.Repeat([]byte{7}, 32)
	if err := e.bind(t, c, sid, false); err != nil {
		t.Fatal(err)
	}
	unbound, _ := e.client(t, e.peer)
	requests := []struct {
		name string
		c    agent.ExtendedAgent
		data []byte
		op   string
	}{
		{"login", c, userauth(sid, e.pub.Marshal(), e.signer.PublicKey()), "login:" + ssh.FingerprintSHA256(e.signer.PublicKey())},
		{"git", c, sshsig("git"), "sign:git"},
		{"file", c, sshsig("file"), "sign:ns:file"},
		{"unbound login", unbound, userauth(bytes.Repeat([]byte{8}, 32), e.pub.Marshal(), nil), "login:unbound"},
		{"raw data", c, []byte("not a payload"), "sign:data"},
	}
	for i, r := range requests {
		for j := 0; j < 2; j++ {
			if _, err := r.c.Sign(e.pub, r.data); err != nil {
				t.Fatalf("%s #%d: %v", r.name, j+1, err)
			}
		}
		if n := e.f.CountShown(fake.KindConfirm); n != i+1 {
			t.Fatalf("%s: %d dialogs after it, want %d (one per kind, then remembered)", r.name, n, i+1)
		}
	}
	ops := map[string]string{}
	for _, en := range e.cache.List() {
		ops[en.Key.Op] = en.Covers
	}
	for _, r := range requests {
		if _, ok := ops[r.op]; !ok {
			t.Fatalf("%s: no approval remembered under %q; have %v", r.name, r.op, ops)
		}
	}
	if len(ops) != len(requests) || ops["sign:git"] != "git commits and tags" || ops["sign:ns:file"] != `data in namespace "file"` || ops["login:unbound"] != "unidentified servers" || ops["sign:data"] != "unrecognized data" {
		t.Fatalf("remembered %v", ops)
	}
}

// A namespace is never one of the fixed kinds: an approval for signatures
// in namespace "data" (or one that only prints as "data" or "git") does not
// cover unrecognised data or git commits, nor they it, in either order.
func TestNamespaceIsNotAFixedKind(t *testing.T) {
	raw := []byte("not a payload")
	for _, tc := range []struct {
		name        string
		first, then []byte
		a, b        string
	}{
		{"namespace data, then raw data", sshsig("data"), raw, `data in namespace "data"`, "unrecognized data"},
		{"raw data, then namespace data", raw, sshsig("data"), "unrecognized data", `data in namespace "data"`},
		{"look-alike data, then raw data", sshsig("da​ta"), raw, `data in namespace "data"`, "unrecognized data"},
		{"look-alike git, then git", sshsig("git\x00"), sshsig("git"), `data in namespace "git"`, "git commits and tags"},
		{"git, then look-alike git", sshsig("git"), sshsig("git\x00"), "git commits and tags", `data in namespace "git"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			c, _ := e.client(t, e.peer)
			for _, data := range [][]byte{tc.first, tc.then} {
				if _, err := c.Sign(e.pub, data); err != nil {
					t.Fatal(err)
				}
			}
			if n := e.f.CountShown(fake.KindConfirm); n != 2 {
				t.Fatalf("%d dialogs, want 2: one approval covered the other kind", n)
			}
			covers := map[string]bool{}
			for _, en := range e.cache.List() {
				covers[en.Covers] = true
			}
			if len(e.cache.List()) != 2 || !covers[tc.a] || !covers[tc.b] {
				t.Fatalf("remembered %+v, want %q and %q apart", e.cache.List(), tc.a, tc.b)
			}
		})
	}
}

// An approval for one namespace never covers another, however the two
// print: one that differs only by a rune Printable drops, or one that shares
// its first 64 characters (all the dialog and audit line show) with the
// approved one, asks on its own. sshsig verifiers compare namespaces byte for
// byte.
func TestNamespaceKeyedExactly(t *testing.T) {
	long := strings.Repeat("n", 64)
	for _, tc := range []struct{ name, approved, other string }{
		{"zero-width rune", "file", "file\u200b"},
		{"NUL", "file", "fi\x00le"},
		{"past 64 characters", long + ".staging", long + ".production"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			c, _ := e.client(t, e.peer)
			for _, ns := range []string{tc.approved, tc.other, tc.approved, tc.other} {
				if _, err := c.Sign(e.pub, sshsig(ns)); err != nil {
					t.Fatal(err)
				}
			}
			if n := e.f.CountShown(fake.KindConfirm); n != 2 {
				t.Fatalf("%d dialogs, want 2: the approval for %q covered %q", n, tc.approved, tc.other)
			}
			if l := e.cache.List(); len(l) != 2 || l[0].Key.Op == l[1].Key.Op {
				t.Fatalf("remembered %+v, want two namespaces apart", l)
			}
		})
	}
}

// A host key the userauth itself carries (publickey-hostbound) with no
// session-bind is the client's word: it names no destination, and the
// approval is remembered as an unbound login, which a later login to the
// server really proved does not ride on.
func TestUnprovedHostKeyNamesNothing(t *testing.T) {
	e := newEnv(t)
	c, _ := e.client(t, e.peer)
	if _, err := c.Sign(e.pub, userauth(bytes.Repeat([]byte{3}, 32), e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if got := e.f.Shown()[0].Prompt.Lines[0]; got != "login to an unidentified server as git" {
		t.Fatalf("summary %q: an unproved host key must not name github.com", got)
	}
	if f, _ := audit.ParseLine(e.sink.Lines()[0]); f["destination"] != "" {
		t.Fatalf("audit destination %q, want none", f["destination"])
	}
	if l := e.cache.List(); len(l) != 1 || l[0].Key.Op != "login:unbound" || l[0].Covers != "unidentified servers" {
		t.Fatalf("remembered %+v", l)
	}
	bound, _ := e.client(t, e.peer)
	sid := bytes.Repeat([]byte{4}, 32)
	if err := e.bind(t, bound, sid, false); err != nil {
		t.Fatal(err)
	}
	if _, err := bound.Sign(e.pub, userauth(sid, e.pub.Marshal(), e.signer.PublicKey())); err != nil {
		t.Fatal(err)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("%d dialogs: the proved login must not ride on the unbound approval", n)
	}
	if got := e.f.Shown()[1].Prompt.Lines[0]; got != "login to github.com as git" {
		t.Fatalf("summary %q", got)
	}
	if l := e.cache.List(); len(l) != 2 {
		t.Fatalf("remembered %+v, want the unbound and the proved login apart", l)
	}
}
