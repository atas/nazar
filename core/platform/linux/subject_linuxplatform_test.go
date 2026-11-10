//go:build linux && linuxplatform

package linux

// The default polkit subject, the login gate's subject in production. The
// conformance run passes its own Subject, so this is where the default is
// run: against fakelogind and a stand-in for polkitd on a private bus, which
// records who it was asked about.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/session"
	"github.com/atas/nazar/core/platform/linux/vault"
	"github.com/atas/nazar/internal/linuxtest/dbustest"
	"github.com/atas/nazar/internal/linuxtest/fakelogind"
	"github.com/atas/nazar/internal/linuxtest/swtpm"
)

// subjectBus starts a private bus and returns a function that opens one
// more connection to it.
func subjectBus(t *testing.T) func() *dbus.Conn {
	t.Helper()
	address := dbustest.Start(t)
	return func() *dbus.Conn {
		conn, err := dbus.Connect(address)
		if err != nil {
			t.Fatalf("connect %s: %v", address, err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
}

// wantSessionSubject checks s is the unix-session subject of session id.
func wantSessionSubject(t *testing.T, s polkit.Subject, id string) {
	t.Helper()
	if s.Kind != "unix-session" {
		t.Fatalf("subject kind = %q, want unix-session", s.Kind)
	}
	if got := s.Details["session-id"].Value(); got != id {
		t.Fatalf("subject session-id = %v, want %q", got, id)
	}
}

// The subject is the display session, as logind says at the time of asking.
func TestDisplaySubjectIsTheDisplaySession(t *testing.T) {
	connect := subjectBus(t)
	uid := os.Getuid()
	l := fakelogind.Serve(t, connect(), uid)
	p := &Platform{session: session.New(connect(), nil, uid)}
	t.Cleanup(p.session.Close)

	s, err := p.displaySubject()
	if err != nil {
		t.Fatalf("displaySubject: %v", err)
	}
	wantSessionSubject(t, s, fakelogind.GraphicalSession)

	l.SetDisplay(fakelogind.X11Session)
	s, err = p.displaySubject()
	if err != nil {
		t.Fatalf("displaySubject after the display changed: %v", err)
	}
	wantSessionSubject(t, s, fakelogind.X11Session)
}

// With no session to name there is no subject: an error, never a subject
// polkit could be asked about.
func TestDisplaySubjectNoSession(t *testing.T) {
	t.Run("no graphical session", func(t *testing.T) {
		connect := subjectBus(t)
		uid := os.Getuid()
		l := fakelogind.Serve(t, connect(), uid)
		l.SetDisplay(fakelogind.TTYSession)
		l.SetNoGraphicalSession()
		p := &Platform{session: session.New(connect(), nil, uid)}
		t.Cleanup(p.session.Close)
		if s, err := p.displaySubject(); err == nil {
			t.Fatalf("displaySubject = %+v, want an error", s)
		}
	})
	t.Run("no connection to logind", func(t *testing.T) {
		p := &Platform{session: session.New(nil, nil, os.Getuid())}
		t.Cleanup(p.session.Close)
		if s, err := p.displaySubject(); err == nil {
			t.Fatalf("displaySubject = %+v, want an error", s)
		}
	})
}

// authorityReply is CheckAuthorization's return value, (bba{ss}).
type authorityReply struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

// defaultSubjectPlatform is a Platform from New with no Subject, its polkit
// and logind on one private bus with fakelogind, and the stand-in for
// polkitd that approves. The channel gets the subject of each check.
func defaultSubjectPlatform(t *testing.T) (*Platform, *fakelogind.Logind, <-chan polkit.Subject) {
	t.Helper()
	connect := subjectBus(t)
	uid := os.Getuid()
	l := fakelogind.Serve(t, connect(), uid)

	asked := make(chan polkit.Subject, 8)
	server := connect()
	err := server.ExportMethodTable(map[string]any{
		"CheckAuthorization": func(s polkit.Subject, _ string, _ map[string]string, _ uint32, _ string) (authorityReply, *dbus.Error) {
			asked <- s
			return authorityReply{IsAuthorized: true}, nil
		},
	}, "/org/freedesktop/PolicyKit1/Authority", "org.freedesktop.PolicyKit1.Authority")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := server.RequestName("org.freedesktop.PolicyKit1", dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("own polkit's name: %v, %v", r, err)
	}

	tr, err := linuxudstpm.Open(swtpm.Start(t))
	if err != nil {
		t.Fatalf("open swtpm: %v", err)
	}
	v, err := vault.Open(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	p, err := New(Options{
		Home:   t.TempDir(),
		TPM:    tr,
		Vault:  v,
		Polkit: connect(),
		Logind: connect(),
		UID:    uid,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p, l, asked
}

var subjectPrompt = platform.Prompt{Title: "nazar", Lines: []string{"a test"}, Timeout: 10 * time.Second}

// New with no Subject asks polkit about the display session.
func TestDefaultSubjectReachesPolkit(t *testing.T) {
	p, _, asked := defaultSubjectPlatform(t)
	ref, err := p.Authenticate(platform.AuthUserPresence, subjectPrompt)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !p.approvals.isLive(ref) {
		t.Fatalf("Authenticate gave ref %v, which is not live", ref)
	}
	select {
	case s := <-asked:
		wantSessionSubject(t, s, fakelogind.GraphicalSession)
	default:
		t.Fatal("polkit was not asked")
	}
}

// With no graphical session the default subject fails the login gate at
// once, with an error that is not the user's refusal: polkit is not asked
// and no ref is issued.
func TestDefaultSubjectNoGraphicalSessionFailsClosed(t *testing.T) {
	p, l, asked := defaultSubjectPlatform(t)
	l.SetDisplay(fakelogind.TTYSession)
	l.SetNoGraphicalSession()

	start := time.Now()
	ref, err := p.Authenticate(platform.AuthUserPresence, subjectPrompt)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Authenticate took %v, want a quick error", took)
	}
	if err == nil || errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Authenticate = %v, want an error other than ErrDenied", err)
	}
	if ref != 0 {
		t.Fatalf("Authenticate issued ref %v, want none", ref)
	}
	if len(p.approvals.live) != 0 {
		t.Fatalf("%d live refs, want none", len(p.approvals.live))
	}
	if len(asked) != 0 {
		t.Fatalf("polkit was asked %d times, want 0", len(asked))
	}
}
