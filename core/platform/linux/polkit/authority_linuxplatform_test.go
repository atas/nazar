//go:build linux && linuxplatform

// Check against stand-ins for polkitd and logind on a private bus
// (dbustest): the answers the container's real polkitd cannot be made to
// give, and the ones a wedged or broken daemon would.
package polkit_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/internal/linuxtest/dbustest"
)

const (
	authorityPath  = dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority")
	authorityIface = "org.freedesktop.PolicyKit1.Authority"
	sessionPath    = dbus.ObjectPath("/org/freedesktop/login1/session/c2")
)

// reply is CheckAuthorization's return value, (bba{ss}).
type reply struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

// handler is a method table for ExportMethodTable.
type handler = map[string]any

// privateBus returns two connections to one private bus: the stand-ins'
// and the one Check uses.
func privateBus(t *testing.T) (server, client *dbus.Conn) {
	t.Helper()
	address := dbustest.Start(t)
	connect := func() *dbus.Conn {
		conn, err := dbus.Connect(address)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	return connect(), connect()
}

func own(t *testing.T, conn *dbus.Conn, name string) {
	t.Helper()
	r, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
	if err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("own %s: %v, %v", name, r, err)
	}
}

// serveAuthority answers on server as polkitd, with the method table given.
func serveAuthority(t *testing.T, server *dbus.Conn, methods handler) {
	t.Helper()
	if err := server.ExportMethodTable(methods, authorityPath, authorityIface); err != nil {
		t.Fatal(err)
	}
	own(t, server, "org.freedesktop.PolicyKit1")
}

// authorityReturning is an authority whose CheckAuthorization returns fn's
// value, and counts the calls.
func authorityReturning[R any](calls *atomic.Int32, fn func() R) handler {
	return handler{"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) (R, *dbus.Error) {
		calls.Add(1)
		return fn(), nil
	}}
}

// serveLogindManager answers GetSession on server as logind: session c2 is
// at sessionPath, any other is unknown.
func serveLogindManager(t *testing.T, server *dbus.Conn) {
	t.Helper()
	err := server.ExportMethodTable(handler{"GetSession": func(id string) (dbus.ObjectPath, *dbus.Error) {
		if id != "c2" {
			return "", dbus.NewError("org.freedesktop.login1.NoSuchSession", []any{"No session '" + id + "' known"})
		}
		return sessionPath, nil
	}}, "/org/freedesktop/login1", "org.freedesktop.login1.Manager")
	if err != nil {
		t.Fatal(err)
	}
	own(t, server, "org.freedesktop.login1")
}

// serveSessionUser answers the session's User property with value.
func serveSessionUser(t *testing.T, server *dbus.Conn, value any) {
	t.Helper()
	err := server.ExportMethodTable(handler{"Get": func(iface, prop string) (dbus.Variant, *dbus.Error) {
		if iface != "org.freedesktop.login1.Session" || prop != "User" {
			return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.UnknownProperty", nil)
		}
		return dbus.MakeVariant(value), nil
	}}, sessionPath, "org.freedesktop.DBus.Properties")
	if err != nil {
		t.Fatal(err)
	}
}

// sessionUser is logind's User property, (uo).
func sessionUser(uid uint32) any {
	return struct {
		UID  uint32
		Path dbus.ObjectPath
	}{uid, "/org/freedesktop/login1/user/_1"}
}

func ownProcessSubject() polkit.Subject {
	return polkit.ProcessSubject(os.Getpid(), 1, os.Getuid())
}

func checkWith(conn *dbus.Conn, subject polkit.Subject) error {
	auth := polkit.New(conn, func() (polkit.Subject, error) { return subject, nil })
	return auth.Check(prompt(5 * time.Second))
}

// wantFailsClosed: an error, and not a refusal, so the log says what broke.
func wantFailsClosed(t *testing.T, err error, text string) {
	t.Helper()
	if err == nil {
		t.Fatal("Check = nil, want an error")
	}
	if errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Check = %v, want an error other than ErrDenied", err)
	}
	if !strings.Contains(err.Error(), text) {
		t.Fatalf("Check = %v, want it to mention %q", err, text)
	}
}

// Anchors the failures below: the stand-in's yes, no and "no agent".
func TestAuthorityReplies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply reply
		check func(error) bool
	}{
		{"authorized", reply{IsAuthorized: true}, func(e error) bool { return e == nil }},
		{"refused", reply{}, func(e error) bool { return errors.Is(e, platform.ErrDenied) }},
		{"no agent", reply{IsChallenge: true}, func(e error) bool {
			return e != nil && !errors.Is(e, platform.ErrDenied) && strings.Contains(e.Error(), "no polkit authentication agent")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := privateBus(t)
			var calls atomic.Int32
			serveAuthority(t, server, authorityReturning(&calls, func() reply { return tc.reply }))
			if err := checkWith(client, ownProcessSubject()); !tc.check(err) {
				t.Fatalf("Check = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("the authority was asked %d times, want 1", calls.Load())
			}
		})
	}
}

// polkit not running: nobody owns its name.
func TestPolkitDownIsAnError(t *testing.T) {
	_, client := privateBus(t)
	start := time.Now()
	wantFailsClosed(t, checkWith(client, ownProcessSubject()), "polkit: CheckAuthorization")
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Check took %v, want a quick error", took)
	}
}

func TestClosedConnectionIsAnError(t *testing.T) {
	_, client := privateBus(t)
	client.Close()
	wantFailsClosed(t, checkWith(client, ownProcessSubject()), "polkit: CheckAuthorization")
}

// polkitd's own errors fail closed; only its Cancelled is a refusal.
func TestAuthorityErrors(t *testing.T) {
	for _, tc := range []struct{ name, errName, text string }{
		{"not an owner", "org.freedesktop.PolicyKit1.Error.NotAuthorized", "Only trusted callers (e.g. uid 0 or an action owner) can use CheckAuthorization() and pass details"},
		{"failed", "org.freedesktop.PolicyKit1.Error.Failed", "Action dev.nazar.authenticate is not registered"},
		{"any other", "org.freedesktop.DBus.Error.NoMemory", "out of memory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := privateBus(t)
			serveAuthority(t, server, handler{"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) (reply, *dbus.Error) {
				return reply{}, dbus.NewError(tc.errName, []any{tc.text})
			}})
			wantFailsClosed(t, checkWith(client, ownProcessSubject()), tc.text)
		})
	}
}

// A user who is not an owner of the action is told the one command that
// fixes it; the check still fails closed.
func TestNotOwnerNamesInstall(t *testing.T) {
	server, client := privateBus(t)
	serveAuthority(t, server, handler{"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) (reply, *dbus.Error) {
		return reply{}, dbus.NewError("org.freedesktop.PolicyKit1.Error.NotAuthorized", []any{"Only trusted callers (e.g. uid 0 or an action owner) can use CheckAuthorization() and pass details"})
	}})
	wantFailsClosed(t, checkWith(client, ownProcessSubject()), `sudo "$(command -v nazar)" install --system`)
}

// Another NotAuthorized is not about ownership and names no fix.
func TestOtherNotAuthorizedNamesNoFix(t *testing.T) {
	server, client := privateBus(t)
	serveAuthority(t, server, handler{"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) (reply, *dbus.Error) {
		return reply{}, dbus.NewError("org.freedesktop.PolicyKit1.Error.NotAuthorized", []any{"Not authorized"})
	}})
	err := checkWith(client, ownProcessSubject())
	wantFailsClosed(t, err, "Not authorized")
	if strings.Contains(err.Error(), "install --system") {
		t.Fatalf("Check = %v, want no install hint", err)
	}
}

func TestCancelledByPolkitIsDenied(t *testing.T) {
	server, client := privateBus(t)
	serveAuthority(t, server, handler{"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) (reply, *dbus.Error) {
		return reply{}, dbus.NewError("org.freedesktop.PolicyKit1.Error.Cancelled", []any{"Authentication dialog was dismissed by the user"})
	}})
	if err := checkWith(client, ownProcessSubject()); !errors.Is(err, platform.ErrDenied) {
		t.Fatalf("Check = %v, want ErrDenied", err)
	}
}

// A reply that is not (bba{ss}) is not a yes, however yes it looks.
func TestMalformedRepliesAreErrors(t *testing.T) {
	type bb struct{ A, B bool }
	type bbds struct {
		A, B bool
		D    map[string]string
		S    string
	}
	type ssd struct {
		A, B string
		D    map[string]string
	}
	var calls atomic.Int32
	methods := map[string]handler{
		"a bool":     authorityReturning(&calls, func() bool { return true }),
		"a string":   authorityReturning(&calls, func() string { return "yes" }),
		"no details": authorityReturning(&calls, func() bb { return bb{true, false} }),
		"an extra":   authorityReturning(&calls, func() bbds { return bbds{A: true, D: map[string]string{}} }),
		"strings":    authorityReturning(&calls, func() ssd { return ssd{"true", "false", map[string]string{}} }),
		"not a struct": {"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) (bool, bool, map[string]string, *dbus.Error) {
			calls.Add(1)
			return true, false, map[string]string{}, nil
		}},
		"nothing": {"CheckAuthorization": func(polkit.Subject, string, map[string]string, uint32, string) *dbus.Error {
			calls.Add(1)
			return nil
		}},
	}
	for name, m := range methods {
		t.Run(name, func(t *testing.T) {
			calls.Store(0)
			server, client := privateBus(t)
			serveAuthority(t, server, m)
			wantFailsClosed(t, checkWith(client, ownProcessSubject()), "polkit: CheckAuthorization reply")
			if calls.Load() != 1 {
				t.Fatalf("the authority was asked %d times, want 1", calls.Load())
			}
		})
	}
}

// A polkitd that takes the check and the cancel and answers neither: Check
// is a refusal within the timeout plus its grace, and it did cancel the
// check it asked for.
func TestWedgedPolkitDoesNotHang(t *testing.T) {
	server, client := privateBus(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	checkID := make(chan string, 1)
	cancelID := make(chan string, 1)
	serveAuthority(t, server, handler{
		"CheckAuthorization": func(_ polkit.Subject, _ string, _ map[string]string, _ uint32, id string) (reply, *dbus.Error) {
			checkID <- id
			<-release
			return reply{IsAuthorized: true}, nil
		},
		"CancelCheckAuthorization": func(id string) *dbus.Error {
			cancelID <- id
			<-release
			return nil
		},
	})
	auth := polkit.New(client, func() (polkit.Subject, error) { return ownProcessSubject(), nil })
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- auth.Check(prompt(time.Second)) }()
	select {
	case err := <-done:
		if !errors.Is(err, platform.ErrDenied) {
			t.Fatalf("Check = %v, want ErrDenied", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Check still blocked after 10 s, with a 1 s timeout and a 5 s grace")
	}
	if took := time.Since(start); took < time.Second {
		t.Fatalf("Check returned after %v, before its timeout", took)
	}
	select {
	case got := <-cancelID:
		if want := <-checkID; got != want {
			t.Fatalf("cancelled %q, the check was %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("the check was not cancelled")
	}
}

// Production's subject is a session, which names no user: logind says
// whose it is, and only this user's reaches polkit.
func TestSessionSubject(t *testing.T) {
	me := uint32(os.Getuid())
	for _, tc := range []struct {
		name    string
		uid     uint32
		session string
		asked   int32
		text    string // empty: Check is nil
	}{
		{name: "this user's", uid: me, session: "c2", asked: 1},
		{name: "root's", uid: 0, session: "c2", text: "root subject"},
		{name: "another user's", uid: me + 1, session: "c2", text: fmt.Sprintf("subject uid %d is not this user", me+1)},
		{name: "unknown", uid: me, session: "c9", text: "No session 'c9' known"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := privateBus(t)
			var calls atomic.Int32
			serveAuthority(t, server, authorityReturning(&calls, func() reply { return reply{IsAuthorized: true} }))
			serveLogindManager(t, server)
			serveSessionUser(t, server, sessionUser(tc.uid))
			err := checkWith(client, polkit.SessionSubject(tc.session))
			if tc.text == "" {
				if err != nil {
					t.Fatalf("Check = %v, want nil", err)
				}
			} else {
				wantFailsClosed(t, err, tc.text)
			}
			if calls.Load() != tc.asked {
				t.Fatalf("polkit was asked %d times, want %d", calls.Load(), tc.asked)
			}
		})
	}
}

// With no logind to say whose session it is, polkit is not asked.
func TestSessionSubjectNoLogind(t *testing.T) {
	server, client := privateBus(t)
	var calls atomic.Int32
	serveAuthority(t, server, authorityReturning(&calls, func() reply { return reply{IsAuthorized: true} }))
	start := time.Now()
	wantFailsClosed(t, checkWith(client, polkit.SessionSubject("c2")), "polkit: subject: session c2")
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("Check took %v, want a quick error", took)
	}
	if calls.Load() != 0 {
		t.Fatalf("polkit was asked %d times, want 0", calls.Load())
	}
}

// A logind that never answers does not hold Check either.
func TestSessionSubjectWedgedLogind(t *testing.T) {
	server, client := privateBus(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	err := server.ExportMethodTable(handler{"GetSession": func(string) (dbus.ObjectPath, *dbus.Error) {
		<-release
		return sessionPath, nil
	}}, "/org/freedesktop/login1", "org.freedesktop.login1.Manager")
	if err != nil {
		t.Fatal(err)
	}
	own(t, server, "org.freedesktop.login1")
	done := make(chan error, 1)
	go func() { done <- checkWith(client, polkit.SessionSubject("c2")) }()
	select {
	case err := <-done:
		wantFailsClosed(t, err, "polkit: subject: session c2")
	case <-time.After(5 * time.Second):
		t.Fatal("Check still blocked after 5 s on a logind that does not answer")
	}
}

// A session whose user is not (uo) names nobody.
func TestSessionSubjectOddUser(t *testing.T) {
	server, client := privateBus(t)
	serveLogindManager(t, server)
	serveSessionUser(t, server, "nazartest")
	wantFailsClosed(t, checkWith(client, polkit.SessionSubject("c2")), "its user")
}
