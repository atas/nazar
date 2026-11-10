//go:build linux && linuxplatform

// The session on private buses: fakelogind stands in for logind and
// fakenotify for the desktop's notification server (test/linux/dbus-private.conf
// lets a test own both names). Nothing here reaches the host's system or
// session bus, and nothing shows a window or a notification on a desktop.
package session_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/session"
	"github.com/atas/nazar/internal/linuxtest/container"
	"github.com/atas/nazar/internal/linuxtest/dbustest"
	"github.com/atas/nazar/internal/linuxtest/fakelogind"
	"github.com/atas/nazar/internal/linuxtest/fakenotify"
)

func TestMain(m *testing.M) { os.Exit(container.Require(m)) }

const uid = 1000

// eventWait bounds how long a test waits for a signal to arrive.
const eventWait = 5 * time.Second

// quiet is how long a test waits to be sure an event does not arrive.
const quiet = 300 * time.Millisecond

// connect opens one connection to the private bus at address, closed at cleanup.
func connect(t *testing.T, address string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatalf("connect %s: %v", address, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// withLogind starts a private bus with fakelogind on it and a Session whose
// logind connection is a second connection to that bus.
func withLogind(t *testing.T) (*fakelogind.Logind, *session.Session) {
	t.Helper()
	address := dbustest.Start(t)
	l := fakelogind.Serve(t, connect(t, address), uid)
	s := session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	return l, s
}

func TestDisplaySession(t *testing.T) {
	_, s := withLogind(t)
	id, err := s.DisplaySession()
	if err != nil {
		t.Fatalf("DisplaySession: %v", err)
	}
	if id != fakelogind.GraphicalSession {
		t.Fatalf("DisplaySession = %q, want the user's Display %q", id, fakelogind.GraphicalSession)
	}
}

func TestDisplaySessionFallback(t *testing.T) {
	l, s := withLogind(t)
	l.SetNoDisplay()
	id, err := s.DisplaySession()
	if err != nil {
		t.Fatalf("DisplaySession with no Display: %v", err)
	}
	// The user's sessions list a tty session, then an inactive x11 session,
	// then the active wayland one; only the last counts. A reader that took
	// the first graphical session without looking at Active would answer
	// the x11 session.
	if id != fakelogind.GraphicalSession {
		t.Fatalf("DisplaySession with no Display = %q, want the active graphical session %q", id, fakelogind.GraphicalSession)
	}
}

// logind elects a tty session (an ssh or console login) as a user's Display
// when it has nothing better. A tty has no lock screen, so its LockedHint
// never turns true: trusting it would read as unlocked.
func TestDisplaySessionTTYDisplay(t *testing.T) {
	l, s := withLogind(t)
	l.SetDisplay(fakelogind.TTYSession)
	id, err := s.DisplaySession()
	if err != nil {
		t.Fatalf("DisplaySession with a tty Display: %v", err)
	}
	if id != fakelogind.GraphicalSession {
		t.Fatalf("DisplaySession with a tty Display = %q, want the active graphical session %q", id, fakelogind.GraphicalSession)
	}

	l.SetNoGraphicalSession()
	if id, err := s.DisplaySession(); err == nil {
		t.Fatalf("DisplaySession with a tty Display and no graphical session = %q, nil; want an error", id)
	}
	if locked, err := s.Locked(); err == nil {
		t.Fatalf("Locked with a tty Display and no graphical session = %v, nil; want an error (fail closed)", locked)
	}
}

func TestLocked(t *testing.T) {
	l, s := withLogind(t)
	if locked, err := s.Locked(); err != nil || locked {
		t.Fatalf("Locked at start = %v, %v; want false, nil", locked, err)
	}
	l.SetLocked(true)
	if locked, err := s.Locked(); err != nil || !locked {
		t.Fatalf("Locked after SetLocked(true) = %v, %v; want true, nil", locked, err)
	}
	l.SetLocked(false)
	if locked, err := s.Locked(); err != nil || locked {
		t.Fatalf("Locked after SetLocked(false) = %v, %v; want false, nil", locked, err)
	}
}

func TestLockedUnknownFailsClosed(t *testing.T) {
	t.Run("no logind on the bus", func(t *testing.T) {
		address := dbustest.Start(t)
		s := session.New(connect(t, address), nil, uid)
		defer s.Close()
		if _, err := s.DisplaySession(); err == nil {
			t.Fatal("DisplaySession with nobody owning org.freedesktop.login1: nil error")
		}
		if locked, err := s.Locked(); err == nil {
			t.Fatalf("Locked with nobody owning org.freedesktop.login1 = %v, nil; want an error", locked)
		}
	})
	t.Run("nil connection", func(t *testing.T) {
		s := session.New(nil, nil, uid)
		defer s.Close()
		if _, err := s.DisplaySession(); err == nil {
			t.Fatal("DisplaySession with a nil connection: nil error")
		}
		if locked, err := s.Locked(); err == nil {
			t.Fatalf("Locked with a nil connection = %v, nil; want an error", locked)
		}
	})
	t.Run("no graphical session", func(t *testing.T) {
		l, s := withLogind(t)
		l.SetNoDisplay()
		l.SetNoGraphicalSession()
		if id, err := s.DisplaySession(); err == nil {
			t.Fatalf("DisplaySession with only a tty session = %q, nil; want an error", id)
		}
		if locked, err := s.Locked(); err == nil {
			t.Fatalf("Locked with only a tty session = %v, nil; want an error", locked)
		}
	})
	// A logind that owns the name but does not answer: both fail, closed,
	// within the call's deadline, rather than hang the gate.
	t.Run("logind does not answer", func(t *testing.T) {
		l, s := withLogind(t)
		l.Stall()
		bound := session.CallTimeout + 2*time.Second
		errs := make(chan error, 2)
		go func() { _, err := s.DisplaySession(); errs <- err }()
		go func() { _, err := s.Locked(); errs <- err }()
		start := time.Now()
		for i := 0; i < 2; i++ {
			select {
			case err := <-errs:
				if err == nil {
					t.Fatal("a call against a logind that does not answer returned no error")
				}
			case <-time.After(bound):
				t.Fatalf("a call against a logind that does not answer did not return within %v", bound)
			}
		}
		if d := time.Since(start); d < session.CallTimeout/2 {
			t.Fatalf("the calls returned after %v: the fake did not hold them, so the deadline was not what was tested", d)
		}
	})
}

// The Display logind elects is trusted for its hint while it is not the
// active session on its seat (the user switched to another VT): switched
// away is not locked, and whoever switches back finds the desktop as its
// lock screen left it. Spec "Weaker than macOS" 3 says so.
func TestLockedInactiveDisplay(t *testing.T) {
	l, s := withLogind(t)
	l.SetActive(fakelogind.GraphicalSession, false)
	if id, err := s.DisplaySession(); err != nil || id != fakelogind.GraphicalSession {
		t.Fatalf("DisplaySession with an inactive Display = %q, %v; want %q, nil", id, err, fakelogind.GraphicalSession)
	}
	if locked, err := s.Locked(); err != nil || locked {
		t.Fatalf("Locked with an inactive, unlocked Display = %v, %v; want false, nil", locked, err)
	}
	l.SetLocked(true)
	if locked, err := s.Locked(); err != nil || !locked {
		t.Fatalf("Locked with an inactive, locked Display = %v, %v; want true, nil", locked, err)
	}
}

// lockCounter registers an OnScreenLock callback and counts its runs. The
// wait it returns expects the count to reach want within eventWait.
func lockCounter(t *testing.T, s *session.Session) func(want int) {
	t.Helper()
	expectBy := lockCounterBy(t, s)
	return func(want int) {
		t.Helper()
		expectBy(want, eventWait)
	}
}

// lockCounterBy is lockCounter with the wait's deadline chosen per call,
// for a callback that follows a bus call's deadline passing.
func lockCounterBy(t *testing.T, s *session.Session) func(want int, within time.Duration) {
	t.Helper()
	fired := make(chan struct{}, 64)
	s.OnScreenLock(func() { fired <- struct{}{} })
	count := 0
	return func(want int, within time.Duration) {
		t.Helper()
		deadline := time.After(within)
		for count < want {
			select {
			case <-fired:
				count++
			case <-deadline:
				t.Fatalf("OnScreenLock ran %d times, want %d", count, want)
			}
		}
		// Make sure no extra run follows.
		select {
		case <-fired:
			t.Fatalf("OnScreenLock ran more than %d times", want)
		case <-time.After(quiet):
		}
	}
}

// resolveHook hooks the session's display session lookups (before the
// first OnScreenLock) and returns a wait for the lookup that found id.
func resolveHook(t *testing.T, s *session.Session) func(id string) {
	t.Helper()
	resolved := make(chan string, 64)
	s.SetResolveHook(func(id string) { resolved <- id })
	return func(id string) {
		t.Helper()
		deadline := time.After(eventWait)
		for {
			select {
			case got := <-resolved:
				if got == id {
					return
				}
			case <-deadline:
				t.Fatalf("the display session was not found as %q within %v", id, eventWait)
			}
		}
	}
}

// withLockWatch is withLogind plus an OnScreenLock counter, returned once
// the event goroutine has found the display session, so a lock the test
// sends right away is seen.
func withLockWatch(t *testing.T) (*fakelogind.Logind, *session.Session, func(want int)) {
	t.Helper()
	_, l, s, _, expect := lockWatchOn(t)
	return l, s, expect
}

// lockWatchOn is withLockWatch for a test that also needs the bus address
// (to put another logind on it) and the lookup wait.
func lockWatchOn(t *testing.T) (address string, l *fakelogind.Logind, s *session.Session, found func(id string), expect func(want int)) {
	t.Helper()
	address = dbustest.Start(t)
	l = fakelogind.Serve(t, connect(t, address), uid)
	s = session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	found = resolveHook(t, s)
	expect = lockCounter(t, s)
	found(fakelogind.GraphicalSession)
	return address, l, s, found, expect
}

func TestOnScreenLockSignal(t *testing.T) {
	l, _, expect := withLockWatch(t)

	l.EmitLock()
	expect(1)

	// The lock screen then sets the hint: the same lock, not a second one.
	l.SetLocked(true)
	expect(1)

	// Unlocking never runs fn.
	l.SetLocked(false)
	l.EmitUnlock()
	expect(1)

	l.EmitLock()
	expect(2)

	// A lock of another session (another user, or the user's tty) is not ours.
	l.EmitLockOn(fakelogind.TTYSession)
	expect(2)
}

// A desktop whose lock screen never sets LockedHint: every Lock signal is a
// lock, with no Unlock or hint change in between (a user unlocking at the
// lock screen makes logind emit nothing).
func TestOnScreenLockSignalTwice(t *testing.T) {
	l, _, expect := withLockWatch(t)
	l.EmitLock()
	expect(1)
	l.EmitLock()
	expect(2)
}

func TestOnScreenLockHint(t *testing.T) {
	l, _, expect := withLockWatch(t)

	l.SetLocked(true)
	expect(1)

	// A Lock signal while the hint already says locked is the same lock.
	l.EmitLock()
	expect(1)

	l.SetLocked(false)
	expect(1)

	l.SetLocked(true)
	expect(2)
}

// The lock screen answers the Lock signal with the hint, the user unlocks
// and locks again at once: the second lock is a lock, however soon after
// the signal it comes. Once a hint has answered the signal, the window in
// which a hint is the same lock is over.
func TestOnScreenLockRelockSoonAfterSignal(t *testing.T) {
	l, _, expect := withLockWatch(t)

	l.EmitLock()
	expect(1)
	l.SetLocked(true)
	l.SetLocked(false)
	l.SetLocked(true)
	expect(2)

	// The same with the hint read back from logind, one step at a time so
	// each read-back sees its own value (each wait is well inside the
	// window after the signal).
	l.SetLockedInvalidating(false)
	expect(2)
	l.EmitLock()
	expect(3)
	l.SetLockedInvalidating(true)
	expect(3)
	l.SetLockedInvalidating(false)
	expect(3)
	l.SetLockedInvalidating(true)
	expect(4)
}

// A logind whose PropertiesChanged only invalidates LockedHint: the value
// is read back from logind, off every lock of the session's own mutex.
func TestOnScreenLockHintInvalidated(t *testing.T) {
	l, _, expect := withLockWatch(t)

	l.SetLockedInvalidating(true)
	expect(1)
	l.SetLockedInvalidating(false)
	expect(1)
	l.SetLockedInvalidating(true)
	expect(2)
}

func TestOnScreenLockTwoCallbacks(t *testing.T) {
	l, s, first := withLockWatch(t)
	second := lockCounter(t, s)
	l.EmitLock()
	first(1)
	second(1)
}

// Any client on the system bus may send a signal with logind's path and
// interface. One that does not own org.freedesktop.login1 must neither run
// the callbacks nor hide the next real lock. The forgeries are addressed to
// the session's unique name, the real attack: the bus delivers a unicast
// signal whatever the match rules say, so only the session's own sender
// check stands in the way. (A broadcast would stop at the match rules and
// would pass with no check in the session at all.)
func TestOnScreenLockIgnoresForgedSignals(t *testing.T) {
	path := fakelogind.SessionPath(fakelogind.GraphicalSession)
	for _, forged := range []struct {
		name, iface, member string
		body                []any
	}{
		{name: "Lock", iface: "org.freedesktop.login1.Session", member: "Lock"},
		{name: "LockedHint", iface: "org.freedesktop.DBus.Properties", member: "PropertiesChanged", body: []any{
			"org.freedesktop.login1.Session", map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{},
		}},
	} {
		t.Run(forged.name, func(t *testing.T) {
			address := dbustest.Start(t)
			l := fakelogind.Serve(t, connect(t, address), uid)
			conn := connect(t, address)
			s := session.New(conn, nil, uid)
			t.Cleanup(s.Close)
			found := resolveHook(t, s)
			expect := lockCounter(t, s)
			found(fakelogind.GraphicalSession)

			msg := &dbus.Message{
				Type: dbus.TypeSignal,
				Headers: map[dbus.HeaderField]dbus.Variant{
					dbus.FieldDestination: dbus.MakeVariant(conn.Names()[0]),
					dbus.FieldPath:        dbus.MakeVariant(path),
					dbus.FieldInterface:   dbus.MakeVariant(forged.iface),
					dbus.FieldMember:      dbus.MakeVariant(forged.member),
				},
				Body: forged.body,
			}
			if len(forged.body) > 0 {
				msg.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(forged.body...))
			}
			if call := connect(t, address).Send(msg, nil); call.Err != nil {
				t.Fatalf("forge %s: %v", forged.name, call.Err)
			}
			expect(0)

			// The real locks still count, both ways.
			l.SetLocked(true)
			expect(1)
			l.SetLocked(false)
			l.EmitLock()
			expect(2)
		})
	}
}

// The agent may start before logind is reachable, or before the user has a
// graphical session; the first lock after that still counts.
func TestOnScreenLockLogindArrivesLate(t *testing.T) {
	address := dbustest.Start(t)
	s := session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	found := resolveHook(t, s)
	expect := lockCounter(t, s)
	found("")

	l := fakelogind.Serve(t, connect(t, address), uid)
	found(fakelogind.GraphicalSession)
	l.SetLocked(true)
	expect(1)
	l.SetLocked(false)
	l.EmitLock()
	expect(2)
}

// The agent starts while the user has only a tty login (logind knows the
// user, but no graphical session is active): the desktop session logind
// elects as the Display later is watched from then on, not from the next
// periodic retry.
func TestOnScreenLockDisplayElectedLater(t *testing.T) {
	address := dbustest.Start(t)
	l := fakelogind.Serve(t, connect(t, address), uid)
	l.SetNoDisplay()
	l.SetNoGraphicalSession()
	s := session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	found := resolveHook(t, s)
	expect := lockCounter(t, s)
	found("")

	l.SetActive(fakelogind.GraphicalSession, true)
	l.SetDisplay(fakelogind.GraphicalSession)
	found(fakelogind.GraphicalSession)
	l.SetLocked(true)
	expect(1)
	l.SetLocked(false)
	l.EmitLock()
	expect(2)
}

// The user logs out of the desktop and in again while the agent runs: the
// new session is the one whose locks count.
func TestOnScreenLockFollowsDisplay(t *testing.T) {
	address := dbustest.Start(t)
	l := fakelogind.Serve(t, connect(t, address), uid)
	s := session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	found := resolveHook(t, s)
	expect := lockCounter(t, s)
	found(fakelogind.GraphicalSession)

	l.SetDisplay(fakelogind.X11Session)
	found(fakelogind.X11Session)
	l.SetLockedOn(fakelogind.X11Session, true)
	expect(1)
	// The old session is no longer ours.
	l.SetLocked(true)
	l.EmitLock()
	expect(1)
	l.EmitLockOn(fakelogind.X11Session)
	expect(1) // already locked
	l.SetLockedOn(fakelogind.X11Session, false)
	l.EmitLockOn(fakelogind.X11Session)
	expect(2)
}

// A lock that lands while the display session is being looked up again (a
// change of the user's sessions came just before it) is a lock: the lookup
// reads the hint already true, and the signal that reported it is still
// to be handled. Fired once, not twice.
func TestOnScreenLockDuringLookup(t *testing.T) {
	l, _, expect := withLockWatch(t)

	l.Stall()
	l.EmitUserInvalidated("Sessions")
	waitStalled(t, l, 1)
	l.SetLocked(true)
	l.Release()
	expect(1)

	// The state after that is the session's: an unlock and a lock count.
	l.SetLocked(false)
	l.EmitLock()
	expect(2)
}

// A lookup that fails (logind does not answer within the call's deadline)
// leaves the lock state unknown, which counts as locked: the callbacks run
// once for the gap. The session found before is kept, so the signal logind
// sends next (here the lock screen's hint) is understood, and from the
// state it reads the next lock counts again. Without this a failed lookup
// forgot the session and every lock until the next successful lookup was
// dropped.
func TestOnScreenLockLookupFails(t *testing.T) {
	l, s := withLogind(t)
	found := resolveHook(t, s)
	expectBy := lockCounterBy(t, s)
	found(fakelogind.GraphicalSession)

	l.Stall()
	l.EmitUserInvalidated("Sessions")
	waitStalled(t, l, 1)
	// The deadline passes: unknown, so the screen counts as locked now.
	expectBy(1, session.CallTimeout+eventWait)
	l.Release()

	// logind answers again. The lock reported now is read by the lookup
	// the signal starts; the screen already counted as locked.
	l.SetLocked(true)
	found(fakelogind.GraphicalSession)
	expectBy(1, eventWait)
	l.SetLocked(false)
	l.EmitLock()
	expectBy(2, eventWait)
	l.SetLocked(true)
	expectBy(2, eventWait)
}

// logind's SessionNew and SessionRemoved are what it sends when the
// user's sessions change (it emits nothing for the Sessions property):
// each makes the session look its display session up again. The user
// with only a tty login logs in at the desktop: the new graphical session
// is found at once, not at the next periodic retry.
func TestOnScreenLockSessionSignals(t *testing.T) {
	address := dbustest.Start(t)
	l := fakelogind.Serve(t, connect(t, address), uid)
	l.SetNoDisplay()
	l.SetNoGraphicalSession()
	s := session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	found := resolveHook(t, s)
	expect := lockCounter(t, s)
	found("")

	l.SetActive(fakelogind.GraphicalSession, true)
	l.EmitSessionNew(fakelogind.GraphicalSession)
	found(fakelogind.GraphicalSession)
	l.SetLocked(true)
	expect(1)
	l.SetLocked(false)

	// The user's other session ends: a lookup, which finds the same
	// display session, in the state it is in.
	l.EmitSessionRemoved(fakelogind.TTYSession)
	found(fakelogind.GraphicalSession)
	l.EmitLock()
	expect(2)
}

// The user logs out of the desktop while the agent runs (lingering), so
// the user has no graphical session: unknown counts as locked, and the
// callbacks run once for the loss. The next desktop session is watched
// from where it starts.
func TestOnScreenLockDisplaySessionLost(t *testing.T) {
	l, _, expect := withLockWatch(t)

	l.SetNoGraphicalSession()
	l.SetNoDisplay()
	expect(1)

	l.SetActive(fakelogind.GraphicalSession, true)
	l.SetDisplay(fakelogind.GraphicalSession)
	expect(1)
	l.SetLocked(true)
	expect(2)
}

// logind restarts under the watch (a package upgrade): it leaves the bus
// and comes back, with every LockedHint false, since it does not keep the
// hint. Leaving the bus makes the state unknown, so a screen known to be
// unlocked counts as locked from then on, once; a screen known to be
// locked stays locked, and the restarted logind's false is an unlock (the
// spec's "Weaker than macOS" 3 says so). Either way the next lock counts.
func TestOnScreenLockLogindRestarts(t *testing.T) {
	t.Run("unlocked before", func(t *testing.T) {
		address, l, _, found, expect := lockWatchOn(t)
		l.Stop()
		found("")
		expect(1)

		l2 := fakelogind.Serve(t, connect(t, address), uid)
		found(fakelogind.GraphicalSession)
		expect(1)
		l2.SetLocked(true)
		expect(2)
		l2.SetLocked(false)
		l2.EmitLock()
		expect(3)
	})
	t.Run("locked before", func(t *testing.T) {
		address, l, s, found, expect := lockWatchOn(t)
		l.SetLocked(true)
		expect(1)
		l.Stop()
		found("")
		expect(1)
		if _, err := s.Locked(); err == nil {
			t.Fatal("Locked with logind gone from the bus: nil error")
		}

		l2 := fakelogind.Serve(t, connect(t, address), uid)
		found(fakelogind.GraphicalSession)
		expect(1)
		// The restarted logind forgot the lock: that reads as unlocked.
		if locked, err := s.Locked(); err != nil || locked {
			t.Fatalf("Locked after a logind restart = %v, %v; want false, nil (logind does not keep the hint)", locked, err)
		}
		l2.EmitLock()
		expect(2)
	})
}

// waitStalled waits until n GetUser calls are held at the fake's stall.
func waitStalled(t *testing.T, l *fakelogind.Logind, n int) {
	t.Helper()
	deadline := time.Now().Add(eventWait)
	for l.Waiting() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d GetUser calls in flight after %v, want %d", l.Waiting(), eventWait, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The user's idle hints change on every screen blank and say nothing about
// the display session: only a change of the user's Display or Sessions is
// worth looking the session up again.
func TestOnScreenLockLooksUpOnSessionChangesOnly(t *testing.T) {
	l, s := withLogind(t)
	resolved := make(chan string, 64)
	s.SetResolveHook(func(id string) { resolved <- id })
	expect := lockCounter(t, s)
	select {
	case <-resolved:
	case <-time.After(eventWait):
		t.Fatal("the display session was not looked up")
	}

	l.EmitUserInvalidated("IdleHint", "IdleSinceHint")
	select {
	case id := <-resolved:
		t.Fatalf("an idle hint change made the session look up its display session again (found %q)", id)
	case <-time.After(quiet):
	}

	l.EmitUserInvalidated("Sessions")
	select {
	case <-resolved:
	case <-time.After(eventWait):
		t.Fatal("a change of the user's sessions did not make the session look up its display session again")
	}
	l.SetLocked(true)
	expect(1)
}

// The connection to the bus closes under the watch (the caller closed it,
// or the bus went away): the callbacks run once, since no lock can be seen
// from then on and unknown counts as locked, and Locked fails closed.
func TestOnScreenLockConnectionLost(t *testing.T) {
	address := dbustest.Start(t)
	fakelogind.Serve(t, connect(t, address), uid)
	conn := connect(t, address)
	s := session.New(conn, nil, uid)
	t.Cleanup(s.Close)
	found := resolveHook(t, s)
	expect := lockCounter(t, s)
	found(fakelogind.GraphicalSession)

	conn.Close()
	expect(1)
	if _, err := s.Locked(); err == nil {
		t.Fatal("Locked on a closed connection: nil error")
	}
}

// The connection is closed before the first OnScreenLock (the bus went
// away between New and the watch): the bus library registers no channel
// on a closed connection, so nothing would ever close it. The loss is
// still reported once, and Locked fails closed.
func TestOnScreenLockConnectionClosedBeforeWatch(t *testing.T) {
	address := dbustest.Start(t)
	fakelogind.Serve(t, connect(t, address), uid)
	conn := connect(t, address)
	s := session.New(conn, nil, uid)
	t.Cleanup(s.Close)
	conn.Close()

	expect := lockCounter(t, s)
	expect(1)
	if _, err := s.Locked(); err == nil {
		t.Fatal("Locked on a connection closed before the watch: nil error")
	}
}

// OnScreenLock returns at once, whatever logind does: the lookups run on
// the event goroutine.
func TestOnScreenLockReturnsAtOnce(t *testing.T) {
	address := dbustest.Start(t)
	l := fakelogind.Serve(t, connect(t, address), uid)
	l.Stall()
	s := session.New(connect(t, address), nil, uid)
	t.Cleanup(s.Close)
	found := resolveHook(t, s)

	start := time.Now()
	expect := lockCounter(t, s)
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("OnScreenLock with a logind that does not answer took %v, want under 100ms", d)
	}
	l.Release()
	found(fakelogind.GraphicalSession)
	l.SetLocked(true)
	expect(1)
}

// A callback that closes the session (a platform shutting down on lock)
// returns; Close does not wait for the callback it is called from.
func TestCloseFromCallback(t *testing.T) {
	l, s := withLogind(t)
	found := resolveHook(t, s)
	returned := make(chan struct{})
	s.OnScreenLock(func() {
		s.Close()
		close(returned)
	})
	found(fakelogind.GraphicalSession)
	l.EmitLock()
	select {
	case <-returned:
	case <-time.After(eventWait):
		t.Fatal("a callback that calls Close did not return")
	}
	if _, err := s.Locked(); err == nil {
		t.Fatal("Locked after Close from a callback: nil error")
	}
}

// A callback that closes the session stops the callbacks after it: none
// starts after Close.
func TestCloseFromCallbackStopsTheRest(t *testing.T) {
	l, s := withLogind(t)
	found := resolveHook(t, s)
	first := make(chan struct{}, 1)
	second := make(chan struct{}, 1)
	s.OnScreenLock(func() {
		s.Close()
		first <- struct{}{}
	})
	s.OnScreenLock(func() { second <- struct{}{} })
	found(fakelogind.GraphicalSession)
	l.EmitLock()
	select {
	case <-first:
	case <-time.After(eventWait):
		t.Fatal("the first callback did not run")
	}
	select {
	case <-second:
		t.Fatal("a callback ran after Close")
	case <-time.After(quiet):
	}
}

// waitCalls waits until the fake notification server saw n Notify calls.
func waitCalls(t *testing.T, srv *fakenotify.Server, n int) []fakenotify.Call {
	t.Helper()
	deadline := time.Now().Add(eventWait)
	for {
		calls := srv.Calls()
		if len(calls) >= n {
			if len(calls) > n {
				t.Fatalf("Notify called %d times, want %d", len(calls), n)
			}
			return calls
		}
		if time.Now().After(deadline) {
			t.Fatalf("Notify called %d times after %v, want %d", len(calls), eventWait, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShowWarningNotifies(t *testing.T) {
	address := dbustest.Start(t)
	srv := fakenotify.Serve(t, connect(t, address))
	s := session.New(nil, connect(t, address), uid)
	defer s.Close()

	w := platform.Warning{
		ID:          "iterm2:github",
		Title:       "iTerm2 blocked",
		Lines:       []string{`key "github"`, "ssh <b>git@github.com</b> & more"},
		CommandLine: 2,
		Count:       1,
		// A path with the characters the body treats as markup: the rule
		// line is escaped like the others.
		SuggestedRule: "nazar ssh-key rule add github --apps 'path:/opt/a&b/<ssh>' --gate dialog --scope session",
	}
	s.ShowWarning(w)
	calls := waitCalls(t, srv, 1)
	c := calls[0]
	if c.AppName != "nazar" {
		t.Errorf("app_name = %q, want nazar", c.AppName)
	}
	if c.AppIcon != "dialog-warning" {
		t.Errorf("app_icon = %q, want dialog-warning", c.AppIcon)
	}
	if c.ReplacesID != 0 {
		t.Errorf("replaces_id = %d, want 0 for a new warning", c.ReplacesID)
	}
	if c.Summary != "iTerm2 blocked" {
		t.Errorf("summary = %q, want the title alone when Count is 1", c.Summary)
	}
	wantBody := "key \"github\"\nssh &lt;b&gt;git@github.com&lt;/b&gt; &amp; more\nSuggested rule: nazar ssh-key rule add github --apps 'path:/opt/a&amp;b/&lt;ssh&gt;' --gate dialog --scope session"
	if c.Body != wantBody {
		t.Errorf("body = %q\nwant   %q", c.Body, wantBody)
	}
	if c.ExpireTimeout != -1 {
		t.Errorf("expire_timeout = %d, want -1 (the server's default)", c.ExpireTimeout)
	}
	urgency, ok := c.Hints["urgency"]
	if !ok {
		t.Fatalf("hints = %v, want an urgency", c.Hints)
	}
	if v, ok := urgency.Value().(byte); !ok || v != 1 {
		t.Errorf("urgency = %#v, want byte 1 (normal)", urgency.Value())
	}
	if len(c.Actions) != 0 {
		t.Errorf("actions = %v, want none", c.Actions)
	}

	// The same warning again, counted: it replaces the notification the
	// server gave an id to, and says how many times.
	w.Count = 3
	s.ShowWarning(w)
	calls = waitCalls(t, srv, 2)
	if calls[1].ReplacesID != calls[0].ID {
		t.Errorf("second replaces_id = %d, want the server's id for the first, %d", calls[1].ReplacesID, calls[0].ID)
	}
	if calls[1].Summary != "iTerm2 blocked (×3)" {
		t.Errorf("second summary = %q, want %q", calls[1].Summary, "iTerm2 blocked (×3)")
	}

	// Another warning is a new notification.
	s.ShowWarning(platform.Warning{ID: "other", Title: "Other", Lines: []string{"x"}, Count: 1})
	calls = waitCalls(t, srv, 3)
	if calls[2].ReplacesID != 0 {
		t.Errorf("another ID's replaces_id = %d, want 0", calls[2].ReplacesID)
	}
	if calls[2].Body != "x" {
		t.Errorf("body without a suggested rule = %q, want %q", calls[2].Body, "x")
	}

	// The first warning again, after an unrelated one: it names the id the
	// server gave the last Notify for it, not the first (the fake hands
	// out a new id on every call, so the two differ).
	w.Count = 4
	s.ShowWarning(w)
	calls = waitCalls(t, srv, 4)
	if calls[1].ID == calls[0].ID {
		t.Fatalf("the fake gave the replace the same id %d as the first call; the test cannot tell last from first", calls[1].ID)
	}
	if calls[3].ReplacesID != calls[1].ID {
		t.Errorf("fourth replaces_id = %d, want the server's latest id for that warning, %d", calls[3].ReplacesID, calls[1].ID)
	}
}

// A server without the body-markup capability shows the body as plain
// text, so escaping would show "&amp;" to the user.
func TestShowWarningPlainBodyWithoutMarkup(t *testing.T) {
	address := dbustest.Start(t)
	srv := fakenotify.Serve(t, connect(t, address))
	srv.SetCapabilities("body")
	s := session.New(nil, connect(t, address), uid)
	defer s.Close()

	s.ShowWarning(platform.Warning{ID: "w", Title: "Blocked", Lines: []string{"a && b <c>"}, Count: 1})
	calls := waitCalls(t, srv, 1)
	if calls[0].Body != "a && b <c>" {
		t.Fatalf("body on a server without body-markup = %q, want it as typed", calls[0].Body)
	}
}

// The server that owns the name can change over the agent's life (a
// notification daemon restarted or swapped in the session). The body
// carries text the blocked program chose, so whether it is escaped is
// decided against the server that gets it, every time, not against the
// first one asked.
func TestShowWarningAsksCapabilitiesEveryTime(t *testing.T) {
	address := dbustest.Start(t)
	srv := fakenotify.Serve(t, connect(t, address))
	srv.SetCapabilities("body")
	s := session.New(nil, connect(t, address), uid)
	defer s.Close()

	s.ShowWarning(platform.Warning{ID: "w", Title: "Blocked", Lines: []string{"a <b>& c"}, Count: 1})
	calls := waitCalls(t, srv, 1)
	if calls[0].Body != "a <b>& c" {
		t.Fatalf("body on a server without body-markup = %q, want it as typed", calls[0].Body)
	}

	srv.SetCapabilities("body", "body-markup")
	s.ShowWarning(platform.Warning{ID: "w", Title: "Blocked", Lines: []string{"a <b>& c"}, Count: 2})
	calls = waitCalls(t, srv, 2)
	if want := "a &lt;b&gt;&amp; c"; calls[1].Body != want {
		t.Fatalf("body once the server reads markup = %q, want %q", calls[1].Body, want)
	}
}

func TestShowWarningNoBusDoesNotBlock(t *testing.T) {
	w := platform.Warning{ID: "w", Title: "Blocked", Lines: []string{"line"}, Count: 1}
	t.Run("nil connection", func(t *testing.T) {
		s := session.New(nil, nil, uid)
		defer s.Close()
		start := time.Now()
		for i := 0; i < 3; i++ {
			s.ShowWarning(w)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("ShowWarning with no connection took %v, want under 100ms", d)
		}
	})
	t.Run("no server on the bus", func(t *testing.T) {
		address := dbustest.Start(t)
		s := session.New(nil, connect(t, address), uid)
		defer s.Close()
		start := time.Now()
		for i := 0; i < 3; i++ {
			s.ShowWarning(w)
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("ShowWarning with no notification server took %v, want under 100ms", d)
		}
		// The dropped calls leave the session usable: a server that comes up
		// later gets the next warning, as a fresh notification. The queue
		// drains on its own goroutine, so give the three failures time to
		// happen before the server exists.
		time.Sleep(quiet)
		srv := fakenotify.Serve(t, connect(t, address))
		s.ShowWarning(w)
		calls := waitCalls(t, srv, 1)
		if calls[0].ReplacesID != 0 || calls[0].Summary != "Blocked" {
			t.Fatalf("after the server came up: replaces_id %d, summary %q; want 0 and Blocked", calls[0].ReplacesID, calls[0].Summary)
		}
	})
	// A server that owns the name but does not answer (a hung daemon, or
	// one the bus is still starting) must not hold the caller either. The
	// warnings queued behind the stuck call with the same ID collapse into
	// the latest one: once the server answers it gets the first call, then
	// the newest warning, which replaces it.
	t.Run("server does not answer", func(t *testing.T) {
		address := dbustest.Start(t)
		srv := fakenotify.Serve(t, connect(t, address))
		srv.Stall()
		s := session.New(nil, connect(t, address), uid)
		defer s.Close()
		start := time.Now()
		s.ShowWarning(platform.Warning{ID: "w", Title: "Blocked", Lines: []string{"1"}, Count: 1})
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("ShowWarning with a notification server that does not answer took %v, want under 100ms", d)
		}
		waitInFlight(t, srv, 1)
		start = time.Now()
		for i := 2; i <= 4; i++ {
			s.ShowWarning(platform.Warning{ID: "w", Title: "Blocked", Lines: []string{fmt.Sprint(i)}, Count: i})
		}
		if d := time.Since(start); d > 100*time.Millisecond {
			t.Fatalf("ShowWarning behind a stuck call took %v, want under 100ms", d)
		}
		if n := len(srv.Calls()); n != 0 {
			t.Fatalf("the stalled server answered %d calls", n)
		}
		srv.Release()
		calls := waitCalls(t, srv, 2)
		if calls[0].Body != "1" || calls[1].Body != "4" {
			t.Errorf("bodies = %q, %q; want the stuck call \"1\" and then only the latest, \"4\"", calls[0].Body, calls[1].Body)
		}
		if calls[1].Summary != "Blocked (×4)" {
			t.Errorf("second summary = %q, want %q", calls[1].Summary, "Blocked (×4)")
		}
		if calls[1].ReplacesID != calls[0].ID {
			t.Errorf("second replaces_id = %d, want the first call's id %d", calls[1].ReplacesID, calls[0].ID)
		}
	})
	// Distinct warnings behind a stuck call queue up to a bound; past it
	// the oldest are dropped, so a flood of blocked requests against a
	// hung server cannot grow memory or deliver stale warnings for ever.
	t.Run("queue is capped", func(t *testing.T) {
		address := dbustest.Start(t)
		srv := fakenotify.Serve(t, connect(t, address))
		srv.Stall()
		s := session.New(nil, connect(t, address), uid)
		defer s.Close()
		s.ShowWarning(platform.Warning{ID: "stuck", Title: "Blocked", Lines: []string{"stuck"}, Count: 1})
		waitInFlight(t, srv, 1)
		n := session.MaxPending + 3
		for i := 1; i <= n; i++ {
			s.ShowWarning(platform.Warning{ID: fmt.Sprintf("w%d", i), Title: "Blocked", Lines: []string{fmt.Sprint(i)}, Count: 1})
		}
		srv.Release()
		calls := waitCalls(t, srv, 1+session.MaxPending)
		if calls[0].Body != "stuck" {
			t.Errorf("first body = %q, want the stuck call", calls[0].Body)
		}
		for i, c := range calls[1:] {
			// The three oldest queued warnings were dropped.
			if want := fmt.Sprint(i + 4); c.Body != want {
				t.Errorf("call %d body = %q, want %q (the newest %d, in order)", i+1, c.Body, want, session.MaxPending)
			}
		}
	})
}

// waitInFlight waits until n Notify calls are held at the fake server's stall.
func waitInFlight(t *testing.T, srv *fakenotify.Server, n int) {
	t.Helper()
	deadline := time.Now().Add(eventWait)
	for srv.Waiting() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d Notify calls in flight after %v, want %d", srv.Waiting(), eventWait, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCloseStopsEvents(t *testing.T) {
	l, s := withLogind(t)
	fired := make(chan struct{}, 64)
	s.OnScreenLock(func() { fired <- struct{}{} })
	s.Close()
	l.EmitLock()
	l.SetLocked(true)
	select {
	case <-fired:
		t.Fatal("OnScreenLock ran after Close")
	case <-time.After(quiet):
	}
	// Close twice is fine, and the other methods still fail closed.
	s.Close()
	if _, err := s.Locked(); err == nil {
		t.Fatal("Locked after Close: nil error")
	}
	s.ShowWarning(platform.Warning{ID: "w", Title: "t", Count: 1})
}
