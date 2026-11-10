//go:build linux

// Package session is the Linux platform's view of the user's desktop
// session: whether the screen is locked, when it locks, and the block
// warning as a desktop notification. The lock state comes from
// systemd-logind over D-Bus (org.freedesktop.login1: the user's display
// session and its LockedHint and Lock signal); the warning goes to the
// desktop's notification server (org.freedesktop.Notifications).
//
// On Linux "only when unlocked" is enforced by nazar from this lock state,
// not by the chip (item 3 of the design's "Weaker than macOS" list), so
// Locked fails closed: when logind cannot be asked, or the user has no
// graphical session (a tty or ssh login is not one), it returns an error
// and the caller refuses.
//
// The lock state is only as good as what the desktop's lock screen tells
// logind. GNOME and KDE set the session's LockedHint; many standalone
// lockers (swaylock, i3lock, slock, most xscreensaver setups) do not, and
// then a locked screen reads as unlocked here. logind does not keep the
// hint across its own restart, so a screen locked before logind restarted
// reads as unlocked until the desktop reports a lock again, and any program
// running as the user may set the hint (logind takes the call from the
// session's owner). A desktop started from a console login (startx, or a
// compositor run from a tty) keeps the tty session's type, so it counts as
// no graphical session: locked. The docs say all of this (the same item 3).
//
// A Session takes its connections; it never opens the system or session
// bus itself, so tests give it private buses with fakes on them.
package session

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	login1       = "org.freedesktop.login1"
	managerPath  = dbus.ObjectPath("/org/freedesktop/login1")
	managerIface = "org.freedesktop.login1.Manager"
	userIface    = "org.freedesktop.login1.User"
	sessionIface = "org.freedesktop.login1.Session"
	propsIface   = "org.freedesktop.DBus.Properties"
	busName      = "org.freedesktop.DBus"
	busIface     = "org.freedesktop.DBus"
)

// callTimeout bounds every bus call: a stuck logind or notification server
// makes the caller fail (closed), not hang.
const callTimeout = 5 * time.Second

// lockWindow is how long after a Lock signal a LockedHint turning true is
// the same lock (the lock screen answering the signal) and not a new one.
// A hint later than that counts as a lock: the error is a second callback,
// not a lock missed. Once a hint has answered a signal, or the hint turns
// false, the window is over: the next hint turning true is a new lock
// however soon it comes.
const lockWindow = 3 * time.Second

// retryEvery is how often the watch goroutine tries again while it does
// not know the lock state, on top of trying when logind reports a change.
const retryEvery = 30 * time.Second

// errNoConn is the answer when the session was made without a connection.
var errNoConn = errors.New("no connection to logind")

// Session answers the lock questions of platform.Platform on Linux and
// shows warnings. Every method may be called from any goroutine.
type Session struct {
	logind *dbus.Conn // the system bus in production; nil: lock state unknown
	notify *dbus.Conn // the session bus in production; nil: no warnings
	uid    int

	mu      sync.Mutex
	closed  bool
	lockFns []func()
	// Lock events: the watch goroutine, started by the first OnScreenLock.
	signals    chan *dbus.Signal
	stop       chan struct{}
	done       chan struct{}
	inCallback bool                   // the watch goroutine is inside a callback
	onResolve  func(sessionID string) // test hook: after each display session lookup

	// Warnings: one goroutine sends them in order (notify.go).
	pending   []warning
	notifying bool
	ids       map[string]uint32 // Warning.ID to the server's notification id
}

// New makes a session for the user with uid. logind is a connection to the
// bus logind is on (the system bus); notify one to the bus the notification
// server is on (the session bus). Either may be nil: then that part fails
// closed (lock state unknown, warnings dropped). The connections stay the
// caller's to close.
func New(logind, notify *dbus.Conn, uid int) *Session {
	return &Session{logind: logind, notify: notify, uid: uid, ids: map[string]uint32{}}
}

// sessionRef is logind's (so): a session id and its object path.
type sessionRef struct {
	ID   string
	Path dbus.ObjectPath
}

// getProperty reads one property of obj with a deadline.
func getProperty(ctx context.Context, obj dbus.BusObject, iface, name string, out any) error {
	var v dbus.Variant
	if err := obj.CallWithContext(ctx, propsIface+".Get", 0, iface, name).Store(&v); err != nil {
		return fmt.Errorf("%s.%s: %w", iface, name, err)
	}
	if err := dbus.Store([]any{v.Value()}, out); err != nil {
		return fmt.Errorf("%s.%s: %w", iface, name, err)
	}
	return nil
}

// graphical reports whether a logind session type has a screen to lock.
func graphical(typ string) bool { return typ == "x11" || typ == "wayland" }

// displaySession finds the user's display session: logind's User.Display
// when it names a graphical session, else the user's active session of
// type x11 or wayland. It returns the user's object path and the session.
// The user's path is returned with an error too once GetUser answered, so
// a watcher with no session yet can still tell the user's changes apart.
//
// Display is checked for its type because logind also elects a tty session
// (an ssh or console login) as the Display of a user with no graphical
// session; such a session has no lock screen, so its LockedHint is always
// false and trusting it would read as unlocked. Display is not required
// to be active: logind prefers an active session for it, and an inactive
// one (the user switched to another VT) is still the user's desktop, with
// the lock state its lock screen reports.
func (s *Session) displaySession(ctx context.Context) (dbus.ObjectPath, sessionRef, error) {
	if s.logind == nil {
		return "", sessionRef{}, errNoConn
	}
	var userPath dbus.ObjectPath
	if err := s.logind.Object(login1, managerPath).CallWithContext(ctx, managerIface+".GetUser", 0, uint32(s.uid)).Store(&userPath); err != nil {
		return "", sessionRef{}, fmt.Errorf("logind: user %d: %w", s.uid, err)
	}
	user := s.logind.Object(login1, userPath)

	var display sessionRef
	if err := getProperty(ctx, user, userIface, "Display", &display); err == nil && display.ID != "" {
		var typ string
		if err := getProperty(ctx, s.logind.Object(login1, display.Path), sessionIface, "Type", &typ); err != nil {
			return userPath, sessionRef{}, fmt.Errorf("logind: session %s: %w", display.ID, err)
		}
		if graphical(typ) {
			return userPath, display, nil
		}
	}

	var refs []sessionRef
	if err := getProperty(ctx, user, userIface, "Sessions", &refs); err != nil {
		return userPath, sessionRef{}, fmt.Errorf("logind: sessions of user %d: %w", s.uid, err)
	}
	for _, ref := range refs {
		obj := s.logind.Object(login1, ref.Path)
		var typ string
		if err := getProperty(ctx, obj, sessionIface, "Type", &typ); err != nil {
			return userPath, sessionRef{}, fmt.Errorf("logind: session %s: %w", ref.ID, err)
		}
		if !graphical(typ) {
			continue
		}
		var active bool
		if err := getProperty(ctx, obj, sessionIface, "Active", &active); err != nil {
			return userPath, sessionRef{}, fmt.Errorf("logind: session %s: %w", ref.ID, err)
		}
		if active {
			return userPath, ref, nil
		}
	}
	return userPath, sessionRef{}, fmt.Errorf("logind: user %d has no graphical session", s.uid)
}

// DisplaySession returns the id of the user's display session: logind's
// User.Display when it is graphical, else the user's active session of type
// x11 or wayland. It is the polkit subject for the login gate.
func (s *Session) DisplaySession() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_, ref, err := s.displaySession(ctx)
	if err != nil {
		return "", err
	}
	return ref.ID, nil
}

// lockedHint reads the LockedHint of the session at path.
func (s *Session) lockedHint(ctx context.Context, path dbus.ObjectPath) (bool, error) {
	var locked bool
	if err := getProperty(ctx, s.logind.Object(login1, path), sessionIface, "LockedHint", &locked); err != nil {
		return false, fmt.Errorf("logind: %w", err)
	}
	return locked, nil
}

// Locked reports whether the display session's screen is locked (its
// LockedHint). It returns an error when it cannot tell: no connection, no
// logind, no graphical session, or a call that fails. Callers treat an
// error as locked.
func (s *Session) Locked() (bool, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return false, errors.New("session closed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_, ref, err := s.displaySession(ctx)
	if err != nil {
		return false, err
	}
	return s.lockedHint(ctx, ref.Path)
}

// OnScreenLock registers fn to run on every lock of the display session:
// its Lock signal, or its LockedHint turning true, once per lock (a lock
// screen that does both runs fn once). fn runs on the session's event
// goroutine, after the callbacks registered before it, so a callback that
// blocks holds up the ones after it and the next lock. The first call
// starts that goroutine and returns at once; the goroutine subscribes to
// logind's signals, finds the display session, and finds it again when
// logind comes or goes, when the user's sessions change, and every
// retryEvery while it does not know the lock state.
//
// Unknown counts as locked, as it does in Locked: fn also runs once when
// the screen was known to be unlocked and the state is lost, because
// logind left the bus (a restart), the display session went away (the
// user logged out) or a lookup failed (logind did not answer). A lock
// during such a gap is covered by that run; once the state is known again
// the next lock runs fn as usual. Without a connection fn is kept but
// there is no lock to report (the lock state itself fails closed in
// Locked). A connection that is closed, or closes under the watch, runs
// fn once whatever the state was: from then on no lock can be seen.
func (s *Session) OnScreenLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockFns = append(s.lockFns, fn)
	if s.closed || s.signals != nil || s.logind == nil {
		return
	}
	s.signals = make(chan *dbus.Signal, 16)
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	// The channel is registered before any match is added, so no signal
	// the bus sends for the matches is lost.
	s.logind.Signal(s.signals)
	go s.watch()
}

// lockMatches are the signals the watch goroutine asks the bus for, all
// from logind itself (the bus checks the sender against the name's owner):
// the Session interface's Lock and PropertiesChanged for it (LockedHint),
// PropertiesChanged on the User (Display; logind sends none for Sessions,
// but a change of it is taken too) and the Manager's SessionNew and
// SessionRemoved to find the display session again; and the bus's own
// NameOwnerChanged for logind, to notice it come or go.
var lockMatches = [][]dbus.MatchOption{
	{dbus.WithMatchSender(login1), dbus.WithMatchInterface(sessionIface), dbus.WithMatchMember("Lock")},
	{dbus.WithMatchSender(login1), dbus.WithMatchInterface(propsIface), dbus.WithMatchMember("PropertiesChanged"), dbus.WithMatchArg(0, sessionIface)},
	{dbus.WithMatchSender(login1), dbus.WithMatchInterface(propsIface), dbus.WithMatchMember("PropertiesChanged"), dbus.WithMatchArg(0, userIface)},
	{dbus.WithMatchSender(login1), dbus.WithMatchInterface(managerIface), dbus.WithMatchMember("SessionNew")},
	{dbus.WithMatchSender(login1), dbus.WithMatchInterface(managerIface), dbus.WithMatchMember("SessionRemoved")},
	{dbus.WithMatchSender(busName), dbus.WithMatchInterface(busIface), dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, login1)},
}

// lockWatch is the state of the watch goroutine. Only that goroutine
// touches it, so its bus calls hold no lock and never hold up ShowWarning,
// Locked or Close.
//
// The display session and its hint are kept across a lookup that fails,
// so the signals that keep coming for it are still understood; known says
// whether the last lookup succeeded, and while it is false the state is
// unknown, which counts as locked (see locked).
type lockWatch struct {
	s        *Session
	matched  bool            // every match in lockMatches was added
	owner    string          // logind's unique name; "" when it is not on the bus
	userPath dbus.ObjectPath // the user's object; "" when never found
	session  dbus.ObjectPath // the display session the signals are filtered on; "" when never found
	known    bool            // the last lookup found logind and the display session
	hint     bool            // last known LockedHint of that session
	lastLock time.Time       // when its last Lock signal came, until a hint answered it
}

// locked is the lock state as the watch knows it: the session's hint, or
// locked when the state is unknown, as Locked fails closed. The callbacks
// run when it goes from false to true.
func (w *lockWatch) locked() bool { return !w.known || w.hint }

// watch turns logind's signals into lock events until Close.
func (s *Session) watch() {
	defer close(s.done)
	w := &lockWatch{s: s}
	w.addMatches()
	w.resolve()
	if w.lost() {
		return
	}
	retry := time.NewTicker(retryEvery)
	defer retry.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-retry.C:
			if !w.matched {
				w.addMatches()
			}
			if !w.known {
				w.resolve()
			}
			if w.lost() {
				return
			}
		case sig, ok := <-s.signals:
			if !ok {
				// The connection closed under the watch (the bus went away,
				// or the caller closed it without Close): no lock can be
				// seen from here on, and an unknown lock state counts as
				// locked, so the callbacks run once. Nothing runs when
				// Close was called first.
				s.fireLock()
				return
			}
			w.handle(sig)
		}
	}
}

// lost reports whether the connection is closed. A connection closed
// before the watch started never delivers its signals (the bus library
// does not register a channel on a closed connection, so the channel is
// never closed either), so it is noticed here, after a lookup failed, and
// treated like a channel that closed: the callbacks run once and the
// watch ends.
func (w *lockWatch) lost() bool {
	if w.known || w.s.logind.Connected() {
		return false
	}
	w.s.fireLock()
	return true
}

// addMatches asks the bus for the signals in lockMatches. A match that
// fails is tried again at the next retry.
func (w *lockWatch) addMatches() {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	for _, opts := range lockMatches {
		if err := w.s.logind.AddMatchSignalContext(ctx, opts...); err != nil {
			return
		}
	}
	w.matched = true
}

// removeMatches tells the bus the session no longer wants the signals.
func (s *Session) removeMatches() {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	for _, opts := range lockMatches {
		s.logind.RemoveMatchSignalContext(ctx, opts...)
	}
}

// resolve finds logind's unique name and the user's display session, and
// reads the session's LockedHint as it stands, so a Lock signal while
// already locked does not count as a new lock. When any step fails the
// state is unknown until the next signal from logind or the next retry:
// what was found before is kept, so the signals still coming for that
// session are understood, and the callbacks run once if the screen was
// known to be unlocked (unknown counts as locked). The user's path is kept
// when logind knows the user but the user has no graphical session yet,
// so the Display logind elects later (the user logs in at the desktop) is
// picked up at once.
//
// When the session found is the one already watched and its hint turned
// true meanwhile, that is a lock that happened during the lookup: the
// callbacks run for it here, and the signal that reported it, still in
// the channel, then finds the hint already true and runs nothing. A hint
// answering a Lock signal reported just before is the same lock. A new
// session's state is only the starting point, unless the screen went from
// unlocked to locked with the change.
func (w *lockWatch) resolve() {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	wasLocked := w.locked()
	id := ""
	defer func() {
		if w.locked() && !wasLocked {
			w.s.fireLock()
		}
		if w.s.onResolve != nil {
			w.s.onResolve(id)
		}
	}()
	w.known = false
	var owner string
	if err := w.s.logind.BusObject().CallWithContext(ctx, busIface+".GetNameOwner", 0, login1).Store(&owner); err != nil {
		w.owner = ""
		return
	}
	w.owner = owner
	userPath, ref, err := w.s.displaySession(ctx)
	if userPath != "" {
		w.userPath = userPath
	}
	if err != nil {
		return
	}
	hint, err := w.s.lockedHint(ctx, ref.Path)
	if err != nil {
		return
	}
	id = ref.ID
	w.known = true
	if ref.Path != w.session {
		w.session, w.hint, w.lastLock = ref.Path, hint, time.Time{}
		return
	}
	if hint && !w.hint && w.sameLock() {
		// The hint answered the Lock signal reported just before the
		// lookup: not a new lock. The watch reads as locked already.
		wasLocked = true
	}
	w.hint = hint
}

// sameLock reports whether a hint turning true now answers the Lock
// signal reported within lockWindow, and ends that window either way: the
// next hint turning true is a new lock.
func (w *lockWatch) sameLock() bool {
	same := !w.lastLock.IsZero() && time.Since(w.lastLock) <= lockWindow
	w.lastLock = time.Time{}
	return same
}

// changes reports whether a PropertiesChanged signal changes or
// invalidates one of the named properties.
func changes(sig *dbus.Signal, names ...string) bool {
	if len(sig.Body) < 3 {
		return false
	}
	changed, _ := sig.Body[1].(map[string]dbus.Variant)
	invalidated, _ := sig.Body[2].([]string)
	for _, name := range names {
		if _, ok := changed[name]; ok || slices.Contains(invalidated, name) {
			return true
		}
	}
	return false
}

// handle applies one signal to the lock state and runs the callbacks when
// it is a new lock of the display session. A signal that is not from the
// bus itself or from logind's connection is ignored: any client on the
// system bus may emit a signal with logind's path and interface.
func (w *lockWatch) handle(sig *dbus.Signal) {
	if sig == nil {
		return
	}
	if sig.Sender == busName {
		if sig.Name == busIface+".NameOwnerChanged" {
			w.resolve()
		}
		return
	}
	if w.owner == "" || sig.Sender != w.owner {
		return
	}
	fire := false
	switch sig.Name {
	case managerIface + ".SessionNew", managerIface + ".SessionRemoved":
		w.resolve()
	case propsIface + ".PropertiesChanged":
		if len(sig.Body) < 1 {
			return
		}
		switch iface, _ := sig.Body[0].(string); {
		case iface == userIface && sig.Path == w.userPath:
			// Only the user's sessions matter here; its idle hints change
			// often and say nothing about which session is the display.
			if changes(sig, "Display", "Sessions") {
				w.resolve()
			}
		case iface == sessionIface && sig.Path == w.session:
			if !w.known {
				// logind is answering again after a lookup failed: find
				// out where things stand rather than wait for the retry.
				// The lookup reads the hint fresh, so the signal's value is
				// not needed.
				w.resolve()
				return
			}
			hint, ok := w.changedHint(sig)
			if !ok {
				return
			}
			was := w.hint
			w.hint = hint
			switch {
			case hint && !was:
				fire = !w.sameLock()
			case !hint:
				// Unlocked: a Lock signal before this is answered or over.
				w.lastLock = time.Time{}
			}
		}
	case sessionIface + ".Lock":
		if sig.Path != w.session {
			return
		}
		if !w.known {
			w.resolve() // as for the hint above
			return
		}
		if w.hint {
			return
		}
		w.lastLock = time.Now()
		fire = true
	}
	if fire {
		w.s.fireLock()
	}
}

// changedHint reads LockedHint out of a PropertiesChanged signal of the
// display session: from its changed properties, or from logind when the
// signal only invalidates it.
func (w *lockWatch) changedHint(sig *dbus.Signal) (bool, bool) {
	if len(sig.Body) < 3 {
		return false, false
	}
	if changed, ok := sig.Body[1].(map[string]dbus.Variant); ok {
		if v, ok := changed["LockedHint"]; ok {
			hint, ok := v.Value().(bool)
			return hint, ok
		}
	}
	if invalidated, ok := sig.Body[2].([]string); ok {
		for _, name := range invalidated {
			if name != "LockedHint" {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
			defer cancel()
			hint, err := w.s.lockedHint(ctx, w.session)
			return hint, err == nil
		}
	}
	return false, false
}

// fireLock runs the callbacks, in registration order, unless closed. A
// callback that closes the session stops the ones after it.
func (s *Session) fireLock() {
	s.mu.Lock()
	fns := append([]func(){}, s.lockFns...)
	closed := s.closed
	s.inCallback = !closed
	s.mu.Unlock()
	if closed {
		return
	}
	for _, fn := range fns {
		s.mu.Lock()
		closed = s.closed
		s.mu.Unlock()
		if closed {
			break
		}
		fn()
	}
	s.mu.Lock()
	s.inCallback = false
	s.mu.Unlock()
}

// Close stops the lock events and drops warnings not yet sent. The
// connections stay open: they are the caller's. Close twice is fine. Close
// waits for the event goroutine, unless a callback is running at the
// time: the caller may be that callback (a platform shutting down on
// lock) and a wait would never end. So a callback that is running, or
// was about to run, when Close was called may still be finishing when it
// returns; the callbacks after it do not run, and no lock after Close
// runs any.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.pending = nil
	signals, stop, done, inCallback := s.signals, s.stop, s.done, s.inCallback
	s.mu.Unlock()
	if signals == nil {
		return
	}
	close(stop)
	if !inCallback {
		<-done
	}
	s.logind.RemoveSignal(signals)
	s.removeMatches()
}
