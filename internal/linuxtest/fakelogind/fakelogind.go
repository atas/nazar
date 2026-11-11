//go:build linux

// Package fakelogind stands in for systemd-logind on a private test bus
// (internal/linuxtest/dbustest): it owns org.freedesktop.login1 and serves
// the parts of the Manager, User and Session interfaces that
// core/platform/linux/session reads, with switches for what a test wants
// to happen (the screen locks, the user has no Display, the Display is a
// tty login, no graphical session at all). Test-only code; nothing in it
// ships.
package fakelogind

import (
	"fmt"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

// The user's sessions. TTYSession is the console login the graphical
// session was started from (active, type tty); GraphicalSession is the
// user's display (active, type wayland); X11Session is a second graphical
// session that is not active. The fake lists them in that order: tty,
// x11, wayland, so that a reader that takes the first graphical session
// without looking at Active picks the wrong one. User.Display names
// GraphicalSession until SetNoDisplay or SetDisplay.
const (
	TTYSession       = "c1"
	GraphicalSession = "c2"
	X11Session       = "c3"
)

const (
	busName      = "org.freedesktop.login1"
	managerPath  = dbus.ObjectPath("/org/freedesktop/login1")
	managerIface = "org.freedesktop.login1.Manager"
	userIface    = "org.freedesktop.login1.User"
	sessionIface = "org.freedesktop.login1.Session"
	propsIface   = "org.freedesktop.DBus.Properties"
)

// sessionRef is logind's (so): a session id and its object path.
type sessionRef struct {
	ID   string
	Path dbus.ObjectPath
}

// sessionSpec is what the fake knows about one session.
type sessionSpec struct {
	id     string
	typ    string
	active bool
}

var sessions = []sessionSpec{
	{TTYSession, "tty", true},
	{X11Session, "x11", false},
	{GraphicalSession, "wayland", true},
}

// Logind is the running fake.
type Logind struct {
	t        testing.TB
	conn     *dbus.Conn
	uid      int
	user     *prop.Properties
	props    map[string]*prop.Properties // per session id
	userPath dbus.ObjectPath

	mu    sync.Mutex
	stall chan struct{} // while non-nil, GetUser waits for it to close
	// waiting counts the GetUser calls that arrived and are held at the
	// stall, until Release lets them through.
	waiting int
}

// Stall makes every Manager.GetUser from now on wait, unanswered, until
// Release: a logind that does not answer. Release also runs at cleanup.
func (l *Logind) Stall() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stall == nil {
		l.stall = make(chan struct{})
	}
}

// Release lets the stalled calls through and answers later ones at once.
// Without a Stall it does nothing.
func (l *Logind) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stall != nil {
		close(l.stall)
		l.stall = nil
		l.waiting = 0
	}
}

// Waiting is how many GetUser calls have arrived and are held at the
// stall: a test uses it to know a lookup is in flight before it changes
// what the lookup will find.
func (l *Logind) Waiting() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waiting
}

// SessionPath is the object path logind gives session id.
func SessionPath(id string) dbus.ObjectPath {
	return dbus.ObjectPath("/org/freedesktop/login1/session/_3" + id)
}

// UserPath is the object path logind gives the user with uid.
func UserPath(uid int) dbus.ObjectPath {
	return dbus.ObjectPath(fmt.Sprintf("/org/freedesktop/login1/user/_%d", uid))
}

// manager serves org.freedesktop.login1.Manager.
type manager struct{ l *Logind }

// GetUser is Manager.GetUser(u uid) -> o.
func (m manager) GetUser(uid uint32) (dbus.ObjectPath, *dbus.Error) {
	m.l.mu.Lock()
	stall := m.l.stall
	if stall != nil {
		m.l.waiting++
	}
	m.l.mu.Unlock()
	if stall != nil {
		<-stall
	}
	if int(uid) != m.l.uid {
		return "", dbus.NewError("org.freedesktop.login1.NoSuchUser", []any{fmt.Sprintf("No user %d known or logged in", uid)})
	}
	return m.l.userPath, nil
}

// GetSession is Manager.GetSession(s id) -> o.
func (m manager) GetSession(id string) (dbus.ObjectPath, *dbus.Error) {
	if _, ok := m.l.props[id]; !ok {
		return "", dbus.NewError("org.freedesktop.login1.NoSuchSession", []any{"No session '" + id + "' known"})
	}
	return SessionPath(id), nil
}

// Serve owns org.freedesktop.login1 on conn (a connection to a private
// bus) and serves a user with uid whose Display is GraphicalSession. The
// name is released at cleanup; conn stays the caller's to close.
func Serve(t testing.TB, conn *dbus.Conn, uid int) *Logind {
	t.Helper()
	l := &Logind{t: t, conn: conn, uid: uid, props: map[string]*prop.Properties{}, userPath: UserPath(uid)}

	if err := conn.Export(manager{l}, managerPath, managerIface); err != nil {
		t.Fatalf("fakelogind: export Manager: %v", err)
	}

	// Session properties never emit on their own: the fake emits
	// PropertiesChanged itself, so a test can choose between a signal
	// that carries the value and one that only invalidates it.
	refs := make([]sessionRef, 0, len(sessions))
	for _, s := range sessions {
		refs = append(refs, sessionRef{s.id, SessionPath(s.id)})
		p, err := prop.Export(conn, SessionPath(s.id), prop.Map{
			sessionIface: {
				"Id":   {Value: s.id, Emit: prop.EmitConst},
				"Type": {Value: s.typ, Emit: prop.EmitConst},
				"User": {Value: struct {
					UID  uint32
					Path dbus.ObjectPath
				}{uint32(uid), l.userPath}, Emit: prop.EmitConst},
				"Active":     {Value: s.active, Emit: prop.EmitFalse},
				"LockedHint": {Value: false, Emit: prop.EmitFalse},
			},
		})
		if err != nil {
			t.Fatalf("fakelogind: export session %s: %v", s.id, err)
		}
		l.props[s.id] = p
	}

	// As logind: a change of Display emits PropertiesChanged with the
	// value; Sessions emits nothing (the Manager's SessionNew and
	// SessionRemoved say so instead, see EmitSessionNew). A test that wants
	// a logind that does emit for Sessions uses EmitUserInvalidated.
	user, err := prop.Export(conn, l.userPath, prop.Map{
		userIface: {
			"Display":  {Value: sessionRef{GraphicalSession, SessionPath(GraphicalSession)}, Emit: prop.EmitTrue},
			"Sessions": {Value: refs, Emit: prop.EmitFalse},
		},
	})
	if err != nil {
		t.Fatalf("fakelogind: export user: %v", err)
	}
	l.user = user

	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		t.Fatalf("fakelogind: RequestName %s: %v", busName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("fakelogind: RequestName %s = %v, want primary owner", busName, reply)
	}
	t.Cleanup(func() {
		l.Release()
		conn.ReleaseName(busName)
	})
	return l
}

// Stop makes the fake leave the bus (it gives org.freedesktop.login1 up),
// as logind does when it is stopped or restarted. A new Serve on another
// connection to the same bus is then the restarted logind: it knows the
// same sessions and, like logind, starts with every LockedHint false.
func (l *Logind) Stop() {
	l.Release()
	if _, err := l.conn.ReleaseName(busName); err != nil {
		l.t.Fatalf("fakelogind: ReleaseName %s: %v", busName, err)
	}
}

// EmitSessionNew emits Manager.SessionNew for session id (one of the
// constants above), as logind does when a session is created.
func (l *Logind) EmitSessionNew(id string) { l.emitManager("SessionNew", id) }

// EmitSessionRemoved emits Manager.SessionRemoved for session id (one of
// the constants above), as logind does when a session ends. The fake keeps
// serving the session: what the reader finds next is set with SetDisplay,
// SetActive and the others.
func (l *Logind) EmitSessionRemoved(id string) { l.emitManager("SessionRemoved", id) }

// emitManager emits one of the Manager's session signals, (so): the id
// and the session's object path.
func (l *Logind) emitManager(member, id string) {
	if err := l.conn.Emit(managerPath, managerIface+"."+member, id, SessionPath(id)); err != nil {
		l.t.Fatalf("fakelogind: emit %s: %v", member, err)
	}
}

// emitChanged emits PropertiesChanged for session id's Session interface,
// as logind does: the new values in the signal, or only the names of the
// properties that changed when the signal invalidates them.
func (l *Logind) emitChanged(id string, changed map[string]dbus.Variant, invalidated []string) {
	if err := l.conn.Emit(SessionPath(id), propsIface+".PropertiesChanged", sessionIface, changed, invalidated); err != nil {
		l.t.Fatalf("fakelogind: emit PropertiesChanged on %s: %v", id, err)
	}
}

// SetLocked sets the display session's LockedHint, which emits
// PropertiesChanged with the new value, as logind does when the lock
// screen reports its state.
func (l *Logind) SetLocked(locked bool) { l.SetLockedOn(GraphicalSession, locked) }

// SetLockedOn sets the LockedHint of session id (one of the constants
// above) and emits PropertiesChanged with the new value.
func (l *Logind) SetLockedOn(id string, locked bool) {
	l.props[id].SetMust(sessionIface, "LockedHint", locked)
	l.emitChanged(id, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(locked)}, []string{})
}

// SetLockedInvalidating sets the display session's LockedHint but the
// PropertiesChanged it emits only invalidates the property: the reader
// has to ask logind for the value.
func (l *Logind) SetLockedInvalidating(locked bool) {
	l.props[GraphicalSession].SetMust(sessionIface, "LockedHint", locked)
	l.emitChanged(GraphicalSession, map[string]dbus.Variant{}, []string{"LockedHint"})
}

// EmitLock emits the display session's Lock signal, as logind does for
// `loginctl lock-session` or on suspend.
func (l *Logind) EmitLock() { l.EmitLockOn(GraphicalSession) }

// EmitUnlock emits the display session's Unlock signal.
func (l *Logind) EmitUnlock() {
	if err := l.conn.Emit(SessionPath(GraphicalSession), sessionIface+".Unlock"); err != nil {
		l.t.Fatalf("fakelogind: emit Unlock: %v", err)
	}
}

// EmitLockOn emits the Lock signal of session id (one of the constants
// above): a lock of a session that is not the user's display.
func (l *Logind) EmitLockOn(id string) {
	if err := l.conn.Emit(SessionPath(id), sessionIface+".Lock"); err != nil {
		l.t.Fatalf("fakelogind: emit Lock on %s: %v", id, err)
	}
}

// SetDisplay points the user's Display at session id (one of the constants
// above), which emits PropertiesChanged on the user as logind does when it
// elects another display session: the tty login when no graphical session
// is left, or a new graphical session after the user logged out and in.
func (l *Logind) SetDisplay(id string) {
	l.user.SetMust(userIface, "Display", sessionRef{id, SessionPath(id)})
}

// EmitUserInvalidated emits PropertiesChanged on the user that only
// invalidates the named User properties ("IdleHint", "Sessions"), as
// logind does for a property whose value it does not send along.
func (l *Logind) EmitUserInvalidated(names ...string) {
	if err := l.conn.Emit(l.userPath, propsIface+".PropertiesChanged", userIface, map[string]dbus.Variant{}, names); err != nil {
		l.t.Fatalf("fakelogind: emit PropertiesChanged on the user: %v", err)
	}
}

// SetNoDisplay clears the user's Display, as logind reports for a user
// whose display session it has not marked (the sessions list stays).
func (l *Logind) SetNoDisplay() {
	l.user.SetMust(userIface, "Display", sessionRef{"", dbus.ObjectPath("/")})
}

// SetNoGraphicalSession makes every graphical session inactive, so the
// user has only the tty: no session to read the lock state from.
func (l *Logind) SetNoGraphicalSession() {
	for _, s := range sessions {
		if s.typ != "tty" {
			l.SetActive(s.id, false)
		}
	}
}

// SetActive sets whether session id (one of the constants above) is the
// active one on its seat and emits PropertiesChanged with the new value,
// as logind does when the user switches to it or away from it.
func (l *Logind) SetActive(id string, active bool) {
	l.props[id].SetMust(sessionIface, "Active", active)
	l.emitChanged(id, map[string]dbus.Variant{"Active": dbus.MakeVariant(active)}, []string{})
}
