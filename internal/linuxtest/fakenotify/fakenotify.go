//go:build linux

// Package fakenotify stands in for the desktop's notification server on a
// private test bus (internal/linuxtest/dbustest): it owns
// org.freedesktop.Notifications, records every Notify call and hands out
// ids, so a test can check what core/platform/linux/session would have
// shown without a notification ever reaching a desktop. Test-only code;
// nothing in it ships.
package fakenotify

import (
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

const (
	busName = "org.freedesktop.Notifications"
	path    = dbus.ObjectPath("/org/freedesktop/Notifications")
	iface   = "org.freedesktop.Notifications"
)

// firstID is the id the server gives its first notification. Not 1, so a
// replaces_id that happens to be small is told from the server's id.
const firstID uint32 = 100

// Call is one org.freedesktop.Notifications.Notify as the server saw it,
// plus the id it answered with.
type Call struct {
	ID            uint32
	AppName       string
	ReplacesID    uint32
	AppIcon       string
	Summary       string
	Body          string
	Actions       []string
	Hints         map[string]dbus.Variant
	ExpireTimeout int32
}

// Server is the running fake.
type Server struct {
	mu    sync.Mutex
	next  uint32
	calls []Call
	caps  []string
	stall chan struct{} // while non-nil, Notify waits for it to close
	// waiting counts the Notify calls that arrived and are held at the
	// stall, until Release lets them through.
	waiting int
}

// notifier is what is exported on the bus: only the Notify and
// GetCapabilities methods, so the Server's own methods are not reachable
// from the bus.
type notifier struct{ s *Server }

// Notify is org.freedesktop.Notifications.Notify. Every call gets a fresh
// id, a replace too (as a server does when the notification it names has
// already gone), so a test tells the id of the last Notify from the first.
func (n notifier) Notify(appName string, replacesID uint32, appIcon, summary, body string, actions []string, hints map[string]dbus.Variant, expireTimeout int32) (uint32, *dbus.Error) {
	n.s.mu.Lock()
	stall := n.s.stall
	if stall != nil {
		n.s.waiting++
	}
	n.s.mu.Unlock()
	if stall != nil {
		<-stall
	}
	n.s.mu.Lock()
	defer n.s.mu.Unlock()
	id := n.s.next
	n.s.next++
	n.s.calls = append(n.s.calls, Call{
		ID:            id,
		AppName:       appName,
		ReplacesID:    replacesID,
		AppIcon:       appIcon,
		Summary:       summary,
		Body:          body,
		Actions:       append([]string(nil), actions...),
		Hints:         hints,
		ExpireTimeout: expireTimeout,
	})
	return id, nil
}

// GetCapabilities is org.freedesktop.Notifications.GetCapabilities: what
// Serve set, or "body" and "body-markup" by default, as GNOME and KDE
// report.
func (n notifier) GetCapabilities() ([]string, *dbus.Error) {
	n.s.mu.Lock()
	defer n.s.mu.Unlock()
	return append([]string(nil), n.s.caps...), nil
}

// Serve owns org.freedesktop.Notifications on conn (a connection to a
// private bus). The name is released at cleanup; conn stays the caller's
// to close.
func Serve(t testing.TB, conn *dbus.Conn) *Server {
	t.Helper()
	s := &Server{next: firstID, caps: []string{"body", "body-markup"}}
	if err := conn.Export(notifier{s}, path, iface); err != nil {
		t.Fatalf("fakenotify: export: %v", err)
	}
	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		t.Fatalf("fakenotify: RequestName %s: %v", busName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("fakenotify: RequestName %s = %v, want primary owner", busName, reply)
	}
	t.Cleanup(func() {
		s.Release()
		conn.ReleaseName(busName)
	})
	return s
}

// SetCapabilities sets what GetCapabilities answers, for example "body"
// alone for a server that shows the body as plain text.
func (s *Server) SetCapabilities(caps ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caps = append([]string(nil), caps...)
}

// Stall makes every Notify from now on wait, unanswered, until Release:
// a notification daemon that hangs, or a bus that is still starting the
// server. Release also runs at cleanup.
func (s *Server) Stall() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stall == nil {
		s.stall = make(chan struct{})
	}
}

// Release lets the stalled Notify calls through, in the order they came,
// and answers later ones at once. Without a Stall it does nothing.
func (s *Server) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stall != nil {
		close(s.stall)
		s.stall = nil
		s.waiting = 0
	}
}

// Waiting is how many Notify calls have arrived and are held at the stall:
// a test uses it to know a call is in flight before it queues more.
func (s *Server) Waiting() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiting
}

// Calls returns every Notify so far, in order.
func (s *Server) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}
