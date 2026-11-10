//go:build linux

package session

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform"
)

const (
	notifyName  = "org.freedesktop.Notifications"
	notifyPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notifyIface = "org.freedesktop.Notifications"
	appName     = "nazar"
	appIcon     = "dialog-warning"
	// urgencyNormal is the Desktop Notifications urgency hint for a warning
	// the user should see but that need not stay on screen.
	urgencyNormal byte = 1
	// expireDefault lets the server choose how long the notification shows.
	expireDefault int32 = -1
	// bodyMarkup is the server capability that makes the body a small HTML
	// subset; without it the body shows as plain text.
	bodyMarkup = "body-markup"
	// maxIDs bounds the Warning.ID to notification id map over the agent's
	// life; past it the map starts over and the next warnings are fresh
	// notifications.
	maxIDs = 256
	// maxPending bounds the warnings waiting to be sent while the server is
	// slow or does not answer (a warning against a server that does not
	// answer takes up to two callTimeouts: GetCapabilities, then Notify);
	// past it the oldest is dropped, as the plan allows for a call that
	// fails.
	maxPending = 16
)

// warning is one ShowWarning, as queued: the body unescaped, since whether
// the server reads markup is known only when it is asked, at send time.
type warning struct {
	id      string
	summary string
	body    string
}

// escapeBody escapes the characters a markup body treats as markup, so a
// line that was a command line or a key name shows as typed.
var escapeBody = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// render turns the warning into the notification's summary and body: the
// Title, with " (×N)" when Count > 1; the lines joined by newlines, then
// "Suggested rule: <rule>" when there is one.
func render(w platform.Warning) warning {
	summary := w.Title
	if w.Count > 1 {
		summary = fmt.Sprintf("%s (×%d)", w.Title, w.Count)
	}
	lines := append([]string(nil), w.Lines...)
	if w.SuggestedRule != "" {
		lines = append(lines, "Suggested rule: "+w.SuggestedRule)
	}
	return warning{id: w.ID, summary: summary, body: strings.Join(lines, "\n")}
}

// ShowWarning shows or updates the block warning as a desktop notification
// (org.freedesktop.Notifications.Notify). It queues the call to the
// session's one notifying goroutine and returns at once, whatever the
// server does; a warning with the same ID replaces the notification the
// server gave for the last one. A call that fails (no connection, no
// server, a server that does not answer) is dropped. While the server is
// slow, a warning still waiting to be sent is replaced by a newer one with
// the same ID (the user sees the latest count, not every step), and the
// queue holds at most maxPending warnings: past that the oldest goes.
func (s *Session) ShowWarning(w platform.Warning) {
	if s.notify == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	r := render(w)
	queued := false
	for i := range s.pending {
		if s.pending[i].id == r.id {
			s.pending[i] = r
			queued = true
			break
		}
	}
	if !queued {
		if len(s.pending) >= maxPending {
			s.pending = s.pending[1:]
		}
		s.pending = append(s.pending, r)
	}
	if !s.notifying {
		s.notifying = true
		go s.sendWarnings()
	}
}

// sendWarnings sends the queued warnings in order until the queue is
// empty, then exits; the next ShowWarning starts it again.
func (s *Session) sendWarnings() {
	for {
		s.mu.Lock()
		if len(s.pending) == 0 || s.closed {
			s.pending = nil
			s.notifying = false
			s.mu.Unlock()
			return
		}
		w := s.pending[0]
		s.pending = s.pending[1:]
		replaces := s.ids[w.id]
		s.mu.Unlock()

		// The body carries text the blocked program chose (its command
		// line), so a server that reads markup gets it escaped. A server
		// that shows plain text gets it as typed, since it would show
		// "&amp;". The server is asked every time: the one that owns the
		// name may change over the agent's life (a notification daemon
		// restarted or swapped), and the answer is never kept. Unknown (the
		// server did not say): escape, as the plan's wording has it.
		if s.bodyMarkup() {
			w.body = escapeBody.Replace(w.body)
		}

		id, err := s.sendNotify(w, replaces)
		if err != nil {
			continue
		}
		s.mu.Lock()
		if !s.closed {
			if _, known := s.ids[w.id]; !known && len(s.ids) >= maxIDs {
				s.ids = map[string]uint32{}
			}
			s.ids[w.id] = id
		}
		s.mu.Unlock()
	}
}

// bodyMarkup asks the server what it shows (GetCapabilities, bounded by
// callTimeout) and reports whether it reads markup in the body. A server
// that does not answer counts as reading markup: the body is then escaped,
// the safe side.
func (s *Session) bodyMarkup() bool {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var caps []string
	if err := s.notify.Object(notifyName, notifyPath).CallWithContext(ctx, notifyIface+".GetCapabilities", 0).Store(&caps); err != nil {
		return true
	}
	return slices.Contains(caps, bodyMarkup)
}

// sendNotify is one Notify call, bounded by callTimeout.
func (s *Session) sendNotify(w warning, replaces uint32) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(urgencyNormal)}
	var id uint32
	err := s.notify.Object(notifyName, notifyPath).CallWithContext(ctx, notifyIface+".Notify", 0,
		appName, replaces, appIcon, w.summary, w.body, []string{}, hints, expireDefault).Store(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}
