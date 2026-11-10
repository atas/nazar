//go:build linux

// Package polkit is the Linux `login` gate: the system's own
// authentication, asked for through polkit. nazar ships one action,
// dev.nazar.authenticate (packaging/linux/dev.nazar.authenticate.policy),
// whose three defaults are auth_self: the user proves it is them (their
// password, or a fingerprint where PAM is set up for one) and nothing is
// kept, so every Check asks again. The action's message is
// $(nazar.prompt), which polkit fills from the detail Check passes: the
// desktop's own polkit agent shows the request's title and lines.
//
// Check fails closed: polkit unreachable, no agent for the session, a
// subject that cannot be named, a reply that is neither yes nor no, all
// are errors. Only a refusal, a cancelled prompt or the timeout is
// platform.ErrDenied. polkit approves root without asking, and an owner
// of the action may ask about subjects of other users, so Check also
// refuses, before polkit is asked, to run as root and to ask about a
// subject that is not this user.
package polkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"

	"github.com/atas/nazar/core/platform"
)

const (
	// ActionID is nazar's polkit action.
	ActionID = "dev.nazar.authenticate"
	// PromptDetail is the CheckAuthorization detail the action's message
	// expands, `$(nazar.prompt)`.
	PromptDetail = "nazar.prompt"
	// OwnerAnnotation is the action annotation that names who may pass
	// details to CheckAuthorization besides root: polkitd refuses the
	// prompt text from anyone else. nazar's action owns it to the user
	// (`unix-user:<name>`, space-separated when several users install).
	OwnerAnnotation = "org.freedesktop.policykit.owner"
	// OwnerPlaceholder stands for the owners in the packaging file.
	// `nazar install --system` replaces it with the installing user and
	// refuses to install the file with it left in; the test image fills
	// in its test user.
	OwnerPlaceholder = "@NAZAR_OWNERS@"

	busName      = "org.freedesktop.PolicyKit1"
	objectPath   = dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority")
	iface        = "org.freedesktop.PolicyKit1.Authority"
	errCancelled = "org.freedesktop.PolicyKit1.Error.Cancelled"
	// polkitd's refusal of details from a caller that does not own the action.
	errNotAuthorized = "org.freedesktop.PolicyKit1.Error.NotAuthorized"
	notOwnerText     = "Only trusted callers"

	// allowUserInteraction is CheckAuthorizationFlags.AllowUserInteraction.
	allowUserInteraction uint32 = 1

	// maxPromptBytes bounds the text handed to polkit and shown by the
	// desktop's agent.
	maxPromptBytes = 1000
	// maxLineBytes bounds one line of a text that does not fit, so that one
	// long line cannot push out the others. An ASCII command line
	// (core/broker caps lines at 400 characters) is not cut by it.
	maxLineBytes = 400
	ellipsis     = "…"

	// cancelGrace bounds the cancel of a timed-out check and the wait for
	// polkit to end it; the answer is ErrDenied either way.
	cancelGrace = 5 * time.Second

	logindName    = "org.freedesktop.login1"
	logindPath    = dbus.ObjectPath("/org/freedesktop/login1")
	logindManager = "org.freedesktop.login1.Manager"
	logindSession = "org.freedesktop.login1.Session"
	// logindTimeout bounds asking logind whose session the subject is.
	logindTimeout = 2 * time.Second
)

// errNoAgent: polkit says the subject could authenticate but nobody can
// ask it, because no polkit authentication agent is registered for its
// session (no graphical session, or a desktop without one).
var errNoAgent = errors.New("no polkit authentication agent for this session")

// errNoTimeout: nothing would end a check that polkit never answers. The
// broker always sets a timeout.
var errNoTimeout = errors.New("polkit: the prompt has no timeout")

// errRoot: polkit approves root for every action without asking, so a nil
// from Check would not mean that anyone authenticated.
var errRoot = errors.New("polkit: running as root, which polkit approves without asking")

// processUIDs is this process's real and effective uid; a variable for the
// tests.
var processUIDs = func() (real, effective int) { return os.Getuid(), os.Geteuid() }

// Subject is a polkit subject, the D-Bus struct (sa{sv}).
type Subject struct {
	Kind    string
	Details map[string]dbus.Variant
}

// SessionSubject is the user's logind session (production): the desktop's
// polkit agent is registered for it.
func SessionSubject(sessionID string) Subject {
	return Subject{Kind: "unix-session", Details: map[string]dbus.Variant{
		"session-id": dbus.MakeVariant(sessionID),
	}}
}

// ProcessSubject is one process (tests, and pkttyagent-style agents):
// pid, its start ticks from /proc/<pid>/stat and its uid, which polkit
// checks against /proc.
func ProcessSubject(pid int, startTicks uint64, uid int) Subject {
	return Subject{Kind: "unix-process", Details: map[string]dbus.Variant{
		"pid":        dbus.MakeVariant(uint32(pid)),
		"start-time": dbus.MakeVariant(startTicks),
		"uid":        dbus.MakeVariant(int32(uid)),
	}}
}

// Authority asks polkit on the system bus for one subject.
type Authority struct {
	conn    *dbus.Conn
	subject func() (Subject, error)
	serial  atomic.Uint64
}

// New makes an Authority on the system bus connection. subject names who
// is asking, resolved on every Check (a session may not exist yet when
// the agent starts).
func New(system *dbus.Conn, subject func() (Subject, error)) *Authority {
	return &Authority{conn: system, subject: subject}
}

// PromptText is what the agent shows: the title, then each line, joined
// by newlines, at most maxPromptBytes. A cut is never silent, because the
// user approves what this says. A text that does not fit first has its long
// lines cut, each ending with an ellipsis. If it still does not fit, the
// title stays with a line saying how many lines are left out, then as many
// lines as fit: the last, the command, the first, then the rest from the
// end. The end of a prompt is what the approval is about (a key's scope,
// what a config change loosens).
func PromptText(p platform.Prompt) string {
	p.Title = markupSafe.Replace(p.Title)
	p.Lines = slices.Clone(p.Lines)
	for i, l := range p.Lines {
		p.Lines[i] = markupSafe.Replace(l)
	}
	if s := joinPrompt(p.Title, p.Lines); len(s) <= maxPromptBytes {
		return s
	}
	title := cutLine(p.Title)
	lines := make([]string, len(p.Lines))
	for i, l := range p.Lines {
		lines[i] = cutLine(l)
	}
	if s := joinPrompt(title, lines); len(s) <= maxPromptBytes {
		return s
	}
	// The title, the marker and the last line always fit: two lines of
	// maxLineBytes and a short marker. Not every line can: the text is too
	// long even without the marker this room is reserved for.
	room := maxPromptBytes - len(title) - 1 - len(notShown(len(lines)))
	keep := make([]bool, len(lines))
	take := func(i int) {
		if i < 0 || i >= len(lines) || keep[i] {
			return
		}
		if n := len(lines[i]) + 1; n <= room {
			keep[i] = true
			room -= n
		}
	}
	take(len(lines) - 1)
	take(p.CommandLine - 1)
	take(0)
	for i := len(lines) - 2; i > 0; i-- {
		take(i)
	}
	kept := make([]string, 0, len(lines))
	for i, l := range lines {
		if keep[i] {
			kept = append(kept, l)
		}
	}
	return joinPrompt(title, append([]string{notShown(len(lines) - len(kept))}, kept...))
}

func joinPrompt(title string, lines []string) string {
	return strings.Join(append([]string{title}, lines...), "\n")
}

// markupSafe replaces the three characters a polkit agent that reads the
// message as markup acts on (mate-polkit and LXQt's agent set it as Pango
// or Qt rich text with no escaping; GNOME Shell's and KDE's were not
// checked) with their fullwidth look-alikes, U+FF1C, U+FF1E and U+FF06.
// A caller's command line, which the broker cleans of control characters
// only, then can neither hide nor restyle the lines around it, and an agent
// that shows plain text shows no entities. The broker's clean keeps these
// (they are printable), and they are three bytes each, so the replacement
// comes before PromptText's bound.
var markupSafe = strings.NewReplacer("<", "＜", ">", "＞", "&", "＆")

// cutLine cuts s to maxLineBytes on a character boundary, ending it with
// an ellipsis.
func cutLine(s string) string {
	if len(s) <= maxLineBytes {
		return s
	}
	cut := maxLineBytes - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}

// notShown is the line that says how many lines are left out.
func notShown(n int) string {
	if n == 1 {
		return "(1 line not shown)"
	}
	return fmt.Sprintf("(%d lines not shown)", n)
}

// requireOwnUser refuses a subject that is root, which polkit approves
// without asking, or another user, which an owner of the action may ask
// about: a nil from polkit would not mean that this user authenticated.
func (a *Authority) requireOwnUser(s Subject, uid int) error {
	subjectUID, err := a.subjectUID(s)
	if err != nil {
		return err
	}
	switch {
	case subjectUID == 0:
		return errors.New("a root subject, which polkit approves without asking")
	case subjectUID != uid:
		return fmt.Errorf("subject uid %d is not this user (uid %d)", subjectUID, uid)
	}
	return nil
}

func (a *Authority) subjectUID(s Subject) (int, error) {
	switch s.Kind {
	case "unix-process":
		uid, ok := s.Details["uid"].Value().(int32)
		if !ok {
			return 0, errors.New("a process subject without a uid")
		}
		return int(uid), nil
	case "unix-session":
		id, ok := s.Details["session-id"].Value().(string)
		if !ok {
			return 0, errors.New("a session subject without a session id")
		}
		return a.sessionUID(id)
	default:
		return 0, fmt.Errorf("a subject of kind %q", s.Kind)
	}
}

// sessionUID asks logind whose session this is. A session subject names no
// user, and it is the subject production uses.
func (a *Authority) sessionUID(id string) (int, error) {
	ctx, done := context.WithTimeout(context.Background(), logindTimeout)
	defer done()
	var path dbus.ObjectPath
	if err := a.conn.Object(logindName, logindPath).CallWithContext(ctx, logindManager+".GetSession", 0, id).Store(&path); err != nil {
		return 0, fmt.Errorf("session %s: %w", id, err)
	}
	var user dbus.Variant
	if err := a.conn.Object(logindName, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, logindSession, "User").Store(&user); err != nil {
		return 0, fmt.Errorf("session %s: %w", id, err)
	}
	var owner struct {
		UID  uint32
		Path dbus.ObjectPath
	}
	if err := user.Store(&owner); err != nil {
		return 0, fmt.Errorf("session %s: its user: %w", id, err)
	}
	return int(owner.UID), nil
}

// authorization is CheckAuthorization's reply, (bba{ss}).
type authorization struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

// Check asks polkit to authenticate the subject for nazar's action, with
// the prompt as the message. nil: the user authenticated. ErrDenied: they
// refused, dismissed the prompt or did not answer within p.Timeout (the
// check is cancelled at polkit, which closes the agent's prompt). Any
// other outcome is an error: no agent to ask, no subject, polkit down, no
// timeout, running as root, a subject that is root or another user. Check
// returns within p.Timeout plus cancelGrace and logindTimeout, whatever
// polkit and logind do.
func (a *Authority) Check(p platform.Prompt) error {
	if p.Timeout <= 0 {
		return errNoTimeout
	}
	realUID, uid := processUIDs()
	if realUID == 0 || uid == 0 {
		return errRoot
	}
	subject, err := a.subject()
	if err != nil {
		return fmt.Errorf("polkit: subject: %w", err)
	}
	if err := a.requireOwnUser(subject, uid); err != nil {
		return fmt.Errorf("polkit: subject: %w", err)
	}
	// Unique per connection, which is what polkit keys cancellations by.
	cancellationID := fmt.Sprintf("nazar-%d-%d", os.Getpid(), a.serial.Add(1))
	details := map[string]string{PromptDetail: PromptText(p)}
	obj := a.conn.Object(busName, objectPath)
	// Ended on return, so a check polkit never answers is not left pending
	// on the connection.
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	call := obj.GoWithContext(ctx, iface+".CheckAuthorization", 0, make(chan *dbus.Call, 1),
		subject, ActionID, details, allowUserInteraction, cancellationID)

	timer := time.NewTimer(p.Timeout)
	defer timer.Stop()
	select {
	case <-call.Done:
		return result(call)
	case <-timer.C:
	}

	// Past the timeout. Cancel at polkit, which tells the agent to close
	// its prompt, and give the reply a moment to arrive so nothing is
	// left pending; the answer is a refusal whatever it says. The cancel
	// and the wait share one bound, so a polkitd that answers neither
	// cannot hold Check past it.
	grace, done := context.WithTimeout(context.Background(), cancelGrace)
	defer done()
	obj.GoWithContext(grace, iface+".CancelCheckAuthorization", 0, make(chan *dbus.Call, 1), cancellationID)
	select {
	case <-call.Done:
	case <-grace.Done():
	}
	return platform.ErrDenied
}

func result(call *dbus.Call) error {
	if call.Err != nil {
		var derr dbus.Error
		if errors.As(call.Err, &derr) && derr.Name == errCancelled {
			return platform.ErrDenied
		}
		if errors.As(call.Err, &derr) && derr.Name == errNotAuthorized && strings.HasPrefix(derr.Error(), notOwnerText) {
			// polkitd takes the prompt text only from an owner of the
			// action, and this user is not one: the policy file names
			// whoever ran install --system.
			return fmt.Errorf("polkit: CheckAuthorization: this user does not own nazar's polkit action; run once: sudo \"$(command -v nazar)\" install --system (%w)", call.Err)
		}
		return fmt.Errorf("polkit: CheckAuthorization: %w", call.Err)
	}
	var r authorization
	if err := call.Store(&r); err != nil {
		return fmt.Errorf("polkit: CheckAuthorization reply: %w", err)
	}
	switch {
	case r.IsAuthorized:
		return nil
	case r.IsChallenge:
		// Authentication would do, but polkit found no agent to run it.
		return errNoAgent
	default:
		// The user refused, failed to authenticate or dismissed the prompt.
		return platform.ErrDenied
	}
}
