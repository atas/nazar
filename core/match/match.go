// Package match evaluates config matchers against a caller chain (spec 4.2):
// apps: against the chain (who asks), to: against the receiver (who gets
// the result).
package match

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// Trust is the pinned state matchers consult (implemented by *trust.Store).
// It is read-only on purpose: matching never creates or changes a pin. Pins
// are written only when a config change that shows them is approved, or by
// `nazar trust --app`, both behind the login gate (spec 4.2, 4.8).
type Trust interface {
	PinnedTeam(bundleID string) (string, bool)
}

// Evaluator evaluates matchers. Note receives notable events (an unpinned
// app, a team mismatch) for the audit log; it may be nil.
type Evaluator struct {
	Trust Trust
	Note  func(msg string)
	// Command resolves a command: matcher's argv[0] to the realpath it
	// names, the way nazar run resolves a request (through the active
	// config's defaults.trustedPath). nil: command: matches nothing.
	Command func(argv0 string) (string, error)
}

func (e *Evaluator) note(format string, args ...any) {
	if e.Note != nil {
		e.Note(fmt.Sprintf(format, args...))
	}
}

// Apps reports whether any matcher in ms matches the chain: any process in
// it for signed: and path:, the chain's app for app:. The chain's app is
// the one in the chain or the one an orphaned helper at its top stands for
// (caller.AppFromHelper; spec 4.1 step 3).
//
// An unknown chain has no app, so app: never matches it. That includes a
// chain shown with a responsible app (caller.AppFromResponsible):
// responsibility is inherited by every process a tab ever started, so
// matching it would let a process shed the stricter rules of its ancestors
// by leaving the chain. Its processes are still what the kernel's parent
// links say, each verified as in any chain (a valid team signature for
// signed:, the executable's path for path:), so signed: and path: match a
// process that is in it (spec 4.2): that a process with
// that code identity is an ancestor of the requester holds whatever sits at
// the top, and a process that leaves its chain loses its ancestors' matches
// with them. An ancestor is not proof that the program started the
// requester: a process can fork its client and then exec the signed program
// over itself (exec keeps the PID and start time), so a signed: rule covers
// whatever can run that program, in any chain (THREAT-MODEL 5.12).
// An unknown chain cut off before launchd (Truncated) may be missing what
// is above the cut, and is matched only by any and unknown.
func (e *Evaluator) Apps(ms []config.Matcher, c *caller.Chain) bool {
	_, ok := e.Matched(ms, c)
	return ok
}

// Matched is Apps with the process that satisfied the matcher: the chain's
// app for app:; for signed: and path:, the outermost process in the session
// (caller.Chain.Below, from the session root down to the peer) whose code
// identity or path satisfies it, or, when none is there, the first
// such process peer first (one above the app, or between the app and its
// session); in an unknown chain, which has neither, the outermost such
// process in it. any and unknown name no process (a zero ref). A session
// approval is bound to that process's run when it is a tool in the session
// (Milestone 7), so a claude a claude started is inside the run of
// the one the user started. The dialog and the audit line name the process
// when the chain they show does not include it (spec 4.4, 4.6).
func (e *Evaluator) Matched(ms []config.Matcher, c *caller.Chain) (platform.ProcessRef, bool) {
	for _, m := range ms {
		if ref, ok := e.appMatch(m, c); ok {
			return ref, true
		}
	}
	return platform.ProcessRef{}, false
}

func (e *Evaluator) appMatch(m config.Matcher, c *caller.Chain) (platform.ProcessRef, bool) {
	if c.Synthetic {
		return platform.ProcessRef{}, false // a run receiver never asks
	}
	switch m.Kind {
	case config.MatchAny:
		return platform.ProcessRef{}, true
	case config.MatchUnknown:
		return platform.ProcessRef{}, c.Unknown
	}
	switch m.Kind {
	case config.MatchApp:
		if !c.Unknown && e.app(m, c) {
			return c.App.Ref, true
		}
	case config.MatchSigned, config.MatchPath:
		if c.Unknown && c.Truncated {
			// The walk stopped before launchd: what was cut off may be an
			// ancestor a stricter rule names, so no process here is matched.
			return platform.ProcessRef{}, false
		}
		for _, p := range c.Below() {
			if e.process(m, p) {
				return p.Ref, true
			}
		}
		if c.Unknown {
			break // Below was the whole chain: each process is judged (and noted) once
		}
		for _, p := range c.Procs {
			if e.process(m, p) {
				return p.Ref, true
			}
		}
	}
	return platform.ProcessRef{}, false
}

// Receiver reports whether any matcher in ms matches the process that gets
// the result (for ssh: the socket peer), judged by its own identity alone.
// A rule without to: never calls this.
func (e *Evaluator) Receiver(ms []config.Matcher, c *caller.Chain) bool {
	peer, ok := c.Peer()
	if c.Synthetic {
		// A nazar run receiver (secrets design 6.3, D4): its record is the
		// agent's resolution, not a live process, so only command: (and
		// any) can match it.
		for _, m := range ms {
			switch m.Kind {
			case config.MatchAny:
				return true
			case config.MatchCommand:
				if ok && e.command(m, peer) {
					return true
				}
			}
		}
		return false
	}
	for _, m := range ms {
		switch m.Kind {
		case config.MatchAny:
			return true
		case config.MatchApp:
			if ok && c.AppSource == caller.AppFromChain && c.App.Ref == peer.Ref && e.app(m, c) {
				return true
			}
		case config.MatchSigned, config.MatchPath:
			if ok && e.process(m, peer) {
				return true
			}
		}
	}
	return false
}

// command reports whether a run receiver satisfies a command: matcher
// (secrets design 6.3.3): the matcher's argv[0] resolves to the receiver's
// realpath, and the rest of its argv equals the command line's byte for
// byte. argv[0] as typed is never compared: whoever runs the command
// chooses it.
func (e *Evaluator) command(m config.Matcher, p platform.ProcessInfo) bool {
	if e.Command == nil || len(m.Command) == 0 || len(p.Args) == 0 || !slices.Equal(m.Command[1:], p.Args[1:]) {
		return false
	}
	path, err := e.Command(m.Command[0])
	if err != nil {
		e.note("command: %s matches nothing: %v", m.Command[0], err)
		return false
	}
	return path != "" && path == p.Path
}

// process reports whether one process satisfies a signed: or path:
// matcher.
func (e *Evaluator) process(m config.Matcher, p platform.ProcessInfo) bool {
	switch m.Kind {
	case config.MatchSigned:
		return signed(m, p.Code)
	case config.MatchPath:
		return e.path(m.Path, p)
	}
	return false
}

// path reports whether p runs the file a path: matcher names (spec 4.2):
// its executable, as the kernel reports it (never argv[0], which the
// caller chooses), is the rule's path with its symlinks resolved now, so
// a Homebrew opt/ link follows an upgrade, or the rule's path itself. A
// path that does not resolve (gone) matches nothing. No hash is pinned:
// the rule is only as safe as who can write that file.
func (e *Evaluator) path(rule string, p platform.ProcessInfo) bool {
	if p.Path == "" || rule == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(rule)
	if err != nil {
		return false
	}
	return p.Path == resolved || p.Path == rule
}

// signed checks team and (when given) signing identifier. CodeIdentity.Team
// is "" for unsigned and ad-hoc code, so those never match any team.
func signed(m config.Matcher, code platform.CodeIdentity) bool {
	team := code.Team()
	if team == "" || team != m.Team {
		return false
	}
	return m.ID == "" || code.SigningID == m.ID
}

// app checks the chain's app against an app: matcher: the bundle ID must
// be the matcher's and the app's team must equal the explicit team: or,
// without one, the team pinned for that bundle ID when the config was
// approved (or by `nazar trust --app`). An unpinned bundle ID matches
// nothing, however many times it asks, and a mismatch is noted but never
// re-pinned: the first process to present a bundle ID must not become the
// app it claims to be.
func (e *Evaluator) app(m config.Matcher, c *caller.Chain) bool {
	if c.AppSource == caller.AppNone || c.App.BundleID != m.ID {
		return false
	}
	team := c.App.Code.Team()
	if team == "" {
		e.note("app %s is not validly signed; it can't match app: %s", m.ID, m.ID)
		return false
	}
	if m.Team != "" {
		return team == m.Team
	}
	pinned, ok := e.Trust.PinnedTeam(m.ID)
	if !ok {
		e.note("app %s has no pinned team, so app: %s matches nothing; approve a config change that pins it or run `nazar trust --app %s`", m.ID, m.ID, m.ID)
		return false
	}
	if pinned != team {
		e.note("app %s has team %s but %s is pinned; not matching", m.ID, team, pinned)
		return false
	}
	return true
}

// Identity is a stable identity string for a process, used as the receiver
// part of approval cache keys: "team:signing-id" for validly signed code,
// "path:<path>#<cdhash>" otherwise (unsigned and ad-hoc code never gets a
// team identity, whatever its fields claim).
func Identity(p platform.ProcessInfo) string {
	if t := p.Code.Team(); t != "" {
		return t + ":" + p.Code.SigningID
	}
	return "path:" + p.Path + "#" + hex.EncodeToString(p.Code.CDHash)
}

// RunIdentity is the receiver part of the approval key of a nazar run
// (secrets design 6.3, D5): the realpath, the digest of everything pinned
// (run.Resolution.Receiver) and the command line, each quoted.
func RunIdentity(p platform.ProcessInfo) string {
	var b strings.Builder
	b.WriteString("run:" + strconv.Quote(p.Path) + "#" + hex.EncodeToString(p.Code.CDHash))
	for i, a := range p.Args {
		if i > 0 { // argv[0] is the path above, whatever a record holds
			b.WriteString(" " + strconv.Quote(a))
		}
	}
	return b.String()
}
