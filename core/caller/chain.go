// Package caller turns a socket peer into a Chain: the process chain up to
// launchd, the GUI app it belongs to and its session (spec 4.1, spike S3).
package caller

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/atas/nazar/core/platform"
)

// AppSource says how Chain.App was found.
type AppSource int

const (
	AppNone            AppSource = iota // no app: the chain is unknown
	AppFromChain                        // a GUI app bundle in the chain
	AppFromResponsible                  // the responsible-process lookup: display only, the chain is still unknown
	AppFromHelper                       // the running app an orphaned helper at the top of the chain stands for (spec 4.1 step 3)
)

func (s AppSource) String() string {
	switch s {
	case AppFromChain:
		return "chain"
	case AppFromResponsible:
		return "responsible"
	case AppFromHelper:
		return "helper"
	}
	return "none"
}

// SessionID identifies a session root process: (pid, start time). The start
// time makes a recycled PID a different session.
type SessionID struct {
	PID   int
	Start time.Time
}

// IsZero reports whether s names no session.
func (s SessionID) IsZero() bool { return s.PID == 0 }

// String is the canonical form used in audit lines, `nazar status` and
// `nazar revoke --session`: "<pid>@<unix seconds>". It is "" for no session.
func (s SessionID) String() string {
	if s.IsZero() {
		return ""
	}
	return fmt.Sprintf("%d@%d", s.PID, s.Start.Unix())
}

// Chain is a resolved caller. A Resolver never fails to produce one: when
// the peer can't be identified the Chain is Unknown with no Procs.
type Chain struct {
	// Procs is the process chain, peer first, launchd excluded.
	Procs []platform.ProcessInfo
	// App is valid only when AppSource != AppNone: the app in the chain
	// (AppFromChain), or the running app that an orphaned helper at the
	// top of the chain stands for (AppFromHelper: iTerm2 after it
	// restarted under a tab kept alive by iTermServer), both identities the
	// chain matches and is remembered under. With AppFromResponsible it is
	// the app the chain was attributed to for display (Summary) and the
	// chain is Unknown: the app is not an identity the chain can match or
	// be remembered under.
	App       platform.AppInfo
	AppSource AppSource
	// Session is zero when there is no session root: an unknown chain, an
	// app found only through the responsible process, the peer being the
	// app itself, or the peer being one of the app's own helpers (the one
	// standing for the app included).
	Session     SessionID
	SessionRoot platform.ProcessRef
	// Unknown is true when no app was found in the chain (spec 4.1 step 5),
	// whether or not a responsible app is shown. An unknown chain is matched
	// by any/unknown, never by app:, by signed: only for a process in
	// it and only when it is not Truncated (match.Evaluator.Apps), and is
	// never covered by a remembered approval (spec 4.2); AppName and
	// AppIdentity report it as having no app.
	Unknown bool
	// Truncated is true when the walk stopped before launchd: the peer or a
	// parent vanished, a loop, a PID-reuse inconsistency or the depth limit.
	Truncated bool
	// Synthetic marks a chain built from the agent's own resolution of a
	// nazar run command line (Synthetic), not from a live process.
	Synthetic bool
}

// Synthetic is the receiver chain of a nazar run (secrets design 5.2): one
// process, the record the agent built from its own resolution of the
// command line (run.Resolution.Receiver), before anything runs. It has no
// app and no session; only a command: matcher or to: any matches it
// (match.Evaluator.Receiver).
// The record keeps only what the agent computes (path, argv, directory,
// digest): no ref, no signature, so nothing in it can pass for a live or
// signed process.
func Synthetic(info platform.ProcessInfo) *Chain {
	p := platform.ProcessInfo{Path: info.Path, Args: info.Args, Cwd: info.Cwd, Code: platform.CodeIdentity{CDHash: info.Code.CDHash}}
	return &Chain{Procs: []platform.ProcessInfo{p}, Synthetic: true}
}

// Peer returns the process connected to the socket (the receiver for ssh).
func (c *Chain) Peer() (platform.ProcessInfo, bool) {
	if len(c.Procs) == 0 {
		return platform.ProcessInfo{}, false
	}
	return c.Procs[0], true
}

// Parent is the chain seen from the peer's parent: the same chain without
// its peer (secrets design 5.2: for the helper and stdout methods the
// receiver is the parent of the nazar CLI that asked). It is for matching
// to: and showing the receiver, both judged by the new peer's own
// identity; the app and session fields are the original chain's. A chain
// with no process left has no peer and matches only to: any.
func (c *Chain) Parent() *Chain {
	p := *c
	if len(p.Procs) > 0 {
		p.Procs = p.Procs[1:]
	}
	return &p
}

// Callers is the chain k8s and aws rules are judged on (k8s design 2.3):
// c is the nazar CLI's, chain[1] the client that ran it, and the rules
// see whoever called the client, chain[2:]. A client launchd started
// (the walk reached launchd right above it: a daemon, a login item) has
// no caller, so it is judged as its own: the view starts at the client.
// That gives a rule naming it nothing a rule naming it did not give
// already, since the client could reach the plugin through kubectl or
// aws, where that rule matches it; rules naming kubectl or aws are
// refused by config check.
func (c *Chain) Callers() *Chain {
	if len(c.Procs) == 2 && !c.Truncated {
		return c.Parent()
	}
	return c.Parent().Parent()
}

// HasApp reports whether the chain has an app as its identity: one found
// in the chain, or the one an orphaned helper stands for. An app shown for
// an unknown chain (AppFromResponsible) is not one.
func (c *Chain) HasApp() bool {
	return !c.Unknown && c.AppSource != AppNone
}

// Helper returns the process standing for the app at the top of the chain
// (AppFromHelper): an orphaned helper such as iTermServer after iTerm2
// restarted. ok is false for every other chain.
func (c *Chain) Helper() (platform.ProcessInfo, bool) {
	if c.AppSource != AppFromHelper || len(c.Procs) == 0 {
		return platform.ProcessInfo{}, false
	}
	return c.Procs[len(c.Procs)-1], true
}

// Tool returns the process ref names when it is a tool running inside the
// session (Milestone 7): strictly below the session root and not
// Apple-signed. A session approval for a rule such a process satisfied is
// that process's run (policy.Engine): the shells, ssh and git are Apple's
// and are the session, not a run in it, so a rule they satisfy stays the
// tab's. ok is false for every other ref: the root, anything above it (the
// app, its helpers, a tool the app started directly, whose session is the
// shell below it, spec 4.1 step 4), an unknown chain, the zero ref.
func (c *Chain) Tool(ref platform.ProcessRef) (platform.ProcessInfo, bool) {
	if c.Unknown || ref.IsZero() || c.SessionRoot.IsZero() {
		return platform.ProcessInfo{}, false
	}
	for _, p := range c.Procs { // peer first: everything before the root is below it
		if p.Ref == c.SessionRoot {
			return platform.ProcessInfo{}, false
		}
		if p.Ref == ref {
			return p, p.Code.Team() != "apple"
		}
	}
	return platform.ProcessInfo{}, false
}

// head is the index in Procs of the process the app is found at: the app
// itself (AppFromChain) or the helper standing for it (AppFromHelper); -1
// when there is none.
func (c *Chain) head() int {
	switch c.AppSource {
	case AppFromChain:
		return indexOf(c.Procs, c.App.Ref)
	case AppFromHelper:
		return len(c.Procs) - 1
	}
	return -1
}

// AppName is the app's display name (its bundle ID when it has no name), or
// "Unknown app" for an unknown chain, including one attributed to a
// responsible app for display: the headline says what the chain is, and
// Summary carries the attribution ("iTerm2 (responsible) → ssh").
func (c *Chain) AppName() string {
	if c.Unknown || c.AppSource == AppNone {
		return "Unknown app"
	}
	return c.appName()
}

func (c *Chain) appName() string {
	if c.App.Name != "" {
		return c.App.Name
	}
	return c.App.BundleID
}

// AppIdentity is "team:bundle" ("apple:bundle" for Apple apps), the identity
// a scope: app approval is remembered under (spec 4.2). It is "" when there
// is no app, the chain is unknown (nothing may be remembered for it), or the
// app's code is not validly signed (unsigned or ad-hoc), so nothing can be
// remembered for an app whose identity can't be verified.
func (c *Chain) AppIdentity() string {
	if c.Unknown || c.AppSource == AppNone {
		return ""
	}
	team := c.App.Code.Team()
	if team == "" {
		return ""
	}
	return team + ":" + c.App.BundleID
}

// Below returns the processes the user thinks of as "the command": from the
// session root (or, without one, the process just below the app or the
// helper standing for it) down to the peer, outermost first. The app, its
// helpers and everything above the app are left out; for a chain without
// an app in it, it is the whole chain.
func (c *Chain) Below() []platform.ProcessInfo {
	start := len(c.Procs) - 1
	head := c.head()
	for i, p := range c.Procs {
		if !c.SessionRoot.IsZero() && p.Ref == c.SessionRoot {
			start = i
			break
		}
		if i == head {
			start = i - 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	out := make([]platform.ProcessInfo, 0, start+1)
	for i := start; i >= 0; i-- {
		out = append(out, c.Procs[i])
	}
	return out
}

// wrappers are the executables Command walks past: ssh and ssh-keygen (the
// socket peer of nearly every ssh-agent request, started by git or another
// tool) and the shells such tools run them through (`sh -c
// "$GIT_SSH_COMMAND"`, a login shell). They are recognised by the base name
// of the executable the kernel reports (ProcessInfo.Path), never by argv[0],
// which a process chooses freely: a program that calls itself "ssh" or
// "-zsh" is not a wrapper and cannot hide behind the command that started
// it.
var wrappers = map[string]bool{
	"ssh": true, "ssh-keygen": true,
	"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true, "ksh": true, "tcsh": true, "csh": true,
}

// Command returns the process whose command line says what the user ran
// (spec 4.4): walking up from the peer within Below(), the first process
// that is not a wrapper. When every process on the way is a wrapper (ssh
// typed at the prompt), it is the peer itself. It is for the dialog and the
// audit line only: nothing is matched or remembered by it.
func (c *Chain) Command() (platform.ProcessInfo, bool) {
	below := c.Below()
	for i := len(below) - 1; i >= 0; i-- {
		if !wrappers[filepath.Base(below[i].Path)] {
			return below[i], true
		}
	}
	return c.Peer()
}

// Summary is the human chain, outermost first: "iTerm2 → bash → git → ssh".
// An app found through the responsible process is marked "(responsible)";
// an app an orphaned helper stands for says through which helper, "iTerm2
// (via iTermServer-3.7.4) → bash → git → ssh"; a truncated chain starts
// with "…".
//
// Every element is rendered through safeName, so an executable's file name
// or an app's display name (both attacker-chosen) can't forge hops, the
// separator, "(responsible)", "(via …)" or the truncation mark: a binary
// named "claude → ssh" renders as the single quoted hop `"claude → ssh"`.
func (c *Chain) Summary() string {
	var parts []string
	if c.AppSource != AppNone {
		name := safeName(c.appName())
		switch c.AppSource {
		case AppFromResponsible:
			name += " (responsible)"
		case AppFromHelper:
			h, _ := c.Helper()
			hn, deleted := ProcName(h)
			via := safeName(hn)
			if deleted {
				via += DeletedMark
			}
			name += " (via " + via + ")"
		}
		parts = append(parts, name)
	}
	for _, p := range c.Below() {
		name, deleted := ProcName(p)
		part := safeName(name)
		if deleted {
			part += DeletedMark
		}
		parts = append(parts, part)
	}
	if c.Truncated {
		parts = append([]string{"…"}, parts...)
	}
	return strings.Join(parts, " → ")
}

// maxNameLen bounds one element of a Summary.
const maxNameLen = 64

// safeName renders one chain element for display. A short plain name (ASCII
// letters, digits and ._+-, at most maxNameLen bytes) is kept verbatim;
// anything else, including spaces, "→", parentheses, "…", quotes and
// non-ASCII, is Go-quoted (and cut to maxNameLen runes first) so it can't be
// mistaken for structure of the summary. An empty name renders as `""`.
func safeName(name string) string {
	if plainName(name) {
		return name
	}
	if r := []rune(name); len(r) > maxNameLen {
		name = string(r[:maxNameLen-1]) + "…"
	}
	return strconv.Quote(name)
}

func plainName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '_', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}
