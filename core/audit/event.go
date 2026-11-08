// Package audit formats one line per request decision (spec 4.6) and hands
// it to a Sink: the macOS unified log in production (subsystem dev.nazar,
// category audit, default level, public fields), memory or a file in tests.
//
// Every caller-derived value (argv, cwd, process names, bundle IDs, signing
// identities, destinations, operations) is quoted so that it can never forge
// a field, a chain element, add a line or smuggle a terminal control
// sequence into the log, and clipped so that a line never exceeds MaxLine
// and an entry can never be made unparseable by padding. A line is printable
// ASCII apart from the ellipsis in the markers Format adds itself: every
// value, and the caller-chosen names inside the receiver and chain values,
// is bare only when it is a plain ASCII word and otherwise quoted with every
// non-ASCII rune escaped, so a look-alike or blank-looking rune cannot make
// one app, program, process, directory or host read as another, in the raw
// line or once unquoted. When a chain is too long, what is dropped is
// decided by a fixed order that a caller cannot steer. Command lines are
// reduced to an allowlist of plain words (RedactArgs) or to the program name
// and argument count; a full command line is never logged. ParseLine inverts
// Format and ParseChain inverts the chain field for `nazar log`.
package audit

import (
	"time"
)

const (
	// Subsystem is the unified-log subsystem nazar writes audit entries to.
	Subsystem = "dev.nazar"
	// Category is the unified-log category of audit entries.
	Category = "audit"
)

// Decision is what happened to a request.
type Decision string

const (
	Allowed  Decision = "allowed"  // covered by a remembered approval (or gate none)
	Approved Decision = "approved" // the user passed the gate just now
	Denied   Decision = "denied"
	Timeout  Decision = "timeout"
	Blocked  Decision = "blocked"
	Error    Decision = "error"
)

// Proc is one chain element as logged: name(pid[, team:id][, deleted]).
type Proc struct {
	Name     string
	PID      int
	Identity string // "Q6L2SF6YDW:com.anthropic.claude-code"; "" when unsigned
	// Deleted marks a process whose executable file is gone (Claude Code
	// after its auto-update). It is logged as a bare "deleted" after the
	// pid and identity, outside the name: the name is caller-chosen text,
	// so a marker inside it could be forged by a binary literally named
	// "claude-code (file deleted)".
	Deleted bool
}

// Event is one audit entry. Never put secret values, signatures or
// payloads in it.
type Event struct {
	Time        time.Time
	Decision    Decision
	Reason      string
	Target      string   // "ssh:github", "secret:GH_TOKEN", "config", "trust:/opt/homebrew/bin/kubectl"
	Delivery    string   // a secret's method: "helper", "stdout" (secrets design 8); "" for ssh
	EnvPassed   []string // the envAllow names the caller supplied (late-env), never values
	Destination string   // ssh: "github.com"
	Operation   string   // ssh: "sign git commit"
	Rule        string   // "1", "key-gate" (the key's own gate), "fallback" (defaults.fallback)
	Scope       string
	Gate        string
	App         string // bundle id
	Session     string
	Chain       []Proc   // outermost first
	Receiver    []string // argv of the receiver (the socket peer)
	// Command is the argv of the command the user ran (caller.Chain.Command,
	// spec 4.4) when it is not the receiver; it is rendered like Receiver.
	Command []string
	Cwd     string // the command's folder
	// Matched is the process that satisfied the rule's apps: matcher when
	// the chain field does not show it (it sits above the app); zero for
	// none. It is rendered as one chain element.
	Matched Proc
}
