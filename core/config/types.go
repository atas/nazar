// Package config parses and validates ~/.nazar/config/config.yaml (spec 4.2).
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/atas/nazar/core/layout"
)

const (
	APIVersion = "nazar/v1"
	KindConfig = "Config"
	// MaxFileSize bounds what Parse accepts.
	MaxFileSize = 1 << 20
	// DefaultSocket is ssh_agent.socket when unset (before ~ expansion).
	DefaultSocket  = layout.AgentSocketTilde
	DefaultTimeout = 60 * time.Second
)

type Gate string

const (
	GateLogin  Gate = "login"
	GateDialog Gate = "dialog"
	GateNone   Gate = "none"
	GateBlock  Gate = "block"
)

// Prompts reports whether the gate asks the user (login or dialog).
func (g Gate) Prompts() bool { return g == GateLogin || g == GateDialog }

type Scope string

const (
	ScopeUse     Scope = "use"
	ScopeSession Scope = "session"
	ScopeApp     Scope = "app"
)

type ArgsMode string

const (
	ArgsRedacted ArgsMode = "redacted"
	ArgsNone     ArgsMode = "none"
)

// Policy is what a rule, a key or defaults.fallback grants. For gates none
// and block, Parse normalises Scope to "use" and Expire to 0.
type Policy struct {
	Scope  Scope
	Gate   Gate
	Expire time.Duration // 0 = no expiry
}

func (p Policy) String() string {
	s := "gate=" + string(p.Gate)
	if p.Gate.Prompts() {
		s += " scope=" + string(p.Scope)
		if p.Expire > 0 {
			s += " expire=" + p.Expire.String()
		}
	}
	return s
}

type MatcherKind string

const (
	MatchSigned MatcherKind = "signed"
	MatchApp    MatcherKind = "app"
	// MatchPath names one executable file by its path, with no pin (spec
	// 4.2): resolved at every match, so a Homebrew opt/ symlink follows an
	// upgrade. It is only as safe as who can write that file.
	MatchPath    MatcherKind = "path"
	MatchCommand MatcherKind = "command"
	MatchAny     MatcherKind = "any"
	MatchUnknown MatcherKind = "unknown"
)

// Matcher is one resolved app matcher. Name is the apps: entry it came from
// ("" when written inline, "any"/"unknown" for the built-ins).
type Matcher struct {
	Kind    MatcherKind
	Name    string
	Team    string   // signed (required), app (optional); "apple" = Apple-signed
	ID      string   // signed: signing identifier (optional); app: bundle id
	Path    string   // path: a clean absolute path, as written
	Command []string // command
}

// Canonical is the matcher's meaning, independent of its name. Two matchers
// with equal Canonical strings match exactly the same processes. Every field
// is quoted (%q), so a field containing a separator can never collide with a
// different matcher: Canonical decides approval identity and rule coverage.
func (m Matcher) Canonical() string {
	switch m.Kind {
	case MatchSigned:
		return fmt.Sprintf("signed:%q:%q", m.Team, m.ID)
	case MatchApp:
		return fmt.Sprintf("app:%q:%q", m.ID, m.Team)
	case MatchPath:
		return fmt.Sprintf("path:%q", m.Path)
	case MatchCommand:
		return "command:" + strings.Join(quoteAll(m.Command), ",")
	}
	return string(m.Kind)
}

// Label is how the matcher is shown to people: its name, or its Canonical form.
func (m Matcher) Label() string {
	if m.Name != "" {
		return m.Name
	}
	return m.Canonical()
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}

// Rule is one entry of a key's rules list. Index is 1-based.
type Rule struct {
	Index  int
	Apps   []Matcher
	To     []Matcher
	Policy Policy
}

// Canonical describes the rule's condition and policy, independent of names
// and position. The order of matchers inside apps: and to: does not change it.
func (r Rule) Canonical() string {
	return "apps=" + atoms(r.Apps) + " to=" + atoms(r.To) + " " + r.Policy.String()
}

// ID identifies the rule for approval caching: position plus a hash of its
// meaning, so an edited or moved rule never inherits the old rule's approvals.
func (r Rule) ID() string {
	sum := sha256.Sum256([]byte(r.Canonical()))
	return fmt.Sprintf("%d:%s", r.Index, hex.EncodeToString(sum[:4]))
}

// atoms joins the matchers' Canonical forms, sorted. Each element is quoted
// throughout, so "," and "]" inside a field can't fake a boundary.
func atoms(ms []Matcher) string {
	s := make([]string, len(ms))
	for i, m := range ms {
		s[i] = m.Canonical()
	}
	sort.Strings(s)
	return "[" + strings.Join(s, ",") + "]"
}

// Key is one ssh_agent.keys entry. Own is the key's own scope/gate/expire,
// nil when the key sets no gate.
type Key struct {
	Name  string
	Rules []Rule
	Own   *Policy
}

type SSHAgent struct {
	Socket string // absolute, ~ expanded
	Keys   map[string]*Key
}

type Defaults struct {
	Timeout  time.Duration
	Fallback Policy
	// TrustedPath is where nazar run resolves a receiver's bare argv[0]
	// and what the receiver gets as PATH (secrets design 6.3.3, 6.3.4):
	// clean absolute directories, in order; DefaultTrustedPath when unset.
	TrustedPath []string
}

// DefaultTrustedPath is defaults.trustedPath when the config sets none. It
// returns a fresh slice.
func DefaultTrustedPath() []string {
	return []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin", "/usr/local/bin"}
}

type Audit struct {
	Args ArgsMode
}

// Config is a parsed, validated config file.
type Config struct {
	APIVersion string
	Kind       string
	Defaults   Defaults
	Audit      Audit
	Apps       map[string]Matcher
	SSHAgent   SSHAgent
	Secrets    map[string]*Secret
	K8s        map[string]*K8sContext
	AWS        map[string]*AWSEntry
	// Unimplemented lists top-level sections that were parsed but are not
	// built yet (none since M12 built k8s; configstage keeps its guard
	// for a section a later version adds before building it).
	Unimplemented []string
	// Raw is nazar's own copy of the file content; Hash its SHA-256 in hex.
	Raw  []byte
	Hash string
}

// KeyNames returns the configured key names, sorted.
func (c *Config) KeyNames() []string {
	names := make([]string, 0, len(c.SSHAgent.Keys))
	for n := range c.SSHAgent.Keys {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Fallback is the policy for callers no rule of key matches: the key's own
// policy if set, otherwise defaults.fallback. Unknown keys get defaults.fallback.
func (c *Config) Fallback(key string) Policy {
	if k, ok := c.SSHAgent.Keys[key]; ok && k.Own != nil {
		return *k.Own
	}
	return c.Defaults.Fallback
}

// Policies lists every policy that can apply to key: all its rules plus
// its fallback (its own policy or defaults.fallback).
func (c *Config) Policies(key string) []Policy {
	var ps []Policy
	if k, ok := c.SSHAgent.Keys[key]; ok {
		for _, r := range k.Rules {
			ps = append(ps, r.Policy)
		}
	}
	return append(ps, c.Fallback(key))
}

// Gates lists every gate that can apply to key: all its rules plus its fallback.
func (c *Config) Gates(key string) []Gate {
	var gs []Gate
	if k, ok := c.SSHAgent.Keys[key]; ok {
		for _, r := range k.Rules {
			gs = append(gs, r.Policy.Gate)
		}
	}
	return append(gs, c.Fallback(key).Gate)
}

// PresenceFits reports whether a user-presence key can serve every policy
// that can apply to key: each is block, or login with scope: use (spec 4.5
// as amended after spike S1: the chip honours one approval for minutes, not
// for a session or an app's lifetime, so a login gate with scope session or
// app would fail once that lapses).
func (c *Config) PresenceFits(key string) bool {
	for _, p := range c.Policies(key) {
		if !ChipPresenceFits(p) {
			return false
		}
	}
	return true
}

// NeedsUserPresence reports whether key is created with Secure Enclave
// user presence: every policy that can apply to it fits (PresenceFits) and
// at least one is login with scope: use. An entry only block reaches is a
// key nobody may use yet, so nothing decides its protection and the rules
// added later do (Milestone 7): with presence, the first dialog or
// session rule would need the key re-created.
func (c *Config) NeedsUserPresence(key string) bool {
	if !c.PresenceFits(key) {
		return false
	}
	for _, p := range c.Policies(key) {
		if p.Gate == GateLogin && p.Scope == ScopeUse {
			return true
		}
	}
	return false
}

// ChipPresenceFits reports whether a policy works with a user-presence key:
// block (never signs) or login with scope: use (a fresh approval per use).
func ChipPresenceFits(p Policy) bool {
	return p.Gate == GateBlock || (p.Gate == GateLogin && p.Scope == ScopeUse)
}

// Delivery is how a secret reaches its receiver (secrets design 6).
type Delivery string

const (
	DeliverHelper  Delivery = "helper"
	DeliverFile    Delivery = "file"
	DeliverLateEnv Delivery = "late-env"
	DeliverEnv     Delivery = "env"
	DeliverStdout  Delivery = "stdout"
)

// DefaultDeliver is deliver: for an entry without one and for a secret
// without an entry. It never grows: a method a later version builds
// is used only where deliver: lists it, so an approved entry never comes to
// mean more by itself. It returns a fresh slice.
func DefaultDeliver() []Delivery { return []Delivery{DeliverHelper, DeliverStdout} }

// Built reports whether this version can deliver by d. Parse refuses the
// others by name and policy blocks them.
func (d Delivery) Built() bool {
	return d == DeliverHelper || d == DeliverStdout || d == DeliverLateEnv
}

// Secret is one secrets entry (secrets design 4). Rules and Own mean what
// they mean for a Key; Deliver is never empty.
type Secret struct {
	Name     string
	Deliver  []Delivery
	Rules    []Rule
	Own      *Policy
	Helper   *Helper // nil without helper:
	EnvAllow []string
}

// Helper is a secret's helper: field (secrets design 4, 6.1): which tool's
// credential protocol it answers, and for whom. Only git is built.
type Helper struct {
	Git *GitHelper
}

// GitHelper answers git's credential protocol for one HTTPS host (only
// https). Host is lower case, with an optional :port; Username, when
// set, is what git is told.
type GitHelper struct {
	Host     string
	Username string
}

// asciiLower lower-cases the ASCII letters of s; ok is false when s has a
// byte outside ASCII.
func asciiLower(s string) (string, bool) {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 0x80:
			return "", false
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b), true
}

// String is the URL the mapping answers for.
func (g *GitHelper) String() string { return "https://" + g.Host }

// GitSecret returns the secret whose helper.git names host (compared in
// ASCII lower case), if one does. Parse allows at most one per host. A
// host that is not ASCII matches nothing: Unicode case folding would turn
// a KELVIN SIGN into k and match a host the config does not name.
func (c *Config) GitSecret(host string) (string, bool) {
	host, ok := asciiLower(host)
	if !ok {
		return "", false
	}
	for _, n := range c.SecretNames() {
		if h := c.Secrets[n].Helper; h != nil && h.Git != nil && h.Git.Host == host {
			return n, true
		}
	}
	return "", false
}

// SecretNames returns the configured secret names, sorted.
func (c *Config) SecretNames() []string {
	names := make([]string, 0, len(c.Secrets))
	for n := range c.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SecretFallback is the policy for callers no rule of secret name matches:
// its own policy if set, otherwise defaults.fallback (also for a secret
// without an entry).
func (c *Config) SecretFallback(name string) Policy {
	if s, ok := c.Secrets[name]; ok && s.Own != nil {
		return *s.Own
	}
	return c.Defaults.Fallback
}

// Deliver is the methods secret name may be delivered by: its entry's
// deliver:, or DefaultDeliver for a secret without an entry.
func (c *Config) Deliver(name string) []Delivery {
	if s, ok := c.Secrets[name]; ok {
		return s.Deliver
	}
	return DefaultDeliver()
}

// keyNameRE is ASCII only: key names become file names (keys/<name>.pub) and
// Keychain item names, so look-alike Unicode letters are refused too.
var keyNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidKeyName reports whether name may be used as a key name. Key names
// become file names (keys/<name>.pub), so this excludes "/", "..", etc.
func ValidKeyName(name string) bool {
	return keyNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// secretNameRE: one or more "/"-separated parts, each led by a letter, digit
// or "_" (secrets design 3.3: k8s/<context> is a name). ASCII only; Go's $
// matches only at the end of the text, so a trailing newline is refused.
var secretNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`)

// ValidSecretName reports whether name may name a secret: secretNameRE, at
// most 64 bytes, no "..". The name becomes the Vault item secret/<name> and,
// with "/" as %2F, a FIFO path that no other valid name maps to.
func ValidSecretName(name string) bool {
	return len(name) <= 64 && secretNameRE.MatchString(name) && !strings.Contains(name, "..")
}

var appNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Env is what Parse needs from the environment.
type Env struct {
	Home string
}

// Default returns the built-in config used when no approved config exists:
// no keys, defaults.fallback gate block.
func Default(env Env) *Config {
	c, probs := Parse([]byte("apiVersion: nazar/v1\nkind: Config\n"), env)
	if probs.HasErrors() {
		panic("config: built-in default does not parse: " + probs.Error())
	}
	c.Raw, c.Hash = nil, ""
	return c
}

// interpreterRE is the typed names of the interpreters nazar run has a
// loader for (secrets design 6.3 step 3): what a command: matcher's text
// shows. The run resolver decides the real kind from the realpath.
var interpreterRE = regexp.MustCompile(`(?i)^(node|nodejs|python|python3|python3\.[0-9]{1,3}t?)$`)

// Interpreter reports whether name, a file's base name, is a Node or
// Python interpreter, ignoring case (APFS does: NODE is node) and with the
// free-threaded python3.Nt builds.
func Interpreter(name string) bool { return interpreterRE.MatchString(name) }

// FileElement is one element of a command line that names a file (secrets
// design 6.3.7): Index is its position in argv, Path the file, which for
// --require=./x.cjs is the part after "=".
type FileElement struct {
	Index int
	Path  string
}

// fileFlags take a file to load as their value, separately or after "=".
var fileFlags = []string{"-r", "--require", "--import", "--env-file", "--env-file-if-exists", "--loader",
	"--experimental-loader", "--openssl-config", "--experimental-config-file", "--snapshot-blob"}

// codeFlags end an interpreter's options without a script: the next
// element is code or a module name, opaque to nazar.
var codeFlags = []string{"-m", "-c", "-e", "-p", "--eval", "--print"}

// valueFlags take a separate value that is not a file (python -W, -X).
var valueFlags = []string{"-W", "-X"}

var scriptExts = []string{".js", ".mjs", ".cjs", ".ts", ".py", ".pyw", ".sh", ".rb", ".pl"}

// fileShaped reports whether a reads as a path whatever its position: an
// absolute path, one starting ./ or ../ (or . and ..), or a name ending in
// a script extension.
func fileShaped(a string) bool {
	if strings.HasPrefix(a, "/") || a == "." || a == ".." || strings.HasPrefix(a, "./") || strings.HasPrefix(a, "../") {
		return true
	}
	if strings.HasPrefix(a, "-") {
		return false
	}
	for _, e := range scriptExts {
		if strings.HasSuffix(a, e) {
			return true
		}
	}
	return false
}

// FileElements returns the file elements of argv[1:] (secrets design
// 6.3.7): file-shaped elements, the values of the file flags, and, for an
// interpreter, its script: the first element after its own options unless
// one of them takes code or a module. The reading is conservative: a flag
// nazar does not know is taken to stand alone, so a value it takes may be
// read as the script and refused, never a script as a value.
func FileElements(argv []string, interpreter bool) []FileElement {
	var out []FileElement
	options := interpreter
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case slices.Contains(fileFlags, a):
			if i+1 < len(argv) {
				i++
				out = append(out, FileElement{Index: i, Path: argv[i]})
			}
			continue
		case strings.HasPrefix(a, "-") && strings.Contains(a, "="):
			// A file flag's value, and the path value of any other
			// --flag=value (6.3.7 (d)): pinned when absolute, refused when
			// relative, rather than left unchecked.
			k, v, _ := strings.Cut(a, "=")
			if slices.Contains(fileFlags, k) || strings.HasPrefix(k, "--") && fileShaped(v) {
				out = append(out, FileElement{Index: i, Path: v})
				continue
			}
		}
		if options {
			switch {
			case a == "--":
				options = false
				if i+1 < len(argv) {
					i++
					out = append(out, FileElement{Index: i, Path: argv[i]})
				}
			case slices.Contains(codeFlags, a):
				options = false
				i++ // the code or module is opaque
			case slices.Contains(valueFlags, a):
				i++
				// -X pycache_prefix=/path names a directory to load from.
				if i < len(argv) {
					if _, v, ok := strings.Cut(argv[i], "="); ok && fileShaped(v) {
						out = append(out, FileElement{Index: i, Path: v})
					}
				}
			case strings.HasPrefix(a, "-"):
			default:
				options = false
				out = append(out, FileElement{Index: i, Path: a})
			}
			continue
		}
		if fileShaped(a) {
			out = append(out, FileElement{Index: i, Path: a})
		}
	}
	return out
}

// interactiveFlags make node read the caller's standard input as a REPL.
var interactiveFlags = []string{"-i", "--interactive"}

// InterpreterStdin says why an interpreter's command line would run code
// from its standard input, which is the caller's (6.3.8): no script and no
// code or module flag, "-" as the script, or -i (node, or inside a python
// flag cluster such as -ui). "" when it does not. argv[0] is the
// interpreter; the reading of options is FileElements'.
func InterpreterStdin(argv []string) string {
	name := filepath.Base(argv[0])
	stdin := name + " with no script reads its program from standard input, which is the caller's; name the script"
	interactive := "-i makes " + name + " read the caller's standard input; remove it"
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-":
			return stdin
		case a == "--":
			if i+1 >= len(argv) || argv[i+1] == "-" {
				return stdin
			}
			return ""
		case slices.Contains(interactiveFlags, a):
			return interactive
		case slices.Contains(codeFlags, a):
			if a == "-m" || a == "-c" {
				return "" // python: the rest are the code's arguments
			}
			// node: options may still follow -e and -p and their code.
			for j := i + 2; j < len(argv) && strings.HasPrefix(argv[j], "-"); j++ {
				if slices.Contains(interactiveFlags, argv[j]) {
					return interactive
				}
			}
			return ""
		case slices.Contains(valueFlags, a), slices.Contains(fileFlags, a):
			i++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			for j, c := range a[1:] {
				if c == 'i' {
					return interactive
				}
				if c == 'c' || c == 'm' {
					return ""
				}
				if c == 'W' || c == 'X' {
					if j == len(a)-2 {
						i++
					}
					break
				}
			}
		default:
			return "" // the script
		}
	}
	return stdin
}
