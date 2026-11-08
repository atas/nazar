// Package control is the protocol between the `nazar` CLI and Nazar.app on
// ~/.nazar/run/control.sock (spec 6): one JSON request per connection, answered
// by one or more JSON objects, one per line, each carrying apiVersion and
// kind. A Problem, when there is one, is the last object of a reply and maps
// to the CLI's exit code. The same objects are what `nazar --json` prints.
package control

import (
	"errors"
	"fmt"
	"time"
)

// APIVersion is carried by every object on the wire and in --json output.
const APIVersion = "nazar/v1"

// Kinds.
const (
	KindRequest      = "Request"
	KindSSHKey       = "SSHKey"
	KindSSHKeyList   = "SSHKeyList"
	KindApproval     = "Approval"
	KindApprovalList = "ApprovalList"
	KindStatus       = "Status"
	KindConfigCheck  = "ConfigCheck"
	KindConfigDiff   = "ConfigDiff"
	KindAppPin       = "AppPin"
	KindRevokeResult = "RevokeResult"
	KindAuditEvent   = "AuditEvent"
	KindAuditSummary = "AuditSummary"
	KindProblem      = "Problem"
	KindSSHKeyRules  = "SSHKeyRules"
	KindConfigEdit   = "ConfigEdit"
	KindAppList      = "AppList"
	KindUI           = "UI"
	KindSecret       = "Secret"
	KindSecretList   = "SecretList"
	// KindSecretValue is wire only: the reply to a value command, never
	// printed by any --json command (secrets design 7.2).
	KindSecretValue = "SecretValue"
	// KindRunPlan is wire only: secret.run's go-ahead (secrets design 7.2).
	KindRunPlan = "RunPlan"
)

// Commands.
const (
	CmdSSHKeyCreate = "ssh-key.create" // args: name, [alwaysAsk=true], [onlyWhenUnlocked=true] (loosen; the entry is the agent's decision)
	CmdSSHKeyList   = "ssh-key.list"   //                           (read)
	CmdSSHKeyPubkey = "ssh-key.pubkey" // args: name                (read)
	CmdSSHKeyDelete = "ssh-key.delete" // args: name                (loosen)
	CmdStatus       = "status"         // follow                    (read)
	CmdRevoke       = "revoke"         // args: all|key|session|app (tighten)
	CmdConfigCheck  = "config.check"   //                           (read)
	CmdConfigApply  = "config.apply"   // args: [hash]              (loosen)
	CmdTrustApp     = "trust.app"      // args: app (bundle id)     (loosen)
	CmdSSHKeyRules  = "ssh-key.rules"  // args: name                (read)
	CmdAppsList     = "apps.list"      //                           (read)
	// CmdConfigEdit edits config.yaml (args: op, key (an SSH key name),
	// secret (a secret name), context (a k8s context name) or aws (an aws
	// entry name), exactly one,
	// and the op's fields, below; key.set takes key only; a context's edit
	// takes no to) and observes it at once: a tightening
	// applies; a loosening is staged only with allowLoosen (the CLI then
	// sends the CmdConfigApply bound to it) and otherwise refused with
	// LoosensRefusal, nothing written; config.edit itself never prompts.
	CmdConfigEdit = "config.edit"

	// Secrets (secrets design 7.3).
	CmdSecretAdd    = "secret.add"    // args: name, valueBase64, [onlyWhenUnlocked=true] (loosen; the entry is the agent's decision, as for ssh-key.create)
	CmdSecretList   = "secret.list"   //                          (read)
	CmdSecretDelete = "secret.delete" // args: name               (loosen)
	CmdSecretGet    = "secret.get"    // args: name               (gated; value; genuine CLI only)
	CmdSecretHelper = "secret.helper" // args: protocol, host, [username]: git's credential protocol (gated; value; genuine CLI only)
	CmdSecretRun    = "secret.run"    // args: name, argv (JSON list), callerEnv (JSON list of NAME=VALUE): late-env (gated; genuine CLI only; up to MaxLargeRequestSize)
)

// ValueCommand reports whether cmd returns a secret's value or a k8s
// credential, or (secret.run) relies on the CLI to exec exactly
// what the agent planned. nazar-agent answers such a command only when the
// connection's peer is the genuine nazar CLI (Server.VerifyCLI,
// PeerIsNazarCLI): same user is not enough.
func ValueCommand(cmd string) bool {
	return cmd == CmdSecretGet || cmd == CmdSecretHelper || cmd == CmdSecretRun || cmd == CmdK8sCredential || cmd == CmdAWSCredential
}

// CmdConfigApply's hash arg, when present, binds the approval to one staged
// change: the hash of the change the caller showed or made (ConfigDiff.Hash,
// as ConfigEdit.Staged and ConfigCheck.Staged carry it). The CLI sends it
// on its own, from the agent's reply (an edit made with --allow-loosen-access
// approves the change it just staged; `nazar config apply` the change
// `config check` showed); no person types it. When config.yaml no longer
// holds that change, nothing is asked and the reply is an error (exit 1,
// never staged/4), so a rewrite landing between an edit and its apply can't
// ride on the user's approval. When it is already the config in force, the
// reply says nothing is staged.

// CmdConfigEdit's allowLoosen arg ("true": the CLI's --allow-loosen-access)
// lets an edit that loosens access be written and staged. Without it such an
// edit is refused with LoosensRefusal (code usage, exit 2) and nothing is
// written; the Problem's Details are the change and what it loosens, as the
// login prompt would show them.
const LoosensRefusal = "this change loosens access; nothing was changed"

// Operations of CmdConfigEdit (Milestone 5) and the args each takes. apps
// and to are JSON arrays of matcher references (config.ParseMatcherRef);
// for rule.set and key.set an arg that is present changes its field, and
// present but empty removes it (to, expire). ifHash, when present, must be
// the content hash of config.yaml (SSHKeyRules.ConfigHash) or the edit is
// refused: the file changed since it was read. "key" below is key, secret
// or context, except for key.set; a context's edit takes no to.
const (
	EditRuleAdd    = "rule.add"    // key, apps, [to], [scope], gate, [expire], [at]
	EditRuleSet    = "rule.set"    // key, index, any of apps, to, scope, gate, expire
	EditRuleRemove = "rule.remove" // key, index
	EditKeySet     = "key.set"     // key, any of scope, gate, expire
)

// Exit codes (spec 6).
const (
	ExitOK          = 0
	ExitError       = 1
	ExitUsage       = 2
	ExitRefused     = 3 // the gate wasn't passed: denied, timed out or blocked
	ExitStaged      = 4 // a config change is staged and waiting for approval
	ExitUnavailable = 5 // nazar-agent isn't running
)

// Problem codes, one per non-zero exit code.
const (
	CodeError       = "error"
	CodeUsage       = "usage"
	CodeRefused     = "refused"
	CodeStaged      = "staged"
	CodeUnavailable = "unavailable"
)

// TypeMeta is the versioned header every object carries.
type TypeMeta struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// Meta returns the TypeMeta for kind.
func Meta(kind string) TypeMeta { return TypeMeta{APIVersion: APIVersion, Kind: kind} }

// Request is the one object a client sends per connection.
type Request struct {
	TypeMeta
	Command string            `json:"command"`
	Args    map[string]string `json:"args,omitempty"`
	Follow  bool              `json:"follow,omitempty"`
}

// NewRequest builds a request.
func NewRequest(cmd string, args map[string]string) Request {
	return Request{TypeMeta: Meta(KindRequest), Command: cmd, Args: args}
}

// Problem is an error object; it is always the last object of a reply.
// Fix, when set, is the command line that makes the refused change, filled
// by the CLI and never by nazar-agent: for LoosensRefusal, the caller's own
// command with --allow-loosen-access.
type Problem struct {
	TypeMeta
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
	Fix     string   `json:"fix,omitempty"`
}

// NewProblem builds a Problem with a formatted message.
func NewProblem(code, format string, args ...any) *Problem {
	return &Problem{TypeMeta: Meta(KindProblem), Code: code, Message: fmt.Sprintf(format, args...)}
}

func (p *Problem) Error() string { return p.Message }

// ExitCode maps the problem code to the CLI exit code. Unknown codes are
// ExitError; a nil Problem (see AsProblem) is ExitOK.
func (p *Problem) ExitCode() int {
	if p == nil {
		return ExitOK
	}
	switch p.Code {
	case CodeUsage:
		return ExitUsage
	case CodeRefused:
		return ExitRefused
	case CodeStaged:
		return ExitStaged
	case CodeUnavailable:
		return ExitUnavailable
	}
	return ExitError
}

// AsProblem returns err as a *Problem: the Problem itself when err is or
// wraps one, a Problem with code "error" for any other error, and nil for a
// nil error (so AsProblem(err).ExitCode() is the exit code for any outcome).
func AsProblem(err error) *Problem {
	if err == nil {
		return nil
	}
	var p *Problem
	if errors.As(err, &p) {
		return p
	}
	return NewProblem(CodeError, "%s", err.Error())
}

type SSHKey struct {
	TypeMeta
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	Broken      bool   `json:"broken"`
	// UserPresence: the key was created with Secure Enclave user presence
	// (`ssh-key create --always-ask`, or an entry that called for it), so
	// the chip asks for the user's authentication on every signature. It
	// is read from the key's vault record, written at creation with the
	// policy the key was created with, never from config.yaml.
	UserPresence bool `json:"userPresence"`
	// WhileLocked: the chip lets the key sign while the Mac is locked too,
	// once the user has logged in since it started. False for a key made
	// with --only-when-unlocked or --always-ask, and for every key made
	// before this field existed (its vault record names no access). Fixed
	// for the key's life; read from the vault record, never config.yaml.
	WhileLocked bool      `json:"whileLocked"`
	Configured  bool      `json:"configured"`
	Rules       []string  `json:"rules"`
	Created     time.Time `json:"created"`
	// Usable is false when the key can't sign at all (Broken): its vault
	// item can't be read or decoded. UnusableReason says why and Remedy
	// what to run.
	Usable         bool   `json:"usable"`
	UnusableReason string `json:"unusableReason,omitempty"`
	Remedy         string `json:"remedy,omitempty"`
	// Warnings are the config warnings about this key: its Secure Enclave
	// protection against its gates, rules that can never match (Milestone 5).
	Warnings []string `json:"warnings"`
	// LastUsed is the last request this key signed for since Nazar.app
	// started (SSHKeyList.Since); nil when none.
	LastUsed *KeyUse `json:"lastUsed,omitempty"`
	// Policy is the key's rules as config.yaml has them now.
	Policy *SSHKeyRules `json:"policy,omitempty"`
}

// KeyUse is one use of a key: when, the decision (allowed or approved), and
// who (the app's bundle id, the chain as the audit log writes it: Chain is
// audit.FormatChain of the event's chain, the chain= value `nazar log`
// shows, which audit.ParseChain reads back).
type KeyUse struct {
	Time     time.Time `json:"time"`
	Decision string    `json:"decision"`
	App      string    `json:"app,omitempty"`
	Chain    string    `json:"chain,omitempty"`
}

type SSHKeyList struct {
	TypeMeta
	Items []SSHKey `json:"items"`
	// Since is when Nazar.app started: LastUsed covers the uses since then
	// (the audit log, `nazar log`, has the rest).
	Since time.Time `json:"since"`
}

// MatcherInfo is one app matcher of a rule or of the top-level apps:.
// Ref is how to write it for --apps/--to: the name, or the app:/signed:/
// path: form of an inline matcher ("" for command:, which rules can't use).
type MatcherInfo struct {
	Name    string   `json:"name,omitempty"`
	Kind    string   `json:"kind"`
	Team    string   `json:"team,omitempty"`
	ID      string   `json:"id,omitempty"`
	Path    string   `json:"path,omitempty"`
	Command []string `json:"command,omitempty"`
	Ref     string   `json:"ref"`
}

// PolicyInfo is a scope, gate and expire as config.yaml says them.
type PolicyInfo struct {
	Scope  string `json:"scope"`
	Gate   string `json:"gate"`
	Expire string `json:"expire,omitempty"`
}

// RuleInfo is one rule of a key, numbered from 1 as `rule set`/`remove` take it.
type RuleInfo struct {
	Index  int           `json:"index"`
	Apps   []MatcherInfo `json:"apps"`
	To     []MatcherInfo `json:"to"`
	Policy PolicyInfo    `json:"policy"`
}

// SSHKeyRules is a key's rules as config.yaml has them: in force, or a
// staged change (Staged) that applies only once approved. ConfigHash is
// the file they come from; an edit given it as ifHash is refused if the
// file changed since. Fallback is what callers no rule matches get: the
// key's own gate (FallbackSource "key-gate") or defaults.fallback.
type SSHKeyRules struct {
	TypeMeta
	Name           string      `json:"name"`
	Configured     bool        `json:"configured"`
	Staged         bool        `json:"staged"`
	ConfigHash     string      `json:"configHash"`
	Rules          []RuleInfo  `json:"rules"`
	Own            *PolicyInfo `json:"own,omitempty"`
	Fallback       PolicyInfo  `json:"fallback"`
	FallbackSource string      `json:"fallbackSource"`
}

// ConfigEdit is the reply to config.edit: whether the file changed, and
// the state of the file as it is after the edit: in force (Applied: a
// tightening, or an edit that changed nothing in a file that is in force)
// or waiting for approval (Staged: the CLI sends the config.apply bound to
// Staged.Hash at once, and prints `nazar config apply`, exit 4, only when
// that prompt could not be shown). An edit that changes nothing in a file
// holding a staged loosening is Staged, not Applied: nothing in that file
// is in force yet.
type ConfigEdit struct {
	TypeMeta
	Op       string          `json:"op"`
	Key      string          `json:"key"`
	Secret   string          `json:"secret,omitempty"`  // a secret's rule edit; Key is ""
	Context  string          `json:"context,omitempty"` // a k8s context's rule edit; Key is ""
	AWS      string          `json:"aws,omitempty"`     // an aws entry's rule edit; Key is ""
	Path     string          `json:"path"`
	Hash     string          `json:"hash"`
	Changed  bool            `json:"changed"`
	Applied  bool            `json:"applied"`
	Staged   *ConfigDiff     `json:"staged,omitempty"`
	Problems []ConfigProblem `json:"problems"`
}

// AppEntry is one entry of the top-level apps: (spec 6.1, Apps tab): its
// matcher, the team pinned for an app: matcher, what keeps it from
// matching and the command that fixes it, and the rules that use it
// ("github rule 1").
type AppEntry struct {
	Name       string      `json:"name"`
	Matcher    MatcherInfo `json:"matcher"`
	PinnedTeam string      `json:"pinnedTeam,omitempty"`
	Problem    string      `json:"problem,omitempty"`
	Fix        string      `json:"fix,omitempty"`
	UsedBy     []string    `json:"usedBy"`
}

type AppList struct {
	TypeMeta
	Staged     bool       `json:"staged"`
	ConfigHash string     `json:"configHash"`
	Items      []AppEntry `json:"items"`
}

type Approval struct {
	TypeMeta
	Event    string     `json:"event,omitempty"` // "added" / "removed" in --follow streams
	Reason   string     `json:"reason,omitempty"`
	Target   string     `json:"target"`
	Rule     string     `json:"rule"`
	Scope    string     `json:"scope"`
	ScopeID  string     `json:"scopeId"`
	Receiver string     `json:"receiver,omitempty"`
	Op       string     `json:"op"`     // what the approval covers, as the cache keys it (spec 4.3): "login:SHA256:…", "login:unbound", "sign:git"
	Covers   string     `json:"covers"` // the same as shown: "github.com", "git commits and tags"
	Chain    string     `json:"chain"`
	App      string     `json:"app,omitempty"`
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires,omitempty"`
}

type ApprovalList struct {
	TypeMeta
	Items []Approval `json:"items"`
}

type ConfigProblem struct {
	Severity string `json:"severity"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
	Message  string `json:"message"`
}

type ConfigDiff struct {
	TypeMeta
	Hash      string   `json:"hash"`
	Loosens   bool     `json:"loosens"`
	Applied   bool     `json:"applied"`
	Changes   []string `json:"changes"`
	Loosening []string `json:"loosening,omitempty"`
}

type ConfigCheck struct {
	TypeMeta
	Path       string          `json:"path"`
	Valid      bool            `json:"valid"`
	Problems   []ConfigProblem `json:"problems"`
	ActiveHash string          `json:"activeHash,omitempty"`
	Staged     *ConfigDiff     `json:"staged,omitempty"`
}

// AppPin is the reply to `nazar trust --app <bundle id>` (spec 4.2, 4.8):
// the team now pinned for BundleID, read from the app installed at Path.
// OldTeam is the pin it replaced ("" for a first pin); Changed is false when
// the installed team was already pinned and nothing was asked or written.
type AppPin struct {
	TypeMeta
	BundleID string `json:"bundleId"`
	Team     string `json:"team"`
	OldTeam  string `json:"oldTeam,omitempty"`
	Path     string `json:"path"`
	Changed  bool   `json:"changed"`
}

type RevokeResult struct {
	TypeMeta
	Revoked int `json:"revoked"`
}

// VaultProblem is a vault item Nazar.app could not read at start or since
// (since Milestone 5): what it means for nazar and the command that fixes
// it. Nazar.app keeps running without it, failing closed.
type VaultProblem struct {
	Item   string `json:"item"`
	Reason string `json:"reason"`
	Effect string `json:"effect"`
	Remedy string `json:"remedy"`
}

type Status struct {
	TypeMeta
	ActiveHash string            `json:"activeHash"`
	Staged     *ConfigDiff       `json:"staged,omitempty"`
	Problems   []ConfigProblem   `json:"problems,omitempty"`
	Vault      []VaultProblem    `json:"vault,omitempty"`
	Approvals  []Approval        `json:"approvals"`
	Pins       map[string]string `json:"pins"`
	AgentPath  string            `json:"agentSocket"`
	// Setup is what the nazar CLI found wrong on the client side (a host
	// of ~/.ssh/config not wired to nazar, git's signing program or key,
	// keys another agent holds), each message ending with its fix. The
	// CLI fills it in `nazar status` (Milestone 7); nazar-agent
	// never does.
	Setup []ConfigProblem `json:"setup,omitempty"`
}

// Secret describes one secret (secrets design 7.2): stored, configured, or
// both. There is no field that could hold a value.
type Secret struct {
	TypeMeta
	Name         string     `json:"name"`
	Created      *time.Time `json:"created,omitempty"` // when stored
	Deliver      []string   `json:"deliver"`
	Rules        []string   `json:"rules"`
	UserPresence bool       `json:"userPresence"` // always false: no secret key has it yet (secrets design 3.5)
	// WhileLocked: the secret's key works while the Mac is locked too (as
	// SSHKey.WhileLocked); false when it is not stored.
	WhileLocked    bool   `json:"whileLocked"`
	Configured     bool   `json:"configured"`
	Stored         bool   `json:"stored"`
	Broken         bool   `json:"broken"`
	UnusableReason string `json:"unusableReason,omitempty"`
	Remedy         string `json:"remedy,omitempty"`
	// Policy is the secret's rules as config.yaml has them now (the staged
	// change when there is one), in the shape of a key's; FallbackSource is
	// "secret-gate" for the secret's own gate.
	Policy *SSHKeyRules `json:"policy,omitempty"`
	// Warnings are the config warnings about this secret's own entry.
	Warnings []string `json:"warnings"`
}

type SecretList struct {
	TypeMeta
	Items []Secret `json:"items"`
}

// SecretValue is the reply to a value command, on the control socket only,
// to the genuine nazar CLI. The value is base64: a JSON string can't carry
// arbitrary bytes.
type SecretValue struct {
	TypeMeta
	Name        string `json:"name"`
	ValueBase64 string `json:"valueBase64"`
	// Username is what git is told with the value (secret.helper): the
	// secret's helper.git username, else the one git asked with.
	Username string `json:"username,omitempty"`
}

type AuditEvent struct {
	TypeMeta
	Time   time.Time         `json:"time"`
	Fields map[string]string `json:"fields"`
}

type AuditSummary struct {
	TypeMeta
	Target    string         `json:"target"`
	Total     int            `json:"total"`
	Decisions map[string]int `json:"decisions"`
	Callers   map[string]int `json:"callers"`
}

// RunPlan is what the CLI execs for secret.run (secrets design 6.3 step
// 4): the absolute realpath it passes to execve, the argv and the
// complete environment, the directory it enters (by fchdir on an fd whose
// identity is CwdDev/CwdIno), and the files whose identity it compares
// with its own fstat right before execve. Every field is the agent's; the
// CLI adds nothing. It never carries a value.
type RunPlan struct {
	TypeMeta
	ExecPath string    `json:"execPath"`
	ExecArgv []string  `json:"execArgv"`
	Env      []string  `json:"env"`
	Cwd      string    `json:"cwd"`
	CwdDev   uint64    `json:"cwdDev"`
	CwdIno   uint64    `json:"cwdIno"`
	Files    []RunFile `json:"files"`
}

// RunFile is a file's identity as the agent pinned it.
type RunFile struct {
	Path    string `json:"path"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtimeNs"`
	CtimeNs int64  `json:"ctimeNs"`
}
