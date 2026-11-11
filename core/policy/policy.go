// Package policy decides which rule applies to a request (spec 4.2):
// first match wins, apps: and to: must both match, otherwise the key's own
// policy or defaults.fallback (block by default).
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
)

// Outcome is the policy decision for one request.
type Outcome struct {
	Target    string // "ssh:<key>", "secret:<name>", "k8s:<context>" or "aws:<name>"
	Key       string // the key's or the secret's name
	RuleIndex int    // 1-based; 0 for the fallback
	RuleID    string // config.Rule.ID(), or "fallback:<hash8>"
	// KeyGate is set when no rule matched and the key's own scope/gate/
	// expire applied, rather than defaults.fallback (since Milestone 5: the
	// audit log says rule=key-gate, not rule=fallback).
	KeyGate bool
	Policy  config.Policy
	Reason  string // "rule 2 matched", "no rule matched", "to: mismatch"
	// Receiver is the receiver identity (match.Identity of the socket peer)
	// when the matched rule has to:, else "". For a secret it is always the
	// receiving process's identity, under any rule or the fallback, and ""
	// only when nazar could not tell who receives (EvaluateSecret).
	Receiver string
	// Matched is the process that satisfied the matched rule's apps: matcher
	// (match.Evaluator.Matched); zero for any, unknown and the fallback.
	Matched platform.ProcessRef
	// ScopeID is "session:<id>" or "app:<team:bundle>" when the approval
	// may be remembered; "" when it must not be (OneShot).
	ScopeID string
	OneShot bool
	// Session is the session the request is judged in (Milestone 7): the
	// chain's, or, for a scope: session rule a tool in the tab
	// satisfied (caller.Chain.Tool), that tool's run. It is the audit
	// line's session= and, with scope: session, the id in ScopeID. Root is
	// the process whose exit ends a remembered approval: the session's
	// root process (the tab's shell or the tool), or the app for scope:
	// app; zero when OneShot.
	Session caller.SessionID
	Root    platform.ProcessRef
	// Unknown is set for unknown chains: never cached, always warned (spec 4.2).
	Unknown bool
}

// Engine evaluates one immutable config. Build a new Engine on reload; it is
// safe for concurrent use.
type Engine struct {
	cfg *config.Config
	m   *match.Evaluator
	// NoCodeSigning says the platform has no code signatures (Linux:
	// platform.Traits.CodeSigning false), so no process is ever Signed and
	// the program that ran nazar (check 1 of a k8s or aws credential) is
	// identified by the file it runs and that file's hash, which is what
	// its approval is remembered under there (match.Identity). The daemon
	// sets it from the platform's traits; false is macOS.
	NoCodeSigning bool
}

// New returns an engine for cfg that evaluates matchers with m.
func New(cfg *config.Config, m *match.Evaluator) *Engine { return &Engine{cfg: cfg, m: m} }

// Config returns the config this engine evaluates.
func (e *Engine) Config() *config.Config { return e.cfg }

// ReasonDelivery is the reason a secret request is blocked when its method
// is not in the secret's deliver: or not built in this version (secrets
// design 4): before any rule is read.
const ReasonDelivery = "delivery not allowed"

// ReasonName is the reason a secret request is blocked when its name is not
// a valid secret name, or matches a secrets entry only ignoring letter case
// (the store compares names case-insensitively): such a name never
// escapes its entry to defaults.fallback.
const ReasonName = "invalid secret name"

// EvaluateSSH decides a request to use ssh key `key` from chain c. Rules are
// walked top to bottom; a rule applies only if both apps: and to: match, and
// a to: miss falls through to later rules. Without a match the key's own
// policy or defaults.fallback applies.
func (e *Engine) EvaluateSSH(key string, c *caller.Chain) Outcome {
	out := Outcome{Target: "ssh:" + key, Key: key, Unknown: c.Unknown}
	k := e.cfg.SSHAgent.Keys[key]
	var rules []config.Rule
	if k != nil {
		rules = k.Rules
	}
	if r := e.first(&out, rules, e.cfg.Fallback(key), k != nil && k.Own != nil, c, c); r != nil && len(r.To) > 0 {
		if peer, ok := c.Peer(); ok {
			out.Receiver = match.Identity(peer)
		}
	}
	e.scope(&out, c)
	return out
}

// EvaluateSecret decides a request for secret name by method d (secrets
// design 5): the first-match walk of EvaluateSSH with apps: judged on ask
// (who asked: the nazar CLI's chain) and to: on recv (who receives the
// value: for helper and stdout the CLI's parent, caller.Chain.Parent). A
// method the secret's deliver: does not list, or this version does not
// build, is blocked before any rule is read. The receiver's identity is in
// every remembered approval, with or without to:, so an approval for one
// receiver never hands the value to another in the same scope; a receiver
// nazar can't identify (nil, or no peer) makes the request one-shot. nil ask
// is an unknown chain.
func (e *Engine) EvaluateSecret(name string, d config.Delivery, ask, recv *caller.Chain) Outcome {
	if ask == nil {
		ask = &caller.Chain{Unknown: true}
	}
	if recv == nil {
		recv = &caller.Chain{Unknown: true}
	}
	out := Outcome{Target: "secret:" + name, Key: name, Unknown: ask.Unknown}
	block := func(reason string) Outcome {
		out.Policy = config.Policy{Scope: config.ScopeUse, Gate: config.GateBlock}
		out.RuleID = FallbackRuleID(out.Target, out.Policy)
		out.Reason = reason
		e.scope(&out, ask)
		return out
	}
	if !config.ValidSecretName(name) || e.caseVariant(name) {
		return block(ReasonName)
	}
	if !d.Built() || !slices.Contains(e.cfg.Deliver(name), d) {
		return block(ReasonDelivery)
	}
	s := e.cfg.Secrets[name]
	var rules []config.Rule
	if s != nil {
		rules = s.Rules
	}
	// The asking chain's peer is the nazar CLI, whoever runs it, so apps:
	// is judged on the chain above it: a rule naming the CLI's own
	// identity would otherwise match every program (in effect apps: any).
	e.first(&out, rules, e.cfg.SecretFallback(name), s != nil && s.Own != nil, ask.Parent(), recv)
	askPeer, _ := ask.Peer()
	if peer, ok := recv.Peer(); ok && recv.Synthetic {
		out.Receiver = match.RunIdentity(peer)
	} else if ok && peer.Ref != askPeer.Ref {
		// A receiver that is the asker itself would key every approval by
		// the CLI, so it is treated as one nazar could not tell.
		out.Receiver = match.Identity(peer)
	}
	e.scope(&out, ask)
	if out.Receiver == "" {
		out.OneShot, out.ScopeID, out.Root = true, "", platform.ProcessRef{}
	}
	return out
}

// caseVariant reports whether name has no secrets entry of its own but one
// that equals it ignoring letter case.
func (e *Engine) caseVariant(name string) bool {
	if _, ok := e.cfg.Secrets[name]; ok {
		return false
	}
	for n := range e.cfg.Secrets {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}

// first walks rules top to bottom (spec 4.2): a rule applies only if apps:
// matches ask and to:, when it has one, matches recv; a to: miss falls
// through. It fills out from the rule that applies and returns it, or, with
// none, from the fallback (keyGate: the entry's own policy) with "no rule
// matched" or "to: mismatch", and returns nil.
func (e *Engine) first(out *Outcome, rules []config.Rule, fallback config.Policy, keyGate bool, ask, recv *caller.Chain) *config.Rule {
	toMismatch := false
	for i := range rules {
		r := &rules[i]
		matched, ok := e.m.Matched(r.Apps, ask)
		if !ok {
			continue
		}
		if len(r.To) > 0 && !e.m.Receiver(r.To, recv) {
			toMismatch = true
			continue
		}
		out.RuleIndex, out.RuleID, out.Policy, out.Matched = r.Index, r.ID(), r.Policy, matched
		out.Reason = "rule " + strconv.Itoa(r.Index) + " matched"
		return r
	}
	out.Policy, out.KeyGate = fallback, keyGate
	out.RuleID = FallbackRuleID(out.Target, fallback)
	out.Reason = "no rule matched"
	if toMismatch {
		out.Reason = "to: mismatch"
	}
	return nil
}

// FallbackRuleID is the rule id of a target's fallback policy; it changes
// whenever the fallback policy changes, so an edited fallback never inherits
// approvals.
func FallbackRuleID(target string, p config.Policy) string {
	sum := sha256.Sum256([]byte(target + "\x00" + p.String()))
	return "fallback:" + hex.EncodeToString(sum[:4])
}

// LiveRuleIDs returns "target|ruleID" for every rule and the fallback of
// every configured key, secret, k8s context and aws entry, for the approval cache to drop approvals
// of edited or removed rules after a config change. Unconfigured keys and
// secrets have no live ids, so their approvals are dropped too.
func LiveRuleIDs(c *config.Config) map[string]bool {
	live := map[string]bool{}
	for _, name := range c.KeyNames() {
		target := "ssh:" + name
		if k := c.SSHAgent.Keys[name]; k != nil {
			for _, r := range k.Rules {
				live[target+"|"+r.ID()] = true
			}
		}
		live[target+"|"+FallbackRuleID(target, c.Fallback(name))] = true
	}
	for _, name := range c.SecretNames() {
		target := "secret:" + name
		for _, r := range c.Secrets[name].Rules {
			live[target+"|"+r.ID()] = true
		}
		live[target+"|"+FallbackRuleID(target, c.SecretFallback(name))] = true
	}
	for _, name := range c.K8sNames() {
		target, k := "k8s:"+name, c.K8s[name]
		for _, r := range k.Rules {
			live[target+"|"+k8sRuleID(r.ID(), k)] = true
		}
		live[target+"|"+k8sRuleID(FallbackRuleID(target, c.K8sFallback(name)), k)] = true
	}
	for _, name := range c.AWSNames() {
		target, e := "aws:"+name, c.AWS[name]
		for _, r := range e.Rules {
			live[target+"|"+awsRuleID(r.ID(), e)] = true
		}
		live[target+"|"+awsRuleID(FallbackRuleID(target, c.AWSFallback(name)), e)] = true
	}
	return live
}

// scope fills Session, and ScopeID, Root and OneShot. The session is the
// chain's, or the run of the tool in the tab that satisfied a scope:
// session rule (spec 4.1 step 4, Milestone 7). An approval is remembered
// only for a prompting gate (login, dialog), a known chain, and a scope
// that has an identity: session with a root, app with a verifiable app
// identity. Everything else is one-shot. The unknown-chain check is the
// engine's own (spec 4.2 "never covered by a remembered approval") and does
// not rely on the resolver leaving Session and App empty. It holds for a
// signed: rule a process in an unknown chain satisfied too
// (spec 4.2): that process's run is a run inside a session (Chain.Tool)
// only when there is a session, and an unknown chain's top, which a
// process can reach by leaving its chain, is no sound session root.
func (e *Engine) scope(out *Outcome, c *caller.Chain) {
	out.OneShot = true
	out.Session = c.Session
	root := c.SessionRoot
	if out.Policy.Scope == config.ScopeSession {
		if p, ok := c.Tool(out.Matched); ok {
			out.Session, root = caller.SessionID{PID: p.Ref.PID, Start: p.StartTime}, p.Ref
		}
	}
	if !out.Policy.Gate.Prompts() || c.Unknown {
		return
	}
	switch out.Policy.Scope {
	case config.ScopeSession:
		if !out.Session.IsZero() {
			out.ScopeID, out.Root, out.OneShot = "session:"+out.Session.String(), root, false
		}
	case config.ScopeApp:
		if id := c.AppIdentity(); id != "" {
			out.ScopeID, out.Root, out.OneShot = "app:"+id, c.App.Ref, false
		}
	}
}
