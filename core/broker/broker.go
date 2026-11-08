// Package broker is the request pipeline shared by every module (spec 4,
// 4.3, 4.4, 4.6): policy → approval cache → gate (login / dialog, one shared
// prompt per (target, rule, scope, receiver), a deadline) → the enclave
// operation → exactly one audit line. A block is refused at once and shown
// as a deduplicated warning with no allow button. Offer says which keys a
// caller may be told about at all (spec 5). Unknown chains, forwarded
// agent requests and scope: use are one-shot: they always prompt and are
// never remembered (a forwarded request under gate none gets a one-time
// dialog, spec 5). Remembered approvals end when the session root exits (the
// tab's shell, or the tool whose run was approved), or the app quits, when
// they expire, or on `nazar revoke`; one the platform
// stops honouring is dropped (audited as an error) and asked for again once.
package broker

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/policy"
)

// Request is one use of a key or a secret.
type Request struct {
	Key         string        // ssh key name
	Chain       *caller.Chain // resolved caller
	Summary     string        // "login to github.com as git"
	Destination string        // for the audit line
	Operation   string        // for the audit line, e.g. "sign git commit"
	// Forwarded is set when the request came through a forwarded agent
	// (session-bind is_forwarding). Such requests never use or create a
	// remembered approval: a remote host must not ride on a local tab's
	// approval.
	Forwarded bool
	// Op is what a remembered approval for this request would cover (spec
	// 4.3, Milestone 7): its ID joins the approval key, its Text is shown.
	// A request with no Op.ID is one-shot: nothing could tell its approval
	// from another's, so none is remembered and none is used.
	Op approval.Op
	// Secret, when set, makes this a request for that secret (secrets
	// design 5) rather than for an ssh key; Key is then unused. Delivery
	// is the method it is asked for by, and Receiver the chain of the
	// process that would receive the value (for helper and stdout the
	// nazar CLI's parent, caller.Chain.Parent); nil when nazar could not
	// tell, which only a rule without to: (or with to: any) matches and
	// which is never remembered. The broker sets Op from Delivery itself (deliveryOp).
	Secret   string
	Delivery config.Delivery
	Receiver *caller.Chain
	// EnvPassed names the envAllow variables the caller supplied to a
	// late-env receiver, for the audit line; never values.
	EnvPassed []string
	// K8s, when set, makes this a request for that k8s context's
	// credential (k8s design 2); Key and Secret are unused. Chain
	// is the nazar CLI's chain: its parent is the client, the receiver.
	// Cluster is the request's spec.cluster (nil: client-go sent none). The
	// broker sets Op from the context itself (k8sOp).
	K8s     string
	Cluster *cluster.Info
	// AWS, when set, makes this a request for that aws entry's credential
	// (aws design 6.1); Key, Secret and K8s are unused. Chain is the nazar
	// CLI's chain: its parent is the client, the receiver. The broker sets
	// Op from the entry itself (awsOp). There is no cluster: nothing in the
	// request but the name addresses it.
	AWS string
	// Do performs the enclave operation once the request is allowed. ref is
	// the approval to sign with (0 for dialog/none gates).
	Do func(ref platform.ApprovalRef) error
}

// DeniedError is what Do returns when it decided not to hand the result
// over after all (a nazar run receiver that changed at exec, secrets
// design 6.3 step 6): the request ends with decision=denied and this
// reason, not decision=error, and the remembered approval it ran under is
// dropped. Wrapped errors count. Reason goes into the audit line as it is:
// it names what differed (a variable's name, a file), never a value.
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return e.Reason }

// target is the policy target of r: "secret:<name>" or "ssh:<key>".
func (r Request) target() string {
	if r.AWS != "" {
		return "aws:" + r.AWS
	}
	if r.K8s != "" {
		return "k8s:" + r.K8s
	}
	if r.Secret != "" {
		return "secret:" + r.Secret
	}
	return "ssh:" + r.Key
}

// noun is how a dialog or warning names what r asks for.
func (r Request) noun() string {
	if r.AWS != "" {
		return fmt.Sprintf("AWS credential %q", r.AWS)
	}
	if r.K8s != "" {
		return fmt.Sprintf("Kubernetes credential %q", r.K8s)
	}
	if r.Secret != "" {
		return fmt.Sprintf("secret %q", r.Secret)
	}
	return fmt.Sprintf("key %q", r.Key)
}

// receiverChain is the chain whose peer receives the result: the caller's
// own (the socket peer) for an ssh key, Receiver for a secret (nil when
// nazar could not tell).
func (r Request) receiverChain() *caller.Chain {
	if r.K8s != "" || r.AWS != "" {
		if r.Chain == nil {
			return nil
		}
		return r.Chain.Parent()
	}
	if r.Secret != "" {
		return r.Receiver
	}
	return r.Chain
}

// deliveryOp is what a remembered approval for a secret covers: one
// delivery method (secrets design 5.1, spec 4.3). The target names the
// secret and the receiver is in the key, so the approval key is
// (secret:<name>, rule, scope, receiver, deliver:<method>). A method this
// version does not build gets no op, so it could never be remembered (and
// policy blocks it anyway).
func deliveryOp(d config.Delivery) approval.Op {
	switch d {
	case config.DeliverHelper:
		return approval.Op{ID: "deliver:helper", Text: "the credential helper"}
	case config.DeliverStdout:
		return approval.Op{ID: "deliver:stdout", Text: "nazar get"}
	case config.DeliverLateEnv:
		return approval.Op{ID: "deliver:late-env", Text: "nazar run"}
	}
	return approval.Op{}
}

// Result is the decision.
type Result struct {
	Decision audit.Decision
	Reason   string
	Outcome  policy.Outcome
}

// Allowed reports whether the operation ran successfully.
func (r Result) Allowed() bool {
	return r.Decision == audit.Allowed || r.Decision == audit.Approved
}

// Options configures a Broker.
type Options struct {
	Platform platform.Platform
	Cache    *approval.Cache
	Audit    *audit.Logger
	Engine   func() *policy.Engine // the current policy (changes on reload)
	Now      func() time.Time
	Home     string // shown as ~ in prompts
	// Timeout overrides defaults.timeout (tests).
	Timeout func() time.Duration
	// WarnWindow is how long repeated blocks update one warning (10 min).
	WarnWindow time.Duration
}

// Broker is safe for concurrent use.
type Broker struct {
	o      Options
	flight approval.Flight[gateResult]
	mu     sync.Mutex
	warns  map[string]*warnState
	// watched holds the processes with a live exit watcher, so that repeated
	// approvals in one scope never pile up watchers.
	watched map[platform.ProcessRef]bool
}

type warnState struct {
	first time.Time
	count int
}

// gateResult is what one prompt (or a shared one) produced.
type gateResult struct {
	ok       bool
	ref      platform.ApprovalRef
	decision audit.Decision
	reason   string
	cached   bool // found in the cache while waiting in line
}

// New returns a Broker over o.
func New(o Options) *Broker {
	if o.WarnWindow <= 0 {
		o.WarnWindow = 10 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Broker{o: o, warns: map[string]*warnState{}, watched: map[platform.ProcessRef]bool{}}
}

func (b *Broker) timeout(eng *policy.Engine) time.Duration {
	d := time.Duration(0)
	if b.o.Timeout != nil {
		d = b.o.Timeout()
	} else if eng != nil && eng.Config() != nil {
		d = eng.Config().Defaults.Timeout
	}
	if d <= 0 {
		d = config.DefaultTimeout
	}
	return d
}

// Handle decides req, runs req.Do when allowed, and logs one audit line.
// It fails closed: a request never ends without one of the six decisions of
// spec 4.6, and a panic on the way (a platform bug, say) is refused as
// decision=error rather than taking the agent down or passing silently.
func (b *Broker) Handle(req Request) (res Result) {
	if req.Chain == nil {
		req.Chain = &caller.Chain{Unknown: true}
	}
	eng := b.o.Engine()
	var out policy.Outcome
	if req.AWS != "" {
		out = eng.EvaluateAWS(req.AWS, req.Chain)
		req.Op = awsOp(req.AWS) // the broker's call, never the module's
	} else if req.K8s != "" {
		out = eng.EvaluateK8s(req.K8s, req.Chain, req.Cluster)
		req.Op = k8sOp(req.K8s) // the broker's call, never the module's
	} else if req.Secret != "" {
		out = eng.EvaluateSecret(req.Secret, req.Delivery, req.Chain, req.Receiver)
		req.Op = deliveryOp(req.Delivery) // the broker's call, never the module's
	} else {
		out = eng.EvaluateSSH(req.Key, req.Chain)
	}
	if req.Forwarded {
		// Spec 5: a forwarded connection never uses a remembered approval,
		// and under gate none it gets a one-time dialog instead of being
		// silent, so a remote host can't sign quietly.
		if out.Policy.Gate == config.GateNone {
			out.Policy.Gate, out.Policy.Scope, out.Policy.Expire = config.GateDialog, config.ScopeUse, 0
		}
		if out.Policy.Gate.Prompts() {
			out.OneShot, out.ScopeID = true, ""
		}
	}
	if req.Op.ID == "" {
		// Nothing says what an approval would cover, so none is remembered
		// and none is used (spec 4.3): a module that forgets fails closed.
		out.OneShot, out.ScopeID = true, ""
	}
	ev := b.event(req, out)
	logged := false
	finish := func(d audit.Decision, reason string) Result {
		if d == "" {
			d, reason = audit.Error, "no decision was reached: "+reason
		}
		ev.Decision, ev.Reason, ev.Time = d, reason, b.o.Now()
		logged = true
		b.o.Audit.Log(ev)
		return Result{Decision: d, Reason: reason, Outcome: out}
	}
	defer func() {
		if p := recover(); p != nil && !logged {
			res = finish(audit.Error, fmt.Sprintf("internal error: %v", p))
		}
		// A panic after the line was written (in a deferred release) keeps
		// the decision already made and returned.
	}()
	run := func(ref platform.ApprovalRef) error {
		if req.Do == nil {
			return nil
		}
		return req.Do(ref)
	}
	fail := func(err error) Result {
		var denied *DeniedError
		if errors.As(err, &denied) {
			// The receiver the approval was for is not what ran: the
			// approval goes, so a caller racing a file swap gets no silent
			// retries in the scope.
			key := approvalKey(req, out)
			b.o.Cache.RevokeWhere("refused after approval", func(e approval.Entry) bool { return e.Key == key })
			reason := "denied after approval"
			if denied != nil && denied.Reason != "" {
				reason = denied.Reason
			}
			return finish(audit.Denied, reason)
		}
		if errors.Is(err, platform.ErrAuthRequired) {
			return finish(audit.Error, "key requires the login gate (it was created with Secure Enclave user presence): "+err.Error())
		}
		return finish(audit.Error, err.Error())
	}
	do := func(ref platform.ApprovalRef, d audit.Decision, reason string) Result {
		if err := run(ref); err != nil {
			return fail(err)
		}
		return finish(d, reason)
	}

	switch out.Policy.Gate {
	case config.GateBlock:
		b.warn(req, out)
		return finish(audit.Blocked, out.Reason)
	case config.GateNone:
		return do(0, audit.Allowed, "gate none")
	case config.GateLogin, config.GateDialog:
	default:
		return finish(audit.Error, fmt.Sprintf("unknown gate %q", string(out.Policy.Gate)))
	}

	prompt := b.prompt(req, out, b.timeout(eng))
	if out.OneShot {
		// Never shared, never remembered: the approval covers this request
		// and is released as soon as the operation is done.
		g := b.runGate(out.Policy.Gate, prompt)
		if !g.ok {
			return finish(g.decision, g.reason)
		}
		defer b.release(g.ref)
		return do(g.ref, audit.Approved, "approved for this request")
	}

	key := approvalKey(req, out)
	// use runs the operation with a remembered login approval. When the
	// platform no longer honours it (ErrAuthRequired; on macOS
	// LocalAuthentication stops accepting a reused LAContext after a few
	// minutes), the entry is dropped so that no later request in the scope
	// fails on it, and dropped reports that. The entry goes only while it
	// still holds the rejected ref: a request that fails late, after another
	// request replaced the entry with a fresh approval, must not drop that
	// one. Removing the entry releases the ref, once, whoever gets there
	// first. A dialog carries no approval (ref 0) and a second dialog could
	// not produce one, so only the login gate's approvals are dropped.
	use := func(ref platform.ApprovalRef) (dropped bool, err error) {
		err = run(ref)
		if err != nil && errors.Is(err, platform.ErrAuthRequired) && out.Policy.Gate == config.GateLogin {
			dropped = b.o.Cache.RevokeWhere(reasonStale, func(e approval.Entry) bool {
				return e.Key == key && e.Ref == ref
			}) > 0
		}
		return dropped, err
	}
	if e, ok := b.o.Cache.Lookup(key); ok {
		dropped, err := use(e.Ref)
		if err == nil {
			return finish(audit.Allowed, "cached approval")
		}
		if !errors.Is(err, platform.ErrAuthRequired) || out.Policy.Gate != config.GateLogin {
			return fail(err)
		}
		// A remembered approval went stale. Audit the drop (one line per
		// dropped entry, by the request that dropped it) and ask again,
		// once, below. An approval out of that prompt is at most one
		// timeout old, so one the platform rejects is not stale but broken:
		// it fails the request rather than prompting again.
		if dropped {
			sev := ev
			sev.Decision, sev.Reason, sev.Time = audit.Error, reasonStale, b.o.Now()
			b.o.Audit.Log(sev)
		}
	}
	g, shared := b.flight.Do(key, func() gateResult {
		if e, ok := b.o.Cache.Lookup(key); ok { // approved while we waited in line
			return gateResult{ok: true, ref: e.Ref, cached: true}
		}
		g := b.runGate(out.Policy.Gate, prompt)
		if g.ok {
			if err := b.remember(key, out, req.Chain, req.Op.Text, g.ref); err != nil {
				// An approval that cannot be made to end with its scope is
				// neither used nor kept.
				b.release(g.ref)
				g = gateResult{decision: audit.Error, reason: err.Error()}
			}
		}
		return g
	})
	if !g.ok && g.decision == "" {
		// The leader panicked out of the prompt: Flight hands waiters the
		// zero value. Refuse, never pass.
		g.decision, g.reason = audit.Error, "the prompt failed"
	}
	switch {
	case !g.ok && shared:
		return finish(g.decision, "shared prompt: "+g.reason)
	case !g.ok:
		return finish(g.decision, g.reason)
	}
	if _, err := use(g.ref); err != nil {
		return fail(err)
	}
	if shared || g.cached {
		return finish(audit.Allowed, "shared approval")
	}
	return finish(audit.Approved, "approved")
}

// approvalKey is the approval cache key of req under out (spec 4.3): the
// policy's target, rule, scope and receiver, and the request's op.
func approvalKey(req Request, out policy.Outcome) approval.Key {
	return approval.Key{Target: out.Target, Rule: out.RuleID, ScopeID: out.ScopeID, Receiver: out.Receiver, Op: req.Op.ID}
}

// reasonStale is the audit reason of a remembered approval that the
// platform stopped honouring and the broker dropped.
const reasonStale = "remembered approval no longer accepted"

// Refuse logs a request that a module refused before it reached the
// pipeline (spec 4.6: every request is logged), such as a SIGN_REQUEST on
// a connection whose session-bind was refused or whose userauth contradicts
// the binding. It writes exactly one audit line, decision=blocked with the
// module's fixed reason and the caller's identity, and nothing else: no
// policy lookup (the refusal is not a policy decision, so no rule or gate
// is logged and the block warning is not shown), no approval cache, no
// prompt, and req.Do never runs.
func (b *Broker) Refuse(req Request, reason string) Result {
	if req.Chain == nil {
		req.Chain = &caller.Chain{Unknown: true}
	}
	target := req.target()
	ev := b.callerEvent(req, target)
	ev.Decision, ev.Reason, ev.Time = audit.Blocked, reason, b.o.Now()
	b.o.Audit.Log(ev)
	return Result{Decision: audit.Blocked, Reason: reason, Outcome: policy.Outcome{Target: target, Key: cmp.Or(req.AWS, req.K8s, req.Secret, req.Key)}}
}

// opListKeys is the audit operation of a key withheld from a listing.
const opListKeys = "list keys"

// Offer decides which of keys, those nazar holds, REQUEST_IDENTITIES may
// list for the caller chain (spec 5, Milestone 7): the keys of the active
// config whose policy for the chain is not block. ssh and ssh-keygen never
// ask to sign with a key the agent did not list, so this is where a caller
// outside a key's rules now stops. A caller offered nothing is reported as
// if it had asked to use each withheld key, one blocked audit line
// (operation "list keys") and the block warning per key, so a program
// outside every rule stays as visible as a refused sign request
// (THREAT-MODEL 4.9). A caller offered some key is told nothing about the
// others (no entry, no warning, no audit line): it did not ask to use them,
// and a sign request for one still runs the whole pipeline. The configured
// check and the policy read one engine, so a key leaving the config can
// never be offered under the new fallback in between. nil is an unknown
// chain; without an active config nothing is offered and nothing reported.
func (b *Broker) Offer(chain *caller.Chain, keys []string) []bool {
	offered := make([]bool, len(keys))
	eng := b.o.Engine()
	if eng == nil || eng.Config() == nil {
		return offered
	}
	if chain == nil {
		chain = &caller.Chain{Unknown: true}
	}
	outs := make([]policy.Outcome, len(keys))
	var withheld []int
	for i, k := range keys {
		if _, configured := eng.Config().SSHAgent.Keys[k]; !configured {
			continue // not a key of the active config: never listed, not a request
		}
		outs[i] = eng.EvaluateSSH(k, chain)
		if outs[i].Policy.Gate != config.GateBlock {
			offered[i] = true
			continue
		}
		withheld = append(withheld, i)
	}
	if slices.Contains(offered, true) {
		return offered
	}
	for _, i := range withheld {
		req := Request{Key: keys[i], Chain: chain, Summary: "asked which keys it may use", Operation: opListKeys}
		b.warn(req, outs[i])
		ev := b.event(req, outs[i])
		ev.Decision, ev.Reason, ev.Time = audit.Blocked, outs[i].Reason, b.o.Now()
		b.o.Audit.Log(ev)
	}
	return offered
}

// runGate shows the login prompt or the dialog and waits at most
// prompt.Timeout. A late answer is discarded and its approval released.
func (b *Broker) runGate(gate config.Gate, prompt platform.Prompt) gateResult {
	if prompt.Timeout <= 0 {
		prompt.Timeout = config.DefaultTimeout
	}
	ch := make(chan gateResult, 1)
	go func() {
		var r gateResult
		defer func() {
			// A gate that panics (a platform bug) is an error, not a crash of
			// the whole agent and never a pass.
			if p := recover(); p != nil {
				ch <- gateResult{decision: audit.Error, reason: fmt.Sprintf("the %s gate failed: %v", string(gate), p)}
			}
		}()
		if gate == config.GateLogin {
			ref, err := b.o.Platform.Authenticate(platform.AuthUserPresence, prompt)
			if err == nil && ref == 0 {
				// Fail closed: "approved" without an approval to sign with
				// is a platform bug, not a pass.
				err = errNoApproval
			}
			r = classify(err == nil, ref, err)
		} else {
			ok, err := b.o.Platform.Confirm(prompt)
			r = classifyDialog(ok, err, prompt.Timeout)
		}
		ch <- r
	}()
	t := time.NewTimer(prompt.Timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r
	case <-t.C:
		go func() { b.release((<-ch).ref) }()
		return gateResult{decision: audit.Timeout, reason: fmt.Sprintf("no answer within %s", prompt.Timeout)}
	}
}

// errNoApproval is the login gate reporting success with a zero ApprovalRef.
var errNoApproval = errors.New("login gate returned no approval")

// classify turns a gate's answer into a gateResult: a denial (ErrDenied or
// a false confirm) is denied, anything else that failed is an error.
func classify(ok bool, ref platform.ApprovalRef, err error) gateResult {
	switch {
	case ok:
		return gateResult{ok: true, ref: ref}
	case err == nil || errors.Is(err, platform.ErrDenied):
		return gateResult{decision: audit.Denied, reason: "user denied"}
	default:
		return gateResult{decision: audit.Error, reason: err.Error()}
	}
}

// classifyDialog is classify for the dialog gate, keeping how a denied
// dialog ended (since Milestone 5): "user denied (Deny button)", "user
// denied (Esc)", "the dialog closed without an answer", or "user denied"
// when the platform did not say; the dialog's own countdown is a timeout,
// like the broker's.
func classifyDialog(ok bool, err error, timeout time.Duration) gateResult {
	var how platform.DialogDenied
	if !ok && errors.As(err, &how) {
		switch how.How {
		case platform.DialogTimedOut:
			return gateResult{decision: audit.Timeout, reason: fmt.Sprintf("no answer within %s", timeout)}
		case platform.DialogClosed:
			return gateResult{decision: audit.Denied, reason: how.How.String()}
		case platform.DialogDenyButton, platform.DialogEscape:
			return gateResult{decision: audit.Denied, reason: "user denied (" + how.How.String() + ")"}
		}
		return gateResult{decision: audit.Denied, reason: "user denied"}
	}
	return classify(ok && err == nil, 0, err)
}

func (b *Broker) release(ref platform.ApprovalRef) {
	if ref != 0 {
		b.o.Platform.ReleaseApproval(ref)
	}
}

// remember stores an approval and arranges for it to end with its scope.
// ref is the login approval (an LAContext on macOS), 0 for dialog. It fails
// closed: if that panics (a platform bug in the exit watcher, say), the
// entry is removed again, which releases ref if it was stored, and the
// error is returned, so an approval that would outlive its scope is never
// kept. The entry is stored before the watcher is installed, so a scope
// that ended during the prompt is revoked at once rather than remembered.
func (b *Broker) remember(key approval.Key, out policy.Outcome, c *caller.Chain, covers string, ref platform.ApprovalRef) (err error) {
	stored := false
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		err = fmt.Errorf("the approval could not be remembered: %v", p)
		if stored {
			b.o.Cache.RevokeWhere("could not watch its scope", func(e approval.Entry) bool { return e.Key == key })
		} else {
			b.release(ref)
		}
	}()
	now := b.o.Now()
	e := approval.Entry{Key: key, Scope: string(out.Policy.Scope), Created: now, Chain: c.Summary(), Covers: covers, Ref: ref}
	if c.HasApp() {
		e.App = c.App.BundleID
	}
	if out.Policy.Expire > 0 {
		e.Expires = now.Add(out.Policy.Expire)
	}
	b.o.Cache.Put(e)
	stored = true
	b.watch(out)
	return nil
}

// watch revokes the scope when the process it is rooted at exits
// (policy.Outcome.Root: the tab's shell, the tool whose run was approved,
// or the app). One watcher per process.
func (b *Broker) watch(out policy.Outcome) {
	ref := out.Root
	if ref.IsZero() {
		return
	}
	reason := "session ended"
	if out.Policy.Scope == config.ScopeApp {
		reason = "app quit"
	}
	b.mu.Lock()
	if b.watched[ref] {
		b.mu.Unlock()
		return
	}
	b.watched[ref] = true
	b.mu.Unlock()
	installed := false
	defer func() {
		// A watcher that was never installed must not count as one, or the
		// scope would never be watched again.
		if !installed {
			b.mu.Lock()
			delete(b.watched, ref)
			b.mu.Unlock()
		}
	}()
	scopeID := out.ScopeID
	b.o.Platform.OnProcessExit(ref, func() {
		b.mu.Lock()
		delete(b.watched, ref)
		b.mu.Unlock()
		b.o.Cache.RevokeScope(scopeID, reason)
	})
	installed = true
}

// Login runs the login gate for an action outside the key pipeline: config
// approval, key creation and deletion, `nazar trust --app` (spec 4.8, 6). The
// approval is released at once. prompt.Timeout defaults to GateTimeout().
//
// The prompt text is cleaned here, not left to callers: the config-change
// dialog shows a rule that malware may have written into config.yaml (spec
// 4.8, section 8), so matcher values in it are attacker-chosen. Every line
// gets the same treatment as a key prompt, and the caller's slice is copied
// rather than rewritten.
func (b *Broker) Login(prompt platform.Prompt) (audit.Decision, string) {
	if prompt.Timeout <= 0 {
		prompt.Timeout = b.GateTimeout()
	}
	prompt.Title = clean(prompt.Title, maxLine)
	prompt.Reason = clean(prompt.Reason, maxLine)
	lines := make([]string, len(prompt.Lines))
	for i, l := range prompt.Lines {
		lines[i] = clean(l, maxLine)
	}
	prompt.Lines = lines
	g := b.runGate(config.GateLogin, prompt)
	b.release(g.ref)
	if g.ok {
		return audit.Approved, "approved"
	}
	return g.decision, g.reason
}

// GateTimeout is the current prompt timeout (defaults.timeout, or the
// Timeout option).
func (b *Broker) GateTimeout() time.Duration { return b.timeout(b.o.Engine()) }
