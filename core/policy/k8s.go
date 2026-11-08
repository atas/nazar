package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
)

// The reasons a k8s request is blocked before its rules are read (k8s
// design 2.1, 2.2). They are the audit line's reason and pick the block
// warning's text.
const (
	ReasonK8sContext = "no such k8s context"
	ReasonK8sCaller  = "the program that ran nazar can't be identified"
	// ReasonK8sLeftoverClients: the context still has a clients: line.
	ReasonK8sLeftoverClients = "the context still has a clients: line, which is no longer used: remove it and approve the change"
	ReasonNoCluster          = "no cluster info: exec.provideClusterInfo must be true"
	ReasonCluster            = "cluster mismatch"
)

// EvaluateK8s decides a request for context name's credential (k8s design
// 2): c is the chain of the nazar CLI that asked (its peer is the CLI,
// checked by the control server: check 0), got the request's spec.cluster
// (nil when client-go sent none). In order: a context the config does not
// have, or one off for a leftover clients: line, is blocked; check 1, the CLI's parent (chain[1], whatever program it
// is: there is no client list) must be identified, as it is the receiver
// of every approval; check 2, got must be the recorded cluster; check 3,
// the first-match walk over the context's rules on whoever called that
// program (chain[2:]; the program itself when launchd started it:
// caller.Chain.Callers), else its own policy or defaults.fallback. A request
// blocked at check 1 or 2 never reads a rule. nil c is an unknown chain
// with no parent.
func (e *Engine) EvaluateK8s(name string, c *caller.Chain, got *cluster.Info) Outcome {
	if c == nil {
		c = &caller.Chain{Unknown: true}
	}
	out := Outcome{Target: "k8s:" + name, Key: name, Unknown: c.Unknown}
	block := func(reason string) Outcome {
		out.Policy = config.Policy{Scope: config.ScopeUse, Gate: config.GateBlock}
		out.RuleID = FallbackRuleID(out.Target, out.Policy)
		out.Reason = reason
		e.scope(&out, c)
		return out
	}
	ctx := e.cfg.K8s[name]
	// A kind other than ca-cert never parses; refusing it here is defence.
	if ctx == nil || ctx.Credential != config.CredentialCACert {
		return block(ReasonK8sContext)
	}
	if ctx.LeftoverClients {
		return block(ReasonK8sLeftoverClients)
	}
	// Check 1: chain[1] is a live, full record with an identity an
	// approval can be remembered under.
	if len(c.Procs) < 2 || !identified(c.Procs[1]) {
		return block(ReasonK8sCaller)
	}
	client := c.Procs[1]
	// Check 2: the cluster the request names is the recorded one.
	if got == nil {
		out.Receiver = match.Identity(client)
		return block(ReasonNoCluster)
	}
	if err := ctx.Cluster.Match(*got); err != nil {
		out.Receiver = match.Identity(client)
		return block(ReasonCluster + ": " + err.Error())
	}
	// Check 3: the rules, on whoever called the client. The view keeps the
	// chain's app and session; the CLI is never matched, nor is the client
	// unless launchd started it (nothing called it: Callers), so a program
	// outside every allowed chain gets nothing, whatever it runs.
	view := c.Callers()
	e.first(&out, ctx.Rules, e.cfg.K8sFallback(name), ctx.Own != nil, view, nil)
	out.RuleID = k8sRuleID(out.RuleID, ctx)
	out.Receiver = match.Identity(client)
	// The scope is the full chain's: when the
	// client is its own session root (an app running kubectl with no shell
	// between), the view has no root and every run would share the app's.
	e.scope(&out, c)
	return out
}

// identified reports whether p, the program that ran the nazar CLI, can
// receive a credential (check 1 of k8s and aws): a full record (not PID-only) whose code signature
// verified and gives it an identity (a team, or a cdhash for ad-hoc code
// such as Homebrew's), which is the receiver of the approval (match.Identity).
func identified(p platform.ProcessInfo) bool {
	return !p.Ref.IsPIDOnly() && !p.Ref.IsZero() && p.Code.Signed && (p.Code.Team() != "" || len(p.Code.CDHash) > 0)
}

// k8sRuleID binds a rule's (or the fallback's) id to what the context
// mints: an approved change of the cluster, the identity, the kind or
// ttl_cert gives every rule a new id, so approvals remembered for the old
// credential end on reload.
func k8sRuleID(id string, ctx *config.K8sContext) string {
	h := sha256.New()
	fmt.Fprintf(h, "%q %q %q %q %q %q %d", ctx.Credential, ctx.Cluster.Server, ctx.Cluster.CASHA256, ctx.Cluster.TLSServerName,
		ctx.Cluster.ProxyURL, ctx.Identity.User, ctx.TTLCert)
	for _, g := range ctx.Identity.Groups {
		fmt.Fprintf(h, " O=%q", g)
	}
	return id + "@" + hex.EncodeToString(h.Sum(nil)[:4])
}
