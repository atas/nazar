package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/match"
)

// The reasons an aws request is blocked before its rules are read (aws
// design 6.1). They are the audit line's reason and pick the block
// warning's text.
const (
	ReasonAWSEntry        = "no such aws entry"
	ReasonAWSNotConnected = "aws entry not connected"
	ReasonAWSCaller       = ReasonK8sCaller // check 1, in the words of k8s's
)

// EvaluateAWS decides a request for entry name's credential (aws design
// 6.1): c is the chain of the nazar CLI that asked (its peer is the CLI,
// checked by the control server: check 0). In order: an entry the config
// does not have, or has without its ARNs, is blocked; check 1, the CLI's
// parent (chain[1], whatever program it is: there is no client list) must
// be identified, as it is the receiver of every approval; check 3, the
// first-match walk over the entry's rules on whoever called that program
// (chain[2:]), else its own policy or defaults.fallback. There is no check
// 2: nothing in the request but the name addresses it. nil c is an unknown
// chain with no parent.
func (e *Engine) EvaluateAWS(name string, c *caller.Chain) Outcome {
	if c == nil {
		c = &caller.Chain{Unknown: true}
	}
	out := Outcome{Target: "aws:" + name, Key: name, Unknown: c.Unknown}
	block := func(reason string) Outcome {
		out.Policy = config.Policy{Scope: config.ScopeUse, Gate: config.GateBlock}
		out.RuleID = FallbackRuleID(out.Target, out.Policy)
		out.Reason = reason
		e.scope(&out, c)
		return out
	}
	entry := e.cfg.AWS[name]
	if entry == nil {
		return block(ReasonAWSEntry)
	}
	if !entry.Connected() {
		return block(ReasonAWSNotConnected)
	}
	// Check 1: chain[1] is a live, full record with an identity an
	// approval can be remembered under (as EvaluateK8s).
	if len(c.Procs) < 2 || !identified(c.Procs[1]) {
		return block(ReasonAWSCaller)
	}
	client := c.Procs[1]
	// Check 3: the rules, on whoever called that program (the program
	// itself when launchd started it: caller.Chain.Callers); the scope is
	// the full chain's (as EvaluateK8s). The CLI is never matched, so a
	// program outside every allowed chain gets nothing, whatever it runs.
	view := c.Callers()
	e.first(&out, entry.Rules, e.cfg.AWSFallback(name), entry.Own != nil, view, nil)
	out.RuleID = awsRuleID(out.RuleID, entry)
	out.Receiver = match.Identity(client)
	e.scope(&out, c)
	return out
}

// awsRuleID binds a rule's (or the fallback's) id to what the entry mints:
// an approved change of an ARN, the identity or the duration gives every
// rule a new id, so approvals remembered for the old credential end on
// reload.
func awsRuleID(id string, e *config.AWSEntry) string {
	h := sha256.New()
	fmt.Fprintf(h, "%q %q %q %q %d", e.TrustAnchorArn, e.ProfileArn, e.RoleArn, e.Identity.User, e.Duration)
	return id + "@" + hex.EncodeToString(h.Sum(nil)[:4])
}
