package broker

import (
	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/policy"
)

// awsOp is what a remembered approval for an entry's credential covers
// (aws design 6.1): that entry, set by the broker, never the module. The
// key is (aws:<name>, rule, scope, receiver, aws:<name>); the receiver is
// the program that ran nazar.
func awsOp(name string) approval.Op {
	return approval.Op{ID: "aws:" + name, Text: "the AWS credential for " + name}
}

// awsCheck reports whether reason is a refusal of check 1, of an unknown
// entry or of one not connected: no rule can allow such a request, so the
// block warning drafts none.
func awsCheck(reason string) bool {
	return reason == policy.ReasonAWSCaller || reason == policy.ReasonAWSEntry || reason == policy.ReasonAWSNotConnected
}

// awsWhy is the block warning's line for those refusals; "" for any other
// outcome.
func awsWhy(out policy.Outcome) string {
	switch out.Reason {
	case policy.ReasonAWSCaller:
		return unidentifiedWhy
	case policy.ReasonAWSNotConnected:
		return "This aws entry has no trustAnchorArn, profileArn and roleArn yet, so nothing can be minted for it."
	case policy.ReasonAWSEntry:
		return "nazar has no aws entry of this name."
	}
	return ""
}
