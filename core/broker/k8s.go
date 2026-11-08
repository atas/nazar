package broker

import (
	"fmt"
	"strings"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/policy"
)

// k8sOp is what a remembered approval for a context's credential covers
// (k8s design 2.4): that context, set by the broker, never the module. The
// target names the context too, and the receiver (the client) is in the
// key, so the approval key is (k8s:<ctx>, rule, scope, client, k8s:<ctx>).
func k8sOp(context string) approval.Op {
	return approval.Op{ID: "k8s:" + context, Text: "the Kubernetes credential for " + context}
}

// k8sCheck reports whether reason is a refusal of check 1 or 2, of an
// unknown context or of one off for a leftover clients: line: no rule can
// allow such a request, so the block warning drafts none.
func k8sCheck(reason string) bool {
	return reason == policy.ReasonK8sCaller || reason == policy.ReasonNoCluster || reason == policy.ReasonK8sContext ||
		reason == policy.ReasonK8sLeftoverClients || strings.HasPrefix(reason, policy.ReasonCluster)
}

// unidentifiedWhy is the block warning's line for check 1 of k8s and aws.
const unidentifiedWhy = "The program that ran nazar can't be identified (it may have exited), so nothing was handed to it."

// k8sWhy is the block warning's line for such a refusal (k8s design 2.1,
// 2.2); "" for any other outcome. c is the nazar CLI's chain, so its
// parent is the program that asked.
func k8sWhy(out policy.Outcome, c *caller.Chain) string {
	client := "The program that ran nazar"
	if c != nil && len(c.Procs) > 1 {
		name, _ := caller.ProcName(c.Procs[1])
		client = programText(name)
	}
	switch {
	case out.Reason == policy.ReasonK8sCaller:
		return unidentifiedWhy
	case out.Reason == policy.ReasonK8sLeftoverClients:
		return fmt.Sprintf("k8s.contexts.%s still has a clients: line, which nazar no longer uses, so the context is off: remove the line from config.yaml and approve the change (nazar config apply).", out.Key)
	case out.Reason == policy.ReasonNoCluster:
		return client + " sent no cluster info, so nazar can't check the server: the kubeconfig's exec entry needs provideClusterInfo: true."
	case strings.HasPrefix(out.Reason, policy.ReasonCluster):
		detail := strings.TrimPrefix(strings.TrimPrefix(out.Reason, policy.ReasonCluster), ": ")
		return fmt.Sprintf("%s asked for this credential for a different server or CA than the recorded one (%s). Your kubeconfig may have been changed.", client, detail)
	case out.Reason == policy.ReasonK8sContext:
		return "nazar has no k8s context of this name."
	}
	return ""
}
