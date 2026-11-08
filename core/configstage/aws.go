package configstage

import (
	"fmt"

	"github.com/atas/nazar/core/config"
)

// awsEntries classifies the aws entries (aws design 7), target aws:<name>,
// as k8sContexts does contexts: the rules and the fallback by the slot
// proof; an entry absent from a config is one block slot. On top, whatever
// the slots say: a changed ARN (adding them, which connects the entry,
// included) mints through another trust anchor, profile or role, a changed
// identity mints another subject, and a longer duration lets it live
// longer: each loosens. An entry added loosens even when every slot blocks,
// and the prompt shows its identity. A shorter duration tightens. An entry
// names no program that receives the credential (aws design 6.1), so there
// is no client set to compare.
func awsEntries(d *Diff, old, nw *config.Config) {
	for _, name := range union(old.AWSNames(), nw.AWSNames()) {
		target := "aws:" + name
		o, inOld := old.AWS[name]
		n, inNew := nw.AWS[name]
		os, ns := awsSlots(old, name), awsSlots(nw, name)
		d.Changes = append(d.Changes, describe(target, "aws", inOld, inNew, os, ns)...)
		d.Loosening = append(d.Loosening, loosenings(target, os, ns)...)
		switch {
		case inOld && inNew:
			awsFields(d, target, o, n)
		case inNew:
			awsFields(d, target, &config.AWSEntry{}, n)
		}
	}
}

func awsSlots(c *config.Config, name string) []slot {
	e, ok := c.AWS[name]
	if !ok {
		return absent
	}
	return slots(e.Rules, c.AWSFallback(name))
}

// awsFields compares what an entry mints and for whom, beyond its rules.
func awsFields(d *Diff, target string, o, n *config.AWSEntry) {
	loosen := func(change, why string) {
		d.Changes = append(d.Changes, target+": "+change)
		d.Loosening = append(d.Loosening, Finding{Target: target, Why: why})
	}
	switch {
	case o.TrustAnchorArn == n.TrustAnchorArn && o.ProfileArn == n.ProfileArn && o.RoleArn == n.RoleArn:
	case !n.Connected():
		d.Changes = append(d.Changes, target+": not connected any more (no ARNs)")
	default:
		loosen(fmt.Sprintf("ARNs %s → %s", arnText(o), arnText(n)),
			fmt.Sprintf("ARNs changed: the credential would be minted through %s with %s for %s", n.TrustAnchorArn, n.ProfileArn, n.RoleArn))
	}
	if o.Identity != n.Identity {
		loosen(fmt.Sprintf("identity %s → %s", awsIDText(o.Identity), awsIDText(n.Identity)), "identity changed: certificates would say "+awsIDText(n.Identity))
	}
	switch {
	case n.Duration > o.Duration:
		loosen(fmt.Sprintf("duration %s → %s", o.Duration, n.Duration), fmt.Sprintf("sessions live longer: duration %s → %s", o.Duration, n.Duration))
	case n.Duration < o.Duration:
		d.Changes = append(d.Changes, fmt.Sprintf("%s: duration %s → %s", target, o.Duration, n.Duration))
	}
}

func arnText(e *config.AWSEntry) string {
	if !e.Connected() {
		return "none"
	}
	return fmt.Sprintf("trust anchor %s, profile %s, role %s", e.TrustAnchorArn, e.ProfileArn, e.RoleArn)
}

func awsIDText(id config.AWSIdentity) string {
	if id.User == "" {
		return "none"
	}
	return "CN=" + id.User
}
