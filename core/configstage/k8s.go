package configstage

import (
	"fmt"
	"slices"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/k8s/cluster"
)

// k8sContexts classifies the k8s contexts (k8s design 3, as built in
// M12), target k8s:<name>. The rules and the fallback are compared by
// the slot proof, as for a key; a context absent from a config is one
// block slot (a request for it is refused), so adding a context loosens
// unless every slot blocks and removing one tightens. On top, whatever the
// slots say: a changed cluster re-points the credential at another server
// (the attack check 2 exists to stop), a changed identity or credential
// mints something else, and a longer ttl_cert lets it live longer: each
// loosens. A context added is all of that from nothing: it loosens even
// when every slot blocks, and the prompt shows its cluster and identity, so
// a context removed and added back can't change them silently. A shorter
// ttl_cert tightens. A context off for a leftover clients: line is one
// block slot, as an absent one: removing the line loosens.
func k8sContexts(d *Diff, old, nw *config.Config) {
	for _, name := range union(old.K8sNames(), nw.K8sNames()) {
		target := "k8s:" + name
		o, inOld := old.K8s[name]
		n, inNew := nw.K8s[name]
		os, ns := k8sSlots(old, name), k8sSlots(nw, name)
		d.Changes = append(d.Changes, describe(target, "context", inOld, inNew, os, ns)...)
		d.Loosening = append(d.Loosening, loosenings(target, os, ns)...)
		switch {
		case inOld && inNew:
			k8sFields(d, target, o, n)
		case inNew:
			k8sFields(d, target, &config.K8sContext{}, n)
		}
	}
}

// absent is the slot of a context a config does not have.
var absent = []slot{{pol: config.Policy{Scope: config.ScopeUse, Gate: config.GateBlock}, label: "no entry"}}

func k8sSlots(c *config.Config, name string) []slot {
	k, ok := c.K8s[name]
	if !ok {
		return absent
	}
	if k.LeftoverClients {
		return []slot{{pol: config.Policy{Scope: config.ScopeUse, Gate: config.GateBlock}, label: "off: clients: line"}}
	}
	return slots(k.Rules, c.K8sFallback(name))
}

// k8sFields compares what a context mints and for whom, beyond its rules.
func k8sFields(d *Diff, target string, o, n *config.K8sContext) {
	loosen := func(change, why string) {
		d.Changes = append(d.Changes, target+": "+change)
		d.Loosening = append(d.Loosening, Finding{Target: target, Why: why})
	}
	if o.Cluster != n.Cluster {
		loosen(fmt.Sprintf("cluster %s → %s", pinText(o), pinText(n)), "cluster changed: the credential would be minted for "+n.Cluster.Server)
	}
	if o.Identity.User != n.Identity.User || !slices.Equal(o.Identity.Groups, n.Identity.Groups) {
		loosen(fmt.Sprintf("identity %s → %s", idText(o.Identity), idText(n.Identity)), "identity changed: certificates would say "+idText(n.Identity))
	}
	if o.Credential != n.Credential {
		loosen(fmt.Sprintf("credential %s → %s", o.Credential, n.Credential), "credential changed")
	}
	switch {
	case o.LeftoverClients && !n.LeftoverClients:
		loosen("clients: line removed", "clients: line removed: the context is on, any program your rules allow gets the credential")
	case !o.LeftoverClients && n.LeftoverClients:
		d.Changes = append(d.Changes, target+": clients: line added: the context is off")
	}
	switch {
	case n.TTLCert > o.TTLCert:
		loosen(fmt.Sprintf("ttl_cert %s → %s", o.TTLCert, n.TTLCert), fmt.Sprintf("certificates live longer: ttl_cert %s → %s", o.TTLCert, n.TTLCert))
	case n.TTLCert < o.TTLCert:
		d.Changes = append(d.Changes, fmt.Sprintf("%s: ttl_cert %s → %s", target, o.TTLCert, n.TTLCert))
	}
}

func pinText(k *config.K8sContext) string {
	if k.Cluster == (cluster.Pin{}) {
		return "none"
	}
	s := fmt.Sprintf("%q ca=sha256:%s", k.Cluster.Server, k.Cluster.CASHA256)
	if k.Cluster.TLSServerName != "" {
		s += fmt.Sprintf(" tls-server-name=%q", k.Cluster.TLSServerName)
	}
	if k.Cluster.ProxyURL != "" {
		s += fmt.Sprintf(" proxy-url=%q", k.Cluster.ProxyURL)
	}
	return s
}

func idText(id config.K8sIdentity) string {
	if id.User == "" {
		return "none"
	}
	s := "CN=" + id.User
	for _, g := range id.Groups {
		s += ",O=" + g
	}
	return s
}
