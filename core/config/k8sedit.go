package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"

	"github.com/atas/nazar/core/k8s/cluster"
)

// K8sContextSpec is the context entry `nazar k8s ca create` writes (k8s
// design).
type K8sContextSpec struct {
	Name     string
	Identity K8sIdentity
	Cluster  cluster.Pin
	Rule     *RuleSpec // the terminal app's login rule; nil = none
}

// AddK8sContext returns src with a new k8s.contexts entry: credential
// ca-cert, the identity, the recorded cluster, the context's own gate
// block, plus rule when it is not nil (as `ssh-key create` and AddSecret
// write theirs). The default ttl_cert is not written. Comments and everything already there are kept; a k8s or
// contexts section that is not a mapping, a name already present (ignoring
// letter case) or anything Parse would refuse in the entry is an error.
func AddK8sContext(src []byte, s K8sContextSpec) ([]byte, error) {
	if !ValidK8sContextName(s.Name) {
		return nil, fmt.Errorf("config: invalid context name %q", s.Name)
	}
	if !k8sSubjectRE.MatchString(s.Identity.User) {
		return nil, errors.New("config: invalid identity user")
	}
	for _, g := range s.Identity.Groups {
		if !k8sSubjectRE.MatchString(g) {
			return nil, errors.New("config: invalid identity group")
		}
	}
	if norm, err := cluster.NormalizeServer(s.Cluster.Server); err != nil || norm != s.Cluster.Server || !caSHA256RE.MatchString(s.Cluster.CASHA256) {
		return nil, errors.New("config: invalid cluster")
	}
	if (s.Cluster.TLSServerName != "" && !tlsNameRE.MatchString(s.Cluster.TLSServerName)) || (s.Cluster.ProxyURL != "" && !validProxyURL(s.Cluster.ProxyURL)) {
		return nil, errors.New("config: invalid cluster")
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("apiVersion: " + APIVersion + "\nkind: " + KindConfig + "\n")
	}
	doc, err := decodeOne(src)
	if err != nil {
		return nil, err
	}
	k8s, err := child(doc.Content[0], "k8s")
	if err != nil {
		return nil, err
	}
	contexts, err := child(k8s, "k8s.contexts")
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(contexts.Content); i += 2 {
		if strings.EqualFold(contexts.Content[i].Value, s.Name) {
			return nil, fmt.Errorf("config: k8s.contexts.%s already exists", contexts.Content[i].Value)
		}
	}
	groups := &yaml.Node{Kind: yaml.SequenceNode}
	for _, g := range s.Identity.Groups {
		groups.Content = append(groups.Content, str(g))
	}
	id := mapNode(str("user"), str(s.Identity.User))
	if len(s.Identity.Groups) > 0 {
		id.Content = append(id.Content, str("groups"), groups)
	}
	cl := mapNode(str("server"), str(s.Cluster.Server), str("ca_sha256"), str(s.Cluster.CASHA256))
	if s.Cluster.TLSServerName != "" {
		cl.Content = append(cl.Content, str("tls_server_name"), str(s.Cluster.TLSServerName))
	}
	if s.Cluster.ProxyURL != "" {
		cl.Content = append(cl.Content, str("proxy_url"), str(s.Cluster.ProxyURL))
	}
	entry := mapNode(str("credential"), str(string(CredentialCACert)), str("identity"), id, str("cluster"), cl, str("gate"), str(string(GateBlock)))
	if s.Rule != nil {
		r, err := ruleNode(*s.Rule)
		if err != nil {
			return nil, err
		}
		entry.Content = append(entry.Content, str("rules"), &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{r}})
	}
	contexts.Content = append(contexts.Content, str(s.Name), entry)
	return encode(doc)
}

// RemoveK8sContext returns src without k8s.contexts.<name> (exact name),
// what `nazar k8s forget` writes; comments elsewhere are kept.
func RemoveK8sContext(src []byte, name string) ([]byte, error) {
	doc, err := decodeOne(src)
	if err != nil {
		return nil, err
	}
	k8s := lookup(doc.Content[0], "k8s")
	if k8s == nil || k8s.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config: no k8s.contexts.%s", name)
	}
	contexts := lookup(k8s, "contexts")
	if contexts == nil || contexts.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config: no k8s.contexts.%s", name)
	}
	for i := 0; i+1 < len(contexts.Content); i += 2 {
		if contexts.Content[i].Value == name {
			contexts.Content = append(contexts.Content[:i], contexts.Content[i+2:]...)
			return encode(doc)
		}
	}
	return nil, fmt.Errorf("config: no k8s.contexts.%s", name)
}
