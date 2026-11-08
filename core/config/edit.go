package config

import (
	"bytes"
	"errors"
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

// AddSSHKey returns src with a new ssh_agent.keys entry `name: {scope, gate}`
// (what `nazar ssh-key create` writes, spec 4.2). Comments and the order of
// everything already there are kept; the file is re-indented with two
// spaces. src may be empty (a file that does not exist yet).
//
// The edit never guesses: a document that is not a mapping, an ssh_agent or
// keys section that is not a mapping (a list, a scalar), or a name already
// present is refused, so nothing the user wrote is dropped or overwritten.
// The entry carries exactly the fields Parse keeps for its gate: scope only
// for a prompting gate, expire only when the scope remembers something.
func AddSSHKey(src []byte, name string, pol Policy) ([]byte, error) {
	if !ValidKeyName(name) {
		return nil, fmt.Errorf("config: invalid key name %q", name)
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("apiVersion: " + APIVersion + "\nkind: " + KindConfig + "\n")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config: the top level must be a mapping")
	}
	agent, err := child(doc.Content[0], "ssh_agent")
	if err != nil {
		return nil, err
	}
	keys, err := child(agent, "ssh_agent.keys")
	if err != nil {
		return nil, err
	}
	if lookup(keys, name) != nil {
		return nil, fmt.Errorf("config: ssh_agent.keys.%s already exists", name)
	}
	entry := &yaml.Node{Kind: yaml.MappingNode}
	if pol.Gate.Prompts() {
		entry.Content = append(entry.Content, scalar("scope"), scalar(string(pol.Scope)))
	}
	entry.Content = append(entry.Content, scalar("gate"), scalar(string(pol.Gate)))
	if pol.Gate.Prompts() && pol.Scope != ScopeUse && pol.Expire > 0 {
		entry.Content = append(entry.Content, scalar("expire"), scalar(pol.Expire.String()))
	}
	keys.Content = append(keys.Content, scalar(name), entry)
	return encode(&doc)
}

// AddSecret returns src with a new secrets entry for name (what `nazar
// secret add` writes for a name without one, as AddSSHKey for
// `ssh-key create`): the secret's own gate block, plus rule when it is not
// nil. Comments and the order of everything already there are kept; a
// secrets section that is not a mapping, a name already present or an
// invalid name or rule is refused. The name is written as a string, so one
// like "true" or "123" stays a name.
func AddSecret(src []byte, name string, rule *RuleSpec) ([]byte, error) {
	if !ValidSecretName(name) {
		return nil, fmt.Errorf("config: invalid secret name %q", name)
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("apiVersion: " + APIVersion + "\nkind: " + KindConfig + "\n")
	}
	doc, err := decodeOne(src)
	if err != nil {
		return nil, err
	}
	sec, err := child(doc.Content[0], "secrets")
	if err != nil {
		return nil, err
	}
	if lookup(sec, name) != nil {
		return nil, fmt.Errorf("config: secrets.%s already exists", name)
	}
	entry := mapNode(str("gate"), str(string(GateBlock)))
	if rule != nil {
		r, err := ruleNode(*rule)
		if err != nil {
			return nil, err
		}
		entry.Content = append(entry.Content, str("rules"), &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{r}})
	}
	sec.Content = append(sec.Content, str(name), entry)
	return encode(doc)
}

// encode writes doc the one way nazar writes config.yaml: block style
// throughout (one field per line, every list item on its own `- ` line),
// indented by two spaces, comments kept. A flow-style part (`{…}`, `[…]`)
// that a hand edit left is rewritten in block style too, so the file never
// mixes the two.
func encode(doc *yaml.Node) ([]byte, error) {
	blockStyle(doc)
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return out.Bytes(), nil
}

// blockStyle clears flow style on n and everything under it.
func blockStyle(n *yaml.Node) {
	if n == nil {
		return
	}
	n.Style &^= yaml.FlowStyle
	for _, c := range n.Content {
		blockStyle(c)
	}
}

func scalar(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: v} }

// lookup returns the value node for key in mapping m, or nil.
func lookup(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// child returns the mapping under the last path element of path in m,
// creating it when it is absent or null. An existing value of any other
// shape is an error: the edit must not replace what the user wrote.
func child(m *yaml.Node, path string) (*yaml.Node, error) {
	key := path
	if i := bytes.LastIndexByte([]byte(path), '.'); i >= 0 {
		key = path[i+1:]
	}
	if v := lookup(m, key); v != nil {
		switch {
		case v.Kind == yaml.MappingNode:
			return v, nil
		case v.Kind == yaml.ScalarNode && v.Tag == "!!null":
			v.Kind, v.Tag, v.Value, v.Style = yaml.MappingNode, "", "", 0
			return v, nil
		}
		return nil, fmt.Errorf("config: %s is not a mapping", path)
	}
	v := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, scalar(key), v)
	return v, nil
}
