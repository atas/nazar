package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// AWSEntrySpec is the entry `nazar aws ca create` writes (aws design 8).
type AWSEntrySpec struct {
	Name     string
	Identity AWSIdentity
	Rule     *RuleSpec // the terminal app's login rule; nil = none
}

// AddAWSEntry returns src with a new aws entry: the identity, the entry's
// own gate block, plus rule when it is not nil (as `ssh-key create` and
// AddK8sContext write theirs). No ARNs: the entry is connected by hand once
// AWS trusts the CA (aws design 10, step 4). The default duration is not
// written, and nothing names a program that receives the credential.
// Comments and everything already there are kept; an aws section that is
// not a mapping, a name already present (ignoring letter case) or anything
// Parse would refuse in the entry is an error.
func AddAWSEntry(src []byte, s AWSEntrySpec) ([]byte, error) {
	if !ValidAWSName(s.Name) {
		return nil, fmt.Errorf("config: invalid aws entry name %q", s.Name)
	}
	if !ValidAWSUser(s.Identity.User) {
		return nil, errors.New("config: invalid identity user")
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("apiVersion: " + APIVersion + "\nkind: " + KindConfig + "\n")
	}
	doc, err := decodeOne(src)
	if err != nil {
		return nil, err
	}
	section, err := child(doc.Content[0], "aws")
	if err != nil {
		return nil, err
	}
	for i := 0; i+1 < len(section.Content); i += 2 {
		if strings.EqualFold(section.Content[i].Value, s.Name) {
			return nil, fmt.Errorf("config: aws.%s already exists", section.Content[i].Value)
		}
	}
	entry := mapNode(str("identity"), mapNode(str("user"), str(s.Identity.User)), str("gate"), str(string(GateBlock)))
	if s.Rule != nil {
		r, err := ruleNode(*s.Rule)
		if err != nil {
			return nil, err
		}
		entry.Content = append(entry.Content, str("rules"), &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{r}})
	}
	section.Content = append(section.Content, str(s.Name), entry)
	return encode(doc)
}

// RemoveAWSEntry returns src without aws.<name> (exact name), what `nazar
// aws forget` writes; comments elsewhere are kept.
func RemoveAWSEntry(src []byte, name string) ([]byte, error) {
	doc, err := decodeOne(src)
	if err != nil {
		return nil, err
	}
	section := lookup(doc.Content[0], "aws")
	if section == nil || section.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config: no aws.%s", name)
	}
	for i := 0; i+1 < len(section.Content); i += 2 {
		if section.Content[i].Value == name {
			section.Content = append(section.Content[:i], section.Content[i+2:]...)
			return encode(doc)
		}
	}
	return nil, fmt.Errorf("config: no aws.%s", name)
}
