package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v3"
)

// The edits `nazar ssh-key rule ...` and `nazar ssh-key set` make to
// config.yaml (spec 6, 6.1; Milestone 5). Each takes the file's bytes and
// returns the edited bytes; nothing is written here. Like AddSSHKey they
// keep comments and the order of everything already there, re-indent with
// two spaces, and never guess: a section of an unexpected shape, a rule
// index that does not exist or a matcher that is not one of the forms below
// is an error, so nothing the user wrote is dropped. The result is not
// validated here: the caller parses it (Parse) and refuses it on errors,
// then hands it to the usual staging (tighten applies, loosen waits for the
// login gate, spec 4.8).

// RuleSpec is a new rule. Apps and To hold matcher references (ParseMatcherRef).
type RuleSpec struct {
	Apps   []string
	To     []string
	Scope  Scope         // "" = not written (Parse's default is use)
	Gate   Gate          // required
	Expire time.Duration // 0 = not written
}

// RulePatch changes some fields of an existing rule; nil leaves a field
// as it is. An empty To or a zero Expire removes the field.
type RulePatch struct {
	Apps   []string
	To     *[]string
	Scope  *Scope
	Gate   *Gate
	Expire *time.Duration
}

// PolicyPatch changes a key's own scope, gate and expire; nil leaves a
// field as it is, a zero Expire removes it.
type PolicyPatch struct {
	Scope  *Scope
	Gate   *Gate
	Expire *time.Duration
}

// Entry names the config.yaml entry a rule edit changes:
// ssh_agent.keys.<Name>, secrets.<Name>, k8s.contexts.<Name> or
// aws.<Name>. Its kind is
// the parser's, so no Entry names two sections.
type Entry struct {
	kind entryKind
	Name string
}

func KeyEntry(name string) Entry    { return Entry{entryKey, name} }
func SecretEntry(name string) Entry { return Entry{entrySecret, name} }
func K8sEntry(name string) Entry    { return Entry{entryK8s, name} }
func AWSRef(name string) Entry      { return Entry{entryAWS, name} }

func (e Entry) IsKey() bool    { return e.kind == entryKey }
func (e Entry) IsSecret() bool { return e.kind == entrySecret }
func (e Entry) IsK8s() bool    { return e.kind == entryK8s }
func (e Entry) IsAWS() bool    { return e.kind == entryAWS }

// String is the entry's path, as messages name it.
func (e Entry) String() string {
	switch e.kind {
	case entrySecret:
		return "secrets." + e.Name
	case entryK8s:
		return "k8s.contexts." + e.Name
	case entryAWS:
		return "aws." + e.Name
	}
	return "ssh_agent.keys." + e.Name
}

// valid reports whether e's name may name an entry of its section.
func (e Entry) valid() error {
	switch {
	case e.IsSecret() && !ValidSecretName(e.Name):
		return fmt.Errorf("config: invalid secret name %q", e.Name)
	case e.IsKey() && !ValidKeyName(e.Name):
		return fmt.Errorf("config: invalid key name %q", e.Name)
	case e.IsK8s() && !ValidK8sContextName(e.Name):
		return fmt.Errorf("config: invalid context name %q", e.Name)
	case e.IsAWS() && !ValidAWSName(e.Name):
		return fmt.Errorf("config: invalid aws entry name %q", e.Name)
	}
	return nil
}

// section returns the mapping e's entry lives in (ssh_agent.keys, secrets
// k8s.contexts or aws), creating it with create; nil when it is missing.
// k8s.contexts and aws are never created (editEntry).
func (e Entry) section(root *yaml.Node, create bool) (*yaml.Node, error) {
	if e.IsAWS() {
		if a := lookup(root, "aws"); a != nil && a.Kind == yaml.MappingNode {
			return a, nil
		}
		return nil, nil
	}
	if e.IsK8s() {
		if k := lookup(root, "k8s"); k != nil && k.Kind == yaml.MappingNode {
			if cs := lookup(k, "contexts"); cs != nil && cs.Kind == yaml.MappingNode {
				return cs, nil
			}
		}
		return nil, nil
	}
	if e.IsSecret() {
		if create {
			return child(root, "secrets")
		}
		if s := lookup(root, "secrets"); s != nil && s.Kind == yaml.MappingNode {
			return s, nil
		}
		return nil, nil
	}
	if create {
		agent, err := child(root, "ssh_agent")
		if err != nil {
			return nil, err
		}
		return child(agent, "ssh_agent.keys")
	}
	if agent := lookup(root, "ssh_agent"); agent != nil && agent.Kind == yaml.MappingNode {
		if ks := lookup(agent, "keys"); ks != nil && ks.Kind == yaml.MappingNode {
			return ks, nil
		}
	}
	return nil, nil
}

// ErrNoSuchRule is returned for a rule index the key does not have.
var ErrNoSuchRule = errors.New("config: no such rule")

// ParseMatcherRef checks one --apps / --to value and returns the YAML it
// becomes in a rule. The forms are:
//
//	<name>                  an entry of the top-level apps:, or any / unknown
//	app:<bundle id>         {app: <bundle id>}
//	signed:<team>[:<id>]    {signed: {team: <team>, id: <id>}} (team apple = Apple-signed)
//	path:<absolute path>    {path: <path>}
//
// Values are written as quoted strings whenever their plain form would read
// as anything else, so a bundle id like "true" or "1e3" stays a string.
// Control characters (C0, DEL, C1) and invalid UTF-8 are refused in every
// form: they could end the line or reach a terminal when the rule is shown.
func ParseMatcherRef(ref string) (*yaml.Node, error) {
	if !utf8.ValidString(ref) || strings.ContainsFunc(ref, isControl) {
		return nil, fmt.Errorf("config: matcher %q: control characters are not allowed", ref)
	}
	kind, val, inline := strings.Cut(ref, ":")
	if !inline {
		if ref == "any" || ref == "unknown" || appNameRE.MatchString(ref) {
			return str(ref), nil
		}
		return nil, fmt.Errorf("config: %q is not an app name (%s), any, unknown, app:<bundle-id>, signed:<team>[:<id>] or path:<path>", ref, appNameRE)
	}
	bad := func(why string) (*yaml.Node, error) { return nil, fmt.Errorf("config: matcher %q: %s", ref, why) }
	switch kind {
	case "app":
		if val == "" {
			return bad("needs a bundle id")
		}
		return mapNode(str("app"), str(val)), nil
	case "signed":
		team, id, hasID := strings.Cut(val, ":")
		if team == "" {
			return bad("needs a team ID (or apple)")
		}
		// A second colon says an id follows. Falling back to the team-only
		// form would widen the rule to every binary of that team.
		if hasID && id == "" {
			return bad("needs an id after the team (or drop the second colon)")
		}
		inner := mapNode(str("team"), str(team))
		if hasID {
			inner.Content = append(inner.Content, str("id"), str(id))
		}
		return mapNode(str("signed"), inner), nil
	case "path":
		if !cleanAbs(val) {
			return bad("needs a clean absolute path")
		}
		return mapNode(str("path"), str(val)), nil
	}
	return bad("unknown kind " + kind + " (app, signed or path)")
}

// isControl reports a C0 control, DEL or a C1 control.
func isControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// matcherList is the node for apps: / to:: a list, one reference or several.
func matcherList(refs []string) (*yaml.Node, error) {
	if len(refs) == 0 {
		return nil, errors.New("config: at least one matcher is needed")
	}
	var nodes []*yaml.Node
	for _, r := range refs {
		n, err := ParseMatcherRef(r)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n)
	}
	return &yaml.Node{Kind: yaml.SequenceNode, Content: nodes}, nil
}

// errToAny: any in to: matches every receiver, as no to: does (Parse
// refuses it).
var errToAny = errors.New("config: any in to: is the same as no to:; leave to: out")

// toList is matcherList for to:, without any.
func toList(refs []string) (*yaml.Node, error) {
	for _, r := range refs {
		if r == "any" {
			return nil, errToAny
		}
	}
	return matcherList(refs)
}

// errK8sTo: the program that runs the plugin is the receiver (k8s design 2.1).
var errK8sTo = errors.New("config: k8s rules take no to: the program that runs the plugin receives the credential")

// errAWSTo: the program that runs credential_process is the receiver (aws
// design 6.1).
var errAWSTo = errors.New("config: aws rules take no to: the program that runs credential_process receives the credential")

// AddRule inserts r into e's rules at position at (1-based; 0 appends),
// creating the entry (a secret's with gate: block, as secret add writes it;
// never a k8s context's or an aws entry's, which ca create writes) and its
// rules list when they are missing.
func AddRule(src []byte, e Entry, r RuleSpec, at int) ([]byte, error) {
	if e.IsK8s() && r.To != nil {
		return nil, errK8sTo
	}
	if e.IsAWS() && r.To != nil {
		return nil, errAWSTo
	}
	rule, err := ruleNode(r)
	if err != nil {
		return nil, err
	}
	return editEntry(src, e, true, func(k *yaml.Node) error {
		rules, err := rulesOf(k)
		if err != nil {
			return err
		}
		switch {
		case at == 0:
			at = len(rules.Content) + 1
		case at < 1 || at > len(rules.Content)+1:
			return fmt.Errorf("config: %s has %d rule(s); a new rule can go at 1 to %d, not %d", e, len(rules.Content), len(rules.Content)+1, at)
		}
		rules.Content = append(rules.Content[:at-1], append([]*yaml.Node{rule}, rules.Content[at-1:]...)...)
		return nil
	})
}

// ruleNode is the mapping a new rule is written as.
func ruleNode(r RuleSpec) (*yaml.Node, error) {
	if r.Gate == "" {
		return nil, errors.New("config: a rule needs a gate")
	}
	rule := &yaml.Node{Kind: yaml.MappingNode}
	apps, err := matcherList(r.Apps)
	if err != nil {
		return nil, err
	}
	setField(rule, "apps", apps)
	if len(r.To) > 0 {
		to, err := toList(r.To)
		if err != nil {
			return nil, err
		}
		setField(rule, "to", to)
	}
	// scope and expire do nothing with block and none, expire nothing with
	// scope use: Parse refuses them there, so they are not written.
	if r.Scope != "" && r.Gate.Prompts() {
		setField(rule, "scope", str(string(r.Scope)))
	}
	setField(rule, "gate", str(string(r.Gate)))
	if r.Expire > 0 && r.Gate.Prompts() && r.Scope != "" && r.Scope != ScopeUse {
		setField(rule, "expire", str(FormatDuration(r.Expire)))
	}
	return rule, nil
}

// SetRule changes the fields p sets on rule index (1-based) of e.
func SetRule(src []byte, e Entry, index int, p RulePatch) ([]byte, error) {
	if p.Apps == nil && p.To == nil && p.Scope == nil && p.Gate == nil && p.Expire == nil {
		return nil, errors.New("config: nothing to change")
	}
	if e.IsK8s() && p.To != nil {
		return nil, errK8sTo
	}
	if e.IsAWS() && p.To != nil {
		return nil, errAWSTo
	}
	return editEntry(src, e, false, func(k *yaml.Node) error {
		rule, err := ruleAt(k, e, index)
		if err != nil {
			return err
		}
		if p.Apps != nil {
			apps, err := matcherList(p.Apps)
			if err != nil {
				return err
			}
			setField(rule, "apps", apps)
		}
		if p.To != nil {
			if len(*p.To) == 0 {
				deleteField(rule, "to")
			} else {
				to, err := toList(*p.To)
				if err != nil {
					return err
				}
				setField(rule, "to", to)
			}
		}
		return patchPolicy(rule, p.Scope, p.Gate, p.Expire)
	})
}

// RemoveRule removes rule index (1-based) of e. A rules list left empty
// is removed too.
func RemoveRule(src []byte, e Entry, index int) ([]byte, error) {
	return editEntry(src, e, false, func(k *yaml.Node) error {
		if _, err := ruleAt(k, e, index); err != nil {
			return err
		}
		rules := lookup(k, "rules")
		rules.Content = append(rules.Content[:index-1], rules.Content[index:]...)
		if len(rules.Content) == 0 {
			deleteField(k, "rules")
		}
		return nil
	})
}

// SetKeyPolicy changes key's own scope, gate and expire (what callers no
// rule matches get), creating the key's entry when it is missing. A key's
// own gate applies to every caller, so it can't be none.
func SetKeyPolicy(src []byte, key string, p PolicyPatch) ([]byte, error) {
	if p.Scope == nil && p.Gate == nil && p.Expire == nil {
		return nil, errors.New("config: nothing to change")
	}
	if p.Gate != nil && *p.Gate == GateNone {
		return nil, errors.New("config: a key's own gate applies to every caller, so it can't be none; add a rule with an apps: matcher")
	}
	return editEntry(src, KeyEntry(key), true, func(k *yaml.Node) error {
		if p.Gate == nil && lookup(k, "gate") == nil {
			return fmt.Errorf("config: ssh_agent.keys.%s has no gate of its own; give --gate too", key)
		}
		return patchPolicy(k, p.Scope, p.Gate, p.Expire)
	})
}

// patchPolicy sets or removes scope, gate and expire on mapping m.
func patchPolicy(m *yaml.Node, scope *Scope, gate *Gate, expire *time.Duration) error {
	if scope != nil {
		setField(m, "scope", str(string(*scope)))
	}
	if gate != nil {
		if *gate == "" {
			return errors.New("config: empty gate")
		}
		setField(m, "gate", str(string(*gate)))
	}
	if expire != nil {
		if *expire <= 0 {
			deleteField(m, "expire")
		} else {
			setField(m, "expire", str(FormatDuration(*expire)))
		}
	}
	// scope and expire do nothing with block and none, expire nothing with
	// scope use: Parse refuses them there, so they are never left there.
	if g := lookup(m, "gate"); g != nil && g.Kind == yaml.ScalarNode && !Gate(g.Value).Prompts() {
		deleteField(m, "scope")
		deleteField(m, "expire")
	}
	if s := lookup(m, "scope"); s == nil || s.Kind == yaml.ScalarNode && Scope(s.Value) == ScopeUse {
		deleteField(m, "expire")
	}
	return nil
}

// editEntry parses src (an empty file starts as a bare Config), finds e's
// entry (creating its sections and, with create, the entry as an empty
// mapping), runs fn on the entry's mapping and encodes the result. A k8s
// context is never created: it needs its cluster and identity, which only
// k8s ca create writes; nor is an aws entry, whose identity aws ca create
// writes.
func editEntry(src []byte, e Entry, create bool, fn func(k *yaml.Node) error) ([]byte, error) {
	if err := e.valid(); err != nil {
		return nil, err
	}
	create = create && !e.IsK8s() && !e.IsAWS()
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("apiVersion: " + APIVersion + "\nkind: " + KindConfig + "\n")
	}
	doc, err := decodeOne(src)
	if err != nil {
		return nil, err
	}
	section, err := e.section(doc.Content[0], create)
	if err != nil {
		return nil, err
	}
	// The entry is looked up by its exact name (names may contain dots, so
	// child's dotted paths can't name it).
	var k *yaml.Node
	if section != nil {
		k = lookup(section, e.Name)
	}
	switch {
	case k == nil && create:
		k = &yaml.Node{Kind: yaml.MappingNode}
		if e.IsSecret() {
			// As secret add writes it: every caller no rule matches is
			// blocked, never defaults.fallback.
			k.Content = []*yaml.Node{scalar("gate"), scalar(string(GateBlock))}
		}
		section.Content = append(section.Content, scalar(e.Name), k)
	case k == nil:
		return nil, fmt.Errorf("config: there is no %s", e)
	case k.Kind == yaml.ScalarNode && k.Tag == "!!null":
		k.Kind, k.Tag, k.Value, k.Style = yaml.MappingNode, "", "", 0
	case k.Kind != yaml.MappingNode:
		return nil, fmt.Errorf("config: %s is not a mapping", e)
	}
	if err := fn(k); err != nil {
		return nil, err
	}
	return encode(doc)
}

// decodeOne decodes src as exactly one YAML document whose top level is a
// mapping. A stream with more documents is refused, as Parse refuses it:
// an edit that kept only the first would drop the rest.
func decodeOne(src []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(src))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("config: only one YAML document is allowed")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("config: the top level must be a mapping")
	}
	return &doc, nil
}

// rulesOf returns the key's rules sequence, creating it when it is missing
// or null.
func rulesOf(k *yaml.Node) (*yaml.Node, error) {
	rules := lookup(k, "rules")
	switch {
	case rules == nil:
		rules = &yaml.Node{Kind: yaml.SequenceNode}
		setField(k, "rules", rules)
	case rules.Kind == yaml.ScalarNode && rules.Tag == "!!null":
		rules.Kind, rules.Tag, rules.Value, rules.Style = yaml.SequenceNode, "", "", 0
	case rules.Kind != yaml.SequenceNode:
		return nil, errors.New("config: rules is not a list")
	}
	return rules, nil
}

// ruleAt returns rule index (1-based) of e's mapping k, which must be a mapping.
func ruleAt(k *yaml.Node, e Entry, index int) (*yaml.Node, error) {
	rules := lookup(k, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode || index < 1 || index > len(rules.Content) {
		n := 0
		if rules != nil && rules.Kind == yaml.SequenceNode {
			n = len(rules.Content)
		}
		return nil, fmt.Errorf("%w: %s has %d rule(s), not a rule %d", ErrNoSuchRule, e, n, index)
	}
	rule := rules.Content[index-1]
	if rule.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config: %s rule %d is not a mapping", e, index)
	}
	return rule, nil
}

// setField sets key to v in mapping m, replacing the value in place (its
// comments kept) or appending the pair.
func setField(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			v.LineComment = m.Content[i+1].LineComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, scalar(key), v)
}

// deleteField removes key from mapping m.
func deleteField(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// str is a string scalar: the encoder quotes it whenever its plain form
// would read as another type.
func str(v string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v} }

func mapNode(kv ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Content: kv}
}

// FormatDuration writes d the way a person would in config.yaml: whole days
// as "7d" (while ParseDuration accepts the count, up to maxDays), otherwise
// Go's form without zero units ("8h", "1h30m", "90s").
func FormatDuration(d time.Duration) string {
	if days := d / (24 * time.Hour); days > 0 && days <= maxDays && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", days)
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
