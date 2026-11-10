package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/atas/nazar/core/secrets/envpolicy"
	yaml "go.yaml.in/yaml/v3"
)

// Parse decodes and validates a config file. The returned Config is nil
// exactly when Problems has errors. Warnings never block a config.
//
// Parse keeps no state between calls, so it is safe to call concurrently.
func Parse(data []byte, env Env) (*Config, Problems) {
	return read(&parser{env: env}, data)
}

// read parses data with p and, without errors, sets Raw and Hash.
func read(p *parser, data []byte) (*Config, Problems) {
	c := p.parse(data)
	if p.probs.HasErrors() {
		return nil, p.probs
	}
	sum := sha256.Sum256(data)
	c.Raw = append([]byte(nil), data...)
	c.Hash = hex.EncodeToString(sum[:])
	return c, p.probs
}

type parser struct {
	env   Env
	probs Problems
	// legacy reads the old forms (migrate.go) as the builds that accepted
	// them did, with a warning each, and records in fixes the edits of doc
	// (the document read) that rewrite them with the same meaning. Only
	// Migrate and ParseApproved set it.
	legacy bool
	fixes  []func()
	doc    *yaml.Node
}

// oldForm reports a form builds before accepted (migrate.go): an error,
// or, read the old way, a warning, with fix (nil when no rewrite keeps the
// meaning) recorded for Migrate.
func (p *parser) oldForm(n *yaml.Node, path string, fix func(), format string, args ...any) {
	if !p.legacy {
		p.errorf(n, path, format, args...)
		return
	}
	p.warnf(n, path, format, args...)
	if fix != nil {
		p.fixes = append(p.fixes, fix)
	}
}

func (p *parser) errorf(n *yaml.Node, path, format string, args ...any) {
	p.add(SevError, n, path, format, args...)
}

func (p *parser) warnf(n *yaml.Node, path, format string, args ...any) {
	p.add(SevWarning, n, path, format, args...)
}

func (p *parser) add(sev Severity, n *yaml.Node, path, format string, args ...any) {
	line := 0
	if n != nil {
		line = n.Line
	}
	p.probs = append(p.probs, Problem{Severity: sev, Path: path, Line: line, Message: fmt.Sprintf(format, args...)})
}

// errorsSince reports whether an error was added after the given length.
func (p *parser) errorsSince(n int) bool {
	return len(p.probs) > n && p.probs[n:].HasErrors()
}

func (p *parser) parse(data []byte) *Config {
	if len(data) > MaxFileSize {
		p.errorf(nil, "", "file is larger than %d bytes", MaxFileSize)
		return nil
	}
	root := p.document(data)
	if root == nil {
		return nil
	}
	c := &Config{
		Defaults: Defaults{Timeout: DefaultTimeout, Fallback: Policy{Scope: ScopeUse, Gate: GateBlock}, TrustedPath: DefaultTrustedPath()},
		Audit:    Audit{Args: ArgsRedacted},
		Apps:     map[string]Matcher{},
		SSHAgent: SSHAgent{Keys: map[string]*Key{}},
		Secrets:  map[string]*Secret{},
		K8s:      map[string]*K8sContext{},
		AWS:      map[string]*AWSEntry{},
	}
	// apiVersion and kind are checked before anything else: nazar never
	// guesses at a schema it doesn't know, so nothing else in the file is
	// reported until they are right.
	c.APIVersion, c.Kind = p.versionAndKind(root)
	if p.probs.HasErrors() {
		return nil
	}
	// The whole tree, the unimplemented sections included, must mean what
	// it says: no aliases, merge keys, repeated or non-string keys.
	p.checkTree(root, "")

	fields := p.mapping(root, "", "apiVersion", "kind", "defaults", "audit", "apps", "ssh_agent", "secrets", "k8s", "aws")
	if n := fields["defaults"]; n != nil {
		p.defaults(n, c)
	}
	if n := fields["audit"]; n != nil {
		p.audit(n, c)
	}
	if n := fields["apps"]; n != nil {
		p.apps(n, c)
	}
	c.SSHAgent.Socket = p.expand(DefaultSocket)
	if n := fields["ssh_agent"]; n != nil {
		p.sshAgent(n, c)
	}
	if n := fields["secrets"]; n != nil {
		p.secrets(n, c)
	}
	if n := fields["k8s"]; n != nil {
		p.k8s(n, c)
	}
	if n := fields["aws"]; n != nil {
		p.aws(n, c)
	}
	p.checkRuleOrder(c)
	return c
}

// document decodes exactly one YAML document and returns its top-level
// mapping, or nil after reporting why.
func (p *parser) document(data []byte) *yaml.Node {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			p.errorf(nil, "apiVersion", "file is empty; it must start with apiVersion: %s", APIVersion)
		} else {
			p.errorf(nil, "", "invalid YAML: %v", err)
		}
		return nil
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		p.errorf(&extra, "", "only one YAML document is allowed")
		return nil
	} else if !errors.Is(err, io.EOF) {
		p.errorf(nil, "", "invalid YAML: %v", err)
		return nil
	}
	p.doc = &doc
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		p.errorf(root, "", "top level must be a mapping starting with apiVersion: %s", APIVersion)
		return nil
	}
	return root
}

// versionAndKind reads the top-level apiVersion and kind. Each must appear
// exactly once as a plain string with the expected value; a repeat is an
// error rather than letting either copy win.
func (p *parser) versionAndKind(root *yaml.Node) (api, kind string) {
	var apiNode, kindNode *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			continue
		}
		switch k.Value {
		case "apiVersion":
			if apiNode != nil {
				p.errorf(k, "apiVersion", "apiVersion is defined more than once")
			} else {
				apiNode = v
			}
		case "kind":
			if kindNode != nil {
				p.errorf(k, "kind", "kind is defined more than once")
			} else {
				kindNode = v
			}
		}
	}
	api = p.str(apiNode, "apiVersion")
	kind = p.str(kindNode, "kind")
	switch {
	case apiNode == nil:
		p.errorf(root, "apiVersion", "missing; this nazar understands apiVersion: %s", APIVersion)
	case api != APIVersion:
		p.errorf(apiNode, "apiVersion", "unknown apiVersion %q; this nazar understands %s", api, APIVersion)
	}
	switch {
	case kindNode == nil:
		p.errorf(root, "kind", "missing; expected kind: %s", KindConfig)
	case kind != KindConfig:
		p.errorf(kindNode, "kind", "unknown kind %q; expected %s", kind, KindConfig)
	}
	return api, kind
}

// checkTree walks the whole document once and refuses what would make the
// file mean something other than what it says: aliases (including alias
// bombs, which are never expanded), merge keys, non-string keys and repeated
// keys, before any section parser reads the tree. Alias targets
// are not followed, so a bomb costs nothing.
func (p *parser) checkTree(n *yaml.Node, path string) {
	switch n.Kind {
	case yaml.AliasNode:
		p.errorf(n, path, "aliases (*%s) are not allowed; write the value out", n.Value)
	case yaml.MappingNode:
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" {
				p.errorf(k, path, "keys must be plain strings (no merge keys, aliases or collections)")
				p.checkTree(v, path)
				continue
			}
			if seen[k.Value] {
				p.errorf(k, join(path, k.Value), "%q is already defined", k.Value)
			}
			seen[k.Value] = true
			p.checkTree(v, join(path, k.Value))
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			p.checkTree(item, fmt.Sprintf("%s[%d]", path, i+1))
		}
	}
}

// mapping checks n is a mapping whose keys are all in allowed and returns
// key → value node. A non-mapping yields nil after an error.
func (p *parser) mapping(n *yaml.Node, path string, allowed ...string) map[string]*yaml.Node {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	out := map[string]*yaml.Node{}
	for _, kv := range p.pairs(n, path) {
		if !ok[kv[0].Value] {
			p.errorf(kv[0], join(path, kv[0].Value), "unknown field %q", kv[0].Value)
			continue
		}
		out[kv[0].Value] = kv[1]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return out
}

// pairs returns the key/value nodes of a mapping, first occurrence of each
// key. Non-string, merge and repeated keys were already reported by
// checkTree, which runs over the whole document before any section is read;
// here they are only skipped.
func (p *parser) pairs(n *yaml.Node, path string) [][2]*yaml.Node {
	if n.Kind != yaml.MappingNode {
		p.errorf(n, path, "must be a mapping")
		return nil
	}
	seen := map[string]bool{}
	var out [][2]*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" || seen[k.Value] {
			continue
		}
		seen[k.Value] = true
		out = append(out, [2]*yaml.Node{k, v})
	}
	return out
}

// str returns a scalar's text. nil (absent) is "", and null or any
// non-scalar is an error so it is never mistaken for an empty value.
func (p *parser) str(n *yaml.Node, path string) string {
	if n == nil {
		return ""
	}
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		p.errorf(n, path, "must be a string")
		return ""
	}
	return n.Value
}

// duration parses a scalar with ParseDuration; 0 means absent or invalid
// (already reported).
func (p *parser) duration(n *yaml.Node, path string) time.Duration {
	before := len(p.probs)
	s := p.str(n, path)
	if p.errorsSince(before) {
		return 0
	}
	d, err := ParseDuration(s)
	if err != nil {
		p.errorf(n, path, "%v", err)
		return 0
	}
	return d
}

// expand replaces a leading ~ or ~/ with the home directory. "~user" forms
// are left alone and fail the absolute-path check.
func (p *parser) expand(s string) string {
	if s == "~" {
		return p.env.Home
	}
	if strings.HasPrefix(s, "~/") {
		return filepath.Join(p.env.Home, s[2:])
	}
	return s
}

func join(path, field string) string {
	if path == "" {
		return field
	}
	return path + "." + field
}

func (p *parser) defaults(n *yaml.Node, c *Config) {
	f := p.mapping(n, "defaults", "timeout", "fallback", "trustedPath")
	if f == nil {
		return
	}
	if tp := f["trustedPath"]; tp != nil {
		if dirs, ok := p.trustedPath(tp, "defaults.trustedPath"); ok {
			c.Defaults.TrustedPath = dirs
		}
	}
	if t := f["timeout"]; t != nil {
		d := p.duration(t, "defaults.timeout")
		if d > 0 && (d < time.Second || d > 10*time.Minute) {
			p.errorf(t, "defaults.timeout", "must be between 1s and 10m, not %s", d)
		} else if d > 0 {
			c.Defaults.Timeout = d
		}
	}
	if fb := f["fallback"]; fb != nil {
		if pol, ok := p.policy(fb, "defaults.fallback"); ok {
			if pol.Gate == GateNone {
				p.errorf(fb, "defaults.fallback.gate", "gate: none would let every caller use every key silently; use a rule with an apps: matcher")
			} else {
				c.Defaults.Fallback = pol
			}
		}
	}
}

// trustedPath reads defaults.trustedPath (secrets design 6.3.3): clean
// absolute directories (~ expanded), each once, none holding ":", which
// would split it in two as the receiver's PATH.
func (p *parser) trustedPath(n *yaml.Node, path string) ([]string, bool) {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		p.errorf(n, path, "must be a non-empty list of directories")
		return nil, false
	}
	before := len(p.probs)
	var out []string
	for _, it := range n.Content {
		at := len(p.probs)
		raw := p.str(it, path)
		if p.errorsSince(at) {
			continue
		}
		d := p.expand(raw)
		switch {
		case !filepath.IsAbs(d) || filepath.Clean(d) != d || strings.ContainsAny(d, "\x00\n"):
			p.errorf(it, path, "must be a clean absolute path, not %q", raw)
		case strings.Contains(d, ":"):
			p.errorf(it, path, "%q holds \":\", which would split it in two as the receiver's PATH", raw)
		case slices.Contains(out, d):
			p.errorf(it, path, "%q is listed twice", raw)
		default:
			out = append(out, d)
		}
	}
	return out, !p.errorsSince(before)
}

func (p *parser) audit(n *yaml.Node, c *Config) {
	f := p.mapping(n, "audit", "args")
	if f == nil {
		return
	}
	if a := f["args"]; a != nil {
		before := len(p.probs)
		v := ArgsMode(p.str(a, "audit.args"))
		if p.errorsSince(before) {
			return
		}
		switch v {
		case ArgsRedacted, ArgsNone:
			c.Audit.Args = v
		default:
			p.errorf(a, "audit.args", "must be redacted or none, not %q", v)
		}
	}
}

// policy reads a mapping that holds only scope/gate/expire (defaults.fallback).
func (p *parser) policy(n *yaml.Node, path string) (Policy, bool) {
	f := p.mapping(n, path, "scope", "gate", "expire")
	if f == nil {
		return Policy{}, false
	}
	return p.policyFields(f, n, path)
}

// policyFields reads scope/gate/expire from the fields of mapping n. The
// gate is required. scope and expire next to none or block, and expire
// next to scope use, do nothing: an error (an old form, which Migrate
// drops).
func (p *parser) policyFields(f map[string]*yaml.Node, n *yaml.Node, path string) (Policy, bool) {
	pol := Policy{Scope: ScopeUse}
	before := len(p.probs)
	if g := f["gate"]; g != nil {
		at := len(p.probs)
		v := Gate(p.str(g, join(path, "gate")))
		switch {
		case p.errorsSince(at):
		case v == GateLogin, v == GateDialog, v == GateNone, v == GateBlock:
			pol.Gate = v
		default:
			p.errorf(g, join(path, "gate"), "must be login, dialog, none or block, not %q", v)
		}
	} else {
		p.errorf(n, join(path, "gate"), "missing gate (login, dialog, none or block)")
	}
	if s := f["scope"]; s != nil {
		at := len(p.probs)
		v := Scope(p.str(s, join(path, "scope")))
		switch {
		case p.errorsSince(at):
		case v == ScopeUse, v == ScopeSession, v == ScopeApp:
			pol.Scope = v
		default:
			p.errorf(s, join(path, "scope"), "must be use, session or app, not %q", v)
		}
	}
	if e := f["expire"]; e != nil {
		pol.Expire = p.duration(e, join(path, "expire"))
	}
	drop := func(k string) func() { return func() { deleteField(n, k) } }
	if pol.Gate == GateNone || pol.Gate == GateBlock {
		for _, k := range []string{"scope", "expire"} {
			if f[k] != nil {
				p.oldForm(f[k], join(path, k), drop(k), "does nothing with gate: %s; remove it", pol.Gate)
			}
		}
		pol.Scope, pol.Expire = ScopeUse, 0
	}
	if pol.Gate.Prompts() && pol.Scope == ScopeUse && f["expire"] != nil {
		p.oldForm(f["expire"], join(path, "expire"), drop("expire"), "does nothing with scope: use (nothing is remembered); remove it")
		pol.Expire = 0
	}
	return pol, !p.errorsSince(before)
}

func (p *parser) apps(n *yaml.Node, c *Config) {
	for _, kv := range p.pairs(n, "apps") {
		k, v := kv[0], kv[1]
		path := "apps." + k.Value
		if !appNameRE.MatchString(k.Value) {
			p.errorf(k, path, "app names must match %s", appNameRE)
			continue
		}
		if k.Value == "any" || k.Value == "unknown" {
			p.errorf(k, path, "%q is built in and can't be redefined", k.Value)
			continue
		}
		if m, ok := p.inlineMatcher(v, path); ok {
			m.Name = k.Value
			c.Apps[k.Value] = m
		}
	}
}

// inlineMatcher parses a mapping such as {signed: {team, id}}, {app: X, team: Y},
// {path: P} or {command: [...]}.
func (p *parser) inlineMatcher(n *yaml.Node, path string) (Matcher, bool) {
	f := p.mapping(n, path, "signed", "app", "team", "path", "command", "cwd")
	if f == nil {
		return Matcher{}, false
	}
	if f["cwd"] != nil {
		p.errorf(f["cwd"], join(path, "cwd"), "the cwd: field is not in this version (a nazar run receiver runs in /)")
		return Matcher{}, false
	}
	kinds := 0
	for _, k := range []string{"signed", "app", "path", "command"} {
		if f[k] != nil {
			kinds++
		}
	}
	if kinds != 1 {
		p.errorf(n, path, "a matcher needs exactly one of signed, app, path or command")
		return Matcher{}, false
	}
	if f["team"] != nil && f["app"] == nil {
		p.errorf(f["team"], join(path, "team"), "team: belongs with app: (use signed: {team, id} otherwise)")
		return Matcher{}, false
	}
	before := len(p.probs)
	var m Matcher
	switch {
	case f["signed"] != nil && p.env.NoCodeSigning:
		p.errorf(f["signed"], path, "signed: needs macOS code signatures; on Linux name the program's file with path: or a desktop app with app:")
		return Matcher{}, false
	case f["app"] != nil && f["team"] != nil && p.env.NoCodeSigning:
		p.errorf(f["team"], path, "team: is macOS only; on Linux an app: rule pins the app's executable when the change is approved")
		return Matcher{}, false
	case f["signed"] != nil:
		sf := p.mapping(f["signed"], join(path, "signed"), "team", "id")
		if sf == nil {
			return Matcher{}, false
		}
		m = Matcher{Kind: MatchSigned, Team: p.str(sf["team"], join(path, "signed.team")), ID: p.str(sf["id"], join(path, "signed.id"))}
		if m.Team == "" && !p.errorsSince(before) {
			p.errorf(f["signed"], join(path, "signed.team"), "team is required (a team ID, or apple)")
		}
		p.appleTeam(m.Team, sf["team"], join(path, "signed.team"))
	case f["app"] != nil:
		m = Matcher{Kind: MatchApp, ID: p.str(f["app"], join(path, "app")), Team: p.str(f["team"], join(path, "team"))}
		if m.ID == "" && !p.errorsSince(before) {
			p.errorf(f["app"], join(path, "app"), "bundle id is required")
		}
		p.appleTeam(m.Team, f["team"], join(path, "team"))
	case f["path"] != nil:
		m = Matcher{Kind: MatchPath, Path: p.str(f["path"], join(path, "path"))}
		if !p.errorsSince(before) && !cleanAbs(m.Path) {
			p.errorf(f["path"], join(path, "path"), "must be a clean absolute path, not %q", m.Path)
		}
	default:
		cn := f["command"]
		if cn.Kind != yaml.SequenceNode || len(cn.Content) == 0 {
			p.errorf(cn, join(path, "command"), "must be a non-empty list of arguments")
			return Matcher{}, false
		}
		m = Matcher{Kind: MatchCommand}
		for _, a := range cn.Content {
			m.Command = append(m.Command, p.str(a, join(path, "command")))
		}
		if !p.errorsSince(before) {
			p.command(cn, join(path, "command"), m.Command)
		}
	}
	if p.errorsSince(before) {
		return Matcher{}, false
	}
	return m, true
}

// appleTeam refuses a team spelled apple in another letter case: teams are
// matched exactly, so it matches nothing, where apple is Apple's. An old
// form with no rewrite: apple would match Apple's programs.
func (p *parser) appleTeam(team string, n *yaml.Node, path string) {
	if team != "apple" && strings.EqualFold(team, "apple") {
		p.oldForm(n, path, nil, "%q matches nothing; Apple's team is written apple", team)
	}
}

// command checks a command: matcher's argv as text (secrets design 6.3.6,
// 6.3.7; 6.3 D6): argv[0] is a bare name, resolved through
// defaults.trustedPath, or a clean absolute path; no argument is empty or
// holds NUL; and every file element is a clean absolute path, because the
// receiver runs in / and a relative one would never mean what was meant.
func (p *parser) command(n *yaml.Node, path string, argv []string) {
	a0 := argv[0]
	if a0 == "" || a0 == "." || a0 == ".." || (strings.Contains(a0, "/") && (!filepath.IsAbs(a0) || filepath.Clean(a0) != a0)) {
		p.errorf(n.Content[0], path, "argv[0] must be a bare name (found through defaults.trustedPath) or a clean absolute path, not %q", a0)
		return
	}
	for i, a := range argv {
		switch {
		case a == "":
			p.errorf(n.Content[i], path, "an empty argument can't be matched; remove it")
			return
		case strings.ContainsRune(a, 0):
			p.errorf(n.Content[i], path, "an argument holds NUL, which no command line can carry")
			return
		}
	}
	interp := Interpreter(filepath.Base(a0))
	if interp {
		if why := InterpreterStdin(argv); why != "" {
			p.errorf(n, path, "%s", why)
			return
		}
	}
	for _, fe := range FileElements(argv, interp) {
		at := n.Content[fe.Index]
		switch {
		case strings.HasPrefix(fe.Path, "~"):
			p.errorf(at, path, "%q: ~ is not expanded in command:; write the absolute path", fe.Path)
		case !filepath.IsAbs(fe.Path):
			p.errorf(at, path, "%q is relative: the receiver runs in /; write the absolute path", fe.Path)
		case filepath.Clean(fe.Path) != fe.Path:
			p.errorf(at, path, "%q must be a clean absolute path", fe.Path)
		}
	}
}

// refs parses an apps:/to: value (field names which): a list of names and
// inline matchers. One shape only: a name or a matcher on its own is an
// old form, read as a list of one only the old way.
func (p *parser) refs(n *yaml.Node, path, field string, c *Config) []Matcher {
	var items []*yaml.Node
	switch {
	case n.Kind == yaml.SequenceNode:
		items = n.Content
		if len(items) == 0 {
			p.errorf(n, path, "must not be empty")
		}
	default:
		p.oldForm(n, path, func() {
			item := *n
			*n = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{&item}}
		}, "must be a list, e.g. %s: [iterm] or %s: [{app: com.example.app}]", field, field)
		if !p.legacy {
			return nil
		}
		items = []*yaml.Node{n}
	}
	var out []Matcher
	for _, it := range items {
		switch {
		case it.Kind == yaml.ScalarNode && it.Tag != "!!null":
			name := it.Value
			switch name {
			case "any":
				out = append(out, Matcher{Kind: MatchAny, Name: "any"})
			case "unknown":
				out = append(out, Matcher{Kind: MatchUnknown, Name: "unknown"})
			default:
				m, ok := c.Apps[name]
				if !ok {
					p.errorf(it, path, "unknown app %q (define it under apps:)", name)
					continue
				}
				out = append(out, m)
			}
		case it.Kind == yaml.MappingNode:
			if m, ok := p.inlineMatcher(it, path); ok {
				out = append(out, m)
			}
		default:
			p.errorf(it, path, "must be an app name or a matcher")
		}
	}
	return out
}

func (p *parser) sshAgent(n *yaml.Node, c *Config) {
	f := p.mapping(n, "ssh_agent", "socket", "keys")
	if f == nil {
		return
	}
	if s := f["socket"]; s != nil {
		before := len(p.probs)
		sock := p.expand(p.str(s, "ssh_agent.socket"))
		switch {
		case p.errorsSince(before):
		case !filepath.IsAbs(sock):
			p.errorf(s, "ssh_agent.socket", "must be an absolute path or start with ~/")
		default:
			c.SSHAgent.Socket = filepath.Clean(sock)
		}
	}
	kn := f["keys"]
	if kn == nil {
		return
	}
	// Key names become keys/<name>.pub on a case-insensitive APFS home, so
	// "Github" and "github" would share one file while staying two Secure
	// Enclave keys with different policies (whichever exports last wins).
	seenFold := map[string]string{}
	for _, kv := range p.pairs(kn, "ssh_agent.keys") {
		k, v := kv[0], kv[1]
		path := "ssh_agent.keys." + k.Value
		if !ValidKeyName(k.Value) {
			p.errorf(k, path, "key names must match %s (they become file names)", keyNameRE)
			continue
		}
		if prev, dup := seenFold[strings.ToLower(k.Value)]; dup {
			p.errorf(k, path, "key names must differ in more than letter case (keys/<name>.pub lives on a case-insensitive file system; %q already defined)", prev)
			continue
		}
		seenFold[strings.ToLower(k.Value)] = k.Value
		if key := p.key(k.Value, v, path, c); key != nil {
			c.SSHAgent.Keys[k.Value] = key
		}
	}
}

// entryKind says whose rules are read: ssh keys, secrets and k8s contexts
// share rules, scope, gate and expire (secrets design 4, k8s design 3), and
// a few checks are stricter for a secret or a context, whose value or
// credential leaves nazar where a key never leaves the chip.
type entryKind int

const (
	entryKey entryKind = iota
	entrySecret
	entryK8s // a k8s context: no to:, and the secret's stricter none
	entryAWS // an aws entry: as a k8s context
)

// key parses one ssh_agent.keys entry. A bare "name:" is a key with no
// rules and no own policy, so defaults.fallback applies to every caller.
func (p *parser) key(name string, n *yaml.Node, path string, c *Config) *Key {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return &Key{Name: name}
	}
	f := p.mapping(n, path, "rules", "scope", "gate", "expire")
	if f == nil {
		return nil
	}
	rules, own, ok := p.entry(f, n, path, c, entryKey)
	if !ok {
		return nil
	}
	return &Key{Name: name, Rules: rules, Own: own}
}

// entry reads what a key, a secret and a context share: the entry's own
// scope/gate/expire and its rules. ok is false after an error that drops
// the entry.
func (p *parser) entry(f map[string]*yaml.Node, n *yaml.Node, path string, c *Config, kind entryKind) ([]Rule, *Policy, bool) {
	var own *Policy
	if f["gate"] != nil {
		if pol, ok := p.policyFields(f, n, path); ok {
			if pol.Gate == GateNone {
				if kind == entryK8s {
					p.errorf(f["gate"], join(path, "gate"), "a context's own gate applies to every caller, so it can't be none; use a rule with an apps: matcher")
				} else if kind == entryAWS {
					p.errorf(f["gate"], join(path, "gate"), "an aws entry's own gate applies to every caller, so it can't be none; use a rule with an apps: matcher")
				} else if kind == entrySecret {
					p.errorf(f["gate"], join(path, "gate"), "a secret's own gate applies to every caller, so it can't be none; use a rule with an apps: matcher")
				} else {
					p.errorf(f["gate"], join(path, "gate"), "a key's own gate applies to every caller, so it can't be none; use a rule with an apps: matcher")
				}
				return nil, nil, false
			}
			own = &pol
		}
	} else if f["scope"] != nil || f["expire"] != nil {
		p.errorf(n, path, "scope/expire without gate")
		return nil, nil, false
	}
	var rules []Rule
	if rn := f["rules"]; rn != nil {
		if rn.Kind != yaml.SequenceNode {
			p.errorf(rn, join(path, "rules"), "must be a list")
			return nil, nil, false
		}
		for i, r := range rn.Content {
			if rule, ok := p.rule(r, fmt.Sprintf("%s.rules[%d]", path, i+1), i+1, c, kind); ok {
				rules = append(rules, rule)
			}
		}
	}
	return rules, own, true
}

// secrets parses the secrets section (secrets design 4). Names follow
// ValidSecretName and, like key names, must differ in more than letter
// case: the store compares names case-insensitively.
func (p *parser) secrets(n *yaml.Node, c *Config) {
	seenFold := map[string]string{}
	for _, kv := range p.pairs(n, "secrets") {
		k, v := kv[0], kv[1]
		path := "secrets." + k.Value
		if !ValidSecretName(k.Value) {
			p.errorf(k, path, "secret names are letters, digits, _ . - and /, at most 64 bytes")
			continue
		}
		fold := strings.ToLower(k.Value)
		if prev, dup := seenFold[fold]; dup {
			p.errorf(k, path, "secret names must differ in more than letter case (%q already defined)", prev)
			continue
		}
		seenFold[fold] = k.Value
		if s := p.secret(k.Value, v, path, c); s != nil {
			c.Secrets[k.Value] = s
		}
	}
	// One secret per host: git asks by host, so two would be a guess.
	hosts := map[string]string{}
	for _, kv := range p.pairs(n, "secrets") {
		s := c.Secrets[kv[0].Value]
		if s == nil || s.Helper == nil || s.Helper.Git == nil {
			continue
		}
		g := s.Helper.Git
		if prev, dup := hosts[g.Host]; dup {
			p.errorf(kv[0], "secrets."+s.Name+".helper.git.host", "%s already answers git for %s", prev, g)
			delete(c.Secrets, s.Name)
			continue
		}
		hosts[g.Host] = s.Name
	}
}

// gitHostRE is a DNS host name with an optional :port, in lower case.
var gitHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)

// gitUserRE is a username git can be told on one protocol line: printable
// ASCII without "=" (secrets design 6.1).
var gitUserRE = regexp.MustCompile(`^[\x21-\x3c\x3e-\x7e]{1,256}$`)

// helper reads a secret's helper: field. Only git is built (since M8); the
// other kinds of the design are refused by name.
func (p *parser) helper(n *yaml.Node, path string) *Helper {
	f := p.mapping(n, path, "git", "docker", "aws")
	if f == nil {
		return nil
	}
	for _, k := range []string{"docker", "aws"} {
		if f[k] != nil {
			p.errorf(f[k], join(path, k), "helper.%s is not in this version (helper.git is)", k)
		}
	}
	gn := f["git"]
	if gn == nil {
		if f["docker"] == nil && f["aws"] == nil {
			p.errorf(n, path, "helper: needs git: {host: …}")
		}
		return nil
	}
	gf := p.mapping(gn, join(path, "git"), "host", "username")
	if gf == nil {
		return nil
	}
	before := len(p.probs)
	g := &GitHelper{}
	if hn := gf["host"]; hn == nil {
		p.errorf(gn, join(path, "git.host"), "host is required (the HTTPS host git asks for, such as github.com)")
	} else if raw := p.str(hn, join(path, "git.host")); !p.errorsSince(before) {
		h, ascii := asciiLower(raw)
		if !ascii || !gitHostRE.MatchString(h) || !validPort(h) {
			p.errorf(hn, join(path, "git.host"), "must be a host name, with an optional :port (no scheme, path or user), not %q", raw)
		}
		g.Host = h
	}
	if un := gf["username"]; un != nil {
		at := len(p.probs)
		u := p.str(un, join(path, "git.username"))
		if !p.errorsSince(at) && !gitUserRE.MatchString(u) {
			p.errorf(un, join(path, "git.username"), "username must be 1 to 256 printable ASCII characters without =")
		}
		g.Username = u
	}
	if p.errorsSince(before) {
		return nil
	}
	return &Helper{Git: g}
}

// validPort reports whether the :port of host, if any, is at most 65535.
func validPort(host string) bool {
	_, port, ok := strings.Cut(host, ":")
	if !ok {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

// laterFields are fields of the secrets design that later tasks build.
// They are refused by name, never ignored, so nothing is approved now to
// work after an upgrade.
var laterFields = []string{"file"}

// secret parses one secrets entry. A bare "NAME:" has the default deliver,
// no rules and no own policy. A rule may be gate: none with any method when it
// names an app, which then covers any child of it; rule() refuses any and unknown.
func (p *parser) secret(name string, n *yaml.Node, path string, c *Config) *Secret {
	s := &Secret{Name: name, Deliver: DefaultDeliver()}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return s
	}
	f := p.mapping(n, path, append([]string{"deliver", "rules", "scope", "gate", "expire", "helper", "envAllow"}, laterFields...)...)
	if f == nil {
		return nil
	}
	before := len(p.probs)
	for _, field := range laterFields {
		if f[field] != nil {
			p.errorf(f[field], join(path, field), "the %s: field is not in this version", field)
		}
	}
	if dn := f["deliver"]; dn != nil {
		s.Deliver = p.deliver(dn, join(path, "deliver"))
	}
	if hn := f["helper"]; hn != nil {
		s.Helper = p.helper(hn, join(path, "helper"))
		if !p.errorsSince(before) && !slices.Contains(s.Deliver, DeliverHelper) {
			p.errorf(hn, join(path, "helper"), "deliver has no helper; add helper to deliver: or remove helper:")
		}
	}
	lateEnv := slices.Contains(s.Deliver, DeliverLateEnv)
	if en := f["envAllow"]; en != nil {
		s.EnvAllow = p.envAllow(en, join(path, "envAllow"))
		if !p.errorsSince(before) && !lateEnv {
			p.errorf(en, join(path, "envAllow"), "envAllow is for late-env; add late-env to deliver")
		}
	}
	rules, own, ok := p.entry(f, n, path, c, entrySecret)
	if !ok || p.errorsSince(before) {
		return nil
	}
	s.Rules, s.Own = rules, own
	p.runRules(f, path, s, lateEnv)
	if p.errorsSince(before) {
		return nil
	}
	if s.Helper != nil && s.Helper.Git != nil {
		for _, r := range s.Rules {
			for _, m := range r.To {
				if m.Kind == MatchSigned && m.Team == "apple" && (m.ID == "" || m.ID == "com.apple.git") {
					p.warnf(f["rules"].Content[r.Index-1], fmt.Sprintf("%s.rules[%d].to", path, r.Index),
						"this to: matches git itself, which only runs the helper for `git credential fill` typed in a shell (it would hand that the token); a fetch's helper is started by git-remote-http: use to: [{signed: {team: apple, id: com.apple.git-remote-http}}]")
					break
				}
			}
		}
	}
	return s
}

// runRules checks a secret's rules against nazar run (secrets design 6.3,
// D4, D5): a command: receiver only ever matches a nazar run receiver, so
// it needs late-env; and a launcher receiver (by the typed name) that won't
// ask again, under gate: none or scope: app, is warned about (secrets design 4).
func (p *parser) runRules(f map[string]*yaml.Node, path string, s *Secret, lateEnv bool) {
	for _, r := range s.Rules {
		rpath := fmt.Sprintf("%s.rules[%d]", path, r.Index)
		rn := f["rules"].Content[r.Index-1]
		var launcher *Matcher
		for i, m := range r.To {
			if m.Kind != MatchCommand {
				continue
			}
			if !lateEnv {
				p.errorf(rn, rpath+".to", "command: receivers are for nazar run; add late-env to deliver")
			}
			if slices.Contains(launcherNames, strings.ToLower(filepath.Base(m.Command[0]))) && launcher == nil {
				launcher = &r.To[i]
			}
		}
		if launcher != nil && r.Policy.Gate == GateNone {
			p.warnf(rn, rpath+".gate", "%s is a launcher; what it runs is chosen by files under your home directory (~/.npmrc) that any process of yours can edit, and this rule delivers %s to it without asking", launcher.Label(), s.Name)
		}
		if launcher != nil && r.Policy.Gate.Prompts() && r.Policy.Scope == ScopeApp {
			p.warnf(rn, rpath+".scope", "%s is a launcher; what it runs is chosen by files under your home directory (~/.npmrc) that any process of yours can edit, and this rule would deliver %s to it without asking again until the app quits; use scope: session or use", launcher.Label(), s.Name)
		}
	}
}

// launcherNames are the typed names (lower-cased) of the launchers of
// secrets design 6.3 step 3, for the warning about silent launcher
// receivers; npx-cli.js is npx's realpath.
var launcherNames = []string{"npx", "npx-cli.js", "npm", "pnpm", "bunx", "uvx", "uv", "pipx"}

// envAllow reads a secret's envAllow: list (secrets design 6.3.4): variable
// names, each once, none in the deny set, none that nazar sets itself.
func (p *parser) envAllow(n *yaml.Node, path string) []string {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		p.errorf(n, path, "must be a non-empty list of variable names")
		return nil
	}
	var out []string
	for _, it := range n.Content {
		at := len(p.probs)
		name := p.str(it, path)
		if p.errorsSince(at) {
			continue
		}
		entry, denied := envpolicy.Denied(name)
		switch {
		case !envpolicy.ValidName(name):
			p.errorf(it, path, "%q is not a variable name", name)
		case denied && entry == name:
			p.errorf(it, path, "%s can never be passed to a receiver", name)
		case denied:
			p.errorf(it, path, "%s can never be passed to a receiver (%s)", name, entry)
		case envpolicy.IsBase(name):
			p.errorf(it, path, "%s is set by nazar", name)
		case slices.Contains(out, name):
			p.errorf(it, path, "%s is listed twice", name)
		default:
			out = append(out, name)
		}
	}
	return out
}

// deliver reads a secret's deliver: list: the methods this version builds,
// each once. A method a later version builds is refused by name.
func (p *parser) deliver(n *yaml.Node, path string) []Delivery {
	if n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		p.errorf(n, path, "must be a non-empty list of methods (helper, late-env, stdout)")
		return nil
	}
	var out []Delivery
	for _, it := range n.Content {
		before := len(p.probs)
		d := Delivery(p.str(it, path))
		switch {
		case p.errorsSince(before):
		case slices.Contains(out, d):
			p.errorf(it, path, "%s is listed twice", d)
		case d.Built():
			out = append(out, d)
			if d == DeliverLateEnv && p.env.NoCodeSigning {
				p.warnf(it, path, "deliver: late-env (nazar run) is not available on Linux yet; use helper or stdout")
			}
		case d == DeliverFile || d == DeliverEnv:
			p.errorf(it, path, "%s is not in this version (helper, late-env and stdout are)", d)
		default:
			p.errorf(it, path, "unknown delivery %q (helper, late-env or stdout)", string(d))
		}
	}
	return out
}

func (p *parser) rule(n *yaml.Node, path string, index int, c *Config, kind entryKind) (Rule, bool) {
	f := p.mapping(n, path, "apps", "to", "scope", "gate", "expire")
	if f == nil {
		return Rule{}, false
	}
	before := len(p.probs)
	r := Rule{Index: index}
	if f["apps"] == nil {
		p.errorf(n, join(path, "apps"), "missing apps: (who may ask)")
	} else {
		r.Apps = p.refs(f["apps"], join(path, "apps"), "apps", c)
		for _, m := range r.Apps {
			if m.Kind == MatchCommand {
				p.errorf(f["apps"], join(path, "apps"), "command: matchers are only allowed in to:")
			}
		}
	}
	if f["to"] != nil && kind == entryK8s {
		p.errorf(f["to"], join(path, "to"), "k8s rules take no to:; the program that runs the plugin receives the credential")
	} else if f["to"] != nil && kind == entryAWS {
		p.errorf(f["to"], join(path, "to"), "aws rules take no to:; the program that runs credential_process receives the credential")
	} else if f["to"] != nil {
		r.To = p.refs(f["to"], join(path, "to"), "to", c)
		for _, m := range r.To {
			if m.Kind == MatchCommand && kind == entryKey {
				p.errorf(f["to"], join(path, "to"), "command: receivers apply to secrets started by nazar run, not to ssh keys")
			}
			if m.Kind == MatchUnknown {
				p.errorf(f["to"], join(path, "to"), "unknown describes callers, not receivers")
			}
		}
	}
	r.Policy, _ = p.policyFields(f, n, path)
	if hasKind(r.To, MatchAny) {
		// any matches every receiver, as no to: does. A secret's approvals
		// name their receiver either way; a key's only with a to:, so for
		// a key no to: means the same only where nothing is remembered.
		same := kind == entrySecret || !r.Policy.Gate.Prompts() || r.Policy.Scope == ScopeUse
		var fix func()
		if same {
			fix = func() { deleteField(n, "to") }
		}
		p.oldForm(f["to"], join(path, "to"), fix, "any in to: is the same as no to:; leave to: out")
		if p.legacy && same {
			r.To = nil
		}
	}
	if kind == entrySecret && r.Policy.Gate != GateBlock && len(r.To) == 0 {
		p.warnf(n, join(path, "to"), "no to:, so any program can receive this secret; name the receiver with to:")
	}
	if r.Policy.Gate == GateNone {
		hint := "login and dialog still accept it; to let every program use the key without a prompt, write apps: [any]"
		if kind != entryKey {
			hint = "login and dialog still accept it"
		}
		for _, m := range r.Apps {
			if m.Kind == MatchCommand {
				continue // already refused above: command: is only allowed in to:
			}
			if !allowedUnderNone(m) {
				p.errorf(f["gate"], join(path, "gate"), "gate: none refuses Apple's programs (Apple-signed matchers, paths under /System, /bin, /sbin and /usr), which sit in almost every caller chain; %s is refused under none (%s)", m.Label(), hint)
			}
		}
		for _, m := range r.Apps {
			if m.Kind != MatchAny && m.Kind != MatchUnknown {
				continue
			}
			// unknown is as wide as any: a program can make itself unknown
			// by leaving its chain (spec 4.2), so both say every program.
			who, chip := "every program on this Mac", "the Secure Enclave"
			if p.env.NoCodeSigning { // Linux
				who, chip = "every program on this computer", "the TPM"
			}
			if kind == entryK8s {
				p.errorf(f["apps"], join(path, "apps"), "rule %d would give this context's credential to %s without asking; name the apps", r.Index, who)
			} else if kind == entryAWS {
				p.errorf(f["apps"], join(path, "apps"), "rule %d would give this entry's credential to %s without asking; name the apps", r.Index, who)
			} else if kind == entrySecret {
				p.errorf(f["apps"], join(path, "apps"), "rule %d would give this secret to %s without asking; name the apps", r.Index, who)
			} else {
				p.warnf(f["apps"], join(path, "apps"), "Rule %d lets %s use this key without asking. The key itself never leaves %s.", r.Index, who, chip)
			}
			break
		}
	}
	return r, !p.errorsSince(before)
}

// allowedUnderNone reports whether a rule with gate: none may use m as an
// apps: matcher (spec 4.2): app:
// matchers, signed: matchers whose team is not Apple, path: matchers
// outside the system volume, and any and unknown.
// Apple-signed matchers (with or without an id) and paths of Apple's
// programs are refused, because shells, login, interpreters and other
// system binaries sit in almost every caller chain, so any of them under
// none silently means "anything, no prompt" by accident. any and unknown
// say that outright: it is the user's choice, and parse warns about it.
// The decision is per matcher kind, team and system directory, never per
// binary. The team is folded so "Apple" can't dodge the check. A path:
// is only as safe as who can write its file: config check warns when that
// is the user (daemon pathAdvice).
func allowedUnderNone(m Matcher) bool {
	switch m.Kind {
	case MatchApp, MatchAny, MatchUnknown:
		return true
	case MatchSigned:
		return !strings.EqualFold(m.Team, "apple")
	case MatchPath:
		return !SystemPath(m.Path)
	}
	return false
}

// checkRuleOrder warns, per key and per secret, about rules an earlier rule
// always beats under first-match (spec 4.2: "config check warns about rules
// that can never match") and about the to: fall-through: a later rule with
// a weaker gate that a caller of an earlier to:-restricted rule reaches
// through a receiver that rule does not list (see fallthrough.go). Rules of
// different entries never interact.
func (p *parser) checkRuleOrder(c *Config) {
	for _, name := range c.KeyNames() {
		p.checkRules("ssh_agent.keys."+name, c.SSHAgent.Keys[name].Rules)
	}
	for _, name := range c.SecretNames() {
		p.checkRules("secrets."+name, c.Secrets[name].Rules)
	}
	for _, name := range c.K8sNames() {
		p.checkRules("k8s.contexts."+name, c.K8s[name].Rules)
	}
	for _, name := range c.AWSNames() {
		p.checkRules("aws."+name, c.AWS[name].Rules)
	}
}

func (p *parser) checkRules(path string, rules []Rule) {
	shadowed := shadowedBy(rules)
	for j, by := range shadowed {
		if by > 0 {
			p.warnf(nil, fmt.Sprintf("%s.rules[%d]", path, rules[j].Index), "can never match: rule %d always matches first", by)
		}
	}
	// fallThroughs returns positions in rules, never Index values: rules
	// that failed to parse are not in the slice, so the two differ.
	for j, from := range fallThroughs(rules, shadowed) {
		if from >= 0 {
			r, ri := rules[j], rules[from]
			p.warnf(nil, fmt.Sprintf("%s.rules[%d]", path, r.Index),
				"to: of rule %d only restricts its receivers: a caller rule %d matches, with a receiver not in that to:, falls through to this rule, whose gate %s is weaker than rule %d's gate %s",
				ri.Index, ri.Index, r.Policy.Gate, ri.Index, ri.Policy.Gate)
		}
	}
	for j, to := range aboveUnknown(rules, shadowed) {
		if to >= 0 {
			r, ru := rules[j], rules[to]
			p.warnf(nil, fmt.Sprintf("%s.rules[%d]", path, r.Index),
				"rule %d also takes unknown callers its program is in (a process with no app above it that runs it), with gate %s, before rule %d (apps: [unknown], gate %s) is reached; to keep those callers at gate %s, move rule %d above rule %d",
				r.Index, r.Policy.Gate, ru.Index, ru.Policy.Gate, ru.Policy.Gate, ru.Index, r.Index)
		}
	}
}
