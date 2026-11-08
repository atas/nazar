package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"

	"github.com/atas/nazar/core/k8s/cluster"
)

// The k8s section (k8s design 3, as built in Milestone 12): contexts whose
// credential is minted from a Secure Enclave CA (credential: ca-cert),
// with the rules, scope, gate and expire of ssh keys, judged on whoever
// ran the program that asks for the credential (k8s design 2.1: no client
// list).

// CredentialKind is k8s.contexts.NAME.credential.
type CredentialKind string

const (
	CredentialCACert CredentialKind = "ca-cert"
	CredentialStored CredentialKind = "stored"
	CredentialJWT    CredentialKind = "jwt"
)

// The lifetime of a minted certificate (ttl_cert): the default, and the
// range config accepts.
const (
	DefaultTTLCert = 15 * time.Minute
	MinTTLCert     = time.Minute
	MaxTTLCert     = time.Hour
)

// maxGroups bounds identity.groups.
const maxGroups = 16

// K8sIdentity is the subject of the certificates a context mints: CN=User,
// one O= per group.
type K8sIdentity struct {
	User   string
	Groups []string
}

// K8sContext is one k8s.contexts entry; Rules and Own mean what they mean
// for a Key. It names no program that receives the credential: whatever
// runs the plugin does, when the rules allow whoever called it (k8s design
// 2.1).
//
// LeftoverClients is set when the entry still has a clients: line, the
// client list nazar no longer has: the context is off (every request is
// refused) and config check warns, naming the fix, until the line is
// removed and that loosening approved. The rest of the config stays in
// force, so an upgrade never turns SSH keys off over a k8s line.
type K8sContext struct {
	Name            string
	Credential      CredentialKind
	Identity        K8sIdentity
	TTLCert         time.Duration
	Cluster         cluster.Pin
	Rules           []Rule
	Own             *Policy
	LeftoverClients bool
}

// K8sClientsGone is the warning on a leftover clients: line.
const K8sClientsGone = "no longer used; remove the line (any program your rules allow now gets the credential); until then this context is off"

// k8sNameRE: the context name is the kubeconfig context name, the audit
// target k8s:<name>, the Vault item k8s-ca/<name> and the file
// k8s-ca-<name>.crt, so "/", ":", whitespace and non-ASCII are refused.
var k8sNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// ValidK8sContextName reports whether name may name a k8s context.
func ValidK8sContextName(name string) bool {
	return k8sNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// k8sSubjectRE is identity.user and each group: what Kubernetes x509 users
// usually look like (admin, system:masters, me@example.com), and nothing a
// prompt or a certificate could render as something else.
var k8sSubjectRE = regexp.MustCompile(`^[A-Za-z0-9._@:+=/-]{1,128}$`)

// ValidK8sSubject reports whether s may be identity.user or a group.
func ValidK8sSubject(s string) bool { return k8sSubjectRE.MatchString(s) }

// K8sNames returns the configured context names, sorted.
func (c *Config) K8sNames() []string {
	names := make([]string, 0, len(c.K8s))
	for n := range c.K8s {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// K8sFallback is the policy for callers no rule of context name matches:
// its own policy if set, otherwise defaults.fallback.
func (c *Config) K8sFallback(name string) Policy {
	if k, ok := c.K8s[name]; ok && k.Own != nil {
		return *k.Own
	}
	return c.Defaults.Fallback
}

// k8sLaterFields are fields of the k8s design that this version does not
// build: refused by name, never ignored.
var k8sLaterFields = []string{"ttl", "credential_ref", "kubeconfig_context", "issuer", "ttl_token"}

// managedSuffixes are the API server domains of managed clusters, whose
// client CA can't be changed (k8s design 6.1).
var managedSuffixes = []string{".eks.amazonaws.com", ".gke.goog", ".azmk8s.io"}

// k8s parses the k8s section: contexts and nothing else.
func (p *parser) k8s(n *yaml.Node, c *Config) {
	f := p.mapping(n, "k8s", "contexts")
	if f == nil {
		return
	}
	cn := f["contexts"]
	if cn == nil {
		p.errorf(n, "k8s.contexts", "missing contexts:")
		return
	}
	seenFold := map[string]string{}
	for _, kv := range p.pairs(cn, "k8s.contexts") {
		k, v := kv[0], kv[1]
		path := "k8s.contexts." + k.Value
		if !ValidK8sContextName(k.Value) {
			p.errorf(k, path, "context names are letters, digits, . _ @ and -, at most 128 bytes (the kubeconfig context name; rename it with kubectl config rename-context)")
			continue
		}
		fold := strings.ToLower(k.Value)
		if prev, dup := seenFold[fold]; dup {
			p.errorf(k, path, "context names must differ in more than letter case (k8s-ca-<name>.crt lives on a case-insensitive file system; %q already defined)", prev)
			continue
		}
		seenFold[fold] = k.Value
		if ctx := p.k8sContext(k.Value, v, path, c); ctx != nil {
			c.K8s[k.Value] = ctx
		}
	}
}

// k8sContext parses one context.
func (p *parser) k8sContext(name string, n *yaml.Node, path string, c *Config) *K8sContext {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		p.errorf(n, join(path, "credential"), "credential is required (credential: ca-cert)")
		return nil
	}
	f := p.mapping(n, path, append([]string{"credential", "identity", "ttl_cert", "cluster", "clients", "rules", "scope", "gate", "expire"}, k8sLaterFields...)...)
	if f == nil {
		return nil
	}
	before := len(p.probs)
	for _, field := range k8sLaterFields {
		if f[field] != nil {
			p.errorf(f[field], join(path, field), "the %s: field is not in this version", field)
		}
	}
	ctx := &K8sContext{Name: name, TTLCert: DefaultTTLCert}
	if cr := f["credential"]; cr == nil {
		p.errorf(n, join(path, "credential"), "credential is required (credential: ca-cert)")
	} else if s := p.str(cr, join(path, "credential")); !p.errorsSince(before) {
		switch CredentialKind(s) {
		case CredentialCACert:
			ctx.Credential = CredentialCACert
		case CredentialStored:
			p.errorf(cr, join(path, "credential"), "stored is not in this version (ca-cert is)")
		case CredentialJWT:
			p.errorf(cr, join(path, "credential"), "jwt is not planned; use ca-cert")
		default:
			p.errorf(cr, join(path, "credential"), "credential must be ca-cert, not %q", s)
		}
	}
	if in := f["identity"]; in == nil {
		p.errorf(n, join(path, "identity"), "identity is required (identity: {user: …, groups: […]})")
	} else {
		ctx.Identity = p.k8sIdentity(in, join(path, "identity"))
	}
	if tn := f["ttl_cert"]; tn != nil {
		at := len(p.probs)
		d := p.duration(tn, join(path, "ttl_cert"))
		switch {
		case p.errorsSince(at):
		case d < MinTTLCert || d > MaxTTLCert:
			p.errorf(tn, join(path, "ttl_cert"), "ttl_cert must be between 1m and 1h, not %s", d)
		default:
			ctx.TTLCert = d
		}
	}
	if cl := f["cluster"]; cl == nil {
		p.errorf(n, join(path, "cluster"), "cluster is required; nazar k8s ca create %s records it", name)
	} else {
		ctx.Cluster = p.k8sCluster(cl, join(path, "cluster"), name)
	}
	if cn := f["clients"]; cn != nil {
		// Gone since the client list was removed. Read as absent, the line
		// would loosen the context without a prompt; as an error, it would
		// leave the whole config unapproved. So the context alone is off
		// until the user deletes the line and approves that loosening.
		p.warnf(cn, join(path, "clients"), "%s", K8sClientsGone)
		ctx.LeftoverClients = true
	}
	rules, own, ok := p.entry(f, n, path, c, entryK8s)
	if !ok || p.errorsSince(before) {
		return nil
	}
	ctx.Rules, ctx.Own = rules, own
	// Rules are judged on who called the program that runs the plugin,
	// never on it (k8s design 2.3), so a rule naming kubectl would never
	// match kubectl asking, and would pass every program kubectl runs: a
	// kubectl-<name> plugin from PATH, which anyone can put there.
	// (A context that is off for a leftover clients: line is not checked:
	// kubectl was a client there, and the rule is reported once the line goes.)
	if !ctx.LeftoverClients {
		p.ruleNamesProgram(f, path, ctx.Rules, "kubectl", "a kubectl-<name> plugin on PATH")
	}
	if p.errorsSince(before) {
		return nil
	}
	host := strings.ToLower(ctx.Cluster.Server)
	if u := strings.TrimPrefix(host, "https://"); u != host {
		h, _, _ := strings.Cut(u, "/")
		h, _, _ = strings.Cut(h, ":")
		for _, s := range managedSuffixes {
			if strings.HasSuffix(h, s) {
				p.warnf(f["cluster"], join(path, "cluster.server"), "managed clusters can't trust a nazar CA (their client CA can't be changed); this context will not work there")
				break
			}
		}
	}
	return ctx
}

// ruleNamesProgram refuses a rule naming prog, the program that asks for
// an entry's credential (kubectl for k8s, aws for aws): rules are judged on
// who called the program that ran nazar, never on it, so such a rule never
// matches prog asking and would pass every program prog runs (runs says
// which). One error per rule.
func (p *parser) ruleNamesProgram(f map[string]*yaml.Node, path string, rules []Rule, prog, runs string) {
	for _, r := range rules {
		for _, m := range r.Apps {
			if namesProgram(m, prog) {
				p.errorf(f["rules"].Content[r.Index-1], fmt.Sprintf("%s.rules[%d].apps", path, r.Index),
					"rule %d names %s; rules are judged on who called it, and it would pass any program %s runs (%s): name the terminal, tool or app instead", r.Index, prog, prog, runs)
				break
			}
		}
	}
}

// namesProgram reports whether rule matcher m is prog: named so, a path:
// to a file called prog, or a signed: matcher of identifier prog.
func namesProgram(m Matcher, prog string) bool {
	switch {
	case m.Name == prog:
		return true
	case m.Kind == MatchPath:
		return filepath.Base(m.Path) == prog
	case m.Kind == MatchSigned:
		return m.ID == prog
	}
	return false
}

func (p *parser) k8sIdentity(n *yaml.Node, path string) K8sIdentity {
	f := p.mapping(n, path, "user", "groups")
	if f == nil {
		return K8sIdentity{}
	}
	var id K8sIdentity
	before := len(p.probs)
	if un := f["user"]; un == nil {
		p.errorf(n, join(path, "user"), "identity.user is required (the certificate's CN)")
	} else if u := p.str(un, join(path, "user")); !p.errorsSince(before) {
		if !k8sSubjectRE.MatchString(u) {
			p.errorf(un, join(path, "user"), "identity.user must be 1 to 128 characters: letters, digits and . _ @ : + = / -")
		}
		id.User = u
	}
	if gn := f["groups"]; gn != nil {
		if gn.Kind != yaml.SequenceNode {
			p.errorf(gn, join(path, "groups"), "identity.groups must be a list")
			return id
		}
		if len(gn.Content) > maxGroups {
			p.errorf(gn, join(path, "groups"), "identity.groups lists at most 16 groups")
		}
		for _, it := range gn.Content {
			at := len(p.probs)
			g := p.str(it, join(path, "groups"))
			switch {
			case p.errorsSince(at):
			case !k8sSubjectRE.MatchString(g):
				p.errorf(it, join(path, "groups"), "identity.groups entries must be 1 to 128 characters: letters, digits and . _ @ : + = / -")
			case slices.Contains(id.Groups, g):
				p.errorf(it, join(path, "groups"), "%s is listed twice", g)
			default:
				id.Groups = append(id.Groups, g)
			}
		}
	}
	return id
}

var caSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (p *parser) k8sCluster(n *yaml.Node, path, name string) cluster.Pin {
	f := p.mapping(n, path, "server", "ca_sha256", "tls_server_name", "proxy_url")
	if f == nil {
		return cluster.Pin{}
	}
	var pin cluster.Pin
	if sn := f["server"]; sn == nil {
		p.errorf(n, join(path, "server"), "cluster.server is required; nazar k8s ca create %s records it", name)
	} else {
		at := len(p.probs)
		s := p.str(sn, join(path, "server"))
		if !p.errorsSince(at) {
			norm, err := cluster.NormalizeServer(s)
			if err != nil {
				p.errorf(sn, join(path, "server"), "cluster.server: %v", err)
			}
			pin.Server = norm
		}
	}
	if cn := f["ca_sha256"]; cn == nil {
		p.errorf(n, join(path, "ca_sha256"), "cluster.ca_sha256 is required; nazar k8s ca create %s records it", name)
	} else {
		at := len(p.probs)
		s := p.str(cn, join(path, "ca_sha256"))
		if !p.errorsSince(at) && !caSHA256RE.MatchString(s) {
			p.errorf(cn, join(path, "ca_sha256"), "cluster.ca_sha256 must be 64 lowercase hex characters; nazar k8s ca create %s records it", name)
		}
		pin.CASHA256 = s
	}
	if tn := f["tls_server_name"]; tn != nil {
		at := len(p.probs)
		s := p.str(tn, join(path, "tls_server_name"))
		if !p.errorsSince(at) && !tlsNameRE.MatchString(s) {
			p.errorf(tn, join(path, "tls_server_name"), "cluster.tls_server_name must be a host name or an IP address")
		}
		pin.TLSServerName = s
	}
	if pn := f["proxy_url"]; pn != nil {
		at := len(p.probs)
		s := p.str(pn, join(path, "proxy_url"))
		if !p.errorsSince(at) && !validProxyURL(s) {
			p.errorf(pn, join(path, "proxy_url"), "cluster.proxy_url must be an http, https or socks5 URL with a host and no user, query or fragment")
		}
		pin.ProxyURL = s
	}
	return pin
}

// tlsNameRE is a host name or an IP address (IPv6 with or without
// brackets): what kubeconfig's tls-server-name holds.
var tlsNameRE = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,253}$`)

// validProxyURL: what client-go accepts as proxy-url, without user info
// (a password in it would be echoed in prompts and audit lines).
func validProxyURL(s string) bool {
	if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return false
	}
	switch u.Scheme {
	case "http", "https", "socks5":
		return true
	}
	return false
}
