package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	yaml "go.yaml.in/yaml/v3"
)

// The aws section (aws design 7): an entry per IAM Roles Anywhere role,
// whose session credentials are minted with a certificate from the entry's
// Secure Enclave CA, with the rules, scope, gate and expire of a k8s
// context, judged on whoever ran the program that runs credential_process
// (aws design 6.1: no client list, as k8s design 2.1).

// The session lifetime (duration): the default, and the range config
// accepts (aws design 5.2).
const (
	DefaultAWSDuration = time.Hour
	MinAWSDuration     = 15 * time.Minute
	MaxAWSDuration     = time.Hour
)

// AWSIdentity is the subject of the certificates an entry mints: CN=User.
type AWSIdentity struct {
	User string
}

// AWSEntry is one aws entry; Rules and Own mean what they mean for a Key.
// It names no program that receives the credential: whatever runs
// credential_process does, when the rules allow whoever ran it (aws design
// 6.1). The three ARNs are all set (Connected) or all empty; Region is the trust
// anchor's and Account the role's, both "" when not connected.
type AWSEntry struct {
	Name           string
	Identity       AWSIdentity
	TrustAnchorArn string
	ProfileArn     string
	RoleArn        string
	Region         string
	Account        string
	Duration       time.Duration
	Rules          []Rule
	Own            *Policy
}

// Connected reports whether the entry names its trust anchor, profile and
// role: only then can a credential be minted.
func (e *AWSEntry) Connected() bool { return e.TrustAnchorArn != "" }

// NotConnected is what config check, aws list and aws credential say about
// an entry with no ARNs yet.
func NotConnected(name string) string {
	return fmt.Sprintf("aws.%s is not connected yet: add trustAnchorArn, profileArn and roleArn (nazar aws ca create printed the steps)", name)
}

// awsNameRE: the entry name is the audit target aws:<name>, the Vault item
// aws-ca/<name>, the file aws-ca-<name>.crt, the CA's CN and an argument of
// the credential_process line, so it stays one plain word.
var awsNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidAWSName reports whether name may name an aws entry.
func ValidAWSName(name string) bool {
	return awsNameRE.MatchString(name) && !strings.Contains(name, "..")
}

// awsUserRE is identity.user: AWS makes CN=<user> the session's source
// identity only up to 61 characters (aws design 4.3), and nothing a prompt
// or a certificate could render as something else.
var awsUserRE = regexp.MustCompile(`^[A-Za-z0-9._@:+=/-]{1,61}$`)

// ValidAWSUser reports whether s may be identity.user.
func ValidAWSUser(s string) bool { return awsUserRE.MatchString(s) }

// The ARNs config accepts: the aws partition, a region of the usual shape,
// a 12-digit account, and Roles Anywhere's resource ids.
var (
	arnPartitionRE = regexp.MustCompile(`^arn:([^:]*):`)
	trustAnchorRE  = regexp.MustCompile(`^arn:aws:rolesanywhere:([^:]*):([0-9]{12}):trust-anchor/[a-f0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}$`)
	profileRE      = regexp.MustCompile(`^arn:aws:rolesanywhere:([^:]*):([0-9]{12}):profile/[a-f0-9]{8}-(?:[a-z0-9]{4}-){3}[a-z0-9]{12}$`)
	roleRE         = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]{1,64}$`)
	regionRE       = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]$`)
)

// ParseTrustAnchorArn returns the region and account of a trust anchor ARN
// config accepts.
func ParseTrustAnchorArn(arn string) (region, account string, ok bool) {
	m := trustAnchorRE.FindStringSubmatch(arn)
	if m == nil || !regionRE.MatchString(m[1]) {
		return "", "", false
	}
	return m[1], m[2], true
}

// AWSNames returns the configured entry names, sorted.
func (c *Config) AWSNames() []string {
	names := make([]string, 0, len(c.AWS))
	for n := range c.AWS {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// AWSFallback is the policy for callers no rule of entry name matches: its
// own policy if set, otherwise defaults.fallback.
func (c *Config) AWSFallback(name string) Policy {
	if e, ok := c.AWS[name]; ok && e.Own != nil {
		return *e.Own
	}
	return c.Defaults.Fallback
}

// AWSNoClients is the error on a clients: line in an aws entry: there is
// no client list (aws design 6.1). AWS was never released with one, so the
// line is an error, not k8s's leftover warning.
const AWSNoClients = "aws entries have no clients: list; any program your rules allow gets the credential: remove the line"

// aws parses the aws section: entry names to entries.
func (p *parser) aws(n *yaml.Node, c *Config) {
	if n.Kind != yaml.MappingNode {
		p.errorf(n, "aws", "must be a mapping")
		return
	}
	seenFold := map[string]string{}
	for _, kv := range p.pairs(n, "aws") {
		k, v := kv[0], kv[1]
		path := "aws." + k.Value
		if !ValidAWSName(k.Value) {
			p.errorf(k, path, "aws entry names are letters, digits, . _ and -, at most 64 bytes")
			continue
		}
		fold := strings.ToLower(k.Value)
		if prev, dup := seenFold[fold]; dup {
			p.errorf(k, path, "aws entry names must differ in more than letter case (aws-ca-<name>.crt lives on a case-insensitive file system; %q already defined)", prev)
			continue
		}
		seenFold[fold] = k.Value
		if e := p.awsEntry(k.Value, v, path, c); e != nil {
			c.AWS[k.Value] = e
		}
	}
}

// awsEntry parses one entry.
func (p *parser) awsEntry(name string, n *yaml.Node, path string, c *Config) *AWSEntry {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		p.errorf(n, join(path, "identity"), "identity is required; nazar aws ca create %s writes it", name)
		return nil
	}
	f := p.mapping(n, path, "identity", "trustAnchorArn", "profileArn", "roleArn", "duration", "clients", "rules", "scope", "gate", "expire")
	if f == nil {
		return nil
	}
	before := len(p.probs)
	e := &AWSEntry{Name: name, Duration: DefaultAWSDuration}
	if in := f["identity"]; in == nil {
		p.errorf(n, join(path, "identity"), "identity is required; nazar aws ca create %s writes it", name)
	} else {
		e.Identity = p.awsIdentity(in, join(path, "identity"))
	}
	p.awsARNs(f, n, path, e)
	if dn := f["duration"]; dn != nil {
		at := len(p.probs)
		d := p.duration(dn, join(path, "duration"))
		switch {
		case p.errorsSince(at):
		case d < MinAWSDuration || d > MaxAWSDuration:
			p.errorf(dn, join(path, "duration"), "duration must be between 15m and 1h, not %s", d)
		default:
			e.Duration = d
		}
	}
	if cn := f["clients"]; cn != nil {
		p.errorf(cn, join(path, "clients"), "%s", AWSNoClients)
	}
	rules, own, ok := p.entry(f, n, path, c, entryAWS)
	if !ok || p.errorsSince(before) {
		return nil
	}
	e.Rules, e.Own = rules, own
	// Rules are judged on who called the program that runs
	// credential_process, never on it, so a rule naming aws would never
	// match aws asking, and would pass every program aws runs: the
	// credential_process of a profile, which any process can write.
	p.ruleNamesProgram(f, path, e.Rules, "aws", "a credential_process of ~/.aws/config, which any process can write")
	if p.errorsSince(before) {
		return nil
	}
	if !e.Connected() {
		p.warnf(n, path, "%s", NotConnected(name))
	}
	return e
}

func (p *parser) awsIdentity(n *yaml.Node, path string) AWSIdentity {
	f := p.mapping(n, path, "user", "groups")
	if f == nil {
		return AWSIdentity{}
	}
	var id AWSIdentity
	before := len(p.probs)
	if f["groups"] != nil {
		p.errorf(f["groups"], join(path, "groups"), "the identity.groups: field is not in this version")
	}
	if un := f["user"]; un == nil {
		p.errorf(n, join(path, "user"), "identity.user is required (the certificate's CN)")
	} else if u := p.str(un, join(path, "user")); !p.errorsSince(before) {
		if !awsUserRE.MatchString(u) {
			p.errorf(un, join(path, "user"), "identity.user must be 1 to 61 characters: letters, digits and . _ @ : + = / - (AWS keeps 61 as the source identity)")
		}
		id.User = u
	}
	return id
}

// awsARNs reads the three ARNs: all or none, of the aws partition, the
// profile in the trust anchor's region.
func (p *parser) awsARNs(f map[string]*yaml.Node, n *yaml.Node, path string, e *AWSEntry) {
	read := func(field string) (string, *yaml.Node) {
		fn := f[field]
		if fn == nil {
			return "", nil
		}
		at := len(p.probs)
		s := p.str(fn, join(path, field))
		if p.errorsSince(at) {
			return "", nil
		}
		return s, fn
	}
	anchor, an := read("trustAnchorArn")
	profile, pn := read("profileArn")
	role, rn := read("roleArn")
	set := 0
	for _, fn := range []*yaml.Node{f["trustAnchorArn"], f["profileArn"], f["roleArn"]} {
		if fn != nil {
			set++
		}
	}
	switch {
	case set == 0:
		return
	case set != 3:
		p.errorf(n, path, "trustAnchorArn, profileArn and roleArn go together: give all three (or none, before AWS is set up)")
		return
	case an == nil || pn == nil || rn == nil:
		return // not strings: reported
	}
	before := len(p.probs)
	for _, a := range []struct {
		arn  string
		node *yaml.Node
	}{{anchor, an}, {profile, pn}, {role, rn}} {
		if m := arnPartitionRE.FindStringSubmatch(a.arn); m != nil && m[1] != "aws" {
			p.errorf(a.node, path, "only the aws partition is in this version, not %q", m[1])
		}
	}
	if p.errorsSince(before) {
		return
	}
	am := trustAnchorRE.FindStringSubmatch(anchor)
	if am == nil {
		p.errorf(an, join(path, "trustAnchorArn"), "trustAnchorArn must be arn:aws:rolesanywhere:<region>:<account>:trust-anchor/<id>")
	} else if !regionRE.MatchString(am[1]) {
		p.errorf(an, join(path, "trustAnchorArn"), "trustAnchorArn names the region %q, which is not of the shape us-east-1", am[1])
	}
	pm := profileRE.FindStringSubmatch(profile)
	switch {
	case pm == nil:
		p.errorf(pn, join(path, "profileArn"), "profileArn must be arn:aws:rolesanywhere:<region>:<account>:profile/<id>")
	case am != nil && pm[1] != am[1]:
		p.errorf(pn, join(path, "profileArn"), "profileArn is in %s, the trust anchor in %s: they must be in one region", pm[1], am[1])
	}
	rm := roleRE.FindStringSubmatch(role)
	if rm == nil {
		p.errorf(rn, join(path, "roleArn"), "roleArn must be arn:aws:iam::<account>:role/<name> (a path before the name is allowed)")
	}
	if p.errorsSince(before) {
		return
	}
	e.TrustAnchorArn, e.ProfileArn, e.RoleArn = anchor, profile, role
	e.Region, e.Account = am[1], rm[1]
}
