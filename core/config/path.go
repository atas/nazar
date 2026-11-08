package config

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// PathUse is one path: matcher of a config with where it is used: the
// rules list it sits in ("ssh_agent.keys.github.rules[1].apps") or the
// apps: entry ("apps.mytool").
type PathUse struct {
	Path  string
	Where string
}

// PathMatchers lists every path: matcher of c, apps: entries first, then
// the rules of keys, secrets, k8s contexts and aws entries, each in name
// order. A rule that uses a named entry is not listed again.
func (c *Config) PathMatchers() []PathUse {
	var out []PathUse
	names := make([]string, 0, len(c.Apps))
	for n := range c.Apps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if m := c.Apps[n]; m.Kind == MatchPath {
			out = append(out, PathUse{Path: m.Path, Where: "apps." + n})
		}
	}
	c.eachRules(func(path string, rules *[]Rule) {
		for _, r := range *rules {
			for _, side := range []struct {
				ms   []Matcher
				name string
			}{{r.Apps, "apps"}, {r.To, "to"}} {
				for _, m := range side.ms {
					if m.Kind == MatchPath && m.Name == "" {
						out = append(out, PathUse{Path: m.Path, Where: path + ".rules[" + strconv.Itoa(r.Index) + "]." + side.name})
					}
				}
			}
		}
	})
	return out
}

// HasPathMatchers reports whether any rule of c has a path: matcher.
func (c *Config) HasPathMatchers() bool {
	found := false
	c.eachRules(func(_ string, rules *[]Rule) {
		for _, r := range *rules {
			found = found || hasKind(r.Apps, MatchPath) || hasKind(r.To, MatchPath)
		}
	})
	return found
}

// DropPathMatchers takes every path: matcher out of c's rules, in place,
// as if it matched nothing: a matcher beside others goes, and a rule left
// with no apps:, or with a to: that had only path: matchers, goes too (it
// could match no request). Rule indexes are kept. It is how a config
// approved while path: matched nothing is held until it is approved again
// (configstage).
func (c *Config) DropPathMatchers() {
	c.eachRules(func(_ string, rules *[]Rule) {
		var kept []Rule
		for _, r := range *rules {
			hadTo := len(r.To) > 0
			r.Apps, r.To = withoutPaths(r.Apps), withoutPaths(r.To)
			if len(r.Apps) == 0 || (hadTo && len(r.To) == 0) {
				continue
			}
			kept = append(kept, r)
		}
		*rules = kept
	})
}

func withoutPaths(ms []Matcher) []Matcher {
	var out []Matcher
	for _, m := range ms {
		if m.Kind != MatchPath {
			out = append(out, m)
		}
	}
	return out
}

// eachRules calls f with every rules list of c and its config path, in
// name order: keys, secrets, k8s contexts, aws entries.
func (c *Config) eachRules(f func(path string, rules *[]Rule)) {
	for _, n := range c.KeyNames() {
		f("ssh_agent.keys."+n, &c.SSHAgent.Keys[n].Rules)
	}
	for _, n := range c.SecretNames() {
		f("secrets."+n, &c.Secrets[n].Rules)
	}
	for _, n := range c.K8sNames() {
		f("k8s.contexts."+n, &c.K8s[n].Rules)
	}
	for _, n := range c.AWSNames() {
		f("aws."+n, &c.AWS[n].Rules)
	}
}

// SystemPath reports whether p, a clean absolute path, is on the macOS
// system volume (/System, /bin, /sbin, /usr outside /usr/local): Apple's
// programs, which sit in almost every caller chain, as Apple-signed
// matchers do.
func SystemPath(p string) bool {
	for _, d := range []string{"/System", "/bin", "/sbin", "/usr"} {
		if p == d || strings.HasPrefix(p, d+"/") {
			return !(p == "/usr/local" || strings.HasPrefix(p, "/usr/local/"))
		}
	}
	return false
}

// cleanAbs reports whether p is a clean absolute path.
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }
