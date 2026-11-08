package daemon

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
)

// keyAdvice compares each SSH key's recorded Secure Enclave auth policy,
// fixed when the key was created (spec 4.5), with the gates c gives it,
// and says which keys need re-creation:
//   - a user-presence key that a dialog or none gate can reach: the enclave
//     refuses to sign without the user's authentication, so those requests
//     fail instead of getting the gate the rule promises;
//   - a key without user presence whose gates are all block, or login with
//     scope: use, could be re-created with chip-level protection; a key only
//     block reaches is not configured yet and gets no advice. Per
//     spike S1 the chip reuses an approval for minutes, not for a session
//     or an app's lifetime, so login with scope: session or app is no
//     candidate.
//
// Every message is a warning: the config stays valid. A record that can't
// be read has no known policy and gets nothing; a vault that can't be listed
// is logged and gives no advice, never a failed check or status.
func (d *Daemon) keyAdvice(c *config.Config) []control.ConfigProblem {
	if c == nil {
		return nil
	}
	list, err := d.keys.List()
	if err != nil {
		d.o.Logf("keys: %v", err)
		return nil
	}
	var out []control.ConfigProblem
	for _, k := range list {
		if k.Broken {
			continue
		}
		msg := presenceAdvice(c, k.Name, k.Auth)
		if msg == "" {
			continue
		}
		p := control.ConfigProblem{Severity: string(config.SevWarning), Message: msg}
		if _, ok := c.SSHAgent.Keys[k.Name]; ok {
			p.Path = "ssh_agent.keys." + k.Name
		}
		out = append(out, p)
	}
	return out
}

// gateSource is one policy that can apply to a key: a rule, the key's own
// gate or defaults.fallback (spec 4.5).
type gateSource struct {
	what string
	pol  config.Policy
}

func gateSources(c *config.Config, name string) []gateSource {
	var srcs []gateSource
	key := c.SSHAgent.Keys[name]
	if key != nil {
		for _, r := range key.Rules {
			srcs = append(srcs, gateSource{fmt.Sprintf("rule %d (gate %s)", r.Index, r.Policy.Gate), r.Policy})
		}
		if key.Own != nil {
			return append(srcs, gateSource{fmt.Sprintf("its own gate (%s)", key.Own.Gate), *key.Own})
		}
	}
	return append(srcs, gateSource{fmt.Sprintf("defaults.fallback (gate %s)", c.Defaults.Fallback.Gate), c.Defaults.Fallback})
}

// presenceAdvice is the advice for key name created with auth under c, or
// "". The name is quoted ASCII-only like every config-derived value shown.
func presenceAdvice(c *config.Config, name string, auth platform.AuthPolicy) string {
	srcs := gateSources(c, name)
	switch auth {
	case platform.AuthUserPresence:
		var weak, lapsing []string
		for _, s := range srcs {
			switch {
			case s.pol.Gate == config.GateDialog || s.pol.Gate == config.GateNone:
				weak = append(weak, s.what)
			case s.pol.Gate == config.GateLogin && s.pol.Scope != config.ScopeUse:
				lapsing = append(lapsing, fmt.Sprintf("%s with scope %s", s.what, s.pol.Scope))
			}
		}
		if len(weak) > 0 {
			return fmt.Sprintf("SSH key %s was created with Secure Enclave user presence, but %s can reach it, so those requests fail; re-create the key without user presence",
				strconv.QuoteToASCII(name), joinAnd(weak))
		}
		if len(lapsing) > 0 {
			return fmt.Sprintf("SSH key %s was created with Secure Enclave user presence, but %s remembers an approval longer than the Secure Enclave honours one (minutes), so those requests fail once it lapses; re-create the key without user presence or use scope: use",
				strconv.QuoteToASCII(name), joinAnd(lapsing))
		}
		return ""
	case platform.AuthNone:
		if !c.NeedsUserPresence(name) {
			return "" // a dialog, none or remembered login can reach it, or nothing may use it yet
		}
		return fmt.Sprintf("SSH key %s was created without Secure Enclave user presence, but every gate that can reach it is block or login with scope: use, so it could be re-created with user presence (then even a compromised nazar process can't sign without your authentication)",
			strconv.QuoteToASCII(name))
	}
	return ""
}

// joinAnd lists items as "a", "a and b" or "a, b and c".
func joinAnd(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
