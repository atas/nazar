package daemon

import (
	"regexp"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// A key's Secure Enclave auth policy (user presence or not) is
// fixed when the key is created (spec 4.5); its gates can change later with
// the config. `config check` and `status` compare the two and say which
// keys need re-creation:
//   - a user-presence key that a dialog or none gate can now reach: those
//     requests will fail (the enclave refuses to sign without the user's
//     authentication);
//   - a key without user presence whose gates are all block, or login with
//     scope: use, could be re-created with chip-level protection. Per spike
//     S1 an approval is reused at the chip for minutes, not for a session,
//     so login with scope: session or app is no candidate.
// Everything else gets no such advice. These are warnings: the config stays
// valid.

// createKey makes a key straight in the registry the daemon reads (same
// fake enclave and vault), with the given auth policy and no prompt.
func (e *env) createKey(t *testing.T, name string, auth platform.AuthPolicy) {
	t.Helper()
	reg := keys.NewRegistry(e.f, e.vault, layout.KeysDir(e.home), nil)
	if _, err := reg.Create(name, auth, platform.AccessWhenUnlocked); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}

// activate writes body and waits until the daemon runs it as the active
// config (a loosening is approved by the fake's login answer).
func (e *env) activate(t *testing.T, body string) {
	t.Helper()
	e.writeConfig(t, body)
	waitFor(t, func() bool { return string(e.d.stager.Active().Raw) == body })
}

var recreateRE = regexp.MustCompile(`(?i)re-?creat`)

// advice returns the problems that tell key name it needs re-creation: the
// message names the key (status prints only messages) and says re-create.
func advice(ps []control.ConfigProblem, name string) []control.ConfigProblem {
	word := regexp.MustCompile(`(^|[^A-Za-z0-9._-])` + regexp.QuoteMeta(name) + `([^A-Za-z0-9._-]|$)`)
	var out []control.ConfigProblem
	for _, p := range ps {
		if recreateRE.MatchString(p.Message) && word.MatchString(p.Message) {
			out = append(out, p)
		}
	}
	return out
}

func allAdvice(ps []control.ConfigProblem) []control.ConfigProblem {
	var out []control.ConfigProblem
	for _, p := range ps {
		if recreateRE.MatchString(p.Message) {
			out = append(out, p)
		}
	}
	return out
}

const policyMix = `apiVersion: nazar/v1
kind: Config
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    okpres:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
    hydra:
      scope: use
      gate: login
    okplain:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
    deploy:
      rules:
        - apps: [iterm]
          gate: none
    presdialog:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
    presnone:
      gate: block
      rules:
        - apps: [iterm]
          gate: none
    presown:
      scope: session
      gate: dialog
      rules:
        - apps: [iterm]
          gate: login
    plainuse:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
        - apps: [claude]
          gate: login
    plainsess:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
    plainapp:
      gate: block
      rules:
        - apps: [iterm]
          scope: app
          gate: login
          expire: 8h
    plainmix:
      gate: block
      rules:
        - apps: [claude]
          gate: dialog
        - apps: [iterm]
          gate: login
    pressess:
      gate: block
      rules:
        - apps: [iterm]
          scope: session
          gate: login
    ghost:
      gate: login
`

// policyKeys is the recorded auth policy of every key policyMix configures
// except ghost, which is configured but was never created.
var policyKeys = map[string]platform.AuthPolicy{
	"okpres": platform.AuthUserPresence, "hydra": platform.AuthUserPresence,
	"okplain": platform.AuthNone, "deploy": platform.AuthNone,
	"presdialog": platform.AuthUserPresence, "presnone": platform.AuthUserPresence, "presown": platform.AuthUserPresence,
	"plainuse": platform.AuthNone, "plainsess": platform.AuthNone, "plainapp": platform.AuthNone, "plainmix": platform.AuthNone,
	"pressess": platform.AuthUserPresence,
}

func checkPolicyAdvice(t *testing.T, where string, ps []control.ConfigProblem) {
	t.Helper()
	for _, name := range []string{"okpres", "hydra", "okplain", "deploy", "plainsess", "plainapp", "plainmix", "ghost"} {
		if a := advice(ps, name); len(a) != 0 {
			t.Errorf("%s: key %s needs no re-creation: %+v", where, name, a)
		}
	}
	// A user-presence key a dialog or none gate can reach: those requests
	// fail; the message says which gate and that it fails.
	for name, gate := range map[string]string{"presdialog": "dialog", "presnone": "none", "presown": "dialog"} {
		a := advice(ps, name)
		if len(a) == 0 {
			t.Errorf("%s: key %s has user presence but gate %s can reach it: config check must say to re-create it\n%+v", where, name, gate, ps)
			continue
		}
		msg := a[0].Message
		if !strings.Contains(msg, gate) || !strings.Contains(strings.ToLower(msg), "fail") {
			t.Errorf("%s: key %s: the advice must name gate %s and say those requests fail: %q", where, name, gate, msg)
		}
		if a[0].Severity != "warning" {
			t.Errorf("%s: key %s: advice is a warning, not %q", where, name, a[0].Severity)
		}
	}
	// Spike S1: a user-presence key under login with scope session lapses
	// after minutes, so its session approval would fail; say so.
	if a := advice(ps, "pressess"); len(a) == 0 || !strings.Contains(a[0].Message, "scope session") || !strings.Contains(a[0].Message, "lapses") {
		t.Errorf("%s: key pressess has user presence and a login rule with scope session: %+v", where, a)
	}
	// A key without user presence whose gates are all block or login with
	// scope: use could get chip-level protection.
	a := advice(ps, "plainuse")
	if len(a) == 0 {
		t.Errorf("%s: key plainuse (no user presence, all gates login+use or block) could be re-created with user presence\n%+v", where, ps)
	} else {
		if !strings.Contains(strings.ToLower(a[0].Message), "presence") {
			t.Errorf("%s: the advice for plainuse must name user presence: %q", where, a[0].Message)
		}
		if a[0].Severity != "warning" {
			t.Errorf("%s: plainuse: advice is a warning, not %q", where, a[0].Severity)
		}
	}
}

func TestConfigCheckAndStatusCompareKeyAuthWithGates(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	for name, auth := range policyKeys {
		e.createKey(t, name, auth)
	}
	// A record nazar can't read: it has no known policy, and must not make
	// check or status fail.
	if err := e.vault.Put(keys.VaultPrefix+"broken", []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	e.activate(t, policyMix+"    broken:\n      gate: login\n")

	chk := e.check(t)
	if !chk.Valid {
		t.Fatalf("advice never makes a config invalid: %+v", chk.Problems)
	}
	if chk.Staged != nil {
		t.Fatalf("nothing is staged: %+v", chk.Staged)
	}
	checkPolicyAdvice(t, "config check", chk.Problems)
	checkPolicyAdvice(t, "status", e.status(t).Problems)
}

// The defaults.fallback counts as a gate that can reach a key without an
// own gate (spec 4.5: all its rules plus its own gate or defaults.fallback).
func TestKeyAuthAdviceCountsDefaultsFallback(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.createKey(t, "github", platform.AuthUserPresence)
	e.createKey(t, "plainkey", platform.AuthNone)
	e.activate(t, `apiVersion: nazar/v1
kind: Config
defaults:
  fallback:
    scope: use
    gate: dialog
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          gate: login
    plainkey:
      rules:
        - apps: [iterm]
          gate: login
`)
	for where, ps := range map[string][]control.ConfigProblem{"config check": e.check(t).Problems, "status": e.status(t).Problems} {
		if a := advice(ps, "github"); len(a) == 0 || !strings.Contains(a[0].Message, "dialog") {
			t.Errorf("%s: github has user presence and defaults.fallback (dialog) reaches it: %+v", where, ps)
		}
		if a := advice(ps, "plainkey"); len(a) != 0 {
			t.Errorf("%s: plainkey can be reached by dialog, so no user presence: %+v", where, a)
		}
	}
}

// Spike S1: the Secure Enclave honours one approval for minutes, so a
// user-presence key that a login gate with scope session or app can reach
// fails once the chip's window lapses, though nazar still remembers the
// approval. config check and status say so for every such source: a rule
// with scope app, defaults.fallback with scope session (for a key without
// its own gate), and the key's own gate. A dialog or none gate is the
// stronger problem (those requests fail at once) and is named first. A
// key whose login gates all use scope use gets no advice.
func TestKeyAuthAdviceLoginScopeLapses(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	for _, name := range []string{"presapp", "presfallback", "presownsess", "presweak", "presuse"} {
		e.createKey(t, name, platform.AuthUserPresence)
	}
	e.createKey(t, "plainfallback", platform.AuthNone)
	e.activate(t, `apiVersion: nazar/v1
kind: Config
defaults:
  fallback:
    scope: session
    gate: login
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    presapp:
      gate: block
      rules:
        - apps: [iterm]
          scope: app
          gate: login
          expire: 8h
    presfallback:
      rules:
        - apps: [iterm]
          gate: login
    presownsess:
      scope: session
      gate: login
    presweak:
      gate: block
      rules:
        - apps: [claude]
          gate: dialog
        - apps: [iterm]
          scope: session
          gate: login
    presuse:
      gate: block
      rules:
        - apps: [iterm]
          scope: use
          gate: login
    plainfallback:
      rules:
        - apps: [iterm]
          gate: login
`)
	for where, ps := range map[string][]control.ConfigProblem{"config check": e.check(t).Problems, "status": e.status(t).Problems} {
		for name, must := range map[string][]string{
			"presapp":      {"scope app", "lapses"},
			"presfallback": {"defaults.fallback", "scope session", "lapses"},
			"presownsess":  {"its own gate", "scope session", "lapses"},
		} {
			a := advice(ps, name)
			if len(a) != 1 {
				t.Errorf("%s: key %s has user presence and a login gate with a remembered approval reaches it: want one advice, got %+v", where, name, a)
				continue
			}
			for _, m := range must {
				if !strings.Contains(a[0].Message, m) {
					t.Errorf("%s: key %s: advice must contain %q: %q", where, name, m, a[0].Message)
				}
			}
			if !strings.Contains(a[0].Message, "scope: use") {
				t.Errorf("%s: key %s: advice must offer scope: use as the fix: %q", where, name, a[0].Message)
			}
			if a[0].Severity != "warning" {
				t.Errorf("%s: key %s: advice is a warning, not %q", where, name, a[0].Severity)
			}
		}
		if a := advice(ps, "presweak"); len(a) != 1 || !strings.Contains(a[0].Message, "dialog") || !strings.Contains(strings.ToLower(a[0].Message), "fail") {
			t.Errorf("%s: key presweak: a dialog gate reaches it, so its one advice names dialog and says those requests fail: %+v", where, a)
		}
		if a := advice(ps, "presuse"); len(a) != 0 {
			t.Errorf("%s: key presuse: block and login with scope use fit user presence: %+v", where, a)
		}
		// Without user presence, a key that defaults.fallback (login, scope
		// session) reaches is no candidate for chip-level presence.
		if a := advice(ps, "plainfallback"); len(a) != 0 {
			t.Errorf("%s: key plainfallback: defaults.fallback has scope session, so no user presence: %+v", where, a)
		}
	}
}

// A clean setup (every key's recorded policy fits its gates, every app
// pinned) gets no problem at all, from check or status.
func TestCleanKeysGetNoProblems(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.createKey(t, "github", platform.AuthUserPresence)
	e.createKey(t, "hydra", platform.AuthUserPresence)
	e.activate(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    github:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
    hydra:
      scope: use
      gate: login
`)
	if ps := e.check(t).Problems; len(ps) != 0 {
		t.Errorf("config check: %+v", ps)
	}
	if ps := e.status(t).Problems; len(ps) != 0 {
		t.Errorf("status: %+v", ps)
	}
}

// config check judges the file it checks: a staged edit that would make a
// user-presence key fail is reported before anyone approves it.
func TestConfigCheckWarnsAboutStagedEdit(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.createKey(t, "github", platform.AuthUserPresence)
	base := `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
ssh_agent:
  keys:
    github:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
`
	e.activate(t, base)
	if a := allAdvice(e.check(t).Problems); len(a) != 0 {
		t.Fatalf("clean before the edit: %+v", a)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{}) // the background prompt is denied: the edit stays staged
	e.stage(t, base+`        - apps: [claude]
          scope: session
          gate: dialog
`, true)
	chk := e.check(t)
	if chk.Staged == nil || !chk.Valid {
		t.Fatalf("the edit must be staged and valid: %+v", chk)
	}
	if a := advice(chk.Problems, "github"); len(a) == 0 || !strings.Contains(a[0].Message, "dialog") {
		t.Fatalf("config check must warn that the staged dialog rule would fail on github: %+v", chk.Problems)
	}
}

// The advice follows the config: tightening the dialog rule to login
// (applied at once, no prompt) makes it go away.
func TestKeyAuthAdviceFollowsTightening(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.createKey(t, "github", platform.AuthUserPresence)
	head := `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    github:
      gate: block
      rules:
        - apps: [iterm]
`
	e.activate(t, head+"          scope: session\n          gate: dialog\n")
	if a := advice(e.status(t).Problems, "github"); len(a) == 0 {
		t.Fatalf("status must say github needs re-creation: %+v", e.status(t).Problems)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{}) // tightening needs no prompt
	e.activate(t, head+"          gate: login\n")
	if a := allAdvice(e.check(t).Problems); len(a) != 0 {
		t.Errorf("config check after tightening: %+v", a)
	}
	if a := allAdvice(e.status(t).Problems); len(a) != 0 {
		t.Errorf("status after tightening: %+v", a)
	}
}

// A key only block reaches is not a presence candidate: nothing may
// use it yet, so nothing decides its protection, and the window's fresh
// key (gate block, no rules) gets no "could be re-created" advice. With a
// login + use rule the advice comes back.
func TestBlockOnlyKeyGetsNoAdvice(t *testing.T) {
	c := cfgFor(t, `apiVersion: nazar/v1
kind: Config
apps:
  iterm:
    app: com.googlecode.iterm2
ssh_agent:
  keys:
    fresh:
      gate: block
    used:
      gate: block
      rules:
        - apps: [iterm]
          gate: login
`)
	if msg := presenceAdvice(c, "fresh", platform.AuthNone); msg != "" {
		t.Fatalf("fresh (block only, no presence): %q", msg)
	}
	if msg := presenceAdvice(c, "used", platform.AuthNone); !strings.Contains(msg, "re-created with user presence") {
		t.Fatalf("used (login + use, no presence): %q", msg)
	}
	// Presence on a block-only key is still fine: no gate can fail.
	if msg := presenceAdvice(c, "fresh", platform.AuthUserPresence); msg != "" {
		t.Fatalf("fresh with presence: %q", msg)
	}
}

func cfgFor(t *testing.T, body string) *config.Config {
	t.Helper()
	c, probs := config.Parse([]byte(body), config.Env{Home: "/Users/u"})
	if probs.HasErrors() {
		t.Fatal(probs)
	}
	return c
}
