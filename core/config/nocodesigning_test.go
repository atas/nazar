package config

import (
	"testing"
)

// On a platform without code signatures (Linux), a matcher that trusts a
// signature can never match anything, so config check refuses it with the
// matcher Linux has instead; nazar run's late-env delivery is not built
// there, so it is warned about. Portable: these run on every OS.

const (
	signedRefused   = "signed: needs macOS code signatures; on Linux name the program's file with path: or a desktop app with app:"
	appTeamRefused  = "team: is macOS only; on Linux an app: rule pins the app's executable when the change is approved"
	lateEnvLinuxMsg = "deliver: late-env (nazar run) is not available on Linux yet; use helper or stdout"
)

var noSigning = Env{Home: "/home/u", NoCodeSigning: true}

// signedInApps defines a signed: app under apps:.
const signedInApps = hdr + `apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          gate: dialog
`

// signedInline names a signed: matcher inline in a rule's apps:.
const signedInline = hdr + `ssh_agent:
  keys:
    github:
      rules:
        - apps: [{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}]
          gate: dialog
`

// signedInTo names a signed: receiver in a rule's to:.
const signedInTo = hdr + `ssh_agent:
  keys:
    github:
      rules:
        - apps: [{path: /usr/bin/ssh}]
          to: [{signed: {team: apple, id: com.apple.git}}]
          gate: dialog
`

const appTeam = hdr + `ssh_agent:
  keys:
    github:
      rules:
        - apps: [{app: org.gnome.Terminal, team: ABCDE12345}]
          gate: dialog
`

const lateEnvSecret = hdr + `apps:
  mcp: {command: [/usr/bin/env, x]}
secrets:
  API:
    deliver: [late-env]
    rules:
      - apps: [{path: /usr/bin/bash}]
        to: [mcp]
        gate: dialog
`

// problemAt returns the problem with exactly msg, failing unless there is
// one, of severity sev, at path.
func problemAt(t *testing.T, probs Problems, sev Severity, path, msg string) {
	t.Helper()
	for _, p := range probs {
		if p.Message == msg {
			if p.Severity != sev || p.Path != path {
				t.Fatalf("%q: severity %s at %q, want %s at %q", msg, p.Severity, p.Path, sev, path)
			}
			return
		}
	}
	t.Fatalf("no problem %q; got:\n%s", msg, probs.Error())
}

func TestSignedRefusedWithoutCodeSigning(t *testing.T) {
	for _, tc := range []struct{ name, src, path string }{
		{"apps section", signedInApps, "apps.claude"},
		{"inline in apps", signedInline, "ssh_agent.keys.github.rules[1].apps"},
		{"inline in to", signedInTo, "ssh_agent.keys.github.rules[1].to"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, probs := Parse([]byte(tc.src), noSigning)
			if c != nil || !probs.HasErrors() {
				t.Fatalf("want an invalid config, got %v", probs)
			}
			problemAt(t, probs, SevError, tc.path, signedRefused)
		})
	}
}

func TestAppTeamRefusedWithoutCodeSigning(t *testing.T) {
	c, probs := Parse([]byte(appTeam), noSigning)
	if c != nil || !probs.HasErrors() {
		t.Fatalf("want an invalid config, got %v", probs)
	}
	problemAt(t, probs, SevError, "ssh_agent.keys.github.rules[1].apps", appTeamRefused)
	// An app: without team: is the Linux matcher and stays valid.
	plain := hdr + "ssh_agent:\n  keys:\n    github:\n      rules:\n        - apps: [{app: org.gnome.Terminal}]\n          gate: dialog\n"
	if c, probs := Parse([]byte(plain), noSigning); c == nil || probs.HasErrors() {
		t.Fatalf("app: alone must parse on Linux: %v", probs)
	}
}

func TestLateEnvWarnsWithoutCodeSigning(t *testing.T) {
	c, probs := Parse([]byte(lateEnvSecret), noSigning)
	if c == nil || probs.HasErrors() {
		t.Fatalf("late-env is a warning, not an error: %v", probs.Error())
	}
	problemAt(t, probs, SevWarning, "secrets.API.deliver", lateEnvLinuxMsg)
}

// With code signing (macOS, and NoCodeSigning's zero value) the same files
// draw none of the Linux problems.
func TestSameConfigValidWithCodeSigning(t *testing.T) {
	for _, src := range []string{signedInApps, signedInline, signedInTo, appTeam, lateEnvSecret} {
		c, probs := Parse([]byte(src), Env{Home: "/Users/u"})
		if c == nil || probs.HasErrors() {
			t.Fatalf("want a valid config, got:\n%s\n%s", probs.Error(), src)
		}
		for _, p := range probs {
			switch p.Message {
			case signedRefused, appTeamRefused, lateEnvLinuxMsg:
				t.Errorf("macOS drew a Linux problem: %s", p)
			}
		}
	}
}

const anyKeyNone = hdr + `ssh_agent:
  keys:
    github:
      rules:
        - apps: [any]
          gate: none
`

const anySecretNone = hdr + `secrets:
  API:
    rules:
      - apps: [any]
        to: [{path: /usr/bin/curl}]
        gate: none
`

// A rule for every program names the machine and the chip the user has:
// this Mac and the Secure Enclave on macOS, this computer and the TPM on
// Linux.
func TestAnyRuleWordingFollowsThePlatform(t *testing.T) {
	for _, tc := range []struct {
		env         Env
		key, secret string
	}{
		{Env{Home: "/Users/u"},
			"Rule 1 lets every program on this Mac use this key without asking. The key itself never leaves the Secure Enclave.",
			"rule 1 would give this secret to every program on this Mac without asking; name the apps"},
		{noSigning,
			"Rule 1 lets every program on this computer use this key without asking. The key itself never leaves the TPM.",
			"rule 1 would give this secret to every program on this computer without asking; name the apps"},
	} {
		_, probs := Parse([]byte(anyKeyNone), tc.env)
		problemAt(t, probs, SevWarning, "ssh_agent.keys.github.rules[1].apps", tc.key)
		_, probs = Parse([]byte(anySecretNone), tc.env)
		problemAt(t, probs, SevError, "secrets.API.rules[1].apps", tc.secret)
	}
}
