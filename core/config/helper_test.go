package config

import (
	"strings"
	"testing"
)

// Secrets design 4, 6.1: helper.git says which HTTPS host a secret
// answers git's credential protocol for. Only https, only the hosts the
// config names; docker and aws helpers are later.

func TestHelperGitParses(t *testing.T) {
	c, probs := mustParse(t, secretsHdr+`  GH_TOKEN:
    deliver: [helper]
    helper:
      git: {host: GitHub.com, username: atas}
    rules:
      - apps: [iterm]
        to: [git-https]
        gate: login
  GHE:
    helper:
      git: {host: "git.example.com:8443"}
`)
	if len(probs) != 0 {
		t.Fatalf("want no problems:\n%s", probs.Error())
	}
	g := c.Secrets["GH_TOKEN"].Helper
	if g == nil || g.Git == nil || g.Git.Host != "github.com" || g.Git.Username != "atas" {
		t.Fatalf("GH_TOKEN helper = %+v (the host is matched in lower case)", g)
	}
	if h := c.Secrets["GHE"].Helper; h == nil || h.Git.Host != "git.example.com:8443" || h.Git.Username != "" {
		t.Fatalf("GHE helper = %+v", h)
	}
	if c.Secrets["GHE"].Deliver[0] != DeliverHelper {
		t.Fatal("the default deliver has helper")
	}
	if name, ok := c.GitSecret("GITHUB.COM"); !ok || name != "GH_TOKEN" {
		t.Fatalf("GitSecret(github.com) = %q %v", name, ok)
	}
	if name, ok := c.GitSecret("git.example.com:8443"); !ok || name != "GHE" {
		t.Fatalf("GitSecret(ghe) = %q %v", name, ok)
	}
	for _, h := range []string{"git.example.com", "example.com", "", "github.com.evil.com"} {
		if name, ok := c.GitSecret(h); ok {
			t.Errorf("GitSecret(%q) = %q: only the hosts the config names", h, name)
		}
	}
	if c.Secrets["GH_TOKEN"].Helper.Git.String() != "https://github.com" {
		t.Fatalf("String = %q", c.Secrets["GH_TOKEN"].Helper.Git.String())
	}
}

func TestHelperGitValidation(t *testing.T) {
	entry := func(body string) string { return secretsHdr + "  X:\n" + body }
	for _, c := range []struct{ body, want string }{
		{"    helper: {docker: {registry: ghcr.io}}\n", "helper.docker is not in this version"},
		{"    helper: {aws: true}\n", "helper.aws is not in this version"},
		{"    helper: {git: {host: github.com, protocol: http}}\n", `unknown field "protocol"`},
		{"    helper: {git: {username: atas}}\n", "host is required"},
		{"    helper: {git: {host: \"https://github.com\"}}\n", "a host name"},
		{"    helper: {git: {host: \"github.com/atas\"}}\n", "a host name"},
		{"    helper: {git: {host: \"-x.com\"}}\n", "a host name"},
		{"    helper: {git: {host: \"x..com\"}}\n", "a host name"},
		{"    helper: {git: {host: \"x.com:\"}}\n", "a host name"},
		{"    helper: {git: {host: \"x.com:123456\"}}\n", "a host name"},
		{"    helper: {git: {host: \"gіthub.com\"}}\n", "a host name"},
		{"    helper: {git: {host: github.com, username: \"a\\nb\"}}\n", "username"},
		{"    helper: {git: {host: github.com, username: \"a=b\"}}\n", "username"},
		{"    helper: {git: {host: github.com, username: \"\"}}\n", "username"},
		{"    helper: {}\n", "helper: needs git"},
		{"    helper: [git]\n", "must be a mapping"},
		{"    deliver: [stdout]\n    helper: {git: {host: github.com}}\n", "deliver has no helper"},
	} {
		wantError(t, entry(c.body), c.want)
	}
	wantError(t, secretsHdr+"  A:\n    helper: {git: {host: github.com}}\n  B:\n    helper: {git: {host: GITHUB.COM}}\n", "already answers git for https://github.com")
	// file: is still for a later task; envAllow: is built (TestEnvAllow) and
	// read only with late-env.
	wantError(t, entry("    file: ~/.nazar/run/files/X\n"), "the file: field is not in this version")
	wantError(t, entry("    envAllow: [HTTPS_PROXY]\n"), "envAllow is for late-env; add late-env to deliver")
}

// The helper is started by git's HTTPS transport, never by git itself, so a
// to: naming com.apple.git would never match a fetch (secrets design 6.1).
func TestHelperGitWarnsAboutGitAsTheReceiver(t *testing.T) {
	_, probs := mustParse(t, secretsHdr+`  X:
    helper: {git: {host: github.com}}
    rules:
      - apps: [iterm]
        to: [{signed: {team: apple, id: com.apple.git}}]
        gate: login
`)
	if !strings.Contains(probs.Error(), "git-remote-http") {
		t.Fatalf("want the warning about git as the receiver:\n%s", probs.Error())
	}
}

// Security review: a host is ASCII. Unicode case folding would make
// "gitlab.\u212ade.org" (KELVIN SIGN) the configured "gitlab.kde.org", so
// a non-ASCII host is refused in the config and never matches a request.
func TestHelperGitHostIsASCII(t *testing.T) {
	wantError(t, secretsHdr+"  X:\n    helper: {git: {host: \"gitlab.\u212ade.org\"}}\n", "a host name")
	c, probs := mustParse(t, secretsHdr+"  X:\n    helper: {git: {host: gitlab.kde.org}}\n")
	if len(probs) != 0 {
		t.Fatal(probs.Error())
	}
	if _, ok := c.GitSecret("gitlab.kde.org"); !ok {
		t.Fatal("the configured host")
	}
	for _, h := range []string{"gitlab.\u212ade.org", "GITLAB.\u212aDE.ORG", "gitlab.kde.org\u0307"} {
		if n, ok := c.GitSecret(h); ok {
			t.Errorf("%q selected %s", h, n)
		}
	}
	if _, ok := c.GitSecret("GitLab.KDE.org"); !ok {
		t.Fatal("ASCII case still folds")
	}
}

// Any to: that matches Apple's git (signed: apple, with its id or none)
// warns: it never matches a fetch, and it hands the token to `git
// credential fill` typed in a shell.
func TestHelperGitWarnsAboutAnyAppleGitReceiver(t *testing.T) {
	for _, to := range []string{"{signed: {team: apple, id: com.apple.git}}", "{signed: {team: apple}}"} {
		_, probs := mustParse(t, secretsHdr+"  X:\n    helper: {git: {host: github.com}}\n    rules:\n      - apps: [iterm]\n        to: ["+to+"]\n        gate: login\n")
		if !strings.Contains(probs.Error(), "git credential fill") {
			t.Errorf("%s: want the warning:\n%s", to, probs.Error())
		}
	}
	_, probs := mustParse(t, secretsHdr+"  X:\n    helper: {git: {host: github.com}}\n    rules:\n      - apps: [iterm]\n        to: [git-https]\n        gate: login\n")
	if strings.Contains(probs.Error(), "git credential fill") {
		t.Fatalf("git-https is the transport:\n%s", probs.Error())
	}
}
