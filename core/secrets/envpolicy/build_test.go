package envpolicy

import (
	"slices"
	"strings"
	"testing"
)

// Secrets design 6.3.4: the receiver's environment is built by the agent
// from its own sources; the caller's environment is input it picks the
// shape-checked LANG/LC_*/TERM and the envAllow names from, never a base.

var host = Host{Home: "/Users/u", User: "u", TmpDir: "/var/folders/xy/abc/T/"}

var trusted = []string{"/usr/bin", "/bin", "/Users/u/.local/share/mise/installs/node/24.0.0/bin"}

var loader = []string{"NODE_OPTIONS=--require \"/Apps/nazar-agent.app/Contents/Resources/loaders/node/env.cjs\"", "NAZAR_SECRET_NAMES=BRAVE_API_KEY"}

func lookup(env []string, name string) (string, bool) {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == name {
			return v, true
		}
	}
	return "", false
}

func TestBuildIgnoresTheCallersBase(t *testing.T) {
	caller := []string{"HOME=/tmp/h", "PATH=/tmp/x:/usr/bin", "USER=root", "LOGNAME=root", "TMPDIR=/tmp/t",
		"LANG=en_US.UTF-8", "TERM=xterm-256color", "LC_ALL=../x", "LC_CTYPE=C", "SHLVL=2"}
	env, passed := Build(Input{TrustedPath: trusted, Host: host, CallerEnv: caller, Loader: loader})
	want := []string{
		"PATH=/usr/bin:/bin:/Users/u/.local/share/mise/installs/node/24.0.0/bin",
		"HOME=/Users/u", "USER=u", "LOGNAME=u", "TMPDIR=/var/folders/xy/abc/T/",
		"LANG=en_US.UTF-8", "LC_CTYPE=C", "TERM=xterm-256color",
	}
	want = append(want, loader...)
	if !slices.Equal(env, want) {
		t.Fatalf("env =\n%q\nwant\n%q", env, want)
	}
	if len(passed) != 0 {
		t.Fatalf("passed = %v", passed)
	}
}

func TestBuildShapeChecksLocaleAndTerm(t *testing.T) {
	for _, kv := range []string{"LANG=../x", "TERM=" + strings.Repeat("x", 40), "LANG=en US", "TERM=", "LC_ALL=a/b", "LANG=$(id)", "LC_=C", "LC_all=C"} {
		env, _ := Build(Input{TrustedPath: trusted, Host: host, CallerEnv: []string{kv}})
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := lookup(env, name); ok {
			t.Errorf("%q must not pass: %q", kv, env)
		}
	}
	for _, kv := range []string{"LANG=C", "LANG=POSIX", "LC_ALL=en_US.UTF-8", "TERM=screen-256color", "LANG=sr_RS@latin"} {
		env, _ := Build(Input{TrustedPath: trusted, Host: host, CallerEnv: []string{kv}})
		name, v, _ := strings.Cut(kv, "=")
		if got, ok := lookup(env, name); !ok || got != v {
			t.Errorf("%q must pass, env %q", kv, env)
		}
	}
}

// Section 11's negative list: none of these reaches the receiver, whatever
// the caller sends, even when a hand-built request carries them.
func TestBuildDropsEverythingElse(t *testing.T) {
	caller := []string{"npm_config_script_shell=/tmp/x.sh", "npm_config_registry=http://127.0.0.1:1", "NPM_CONFIG_REGISTRY=http://x",
		"XDG_CONFIG_HOME=/tmp/c", "PIP_INDEX_URL=http://x", "UV_INDEX_URL=http://x", "PIPX_HOME=/tmp/p", "VIRTUAL_ENV=/tmp/v",
		"NODE_OPTIONS=--require /tmp/x.cjs", "PYTHONSTARTUP=/tmp/s.py", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib", "BASH_ENV=/tmp/b",
		"SHELL=/tmp/sh", "HTTPS_PROXY=http://proxy:8080", "NAZAR_X=1", "FOO=bar", "PYTHONPATH=/tmp/p"}
	env, passed := Build(Input{TrustedPath: trusted, Host: host, CallerEnv: caller})
	for _, kv := range caller {
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := lookup(env, name); ok {
			t.Errorf("%s reached the receiver: %q", name, env)
		}
	}
	if len(passed) != 0 {
		t.Fatalf("passed = %v", passed)
	}
}

func TestBuildPassesEnvAllow(t *testing.T) {
	caller := []string{"HTTPS_PROXY=http://proxy:8080", "NODE_ENV=production", "NODE_OPTIONS=--require /tmp/x.cjs"}
	env, passed := Build(Input{TrustedPath: trusted, Host: host, CallerEnv: caller,
		Allow: []string{"HTTPS_PROXY", "NO_PROXY", "NODE_OPTIONS", "HOME"}})
	if v, ok := lookup(env, "HTTPS_PROXY"); !ok || v != "http://proxy:8080" {
		t.Fatalf("HTTPS_PROXY: %q", env)
	}
	if _, ok := lookup(env, "NO_PROXY"); ok {
		t.Fatal("an allowed name the caller did not set is absent")
	}
	if v, _ := lookup(env, "NODE_OPTIONS"); v != "" {
		t.Fatal("an allow list naming a denied variable still never passes it")
	}
	if v, _ := lookup(env, "HOME"); v != host.Home {
		t.Fatal("an allow list naming a base variable never overrides it")
	}
	if _, ok := lookup(env, "NODE_ENV"); ok {
		t.Fatal("NODE_ENV is not allowed")
	}
	if !slices.Equal(passed, []string{"HTTPS_PROXY"}) {
		t.Fatalf("passed = %v", passed)
	}
}

// A name the caller sends twice has no one value: it is not passed.
func TestBuildRefusesAmbiguousCallerValues(t *testing.T) {
	env, passed := Build(Input{TrustedPath: trusted, Host: host, Allow: []string{"HTTPS_PROXY"},
		CallerEnv: []string{"HTTPS_PROXY=http://a", "HTTPS_PROXY=http://b", "LANG=C", "LANG=en_US.UTF-8", "junk", "=x"}})
	if _, ok := lookup(env, "HTTPS_PROXY"); ok || len(passed) != 0 {
		t.Fatalf("an ambiguous value must not pass: %q", env)
	}
	if _, ok := lookup(env, "LANG"); ok {
		t.Fatalf("an ambiguous LANG must not pass: %q", env)
	}
}

// No base value is ever empty, and no TMPDIR is invented.
func TestBuildWithoutTmpDir(t *testing.T) {
	env, _ := Build(Input{TrustedPath: trusted, Host: Host{Home: "/h", User: "u"}})
	if _, ok := lookup(env, "TMPDIR"); ok {
		t.Fatalf("no TMPDIR when the host has none: %q", env)
	}
	if names := Names(env); slices.Contains(names, "") {
		t.Fatalf("names = %q", names)
	}
}

// Review: no base variable is ever empty; a host without a home or a user
// name gives none of HOME, USER, LOGNAME (the agent refuses such a host
// before it gets here).
func TestBuildOmitsEmptyBaseValues(t *testing.T) {
	env, _ := Build(Input{TrustedPath: trusted, Host: Host{}})
	for _, n := range []string{"HOME", "USER", "LOGNAME", "TMPDIR"} {
		if _, ok := lookup(env, n); ok {
			t.Errorf("%s must be omitted when empty: %q", n, env)
		}
	}
	for _, kv := range env {
		if strings.HasSuffix(kv, "=") {
			t.Errorf("empty value %q", kv)
		}
	}
}
