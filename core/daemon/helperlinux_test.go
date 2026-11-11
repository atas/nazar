package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Secrets design 6.1 on a platform without code signatures (Linux): git
// runs its credential helper through /bin/sh -c, which on Debian and
// Ubuntu is dash and stays as the helper's parent, and `credential.helper
// = nazar` puts an unsigned `git credential-nazar get` dispatcher under
// it. The receiver is still git's HTTPS transport, named by a to: path:
// rule, and `git credential fill` from a shell is still refused.
// Portable: these run on every OS.

// helperLinuxConfig names the transport by the file at path.
func helperLinuxConfig(path string) string {
	return `apiVersion: nazar/v1
kind: Config
apps:
  git-https: {path: ` + path + `}
secrets:
  GH_TOKEN:
    deliver: [helper]
    helper:
      git: {host: github.com, username: atas}
    rules:
      - apps: [any]
        to: [git-https]
        scope: use
        gate: dialog
`
}

// transportFile is a file standing for /usr/lib/git-core/git-remote-http:
// a path: rule matches only a path that exists.
func transportFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "git-remote-http")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The processes of a Debian git over HTTPS, none signed.
func linuxGit(args ...string) fake.Proc {
	return fake.Proc{Path: "/usr/bin/git", Args: append([]string{"git"}, args...), Cwd: "/home/u/projects/foo", Code: fake.Unsigned}
}

func linuxTransport(path string) fake.Proc {
	return fake.Proc{Path: path, Args: []string{"git-remote-https", "origin", "https://github.com/atas/nazar.git"}, Cwd: "/home/u/projects/foo", Code: fake.Unsigned}
}

// dash is the /bin/sh -c git runs a helper through (run-command.c passes
// the command again as $0); it does not exec its command, so it stays as
// the parent.
func dash(command string) fake.Proc {
	return fake.Proc{Path: "/usr/bin/dash", Args: []string{"/bin/sh", "-c", command, command}, Cwd: "/home/u/projects/foo", Code: fake.Unsigned}
}

func startLinuxHelper(t *testing.T, mod func(f *fake.Fake, o *Options)) (*env, string) {
	t.Helper()
	path := transportFile(t)
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		if mod != nil {
			mod(f, o)
		}
	})
	e.approved(t, helperLinuxConfig(path))
	e.asCLI(cliProc("secret", "add", "GH_TOKEN"))
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if _, p := e.addSecret(t, "GH_TOKEN", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	return e, path
}

func TestLinuxHelperReceiverIsTheTransport(t *testing.T) {
	e, path := startLinuxHelper(t, onLinux)
	args := map[string]string{"protocol": "https", "host": "github.com"}
	shown := e.f.CountShown(fake.KindConfirm)
	for name, chain := range map[string][]fake.Proc{
		"credential.helper = nazar":                   {linuxGit("fetch", "origin"), linuxTransport(path), dash("git credential-nazar get"), linuxGit("credential-nazar", "get"), helperCLI()},
		"credential.helper by the link's path":        {linuxGit("fetch", "origin"), linuxTransport(path), dash("/home/u/.local/bin/git-credential-nazar get"), helperCLI()},
		"a shell given the command without $0":        {linuxGit("fetch", "origin"), linuxTransport(path), {Path: "/bin/dash", Args: []string{"sh", "-c", "git credential-nazar get"}, Code: fake.Unsigned}, linuxGit("credential-nazar", "get"), helperCLI()},
		"a shell given the command and its arguments": {linuxGit("fetch", "origin"), linuxTransport(path), {Path: "/usr/bin/dash", Args: []string{"/bin/sh", "-c", `git credential-nazar "$@"`, "git credential-nazar", "get"}, Code: fake.Unsigned}, linuxGit("credential-nazar", "get"), helperCLI()},
		"a shell that execs the helper (bash as sh)":  {linuxGit("fetch", "origin"), linuxTransport(path), linuxGit("credential-nazar", "get"), helperCLI()},
		"a transport that runs the link itself":       {linuxGit("fetch", "origin"), linuxTransport(path), helperCLI()},
	} {
		e.asCLI(chain...)
		v, p := e.helper(t, args)
		if p != nil || v.ValueBase64 != b64(testValue) || v.Username != "atas" {
			t.Fatalf("%s: %+v %+v", name, p, v)
		}
		shown++
		if e.f.CountShown(fake.KindConfirm) != shown {
			t.Fatalf("%s: the transport's request did not reach a dialog", name)
		}
		lines := e.auditFor(t, "secret:GH_TOKEN")
		if f := lines[len(lines)-1]; f["decision"] != string(audit.Approved) || !strings.HasPrefix(f["receiver"], "git-remote-https ") {
			t.Fatalf("%s: audit %v", name, f)
		}
	}
}

// Stepping over the dispatcher and the shell never moves the receiver past
// what git itself put there: `git credential fill` from a shell, a shell
// given more than the helper to run, and a shell that is not git's are
// the receiver themselves, and to: does not match them.
func TestLinuxHelperStillRefusesOtherReceivers(t *testing.T) {
	e, path := startLinuxHelper(t, onLinux)
	args := map[string]string{"protocol": "https", "host": "github.com"}
	shown := e.f.CountShown(fake.KindConfirm)
	for name, chain := range map[string][]fake.Proc{
		"git credential fill from a shell":       {scriptProc("x.sh"), linuxGit("credential", "fill"), dash("git credential-nazar get"), linuxGit("credential-nazar", "get"), helperCLI()},
		"a shell that runs more than the helper": {linuxGit("fetch", "origin"), linuxTransport(path), dash("git credential-nazar get; cat /tmp/x"), linuxGit("credential-nazar", "get"), helperCLI()},
		"a shell with a pipe":                    {linuxGit("fetch", "origin"), linuxTransport(path), dash("git credential-nazar get | tee /tmp/x"), linuxGit("credential-nazar", "get"), helperCLI()},
		"a shell told to run something else":     {linuxGit("fetch", "origin"), linuxTransport(path), dash("/home/u/evil get"), helperCLI()},
		"a shell with a second argument":         {linuxGit("fetch", "origin"), linuxTransport(path), {Path: "/usr/bin/dash", Args: []string{"/bin/sh", "-c", "git credential-nazar get", "x"}, Code: fake.Unsigned}, helperCLI()},
		"a program called sh that is not one":    {linuxGit("fetch", "origin"), linuxTransport(path), {Path: "/home/u/sh", Args: []string{"sh", "-c", "git credential-nazar get"}, Code: fake.Unsigned}, helperCLI()},
		"the shell run by something else":        {scriptProc("x.sh"), dash("git credential-nazar get"), linuxGit("credential-nazar", "get"), helperCLI()},
		// A look-alike git set as the helper, which runs the real one and
		// reads its output: it is the receiver, not the transport above it.
		"a git that is not the system's, under the shell": {linuxGit("fetch", "origin"), linuxTransport(path), dash("/home/u/.cache/x/git credential-nazar get"), fake.Proc{Path: "/home/u/.cache/x/git", Args: []string{"/home/u/.cache/x/git", "credential-nazar", "get"}, Cwd: "/home/u/projects/foo", Code: fake.Unsigned}, helperCLI()},
		"a git that is not the system's, alone":           {linuxGit("fetch", "origin"), linuxTransport(path), fake.Proc{Path: "/home/u/.cache/x/git", Args: []string{"/home/u/.cache/x/git", "credential-nazar", "get"}, Cwd: "/home/u/projects/foo", Code: fake.Unsigned}, helperCLI()},
		"it runs the system's git":                        {linuxGit("fetch", "origin"), linuxTransport(path), dash("/home/u/.cache/x/git credential-nazar get"), fake.Proc{Path: "/home/u/.cache/x/git", Args: []string{"/home/u/.cache/x/git", "credential-nazar", "get"}, Cwd: "/home/u/projects/foo", Code: fake.Unsigned}, linuxGit("credential-nazar", "get"), helperCLI()},
	} {
		e.asCLI(chain...)
		v, p := e.helper(t, args)
		if p == nil || p.ExitCode() != control.ExitRefused || v.ValueBase64 != "" {
			t.Fatalf("%s: %+v %+v", name, p, v)
		}
		if e.f.CountShown(fake.KindConfirm) != shown {
			t.Fatalf("%s: a dialog was shown", name)
		}
	}
}

// On macOS the same unsigned chain is refused as before: only Apple's git
// is stepped over, by its signature, and no shell is.
func TestMacHelperIgnoresUnsignedDispatcherAndShell(t *testing.T) {
	e, path := startLinuxHelper(t, nil)
	if e.d.traits != platform.MacTraits {
		t.Fatal("not the macOS daemon")
	}
	args := map[string]string{"protocol": "https", "host": "github.com"}
	shown := e.f.CountShown(fake.KindConfirm)
	for name, chain := range map[string][]fake.Proc{
		"an unsigned dispatcher under a shell": {linuxGit("fetch", "origin"), linuxTransport(path), dash("git credential-nazar get"), linuxGit("credential-nazar", "get"), helperCLI()},
		"a shell alone":                        {linuxGit("fetch", "origin"), linuxTransport(path), dash("/home/u/.local/bin/git-credential-nazar get"), helperCLI()},
		"an unsigned dispatcher alone":         {linuxGit("fetch", "origin"), linuxTransport(path), linuxGit("credential-nazar", "get"), helperCLI()},
	} {
		e.asCLI(chain...)
		if v, p := e.helper(t, args); p == nil || p.ExitCode() != control.ExitRefused || v.ValueBase64 != "" {
			t.Fatalf("%s: %+v %+v", name, p, v)
		}
		if e.f.CountShown(fake.KindConfirm) != shown {
			t.Fatalf("%s: a dialog was shown", name)
		}
	}
	// The transport running the link itself is the receiver on both.
	e.asCLI(linuxGit("fetch", "origin"), linuxTransport(path), helperCLI())
	if _, p := e.helper(t, args); p != nil {
		t.Fatal(p)
	}
}
