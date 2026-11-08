package daemon

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Secrets design 6.1: secret.helper answers git's credential
// protocol. Only https, only a host a secret's helper.git names; the
// receiver is git's HTTPS transport (the parent of the `git
// credential-nazar` dispatcher that runs the helper); only the genuine CLI
// gets an answer.

const helperConfig = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  git-https: {signed: {team: apple, id: com.apple.git-remote-http}}
secrets:
  GH_TOKEN:
    deliver: [helper]
    helper:
      git: {host: github.com, username: atas}
    rules:
      - apps: [iterm]
        to: [git-https]
        scope: session
        gate: dialog
`

func gitFetch() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/bin/git", Args: []string{"git", "fetch", "origin"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git")}
}

func gitTransport() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http", Args: []string{"git-remote-https", "origin", "https://github.com/atas/nazar.git"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git-remote-http")}
}

// gitDispatcher is the `git credential-nazar get` that git starts for
// `credential.helper = nazar`; it runs git-credential-nazar as its child.
func gitDispatcher() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/bin/git", Args: []string{"git", "credential-nazar", "get"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git")}
}

func helperCLI() fake.Proc {
	p := cliProc()
	p.Args = []string{"git-credential-nazar", "get"}
	return p
}

func (e *env) helper(t *testing.T, args map[string]string) (control.SecretValue, *control.Problem) {
	t.Helper()
	var v control.SecretValue
	err := e.call(t, control.CmdSecretHelper, args, control.KindSecretValue, &v)
	return v, control.AsProblem(err)
}

func startHelper(t *testing.T) *env {
	t.Helper()
	e := startSecrets(t)
	e.approved(t, helperConfig)
	e.asCLI(cliProc("secret", "add", "GH_TOKEN"))
	if _, p := e.addSecret(t, "GH_TOKEN", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	return e
}

func TestHelperAnswersGitsTransport(t *testing.T) {
	e := startHelper(t)
	e.asCLI(gitFetch(), gitTransport(), gitDispatcher(), helperCLI())
	v, p := e.helper(t, map[string]string{"protocol": "https", "host": "GitHub.com"})
	if p != nil || v.Name != "GH_TOKEN" || v.ValueBase64 != b64(testValue) || v.Username != "atas" {
		t.Fatalf("%v: name %q, username %q, %d bytes", p, v.Name, v.Username, len(v.ValueBase64))
	}
	lines := e.auditFor(t, "secret:GH_TOKEN")
	f := lines[len(lines)-1]
	if f["decision"] != string(audit.Approved) || f["delivery"] != "helper" || !strings.HasPrefix(f["receiver"], "git-remote-https ") ||
		f["destination"] != "github.com" || f["rule"] != "1" {
		t.Fatalf("audit %v", f)
	}
	// The same transport asks again in the tab: remembered.
	if _, p := e.helper(t, map[string]string{"protocol": "https", "host": "github.com"}); p != nil {
		t.Fatal(p)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("%d dialogs, want 1", n)
	}
	// A username the request names must be the configured one.
	if _, p := e.helper(t, map[string]string{"protocol": "https", "host": "github.com", "username": "someone"}); p.ExitCode() != control.ExitRefused {
		t.Fatalf("another username: %+v", p)
	}
}

// Transport narrowing: only https, only a host the config names; the
// refusal comes before the pipeline (nothing asked, nothing opened).
func TestHelperOnlyHTTPSAndConfiguredHosts(t *testing.T) {
	e := startHelper(t)
	e.asCLI(gitFetch(), gitTransport(), gitDispatcher(), helperCLI())
	for _, args := range []map[string]string{
		{"protocol": "http", "host": "github.com"},
		{"protocol": "ssh", "host": "github.com"},
		{"protocol": "", "host": "github.com"},
		{"protocol": "https", "host": "gitlab.com"},
		{"protocol": "https", "host": "github.com.evil.example"},
		{"protocol": "https", "host": ""},
		{"protocol": "https", "host": "github.com\nhost=x"},
	} {
		if v, p := e.helper(t, args); p.ExitCode() != control.ExitRefused || v.ValueBase64 != "" {
			t.Errorf("%q: %+v", args, p)
		}
	}
	if e.f.CountShown(fake.KindConfirm) != 0 {
		t.Fatal("no dialog for a request nazar has no secret for")
	}
}

// `git credential fill` typed in a shell: the dispatcher's parent is git
// itself, not the HTTPS transport, so to: misses (secrets design 6.1). A
// process that only looks like the dispatcher (not Apple's git) is never
// skipped: its own identity is the receiver.
func TestHelperReceiverIsTheTransport(t *testing.T) {
	e := startHelper(t)
	args := map[string]string{"protocol": "https", "host": "github.com"}
	fill := fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/bin/git", Args: []string{"git", "credential", "fill"}, Code: fake.AppleCode("com.apple.git")}
	e.asCLI(scriptProc("x.sh"), fill, gitDispatcher(), helperCLI())
	if _, p := e.helper(t, args); p.ExitCode() != control.ExitRefused {
		t.Fatalf("credential fill from a shell: %+v", p)
	}
	lookalike := gitDispatcher()
	lookalike.Path, lookalike.Code = "/tmp/git", platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "com.apple.git"}
	e.asCLI(gitFetch(), gitTransport(), lookalike, helperCLI())
	if _, p := e.helper(t, args); p.ExitCode() != control.ExitRefused {
		t.Fatalf("a look-alike dispatcher must be the receiver itself: %+v", p)
	}
	// The helper run directly by the transport (credential.helper set to
	// the absolute path of git-credential-nazar) has the transport as its
	// parent.
	e.asCLI(gitFetch(), gitTransport(), helperCLI())
	if _, p := e.helper(t, args); p != nil {
		t.Fatalf("helper run by the transport: %+v", p)
	}
	if e.f.CountShown(fake.KindConfirm) != 1 {
		t.Fatal("only the transport's request reaches a dialog")
	}
}

// secret.helper is a value command: any peer but the genuine CLI is refused.
func TestHelperAnswersOnlyTheGenuineCLI(t *testing.T) {
	e := startHelper(t)
	fakeCLI := fake.Proc{Path: "/Users/u/.local/bin/git-credential-nazar", Args: []string{"git-credential-nazar", "get"}, Code: fake.Unsigned}
	e.asCLI(gitFetch(), gitTransport(), gitDispatcher(), fakeCLI)
	if _, p := e.helper(t, map[string]string{"protocol": "https", "host": "github.com"}); p.ExitCode() != control.ExitRefused || p.Message != "peer is not the nazar CLI" {
		t.Fatalf("%+v", p)
	}
	lines := e.auditFor(t, "secret:")
	if f := lines[len(lines)-1]; f["decision"] != string(audit.Blocked) || f["delivery"] != "helper" {
		t.Fatalf("audit %v", f)
	}
}

// A refusal reads as the URL git asked for, quoted only when
// it is not a plain host; a non-genuine helper's blocked audit line names
// the transport as the receiver, as an answered one does.
func TestHelperRefusalTextAndAuditedReceiver(t *testing.T) {
	e := startHelper(t)
	e.asCLI(gitFetch(), gitTransport(), gitDispatcher(), helperCLI())
	if _, p := e.helper(t, map[string]string{"protocol": "https", "host": "gitlab.com"}); p.Message != "no secret for https://gitlab.com" {
		t.Fatalf("%q", p.Message)
	}
	if _, p := e.helper(t, map[string]string{"protocol": "https", "host": "a\nb"}); p.Message != `no secret for "https://a\nb"` {
		t.Fatalf("%q", p.Message)
	}
	fakeCLI := fake.Proc{Path: "/Users/u/.local/bin/git-credential-nazar", Args: []string{"git-credential-nazar", "get"}, Code: fake.Unsigned}
	e.asCLI(gitFetch(), gitTransport(), gitDispatcher(), fakeCLI)
	e.helper(t, map[string]string{"protocol": "https", "host": "github.com"})
	lines := e.auditFor(t, "secret:GH_TOKEN")
	if f := lines[len(lines)-1]; f["decision"] != string(audit.Blocked) || !strings.HasPrefix(f["receiver"], "git-remote-https ") {
		t.Fatalf("audit %v", f)
	}
}
