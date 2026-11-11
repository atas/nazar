//go:build linux && linuxe2e

package e2e

// The two deliveries that go through Debian's /bin/sh, which is dash and
// does not exec the command of `sh -c`: git runs its credential helper
// that way (secrets design 6.1), and the Go SDK and Terraform run
// credential_process that way (aws design 3.4). Both are driven here with
// the image's real git and sh against local TLS servers.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/aws/awstest"
	"github.com/atas/nazar/core/layout"
)

// gitTransport is the file git's HTTPS transport runs as on this image:
// git-remote-https under `git --exec-path`, links resolved, which is what
// /proc reports and what docs/CLI.md tells a user to name in to:.
func gitTransport(t *testing.T) string {
	t.Helper()
	out, err := exec.Command(gitPath, "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path: %v", err)
	}
	p, err := filepath.EvalSymlinks(filepath.Join(strings.TrimSpace(string(out)), "git-remote-https"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// certFile writes a TLS test server's certificate as PEM, for git's
// http.sslCAInfo and the agent's AWS roots.
func certFile(t *testing.T, dir string, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(dir, "server.crt")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestGitHTTPSCredentialHelper: with `credential.helper = nazar` and the
// rule docs/CLI.md gives (`to:` the transport's file), git over HTTPS gets
// the token after a dialog, through `git credential-nazar get` under the
// /bin/sh git runs it with; `git credential fill` from a shell gets
// nothing, with no dialog.
func TestGitHTTPSCredentialHelper(t *testing.T) {
	const token = "ghp-e2e-token-3f9a"
	w := newWorld(t)
	var authed atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("atas:"+token)) {
			rw.Header().Set("WWW-Authenticate", `Basic realm="nazar e2e"`)
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		authed.Add(1)
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK) // dumb HTTP: an empty info/refs is a repository with no refs
	}))
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "https://")
	ca := certFile(t, w.home, srv)

	w.q.Push(true)
	if out, code := w.run(token, nil, filepath.Join(bin, "nazar"), "secret", "add", "GH_TOKEN"); code != 0 {
		t.Fatalf("secret add: exit %d\n%s", code, out)
	}
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\napps:\n  githttp: {path: " + gitTransport(t) + "}\n" +
		"secrets:\n  GH_TOKEN:\n    deliver: [helper]\n    helper:\n      git: {host: \"" + host + "\", username: atas}\n" +
		"    rules:\n      - apps: [any]\n        to: [githttp]\n        gate: dialog\n        scope: use\n")

	// git finds git-credential-nazar on PATH, as nazar install links it.
	env := []string{"PATH=/usr/bin:/bin:/usr/local/bin:" + bin, "GIT_TERMINAL_PROMPT=0"}
	w.q.Push(true)
	out, code := w.run("", env, gitPath, "-c", "credential.helper=nazar", "-c", "http.sslCAInfo="+ca, "ls-remote", srv.URL+"/repo.git")
	if code != 0 || authed.Load() == 0 {
		t.Fatalf("git ls-remote with the helper: exit %d, %d authenticated requests\n%s", code, authed.Load(), out)
	}
	if strings.Contains(out, token) {
		t.Fatal("the token is in git's output")
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1", n)
	}
	approved := w.log("--decision", "approved", "--target", "secret:GH_TOKEN")
	if !strings.Contains(approved, "git-remote-http") {
		t.Fatalf("the approval does not name the transport as the receiver:\n%s", approved)
	}

	// `git credential fill` from a shell: the dispatcher and the sh are
	// stepped over and the receiver is git itself, which to: does not name.
	w.q.Push(true)
	out, code = w.run("protocol=https\nhost="+host+"\n\n", env, gitPath, "-c", "credential.helper=nazar", "credential", "fill")
	if strings.Contains(out, token) || strings.Contains(out, "password=") {
		t.Fatalf("git credential fill got the token (exit %d):\n%s", code, out)
	}
	if n := w.dialogs(); n != 1 {
		t.Fatalf("%d dialogs shown, want 1: the refusal comes before any prompt", n)
	}
	if allow, ok := w.q.Pop(0); !ok || !allow {
		t.Fatal("credential fill consumed the queued answer: a prompt was shown")
	}
	if blocked := w.log("--decision", "blocked", "--target", "secret:GH_TOKEN"); !strings.Contains(blocked, "to:") {
		t.Fatalf("no blocked line naming the to: rule:\n%s", blocked)
	}
}

// TestAWSCredentialProcess: an aws entry set up with nazar aws ca create
// against a fake Roles Anywhere endpoint, then credential_process run the
// three ways programs run it: directly (the AWS CLI), by `/bin/sh -c`
// with stdout a pipe (the Go SDK, Terraform; the sh stays as the parent on
// Debian) and by a shell that relays the output through another program,
// which is refused before any prompt.
func TestAWSCredentialProcess(t *testing.T) {
	const (
		anchor  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
		profile = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
		role    = "arn:aws:iam::123456789012:role/dev"
	)
	var srv *awstest.Server
	w := newWorld(t, func(w *world) {
		srv = awstest.Start(t, "us-east-1", nil)
		w.agentEnv = []string{"NAZAR_TEST_AWS_ENDPOINT=" + srv.URL, "NAZAR_TEST_AWS_ROOTS=" + certFile(t, w.home, srv.Server)}
	})

	w.q.Push(true)
	if out, code := w.nazar("aws", "ca", "create", "dev"); code != 0 {
		t.Fatalf("aws ca create: exit %d\n%s", code, out)
	}
	caPEM, err := os.ReadFile(filepath.Join(layout.KeysDir(w.home), "aws-ca-dev.crt"))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetAnchors(caPEM)
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\naws:\n  dev:\n    identity: {user: " + testUser + "-nazar}\n" +
		"    trustAnchorArn: " + anchor + "\n    profileArn: " + profile + "\n    roleArn: " + role + "\n" +
		"    rules:\n      - apps: [any]\n        gate: dialog\n        scope: use\n")

	nazar := filepath.Join(bin, "nazar")
	// run runs credential_process as a program would: stdout a pipe this
	// process reads, stderr apart.
	run := func(name string, args ...string) (stdout, stderr string, code int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = w.env()
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		if ctx.Err() != nil {
			t.Fatalf("%s %v hung", name, args)
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return out.String(), errb.String(), ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return out.String(), errb.String(), 0
	}
	session := func(name string, stdout string) {
		t.Helper()
		var c struct {
			Version         int    `json:"Version"`
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			SessionToken    string `json:"SessionToken"`
		}
		if err := json.Unmarshal([]byte(stdout), &c); err != nil || c.Version != 1 || c.AccessKeyID != awstest.AccessKeyID ||
			c.SecretAccessKey != awstest.SecretAccessKey || c.SessionToken != awstest.SessionToken {
			t.Fatalf("%s: not the fake's session (%v): %s", name, err, stdout)
		}
	}

	// Directly, as the AWS CLI runs it.
	w.q.Push(true)
	out, errb, code := run(nazar, "aws", "credential", "dev")
	if code != 0 {
		t.Fatalf("aws credential: exit %d\n%s%s", code, out, errb)
	}
	session("direct", out)
	if srv.Accepted() != 1 || w.dialogs() != 1 {
		t.Fatalf("%d sessions, %d dialogs; want 1 and 1", srv.Accepted(), w.dialogs())
	}

	// By /bin/sh -c, as the Go SDK and Terraform run it: dash stays
	// between the program and the CLI, holding the write end it passed on.
	w.q.Push(true)
	out, errb, code = run("/bin/sh", "-c", nazar+" aws credential dev")
	if code != 0 {
		t.Fatalf("sh -c credential_process: exit %d\n%s%s", code, out, errb)
	}
	session("sh -c", out)
	if srv.Accepted() != 2 || w.dialogs() != 2 {
		t.Fatalf("%d sessions, %d dialogs; want 2 and 2", srv.Accepted(), w.dialogs())
	}
	// Two credential approvals in the log (the entry's setup is a third
	// approved line), the second with the shell in its chain.
	approved := w.log("--decision", "approved", "--target", "aws:dev")
	if strings.Count(approved, "approved for this request") != 2 || !strings.Contains(approved, "> dash(") {
		t.Fatalf("want two credential approvals in the log, one through dash:\n%s", approved)
	}
	for _, secret := range []string{awstest.SecretAccessKey, awstest.SessionToken} {
		if strings.Contains(w.read(layout.AuditLog(w.home)), secret) || strings.Contains(w.read(w.agentLog), secret) {
			t.Fatal("a session secret is in a log")
		}
	}

	// A shell that relays the output through another program: the CLI's
	// pipe goes to tee, not to the program that ran the shell, so it is
	// refused before any prompt and nothing is minted.
	w.q.Push(true)
	out, errb, code = run("/bin/sh", "-c", nazar+" aws credential dev | tee /dev/null")
	if strings.Contains(out, awstest.AccessKeyID) || !strings.Contains(errb, "the credential's output does not go straight to the program that ran it") {
		t.Fatalf("relayed through tee: exit %d\nstdout %s\nstderr %s", code, out, errb)
	}
	if srv.Accepted() != 2 || w.dialogs() != 2 {
		t.Fatalf("%d sessions, %d dialogs; want still 2 and 2", srv.Accepted(), w.dialogs())
	}
	if allow, ok := w.q.Pop(0); !ok || !allow {
		t.Fatal("the relayed run consumed the queued answer: a prompt was shown")
	}
	if blocked := w.log("--decision", "blocked", "--target", "aws:dev"); !strings.Contains(blocked, "does not go straight") {
		t.Fatalf("the refusal is not in the log:\n%s", blocked)
	}
}
