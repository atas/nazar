package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/unixsock"
)

// Secrets design 6.1, 6.5: git-credential-nazar speaks git's
// credential protocol on stdin/stdout; nazar get prints a value to stdout.
// No test touches the real git config: git runs with GIT_CONFIG_GLOBAL in
// a temp HOME and GIT_CONFIG_NOSYSTEM.

const helperValue = "nazar-m8-04-helper-value-5c1e"

func (h *harness) helperServer(t *testing.T, refuse bool) {
	t.Helper()
	h.serve(t, func(ctx context.Context, req control.Request, out control.Emitter) {
		switch {
		case refuse:
			out.Emit(control.NewProblem(control.CodeRefused, "refused: rule 1 blocks this caller"))
		case req.Command == control.CmdSecretHelper || req.Command == control.CmdSecretGet:
			out.Emit(control.SecretValue{TypeMeta: control.Meta(control.KindSecretValue), Name: "GH_TOKEN", Username: "atas",
				ValueBase64: base64.StdEncoding.EncodeToString([]byte(helperValue))})
		default:
			out.Emit(control.NewProblem(control.CodeUsage, "unexpected %s", req.Command))
		}
	})
}

func (h *harness) credential(action, in string) int {
	h.out.Reset()
	h.errb.Reset()
	h.a.stdin = strings.NewReader(in)
	return h.a.gitCredential([]string{action})
}

func TestGitCredentialGet(t *testing.T) {
	h := newHarness(t)
	h.helperServer(t, false)
	in := "protocol=https\nhost=github.com\npath=atas/nazar.git\nwwwauth[]=Basic realm=\"GitHub\"\ncapability[]=authtype\n\nignored=after the blank line\n"
	if code := h.credential("get", in); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if got := h.out.String(); got != "username=atas\npassword="+helperValue+"\n" {
		t.Fatalf("stdout has %d bytes, want the username and password lines", len(got))
	}
	r := h.requests()
	if len(r) != 1 || r[0].Command != control.CmdSecretHelper || r[0].Args["protocol"] != "https" || r[0].Args["host"] != "github.com" ||
		r[0].Args["username"] != "" || len(r[0].Args) != 2 {
		t.Fatalf("request %+v", r)
	}
	if code := h.credential("get", "protocol=https\nhost=github.com\nusername=atas\n"); code != 0 || h.requests()[1].Args["username"] != "atas" {
		t.Fatalf("username passed on: exit %d %+v", code, h.requests()[1])
	}
}

// store and erase do nothing (nazar is the source of truth), and so does
// any action git adds later; none asks nazar-agent anything.
func TestGitCredentialStoreEraseAndOthers(t *testing.T) {
	h := newHarness(t)
	h.helperServer(t, false)
	for _, action := range []string{"store", "erase", "capability", "future"} {
		if code := h.credential(action, "protocol=https\nhost=github.com\npassword=whatever\n"); code != 0 || h.out.Len() != 0 {
			t.Errorf("%s: exit %d, stdout %q", action, code, h.out.String())
		}
	}
	if n := len(h.requests()); n != 0 {
		t.Fatalf("%d requests", n)
	}
	for _, args := range [][]string{{}, {"get", "extra"}} {
		h.a.stdin = strings.NewReader("")
		h.out.Reset()
		if code := h.a.gitCredential(args); code != control.ExitUsage || h.out.Len() != 0 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

// Narrowing on the CLI side too: only https asks at all; a refusal or a
// value git's protocol could not carry prints nothing and exits non-zero,
// so git falls through to its next helper or its prompt.
func TestGitCredentialRefusals(t *testing.T) {
	h := newHarness(t)
	h.helperServer(t, false)
	for _, in := range []string{
		"protocol=http\nhost=github.com\n",
		"protocol=ssh\nhost=github.com\n",
		"host=github.com\n",
		"protocol=https\n",
		"protocol=https\nhost=a\nhost=b\n",
		"protocol=https\nprotocol=http\nhost=github.com\n",
		"garbage\n",
	} {
		if code := h.credential("get", in); code != control.ExitRefused || h.out.Len() != 0 {
			t.Errorf("%q: exit %d, stdout %q", in, code, h.out.String())
		}
	}
	if n := len(h.requests()); n != 0 {
		t.Fatalf("%d requests for input nazar never asks about", n)
	}
	h2 := newHarness(t)
	h2.helperServer(t, true)
	if code := h2.credential("get", "protocol=https\nhost=github.com\n"); code != control.ExitRefused || h2.out.Len() != 0 {
		t.Fatalf("refused: exit %d, stdout %q", code, h2.out.String())
	}
	if !strings.Contains(h2.errb.String(), "rule 1 blocks") {
		t.Fatalf("stderr %q", h2.errb.String())
	}
}

// A value or username with a newline or NUL would add lines to git's
// protocol: refused, nothing printed.
func TestGitCredentialRefusesValuesTheProtocolCantCarry(t *testing.T) {
	for _, c := range []struct{ value, user string }{{"a\nhost=evil", "atas"}, {"a\x00b", "atas"}, {"ok", "at\nas"}} {
		h := newHarness(t)
		h.serve(t, func(ctx context.Context, req control.Request, out control.Emitter) {
			out.Emit(control.SecretValue{TypeMeta: control.Meta(control.KindSecretValue), Name: "X", Username: c.user, ValueBase64: base64.StdEncoding.EncodeToString([]byte(c.value))})
		})
		if code := h.credential("get", "protocol=https\nhost=github.com\n"); code == 0 || h.out.Len() != 0 {
			t.Errorf("%q/%q: exit %d, stdout %q", c.value, c.user, code, h.out.String())
		}
	}
}

func TestNazarGet(t *testing.T) {
	h := newHarness(t)
	h.helperServer(t, false)
	if code := h.run("get", "GH_TOKEN"); code != 0 || h.out.String() != helperValue+"\n" {
		t.Fatalf("exit %d, %d bytes on stdout", code, h.out.Len())
	}
	if r := h.requests(); r[0].Command != control.CmdSecretGet || r[0].Args["name"] != "GH_TOKEN" {
		t.Fatalf("%+v", r)
	}
	// --json changes only the failure path: no JSON kind carries a value.
	h.a.json = true
	h.out.Reset()
	if code := h.a.run([]string{"--json", "get", "GH_TOKEN"}); code != 0 || h.out.String() != helperValue+"\n" {
		t.Fatalf("--json success must still print the raw value: exit %d", code)
	}
	for _, bad := range [][]string{{"get"}, {"get", "a", "b"}, {"get", "a b"}} {
		if code := h.run(bad...); code != control.ExitUsage || strings.Contains(h.out.String(), helperValue) {
			t.Errorf("%q: exit %d", bad, code)
		}
	}
	r := newHarness(t)
	r.helperServer(t, true)
	if code := r.run("get", "GH_TOKEN"); code != control.ExitRefused || r.out.Len() != 0 {
		t.Fatalf("refused: exit %d, stdout %q", code, r.out.String())
	}
	r.out.Reset()
	if code := r.a.run([]string{"--json", "get", "GH_TOKEN"}); code != control.ExitRefused {
		t.Fatalf("--json refused: exit %d", code)
	}
	var p control.Problem
	if err := json.Unmarshal(r.out.Bytes(), &p); err != nil || p.Kind != control.KindProblem || p.Code != control.CodeRefused {
		t.Fatalf("--json failure is a Problem: %q %v", r.out.String(), err)
	}
}

// The real binary, installed as git-credential-nazar next to nazar and
// named by `credential.https://github.com.helper nazar`, answers a real
// `git credential fill`; git never asks for a host the helper line does not
// cover, and nazar is never asked for one.
func TestGitRunsTheHelperThroughGitConfig(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git on this machine")
	}
	dir, err := os.MkdirTemp("/tmp", "nzgc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	bin := buildNazar(t, dir)
	if err := os.Symlink(bin, filepath.Join(dir, "git-credential-nazar")); err != nil {
		t.Fatal(err)
	}
	// The README's two lines, run against this file only: the empty helper
	// clears any helper set before (the system's osxkeychain), then nazar.
	gitconfig := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(gitconfig, []byte("[credential]\n\thelper = \"!echo password=from-the-old-helper\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"config", "--global", "--replace-all", "credential.https://github.com.helper", ""},
		{"config", "--global", "--add", "credential.https://github.com.helper", "nazar"},
	} {
		cmd := exec.Command(gitBin, args...)
		cmd.Env = []string{"HOME=" + dir, "GIT_CONFIG_GLOBAL=" + gitconfig, "GIT_CONFIG_NOSYSTEM=1", "PATH=/usr/bin:/bin"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %q: %v\n%s", args, err, out)
		}
	}
	sock := filepath.Join(dir, "c.sock")
	l, err := unixsock.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	reqs := make(chan control.Request, 8)
	srv := &control.Server{Resolve: func(int) *caller.Chain { return &caller.Chain{} }, Handler: handlerFunc(func(ctx context.Context, req control.Request, out control.Emitter) {
		reqs <- req
		out.Emit(control.SecretValue{TypeMeta: control.Meta(control.KindSecretValue), Name: "GH_TOKEN", Username: "atas",
			ValueBase64: base64.StdEncoding.EncodeToString([]byte(helperValue))})
	})}
	go srv.Serve(l)

	fill := func(in string) (string, error) {
		cmd := exec.Command(gitBin, "credential", "fill")
		cmd.Env = []string{"HOME=" + dir, "PATH=" + dir + ":/usr/bin:/bin", "GIT_CONFIG_GLOBAL=" + gitconfig, "GIT_CONFIG_NOSYSTEM=1",
			"GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false",
			"NAZAR_CONTROL_SOCKET=" + sock, "NAZAR_TEST_PEER=same-user"}
		cmd.Stdin = strings.NewReader(in)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			return "", err
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			return out.String(), err
		case <-time.After(20 * time.Second):
			cmd.Process.Kill()
			return out.String(), <-done
		}
	}
	out, err := fill("protocol=https\nhost=github.com\n\n")
	if err != nil || strings.Contains(out, "from-the-old-helper") || !strings.Contains(out, "username=atas\n") || !strings.Contains(out, "password="+helperValue+"\n") {
		t.Fatalf("git credential fill: %v, %d bytes", err, len(out))
	}
	select {
	case r := <-reqs:
		if r.Command != control.CmdSecretHelper || r.Args["host"] != "github.com" || r.Args["protocol"] != "https" {
			t.Fatalf("%+v", r)
		}
	default:
		t.Fatal("nazar-agent was not asked")
	}
	// gitlab.com has no nazar line: only the old helper answers, and nazar
	// is never asked.
	if out, _ := fill("protocol=https\nhost=gitlab.com\n\n"); strings.Contains(out, helperValue) {
		t.Fatalf("gitlab.com must not be answered by nazar: %q", out)
	}
	select {
	case r := <-reqs:
		t.Fatalf("nazar-agent was asked about another host: %+v", r)
	default:
	}
}
