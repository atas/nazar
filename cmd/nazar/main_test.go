package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/unixsock"
)

type handlerFunc func(ctx context.Context, req control.Request, out control.Emitter)

func (h handlerFunc) Serve(ctx context.Context, req control.Request, _ *caller.Chain, out control.Emitter) {
	h(ctx, req, out)
}

type harness struct {
	a      *app
	out    *bytes.Buffer
	errb   *bytes.Buffer
	env    map[string]string
	mu     sync.Mutex
	reqs   []control.Request
	execed []string
	home   string
	app    appLocation
	// launchctl records every launchctl call install/uninstall made.
	launchctl []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "nzcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	h := &harness{out: &bytes.Buffer{}, errb: &bytes.Buffer{}, home: home,
		env: map[string]string{"HOME": home, "NAZAR_CONTROL_SOCKET": filepath.Join(home, "c.sock")}}
	h.a = &app{
		stdout: h.out, stderr: h.errb,
		getenv:  func(k string) string { return h.env[k] },
		environ: func() []string { return []string{"PATH=/usr/bin", "SSH_AUTH_SOCK=/old/agent", "HOME=" + home} },
		exec: func(argv0 string, argv, envv []string) error {
			h.execed = append(append([]string{argv0}, argv...), envv...)
			return errors.New("stub exec")
		},
		runLog:      func(context.Context, []string, func([]byte)) error { return nil },
		verifier:    control.SameUserVerifier{},
		accountHome: func() string { return home },
	}
	h.app = fakeBundle(t, home)
	h.a.executable = func() (string, error) { return h.app.CLI, nil }
	h.a.plistProgram = func(string) (string, error) { return "", errors.New("no plist in tests") }
	h.a.imageUUID = func(string) (string, error) { return testAppUUID, nil }
	// The production signature seams: this test binary is ad hoc, so the
	// agent it trusts is the (unsigned, so unusable) fake bundle's build.
	h.a.selfTeam = selfTeamID
	h.a.designated = designatedRequirement
	h.a.uid = func() int { return 501 }
	h.a.launchctl = func(args ...string) error { // never the real launchctl in unit tests
		if args[0] == "print" {
			return errors.New("launchctl print: exit status 113: Could not find service") // gone at once
		}
		h.mu.Lock()
		h.launchctl = append(h.launchctl, strings.Join(args, " "))
		h.mu.Unlock()
		return nil
	}
	h.a.sleep = func(time.Duration) {} // never sleep for real in unit tests
	return h
}

// fakeBundle makes <dir>/Nazar.app with empty Nazar and nazar executables
// and returns its location with symlinks resolved.
func fakeBundle(t *testing.T, dir string) appLocation {
	t.Helper()
	macos := filepath.Join(dir, "Nazar.app", "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{appExeName, cliExeName} {
		if err := os.WriteFile(filepath.Join(macos, n), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	real, err := filepath.EvalSymlinks(filepath.Join(macos, cliExeName))
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := bundleOf(real)
	return loc
}

// serve runs a stub Nazar.app control server.
func (h *harness) serve(t *testing.T, fn handlerFunc) {
	t.Helper()
	l, err := unixsock.Listen(h.env["NAZAR_CONTROL_SOCKET"])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := &control.Server{Resolve: func(int) *caller.Chain { return &caller.Chain{} }, Handler: handlerFunc(func(ctx context.Context, req control.Request, out control.Emitter) {
		h.mu.Lock()
		h.reqs = append(h.reqs, req)
		h.mu.Unlock()
		fn(ctx, req, out)
	})}
	go srv.Serve(l)
}

// requests returns a copy of the requests the stub server received.
func (h *harness) requests() []control.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]control.Request(nil), h.reqs...)
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.errb.Reset()
	h.a.json = false
	return h.a.run(args)
}

// jsonLines decodes every stdout line as a JSON object and checks that each
// carries apiVersion nazar/v1 and a kind (spec 6).
func jsonLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var objs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stdout line is not one JSON object: %q (%v)", l, err)
		}
		if m["apiVersion"] != control.APIVersion {
			t.Fatalf("line without apiVersion %s: %q", control.APIVersion, l)
		}
		if k, _ := m["kind"].(string); k == "" {
			t.Fatalf("line without kind: %q", l)
		}
		objs = append(objs, m)
	}
	return objs
}

// replyFor answers every command with an object of the kind it expects.
func replyFor(req control.Request, out control.Emitter) {
	switch req.Command {
	case control.CmdSSHKeyCreate, control.CmdSSHKeyPubkey, control.CmdSSHKeyDelete:
		out.Emit(control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: req.Args["name"], Type: "ecdsa-sha2-nistp256",
			Fingerprint: "SHA256:abc", PublicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNh " + req.Args["name"], Configured: true, Rules: []string{"fallback: gate=block"},
			UserPresence: req.Args["alwaysAsk"] == "true", WhileLocked: req.Args["alwaysAsk"] != "true" && req.Args["onlyWhenUnlocked"] != "true"})
	case control.CmdSSHKeyList:
		out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{}})
	case control.CmdStatus:
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{}})
	case control.CmdRevoke:
		out.Emit(control.RevokeResult{TypeMeta: control.Meta(control.KindRevokeResult), Revoked: 2})
	case control.CmdConfigCheck:
		out.Emit(control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Valid: true})
	case control.CmdConfigApply:
		out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Applied: true, Changes: []string{}})
	case control.CmdTrustApp:
		out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: req.Args["app"], Team: "TOOLTEAM01", Path: "/Applications/Tool.app", Changed: true})
	default:
		out.Emit(control.NewProblem(control.CodeUsage, "unknown command %q", req.Command))
	}
}

func TestUsageAndHelp(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{}, {"bogus"}, {"ssh-key"}, {"ssh-key", "create"}, {"ssh-key", "create", "a", "b"}, {"revoke", "--nope"}, {"config"}, {"log", "--since", "forever"}} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%v: exit %d, want 2 (stderr %q)", args, code, h.errb.String())
		}
	}
	if code := h.run("help"); code != 0 || !strings.Contains(h.out.String(), "ssh-key create") {
		t.Fatal("help")
	}
	if code := h.run("--json", "version"); code != 0 || !strings.Contains(h.out.String(), `"apiVersion":"nazar/v1"`) {
		t.Fatalf("version: %s", h.out)
	}
}

// Usage errors are decided before anything is sent to Nazar.app.
func TestUsageErrorsSendNothing(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	for _, args := range [][]string{
		{"bogus"},
		{"--bogus", "status"},
		{"ssh-key", "frobnicate"},
		{"ssh-key", "create"},
		{"ssh-key", "create", "a", "b"},
		{"ssh-key", "create", "work", "--gate", "bogus"},
		{"ssh-key", "create", "work", "--scope", "forever"},
		{"ssh-key", "create", "work", "--gate"},
		// create takes the name and no flag at all; the name becomes
		// keys/<name>.pub.
		{"ssh-key", "create", "work", "--gate", "none"},
		{"ssh-key", "create", "work", "--gate", "dialog"},
		{"ssh-key", "create", "work", "--scope", "session"},
		{"ssh-key", "create", "--gate", "block", "hydra"},
		{"ssh-key", "create", "../x"},
		{"ssh-key", "create", "a/b"},
		{"ssh-key", "pubkey"},
		{"ssh-key", "pubkey", "a", "b"},
		{"ssh-key", "delete"},
		{"ssh-key", "delete", "a", "b"},
		{"ssh-key", "list", "extra"},
		{"status", "extra"},
		{"status", "--nope"},
		{"revoke", "--nope"},
		{"revoke", "--key"},
		// Exactly one selector: a bare revoke must never mean "everything",
		// and two selectors are never sent for the server to pick from.
		{"revoke"},
		{"revoke", "--all", "--key", "x"},
		{"revoke", "--key", "a", "--app", "b"},
		{"config"},
		{"config", "frobnicate"},
		{"config", "apply", "extra"},
		{"config", "check", "extra"},
		{"trust"},
		{"trust", "a", "b"},
		{"trust", "/bin/ls"},
		{"log", "--since", "forever"},
		{"log", "--since", "0s"},
		{"log", "--since", "-1h"},
		{"log", "extra"},
		{"log", "summary", "--follow"},
		{"log", "summary", "--since", "soon"},
	} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%v: exit %d, want 2 (stderr %q)", args, code, h.errb.String())
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("usage errors reached Nazar.app: %+v", r)
	}
	// create takes no --gate; the error says so and points at its help.
	h.run("ssh-key", "create", "work", "--gate", "dialog")
	if !strings.Contains(h.errb.String(), "nazar help ssh-key create:") || strings.Contains(h.errb.String(), "--gate") && !strings.Contains(h.errb.String(), "not defined") {
		t.Fatalf("--gate: %q", h.errb)
	}
}

// With --json, a problem is one versioned Problem object on stdout.
func TestUsageErrorAsJSONProblem(t *testing.T) {
	h := newHarness(t)
	if code := h.run("--json", "bogus"); code != control.ExitUsage {
		t.Fatalf("exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindProblem || objs[0]["code"] != control.CodeUsage {
		t.Fatalf("stdout %q", h.out)
	}
}

func TestHelpVariantsAndVersion(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}} {
		if code := h.run(args...); code != 0 {
			t.Errorf("%v: exit %d", args, code)
		}
		for _, want := range []string{"ssh-key create", "status", "revoke", "config check", "trust", "log", "sign-git"} {
			if !strings.Contains(h.out.String(), want) {
				t.Errorf("%v: help lacks %q", args, want)
			}
		}
	}
	if code := h.run("version"); code != 0 || !strings.HasPrefix(h.out.String(), "nazar ") {
		t.Fatalf("version: %d %q", code, h.out)
	}
	if code := h.run("--json", "version"); code != 0 {
		t.Fatal(code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["version"] == nil {
		t.Fatalf("%s", h.out)
	}
}

func TestUnavailableIsExit5(t *testing.T) {
	h := newHarness(t)
	if code := h.run("status"); code != control.ExitUnavailable || !strings.Contains(h.errb.String(), "isn't running") {
		t.Fatalf("exit %d stderr %q", code, h.errb)
	}
	// spec 9: `nazar status` explains and suggests `nazar install`.
	if !strings.Contains(h.errb.String(), "nazar install") {
		t.Fatalf("no install hint: %q", h.errb)
	}
	if code := h.run("--json", "status"); code != control.ExitUnavailable {
		t.Fatal(code)
	}
	var p control.Problem
	if err := json.Unmarshal(h.out.Bytes(), &p); err != nil || p.Kind != "Problem" || p.Code != "unavailable" {
		t.Fatalf("--json problem: %s", h.out)
	}
}

// Every command that needs Nazar.app exits 5 when nothing listens.
func TestEveryControlCommandIsExit5WhenNotRunning(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		{"ssh-key", "create", "work"},
		{"ssh-key", "list"},
		{"ssh-key", "pubkey", "work"},
		{"ssh-key", "delete", "work"},
		{"status"},
		{"status", "--follow"},
		{"revoke", "--all"},
		{"config", "apply"},
		{"trust", "--app", "com.googlecode.iterm2"},
	} {
		if code := h.run(args...); code != control.ExitUnavailable {
			t.Errorf("%v: exit %d, want 5 (stderr %q)", args, code, h.errb)
		}
	}
}

func TestJSONObjectsCarryVersionAndKind(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{{TypeMeta: control.Meta(control.KindSSHKey), Name: "github", Configured: true, Rules: []string{"fallback: gate=block"}}}})
	})
	if code := h.run("ssh-key", "list", "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	var m map[string]any
	if err := json.Unmarshal(h.out.Bytes(), &m); err != nil || m["apiVersion"] != "nazar/v1" || m["kind"] != "SSHKeyList" {
		t.Fatalf("%s", h.out)
	}
	if code := h.run("ssh-key", "list"); code != 0 || !strings.Contains(h.out.String(), "github") {
		t.Fatalf("human: %s", h.out)
	}
}

// Each CLI command sends the matching control command with its arguments,
// and --json prints the reply object of the expected kind.
func TestCommandsMapToControlRequests(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	cases := []struct {
		args []string
		cmd  string
		want map[string]string
		kind string
	}{
		{[]string{"ssh-key", "list"}, control.CmdSSHKeyList, nil, control.KindSSHKeyList},
		{[]string{"ssh-key", "pubkey", "github"}, control.CmdSSHKeyPubkey, map[string]string{"name": "github"}, control.KindSSHKey},
		{[]string{"ssh-key", "delete", "github"}, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey},
		{[]string{"ssh-key", "create", "work"}, control.CmdSSHKeyCreate, map[string]string{"name": "work"}, control.KindSSHKey},
		{[]string{"status"}, control.CmdStatus, nil, control.KindStatus},
		{[]string{"revoke", "--all"}, control.CmdRevoke, map[string]string{"all": "true"}, control.KindRevokeResult},
		{[]string{"revoke", "--key", "github"}, control.CmdRevoke, map[string]string{"key": "github"}, control.KindRevokeResult},
		{[]string{"revoke", "--session", "4120@1791072112"}, control.CmdRevoke, map[string]string{"session": "4120@1791072112"}, control.KindRevokeResult},
		{[]string{"revoke", "--app", "com.googlecode.iterm2"}, control.CmdRevoke, map[string]string{"app": "com.googlecode.iterm2"}, control.KindRevokeResult},
		{[]string{"config", "apply"}, control.CmdConfigApply, nil, control.KindConfigDiff},
		{[]string{"trust", "--app", "com.googlecode.iterm2"}, control.CmdTrustApp, map[string]string{"app": "com.googlecode.iterm2"}, control.KindAppPin},
	}
	for _, c := range cases {
		before := len(h.requests())
		args := append([]string{"--json"}, c.args...)
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d stdout %q stderr %q", c.args, code, h.out, h.errb)
		}
		reqs := h.requests()[before:]
		want := 1
		if c.cmd == control.CmdConfigApply { // reads what is staged (status) first
			want = 2
			if reqs[0].Command != control.CmdStatus {
				t.Fatalf("%v: first request %+v, want status", c.args, reqs[0])
			}
		}
		if len(reqs) != want {
			t.Fatalf("%v: %d requests, want %d: %+v", c.args, len(reqs), want, reqs)
		}
		r := reqs[len(reqs)-1]
		if r.Command != c.cmd || r.APIVersion != control.APIVersion || r.Follow {
			t.Errorf("%v: request %+v, want command %s without follow", c.args, r, c.cmd)
		}
		for k, v := range c.want {
			if r.Args[k] != v {
				t.Errorf("%v: arg %s = %q, want %q (args %v)", c.args, k, r.Args[k], v, r.Args)
			}
		}
		if c.cmd == control.CmdRevoke {
			// A narrow revoke must never turn into "revoke everything" or
			// carry a selector the user didn't give.
			for _, k := range []string{"all", "key", "session", "app"} {
				if _, asked := c.want[k]; !asked && r.Args[k] != "" && r.Args[k] != "false" {
					t.Errorf("%v: unexpected %s=%q", c.args, k, r.Args[k])
				}
			}
		}
		if c.cmd == control.CmdSSHKeyCreate {
			// create sends the name and nothing else; the agent decides the entry.
			for k, v := range r.Args {
				if k != "name" {
					t.Errorf("%v: unexpected %s=%q", c.args, k, v)
				}
			}
		}
		objs := jsonLines(t, h.out.String())
		if len(objs) != 1 || objs[0]["kind"] != c.kind {
			t.Errorf("%v: stdout %q, want one %s", c.args, h.out, c.kind)
		}
	}
}

func TestHumanOutput(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyList:
			out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{
				{TypeMeta: control.Meta(control.KindSSHKey), Name: "github", Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:gh", Configured: true, Rules: []string{"rule 1", "fallback: gate=block"}},
				{TypeMeta: control.Meta(control.KindSSHKey), Name: "lost", Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:lo", Broken: true, Configured: true, Rules: []string{"fallback: gate=block"}},
			}})
		default:
			replyFor(req, out)
		}
	})
	if code := h.run("ssh-key", "list"); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"github", "SHA256:gh", "lost", "broken"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("ssh-key list lacks %q:\n%s", want, h.out)
		}
	}
	if code := h.run("ssh-key", "pubkey", "github"); code != 0 || strings.TrimSpace(h.out.String()) != "ecdsa-sha2-nistp256 AAAAE2VjZHNh github" {
		t.Fatalf("pubkey prints the OpenSSH line only: %q", h.out)
	}
	if code := h.run("revoke", "--all"); code != 0 || !strings.Contains(h.out.String(), "2") {
		t.Fatalf("revoke: %q", h.out)
	}
}

func TestRefusedAndStagedExitCodes(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyCreate:
			out.Emit(control.NewProblem(control.CodeRefused, "not created: user denied"))
		case control.CmdStatus: // config apply reads what is staged first
			out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{}})
		case control.CmdConfigApply:
			out.Emit(control.NewProblem(control.CodeStaged, "an approval prompt is already open"))
		case control.CmdSSHKeyDelete:
			out.Emit(control.NewProblem(control.CodeRefused, "not deleted: timed out"))
		case control.CmdTrustApp:
			out.Emit(control.NewProblem(control.CodeError, "no such app"))
		}
	})
	if code := h.run("ssh-key", "create", "work"); code != control.ExitRefused {
		t.Fatalf("exit %d", code)
	}
	if r := h.requests()[0]; r.Args["name"] != "work" || len(r.Args) != 1 {
		t.Fatalf("create sends the name and nothing else: %+v", r.Args)
	}
	if code := h.run("config", "apply"); code != control.ExitStaged {
		t.Fatalf("exit %d", code)
	}
	if code := h.run("ssh-key", "delete", "work"); code != control.ExitRefused || !strings.Contains(h.errb.String(), "timed out") {
		t.Fatalf("delete: exit %d stderr %q", code, h.errb)
	}
	if code := h.run("--json", "trust", "--app", "com.nope"); code != control.ExitError {
		t.Fatalf("trust: exit %d", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindProblem || objs[0]["message"] != "no such app" {
		t.Fatalf("trust --json: %q", h.out)
	}
}

// A reply that isn't what the command expects is an error, never success.
func TestMalformedRepliesAreErrors(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyList: // wrong kind
			out.Emit(control.RevokeResult{TypeMeta: control.Meta(control.KindRevokeResult)})
		case control.CmdRevoke: // nothing at all
		case control.CmdSSHKeyPubkey: // two objects
			out.Emit(control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: "a"})
			out.Emit(control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: "b"})
		}
	})
	for _, args := range [][]string{{"ssh-key", "list"}, {"revoke", "--all"}, {"ssh-key", "pubkey", "a"}} {
		if code := h.run(args...); code != control.ExitError {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
}

func writeConfig(t *testing.T, h *harness, body string) {
	t.Helper()
	p := layout.ConfigFile(h.home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigCheck(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, "apiVersion: nazar/v9\nkind: Config\n")
	if code := h.run("config", "check"); code != control.ExitError || !strings.Contains(h.out.String(), "unknown apiVersion") {
		t.Fatalf("invalid file without the app: exit %d\n%s", code, h.out)
	}
	writeConfig(t, h, "apiVersion: nazar/v1\nkind: Config\n")
	if code := h.run("config", "check"); code != 0 || !strings.Contains(h.out.String(), "isn't running") {
		t.Fatalf("valid file without the app: exit %d\n%s", code, h.out)
	}
	h.serve(t, func(_ context.Context, _ control.Request, out control.Emitter) {
		out.Emit(control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Path: layout.ConfigFile(h.home),
			Valid: true, Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Loosens: true, Changes: []string{"ssh:github: added rule 1"}}})
	})
	if code := h.run("--json", "config", "check"); code != control.ExitStaged {
		t.Fatalf("staged: exit %d\n%s", code, h.out)
	}
	var c control.ConfigCheck
	json.Unmarshal(h.out.Bytes(), &c)
	if c.Staged == nil || c.Staged.Changes[0] != "ssh:github: added rule 1" {
		t.Fatalf("%s", h.out)
	}
	// An invalid file beats a staged diff: exit 1, never 4 or 0.
	writeConfig(t, h, "apiVersion: nazar/v1\nkind: Config\nbogus_section: 1\n")
	if code := h.run("--json", "config", "check"); code != control.ExitError {
		t.Fatalf("invalid while staged: exit %d\n%s", code, h.out)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindConfigCheck || objs[0]["valid"] != false {
		t.Fatalf("%s", h.out)
	}
}

func TestConfigCheckWithoutTheApp(t *testing.T) {
	h := newHarness(t)
	// No file at all: valid (everything is blocked), exit 0.
	if code := h.run("--json", "config", "check"); code != 0 {
		t.Fatalf("missing file: exit %d %s", code, h.out)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindConfigCheck || objs[0]["valid"] != true || objs[0]["staged"] != nil {
		t.Fatalf("%s", h.out)
	}
	// NAZAR_CONFIG points at another file.
	other := filepath.Join(h.home, "other.yaml")
	os.WriteFile(other, []byte("kind: Config\n"), 0o600)
	h.env["NAZAR_CONFIG"] = other
	if code := h.run("--json", "config", "check"); code != control.ExitError {
		t.Fatalf("NAZAR_CONFIG with missing apiVersion: exit %d %s", code, h.out)
	}
	if objs := jsonLines(t, h.out.String()); objs[0]["path"] != other {
		t.Fatalf("path %v, want %s", objs[0]["path"], other)
	}
}

// Spec 4.2: gate: none refuses
// Apple-signed matchers and paths of Apple's programs; `config check`
// rejects them, locally. any and unknown are the user's explicit choice
// and pass (with a warning); so does a path: off the system volume.
func TestConfigCheckRejectsWeakMatchersUnderGateNone(t *testing.T) {
	h := newHarness(t)
	base := "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    deploy:\n      rules:\n        - apps: [%s]\n          gate: %s\n"
	for _, c := range []struct {
		apps, gate string
		code       int
	}{
		{"{path: /bin/zsh}", "none", control.ExitError},
		{"{path: /opt/homebrew/opt/mytool/bin/mytool}", "none", control.ExitOK},
		{"{signed: {team: apple}}", "none", control.ExitError},
		{"{signed: {team: apple, id: com.apple.ssh}}", "none", control.ExitError},
		{"any", "none", control.ExitOK},
		{"unknown", "none", control.ExitOK},
		{"{app: com.googlecode.iterm2}", "none", control.ExitOK},
		{"{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}", "none", control.ExitOK},
		{"{path: /bin/zsh}", "login", control.ExitOK},
		{"any", "dialog", control.ExitOK},
	} {
		writeConfig(t, h, fmt.Sprintf(base, c.apps, c.gate))
		if code := h.run("config", "check"); code != c.code {
			t.Errorf("apps %s gate %s: exit %d, want %d\n%s", c.apps, c.gate, code, c.code, h.out)
		}
		warned := strings.Contains(h.out.String()+h.errb.String(), "use this key without asking")
		if want := (c.apps == "any" || c.apps == "unknown") && c.gate == "none"; warned != want {
			t.Errorf("apps %s gate %s: every-program warning shown %v, want %v\n%s%s", c.apps, c.gate, warned, want, h.out, h.errb)
		}
	}
}

func TestStatusFollowStreamsLines(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if !req.Follow {
			t.Error("follow not sent")
		}
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus)})
		out.Emit(control.Approval{TypeMeta: control.Meta(control.KindApproval), Event: "added", Target: "ssh:github"})
		out.Emit(control.Approval{TypeMeta: control.Meta(control.KindApproval), Event: "removed", Target: "ssh:github"})
	})
	if code := h.run("status", "--follow", "--json"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 JSON lines, got %q", lines)
	}
	for _, l := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["apiVersion"] != "nazar/v1" {
			t.Fatalf("line %q", l)
		}
	}
	// Human follow output shows each event.
	if code := h.run("status", "--follow"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if !strings.Contains(h.out.String(), "added") || !strings.Contains(h.out.String(), "removed") {
		t.Fatalf("human follow: %q", h.out)
	}
}

// The human status and --follow views don't rely on Nazar.app having
// escaped a value: a non-printing rune in a target, scope id, chain or
// reason is shown escaped, while a printable chain ("iTerm2 → ssh") is kept.
func TestStatusHumanOutputIsEscaped(t *testing.T) {
	h := newHarness(t)
	ap := control.Approval{TypeMeta: control.Meta(control.KindApproval), Event: "added", Target: "ssh:github", Rule: "r1", Scope: "session",
		ScopeID: "t\x1b[2Jx", Op: "login:SHA256:x", Covers: "github.com\u202e", Chain: "iTerm2 → zsh → ssh", Reason: "ok\u202e"}
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Approvals: []control.Approval{ap}})
		if req.Follow {
			out.Emit(ap)
		}
	})
	for _, args := range [][]string{{"status"}, {"status", "--follow"}} {
		if code := h.run(args...); code != 0 {
			t.Fatalf("%v: exit %d %s", args, code, h.errb)
		}
		out := h.out.String()
		if strings.ContainsRune(out, '\x1b') || strings.ContainsRune(out, '\u202e') {
			t.Fatalf("%v: raw control/bidi rune: %q", args, out)
		}
		if !strings.Contains(out, `"t\x1b[2Jx"`) || !strings.Contains(out, "iTerm2 → zsh → ssh") || !strings.Contains(out, `for "github.com\u202e"`) {
			t.Fatalf("%v: %q", args, out)
		}
		if args[len(args)-1] == "--follow" && !strings.Contains(out, `"ok\u202e"`) {
			t.Fatalf("%v: reason not escaped: %q", args, out)
		}
	}
}

// A problem at the end of a stream still sets the exit code.
func TestStatusStreamEndingInProblem(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus)})
		out.Emit(control.NewProblem(control.CodeError, "approval cache gone"))
	})
	if code := h.run("--json", "status", "--follow"); code != control.ExitError {
		t.Fatalf("exit %d", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 2 || objs[1]["kind"] != control.KindProblem {
		t.Fatalf("%q", h.out)
	}
}

func TestVerifierRefusalSendsNothing(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(context.Context, control.Request, control.Emitter) {})
	h.a.verifier = control.VerifierFunc(func(*net.UnixConn) error { return errors.New("wrong code signature") })
	if code := h.run("revoke", "--all"); code != control.ExitError || !strings.Contains(h.errb.String(), "not nazar-agent") {
		t.Fatalf("exit %d %q", code, h.errb)
	}
	if len(h.requests()) != 0 {
		t.Fatal("a request reached an unverified peer")
	}
}

// Every control command checks the peer, including the loosening ones and
// the remote half of `config check`.
func TestVerifierRunsForEveryControlCommand(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	var calls int
	h.a.verifier = control.VerifierFunc(func(*net.UnixConn) error { calls++; return errors.New("impostor") })
	for _, args := range [][]string{
		{"ssh-key", "create", "work"}, {"ssh-key", "delete", "work"}, {"ssh-key", "list"}, {"ssh-key", "pubkey", "work"},
		{"status"}, {"revoke", "--key", "work"}, {"config", "apply"}, {"config", "check"}, {"trust", "--app", "com.googlecode.iterm2"},
	} {
		before := calls
		if code := h.run(args...); code == 0 {
			t.Errorf("%v: exit 0 with an impostor on the socket", args)
		}
		if calls != before+1 {
			t.Errorf("%v: verifier called %d times", args, calls-before)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("requests reached an unverified peer: %+v", r)
	}
}

// With no verifier set (what main() does), the CLI checks that the peer is
// Nazar.app. The stub server here is this test binary, not the
// trusted bundle (the harness's bundle is two shell scripts), so it is
// refused before any request is sent; NAZAR_TEST_PEER=same-user restores
// the same-user check and says so. The positive case (a signed bundle
// accepted) is core/codesign's TestPeerMustBeTheTrustedApp.
func TestDefaultVerifier(t *testing.T) {
	h := newHarness(t)
	h.a.verifier = nil
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("status"); code == 0 {
		t.Fatalf("a control socket peer that is not Nazar.app was accepted: %q", h.out)
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("requests reached an unverified peer: %+v", r)
	}
	h.env["NAZAR_TEST_PEER"] = "same-user"
	h.errb.Reset()
	if code := h.run("status"); code != 0 {
		t.Fatalf("same-user override refused: exit %d %q", code, h.errb)
	}
	if !strings.Contains(h.errb.String(), "NAZAR_TEST_PEER=same-user") {
		t.Fatalf("the override must warn on stderr: %q", h.errb)
	}
	h.env["NAZAR_TEST_PEER"] = "yes" // anything else is no override
	if code := h.run("status"); code == 0 {
		t.Fatal("NAZAR_TEST_PEER=yes weakened the check")
	}
}

// The refusal is the ordinary "not Nazar.app" error (exit 1), every
// control command is refused the same way, and nothing reaches the peer.
func TestDefaultVerifierRefusesEveryCommand(t *testing.T) {
	h := newHarness(t)
	h.a.verifier = nil
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	for _, args := range [][]string{
		{"status"}, {"ssh-key", "create", "work"}, {"ssh-key", "delete", "work"}, {"ssh-key", "list"},
		{"revoke", "--all"}, {"config", "apply"}, {"trust", "--app", "com.googlecode.iterm2"},
	} {
		if code := h.run(args...); code != control.ExitError || !strings.Contains(h.errb.String(), "not nazar-agent") {
			t.Errorf("%v: exit %d %q, want %d and a not-Nazar.app error", args, code, h.errb, control.ExitError)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("requests reached an unverified peer: %+v", r)
	}
}

// Only the exact value same-user drops the code check: near misses keep it.
func TestTestPeerOverrideIsExact(t *testing.T) {
	h := newHarness(t)
	h.a.verifier = nil
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	for _, v := range []string{"1", "true", "SAME-USER", "Same-User", " same-user", "same-user ", "same-user\n", "sameuser", "same_user", "same-user,"} {
		h.env["NAZAR_TEST_PEER"] = v
		if code := h.run("status"); code == 0 {
			t.Errorf("NAZAR_TEST_PEER=%q weakened the check", v)
		}
		if strings.Contains(h.errb.String(), "NAZAR_TEST_PEER=same-user") {
			t.Errorf("NAZAR_TEST_PEER=%q printed the override warning: %q", v, h.errb)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("requests reached an unverified peer: %+v", r)
	}
}

// With the override, --json output stays clean JSON on stdout and carries
// no warning on either stream (an integration harness reading
// stdout+stderr broke on it once).
func TestTestPeerOverrideJSONHasNoWarning(t *testing.T) {
	h := newHarness(t)
	h.a.verifier = nil
	h.env["NAZAR_TEST_PEER"] = "same-user"
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("--json", "status"); code != 0 {
		t.Fatalf("exit %d %q %q", code, h.out, h.errb)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindStatus {
		t.Fatalf("stdout %q", h.out)
	}
	if strings.Contains(h.out.String()+h.errb.String(), "NAZAR_TEST_PEER") {
		t.Fatalf("--json output carries the override warning: stdout %q stderr %q", h.out, h.errb)
	}
}

// With no agent to trust (an ad-hoc CLI outside an agent bundle), the CLI
// refuses rather than falling back to same-user, even when a LaunchAgent
// names a bundle: a path is never an identity (Milestone 6).
func TestDefaultVerifierWithoutAnAgentRefuses(t *testing.T) {
	h := newHarness(t)
	h.a.verifier = nil
	h.a.selfTeam = func() (string, error) { return "", nil }
	h.a.designated = func(string) (string, error) { t.Fatal("no bundle to read a requirement from"); return "", nil }
	h.a.executable = func() (string, error) { return "/usr/local/bin/nazar", nil }
	h.a.plistProgram = func(string) (string, error) { return h.app.MainExe, nil }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	if code := h.run("status"); code == 0 {
		t.Fatalf("accepted a peer with no agent to trust: %q", h.out)
	}
	if !strings.Contains(h.errb.String(), "has no agent to trust") {
		t.Fatalf("stderr %q", h.errb)
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("requests reached an unverified peer: %+v", r)
	}
}

// checkAgentPeer refuses this test binary against a requirement it does
// not meet, an empty or malformed requirement, and a descriptor that is
// not a connected socket.
func TestCheckAgentPeerRefuses(t *testing.T) {
	h := newHarness(t)
	sock := h.env["NAZAR_CONTROL_SOCKET"]
	l, err := unixsock.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, req := range []string{
		`identifier "dev.nazar.agent" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"`,
		`cdhash H"0000000000000000000000000000000000000000"`,
		"", "garbage(",
	} {
		err := unixsock.WithFD(c.(*net.UnixConn), func(fd int) error { return checkAgentPeer(fd, req) })
		if err == nil {
			t.Errorf("checkAgentPeer(%q) accepted this test binary", req)
		}
	}
	if err := checkAgentPeer(-1, `cdhash H"0000000000000000000000000000000000000000"`); err == nil {
		t.Error("checkAgentPeer(-1) passed")
	}
}

func TestSignGitExecsSSHKeygenWithAgentSocket(t *testing.T) {
	h := newHarness(t)
	args := []string{"-Y", "sign", "-n", "git", "-f", "/k.pub", "--json", "/tmp/buf"}
	if code := h.a.run(append([]string{"sign-git"}, args...)); code != control.ExitError {
		t.Fatalf("exit %d", code)
	}
	want := layout.AgentSocket(h.home)
	got := strings.Join(h.execed, "|")
	if !strings.HasPrefix(got, "/usr/bin/ssh-keygen|ssh-keygen|-Y|sign|-n|git|-f|/k.pub|--json|/tmp/buf|SSH_AUTH_SOCK="+want+"|") {
		t.Fatalf("exec %q", got)
	}
	if strings.Count(got, "SSH_AUTH_SOCK=") != 1 {
		t.Fatalf("SSH_AUTH_SOCK must be replaced, not duplicated: %q", got)
	}
	// The config file on disk is not approved: it never chooses the socket
	// (see signgit_test.go for the daemon's approved socket).
	writeConfig(t, h, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  socket: ~/custom.sock\n")
	h.a.signGit(nil)
	if got := strings.Join(h.execed, "|"); !strings.Contains(got, "SSH_AUTH_SOCK="+want+"|") || strings.Contains(got, "custom.sock") {
		t.Fatalf("unapproved config socket used: %q", h.execed)
	}
	h.env["NAZAR_AGENT_SOCK"] = "/tmp/x.sock"
	h.a.signGit(nil)
	if !strings.Contains(strings.Join(h.execed, "|"), "SSH_AUTH_SOCK=/tmp/x.sock") {
		t.Fatalf("override not used: %q", h.execed)
	}
}

// git's arguments reach ssh-keygen byte for byte, whatever they look like:
// nazar's own flags and commands are not interpreted after sign-git.
func TestSignGitPassesArgumentsUnchanged(t *testing.T) {
	h := newHarness(t)
	args := []string{"--yes", "--json", "--", "help", "-Y", "verify", "-n", "git", "-I", "a b", "-s", "", "version", "--help"}
	for _, prefix := range [][]string{{"sign-git"}, {"--json", "sign-git"}} {
		h.execed = nil
		h.out.Reset()
		h.errb.Reset()
		h.a.run(append(append([]string{}, prefix...), args...))
		if len(h.execed) < 2+len(args) {
			t.Fatalf("%v: exec %q", prefix, h.execed)
		}
		if h.execed[0] != "/usr/bin/ssh-keygen" || h.execed[1] != "ssh-keygen" {
			t.Fatalf("%v: argv0 %q", prefix, h.execed[:2])
		}
		for i, a := range args {
			if h.execed[2+i] != a {
				t.Fatalf("%v: arg %d = %q, want %q (exec %q)", prefix, i, h.execed[2+i], a, h.execed)
			}
		}
		if h.execed[2+len(args)] == "" || !strings.Contains(h.execed[2+len(args)], "=") {
			t.Fatalf("%v: extra argument after git's: %q", prefix, h.execed)
		}
	}
}

// ssh-keygen is run by absolute path, never via $PATH, and the environment
// is kept (minus the old agent socket).
func TestSignGitIgnoresPATHAndKeepsEnvironment(t *testing.T) {
	h := newHarness(t)
	h.a.environ = func() []string {
		return []string{"PATH=/evil/bin:/usr/bin", "SSH_AUTH_SOCK=/evil/agent.sock", "GIT_DIR=/repo/.git", "SSH_AUTH_SOCK=/second"}
	}
	h.a.signGit([]string{"-Y", "sign"})
	if len(h.execed) == 0 || h.execed[0] != "/usr/bin/ssh-keygen" {
		t.Fatalf("exec %q", h.execed)
	}
	env := strings.Join(h.execed, "|")
	if strings.Count(env, "SSH_AUTH_SOCK=") != 1 || strings.Contains(env, "/evil/agent.sock") || strings.Contains(env, "/second") {
		t.Fatalf("old SSH_AUTH_SOCK leaked: %q", h.execed)
	}
	for _, keep := range []string{"PATH=/evil/bin:/usr/bin", "GIT_DIR=/repo/.git"} {
		if !strings.Contains(env, keep) {
			t.Fatalf("%s dropped: %q", keep, h.execed)
		}
	}
}

// A config file on disk, valid or not, never redirects signing: without the
// app the default socket is used.
func TestSignGitInvalidConfigUsesDefaultSocket(t *testing.T) {
	h := newHarness(t)
	writeConfig(t, h, "apiVersion: nazar/v9\nkind: Config\nssh_agent:\n  socket: /tmp/evil.sock\n")
	h.a.signGit([]string{"-Y", "sign"})
	want := "SSH_AUTH_SOCK=" + layout.AgentSocket(h.home)
	if got := strings.Join(h.execed, "|"); !strings.Contains(got, want) || strings.Contains(got, "evil") {
		t.Fatalf("exec %q, want %s", got, want)
	}
	// Nor does a valid file named by NAZAR_CONFIG (the file on disk is
	// never read for the socket).
	other := filepath.Join(h.home, "other.yaml")
	os.WriteFile(other, []byte("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  socket: ~/via-env.sock\n"), 0o600)
	h.env["NAZAR_CONFIG"] = other
	h.a.signGit([]string{"-Y", "sign"})
	if got := strings.Join(h.execed, "|"); !strings.Contains(got, want) || strings.Contains(got, "via-env") {
		t.Fatalf("NAZAR_CONFIG redirected signing: %q", got)
	}
}

func TestSignGitExecFailureIsAnError(t *testing.T) {
	h := newHarness(t)
	if code := h.a.signGit([]string{"-Y", "sign"}); code != control.ExitError || !strings.Contains(h.errb.String(), "ssh-keygen") {
		t.Fatalf("exit %d stderr %q", code, h.errb)
	}
}

// buildNazar compiles this package into dir and returns the binary.
func buildNazar(t *testing.T, dir string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(dir, "nazar")
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// The real binary, invoked as nazar-sign-git (git's gpg.ssh.program) or as
// `nazar sign-git`, execs /usr/bin/ssh-keygen pointed at nazar's agent
// socket, not at the caller's SSH_AUTH_SOCK and not at a ssh-keygen on PATH.
// Uses a throwaway public key and a socket in a temp dir; nothing prompts.
func TestSignGitBinaryReachesNazarAgent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "nzsg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	bin := buildNazar(t, dir)
	if err := os.Symlink(bin, filepath.Join(dir, "nazar-sign-git")); err != nil {
		t.Fatal(err)
	}
	// A ssh-keygen on PATH that must never run.
	fake := filepath.Join(dir, "fakebin")
	os.Mkdir(fake, 0o700)
	marker := filepath.Join(dir, "fake-ran")
	os.WriteFile(filepath.Join(fake, "ssh-keygen"), []byte("#!/bin/sh\ntouch "+marker+"\nexit 0\n"), 0o700)
	// Throwaway key; only the public half stays, so ssh-keygen must use the agent.
	key := filepath.Join(dir, "k")
	if out, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-C", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	os.Remove(key)
	buf := filepath.Join(dir, "buf")
	os.WriteFile(buf, []byte("tree 0\n"), 0o600)

	for _, argv := range [][]string{
		{filepath.Join(dir, "nazar-sign-git")},
		{bin, "sign-git"},
	} {
		sock := filepath.Join(dir, "a.sock")
		os.Remove(sock)
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		connected := make(chan struct{}, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			connected <- struct{}{}
			c.Close()
		}()
		cmd := exec.Command(argv[0], append(argv[1:], "-Y", "sign", "-n", "git", "-f", key+".pub", buf)...)
		cmd.Env = []string{"HOME=" + dir, "PATH=" + fake + ":/usr/bin:/bin", "NAZAR_AGENT_SOCK=" + sock,
			"SSH_AUTH_SOCK=" + filepath.Join(dir, "wrong.sock"), "NAZAR_CONTROL_SOCKET=" + filepath.Join(dir, "c.sock")}
		cmd.Stdin = nil
		done := make(chan error, 1)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Fatalf("%v: ssh-keygen hung\n%s", argv, out.String())
		}
		l.Close()
		select {
		case <-connected:
		default:
			t.Errorf("%v: nothing connected to NAZAR_AGENT_SOCK\n%s", argv, out.String())
		}
		if strings.Contains(out.String(), "usage: nazar") {
			t.Errorf("%v: nazar parsed git's arguments itself:\n%s", argv, out.String())
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a ssh-keygen from PATH ran")
	}
	// Invoked as plain `nazar`, git's arguments are not a command.
	cmd := exec.Command(bin, "-Y", "sign", "-n", "git", "-f", key+".pub", buf)
	cmd.Env = []string{"HOME=" + dir, "PATH=" + fake + ":/usr/bin:/bin"}
	err = cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != control.ExitUsage {
		t.Fatalf("nazar -Y ...: %v, want exit 2", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a ssh-keygen from PATH ran")
	}
}

// testAppUUID is the LC_UUID the test harness reports for Nazar.app.
const testAppUUID = "11111111-2222-3333-4444-555555555555"

// fromApp is the sender fields of an entry Nazar.app wrote.
const fromApp = `,"processImageUUID":"11111111-2222-3333-4444-555555555555","senderImageUUID":"11111111-2222-3333-4444-555555555555"}`

func auditLines() []string {
	return []string{
		`{"timestamp":"2026-10-04 00:01:52.000000+0000","eventMessage":"decision=allowed reason=\"cached approval\" target=ssh:github app=com.googlecode.iterm2"` + fromApp,
		`{"timestamp":"2026-10-04 00:02:00.000000+0000","eventMessage":"decision=blocked target=ssh:github chain=\"python3(9) > ssh(10)\""` + fromApp,
		`{"timestamp":"2026-10-04 00:03:00.000000+0000","eventMessage":"decision=approved target=ssh:hydra app=com.googlecode.iterm2"` + fromApp,
		`not json`,
		`{"eventMessage":"garbage without fields"}`,
		// Forged: right subsystem and a well-formed line, but another sender.
		`{"timestamp":"2026-10-04 00:04:00.000000+0000","eventMessage":"decision=allowed target=ssh:github app=com.evil","processImageUUID":"AAAAAAAA-2222-3333-4444-555555555555","senderImageUUID":"AAAAAAAA-2222-3333-4444-555555555555"}`,
		// Forged sender image inside Nazar's process (e.g. an injected library).
		`{"timestamp":"2026-10-04 00:05:00.000000+0000","eventMessage":"decision=allowed target=ssh:github app=com.evil2","processImageUUID":"11111111-2222-3333-4444-555555555555","senderImageUUID":"BBBBBBBB-2222-3333-4444-555555555555"}`,
	}
}

// lastMinutes converts a `log show --last` value (Nm, Nh, Nd or Ns) to minutes.
func lastMinutes(t *testing.T, v string) float64 {
	t.Helper()
	if v == "" {
		t.Fatal("empty --last")
	}
	n, err := strconv.ParseFloat(v[:len(v)-1], 64)
	if err != nil {
		t.Fatalf("--last %q", v)
	}
	switch v[len(v)-1] {
	case 's':
		return n / 60
	case 'm':
		return n
	case 'h':
		return n * 60
	case 'd':
		return n * 1440
	}
	t.Fatalf("--last %q", v)
	return 0
}

// checkLogArgs checks a /usr/bin/log invocation: the verb, ndjson style, a
// predicate restricted to subsystem dev.nazar and category audit, and (for
// show) the --last window in minutes.
func checkLogArgs(t *testing.T, args []string, verb string, minutes float64) {
	t.Helper()
	if len(args) == 0 || args[0] != verb {
		t.Fatalf("log args %q, want verb %s", args, verb)
	}
	val := func(flag string) string {
		for i := 0; i+1 < len(args); i++ {
			if args[i] == flag {
				return args[i+1]
			}
		}
		return ""
	}
	if val("--style") != "ndjson" {
		t.Fatalf("log args %q: want --style ndjson", args)
	}
	pred := val("--predicate")
	if !strings.Contains(pred, `subsystem == "dev.nazar"`) || !strings.Contains(pred, `category == "audit"`) || strings.Contains(pred, " OR ") {
		t.Fatalf("predicate %q", pred)
	}
	if verb == "show" {
		if got := lastMinutes(t, val("--last")); got != minutes {
			t.Fatalf("--last %q = %v minutes, want %v", val("--last"), got, minutes)
		}
	}
}

func TestLogParsesFiltersAndSummarises(t *testing.T) {
	h := newHarness(t)
	var gotArgs []string
	h.a.runLog = func(_ context.Context, args []string, line func([]byte)) error {
		gotArgs = args
		for _, l := range auditLines() {
			line([]byte(l))
		}
		return nil
	}
	if code := h.run("--json", "log", "--target", "github", "--decision", "blocked"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	lines := strings.Split(strings.TrimSpace(h.out.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], `"kind":"AuditEvent"`) || !strings.Contains(lines[0], `"decision":"blocked"`) {
		t.Fatalf("%q", lines)
	}
	checkLogArgs(t, gotArgs, "show", 1440)
	if code := h.run("--json", "log", "summary"); code != 0 {
		t.Fatal(code)
	}
	if !strings.Contains(h.out.String(), `"target":"ssh:github","total":2`) || !strings.Contains(h.out.String(), `"python3":1`) {
		t.Fatalf("%s", h.out)
	}
	checkLogArgs(t, gotArgs, "show", 7*1440)
	if code := h.run("log", "--follow", "--caller", "python3"); code != 0 || gotArgs[0] != "stream" {
		t.Fatalf("follow: %d %v", code, gotArgs)
	}
	checkLogArgs(t, gotArgs, "stream", 0)
	if !strings.Contains(h.out.String(), "python3") || strings.Contains(h.out.String(), "ssh:hydra") {
		t.Fatalf("--caller python3 human: %q", h.out)
	}
}

func TestLogJSONEvents(t *testing.T) {
	h := newHarness(t)
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		for _, l := range auditLines() {
			line([]byte(l))
		}
		return nil
	}
	if code := h.run("--json", "log", "--since", "2h"); code != 0 {
		t.Fatal(code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 3 {
		t.Fatalf("want the 3 parseable entries, got %q", h.out)
	}
	var ev control.AuditEvent
	if err := json.Unmarshal([]byte(strings.Split(h.out.String(), "\n")[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Kind != control.KindAuditEvent || ev.Fields["reason"] != "cached approval" || ev.Fields["app"] != "com.googlecode.iterm2" {
		t.Fatalf("%+v", ev)
	}
	if want := time.Date(2026, 10, 4, 0, 1, 52, 0, time.UTC); !ev.Time.Equal(want) {
		t.Fatalf("time %v, want %v", ev.Time, want)
	}
	// Filters: --target accepts the full target too; --caller matches the app.
	for _, c := range []struct {
		args []string
		n    int
	}{
		{[]string{"--target", "ssh:github"}, 2},
		{[]string{"--target", "hydra"}, 1},
		{[]string{"--target", "nope"}, 0},
		{[]string{"--caller", "iterm2"}, 2},
		{[]string{"--decision", "approved"}, 1},
		{[]string{"--target", "github", "--caller", "iterm2"}, 1},
	} {
		if code := h.run(append([]string{"--json", "log"}, c.args...)...); code != 0 {
			t.Fatalf("%v: exit %d", c.args, code)
		}
		if got := len(jsonLines(t, h.out.String())); got != c.n {
			t.Errorf("%v: %d entries, want %d\n%s", c.args, got, c.n, h.out)
		}
	}
}

// Filter values are applied by nazar, never spliced into the log predicate,
// so a crafted --target/--caller/--decision can't widen or change the query.
func TestLogFiltersNeverReachThePredicate(t *testing.T) {
	h := newHarness(t)
	var gotArgs [][]string
	h.a.runLog = func(_ context.Context, args []string, _ func([]byte)) error {
		gotArgs = append(gotArgs, args)
		return nil
	}
	h.run("log")
	evil := `x" OR subsystem == "com.apple" OR "1" == "1`
	h.run("log", "--target", evil, "--caller", evil, "--decision", evil)
	if len(gotArgs) != 2 || strings.Join(gotArgs[0], "\x00") != strings.Join(gotArgs[1], "\x00") {
		t.Fatalf("filters changed the log query: %q", gotArgs)
	}
}

// The human log view prints values escaped as the audit line has them, and
// drops any entry that isn't a well-formed audit line (raw control or
// look-alike runes), so a caller can't paint the terminal or forge text.
func TestLogHumanOutputIsEscaped(t *testing.T) {
	h := newHarness(t)
	entries := []map[string]string{
		{"timestamp": "2026-10-04 00:01:52.000000+0000", "eventMessage": `decision=blocked target=ssh:github app="com.evil\u202egpj" cwd="~/x\x1b[2J"`, "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
		{"timestamp": "2026-10-04 00:01:53.000000+0000", "eventMessage": "decision=blocked target=ssh:github app=\"com.raw\u202e\"", "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
		{"timestamp": "2026-10-04 00:01:54.000000+0000", "eventMessage": "decision=blocked target=ssh:github cwd=\"\x1b[31mred\"", "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
		{"timestamp": "2026-10-04 00:01:55.000000+0000", "eventMessage": "decision=blocked target=ssh:github\ndecision=allowed target=ssh:forged", "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
	}
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		for _, e := range entries {
			b, _ := json.Marshal(e)
			line(b)
		}
		return nil
	}
	if code := h.run("log"); code != 0 {
		t.Fatal(code)
	}
	out := h.out.String()
	if strings.ContainsRune(out, '\u202e') || strings.ContainsRune(out, '\x1b') {
		t.Fatalf("raw control/bidi rune in human output: %q", out)
	}
	if !strings.Contains(out, `\u202e`) || !strings.Contains(out, `\x1b`) {
		t.Fatalf("escaped entry missing or unescaped: %q", out)
	}
	if strings.Contains(out, "ssh:forged") || strings.Contains(out, "com.raw") {
		t.Fatalf("malformed entry printed: %q", out)
	}
	if n := strings.Count(strings.TrimSpace(out), "\n") + 1; n != 1 {
		t.Fatalf("want exactly the one well-formed entry, got %d lines: %q", n, out)
	}
	if code := h.run("--json", "log"); code != 0 {
		t.Fatal(code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 {
		t.Fatalf("--json: %q", h.out)
	}
}

// The human summary prints parsed (unquoted) values, so it re-escapes them:
// a caller-chosen app id or target can't paint the terminal, hide its row,
// or forge another caller's count with ", " and " x9" inside the value.
func TestLogSummaryHumanOutputIsEscaped(t *testing.T) {
	h := newHarness(t)
	entries := []map[string]string{
		{"timestamp": "2026-10-04 00:01:52.000000+0000", "eventMessage": `decision=blocked target="ssh:github\u202e" app="com.evil\x1b[2K\x1b[1;31mAPPROVED com.googlecode.iterm2"`, "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
		{"timestamp": "2026-10-04 00:01:53.000000+0000", "eventMessage": `decision=blocked target=ssh:github app="com.googlecode.iterm2 x9, com.other"`, "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
		{"timestamp": "2026-10-04 00:01:54.000000+0000", "eventMessage": `decision=approved target=ssh:github app=com.googlecode.iterm2`, "processImageUUID": testAppUUID, "senderImageUUID": testAppUUID},
	}
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		for _, e := range entries {
			b, _ := json.Marshal(e)
			line(b)
		}
		return nil
	}
	if code := h.run("log", "summary"); code != 0 {
		t.Fatal(code)
	}
	out := h.out.String()
	if strings.ContainsRune(out, '\u202e') || strings.ContainsRune(out, '\x1b') {
		t.Fatalf("raw control/bidi rune in human summary: %q", out)
	}
	for _, want := range []string{
		`"ssh:github\u202e"`,
		`"com.evil\x1b[2K\x1b[1;31mAPPROVED com.googlecode.iterm2" x1`,
		`"com.googlecode.iterm2 x9, com.other" x1`,
		"com.googlecode.iterm2 x1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	// The forged text never appears outside quotes, so a reader sees one
	// caller with a strange name, not iTerm2 used nine times.
	if strings.Contains(out, ` com.googlecode.iterm2 x9`) || strings.Contains(out, "APPROVED com.googlecode.iterm2 x") && !strings.Contains(out, `APPROVED com.googlecode.iterm2" x1`) {
		t.Fatalf("forged caller count printed bare: %q", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header plus one row per target, got %q", lines)
	}
	// JSON keeps the values as they are: encoding/json escapes control
	// runes on the wire and a consumer decodes the rest itself.
	if code := h.run("--json", "log", "summary"); code != 0 {
		t.Fatal(code)
	}
	if strings.ContainsRune(h.out.String(), '\x1b') {
		t.Fatalf("raw control rune in --json summary: %q", h.out)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 2 {
		t.Fatalf("--json summary: %q", h.out)
	}
	var s control.AuditSummary
	if err := json.Unmarshal([]byte(strings.Split(h.out.String(), "\n")[0]), &s); err != nil {
		t.Fatal(err)
	}
	if s.Target != "ssh:github" || s.Callers["com.googlecode.iterm2 x9, com.other"] != 1 || s.Callers["com.googlecode.iterm2"] != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestLogSummaryHumanAndErrors(t *testing.T) {
	h := newHarness(t)
	h.a.runLog = func(_ context.Context, _ []string, line func([]byte)) error {
		for _, l := range auditLines() {
			line([]byte(l))
		}
		return nil
	}
	if code := h.run("log", "summary", "--since", "1d"); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"ssh:github", "ssh:hydra", "python3", "com.googlecode.iterm2"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, h.out)
		}
	}
	if code := h.run("--json", "log", "summary"); code != 0 {
		t.Fatal(code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 2 {
		t.Fatalf("want one AuditSummary per target: %q", h.out)
	}
	for _, o := range objs {
		if o["kind"] != control.KindAuditSummary {
			t.Fatalf("%v", o)
		}
	}
	h.a.runLog = func(context.Context, []string, func([]byte)) error { return errors.New("log: Must be admin") }
	if code := h.run("log"); code != control.ExitError || !strings.Contains(h.errb.String(), "Must be admin") {
		t.Fatalf("runLog failure: exit %d %q", code, h.errb)
	}
}

// --yes is accepted for scripts (spec 6) and changes nothing.
func TestYesIsAccepted(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { replyFor(req, out) })
	for _, args := range [][]string{{"--yes", "status"}, {"status", "--yes"}, {"--json", "--yes", "revoke", "--all"}} {
		if code := h.run(args...); code != 0 {
			t.Errorf("%v: exit %d %q", args, code, h.errb)
		}
	}
}

// The CLI must never read the terminal for an approval: human approval
// only happens on Nazar.app's own gate (spec 6). Three entry points read
// stdin, and never for a yes or no: `secret add`, for the value (secrets
// design 7.1), which must never be an argument; the git credential
// helper's readCredential, for git's request; and `k8s ca create`
// at a terminal, for the context, the server and its CA (see
// TestK8sCACreateNeverTakesAYesForAnApproval). So os.Stdin
// appears only where main wires it into app.stdin, the hidden terminal
// read only in tty_darwin.go (wired into app.readHidden), and those seams
// are used only inside those functions (checked on the syntax tree, so no
// other function of the same file can ask a question either).
func TestNeverReadsStdin(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		src := string(b)
		if f == "main.go" {
			src = regexp.MustCompile(`stdin:\s+os\.Stdin,`).ReplaceAllString(src, "")
		}
		for _, banned := range []string{"os.Stdin", "term.ReadPassword", "bufio.NewReader(os.Std", "os.NewFile(0", "unix.Read(", "syscall.Read("} {
			if f == "tty_darwin.go" && banned == "unix.Read(" {
				continue
			}
			if strings.Contains(src, banned) {
				t.Errorf("%s uses %s", f, banned)
			}
		}
		for _, use := range seamUses(t, f) {
			// readCredential reads git's request (git-credential-nazar):
			// key=value lines from git, never the terminal.
			// k8sCACreate asks whether stdin is a terminal, and askSetup
			// asks there for the context, the server and its CA.
			if use != "readValue" && !(use == "readCredential" && f == "gitcred.go") && !((use == "k8sCACreate" || use == "askSetup") && f == "k8s.go") {
				t.Errorf("%s: %s uses app.stdin or app.readHidden: only secret add's readValue, the git helper's readCredential and k8s ca create's askSetup read stdin", f, use)
			}
		}
		if f != "main.go" && !strings.HasPrefix(f, "tty_") && strings.Contains(src, "readHiddenLine") {
			t.Errorf("%s uses readHiddenLine: only main wires it, into app.readHidden", f)
		}
	}
}

// seamUses returns the names of the functions of file f that use a.stdin
// or a.readHidden (any receiver variable).
func seamUses(t *testing.T, f string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, f, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "stdin" || sel.Sel.Name == "readHidden" || sel.Sel.Name == "stdinTerminal") {
				out = append(out, fn.Name.Name)
				return false
			}
			return true
		})
	}
	return out
}

// No command but secret add touches the stdin seams: with a reader and a
// hidden prompt that count every use, every other command leaves them
// alone, refused or not.
func TestNoOtherCommandUsesTheStdinSeams(t *testing.T) {
	h := newHarness(t)
	refuse := false
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if refuse {
			out.Emit(control.NewProblem(control.CodeRefused, "denied"))
			return
		}
		replyFor(req, out)
	})
	r := strings.NewReader("y\nyes\n")
	asked := 0
	h.a.stdin = r
	h.a.stdinTerminal = func() bool { asked++; return true }
	h.a.readHidden = func() ([]byte, error) { asked++; return []byte("y"), nil }
	writeConfig(t, h, "apiVersion: nazar/v1\nkind: Config\n")
	for _, ref := range []bool{false, true} {
		refuse = ref
		for _, args := range [][]string{
			{"ssh-key", "create", "work"}, {"ssh-key", "delete", "work"}, {"config", "apply"}, {"trust", "--app", "com.googlecode.iterm2"},
			{"revoke", "--all"}, {"status"}, {"config", "check"}, {"help"}, {"bogus"},
			{"secret", "list"}, {"secret", "rm", "X"}, {"secret"}, {"secret", "bogus"}, {"get", "X"},
			{"k8s", "list"}, {"k8s", "forget", "hydra"}, {"k8s", "ca", "show", "hydra"}, {"k8s", "rule", "remove", "hydra", "1"},
		} {
			h.run(args...)
		}
	}
	if asked != 0 || r.Len() != len("y\nyes\n") {
		t.Fatalf("a stdin seam was used: %d prompts, %d bytes read", asked, len("y\nyes\n")-r.Len())
	}
}

// Behavioural twin of TestNeverReadsStdin: with an answer waiting on stdin,
// no command (loosening ones included, refused or not) consumes a byte.
func TestNoCommandConsumesStdin(t *testing.T) {
	h := newHarness(t)
	refuse := false
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if refuse {
			out.Emit(control.NewProblem(control.CodeRefused, "denied"))
			return
		}
		replyFor(req, out)
	})
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	answer := "y\nyes\n"
	w.WriteString(answer)
	w.Close()
	old := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = old }()
	writeConfig(t, h, "apiVersion: nazar/v1\nkind: Config\n")
	for _, ref := range []bool{false, true} {
		refuse = ref
		for _, args := range [][]string{
			{"ssh-key", "create", "work"}, {"ssh-key", "delete", "work"}, {"config", "apply"}, {"trust", "--app", "com.googlecode.iterm2"},
			{"revoke", "--all"}, {"status"}, {"config", "check"}, {"help"}, {"bogus"},
		} {
			h.run(args...)
		}
	}
	os.Stdin = old
	rest, _ := io.ReadAll(r)
	if string(rest) != answer {
		t.Fatalf("stdin was read: %q left of %q", rest, answer)
	}
}

// hostile is a value that would clear the line, return the cursor and
// flip the reading direction if a human view ever printed it raw.
const hostile = "bad\x1b[2K\rname\u202e"

// hostileEscaped is how every human view must show hostile (Go-quoted,
// shown here without the surrounding quotes because the value may sit
// inside a longer quoted string such as a config problem path).
const hostileEscaped = `bad\x1b[2K\rname\u202e`

// assertEscaped fails when either stream carries a raw non-printing rune
// (other than the newlines between lines) or when the stream the command
// reports on does not show the escaped value.
func assertEscaped(t *testing.T, what string, h *harness, onStderr bool) {
	t.Helper()
	for _, r := range h.out.String() + h.errb.String() {
		if r != '\n' && !unicode.IsPrint(r) {
			t.Errorf("%s: raw non-printing rune %U reached the output: stdout %q stderr %q", what, r, h.out, h.errb)
			return
		}
	}
	want := h.out.String()
	if onStderr {
		want = h.errb.String()
	}
	if !strings.Contains(want, hostileEscaped) {
		t.Errorf("%s: escaped value missing: %q", what, want)
	}
}

// hostileReplies answers every control command with hostile strings in
// each field a human view prints.
func hostileReplies(_ context.Context, req control.Request, out control.Emitter) {
	key := control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: hostile, Type: hostile, Fingerprint: hostile,
		PublicKey: hostile, Configured: true, Rules: []string{hostile}}
	switch req.Command {
	case control.CmdSSHKeyCreate, control.CmdSSHKeyPubkey, control.CmdSSHKeyDelete:
		out.Emit(key)
	case control.CmdSSHKeyList:
		out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{key}})
	case control.CmdStatus:
		out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), AgentPath: hostile,
			Staged:    &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: strings.Repeat("ab", 32), Changes: []string{hostile}, Loosening: []string{hostile}}, // a well-formed hash, or config apply refuses it before printing
			Problems:  []control.ConfigProblem{{Severity: hostile, Path: hostile, Message: hostile}},
			Approvals: []control.Approval{{TypeMeta: control.Meta(control.KindApproval), Target: hostile, Rule: hostile, Scope: hostile, ScopeID: hostile, Op: hostile, Covers: hostile, Chain: hostile}}})
		if req.Follow {
			out.Emit(control.Approval{TypeMeta: control.Meta(control.KindApproval), Event: hostile, Target: hostile, Rule: hostile, Scope: hostile, ScopeID: hostile, Op: hostile, Covers: hostile, Chain: hostile, Reason: hostile})
		}
	case control.CmdRevoke:
		p := control.NewProblem(control.CodeRefused, "%s", hostile)
		p.Details = []string{hostile}
		out.Emit(p)
	case control.CmdConfigCheck:
		out.Emit(control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Path: req.Args["path"], Valid: true,
			Problems: []control.ConfigProblem{{Severity: hostile, Path: hostile, Message: hostile}},
			// A well-formed hash: config apply refuses any other before it
			// prints a line (TestConfigApplyShowsAndBindsTheStagedChange).
			Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: strings.Repeat("ab", 32), Loosens: true, Changes: []string{hostile}, Loosening: []string{hostile}}})
	case control.CmdConfigApply:
		out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Applied: true, Changes: []string{hostile}, Loosening: []string{hostile}})
	case control.CmdTrustApp:
		out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: hostile, Team: hostile, OldTeam: hostile, Path: hostile, Changed: true})
	default:
		out.Emit(control.NewProblem(control.CodeError, "%s", hostile))
	}
}

// Every human view escapes what it prints itself: a config-derived name,
// a path, a problem message or a reply field with a control, ESC, CR or
// bidi rune is rendered visibly, never relied on Nazar.app to have escaped
// it. The same runs with --json stay valid JSON.
func TestHumanOutputEscapesHostileStrings(t *testing.T) {
	h := newHarness(t)
	configPath := layout.ConfigFile(h.home)
	h.serve(t, func(ctx context.Context, req control.Request, out control.Emitter) {
		if req.Command == control.CmdConfigCheck {
			req.Args = map[string]string{"path": configPath}
		}
		hostileReplies(ctx, req, out)
	})
	// The config file itself names a key with the hostile string, so the
	// local validation problem carries it in its path.
	writeConfig(t, h, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    \"bad\\e[2K\\rname\\u202e\":\n      gate: login\n")
	cases := []struct {
		args   []string
		stderr bool
	}{
		{args: []string{"config", "check"}},
		{args: []string{"config", "apply"}},
		{args: []string{"status"}},
		{args: []string{"status", "--follow"}},
		{args: []string{"ssh-key", "list"}},
		{args: []string{"ssh-key", "pubkey", "github"}},
		{args: []string{"ssh-key", "delete", "github"}},
		{args: []string{"ssh-key", "create", "github"}},
		{args: []string{"trust", "--app", "com.googlecode.iterm2"}},
		{args: []string{"revoke", "--all"}, stderr: true},
		{args: []string{"revoke", "--all", "--" + hostile}, stderr: true},
		{args: []string{hostile}, stderr: true},
	}
	for _, c := range cases {
		h.run(c.args...)
		assertEscaped(t, fmt.Sprint(c.args), h, c.stderr)
		h.run(append([]string{"--json"}, c.args...)...)
		for _, l := range strings.Split(strings.TrimSpace(h.out.String()), "\n") {
			if !json.Valid([]byte(l)) {
				t.Errorf("--json %v: stdout line is not valid JSON: %q", c.args, l)
			}
		}
		if h.errb.Len() != 0 {
			t.Errorf("--json %v: wrote to stderr: %q", c.args, h.errb)
		}
	}
	// Without Nazar.app, config check still prints the file's own problem.
	h.env["NAZAR_CONTROL_SOCKET"] = filepath.Join(h.home, "absent.sock")
	if code := h.run("config", "check"); code != control.ExitError {
		t.Fatalf("exit %d\n%s", code, h.out)
	}
	assertEscaped(t, "config check without the app", h, false)
}
