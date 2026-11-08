package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/unixsock"
)

// `nazar aws credential <name>` is credential_process (aws design 3): it
// reads no environment at all, dials <passwd home>/.nazar/run/control.sock, and
// writes exactly the credential_process JSON to stdout in one write; on
// failure one line to stderr and the exit code of 6.3.

var awsExp = time.Date(2026, 10, 31, 13, 0, 0, 0, time.UTC)

func awsCred(name string) control.AWSCredential {
	return control.AWSCredential{TypeMeta: control.Meta(control.KindAWSCredential), Name: name, AccessKeyID: "ASIAFAKEAWSTESTKEY01",
		SecretAccessKey: "fake/Secret+Access+Key", SessionToken: "FakeToken//Zm9v+=", Expiration: awsExp, AccountID: "123456789012"}
}

const awsWant = `{"Version":1,"AccessKeyId":"ASIAFAKEAWSTESTKEY01","SecretAccessKey":"fake/Secret+Access+Key","SessionToken":"FakeToken//Zm9v+=","Expiration":"2026-10-31T13:00:00Z","AccountId":"123456789012"}` + "\n"

// awsServer runs a stub nazar-agent at <dir>/.nazar/run/control.sock answering
// aws.credential with reply (a Problem, or a credential).
func awsServer(t *testing.T, reply any) (dir string, reqs *[]control.Request, dials *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "nzaw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.MkdirAll(filepath.Join(dir, ".nazar"), 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := unixsock.Listen(layout.ControlSocket(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var got []control.Request
	var n atomic.Int32
	srv := &control.Server{Resolve: func(int) *caller.Chain { n.Add(1); return &caller.Chain{} }, Handler: handlerFunc(func(_ context.Context, req control.Request, out control.Emitter) {
		got = append(got, req)
		_ = out.Emit(reply)
	})}
	go func() { _ = srv.Serve(l) }()
	return dir, &got, &n
}

func awsHarness(t *testing.T, reply any) (*harness, *[]control.Request, *atomic.Int32) {
	t.Helper()
	h := newHarness(t)
	dir, reqs, dials := awsServer(t, reply)
	h.a.accountHome = func() string { return dir }
	return h, reqs, dials
}

// oneWrite counts the writes to stdout.
type oneWrite struct {
	bytes.Buffer
	n int
}

func (w *oneWrite) Write(p []byte) (int, error) { w.n++; return w.Buffer.Write(p) }

func TestAWSCredentialCLI(t *testing.T) {
	h, reqs, _ := awsHarness(t, awsCred("dev"))
	w := &oneWrite{}
	h.a.stdout = w
	if code := h.a.run([]string{"aws", "credential", "dev"}); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.errb)
	}
	if w.String() != awsWant || w.n != 1 || h.errb.Len() != 0 {
		t.Fatalf("stdout must be exactly the credential_process JSON, in one write (%d):\n%q\nstderr %q", w.n, w.String(), h.errb)
	}
	if len(*reqs) != 1 || (*reqs)[0].Command != control.CmdAWSCredential || len((*reqs)[0].Args) != 1 || (*reqs)[0].Args["name"] != "dev" {
		t.Fatalf("request %+v", *reqs)
	}
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"invalid name":   {[]string{"aws", "credential", "a/b"}, control.ExitUsage},
		"no name":        {[]string{"aws", "credential"}, control.ExitUsage},
		"two names":      {[]string{"aws", "credential", "a", "b"}, control.ExitUsage},
		"--json":         {[]string{"--json", "aws", "credential", "dev"}, control.ExitUsage},
		"unknown option": {[]string{"aws", "credential", "--x", "dev"}, control.ExitUsage},
	} {
		h, reqs, dials := awsHarness(t, awsCred("dev"))
		if code := h.run(tc.args...); code != tc.code {
			t.Errorf("%s: exit %d, want %d", name, code, tc.code)
		}
		if h.out.Len() != 0 || len(*reqs) != 0 || dials.Load() != 0 {
			t.Errorf("%s: nothing sent, nothing on stdout: %q", name, h.out)
		}
		if strings.Count(h.errb.String(), "\n") != 1 || !strings.HasPrefix(h.errb.String(), "nazar: ") {
			t.Errorf("%s: exactly one stderr line: %q", name, h.errb)
		}
	}
	// Each exit code of aws design 6.3, nothing on stdout, one stderr line.
	for name, tc := range map[string]struct {
		reply any
		code  int
	}{
		"refused":       {control.NewProblem(control.CodeRefused, "refused: not a trusted aws client"), control.ExitRefused},
		"usage":         {control.NewProblem(control.CodeUsage, "no aws entry dev in config.yaml"), control.ExitUsage},
		"aws refused":   {control.NewProblem(control.CodeError, "aws: AccessDeniedException: Unable to assume role"), control.ExitError},
		"not connected": {control.NewProblem(control.CodeError, "aws.dev is not connected yet"), control.ExitError},
		"another entry": {awsCred("prod"), control.ExitError},
		"bad key id":    {func() control.AWSCredential { c := awsCred("dev"); c.AccessKeyID = "asia"; return c }(), control.ExitError},
		"no secret":     {func() control.AWSCredential { c := awsCred("dev"); c.SecretAccessKey = ""; return c }(), control.ExitError},
		"ctl in token":  {func() control.AWSCredential { c := awsCred("dev"); c.SessionToken = "a\x1b[2Jb"; return c }(), control.ExitError},
		"no expiry":     {func() control.AWSCredential { c := awsCred("dev"); c.Expiration = time.Time{}; return c }(), control.ExitError},
		"bad account":   {func() control.AWSCredential { c := awsCred("dev"); c.AccountID = "x"; return c }(), control.ExitError},
	} {
		h, _, _ := awsHarness(t, tc.reply)
		if code := h.run("aws", "credential", "dev"); code != tc.code || h.out.Len() != 0 || strings.Count(h.errb.String(), "\n") != 1 {
			t.Errorf("%s: exit %d (want %d), out %q, err %q", name, code, tc.code, h.out, h.errb)
		}
		if strings.Contains(h.errb.String(), "Secret") || strings.Contains(h.errb.String(), "FakeToken") {
			t.Errorf("%s: a credential on stderr", name)
		}
	}
	// nazar-agent not running: exit 5.
	h = newHarness(t)
	dir := t.TempDir()
	h.a.accountHome = func() string { return dir }
	if code := h.run("aws", "credential", "dev"); code != control.ExitUnavailable || h.out.Len() != 0 || strings.Count(h.errb.String(), "\n") != 1 {
		t.Fatalf("not running: exit %d, err %q", code, h.errb)
	}
}

// ~/.aws/config is any process's to write, and an SDK passes its own
// environment on: HOME, NAZAR_CONTROL_SOCKET, NAZAR_TEST_CONTROL_SOCKET and
// AWS_* are all ignored.
func TestAWSCredentialIgnoresTheEnvironment(t *testing.T) {
	h, reqs, dials := awsHarness(t, awsCred("dev"))
	decoy, err := os.MkdirTemp("/tmp", "nza")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(decoy) })
	homeDials := decoySocket(t, layout.ControlSocket(decoy))
	sockDials := decoySocket(t, filepath.Join(decoy, "sock"))
	h.env["HOME"] = decoy
	h.env["NAZAR_CONTROL_SOCKET"] = filepath.Join(decoy, "sock")
	h.env["NAZAR_TEST_CONTROL_SOCKET"] = filepath.Join(decoy, "sock")
	h.env["AWS_PROFILE"] = "other"
	h.env["AWS_REGION"] = "eu-west-2"
	h.env["AWS_ENDPOINT_URL"] = "https://evil.example"
	if code := h.run("aws", "credential", "dev"); code != control.ExitOK {
		t.Fatalf("exit %d\n%s", code, h.errb)
	}
	if dials.Load() != 1 || len(*reqs) != 1 || homeDials.Load() != 0 || sockDials.Load() != 0 || len((*reqs)[0].Args) != 1 {
		t.Fatalf("the passwd home's socket, the name only: %d %d %d %+v", dials.Load(), homeDials.Load(), sockDials.Load(), *reqs)
	}
}

// A prefix another writer put on the pipe before nazar ran can't make the
// clients read other values (aws design 3.4): the whole text fails to
// parse, or parses to nazar's values.
func FuzzAWSCredentialPrefix(f *testing.F) {
	out, err := encodeProcessCredential(awsCred("dev"))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"", " ", "\n", "{", `{"AccessKeyId":"AKIAEVIL",`, `[`, `{"x":`, `"`, `{"SecretAccessKey":"evil"}`, `{"a":1} `, "\ufeff", `//`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, prefix string) {
		var got processCredential
		dec := json.NewDecoder(strings.NewReader(prefix + string(out)))
		if err := dec.Decode(&got); err != nil {
			return
		}
		if _, err := dec.Token(); err != io.EOF {
			return // extra data: json.loads and json.Unmarshal refuse the text
		}
		if got.AccessKeyID != "ASIAFAKEAWSTESTKEY01" || got.SecretAccessKey != "fake/Secret+Access+Key" || got.SessionToken != "FakeToken//Zm9v+=" ||
			got.Expiration != "2026-10-31T13:00:00Z" || got.AccountID != "123456789012" || got.Version != 1 {
			t.Fatalf("prefix %q gave %+v", prefix, got)
		}
		// json.Unmarshal, as the Go SDK reads it, agrees.
		var again processCredential
		if json.Unmarshal([]byte(prefix+string(out)), &again) == nil && again != got {
			t.Fatalf("prefix %q: Unmarshal %+v", prefix, again)
		}
	})
}

func TestAWSCACreateCLI(t *testing.T) {
	h := newHarness(t)
	// No aws on PATH: nothing is pinned, so none is needed (aws design 6.1).
	h.env["PATH"] = "/nonexistent"
	h.a.selfPath = func() (string, error) { return "/Users/you/.local/bin/nazar", nil }
	cert := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	var whileLocked atomic.Bool
	whileLocked.Store(true)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.AWSEntry{TypeMeta: control.Meta(control.KindAWSEntry), Name: req.Args["name"], Configured: true,
			Identity: &control.AWSIdentity{User: "you-nazar"}, Duration: "1h", Rules: []string{}, State: control.AWSStateNotConnected,
			CA: &control.AWSCA{TypeMeta: control.Meta(control.KindAWSCA), Name: req.Args["name"], Fingerprint: "ab12", CertFile: "/Users/you/.nazar/keys/aws-ca-dev.crt",
				CertPEM: cert, WhileLocked: whileLocked.Load()}})
	})
	if code := h.run("aws", "ca", "create", "dev"); code != control.ExitOK {
		t.Fatalf("exit %d: %s", code, h.errb)
	}
	r := h.requests()
	if len(r) != 1 || r[0].Command != control.CmdAWSCACreate || len(r[0].Args) != 1 || r[0].Args["name"] != "dev" {
		t.Fatalf("%+v", r)
	}
	out := h.out.String()
	for _, want := range []string{
		"dev is set up: its CA is in the Secure Enclave (SHA-256 ab12), config.yaml has aws.dev.",
		"1. A trust anchor holding the CA (this step needs jq: brew install jq):",
		"--rawfile pem /Users/you/.nazar/keys/aws-ca-dev.crt",
		`"aws:PrincipalTag/x509Subject/CN": "you-nazar"`,
		`"aws:PrincipalTag/x509Issuer/CN": "nazar aws CA dev"`,
		"aws iam create-role --role-name dev",
		"aws rolesanywhere create-profile --name nazar-dev",
		"trustAnchorArn: <trust anchor ARN>",
		"[profile dev]\ncredential_process = /Users/you/.local/bin/nazar aws credential dev\n",
		"aws sts get-caller-identity --profile dev",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// --only-when-unlocked, answered with a CA that works while locked: refused.
	if code := h.run("aws", "ca", "create", "dev", "--only-when-unlocked"); code != control.ExitError || !strings.Contains(h.errb.String(), "nazar aws forget dev") {
		t.Fatalf("exit %d: %s", code, h.errb)
	}
	if r := h.requests(); r[len(r)-1].Args["onlyWhenUnlocked"] != "true" {
		t.Fatalf("%+v", r[len(r)-1])
	}
	whileLocked.Store(false)
	if code := h.run("--json", "aws", "ca", "create", "dev", "--only-when-unlocked"); code != control.ExitOK || !strings.Contains(h.out.String(), `"certPEM":"-----BEGIN CERTIFICATE-----`) {
		t.Fatalf("exit %d: %s %s", code, h.out, h.errb)
	}
	// A path with a space is quoted; one with a character AWS refuses is refused.
	if got := credentialProcess("/Users/you/my bin/nazar", "dev"); got != `credential_process = "/Users/you/my bin/nazar" aws credential dev` {
		t.Fatal(got)
	}
	h.a.selfPath = func() (string, error) { return "/Users/you/bin$x/nazar", nil }
	n := len(h.requests())
	if code := h.run("aws", "ca", "create", "dev"); code != control.ExitError || len(h.requests()) != n {
		t.Fatalf("exit %d: %s", code, h.errb)
	}
	if strings.Contains(h.out.String()+h.errb.String(), "client") {
		t.Fatalf("no client is named:\n%s%s", h.out, h.errb)
	}
}
