package daemon

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/aws"
	"github.com/atas/nazar/core/aws/awstest"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets/envpolicy"
)

// aws design 3.3, 6: aws.credential is a value command, answered only to
// the genuine nazar CLI; nazar-agent runs checks 1 and 3 (check 1: the
// program that ran the CLI is identified; there is no client list), the stdout check
// and the gate, checks the entry again at mint time, mints one leaf from
// the entry's CA, signs one CreateSession with it and hands the CLI the
// session. The fake endpoint stands in for AWS.

var awsCode = platform.CodeIdentity{Signed: true, TeamID: "94KV3E626L", SigningID: "aws", CDHash: []byte{0xa5}}

func awsProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/usr/local/aws-cli/aws", Args: append([]string{"aws"}, args...), Cwd: "/Users/u/projects/foo", Code: awsCode}
}

// awsCredCLI is credential_process as botocore runs it: stdout a pipe
// whose read end its parent holds.
func awsCredCLI(name string) fake.Proc {
	p := cliProc("aws", "credential", name)
	p.StdoutToParent = true
	return p
}

const (
	testAnchor  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
	testProfile = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
	testRole    = "arn:aws:iam::123456789012:role/dev"
)

const awsConfig = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  aws: {signed: {team: 94KV3E626L, id: aws}}
aws:
  dev:
    identity: {user: dev-nazar}
    trustAnchorArn: ` + testAnchor + `
    profileArn: ` + testProfile + `
    roleArn: ` + testRole + `
    duration: 30m
    rules:
      - apps: [iterm]
        scope: session
        gate: dialog
  later:
    identity: {user: dev-nazar}
    rules:
      - apps: [iterm]
        gate: dialog
`

type awsEnv struct {
	*env
	fake   *awstest.Server
	logs   *logBuf
	shown0 int
}

func startAWS(t *testing.T) *awsEnv { t.Helper(); return startAWSWith(t, nil) }

// startAWSWith is startAWS with more set on the fake platform first.
func startAWSWith(t *testing.T, more func(f *fake.Fake)) *awsEnv {
	t.Helper()
	logs := &logBuf{}
	client := &aws.Client{}
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		o.Logf = logs.Printf
		o.Pipes = f
		o.AWS = client
		if more != nil {
			more(f)
		}
	})
	e.approved(t, awsConfig)
	ca, err := e.d.awsCA.Create("dev", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.awsCA.Create("later", platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	srv := awstest.Start(t, "us-east-1", ca.CertPEM())
	client.Endpoint, client.RootCAs = srv.URL, srv.RootCAs()
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	return &awsEnv{env: e, fake: srv, logs: logs, shown0: len(e.f.Shown())}
}

func (e *awsEnv) credential(t *testing.T, name string) (control.AWSCredential, *control.Problem) {
	t.Helper()
	var c control.AWSCredential
	err := e.call(t, control.CmdAWSCredential, map[string]string{"name": name}, control.KindAWSCredential, &c)
	return c, control.AsProblem(err)
}

func TestAWSCredentialMintsASession(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, awsProc("s3", "ls"), awsCredCLI("dev"))
	e.f.SetDefaultPeer(tab.Peer())
	before := time.Now()
	c, p := e.credential(t, "dev")
	if p != nil {
		t.Fatal(p)
	}
	if c.Kind != control.KindAWSCredential || c.Name != "dev" || c.AccessKeyID != awstest.AccessKeyID || c.SecretAccessKey != awstest.SecretAccessKey ||
		c.SessionToken != awstest.SessionToken || c.AccountID != "123456789012" || c.Expiration.Before(before.Add(29*time.Minute)) ||
		c.Expiration.After(time.Now().Add(31*time.Minute)) {
		t.Fatalf("%+v", c)
	}
	seen := e.fake.Seen()
	if len(seen) != 1 || seen[0].Err != nil || seen[0].Params.DurationSeconds != 1800 || seen[0].CN != "dev-nazar" || seen[0].Issuer != "nazar aws CA dev" ||
		seen[0].UserAgent != "nazar" {
		t.Fatalf("%+v", seen)
	}
	f := e.lastAudit(t)
	if f["target"] != "aws:dev" || f["decision"] != "approved" || f["destination"] != testRole ||
		f["operation"] != "aws credential session "+seen[0].SerialHex || !strings.HasPrefix(f["receiver"], "aws s3 ls") {
		t.Fatalf("audit %v (the serial AWS saw: %s)", f, seen[0].SerialHex)
	}
	prompt := e.f.Shown()[len(e.f.Shown())-1].Prompt
	if prompt.Title != `iTerm2 wants to use AWS credential "dev"` || !strings.Contains(strings.Join(prompt.Lines, "\n"), "the AWS credential for "+testRole+", 30m") {
		t.Fatalf("prompt %+v", prompt)
	}
	// The same tab: covered, a new session with a new serial.
	a := e.f.Launch(tab.Shell, awsProc("sts", "get-caller-identity"))
	e.f.SetDefaultPeer(e.f.Launch(a, awsCredCLI("dev")))
	if _, p := e.credential(t, "dev"); p != nil {
		t.Fatal(p)
	}
	if f := e.lastAudit(t); f["decision"] != "allowed" || f["reason"] != "cached approval" || f["operation"] == "aws credential session "+seen[0].SerialHex {
		t.Fatalf("audit %v", f)
	}
	if n := len(e.fake.Seen()); n != 2 || e.fake.Accepted() != 2 {
		t.Fatalf("one CreateSession per run: %d", n)
	}
}

func TestAWSCredentialAnswersOnlyTheGenuineCLI(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	for name, impostor := range map[string]fake.Proc{
		"unsigned":   {Path: "/tmp/fake-nazar", Args: []string{"nazar", "aws", "credential", "dev"}},
		"ad hoc":     {Path: "/tmp/fake-nazar", Args: []string{"nazar"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "dev.nazar.cli"}},
		"aws itself": awsProc("s3", "ls"),
	} {
		e.asCLI(awsProc(), impostor)
		c, p := e.credential(t, "dev")
		if p == nil || p.Code != control.CodeRefused || p.Message != errNotCLI || c.SecretAccessKey != "" {
			t.Fatalf("%s: %+v", name, p)
		}
		if f := e.lastAudit(t); f["decision"] != "blocked" || f["target"] != "aws:dev" || f["reason"] != errNotCLI {
			t.Fatalf("%s: audit %v", name, f)
		}
	}
	e.asCLI(awsProc(), fake.Proc{Path: "/tmp/fake-nazar"})
	if _, p := e.credential(t, "../x\x1b"); p == nil || p.Code != control.CodeRefused {
		t.Fatalf("%+v", p)
	}
	if f := e.lastAudit(t); f["target"] != "aws:(invalid name)" {
		t.Fatalf("audit %v", f)
	}
	if len(e.fake.Seen()) != 0 || len(e.f.Shown()) != e.shown0 {
		t.Fatal("nothing asked, nothing sent")
	}
}

// No client list (aws design 6.1): whatever program runs
// credential_process in an allowed chain gets the session, with no nazar
// trust; one whose code identity can't be told gets nothing, and no prompt.
func TestAWSCredentialGoesToAnyProgramInAnAllowedChain(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	py := fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "deploy.py"}, Code: fake.AppleCode("com.apple.python3")}
	tf := fake.Proc{Path: "/opt/homebrew/bin/terraform", Args: []string{"terraform", "plan"}, Code: platform.CodeIdentity{Signed: true, TeamID: "TFTEAM0001", SigningID: "terraform"}}
	for name, procs := range map[string][]fake.Proc{
		"terraform": {tf, awsCredCLI("dev")},
		"python3":   {py, awsCredCLI("dev")},
		"the shell": {awsCredCLI("dev")},
	} {
		e.asCLI(procs...)
		if c, p := e.credential(t, "dev"); p != nil || c.SecretAccessKey == "" {
			t.Fatalf("%s: %+v", name, p)
		}
	}
	signs, shown, sent := e.f.SignCalls(), len(e.f.Shown()), len(e.fake.Seen())
	e.asCLI(fake.Proc{Path: "/usr/local/aws-cli/aws", Args: []string{"aws"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "aws"}}, awsCredCLI("dev"))
	if _, p := e.credential(t, "dev"); p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "can't be identified") {
		t.Fatalf("no cdhash, no team: %+v", p)
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != shown || len(e.fake.Seen()) != sent {
		t.Fatal("nothing signed, asked or sent")
	}
	if w := e.f.Warnings(); len(w) == 0 || !strings.Contains(strings.Join(w[len(w)-1].Lines, "\n"), "can't be identified") {
		t.Fatalf("the block warning: %+v", w)
	}
}

func TestAWSCredentialRefusals(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	signs := e.f.SignCalls()
	// The stdout check, before any prompt.
	e.asCLI(awsProc("s3", "ls"), cliProc("aws", "credential", "dev"))
	if _, p := e.credential(t, "dev"); p == nil || p.Code != control.CodeRefused || p.Message != "refused: "+errAWSStdout {
		t.Fatalf("stdout: %+v", p)
	}
	if f := e.lastAudit(t); f["decision"] != "blocked" || f["reason"] != errAWSStdout || !strings.HasPrefix(f["operation"], "aws credential session ") {
		t.Fatalf("audit %v", f)
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 || len(e.fake.Seen()) != 0 {
		t.Fatal("nothing signed, asked or sent")
	}
	// Usage: an invalid name, an unknown entry.
	e.asCLI(awsProc(), awsCredCLI("dev"))
	for _, n := range []string{"a/b", "prod"} {
		if _, p := e.credential(t, n); p == nil || p.Code != control.CodeUsage {
			t.Fatalf("%s: %+v", n, p)
		}
	}
	// Not connected: exit 1 with the fix.
	if _, p := e.credential(t, "later"); p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "is not connected yet: add trustAnchorArn") {
		t.Fatalf("not connected: %+v", p)
	}
	// No CA: refused with the fix.
	if err := e.d.awsCA.Delete("dev"); err != nil {
		t.Fatal(err)
	}
	if _, p := e.credential(t, "dev"); p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "nazar aws ca create dev") {
		t.Fatalf("no CA: %+v", p)
	}
	if len(e.f.Shown()) != e.shown0 || len(e.fake.Seen()) != 0 {
		t.Fatal("nothing asked or sent")
	}
}

// aws design 3.4, THREAT-MODEL 5.16: the stdout check of k8s, unchanged. A
// profile whose credential_process wraps nazar keeps aws the CLI's parent
// but copies the reply (`exec > >(tee leak); exec nazar …`); that, a pipe
// the shell or the CLI's own child reads and a co-writer are refused
// before any prompt, with nothing signed or sent.
func TestAWSCredentialRefusesAnOutputThatDoesNotGoStraightToTheProgram(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	signs := e.f.SignCalls()
	tee := fake.Proc{Path: "/usr/bin/tee", Args: []string{"tee", "/tmp/leak"}, Code: fake.AppleCode("com.apple.tee")}
	plain := cliProc("aws", "credential", "dev") // fd 1 no pipe anyone reads
	for name, setup := range map[string]func(){
		"a pipe the shell reads": func() {
			tab := e.f.ITermTab(platform.ProcessRef{}, awsProc("s3", "ls"), plain)
			e.f.SetStdout(tab.Peer(), tab.Shell)
			e.f.SetDefaultPeer(tab.Peer())
		},
		"a pipe its own child reads": func() {
			tab := e.f.ITermTab(platform.ProcessRef{}, awsProc("s3", "ls"), plain)
			e.f.SetStdout(tab.Peer(), e.f.Launch(tab.Peer(), tee))
			e.f.SetDefaultPeer(tab.Peer())
		},
		"an exec-hop relay through tee": func() {
			a := e.f.Launch(e.f.ITermTab(platform.ProcessRef{}).Shell, awsProc("s3", "ls"))
			cli := e.f.Launch(a, plain)
			t := e.f.Launch(cli, tee)
			e.f.SetStdout(cli, t)
			e.f.SetStdout(t, a)
			e.f.SetDefaultPeer(cli)
		},
		"a pipe with a co-writer": func() {
			cli := e.asCLI(awsProc("s3", "ls"), awsCredCLI("dev"))
			e.f.Launch(cli, fake.Proc{Path: "/bin/sleep", Args: []string{"sleep", "1"}, Code: fake.AppleCode("com.apple.sleep")})
			e.f.SetStdoutForeign(cli)
		},
	} {
		setup()
		c, p := e.credential(t, "dev")
		if p == nil || p.Code != control.CodeRefused || p.Message != "refused: "+errAWSStdout || c.SecretAccessKey != "" {
			t.Fatalf("%s: %+v", name, p)
		}
		if f := e.lastAudit(t); f["decision"] != "blocked" || f["target"] != "aws:dev" || f["reason"] != errAWSStdout {
			t.Fatalf("%s: audit %v", name, f)
		}
	}
	if e.f.SignCalls() != signs || len(e.f.Shown()) != e.shown0 || len(e.fake.Seen()) != 0 {
		t.Fatal("nothing signed, asked or sent")
	}
}

// The stdout check runs again at mint time: a pipe that passed before the
// prompt and fails after it gets nothing, and AWS is never called.
func TestAWSCredentialChecksTheOutputAgainAtMint(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	e := startAWSWith(t, func(f *fake.Fake) {
		f.StdoutFunc = func(platform.ProcessRef, platform.ProcessRef) (bool, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			return calls == 1, nil
		}
	})
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(awsProc("s3", "ls"), awsCredCLI("dev"))
	signs := e.f.SignCalls()
	c, p := e.credential(t, "dev")
	if p == nil || !strings.Contains(p.Message, errAWSStdout) || c.SecretAccessKey != "" {
		t.Fatalf("%+v", p)
	}
	if e.f.SignCalls() != signs || len(e.fake.Seen()) != 0 {
		t.Fatal("nothing may be signed or sent")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("%d checks, want one before the prompt and one at mint", calls)
	}
}

// AWS's refusal is an error (exit 1), never the user's (exit 3), with AWS's
// code in the message and the audit line.
func TestAWSCredentialAWSErrors(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.asCLI(awsProc("s3", "ls"), awsCredCLI("dev"))
	for _, tc := range []struct {
		status int
		code   string
	}{{403, "AccessDeniedException"}, {400, "ValidationException"}, {404, "ResourceNotFoundException"}, {429, "ThrottlingException"}} {
		e.fake.Fail(tc.status, tc.code, "nope")
		c, p := e.credential(t, "dev")
		if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, tc.code+": nope") || strings.HasPrefix(p.Message, "refused") || c.SecretAccessKey != "" {
			t.Fatalf("%s: %+v", tc.code, p)
		}
		if f := e.lastAudit(t); f["decision"] != "error" || !strings.Contains(f["reason"], tc.code) {
			t.Fatalf("%s: audit %v", tc.code, f)
		}
	}
	// An unreachable endpoint.
	e.fake.SetReply(func(w http.ResponseWriter, _ awstest.Seen) bool {
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
		return true
	})
	if _, p := e.credential(t, "dev"); p == nil || p.ExitCode() != control.ExitError {
		t.Fatalf("connection dropped: %+v", p)
	}
}

// A CA that signs only while the Mac is unlocked mints nothing while it
// is locked: exit 1, saying so, and no request reaches AWS.
func TestAWSCredentialLockedCA(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.asCLI(awsProc("s3", "ls"), awsCredCLI("dev"))
	e.f.SetLocked(true)
	_, p := e.credential(t, "dev")
	if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "aws: the Mac is locked; the CA of dev signs only while it's unlocked") {
		t.Fatalf("%+v", p)
	}
	if len(e.fake.Seen()) != 0 {
		t.Fatal("nothing may be sent")
	}
	if f := e.lastAudit(t); f["decision"] != "error" || !strings.Contains(f["reason"], "the Mac is locked") {
		t.Fatalf("audit %v", f)
	}
}

// The entry is read again at mint time: any change while the dialog was
// open mints nothing and sends nothing.
func TestAWSCredentialChecksAgainAtMint(t *testing.T) {
	for name, edit := range map[string]func(string) string{
		"removed": func(string) string {
			return "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n"
		},
		"role":     func(b string) string { return strings.Replace(b, "role/dev", "role/admin", 1) },
		"duration": func(b string) string { return strings.Replace(b, "duration: 30m", "duration: 15m", 1) },
		"identity": func(b string) string {
			return strings.Replace(b, "identity: {user: dev-nazar}", "identity: {user: other-nazar}", 1)
		},
		"blocked": func(b string) string {
			return strings.Replace(b, "    duration: 30m\n    rules:\n      - apps: [iterm]\n        scope: session\n        gate: dialog\n", "    duration: 30m\n    gate: block\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := startAWS(t)
			hold := make(chan struct{})
			e.f.ScriptConfirm(fake.Answer{Allow: true, Wait: hold})
			e.asCLI(awsProc("s3", "ls"), awsCredCLI("dev"))
			var c control.AWSCredential
			done := e.callInBackground(t, control.CmdAWSCredential, map[string]string{"name": "dev"}, control.KindAWSCredential, &c)
			waitFor(t, func() bool { return e.f.CountShown(fake.KindConfirm) == 1 })
			signs := e.f.SignCalls()
			body := edit(awsConfig)
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
			e.writeConfig(t, body)
			waitFor(t, func() bool {
				if string(e.d.stager.Active().Raw) == body {
					return true
				}
				_, _ = e.apply(t)
				return string(e.d.stager.Active().Raw) == body
			})
			close(hold)
			p := <-done
			if p == nil || c.SecretAccessKey != "" || e.f.SignCalls() != signs || len(e.fake.Seen()) != 0 {
				t.Fatalf("nothing may be minted or sent: %+v (%d signs, %d requests)", p, e.f.SignCalls()-signs, len(e.fake.Seen()))
			}
		})
	}
}

// The session credentials leave only in the reply, and the reply carries no
// certificate or key: not the audit log, the daemon's log, a problem,
// status, config.yaml or any file holds them.
func TestAWSCredentialLeavesOnlyThroughTheReply(t *testing.T) {
	e := startAWS(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.asCLI(awsProc("s3", "ls"), awsCredCLI("dev"))
	c, p := e.credential(t, "dev")
	if p != nil {
		t.Fatal(p)
	}
	reply, _ := json.Marshal(c)
	if strings.Contains(string(reply), "BEGIN") || strings.Contains(string(reply), "MII") {
		t.Fatalf("the reply holds a certificate or a key: %s", reply)
	}
	e.fake.Fail(403, "AccessDeniedException", "denied")
	_, refused := e.credential(t, "dev")
	var st control.Status
	_ = e.call(t, control.CmdStatus, nil, control.KindStatus, &st)
	stJSON, _ := json.Marshal(st)
	hay := map[string]string{
		"audit":   strings.Join(e.sink.Lines(), "\n"),
		"logs":    e.logs.String(),
		"status":  string(stJSON),
		"problem": refused.Message,
		"config":  e.readConfig(t),
	}
	_ = filepath.Walk(e.home, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			b, _ := os.ReadFile(path)
			hay["file "+path] = string(b)
		}
		return nil
	})
	for where, text := range hay {
		for _, n := range []string{awstest.AccessKeyID, awstest.SecretAccessKey, awstest.SessionToken, awstest.SecretAccessKey[:16], awstest.SessionToken[:16]} {
			if strings.Contains(text, n) {
				t.Fatalf("credential material in %s", where)
			}
		}
	}
}

// --- ca create, show, list, forget, rules ---

type awsAdmin struct {
	*env
}

func startAWSAdmin(t *testing.T) *awsAdmin {
	t.Helper()
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.VerifyCLI = genuineCLI(f)
		o.Pipes = f
		o.RunHost = func(int) (envpolicy.Host, error) { return envpolicy.Host{Home: "/Users/dev", User: "dev"}, nil }
	})
	// No apps.aws and no aws binary: nothing needs them (ca create pins no
	// program).
	e.approved(t, "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\n")
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(cliProc("aws"))
	return &awsAdmin{env: e}
}

func (e *awsAdmin) create(t *testing.T, args map[string]string) (control.AWSEntry, *control.Problem) {
	t.Helper()
	var o control.AWSEntry
	err := e.call(t, control.CmdAWSCACreate, args, control.KindAWSEntry, &o)
	return o, control.AsProblem(err)
}

func TestAWSCACreate(t *testing.T) {
	e := startAWSAdmin(t)
	logins := e.logins()
	o, p := e.create(t, map[string]string{"name": "dev"})
	if p != nil {
		t.Fatal(p)
	}
	if e.logins() != logins+1 {
		t.Fatal("one login prompt")
	}
	if !o.Configured || o.State != control.AWSStateNotConnected || o.Identity == nil || o.Identity.User != "dev-nazar" || o.CA == nil ||
		!o.CA.WhileLocked || !strings.HasPrefix(o.CA.CertPEM, "-----BEGIN CERTIFICATE-----") || o.Duration != "1h" ||
		!strings.Contains(o.Remedy, "not connected yet") {
		t.Fatalf("%+v", o)
	}
	text := promptText(e.f.Shown()[len(e.f.Shown())-1].Prompt)
	for _, want := range []string{`Set up AWS entry "dev"?`, "identity: CN=dev-nazar", "not connected yet",
		"the program that runs credential_process (the AWS CLI, an SDK, terraform …) gets the credential when the rules allow whoever ran it"} {
		if !strings.Contains(text, want) {
			t.Errorf("prompt lacks %q:\n%s", want, text)
		}
	}
	for _, never := range []string{"clients", "trust /", "cdhash", "apps.aws"} {
		if strings.Contains(text, never) {
			t.Errorf("no program is pinned: the prompt must not show %q:\n%s", never, text)
		}
	}
	cfg := e.readConfig(t)
	if !strings.Contains(cfg, "aws:\n  dev:\n    identity:\n      user: dev-nazar\n    gate: block\n    rules:") || strings.Contains(cfg, "clients") ||
		e.d.stager.Active().Apps["aws"].Kind != "" {
		t.Fatalf("config.yaml (no clients, no apps.aws):\n%s", cfg)
	}
	crt, err := os.ReadFile(filepath.Join(layout.KeysDir(e.home), "aws-ca-dev.crt"))
	if err != nil || string(crt) != o.CA.CertPEM {
		t.Fatalf("the certificate file: %v", err)
	}
	// Again: answered at once; with the other access refused.
	if _, p := e.create(t, map[string]string{"name": "dev"}); p != nil || e.logins() != logins+1 {
		t.Fatalf("again: %+v", p)
	}
	if _, p := e.create(t, map[string]string{"name": "dev", "onlyWhenUnlocked": "true"}); p == nil || !strings.Contains(p.Message, "nazar aws forget dev") {
		t.Fatalf("other access: %+v", p)
	}
	// --only-when-unlocked.
	o, p = e.create(t, map[string]string{"name": "prod", "onlyWhenUnlocked": "true"})
	if p != nil || o.CA == nil || o.CA.WhileLocked {
		t.Fatalf("prod: %+v %+v", o, p)
	}
	if ca, _ := e.d.awsCA.Get("prod"); ca.Access != platform.AccessWhenUnlocked {
		t.Fatal("prod signs only while unlocked")
	}
	// show and list.
	var ca control.AWSCA
	if err := e.call(t, control.CmdAWSCAShow, map[string]string{"name": "dev"}, control.KindAWSCA, &ca); err != nil || ca.CertPEM != string(crt) || ca.Kind != control.KindAWSCA {
		t.Fatalf("show: %v %+v", err, ca)
	}
	var l control.AWSEntryList
	if err := e.call(t, control.CmdAWSList, nil, control.KindAWSEntryList, &l); err != nil || len(l.Items) != 2 || l.Items[0].Name != "dev" ||
		l.Items[0].CA.CertPEM != "" || l.Items[0].Policy == nil || l.Items[0].Policy.FallbackSource != "entry-gate" {
		t.Fatalf("list: %v %+v", err, l)
	}
}

func TestAWSCACreateRefusals(t *testing.T) {
	e := startAWSAdmin(t)
	logins := e.logins()
	for name, tc := range map[string]struct {
		args map[string]string
		want string
	}{
		"bad name":   {map[string]string{"name": "a/b"}, "invalid aws entry name"},
		"bad access": {map[string]string{"name": "dev", "onlyWhenUnlocked": "on"}, "onlyWhenUnlocked"},
	} {
		if _, p := e.create(t, tc.args); p == nil || !strings.Contains(p.Message, tc.want) {
			t.Errorf("%s: %+v", name, p)
		}
	}
	if e.logins() != logins {
		t.Fatal("no prompt for a refused create")
	}
	if l, _ := e.d.awsCA.List(); len(l) != 0 {
		t.Fatal("nothing made")
	}
}

func TestAWSRulesAndForget(t *testing.T) {
	e := startAWSAdmin(t)
	if _, p := e.create(t, map[string]string{"name": "dev"}); p != nil {
		t.Fatal(p)
	}
	// A rule edit: an aws entry's, no to. Refused without the flag, as a
	// key's: nothing written.
	var r control.ConfigEdit
	err := e.call(t, control.CmdConfigEdit, map[string]string{"op": control.EditRuleAdd, "aws": "dev", "apps": `["signed:Q6L2SF6YDW:com.anthropic.claude-code"]`,
		"gate": "dialog", "scope": "session"}, control.KindConfigEdit, &r)
	if err == nil || !strings.Contains(err.Error(), control.LoosensRefusal) {
		t.Fatalf("rule add without the flag: %v", err)
	}
	if strings.Contains(e.readConfig(t), "com.anthropic.claude-code") {
		t.Fatal("a refused rule edit wrote config.yaml")
	}
	err = e.call(t, control.CmdConfigEdit, map[string]string{"op": control.EditRuleAdd, "aws": "dev", "apps": `["signed:Q6L2SF6YDW:com.anthropic.claude-code"]`,
		"gate": "dialog", "scope": "session", "allowLoosen": "true"}, control.KindConfigEdit, &r)
	if err != nil {
		t.Fatalf("rule add: %v", err)
	}
	if r.AWS != "dev" || r.Staged == nil { // a new rule loosens: staged
		t.Fatalf("rule add: %+v", r)
	}
	if !strings.Contains(e.readConfig(t), "com.anthropic.claude-code") {
		t.Fatal("the rule is in config.yaml")
	}
	if _, p := e.applyHash(t, r.Staged.Hash); p != nil {
		t.Fatal(p)
	}
	err = e.call(t, control.CmdConfigEdit, map[string]string{"op": control.EditRuleAdd, "aws": "dev", "apps": `["any"]`, "to": `["any"]`, "gate": "login"}, control.KindConfigEdit, &r)
	if p := control.AsProblem(err); p == nil || p.Code != control.CodeUsage || !strings.Contains(p.Message, "take no to") {
		t.Fatalf("to: %+v", p)
	}
	err = e.call(t, control.CmdConfigEdit, map[string]string{"op": control.EditRuleRemove, "aws": "nope", "index": "1"}, control.KindConfigEdit, &r)
	if p := control.AsProblem(err); p == nil || !strings.Contains(p.Message, "there is no aws entry nope") {
		t.Fatalf("unknown entry: %+v", p)
	}
	// Forget: one login, everything gone.
	e.f.Advance(2 * time.Minute)
	var o control.AWSEntry
	if err := e.call(t, control.CmdAWSForget, map[string]string{"name": "dev"}, control.KindAWSEntry, &o); err != nil {
		t.Fatal(err)
	}
	if o.State != control.AWSStateAbsent || strings.Contains(e.readConfig(t), "dev-nazar") {
		t.Fatalf("%+v\n%s", o, e.readConfig(t))
	}
	if _, err := os.Stat(filepath.Join(layout.KeysDir(e.home), "aws-ca-dev.crt")); !os.IsNotExist(err) {
		t.Fatal("the certificate file is gone")
	}
	if text := promptText(e.f.Shown()[len(e.f.Shown())-1].Prompt); !strings.Contains(text, `Forget AWS entry "dev"?`) || !strings.Contains(text, "trust anchor") {
		t.Fatalf("prompt:\n%s", text)
	}
	if err := e.call(t, control.CmdAWSForget, map[string]string{"name": "dev"}, control.KindAWSEntry, &o); control.AsProblem(err) == nil {
		t.Fatal("forget twice")
	}
}

// An entry with no CA is warned about in status and config check.
func TestAWSAdvice(t *testing.T) {
	e := startAWS(t)
	if err := e.d.awsCA.Delete("dev"); err != nil {
		t.Fatal(err)
	}
	var st control.Status
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range st.Problems {
		if p.Path == "aws.dev" && strings.Contains(p.Message, "has no CA") {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", st.Problems)
	}
}

func promptText(p platform.Prompt) string { return p.Title + "\n" + strings.Join(p.Lines, "\n") }
