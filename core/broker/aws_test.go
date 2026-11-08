package broker

import (
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/policy"
)

// aws design 6.1: a request for an entry's credential runs the shared
// pipeline. The approval key is (aws:<name>, rule, scope, the identity of
// the program that ran nazar, op aws:<name>); check 1, an unknown entry and
// one not connected block without a prompt, audited, with the block warning
// and no drafted rule.

var awsCLICode = platform.CodeIdentity{Signed: true, TeamID: "94KV3E626L", SigningID: "aws", CDHash: []byte{0xa5}}

func awsCLI(args ...string) fake.Proc {
	return fake.Proc{Path: "/usr/local/aws-cli/aws", Args: append([]string{"aws"}, args...), Cwd: "/Users/u/projects/foo", Code: awsCLICode}
}

const awsEntries = `aws:
  dev:
    identity: {user: you-nazar}
    trustAnchorArn: arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539
    profileArn: arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380
    roleArn: arn:aws:iam::123456789012:role/dev
    rules:
      - apps: [iterm]
        scope: session
        gate: dialog
  prod:
    identity: {user: you-nazar}
    trustAnchorArn: arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539
    profileArn: arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380
    roleArn: arn:aws:iam::123456789012:role/prod
    rules:
      - apps: [iterm]
        scope: session
        gate: dialog
  later:
    identity: {user: you-nazar}
    rules:
      - apps: [iterm]
        gate: dialog
`

func newAWSBroker(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, cfgSrc+awsEntries, 200*time.Millisecond)
}

func (e *env) awsReq(name string, peer platform.ProcessRef) Request {
	return Request{
		AWS: name, Chain: e.r.Resolve(peer),
		Summary: "the AWS credential for arn:aws:iam::123456789012:role/" + name + ", 1h", Operation: "aws credential session 0123",
		Destination: "arn:aws:iam::123456789012:role/" + name,
		Do:          func(platform.ApprovalRef) error { e.calls.Add(1); return nil },
	}
}

func TestAWSApprovalCoversOneEntryAndOneClient(t *testing.T) {
	e := newAWSBroker(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, awsCLI("s3", "ls"), cliProc())
	first := e.awsReq("dev", tab.Peer())
	first.Op = approval.Op{ID: "login:SHA256:gh", Text: "github.com"} // a module can't choose what it covers
	if r := e.b.Handle(first); r.Decision != audit.Approved || r.Outcome.Target != "aws:dev" {
		t.Fatalf("first: %+v", r)
	}
	again := e.f.Launch(tab.Shell, awsCLI("sts", "get-caller-identity"))
	if r := e.b.Handle(e.awsReq("dev", e.f.Launch(again, cliProc()))); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("another aws in the same tab, same entry: %+v", r)
	}
	if r := e.b.Handle(e.awsReq("prod", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("prod: %+v", r)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("one approval per entry: %d dialogs, want 2", n)
	}
	for _, en := range e.cache.List() {
		name := strings.TrimPrefix(en.Key.Target, "aws:")
		if en.Key.Op != "aws:"+name || en.Covers != "the AWS credential for "+name || en.Key.Receiver == "" {
			t.Fatalf("approval %+v", en)
		}
	}
}

func TestAWSPromptNamesTheClientCommand(t *testing.T) {
	e := newAWSBroker(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, awsCLI("s3", "ls", "s3://bucket"), cliProc())
	if r := e.b.Handle(e.awsReq("dev", tab.Peer())); r.Decision != audit.Approved {
		t.Fatal(r)
	}
	p := e.f.Shown()[0].Prompt
	text := promptText(p)
	if p.Title != `iTerm2 wants to use AWS credential "dev"` || !strings.Contains(text, "aws s3 ls") ||
		!strings.Contains(text, "arn:aws:iam::123456789012:role/dev, 1h") {
		t.Fatalf("prompt %q:\n%s", p.Title, text)
	}
	f := e.lastLine(t)
	if f["target"] != "aws:dev" || f["operation"] != "aws credential session 0123" || f["destination"] != "arn:aws:iam::123456789012:role/dev" ||
		!strings.HasPrefix(f["receiver"], "aws s3 ls") {
		t.Fatalf("audit %v", f)
	}
}

func TestAWSBlocksWarnAndAudit(t *testing.T) {
	e := newAWSBroker(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	// Check 1: the program that ran nazar exited, so it can't be told.
	tab := e.f.ITermTab(platform.ProcessRef{}, awsCLI("s3", "ls"), cliProc())
	e.f.Exit(tab.Procs[0])
	r := e.b.Handle(e.awsReq("dev", tab.Peer()))
	if r.Decision != audit.Blocked || r.Reason != policy.ReasonAWSCaller || e.calls.Load() != 0 || len(e.f.Shown()) != 0 {
		t.Fatalf("check 1: %+v", r)
	}
	if f := e.lastLine(t); f["decision"] != "blocked" || f["target"] != "aws:dev" || f["reason"] != policy.ReasonAWSCaller {
		t.Fatalf("audit %v", f)
	}
	w := e.f.Warnings()
	if text := strings.Join(w[0].Lines, "\n"); len(w) != 1 || w[0].SuggestedRule != "" || !strings.Contains(text, "can't be identified") ||
		strings.Contains(text, "nazar trust") || strings.Contains(text, "clients") {
		t.Fatalf("warning %+v", w)
	}
	tab = e.f.ITermTab(platform.ProcessRef{}, awsCLI(), cliProc())
	if r := e.b.Handle(e.awsReq("later", tab.Peer())); r.Decision != audit.Blocked || r.Reason != policy.ReasonAWSNotConnected || e.calls.Load() != 0 {
		t.Fatalf("not connected: %+v", r)
	}
	if w := e.f.Warnings(); w[len(w)-1].SuggestedRule != "" || !strings.Contains(strings.Join(w[len(w)-1].Lines, "\n"), "no trustAnchorArn") {
		t.Fatalf("warning %+v", w[len(w)-1])
	}
	// No rule: the draft names the caller of the program that ran nazar,
	// never aws or the CLI.
	cursor := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Cursor.app/Contents/MacOS/Cursor",
		Code: platform.CodeIdentity{Signed: true, TeamID: "VDXQ22DGB9", SigningID: "com.todesktop.230313mzl4w4u92", CDHash: []byte{0xcc}},
		App:  &fake.App{BundleID: "com.todesktop.230313mzl4w4u92", Name: "Cursor"}})
	sh := e.f.Launch(cursor, fake.Proc{Path: "/bin/zsh", Args: []string{"-zsh"}, Code: fake.AppleCode("com.apple.zsh")})
	cl := e.f.Launch(sh, fake.ClaudeProc())
	a := e.f.Launch(cl, awsCLI("s3", "rm", "--recursive", "s3://bucket"))
	r = e.b.Handle(e.awsReq("dev", e.f.Launch(a, cliProc())))
	if r.Decision != audit.Blocked || r.Reason != "no rule matched" {
		t.Fatalf("no rule: %+v", r)
	}
	w = e.f.Warnings()
	last := w[len(w)-1]
	if !strings.Contains(last.SuggestedRule, "Q6L2SF6YDW") || strings.Contains(last.SuggestedRule, "94KV3E626L") || strings.Contains(last.SuggestedRule, "dev.nazar.cli") {
		t.Fatalf("the drafted rule must name the caller of aws (Claude Code): %q", last.SuggestedRule)
	}
	// Refuse (check 0, the stdout check) logs the aws target.
	if r := e.b.Refuse(Request{AWS: "dev", Chain: e.r.Resolve(tab.Peer()), Operation: "aws credential"}, "not the nazar CLI"); r.Outcome.Target != "aws:dev" || r.Outcome.Key != "dev" {
		t.Fatalf("refuse: %+v", r)
	}
	if f := e.lastLine(t); f["target"] != "aws:dev" || f["decision"] != "blocked" {
		t.Fatalf("audit %v", f)
	}
}

// No client list (aws design 6.1): python3 or terraform running
// credential_process in an iTerm2 tab is judged as iTerm2, and asks like
// aws does.
func TestAWSAnyProgramInTheTabAsks(t *testing.T) {
	e := newAWSBroker(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	py := scriptProc("/usr/bin/python3", "com.apple.python3", "python3", "deploy.py")
	tf := fake.Proc{Path: "/opt/homebrew/bin/terraform", Args: []string{"terraform", "plan"}, Code: platform.CodeIdentity{Signed: true, TeamID: "TFTEAM0001", SigningID: "terraform"}}
	for _, p := range []fake.Proc{py, tf} {
		tab := e.f.ITermTab(platform.ProcessRef{}, p, cliProc())
		if r := e.b.Handle(e.awsReq("dev", tab.Peer())); r.Decision != audit.Approved || r.Outcome.Receiver == "" {
			t.Fatalf("%s: %+v", p.Path, r)
		}
	}
}
