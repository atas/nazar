package policy

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// aws design 6.1: a request for an entry's credential is decided by check 1
// (the CLI's parent, whatever program it is, is identified) and check 3
// (the first-match walk on whoever called that program), in that order;
// there is no check 2, and no client list: any program in a chain the rules
// allow receives it.

var awsCode = platform.CodeIdentity{Signed: true, TeamID: "94KV3E626L", SigningID: "aws", CDHash: []byte{0xa5}}

func awsProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/usr/local/aws-cli/aws", Args: append([]string{"aws"}, args...), Cwd: "/Users/u/projects/foo", Code: awsCode}
}

func awsCredProc(name string) fake.Proc { return cliProc("nazar", "aws", "credential", name) }

const (
	awsAnchor  = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/4579702c-9abb-47c2-88b2-c734e0b29539"
	awsProfile = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/6f4943fb-13d4-4242-89c4-be367595c380"
)

const awsSrc = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
aws:
  dev:
    identity: {user: you-nazar}
    trustAnchorArn: ` + awsAnchor + `
    profileArn: ` + awsProfile + `
    roleArn: arn:aws:iam::123456789012:role/dev
    duration: 30m
    gate: block
    rules:
      - apps: [claude]
        gate: dialog
      - apps: [iterm]
        scope: session
        gate: login
        expire: 8h
  later:
    identity: {user: you-nazar}
    rules:
      - apps: [iterm]
        gate: login
`

// newAWSEnv has no `nazar trust` of anything: no program is pinned for aws.
func newAWSEnv(t *testing.T) *env {
	t.Helper()
	return newEnvSrc(t, awsSrc)
}

func terraformProc() fake.Proc {
	return fake.Proc{Path: "/opt/homebrew/bin/terraform", Args: []string{"terraform", "plan"}, Code: platform.CodeIdentity{Signed: true, TeamID: "TFTEAM0001", SigningID: "terraform"}}
}

func TestEvaluateAWSAllowsThroughTheRules(t *testing.T) {
	en := newAWSEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, awsProc("s3", "ls"), awsCredProc("dev"))
	out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer()))
	if out.Target != "aws:dev" || out.Key != "dev" || out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin || out.Reason != "rule 2 matched" {
		t.Fatalf("iTerm2 → bash → aws → nazar must get the iterm rule: %+v", out)
	}
	if out.Receiver == "" || out.OneShot || !strings.HasPrefix(out.ScopeID, "session:") {
		t.Fatalf("the program that ran nazar receives, the approval is the tab's: %+v", out)
	}
	if !LiveRuleIDs(en.e.Config())["aws:dev|"+out.RuleID] {
		t.Fatal("the outcome's rule id must be live")
	}
	// Claude Code in the tab runs aws: Claude's rule.
	tab = en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), awsProc("s3", "rm"), awsCredProc("dev"))
	if out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer())); out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog {
		t.Fatalf("claude ▸ aws ▸ nazar: %+v", out)
	}
}

// The owner's decision (aws design 6.1, as k8s design 2.1 "no client
// list"): whatever program runs credential_process receives the credential
// when the chain above it passes the rules, with no list and no `nazar
// trust`. Approvals stay per program (the receiver).
func TestEvaluateAWSAnyProgramInAnAllowedChain(t *testing.T) {
	en := newAWSEnv(t)
	changed := awsProc()
	changed.Code = platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0xba, 0xd0}} // after an upgrade
	moved := awsProc()
	moved.Path = "/opt/homebrew/bin/aws"
	tool := fake.Proc{Path: "/Users/u/go/bin/mytool", Args: []string{"mytool"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x70, 0x01}}}
	// Homebrew's awscli and boto3 run as the Python interpreter.
	py := fake.Proc{Path: "/opt/homebrew/bin/python3.13", Args: []string{"python3.13", "/opt/homebrew/bin/aws", "s3", "ls"}, Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x9e}}}
	applePy := fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "deploy.py"}, Code: fake.AppleCode("com.apple.python3")}
	seen := map[string]string{}
	for name, p := range map[string]fake.Proc{
		"aws": awsProc("s3", "ls"), "aws after an upgrade": changed, "terraform": terraformProc(),
		"a binary of the user's": tool, "Homebrew's python": py, "Apple's python3": applePy,
	} {
		tab := en.f.ITermTab(platform.ProcessRef{}, p, awsCredProc("dev"))
		out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer()))
		if out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin || out.Receiver == "" {
			t.Errorf("%s in an iTerm2 tab must get the iterm rule: %+v", name, out)
			continue
		}
		if prev, dup := seen[out.Receiver]; dup {
			t.Errorf("%s and %s share the receiver %q: one's approval would cover the other", name, prev, out.Receiver)
		}
		seen[out.Receiver] = name
	}
	// The same signed aws at another path is the same program (identity by
	// signature): the same receiver, and the same rule.
	tab := en.f.ITermTab(platform.ProcessRef{}, moved, awsCredProc("dev"))
	if out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer())); out.RuleIndex != 2 || seen[out.Receiver] != "aws" {
		t.Errorf("aws elsewhere: %+v", out)
	}
	// The shell itself runs the CLI: it is the program that receives it,
	// judged on who ran the shell (iTerm2).
	tab = en.f.ITermTab(platform.ProcessRef{}, awsCredProc("dev"))
	if out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer())); out.RuleIndex != 2 || out.Receiver == "" {
		t.Errorf("bash as the parent: %+v", out)
	}
	// A parent whose code signature does not verify has no identity to
	// remember an approval under.
	unsigned := terraformProc()
	unsigned.Code = platform.CodeIdentity{CDHash: []byte{0x01}}
	tab = en.f.ITermTab(platform.ProcessRef{}, unsigned, awsCredProc("dev"))
	if out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer())); out.Reason != ReasonAWSCaller || out.Policy.Gate != config.GateBlock || out.Receiver != "" {
		t.Errorf("unverified parent: %+v", out)
	}
	// Ad hoc with no cdhash: no identity either.
	spoofed := awsProc()
	spoofed.Code = platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "aws"}
	tab = en.f.ITermTab(platform.ProcessRef{}, spoofed, awsCredProc("dev"))
	if out := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer())); out.Reason != ReasonAWSCaller || out.Receiver != "" {
		t.Errorf("no cdhash, no team: %+v", out)
	}
}

func TestEvaluateAWSChecks(t *testing.T) {
	en := newAWSEnv(t)
	block := func(what string, out Outcome, reason string) {
		t.Helper()
		if out.Policy.Gate != config.GateBlock || out.Reason != reason || out.RuleIndex != 0 || !out.OneShot || out.ScopeID != "" {
			t.Errorf("%s: %+v", what, out)
		}
	}
	// The parent exited, nil and a short chain: check 1 (no "unknown" path
	// for the program that receives the credential).
	tab := en.f.ITermTab(platform.ProcessRef{}, awsProc(), awsCredProc("dev"))
	c := en.r.Resolve(tab.Peer())
	alone := *c
	alone.Procs = c.Procs[:1]
	block("no parent", en.e.EvaluateAWS("dev", &alone), ReasonAWSCaller)
	block("nil chain", en.e.EvaluateAWS("dev", nil), ReasonAWSCaller)
	pidOnly := *c
	pidOnly.Procs = append(pidOnly.Procs[:0:0], c.Procs...)
	pidOnly.Procs[1].Ref.Generation = 0
	block("PID-only parent", en.e.EvaluateAWS("dev", &pidOnly), ReasonAWSCaller)
	exited := en.f.ITermTab(platform.ProcessRef{}, awsProc(), awsCredProc("dev"))
	en.f.Exit(exited.Procs[0])
	block("parent exited", en.e.EvaluateAWS("dev", en.r.Resolve(exited.Peer())), ReasonAWSCaller)
	// An unknown entry, and one not connected yet, whatever else.
	block("unknown entry", en.e.EvaluateAWS("nope", c), ReasonAWSEntry)
	tab = en.f.ITermTab(platform.ProcessRef{}, awsProc(), awsCredProc("later"))
	block("not connected", en.e.EvaluateAWS("later", en.r.Resolve(tab.Peer())), ReasonAWSNotConnected)
	// Rules are judged on chain[2:], never on the CLI or the program that
	// runs it: without a client list this is what keeps a program outside
	// every allowed chain out, whatever it runs. Malware outside any app
	// runs aws, terraform or the CLI itself: no rule, the entry's block.
	mal := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/mal", Code: platform.CodeIdentity{Signed: true, AdHoc: true, CDHash: []byte{0x66}}})
	for name, p := range map[string]fake.Proc{"aws": awsProc("sts", "get-caller-identity"), "terraform": terraformProc()} {
		cli := en.f.Launch(en.f.Launch(mal, p), awsCredProc("dev"))
		if out := en.e.EvaluateAWS("dev", en.r.Resolve(cli)); out.Policy.Gate != config.GateBlock || !out.KeyGate || out.Receiver == "" {
			t.Fatalf("malware ▸ %s ▸ nazar must get the entry's block: %+v", name, out)
		}
	}
	if out := en.e.EvaluateAWS("dev", en.r.Resolve(en.f.Launch(mal, awsCredProc("dev")))); out.Policy.Gate != config.GateBlock || !out.KeyGate {
		t.Fatalf("malware ▸ nazar must get the entry's block: %+v", out)
	}
}

// An approval is for what the entry was when it was given: a change to an
// ARN, the identity or the duration gives every rule and the fallback a new
// id. (The receiver, the program that ran nazar, is a separate part of the
// approval key.)
func TestAWSRuleIDsTrackTheEntry(t *testing.T) {
	en := newAWSEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, awsProc(), awsCredProc("dev"))
	before := en.e.EvaluateAWS("dev", en.r.Resolve(tab.Peer()))
	fallback := "aws:dev|" + awsRuleID(FallbackRuleID("aws:dev", en.e.Config().AWSFallback("dev")), en.e.Config().AWS["dev"])
	if !LiveRuleIDs(en.e.Config())[fallback] {
		t.Fatal("the fallback's id must be live")
	}
	for name, edited := range map[string]string{
		"trust anchor": strings.Replace(awsSrc, "trust-anchor/4579702c", "trust-anchor/0579702c", 1),
		"profile":      strings.Replace(awsSrc, "profile/6f4943fb", "profile/0f4943fb", 1),
		"role":         strings.Replace(awsSrc, "role/dev", "role/admin", 1),
		"identity":     strings.Replace(awsSrc, "    identity: {user: you-nazar}\n    trustAnchorArn", "    identity: {user: me-nazar}\n    trustAnchorArn", 1),
		"duration":     strings.Replace(awsSrc, "duration: 30m", "duration: 1h", 1),
	} {
		live := LiveRuleIDs(parse(t, edited))
		if live["aws:dev|"+before.RuleID] || live[fallback] {
			t.Errorf("%s changed: the old approvals must not stay live", name)
		}
	}
	other := strings.Replace(awsSrc, "  later:\n    identity: {user: you-nazar}\n", "  later:\n    identity: {user: other-nazar}\n", 1)
	if !LiveRuleIDs(parse(t, other))["aws:dev|"+before.RuleID] {
		t.Fatal("another entry's change must not drop dev's approvals")
	}
}
