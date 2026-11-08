package policy

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Secrets design 5, 5.2: a request for a secret is decided by the
// first-match walk of ssh keys, with apps: judged on the chain that asked
// (the nazar CLI's) and to: on the chain that receives the value (for
// helper and stdout, the CLI's parent).

const secretSrc = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
  git-https: {signed: {team: apple, id: com.apple.git-remote-http}}
ssh_agent:
  keys:
    GH_TOKEN:
      rules:
        - apps: [iterm]
          gate: none
secrets:
  GH_TOKEN:
    deliver: [helper]
    rules:
      - apps: [claude]
        to: [git-https]
        gate: block
      - apps: [iterm]
        to: [git-https]
        scope: session
        gate: login
  NOTES:
    rules:
      - apps: [iterm]
        scope: session
        gate: dialog
  OWN:
    scope: session
    gate: login
`

var nazarCLI = platform.CodeIdentity{Signed: true, TeamID: "NAZARTEAM0", SigningID: "dev.nazar.cli", CDHash: []byte{0x9a}}

func fetchProc() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/bin/git", Args: []string{"git", "fetch", "origin"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git")}
}

func transportProc() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http", Args: []string{"git-remote-https", "origin", "https://github.com/atas/nazar.git"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git-remote-http")}
}

func scriptProc(path, id string, args ...string) fake.Proc {
	return fake.Proc{Path: path, Args: args, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode(id)}
}

func cliProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Args: args, Code: nazarCLI}
}

// secret resolves the CLI at peer and evaluates name for d, with the CLI's
// parent as the receiver (helper and stdout, secrets design 5.2).
func (en *env) secret(name string, d config.Delivery, peer platform.ProcessRef) Outcome {
	c := en.r.Resolve(peer)
	return en.e.EvaluateSecret(name, d, c, c.Parent())
}

func TestSecretRulesJudgeAppsOnTheAskerAndToOnTheReceiver(t *testing.T) {
	en := newEnvSrc(t, secretSrc)
	tab := en.f.ITermTab(platform.ProcessRef{}, fetchProc(), transportProc(), cliProc("git-credential-nazar", "get"))
	out := en.secret("GH_TOKEN", config.DeliverHelper, tab.Peer())
	if out.Target != "secret:GH_TOKEN" || out.Key != "GH_TOKEN" || out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin || out.Reason != "rule 2 matched" {
		t.Fatalf("iTerm2 → git → git-remote-https → nazar must get rule 2, got %+v", out)
	}
	if out.Receiver != "apple:com.apple.git-remote-http" {
		t.Fatalf("the receiver is the CLI's parent, got %q", out.Receiver)
	}
	if out.OneShot || !strings.HasPrefix(out.ScopeID, "session:") {
		t.Fatalf("scope %+v", out)
	}
	// git credential fill typed in a shell: the CLI's parent is git, not
	// the HTTPS transport, so to: misses (secrets design 6.1).
	fill := en.f.ITermTab(tab.App, scriptProc("/Library/Developer/CommandLineTools/usr/bin/git", "com.apple.git", "git", "credential", "fill"), cliProc("git-credential-nazar", "get"))
	if out := en.secret("GH_TOKEN", config.DeliverHelper, fill.Peer()); out.RuleIndex != 0 || out.Reason != "to: mismatch" || out.Policy.Gate != config.GateBlock {
		t.Fatalf("a receiver outside to: must fall through to the fallback, got %+v", out)
	}
	// to: is never judged on the asker's own peer: the nazar CLI is not
	// git's transport.
	c := en.r.Resolve(tab.Peer())
	if out := en.e.EvaluateSecret("GH_TOKEN", config.DeliverHelper, c, c); out.Reason != "to: mismatch" {
		t.Fatalf("the CLI as receiver must miss to:, got %+v", out)
	}
	// Claude Code in the tab hits rule 1 (block) first.
	cl := en.f.ITermTab(tab.App, fake.ClaudeProc(), fetchProc(), transportProc(), cliProc("git-credential-nazar", "get"))
	if out := en.secret("GH_TOKEN", config.DeliverHelper, cl.Peer()); out.RuleIndex != 1 || out.Policy.Gate != config.GateBlock {
		t.Fatalf("claude must get rule 1 (block), got %+v", out)
	}
}

func TestSecretDeliveryNotAllowedIsBlockedBeforeAnyRule(t *testing.T) {
	en := newEnvSrc(t, secretSrc)
	tab := en.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "deploy.sh"), cliProc("nazar", "get", "X"))
	for _, tc := range []struct {
		name string
		d    config.Delivery
	}{
		{"GH_TOKEN", config.DeliverStdout}, // deliver: [helper]
		{"NOTES", config.DeliverLateEnv},   // not in NOTES's deliver (the default: helper, stdout)
		{"NOTES", config.DeliverEnv},
		{"NOTES", config.DeliverFile},
		{"NOTES", ""},
		{"NOT_CONFIGURED", config.DeliverLateEnv},
	} {
		out := en.secret(tc.name, tc.d, tab.Peer())
		if out.Policy.Gate != config.GateBlock || out.Reason != ReasonDelivery || out.RuleIndex != 0 || !out.OneShot {
			t.Errorf("%s via %q: must be blocked as %q, got %+v", tc.name, tc.d, ReasonDelivery, out)
		}
	}
	// stdout is in NOTES's default deliver: its rule decides.
	if out := en.secret("NOTES", config.DeliverStdout, tab.Peer()); out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog {
		t.Fatalf("NOTES via stdout: %+v", out)
	}
}

func TestSecretFallbackIsOwnPolicyThenDefaults(t *testing.T) {
	en := newEnvSrc(t, secretSrc)
	tab := en.f.ITermTab(platform.ProcessRef{}, cliProc("nazar", "get", "X"))
	own := en.secret("OWN", config.DeliverStdout, tab.Peer())
	if own.RuleIndex != 0 || !own.KeyGate || own.Policy.Gate != config.GateLogin || own.Reason != "no rule matched" || !strings.HasPrefix(own.RuleID, "fallback:") {
		t.Fatalf("OWN: its own policy, got %+v", own)
	}
	none := en.secret("NOT_CONFIGURED", config.DeliverStdout, tab.Peer())
	mustBeBlockedFallback(t, "a secret without an entry", none)
	if none.KeyGate || none.Target != "secret:NOT_CONFIGURED" {
		t.Fatalf("defaults.fallback, not an own policy: %+v", none)
	}
}

// Every remembered secret approval names its receiver, with or without
// to:, and a receiver nazar cannot identify is never remembered.
func TestSecretReceiverIsAlwaysPartOfTheApproval(t *testing.T) {
	en := newEnvSrc(t, secretSrc)
	a := en.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc("nazar", "get", "NOTES"))
	py := en.f.Launch(a.Shell, scriptProc("/usr/bin/python3", "com.apple.python3", "python3", "b.py"))
	b := en.f.Launch(py, cliProc("nazar", "get", "NOTES"))
	oa, ob := en.secret("NOTES", config.DeliverStdout, a.Peer()), en.secret("NOTES", config.DeliverStdout, b)
	if oa.RuleIndex != 1 || ob.RuleIndex != 1 || oa.Receiver == "" || ob.Receiver == "" || oa.Receiver == ob.Receiver || oa.ScopeID != ob.ScopeID {
		t.Fatalf("one tab, two receivers, two approvals: %+v / %+v", oa, ob)
	}
	c := en.r.Resolve(a.Peer())
	out := en.e.EvaluateSecret("NOTES", config.DeliverStdout, c, nil)
	if out.RuleIndex != 1 || out.Receiver != "" {
		t.Fatalf("NOTES has no to:, so rule 1 applies to an unknown receiver: %+v", out)
	}
	mustBeOneShot(t, "unknown receiver", out)
	if out := en.e.EvaluateSecret("NOTES", config.DeliverStdout, nil, nil); !out.Unknown || out.RuleIndex != 0 || out.Policy.Gate != config.GateBlock {
		t.Fatalf("no asker is an unknown chain: %+v", out)
	}
}

func TestLiveRuleIDsCoverSecrets(t *testing.T) {
	cfg := parse(t, secretSrc)
	live := LiveRuleIDs(cfg)
	for _, r := range cfg.Secrets["GH_TOKEN"].Rules {
		if !live["secret:GH_TOKEN|"+r.ID()] {
			t.Errorf("rule %d of GH_TOKEN is not live", r.Index)
		}
	}
	for _, n := range []string{"GH_TOKEN", "NOTES", "OWN"} {
		target := "secret:" + n
		if !live[target+"|"+FallbackRuleID(target, cfg.SecretFallback(n))] {
			t.Errorf("the fallback of %s is not live", n)
		}
	}
	if !live["ssh:GH_TOKEN|"+cfg.SSHAgent.Keys["GH_TOKEN"].Rules[0].ID()] {
		t.Error("the ssh key of the same name is its own target")
	}
	if live["secret:NOT_CONFIGURED|"+FallbackRuleID("secret:NOT_CONFIGURED", cfg.Defaults.Fallback)] {
		t.Error("a secret without an entry has no live ids")
	}
	// An edited rule is a new id, so its old approvals are dropped.
	edited := parse(t, strings.Replace(secretSrc, "        scope: session\n        gate: login\n", "        scope: session\n        gate: dialog\n", 1))
	if LiveRuleIDs(edited)["secret:GH_TOKEN|"+cfg.Secrets["GH_TOKEN"].Rules[1].ID()] {
		t.Error("an edited secret rule must not stay live")
	}
}

// Security review: the asker of every secret request is the nazar
// CLI, so apps: is judged on the chain above it. A rule naming the CLI's
// own identity would otherwise match every program, in effect apps: any.
func TestSecretAppsNeverMatchTheCLIItself(t *testing.T) {
	src := strings.Replace(secretSrc, "  OWN:\n", `  CLIRULE:
    deliver: [helper]
    rules:
      - apps: [{signed: {team: NAZARTEAM0, id: dev.nazar.cli}}]
        gate: none
  OWN:
`, 1)
	en := newEnvSrc(t, src)
	tab := en.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc("nazar", "get", "X"))
	if out := en.secret("CLIRULE", config.DeliverHelper, tab.Peer()); out.RuleIndex != 0 || out.Policy.Gate != config.GateBlock {
		t.Fatalf("a rule naming the nazar CLI must match nothing: %+v", out)
	}
	// apps: iterm still matches: the app is above the CLI.
	if out := en.secret("NOTES", config.DeliverStdout, tab.Peer()); out.RuleIndex != 1 {
		t.Fatalf("NOTES rule 1 must still match: %+v", out)
	}
}

// A name that is not a valid secret name, or that matches an entry only
// ignoring letter case, never escapes the entry: blocked before any rule.
func TestSecretNameMustMatchItsEntryExactly(t *testing.T) {
	src := strings.Replace(secretSrc, "kind: Config\n", "kind: Config\ndefaults:\n  fallback: {scope: session, gate: dialog}\n", 1)
	en := newEnvSrc(t, src)
	tab := en.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc("nazar", "get", "X"))
	for _, n := range []string{"gh_token", "Gh_Token", "notes", "", "a b", "../x"} {
		out := en.secret(n, config.DeliverHelper, tab.Peer())
		if out.Policy.Gate != config.GateBlock || out.Reason != ReasonName || !out.OneShot {
			t.Errorf("%q: must be blocked as %q, got %+v", n, ReasonName, out)
		}
	}
	// A valid name with no entry at all gets defaults.fallback.
	if out := en.secret("OTHER", config.DeliverHelper, tab.Peer()); out.Policy.Gate != config.GateDialog {
		t.Fatalf("OTHER: %+v", out)
	}
}

// A receiver that is the asker itself tells approvals apart by nothing, so
// such a request is one-shot.
func TestReceiverThatIsTheAskerIsOneShot(t *testing.T) {
	en := newEnvSrc(t, secretSrc)
	tab := en.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc("nazar", "get", "NOTES"))
	c := en.r.Resolve(tab.Peer())
	out := en.e.EvaluateSecret("NOTES", config.DeliverStdout, c, c)
	if out.RuleIndex != 1 || out.Receiver != "" {
		t.Fatalf("%+v", out)
	}
	mustBeOneShot(t, "receiver is the asker", out)
}
