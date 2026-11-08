package policy

import (
	"errors"
	"testing"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Secrets design 5.2: a late-env request is judged with apps: on
// the CLI's chain and to: on the synthetic receiver of the agent's
// resolution. The approval is remembered under that receiver's identity,
// which names every pinned byte and argument (D5).

const runSrc = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
  brave-mcp: {command: [npx, -y, "@brave/brave-search-mcp-server"]}
secrets:
  BRAVE_API_KEY:
    deliver: [late-env]
    rules:
      - apps: [claude]
        to: [brave-mcp]
        scope: session
        gate: dialog
`

const npxReal = "/Users/u/.local/share/mise/installs/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js"

func runEnv(t *testing.T) *env {
	en := newEnvSrc(t, runSrc)
	en.e = New(en.e.Config(), &match.Evaluator{Trust: en.st, Command: func(a0 string) (string, error) {
		if a0 == "npx" {
			return npxReal, nil
		}
		return "", errors.New("not found")
	}})
	return en
}

func recvFor(digest byte, argv ...string) *caller.Chain {
	return caller.Synthetic(platform.ProcessInfo{Path: npxReal, Args: argv, Cwd: "/", Code: platform.CodeIdentity{CDHash: []byte{digest}}})
}

func TestLateEnvRunIsJudgedOnTheSyntheticReceiver(t *testing.T) {
	en := runEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), cliProc("nazar", "run", "--secret", "BRAVE_API_KEY", "--", "npx", "-y", "@brave/brave-search-mcp-server"))
	ask := en.r.Resolve(tab.Peer())
	out := en.e.EvaluateSecret("BRAVE_API_KEY", config.DeliverLateEnv, ask, recvFor(1, "npx", "-y", "@brave/brave-search-mcp-server"))
	if out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog || out.OneShot || out.Receiver == "" {
		t.Fatalf("the brave run must get rule 1, remembered per receiver: %+v", out)
	}
	other := en.e.EvaluateSecret("BRAVE_API_KEY", config.DeliverLateEnv, ask, recvFor(2, "npx", "-y", "@brave/brave-search-mcp-server"))
	if other.RuleIndex != 1 || other.Receiver == out.Receiver {
		t.Fatalf("other pinned bytes are another receiver: %q vs %q", other.Receiver, out.Receiver)
	}
	// printenv, or another package, through the same claude: to: misses
	// and the fallback blocks, before any prompt.
	for _, recv := range []*caller.Chain{
		recvFor(1, "npx", "-y", "@evil/server"),
		caller.Synthetic(platform.ProcessInfo{Path: "/usr/bin/printenv", Args: []string{"printenv"}, Code: platform.CodeIdentity{CDHash: []byte{1}}}),
	} {
		if o := en.e.EvaluateSecret("BRAVE_API_KEY", config.DeliverLateEnv, ask, recv); o.Reason != "to: mismatch" || o.Policy.Gate != config.GateBlock {
			t.Fatalf("%v: must be a to: mismatch blocked by the fallback, got %+v", recv.Procs[0].Args, o)
		}
	}
	// A method the secret does not list is blocked before any rule.
	if o := en.e.EvaluateSecret("BRAVE_API_KEY", config.DeliverStdout, ask, recvFor(1, "npx", "-y", "@brave/brave-search-mcp-server")); o.Reason != ReasonDelivery {
		t.Fatalf("stdout is not in deliver: %+v", o)
	}
}
