package match

import (
	"errors"
	"testing"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// Secrets design 5.2, 6.3.3 (6.3 D4): the receiver of a nazar
// run is a synthetic chain built from the agent's own resolution. Only a
// command: matcher (or to: any) matches it: the matcher's argv[0] resolves,
// through the same resolver, to the receiver's realpath, and its tail
// equals the command line byte for byte. argv[0] as typed never matters.

const npxCLI = "/Users/u/.local/share/mise/installs/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js"

func runRecv(path string, argv ...string) *caller.Chain {
	return caller.Synthetic(platform.ProcessInfo{Path: path, Args: argv, Cwd: "/", Code: platform.CodeIdentity{CDHash: []byte{1, 2, 3}}})
}

func resolveTo(m map[string]string) func(string) (string, error) {
	return func(a0 string) (string, error) {
		if p, ok := m[a0]; ok {
			return p, nil
		}
		return "", errors.New("not found")
	}
}

func TestCommandMatchesTheRunReceiver(t *testing.T) {
	en := newEnv(t)
	en.e.Command = resolveTo(map[string]string{"npx": npxCLI, "/Users/u/.local/bin/npx": npxCLI, "node": "/usr/local/bin/node"})
	brave := config.Matcher{Kind: config.MatchCommand, Command: []string{"npx", "-y", "@brave/brave-search-mcp-server"}}
	for _, tc := range []struct {
		name string
		recv *caller.Chain
		want bool
	}{
		{"same", runRecv(npxCLI, "npx", "-y", "@brave/brave-search-mcp-server"), true},
		{"typed by another path, same realpath", runRecv(npxCLI, "/Users/u/.local/bin/npx", "-y", "@brave/brave-search-mcp-server"), true},
		{"argv[0] is never compared", runRecv(npxCLI, "anything", "-y", "@brave/brave-search-mcp-server"), true},
		{"another package", runRecv(npxCLI, "npx", "-y", "@brave/brave-search-mcp-server-evil"), false},
		{"an extra argument", runRecv(npxCLI, "npx", "-y", "@brave/brave-search-mcp-server", "--x"), false},
		{"a missing argument", runRecv(npxCLI, "npx", "@brave/brave-search-mcp-server"), false},
		{"another file named npx", runRecv("/tmp/x/npx", "npx", "-y", "@brave/brave-search-mcp-server"), false},
		{"node is not npx", runRecv("/usr/local/bin/node", "npx", "-y", "@brave/brave-search-mcp-server"), false},
	} {
		if got := en.e.Receiver([]config.Matcher{brave}, tc.recv); got != tc.want {
			t.Errorf("%s: Receiver = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A matcher whose argv[0] does not resolve matches nothing.
	ghost := config.Matcher{Kind: config.MatchCommand, Command: []string{"ghost", "-y", "@brave/brave-search-mcp-server"}}
	if en.e.Receiver([]config.Matcher{ghost}, runRecv(npxCLI, "npx", "-y", "@brave/brave-search-mcp-server")) {
		t.Fatal("an unresolvable matcher must not match")
	}
	// No resolver, no match: fail closed.
	en.e.Command = nil
	if en.e.Receiver([]config.Matcher{brave}, runRecv(npxCLI, "npx", "-y", "@brave/brave-search-mcp-server")) {
		t.Fatal("without a resolver a command: matcher matches nothing")
	}
	if !en.e.Receiver([]config.Matcher{anyM}, runRecv(npxCLI, "npx")) {
		t.Fatal("to: any matches a run receiver")
	}
}

// signed:, path: and app: describe live processes; a run receiver is never
// one of them, whatever its record says (D4).
func TestOnlyCommandMatchersMatchARunReceiver(t *testing.T) {
	en := newEnv(t)
	node := "/opt/homebrew/bin/node"
	recv := caller.Synthetic(platform.ProcessInfo{Path: node, Args: []string{"node", "/s.js"}, Code: platform.CodeIdentity{Signed: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code", CDHash: []byte{1, 2, 3}}})
	for _, m := range []config.Matcher{{Kind: config.MatchPath, Path: node}, claudeM, itermM, unknown} {
		if en.e.Receiver([]config.Matcher{m}, recv) {
			t.Errorf("%s matched a run receiver", m.Canonical())
		}
	}
	// And a command: matcher never matches a live process (helper, stdout).
	en.e.Command = resolveTo(map[string]string{"node": node})
	live := &caller.Chain{Procs: []platform.ProcessInfo{{Path: node, Args: []string{"node", "/s.js"}}}}
	if en.e.Receiver([]config.Matcher{{Kind: config.MatchCommand, Command: []string{"node", "/s.js"}}}, live) {
		t.Fatal("a command: matcher must not match a live process")
	}
}

// Review: a synthetic chain keeps only what the agent computed; a
// record that claims a signature loses it, and apps: never matches one.
func TestSyntheticKeepsOnlyTheResolution(t *testing.T) {
	en := newEnv(t)
	c := caller.Synthetic(platform.ProcessInfo{Ref: platform.ProcessRef{PID: 9, Generation: 9}, Path: "/x", Args: []string{"/x"}, Cwd: "/",
		Code: platform.CodeIdentity{Signed: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code", CDHash: []byte{7}}})
	p, _ := c.Peer()
	if !p.Ref.IsZero() || p.Code.Signed || p.Code.TeamID != "" || p.Code.SigningID != "" || len(p.Code.CDHash) != 1 {
		t.Fatalf("record %+v", p)
	}
	if en.e.Apps([]config.Matcher{claudeM}, c) || en.e.Apps([]config.Matcher{anyM}, c) {
		t.Fatal("apps: is never judged on a run receiver")
	}
}
