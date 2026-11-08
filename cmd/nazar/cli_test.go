package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/atas/nazar/core/control"
)

// commandPaths returns every command of the tree below the root, hidden
// ones too, as argument lists.
func commandPaths(t *testing.T, h *harness) [][]string {
	t.Helper()
	var paths [][]string
	var visit func(c *cobra.Command, path []string)
	visit = func(c *cobra.Command, path []string) {
		if len(path) > 0 {
			paths = append(paths, path)
		}
		for _, s := range c.Commands() {
			visit(s, append(slices.Clone(path), s.Name()))
		}
	}
	visit(h.a.commands(false), nil)
	return paths
}

func lookup(t *testing.T, h *harness, path []string) *cobra.Command {
	t.Helper()
	root := h.a.commands(false)
	c, rest := find(root, path)
	if len(rest) != 0 {
		t.Fatalf("no command %q", path)
	}
	return c
}

// Explicitly asked-for help is on stdout with exit 0, at every level, in
// every spelling, and nothing is sent to nazar-agent.
func TestHelpAtEveryLevel(t *testing.T) {
	h := newHarness(t)
	h.serve(t, contractReply)
	for _, path := range commandPaths(t, h) {
		c := lookup(t, h, path)
		if passthrough(c) {
			continue // TestPassthroughNeverShowsHelp
		}
		forms := [][]string{append(slices.Clone(path), "--help"), append(slices.Clone(path), "-h"), append([]string{"help"}, path...),
			append([]string{"--json"}, append(slices.Clone(path), "-h")...), append([]string{"--help"}, path...)}
		for _, args := range forms {
			if code := h.run(args...); code != 0 || h.errb.Len() != 0 {
				t.Errorf("%q: exit %d, stderr %q", args, code, h.errb)
				continue
			}
			out := h.out.String()
			if !strings.Contains(out, "Usage:\n  nazar "+strings.Join(path, " ")) || !strings.Contains(out, c.Short) && !strings.Contains(out, c.Long) {
				t.Errorf("%q: not the help of %q:\n%s", args, path, out)
			}
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("help sent %+v", r)
	}
}

// The root's help is the usage text, as it always was.
func TestRootHelpIsTheUsageText(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {"--json", "help"}, {"help", "nonsense"}} {
		if code := h.run(args...); code != 0 || h.out.String() != usage || h.errb.Len() != 0 {
			t.Errorf("%q: exit %d stdout %q stderr %q", args, code, h.out, h.errb)
		}
	}
	for _, want := range []string{"completion bash|zsh|fish", "help [<command>]", "Exit codes:"} {
		if !strings.Contains(usage, want) {
			t.Errorf("usage lacks %q", want)
		}
	}
}

// A group's help lists its subcommands with their one-line descriptions;
// a command's shows its usage, flags (with their values) and examples.
func TestHelpContents(t *testing.T) {
	h := newHarness(t)
	h.run("ssh-key", "--help")
	out := h.out.String()
	for _, sub := range []string{"create", "list", "pubkey", "delete", "rules", "rule", "set"} {
		c := lookup(t, h, []string{"ssh-key", sub})
		if !strings.Contains(out, "\n  "+sub+" ") || !strings.Contains(out, c.Short) {
			t.Errorf("ssh-key --help lacks %s (%s):\n%s", sub, c.Short, out)
		}
	}
	h.run("ssh-key", "rule", "add", "-h")
	out = h.out.String()
	for _, want := range []string{"Usage:\n  nazar ssh-key rule add <key> --apps M[,M]", "Examples:\n  nazar ssh-key rule add github",
		"--apps M[,M]", "--gate G", "login", "dialog", "none", "block", "--scope S", "use", "session", "--expire D", "--at N", "--if-hash H",
		"--allow-loosen-access", "Global Flags:", "--json", "-y, --yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("ssh-key rule add -h lacks %q:\n%s", want, out)
		}
	}
	// Flags a command refuses with a reason are not offered.
	h.run("k8s", "rule", "add", "--help")
	if out := h.out.String(); strings.Contains(out, "\n      --to ") || strings.Contains(out, "--no-to") || strings.Contains(out, "--no-expire") {
		t.Errorf("k8s rule add offers a flag it refuses:\n%s", out)
	}
	h.run("ssh-key", "set", "--help")
	if out := h.out.String(); !strings.Contains(out, "login, dialog or block") {
		t.Errorf("ssh-key set's gate values:\n%s", out)
	}
	// The hidden command stays out of its group's help.
	h.run("k8s", "--help")
	if out := h.out.String(); strings.Contains(out, "\n  credential") {
		t.Errorf("k8s --help lists credential:\n%s", out)
	}
}

// -h is a flag of nazar's only where the command's own parser would have
// taken it as one: never as the value of a flag, never after `--`.
func TestHelpOnlyWhereTheParserSawAFlag(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		{"ssh-key", "rule", "add", "github", "--apps", "-h"},
		{"ssh-key", "rule", "add", "github", "--apps=x", "--gate", "--help"},
		{"ssh-key", "rule", "add", "github", "--apps", "x", "--gate", "login", "--", "-h"},
		{"ssh-key", "rule", "add", "github", "--bogus", "-h"},
		{"ssh-key", "rule", "add", "github", "---h"},
		{"k8s", "rule", "add", "hydra", "--to", "-h"},
		{"secret", "add", "--", "-h"},
		{"run", "--secret", "-h", "--", "x"},
		{"log", "--since", "--help"},
		{"bogus", "-h"},
	} {
		if code := h.run(args...); code != control.ExitUsage || strings.Contains(h.out.String(), "Usage:") {
			t.Errorf("%q: exit %d stdout %q", args, code, h.out)
		}
	}
	for _, args := range [][]string{
		{"ssh-key", "rule", "add", "github", "--apps", "x", "-h"},
		{"ssh-key", "rule", "add", "github", "--no-expire", "--help"},
		{"ssh-key", "rule", "add", "github", "-help=x"},
		{"ssh-key", "frob", "-h"},
		{"log", "--follow", "-h"},
		{"run", "-h", "--", "x"},
	} {
		if code := h.run(args...); code != 0 || !strings.Contains(h.out.String(), "Usage:") {
			t.Errorf("%q: exit %d stdout %q stderr %q", args, code, h.out, h.errb)
		}
	}
}

// Everything after run's `--` is the program's: its -h, --help, --json and
// -y reach nazar-agent byte for byte and are never help.
func TestRunPassesHelpFlagsThrough(t *testing.T) {
	h := newHarness(t)
	f := newRunFixture(t, h)
	h.serveRun(t, func() control.RunPlan { return f.plan }, nil)
	code := h.run("run", "--secret", "API_KEY", "--", "node", "-h", "--help", "help", "--json", "-y", "--", "-h")
	if code != control.ExitError || !strings.Contains(h.errb.String(), "stub exec") || strings.Contains(h.out.String(), "Usage:") {
		t.Fatalf("exit %d stdout %q stderr %q", code, h.out, h.errb)
	}
	reqs := h.requests()
	if len(reqs) != 1 || reqs[0].Command != control.CmdSecretRun {
		t.Fatalf("requests %+v", reqs)
	}
	var argv []string
	if err := json.Unmarshal([]byte(reqs[0].Args["argv"]), &argv); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(argv, []string{"node", "-h", "--help", "help", "--json", "-y", "--", "-h"}) {
		t.Fatalf("argv %q", argv)
	}
}

// sign-git's arguments are ssh-keygen's and k8s credential's kubectl's
// (from the kubeconfig): neither ever shows help.
func TestPassthroughNeverShowsHelp(t *testing.T) {
	h := newHarness(t)
	h.env["NAZAR_AGENT_SOCK"] = "/x/agent.sock"
	for _, args := range [][]string{{"sign-git", "-h"}, {"sign-git", "--help"}, {"sign-git", "-Y", "sign", "--help"}} {
		h.execed = nil
		if code := h.run(args...); code != control.ExitError || strings.Contains(h.out.String(), "Usage:") {
			t.Errorf("%q: exit %d stdout %q", args, code, h.out)
		}
		if want := append([]string{sshKeygen, "ssh-keygen"}, args[1:]...); len(h.execed) < len(want) || !slices.Equal(h.execed[:len(want)], want) {
			t.Errorf("%q: exec %q", args, h.execed)
		}
	}
	for _, args := range [][]string{{"k8s", "credential", "-h"}, {"k8s", "credential", "--help"}, {"k8s", "credential", "ctx", "-h"}} {
		if code := h.run(args...); code != control.ExitUsage || h.out.Len() != 0 || strings.Contains(h.errb.String(), "Usage:") {
			t.Errorf("%q: exit %d stdout %q stderr %q", args, code, h.out, h.errb)
		}
	}
}

// An unknown command or subcommand is still a usage error (exit 2, on
// stderr), now with cobra's suggestions; --json output is unchanged.
func TestUnknownCommandSuggests(t *testing.T) {
	h := newHarness(t)
	// An unknown command gets the list of commands; an unknown subcommand
	// only the line naming its command's help, not every command.
	for args, want := range map[string][2]string{
		"sssh-key":           {"\tssh-key\n", usage},
		"ssh-key lst":        {"\tlist\n", "nazar help ssh-key: its flags and examples\n"},
		"secret ad":          {"\tadd\n", "nazar help secret: its flags and examples\n"},
		"k8s ca shw":         {"\tshow\n", "nazar help k8s ca: its flags and examples\n"},
		"config aply":        {"\tapply\n", "nazar help config: its flags and examples\n"},
		"ssh-key rule rmove": {"\tremove\n", "nazar help ssh-key rule: its flags and examples\n"},
		"apps lis":           {"\tlist\n", "nazar help apps: its flags and examples\n"},
	} {
		code := h.run(strings.Fields(args)...)
		if code != control.ExitUsage || h.out.Len() != 0 || !strings.Contains(h.errb.String(), "\nDid you mean this?\n"+want[0]) || !strings.HasSuffix(h.errb.String(), want[1]) {
			t.Errorf("%q: exit %d stderr %q", args, code, h.errb)
		}
	}
	// A known command's usage error is two lines, never the whole list.
	if code := h.run("k8s", "ca", "create", "a", "b", "c"); code != control.ExitUsage || strings.Contains(h.errb.String(), "Exit codes:") ||
		!strings.HasSuffix(h.errb.String(), "nazar help k8s ca create: its flags and examples\n") {
		t.Errorf("k8s ca create with 3 arguments: exit %d stderr %q", code, h.errb)
	}
	// The hidden command is never suggested.
	if h.run("k8s", "credentail"); strings.Contains(h.errb.String(), "Did you mean") {
		t.Errorf("suggested a hidden command: %q", h.errb)
	}
	if code := h.run("--json", "sssh-key"); code != control.ExitUsage || h.out.String() != `{"apiVersion":"nazar/v1","kind":"Problem","code":"usage","message":"unknown command \"sssh-key\""}`+"\n" {
		t.Errorf("--json: %q", h.out)
	}
}

// Every command of the tree is one a.run dispatches, at every level.
func TestTreeNamesEveryCommand(t *testing.T) {
	h := newHarness(t)
	h.serve(t, contractReply)
	h.env["NAZAR_AGENT_SOCK"] = "/x/agent.sock"
	for _, path := range commandPaths(t, h) {
		if !lookup(t, h, path).Runnable() {
			continue // a group: its commands are in the list
		}
		args := append(slices.Clone(path), "zz1", "zz2", "zz3")
		h.run(args...)
		for _, bad := range []string{"unknown command", "unknown " + path[0], "subcommand", "expected create or show"} {
			if strings.Contains(h.errb.String(), bad) {
				t.Errorf("%q is not dispatched: %q", path, h.errb)
			}
		}
	}
}

// The flags of the tree are the flags of each command's own parser: a
// declared flag is never "not defined" there, and a flag the tree does not
// declare for a command is. Extra arguments make every run a usage error,
// decided before anything is sent.
func TestTreeMirrorsTheParsers(t *testing.T) {
	h := newHarness(t)
	h.serve(t, contractReply)
	all := map[string]bool{}
	var leaves [][]string
	for _, path := range commandPaths(t, h) {
		c := lookup(t, h, path)
		c.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) { all[f.Name] = true })
		if c.Runnable() {
			leaves = append(leaves, path)
		}
	}
	delete(all, "help")
	for _, path := range leaves {
		c := lookup(t, h, path)
		switch c.CommandPath() {
		case "nazar sign-git", "nazar version", "nazar completion":
			continue // no FlagSet: ssh-keygen's arguments; no arguments read; one shell
		}
		run := func(flag string) {
			args := append(slices.Clone(path), flag, "zz1", "zz2", "zz3", "zz4")
			if path[0] == "run" {
				args = append(args, "--", "x")
			}
			if code := h.run(args...); code != control.ExitUsage {
				t.Errorf("%q: exit %d, stderr %q", args, code, h.errb)
			}
		}
		for name := range all {
			f := c.LocalNonPersistentFlags().Lookup(name)
			arg := "--" + name + "=v"
			if f != nil && f.NoOptDefVal != "" {
				arg = "--" + name
			}
			run(arg)
			notDefined := strings.Contains(h.errb.String(), "flag provided but not defined: -"+name)
			if f != nil && notDefined {
				t.Errorf("%s declares --%s, its parser doesn't: %q", c.CommandPath(), name, h.errb)
			}
			if f == nil && !notDefined {
				t.Errorf("%s's parser takes --%s, the tree doesn't declare it: %q", c.CommandPath(), name, h.errb)
			}
			if f != nil {
				// Last, a flag that takes a value has none; a flag that takes
				// none is complete.
				args := append(slices.Clone(path), "zz1", "zz2", "--"+name)
				if path[0] == "run" {
					args = append(args, "--", "x")
				}
				h.run(args...)
				needs := strings.Contains(h.errb.String(), "flag needs an argument: -"+name)
				if takesValue := f.NoOptDefVal == ""; needs != takesValue {
					t.Errorf("%s --%s: the tree says it takes a value: %v; its parser: %q", c.CommandPath(), name, takesValue, h.errb)
				}
			}
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("usage errors reached nazar-agent: %+v", r)
	}
}

// `nazar completion` prints bash, zsh and fish scripts and nothing else.
func TestCompletionScripts(t *testing.T) {
	h := newHarness(t)
	for _, sh := range []string{"bash", "zsh", "fish"} {
		if code := h.run("completion", sh); code != 0 || h.errb.Len() != 0 || !strings.Contains(h.out.String(), "__complete") || !strings.Contains(h.out.String(), "nazar") {
			t.Errorf("%s: exit %d stderr %q", sh, code, h.errb)
		}
	}
	if h.run("completion", "zsh"); !strings.HasPrefix(h.out.String(), "#compdef nazar\n") {
		t.Errorf("zsh: %.40q", h.out)
	}
	for _, args := range [][]string{{"completion"}, {"completion", "powershell"}, {"completion", "zsh", "bash"}} {
		if code := h.run(args...); code != control.ExitUsage || h.out.Len() != 0 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}
