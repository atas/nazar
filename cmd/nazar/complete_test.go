package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/atas/nazar/core/control"
)

// completionPolicy is the rules a completion reply carries for name.
func completionPolicy(name string) *control.SSHKeyRules {
	return &control.SSHKeyRules{TypeMeta: control.Meta(control.KindSSHKeyRules), Name: name, Configured: true, Rules: []control.RuleInfo{
		{Index: 1, Apps: []control.MatcherInfo{{Kind: "app", Ref: "iterm"}}, Policy: control.PolicyInfo{Scope: "session", Gate: "login"}},
		{Index: 2, Apps: []control.MatcherInfo{{Kind: "any", Ref: "any"}}, Policy: control.PolicyInfo{Scope: "use", Gate: "dialog\tx\ny"}},
	}}
}

// completionReplies answers the five list calls, with names a shell must
// never be offered among the good ones.
func completionReplies(_ context.Context, req control.Request, out control.Emitter) {
	switch req.Command {
	case control.CmdSSHKeyList:
		var items []control.SSHKey
		for _, n := range []string{"github", "hydra", "bad name", "x\ny", "-rf", "a/b", "$(touch x)"} {
			items = append(items, control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: n, Fingerprint: "SHA256:f\tg", Policy: completionPolicy(n)})
		}
		out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: items})
	case control.CmdSecretList:
		var items []control.Secret
		for _, n := range []string{"GH_TOKEN", "k8s/hydra", "bad name", "x;y"} {
			items = append(items, control.Secret{TypeMeta: control.Meta(control.KindSecret), Name: n, Policy: completionPolicy(n)})
		}
		out.Emit(control.SecretList{TypeMeta: control.Meta(control.KindSecretList), Items: items})
	case control.CmdK8sList:
		var items []control.K8sContext
		for _, n := range []string{"hydra-nazar", "bad context"} {
			items = append(items, control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: n, Policy: completionPolicy(n)})
		}
		out.Emit(control.K8sContextList{TypeMeta: control.Meta(control.KindK8sContextList), Items: items})
	case control.CmdAWSList:
		var items []control.AWSEntry
		for _, n := range []string{"dev", "bad entry", "a/b"} {
			items = append(items, control.AWSEntry{TypeMeta: control.Meta(control.KindAWSEntry), Name: n, Policy: completionPolicy(n)})
		}
		out.Emit(control.AWSEntryList{TypeMeta: control.Meta(control.KindAWSEntryList), Items: items})
	case control.CmdAppsList:
		out.Emit(control.AppList{TypeMeta: control.Meta(control.KindAppList), Items: []control.AppEntry{
			{Name: "iterm", Matcher: control.MatcherInfo{Kind: "app", ID: "com.googlecode.iterm2", Ref: "iterm"}},
			{Matcher: control.MatcherInfo{Kind: "signed", Team: "Q6L2SF6YDW", ID: "com.anthropic.claude-code", Ref: "signed:Q6L2SF6YDW:com.anthropic.claude-code"}},
			{Name: "Bad Name", Matcher: control.MatcherInfo{Kind: "app", ID: "evil id\x1b[2J", Ref: "Bad Name"}},
			{Matcher: control.MatcherInfo{Kind: "path", ID: "/opt/a‮gpj.sh", Ref: "path:/opt/a‮gpj.sh"}},
			// A path: entry is offered by its name; an inline one with a
			// control or bidi character in its path is not (above).
			{Name: "mytool", Matcher: control.MatcherInfo{Name: "mytool", Kind: "path", Path: "/opt/homebrew/opt/mytool/bin/mytool", Ref: "mytool"}},
			{Matcher: control.MatcherInfo{Kind: "path", Path: "/opt/homebrew/opt/other/bin/other", Ref: "path:/opt/homebrew/opt/other/bin/other"}},
		}})
	default:
		out.Emit(control.NewProblem(control.CodeUsage, "completion sent %s", req.Command))
	}
}

// noSideEffects makes every seam that acts fail the test: completion only
// ever talks to the control socket.
func noSideEffects(t *testing.T, h *harness) {
	t.Helper()
	h.a.exec = func(string, []string, []string) error { t.Error("completion exec'd"); return errors.New("no") }
	h.a.launchctl = func(...string) error { t.Error("completion ran launchctl"); return errors.New("no") }
	h.a.openUI = func(string) (string, error) { t.Error("completion opened the UI"); return "", errors.New("no") }
	h.a.output = func(context.Context, string, ...string) ([]byte, error) {
		t.Error("completion ran a program")
		return nil, errors.New("no")
	}
	h.a.runLog = func(context.Context, []string, func([]byte)) error {
		t.Error("completion read the log")
		return errors.New("no")
	}
	h.a.stdinTerminal = func() bool { t.Error("completion looked at stdin"); return false }
	h.a.readHidden = func() ([]byte, error) { t.Error("completion read a prompt"); return nil, errors.New("no") }
	h.a.resetForExec = func(int) error { t.Error("completion readied an exec"); return errors.New("no") }
}

// complete runs `nazar __complete args…` and returns the completions
// (without descriptions) and the directive.
func (h *harness) complete(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	if code := h.run(append([]string{cobra.ShellCompRequestCmd}, args...)...); code != 0 {
		t.Fatalf("%q: exit %d", args, code)
	}
	if h.errb.Len() != 0 {
		t.Fatalf("%q: stderr %q", args, h.errb)
	}
	lines := strings.Split(strings.TrimSuffix(h.out.String(), "\n"), "\n")
	last := lines[len(lines)-1]
	d, err := strconv.Atoi(strings.TrimPrefix(last, ":"))
	if !strings.HasPrefix(last, ":") || err != nil {
		t.Fatalf("%q: no directive in %q", args, h.out)
	}
	var comps []string
	for _, l := range lines[:len(lines)-1] {
		v, _, _ := strings.Cut(l, "\t")
		comps = append(comps, v)
	}
	return comps, cobra.ShellCompDirective(d)
}

func TestCompletionOffersCommandsAndFlags(t *testing.T) {
	h := newHarness(t)
	noSideEffects(t, h)
	has := func(args []string, want, not []string) {
		t.Helper()
		got, _ := h.complete(t, args...)
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("%q: lacks %q in %q", args, w, got)
			}
		}
		for _, n := range not {
			if slices.Contains(got, n) {
				t.Errorf("%q: offers %q", args, n)
			}
		}
	}
	has([]string{""}, []string{"ssh-key", "secret", "get", "run", "k8s", "aws", "apps", "status", "revoke", "config", "trust", "log", "sign-git",
		"install", "uninstall", "ui", "version", "completion", "help"}, []string{"__complete", "credential"})
	has([]string{"ssh-key", ""}, []string{"create", "list", "pubkey", "delete", "rules", "rule", "set"}, nil)
	has([]string{"k8s", ""}, []string{"ca", "list", "rule", "forget"}, []string{"credential"})
	has([]string{"k8s", "ca", ""}, []string{"create", "show"}, nil)
	has([]string{"aws", ""}, []string{"ca", "list", "rule", "forget"}, []string{"credential"})
	has([]string{"aws", "ca", ""}, []string{"create", "show"}, nil)
	has([]string{"aws", "rule", "add", "dev", "--"}, []string{"--apps", "--gate"}, []string{"--to", "--no-to"})
	has([]string{"aws", "ca", "create", "dev", "--"}, []string{"--only-when-unlocked"}, nil)
	has([]string{"help", "ssh"}, []string{"ssh-key"}, nil)
	has([]string{"ssh-key", "rule", "add", "github", "--"}, []string{"--apps", "--to", "--gate", "--scope", "--expire", "--at", "--allow-loosen-access", "--if-hash", "--json", "--yes"},
		[]string{"--no-to", "--no-expire"})
	has([]string{"ssh-key", "rule", "set", "github", "1", "--"}, []string{"--no-to", "--no-expire", "--allow-loosen-access"}, []string{"--at"})
	has([]string{"ssh-key", "rule", "remove", "github", "1", "--"}, []string{"--allow-loosen-access", "--if-hash"}, []string{"--apps"})
	has([]string{"ssh-key", "set", "github", "--"}, []string{"--allow-loosen-access", "--gate"}, []string{"--apps"})
	has([]string{"k8s", "rule", "add", "hydra-nazar", "--"}, []string{"--apps", "--gate", "--allow-loosen-access"}, []string{"--to", "--no-to"})
	has([]string{"config", "apply", "--"}, []string{"--json"}, []string{"--hash"})
	has([]string{"log", "summary", "--"}, []string{"--since", "--target"}, []string{"--follow"})
	// Fixed values, read from the parsers.
	has([]string{"ssh-key", "rule", "add", "github", "--gate", ""}, []string{"login", "dialog", "none", "block"}, nil)
	has([]string{"ssh-key", "set", "github", "--gate", ""}, []string{"login", "dialog", "block"}, []string{"none"})
	has([]string{"secret", "rule", "set", "GH_TOKEN", "1", "--scope", ""}, []string{"use", "session", "app"}, nil)
	has([]string{"log", "--decision", ""}, []string{"allowed", "approved", "denied", "timeout", "blocked", "error"}, nil)
	has([]string{"completion", ""}, []string{"bash", "zsh", "fish"}, []string{"powershell"})
	// Paths complete as files where a path goes, and nowhere else.
	for args, want := range map[string]cobra.ShellCompDirective{
		"trust|":                       cobra.ShellCompDirectiveNoFileComp, // no path: trust --app only
		"install|--bin-dir|":           cobra.ShellCompDirectiveFilterDirs,
		"run|--secret|X|--|":           cobra.ShellCompDirectiveDefault,
		"ssh-key|create|":              cobra.ShellCompDirectiveNoFileComp,
		"secret|add|":                  cobra.ShellCompDirectiveNoFileComp,
		"ssh-key|rule|add|g|--expire|": cobra.ShellCompDirectiveNoFileComp,
	} {
		if _, d := h.complete(t, strings.Split(args, "|")...); d != want {
			t.Errorf("%q: directive %d, want %d", args, d, want)
		}
	}
	// After run's --, nothing of nazar's.
	if got, _ := h.complete(t, "run", "--secret", "X", "--", "node", "--"); len(got) != 0 {
		t.Errorf("after --: %q", got)
	}
}

func TestCompletionOffersNamesFromTheAgent(t *testing.T) {
	h := newHarness(t)
	noSideEffects(t, h)
	h.serve(t, completionReplies)
	keys := []string{"github", "hydra"}
	secrets := []string{"GH_TOKEN", "k8s/hydra"}
	contexts := []string{"hydra-nazar"}
	for args, want := range map[string][]string{
		"ssh-key|pubkey|":                 keys,
		"ssh-key|delete|":                 keys,
		"ssh-key|rules|":                  keys,
		"ssh-key|set|":                    keys,
		"ssh-key|rule|add|":               keys,
		"ssh-key|rule|set|":               keys,
		"ssh-key|rule|set|github|":        {"1", "2"},
		"ssh-key|rule|remove|hydra|":      {"1", "2"},
		"ssh-key|rule|add|github|--at|":   {"1", "2"},
		"ssh-key|pubkey|github|":          nil,
		"revoke|--key|":                   keys,
		"secret|rm|":                      secrets,
		"secret|rule|remove|":             secrets,
		"secret|rule|set|GH_TOKEN|":       {"1", "2"},
		"get|":                            secrets,
		"get|GH_TOKEN|":                   nil,
		"run|--secret|":                   secrets,
		"k8s|forget|":                     contexts,
		"k8s|ca|show|":                    contexts,
		"k8s|rule|add|":                   contexts,
		"k8s|rule|set|hydra-nazar|":       {"1", "2"},
		"k8s|ca|create|":                  nil,
		"aws|forget|":                     {"dev"},
		"aws|ca|show|":                    {"dev"},
		"aws|rule|add|":                   {"dev"},
		"aws|rule|remove|dev|":            {"1", "2"},
		"aws|ca|create|":                  nil,
		"aws|credential|":                 nil,
		"log|--target|":                   {"ssh:github", "ssh:hydra", "secret:GH_TOKEN", "secret:k8s/hydra", "k8s:hydra-nazar", "aws:dev"},
		"trust|--app|":                    {"com.googlecode.iterm2"},
		"revoke|--app|":                   {"com.googlecode.iterm2"},
		"ssh-key|rule|add|github|--apps|": {"any", "unknown", "app:", "signed:", "path:", "iterm", "signed:Q6L2SF6YDW:com.anthropic.claude-code", "mytool", "path:/opt/homebrew/opt/other/bin/other"},
		"ssh-key|rule|add|github|--to|a,": {"a,any", "a,unknown", "a,app:", "a,signed:", "a,path:", "a,iterm", "a,signed:Q6L2SF6YDW:com.anthropic.claude-code", "a,mytool", "a,path:/opt/homebrew/opt/other/bin/other"},
	} {
		got, _ := h.complete(t, strings.Split(args, "|")...)
		if !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", args, got, want)
		}
	}
	// A description is one line without a stray tab.
	h.complete(t, "ssh-key", "rule", "set", "github", "")
	for _, l := range strings.Split(strings.TrimSuffix(h.out.String(), "\n"), "\n") {
		if strings.Count(l, "\t") > 1 {
			t.Errorf("line %q", l)
		}
	}
	if !strings.Contains(h.out.String(), "1\tapps iterm, gate login, scope session\n") {
		t.Errorf("rule descriptions: %q", h.out)
	}
	if _, d := h.complete(t, "ssh-key", "rule", "add", "github", "--apps", ""); d&cobra.ShellCompDirectiveNoSpace == 0 {
		t.Error("a matcher list gets no space after an item")
	}
	for _, r := range h.requests() {
		if _, ok := completionCommands[r.Command]; !ok || len(r.Args) != 0 {
			t.Errorf("completion sent %s %v", r.Command, r.Args)
		}
	}
	if len(h.requests()) == 0 {
		t.Fatal("no list call reached the agent")
	}
}

// The only control commands completion may send are the read-only lists.
func TestCompletionSendsOnlyReadOnlyLists(t *testing.T) {
	for cmd, kind := range completionCommands {
		switch cmd {
		case control.CmdSSHKeyList, control.CmdSecretList, control.CmdK8sList, control.CmdAWSList, control.CmdAppsList:
		default:
			t.Errorf("completion may send %s", cmd)
		}
		if control.ValueCommand(cmd) || kind == "" {
			t.Errorf("%s", cmd)
		}
	}
	// Anything else is refused before a connection is made.
	h := newHarness(t)
	h.serve(t, completionReplies)
	var s control.Status
	if h.a.completionList(control.CmdStatus, &s) || len(h.requests()) != 0 {
		t.Fatal("completionList sent status")
	}
}

// No agent, an agent that hangs, a peer that fails verification: no names,
// nothing on stderr, exit 0, and soon.
func TestCompletionIsSilentAndQuickOnErrors(t *testing.T) {
	h := newHarness(t)
	noSideEffects(t, h)
	if got, _ := h.complete(t, "ssh-key", "pubkey", ""); len(got) != 0 {
		t.Errorf("no agent: %q", got)
	}
	if got, _ := h.complete(t, "ssh-key", "rule", "add", "g", "--apps", ""); !slices.Equal(got, []string{"any", "unknown", "app:", "signed:", "path:"}) {
		t.Errorf("no agent, --apps: %q", got)
	}

	stalled := newHarness(t)
	noSideEffects(t, stalled)
	stalled.serve(t, func(ctx context.Context, _ control.Request, _ control.Emitter) { <-ctx.Done() })
	start := time.Now()
	if got, _ := stalled.complete(t, "log", "--target", ""); len(got) != 0 {
		t.Errorf("stalled agent: %q", got)
	}
	if d := time.Since(start); d > 3*completionTimeout+time.Second {
		t.Errorf("a stalled agent held completion for %v", d)
	}

	refused := newHarness(t)
	noSideEffects(t, refused)
	refused.serve(t, completionReplies)
	refused.a.verifier = control.VerifierFunc(func(*net.UnixConn) error { return errors.New("not nazar-agent") })
	if got, _ := refused.complete(t, "get", ""); len(got) != 0 || len(refused.requests()) != 0 {
		t.Errorf("refused peer: %q, %d requests", got, len(refused.requests()))
	}

	// Under NAZAR_TEST_PEER the human warning stays off stderr too.
	peer := newHarness(t)
	peer.a.verifier = nil
	peer.env["NAZAR_TEST_PEER"] = "same-user"
	peer.serve(t, completionReplies)
	if got, _ := peer.complete(t, "get", ""); !slices.Equal(got, []string{"GH_TOKEN", "k8s/hydra"}) {
		t.Errorf("NAZAR_TEST_PEER: %q", got)
	}
}

// cobra appends its debug lines to $BASH_COMP_DEBUG_FILE; completion
// writes nothing, so it never does.
func TestCompletionWritesNothing(t *testing.T) {
	h := newHarness(t)
	noSideEffects(t, h)
	h.serve(t, completionReplies)
	debug := filepath.Join(h.home, "debug.log")
	t.Setenv("BASH_COMP_DEBUG_FILE", debug)
	h.complete(t, "ssh-key", "rule", "add", "--bogus", "")
	h.complete(t, "get", "")
	if _, err := os.Stat(debug); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completion wrote %s: %v", debug, err)
	}
	entries, err := os.ReadDir(h.home)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "Nazar.app" && e.Name() != "c.sock" {
			t.Errorf("completion left %s", e.Name())
		}
	}
}
