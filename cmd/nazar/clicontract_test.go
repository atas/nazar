package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/atas/nazar/core/control"
)

// The CLI's contract with scripts and agents: for every command path, with
// good and bad arguments, the exit code and the exact stdout and stderr,
// pinned in testdata/cli-contract.golden. A change to any of them shows as
// a diff of that file; the only ones meant to change are help and usage
// text. Regenerate with: go test ./cmd/nazar -run TestCLIContract -update-contract
var updateContract = flag.Bool("update-contract", false, "rewrite testdata/cli-contract.golden")

const contractGolden = "testdata/cli-contract.golden"

// contractHash is a well-formed staged-change hash (64 hex digits).
const contractHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// contractReply answers each command with a fixed reply of the kind it
// expects, so every output is deterministic.
func contractReply(_ context.Context, req control.Request, out control.Emitter) {
	rules := &control.SSHKeyRules{TypeMeta: control.Meta(control.KindSSHKeyRules), Name: req.Args["name"], Configured: true,
		Rules: []control.RuleInfo{{Index: 1, Apps: []control.MatcherInfo{{Kind: "app", Ref: "app:com.googlecode.iterm2"}},
			To: []control.MatcherInfo{}, Policy: control.PolicyInfo{Scope: "session", Gate: "login"}}},
		Fallback: control.PolicyInfo{Scope: "use", Gate: "block"}, FallbackSource: "key-gate"}
	switch req.Command {
	case control.CmdSSHKeyCreate, control.CmdSSHKeyPubkey, control.CmdSSHKeyDelete:
		out.Emit(control.SSHKey{TypeMeta: control.Meta(control.KindSSHKey), Name: req.Args["name"], Type: "ecdsa-sha2-nistp256",
			Fingerprint: "SHA256:abc", PublicKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNh " + req.Args["name"], Configured: true,
			Rules: []string{"1: apps=iterm gate=login", "fallback: gate=block"}, Usable: true,
			UserPresence: req.Args["alwaysAsk"] == "true", WhileLocked: req.Args["alwaysAsk"] != "true" && req.Args["onlyWhenUnlocked"] != "true"})
	case control.CmdSSHKeyList:
		out.Emit(control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{{TypeMeta: control.Meta(control.KindSSHKey),
			Name: "github", Type: "ecdsa-sha2-nistp256", Fingerprint: "SHA256:abc", Configured: true, Usable: true, WhileLocked: true,
			Rules: []string{"1: apps=iterm gate=login", "fallback: gate=block"}, Policy: rules}}})
	case control.CmdSSHKeyRules:
		out.Emit(rules)
	case control.CmdSecretList:
		out.Emit(control.SecretList{TypeMeta: control.Meta(control.KindSecretList), Items: []control.Secret{{TypeMeta: control.Meta(control.KindSecret),
			Name: "GH_TOKEN", Deliver: []string{"helper"}, Rules: []string{"1: apps=iterm gate=login"}, Configured: true, Stored: true, WhileLocked: true}}})
	case control.CmdSecretAdd, control.CmdSecretDelete:
		out.Emit(control.Secret{TypeMeta: control.Meta(control.KindSecret), Name: req.Args["name"], Deliver: []string{"helper"},
			Rules: []string{"1: apps=iterm gate=login"}, Configured: true, Stored: true, WhileLocked: req.Args["onlyWhenUnlocked"] != "true"})
	case control.CmdSecretGet, control.CmdSecretHelper:
		out.Emit(control.NewProblem(control.CodeRefused, "secret GH_TOKEN: no rule allows this caller"))
	case control.CmdK8sList:
		out.Emit(control.K8sContextList{TypeMeta: control.Meta(control.KindK8sContextList), Items: []control.K8sContext{{TypeMeta: control.Meta(control.KindK8sContext),
			Name: "hydra-nazar", Rules: []string{}}}})
	case control.CmdK8sCAShow:
		out.Emit(control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: req.Args["name"], Fingerprint: "ab",
			CertPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"})
	case control.CmdK8sForget:
		out.Emit(control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: req.Args["name"], Rules: []string{}})
	case control.CmdAWSList:
		out.Emit(control.AWSEntryList{TypeMeta: control.Meta(control.KindAWSEntryList), Items: []control.AWSEntry{{TypeMeta: control.Meta(control.KindAWSEntry),
			Name: "dev", Configured: true, Identity: &control.AWSIdentity{User: "you-nazar"}, Duration: "1h",
			Rules: []string{"1: apps=iterm gate=login", "fallback: gate=block"}, State: control.AWSStateNotConnected,
			Remedy: "aws.dev is not connected yet: add trustAnchorArn, profileArn and roleArn (nazar aws ca create printed the steps)",
			CA:     &control.AWSCA{TypeMeta: control.Meta(control.KindAWSCA), Name: "dev", Fingerprint: "ab", CertFile: "/k/aws-ca-dev.crt", WhileLocked: true}}}})
	case control.CmdAWSCAShow:
		out.Emit(control.AWSCA{TypeMeta: control.Meta(control.KindAWSCA), Name: req.Args["name"], Fingerprint: "ab",
			CertPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"})
	case control.CmdAWSForget:
		out.Emit(control.AWSEntry{TypeMeta: control.Meta(control.KindAWSEntry), Name: req.Args["name"], State: control.AWSStateAbsent, Rules: []string{}})
	case control.CmdAppsList:
		out.Emit(control.AppList{TypeMeta: control.Meta(control.KindAppList), Items: []control.AppEntry{{Name: "iterm",
			Matcher: control.MatcherInfo{Kind: "app", ID: "com.googlecode.iterm2", Ref: "iterm"}, UsedBy: []string{"github rule 1"}}}})
	case control.CmdConfigEdit:
		// As nazar-agent answers a loosening: refused without allowLoosen,
		// staged with it (the CLI then sends config.apply); a removal is
		// the tightening, in force.
		switch {
		case req.Args["op"] == control.EditRuleRemove:
			out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Op: req.Args["op"], Key: req.Args["key"], Path: "config.yaml",
				Changed: true, Applied: true, Problems: []control.ConfigProblem{}})
		case req.Args["allowLoosen"] != "true":
			p := control.NewProblem(control.CodeUsage, "%s", control.LoosensRefusal)
			p.Details = []string{"ssh:github: added rule 2: apps=[any] to=[] gate=dialog", "loosens ssh:github: requests that got gate=block (fallback) can now get gate=dialog (rule 2)"}
			out.Emit(p)
		default:
			out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Op: req.Args["op"], Key: req.Args["key"], Path: "config.yaml",
				Changed: true, Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: contractHash, Changes: []string{"a rule"}}})
		}
	case control.CmdConfigCheck:
		out.Emit(control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Path: "config.yaml", Valid: true, Problems: []control.ConfigProblem{},
			Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: contractHash, Loosens: true, Changes: []string{"a rule"}, Loosening: []string{"ssh:github: more"}}})
	case control.CmdConfigApply:
		out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: contractHash, Applied: true, Changes: []string{"a rule"}})
	case control.CmdTrustApp:
		out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: req.Args["app"], Team: "TEAM", Path: "/Applications/X.app", Changed: true})
	default:
		replyFor(req, out)
	}
}

type contractCase struct {
	entry    string // "" (nazar), gitCredentialName or "nazar-sign-git"
	args     []string
	stdin    string
	noServer bool
}

func contractCases() []contractCase {
	c := func(args ...string) contractCase { return contractCase{args: args} }
	in := func(stdin string, args ...string) contractCase { return contractCase{args: args, stdin: stdin} }
	down := func(args ...string) contractCase { return contractCase{args: args, noServer: true} }
	return []contractCase{
		// The command line itself, global flags and help.
		c(), c("bogus"), c("--bogus", "status"), c("sssh-key"), c("-json", "version"), c("--json", "bogus"),
		c("help"), c("-h"), c("--help"), c("help", "ssh-key"), c("help", "ssh-key", "rule", "add"), c("--json", "help"),
		c("version"), c("--json", "version"), c("version", "--json"), c("version", "extra"), c("-y", "version"), c("--yes", "version"),
		c("version", "-h"), c("completion"), c("completion", "zsh"),
		// ssh-key
		c("ssh-key"), c("ssh-key", "-h"), c("ssh-key", "--help"), c("ssh-key", "creat", "x"), c("ssh-key", "list"), c("--json", "ssh-key", "list"),
		c("ssh-key", "list", "--json"), c("ssh-key", "--json", "list"), c("ssh-key", "list", "-y"), c("ssh-key", "list", "-h"), c("ssh-key", "list", "extra"),
		c("ssh-key", "create"), c("ssh-key", "create", "work"), c("ssh-key", "create", "work", "--always-ask"),
		c("ssh-key", "create", "--only-when-unlocked", "work"), c("ssh-key", "create", "-h"), c("ssh-key", "create", "work", "--gate", "dialog"),
		c("ssh-key", "create", "../x"), c("ssh-key", "create", "work", "--always-ask=false"), c("ssh-key", "create", "-always-ask", "work"),
		c("ssh-key", "pubkey", "github"), c("ssh-key", "pubkey"), c("ssh-key", "delete", "github"), c("ssh-key", "rules", "github"),
		c("--json", "ssh-key", "rules", "github"), c("ssh-key", "rules", "a/b"), c("ssh-key", "rules", "-h"),
		c("ssh-key", "rule"), c("ssh-key", "rule", "-h"), c("ssh-key", "rule", "ad"),
		c("ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "login", "--scope", "session"),
		c("--json", "ssh-key", "rule", "add", "github", "--apps", "any", "--to", "signed:apple:com.apple.git-remote-http", "--gate", "dialog", "--expire", "8h", "--at", "1"),
		c("ssh-key", "rule", "add", "github", "-apps=any", "-gate=none", "-scope=app"),
		c("ssh-key", "rule", "add", "github", "--apps", "any", "--gate", "dialog", "--allow-loosen-access"),
		c("--json", "ssh-key", "rule", "add", "github", "--apps", "any", "--gate", "dialog", "--allow-loosen-access"),
		c("ssh-key", "rule", "add", "github", "--apps", "app:my tools.x", "--gate", "none"),
		c("ssh-key", "rule", "add", "github", "--apps", "app:com.x!y", "--gate", "none"),
		c("ssh-key", "rule", "add", "github", "--apps", "any", "--gate", "dialog", "--allow-loosen-access=false"),
		c("ssh-key", "rule", "add", "github", "--gate", "login"), c("ssh-key", "rule", "add", "-h"), c("ssh-key", "rule", "add", "--help"),
		c("ssh-key", "rule", "add", "github", "--apps", "-h"), c("ssh-key", "rule", "add", "github", "--bogus", "-h"),
		c("ssh-key", "rule", "add", "github", "--apps", "x", "--gate", "login", "--", "-h"), c("ssh-key", "rule", "add", "github", "-help"),
		c("ssh-key", "rule", "add", "github", "--help=1"), c("ssh-key", "rule", "add", "github", "--gate"),
		c("ssh-key", "rule", "add", "github", "--apps", "x", "--gate", "maybe"), c("ssh-key", "rule", "add", "github", "--apps", "x", "--gate", "login", "--no-to"),
		c("ssh-key", "rule", "set", "github", "1", "--gate", "dialog"), c("ssh-key", "rule", "set", "github", "0", "--gate", "dialog"),
		c("ssh-key", "rule", "set", "github", "1"), c("ssh-key", "rule", "set", "github", "1", "--no-to", "--to", "x"),
		c("ssh-key", "rule", "set", "github", "1", "--no-expire"), c("ssh-key", "rule", "set", "-h"),
		c("ssh-key", "rule", "remove", "github", "1"), c("ssh-key", "rule", "remove", "github"), c("ssh-key", "rule", "remove", "github", "1", "--gate", "x"),
		c("ssh-key", "rule", "remove", "-h"),
		c("ssh-key", "set", "github", "--gate", "block"), c("ssh-key", "set", "github", "--gate", "none"), c("ssh-key", "set", "github"),
		c("ssh-key", "set", "github", "--scope", "forever"), c("ssh-key", "set", "github", "--expire", "8h", "--if-hash", contractHash), c("ssh-key", "set", "-h"),
		// secret
		c("secret"), c("secret", "-h"), c("secret", "lst"), c("secret", "list"), c("--json", "secret", "list"), c("secret", "list", "-h"),
		c("secret", "rm", "GH_TOKEN"), c("secret", "rm"), c("secret", "rm", "-h"),
		c("secret", "add", "NOTES"), in("value\n", "secret", "add", "NOTES"), in("value", "secret", "add", "bad name"),
		in("value", "--json", "secret", "add", "NOTES", "--only-when-unlocked"), in("", "secret", "add", "NOTES"), in("value", "secret", "add", "-h"),
		in("value", "secret", "add", "NOTES", "--value", "x"),
		c("secret", "rule"), c("secret", "rule", "add", "GH_TOKEN", "--apps", "any", "--gate", "dialog"), c("secret", "rule", "remove", "GH_TOKEN", "1"),
		c("secret", "rule", "set", "GH_TOKEN", "1", "--to", "signed:apple:com.apple.git-remote-http"), c("secret", "rule", "add", "-h"),
		// get
		c("get", "GH_TOKEN"), c("--json", "get", "GH_TOKEN"), c("get"), c("get", "a", "b"), c("get", "bad name"), c("get", "-h"),
		// run
		c("run"), c("run", "--secret", "X"), c("run", "--secret", "X", "--"), c("run", "--", "cmd"),
		c("run", "--secret", "X", "--", "node", "-h"), c("run", "--secret", "X", "--", "node", "--json", "--help", "-y"),
		c("run", "--json", "--secret", "X", "--", "cmd", "--json"), c("run", "-h"), c("run", "--help"), c("run", "--secret", "X", "-h", "--", "cmd"),
		c("run", "--secret", "-h", "--", "cmd"), c("run", "--secret", "bad name", "--", "cmd"), c("run", "--secret", "X", "--secret", "Y", "--", "cmd"),
		// k8s
		c("k8s"), c("k8s", "-h"), c("k8s", "lst"), c("k8s", "list"), c("--json", "k8s", "list"), c("k8s", "list", "-h"),
		c("k8s", "ca"), c("k8s", "ca", "-h"), c("k8s", "ca", "creat"),
		c("k8s", "ca", "create"), c("k8s", "ca", "create", "a", "b", "c"), c("k8s", "ca", "create", "-h"),
		c("k8s", "ca", "create", "hydra-nazar", "https://hydra.example:16443", "--only-when-unlocked"),
		c("k8s", "ca", "show", "hydra-nazar"), c("k8s", "ca", "show", "hydra-nazar", "--microk8s"), c("k8s", "ca", "show"), c("k8s", "ca", "show", "-h"),
		c("k8s", "forget"), c("k8s", "forget", "hydra-nazar"), c("k8s", "forget", "-h"),
		c("k8s", "rule", "add", "hydra-nazar", "--apps", "any", "--gate", "login"), c("k8s", "rule", "add", "hydra-nazar", "--apps", "any", "--gate", "login", "--to", "x"),
		c("k8s", "rule", "add", "hydra-nazar", "--to", "-h"), c("k8s", "rule", "set", "hydra-nazar", "1", "--no-to"), c("k8s", "rule", "set", "hydra-nazar", "1"),
		c("k8s", "rule", "remove", "hydra-nazar", "1"), c("k8s", "rule", "add", "-h"),
		c("k8s", "credential"), c("k8s", "credential", "hydra-nazar"), c("k8s", "credential", "-h"), c("k8s", "credential", "--help"),
		c("--json", "k8s", "credential", "x"), c("k8s", "credential", "hydra-nazar", "--json"), c("k8s", "credential", "a", "b"),
		// aws
		c("aws"), c("aws", "-h"), c("aws", "lst"), c("aws", "list"), c("--json", "aws", "list"), c("aws", "list", "-h"), c("aws", "list", "x"),
		c("aws", "ca"), c("aws", "ca", "-h"), c("aws", "ca", "creat"),
		c("aws", "ca", "create"), c("aws", "ca", "create", "a", "b"), c("aws", "ca", "create", "-h"), c("aws", "ca", "create", "a/b"),
		c("aws", "ca", "create", "dev", "--only-when-unlocked"), c("aws", "ca", "create", "dev", "--gate", "login"),
		c("aws", "ca", "show", "dev"), c("--json", "aws", "ca", "show", "dev"), c("aws", "ca", "show"), c("aws", "ca", "show", "-h"),
		c("aws", "forget"), c("aws", "forget", "dev"), c("aws", "forget", "-h"),
		c("aws", "rule", "add", "dev", "--apps", "any", "--gate", "login"), c("aws", "rule", "add", "dev", "--apps", "any", "--gate", "login", "--to", "x"),
		c("aws", "rule", "add", "dev", "--to", "-h"), c("aws", "rule", "set", "dev", "1", "--no-to"), c("aws", "rule", "set", "dev", "1"),
		c("aws", "rule", "remove", "dev", "1"), c("aws", "rule", "add", "-h"), c("aws", "rule", "add", "a/b", "--apps", "any", "--gate", "login"),
		c("aws", "credential"), c("aws", "credential", "dev"), c("aws", "credential", "-h"), c("aws", "credential", "--help"),
		c("--json", "aws", "credential", "x"), c("aws", "credential", "dev", "--json"), c("aws", "credential", "a", "b"), c("aws", "credential", "a/b"),
		// status, revoke, config, trust, log, apps, ui, install, uninstall, sign-git
		c("status"), c("--json", "status"), c("status", "--follow"), c("status", "-h"), c("status", "extra"), c("status", "--nope"),
		c("revoke"), c("revoke", "--all"), c("revoke", "--key", "github"), c("revoke", "--session", "s1"), c("revoke", "--app", "com.x"),
		c("revoke", "--all", "--key", "x"), c("revoke", "--key"), c("revoke", "-h"),
		c("config"), c("config", "-h"), c("config", "chek"), c("config", "check"), c("--json", "config", "check"), c("config", "check", "-h"),
		c("config", "apply"), c("config", "apply", "--hash", "abc"), c("config", "apply", "--hash", contractHash), c("config", "apply", "--hash", "a", "--hash", "b"),
		c("config", "apply", "-h"),
		c("trust"), c("trust", "/bin/ls"), c("trust", "--app", "com.googlecode.iterm2"), c("trust", "--app", ""), c("trust", "a", "--app", "x"),
		c("trust", "a", "b"), c("trust", "-h"),
		c("log", "--since", "forever"), c("log", "--since", "0s"), c("log", "extra"), c("log", "summary", "--follow"), c("log", "-h"), c("log", "summary", "-h"),
		c("log", "--since", "1h", "--target", "github", "--caller", "iterm", "--decision", "blocked"), c("log", "summary"), c("log", "sumary"),
		c("apps"), c("apps", "lst"), c("apps", "list"), c("--json", "apps", "list"), c("apps", "-h"), c("apps", "list", "-h"), c("apps", "list", "x"),
		c("ui"), c("ui", "extra"), c("ui", "-h"),
		c("install", "--bin-dir", "rel"), c("install", "-h"), c("install", "extra"), c("install", "--no-links", "--bin-dir", "/x"),
		c("uninstall", "--no-links"), c("uninstall", "-h"), c("uninstall", "--bin-dir", "rel"),
		c("sign-git", "-Y", "sign", "-n", "git", "-f", "/k.pub", "-h"), c("sign-git", "--help"), c("sign-git", "--json", "-y"),
		// Without nazar-agent.
		down("ssh-key", "list"), down("--json", "status"), down("get", "GH_TOKEN"), down("secret", "list"), down("k8s", "list"), down("aws", "list"),
		// The argv[0] entry points.
		{entry: gitCredentialName, args: []string{"get"}, stdin: "protocol=https\nhost=github.com\n\n"},
		{entry: gitCredentialName, args: []string{"get"}, stdin: "protocol=http\nhost=github.com\n\n"},
		{entry: gitCredentialName}, {entry: gitCredentialName, args: []string{"store"}}, {entry: gitCredentialName, args: []string{"get", "-h"}},
		{entry: gitCredentialName, args: []string{"--help"}},
		{entry: "nazar-sign-git", args: []string{"-Y", "sign", "-n", "git", "--help"}}, {entry: "nazar-sign-git", args: []string{"help"}},
	}
}

// helpTexts maps each command's help, and each completion script, to a
// placeholder: their text is not part of the contract (help_test.go checks
// it), only which command line prints which one, on stdout with exit 0.
func helpTexts(t *testing.T, a *app) map[string]string {
	t.Helper()
	m := map[string]string{}
	root := a.commands(false)
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		if c != root {
			var b bytes.Buffer
			c.SetOut(&b)
			if err := c.Help(); err != nil {
				t.Fatal(err)
			}
			c.SetOut(nil)
			m[b.String()] = "<help: " + c.CommandPath() + ">\n"
		}
		for _, s := range c.Commands() {
			visit(s)
		}
	}
	visit(root)
	for _, sh := range []string{"bash", "zsh", "fish"} {
		var b bytes.Buffer
		var err error
		switch sh {
		case "bash":
			err = root.GenBashCompletionV2(&b, true)
		case "zsh":
			err = root.GenZshCompletion(&b)
		case "fish":
			err = root.GenFishCompletion(&b, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		m[b.String()] = "<completion script: " + sh + ">\n"
	}
	return m
}

// runContract runs every case and renders the results the way the golden
// file holds them: the temporary home as $HOME, the usage text as <usage>,
// a help text or completion script as its placeholder.
func runContract(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	h := newHarness(t)
	h.serve(t, contractReply)
	down := newHarness(t)
	helps := helpTexts(t, h.a)
	for _, tc := range contractCases() {
		hh := h
		if tc.noServer {
			hh = down
		}
		hh.execed = nil
		hh.a.stdin = nil
		if tc.stdin != "" || tc.entry == gitCredentialName {
			hh.a.stdin = strings.NewReader(tc.stdin)
		}
		hh.out.Reset()
		hh.errb.Reset()
		hh.a.json = false
		var code int
		switch tc.entry {
		case "":
			code = hh.a.run(tc.args)
		case gitCredentialName:
			code = hh.a.gitCredential(tc.args)
		case "nazar-sign-git":
			code = hh.a.signGit(tc.args)
		}
		norm := func(s string) string {
			if p, ok := helps[s]; ok {
				return p
			}
			s = strings.ReplaceAll(s, usage, "<usage>\n")
			return strings.ReplaceAll(s, hh.home, "$HOME")
		}
		name := tc.entry
		if name == "" {
			name = "nazar"
		}
		fmt.Fprintf(&b, "=== %s %q", name, tc.args)
		if tc.stdin != "" {
			fmt.Fprintf(&b, " stdin=%q", tc.stdin)
		}
		if tc.noServer {
			b.WriteString(" (no nazar-agent)")
		}
		fmt.Fprintf(&b, "\nexit %d\n", code)
		if len(hh.execed) > 0 {
			// The argv only: the environment holds the test's paths.
			argv := hh.execed
			for i, x := range argv {
				if strings.Contains(x, "=") {
					argv = argv[:i]
					break
				}
			}
			fmt.Fprintf(&b, "exec %q\n", argv)
		}
		fmt.Fprintf(&b, "--- stdout\n%s--- stderr\n%s", norm(hh.out.String()), norm(hh.errb.String()))
	}
	return b.String()
}

func TestCLIContract(t *testing.T) {
	got := runContract(t)
	if *updateContract {
		if err := os.WriteFile(contractGolden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(contractGolden)
	if err != nil {
		t.Fatal(err)
	}
	if got == string(want) {
		return
	}
	g, w := strings.SplitAfter(got, "\n=== "), strings.SplitAfter(string(want), "\n=== ")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gi, wi string
		if i < len(g) {
			gi = g[i]
		}
		if i < len(w) {
			wi = w[i]
		}
		if gi != wi {
			t.Fatalf("the CLI's behaviour changed (case %d); got:\n%s\nwant:\n%s", i, gi, wi)
		}
	}
}
