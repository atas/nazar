package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// The command tree (spf13/cobra) is the CLI's help and its shell
// completion, and nothing else. Every command still runs through a.run's
// switch and its own flag.FlagSet: cobra never parses a command line that
// runs, so the arguments, defaults, messages and exit codes are the ones
// the commands always had (TestCLIContract pins them). The flags declared
// here mirror those FlagSets (TestTreeMirrorsTheParsers): they are what
// help shows and completion offers, and they tell helpRequested which flag
// takes the next argument as its value.

func noRun(*cobra.Command, []string) {}

// newCmd is a command that runs (cobra's Runnable, for its usage line);
// its Run is never called.
func newCmd(use, short, long, example string) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, Long: strings.TrimSpace(long), Example: strings.Trim(example, "\n"),
		DisableFlagsInUseLine: true, Run: noRun, ValidArgsFunction: cobra.NoFileCompletions}
}

// newGroup is a command that only holds subcommands.
func newGroup(use, short, long string, subs ...*cobra.Command) *cobra.Command {
	g := &cobra.Command{Use: use, Short: short, Long: strings.TrimSpace(long), DisableFlagsInUseLine: true}
	g.AddCommand(subs...)
	return g
}

// tree builds the command tree. withCompletion also registers the flag
// value completions, which cobra keeps in a process-wide table: only the
// tree that serves `nazar __complete` needs them.
type tree struct {
	a     *app
	comps []func()
}

// flagComp registers fn for the flag once the tree is whole.
func (t *tree) flagComp(c *cobra.Command, name string, fn cobra.CompletionFunc) {
	t.comps = append(t.comps, func() { _ = c.RegisterFlagCompletionFunc(name, fn) })
}

// fixed completes a flag's fixed values ("value\tdescription").
func fixed(values ...string) cobra.CompletionFunc {
	return func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// noValue is a flag whose value can't be completed (a duration, a hash).
func noValue(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

var (
	scopeValues = []string{"use\tasks every time", "session\tonce per terminal tab or tool run", "app\tuntil the app quits"}
	gateValues  = []string{"login\tTouch ID, Apple Watch or password", "dialog\tan Allow / Deny dialog", "none\tsilent: the apps match is the only check", "block\trefused at once"}
	// A key's own gate applies to every caller, so it is never none.
	keyGateValues   = []string{gateValues[0], gateValues[1], gateValues[3]}
	shellValues     = []string{"bash", "zsh", "fish"}
	decisionValues  = []string{"allowed\tcovered by an approval (or gate none)", "approved\tapproved at the gate just now", "denied", "timeout", "blocked", "error"}
	matcherHelpText = `M is an apps: name, any, unknown, app:<bundle-id>, signed:<team>[:<id>] or path:<path>.
--apps and --to take a comma-separated list and may be given more than once.`
)

const (
	gateUsage   = "what has to happen, `G`: login (Touch ID, Watch or password), dialog (Allow/Deny), none or block"
	scopeUsage  = "how long one approval lasts, `S`: use (asks every time), session (once per terminal tab or tool run) or app (until the app quits)"
	expireUsage = "the longest an approval lasts, `D` such as 8h or 7d"
	ifHashUsage = "refuse the edit if config.yaml no longer has the hash `H` (configHash in --json output)"
	allowUsage  = "make the change even if it loosens access: it is written and asks for your Touch ID at once (without it, such a change is refused and only shown)"
	loosenHelp  = `
A change that loosens access is made only with --allow-loosen-access: it is written to
config.yaml and asks for your Touch ID / Watch / password at once (exit 3 if denied; the change
then stays in config.yaml and ` + "`nazar config apply`" + ` asks again). Without the flag nazar
refuses it, prints what it would loosen and the command to run (exit 2), and changes nothing: an
agent can show you the rule without touching the file. A change that tightens applies at once.`
)

// commands returns the command tree. It names every command a.run
// dispatches (TestTreeNamesEveryCommand).
func (a *app) commands(withCompletion bool) *cobra.Command {
	t := &tree{a: a}
	root := &cobra.Command{
		Use:   "nazar",
		Short: "nazar keeps SSH keys, secrets, Kubernetes and AWS CAs in the Secure Enclave and decides, per app, who may use them",
		// cobra prints nothing and adds no commands or flags of its own: the
		// completion command is completionCmd, help is a.help.
		SilenceErrors: true, SilenceUsage: true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	root.PersistentFlags().Bool("json", false, "print one JSON object per line, for scripts and agents (a problem too, on stdout)")
	root.PersistentFlags().BoolP("yes", "y", false, "accepted for scripts; nazar never asks in the terminal")

	root.AddCommand(
		t.sshKeyCmd(), t.secretCmd(), t.getCmd(), t.runCmd(), t.k8sCmd(), t.awsCmd(), t.appsCmd(), t.statusCmd(), t.revokeCmd(),
		t.configCmd(), t.trustCmd(), t.logCmd(), t.signGitCmd(), t.installCmd(), t.uninstallCmd(), t.uiCmd(),
		newCmd("version", "Print nazar's version", "Print nazar's version (with --json, also the API version).", "  nazar version\n  nazar --json version"),
		t.completionCmd(),
	)
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		c.InitDefaultHelpFlag()
		c.SuggestionsMinimumDistance = 2 // cobra's default, which it sets only in Execute
		for _, s := range c.Commands() {
			visit(s)
		}
	}
	visit(root)
	if withCompletion {
		for _, f := range t.comps {
			f()
		}
	}
	return root
}

func (t *tree) completionCmd() *cobra.Command {
	c := newCmd("completion bash|zsh|fish", "Print the shell completion script for bash, zsh or fish", `
Print the shell completion script for bash, zsh or fish to stdout.

Completion offers commands, flags and their values, and the names of your keys, secrets,
contexts and apps. Names come from nazar-agent through the read-only list calls that
`+"`nazar ssh-key list`"+` and the other lists make; completing never asks for Touch ID, never shows
a dialog, never changes anything, and offers no names when nazar-agent isn't running.
nazar never edits a shell's startup file: add the line for your shell yourself.`, `
  # zsh: in ~/.zshrc, after compinit
  source <(nazar completion zsh)

  # bash: in ~/.bashrc (needs the bash-completion package)
  source <(nazar completion bash)

  # fish: in ~/.config/fish/config.fish
  nazar completion fish | source`)
	c.ValidArgsFunction = func(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return shellValues, cobra.ShellCompDirectiveNoFileComp
	}
	return c
}

// nameArg completes the first argument from names and nothing after it.
func nameArg(names func() []string) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return names(), cobra.ShellCompDirectiveNoFileComp
	}
}

func (t *tree) sshKeyCmd() *cobra.Command {
	a := t.a
	create := newCmd("create <name> [--always-ask] [--only-when-unlocked]", "Create an SSH key in the Secure Enclave (Touch ID once)", `
Create an SSH key in the Secure Enclave. Touch ID once.

nazar-agent writes the key's entry in config.yaml: its own gate block, plus a login rule for
the terminal app the command is typed in (none when it is not typed in a terminal, so the key
is blocked for every app until you add a rule). The public key is written to
~/.nazar/keys/<name>.pub.

--always-ask makes the chip ask for Touch ID on every use; nazar then refuses any looser rule
for the key. --only-when-unlocked makes the chip refuse the key while the Mac is locked;
without it the key also works while the Mac is locked, once you have logged in since it
started. Both are fixed for the key's life.`, `
  nazar ssh-key create github
  nazar ssh-key create hydra --always-ask
  nazar ssh-key create deploy --only-when-unlocked`)
	create.Flags().Bool("always-ask", false, "Touch ID on every use, enforced by the chip; nazar refuses looser rules for this key")
	create.Flags().Bool("only-when-unlocked", false, "the chip refuses the key while the Mac is locked")

	list := newCmd("list", "List SSH keys: type, fingerprint, number of rules", `
List the SSH keys: name, type, fingerprint and number of rules, and a fix for a key nazar-agent
can't read. With --json each key also has its rules, warnings and last use.`, "  nazar ssh-key list\n  nazar --json ssh-key list")

	pubkey := newCmd("pubkey <name>", "Print a key's OpenSSH public key", "Print a key's OpenSSH public key line.",
		"  nazar ssh-key pubkey github | pbcopy")
	pubkey.ValidArgsFunction = nameArg(a.keyNames)

	del := newCmd("delete <name>", "Delete an SSH key for good (Touch ID)", `
Delete an SSH key from the Secure Enclave, for good. Touch ID. config.yaml keeps its entry.`,
		"  nazar ssh-key delete old-laptop")
	del.ValidArgsFunction = nameArg(a.keyNames)

	rules := newCmd("rules <name>", "Show a key's rules and what other callers get", `
Show a key's rules, numbered from 1 as rule set and rule remove take them (first match wins),
and what callers no rule matches get.`, "  nazar ssh-key rules github")
	rules.ValidArgsFunction = nameArg(a.keyNames)

	set := newCmd("set <key> [--scope S] [--gate G] [--expire D | --no-expire] [--allow-loosen-access]", "Set what callers no rule matches get: the key's own gate", `
Set the key's own scope, gate and expire: what callers no rule matches get. Its gate is login,
dialog or block (never none: it applies to every caller; add a rule with --apps instead).
`+loosenHelp,
		"  nazar ssh-key set github --gate block\n  nazar ssh-key set github --gate dialog --scope session --expire 8h --allow-loosen-access")
	set.ValidArgsFunction = nameArg(a.keyNames)
	set.Flags().String("scope", "", scopeUsage)
	set.Flags().String("gate", "", "callers no rule matches: `G` is login, dialog or block")
	set.Flags().String("expire", "", expireUsage)
	set.Flags().Bool("no-expire", false, "remove the expire")
	set.Flags().Bool("allow-loosen-access", false, allowUsage)
	set.Flags().String("if-hash", "", ifHashUsage)
	t.flagComp(set, "scope", fixed(scopeValues...))
	t.flagComp(set, "gate", fixed(keyGateValues...))
	t.flagComp(set, "expire", noValue)
	t.flagComp(set, "if-hash", noValue)

	return newGroup("ssh-key", "Create, list and delete SSH keys, and edit who may use them", `
Create, list and delete the SSH keys in the Secure Enclave, and edit who may use them.

A key's rules say who may use it (--apps), what has to happen (--gate) and how long one
approval lasts (--scope); callers no rule matches get the key's own gate (ssh-key set).`,
		create, list, pubkey, del, rules, t.ruleCmd(keyTarget, "key", "github", a.keyNames), set)
}

// ruleCmd is `<cmd> rule add|set|remove` for keys, secrets, k8s contexts
// and aws entries; its flags mirror ruleEdit's FlagSets.
func (t *tree) ruleCmd(target ruleTarget, what, example string, names func() []string) *cobra.Command {
	a := t.a
	k8s := target.noTo != ""
	toMeta := " [--to M[,M]]"
	setToMeta := " [--to M[,M] | --no-to]"
	if k8s {
		toMeta, setToMeta = "", ""
	}
	cmdPath := "nazar " + target.cmd + " rule"
	loosen := loosenHelp
	matchers := matcherHelpText
	if k8s {
		matchers = strings.Replace(matchers, "--apps and --to take", "--apps takes", 1)
	}
	extra := ""
	switch target.cmd {
	case "secret":
		extra = "\n\nA secret's own gate stays block: callers no rule matches are refused."
	case "k8s":
		extra = "\n\nk8s rules take no --to: the program that runs the plugin (kubectl, helm, k9s …) receives the\ncredential. Rules are judged on whoever ran that program, never on the program itself. The\ncontext's own gate stays block."
	case "aws":
		extra = "\n\naws rules take no --to: the program that runs credential_process (the AWS CLI, an SDK,\nterraform …) receives the credential. Rules are judged on whoever ran that program, never on the\nprogram itself. The entry's own gate stays block."
	}
	ruleNumber := func(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			return names(), cobra.ShellCompDirectiveNoFileComp
		case 1:
			return a.ruleNumbers(target, args[0]), cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	policyFlags := func(c *cobra.Command, set bool) {
		c.Flags().StringArray("apps", nil, "who asks: `M[,M]`, matchers as above")
		c.Flags().StringArray("to", nil, "who receives the result: `M[,M]` (for a key, the process on the agent socket, normally ssh)")
		c.Flags().String("scope", "", scopeUsage)
		c.Flags().String("gate", "", gateUsage)
		c.Flags().String("expire", "", expireUsage)
		c.Flags().Bool("no-expire", false, "remove the rule's expire")
		if set || k8s {
			c.Flags().Bool("no-to", false, "remove the rule's to:, so any receiver matches")
		}
		if k8s {
			_ = c.Flags().MarkHidden("to") // registered to be refused with the reason
			_ = c.Flags().MarkHidden("no-to")
		}
		if !set {
			_ = c.Flags().MarkHidden("no-expire") // for rule set; add refuses it with the reason
		}
		t.flagComp(c, "apps", a.completeMatchers)
		t.flagComp(c, "to", a.completeMatchers)
		t.flagComp(c, "scope", fixed(scopeValues...))
		t.flagComp(c, "gate", fixed(gateValues...))
		t.flagComp(c, "expire", noValue)
	}

	add := newCmd("add <"+what+"> --apps M[,M]"+toMeta+" --gate G [--scope S] [--expire D] [--at N] [--allow-loosen-access]", "Add a rule for a "+what, `
Add a rule for a `+what+`: the apps it matches (--apps), what has to happen (--gate) and how long
one approval lasts (--scope, default use). Rules are tried in order, first match wins; --at N
puts the new rule at number N (default: after the others).

`+matchers+extra+"\n"+loosen,
		ruleExamples(target.cmd, "add", example))
	add.ValidArgsFunction = nameArg(names)
	policyFlags(add, false)
	add.Flags().String("at", "", "put the rule at number `N` (first match wins; default: last)")
	t.flagComp(add, "at", func(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return a.ruleNumbers(target, args[0]), cobra.ShellCompDirectiveNoFileComp
	})

	set := newCmd("set <"+what+"> <n> [--apps M[,M]]"+setToMeta+" [--scope S] [--gate G] [--expire D | --no-expire] [--allow-loosen-access]", "Change rule n of a "+what, `
Change rule n of a `+what+` (numbered from 1, as `+rulesCommand(target.cmd)+` shows them): only
the flags you give change.

`+matchers+extra+"\n"+loosen, ruleExamples(target.cmd, "set", example))
	set.ValidArgsFunction = ruleNumber
	policyFlags(set, true)

	remove := newCmd("remove <"+what+"> <n> [--allow-loosen-access]", "Remove rule n of a "+what, `
Remove rule n of a `+what+` (numbered from 1, as `+rulesCommand(target.cmd)+` shows them).
Removing a rule normally tightens access and applies at once; when it loosens (a later, looser
rule then matches), it is made only with --allow-loosen-access, as a rule add.`, ruleExamples(target.cmd, "remove", example))
	remove.ValidArgsFunction = ruleNumber

	for _, c := range []*cobra.Command{add, set, remove} {
		c.Flags().Bool("allow-loosen-access", false, allowUsage)
		c.Flags().String("if-hash", "", ifHashUsage)
		t.flagComp(c, "if-hash", noValue)
	}
	return newGroup("rule", "Add, change or remove a "+what+"'s rules", "Add, change or remove a "+what+"'s rules ("+cmdPath+" add|set|remove)."+extra,
		add, set, remove)
}

// rulesCommand is where a target's rule numbers are shown.
func rulesCommand(cmd string) string {
	switch cmd {
	case "secret":
		return "`nazar --json secret list`"
	case "k8s":
		return "`nazar k8s list`"
	case "aws":
		return "`nazar aws list`"
	}
	return "`nazar ssh-key rules`"
}

func ruleExamples(cmd, sub, name string) string {
	switch cmd + " " + sub {
	case "ssh-key add":
		return "  nazar ssh-key rule add " + name + " --apps app:com.googlecode.iterm2 --gate login --scope session\n" +
			"  nazar ssh-key rule add " + name + " --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session --at 1"
	case "secret add":
		return "  nazar secret rule add " + name + " --apps app:com.googlecode.iterm2 --to signed:apple:com.apple.git-remote-http --gate login --scope session"
	case "k8s add":
		return "  nazar k8s rule add " + name + " --apps app:com.googlecode.iterm2 --gate login --scope session"
	case "aws add":
		return "  nazar aws rule add " + name + " --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session"
	}
	if sub == "set" {
		return "  nazar " + cmd + " rule set " + name + " 2 --gate login\n  nazar " + cmd + " rule set " + name + " 1 --expire 8h"
	}
	return "  nazar " + cmd + " rule remove " + name + " 2"
}

func (t *tree) secretCmd() *cobra.Command {
	a := t.a
	add := newCmd("add <name> [--only-when-unlocked]", "Store a secret, read from stdin or a hidden prompt (Touch ID once)", `
Store a secret (an API token, say), sealed to its own Secure Enclave key. Touch ID once.

The value is read from stdin, or typed at a hidden prompt; it is never an argument (an argument
is visible in ps). The prompt takes one line of at most about 1000 bytes; pipe anything longer
or with several lines. nazar-agent writes the secret's entry under secrets: in config.yaml:
blocked, plus a login rule for the terminal app it is typed in. --only-when-unlocked makes the
chip refuse the secret while the Mac is locked. To change a value, rm the secret and add it again.`, `
  printf '%s' "$TOKEN" | nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN
  nazar secret add NOTES < notes.txt
  nazar secret add NOTES                  # typed at a hidden prompt`)
	add.Flags().Bool("only-when-unlocked", false, "the chip refuses the secret while the Mac is locked")

	list := newCmd("list", "List secrets (names, never values)", `
List the secrets: name, when stored, number of rules, state. Never a value. With --json each
secret also has its rules (numbered as secret rule set and remove take them).`, "  nazar secret list\n  nazar --json secret list")

	rm := newCmd("rm <name>", "Erase a secret for good (Touch ID)", "Erase a secret's value for good. Touch ID. config.yaml keeps its entry.",
		"  nazar secret rm NOTES")
	rm.ValidArgsFunction = nameArg(a.secretNames)

	return newGroup("secret", "Store, list and erase secrets, and edit who may receive them", `
Store, list and erase secrets (API tokens), and edit who may receive them. A secret's rules
are a key's, with the same flags; git gets one through git-credential-nazar, a script through
`+"`nazar get`"+`, a Node or Python program through `+"`nazar run`"+`.`,
		add, list, rm, t.ruleCmd(secretTarget, "secret", "GH_TOKEN", a.secretNames))
}

func (t *tree) getCmd() *cobra.Command {
	c := newCmd("get <name>", "Print a secret's value to stdout, for a script", `
Print a secret's value and a newline to stdout, nothing else; exit 3 and nothing printed when
refused. It needs stdout in the secret's deliver: and a rule whose to: names what runs the
script. git uses git-credential-nazar instead.`, "  nazar get API_TOKEN | some-tool --token-stdin")
	c.ValidArgsFunction = nameArg(t.a.secretNames)
	return c
}

func (t *tree) runCmd() *cobra.Command {
	c := newCmd("run --secret <name> -- <command> [args...]", "Run a program with a secret in its environment", `
Run a Node or Python program (node, python3 or npx) with a secret in its environment: the value
is never on disk, on a command line or in the environment nazar starts with. Everything after
-- is the program's command line, passed on untouched (its own -h or --json too).

The secret needs late-env in its deliver: and a rule whose to: names that exact command line.
Refused at the prompt or before it, nazar run exits 3 and nothing runs; refused after the exec,
the program runs without the value and prints `+"`nazar: secret NAME not delivered: <why>`"+`.`, `
  nazar run --secret BRAVE_API_KEY -- npx -y @brave/brave-search-mcp-server`)
	c.Flags().String("secret", "", "the secret to put in the program's environment, by `name`")
	t.flagComp(c, "secret", func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return t.a.secretNames(), cobra.ShellCompDirectiveNoFileComp
	})
	c.ValidArgsFunction = func(cmd *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if cmd.Flags().ArgsLenAtDash() >= 0 {
			return nil, cobra.ShellCompDirectiveDefault // the program's command line: the shell's own completion
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return c
}

func (t *tree) k8sCmd() *cobra.Command {
	a := t.a
	create := newCmd("create [<context> [<server>]] [--only-when-unlocked]", "Set a context up: a CA in the Secure Enclave, its rules and kubeconfig entries", `
Set a Kubernetes context up: a certificate authority for it in the Secure Enclave, its entry
in config.yaml (blocked, plus a login rule for the terminal app it is typed in), and three
kubeconfig entries (the context, and the cluster and user nazar-<context>). One Touch ID covers it all. It then prints the steps that make the cluster
trust the CA; nazar never touches the cluster.

At a terminal it asks for the context name, the server and the server's CA, with defaults from
the kubeconfig's current context. Without a terminal give both arguments; the CA is then the
one of the kubeconfig cluster with exactly that server. --only-when-unlocked makes the chip
refuse the CA while the Mac is locked (fixed for its life).`, `
  nazar k8s ca create
  nazar k8s ca create hydra-nazar https://hydra.example:16443`)
	create.Flags().Bool("only-when-unlocked", false, "the chip refuses the CA while the Mac is locked")

	show := newCmd("show <context> [--microk8s]", "Print a context's CA certificate, or the microk8s steps", `
Print a context's CA certificate (PEM), or with --microk8s the steps that make a microk8s API
server trust it (run them on the node; nazar never does).`, "  nazar k8s ca show hydra-nazar --microk8s")
	show.Flags().Bool("microk8s", false, "print the steps that add the CA to microk8s instead")
	show.ValidArgsFunction = nameArg(a.contextNames)

	list := newCmd("list", "List contexts, their CAs and rules", "List the k8s contexts: identity, cluster, rules and CA.", "  nazar k8s list")

	forget := newCmd("forget <context>", "Delete a context's CA, its config entry and nazar's kubeconfig entries (Touch ID)", `
Delete a context's CA from the Secure Enclave and its entry from config.yaml (Touch ID), then
remove nazar's three kubeconfig entries while they are exactly as nazar wrote them (it names any
others for you to remove). Certificates already handed out stay valid until they end.`, "  nazar k8s forget hydra-nazar")
	forget.ValidArgsFunction = nameArg(a.contextNames)

	// kubectl runs it from the kubeconfig's exec entry; people don't.
	cred := newCmd("credential <context>", "kubectl's exec credential plugin (run by kubectl, not by people)", "", "")
	cred.Hidden = true
	cred.ValidArgsFunction = nil

	ca := newGroup("ca", "Create a context's CA, or show it", "Create a context's certificate authority in the Secure Enclave, or show it.", create, show)
	return newGroup("k8s", "Stand in for a cluster's admin credential: a CA in the Secure Enclave per context", `
Stand in for a self-managed cluster's admin credential (microk8s, kubeadm): nazar keeps a
certificate authority per context in the Secure Enclave and gives kubectl a fresh client
certificate, valid 15 minutes, each time your rules allow it. kubectl runs
`+"`nazar k8s credential <context>`"+` itself.`,
		ca, list, t.ruleCmd(k8sTarget, "context", "hydra-nazar", a.contextNames), forget, cred)
}

func (t *tree) awsCmd() *cobra.Command {
	a := t.a
	create := newCmd("create <name> [--only-when-unlocked]", "Set an entry up: a CA in the Secure Enclave and its rules", `
Set an AWS entry up: a certificate authority for it in the Secure Enclave and its entry in
config.yaml (blocked, plus a login rule for the terminal app it is typed in). One Touch ID
covers it all. It then prints the AWS-side steps (a trust
anchor, a role, a profile), the ARNs to add to the entry and the ~/.aws/config lines; nazar
never runs them, never edits ~/.aws and never calls AWS for setup. --only-when-unlocked makes
the chip refuse the CA while the Mac is locked (fixed for its life).`, `
  nazar aws ca create dev
  nazar aws ca create prod --only-when-unlocked`)
	create.Flags().Bool("only-when-unlocked", false, "the chip refuses the CA while the Mac is locked")

	show := newCmd("show <name>", "Print an entry's CA certificate", `
Print an entry's CA certificate (PEM), as the trust anchor holds it.`, "  nazar aws ca show dev")
	show.ValidArgsFunction = nameArg(a.awsNames)

	list := newCmd("list", "List entries, their CAs and rules", "List the aws entries: identity, role, trust anchor, profile, rules and CA.", "  nazar aws list")

	forget := newCmd("forget <name>", "Delete an entry's CA and its config entry (Touch ID)", `
Delete an entry's CA from the Secure Enclave and its entry from config.yaml (Touch ID). Sessions
already handed out stay valid until they end; disable or delete the trust anchor in AWS, and
remove the profile's credential_process line from ~/.aws/config yourself.`, "  nazar aws forget dev")
	forget.ValidArgsFunction = nameArg(a.awsNames)

	// The AWS CLI and SDKs run it from ~/.aws/config; people don't.
	cred := newCmd("credential <name>", "credential_process for the AWS CLI and SDKs (run by them, not by people)", "", "")
	cred.Hidden = true
	cred.ValidArgsFunction = nil

	ca := newGroup("ca", "Create an entry's CA, or show it", "Create an entry's certificate authority in the Secure Enclave, or show it.", create, show)
	return newGroup("aws", "AWS session credentials through IAM Roles Anywhere: a CA in the Secure Enclave per entry", `
Give the AWS CLI and SDKs short-lived session credentials through IAM Roles Anywhere: nazar
keeps a certificate authority per entry in the Secure Enclave, and each time your rules allow
it mints a certificate for one CreateSession call and hands the session to the client. No
long-lived AWS key exists anywhere. The AWS CLI runs `+"`nazar aws credential <name>`"+` itself
(credential_process).`,
		ca, list, t.ruleCmd(awsTarget, "entry", "dev", a.awsNames), forget, cred)
}

func (t *tree) appsCmd() *cobra.Command {
	list := newCmd("list", "List the apps: matchers, pinned teams and the rules that use them", `
List the top-level apps: matchers and the ones written inline in rules: the team pinned for an
app: matcher, what keeps one from matching and its fix, and the rules that use it.`, "  nazar apps list")
	return newGroup("apps", "List the app matchers nazar knows", "List the app matchers nazar knows (nazar apps list).", list)
}

func (t *tree) statusCmd() *cobra.Command {
	c := newCmd("status [--follow]", "Show the agent, approvals, staged config, and what is not wired to nazar", `
Show the agent socket, the current approvals and what each covers, a staged config change,
vault items nazar-agent can't use, and setup: lines naming what of ssh and git is not wired to
nazar, each with its fix. It edits nothing.`, "  nazar status\n  nazar status --follow")
	c.Flags().Bool("follow", false, "keep running and print approvals as they are added and removed")
	return c
}

func (t *tree) revokeCmd() *cobra.Command {
	a := t.a
	c := newCmd("revoke --all | --key <name> | --session <id> | --app <bundle-id>", "Forget remembered approvals now", `
Forget remembered approvals now: all of them, a key's, a session's or an app's. Exactly one
selector; a bare revoke is refused. Revoking tightens access, so it applies at once.`,
		"  nazar revoke --all\n  nazar revoke --key github")
	c.Flags().Bool("all", false, "every approval")
	c.Flags().String("key", "", "the approvals of the key `name`")
	c.Flags().String("session", "", "the approvals of the session `id` (nazar status shows it)")
	c.Flags().String("app", "", "the approvals of the app `bundle-id`")
	t.flagComp(c, "key", func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return a.keyNames(), cobra.ShellCompDirectiveNoFileComp
	})
	t.flagComp(c, "session", noValue)
	t.flagComp(c, "app", a.completeBundleIDs)
	return c
}

func (t *tree) configCmd() *cobra.Command {
	check := newCmd("check", "Check config.yaml without applying it", `
Check config.yaml without applying it: its problems, and the change staged in it, if any.`, "  nazar config check")
	apply := newCmd("apply", "Approve the change staged in config.yaml (Touch ID)", `
Show the change staged in config.yaml (one made by hand, or one a nazar command left waiting
because its prompt was denied or could not be shown) and ask for your Touch ID / Watch /
password. Exactly the change shown is approved: when config.yaml changes in between, nothing
is asked.`, "  nazar config apply")
	return newGroup("config", "Check config.yaml, or approve its staged change", "Check config.yaml, or approve the change staged in it.", check, apply)
}

func (t *tree) trustCmd() *cobra.Command {
	c := newCmd("trust --app <bundle-id>", "Pin an installed app's team for app: matchers (Touch ID)", `
Pin the team of an installed app for app: matchers, after an update that changed the app's
signing team (approving a config pins it the first time). It loosens access: Touch ID.`,
		"  nazar trust --app com.googlecode.iterm2")
	c.Flags().String("app", "", "pin the installed app `bundle-id`")
	t.flagComp(c, "app", t.a.completeBundleIDs)
	c.ValidArgsFunction = func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return c
}

func (t *tree) logCmd() *cobra.Command {
	a := t.a
	filters := func(c *cobra.Command, since string) {
		c.Flags().Bool("follow", false, "keep running and print new entries as they come")
		c.Flags().String("since", since, "how far back to read, `D` such as 1h, 24h or 7d")
		c.Flags().String("target", "", "only entries about `T`: ssh:<key> (or just the key's name), secret:<name>, k8s:<context> or aws:<name>")
		c.Flags().String("caller", "", "only entries whose caller is `C`")
		c.Flags().String("decision", "", "only entries with decision `D`: allowed, approved, denied, timeout, blocked or error")
		t.flagComp(c, "since", fixed("1h", "24h", "7d"))
		t.flagComp(c, "target", a.completeTargets)
		t.flagComp(c, "caller", noValue)
		t.flagComp(c, "decision", fixed(decisionValues...))
	}
	summary := newCmd("summary [--since 7d]", "Count decisions and callers per target", `
Count, per key, secret or context, the decisions and the callers in the macOS log. Takes the
filters of nazar log, without --follow.`, "  nazar log summary --since 7d")
	filters(summary, "7d")
	_ = summary.Flags().MarkHidden("follow") // refused with the reason
	c := newCmd("log [--follow] [--since 24h] [--target T] [--caller C] [--decision D]", "Show who used your keys, secrets and contexts", `
Show nazar's entries in the macOS log: every request, who asked, and what was decided. Only
entries written by nazar-agent itself are shown.`, `
  nazar log --since 1h
  nazar log --since 10m --decision blocked
  nazar log --target secret:GH_TOKEN --since 10m
  nazar log summary --since 7d`)
	filters(c, "24h")
	c.AddCommand(summary)
	return c
}

func (t *tree) signGitCmd() *cobra.Command {
	c := newCmd("sign-git <ssh-keygen args>", "git's gpg.ssh.program: ssh-keygen through nazar's agent", `
git's gpg.ssh.program, installed as ~/.local/bin/nazar-sign-git: it runs /usr/bin/ssh-keygen
with git's arguments, byte for byte, and SSH_AUTH_SOCK pointed at nazar's agent. Every argument
is ssh-keygen's, -h and --help too; git runs it, not people.`, "  git config --global gpg.ssh.program ~/.local/bin/nazar-sign-git")
	// Its arguments are ssh-keygen's: no flag of nazar's, and no help.
	c.DisableFlagParsing = true
	c.ValidArgsFunction = nil
	return c
}

func (t *tree) installCmd() *cobra.Command {
	c := newCmd("install [--bin-dir DIR | --no-links]", "Install nazar-agent's LaunchAgent and the nazar links", `
Set up the LaunchAgent for the nazar-agent.app this CLI ships in, the private ~/.nazar folder,
and the links nazar, nazar-sign-git and git-credential-nazar in the bin folder. Run it from the
CLI inside nazar-agent.app; run it again to repair the setup or after moving the app. It never
touches keys, config or shell startup files.`, "  /Applications/nazar-agent.app/Contents/MacOS/nazar install")
	c.Flags().String("bin-dir", "~/.local/bin", "where the links go: `DIR`, an absolute path")
	c.Flags().Bool("no-links", false, "make no links (a package manager links the CLI itself)")
	t.flagComp(c, "bin-dir", dirValue)
	return c
}

func (t *tree) uninstallCmd() *cobra.Command {
	c := newCmd("uninstall [--bin-dir DIR]", "Remove nazar-agent's LaunchAgent and the nazar links", `
Stop and remove nazar-agent's LaunchAgent and the links in the bin folder that point into a
nazar bundle. Keys, config and the Keychain items are kept.`, "  nazar uninstall")
	c.Flags().String("bin-dir", "~/.local/bin", "where the links are: `DIR`, an absolute path")
	t.flagComp(c, "bin-dir", dirValue)
	return c
}

func dirValue(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveFilterDirs
}

func (t *tree) uiCmd() *cobra.Command {
	return newCmd("ui", "Open Nazar UI.app, if it is installed", `
Open Nazar UI.app through Launch Services, if it is installed. It is optional: everything it
does is a nazar command.`, "  nazar ui")
}

// find walks args from the root along subcommand names, the way a.run's
// switch and each command's own switch take them (always the first
// argument left), and returns the command reached and the arguments after
// its name.
func find(root *cobra.Command, args []string) (*cobra.Command, []string) {
	c := root
	for len(args) > 0 {
		var next *cobra.Command
		for _, s := range c.Commands() {
			if s.Name() == args[0] {
				next = s
				break
			}
		}
		if next == nil {
			break
		}
		c, args = next, args[1:]
	}
	return c, args
}

// passthrough reports whether a command's arguments belong to another
// program: sign-git's are ssh-keygen's, k8s credential's come from the
// kubeconfig for kubectl's exec plugin, and aws credential's from
// ~/.aws/config. None ever shows help.
func passthrough(c *cobra.Command) bool {
	switch c.CommandPath() {
	case "nazar sign-git", "nazar k8s credential", "nazar aws credential":
		return true
	}
	return false
}

// helpRequested reports whether args, after command c's name, ask for its
// help: when Go's flag package, parsing them as the command's FlagSet does
// (a.parseArgs: flags and positionals in any order, everything after `--`
// positional), would stop at -h, -help, --h or --help (flag.ErrHelp,
// which the commands always reported as a usage error). It stops where the
// parse would fail first, at an unknown flag or bad syntax, and steps over
// the value of a flag that takes one, so `--apps -h` is still the value
// "-h". Only run's arguments before its first `--` are its own.
func helpRequested(c *cobra.Command, args []string) bool {
	if passthrough(c) {
		return false
	}
	if c.CommandPath() == "nazar run" {
		for i, x := range args {
			if x == "--" {
				args = args[:i]
				break
			}
		}
	}
	flags := c.LocalNonPersistentFlags()
	for i := 0; i < len(args); i++ {
		s := args[i]
		if len(s) < 2 || s[0] != '-' {
			continue // a positional
		}
		name := s[1:]
		if name[0] == '-' {
			if name = name[1:]; name == "" {
				return false // `--`: the rest is positional
			}
		}
		if name == "" || name[0] == '-' || name[0] == '=' {
			return false // bad flag syntax
		}
		name, _, hasValue := strings.Cut(name, "=")
		if name == "h" || name == "help" {
			return true
		}
		f := flags.Lookup(name)
		if f == nil || f.Name == "help" {
			return false // flag provided but not defined
		}
		if f.NoOptDefVal == "" && !hasValue {
			i++ // its value, whatever it looks like
		}
	}
	return false
}

// help prints the help of the command args name: the usage text for nazar
// itself, cobra's help (usage, flags, examples) for a command.
func (a *app) help(args []string) int {
	root := a.commands(false)
	c, _ := find(root, args)
	return a.showHelp(root, c)
}

func (a *app) showHelp(root, c *cobra.Command) int {
	if c == root {
		fmt.Fprint(a.stdout, usage)
		return 0
	}
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	if err := c.Help(); err != nil {
		return a.fail(err)
	}
	return 0
}

// suggestions are cobra's "did you mean" for an unknown command or
// subcommand: c holds only subcommands and args[0] names none of them.
func suggestions(c *cobra.Command, args []string) []string {
	if c.Runnable() || len(args) == 0 || strings.HasPrefix(args[0], "-") || args[0] == "" {
		return nil
	}
	return c.SuggestionsFor(args[0])
}
