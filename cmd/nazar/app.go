package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

// version is what `nazar version` prints. `make agent` sets it to the
// bundle's CFBundleShortVersionString (-ldflags -X main.version=…), so the
// CLI and the agent it ships in say the same; a plain `go build` says dev.
var version = "0.1.0-dev"

// app holds everything the CLI touches, so tests can replace it. The CLI
// never asks for approval in the terminal (spec 6); approval happens on
// nazar-agent's own gate. stdin is read by two commands only: `secret add`,
// for the value (never an argument, secrets design 7.1), and `k8s ca
// create` at a terminal, for the context, the server and its CA.
type app struct {
	stdout, stderr io.Writer
	stdin          io.Reader
	// stdinTerminal reports whether stdin is a terminal, and readHidden
	// reads one line from it with echo off (nil = no hidden prompt).
	stdinTerminal func() bool
	readHidden    func() ([]byte, error)
	getenv        func(string) string
	environ       func() []string
	exec          func(argv0 string, argv []string, envv []string) error
	// resetForExec readies the process for nazar run's exec: the folder
	// dirFD names becomes the working directory, and the process state the
	// caller left (fds, umask, core limit, signals, and on macOS the Mach
	// exception ports) is reset. nil refuses every run.
	resetForExec func(dirFD int) error
	runLog       func(ctx context.Context, args []string, line func([]byte)) error
	verifier     control.PeerVerifier // nil = a.defaultVerifier()
	// executable returns the CLI's own path with symlinks resolved, and
	// plistProgram ProgramArguments[0] of a LaunchAgent plist; together
	// they locate the Nazar.app to trust (appident.go).
	executable   func() (string, error)
	plistProgram func(plist string) (string, error)
	// selfTeam is the team of the CLI's own signature ("" ad hoc) and
	// designated a bundle's designated requirement: together they name the
	// agent the CLI trusts (verifier.go).
	selfTeam   func() (string, error)
	designated func(path string) (string, error)
	// imageUUID returns an executable's Mach-O LC_UUID (machoUUID); the
	// log keeps only entries whose sender has the trusted app's UUID.
	imageUUID func(path string) (string, error)
	// launchctl runs /bin/launchctl and uid is the user ID (install).
	// Tests always replace launchctl; a nil one refuses to install.
	launchctl func(args ...string) error
	uid       func() int
	// openUI opens the app Launch Services has for a bundle id and
	// returns its path (errUINotInstalled when there is none): `nazar ui`.
	openUI func(bundleID string) (string, error)
	// sleep waits between launchctl polls (nil = time.Sleep).
	sleep func(time.Duration)
	// output runs a program by absolute path with the CLI's environment and
	// returns its stdout (the client-side checks of `status`: ssh -G,
	// xcode-select, git config); nil = those checks are skipped. Tests
	// replace it; main sets runOutput.
	output func(ctx context.Context, argv0 string, args ...string) ([]byte, error)
	// accountHome is the account's home in the user database (ssh's, not
	// $HOME); the ssh checks run only when $HOME is it.
	accountHome func() string
	// selfPath is the absolute path this CLI was started by, links not
	// resolved: what nazar k8s ca create writes into a kubeconfig and aws
	// ca create prints for ~/.aws/config.
	selfPath func() (string, error)

	json bool
	// suggest is cobra's "did you mean" for this command line's unknown
	// command or subcommand, printed under a human usage error.
	suggest []string
	// helpFor is the command this command line names ("k8s ca create"):
	// a usage error points at its help instead of printing every command.
	helpFor string
	// argv is this run's command line as given (after the program name):
	// what a refused loosening is told to run again with
	// --allow-loosen-access (suggestedCommand).
	argv []string
}

const usage = `usage: nazar [--json] [--yes] <command> [args]

  ssh-key create <name> [--always-ask] [--only-when-unlocked]
      (the terminal it is typed in gets a login rule; --always-ask: Touch ID
       on every use, enforced by the chip; nazar refuses looser rules for it;
       --only-when-unlocked: the chip refuses the key while the Mac is locked,
       as it does for --always-ask; without it the key works while locked too)
  ssh-key list
  ssh-key pubkey <name>
  ssh-key delete <name>
  ssh-key rules <name>
  ssh-key rule add <key> --apps M[,M] [--to M[,M]] --gate G [--scope S] [--expire D] [--at N]
  ssh-key rule set <key> <n> [--apps M[,M]] [--to M[,M] | --no-to] [--scope S] [--gate G] [--expire D | --no-expire]
  ssh-key rule remove <key> <n>
  ssh-key set <key> [--scope S] [--gate login|dialog|block] [--expire D | --no-expire]
      (rule and set also take --allow-loosen-access, without which a change
       that loosens access is refused and only shown, and --if-hash H;
       M is an apps: name, any, unknown, app:<bundle-id>, signed:<team>[:<id>] or path:<path>)
  secret add <name> [--only-when-unlocked]
                                   (the value on stdin, or typed at a hidden prompt; never an argument)
  secret list
  secret rm <name>
  secret rule add|set|remove <name> …
                                   (the flags of ssh-key rule; a secret's own gate stays block)
  get <name>                       (prints the value to stdout, for a script; git uses git-credential-nazar)
  run --secret <name> -- <command> (runs the command in / with the secret in its environment, never on disk or argv)
  k8s ca create [<context> [<server>]] [--only-when-unlocked]
                                   (sets a context up: its CA in the Secure Enclave, its config entry, the kubectl
                                    pin and its kubeconfig entries; asks at a terminal, else both arguments are needed)
  k8s ca show <context> [--microk8s]
                                   (its certificate, or the steps to add it to microk8s)
  k8s list
  k8s rule add|set|remove <context> …
                                   (the flags of ssh-key rule without --to or --no-to; a context's own gate stays block)
  k8s forget <context>             (deletes its CA, its config entry and nazar's kubeconfig entries)
  k8s credential <context>         (kubectl's exec plugin; run by kubectl, not by people)
  aws ca create <name> [--only-when-unlocked]
                                   (sets an entry up: its CA in the Secure Enclave and its config entry;
                                    prints the AWS-side steps and the ~/.aws/config lines)
  aws ca show <name>               (its certificate, for the trust anchor)
  aws list
  aws rule add|set|remove <name> …
                                   (the flags of k8s rule; an entry's own gate stays block)
  aws forget <name>                (deletes its CA and its config entry)
  aws credential <name>            (credential_process; run by the AWS CLI and SDKs, not by people)
  apps list
  status [--follow]
  revoke --all | --key <name> | --session <id> | --app <bundle-id>
  config check
  config apply                     (shows the change staged in config.yaml and asks for Touch ID)
  trust --app <bundle-id>
  log [--follow] [--since 24h] [--target T] [--caller C] [--decision D]
  log summary [--since 7d]
  sign-git <ssh-keygen args>      (gpg.ssh.program wrapper)
  install [--bin-dir DIR] | uninstall [--bin-dir DIR]
  ui                              (open Nazar UI.app, if installed)
  version
  completion bash|zsh|fish        (the shell completion script: source <(nazar completion zsh))
  help [<command>]                (this text, or a command's flags and examples; also <command> --help)

Exit codes: 0 ok, 1 error, 2 usage (or a change that loosens access, refused without
--allow-loosen-access), 3 refused, 4 staged (the prompt could not be shown; nazar config apply
asks), 5 nazar-agent not running.
Guide (for people and AI agents): https://github.com/atas/nazar/blob/main/docs/CLI.md
`

func (a *app) home() string { return a.getenv("HOME") }

func (a *app) controlSocket() string {
	if s := a.getenv("NAZAR_CONTROL_SOCKET"); s != "" {
		return s
	}
	return layout.ControlSocket(a.home())
}

func (a *app) configPath() string {
	if p := a.getenv("NAZAR_CONFIG"); p != "" {
		return p
	}
	return layout.ConfigFile(a.home())
}

// client returns a control client that verifies the peer before sending.
func (a *app) client() *control.Client {
	v := a.verifier
	if v == nil {
		v = a.defaultVerifier()
	}
	return &control.Client{Socket: a.controlSocket(), Verifier: v}
}

// run executes one command line and returns the exit code.
func (a *app) run(args []string) int {
	a.suggest = nil
	a.helpFor = ""
	a.argv = args
	// The shell's completion request (the script of `nazar completion`):
	// it never runs a command.
	if len(args) > 0 && (args[0] == cobra.ShellCompRequestCmd || args[0] == cobra.ShellCompNoDescRequestCmd) {
		return a.complete(args)
	}
	// Global flags may appear before the command, or after it for every
	// command except sign-git, whose arguments belong to ssh-keygen byte for
	// byte and are never interpreted here, and run, whose command after its
	// `--` is the program's, byte for byte.
	var rest []string
	for i, x := range args {
		if len(rest) > 0 && (rest[0] == "sign-git" || (rest[0] == "run" && x == "--")) {
			rest = append(rest, args[i:]...)
			break
		}
		switch x {
		case "--json":
			a.json = true
		case "--yes", "-y":
			// Accepted for scripts (spec 6); nazar never asks anyway.
		default:
			rest = append(rest, x)
		}
	}
	if len(rest) == 0 {
		return a.usageError("a command is required")
	}
	switch rest[0] {
	case "help", "-h", "--help":
		return a.help(rest[1:])
	}
	// Help asked for anywhere a command's own parser would have stopped at
	// -h or --help is that command's help; an unknown subcommand gets
	// cobra's suggestions. Nothing else of cobra's touches the arguments.
	root := a.commands(false)
	if c, after := find(root, rest); c != root {
		if helpRequested(c, after) {
			return a.showHelp(root, c)
		}
		a.suggest = suggestions(c, after)
		a.helpFor = strings.TrimPrefix(c.CommandPath(), root.Name()+" ")
	} else {
		a.suggest = suggestions(root, rest)
	}
	cmd, rest := rest[0], rest[1:]
	switch cmd {
	case "completion":
		return a.completion(rest)
	case "version":
		return a.emit(map[string]string{"apiVersion": control.APIVersion, "kind": "Version", "version": version},
			func() { fmt.Fprintln(a.stdout, "nazar", version) })
	case "ssh-key":
		return a.sshKey(rest)
	case "secret":
		return a.secret(rest)
	case "get":
		return a.get(rest)
	case "run":
		return a.runSecret(rest)
	case "k8s":
		return a.k8s(rest)
	case "aws":
		return a.aws(rest)
	case "status":
		return a.status(rest)
	case "revoke":
		return a.revoke(rest)
	case "config":
		return a.config(rest)
	case "trust":
		return a.trust(rest)
	case "log":
		return a.log(rest)
	case "sign-git":
		return a.signGit(rest)
	case "apps":
		return a.apps(rest)
	case "ui":
		return a.ui(rest)
	case "install":
		return a.install(rest)
	case "uninstall":
		return a.uninstall(rest)
	}
	return a.usageError("unknown command %q", cmd)
}

// completion is `nazar completion bash|zsh|fish`: the script on stdout.
func (a *app) completion(args []string) int {
	if len(args) != 1 {
		return a.usageError("completion: expected one shell: bash, zsh or fish")
	}
	root := a.commands(false)
	var err error
	switch args[0] {
	case "bash":
		err = root.GenBashCompletionV2(a.stdout, true)
	case "zsh":
		err = root.GenZshCompletion(a.stdout)
	case "fish":
		err = root.GenFishCompletion(a.stdout, true)
	default:
		return a.usageError("completion: unknown shell %q (bash, zsh or fish)", args[0])
	}
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "completion: %v", err))
	}
	return control.ExitOK
}

func (a *app) usageError(format string, args ...any) int {
	return a.fail(control.NewProblem(control.CodeUsage, format, args...))
}

// fail prints a problem (one JSON object on stdout with --json, text on
// stderr otherwise) and returns its exit code.
func (a *app) fail(err error) int {
	p := control.AsProblem(err)
	if a.json {
		if encErr := json.NewEncoder(a.stdout).Encode(p); encErr != nil {
			return control.ExitError
		}
		return p.ExitCode()
	}
	fmt.Fprintf(a.stderr, "nazar: %s\n", term(p.Message))
	for _, d := range p.Details {
		fmt.Fprintf(a.stderr, "  %s\n", term(d))
	}
	if p.Code == control.CodeUsage {
		if len(a.suggest) > 0 {
			fmt.Fprintf(a.stderr, "\nDid you mean this?\n")
			for _, s := range a.suggest {
				fmt.Fprintf(a.stderr, "\t%s\n", s)
			}
			fmt.Fprintln(a.stderr)
		}
		if a.helpFor != "" {
			fmt.Fprintf(a.stderr, "nazar help %s: its flags and examples\n", a.helpFor)
		} else {
			fmt.Fprint(a.stderr, usage)
		}
	}
	return p.ExitCode()
}

// term renders one untrusted string for the terminal: a config-derived
// name or path, an app id, a problem message, a process name, a reply
// field. Nazar.app escapes what it sends (caller.Chain.Summary quotes every
// hop; the audit formatter quotes every value), but the CLI never relies on
// that: a value is printed unchanged only when every rune is printable,
// otherwise it is Go-quoted ASCII-only, so a control, ESC, CR, bidi or
// other non-printing rune can never reach the terminal raw. Every human
// view prints untrusted text through term; --json output needs nothing,
// because encoding/json escapes control runes itself.
func term(v string) string {
	if utf8.ValidString(v) && strings.IndexFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return v
	}
	return strconv.QuoteToASCII(v)
}

// emit prints v as one JSON line with --json, otherwise calls human.
func (a *app) emit(v any, human func()) int {
	if a.json {
		if err := json.NewEncoder(a.stdout).Encode(v); err != nil {
			return control.ExitError
		}
		return control.ExitOK
	}
	human()
	return control.ExitOK
}

// flags returns a FlagSet that reports usage errors instead of exiting or
// printing on its own.
func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse parses args into fs, allowing flags and positionals in any order
// (`set work --gate block` and `set --gate block work` both work;
// everything after `--` is positional), and checks the positional count.
func (a *app) parse(fs *flag.FlagSet, args []string, positional int) ([]string, error) {
	pos, err := a.parseArgs(fs, args)
	if err != nil {
		return nil, err
	}
	if len(pos) != positional {
		return nil, control.NewProblem(control.CodeUsage, "%s: expected %d argument(s), got %d", fs.Name(), positional, len(pos))
	}
	return pos, nil
}

// parseArgs is parse without the positional count check, for a command
// whose argument count depends on its flags.
func (a *app) parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, control.NewProblem(control.CodeUsage, "%s: see `nazar help`", fs.Name())
			}
			return nil, control.NewProblem(control.CodeUsage, "%s: %v", fs.Name(), err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			pos = append(pos, rest...)
			break
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
	return pos, nil
}

// onceFlag is a string flag that may be given at most once, and that
// remembers whether it was given at all (so `--app=` is told apart from no
// `--app`): a repeated or empty value is a usage error, never a silent
// "last one wins".
type onceFlag struct {
	value string
	set   bool
}

func (f *onceFlag) String() string { return f.value }

func (f *onceFlag) Set(v string) error {
	if f.set {
		return errors.New("given more than once")
	}
	f.set, f.value = true, v
	return nil
}

// call sends one request and decodes the single reply of the given kind.
func (a *app) call(cmd string, args map[string]string, kind string, out any) error {
	return a.client().Call(context.Background(), control.NewRequest(cmd, args), kind, out)
}
