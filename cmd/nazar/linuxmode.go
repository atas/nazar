package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
)

// The CLI's words for the platform it runs on. Every text is written once,
// in its macOS words; on Linux (a.linux) the help, the usage text and the
// messages nazar prints itself take the words of a.traits() instead. The
// macOS text is never rewritten, so it stays byte for byte as it was.

// runOnLinux is why `nazar run` refuses on Linux (spec, "Weaker than
// macOS" 5).
const runOnLinux = "nazar run is not available on Linux yet (it needs to watch the program's exec, which Linux allows only to root); deliver the secret with a helper or stdout instead"

// uiOnLinux is why `nazar ui` refuses on Linux.
const uiOnLinux = "Nazar UI is macOS only"

// yourGate is the login gate as the object of "asks for": "your Touch
// ID", "your password".
func yourGate(t platform.Traits) string {
	if strings.HasPrefix(t.LoginGate, "your ") {
		return t.LoginGate
	}
	return "your " + t.LoginGate
}

// capitalized is s with its first letter upper case.
func capitalized(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// wordsFor rewrites a text written in macOS words into t's. The pairs are
// tried in order at each place, so a phrase comes before the words in it.
func wordsFor(t platform.Traits) *strings.Replacer {
	m := platform.MacTraits
	gate := yourGate(t)
	return strings.NewReplacer(
		// Examples and matchers: Linux has no code signatures and no
		// bundle ids; app: names a desktop app id.
		"--apps signed:Q6L2SF6YDW:com.anthropic.claude-code", "--apps app:code",
		"--to signed:apple:com.apple.git-remote-http", `--to path:"$(git --exec-path)/git-remote-http"`,
		"com.googlecode.iterm2", "org.kde.konsole",
		"app:<bundle-id>, signed:<team>[:<id>] or path:<path>", "app:<app-id> or path:<path>",
		"<bundle-id>", "<app-id>",
		"`bundle-id`", "`app-id`",
		"a bundle id", "an app id",
		" | pbcopy", "",
		", a Node or Python program through `nazar run`", "",
		// What an app: pin records.
		"Pin an installed app's "+m.PinWord, "Pin an installed app's "+t.PinWord,
		"Pin the "+m.PinWord+" of an installed app for app: matchers, after an update that changed the app's\nsigning team",
		"Pin the "+t.PinWord+" of an installed app for app: matchers, after an update that changed the app's\nexecutable",
		"pinned "+m.PinWord+"s", "pinned "+t.PinWord+"es",
		"the "+m.PinWord+" pinned for an", "the "+t.PinWord+" pinned for an",
		// The login gate.
		"your Touch ID / Watch /\npassword", gate,
		"your Touch ID / Watch / password", gate,
		"Touch ID / Watch / password", t.LoginGate,
		"Touch ID, Apple Watch or password", t.LoginGate,
		"Touch ID, Watch or password", t.LoginGate,
		"One "+m.LoginGate, "One prompt for "+gate,
		". "+m.LoginGate+" once.", ". It asks for "+gate+" once.",
		". "+m.LoginGate+". ", ". It asks for "+gate+". ",
		"your "+m.LoginGate, gate,
		"for "+m.LoginGate, "for "+gate,
		". "+m.LoginGate, ". "+capitalized(t.LoginGate),
		m.LoginGate, t.LoginGate,
		// Where keys are and who enforces their protection. No chip
		// keeps a key from working before the first login on Linux, and
		// nothing fixes the choice for the key's life: it is a byte of the
		// key's record that nazar reads on every use (THREAT-MODEL 7.3,
		// 7.11), so the help never says "fixed", as lockedLine does not.
		", once you have logged in since it\nstarted. Both are fixed for the key's life.", ". Both are "+linuxLockedBy+".",
		"refuse the CA while the Mac is locked (fixed for its life).", "refuse the CA while "+t.Machine+" is locked ("+linuxLockedBy+").",
		"fixed for the key's life", linuxLockedBy,
		"fixed for its life", linuxLockedBy,
		", once you have logged in since it\nstarted.", ".",
		m.Chip, t.Chip,
		strings.TrimPrefix(m.Chip, "the "), t.KeyChip(),
		"the\nchip ", t.Enforcer+"\n",
		m.Enforcer, t.Enforcer,
		m.Machine, t.Machine,
	)
}

// linuxWords is texts in this platform's words: unchanged on macOS.
func (a *app) linuxWords(texts []string) []string {
	if !a.linux {
		return texts
	}
	r := wordsFor(a.traits())
	out := make([]string, len(texts))
	for i, s := range texts {
		out[i] = r.Replace(s)
	}
	return out
}

// say is one text in this platform's words.
func (a *app) say(s string) string { return a.linuxWords([]string{s})[0] }

// gateCompletions are the --gate values a rule offers, in this platform's
// words.
func (a *app) gateCompletions() []string { return a.linuxWords(gateValues) }

// usageText is `nazar help`: the usage, as this build can keep its word and
// in this platform's words. The prompt's words come first: promptWords looks
// for the macOS text.
func (a *app) usageText() string {
	text := a.promptWords(usage)
	if !a.linux {
		return text
	}
	return strings.NewReplacer(
		"(runs the command in / with the secret in its environment, never on disk or argv)", "(not available on Linux yet)",
		"(open Nazar UI.app, if installed)", "("+uiOnLinux+")",
		"install [--bin-dir DIR] | uninstall [--bin-dir DIR]", "install [--bin-dir DIR | --no-links | --system] | uninstall [--bin-dir DIR | --system]",
	).Replace(wordsFor(a.traits()).Replace(text))
}

// linuxHelp puts the command tree's help in Linux words, and says that
// run and ui are not there.
func (a *app) linuxHelp(root *cobra.Command) {
	r := wordsFor(a.traits())
	var visit func(c *cobra.Command)
	visit = func(c *cobra.Command) {
		c.Use, c.Short, c.Long, c.Example = r.Replace(c.Use), r.Replace(c.Short), r.Replace(c.Long), r.Replace(c.Example)
		for _, fs := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags()} {
			fs.VisitAll(func(f *pflag.Flag) { f.Usage = r.Replace(f.Usage) })
		}
		switch c.CommandPath() {
		case "nazar run":
			c.Short = "Run a program with a secret in its environment (not available on Linux yet)"
			c.Long = "Not available on Linux yet: it needs to watch the program's exec, which Linux allows only to root.\n" +
				"Deliver the secret with a helper (git-credential-nazar) or stdout (nazar get) instead."
		case "nazar log":
			c.Long = "Show nazar's entries in its audit log, " + layout.AuditLog("~") + ": every request, who asked,\n" +
				"and what was decided. Any program running as you can write to that file, so it can't prove who\n" +
				"wrote an entry."
		case "nazar log summary":
			c.Long = strings.ReplaceAll(c.Long, "the macOS log", "the audit log")
		case "nazar ui":
			c.Short, c.Long, c.Example = uiOnLinux, uiOnLinux+": everything Nazar UI does is a nazar command.", ""
		case "nazar install":
			c.Use = "install [--bin-dir DIR | --no-links | --system]"
			c.Short = "Install nazar-agent's systemd user service and the nazar links"
			c.Long = "Set up the systemd user service for the nazar-agent next to this CLI, the private ~/.nazar folder,\n" +
				"the record of both programs' hashes, and the links nazar, nazar-sign-git and git-credential-nazar\n" +
				"in the bin folder. Run it as yourself; run it again to repair the setup, and after every upgrade or\n" +
				"move. It never touches keys, config or shell startup files. The service is started at login by\n" +
				"graphical-session.target; install warns when your desktop has not activated it.\n\n" +
				"First, once per user, run it with sudo and --system: that installs the polkit action and the udev\n" +
				"rule for the TPM and adds you to the tss group. Then log out and back in."
			c.Example = "  sudo /path/to/nazar install --system\n  /path/to/nazar install"
		case "nazar uninstall":
			c.Use = "uninstall [--bin-dir DIR | --system]"
			c.Short = "Remove nazar-agent's systemd user service and the nazar links"
			c.Long = "Stop and remove nazar-agent's systemd user service and the links in the bin folder that point at a\n" +
				"nazar CLI. ~/.nazar is kept.\n\n" +
				"With sudo and --system it removes the polkit action and the udev rule instead, for every user of\n" +
				"this machine. The tss group and its members are kept."
			c.Example = "  nazar uninstall\n  sudo /path/to/nazar uninstall --system"
		}
		for _, s := range c.Commands() {
			visit(s)
		}
	}
	visit(root)
}

// approval is what approving a staged change asks for.
func (a *app) approval() string {
	if a.linux {
		return a.traits().LoginGate
	}
	return "Touch ID / Watch / password"
}

// alwaysAskMark is how the human views mark a key that asks on every use
// (SSHKey.UserPresence), naming who enforces it.
func (a *app) alwaysAskMark() string {
	return "asks every time (" + strings.TrimPrefix(a.traits().Enforcer, "the ") + ")"
}

// lockedLine is what the human create outputs say about when the new key,
// secret or CA works. On macOS the chip holds the choice, so it is fixed
// for the key's life. On Linux it is a byte of the key's record that nazar
// reads on every use (THREAT-MODEL 7.3, 7.11), so the line says who
// enforces it and never that it is fixed.
func (a *app) lockedLine(whileLocked bool) string {
	t := a.traits()
	if !a.linux {
		if whileLocked {
			return "works while the Mac is locked too, once you have logged in since it started (fixed for its life)"
		}
		return onlyWhenUnlockedMark + ": the chip refuses it while the Mac is locked (fixed for its life)"
	}
	// No chip keeps it from working before the first login on Linux:
	// only nazar's check of the screen lock is promised.
	if whileLocked {
		return fmt.Sprintf("works while %s is locked too (%s)", t.Machine, linuxLockedBy)
	}
	return fmt.Sprintf("%s: %s refuses it while %s is locked (%s)", onlyWhenUnlockedMark, t.Enforcer, t.Machine, linuxLockedBy)
}

// linuxLockedBy is the parenthesis of lockedLine and caLockedLine on Linux,
// where macOS says "fixed for its life".
const linuxLockedBy = "enforced by nazar from the key's record"

// caLockedLine is lockedLine for the CA of a k8s context or aws entry.
func (a *app) caLockedLine(whileLocked bool) string {
	t := a.traits()
	switch {
	case !a.linux && whileLocked:
		return "The CA signs while the Mac is locked too, once you have logged in since it started (fixed for its life)."
	case !a.linux:
		return "The CA signs only while the Mac is unlocked (fixed for its life)."
	case whileLocked:
		return fmt.Sprintf("The CA signs while %s is locked too (%s).", t.Machine, linuxLockedBy)
	}
	return fmt.Sprintf("The CA signs only while %s is unlocked (%s).", t.Machine, linuxLockedBy)
}

// wrongAccess is the error for a reply that works while locked though
// --only-when-unlocked asked otherwise (a nazar-agent that ignored the
// argument): what was made, and how to undo it.
func (a *app) wrongAccess(what, undo string) *control.Problem {
	return control.NewProblem(control.CodeError, "%s works while %s is locked, though --only-when-unlocked asked otherwise (is nazar-agent older than this nazar?); don't use it: %s", what, a.traits().Machine, undo)
}

// linuxSelfPath is selfPath on Linux: the path this process was started
// by (invokedPath), where macOS has os.Executable.
func linuxSelfPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return invokedPath(os.Args[0], os.Getenv("PATH"), cwd, exe)
}

// invokedPath is the path a program was started by, links not resolved:
// argv0 made absolute against cwd, or, when it is a bare name, the file
// PATH gives for it, as the shell found it. It is what `nazar k8s ca
// create` writes into a kubeconfig and `aws ca create` prints for
// ~/.aws/config, and on macOS it is what os.Executable gives. On Linux
// os.Executable reads /proc/self/exe: the file itself under
// ~/.local/lib/nazar/<version> or a Homebrew Cellar, which the next
// upgrade removes, while the link the user runs (~/.local/bin/nazar,
// <prefix>/bin/nazar) is moved to the new version. kubectl and the AWS
// CLI must name the link. The path must resolve to the running image
// (exe): an argv0 that names some other file is an error, and nothing is
// written.
func invokedPath(argv0, pathEnv, cwd, exe string) (string, error) {
	if argv0 == "" {
		return "", errors.New("the program name is empty")
	}
	p := argv0
	if !strings.Contains(argv0, "/") {
		p = ""
		for _, dir := range filepath.SplitList(pathEnv) {
			if dir == "" {
				dir = "." // an empty PATH entry is the current folder, as the shell reads it
			}
			c := filepath.Join(dir, argv0)
			if !filepath.IsAbs(c) {
				c = filepath.Join(cwd, c)
			}
			if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
				p = c
				break
			}
		}
		if p == "" {
			return "", fmt.Errorf("%s is not on PATH", argv0)
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	want, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	if real != want {
		return "", fmt.Errorf("%s is %s, not the running %s", p, real, want)
	}
	return p, nil
}
