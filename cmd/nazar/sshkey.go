package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

func (a *app) sshKey(args []string) int {
	if len(args) == 0 {
		return a.usageError("ssh-key needs a subcommand: create, list, pubkey, delete, rules, rule, set")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "create":
		return a.sshKeyCreate(args)
	case "rules":
		return a.sshKeyRules(args)
	case "rule":
		return a.ruleEdit(keyTarget, args)
	case "set":
		return a.sshKeySet(args)
	case "list":
		if _, err := a.parse(a.flags("ssh-key list"), args, 0); err != nil {
			return a.fail(err)
		}
		var l control.SSHKeyList
		if err := a.call(control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l); err != nil {
			return a.fail(err)
		}
		return a.emit(l, func() { a.printKeyList(l) })
	case "pubkey":
		pos, err := a.parse(a.flags("ssh-key pubkey"), args, 1)
		if err != nil {
			return a.fail(err)
		}
		var k control.SSHKey
		if err := a.call(control.CmdSSHKeyPubkey, map[string]string{"name": pos[0]}, control.KindSSHKey, &k); err != nil {
			return a.fail(err)
		}
		// An OpenSSH public key line is printable ASCII, so term leaves a
		// real one untouched and only a malformed reply is shown quoted.
		return a.emit(k, func() { fmt.Fprintln(a.stdout, term(k.PublicKey)) })
	case "delete":
		pos, err := a.parse(a.flags("ssh-key delete"), args, 1)
		if err != nil {
			return a.fail(err)
		}
		var k control.SSHKey
		if err := a.call(control.CmdSSHKeyDelete, map[string]string{"name": pos[0]}, control.KindSSHKey, &k); err != nil {
			return a.fail(err)
		}
		return a.emit(k, func() { fmt.Fprintf(a.stdout, "deleted SSH key %s\n", term(k.Name)) })
	}
	return a.usageError("unknown ssh-key subcommand %q", sub)
}

// alwaysAskMark is how the human views mark a key the chip asks for on
// every use (SSHKey.UserPresence).
const alwaysAskMark = "asks every time (chip)"

// onlyWhenUnlockedMark is how the human views mark a key, secret or CA
// the chip refuses while the Mac is locked (whileLocked false): made with
// --only-when-unlocked or --always-ask, or before nazar knew the difference.
const onlyWhenUnlockedMark = "only when unlocked"

// lockedLine is what the human create outputs say about when the new key
// works.
func lockedLine(whileLocked bool) string {
	if whileLocked {
		return "works while the Mac is locked too, once you have logged in since it started (fixed for its life)"
	}
	return onlyWhenUnlockedMark + ": the chip refuses it while the Mac is locked (fixed for its life)"
}

// onlyWhenUnlockedFlag is the --only-when-unlocked flag of ssh-key create,
// secret add and k8s ca create.
func onlyWhenUnlockedFlag(fs *flag.FlagSet) *bool { return fs.Bool("only-when-unlocked", false, "") }

// withOnlyWhenUnlocked adds the request argument onlyWhenUnlocked=true
// when the flag was given.
func withOnlyWhenUnlocked(req map[string]string, on bool) map[string]string {
	if on {
		req["onlyWhenUnlocked"] = "true"
	}
	return req
}

// wrongAccess is the error for a reply that works while the Mac is locked
// though --only-when-unlocked asked otherwise (a nazar-agent that ignored
// the argument): what was made, and how to undo it.
func wrongAccess(what, undo string) *control.Problem {
	return control.NewProblem(control.CodeError, "%s works while the Mac is locked, though --only-when-unlocked asked otherwise (is nazar-agent older than this nazar?); don't use it: %s", what, undo)
}

// sshKeyCreate sends the name and nothing else: nazar-agent writes
// the entry (the key's own gate block, plus a login rule for the terminal
// app the command was typed in, when there is one), shows the change on
// the login gate, and decides the key's Secure Enclave protection from the
// entry. For a name config.yaml already has an entry for, the key is
// created under that entry. --always-ask adds the request argument
// alwaysAsk=true: the agent then writes an entry that calls for Secure
// Enclave user presence, or refuses. The reply is checked: a key that came
// back without it (an older nazar-agent ignores the argument) is an error.
// --only-when-unlocked adds onlyWhenUnlocked=true, checked the same way.
func (a *app) sshKeyCreate(args []string) int {
	fs := a.flags("ssh-key create")
	alwaysAsk := fs.Bool("always-ask", false, "")
	onlyWhenUnlocked := onlyWhenUnlockedFlag(fs)
	pos, err := a.parse(fs, args, 1)
	if err != nil {
		return a.fail(err)
	}
	name := pos[0]
	if !config.ValidKeyName(name) {
		return a.usageError("ssh-key create: invalid key name %q (letters, digits, '.', '_' and '-'; it becomes keys/<name>.pub)", name)
	}
	req := map[string]string{"name": name}
	if *alwaysAsk {
		req["alwaysAsk"] = "true"
	}
	withOnlyWhenUnlocked(req, *onlyWhenUnlocked)
	var k control.SSHKey
	if err := a.call(control.CmdSSHKeyCreate, req, control.KindSSHKey, &k); err != nil {
		return a.fail(err)
	}
	if *alwaysAsk && !k.UserPresence {
		return a.fail(control.NewProblem(control.CodeError, "SSH key %s was created without chip protection, though --always-ask asked for it (is nazar-agent older than this nazar?); "+
			"don't use it: nazar ssh-key delete %s", name, name))
	}
	if *onlyWhenUnlocked && k.WhileLocked {
		return a.fail(wrongAccess("SSH key "+name, "nazar ssh-key delete "+name))
	}
	return a.emit(k, func() {
		fmt.Fprintf(a.stdout, "created SSH key %s (%s)\n", term(k.Name), term(k.Fingerprint))
		if k.UserPresence {
			fmt.Fprintf(a.stdout, "%s: Touch ID on every use, enforced by the chip\n", alwaysAskMark)
		}
		fmt.Fprintln(a.stdout, lockedLine(k.WhileLocked))
		fmt.Fprintf(a.stdout, "public key: %s\n", term(filepath.Join(layout.KeysDir(a.home()), k.Name+".pub")))
		fmt.Fprintf(a.stdout, "its rules (nazar ssh-key rules %s):\n", term(k.Name))
		for _, r := range k.Rules {
			fmt.Fprintf(a.stdout, "  %s\n", term(r))
		}
	})
}

func (a *app) printKeyList(l control.SSHKeyList) {
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTYPE\tFINGERPRINT\tRULES")
	var unusable []control.SSHKey
	for _, k := range l.Items {
		state := k.Type
		if k.Broken {
			state = "broken" // spec 9
			if k.UnusableReason != "" {
				unusable = append(unusable, k)
			}
		}
		rules := "not configured (blocked)"
		if k.Configured {
			n := 0
			for _, r := range k.Rules {
				if !strings.HasPrefix(r, "fallback:") {
					n++
				}
			}
			rules = fmt.Sprintf("%d", n)
		}
		if k.UserPresence {
			rules += ", " + alwaysAskMark
		}
		if !k.WhileLocked && !k.Broken {
			rules += ", " + onlyWhenUnlockedMark
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", term(k.Name), term(state), term(k.Fingerprint), rules)
	}
	tw.Flush()
	for _, k := range unusable {
		fmt.Fprintf(a.stdout, "%s: %s\n  fix: %s\n", term(k.Name), term(k.UnusableReason), term(k.Remedy))
	}
}
