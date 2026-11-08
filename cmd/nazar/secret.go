package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/secrets/seal"
)

// secret is `nazar secret add|list|rm` (secrets design 7.1) and
// `nazar secret rule add|set|remove`.
func (a *app) secret(args []string) int {
	if len(args) == 0 {
		return a.usageError("secret needs a subcommand: add, list, rm, rule")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "add":
		return a.secretAdd(args)
	case "list":
		if _, err := a.parse(a.flags("secret list"), args, 0); err != nil {
			return a.fail(err)
		}
		var l control.SecretList
		if err := a.call(control.CmdSecretList, nil, control.KindSecretList, &l); err != nil {
			return a.fail(err)
		}
		return a.emit(l, func() { a.printSecretList(l) })
	case "rm":
		pos, err := a.parse(a.flags("secret rm"), args, 1)
		if err != nil {
			return a.fail(err)
		}
		var s control.Secret
		if err := a.call(control.CmdSecretDelete, map[string]string{"name": pos[0]}, control.KindSecret, &s); err != nil {
			return a.fail(err)
		}
		return a.emit(s, func() { fmt.Fprintf(a.stdout, "deleted secret %s\n", term(s.Name)) })
	case "rule":
		return a.ruleEdit(secretTarget, args)
	}
	return a.usageError("unknown secret subcommand %q", sub)
}

// secretAdd reads the value and sends it with the name; nazar-agent writes
// the entry for a new name (the secret's own gate block, plus a login rule
// for the terminal app the command was typed in) and asks on its login
// gate. The value is never an argument and never printed.
// --only-when-unlocked adds onlyWhenUnlocked=true, and the reply is checked.
func (a *app) secretAdd(args []string) int {
	fs := a.flags("secret add")
	onlyWhenUnlocked := onlyWhenUnlockedFlag(fs)
	pos, err := a.parse(fs, args, 1)
	if err != nil {
		return a.fail(err)
	}
	name := pos[0]
	if !config.ValidSecretName(name) {
		return a.usageError("secret add: invalid secret name %q (letters, digits, _ . - and /, at most 64 bytes)", name)
	}
	if a.getenv("NAZAR_TEST_PEER") != "" {
		// That hook skips the check that the control socket is nazar-agent;
		// a value is never sent to a listener nobody checked.
		return a.usageError("secret add: refused while NAZAR_TEST_PEER is set")
	}
	value, err := a.readValue(name)
	defer clear(value)
	if err != nil {
		return a.fail(err)
	}
	var s control.Secret
	req := withOnlyWhenUnlocked(map[string]string{"name": name, "valueBase64": base64.StdEncoding.EncodeToString(value)}, *onlyWhenUnlocked)
	err = a.call(control.CmdSecretAdd, req, control.KindSecret, &s)
	if err != nil {
		return a.fail(err)
	}
	if *onlyWhenUnlocked && s.WhileLocked {
		return a.fail(wrongAccess("secret "+name, "nazar secret rm "+name))
	}
	return a.emit(s, func() {
		fmt.Fprintf(a.stdout, "added secret %s\n", term(s.Name))
		fmt.Fprintf(a.stdout, "deliver: %s\n", term(strings.Join(s.Deliver, ", ")))
		fmt.Fprintln(a.stdout, lockedLine(s.WhileLocked))
		fmt.Fprintln(a.stdout, "its rules (config.yaml, secrets."+term(s.Name)+"):")
		for _, r := range s.Rules {
			fmt.Fprintf(a.stdout, "  %s\n", term(r))
		}
	})
}

// readValue reads a secret's value: one hidden line from a terminal, or
// everything on stdin up to EOF with exactly one trailing newline stripped
// (`echo "$X" | nazar secret add X`). Empty or over 32 KiB is a usage
// error, before anything is sent.
func (a *app) readValue(name string) ([]byte, error) {
	var v []byte
	if a.stdinTerminal != nil && a.stdinTerminal() {
		fmt.Fprintf(a.stderr, "value for %s (typing is hidden): ", term(name))
		line, err := a.readHidden()
		if err != nil {
			clear(line)
			return nil, control.NewProblem(control.CodeUsage, "secret add: %v", err)
		}
		v = line
	} else {
		if a.stdin == nil {
			return nil, control.NewProblem(control.CodeUsage, "secret add: no stdin to read the value from")
		}
		// One buffer, read in place: no growing copies of the value are
		// left behind uncleared.
		buf := make([]byte, seal.MaxValue+2)
		n, err := io.ReadFull(a.stdin, buf)
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			clear(buf)
			return nil, control.NewProblem(control.CodeError, "secret add: reading the value from stdin: %v", err)
		}
		v = buf[:n]
	}
	v = bytes.TrimSuffix(v, []byte("\n"))
	switch {
	case len(v) == 0:
		return v, control.NewProblem(control.CodeUsage, "secret add: the value is empty")
	case len(v) > seal.MaxValue:
		return v, control.NewProblem(control.CodeUsage, "secret add: the value is larger than 32 KiB")
	}
	return v, nil
}

func (a *app) printSecretList(l control.SecretList) {
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tCREATED\tRULES\tSTATE")
	var unusable []control.Secret
	for _, s := range l.Items {
		created := "-"
		if s.Created != nil {
			created = s.Created.Local().Format("2006-01-02 15:04")
		}
		state := "stored"
		switch {
		case s.Broken:
			state = "broken"
			unusable = append(unusable, s)
		case !s.Stored:
			state = "not stored"
		case !s.WhileLocked:
			state += ", " + onlyWhenUnlockedMark
		}
		rules := "not configured (blocked)"
		if s.Configured {
			n := 0
			for _, r := range s.Rules {
				if !strings.HasPrefix(r, "fallback:") {
					n++
				}
			}
			rules = fmt.Sprintf("%d", n)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", term(s.Name), created, rules, state)
	}
	tw.Flush()
	for _, s := range unusable {
		fmt.Fprintf(a.stdout, "%s: %s\n  fix: %s\n", term(s.Name), term(s.UnusableReason), term(s.Remedy))
	}
}
