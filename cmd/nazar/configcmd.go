package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

func (a *app) config(args []string) int {
	if len(args) == 0 {
		return a.usageError("config needs a subcommand: check, apply")
	}
	sub, args := args[0], args[1:]
	switch sub {
	case "check", "apply":
	default:
		return a.usageError("unknown config subcommand %q", sub)
	}
	if _, err := a.parse(a.flags("config "+sub), args, 0); err != nil {
		return a.fail(err)
	}
	if sub == "check" {
		return a.configCheck()
	}
	return a.configApply()
}

// configApply is `nazar config apply`: for a change made by hand in
// config.yaml, or one an edit left staged (denied, or its prompt not
// shown). It first asks nazar-agent what is staged (status, which reads
// what the agent has observed and observes nothing itself, so no
// background prompt starts here) and shows it, as `config check` does, so
// the person reads the change before the prompt; then it sends the
// config.apply bound to exactly that change (the hash from the reply,
// never typed or printed): when config.yaml holds anything else by then,
// nazar-agent asks nothing (exit 1) and `nazar config apply` again shows
// what it holds now. A hand edit the agent has not observed yet is not
// shown here: config.apply observes it and its prompt shows the diff.
func (a *app) configApply() int {
	var st control.Status
	if err := a.call(control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		return a.fail(err)
	}
	var req map[string]string
	if st.Staged != nil {
		if !validConfigHash(st.Staged.Hash) || st.Staged.Hash == "missing" {
			return a.fail(control.NewProblem(control.CodeError, "nazar-agent staged the change under an invalid hash; run `nazar config check`"))
		}
		req = map[string]string{"hash": st.Staged.Hash}
		if !a.json {
			fmt.Fprintln(a.stdout, "staged in config.yaml, waiting for your approval (Touch ID / Watch / password):")
			for _, l := range st.Staged.Changes {
				fmt.Fprintf(a.stdout, "  %s\n", term(l))
			}
			for _, l := range st.Staged.Loosening {
				fmt.Fprintf(a.stdout, "  loosens: %s\n", term(l))
			}
		}
	}
	var d control.ConfigDiff
	if err := a.call(control.CmdConfigApply, req, control.KindConfigDiff, &d); err != nil {
		return a.fail(err)
	}
	return a.emit(d, func() {
		if d.Applied {
			fmt.Fprintln(a.stdout, "config change approved and applied")
			for _, c := range d.Changes {
				fmt.Fprintf(a.stdout, "  %s\n", term(c))
			}
		} else {
			fmt.Fprintln(a.stdout, "nothing is staged")
		}
	})
}

// validConfigHash reports whether h is a config content hash as Nazar.app
// writes them: 64 lowercase hex digits, or "missing" (no file).
func validConfigHash(h string) bool {
	if h == "missing" {
		return true
	}
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// configCheck validates the file locally (so it works without Nazar.app),
// then asks Nazar.app for the staged diff. Exit: 1 invalid (beats staged),
// 4 staged, 0 ok.
func (a *app) configCheck() int {
	path := a.configPath()
	res := control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Path: path, Problems: []control.ConfigProblem{}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.Valid = true
		res.Problems = append(res.Problems, control.ConfigProblem{Severity: string(config.SevWarning), Message: "no config file; every key is blocked"})
	case err != nil:
		return a.fail(control.NewProblem(control.CodeError, "reading %s: %v", path, err))
	default:
		_, probs := config.Parse(data, config.Env{Home: a.home()})
		res.Valid = !probs.HasErrors()
		for _, p := range probs {
			res.Problems = append(res.Problems, control.ConfigProblem{Severity: string(p.Severity), Path: p.Path, Line: p.Line, Message: p.Message})
		}
	}
	running := true
	var remote control.ConfigCheck
	if err := a.call(control.CmdConfigCheck, nil, control.KindConfigCheck, &remote); err != nil {
		if control.AsProblem(err).Code != control.CodeUnavailable {
			return a.fail(err)
		}
		running = false
	} else if filepath.Clean(remote.Path) == filepath.Clean(path) {
		// The staged diff and Nazar.app's problems (unpinned app: matchers,
		// keys whose Secure Enclave policy no longer fits their gates) only
		// mean something for the file we validated. Nazar.app parses the
		// same file, so a parse problem it repeats is shown once.
		res.Staged, res.ActiveHash = remote.Staged, remote.ActiveHash
		res.Problems = mergeProblems(res.Problems, remote.Problems)
	}
	code := control.ExitOK
	switch {
	case !res.Valid:
		code = control.ExitError
	case res.Staged != nil:
		code = control.ExitStaged
	}
	if rc := a.emit(res, func() { a.printConfigCheck(res, running) }); rc != control.ExitOK {
		return rc
	}
	return code
}

// mergeProblems appends to local every problem of remote that local does
// not already hold (same severity, path, line and message), in order.
func mergeProblems(local, remote []control.ConfigProblem) []control.ConfigProblem {
	seen := make(map[control.ConfigProblem]bool, len(local))
	for _, p := range local {
		seen[p] = true
	}
	for _, p := range remote {
		if !seen[p] {
			seen[p] = true
			local = append(local, p)
		}
	}
	return local
}

// printConfigCheck is the human view. Problem paths and messages carry
// config-derived names (a key name is spliced into both), so every value
// goes through term.
func (a *app) printConfigCheck(res control.ConfigCheck, running bool) {
	for _, p := range res.Problems {
		loc := term(p.Path)
		if p.Line > 0 {
			loc = fmt.Sprintf("line %d: %s", p.Line, term(p.Path))
		}
		if loc == "" {
			fmt.Fprintf(a.stdout, "%s: %s\n", term(p.Severity), term(p.Message))
		} else {
			fmt.Fprintf(a.stdout, "%s: %s: %s\n", term(p.Severity), loc, term(p.Message))
		}
	}
	if res.Valid {
		fmt.Fprintf(a.stdout, "%s is valid\n", term(res.Path))
	} else {
		fmt.Fprintf(a.stdout, "%s is invalid; nazar-agent keeps the last approved config\n", term(res.Path))
	}
	if res.Staged != nil {
		fmt.Fprintln(a.stdout, "staged, waiting for approval (Touch ID / Watch / password):")
		for _, c := range res.Staged.Changes {
			fmt.Fprintf(a.stdout, "  %s\n", term(c))
		}
		for _, l := range res.Staged.Loosening {
			fmt.Fprintf(a.stdout, "  loosens: %s\n", term(l))
		}
		fmt.Fprintln(a.stdout, "run `nazar config apply` to show the prompt again")
	}
	if !running {
		fmt.Fprintln(a.stdout, "nazar-agent isn't running, so nothing is applied")
	}
}

// trust pins the installed app's team for app: matchers (`trust --app
// <bundle id>`, the fix every unpinned-app message names). Anything else,
// a path among them (a path: rule needs no trust, spec 4.2), is decided
// locally as a usage error and reaches nothing. It is a loosening:
// Nazar.app shows the login gate.
func (a *app) trust(args []string) int {
	fs := a.flags("trust")
	var appID onceFlag
	fs.Var(&appID, "app", "bundle id of an installed app to pin")
	pos, err := a.parseArgs(fs, args)
	if err != nil {
		return a.fail(err)
	}
	switch {
	case len(pos) > 0:
		return a.usageError("trust: a path: rule needs no trust; trust takes --app <bundle-id>")
	case !appID.set:
		return a.usageError("trust: expected --app <bundle-id>")
	case appID.value == "":
		return a.usageError("trust: --app needs a bundle id")
	}
	return a.trustApp(appID.value)
}

// trustApp sends `trust --app`. Every field of the reply is Nazar.app's
// reading of the config and the disk, so the human view prints it through
// term.
func (a *app) trustApp(bundleID string) int {
	var pin control.AppPin
	if err := a.call(control.CmdTrustApp, map[string]string{"app": bundleID}, control.KindAppPin, &pin); err != nil {
		return a.fail(err)
	}
	return a.emit(pin, func() {
		switch {
		case !pin.Changed:
			fmt.Fprintf(a.stdout, "app %s is already pinned to team %s (installed at %s)\n", term(pin.BundleID), term(pin.Team), term(pin.Path))
		case pin.OldTeam != "":
			fmt.Fprintf(a.stdout, "pinned app %s to team %s, replacing %s (installed at %s)\n", term(pin.BundleID), term(pin.Team), term(pin.OldTeam), term(pin.Path))
		default:
			fmt.Fprintf(a.stdout, "pinned app %s to team %s (installed at %s)\n", term(pin.BundleID), term(pin.Team), term(pin.Path))
		}
		fmt.Fprintln(a.stdout, "app: matchers for this bundle id now match that team")
	})
}
