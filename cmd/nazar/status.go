package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atas/nazar/core/control"
)

func (a *app) status(args []string) int {
	fs := a.flags("status")
	follow := fs.Bool("follow", false, "stream approval changes")
	if _, err := a.parse(fs, args, 0); err != nil {
		return a.fail(err)
	}
	ctx, stop := commandContext(*follow)
	defer stop()
	req := control.NewRequest(control.CmdStatus, nil)
	req.Follow = *follow
	err := a.client().Do(ctx, req, func(kind string, raw json.RawMessage) error {
		if kind == control.KindStatus {
			var s control.Status
			if err := json.Unmarshal(raw, &s); err != nil {
				return control.NewProblem(control.CodeError, "control: bad %s reply: %v", kind, err)
			}
			// The client side (ssh config, git signing, another agent) is
			// the CLI's to check, after nazar-agent has answered:
			// nazar-agent never runs ssh or git. With --json the object is
			// printed again with the findings in it, by the same encoder on
			// the same type (the UI fixtures prove nothing else changes).
			s.Setup = a.setupChecks(ctx, s.AgentPath)
			if a.json {
				return json.NewEncoder(a.stdout).Encode(s)
			}
			a.printStatus(s)
			return nil
		}
		if a.json {
			// raw is one reply line as received; print it as one line.
			_, err := a.stdout.Write(append(bytes.TrimRight(raw, "\r\n"), '\n'))
			return err
		}
		if kind == control.KindApproval {
			var ap control.Approval
			if err := json.Unmarshal(raw, &ap); err != nil {
				return control.NewProblem(control.CodeError, "control: bad %s reply: %v", kind, err)
			}
			fmt.Fprintf(a.stdout, "%s %s %s %s %s for %s (%s) %s\n", time.Now().Format("15:04:05"), term(ap.Event), term(ap.Target), term(ap.Scope), term(ap.ScopeID), term(ap.Covers), term(ap.Chain), term(ap.Reason))
		}
		return nil
	})
	if err != nil {
		return a.fail(err)
	}
	return control.ExitOK
}

func (a *app) printStatus(s control.Status) {
	fmt.Fprintf(a.stdout, "agent socket: %s\n", term(s.AgentPath))
	// Vault items Nazar.app runs without, in the order to fix them.
	for _, v := range s.Vault {
		fmt.Fprintf(a.stdout, "vault: %s\n  %s\n  effect: %s\n  fix: %s\n", term(v.Item), term(v.Reason), term(v.Effect), term(v.Remedy))
	}
	if s.Staged != nil {
		fmt.Fprintln(a.stdout, "config: a change is staged and waiting for approval (`nazar config apply`)")
	}
	for _, p := range s.Problems {
		fmt.Fprintf(a.stdout, "config: %s: %s\n", term(p.Severity), term(p.Message))
	}
	// The client side: each line ends with its fix.
	for _, p := range s.Setup {
		fmt.Fprintf(a.stdout, "setup: %s: %s: %s\n", term(p.Severity), term(p.Path), term(p.Message))
	}
	if len(s.Approvals) == 0 {
		fmt.Fprintln(a.stdout, "no current approvals")
	}
	for _, ap := range s.Approvals {
		exp := "until the scope ends"
		if ap.Expires != nil {
			exp = "until " + ap.Expires.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(a.stdout, "%s  rule %s  %s %s  for %s  %s  %s\n", term(ap.Target), term(ap.Rule), term(ap.Scope), term(ap.ScopeID), term(ap.Covers), term(ap.Chain), exp)
	}
}

// revoke needs exactly one selector: a bare `nazar revoke` must never turn
// into "revoke everything", and only the selector the user gave is sent.
func (a *app) revoke(args []string) int {
	fs := a.flags("revoke")
	all := fs.Bool("all", false, "")
	key := fs.String("key", "", "")
	session := fs.String("session", "", "")
	appID := fs.String("app", "", "")
	if _, err := a.parse(fs, args, 0); err != nil {
		return a.fail(err)
	}
	m := map[string]string{}
	if *all {
		m["all"] = "true"
	}
	for k, v := range map[string]string{"key": *key, "session": *session, "app": *appID} {
		if v != "" {
			m[k] = v
		}
	}
	if len(m) != 1 {
		return a.usageError("revoke: give exactly one of --all, --key <name>, --session <id> or --app <bundle-id>")
	}
	var r control.RevokeResult
	if err := a.call(control.CmdRevoke, m, control.KindRevokeResult, &r); err != nil {
		return a.fail(err)
	}
	return a.emit(r, func() { fmt.Fprintf(a.stdout, "revoked %d approval(s)\n", r.Revoked) })
}
