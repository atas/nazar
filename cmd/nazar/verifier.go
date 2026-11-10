package main

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/atas/nazar/core/codesign"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/unixsock"
)

// defaultVerifier checks who listens on the control socket before the CLI
// sends anything (spec 6): the peer must run as the current user and
// be the agent the CLI trusts, checked by audit token against
// agentRequirement (verifier_darwin.go).
//
// This is a necessary but NOT sufficient gate. The audit token names the
// process that last touched the listening socket, not the one servicing
// accept(), so same-user malware that owns control.sock behind a genuine
// agent listen-owner and serves forged replies from another process is not
// caught here (codesign package doc). A pass means "the listen-owner is
// the agent", never more.
//
// NAZAR_TEST_PEER=same-user drops the code-signature check (integration
// tests run a test daemon that is not the agent). It only weakens the CLI
// it is set for, and the human output says so on every run (--json output
// stays one clean JSON object per line).
func (a *app) defaultVerifier() control.PeerVerifier {
	if a.getenv("NAZAR_TEST_PEER") == "same-user" {
		if !a.json {
			fmt.Fprintln(a.stderr, "nazar: warning: NAZAR_TEST_PEER=same-user: not checking that the control socket is nazar-agent")
		}
		return control.SameUserVerifier{}
	}
	return a.agentVerifier(a.home())
}

// agentVerifier is the signature check of the control socket's peer
// against agentRequirement, with no test override: what k8s credential
// uses whatever its environment says. On Linux (a.linux) there is no
// signature to check: after the same same-user check, the peer must hash
// to the nazar-agent `nazar install` recorded in home, and this CLI to the
// nazar it recorded there (checkLinuxAgent, core/peertrust). home is the
// caller's to choose, because the record is what the check trusts: k8s
// credential and aws credential pass the user database's, never $HOME,
// which their environment controls. macOS reads no file and ignores it.
func (a *app) agentVerifier(home string) control.PeerVerifier {
	return control.VerifierFunc(func(c *net.UnixConn) error {
		if err := unixsock.RequireSameUser(c); err != nil {
			return err
		}
		if a.linux {
			return unixsock.WithFD(c, func(fd int) error { return checkLinuxAgent(fd, home) })
		}
		req, err := a.agentRequirement()
		if err != nil {
			return err
		}
		return unixsock.WithFD(c, func(fd int) error { return checkAgentPeer(fd, req) })
	})
}

// agentRequirement is the code requirement the control socket's peer must
// satisfy (spec 4, Milestone 6: identity is the signature, never the path):
//
//   - A CLI signed by a team (a release, or a developer's Apple Development
//     build) trusts signing identifier dev.nazar.agent signed by that same
//     team, wherever the agent runs from, so a CLI of the next version
//     talks to the agent of the last one during an upgrade.
//   - An ad-hoc CLI (`make agent`) has no team to name; it trusts exactly
//     the build of the agent bundle it ships in (that bundle's designated
//     requirement, a cdhash), the bundle whose seal covers the CLI itself.
//
// Nothing else: not the LaunchAgent's ProgramArguments (a path any process
// of the user can rewrite), and a team CLI never falls back to the bundle
// rule. A CLI that can't read its own signature, or an ad-hoc one outside
// an agent bundle, trusts no peer at all.
func (a *app) agentRequirement() (string, error) {
	if a.selfTeam == nil || a.designated == nil || a.executable == nil {
		return "", control.NewProblem(control.CodeError, "this nazar CLI can't check the agent's signature in this build")
	}
	team, err := a.selfTeam()
	if err != nil {
		return "", control.NewProblem(control.CodeError, "can't read this nazar CLI's own signature, so no agent can be trusted: %v", err)
	}
	if team != "" {
		req, err := codesign.TeamRequirement(agentBundleID, team)
		if err != nil {
			return "", control.NewProblem(control.CodeError, "%v", err)
		}
		return req, nil
	}
	exe, err := a.executable()
	if err != nil {
		return "", control.NewProblem(control.CodeError, "can't tell where this nazar CLI runs from: %v", err)
	}
	loc, ok := bundleOf(exe)
	if !ok || !isFile(loc.MainExe) || filepath.Base(exe) != cliExeName {
		return "", errNoAgentToTrust
	}
	return a.designated(loc.Bundle)
}

// errNoAgentToTrust: an ad-hoc CLI outside an agent bundle.
var errNoAgentToTrust = control.NewProblem(control.CodeError,
	"this nazar CLI is signed ad hoc and does not run inside nazar-agent.app, so it has no agent to trust: run the nazar inside nazar-agent.app (…/nazar-agent.app/Contents/MacOS/nazar), or the link `nazar install` made to it")
