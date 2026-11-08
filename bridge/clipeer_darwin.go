//go:build darwin

package main

import (
	"github.com/atas/nazar/core/codesign"
	"github.com/atas/nazar/core/platform"
)

// cliVerifier is daemon.Options.VerifyCLI for this nazar-agent (secrets
// design 7.3): the control peer of a value-returning command must
// be live code satisfying codesign.CLIRequirement, checked by its audit
// token as the CLI checks the agent (cmd/nazar/verifier.go). The rule is
// built once, from the agent's own signature: its team, or, for an ad-hoc
// build, devCLIPin, the cdhash of the CLI `make agent` signed before
// linking this archive into the agent's executable, so the pin is part of
// the agent's code pages, which the kernel holds to its signature: no file
// on disk can change it. When the rule can't be built, no peer is the
// CLI: no value is returned to anyone.
//
// The token is read once per check; the PID it names is resolved through
// the platform to the live process's full ref, which the control server
// compares with the peer of the caller chain it resolved: both name the
// same process only when that process was alive throughout.
func cliVerifier(p platform.Platform, logf func(string, ...any)) func(fd int) (platform.ProcessRef, error) {
	req, err := cliRequirement()
	if err != nil {
		logf("no nazar CLI can be trusted with a secret value: %v", err)
		return func(int) (platform.ProcessRef, error) { return platform.ProcessRef{}, err }
	}
	return func(fd int) (platform.ProcessRef, error) {
		tok, err := codesign.PeerAuditToken(fd)
		if err != nil {
			return platform.ProcessRef{}, err
		}
		if err := codesign.CheckPeer(tok, req); err != nil {
			return platform.ProcessRef{}, err
		}
		info, err := p.Process(platform.ProcessRef{PID: tok.PID()})
		if err != nil {
			return platform.ProcessRef{}, err
		}
		return info.Ref, nil
	}
}

func cliRequirement() (string, error) {
	team, err := codesign.SelfTeamID()
	if err != nil {
		return "", err
	}
	return codesign.CLIRequirement(team, devCLIPin)
}
