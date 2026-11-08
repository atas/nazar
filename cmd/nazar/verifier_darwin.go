//go:build darwin && cgo

package main

import "github.com/atas/nazar/core/codesign"

// checkAgentPeer: the socket peer is live code that satisfies requirement
// (agentRequirement).
func checkAgentPeer(fd int, requirement string) error {
	tok, err := codesign.PeerAuditToken(fd)
	if err != nil {
		return err
	}
	return codesign.CheckPeer(tok, requirement)
}

// selfTeamID and designatedRequirement are the app's selfTeam and
// designated seams.
func selfTeamID() (string, error)                       { return codesign.SelfTeamID() }
func designatedRequirement(path string) (string, error) { return codesign.DesignatedRequirement(path) }
