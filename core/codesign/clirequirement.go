package codesign

import (
	"errors"
	"fmt"
	"regexp"
)

// CLIIdentifier is the signing identifier of the nazar CLI (`make agent`
// signs Contents/MacOS/nazar with it).
const CLIIdentifier = "dev.nazar.cli"

// pinRE is a cdhash as codesign prints it: 20 bytes, lowercase hex.
var pinRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CLIRequirement is the code requirement nazar-agent holds the peer of a
// value-returning control command to (secrets design 7.3), the twin
// of Nazar UI.app's CLIRequirement:
//
//   - signed by a team: identifier dev.nazar.cli signed with an
//     Apple-issued certificate of that same team. The pin is ignored, so a
//     team build never trusts by cdhash.
//   - ad hoc: exactly the CLI build whose cdhash is pinned (compiled into
//     the agent by `make agent`, bridge devCLIPin).
//   - ad hoc without a pin: no CLI at all (an error).
//
// Both values are checked byte for byte before they reach requirement
// text, so neither can add a clause.
func CLIRequirement(team, devPin string) (string, error) {
	if team != "" {
		return TeamRequirement(CLIIdentifier, team)
	}
	if devPin == "" {
		return "", errors.New("codesign: this nazar-agent is not signed by a team and pins no CLI build (make agent compiles one in), so it trusts no nazar CLI")
	}
	if !pinRE.MatchString(devPin) {
		return "", fmt.Errorf("codesign: invalid CLI pin %q", devPin)
	}
	return fmt.Sprintf(`identifier "%s" and cdhash H"%s"`, CLIIdentifier, devPin), nil
}
