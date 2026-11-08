package codesign

import (
	"fmt"
	"regexp"
)

// The parts of a requirement TeamRequirement writes. Both are checked
// byte for byte before they reach requirement-language text, so neither
// can close the quotes and add a clause (`X" or anchor apple`).
var (
	teamRE       = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	identifierRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)
)

// TeamRequirement is the code requirement "signing identifier identifier,
// signed with an Apple-issued certificate of team team": what nazar's
// programs require of each other (spec 4 and 6.1, Milestone 6). It names
// no path and no build, so it holds wherever a program is installed and
// across upgrades, and nothing but Apple can issue a certificate whose
// subject OU is that team (`anchor apple generic`). An ad-hoc signature
// never satisfies it.
func TeamRequirement(identifier, team string) (string, error) {
	if !identifierRE.MatchString(identifier) {
		return "", fmt.Errorf("codesign: invalid signing identifier %q", identifier)
	}
	if !teamRE.MatchString(team) {
		return "", fmt.Errorf("codesign: invalid team identifier %q", team)
	}
	return fmt.Sprintf(`identifier "%s" and anchor apple generic and certificate leaf[subject.OU] = "%s"`, identifier, team), nil
}
