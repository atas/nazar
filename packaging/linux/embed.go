// Package linuxfiles holds the files `nazar install --system` puts on a
// Linux machine, embedded in the CLI. It is portable, as the install code
// that uses it is, so its tests run on every OS.
package linuxfiles

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// OwnerPlaceholder stands for the action's owners in the shipped policy
// (polkit.OwnerPlaceholder names the same text, which that package cannot
// share with a portable one; both are tested against the file).
const OwnerPlaceholder = "@NAZAR_OWNERS@"

// Policy is the polkit action as shipped, with OwnerPlaceholder in it. It
// never goes on a machine as it is: PolicyFor fills in the owners.
//
//go:embed dev.nazar.authenticate.policy
var Policy []byte

// UdevRule gives the tss group /dev/tpmrm0.
//
//go:embed 70-nazar-tpm.rules
var UdevRule []byte

// ownerRE is one owner as polkit takes it and as nothing in the XML file
// can be misread: a user, never a group, which polkit does not count.
var ownerRE = regexp.MustCompile(`^unix-user:[a-z_][a-z0-9_-]*$`)

// PolicyFor is Policy with its placeholder replaced by the owners, joined
// by one space. No owner, an owner that is not a plain unix-user:<name> or
// a Policy without the placeholder is an error, so a policy that would
// fail every login gate is never written.
func PolicyFor(owners []string) ([]byte, error) {
	if len(owners) == 0 {
		return nil, errors.New("the polkit action needs an owner")
	}
	for _, o := range owners {
		if !ownerRE.MatchString(o) {
			return nil, fmt.Errorf("%q is not an owner polkit can have (unix-user:<name>)", o)
		}
	}
	if !bytes.Contains(Policy, []byte(OwnerPlaceholder)) {
		return nil, fmt.Errorf("the shipped polkit action has no %s placeholder", OwnerPlaceholder)
	}
	return bytes.ReplaceAll(Policy, []byte(OwnerPlaceholder), []byte(strings.Join(owners, " "))), nil
}
