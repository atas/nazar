// Package aws is the AWS adapter (aws design, Part 2): a CA per entry in
// the certificate engine, the leaf each credential_process run mints, the
// AWS4-X509-ECDSA-SHA256 signature of one CreateSession request, and the
// call to IAM Roles Anywhere that turns it into session credentials.
package aws

import (
	"errors"
	"time"

	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// VaultPrefix is the Vault item prefix of the CA records: aws-ca/<name>.
const VaultPrefix = "aws-ca/"

// kind is the aws entries' CA records: never a k8s one's (aws design 1).
var kind = certs.NewKind("aws", VaultPrefix, "entry", "nazar aws CA ", config.ValidAWSName)

var (
	ErrExists      = kind.ErrExists()
	ErrNotFound    = kind.ErrNotFound()
	ErrInvalidName = kind.ErrInvalidName()
	// ErrUnreadable: the Vault refused to return the record (spec 9); such
	// a record is never deleted by the store.
	ErrUnreadable = kind.ErrUnreadable()
	// ErrBroken: the record reads but can't be used.
	ErrBroken = kind.ErrBroken()
)

// NewCAStore returns the store of the aws entries' CAs over p and v.
func NewCAStore(p platform.Platform, v platform.Vault, now func() time.Time) *certs.Store {
	return certs.NewStore(kind, p, v, now)
}

// Skew is how far either side of the Mac's clock a leaf is valid (aws
// design 5.1): it is used once, within a second, and only has to survive
// the clock difference between the Mac and AWS.
const Skew = 5 * time.Minute

// Issue mints the leaf of one CreateSession (aws design 4.3, 5.1): CN=user,
// no O=, serial, valid now-5m to now+5m, signed by ca's enclave key with
// ref. ca must come from NewCAStore's store.
func Issue(ca *certs.CA, p platform.Platform, user string, serial certs.Serial, now time.Time, ref platform.ApprovalRef) (certs.Leaf, error) {
	if !config.ValidAWSUser(user) {
		return certs.Leaf{}, errors.New("aws: invalid identity user")
	}
	if serial.Hex() == "" {
		return certs.Leaf{}, errors.New("aws: a leaf needs its serial")
	}
	return ca.Issue(p, certs.LeafSpec{CN: user, NotBefore: now.Add(-Skew), NotAfter: now.Add(Skew), Serial: serial}, now, ref)
}
