package control

import "time"

// The aws commands (aws design 8).
const (
	// CmdAWSCredential is credential_process's request (args: name): gated,
	// and a value command, answered only to the genuine nazar CLI.
	CmdAWSCredential = "aws.credential"
	// CmdAWSCACreate sets an entry up on one login prompt: its CA, its
	// config entry (identity <user>-nazar, gate block, the terminal's login
	// rule; no program is pinned). Args: name, [onlyWhenUnlocked=true]. The
	// reply is an AWSEntry whose CA carries its certificate.
	CmdAWSCACreate = "aws.ca.create"
	CmdAWSCAShow   = "aws.ca.show" // args: name (read)
	CmdAWSList     = "aws.list"    //            (read)
	CmdAWSForget   = "aws.forget"  // args: name (login: the CA is destroyed)
)

// KindAWSCredential is wire only: the reply to aws.credential, never
// printed by a --json command.
const KindAWSCredential = "AWSCredential"

// Kinds of the management commands.
const (
	KindAWSCA        = "AWSCA"
	KindAWSEntry     = "AWSEntry"
	KindAWSEntryList = "AWSEntryList"
)

// AWSCredential is a session from IAM Roles Anywhere: what
// credential_process prints. Never a certificate or a key.
type AWSCredential struct {
	TypeMeta
	Name            string    `json:"name"`
	AccessKeyID     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Expiration      time.Time `json:"expiration"`
	AccountID       string    `json:"accountId"`
}

// AWSCA is an entry's certificate authority: public facts only (as K8sCA).
type AWSCA = K8sCA

// AWSIdentity is the subject of the entry's certificates.
type AWSIdentity struct {
	User string `json:"user"`
}

// AWSEntry is an entry as config.yaml configures it and its CA as the
// Vault holds it; either may be missing.
type AWSEntry struct {
	TypeMeta
	Name           string       `json:"name"`
	Configured     bool         `json:"configured"`
	Identity       *AWSIdentity `json:"identity,omitempty"`
	TrustAnchorArn string       `json:"trustAnchorArn,omitempty"`
	ProfileArn     string       `json:"profileArn,omitempty"`
	RoleArn        string       `json:"roleArn,omitempty"`
	Region         string       `json:"region,omitempty"`
	Duration       string       `json:"duration,omitempty"`
	Rules          []string     `json:"rules"`
	// Policy is the entry's rules as config.yaml has them now (the staged
	// change when there is one), in the shape of a key's; FallbackSource is
	// "entry-gate" for the entry's own gate. Absent when config.yaml has no
	// entry for it.
	Policy   *SSHKeyRules `json:"policy,omitempty"`
	Warnings []string     `json:"warnings"`
	// State is one of the AWSState values; Remedy says what fixes it.
	State          string `json:"state"`
	CA             *AWSCA `json:"ca"`
	CABroken       bool   `json:"caBroken"`
	UnusableReason string `json:"unusableReason,omitempty"`
	Remedy         string `json:"remedy,omitempty"`
}

// States of an entry (AWSEntry.State): those of a k8s context, and
// not-connected for an entry without its ARNs.
const (
	AWSStateOK           = K8sStateOK
	AWSStateNotConnected = "not-connected" // configured and a CA, no ARNs yet
	AWSStateNoEntry      = K8sStateNoEntry
	AWSStateNoCA         = K8sStateNoCA
	AWSStateCAUnusable   = K8sStateCAUnusable
	AWSStateAbsent       = K8sStateAbsent
)

// AWSEntryList is the reply to aws.list.
type AWSEntryList struct {
	TypeMeta
	Items []AWSEntry `json:"items"`
}
