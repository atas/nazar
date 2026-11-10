package main

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

// awsCredential is `nazar aws credential <name>`, the AWS CLI's and SDKs'
// credential_process (aws design 3). It is a pipe, as k8s credential is:
// no --json, no config file, no environment variable read at all, the
// socket from the user database's home, the agent checked by its
// signature, or on Linux by its hash against the record in that same home
// (the nazartest build's test socket only). One write of the
// credential_process JSON to stdout, or one line to stderr and the exit
// code (6.3).
func (a *app) awsCredential(args []string) int {
	if a.json {
		return a.credFail(control.NewProblem(control.CodeUsage, "aws credential takes no --json: its stdout is the credential_process JSON"))
	}
	pos, err := a.parse(a.flags("aws credential"), args, 1)
	if err != nil {
		return a.credFail(err)
	}
	name := pos[0]
	if !config.ValidAWSName(name) {
		return a.credFail(control.NewProblem(control.CodeUsage, "aws credential: invalid entry name %q", name))
	}
	c, err := a.credentialClient()
	if err != nil {
		return a.credFail(err)
	}
	var cred control.AWSCredential
	if err := c.Call(context.Background(), control.NewRequest(control.CmdAWSCredential, map[string]string{"name": name}), control.KindAWSCredential, &cred); err != nil {
		return a.credFail(err)
	}
	if cred.Name != name {
		return a.credFail(control.NewProblem(control.CodeError, "aws credential: a credential for another entry came back"))
	}
	out, err := encodeProcessCredential(cred)
	if err != nil {
		return a.credFail(control.NewProblem(control.CodeError, "aws credential: a malformed credential came back"))
	}
	defer clear(out)
	if _, err := a.stdout.Write(out); err != nil {
		return control.ExitError
	}
	return control.ExitOK
}

// processCredential is the credential_process reply (aws design 3.5), in
// the order the AWS guides give its fields.
type processCredential struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
	AccountID       string `json:"AccountId"`
}

var (
	accessKeyIDRE = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	accountIDRE   = regexp.MustCompile(`^[0-9]{12}$`)
	tokenRE       = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// errMalformed: the agent's reply is not a credential the CLI will print.
var errMalformed = control.NewProblem(control.CodeError, "malformed credential")

// encodeProcessCredential renders c as one JSON object and a newline,
// after checking each field is of its shape.
func encodeProcessCredential(c control.AWSCredential) ([]byte, error) {
	if !accessKeyIDRE.MatchString(c.AccessKeyID) || !plainToken(c.SecretAccessKey) || !plainToken(c.SessionToken) ||
		!accountIDRE.MatchString(c.AccountID) || c.Expiration.IsZero() {
		return nil, errMalformed
	}
	b, err := json.Marshal(processCredential{Version: 1, AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken,
		Expiration: c.Expiration.UTC().Format(time.RFC3339), AccountID: c.AccountID})
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// plainToken: printable ASCII without spaces, at most 16 KiB.
func plainToken(s string) bool { return len(s) <= 16<<10 && tokenRE.MatchString(s) }
