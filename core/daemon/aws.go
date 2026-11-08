package daemon

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/aws"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
)

// The aws commands (aws design 3, 6, 8). aws.credential is
// credential_process's request: a value command, so Serve has checked its
// peer is the genuine nazar CLI (check 0) before it gets here.

// opAWSCredential is the audit operation of a credential request; the
// leaf's serial follows it ("aws credential session <32 hex digits>"),
// which is the role session name AWS gives the session.
const opAWSCredential = "aws credential"

// errAWSStdout is the refusal of a credential whose output is not a pipe
// the program that ran nazar alone reads (aws design 3.4).
const errAWSStdout = "the credential's output does not go straight to the program that ran it"

// awsDisplay renders a name from a request for a message.
func awsDisplay(s string) string {
	if len(s) > 256 {
		s = s[:256]
	}
	return strconv.QuoteToASCII(s)
}

// refuseAWSNotCLI refuses aws.credential from a peer that is not the
// genuine nazar CLI: one blocked audit line, no prompt, nothing minted.
func (d *Daemon) refuseAWSNotCLI(req control.Request, peer *caller.Chain) error {
	name := req.Args["name"]
	if !config.ValidAWSName(name) {
		name = "(invalid name)"
	}
	d.broker.Refuse(broker.Request{AWS: name, Chain: peer, Operation: opAWSCredential}, errNotCLI)
	return control.NewProblem(control.CodeRefused, errNotCLI)
}

// awsClient is the Roles Anywhere client: the daemon option (set by tests
// only), else AWS itself.
func (d *Daemon) awsClient() *aws.Client {
	if d.o.AWS != nil {
		return d.o.AWS
	}
	return &aws.Client{}
}

// awsCredential mints a session for entry name (aws design 3.3, 6). Before
// the broker: a valid, configured name (else usage: exit 2), an entry that
// is connected and has a usable CA (else exit 1 with the fix, or refused
// for a missing CA), the leaf's serial drawn for the audit line, and the
// stdout check. The broker runs checks 1 and 3 and the gate. At mint time
// the entry in force must be the one the request was checked and shown
// against, and the stdout check passes again; then one leaf is issued,
// one CreateSession sent with it, the reply checked, and the leaf's key
// dropped. The CLI gets the session, never the certificate or the key.
func (d *Daemon) awsCredential(ctx context.Context, args map[string]string, peer *caller.Chain, out control.Emitter) error {
	name := args["name"]
	if !config.ValidAWSName(name) {
		return control.NewProblem(control.CodeUsage, "invalid aws entry name %s", awsDisplay(name))
	}
	target := "aws:" + name
	asked := d.stager.Active()
	entry, ok := asked.AWS[name]
	if !ok {
		d.logOp(target, audit.Error, "aws credential: no such entry in config.yaml", peer)
		return control.NewProblem(control.CodeUsage, "no aws entry %s in config.yaml; nazar aws ca create %s sets it up", name, name)
	}
	if !entry.Connected() {
		d.logOp(target, audit.Error, "aws credential: the entry is not connected", peer)
		return control.NewProblem(control.CodeError, "%s", config.NotConnected(name))
	}
	switch _, err := d.awsCA.Get(name); {
	case errors.Is(err, aws.ErrNotFound):
		d.logOp(target, audit.Blocked, "aws credential: the entry has no CA", peer)
		return control.NewProblem(control.CodeRefused, "refused: %s has no CA; nazar aws forget %s, then nazar aws ca create %s makes one", name, name, name)
	case err != nil:
		d.logOp(target, audit.Error, "aws credential: the entry's CA is unusable: "+err.Error(), peer)
		return control.NewProblem(control.CodeError, "the CA of %s can't be used by this nazar-agent; fix: %s", name, awsCAFix(name, err))
	}
	if peer == nil {
		peer = &caller.Chain{Unknown: true}
	}
	serial, err := certs.NewSerial()
	if err != nil {
		return err
	}
	op := opAWSCredential + " session " + serial.Hex()
	// Where the reply goes, before any prompt and whatever approval is
	// cached; a chain with no full chain[1] is check 1's to refuse.
	if c := peer.Procs; len(c) >= 2 && !c[1].Ref.IsPIDOnly() && !c[1].Ref.IsZero() {
		if reason := d.awsStdout(peer); reason != "" {
			d.broker.Refuse(broker.Request{AWS: name, Chain: peer, Operation: op, Destination: entry.RoleArn}, reason)
			return control.NewProblem(control.CodeRefused, "refused: %s", reason)
		}
	}
	var sess aws.Session
	r := d.broker.Handle(broker.Request{
		AWS: name, Chain: peer,
		Summary:   fmt.Sprintf("the AWS credential for %s, %s", entry.RoleArn, shortDuration(entry.Duration)),
		Operation: op, Destination: entry.RoleArn,
		Do: func(ref platform.ApprovalRef) error {
			// The entry in force now must be the one the request was
			// checked and shown against, in full, and the fallback it
			// falls to; a change of any kind while the prompt was open
			// mints nothing and calls nothing.
			cur := d.stager.Active()
			now := cur.AWS[name]
			if now == nil || !reflect.DeepEqual(now, entry) || cur.AWSFallback(name) != asked.AWSFallback(name) {
				return errors.New("the entry changed while the request waited; nothing was minted; run the command again")
			}
			if reason := d.awsStdout(peer); reason != "" {
				return errors.New(reason + "; nothing was minted")
			}
			ca, err := d.awsCA.Get(name)
			if err != nil {
				return err
			}
			at := d.o.Now()
			leaf, err := aws.Issue(ca, d.o.Platform, now.Identity.User, serial, at, ref)
			if err != nil {
				return err
			}
			defer func() { leaf.Key = nil }() // used once; never in a reply, a log or a file
			s, err := d.awsClient().CreateSession(ctx, now, leaf, at)
			if err != nil {
				return err
			}
			sess = s
			return nil
		},
	})
	if !r.Allowed() {
		if r.Decision == audit.Error {
			return control.NewProblem(control.CodeError, "%s", r.Reason)
		}
		return control.NewProblem(control.CodeRefused, "refused: %s", r.Reason)
	}
	return out.Emit(control.AWSCredential{TypeMeta: control.Meta(control.KindAWSCredential), Name: name,
		AccessKeyID: sess.AccessKeyID, SecretAccessKey: sess.SecretAccessKey, SessionToken: sess.SessionToken,
		Expiration: sess.Expiration, AccountID: sess.AccountID})
}

// shortDuration renders d as config.yaml writes it: 1h, 30m.
func shortDuration(d time.Duration) string {
	switch {
	case d > 0 && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d > 0 && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// awsStdout is k8sStdout for credential_process: fd 1 of the CLI is a pipe
// whose read end chain[1] alone holds. It returns the refusal's reason, or
// "". Fail closed.
func (d *Daemon) awsStdout(peer *caller.Chain) string {
	if d.o.Pipes == nil {
		return "this system can't check where the credential's output goes"
	}
	if len(peer.Procs) < 2 {
		return errAWSStdout
	}
	ok, err := d.o.Pipes.StdoutReadBy(peer.Procs[0].Ref, peer.Procs[1].Ref)
	if err != nil {
		d.o.Logf("aws credential: the output can't be checked: %v", err)
	}
	if err != nil || !ok {
		return errAWSStdout
	}
	return ""
}
