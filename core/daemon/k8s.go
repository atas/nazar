package daemon

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
)

// The k8s commands (k8s design 7, Milestone 12). k8s.credential is the
// exec plugin's request: a value command, so Serve has checked its peer is
// the genuine nazar CLI (check 0) before it gets here.

// providers registers the credential providers by kind (k8s design 4):
// Milestone 12 builds ca-cert only.
func providers(s *k8s.CAStore, p platform.Platform) map[config.CredentialKind]k8s.Provider {
	m := map[config.CredentialKind]k8s.Provider{}
	for _, pr := range []k8s.Provider{k8s.CACertProvider(s, p)} {
		m[pr.Kind()] = pr
	}
	return m
}

// refuseK8sNotCLI refuses k8s.credential from a peer that is not the
// genuine nazar CLI: one blocked audit line with the caller's chain, no
// prompt, nothing minted (k8s design 2.0).
func (d *Daemon) refuseK8sNotCLI(req control.Request, peer *caller.Chain) error {
	name := req.Args["name"]
	if !config.ValidK8sContextName(name) {
		name = "(invalid name)"
	}
	d.broker.Refuse(broker.Request{K8s: name, Chain: peer, Operation: opK8sCredential}, errNotCLI)
	return control.NewProblem(control.CodeRefused, errNotCLI)
}

// opK8sCredential is the audit operation of a credential request.
const opK8sCredential = "k8s credential"

// k8sCACheckRest closes the check that opens the remedy for a CA nazar made, as keyCheckFirst
// does for a key: the check that loses nothing comes first.
const k8sCACheckRest = "and run nazar k8s list again (deleting the item destroys the CA for good, and the cluster must then trust a new one); if the CA is still unreadable: "

// k8sCARemedy is keyRemedy for a k8s-ca/<name> item (spec 9): the check
// first, then the item removed by hand, then a new CA, which the cluster
// must trust again. Context names are plain words; anything else gets only
// the way to remove the one item.
func (w vaultWords) k8sCARemedy(name string) string {
	account := k8s.VaultPrefix + name
	if !config.ValidK8sContextName(name) || !plainWord(account) {
		if !plainWord(account) {
			return w.removeItemByHand(account)
		}
		return w.deleteItem(account)
	}
	// ca create refuses a context set up already, so forget comes first; it
	// also drops the context's rules, which the user adds again.
	return fmt.Sprintf("%s%s, then nazar k8s forget %s (it removes the context's config entry, its rules and nazar's kubeconfig entries), then nazar k8s ca create %s, then add its certificate to the cluster's client CA bundle (nazar k8s ca show %s --microk8s), then add the context's rules again",
		w.checkFirst(k8sCACheckRest, account), w.deleteItem(account), name, name, name)
}

// k8sCredential mints a credential for context name (k8s design 1.2, 6.1).
// Before the broker: a valid, configured name and parseable exec info
// (else usage: the plugin's exit 2) and a usable CA (else refused, with
// the fix). The broker runs checks 1 to 3 and the gate. At mint time the
// context is read again from the config in force and check 2 is run
// against it again, so a context removed or re-pointed while the prompt was
// open mints nothing, and what is minted is what the config says then.
func (d *Daemon) k8sCredential(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	name := args["name"]
	if !config.ValidK8sContextName(name) {
		return control.NewProblem(control.CodeUsage, "invalid k8s context name %s", cluster.Display(name))
	}
	target := "k8s:" + name
	asked := d.stager.Active() // what the request is checked and shown against
	ctx, ok := asked.K8s[name]
	if !ok {
		d.logOp(target, audit.Error, "k8s credential: no such context in config.yaml", peer)
		return control.NewProblem(control.CodeUsage, "no k8s context %s in config.yaml; nazar k8s ca create %s sets it up", name, name)
	}
	got, err := k8s.ParseExecInfo(args["execInfo"])
	if err != nil {
		var u *k8s.UsageError
		if errors.As(err, &u) {
			d.logOp(target, audit.Error, "k8s credential: "+u.Msg, peer)
			return control.NewProblem(control.CodeUsage, "%s", u.Msg)
		}
		return err
	}
	switch _, err := d.k8sCA.Get(name); {
	case errors.Is(err, k8s.ErrNotFound):
		d.logOp(target, audit.Blocked, "k8s credential: the context has no CA", peer)
		return control.NewProblem(control.CodeRefused, "refused: %s has no CA; nazar k8s ca create %s makes one", name, name)
	case err != nil:
		d.logOp(target, audit.Error, "k8s credential: the context's CA is unusable: "+err.Error(), peer)
		return control.NewProblem(control.CodeError, "the CA of %s can't be used by this nazar-agent; fix: %s", name, d.vault.k8sCAFix(name, err))
	}
	provider := d.k8sIssue[ctx.Credential]
	if provider == nil {
		d.logOp(target, audit.Error, "k8s credential: credential "+string(ctx.Credential)+" is not implemented yet", peer)
		return control.NewProblem(control.CodeError, "credential %s is not implemented yet", ctx.Credential)
	}
	if peer == nil {
		peer = &caller.Chain{Unknown: true}
	}
	dest := ""
	if got != nil {
		dest = got.Server // the audit log quotes it
	}
	// Where the reply goes, before any prompt and whatever approval
	// is cached. A chain with no full chain[1] is check 1's to refuse, with
	// its reason and the block warning (k8s design 2.1); Do checks again.
	if c := peer.Procs; len(c) >= 2 && !c[1].Ref.IsPIDOnly() && !c[1].Ref.IsZero() {
		if reason := d.k8sStdout(peer); reason != "" {
			d.broker.Refuse(broker.Request{K8s: name, Cluster: got, Chain: peer, Operation: opK8sCredential, Destination: dest}, reason)
			return control.NewProblem(control.CodeRefused, "refused: %s", reason)
		}
	}
	var cred k8s.Credential
	defer func() { clear(cred.KeyPEM) }()
	r := d.broker.Handle(broker.Request{
		K8s: name, Cluster: got, Chain: peer,
		Summary: "the Kubernetes credential for " + ctx.Cluster.Server, Operation: opK8sCredential, Destination: dest,
		Do: func(ref platform.ApprovalRef) error {
			// Security review: the context in force now must be the
			// one the request was checked and shown against, in full (its
			// rules, clients, identity, ttl_cert and cluster, and the
			// fallback it falls to); a change of any kind while the prompt
			// was open mints nothing.
			cur := d.stager.Active()
			now := cur.K8s[name]
			if now == nil || got == nil || !reflect.DeepEqual(now, ctx) || cur.K8sFallback(name) != asked.K8sFallback(name) {
				return errors.New("the context changed while the request waited; nothing was minted; run the command again")
			}
			if err := now.Cluster.Match(*got); err != nil {
				return errors.New("the context's cluster does not match; nothing was minted")
			}
			if reason := d.k8sStdout(peer); reason != "" {
				return errors.New(reason + "; nothing was minted")
			}
			c, err := provider.Issue(k8s.IssueInput{Context: now, Approval: ref, Now: d.o.Now()})
			cred = c
			return err
		},
	})
	if !r.Allowed() {
		code := control.CodeRefused
		if r.Decision == audit.Error {
			code = control.CodeError
		}
		return control.NewProblem(code, "refused: %s", r.Reason)
	}
	return out.Emit(control.K8sCredential{TypeMeta: control.Meta(control.KindK8sCredential), Name: name,
		ClientCertificateData: string(cred.CertPEM), ClientKeyData: string(cred.KeyPEM), ExpirationTimestamp: cred.NotAfter})
}

// errStdout is the refusal of a credential whose plugin output is not a
// pipe the client reads (THREAT-MODEL 5.16).
const errStdout = "the plugin's output does not go straight to the program that ran it"

// k8sStdout checks that the CLI's stdout is a pipe whose read end chain[1]
// holds, as client-go runs an exec plugin: a wrapper with exec hops that
// keeps kubectl the CLI's parent but copies its output (tee) is refused.
// It returns the refusal's reason, or "". Fail closed: no chain[1], no
// platform check, or a check that can't tell is a refusal.
func (d *Daemon) k8sStdout(peer *caller.Chain) string {
	if d.o.Pipes == nil {
		return "this system can't check where the plugin's output goes"
	}
	if len(peer.Procs) < 2 {
		return errStdout
	}
	ok, err := d.o.Pipes.StdoutReadBy(peer.Procs[0].Ref, peer.Procs[1].Ref)
	if err != nil {
		d.o.Logf("k8s credential: the plugin's output can't be checked: %v", err)
		return d.stdoutUnknown(err, errStdout, "can't tell who reads the plugin's output; try again")
	}
	if !ok {
		return errStdout
	}
	return ""
}

// stdoutUnknown is the refusal for a stdout check that failed with err. On
// Linux the check reads /proc and fails closed for a moment on a process it
// cannot see into (package pipes): nothing wrapped the program, so the
// message says to try again, unless the client is gone. macOS has next to
// no such error and keeps its refusal word for word.
func (d *Daemon) stdoutUnknown(err error, refused, unknown string) string {
	if d.traits.Enforcer != platform.MacTraits.Enforcer && !errors.Is(err, platform.ErrNoProcess) {
		return unknown
	}
	return refused
}
