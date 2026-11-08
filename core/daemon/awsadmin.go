package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/aws"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
)

// The aws management commands (aws design 8): ca create and show, list
// and forget, as the k8s ones. nazar-agent never reads or writes ~/.aws and
// never calls AWS for setup.

// awsCAFile is where an entry's CA certificate is written for the AWS-side
// steps; nazar never reads it back.
func (d *Daemon) awsCAFile(name string) string {
	return filepath.Join(d.o.PubKeyDir, "aws-ca-"+name+".crt")
}

func (d *Daemon) awsCAObj(ca *certs.CA) control.AWSCA {
	i := ca.Info()
	return control.AWSCA{TypeMeta: control.Meta(control.KindAWSCA), Name: ca.Name, Fingerprint: i.Fingerprint,
		Created: i.Created, NotAfter: i.NotAfter, CertFile: d.awsCAFile(ca.Name), WhileLocked: ca.Access == platform.AccessAfterFirstUnlock}
}

// awsCACheckFirst opens the remedy for a CA nazar made: the check that
// loses nothing comes first.
const awsCACheckFirst = "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
	"and run nazar aws list again (deleting the item destroys the CA for good, and AWS must then trust a new one); if the CA is still unreadable: "

// awsCARemedy is the spec 9 remedy for an aws-ca/<name> item.
func awsCARemedy(name string) string {
	account := aws.VaultPrefix + name
	if !config.ValidAWSName(name) || !plainWord(account) {
		if !plainWord(account) {
			return removeItemByHand(account)
		}
		return deleteItem(account)
	}
	return fmt.Sprintf("%s%s, then nazar aws forget %s, then nazar aws ca create %s, then give the trust anchor its certificate (nazar aws ca show %s)",
		awsCACheckFirst, deleteItem(account), name, name, name)
}

// awsCAFix is the fix for a CA store error: a record that reads but can't
// be used is nazar's to delete (forget removes it); one the Keychain
// refuses gets the spec 9 remedy.
func awsCAFix(name string, err error) string {
	if errors.Is(err, aws.ErrBroken) && config.ValidAWSName(name) {
		return fmt.Sprintf("nazar aws forget %s deletes it (and the entry's config), then nazar aws ca create %s; the trust anchor must then hold the new CA", name, name)
	}
	return awsCARemedy(name)
}

// awsCAProblem turns a CA store error into a refusal with its remedy.
func awsCAProblem(name string, err error) error {
	switch {
	case errors.Is(err, aws.ErrNotFound):
		return control.NewProblem(control.CodeError, "%s has no CA; nazar aws ca create %s makes one", name, name)
	case errors.Is(err, aws.ErrBroken):
		return control.NewProblem(control.CodeError, "the CA record of %s reads but can't be used; nothing was changed. To fix it: %s", name, awsCAFix(name, err))
	case errors.Is(err, aws.ErrUnreadable):
		return control.NewProblem(control.CodeError, "the CA of %s can't be used by this nazar-agent: its Keychain item belongs to another signature of the agent, "+
			"the login keychain is locked, or the item is not one nazar made; nothing was changed. To fix it: %s", name, awsCARemedy(name))
	}
	return err
}

// awsCACreate sets an entry up (aws design 8): its CA in the Secure
// Enclave and its certificate file, its config entry (identity
// <user>-nazar, its own gate block and one login rule for the terminal app
// it was typed in, no ARNs yet): both on one login prompt that shows each.
// No program is pinned: whatever runs credential_process receives the
// credential when the rules allow whoever ran it (aws design 6.1). Refused
// before any prompt: bad arguments, a CA or an entry of that name already
// (one set up with the same identity and access is answered at once),
// unapproved changes. After the prompt config.yaml is re-read and nothing
// is made if it changed; a step that fails undoes the ones before it.
func (d *Daemon) awsCACreate(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	onlyWhenUnlocked, err := onlyWhenUnlockedArg("aws ca create", args)
	if err != nil {
		return err
	}
	access := createAccess(platform.AuthNone, onlyWhenUnlocked)
	name := args["name"]
	if !config.ValidAWSName(name) {
		return control.NewProblem(control.CodeUsage, "invalid aws entry name %s (letters, digits, . _ -)", awsDisplay(name))
	}
	host, err := d.o.RunHost(os.Getuid())
	if err != nil {
		return control.NewProblem(control.CodeError, "can't tell your user name, which the entry's identity is made of: %v", err)
	}
	s := config.AWSEntrySpec{Name: name, Identity: config.AWSIdentity{User: host.User + "-nazar"}}
	if !config.ValidAWSUser(s.Identity.User) {
		return control.NewProblem(control.CodeError, "your user name %s can't make the certificate's CN (%s: 1 to 61 of letters, digits and . _ @ : + = / -)",
			awsDisplay(host.User), awsDisplay(s.Identity.User))
	}
	target := "aws:" + name
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	list, err := d.awsCA.List()
	if err != nil {
		return err
	}
	hasCA, caAccess := false, platform.AccessWhenUnlocked
	for _, i := range list {
		if !strings.EqualFold(i.Name, name) {
			continue
		}
		if i.Broken {
			why := aws.ErrBroken
			if i.Unreadable {
				why = aws.ErrUnreadable
			}
			return awsCAProblem(i.Name, why)
		}
		if i.Name != name {
			return control.NewProblem(control.CodeError, "%s already has a CA, and names must differ in more than letter case", i.Name)
		}
		hasCA, caAccess = true, i.Access
	}
	e, configured := active.AWS[name]
	switch {
	case hasCA && configured && e.Identity == s.Identity && caAccess == access:
		return out.Emit(d.awsSetupObj(name)) // set up already: nothing loosened, nothing asked
	case hasCA && configured && e.Identity == s.Identity:
		if caAccess == platform.AccessWhenUnlocked {
			return control.NewProblem(control.CodeError, "%s is set up already, and its CA signs only while the Mac is unlocked, for the CA's life: run this again with --only-when-unlocked, or nazar aws forget %s, then nazar aws ca create %s, for a new CA", name, name, name)
		}
		return control.NewProblem(control.CodeError, "%s is set up already, and its CA signs while the Mac is locked too, for the CA's life: run this again without --only-when-unlocked, or nazar aws forget %s, then nazar aws ca create %s --only-when-unlocked, for a new CA", name, name, name)
	case hasCA || configured:
		return control.NewProblem(control.CodeError, "%s is set up already (a CA or aws.%s in config.yaml); nazar aws list shows it, nazar aws forget %s removes it", name, name, name)
	}
	for n := range active.AWS {
		if strings.EqualFold(n, name) {
			return control.NewProblem(control.CodeError, "config.yaml has an aws entry %s, and names must differ in more than letter case", n)
		}
	}
	if _, pending := d.stager.Pending(); pending || !sameContent(data, active) {
		return control.NewProblem(control.CodeStaged, "config.yaml has changes that aren't approved yet; run `nazar config check`")
	}
	if app := terminalApp(peer); app != "" {
		r := defaultRule
		r.Apps = []string{"app:" + app}
		s.Rule = &r
	}
	newData, err := config.AddAWSEntry(data, s)
	if err != nil {
		return err
	}
	pv, err := d.stager.Preview(newData)
	if err != nil {
		return err
	}
	lines := []string{
		"The CA key is made in the Secure Enclave. AWS accepts every certificate it issues for any role whose trust policy names its trust anchor.",
		accessLine(access),
		"identity: CN=" + s.Identity.User,
		"the program that runs credential_process (the AWS CLI, an SDK, terraform …) gets the credential when the rules allow whoever ran it",
	}
	if s.Rule == nil {
		lines = append(lines, "no rule yet: every caller is blocked until one is added (nazar aws rule add "+name+" …)")
	}
	lines = append(lines, "not connected yet: you add the trust anchor, profile and role ARNs once AWS trusts the CA")
	lines = append(lines, pv.Diff.Changes...)
	for _, f := range pv.Diff.Loosening {
		lines = append(lines, "loosens "+f.Target+": "+f.Why)
	}
	cl, err := d.claimLogin(target, "set up aws entry", "not set up", peer)
	if err != nil {
		return err
	}
	defer cl.close()
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Set up AWS entry %q?", name),
		Lines:  lines,
		Reason: fmt.Sprintf("set up the AWS entry %q", name),
	})
	if dec != audit.Approved {
		cl.end(false)
		d.logOp(target, dec, "set up aws entry: "+reason, peer)
		return control.NewProblem(control.CodeRefused, "not set up: %s", reason)
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	again, err := d.readConfig()
	if err != nil {
		d.logOp(target, audit.Error, "set up aws entry: approved, but config.yaml could not be re-read after the prompt; nothing made: "+err.Error(), peer)
		return err
	}
	if !bytes.Equal(again, data) {
		cl.end(false)
		d.logOp(target, audit.Error, "set up aws entry: approved, but config.yaml changed while the prompt was open; nothing made", peer)
		return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; nothing was made; run `nazar aws ca create` again")
	}
	d.logOp(target, dec, "set up aws entry: "+reason, peer)
	d.cache.RevokeTarget(target, "aws entry set up")
	var undo []func()
	failed := func(what string, err error) error {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		d.logOp(target, audit.Error, "set up aws entry: approved, but "+what+"; nothing kept: "+err.Error(), peer)
		return fmt.Errorf("%s; nothing was kept: %w", what, err)
	}
	ca, err := d.awsCA.Create(name, access)
	if err != nil {
		d.logOp(target, audit.Error, "set up aws entry: approved, but the CA could not be made: "+err.Error(), peer)
		return awsCAProblem(name, err)
	}
	undo = append(undo, func() {
		if err := d.awsCA.Delete(name); err != nil {
			d.o.Logf("aws: undoing the CA of %s: %v", name, err)
		}
		_ = os.Remove(d.awsCAFile(name))
	})
	if err := writePublic(d.awsCAFile(name), ca.CertPEM()); err != nil {
		return failed("the certificate file could not be written", err)
	}
	if err := writeFileAtomic(d.o.ConfigPath, newData); err != nil {
		return failed("config.yaml could not be updated", err)
	}
	if err := d.stager.ApplyAuthenticated(pv); err != nil {
		if werr := writeFileAtomic(d.o.ConfigPath, data); werr != nil {
			d.o.Logf("aws: restoring config.yaml: %v", werr)
		}
		return failed("the new config.yaml could not be applied", err)
	}
	d.mu.Lock()
	d.lastSeen = contentHash(newData)
	d.mu.Unlock()
	d.prompts.forget()
	cl.end(true)
	return out.Emit(d.awsSetupObj(name))
}

// awsSetupObj is ca create's reply: the entry, its CA with the certificate.
func (d *Daemon) awsSetupObj(name string) control.AWSEntry {
	o := d.awsObj(name, d.stager.Active())
	if ca, err := d.awsCA.Get(name); err == nil && o.CA != nil {
		o.CA.CertPEM = string(ca.CertPEM())
	}
	return o
}

// awsCAShow returns a CA with its certificate, read from the Vault record.
func (d *Daemon) awsCAShow(name string, out control.Emitter) error {
	if !config.ValidAWSName(name) {
		return control.NewProblem(control.CodeUsage, "invalid aws entry name %s", awsDisplay(name))
	}
	ca, err := d.awsCA.Get(name)
	if err != nil {
		return awsCAProblem(name, err)
	}
	o := d.awsCAObj(ca)
	o.CertPEM = string(ca.CertPEM())
	return out.Emit(o)
}

// awsObj describes entry name as c configures it and its CA as stored,
// with its state and the remedy for it (as k8sObj).
func (d *Daemon) awsObj(name string, c *config.Config) control.AWSEntry {
	o := control.AWSEntry{TypeMeta: control.Meta(control.KindAWSEntry), Name: name, Rules: []string{}, Warnings: []string{}}
	if shown, staged := d.shownConfig(); shown.AWS[name] != nil {
		pol := entryRules(config.AWSRef(name), shown, staged)
		o.Policy, o.Warnings = &pol, entryWarnings(d.stager.LastProblems(), "aws.", name, shown.AWSNames())
	}
	e, ok := c.AWS[name]
	if ok {
		o.Configured, o.Duration = true, shortDuration(e.Duration)
		o.Identity = &control.AWSIdentity{User: e.Identity.User}
		o.TrustAnchorArn, o.ProfileArn, o.RoleArn, o.Region = e.TrustAnchorArn, e.ProfileArn, e.RoleArn, e.Region
		for _, r := range e.Rules {
			o.Rules = append(o.Rules, fmt.Sprintf("%d: %s", r.Index, r.Canonical()))
		}
		o.Rules = append(o.Rules, "fallback: "+c.AWSFallback(name).String())
	}
	switch ca, err := d.awsCA.Get(name); {
	case err == nil && o.Configured && !e.Connected():
		co := d.awsCAObj(ca)
		o.CA, o.State, o.Remedy = &co, control.AWSStateNotConnected, config.NotConnected(name)
	case err == nil && o.Configured:
		co := d.awsCAObj(ca)
		o.CA, o.State = &co, control.AWSStateOK
	case err == nil:
		co := d.awsCAObj(ca)
		o.CA, o.State = &co, control.AWSStateNoEntry
		o.Remedy = fmt.Sprintf("nazar aws forget %s, then nazar aws ca create %s", name, name)
	case errors.Is(err, aws.ErrNotFound) && o.Configured:
		o.State, o.Remedy = control.AWSStateNoCA, fmt.Sprintf("nazar aws forget %s, then nazar aws ca create %s", name, name)
	case errors.Is(err, aws.ErrNotFound):
		o.State = control.AWSStateAbsent
	default:
		o.State = control.AWSStateCAUnusable
		o.CABroken, o.UnusableReason, o.Remedy = true, err.Error(), awsCAFix(name, err)
	}
	return o
}

// awsList lists every configured entry and every CA record.
func (d *Daemon) awsList(out control.Emitter) error {
	c := d.stager.Active()
	list, err := d.awsCA.List()
	if err != nil {
		return err
	}
	names := c.AWSNames()
	for _, i := range list {
		if !slices.Contains(names, i.Name) {
			names = append(names, i.Name)
		}
	}
	slices.Sort(names)
	res := control.AWSEntryList{TypeMeta: control.Meta(control.KindAWSEntryList), Items: []control.AWSEntry{}}
	for _, n := range names {
		res.Items = append(res.Items, d.awsObj(n, c))
	}
	return out.Emit(res)
}

// awsForget deletes an entry's CA (Secure Enclave key and Vault item), its
// .crt file and its config entry, and drops its remembered approvals,
// behind one login prompt (as k8sForget). AWS keeps trusting the CA's
// certificate until the trust anchor is disabled; nothing can be issued
// under it any more.
func (d *Daemon) awsForget(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	name := args["name"]
	if !config.ValidAWSName(name) {
		return control.NewProblem(control.CodeUsage, "invalid aws entry name %s", awsDisplay(name))
	}
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	_, configured := active.AWS[name]
	_, caErr := d.awsCA.Get(name)
	hasCA := caErr == nil || errors.Is(caErr, aws.ErrBroken)
	switch {
	case errors.Is(caErr, aws.ErrUnreadable):
		return awsCAProblem(name, caErr)
	case !configured && !hasCA:
		return control.NewProblem(control.CodeError, "no aws entry or CA named %s", name)
	}
	var newData []byte
	if configured {
		if _, pending := d.stager.Pending(); pending || !sameContent(data, active) {
			return control.NewProblem(control.CodeStaged, "config.yaml has changes that aren't approved yet; run `nazar config check`")
		}
		if newData, err = config.RemoveAWSEntry(data, name); err != nil {
			return err
		}
	}
	target := "aws:" + name
	cl, err := d.claimLogin(target, "forget aws entry", "not forgotten", peer)
	if err != nil {
		return err
	}
	defer cl.close()
	var lines []string
	if hasCA {
		lines = append(lines, "The CA is destroyed in the Secure Enclave; this can't be undone. Sessions it gave stay valid until they end.")
	}
	if configured {
		lines = append(lines, "config.yaml loses aws."+name+".")
	}
	lines = append(lines, "~/.aws/config is not touched; AWS keeps the trust anchor until you disable or delete it.")
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Forget AWS entry %q?", name),
		Lines:  lines,
		Reason: fmt.Sprintf("forget the AWS entry %q", name),
	})
	d.logOp(target, dec, "forget aws entry: "+reason, peer)
	if dec != audit.Approved {
		cl.end(false)
		return control.NewProblem(control.CodeRefused, "not forgotten: %s", reason)
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	if configured {
		again, err := d.readConfig()
		if err != nil || !bytes.Equal(again, data) {
			cl.end(false)
			d.logOp(target, audit.Error, "forget aws entry: approved, but config.yaml changed while the prompt was open; nothing changed", peer)
			return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; run `nazar aws forget %s` again", name)
		}
	}
	d.cache.RevokeTarget(target, "aws entry forgotten")
	if hasCA {
		if err := d.awsCA.Delete(name); err != nil {
			d.logOp(target, audit.Error, "forget aws entry: approved, but the CA could not be deleted: "+err.Error(), peer)
			return awsCAProblem(name, err)
		}
		if err := os.Remove(d.awsCAFile(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			d.o.Logf("aws: removing %s: %v", d.awsCAFile(name), err)
		}
	}
	if configured {
		if err := writeFileAtomic(d.o.ConfigPath, newData); err != nil {
			d.logOp(target, audit.Error, "forget aws entry: the CA is gone, but config.yaml could not be updated: "+err.Error(), peer)
			return err
		}
		pv, err := d.stager.Preview(newData)
		if err == nil {
			err = d.stager.ApplyAuthenticated(pv)
		}
		if err != nil {
			d.logOp(target, audit.Error, "forget aws entry: the CA is gone, but the new config.yaml could not be applied: "+err.Error(), peer)
			return err
		}
		d.mu.Lock()
		d.lastSeen = contentHash(newData)
		d.mu.Unlock()
		d.prompts.forget()
	}
	cl.end(true)
	return out.Emit(d.awsObj(name, d.stager.Active()))
}

// awsAdvice warns about every entry c configures that has no CA.
func (d *Daemon) awsAdvice(c *config.Config) []control.ConfigProblem {
	if c == nil {
		return nil
	}
	var out []control.ConfigProblem
	for _, name := range c.AWSNames() {
		if _, err := d.awsCA.Get(name); errors.Is(err, aws.ErrNotFound) {
			out = append(out, control.ConfigProblem{Severity: string(config.SevWarning), Path: "aws." + name,
				Message: fmt.Sprintf("aws entry %s has no CA, so it gets no credential; run `nazar aws forget %s`, then `nazar aws ca create %s`", name, name, name)})
		}
	}
	return out
}

// awsCAProblems lists the unusable aws-ca/ items for nazar status.
func (d *Daemon) awsCAProblems() []control.VaultProblem {
	list, err := d.awsCA.List()
	if err != nil {
		d.o.Logf("aws: %v", err)
		return nil
	}
	var out []control.VaultProblem
	for _, i := range list {
		if !i.Broken {
			continue
		}
		why := aws.ErrBroken
		if i.Unreadable {
			why = aws.ErrUnreadable
		}
		p := control.VaultProblem{Item: aws.VaultPrefix + i.Name, Reason: i.Problem,
			Effect: fmt.Sprintf("the AWS CLI and SDKs get no credential for aws entry %s", i.Name), Remedy: awsCAFix(i.Name, why)}
		if !config.ValidAWSName(i.Name) {
			p.Item, p.Effect = awsDisplay(p.Item), "none: nazar never uses it as a CA; it is listed so that it can be removed"
		}
		out = append(out, p)
	}
	return out
}
