package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/platform"
)

// Serve implements control.Handler. Read commands need nothing, tighten
// commands apply at once, loosen commands need the login gate (spec 6).
func (d *Daemon) Serve(ctx context.Context, req control.Request, peer *caller.Chain, out control.Emitter) {
	var err error
	switch {
	case control.ValueCommand(req.Command) && !control.PeerIsNazarCLI(ctx):
		// A value goes to the genuine nazar CLI only (secrets design 7.3):
		// one guard for every command that returns one, before its handler.
		err = d.refuseNotCLI(req, peer)
	case req.Command == control.CmdSecretAdd:
		err = d.secretAdd(req.Args, peer, out)
	case req.Command == control.CmdSecretList:
		err = d.secretList(out)
	case req.Command == control.CmdSecretDelete:
		err = d.secretDelete(req.Args["name"], peer, out)
	case req.Command == control.CmdSecretGet:
		err = d.secretGet(req.Args["name"], peer, out)
	case req.Command == control.CmdSecretHelper:
		err = d.secretHelper(req.Args, peer, out)
	case req.Command == control.CmdSecretRun:
		err = d.secretRun(req.Args, peer, out)
	case req.Command == control.CmdK8sCredential:
		err = d.k8sCredential(req.Args, peer, out)
	case req.Command == control.CmdK8sCACreate:
		err = d.k8sCACreate(req.Args, peer, out)
	case req.Command == control.CmdK8sCAShow:
		err = d.k8sCAShow(req.Args["name"], out)
	case req.Command == control.CmdK8sList:
		err = d.k8sList(out)
	case req.Command == control.CmdK8sForget:
		err = d.k8sForget(req.Args, peer, out)
	case req.Command == control.CmdAWSCredential:
		err = d.awsCredential(ctx, req.Args, peer, out)
	case req.Command == control.CmdAWSCACreate:
		err = d.awsCACreate(req.Args, peer, out)
	case req.Command == control.CmdAWSCAShow:
		err = d.awsCAShow(req.Args["name"], out)
	case req.Command == control.CmdAWSList:
		err = d.awsList(out)
	case req.Command == control.CmdAWSForget:
		err = d.awsForget(req.Args, peer, out)
	default:
		err = d.serveOther(ctx, req, peer, out)
	}
	if err != nil {
		if e := out.Emit(control.AsProblem(err)); e != nil {
			d.o.Logf("control: reply: %v", e)
		}
	}
}

// serveOther serves the commands that are not about secrets.
func (d *Daemon) serveOther(ctx context.Context, req control.Request, peer *caller.Chain, out control.Emitter) error {
	var err error
	switch req.Command {
	case control.CmdSSHKeyList:
		err = d.sshKeyList(out)
	case control.CmdSSHKeyPubkey:
		err = d.sshKeyPubkey(req.Args["name"], out)
	case control.CmdSSHKeyCreate:
		err = d.sshKeyCreate(req.Args, peer, out)
	case control.CmdSSHKeyDelete:
		err = d.sshKeyDelete(req.Args["name"], peer, out)
	case control.CmdStatus:
		err = d.status(ctx, req.Follow, out)
	case control.CmdRevoke:
		err = d.revoke(req.Args, peer, out)
	case control.CmdConfigCheck:
		err = d.configCheck(out)
	case control.CmdConfigApply:
		err = d.configApply(req.Args["hash"], peer, out)
	case control.CmdTrustApp:
		err = d.trustApp(req.Args["app"], peer, out)
	case control.CmdSSHKeyRules:
		err = d.sshKeyRules(req.Args["name"], out)
	case control.CmdAppsList:
		err = d.appsList(out)
	case control.CmdConfigEdit:
		err = d.configEdit(req.Args, peer, out)
	default:
		err = control.NewProblem(control.CodeUsage, "unknown command %q", req.Command)
	}
	return err
}

func (d *Daemon) sshKey(info keys.Info) control.SSHKey {
	c := d.stager.Active()
	k := control.SSHKey{
		TypeMeta: control.Meta(control.KindSSHKey), Name: info.Name, Type: info.Type,
		Fingerprint: info.Fingerprint, PublicKey: info.AuthorizedKey, Broken: info.Broken,
		UserPresence: info.Auth == platform.AuthUserPresence, WhileLocked: !info.Broken && info.Access == platform.AccessAfterFirstUnlock,
		Created: info.Created, Rules: []string{}, Usable: !info.Broken,
	}
	if info.Broken {
		k.UnusableReason, k.Remedy = keyReason(info), keyRemedy(info.Name)
	}
	shown, staged := d.shownConfig()
	policy := entryRules(config.KeyEntry(info.Name), shown, staged)
	k.Policy, k.Warnings, k.LastUsed = &policy, d.keyWarnings(info, shown), d.uses.last(info.Name)
	if ck, ok := c.SSHAgent.Keys[info.Name]; ok {
		k.Configured = true
		for _, r := range ck.Rules {
			k.Rules = append(k.Rules, fmt.Sprintf("%d: %s", r.Index, r.Canonical()))
		}
	}
	k.Rules = append(k.Rules, "fallback: "+c.Fallback(info.Name).String())
	return k
}

func (d *Daemon) sshKeyList(out control.Emitter) error {
	list, err := d.keys.List()
	if err != nil {
		return err
	}
	res := control.SSHKeyList{TypeMeta: control.Meta(control.KindSSHKeyList), Items: []control.SSHKey{}, Since: d.started}
	for _, k := range list {
		res.Items = append(res.Items, d.sshKey(k))
	}
	return out.Emit(res)
}

func (d *Daemon) sshKeyPubkey(name string, out control.Emitter) error {
	info, err := d.keys.Get(name)
	if errors.Is(err, keys.ErrNotFound) || errors.Is(err, keys.ErrInvalidName) {
		return control.NewProblem(control.CodeError, "no SSH key named %q", name)
	}
	if err != nil {
		return err
	}
	return out.Emit(d.sshKey(info))
}

// defaultRule is the one rule `nazar ssh-key create` writes for the
// terminal app the command was typed in: the app's own identity
// (an app: matcher, team pinned by the same approval), login once per tab,
// for at most 8 hours. It is the README's own posture for a terminal.
var defaultRule = config.RuleSpec{Scope: config.ScopeSession, Gate: config.GateLogin, Expire: 8 * time.Hour}

// alwaysAskRule is the one rule `ssh-key create --always-ask` writes for
// the terminal app instead: login on every use, no expiry. With the key's
// own gate block, every policy that can reach the key fits the chip, so
// the key is created with Secure Enclave user presence (spec 4.5). With no
// terminal the entry is the key's own gate block alone, as without the
// flag: the flag never widens who may ask for the key.
var alwaysAskRule = config.RuleSpec{Scope: config.ScopeUse, Gate: config.GateLogin}

// createAuth is the Secure Enclave protection a key created under c gets
// (spec 4.5). Without alwaysAsk: user presence when the entry calls for it
// (config.NeedsUserPresence; a block-only entry does not). With
// alwaysAsk (`ssh-key create --always-ask`): user presence whenever every
// policy that can reach the key fits the chip (config.PresenceFits), a
// block-only entry included, and ok is false otherwise: such a key is
// never created without it.
func createAuth(c *config.Config, name string, alwaysAsk bool) (auth platform.AuthPolicy, ok bool) {
	switch {
	case alwaysAsk && c.PresenceFits(name):
		return platform.AuthUserPresence, true
	case alwaysAsk:
		return platform.AuthNone, false
	case c.NeedsUserPresence(name):
		return platform.AuthUserPresence, true
	}
	return platform.AuthNone, true
}

// onlyWhenUnlockedArg reads the request argument onlyWhenUnlocked of what
// (ssh-key create, secret add, k8s ca create, aws ca create): "true" (the CLI's
// --only-when-unlocked) or absent; anything else is a usage error.
func onlyWhenUnlockedArg(what string, args map[string]string) (bool, error) {
	v, ok := args["onlyWhenUnlocked"]
	if !ok {
		return false, nil
	}
	if v != "true" {
		return false, control.NewProblem(control.CodeUsage, "%s: onlyWhenUnlocked must be true or absent, not %q", what, v)
	}
	return true, nil
}

// createAccess is when the chip lets a new key work, fixed for its life:
// only while the Mac is unlocked when onlyWhenUnlocked asks for it or the
// key gets user presence (it asks for Touch ID on every use, which a
// locked Mac can't give, and so keeps the locked screen's protection);
// otherwise also while the Mac is locked, once the user has logged in.
func createAccess(auth platform.AuthPolicy, onlyWhenUnlocked bool) platform.Access {
	if onlyWhenUnlocked || auth == platform.AuthUserPresence {
		return platform.AccessWhenUnlocked
	}
	return platform.AccessAfterFirstUnlock
}

// accessLine is the create prompt's line on when the new key works: the
// one place a person learns it at creation.
func accessLine(a platform.Access) string {
	if a == platform.AccessWhenUnlocked {
		return "works only while the Mac is unlocked; fixed for the key's life"
	}
	return "works while the Mac is locked too, once you have logged in since it started; fixed for the key's life"
}

// terminalApp is the bundle id of the terminal app a create request was
// typed in, or "" when there is none: an unknown chain (launchd, a
// detached tool, even one still responsible to an app: that app is shown,
// never an identity), an app without a team (ad hoc, unsigned: nothing an
// app: matcher could match once pinned), or an app that runs the CLI with
// no session between them (Nazar UI.app, a Shortcuts or Automator app: the
// CLI is the session root, or a verified helper with none). A terminal is
// an app with a session between it and the command, the structure spec
// 4.1 already uses for scope: session; no bundle id or path is compared.
func terminalApp(peer *caller.Chain) string {
	if peer == nil || !peer.HasApp() || peer.AppIdentity() == "" || peer.SessionRoot.IsZero() {
		return ""
	}
	if p, ok := peer.Peer(); !ok || p.Ref == peer.SessionRoot {
		return ""
	}
	return peer.App.BundleID
}

// presenceLine is the prompt line that says whether the chip itself guards
// the key (spec 4.5): the one place a person learns it at creation.
func presenceLine(auth platform.AuthPolicy) string {
	if auth == platform.AuthUserPresence {
		return "Touch ID on every use, enforced by the chip: this key can never get a session, dialog or no-prompt rule"
	}
	return "Secure Enclave user presence: off (a rule remembers approvals or allows a dialog, or no rule allows the key yet; nazar's gates are the check)"
}

// sshKeyCreate creates a key and, for a name config.yaml has no entry for,
// writes its entry: the key's own gate block, plus one rule for the
// terminal app the command was typed in (defaultRule) when there is one.
// With alwaysAsk ("true", the CLI's --always-ask; any other value is a
// usage error) the rule is alwaysAskRule, and the key gets user presence
// (createAuth, checked before anything is shown).
// The change is previewed as config apply would show it (the diff and the
// team pin, configstage.Preview), approved on the login gate, and written
// only then: the file is re-read after the gate and the edit is refused
// if it changed while the prompt was open. The key's Secure Enclave
// protection follows the entry (config.NeedsUserPresence), and it works
// while the Mac is locked unless onlyWhenUnlocked is "true" or it gets user
// presence (createAccess).
//
// A name config.yaml already has an entry for, but no key (a hand-written
// entry; or the last step of the fix for a key whose vault item another
// signature made: its item removed by hand, then `ssh-key create`), gets
// its key under that entry, which is kept as it is.
func (d *Daemon) sshKeyCreate(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	name := args["name"]
	if !config.ValidKeyName(name) {
		return control.NewProblem(control.CodeUsage, "invalid key name %q", name)
	}
	if args["scope"] != "" || args["gate"] != "" {
		return control.NewProblem(control.CodeUsage, "ssh-key create takes no --scope or --gate: the key's rules decide its protection (for a key the chip itself guards: `nazar ssh-key create %s --always-ask`)", name)
	}
	alwaysAsk := false
	if v, ok := args["alwaysAsk"]; ok {
		if v != "true" {
			return control.NewProblem(control.CodeUsage, "ssh-key create: alwaysAsk must be true or absent, not %q", v)
		}
		alwaysAsk = true
	}
	onlyWhenUnlocked, err := onlyWhenUnlockedArg("ssh-key create", args)
	if err != nil {
		return err
	}
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	if pend, pending := d.stager.Pending(); pending || !sameContent(data, active) {
		if pending {
			if _, ok := pend.Config.SSHAgent.Keys[name]; ok {
				return control.NewProblem(control.CodeStaged, "config.yaml has an entry for %q that isn't approved yet; run `nazar config apply`, then `nazar ssh-key create %s` again", name, name)
			}
		}
		return control.NewProblem(control.CodeStaged, "config.yaml has changes that aren't approved yet; run `nazar config check`")
	}
	if _, ok := active.SSHAgent.Keys[name]; ok {
		return d.sshKeyRecreate(name, alwaysAsk, onlyWhenUnlocked, peer, out)
	}
	if _, err := d.keys.Get(name); err == nil {
		return control.NewProblem(control.CodeError, "an SSH key named %q already exists", name)
	}
	newData, err := config.AddSSHKey(data, name, config.Policy{Gate: config.GateBlock})
	if err != nil {
		return err
	}
	var lines []string
	if app := terminalApp(peer); app != "" {
		r := defaultRule
		if alwaysAsk {
			r = alwaysAskRule
		}
		r.Apps = []string{"app:" + app}
		if newData, err = config.AddRule(newData, config.KeyEntry(name), r, 0); err != nil {
			return err
		}
	} else if alwaysAsk {
		lines = append(lines, "no rule yet: every caller is blocked until one is added, and only a rule that asks on every use can be (nazar ssh-key rule add "+name+" --apps … --gate login --scope use)")
	} else {
		lines = append(lines, "no rule yet: every caller is blocked until one is added (nazar ssh-key rule add "+name+" …)")
	}
	p, err := d.stager.Preview(newData)
	if err != nil {
		return err
	}
	lines = append(lines, p.Diff.Changes...)
	for _, f := range p.Diff.Loosening {
		lines = append(lines, "loosens "+f.Target+": "+f.Why)
	}
	// Spec 4.5: chip-level user presence only when the entry's policies say
	// so, or --always-ask asks for it (the same test as under an existing
	// entry).
	auth, ok := createAuth(p.Config, name, alwaysAsk)
	if !ok {
		// The entry above always fits; never create a key that was asked
		// to be always-ask without it.
		return control.NewProblem(control.CodeError, "ssh-key create --always-ask: the new entry for %q would not fit a key the chip asks for on every use; nothing was changed", name)
	}
	access := createAccess(auth, onlyWhenUnlocked)
	lines = append(lines, accessLine(access), presenceLine(auth))
	target := "ssh:" + name
	cl, err := d.claimLogin(target, "create key", "not created", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Create SSH key %q?", name),
		Lines:  lines,
		Reason: fmt.Sprintf("create SSH key %q", name),
	})
	if dec != audit.Approved {
		cl.end(false)
		d.logOp(target, dec, "create key: "+reason, peer)
		return control.NewProblem(control.CodeRefused, "not created: %s", reason)
	}

	// From here on the poller must not observe the file: the edit below is
	// approved already, and the poller would otherwise stage it and ask
	// again. The file must also still be what the user approved an edit of.
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	again, err := d.readConfig()
	if err != nil {
		d.logOp(target, audit.Error, "create key: approved, but config.yaml could not be re-read after the prompt; nothing created: "+err.Error(), peer)
		return err
	}
	if !bytes.Equal(again, data) {
		// The approval was of an edit to a file that is gone: it applied
		// nothing, so for the throttle it is not an approval.
		cl.end(false)
		d.logOp(target, audit.Error, "create key: approved, but config.yaml changed while the prompt was open; nothing created", peer)
		return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; run `nazar ssh-key create` again")
	}
	d.logOp(target, dec, "create key: "+reason, peer)
	info, err := d.keys.Create(name, auth, access)
	if err != nil {
		d.logOp(target, audit.Error, "create key: approved, but the key could not be created: "+err.Error(), peer)
		return err
	}
	if err := writeFileAtomic(d.o.ConfigPath, newData); err != nil {
		d.logOp(target, audit.Error, "create key: approved and key created, but config.yaml could not be updated: "+err.Error(), peer)
		return fmt.Errorf("key created, but config.yaml could not be updated (the key stays blocked until configured): %w", err)
	}
	if err := d.stager.ApplyAuthenticated(p); err != nil {
		d.logOp(target, audit.Error, "create key: approved and key created, but the new config.yaml could not be applied: "+err.Error(), peer)
		return err
	}
	d.mu.Lock()
	d.lastSeen = contentHash(newData)
	d.mu.Unlock()
	d.prompts.forget() // the contents seen so far were changes against the old config
	cl.end(true)
	return out.Emit(d.sshKey(info))
}

// sshKeyRecreate creates the key for an existing config entry, behind the
// login gate, without touching config.yaml. The entry must be in force
// (nothing staged) and no key of that name may exist. With alwaysAsk every
// policy of the entry must already fit the chip (createAuth): --always-ask
// never rewrites an entry, so any other is refused before the prompt. It
// is checked here, on the config this function read, not by the caller.
func (d *Daemon) sshKeyRecreate(name string, alwaysAsk, onlyWhenUnlocked bool, peer *caller.Chain, out control.Emitter) error {
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	if _, pending := d.stager.Pending(); pending || !sameContent(data, active) {
		return control.NewProblem(control.CodeStaged, "config.yaml has changes that aren't approved yet; run `nazar config check`")
	}
	if _, ok := active.SSHAgent.Keys[name]; !ok {
		return control.NewProblem(control.CodeError, "config.yaml no longer has an entry for %q", name)
	}
	auth, ok := createAuth(active, name, alwaysAsk)
	if !ok {
		return control.NewProblem(control.CodeUsage, "ssh-key create --always-ask: config.yaml already has an entry for %q that allows more than a prompt on every use, and --always-ask never rewrites an entry; nothing was changed. Use a new name, or make every policy of that entry login with scope use, or block, first", name)
	}
	if _, err := d.keys.Get(name); err == nil {
		return control.NewProblem(control.CodeError, "an SSH key named %q already exists; delete it first (`nazar ssh-key delete %s`)", name, name)
	}
	access := createAccess(auth, onlyWhenUnlocked)
	target := "ssh:" + name
	cl, err := d.claimLogin(target, "create key", "not created", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	dec, reason := d.broker.Login(platform.Prompt{
		Title: fmt.Sprintf("Create SSH key %q?", name),
		Lines: []string{"for its entry in config.yaml (ssh_agent.keys." + name + "; its rules are kept)",
			"a previous key of this name stops working", accessLine(access), presenceLine(auth)},
		Reason: fmt.Sprintf("create SSH key %q", name),
	})
	d.logOp(target, dec, "create key again: "+reason, peer)
	if dec != audit.Approved {
		cl.end(false)
		return control.NewProblem(control.CodeRefused, "not created: %s", reason)
	}
	// Approvals remembered for the old key never sign with the new one:
	// they go before the key exists, and again once it does, so none made
	// for the old key's name in between survives either.
	d.cache.RevokeTarget(target, "key created again")
	info, err := d.keys.Create(name, auth, access)
	if err != nil {
		d.logOp(target, audit.Error, "create key again: approved, but the key could not be created: "+err.Error(), peer)
		return err
	}
	d.cache.RevokeTarget(target, "key created again")
	cl.end(true)
	return out.Emit(d.sshKey(info))
}

// sshKeyDelete destroys a key behind the login gate. Two cases show no
// prompt and change nothing: no key of that name (when the config in
// force keeps an entry for it, the reply names `nazar ssh-key create`,
// the step left once its item was removed by hand), and a key whose item
// the Keychain won't give this agent (Info.Unreadable: securityd refuses
// the agent's delete of another signature's item as it refuses its read,
// so a prompt would be a Touch ID for nothing; the reply is the fix,
// keyRemedy). A name that reaches ErrNotFound passed
// config.ValidKeyName (Registry.load checks it first), so it is a plain
// word.
func (d *Daemon) sshKeyDelete(name string, peer *caller.Chain, out control.Emitter) error {
	info, err := d.keys.Get(name)
	if errors.Is(err, keys.ErrNotFound) {
		if _, ok := d.stager.Active().SSHAgent.Keys[name]; ok {
			return control.NewProblem(control.CodeError, "no SSH key named %q; config.yaml keeps its entry: nazar ssh-key create %s makes a key for it", name, name)
		}
	}
	if errors.Is(err, keys.ErrNotFound) || errors.Is(err, keys.ErrInvalidName) {
		return control.NewProblem(control.CodeError, "no SSH key named %q", name)
	}
	if err != nil {
		return err
	}
	if info.Unreadable {
		return control.NewProblem(control.CodeError, "SSH key %s can't be deleted by this nazar-agent: its Keychain item belongs to another signature of the agent, "+
			"or the login keychain is locked; nothing was changed. To fix it: %s", name, keyRemedy(name))
	}
	cl, err := d.claimLogin("ssh:"+name, "delete key", "not deleted", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Delete SSH key %q?", name),
		Lines:  []string{info.Fingerprint, "The key is destroyed in the Secure Enclave. This can't be undone."},
		Reason: fmt.Sprintf("delete SSH key %q", name),
	})
	d.logOp("ssh:"+name, dec, "delete key: "+reason, peer)
	if dec != audit.Approved {
		cl.end(false)
		return control.NewProblem(control.CodeRefused, "not deleted: %s", reason)
	}
	if err := d.keys.Delete(name); err != nil {
		d.logOp("ssh:"+name, audit.Error, "delete key: approved, but the key could not be deleted: "+err.Error(), peer)
		return err
	}
	d.cache.RevokeTarget("ssh:"+name, "key deleted")
	cl.end(true)
	return out.Emit(d.sshKey(info))
}

func approvalObj(e approval.Entry) control.Approval {
	a := control.Approval{
		TypeMeta: control.Meta(control.KindApproval), Target: e.Key.Target, Rule: e.Key.Rule,
		Scope: e.Scope, ScopeID: e.Key.ScopeID, Receiver: e.Key.Receiver, Op: e.Key.Op, Covers: e.Covers,
		Chain: e.Chain, App: e.App, Created: e.Created,
	}
	if !e.Expires.IsZero() {
		t := e.Expires
		a.Expires = &t
	}
	return a
}

func (d *Daemon) statusObj() control.Status {
	st := control.Status{
		TypeMeta: control.Meta(control.KindStatus), ActiveHash: d.stager.Active().Hash,
		Approvals: []control.Approval{}, Pins: d.trust.Pins(), AgentPath: d.AgentSocket(),
	}
	if p, ok := d.stager.Pending(); ok {
		st.Staged = diffObj(p, false)
	}
	st.Problems = append(problems(d.stager.LastProblems()), d.appProblems()...)
	st.Problems = append(st.Problems, d.keyAdvice(d.stager.Active())...)
	st.Problems = append(st.Problems, d.secretAdvice(d.stager.Active())...)
	st.Problems = append(st.Problems, d.k8sAdvice(d.stager.Active())...)
	st.Problems = append(st.Problems, d.awsAdvice(d.stager.Active())...)
	st.Vault = d.vaultProblems()
	for _, e := range d.cache.List() {
		st.Approvals = append(st.Approvals, approvalObj(e))
	}
	return st
}

// status prints the current state; with follow it then streams approval
// changes until the client goes away.
func (d *Daemon) status(ctx context.Context, follow bool, out control.Emitter) error {
	var events <-chan approval.Event
	if follow {
		ch, cancel := d.cache.Subscribe()
		defer cancel()
		events = ch
	}
	if err := out.Emit(d.statusObj()); err != nil || !follow {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			a := approvalObj(ev.Entry)
			a.Event, a.Reason = string(ev.Type), ev.Reason
			if err := out.Emit(a); err != nil {
				return nil
			}
		}
	}
}

// revoke is a tightening command: it needs no gate.
func (d *Daemon) revoke(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	set := 0
	for _, k := range []string{"all", "key", "session", "app"} {
		if args[k] != "" {
			set++
		}
	}
	if set != 1 {
		return control.NewProblem(control.CodeUsage, "revoke needs exactly one of --all, --key, --session, --app")
	}
	var n int
	switch {
	case args["all"] != "":
		n = d.cache.RevokeAll("revoked")
	case args["key"] != "":
		n = d.cache.RevokeTarget("ssh:"+args["key"], "revoked")
	case args["session"] != "":
		n = d.cache.RevokeScope("session:"+args["session"], "revoked")
	case args["app"] != "":
		n = d.cache.RevokeApp(args["app"], "revoked")
	}
	d.logOp("approvals", audit.Allowed, fmt.Sprintf("revoked %d", n), peer)
	return out.Emit(control.RevokeResult{TypeMeta: control.Meta(control.KindRevokeResult), Revoked: n})
}

func problems(ps config.Problems) []control.ConfigProblem {
	var out []control.ConfigProblem
	for _, p := range ps {
		out = append(out, control.ConfigProblem{Severity: string(p.Severity), Path: p.Path, Line: p.Line, Message: p.Message})
	}
	return out
}

// appProblems reports, as warnings, every app: matcher of the active
// config that matches nothing or whose installed app no longer matches its
// pin, each naming the fix (`nazar trust --app <id>`). The bundle id comes
// from the config file and is quoted ASCII-only, as configstage does.
func (d *Daemon) appProblems() []control.ConfigProblem {
	var out []control.ConfigProblem
	for _, p := range configstage.AppProblems(d.stager.Active(), d.trust, d.o.Platform) {
		out = append(out, control.ConfigProblem{Severity: string(config.SevWarning),
			Message: fmt.Sprintf("app: %s: %s; run `%s`", strconv.QuoteToASCII(p.BundleID), p.Reason, p.Fix)})
	}
	return out
}

// fileProblems is what config check says about a file's config c (nil
// when invalid) read with probs: the parse problems, then the advice that
// needs the Mac's state (keys, secrets, CAs, writable path: files), each
// once. A rule edit shows the same for the file it wrote.
func (d *Daemon) fileProblems(c *config.Config, probs config.Problems) []control.ConfigProblem {
	all := problems(probs)
	all = append(all, d.keyAdvice(c)...)
	if !probs.HasErrors() {
		all = append(all, d.secretAdvice(c)...)
		all = append(all, d.k8sAdvice(c)...)
		all = append(all, d.awsAdvice(c)...)
		all = append(all, d.pathAdvice(c)...)
	}
	out := []control.ConfigProblem{}
	seen := map[control.ConfigProblem]bool{}
	for _, p := range all {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func diffObj(p configstage.Pending, applied bool) *control.ConfigDiff {
	diff := &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: p.Config.Hash,
		Loosens: p.Diff.Loosens(), Applied: applied, Changes: append([]string{}, p.Diff.Changes...)}
	for _, f := range p.Diff.Loosening {
		diff.Loosening = append(diff.Loosening, f.Target+": "+f.Why)
	}
	return diff
}

func (d *Daemon) configCheck(out control.Emitter) error {
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	res := control.ConfigCheck{TypeMeta: control.Meta(control.KindConfigCheck), Path: d.o.ConfigPath,
		ActiveHash: d.stager.Active().Hash, Problems: []control.ConfigProblem{}}
	if data == nil {
		res.Valid = true
		res.Problems = append(res.Problems, control.ConfigProblem{Severity: string(config.SevWarning), Message: "no config file; every key is blocked"})
	} else {
		// The key advice judges the file checked (a staged edit included),
		// not the active config; an invalid file gets its errors only, and
		// a missing one blocks every key, so neither has gates to compare.
		c, probs := config.Parse(data, config.Env{Home: d.o.Home})
		res.Valid = !probs.HasErrors()
		res.Problems = append(res.Problems, d.fileProblems(c, probs)...)
	}
	res.Problems = append(res.Problems, d.appProblems()...)
	if p, ok := d.stager.Pending(); ok {
		res.Staged = diffObj(p, false)
	}
	return out.Emit(res)
}

// configApply is `nazar config apply`: the one way to ask again for a
// staged change once the background prompt was denied or not answered. It
// observes the file itself (without the background prompt, so the prompt it
// shows is its own), and is refused without a prompt while a login prompt
// is open or during the cooldown after a prompt that approved nothing:
// the change stays staged, so the exit code is 4 (spec 6). A content
// it was the first to observe and then can't ask about is reported blocked
// like one the poller found, since the poller won't see it again. Every
// refusal is audited as blocked with the caller's chain, like the other
// loosen commands' (claimLogin): a process polling `config apply` to be
// the one asking the moment the cooldown ends must leave a trace of who
// it was (spec 4.6), and the per-content line of autoPrompt names nobody.
//
// want, when not empty, is the hash of the staged change the caller asks
// about (the CLI sends the hash of the change its edit staged, or the one
// `config check` showed it): the file is observed first, and when
// what is staged then is not that change (another process rewrote
// config.yaml after the edit) nothing is claimed or shown and the reply is
// a plain error (exit 1, so the caller does not run apply again); the
// rewrite is reported blocked like any content nobody asked about, never
// put in front of the user in the prompt they expect for their own change.
// A change already in force answers "nothing is staged".
// Approve(want) then refuses a change made while the prompt is open.
//
// While an edit's loosening holds the background prompt (editHold), only
// that change is asked about: `config apply` of any other content, with or
// without a hash, is refused the same way (exit 1, nothing asked), or a
// process that rewrote the file would run it at once and its prompt would
// be the one the user is waiting for. The hold ends once the prompt for the
// edit's change has been shown, whatever its outcome. An apply that showed
// nothing (another prompt open, the cooldown, the vault, or the file
// changing before the prompt came up) handled nothing and leaves it on
// until its bound: a process can cause such an apply on purpose, and its
// next rewrite would get the background prompt the user expects for the
// edit. So does an apply refused because the file no longer holds the
// edit's change, since something is rewriting the file. The hold is read
// before the claim, and an edit can take it in between; approveStagedShown
// reads it again once the prompt is claimed (errHeld), and that refusal is
// this one too.
func (d *Daemon) configApply(want string, peer *caller.Chain, out control.Emitter) error {
	staged, held := d.syncConfig()
	p, ok := d.stager.Pending()
	why := "it changed again while an earlier change was waiting for your approval, so nazar did not ask about it, and does not ask about it on its own later."
	if held != "" {
		why = editHoldWhy
	}
	if want != "" && (!ok || p.Config.Hash != want) {
		if !ok && d.stager.Active().Hash == want {
			return out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: want, Changes: []string{}})
		}
		d.logOp("config", audit.Blocked, "config apply: the staged change is not the one asked for", peer)
		if ok && (staged || held != "") {
			d.blockStaged(p.Config.Hash, why)
		}
		return control.NewProblem(control.CodeError, "config.yaml changed since the change you asked to approve was staged; nothing was asked and nothing applied; run `nazar config check` to see what it holds now")
	}
	if ok && held != "" && p.Config.Hash != held {
		return d.refuseHeld(p.Config.Hash, peer)
	}
	if !ok {
		return out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: d.stager.Active().Hash, Changes: []string{}})
	}
	// The opening prompt is recorded in the vault first, so a process killed
	// with it on screen relaunches suppressed; no record, no prompt.
	cl, err := d.prompts.claim(d.o.Now, true)
	switch {
	case err == nil:
	case errors.Is(err, errPromptOpen), errors.As(err, new(cooldownError)):
		d.logOp("config", audit.Blocked, "config apply: not asked: "+err.Error(), peer)
		if staged {
			d.autoPrompt(p.Config.Hash) // reports the content blocked
		}
		return control.NewProblem(control.CodeStaged, "%v (the change stays staged)", err)
	default:
		d.logOp("config", audit.Error, "config prompt not shown: the vault refused to record it", peer)
		return control.NewProblem(control.CodeError, "cannot record the config prompt in the vault (is the login keychain locked?): %v; the change stays staged", err)
	}
	// approveStaged ends the claim on every way out.
	applied, shown, err := d.approveStagedShown(cl, p.Config.Hash, peer, false)
	if shown { // a hold on this change (the edit's own) has been handled
		d.releaseHold(p.Config.Hash)
	}
	switch {
	case errors.Is(err, errHeld):
		// The hold started after it was read above, before the claim.
		return d.refuseHeld(p.Config.Hash, peer)
	case errors.Is(err, configstage.ErrBusy):
		return control.NewProblem(control.CodeStaged, "an approval prompt for this change is already open")
	case !shown && (errors.Is(err, configstage.ErrStale) || errors.Is(err, configstage.ErrNothingStaged)):
		return control.NewProblem(control.CodeStaged, "config.yaml changed before the prompt was shown; nothing was asked and nothing applied; run `nazar config apply` again")
	case errors.Is(err, configstage.ErrStale), errors.Is(err, configstage.ErrNothingStaged):
		return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; nothing applied; run `nazar config apply` again")
	case err != nil:
		return err
	case !applied:
		return control.NewProblem(control.CodeRefused, "the config change was not approved; it stays staged")
	}
	return out.Emit(diffObj(p, true))
}

// refuseHeld is configApply's refusal of a staged change (hash) other than
// the one an edit's hold waits for: nothing asked, the caller audited
// blocked with its chain, the content reported blocked once (exit 1).
func (d *Daemon) refuseHeld(hash string, peer *caller.Chain) error {
	d.logOp("config", audit.Blocked, "config apply: a change made with nazar is waiting for approval; the staged change is not it", peer)
	d.blockStaged(hash, editHoldWhy)
	return control.NewProblem(control.CodeError, "config.yaml changed while a change made with nazar was waiting for approval; nothing was asked and nothing applied; run `nazar config check` to see what it holds now, and `nazar config apply` again once that change has been approved or denied (at most %s)", seconds(editHoldFor))
}

// claimLogin claims the login prompt of a loosen command (target, for the
// audit log; op names the command there) under the throttle. A
// refusal is audited as blocked, with the caller's chain, and returned as
// exit 3 (the gate was not passed) spelling refusal and the reason; a
// vault that cannot record the opening prompt is exit 1. On success the
// caller defers the claim's close at once, shows the prompt, and ends the
// claim as applied only once the change took effect; any other return
// leaves it to the deferred close, which counts as not applied.
func (d *Daemon) claimLogin(target, op, refusal string, peer *caller.Chain) (*loginClaim, error) {
	cl, err := d.prompts.claim(d.o.Now, false)
	switch {
	case err == nil:
		return cl, nil
	case errors.Is(err, errPromptOpen), errors.As(err, new(cooldownError)):
		d.logOp(target, audit.Blocked, op+": not asked: "+err.Error(), peer)
		return nil, control.NewProblem(control.CodeRefused, "%s: %v", refusal, err)
	default:
		d.logOp(target, audit.Error, op+": prompt not shown: the vault refused to record it", peer)
		return nil, control.NewProblem(control.CodeError, "cannot record the approval prompt in the vault (is the login keychain locked?): %v", err)
	}
}

// trustApp is `nazar trust --app <bundle id>` (spec 4.2, 4.8): it pins the
// team of the installed app for the bundle id, behind the login gate,
// because a pin is new trust. configstage.TrustApp refuses an app that
// can't be pinned (not installed, ambiguous, not validly signed) before
// any prompt and returns an already matching pin without one. Every value
// shown or logged comes from the config or from disk, so it is quoted
// ASCII-only; the broker cleans the prompt and the audit formatter quotes
// the line as well.
func (d *Daemon) trustApp(bundleID string, peer *caller.Chain, out control.Emitter) error {
	if bundleID == "" {
		return control.NewProblem(control.CodeUsage, "trust --app needs a bundle id")
	}
	q := strconv.QuoteToASCII
	var reason string
	// The claim is taken inside the approver, once TrustApp found a pin to
	// ask about; it is ended as applied below, only once the pin is written,
	// and as not applied by the deferred close on any other way out.
	var cl *loginClaim
	defer func() {
		if cl != nil {
			cl.close()
		}
	}()
	approved := false
	c, err := configstage.TrustApp(bundleID, d.trust, d.o.Platform, func(c configstage.PinChange) (bool, error) {
		lines := []string{
			"app: " + q(c.BundleID),
			"installed at " + q(c.Path),
			"signed by team " + q(c.Team),
		}
		if c.Old != "" {
			lines = append(lines, "replaces the pinned team "+q(c.Old)+": the app's signer changed")
		}
		lines = append(lines, "app: matchers for this bundle id will match only this team from now on.")
		title := fmt.Sprintf("Trust team %s as app %s?", q(c.Team), q(c.BundleID))
		if c.Old != "" {
			title = fmt.Sprintf("Replace the pinned team of app %s (%s → %s)?", q(c.BundleID), q(c.Old), q(c.Team))
		}
		claim, err := d.claimLogin("app:"+c.BundleID, "trust --app", "not pinned", peer)
		if err != nil {
			return false, err
		}
		cl = claim
		var dec audit.Decision
		dec, reason = d.broker.Login(platform.Prompt{Title: title, Lines: lines, Reason: "trust app " + q(c.BundleID)})
		d.logOp("app:"+c.BundleID, dec, fmt.Sprintf("trust --app: pin team %s: %s", q(c.Team), reason), peer)
		approved = dec == audit.Approved
		if !approved {
			cl.end(false)
		}
		return approved, nil
	})
	if err != nil && approved {
		d.logOp("app:"+c.BundleID, audit.Error, "trust --app: approved, but the pin could not be written: "+err.Error(), peer)
	}
	var refused *control.Problem
	switch {
	case errors.As(err, &refused):
		return refused // the throttle refused the prompt
	case errors.Is(err, configstage.ErrNotApproved):
		return control.NewProblem(control.CodeRefused, "not pinned: %s", reason)
	case errors.Is(err, platform.ErrNotFound):
		return control.NewProblem(control.CodeError, "app %s can't be pinned: no app with this bundle id is installed", q(bundleID))
	case errors.Is(err, platform.ErrAmbiguous):
		return control.NewProblem(control.CodeError, "app %s can't be pinned: several installed apps have this bundle id and they are signed by different teams", q(bundleID))
	case err != nil:
		return control.NewProblem(control.CodeError, "%v", err)
	}
	if cl != nil {
		cl.end(true) // the pin is written (no claim: it already matched, no prompt)
	}
	return out.Emit(control.AppPin{TypeMeta: control.Meta(control.KindAppPin), BundleID: c.BundleID, Team: c.Team,
		OldTeam: c.Old, Path: c.Path, Changed: c.Old != c.Team})
}

// seconds spells a whole-second duration for a message ("1 second", "59
// seconds"); time.Duration would print a minute as "1m0s".
func seconds(d time.Duration) string {
	n := int64(d / time.Second)
	if n == 1 {
		return "1 second"
	}
	return fmt.Sprintf("%d seconds", n)
}

func sameContent(data []byte, active *config.Config) bool {
	if data == nil {
		return active.Raw == nil
	}
	return bytes.Equal(data, active.Raw)
}

// writeFileAtomic replaces path, keeping its mode (0600 for a new file). If
// path is a symlink (dotfile managers), the link's target is replaced and
// the link is kept.
func writeFileAtomic(path string, data []byte) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	done = true
	return nil
}
