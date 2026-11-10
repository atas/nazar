package daemon

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/k8s/cluster"
	"github.com/atas/nazar/core/platform"
)

// The k8s management commands (k8s design 7): ca create and show, list and
// forget. ca create sets a context up on one login prompt (its CA, its
// config entry written as ssh-key create writes a key's, the kubectl pin);
// forget is login-gated like ssh-key delete. nazar-agent never reads or writes a kubeconfig (the
// CLI adds and removes its entries), and never touches a cluster.

// caFile is where a context's CA certificate is written for the cluster
// steps; nazar never reads it back.
func (d *Daemon) caFile(name string) string {
	return filepath.Join(d.o.PubKeyDir, "k8s-ca-"+name+".crt")
}

func (d *Daemon) caObj(ca *k8s.CA) control.K8sCA {
	i := ca.Info()
	return control.K8sCA{TypeMeta: control.Meta(control.KindK8sCA), Name: ca.Name, Fingerprint: i.Fingerprint,
		Created: i.Created, NotAfter: i.NotAfter, CertFile: d.caFile(ca.Name), WhileLocked: ca.Access == platform.AccessAfterFirstUnlock}
}

// writePublic writes a public file: a fresh temp file renamed over path, so
// a link planted at path is replaced, never written through.
func writePublic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// caProblem turns a CA store error into a refusal with the spec 9 remedy.
func (d *Daemon) caProblem(name string, err error) error {
	switch {
	case errors.Is(err, k8s.ErrNotFound):
		return control.NewProblem(control.CodeError, "%s has no CA; nazar k8s ca create %s makes one", name, name)
	case errors.Is(err, k8s.ErrBroken):
		return control.NewProblem(control.CodeError, "the CA record of %s reads but can't be used; nothing was changed. To fix it: %s", name, d.vault.k8sCAFix(name, err))
	case errors.Is(err, k8s.ErrUnreadable):
		return control.NewProblem(control.CodeError, "the CA of %s can't be used by this nazar-agent: %s; nothing was changed. To fix it: %s", name, d.vault.caUnreadable(), d.vault.k8sCARemedy(name))
	}
	return err
}

// k8sCAFix is the fix for a CA store error: a
// record that reads but can't be used is nazar's to delete, so forget
// removes it; one the Keychain refuses gets the spec 9 remedy.
func (w vaultWords) k8sCAFix(name string, err error) string {
	if errors.Is(err, k8s.ErrBroken) && config.ValidK8sContextName(name) {
		return fmt.Sprintf("nazar k8s forget %s deletes it (and the context's config entry), then nazar k8s ca create %s; the cluster must then trust the new CA", name, name)
	}
	return w.k8sCARemedy(name)
}

// k8sSetupSpec reads and checks ca create's arguments (k8s
// design): the context entry to write. The
// identity is the agent's own reading of the user: <short user name>-nazar,
// with no groups (a ClusterRoleBinding gives it its role; system:masters
// would bypass RBAC and could not be revoked). Each value is checked again
// by Parse when the entry is previewed.
func (d *Daemon) k8sSetupSpec(args map[string]string) (config.K8sContextSpec, error) {
	bad := func(what string) (config.K8sContextSpec, error) {
		return config.K8sContextSpec{}, control.NewProblem(control.CodeUsage, "k8s ca create: invalid %s", what)
	}
	s := config.K8sContextSpec{Name: args["name"],
		Cluster: cluster.Pin{Server: args["server"], CASHA256: args["caSHA256"], TLSServerName: args["tlsServerName"], ProxyURL: args["proxyURL"]}}
	if !config.ValidK8sContextName(s.Name) {
		return config.K8sContextSpec{}, control.NewProblem(control.CodeUsage, "invalid context name %s (letters, digits, . _ @ -)", cluster.Display(s.Name))
	}
	if norm, err := cluster.NormalizeServer(s.Cluster.Server); err != nil || norm != s.Cluster.Server {
		return bad("cluster server")
	}
	if kc := args["kubeconfig"]; kc != "" && (!filepath.IsAbs(kc) || filepath.Clean(kc) != kc) {
		return bad("kubeconfig path")
	}
	host, err := d.o.RunHost(os.Getuid())
	if err != nil {
		return config.K8sContextSpec{}, control.NewProblem(control.CodeError, "can't tell your user name, which the context's identity is made of: %v", err)
	}
	s.Identity = config.K8sIdentity{User: host.User + "-nazar"}
	if !config.ValidK8sSubject(s.Identity.User) {
		return config.K8sContextSpec{}, control.NewProblem(control.CodeError, "your user name %s can't make a Kubernetes user name (%s: letters, digits and . _ @ : + = / -)",
			cluster.Display(host.User), cluster.Display(s.Identity.User))
	}
	if _, err := config.AddK8sContext(nil, s); err != nil {
		return bad("cluster")
	}
	return s, nil
}

func samePin(k *config.K8sContext, s config.K8sContextSpec) bool {
	return k.Cluster == s.Cluster && k.Identity.User == s.Identity.User && slices.Equal(k.Identity.Groups, s.Identity.Groups)
}

// k8sCACreate sets a context up (k8s design): its CA in the
// Secure Enclave and its certificate file, its config entry (credential
// ca-cert, the cluster pin, identity <user>-nazar with no groups, its own
// gate block and one login rule for the terminal app it was typed in, as
// for a key): all on one login prompt that shows each. No program is
// pinned: whatever runs the plugin receives the credential when the rules
// allow whoever called it (k8s design 2.1). Refused before any prompt: bad
// arguments, a CA or a config entry of that name already (a run whose
// kubeconfig write failed, with the same cluster and identity, is answered
// at once instead, when its CA has the access asked for: the access is fixed
// for the CA's life, so another is refused, never ignored), unapproved
// changes. The CA signs while the Mac is locked unless onlyWhenUnlocked is
// "true" (createAccess). After the prompt config.yaml is
// re-read and nothing is made if it changed; a step that fails undoes the
// ones before it.
func (d *Daemon) k8sCACreate(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	onlyWhenUnlocked, err := onlyWhenUnlockedArg("k8s ca create", args)
	if err != nil {
		return err
	}
	access := createAccess(platform.AuthNone, onlyWhenUnlocked)
	s, err := d.k8sSetupSpec(args)
	if err != nil {
		return err
	}
	name, target := s.Name, "k8s:"+s.Name
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	list, err := d.k8sCA.List()
	if err != nil {
		return err
	}
	hasCA, caAccess := false, platform.AccessWhenUnlocked
	for _, i := range list {
		if !strings.EqualFold(i.Name, name) {
			continue
		}
		if i.Broken {
			why := k8s.ErrBroken
			if i.Unreadable {
				why = k8s.ErrUnreadable
			}
			return d.caProblem(i.Name, why)
		}
		if i.Name != name {
			return control.NewProblem(control.CodeError, "%s already has a CA, and names must differ in more than letter case", i.Name)
		}
		hasCA, caAccess = true, i.Access
	}
	k, configured := active.K8s[name]
	switch {
	case hasCA && configured && samePin(k, s) && caAccess == access:
		// Set up already, with this cluster and identity (a run whose
		// kubeconfig write failed): nothing is loosened, nothing asked.
		return out.Emit(d.k8sSetupObj(name))
	case hasCA && configured && samePin(k, s):
		// Set up already, but its CA has the other access, which is fixed
		// for the CA's life: refused, never answered with a CA that is
		// not what was asked for.
		if caAccess == platform.AccessWhenUnlocked {
			return control.NewProblem(control.CodeError, "%s is set up already, and its CA signs only while %s is unlocked, for the CA's life: run this again with --only-when-unlocked to finish its setup, or nazar k8s forget %s, then nazar k8s ca create %s, for a new CA", name, d.traits.Machine, name, name)
		}
		return control.NewProblem(control.CodeError, "%s is set up already, and its CA signs while %s is locked too, for the CA's life: run this again without --only-when-unlocked to finish its setup, or nazar k8s forget %s, then nazar k8s ca create %s --only-when-unlocked, for a new CA", name, d.traits.Machine, name, name)
	case hasCA || configured:
		return control.NewProblem(control.CodeError, "%s is set up already (a CA or k8s.contexts.%s in config.yaml); nazar k8s list shows it, nazar k8s forget %s removes it", name, name, name)
	}
	for n := range active.K8s {
		if strings.EqualFold(n, name) {
			return control.NewProblem(control.CodeError, "config.yaml has a context %s, and names must differ in more than letter case", n)
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
	newData, err := config.AddK8sContext(data, s)
	if err != nil {
		return err
	}
	pv, err := d.stager.Preview(newData)
	if err != nil {
		return err
	}
	lines := []string{
		"The CA key is made in " + d.traits.Chip + ". A cluster that trusts its certificate accepts every certificate nazar mints for " + name + ".",
		accessLine(access, d.traits),
		"identity: CN=" + s.Identity.User + " (no groups: a ClusterRoleBinding gives it its role)",
		"server: " + s.Cluster.Server,
		// Security review: the whole fingerprint, as `openssl x509
		// -fingerprint -sha256` prints it on the node (for one certificate
		// the pinned hash is its SHA-256).
		"server CA: sha256 Fingerprint=" + colonHex(s.Cluster.CASHA256),
	}
	if s.Cluster.TLSServerName != "" {
		lines = append(lines, "tls-server-name: "+s.Cluster.TLSServerName)
	}
	if s.Cluster.ProxyURL != "" {
		lines = append(lines, "proxy-url: "+s.Cluster.ProxyURL)
	}
	lines = append(lines, "the program that runs the plugin (kubectl, helm, k9s …) gets the credential when the rules allow whoever ran it")
	if s.Rule == nil {
		lines = append(lines, "no rule yet: every caller is blocked until one is added (nazar k8s rule add "+name+" …)")
	}
	lines = append(lines, pv.Diff.Changes...)
	for _, f := range pv.Diff.Loosening {
		lines = append(lines, "loosens "+f.Target+": "+f.Why)
	}
	if kc := args["kubeconfig"]; kc != "" {
		lines = append(lines, "then the CLI adds the context "+name+" and its cluster and user "+"nazar-"+name+" to "+cluster.Display(kc)+"; nothing there is changed")
	}
	cl, err := d.claimLogin(target, "set up context", "not set up", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Set up Kubernetes context %q?", name),
		Lines:  lines,
		Reason: fmt.Sprintf("set up the Kubernetes context %q", name),
	})
	if dec != audit.Approved {
		cl.end(false)
		d.logOp(target, dec, "set up context: "+reason, peer)
		return control.NewProblem(control.CodeRefused, "not set up: %s", reason)
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	again, err := d.readConfig()
	if err != nil {
		d.logOp(target, audit.Error, "set up context: approved, but config.yaml could not be re-read after the prompt; nothing made: "+err.Error(), peer)
		return err
	}
	if !bytes.Equal(again, data) {
		cl.end(false)
		d.logOp(target, audit.Error, "set up context: approved, but config.yaml changed while the prompt was open; nothing made", peer)
		return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; nothing was made; run `nazar k8s ca create` again")
	}
	d.logOp(target, dec, "set up context: "+reason, peer)
	d.cache.RevokeTarget(target, "context set up")
	// Each step that fails undoes the ones before it: nothing half made.
	var undo []func()
	failed := func(what string, err error) error {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		d.logOp(target, audit.Error, "set up context: approved, but "+what+"; nothing kept: "+err.Error(), peer)
		return fmt.Errorf("%s; nothing was kept: %w", what, err)
	}
	ca, err := d.k8sCA.Create(name, access)
	if err != nil {
		d.logOp(target, audit.Error, "set up context: approved, but the CA could not be made: "+err.Error(), peer)
		return d.caProblem(name, err)
	}
	undo = append(undo, func() {
		if err := d.k8sCA.Delete(name); err != nil {
			d.o.Logf("k8s: undoing the CA of %s: %v", name, err)
		}
		_ = os.Remove(d.caFile(name))
	})
	if err := writePublic(d.caFile(name), ca.CertPEM()); err != nil {
		return failed("the certificate file could not be written", err)
	}
	if err := writeFileAtomic(d.o.ConfigPath, newData); err != nil {
		return failed("config.yaml could not be updated", err)
	}
	if err := d.stager.ApplyAuthenticated(pv); err != nil {
		if werr := writeFileAtomic(d.o.ConfigPath, data); werr != nil {
			d.o.Logf("k8s: restoring config.yaml: %v", werr)
		}
		return failed("the new config.yaml could not be applied", err)
	}
	d.mu.Lock()
	d.lastSeen = contentHash(newData)
	d.mu.Unlock()
	d.prompts.forget() // the contents seen so far were changes against the old config
	cl.end(true)
	return out.Emit(d.k8sSetupObj(name))
}

// colonHex renders a hex hash as openssl does: upper case, a colon
// between bytes.
func colonHex(h string) string {
	h = strings.ToUpper(h)
	var b strings.Builder
	for i := 0; i+1 < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// k8sSetupObj is ca create's reply: the context, its CA with the
// certificate (the CLI prints the cluster steps with it).
func (d *Daemon) k8sSetupObj(name string) control.K8sContext {
	o := d.k8sObj(name, d.stager.Active())
	if ca, err := d.k8sCA.Get(name); err == nil && o.CA != nil {
		o.CA.CertPEM = string(ca.CertPEM())
	}
	return o
}

// k8sCAShow returns a CA with its certificate, read from the Vault record,
// never from the file.
func (d *Daemon) k8sCAShow(name string, out control.Emitter) error {
	ca, err := d.k8sCA.Get(name)
	if err != nil {
		return d.caProblem(name, err)
	}
	o := d.caObj(ca)
	o.CertPEM = string(ca.CertPEM())
	return out.Emit(o)
}

// k8sObj describes context name as c configures it and its CA as stored,
// with its state and the remedy for it. Its policy and warnings are the
// config the window shows and edits (the staged change when there is one),
// as for a key or a secret; a context with no entry there has no
// policy: it is refused to every caller.
func (d *Daemon) k8sObj(name string, c *config.Config) control.K8sContext {
	o := control.K8sContext{TypeMeta: control.Meta(control.KindK8sContext), Name: name, Rules: []string{}, Warnings: []string{}}
	if shown, staged := d.shownConfig(); shown.K8s[name] != nil {
		pol := entryRules(config.K8sEntry(name), shown, staged)
		o.Policy, o.Warnings = &pol, entryWarnings(d.stager.LastProblems(), "k8s.contexts.", name, shown.K8sNames())
	}
	if k, ok := c.K8s[name]; ok {
		o.Configured, o.Credential, o.TTLCert = true, string(k.Credential), k.TTLCert.String()
		o.Identity = &control.K8sIdentity{User: k.Identity.User, Groups: append([]string{}, k.Identity.Groups...)}
		o.Cluster = &control.K8sCluster{Server: k.Cluster.Server, CASHA256: k.Cluster.CASHA256, TLSServerName: k.Cluster.TLSServerName, ProxyURL: k.Cluster.ProxyURL}
		for _, r := range k.Rules {
			o.Rules = append(o.Rules, fmt.Sprintf("%d: %s", r.Index, r.Canonical()))
		}
		o.Rules = append(o.Rules, "fallback: "+c.K8sFallback(name).String())
	}
	switch ca, err := d.k8sCA.Get(name); {
	case err == nil && o.Configured:
		co := d.caObj(ca)
		o.CA, o.State = &co, control.K8sStateOK
	case err == nil:
		co := d.caObj(ca)
		o.CA, o.State = &co, control.K8sStateNoEntry
		o.Remedy = fmt.Sprintf("nazar k8s forget %s, then nazar k8s ca create %s", name, name)
	case errors.Is(err, k8s.ErrNotFound) && o.Configured:
		o.State, o.Remedy = control.K8sStateNoCA, fmt.Sprintf("nazar k8s forget %s, then nazar k8s ca create %s", name, name)
	case errors.Is(err, k8s.ErrNotFound):
		o.State = control.K8sStateAbsent
	default:
		o.State = control.K8sStateCAUnusable
		o.CABroken, o.UnusableReason, o.Remedy = true, err.Error(), d.vault.k8sCAFix(name, err)
	}
	return o
}

// k8sList lists every configured context and every CA record.
func (d *Daemon) k8sList(out control.Emitter) error {
	c := d.stager.Active()
	list, err := d.k8sCA.List()
	if err != nil {
		return err
	}
	names := c.K8sNames()
	for _, i := range list {
		if !slices.Contains(names, i.Name) {
			names = append(names, i.Name)
		}
	}
	slices.Sort(names)
	res := control.K8sContextList{TypeMeta: control.Meta(control.KindK8sContextList), Items: []control.K8sContext{}}
	for _, n := range names {
		res.Items = append(res.Items, d.k8sObj(n, c))
	}
	return out.Emit(res)
}

// k8sForget deletes a context's CA (Secure Enclave key and Vault item),
// its .crt file and its config entry, and drops its remembered approvals,
// behind one login prompt. An unknown name, an unreadable CA (spec 9: never
// deleted by the agent) and unapproved changes in config.yaml are refused
// before any prompt; a config.yaml changed while the prompt was open
// changes nothing. Removing the entry tightens. kubeconfig names the file
// the CLI removes nazar's entries from once this succeeds, for the prompt.
func (d *Daemon) k8sForget(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	name, kc := args["name"], args["kubeconfig"]
	if !config.ValidK8sContextName(name) {
		return control.NewProblem(control.CodeUsage, "invalid context name %s", cluster.Display(name))
	}
	if kc != "" && (!filepath.IsAbs(kc) || filepath.Clean(kc) != kc) {
		return control.NewProblem(control.CodeUsage, "k8s forget: invalid kubeconfig path")
	}
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	_, configured := active.K8s[name]
	_, caErr := d.k8sCA.Get(name)
	hasCA := caErr == nil || errors.Is(caErr, k8s.ErrBroken)
	switch {
	case errors.Is(caErr, k8s.ErrUnreadable):
		return d.caProblem(name, caErr)
	case !configured && !hasCA:
		return control.NewProblem(control.CodeError, "no k8s context or CA named %s", name)
	}
	var newData []byte
	if configured {
		if _, pending := d.stager.Pending(); pending || !sameContent(data, active) {
			return control.NewProblem(control.CodeStaged, "config.yaml has changes that aren't approved yet; run `nazar config check`")
		}
		if newData, err = config.RemoveK8sContext(data, name); err != nil {
			return err
		}
	}
	target := "k8s:" + name
	cl, err := d.claimLogin(target, "forget context", "not forgotten", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	var lines []string
	if hasCA {
		lines = append(lines, d.deleted("The CA is destroyed in "+d.traits.Chip+"; this can't be undone.", "CA")+" Certificates it minted stay valid until they end.")
	}
	if configured {
		lines = append(lines, "config.yaml loses k8s.contexts."+name+".")
	}
	if kc != "" {
		lines = append(lines, "Then the CLI removes nazar's entries for "+name+" from "+cluster.Display(kc)+"; nothing else there is changed.")
	} else {
		lines = append(lines, "The kubeconfig is not touched.")
	}
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Forget Kubernetes context %q?", name),
		Lines:  lines,
		Reason: fmt.Sprintf("forget the Kubernetes context %q", name),
	})
	d.logOp(target, dec, "forget context: "+reason, peer)
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
			d.logOp(target, audit.Error, "forget context: approved, but config.yaml changed while the prompt was open; nothing changed", peer)
			return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; run `nazar k8s forget %s` again", name)
		}
	}
	d.cache.RevokeTarget(target, "context forgotten")
	if hasCA {
		if err := d.k8sCA.Delete(name); err != nil {
			d.logOp(target, audit.Error, "forget context: approved, but the CA could not be deleted: "+err.Error(), peer)
			return d.caProblem(name, err)
		}
		if err := os.Remove(d.caFile(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			d.o.Logf("k8s: removing %s: %v", d.caFile(name), err)
		}
	}
	if configured {
		if err := writeFileAtomic(d.o.ConfigPath, newData); err != nil {
			d.logOp(target, audit.Error, "forget context: the CA is gone, but config.yaml could not be updated: "+err.Error(), peer)
			return err
		}
		pv, err := d.stager.Preview(newData)
		if err == nil {
			err = d.stager.ApplyAuthenticated(pv)
		}
		if err != nil {
			d.logOp(target, audit.Error, "forget context: the CA is gone, but the new config.yaml could not be applied: "+err.Error(), peer)
			return err
		}
		d.mu.Lock()
		d.lastSeen = contentHash(newData)
		d.mu.Unlock()
		d.prompts.forget()
	}
	cl.end(true)
	return out.Emit(d.k8sObj(name, d.stager.Active()))
}

// k8sAdvice warns about every context c configures that has no CA.
func (d *Daemon) k8sAdvice(c *config.Config) []control.ConfigProblem {
	if c == nil {
		return nil
	}
	var out []control.ConfigProblem
	for _, name := range c.K8sNames() {
		if _, err := d.k8sCA.Get(name); errors.Is(err, k8s.ErrNotFound) {
			out = append(out, control.ConfigProblem{Severity: string(config.SevWarning), Path: "k8s.contexts." + name,
				Message: fmt.Sprintf("context %s has no CA, so kubectl gets nothing for it; run `nazar k8s forget %s`, then `nazar k8s ca create %s`", name, name, name)})
		}
	}
	return out
}
