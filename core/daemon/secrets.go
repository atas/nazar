package daemon

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/secrets/seal"
)

// The secrets commands (secrets design 7). secret.add and
// secret.delete are loosen commands gated as ssh-key.create and
// ssh-key.delete are; secret.list is a read; secret.get returns a value and
// is answered only to the genuine nazar CLI (Serve's guard). No reply,
// error, prompt or audit line carries a value.

// errNotCLI is the reason a value command from any other peer is refused.
const errNotCLI = "peer is not the nazar CLI"

// refuseNotCLI refuses a value command whose peer the control server did
// not find to be the genuine nazar CLI (control.PeerIsNazarCLI): one
// blocked audit line with the caller's chain, no prompt, nothing opened.
func (d *Daemon) refuseNotCLI(req control.Request, peer *caller.Chain) error {
	if req.Command == control.CmdK8sCredential {
		return d.refuseK8sNotCLI(req, peer)
	}
	if req.Command == control.CmdAWSCredential {
		return d.refuseAWSNotCLI(req, peer)
	}
	name := req.Args["name"]
	dlv := config.DeliverStdout
	switch req.Command {
	case control.CmdSecretHelper:
		dlv = config.DeliverHelper
		name, _ = d.stager.Active().GitSecret(req.Args["host"])
	case control.CmdSecretRun:
		dlv = config.DeliverLateEnv
	}
	if !config.ValidSecretName(name) {
		name = "(invalid name)"
	}
	var recv *caller.Chain
	if peer != nil {
		switch req.Command {
		case control.CmdSecretHelper:
			recv = d.gitReceiver(peer)
		case control.CmdSecretRun: // nothing was resolved: no receiver
		default:
			recv = peer.Parent()
		}
	}
	d.broker.Refuse(broker.Request{Secret: name, Delivery: dlv, Chain: peer, Receiver: recv, Operation: req.Command}, errNotCLI)
	return control.NewProblem(control.CodeRefused, errNotCLI)
}

// secretObj describes a secret as stored (info, when stored) and as c
// configures it.
func (d *Daemon) secretObj(name string, info *secrets.Info, c *config.Config) control.Secret {
	s := control.Secret{TypeMeta: control.Meta(control.KindSecret), Name: name, Deliver: []string{}, Rules: []string{}}
	for _, m := range c.Deliver(name) {
		s.Deliver = append(s.Deliver, string(m))
	}
	if cs, ok := c.Secrets[name]; ok {
		s.Configured = true
		for _, r := range cs.Rules {
			s.Rules = append(s.Rules, fmt.Sprintf("%d: %s", r.Index, r.Canonical()))
		}
	}
	s.Rules = append(s.Rules, "fallback: "+c.SecretFallback(name).String())
	// The structured rules are the config the window shows and edits (the
	// staged change when there is one), as for a key.
	shown, staged := d.shownConfig()
	pol := entryRules(config.SecretEntry(name), shown, staged)
	s.Policy, s.Warnings = &pol, entryWarnings(d.stager.LastProblems(), "secrets.", name, shown.SecretNames())
	if info != nil {
		s.Stored = true
		s.UserPresence = info.Auth == platform.AuthUserPresence
		s.WhileLocked = !info.Broken && info.Access == platform.AccessAfterFirstUnlock
		if info.Broken {
			s.Broken, s.UnusableReason, s.Remedy = true, d.vault.secretReason(*info), d.vault.secretRemedy(name)
		} else {
			created := info.Created
			s.Created = &created
		}
	}
	return s
}

// entryWarnings is the parse warnings about the own entry of name, one of
// names under section ("secrets." or "k8s.contexts."): the entry whose name
// is the longest that prefixes the warning's path, so secrets.A never gets
// secrets.A.B's (names may contain dots). Never nil.
func entryWarnings(probs config.Problems, section, name string, names []string) []string {
	w := []string{}
	for _, p := range probs {
		if p.Severity != config.SevWarning {
			continue
		}
		owner := ""
		for _, n := range names {
			pre := section + n
			if (p.Path == pre || strings.HasPrefix(p.Path, pre+".")) && len(n) > len(owner) {
				owner = n
			}
		}
		if owner == name {
			w = append(w, p.Message)
		}
	}
	return w
}

func (d *Daemon) secretList(out control.Emitter) error {
	list, err := d.secrets.List()
	if err != nil {
		return err
	}
	c := d.stager.Active()
	res := control.SecretList{TypeMeta: control.Meta(control.KindSecretList), Items: []control.Secret{}}
	stored := map[string]bool{}
	for _, info := range list {
		stored[info.Name] = true
		res.Items = append(res.Items, d.secretObj(info.Name, &info, c))
	}
	for _, name := range c.SecretNames() {
		if !stored[name] {
			res.Items = append(res.Items, d.secretObj(name, nil, c))
		}
	}
	return out.Emit(res)
}

// deliverLine is the prompt line that names the methods the secret will
// have (secrets design 7.1).
func deliverLine(c *config.Config, name string) string {
	var ms []string
	for _, m := range c.Deliver(name) {
		ms = append(ms, string(m))
	}
	if s, ok := c.Secrets[name]; ok && !slicesEqual(s.Deliver, config.DefaultDeliver()) {
		return "deliver: " + strings.Join(ms, ", ") + " (its entry in config.yaml)"
	}
	return "deliver: " + strings.Join(ms, ", ") + " (the default; edit config.yaml to change it)"
}

func slicesEqual(a, b []config.Delivery) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// secretValue decodes and checks the value of a secret.add request.
func secretValue(arg string) ([]byte, error) {
	v, err := base64.StdEncoding.Strict().DecodeString(arg)
	if err != nil {
		clear(v) // what decoded before the error
		return nil, control.NewProblem(control.CodeUsage, "secret add: valueBase64 is not base64")
	}
	switch err := seal.Check(v); {
	case errors.Is(err, seal.ErrEmpty):
		return nil, control.NewProblem(control.CodeUsage, "secret add: the value is empty")
	case errors.Is(err, seal.ErrTooLarge):
		clear(v)
		return nil, control.NewProblem(control.CodeUsage, "secret add: the value is larger than 32 KiB")
	case err != nil:
		clear(v)
		return nil, control.NewProblem(control.CodeUsage, "secret add: %v", err)
	}
	return v, nil
}

// storedLike returns the stored secret whose name equals name ignoring
// letter case (the store refuses such a pair), or "".
func (d *Daemon) storedLike(name string) (string, error) {
	list, err := d.secrets.List()
	if err != nil {
		return "", err
	}
	for _, s := range list {
		if strings.EqualFold(s.Name, name) {
			return s.Name, nil
		}
	}
	return "", nil
}

// secretAdd stores a secret behind the login gate (secrets design 7.1),
// as sshKeyCreate creates a key: for a name config.yaml has no
// entry for, it writes the entry (the secret's own gate block, plus one
// login rule for the terminal app the command was typed in), shows the
// change and the deliver list on one prompt, and writes the file only after
// the approval, refusing if it changed while the prompt was open. An
// existing entry is kept as it is. The secret's key works while the Mac is
// locked unless onlyWhenUnlocked is "true" (createAccess). Every refusal
// but the prompt's own comes before any prompt.
func (d *Daemon) secretAdd(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	name := args["name"]
	if !config.ValidSecretName(name) {
		return control.NewProblem(control.CodeUsage, "invalid secret name %q (letters, digits, _ . - and /, at most 64 bytes)", name)
	}
	onlyWhenUnlocked, err := onlyWhenUnlockedArg("secret add", args)
	if err != nil {
		return err
	}
	access := createAccess(platform.AuthNone, onlyWhenUnlocked)
	value, err := secretValue(args["valueBase64"])
	if err != nil {
		return err
	}
	defer clear(value)
	d.Reload()
	data, err := d.readConfig()
	if err != nil {
		return err
	}
	active := d.stager.Active()
	if pend, pending := d.stager.Pending(); pending || !sameContent(data, active) {
		if pending {
			if _, ok := pend.Config.Secrets[name]; ok {
				return control.NewProblem(control.CodeStaged, "config.yaml has an entry for %q that isn't approved yet; run `nazar config apply`, then `nazar secret add %s` again", name, name)
			}
		}
		return control.NewProblem(control.CodeStaged, "config.yaml has changes that aren't approved yet; run `nazar config check`")
	}
	switch taken, err := d.storedLike(name); {
	case err != nil:
		return err
	case taken == name:
		return control.NewProblem(control.CodeError, "a secret named %q already exists; to change its value: nazar secret rm %s, then nazar secret add %s", name, name, name)
	case taken != "":
		return control.NewProblem(control.CodeError, "a secret named %q already exists, and names must differ in more than letter case", taken)
	}
	_, hasEntry := active.Secrets[name]
	var p *configPreview
	lines := []string{deliverLine(active, name), accessLine(access, d.traits)}
	if hasEntry {
		lines = append(lines, "for its entry in config.yaml (secrets."+name+"; its rules are kept)")
	} else {
		var rule *config.RuleSpec
		if app := terminalApp(peer); app != "" {
			r := defaultRule
			r.Apps = []string{"app:" + app}
			rule = &r
		} else {
			lines = append(lines, "no rule yet: every caller is blocked until one is added (nazar secret rule add "+name+" …)")
		}
		newData, err := config.AddSecret(data, name, rule)
		if err != nil {
			return err
		}
		pv, err := d.stager.Preview(newData)
		if err != nil {
			return err
		}
		p = &configPreview{data: newData, pending: pv}
		lines = append(lines, pv.Diff.Changes...)
		for _, f := range pv.Diff.Loosening {
			lines = append(lines, "loosens "+f.Target+": "+f.Why)
		}
	}
	target := "secret:" + name
	cl, err := d.claimLogin(target, "add secret", "not added", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Add secret %q?", name),
		Lines:  lines,
		Reason: fmt.Sprintf("add secret %q", name),
	})
	if dec != audit.Approved {
		cl.end(false)
		d.logOp(target, dec, "add secret: "+reason, peer)
		return control.NewProblem(control.CodeRefused, "not added: %s", reason)
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	again, err := d.readConfig()
	if err != nil {
		d.logOp(target, audit.Error, "add secret: approved, but config.yaml could not be re-read after the prompt; nothing added: "+err.Error(), peer)
		return err
	}
	if !bytes.Equal(again, data) {
		cl.end(false)
		d.logOp(target, audit.Error, "add secret: approved, but config.yaml changed while the prompt was open; nothing added", peer)
		return control.NewProblem(control.CodeStaged, "config.yaml changed while the prompt was open; run `nazar secret add` again")
	}
	d.logOp(target, dec, "add secret: "+reason, peer)
	// Approvals remembered for this name (a secret removed before, or a
	// request for a name nothing was stored under) never cover the new
	// value: they go before it exists.
	d.cache.RevokeTarget(target, "secret added")
	info, err := d.secrets.Add(name, value, access)
	if err != nil {
		d.logOp(target, audit.Error, "add secret: approved, but the secret could not be stored: "+err.Error(), peer)
		return err
	}
	if p != nil {
		if err := writeFileAtomic(d.o.ConfigPath, p.data); err != nil {
			d.logOp(target, audit.Error, "add secret: approved and stored, but config.yaml could not be updated: "+err.Error(), peer)
			return fmt.Errorf("secret stored, but config.yaml could not be updated (the secret stays blocked until configured): %w", err)
		}
		if err := d.stager.ApplyAuthenticated(p.pending); err != nil {
			d.logOp(target, audit.Error, "add secret: approved and stored, but the new config.yaml could not be applied: "+err.Error(), peer)
			return err
		}
		d.mu.Lock()
		d.lastSeen = contentHash(p.data)
		d.mu.Unlock()
		d.prompts.forget() // the contents seen so far were changes against the old config
	}
	cl.end(true)
	return out.Emit(d.secretObj(name, &info, d.stager.Active()))
}

// configPreview is a config edit and how it classifies.
type configPreview struct {
	data    []byte
	pending configstage.Pending
}

// secretDelete erases a secret behind the login gate (secrets design 3.4).
// No stored secret of that name, or a record the Keychain won't give this
// agent, is refused before any prompt; config.yaml is never edited.
func (d *Daemon) secretDelete(name string, peer *caller.Chain, out control.Emitter) error {
	c := d.stager.Active()
	info, err := d.secrets.Get(name)
	if errors.Is(err, secrets.ErrNotFound) {
		if _, ok := c.Secrets[name]; ok {
			return control.NewProblem(control.CodeError, "no secret named %q; config.yaml keeps its entry: nazar secret add %s stores one for it", name, name)
		}
	}
	if errors.Is(err, secrets.ErrNotFound) || errors.Is(err, secrets.ErrInvalidName) {
		return control.NewProblem(control.CodeError, "no secret named %q", name)
	}
	if err != nil {
		return err
	}
	if info.Unreadable {
		return control.NewProblem(control.CodeError, "secret %s can't be deleted by this nazar-agent: %s; nothing was changed. To fix it: %s", name, d.vault.unreadable(), d.vault.secretRemedy(name))
	}
	target := "secret:" + name
	cl, err := d.claimLogin(target, "delete secret", "not deleted", peer)
	if err != nil {
		return err
	}
	defer cl.close() // any return before cl.end(true) is an approval that applied nothing
	dec, reason := d.broker.Login(platform.Prompt{
		Title:  fmt.Sprintf("Delete secret %q?", name),
		Lines:  []string{d.deleted("This can't be undone;", "secret") + " config.yaml keeps its entry."},
		Reason: fmt.Sprintf("delete secret %q", name),
	})
	d.logOp(target, dec, "delete secret: "+reason, peer)
	if dec != audit.Approved {
		cl.end(false)
		return control.NewProblem(control.CodeRefused, "not deleted: %s", reason)
	}
	if err := d.secrets.Delete(name); err != nil {
		d.logOp(target, audit.Error, "delete secret: approved, but the secret could not be deleted: "+err.Error(), peer)
		return err
	}
	d.cache.RevokeTarget(target, "secret deleted")
	cl.end(true)
	return out.Emit(d.secretObj(name, nil, d.stager.Active()))
}

// secretGet is the stdout delivery on the control socket (secrets design
// 6.5): the asker is the nazar CLI's chain, the receiver its parent. Serve
// has checked the peer is the genuine CLI. A name with nothing stored is an
// error before any prompt. The value is cleared once it is sent.
func (d *Daemon) secretGet(name string, peer *caller.Chain, out control.Emitter) error {
	if !config.ValidSecretName(name) {
		return control.NewProblem(control.CodeUsage, "invalid secret name %q", name)
	}
	info, err := d.secrets.Get(name)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		d.logOp("secret:"+name, audit.Error, "nazar get: no such secret", peer)
		return control.NewProblem(control.CodeError, "no secret named %q", name)
	case err != nil:
		return err
	case info.Broken:
		d.logOp("secret:"+name, audit.Error, "nazar get: the secret's record is unusable", peer)
		return control.NewProblem(control.CodeError, "secret %s can't be used: %s; fix: %s", name, d.vault.secretReason(info), d.vault.secretRemedy(name))
	}
	if peer == nil {
		peer = &caller.Chain{Unknown: true}
	}
	var value []byte
	defer func() { clear(value) }()
	r := d.broker.Handle(broker.Request{
		Secret: name, Delivery: config.DeliverStdout, Chain: peer, Receiver: peer.Parent(),
		Summary: "nazar get " + name, Operation: "nazar get",
		Do: func(ref platform.ApprovalRef) error {
			v, err := d.secrets.Open(name, ref)
			value = v
			return err
		},
	})
	if !r.Allowed() {
		return resultProblem(r)
	}
	return out.Emit(control.SecretValue{TypeMeta: control.Meta(control.KindSecretValue), Name: name, ValueBase64: base64.StdEncoding.EncodeToString(value)})
}

// resultProblem is the CLI's Problem for a request the broker did not
// allow (nil when it did).
func resultProblem(r broker.Result) error {
	if r.Allowed() {
		return nil
	}
	code := control.CodeRefused
	if r.Decision == audit.Error {
		code = control.CodeError
	}
	return control.NewProblem(code, "refused: %s", r.Reason)
}

// gitReceiver is the receiver of a git credential request (secrets design
// 6.1): the CLI's parent, which is git's HTTPS transport when the
// transport runs the helper by its path. For `credential.helper = nazar`
// git runs `git credential-nazar get`, which runs the CLI as its child: a
// parent that is Apple's own git (by signature, never by path or name)
// running exactly that is skipped, once, and its parent is the receiver.
// Anything else, a look-alike git included, is the receiver itself.
//
// Without code signatures (Linux) there is no Apple git to recognise, and
// git runs every helper through `/bin/sh -c`, which on Debian and Ubuntu
// is dash and stays as the helper's parent (macOS's sh execs it). So there
// the dispatcher is known by what it runs (a `git` running
// `credential-nazar`) and the shell by what it was told to run (the
// helper's command line, nothing else), and each is stepped over once. A
// to: rule still has to match what is left, and only the file the kernel
// reports as running can match path: (match.Evaluator.path). Both must be
// the system's own files (isSystemGit, isSystemShell): a git or sh from a
// folder the user can write to is not stepped over, so it is the receiver
// itself and a to: rule that names the transport refuses it. Otherwise a
// look-alike git set as the helper would run the real one, read the token
// and pass as the transport above it.
func (d *Daemon) gitReceiver(peer *caller.Chain) *caller.Chain {
	recv := peer.Parent()
	p, ok := recv.Peer()
	if !ok {
		return recv
	}
	if d.traits.CodeSigning {
		if p.Code.Team() == "apple" && p.Code.SigningID == "com.apple.git" && len(p.Args) >= 2 && p.Args[1] == "credential-nazar" {
			return recv.Parent()
		}
		return recv
	}
	if isSystemGit(p) && len(p.Args) >= 2 && p.Args[1] == "credential-nazar" {
		recv = recv.Parent()
		if p, ok = recv.Peer(); !ok {
			return recv
		}
	}
	if isHelperShell(p) {
		return recv.Parent()
	}
	return recv
}

// isSystemGit reports whether p runs the system's git: the file the kernel
// reports is git under /bin, /usr/bin or git's own folder there, which only
// root can write to. A git elsewhere (Homebrew's, one under the home
// folder) is a program like any other, and is the receiver itself.
func isSystemGit(p platform.ProcessInfo) bool {
	switch dir, base := filepath.Split(p.Path); dir {
	case "/bin/", "/usr/bin/", "/usr/lib/git-core/", "/usr/libexec/git-core/":
		return base == "git"
	}
	return false
}

// isHelperShell reports whether p is the /bin/sh git runs a credential
// helper through (run-command.c, prepare_shell_cmd, which passes the
// command again as $0): `sh -c '<helper> get' '<helper> get'`, or `sh -c
// '<cmd> "$@"' <cmd> <args…>` for a command with separate arguments. It
// must be the system's shell (sh, dash or bash under /bin or /usr/bin, by
// the file the kernel reports) given that one command and nothing else:
// the command runs the nazar helper (`git credential-nazar …` or the
// `git-credential-nazar` link by its path), with no `;`, `|`, `&&` or
// redirection, which would make the shell a program of its own. The
// positional parameters ($0 and the "$@" arguments) are not parsed by
// the shell, so they are only required to be what git puts there.
func isHelperShell(p platform.ProcessInfo) bool {
	if !isSystemShell(p) || len(p.Args) < 3 || p.Args[1] != "-c" {
		return false
	}
	command, rest := p.Args[2], p.Args[3:]
	switch {
	case len(rest) == 0:
	case len(rest) == 1 && rest[0] == command:
	default:
		c, ok := strings.CutSuffix(command, ` "$@"`)
		if !ok || len(rest) < 2 || rest[0] != c {
			return false
		}
		command = c
	}
	if strings.ContainsAny(command, ";|&<>()`$\n") {
		return false
	}
	f := strings.Fields(command)
	if len(f) == 0 {
		return false
	}
	if len(f) == 1 {
		// `sh -c '<link> "$@"' <link> get`: the link by its path alone.
		return len(rest) >= 2 && filepath.Base(f[0]) == "git-credential-nazar"
	}
	switch filepath.Base(f[0]) {
	case "git":
		return f[1] == "credential-nazar"
	case "git-credential-nazar":
		return true
	}
	return false
}

// urlText is protocol://host for a message: as is when it is plain
// (letters, digits and . - : only), Go-quoted otherwise, since both come
// from whoever ran the CLI.
func urlText(protocol, host string) string {
	u := protocol + "://" + host
	for _, r := range protocol + host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return strconv.QuoteToASCII(u)
		}
	}
	return u
}

// secretHelper answers git's credential protocol (secrets design 6.1):
// only https, only a host a secret's helper.git names, and a
// username, when git and the config both give one, that is the configured
// one; anything else is refused before the pipeline, so nothing is asked
// and nothing opened. The protocol and host are git's request, which
// whoever runs the CLI writes: they choose which secret is asked for,
// never whether; the rules decide that. Serve has checked the peer is the
// genuine CLI.
func (d *Daemon) secretHelper(args map[string]string, peer *caller.Chain, out control.Emitter) error {
	host := args["host"]
	c := d.stager.Active()
	name, ok := c.GitSecret(host)
	if args["protocol"] != "https" || !ok {
		return control.NewProblem(control.CodeRefused, "no secret for %s", urlText(args["protocol"], host))
	}
	g := c.Secrets[name].Helper.Git
	user := g.Username
	if u := args["username"]; u != "" {
		if user != "" && u != user {
			return control.NewProblem(control.CodeRefused, "no secret for %s as %s", g, strconv.QuoteToASCII(u))
		}
		if user == "" {
			user = u
		}
	}
	info, err := d.secrets.Get(name)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		d.logOp("secret:"+name, audit.Error, "git credential: no such secret", peer)
		return control.NewProblem(control.CodeError, "no secret named %q; config.yaml names it for %s: nazar secret add %s stores it", name, g, name)
	case err != nil:
		return err
	case info.Broken:
		d.logOp("secret:"+name, audit.Error, "git credential: the secret's record is unusable", peer)
		return control.NewProblem(control.CodeError, "secret %s can't be used: %s; fix: %s", name, d.vault.secretReason(info), d.vault.secretRemedy(name))
	}
	if peer == nil {
		peer = &caller.Chain{Unknown: true}
	}
	var value []byte
	defer func() { clear(value) }()
	r := d.broker.Handle(broker.Request{
		Secret: name, Delivery: config.DeliverHelper, Chain: peer, Receiver: d.gitReceiver(peer),
		Summary: "git credential for " + g.String(), Operation: "git credential", Destination: g.Host,
		Do: func(ref platform.ApprovalRef) error {
			v, err := d.secrets.Open(name, ref)
			value = v
			return err
		},
	})
	if !r.Allowed() {
		return resultProblem(r)
	}
	return out.Emit(control.SecretValue{TypeMeta: control.Meta(control.KindSecretValue), Name: name, Username: user,
		ValueBase64: base64.StdEncoding.EncodeToString(value)})
}

// secretAdvice warns about every secret c configures that has nothing
// stored (secrets design 4). A vault that can't be listed is logged and
// gives no advice.
func (d *Daemon) secretAdvice(c *config.Config) []control.ConfigProblem {
	if c == nil {
		return nil
	}
	list, err := d.secrets.List()
	if err != nil {
		d.o.Logf("secrets: %v", err)
		return nil
	}
	stored := map[string]bool{}
	for _, s := range list {
		stored[s.Name] = true
	}
	var out []control.ConfigProblem
	for _, name := range c.SecretNames() {
		if !stored[name] {
			out = append(out, control.ConfigProblem{Severity: string(config.SevWarning), Path: "secrets." + name,
				Message: fmt.Sprintf("secret %s is configured but not stored; run `nazar secret add %s`", name, name)})
		}
	}
	return out
}
