// Package daemon wires the core together: config staging, policy, approval
// cache, broker, SSH agent socket and control socket. Nazar.app (Milestone 3)
// runs it with the Swift platform; tests and nazar-testd run it with the fake.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/aws"
	"github.com/atas/nazar/core/broker"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/certs"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/policy"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/secrets/envpolicy"
	"github.com/atas/nazar/core/secrets/run"
	"github.com/atas/nazar/core/sshagent"
	"github.com/atas/nazar/core/trust"
	"github.com/atas/nazar/core/unixsock"
)

// Options configures a Daemon. Paths default from Home.
type Options struct {
	Platform      platform.Platform
	Vault         platform.Vault
	AuditSink     audit.Sink
	Home          string
	ConfigPath    string // ~/.nazar/config/config.yaml
	ControlSocket string // ~/.nazar/run/control.sock
	KnownHosts    string // ~/.ssh/known_hosts
	PubKeyDir     string // ~/.nazar/keys
	Now           func() time.Time
	PollInterval  time.Duration        // config file polling (1s)
	GateTimeout   func() time.Duration // overrides defaults.timeout (tests)
	Logf          func(string, ...any) // diagnostics (not the audit log)
	// VerifyCLI checks that a control connection's peer is the genuine
	// nazar CLI and returns the process it checked (secrets design 7.3;
	// control.Server.VerifyCLI): the bridge sets it from the agent's own
	// signature. nil returns no secret value to anyone.
	VerifyCLI func(fd int) (platform.ProcessRef, error)

	// Exec is the exec seam nazar run's late-env handover needs (secrets
	// design 6.3, D8); nil refuses late-env before any prompt.
	Exec platform.Exec
	// Mounts tells a late-env run whether a volume was mounted or unmounted
	// while it ran (D12); nil refuses late-env before any prompt.
	Mounts platform.Mounts
	// Pipes tells whether the CLI's stdout is a pipe its parent reads
	// (THREAT-MODEL 5.16); nil refuses k8s.credential before any
	// prompt.
	Pipes platform.Pipes
	// LoaderDir holds the loaders (node/env.cjs, python/sitecustomize.py):
	// the agent bundle's Contents/Resources/loaders, a realpath (D9). ""
	// refuses late-env before any prompt.
	LoaderDir string
	// RunHost is what the agent knows of a run's user (home, name, temp
	// folder) from its own sources (defaultRunHost).
	RunHost func(uid int) (envpolicy.Host, error)
	// ShimDirs are the folders of Apple's xcode-select shims (run.Resolver;
	// /usr/bin on macOS).
	ShimDirs []string
	// RunExecTimeout bounds the wait for the CLI's exec (10 s) and
	// RunHandoverTimeout the wait for the target to connect (120 s).
	RunExecTimeout     time.Duration
	RunHandoverTimeout time.Duration
	// AWS is the IAM Roles Anywhere client (aws design 9.4); nil is AWS
	// itself. Only the daemon's tests point it at a fake endpoint
	// (core/aws/awstest); never config, the environment or nazar-testd,
	// which leaves it nil (it sets no VerifyCLI, so check 0 refuses every
	// aws credential there before AWS could be called).
	AWS *aws.Client
}

// Daemon is the running core.
type Daemon struct {
	o        Options
	traits   platform.Traits // o.Platform's: what it can match and the words its messages use
	vault    vaultWords      // how its vault's reasons and remedies are worded
	stager   *configstage.Stager
	engine   atomic.Pointer[policy.Engine]
	trust    *trust.Store
	eval     *match.Evaluator
	keys     *keys.Registry
	secrets  *secrets.Store
	k8sCA    *k8s.CAStore // the k8s contexts' CAs
	k8sIssue map[config.CredentialKind]k8s.Provider
	awsCA    *certs.Store // the aws entries' CAs
	cache    *approval.Cache
	audit    *audit.Logger
	broker   *broker.Broker
	resolver *caller.Resolver
	agent    *sshagent.Server
	uses     keyUses   // last use of each key (Milestone 5)
	started  time.Time // when New ran: uses covers the time since

	// reloadMu serialises observing the config file with the one handler
	// that edits it (ssh-key create), so the file poller can never stage
	// and prompt for a change the daemon itself is in the middle of
	// applying as an authenticated edit. Lock order: reloadMu before
	// prompts.mu (configEdit, ssh-key create); nothing takes reloadMu while
	// holding prompts.mu.
	reloadMu sync.Mutex
	hold     editHold // guarded by reloadMu

	mu        sync.Mutex
	agentL    *net.UnixListener
	agentPath string
	lastSeen  string
	running   bool

	prompts loginPrompts

	// stopping is closed when Run stops, so a nazar run handover waiting
	// for its target does not hold the control server open.
	stopping chan struct{}
	stopOnce sync.Once
}

// ConfigApplyCooldown is how long the daemon refuses to open another
// login prompt of its own (`nazar config apply`, `ssh-key create`,
// `ssh-key delete`, `trust`, and the background config prompt) after one
// ended denied, timed out or failed, so neither the control socket nor the
// config file can drive a prompt loop.
const ConfigApplyCooldown = 60 * time.Second

// editHoldFor bounds the hold a loosening staged by config.edit puts on the
// background prompt (editHold). The CLI (for a person, a script, an agent
// or the window alike) sends the config.apply bound to the edit's hash the
// moment the edit returns staged, so the hold normally ends within a
// second; the bound only matters when no apply comes (a CLI killed in
// between, or a client of the control socket that is not the CLI), and
// keeps a later hand edit from going unprompted for long.
const editHoldFor = 30 * time.Second

// editHoldWhy is the warning's reason for a content staged during a hold.
const editHoldWhy = "it changed while a change made with nazar (`nazar ssh-key rule`, `nazar ssh-key set` or the Nazar window) was waiting for approval, so nazar did not ask about it, and does not ask about it on its own later."

// editHold is the hold on the background prompt from the moment
// config.edit stages a loosening (hash, the edit's content) until the
// `config apply` of that change has been handled or until passes.
// A process watching config.yaml sees the edit land before the edit's
// reply reaches the CLI; a rewrite it makes then, prompted for in the
// background (the poller's tick, or its own `nazar config check`), would
// put its change in front of the user exactly when they expect the prompt
// for their own, under the same title. During the hold no other content is
// prompted for, by the poller or by `config apply`: each is reported
// blocked once and never asked about on its own later. Guarded by reloadMu.
type editHold struct {
	hash  string
	until time.Time
}

// stagedBlockedReason is the audit reason of a staged change that got no
// automatic prompt.
const stagedBlockedReason = "config change staged; run nazar config apply"

// maxSeenHashes bounds the memory a process rewriting the file without end
// can make the daemon hold; past it the set starts over, which can cost a
// second blocked line and warning for an old content, never a prompt while
// prompts are suppressed.
const maxSeenHashes = 4096

// PromptsVaultItem is the vault item that carries the config-prompt
// suppression and the cooldown across restarts. A same-user process
// can kill Nazar.app and let launchd relaunch it, so state that lived only
// in memory would hand it a fresh prompt per relaunch. The item is written
// when a prompt opens (so a process killed with the prompt on screen counts
// as not approved) and when it ends; it is removed once nothing is
// suppressed and no cooldown runs.
const PromptsVaultItem = "config/prompts"

// promptRecord is the vault item's content.
type promptRecord struct {
	Suppressed bool      `json:"suppressed"`
	Until      time.Time `json:"until"`
}

// errPromptOpen refuses a login prompt while another one is on screen.
var errPromptOpen = errors.New("an approval prompt is already open")

// errHeld refuses, after the prompt was claimed, a config prompt for a
// change other than the one an edit's hold is waiting for (editHold): the
// caller read the hold before it claimed, and the hold started in between.
var errHeld = errors.New("a change made with nazar is waiting for approval; the staged change is not it")

// cooldownError refuses a login prompt during the cooldown after one that
// ended without an approval.
type cooldownError struct{ left time.Duration }

func (e cooldownError) Error() string {
	return "the last approval prompt was denied, not answered, or approved after the file had changed; nazar can ask again in " + seconds(e.left)
}

// loginPrompts throttles every login prompt the daemon opens outside the
// agent socket: the background prompt for a staged config change and the
// prompts of the loosen commands (`config apply`, `ssh-key create`,
// `ssh-key delete`, `trust`, `trust --app`), which all look the same on
// screen (spec 4.8, 6, 8). The config file and the control socket are
// both open to any same-user process, which could otherwise keep a fresh
// prompt on screen for ever (a denial of service, and a lesson in approving
// by reflex). So:
//   - one such prompt is open at a time;
//   - a staged content hash is prompted for automatically at most once, and
//     never once a background prompt ended without its change being
//     applied: from then on only an approved `nazar config apply` turns the
//     automatic prompt back on;
//   - after any of these prompts ends denied, timed out, failed, or approved
//     without its change being applied (the file changed while it was
//     open), none of them opens for ConfigApplyCooldown.
//
// The suppression and the cooldown are kept in the vault (PromptsVaultItem),
// so a restart does not reset them; when the vault refuses to record an
// opening prompt, the prompt is not shown (a locked Keychain must not turn
// into an unthrottled prompt). Every vault write is made under mu, in the
// same step as the memory change it records: written after the unlock, a
// slow write (Keychain XPC) could land after a newer one and leave the vault
// describing an older state than memory, e.g. the Delete that ends an
// approved prompt erasing the record of the next prompt, claimed in that
// window, so that a kill-and-relaunch with it on screen finds no cooldown
// and no suppression. mu is a leaf lock and the vault never calls back, so
// holding it across the write only makes the other throttle calls wait. The
// sign prompts of the agent socket are governed by the rules and the
// approval cache instead.
type loginPrompts struct {
	vault   platform.Vault
	logf    func(string, ...any)
	timeout func() time.Duration // how long a prompt can stay open (the gate timeout); nil = unknown

	mu         sync.Mutex
	unreadable string              // why the vault item could not be read at load ("" = read, absent, or written since)
	seen       map[string]struct{} // config hashes prompted for or reported blocked since the active config last changed
	open       bool                // a login prompt is on screen
	suppressed bool                // no automatic config prompts until `nazar config apply` applies
	until      time.Time           // no login prompt before this
	blocked    int                 // contents blocked since the last applied config (the warning's count)
}

// load restores, at now, the suppression and cooldown a previous process
// left in the vault. A missing item means nothing is pending. An item that
// can't be read (an item of another build of Nazar.app, a locked keychain)
// or parsed is taken as suppressed (fail closed) and remembered in
// unreadable for `nazar status`: every claim must
// write the item first, so no login prompt opens until the user deletes it
// (or it reads again). The cooldown inherited is at most
// ConfigApplyCooldown from now: the record of a prompt that was open when
// the process died carries the prompt's whole timeout on top of the
// cooldown (claim), and a wall clock that jumped backwards since the write
// would otherwise turn any record into a lockout of hours, with `nazar
// config apply` refused until the clock catches up.
func (c *loginPrompts) load(now time.Time) {
	b, err := c.vault.Get(PromptsVaultItem)
	if errors.Is(err, platform.ErrNotFound) {
		return
	}
	var r promptRecord
	if err == nil {
		err = json.Unmarshal(b, &r)
	}
	if err != nil {
		c.logf("config: unreadable %s item, treating config prompts as suppressed: %v", PromptsVaultItem, err)
		r = promptRecord{Suppressed: true}
		c.mu.Lock()
		c.unreadable = err.Error()
		c.mu.Unlock()
	}
	if limit := now.Add(ConfigApplyCooldown); r.Until.After(limit) {
		r.Until = limit
	}
	c.mu.Lock()
	c.suppressed, c.until = r.Suppressed, r.Until
	c.mu.Unlock()
}

// unreadableReason is why the vault item could not be read at load, or ""
// once it was read, was absent, or has been written since.
func (c *loginPrompts) unreadableReason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.unreadable
}

// persist writes r to the vault; a record that neither suppresses nor
// cools down removes the item. The caller holds mu (see loginPrompts).
func (c *loginPrompts) persist(r promptRecord, now time.Time) error {
	if !r.Suppressed && !r.Until.After(now) {
		if err := c.vault.Delete(PromptsVaultItem); err != nil && !errors.Is(err, platform.ErrNotFound) {
			return err
		}
		c.unreadable = ""
		return nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := c.vault.Put(PromptsVaultItem, b); err != nil {
		return err
	}
	c.unreadable = "" // the item now holds a record this build wrote
	return nil
}

// claim opens a login prompt at now(): it fails during the cooldown, while
// another one is on screen, and when the vault refuses to record the
// opening (then nothing is claimed). The record makes a relaunched process
// treat the prompt as not approved, with the cooldown counted from the
// latest moment the prompt can end (now + the gate timeout), not from now:
// a process killed with a long prompt on screen must relaunch into a
// cooldown however long the prompt had been open (load caps what it
// inherits at ConfigApplyCooldown). For a config prompt the record also
// suppresses the automatic prompts. The memory state is left alone, so an
// open prompt is still reported as open, not as denied. The returned claim
// is ended by its holder (loginClaim).
func (c *loginPrompts) claim(now func() time.Time, config bool) (*loginClaim, error) {
	at := now()
	until := at.Add(c.longest() + ConfigApplyCooldown)
	c.mu.Lock()
	defer c.mu.Unlock()
	if left := c.left(at); left > 0 {
		return nil, cooldownError{left}
	}
	if c.open {
		return nil, errPromptOpen
	}
	if err := c.persist(promptRecord{Suppressed: c.suppressed || config, Until: until}, at); err != nil {
		return nil, err
	}
	c.open = true
	return &loginClaim{c: c, config: config, now: now}, nil
}

// longest is how long a prompt claimed now can stay open: the gate
// timeout, or its built-in default when the throttle has no gate to ask.
func (c *loginPrompts) longest() time.Duration {
	if c.timeout != nil {
		if d := c.timeout(); d > 0 {
			return d
		}
	}
	return config.DefaultTimeout
}

// loginClaim is a claim on the login prompt (loginPrompts.claim), held by
// one command or background prompt and ended exactly once: by end once
// the prompt was shown (applied says whether the change it asked about
// took effect: only then is it an approval for the throttle), or by
// release when no prompt was shown after all. Every holder defers close
// right after claiming, so a claim left open by an early return after the
// approval (the config file became unreadable, the vault refused the
// write, the key could not be deleted) or by a panic is ended as not
// applied; otherwise the prompt would count as open for the rest of the
// process and every later login prompt would be refused as "already
// open", a denial of service any same-user process can arrange. A
// claim is used by one goroutine at a time.
type loginClaim struct {
	c      *loginPrompts
	config bool
	now    func() time.Time
	ended  bool
}

// end ends the claim of a prompt that was shown (loginPrompts.outcome).
func (l *loginClaim) end(applied bool) {
	if l.ended {
		return
	}
	l.ended = true
	l.c.outcome(applied, l.config, l.now())
}

// release ends the claim of a prompt that was never shown
// (loginPrompts.release).
func (l *loginClaim) release() {
	if l.ended {
		return
	}
	l.ended = true
	l.c.release(l.now())
}

// close is the deferred guard: a claim still open is ended as not applied.
func (l *loginClaim) close() { l.end(false) }

// release ends a claim whose prompt was never shown after all (the staged
// change moved on first): the vault goes back to the memory state.
func (c *loginPrompts) release(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open = false
	if err := c.persist(promptRecord{Suppressed: c.suppressed, Until: c.until}, now); err != nil {
		c.logf("config: cannot record the prompt state in the vault: %v", err)
	}
}

// outcome ends a claim whose prompt was shown, in memory and in the vault.
// ok says the prompt was approved AND its change applied; anything else
// starts the cooldown, and for a config prompt suppresses the automatic
// prompts. An applied config lifts the suppression and forgets the contents
// seen so far (they were changes against the old config); another applied
// change leaves it alone. A vault that refuses the record of a failure
// leaves the one written when the prompt opened, which already cools down.
func (c *loginPrompts) outcome(ok, config bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open = false
	switch {
	case ok && config:
		c.suppressed, c.until, c.blocked, c.seen = false, time.Time{}, 0, nil
	case !ok:
		c.until = now.Add(ConfigApplyCooldown)
		if config {
			c.suppressed = true
		}
	}
	if err := c.persist(promptRecord{Suppressed: c.suppressed, Until: c.until}, now); err != nil {
		c.logf("config: cannot record the prompt outcome in the vault: %v", err)
	}
}

// forget drops the contents seen so far: the active config changed under
// them (a tightening, an authenticated edit), so the same bytes staged
// again are a new change, to be prompted for or reported blocked once
// more. The suppression and the cooldown are untouched.
func (c *loginPrompts) forget() {
	c.mu.Lock()
	c.seen = nil
	c.mu.Unlock()
}

// mark records hash as seen; it reports whether it was new. The caller
// holds mu.
func (c *loginPrompts) mark(hash string) bool {
	if _, ok := c.seen[hash]; ok {
		return false
	}
	if c.seen == nil || len(c.seen) >= maxSeenHashes {
		c.seen = map[string]struct{}{}
	}
	c.seen[hash] = struct{}{}
	return true
}

// left is how long the cooldown still runs at now (0 = not at all), in
// whole seconds, rounded up. The caller holds mu.
func (c *loginPrompts) left(now time.Time) time.Duration {
	left := c.until.Sub(now)
	if left <= 0 {
		return 0
	}
	return (left + time.Second - 1).Truncate(time.Second)
}

func (o *Options) defaults() {
	if o.ConfigPath == "" {
		o.ConfigPath = layout.ConfigFile(o.Home)
	}
	if o.ControlSocket == "" {
		o.ControlSocket = layout.ControlSocket(o.Home)
	}
	if o.KnownHosts == "" {
		o.KnownHosts = filepath.Join(o.Home, ".ssh", "known_hosts")
	}
	if o.PubKeyDir == "" {
		o.PubKeyDir = layout.KeysDir(o.Home)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.PollInterval == 0 {
		o.PollInterval = time.Second
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.RunHost == nil {
		o.RunHost = defaultRunHost
	}
	if o.ShimDirs == nil && runtime.GOOS == "darwin" {
		o.ShimDirs = []string{"/usr/bin"}
	}
	if o.RunExecTimeout == 0 {
		o.RunExecTimeout = 10 * time.Second
	}
	if o.RunHandoverTimeout == 0 {
		o.RunHandoverTimeout = 120 * time.Second
	}
}

// New builds a daemon and loads the last approved config. It does not
// listen yet; call Run.
func New(o Options) (*Daemon, error) {
	o.defaults()
	if o.Platform == nil || o.Vault == nil || o.AuditSink == nil || o.Home == "" {
		return nil, errors.New("daemon: Platform, Vault, AuditSink and Home are required")
	}
	d := &Daemon{o: o, traits: platform.TraitsOf(o.Platform), vault: vaultWordsOf(platform.TraitsOf(o.Platform)), resolver: &caller.Resolver{P: o.Platform}, stopping: make(chan struct{})}
	d.prompts = loginPrompts{vault: o.Vault, logf: o.Logf}
	// The suppression a previous process left behind is honoured before the
	// first Reload, so a relaunch is not a fresh prompt. Vault items
	// this build can't read (an item of another build of Nazar.app: every
	// ad-hoc rebuild is a new app to the Keychain) don't stop the app: each
	// degrades on its own, failing closed, and `nazar status` names it with
	// the command that fixes it (vaulthealth.go).
	d.prompts.load(o.Now())
	// The helpers a previous process saw below their apps (THREAT-MODEL
	// 5.14), so a tab that outlived its app's restart stays the app's
	// across this one.
	d.resolver.Remember(o.Vault, o.Logf)
	d.trust = trust.OpenOrDegrade(o.Vault)
	d.audit = audit.NewLogger(o.AuditSink, audit.Formatter{Home: o.Home}, func(err error) { o.Logf("audit: %v", err) })
	d.audit.SetObserver(d.uses.record)
	d.started = o.Now()
	d.eval = &match.Evaluator{Trust: d.trust, Note: func(m string) { o.Logf("match: %s", m) }, PinWord: d.pinWord()}
	d.cache = approval.New(o.Now, o.Platform.ReleaseApproval)
	d.keys = keys.NewRegistry(o.Platform, o.Vault, o.PubKeyDir, o.Now)
	d.secrets = secrets.NewStore(o.Platform, o.Vault, o.Now)
	d.k8sCA = k8s.NewCAStore(o.Platform, o.Vault, o.Now)
	d.k8sIssue = providers(d.k8sCA, o.Platform)
	d.awsCA = aws.NewCAStore(o.Platform, o.Vault, o.Now)
	d.broker = broker.New(broker.Options{
		Platform: o.Platform, Cache: d.cache, Audit: d.audit, Engine: d.engine.Load,
		Now: o.Now, Home: o.Home, Timeout: o.GateTimeout,
	})
	d.prompts.timeout = d.broker.GateTimeout // a claim's record outlasts the prompt it opens
	d.agent = &sshagent.Server{Keys: d.keys, Broker: d.broker, Resolver: d.resolver,
		KnownHosts: func() string { return o.KnownHosts }, Logf: o.Logf}
	env := d.configEnv()
	// The stager gets the trust store and the platform so that an approved
	// loosening pins app: teams from the installed apps (spec 4.2). An
	// approved config it can't read is "none yet": the built-in default
	// blocks every key and config.yaml waits for the login gate.
	d.stager = configstage.OpenOrDefault(env, o.Vault, d.trust, o.Platform, d.apply)
	return d, nil
}

// configEnv is the config.Env every parse of config.yaml uses: on a
// platform without code signatures, signed: and app: team: are refused.
func (d *Daemon) configEnv() config.Env {
	return config.Env{Home: d.o.Home, NoCodeSigning: !d.traits.CodeSigning}
}

// pinWord is the Evaluator's PinWord: "" on macOS, whose notes keep their
// wording, the platform's PinWord elsewhere.
func (d *Daemon) pinWord() string {
	if d.traits.PinWord == platform.MacTraits.PinWord {
		return ""
	}
	return d.traits.PinWord
}

// apply makes c the active config: the policy engine is swapped, the
// audit formatter follows audit.args, approvals of edited or removed rules
// are dropped, and the agent socket moves if its path changed.
func (d *Daemon) apply(c *config.Config) {
	// command: matchers resolve through this config's trustedPath, on a
	// copy of the evaluator: an engine already in use keeps its own.
	ev := *d.eval
	ev.Command = (&run.Resolver{TrustedPath: c.Defaults.TrustedPath, ShimDirs: d.o.ShimDirs}).Locate
	eng := policy.New(c, &ev)
	eng.NoCodeSigning = !d.traits.CodeSigning
	d.engine.Store(eng)
	d.audit.SetFormatter(audit.Formatter{Args: audit.ArgsMode(c.Audit.Args), Home: d.o.Home})
	d.cache.RetainRules(policy.LiveRuleIDs(c), "config changed")
	d.mu.Lock()
	relisten := d.running && c.SSHAgent.Socket != d.agentPath
	d.mu.Unlock()
	if relisten {
		if err := d.listenAgent(c.SSHAgent.Socket); err != nil {
			d.o.Logf("agent: cannot move socket to %s: %v", c.SSHAgent.Socket, err)
		}
	}
}

// Run listens on the control and agent sockets and polls the config file
// until ctx is done. It returns nil once everything it started is stopped.
// An install of the old layout is moved into ~/.nazar first (layout.Migrate).
func (d *Daemon) Run(ctx context.Context) error {
	if err := layout.Prepare(d.o.Home); err != nil {
		return err
	}
	for _, l := range layout.Migrate(d.o.Home) {
		d.o.Logf("layout: %s", l)
	}
	d.migrateConfig()
	d.Reload()
	d.sweepRunSockets()
	cl, err := unixsock.Listen(d.o.ControlSocket)
	if err != nil {
		return err
	}
	ctrl := &control.Server{Handler: d, Resolve: d.resolver.ResolveFD, Logf: d.o.Logf, VerifyCLI: d.o.VerifyCLI}
	ctrlDone := make(chan struct{})
	go func() {
		defer close(ctrlDone)
		if err := ctrl.Serve(cl); err != nil {
			d.o.Logf("control: %v", err)
		}
	}()
	d.mu.Lock()
	d.running = true
	d.mu.Unlock()
	if err := d.listenAgent(d.stager.Active().SSHAgent.Socket); err != nil {
		cl.Close()
		<-ctrlDone
		return err
	}
	t := time.NewTicker(d.o.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.stopOnce.Do(func() { close(d.stopping) })
			cl.Close()
			d.mu.Lock()
			d.running = false
			l := d.agentL
			d.agentL = nil
			d.mu.Unlock()
			if l != nil {
				l.Close()
			}
			<-ctrlDone
			return nil
		case <-t.C:
			d.Reload()
			d.cache.Sweep()
		}
	}
}

// listenAgent (re)binds the agent socket at path and serves it; the
// previous listener, if any, is closed.
func (d *Daemon) listenAgent(path string) error {
	l, err := unixsock.Listen(path)
	if err != nil {
		return err
	}
	d.mu.Lock()
	old := d.agentL
	d.agentL, d.agentPath = l, path
	d.mu.Unlock()
	if old != nil {
		old.Close()
	}
	go func() {
		if err := d.agent.Serve(l); err != nil {
			d.o.Logf("agent: %v", err)
		}
	}()
	return nil
}

// AgentSocket is the path the agent listens on ("" before Run).
func (d *Daemon) AgentSocket() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.agentPath
}

// readConfig returns the file contents, or nil if it doesn't exist. A file
// over the size limit is returned truncated so Parse rejects it.
func (d *Daemon) readConfig() ([]byte, error) {
	f, err := os.Open(d.o.ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, config.MaxFileSize+1))
}

// contentHash identifies file contents for the poller; a missing file has
// its own value so that removing the file counts as a change.
func contentHash(data []byte) string {
	if data == nil {
		return "missing"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Reload observes the config file if it changed since the last look. A
// tightening applies at once, an invalid file keeps the last approved
// config, and a staged (loosening) change starts the login prompt in the
// background (spec 4.8), at most once per content and never while prompts
// are suppressed (see loginPrompts).
//
// While an edit's loosening waits for its `config apply` (editHold), no
// other content is prompted for: it is reported blocked once, with
// editHoldWhy. The edit's own content gets no background prompt either;
// its apply is on the way.
func (d *Daemon) Reload() {
	staged, held := d.syncConfig()
	if !staged {
		return
	}
	p, ok := d.stager.Pending()
	switch {
	case !ok:
	case held == "":
		d.autoPrompt(p.Config.Hash)
	case p.Config.Hash != held:
		d.blockStaged(p.Config.Hash, editHoldWhy)
	}
}

// syncConfig is Reload without the background prompt: it reports whether a
// change is staged and leaves asking to the caller. held is the hash of
// the edit whose apply holds the background prompt, read under the same
// lock as the observation ("" = no hold).
func (d *Daemon) syncConfig() (staged bool, held string) {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	return d.observe(), d.heldLocked()
}

// heldLocked returns the hash of the edit holding the background prompt,
// or "" when there is no hold or it has run out. The caller holds reloadMu.
func (d *Daemon) heldLocked() string {
	if d.hold.hash != "" && !d.o.Now().Before(d.hold.until) {
		d.hold = editHold{}
	}
	return d.hold.hash
}

// releaseHold ends the hold of the edit whose content hash is hash (its
// `config apply` was handled); a hold of another edit stays.
func (d *Daemon) releaseHold(hash string) {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	if d.hold.hash == hash {
		d.hold = editHold{}
	}
}

// autoPrompt starts the background prompt for the newly staged content
// hash, or, when it may not prompt (seen before, prompts suppressed, a
// prompt open, the cooldown running, the vault refusing to record the
// prompt), reports the content as blocked: one audit line and one update
// of the non-modal warning per content, naming `nazar config apply`. The
// warning says why this content got no prompt, which is not the same for
// every cause: after a suppression nazar never asks on its own again, while
// another prompt or the cooldown only stood in the way of this content,
// which is still not asked about later. A content seen before is one
// prompted for or reported blocked against the current active config; every
// change of that config forgets them all.
func (d *Daemon) autoPrompt(hash string) {
	c := &d.prompts
	c.mu.Lock()
	if !c.mark(hash) {
		c.mu.Unlock()
		return
	}
	suppressed := c.suppressed
	c.mu.Unlock()
	why := "nazar does not ask again on its own after a prompt was denied, not answered, or approved after the file had changed."
	if !suppressed {
		var cool cooldownError
		switch cl, err := c.claim(d.o.Now, true); {
		case err == nil:
			go func() {
				if _, err := d.approveStaged(cl, hash, nil, true); err != nil && !errors.Is(err, configstage.ErrBusy) && !errors.Is(err, errHeld) {
					d.o.Logf("config: approval: %v", err)
				}
			}()
			return
		case errors.Is(err, errPromptOpen):
			why = "nazar does not ask while another approval prompt is open, and does not ask about this change on its own later."
		case errors.As(err, &cool):
			why = "nazar does not ask for " + seconds(cool.left) + " after a prompt was denied, not answered, or approved after the file had changed, and does not ask about this change on its own later."
		default:
			d.o.Logf("config: cannot record the prompt in the vault, not asking: %v", err)
			why = "nazar could not record the prompt in the vault " + d.vault.cantRecord() + ", so it did not ask."
		}
	}
	d.warnStaged(why)
}

// blockStaged reports the staged content hash blocked without asking, as
// autoPrompt does when it may not prompt (once per content), saying why.
func (d *Daemon) blockStaged(hash, why string) {
	c := &d.prompts
	c.mu.Lock()
	fresh := c.mark(hash)
	c.mu.Unlock()
	if fresh {
		d.warnStaged(why)
	}
}

// warnStaged is the blocked report of a staged content: one audit line and
// one update of the non-modal warning, saying why it got no prompt.
func (d *Daemon) warnStaged(why string) {
	c := &d.prompts
	c.mu.Lock()
	c.blocked++
	count := c.blocked
	c.mu.Unlock()
	d.logOp("config", audit.Blocked, stagedBlockedReason, nil)
	d.o.Platform.ShowWarning(platform.Warning{
		ID:    "config|staged",
		Title: "A change to nazar's config is waiting for approval",
		Lines: []string{
			layout.ConfigFileTilde + " changed, but the new rules are not in force:",
			why,
			"Run `nazar config check` to see the change and `nazar config apply` to approve it.",
		},
		Count: count,
	})
}

// approveStaged shows the login prompt for the staged change whose hash is
// hash and applies it on approval. The caller has claimed the prompt (cl);
// it is ended here whatever happens, with the outcome decided by what
// happened to the change, not by the gate's answer alone: an approval of a
// change that was no longer the file's content when it came (the file was
// rewritten while the prompt was open) or that could not be recorded
// applied nothing, so it counts as not approved and cannot re-arm the
// automatic prompt. peer is the control client that asked (nil for
// the background prompt), for the audit log. With auto, a content that got
// no prompt after all (the staged change moved on first) is forgotten
// again, so a later staging of it can still be asked about once. A content
// whose prompt was shown is remembered only when its change did not apply:
// an applied one is the active config now, and the throttle's memory
// starts over with it (loginPrompts.outcome), so the same bytes staged
// again after a later change are asked about again.
//
// The edit hold is read again once the prompt is claimed, right before it
// is shown: the caller read it before claiming (Reload, configApply), and
// an edit can stage its loosening and take the hold in between (claiming
// is a vault write). Approve's hash check does not catch that, since the
// attacker can write its content again after the edit (A → C0 → X → A).
// From the claim on, no hold can start (configEdit is refused while a
// prompt is claimed), so this read is authoritative. A change that is not
// the held one gets no prompt (errHeld): the claim is released without a
// cooldown, and the background prompt reports the content blocked with
// editHoldWhy instead of forgetting it.
func (d *Daemon) approveStaged(cl *loginClaim, hash string, peer *caller.Chain, auto bool) (bool, error) {
	applied, _, err := d.approveStagedShown(cl, hash, peer, auto)
	return applied, err
}

// approveStagedShown is approveStaged that also reports whether the prompt
// was shown: an apply that showed nothing has not handled the change.
func (d *Daemon) approveStagedShown(cl *loginClaim, hash string, peer *caller.Chain, auto bool) (bool, bool, error) {
	defer cl.close()
	shown := false
	var dec audit.Decision
	var reason string
	ok, err := d.stager.Approve(hash, func(p configstage.Pending) (bool, error) {
		d.reloadMu.Lock()
		held := d.heldLocked()
		d.reloadMu.Unlock()
		if held != "" && held != p.Config.Hash {
			return false, errHeld
		}
		shown = true
		lines := append([]string{}, p.Diff.Changes...)
		for _, f := range p.Diff.Loosening {
			lines = append(lines, "loosens "+f.Target+": "+f.Why)
		}
		dec, reason = d.broker.Login(platform.Prompt{
			Title:  "Allow this change to nazar's config?",
			Lines:  lines,
			Reason: "approve a change to " + layout.ConfigFileTilde,
		})
		return dec == audit.Approved, nil
	})
	if !shown {
		cl.release()
		switch {
		case auto && errors.Is(err, errHeld):
			// autoPrompt marked it seen and reported nothing: report it
			// now, once, and never ask about it on its own later.
			d.prompts.mu.Lock()
			d.prompts.mark(hash)
			d.prompts.mu.Unlock()
			d.warnStaged(editHoldWhy)
		case auto:
			d.prompts.mu.Lock()
			delete(d.prompts.seen, hash)
			d.prompts.mu.Unlock()
		}
		return ok, false, err
	}
	applied := ok && err == nil
	if !applied {
		d.prompts.mu.Lock()
		d.prompts.mark(hash)
		d.prompts.mu.Unlock()
	}
	cl.end(applied)
	switch {
	case applied:
		d.logOp("config", audit.Approved, "config change: "+reason, peer)
	case dec == audit.Approved && errors.Is(err, configstage.ErrStale):
		d.logOp("config", audit.Error, "config change: approved, but config.yaml changed while the prompt was open; nothing applied", peer)
	case dec == audit.Approved:
		d.logOp("config", audit.Error, "config change: approved, but it could not be applied: "+err.Error(), peer)
	default:
		d.logOp("config", dec, "config change: "+reason, peer)
	}
	return ok, true, err
}

// observe reads and stages the file; it reports whether a change was
// staged. The caller holds reloadMu.
func (d *Daemon) observe() (staged bool) {
	data, err := d.readConfig()
	if err != nil {
		d.o.Logf("config: %v", err)
		return false
	}
	h := contentHash(data)
	d.mu.Lock()
	same := h == d.lastSeen
	d.lastSeen = h
	d.mu.Unlock()
	if same {
		return false
	}
	r := d.stager.Observe(data)
	switch {
	case r.Invalid:
		d.o.Logf("config: invalid, keeping the last approved config:\n%s", r.Problems.Error())
		d.logOp("config", audit.Error, "invalid config file; last approved config kept", nil)
	case r.Applied:
		d.prompts.forget() // the contents seen so far were changes against the old config
		d.logOp("config", audit.Allowed, "tightening change applied", nil)
	case r.Staged:
		return true
	}
	return false
}

// logOp writes an audit line for a control or config action. The CLI's
// chain (peer) says who asked; the audit formatter quotes every value.
func (d *Daemon) logOp(target string, dec audit.Decision, reason string, peer *caller.Chain) {
	e := audit.Event{Time: d.o.Now(), Decision: dec, Reason: reason, Target: target}
	if peer != nil {
		if peer.HasApp() {
			e.App = peer.App.BundleID
		}
		e.Session = peer.Session.String()
		e.Chain = broker.AuditChain(peer) // the broker's chain, deleted mark outside the name
		if pr, ok := peer.Peer(); ok {
			e.Receiver, e.Cwd = pr.Args, pr.Cwd
		}
	}
	d.audit.Log(e)
}
