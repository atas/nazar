package configstage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
)

// ApprovedVaultItem is where the last approved config is kept (spec 4.8).
// The item is absent while the built-in default is the approved config.
const ApprovedVaultItem = "config/approved"

// PathsApprovedVaultItem records that the approved config's path:
// matchers were approved as matching: the config's hash, written by this
// build when it saves an approved config that has path: matchers. Builds
// before it had no path: matcher that matched anything (one matched
// nothing for a while, and was then added without a prompt; before that
// only with `nazar trust`), so a config with path: matchers that this
// record does not name is held without them until the owner approves it
// again (Open). It is a vault item of its own, never anything in the
// config: the approved item is config.yaml byte for byte, which any
// process of the user could write while a new path: rule needed no
// approval.
const PathsApprovedVaultItem = "config/approved-paths"

// Pending is a loosening change waiting for the login gate.
type Pending struct {
	Config *config.Config
	Diff   Diff
	// Problems are Config's parse warnings (from Preview, or Observe for a
	// staged change): what LastProblems says once ApplyAuthenticated made it
	// active.
	Problems config.Problems
}

// Result says what Observe did.
type Result struct {
	Applied  bool // the new config is active now
	Staged   bool // a loosening change is waiting for approval
	Invalid  bool // the file is invalid; the active config is unchanged
	Diff     Diff
	Problems config.Problems
}

// Approver runs the login gate for a staged change; true means approved.
// It is called without any Stager lock held, so it may use the Stager.
type Approver func(p Pending) (bool, error)

// Errors Approve returns.
var (
	// ErrNothingStaged: there is no pending change.
	ErrNothingStaged = errors.New("configstage: nothing is staged")
	// ErrStale: the pending change is not the one the caller asked about,
	// or the file changed while the prompt was open.
	ErrStale = errors.New("configstage: the staged change is no longer what the file says")
	// ErrBusy: another approval prompt is open.
	ErrBusy = errors.New("configstage: an approval is already in progress")
)

// Stager holds the active (approved) config and at most one pending change.
// Every method may be called from any goroutine.
type Stager struct {
	env     config.Env
	vault   platform.Vault
	onApply func(*config.Config)
	// pins and apps, when set (OpenWithTrust), let a loosening change show
	// and, on approval, record app: team pins (pins.go). Without them no
	// config change ever pins.
	pins PinStore
	apps AppResolver

	// applyMu serialises everything that can change what is active or
	// staged (Observe, the apply half of Approve, ApplyAuthenticated) and
	// the onApply calls, so configs are announced in the order they became
	// active. It is never held while an Approver runs.
	applyMu sync.Mutex
	// mu guards the fields below for the readers; it is only ever held
	// briefly and never while calling out.
	mu        sync.Mutex
	active    *config.Config
	pending   *Pending
	lastErr   config.Problems
	approving bool
	// unreadable is why the approved config could not be read at Open
	// (OpenOrDefault); "" once a config was saved as approved since.
	unreadable string
	// held is set when the active config is the approved one without its
	// path: matchers, which were approved while they matched nothing
	// (PathsApprovedVaultItem): the file is classified against it even
	// when its bytes are the approved ones, so the matchers need the gate.
	held bool
}

// Open loads the last approved config from the vault: the built-in default
// when there is none, or when the stored item no longer parses (corrupt, or
// refused by today's validation; old forms a build before accepted are
// read as it read them, config.ParseApproved). Any other vault error is returned, since
// starting from the default would forget what was approved. onApply is
// called whenever a config becomes active, the initial one included, with
// applyMu held: it may read the Stager but must not call Observe, Approve
// or ApplyAuthenticated.
func Open(env config.Env, v platform.Vault, onApply func(*config.Config)) (*Stager, error) {
	return OpenWithTrust(env, v, nil, nil, onApply)
}

// OpenWithTrust is Open with the trust store and the platform that let an
// approved loosening pin app: matchers' teams from the installed apps (spec
// 4.2). Loading the approved config here never pins anything: the gate was
// passed for the config, not for apps installed since.
func OpenWithTrust(env config.Env, v platform.Vault, pins PinStore, apps AppResolver, onApply func(*config.Config)) (*Stager, error) {
	s := &Stager{env: env, vault: v, onApply: onApply, pins: pins, apps: apps, active: config.Default(env)}
	b, err := v.Get(ApprovedVaultItem)
	switch {
	case errors.Is(err, platform.ErrNotFound):
	case err != nil:
		return nil, err
	default:
		// A record that can't be read is no record.
		mark, markErr := v.Get(PathsApprovedVaultItem)
		pathsOK := markErr == nil && string(mark) == contentHash(b)
		c, probs := config.Parse(b, env)
		if probs.HasErrors() {
			// An approved config in old forms (config.Migrate): rewritten
			// in today's where that keeps the meaning, and read as the
			// build that approved it read it, so it stays in force.
			if nb, ok := config.Migrate(b, env); ok {
				c, probs = config.ParseApproved(nb, env)
				pathsOK = pathsOK || markErr == nil && string(mark) == c.Hash
				migrateApproved(v, c, pathsOK)
			} else {
				c, probs = config.ParseApproved(b, env)
			}
		}
		if !probs.HasErrors() {
			if c.HasPathMatchers() && !pathsOK {
				// Approved while path: matched nothing, unless this
				// build recorded approving exactly this config: held
				// until the owner approves the file again.
				c.DropPathMatchers()
				s.held = true
			}
			s.active = c
		}
	}
	s.applyMu.Lock()
	s.notify(s.active)
	s.applyMu.Unlock()
	return s, nil
}

// migrateApproved stores c, the approved config rewritten in today's
// forms (config.Migrate: the same meaning, so no prompt), in place of the
// old-form item it was read from. Its input is the vault
// item, never config.yaml, so nothing becomes approved that was not. The
// path: record follows only when it named the old item (pathsOK), and is
// written first: a start that stops in between finds the record naming
// the rewrite of the item still there, which Open accepts. A vault that
// refuses the writes leaves both as they were: c is in force from memory,
// and the next start tries again.
func migrateApproved(v platform.Vault, c *config.Config, pathsOK bool) {
	if pathsOK && c.HasPathMatchers() {
		if err := v.Put(PathsApprovedVaultItem, []byte(c.Hash)); err != nil {
			return
		}
	}
	_ = v.Put(ApprovedVaultItem, c.Raw)
}

// contentHash is the hex SHA-256 of b, as config.Parse sets Config.Hash.
func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// OpenOrDefault is OpenWithTrust for Nazar.app's start (since Milestone
// 5): an approved config the vault can't read (an item of another build
// of Nazar.app, a locked keychain) is treated
// like no approved config at all. The built-in default, which blocks every
// key, is active, so config.yaml is staged against it and takes effect only
// through the login gate, showing every rule as new: never fail open.
// Unreadable says why until a config is saved as approved again (which
// needs the item to be writable: the user deletes the unreadable one).
func OpenOrDefault(env config.Env, v platform.Vault, pins PinStore, apps AppResolver, onApply func(*config.Config)) *Stager {
	s, err := OpenWithTrust(env, v, pins, apps, onApply)
	if err == nil {
		return s
	}
	s = &Stager{env: env, vault: v, onApply: onApply, pins: pins, apps: apps, active: config.Default(env),
		unreadable: err.Error()}
	s.applyMu.Lock()
	s.notify(s.active)
	s.applyMu.Unlock()
	return s
}

// Unreadable reports why the approved config could not be read at Open,
// or "" (it was read, there was none, or one was saved since).
func (s *Stager) Unreadable() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unreadable
}

// Active returns the config in force.
func (s *Stager) Active() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Pending returns the staged change, if any.
func (s *Stager) Pending() (Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		return Pending{}, false
	}
	return *s.pending, true
}

// LastProblems returns the problems of the last file observed, or nil when
// it was valid without warnings.
func (s *Stager) LastProblems() config.Problems {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// Observe handles new file contents; nil data means the file doesn't exist,
// which is the built-in default config. A valid file that only tightens (or
// changes nothing that matters) becomes active at once; one that loosens is
// staged until Approve says yes; an invalid file leaves the active config
// alone and clears any staged change, since the file no longer says that.
//
// A tightening is in force whether or not the vault takes it: it is active
// before the save is tried, and a save failure comes back as a warning
// Problem (Applied stays true, LastProblems carries it). Withholding the
// stricter config until the Keychain is reachable would keep the looser one
// active, which is the one failure mode this package exists to prevent.
// Nothing is lost either way: after a restart Open loads the older approved
// config and the file, still stricter than it, applies again at once.
func (s *Stager) Observe(data []byte) Result {
	var nw *config.Config
	var probs config.Problems
	if data == nil {
		nw = config.Default(s.env)
	} else {
		nw, probs = config.Parse(data, s.env)
	}

	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	s.mu.Lock()
	s.lastErr = probs
	if probs.HasErrors() {
		s.pending = nil
		s.mu.Unlock()
		return Result{Invalid: true, Problems: probs}
	}
	active := s.active
	if bytes.Equal(nw.Raw, active.Raw) && !s.held {
		s.pending = nil
		s.mu.Unlock()
		return Result{Problems: probs}
	}
	if s.pending != nil && bytes.Equal(nw.Raw, s.pending.Config.Raw) {
		p := *s.pending
		s.mu.Unlock()
		return Result{Staged: true, Diff: p.Diff, Problems: probs}
	}
	s.mu.Unlock()

	d := Classify(active, nw)
	stagePins(s.pins, s.apps, active, nw, &d)
	if d.Loosens() {
		s.mu.Lock()
		s.pending = &Pending{Config: nw, Diff: d, Problems: probs}
		s.mu.Unlock()
		return Result{Staged: true, Diff: d, Problems: probs}
	}
	s.activate(nw)
	if err := s.persist(nw); err != nil {
		probs = append(probs, config.Problem{Severity: config.SevWarning, Message: "could not save the approved config: " +
			err.Error() + " (it is in force now and will be re-applied from the file after a restart)"})
		s.mu.Lock()
		s.lastErr = probs
		s.mu.Unlock()
	}
	return Result{Applied: true, Diff: d, Problems: probs}
}

// Approve runs approve for the pending change whose content hash is hash
// ("" = whatever is pending) and applies it if approved, recording the
// app: team pins its diff showed (Pending.Diff.Pins) exactly as shown: a
// bundle swapped while the prompt was open is not what the user approved.
// Only one prompt runs at a time. The change applied is exactly the one the approver was
// shown: if the file changed meanwhile (a different change staged, a
// tightening applied, the change reverted or the file broken) the approval
// is stale and nothing is applied. A denied or failed approval leaves the
// change staged so `nazar config apply` can ask again.
func (s *Stager) Approve(hash string, approve Approver) (bool, error) {
	s.mu.Lock()
	if s.pending == nil {
		s.mu.Unlock()
		return false, ErrNothingStaged
	}
	if hash != "" && s.pending.Config.Hash != hash {
		s.mu.Unlock()
		return false, ErrStale
	}
	if s.approving {
		s.mu.Unlock()
		return false, ErrBusy
	}
	s.approving = true
	p := *s.pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.approving = false
		s.mu.Unlock()
	}()

	ok, err := approve(p)
	if err != nil || !ok {
		return false, err
	}

	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	stale := s.pending == nil || s.pending.Config.Hash != p.Config.Hash
	s.mu.Unlock()
	if stale {
		return false, ErrStale
	}
	// The pins shown are recorded first: a config whose app: matchers can't
	// be pinned must not take effect with them silently inactive, and a pin
	// without its config is harmless (the user approved that team, behind
	// the gate). Pins already written stay if the config then fails to
	// save; the change stays staged and the retry shows the same pins.
	if err := recordPins(s.pins, p.Diff.Pins); err != nil {
		return false, err
	}
	if err := s.apply(p.Config); err != nil {
		return false, err
	}
	return true, nil
}

// Preview classifies data against the active config exactly as Observe
// would, with the app: pins an approval of it records (Diff.Pins), and
// stages nothing: what `nazar ssh-key create` shows on its login gate
// before it writes the file. ApplyAuthenticated then takes the result.
func (s *Stager) Preview(data []byte) (Pending, error) {
	nw, probs := config.Parse(data, s.env)
	if probs.HasErrors() {
		return Pending{}, errors.New(probs.Error())
	}
	active := s.Active()
	d := Classify(active, nw)
	stagePins(s.pins, s.apps, active, nw, &d)
	return Pending{Config: nw, Diff: d, Problems: probs}, nil
}

// ApplyAuthenticated makes p.Config active without classification, after
// recording the pins p.Diff shows, exactly as shown (first writer wins, as
// Approve). The caller must already have passed the login gate for exactly
// this change (used by `nazar ssh-key create`, which previews the file it
// will write, shows the diff and writes it after the gate).
func (s *Stager) ApplyAuthenticated(p Pending) error {
	if p.Config == nil {
		return errors.New("configstage: nothing to apply")
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if err := recordPins(s.pins, p.Diff.Pins); err != nil {
		return err
	}
	if err := s.apply(p.Config); err != nil {
		return err
	}
	s.mu.Lock()
	s.lastErr = p.Problems
	s.mu.Unlock()
	return nil
}

// apply saves c as the approved config, then makes it active, drops any
// pending change and announces it. Nothing changes if the vault refuses the
// save: this is the path for approved loosenings and authenticated edits,
// where a config that can't be recorded as approved must not take effect.
// Called with applyMu held.
func (s *Stager) apply(c *config.Config) error {
	if err := s.persist(c); err != nil {
		return err
	}
	s.activate(c)
	return nil
}

// persist records c as the approved config in the vault. Called with
// applyMu held.
func (s *Stager) persist(c *config.Config) error {
	if len(c.Raw) == 0 {
		// The built-in default: no item, so a later Open starts from it too.
		if err := s.vault.Delete(ApprovedVaultItem); err != nil && !errors.Is(err, platform.ErrNotFound) {
			return err
		}
	} else if err := s.vault.Put(ApprovedVaultItem, c.Raw); err != nil {
		return err
	} else if c.HasPathMatchers() {
		// After the config: a record without its config names nothing
		// approved, and a config without its record is held (Open).
		if err := s.vault.Put(PathsApprovedVaultItem, []byte(c.Hash)); err != nil {
			return fmt.Errorf("could not record that its path: matchers were approved (vault item %s): %w", PathsApprovedVaultItem, err)
		}
	}
	s.mu.Lock()
	s.unreadable = "" // the item holds an approved config this build wrote
	s.mu.Unlock()
	return nil
}

// activate makes c active, drops any pending change and announces it.
// Called with applyMu held.
func (s *Stager) activate(c *config.Config) {
	s.mu.Lock()
	s.active = c
	s.pending = nil
	s.held = false
	s.mu.Unlock()
	s.notify(c)
}

func (s *Stager) notify(c *config.Config) {
	if s.onApply != nil {
		s.onApply(c)
	}
}
