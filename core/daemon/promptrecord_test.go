package daemon

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The vault record of an open prompt survives the end of the
// prompt before it.
//
// The throttle's memory state and its vault record must change in the same
// order. When prompt A ends approved and applied, its record is deleted; a
// same-user process hammering the control socket (or the config file) gets
// its claim B in the moment A's memory state says "not open", and B writes
// its own record (cooldown, and for a config prompt the suppression). If
// A's Delete reaches the vault after B's Put (Keychain writes are XPC calls
// of unknown latency), B is on screen with no record: kill Nazar.app and
// let launchd relaunch it, and the new process has no cooldown and no
// suppression, the exact state the record exists to prevent. The fix
// writes each record under the throttle's lock, in the step that changes
// the memory state.

// gatedDeleteVault is a platform.Vault whose first Delete of the prompts
// item blocks until the test lets it through: Keychain latency, stretched
// to a window the test controls. started is closed when that Delete
// begins; proceed is closed by the test to let it finish.
type gatedDeleteVault struct {
	platform.Vault
	started chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func newGatedDeleteVault(inner platform.Vault) *gatedDeleteVault {
	return &gatedDeleteVault{Vault: inner, started: make(chan struct{}), proceed: make(chan struct{})}
}

func (v *gatedDeleteVault) Delete(name string) error {
	if name == PromptsVaultItem {
		gated := false
		v.once.Do(func() { gated = true })
		if gated {
			close(v.started)
			<-v.proceed
		}
	}
	return v.Vault.Delete(name)
}

// promptRecordIn reads the throttle's vault record, failing when it is
// missing or unreadable.
func (e *env) promptRecordIn(t *testing.T, what string) promptRecord {
	t.Helper()
	b, err := e.vault.Get(PromptsVaultItem)
	if err != nil {
		t.Fatalf("vault record %s: %v", what, err)
	}
	var r promptRecord
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("vault record %s: %v %q", what, err, b)
	}
	return r
}

// Prompt A (an approved, applied `trust --app`, or an approved, applied
// background config prompt) ends while its vault Delete is still in
// flight; prompt B (another `trust --app`, or the automatic prompt for the next
// staged loosening) is claimed in that window. Whatever order the vault
// sees the two writes in, B's record must be the one that remains, and a
// kill-and-relaunch with B on screen must inherit its cooldown (and, for a
// config B, its suppression).
func TestOpenPromptRecordSurvivesLateDeleteOfPreviousPrompt(t *testing.T) {
	for _, via := range []string{"trust", "config"} {
		t.Run(via, func(t *testing.T) {
			var gate *gatedDeleteVault
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.GateTimeout = func() time.Duration { return 30 * time.Second }
				gate = newGatedDeleteVault(o.Vault)
				o.Vault = gate
			})
			trust := func(id string) *control.Problem {
				_, p := e.trustApp(t, id)
				return p
			}
			loose := strings.Replace(rules, "scope: session\n          gate: dialog", "gate: none", 1)

			// Prompt A, approved and applied; its Delete of the record stalls.
			releaseA := e.holdLogin(t, true)
			doneA := make(chan *control.Problem, 1)
			if via == "trust" {
				id := e.probeApp(t)
				go func() { doneA <- trust(id) }()
			} else {
				e.writeConfig(t, rules)
			}
			waitFor(t, func() bool { return e.logins() == 1 })
			if r := e.promptRecordIn(t, "while prompt A is open"); !r.Until.After(e.f.Now()) {
				t.Fatalf("setup: prompt A's record must cool down: %+v", r)
			}
			releaseA()
			select {
			case <-gate.started:
			case <-time.After(3 * time.Second):
				t.Fatal("setup: the approved prompt A must delete its record")
			}

			// Prompt B, claimed in that window: a second trust, or the
			// automatic prompt for the next loosening (A's applied config
			// reset the contents seen).
			e.holdLogin(t, true)
			doneB := make(chan *control.Problem, 1)
			if via == "trust" {
				id := e.probeApp(t)
				go func() { doneB <- trust(id) }()
			} else {
				e.writeConfig(t, loose)
			}
			settle() // B's claim either landed (the race) or waits on the lock (the fix)
			close(gate.proceed)
			waitFor(t, func() bool { return e.logins() == 2 })
			if via == "trust" {
				select {
				case p := <-doneA:
					if p != nil {
						t.Fatalf("the approved trust must complete: %+v", p)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("the approved trust must complete")
				}
			} else {
				waitFor(t, func() bool { return len(e.configAudit(t, audit.Approved)) == 1 })
				if _, ok := e.d.stager.Pending(); !ok {
					t.Fatal("setup: the second loosening must be staged, with prompt B open")
				}
			}

			// B is on screen: the vault must say so.
			r := e.promptRecordIn(t, "while prompt B is open")
			if !r.Until.After(e.f.Now()) {
				t.Fatalf("the record of the open prompt B must cool down: %+v", r)
			}
			if via == "config" && !r.Suppressed {
				t.Fatalf("the record of the open config prompt B must suppress the automatic prompts: %+v", r)
			}

			// Kill-and-relaunch with B open: B is never answered (its process
			// is gone), so the new process must refuse every login prompt for
			// the cooldown left: one full cooldown, since B's record reaches
			// its timeout plus a cooldown ahead and a relaunch inherits at
			// most one cooldown from now.
			e.f.Advance(time.Second)
			e.relaunch(t)
			if via == "trust" {
				if p := trust(e.probeApp(t)); p == nil || p.ExitCode() != control.ExitRefused || !fullCooldown.MatchString(p.Message) {
					t.Fatalf("trust right after a relaunch during prompt B: want exit %d with one cooldown left (60 s), got %+v", control.ExitRefused, p)
				}
				e.stage(t, rules, false)
				settle()
				if got := e.logins(); got != 2 {
					t.Fatalf("a relaunch during prompt B must inherit its cooldown, no prompt may open: %d", got)
				}
				return
			}
			e.stage(t, loose, false) // already on disk; waits for the new process to stage it
			settle()
			if got := e.logins(); got != 2 {
				t.Fatalf("a relaunch during config prompt B must inherit its suppression, no automatic prompt may open: %d", got)
			}
			if got := len(e.contentBlocked(t)); got < 1 {
				t.Fatal("the relaunched process must report the staged change blocked")
			}
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !fullCooldown.MatchString(p.Message) {
				t.Fatalf("config apply right after the relaunch: want exit %d with one cooldown left (60 s), got %+v", control.ExitStaged, p)
			}
			// Past the cooldown the suppression still holds: the next content
			// is reported blocked, not asked about.
			e.f.Advance(configApplyCooldown)
			blocked := len(e.contentBlocked(t))
			e.stage(t, rev(loose, 1), false)
			settle()
			if got := e.logins(); got != 2 {
				t.Fatalf("after the cooldown, the relaunch during config prompt B must still suppress automatic prompts: %d", got)
			}
			if got := len(e.contentBlocked(t)); got != blocked+1 {
				t.Fatalf("the content staged after the cooldown must get one blocked line: %d (was %d)", got, blocked)
			}
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitRefused || e.logins() != 3 {
				t.Fatalf("only config apply asks, once (the fake denies): %+v, %d prompts", p, e.logins())
			}
		})
	}
}
