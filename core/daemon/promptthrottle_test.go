package daemon

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The throttle's edges.
//
//   - A claim whose prompt is never shown (the staged change moved on
//     before the approval ran) is released: the prompt counts as not open
//     again, with no cooldown and no suppression. Left open, every later
//     login prompt would be refused as "already open" for the rest of the
//     process (a denial of service any same-user process can arrange by
//     rewriting the file at the right moment).
//   - The record written when a prompt opens covers the prompt's whole
//     timeout plus the cooldown, so a process killed late in a long prompt
//     still relaunches into a cooldown; and what a relaunch inherits is
//     capped at one cooldown from now, so a record from the future (a wall
//     clock that jumped) cannot lock the prompts out for hours.
//   - The block warning names the actual cause: a suppression, another
//     prompt open, or the cooldown.

// fullCooldown is the remaining cooldown as a refusal spells it right after
// the cooldown was set or inherited (60 s).
var fullCooldown = regexp.MustCompile(`\b60 seconds\b`)

// isOpen reports whether the throttle thinks a login prompt is on screen.
func (e *env) isOpen() bool {
	e.d.prompts.mu.Lock()
	defer e.d.prompts.mu.Unlock()
	return e.d.prompts.open
}

// seenHash reports whether the throttle remembers hash as prompted for or
// reported blocked.
func (e *env) seenHash(hash string) bool {
	e.d.prompts.mu.Lock()
	defer e.d.prompts.mu.Unlock()
	_, ok := e.d.prompts.seen[hash]
	return ok
}

// pendingHash is the hash of the staged change.
func (e *env) pendingHash(t *testing.T) string {
	t.Helper()
	p, ok := e.d.stager.Pending()
	if !ok {
		t.Fatal("nothing is staged")
	}
	return p.Config.Hash
}

// suppressedPastCooldown leaves the daemon with the automatic prompts
// suppressed (one denied background prompt) and the cooldown over, so a
// claim succeeds and a newly staged content is reported blocked, not
// prompted for.
func (e *env) suppressedPastCooldown(t *testing.T) {
	t.Helper()
	e.denyFirst(t)
	e.f.Advance(configApplyCooldown + time.Second)
}

// A claim whose prompt is never shown is released. The approval for a
// content runs after the staged change moved on: the content was
// rewritten in the file before approveStaged got to the stager, or the
// hash it was claimed for is stale outright. Either way the stager refuses
// with ErrStale before any prompt, and the claim must be ended: the prompt
// is not open, there is no cooldown, and the next `config apply` opens its
// prompt and applies the current content.
func TestStaleApprovalReleasesTheClaim(t *testing.T) {
	for _, via := range []string{"stale hash", "rewritten"} {
		t.Run(via, func(t *testing.T) {
			e := startWith(t, withClock)
			e.suppressedPastCooldown(t)
			before := e.logins()

			e.stage(t, rev(rules, 1), false)
			waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
			first := e.pendingHash(t)
			cl, err := e.d.prompts.claim(e.d.o.Now, true)
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			if !e.isOpen() {
				t.Fatal("setup: the claim must mark the prompt open")
			}

			hash, auto := "0000000000000000000000000000000000000000000000000000000000000000", false
			if via == "rewritten" {
				// The file changes before the approval runs: the staged change
				// is the new content, the claim was for the old one.
				e.stage(t, rev(rules, 2), false)
				waitFor(t, func() bool { return len(e.contentBlocked(t)) == 2 })
				hash, auto = first, true
			}
			applied, err := e.d.approveStaged(cl, hash, nil, auto)
			if applied || !errors.Is(err, configstage.ErrStale) {
				t.Fatalf("approveStaged for a stale hash: want (false, ErrStale), got (%v, %v)", applied, err)
			}
			if got := e.logins(); got != before {
				t.Fatalf("no prompt may be shown for a stale hash: %d (was %d)", got, before)
			}
			if e.isOpen() {
				t.Fatal("a claim whose prompt was never shown must be released: the prompt still counts as open")
			}
			if auto && e.seenHash(first) {
				t.Fatal("a content that got no prompt after all must be forgotten, so a later staging of it is asked about once")
			}

			// The next login prompt opens: no cooldown, nothing open. config
			// apply asks exactly once and applies the current content.
			e.f.ScriptAuth(fake.Answer{Allow: true})
			diff, p := e.apply(t)
			if p != nil {
				t.Fatalf("config apply after a released claim must prompt and apply, got %+v", p)
			}
			if got := e.logins(); got != before+1 {
				t.Fatalf("config apply after a released claim shows exactly one prompt: %d (was %d)", got, before)
			}
			if diff.Hash != e.d.stager.Active().Hash || e.stillStaged() {
				t.Fatalf("the current content must be active now: diff %s, active %s", diff.Hash, e.d.stager.Active().Hash)
			}
		})
	}
}

// stillStaged reports whether a change is still staged.
func (e *env) stillStaged() bool { _, ok := e.d.stager.Pending(); return ok }

// The same on the throttle alone, without a daemon: release ends the claim
// in memory and in the vault, and a second claim right after succeeds.
func TestReleaseEndsTheClaim(t *testing.T) {
	v := fake.NewVault()
	now := time.Now()
	c := &loginPrompts{vault: v, logf: t.Logf}
	cl, err := c.claim(func() time.Time { return now }, false)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, err := c.claim(func() time.Time { return now }, false); !errors.Is(err, errPromptOpen) {
		t.Fatalf("a second claim while the first is held: want errPromptOpen, got %v", err)
	}
	cl.release()
	if c.open {
		t.Fatal("release must mark the prompt not open")
	}
	if _, err := v.Get(PromptsVaultItem); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("release of a claim with nothing to keep must remove the vault record, got %v", err)
	}
	cl2, err := c.claim(func() time.Time { return now }, true)
	if err != nil {
		t.Fatalf("a claim after a release must succeed: %v", err)
	}
	cl2.release()
	if c.open || c.suppressed || !c.until.IsZero() {
		t.Fatalf("release leaves the memory state alone: open=%v suppressed=%v until=%v", c.open, c.suppressed, c.until)
	}
}

// The record a relaunch inherits is capped at one cooldown from now. A
// record whose Until lies hours ahead (the wall clock jumped backwards
// since it was written, or a process on a broken clock wrote it) refuses
// `config apply` for 60 s, not for hours.
func TestInheritedCooldownIsCappedAtOneCooldown(t *testing.T) {
	for _, suppressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "cooldown only", true: "suppressed"}[suppressed], func(t *testing.T) {
			e := startWith(t, withClock)
			b, _ := json.Marshal(promptRecord{Suppressed: suppressed, Until: e.f.Now().Add(24 * time.Hour)})
			if err := e.vault.Put(PromptsVaultItem, b); err != nil {
				t.Fatal(err)
			}
			e.relaunch(t)
			e.stage(t, rules, false)
			waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
			if got := e.logins(); got != 0 {
				t.Fatalf("a record from the future still cools down: %d prompts", got)
			}
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !fullCooldown.MatchString(p.Message) {
				t.Fatalf("config apply on a record from the future: want exit %d with one cooldown left (60 s), got %+v", control.ExitStaged, p)
			}

			e.f.Advance(configApplyCooldown)
			e.f.ScriptAuth(fake.Answer{Allow: true})
			if _, p := e.apply(t); p != nil {
				t.Fatalf("config apply one cooldown after a relaunch on a record from the future must prompt and apply, got %+v", p)
			}
			if got := e.logins(); got != 1 {
				t.Fatalf("exactly one prompt: %d", got)
			}
		})
	}
}

// A process killed late in a long prompt still relaunches into a cooldown.
// With a 5-minute gate timeout the record of the opening prompt reaches
// 5 min + 60 s ahead; killed 3 minutes in (past a bare cooldown), the
// relaunched process refuses `config apply` and `trust` for one cooldown,
// then asks. Without it, kill-at-61-s-and-relaunch would be a fresh prompt
// per minute, whatever the timeout.
func TestRelaunchLateInALongPromptInheritsACooldown(t *testing.T) {
	const gate = 5 * time.Minute
	for _, via := range []string{"background config prompt", "trust"} {
		t.Run(via, func(t *testing.T) {
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.GateTimeout = func() time.Duration { return gate }
			})
			hold := make(chan struct{})
			t.Cleanup(func() { close(hold) })
			trust := func() *control.Problem { return e.probeLogin(t) }
			e.f.ScriptAuth(fake.Answer{Wait: hold})
			var held <-chan *control.Problem
			if via == "trust" {
				held = e.callInBackground(t, control.CmdTrustApp, map[string]string{"app": e.probeApp(t)}, control.KindAppPin, &control.AppPin{})
			} else {
				e.stage(t, rules, false)
			}
			waitFor(t, func() bool { return e.logins() == 1 })
			opened := e.f.Now()
			r := e.promptRecordIn(t, "while the prompt is open")
			if want := opened.Add(gate + configApplyCooldown); !r.Until.Equal(want) {
				t.Fatalf("the record of an open prompt must cool down until the prompt's timeout plus one cooldown (%v), got %v", want, r.Until)
			}
			if r.Suppressed != (via != "trust") {
				t.Fatalf("suppressed=%v for a %s prompt", r.Suppressed, via)
			}

			e.f.Advance(3 * time.Minute) // past a bare cooldown, within the timeout
			e.relaunch(t)                // the prompt in the old process is never answered
			if held != nil {
				select {
				case <-held:
				case <-time.After(3 * time.Second):
					t.Fatal("the old process's trust call must have ended with its daemon")
				}
			}
			if via != "trust" {
				e.stage(t, rules, false) // already on disk; waits for the new process to stage it
			}
			settle()
			if got := e.logins(); got != 1 {
				t.Fatalf("a relaunch during an open prompt must not open another: %d", got)
			}
			if p := trust(); p == nil || p.ExitCode() != control.ExitRefused || !fullCooldown.MatchString(p.Message) {
				t.Fatalf("trust after a relaunch 3 minutes into a 5-minute prompt: want exit %d with one cooldown left (60 s), got %+v", control.ExitRefused, p)
			}
			if via != "trust" {
				if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !fullCooldown.MatchString(p.Message) {
					t.Fatalf("config apply after that relaunch: want exit %d with one cooldown left (60 s), got %+v", control.ExitStaged, p)
				}
			}
			if got := e.logins(); got != 1 {
				t.Fatalf("those refusals must not prompt: %d", got)
			}

			// One cooldown later the commands ask again, exactly once.
			e.f.Advance(configApplyCooldown)
			e.f.ScriptAuth(fake.Answer{Allow: true})
			if p := trust(); p != nil {
				t.Fatalf("trust one cooldown after the relaunch: %+v", p)
			}
			if got := e.logins(); got != 2 {
				t.Fatalf("exactly one prompt after the cooldown: %d", got)
			}
		})
	}
}

// lastStagedWarning is the latest block warning for a staged config
// change.
func (e *env) lastStagedWarning(t *testing.T) platform.Warning {
	t.Helper()
	var last *platform.Warning
	for _, w := range e.f.Warnings() {
		if w.ID == "config|staged" {
			w := w
			last = &w
		}
	}
	if last == nil {
		t.Fatal("no block warning was shown")
	}
	return *last
}

// The block warning names the cause this content got no prompt: after a
// denial the automatic prompts are off until `config apply`; while another
// prompt is open, or during the cooldown after a loosen command's prompt
// ended without an approval, it names that instead (with the seconds left),
// and says this content is not asked about on its own later. Each case
// must not claim one of the others.
func TestBlockWarningNamesTheCause(t *testing.T) {
	type cause struct {
		name    string
		setup   func(t *testing.T, e *env) (before int)
		must    []string
		mustNot []string
	}
	cases := []cause{
		{
			name: "denied",
			setup: func(t *testing.T, e *env) int {
				e.denyFirst(t)
				return e.logins()
			},
			must:    []string{"denied, not answered, or approved after the file had changed"},
			mustNot: []string{"another approval prompt is open", "seconds"},
		},
		{
			name: "another prompt open",
			setup: func(t *testing.T, e *env) int {
				e.holdLogin(t, false)
				e.stage(t, rules, false)
				waitFor(t, func() bool { return e.logins() == 1 })
				return e.logins()
			},
			must:    []string{"another approval prompt is open", "not ask about this change on its own later"},
			mustNot: []string{"denied", "seconds"},
		},
		{
			name: "cooldown",
			setup: func(t *testing.T, e *env) int {
				// A denied `trust --app` cools every login prompt down without
				// suppressing the automatic config prompt.
				if p := e.probeLogin(t); p == nil || p.ExitCode() != control.ExitRefused {
					t.Fatalf("denied trust: %+v", p)
				}
				return e.logins()
			},
			must:    []string{"60 seconds after a prompt was denied, not answered, or approved after the file had changed", "not ask about this change on its own later"},
			mustNot: []string{"another approval prompt is open", "does not ask again on its own after"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := startWith(t, withClock)
			before := c.setup(t, e)
			blocked := len(e.contentBlocked(t))
			e.stage(t, rev(rules, 7), false)
			waitFor(t, func() bool { return len(e.contentBlocked(t)) == blocked+1 })
			settle()
			if got := e.logins(); got != before {
				t.Fatalf("the blocked content must not prompt: %d (was %d)", got, before)
			}
			w := e.lastStagedWarning(t)
			text := strings.Join(w.Lines, "\n")
			for _, s := range c.must {
				if !strings.Contains(text, s) {
					t.Errorf("the warning must say %q, got:\n%s", s, text)
				}
			}
			for _, s := range c.mustNot {
				if strings.Contains(text, s) {
					t.Errorf("the warning must not say %q, got:\n%s", s, text)
				}
			}
			if !strings.Contains(text, "nazar config apply") {
				t.Errorf("the warning must name `nazar config apply`, got:\n%s", text)
			}
		})
	}
}
