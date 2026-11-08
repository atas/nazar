package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Config-approval prompts can't be flooded (spec 4.8, 6, 8).
//
// The config file is an ordinary file of the user, so a same-user process
// can rewrite it as often as it likes. Each rewrite that loosens (a changed
// comment is enough to make new content) must not put a fresh login prompt
// on screen: that is a denial of service and trains the user to approve by
// reflex. So:
//   - the daemon prompts on its own at most once per staged content, and
//     never while another config prompt is open;
//   - once a background config prompt ends denied, timed out or failed,
//     no further automatic prompt is shown until the user runs `nazar
//     config apply`; each newly staged content gets one audit line
//     target=config decision=blocked and at most one block warning;
//   - `nazar config apply` (control config.apply) has a cooldown after a
//     denial or timeout, so the control socket can't drive a prompt loop
//     either; it is refused with the remaining time and exit 4 (the change
//     stays staged, waiting for approval);
//   - tightenings still apply at once, with no prompt.

// configApplyCooldown is the cooldown the task names (60 s after a denial
// or timeout).
const configApplyCooldown = 60 * time.Second

// blockedReason is the audit reason of a suppressed automatic prompt.
const blockedReason = "config change staged; run nazar config apply"

// withClock runs the daemon on the fake's clock, so the cooldown can be
// crossed without sleeping.
func withClock(f *fake.Fake, o *Options) { o.Now = f.Now }

// rev is rules (a loosening against the built-in default) with a comment
// that makes its content, and so its hash, distinct: the cheapest rewrite
// an attacker can make.
func rev(base string, i int) string {
	return base + fmt.Sprintf("# rewrite %d\n", i)
}

// stage writes body and waits until the daemon has staged exactly it. With
// viaCheck the observation is forced through `config check` (which re-reads
// the file) instead of the poller: both paths must behave the same.
func (e *env) stage(t *testing.T, body string, viaCheck bool) {
	t.Helper()
	e.writeConfig(t, body)
	if viaCheck {
		e.check(t)
	}
	waitFor(t, func() bool {
		p, ok := e.d.stager.Pending()
		return ok && bytes.Equal(p.Config.Raw, []byte(body))
	})
}

// configAudit returns the audit lines for target=config with decision dec.
func (e *env) configAudit(t *testing.T, dec audit.Decision) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.auditFor(t, "config") {
		if l["target"] == "config" && l["decision"] == string(dec) {
			out = append(out, l)
		}
	}
	return out
}

// contentBlocked returns the per-content blocked lines: one for each staged
// content that got no prompt (reason blockedReason, no caller).
func (e *env) contentBlocked(t *testing.T) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.configAudit(t, audit.Blocked) {
		if l["reason"] == blockedReason {
			out = append(out, l)
		}
	}
	return out
}

// applyRefused returns the per-call blocked lines of `config apply`
// refusals under the throttle, each of which must name the caller: the
// audit log is how the user finds the process driving the prompts.
func (e *env) applyRefused(t *testing.T) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.configAudit(t, audit.Blocked) {
		if strings.HasPrefix(l["reason"], "config apply: not asked: ") {
			if l["chain"] == "" && l["session"] == "" {
				t.Fatalf("a refused config apply must be audited with its caller: %v", l)
			}
			out = append(out, l)
		}
	}
	return out
}

// settle gives a wrongly started background prompt time to show.
func settle() { time.Sleep(250 * time.Millisecond) }

func (e *env) logins() int { return e.f.CountShown(fake.KindAuthenticate) }

func (e *env) apply(t *testing.T) (control.ConfigDiff, *control.Problem) {
	t.Helper()
	var diff control.ConfigDiff
	err := e.call(t, control.CmdConfigApply, nil, control.KindConfigDiff, &diff)
	return diff, control.AsProblem(err)
}

// denyFirst stages rules, lets the background prompt be denied (the fake's
// default) and waits for its audit line.
func (e *env) denyFirst(t *testing.T) {
	t.Helper()
	e.stage(t, rules, false)
	waitFor(t, func() bool { return e.logins() == 1 })
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Denied)) == 1 })
}

// N distinct loosening rewrites after one denial show no further prompt,
// whether the poller or `config check` observes them; each new content gets
// exactly one blocked audit line with the fixed reason; the block warning
// is shown at most once per content, also when old contents come back.
func TestConfigRewritesAfterDenialDoNotPromptAgain(t *testing.T) {
	e := startWith(t, withClock)
	e.denyFirst(t)

	const n = 6
	for i := 1; i <= n; i++ {
		e.stage(t, rev(rules, i), i%2 == 0)
	}
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("after one denial, %d distinct loosening rewrites must show no new prompt: %d login prompts shown", n, got)
	}
	if e.f.CountShown(fake.KindConfirm) != 0 {
		t.Fatal("a config change must never use the dialog gate")
	}
	if len(e.d.stager.Active().SSHAgent.Keys) != 0 {
		t.Fatal("a suppressed change must stay staged, not active")
	}
	if _, ok := e.d.stager.Pending(); !ok {
		t.Fatal("the last rewrite must stay staged for `nazar config apply`")
	}

	waitFor(t, func() bool { return len(e.contentBlocked(t)) >= n })
	blocked := e.contentBlocked(t)
	if len(blocked) != n {
		t.Fatalf("want exactly one blocked audit line per newly staged content (%d), got %d:\n%s", n, len(blocked), strings.Join(e.sink.Lines(), "\n"))
	}
	for _, l := range blocked {
		if l["reason"] != blockedReason {
			t.Fatalf("blocked line reason %q, want %q", l["reason"], blockedReason)
		}
	}

	warns := e.f.Warnings()
	if len(warns) == 0 || len(warns) > n {
		t.Fatalf("the block warning must be shown, at most once per staged content: %d warnings for %d contents", len(warns), n)
	}
	mentions := false
	for _, w := range warns {
		if strings.Contains(w.Title+"\n"+strings.Join(w.Lines, "\n"), "config apply") {
			mentions = true
		}
	}
	if !mentions {
		t.Fatalf("the block warning must tell the user to run `nazar config apply`: %+v", warns)
	}

	// Old contents coming back (an attacker alternating two files) neither
	// prompt nor show more warnings than there are distinct contents.
	for i := 0; i < 6; i++ {
		e.stage(t, rev(rules, 1+i%2), i%2 == 1)
	}
	// The very first (denied) content again: it was prompted once already.
	e.stage(t, rules, true)
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("re-staging contents seen before must not prompt: %d login prompts", got)
	}
	if got := len(e.f.Warnings()); got > n+1 {
		t.Fatalf("at most one block warning per content: %d warnings for %d contents", got, n+1)
	}
}

// A background prompt that times out or fails suppresses later automatic
// prompts exactly like a denial, and starts the `config apply` cooldown.
func TestConfigPromptTimeoutOrErrorSuppressesToo(t *testing.T) {
	for _, tc := range []struct {
		name string
		dec  audit.Decision
		ans  func(t *testing.T) fake.Answer
	}{
		{"timeout", audit.Timeout, func(t *testing.T) fake.Answer {
			never := make(chan struct{})
			t.Cleanup(func() { close(never) })
			return fake.Answer{Wait: never}
		}},
		{"error", audit.Error, func(t *testing.T) fake.Answer {
			return fake.Answer{Err: errors.New("LAContext: unexpected failure")}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.GateTimeout = func() time.Duration { return 300 * time.Millisecond }
			})
			e.f.ScriptAuth(tc.ans(t))
			e.stage(t, rules, false)
			waitFor(t, func() bool { return len(e.configAudit(t, tc.dec)) == 1 })
			for i := 1; i <= 4; i++ {
				e.stage(t, rev(rules, i), i%2 == 0)
			}
			settle()
			if got := e.logins(); got != 1 {
				t.Fatalf("after a %s, rewrites must not prompt again: %d login prompts", tc.name, got)
			}
			if got := len(e.contentBlocked(t)); got != 4 {
				t.Fatalf("want 4 blocked audit lines, got %d", got)
			}
			e.f.Advance(time.Second)
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
				t.Fatalf("config apply right after a %s must be refused for the cooldown with exit %d, got %+v", tc.name, control.ExitStaged, p)
			}
			if got := e.logins(); got != 1 {
				t.Fatalf("a refused config apply must not prompt: %d login prompts", got)
			}
		})
	}
}

// While a config prompt is open no second one appears, for new contents or
// for `config apply`; when it ends denied, later rewrites stay silent.
func TestNoSecondConfigPromptWhileOneIsOpen(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		o.GateTimeout = func() time.Duration { return 10 * time.Second }
	})
	hold := make(chan struct{})
	released := false
	release := func() {
		if !released {
			released = true
			close(hold)
		}
	}
	t.Cleanup(release)
	e.f.ScriptAuth(fake.Answer{Wait: hold}) // denies once released

	e.stage(t, rules, false)
	waitFor(t, func() bool { return e.logins() == 1 })
	// A content staged while the prompt is open is reported blocked at
	// once, with the fixed reason: it will not be asked about by itself.
	e.stage(t, rev(rules, 1), false)
	waitFor(t, func() bool { return len(e.contentBlocked(t)) >= 1 })
	if blocked := e.contentBlocked(t); len(blocked) != 1 || blocked[0]["reason"] != blockedReason {
		t.Fatalf("content staged while a prompt is open: want 1 blocked line with reason %q, got %v", blockedReason, blocked)
	}
	e.stage(t, rev(rules, 2), true)
	waitFor(t, func() bool { return len(e.contentBlocked(t)) == 2 })
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("a second config prompt must never open while one is on screen: %d", got)
	}
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("config apply while a prompt is open: want exit %d, got %+v", control.ExitStaged, p)
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("config apply must not open a second prompt: %d", got)
	}
	if _, err := e.vault.Get(PromptsVaultItem); err != nil {
		t.Fatalf("a refused config apply must leave the open prompt's vault record in place: %v", err)
	}
	// Refused for the open prompt: audited with the caller, like the
	// cooldown refusal; no new per-content line (both contents are known).
	if got := e.applyRefused(t); len(got) != 1 || !strings.Contains(got[0]["reason"], "already open") {
		t.Fatalf("config apply refused for an open prompt must add one blocked line naming it, with the caller, got %v", got)
	}
	if got := len(e.contentBlocked(t)); got != 2 {
		t.Fatalf("the refusal must not add a per-content blocked line: %d", got)
	}

	release()
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Denied)) == 1 })
	for i := 3; i <= 5; i++ {
		e.stage(t, rev(rules, i), i%2 == 0)
	}
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("after the open prompt was denied, rewrites must not prompt: %d", got)
	}
}

var secondsLeft = regexp.MustCompile(`\b59\s*(s|sec|secs|second|seconds)\b`)

// `config apply` during the cooldown is refused without a prompt, with the
// remaining time and exit 4, and changes nothing; after the cooldown it
// shows exactly one prompt. A denied `config apply` starts a new cooldown.
// An approved one applies the change and ends the suppression, so the next
// loosening prompts once on its own again.
func TestConfigApplyCooldown(t *testing.T) {
	e := startWith(t, withClock)
	e.denyFirst(t)
	e.stage(t, rev(rules, 1), false)
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("suppressed rewrite prompted: %d", got)
	}

	e.f.Advance(time.Second)
	_, p := e.apply(t)
	if p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("config apply during the cooldown: want exit %d (staged, waiting for approval), got %+v", control.ExitStaged, p)
	}
	if !secondsLeft.MatchString(p.Message) {
		t.Fatalf("the refusal must say how long the cooldown still runs (59s left): %q", p.Message)
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("config apply during the cooldown must not prompt: %d", got)
	}
	if pend, ok := e.d.stager.Pending(); !ok || !bytes.Equal(pend.Config.Raw, []byte(rev(rules, 1))) {
		t.Fatal("a refused config apply must leave the change staged")
	}
	if len(e.d.stager.Active().SSHAgent.Keys) != 0 {
		t.Fatal("a refused config apply must not apply anything")
	}
	// The refusal itself is audited, with the caller (regression: a
	// polling process left no trace while its content was already
	// reported blocked), and it adds no second per-content line.
	if got := e.applyRefused(t); len(got) != 1 || !secondsLeft.MatchString(got[0]["reason"]) {
		t.Fatalf("a refused config apply must add one blocked line naming the cooldown left, got %v:\n%s", got, strings.Join(e.sink.Lines(), "\n"))
	}
	if got := len(e.contentBlocked(t)); got != 1 {
		t.Fatalf("a refused config apply must not add a per-content blocked line: %d", got)
	}

	// Hammering the control socket during the cooldown changes nothing,
	// and every refused call is audited with the caller's chain.
	for i := 0; i < 5; i++ {
		e.f.Advance(10 * time.Second) // up to 51 s after the denial
		if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
			t.Fatalf("config apply %d s after the denial: want exit %d, got %+v", 1+10*(i+1), control.ExitStaged, p)
		}
		if got := len(e.applyRefused(t)); got != i+2 {
			t.Fatalf("after %d refused config apply calls: want %d blocked lines with the caller, got %d:\n%s", i+2, i+2, got, strings.Join(e.sink.Lines(), "\n"))
		}
	}
	e.f.Advance(7 * time.Second) // 58 s
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("config apply 58 s after the denial: want exit %d, got %+v", control.ExitStaged, p)
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("no prompt may appear during the cooldown: %d", got)
	}
	if got := len(e.applyRefused(t)); got != 7 {
		t.Fatalf("7 refused config apply calls must leave 7 blocked lines with the caller, got %d", got)
	}
	for _, l := range e.applyRefused(t) {
		if !strings.Contains(l["chain"], "ssh") || l["session"] == "" {
			t.Fatalf("the refusal's audit line must carry the caller's chain and session: %v", l)
		}
	}
	if got := len(e.contentBlocked(t)); got != 1 {
		t.Fatalf("refused config apply calls must not add per-content blocked lines: %d", got)
	}

	// After the cooldown: exactly one prompt; denied → exit 3.
	e.f.Advance(configApplyCooldown) // well past it
	e.f.ScriptAuth(fake.Answer{Allow: false})
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitRefused {
		t.Fatalf("config apply after the cooldown, denied: want exit %d, got %+v", control.ExitRefused, p)
	}
	if got := e.logins(); got != 2 {
		t.Fatalf("config apply after the cooldown must show exactly one prompt: %d total", got)
	}
	if !promptMentions(e.f, fake.KindAuthenticate, fake.ITermCode.Team()) {
		t.Fatal("the config apply prompt must show the diff it approves")
	}

	// That denial starts a new cooldown, and automatic prompts stay off.
	e.f.Advance(time.Second)
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("config apply right after a denied config apply: want exit %d, got %+v", control.ExitStaged, p)
	}
	e.stage(t, rev(rules, 2), true)
	settle()
	if got := e.logins(); got != 2 {
		t.Fatalf("after a denied config apply, rewrites must not prompt: %d", got)
	}

	// After the next cooldown an approved config apply applies exactly the
	// staged change.
	e.f.Advance(configApplyCooldown + time.Second)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	diff, p := e.apply(t)
	if p != nil || !diff.Applied {
		t.Fatalf("approved config apply: %+v %+v", diff, p)
	}
	if got := e.logins(); got != 3 {
		t.Fatalf("approved config apply: want exactly one more prompt, %d total", got)
	}
	if !bytes.Equal(e.d.stager.Active().Raw, []byte(rev(rules, 2))) {
		t.Fatal("config apply must apply the staged content")
	}

	// The user ran config apply: automatic prompts are back, once per
	// content (the fake's default denies).
	e.stage(t, strings.Replace(rev(rules, 2), "scope: session\n          gate: dialog", "gate: none", 1), false)
	waitFor(t, func() bool { return e.logins() == 4 })
	settle()
	if got := e.logins(); got != 4 {
		t.Fatalf("after an approved config apply, a new loosening prompts exactly once: %d total", got)
	}
}

// Tightenings are unaffected by the suppression and the cooldown: they
// apply at once without a prompt, and they don't end the suppression.
func TestTighteningAppliesDuringSuppression(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.writeConfig(t, rules) // approved by the background prompt
	waitFor(t, func() bool { return len(e.d.stager.Active().SSHAgent.Keys) == 1 })
	if got := e.logins(); got != 1 {
		t.Fatalf("setup: %d prompts", got)
	}

	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	loose := strings.Replace(rules, "scope: session\n          gate: dialog", "gate: none", 1)
	e.stage(t, loose, false)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Denied)) == 1 })
	if got := e.logins(); got != 2 {
		t.Fatalf("the first loosening prompts once: %d", got)
	}

	tight := strings.Replace(rules, "gate: dialog", "gate: login", 1)
	e.writeConfig(t, tight)
	waitFor(t, func() bool {
		k := e.d.stager.Active().SSHAgent.Keys["github"]
		return k != nil && len(k.Rules) == 1 && k.Rules[0].Policy.Gate == "login"
	})
	if _, ok := e.d.stager.Pending(); ok {
		t.Fatal("a tightening clears the staged loosening")
	}
	settle()
	if got := e.logins(); got != 2 {
		t.Fatalf("a tightening during the suppression must apply without a prompt: %d", got)
	}

	// Still suppressed, and the cooldown still runs.
	e.stage(t, rev(loose, 1), true)
	settle()
	if got := e.logins(); got != 2 {
		t.Fatalf("a tightening must not end the suppression: %d", got)
	}
	if got := len(e.contentBlocked(t)); got != 1 {
		t.Fatalf("want one blocked line for the new loosening, got %d", got)
	}
	e.f.Advance(time.Second)
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("a tightening must not end the config apply cooldown: %+v", p)
	}
	if got := e.logins(); got != 2 {
		t.Fatalf("refused config apply prompted: %d", got)
	}
}

// A content is remembered as prompted for (or reported blocked) only until
// the active config changes. Once a change was approved and applied, or a
// tightening or an authenticated edit replaced the active config, the same
// bytes staged again are a new change against a different base, and spec
// 4.8 says a changed config.yaml is shown and asked about: with nothing
// suppressed and no cooldown running it prompts again; while suppressed it
// is reported blocked again. Forgetting applied contents costs no flood
// protection: new contents are free anyway (a changed comment), so the
// bound comes from the suppression and the cooldown, not from the memory.
func TestReaddedContentPromptsAgainAfterApply(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.writeConfig(t, rules) // approved by the background prompt
	waitFor(t, func() bool { return len(e.d.stager.Active().SSHAgent.Keys) == 1 })
	loose := strings.Replace(rules, "scope: session\n          gate: dialog", "gate: none", 1)
	e.writeConfig(t, loose) // approved too
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Approved)) == 2 })
	if got := e.logins(); got != 2 {
		t.Fatalf("setup: %d prompts", got)
	}

	// Put the stricter rule back (a tightening, applied at once), then the
	// loose one again: the user changing their mind twice.
	e.writeConfig(t, rules)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Allowed)) == 1 })
	e.writeConfig(t, loose)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Approved)) == 3 })
	if got := e.logins(); got != 3 {
		t.Fatalf("the same loosening staged again after an applied config must prompt again: %d prompts", got)
	}
	if _, ok := e.d.stager.Pending(); ok {
		t.Fatal("the approved change must have applied")
	}
	if got := e.d.stager.Active().SSHAgent.Keys["github"].Rules[0].Policy.Gate; got != "none" {
		t.Fatalf("active gate %q, want none", got)
	}

	// The same bytes staged a third time, now while suppressed after a
	// denial: not silently ignored, but reported blocked once more.
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	e.writeConfig(t, rules)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Allowed)) == 2 })
	e.stage(t, loose, false)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Denied)) == 1 })
	if got := e.logins(); got != 4 {
		t.Fatalf("the loosening after the second tightening prompts once: %d", got)
	}
	tight := strings.Replace(rules, "gate: dialog", "gate: login", 1)
	e.writeConfig(t, tight)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Allowed)) == 3 })
	e.stage(t, loose, false)
	waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
	settle()
	if got := e.logins(); got != 4 {
		t.Fatalf("while suppressed, the re-staged loosening must not prompt: %d", got)
	}
	if _, ok := e.d.stager.Pending(); !ok {
		t.Fatal("the blocked change must stay staged for `nazar config apply`")
	}
}

// A relaunch does not reset the suppression. A same-user process can kill
// Nazar.app (same uid) and let launchd or `open -a Nazar` start it again,
// so state that lived only in memory would hand it a fresh prompt per
// relaunch (write X; kill; relaunch; prompt). The suppression and the
// cooldown are kept in the vault: the new process stages the file,
// reports it blocked, shows no prompt, and refuses `config apply` for the
// rest of the cooldown; only an approved `config apply` clears it.
func TestRelaunchAfterDenialStaysSuppressed(t *testing.T) {
	e := startWith(t, withClock)
	e.denyFirst(t)
	e.stage(t, rev(rules, 1), false)
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("setup: suppressed rewrite prompted: %d", got)
	}
	if _, err := e.vault.Get(PromptsVaultItem); err != nil {
		t.Fatalf("the suppression must be in the vault after a denial: %v", err)
	}

	e.f.Advance(time.Second)
	e.relaunch(t)
	e.stage(t, rev(rules, 1), false) // already on disk; waits for the new process to stage it
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("after a relaunch the staged change must not prompt: %d login prompts (was 1 before the relaunch)", got)
	}
	if got := len(e.contentBlocked(t)); got != 2 {
		t.Fatalf("the relaunched process reports the staged change blocked once: want 2 blocked lines in all, got %d", got)
	}
	_, p := e.apply(t)
	if p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("config apply on the relaunched process during the cooldown: want exit %d, got %+v", control.ExitStaged, p)
	}
	if !secondsLeft.MatchString(p.Message) {
		t.Fatalf("the refusal must carry the cooldown left from before the relaunch (59s): %q", p.Message)
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("config apply during the inherited cooldown must not prompt: %d", got)
	}

	// Kill-and-relaunch in a loop: still no prompt, and new contents only
	// cost blocked lines.
	for i := 2; i <= 4; i++ {
		e.relaunch(t)
		e.stage(t, rev(rules, i), i%2 == 0)
	}
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("relaunching with new contents must not prompt: %d", got)
	}
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("config apply after repeated relaunches: want exit %d, got %+v", control.ExitStaged, p)
	}

	// After the cooldown an explicit config apply asks once; its denial
	// starts a new cooldown that the next relaunch inherits too.
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Allow: false})
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitRefused {
		t.Fatalf("config apply after the cooldown: want exit %d, got %+v", control.ExitRefused, p)
	}
	if got := e.logins(); got != 2 {
		t.Fatalf("config apply after the cooldown shows exactly one prompt: %d total", got)
	}
	e.f.Advance(time.Second)
	e.relaunch(t)
	e.stage(t, rev(rules, 4), false)
	settle()
	if got := e.logins(); got != 2 {
		t.Fatalf("after a denied config apply and a relaunch, no automatic prompt: %d", got)
	}
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !secondsLeft.MatchString(p.Message) {
		t.Fatalf("the new cooldown must survive the relaunch: %+v", p)
	}

	// An approved config apply clears the vault record; after the next
	// relaunch a new loosening prompts once on its own again.
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("approved config apply: %+v %+v", diff, p)
	}
	if _, err := e.vault.Get(PromptsVaultItem); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("an approval must remove the suppression from the vault: %v", err)
	}
	e.relaunch(t)
	e.stage(t, strings.Replace(rev(rules, 4), "scope: session\n          gate: dialog", "gate: none", 1), false)
	waitFor(t, func() bool { return e.logins() == 4 })
	settle()
	if got := e.logins(); got != 4 {
		t.Fatalf("after an approval and a relaunch, a new loosening prompts exactly once: %d total", got)
	}
}

// Killing the process while a config prompt is on screen must not be a
// way around the suppression either (write X; kill during the prompt, so
// no denial is ever recorded; relaunch; prompt). The vault record is
// written when the prompt opens, by the background path and by `config
// apply` alike, so the relaunched process treats an unanswered prompt as
// not approved, with the cooldown counted from when it opened.
func TestRelaunchDuringOpenPromptStaysSuppressed(t *testing.T) {
	for _, via := range []string{"background", "config apply"} {
		t.Run(via, func(t *testing.T) {
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.GateTimeout = func() time.Duration { return 30 * time.Second }
			})
			hold := make(chan struct{})
			t.Cleanup(func() { close(hold) })
			var applied chan *control.Problem
			if via == "background" {
				e.f.ScriptAuth(fake.Answer{Wait: hold})
				e.stage(t, rules, false)
				waitFor(t, func() bool { return e.logins() == 1 })
			} else {
				// Suppressed by one denial, past the cooldown: config apply opens
				// the (held) prompt.
				e.denyFirst(t)
				e.f.Advance(configApplyCooldown + time.Second)
				e.f.ScriptAuth(fake.Answer{Wait: hold})
				applied = make(chan *control.Problem, 1)
				go func() {
					_, p := e.apply(t)
					applied <- p
				}()
				waitFor(t, func() bool { return e.logins() == 2 })
			}
			before := e.logins()
			if n := len(e.configAudit(t, audit.Denied)) + len(e.configAudit(t, audit.Timeout)); n != before-1 {
				t.Fatal("setup: the held prompt must still be open")
			}

			e.f.Advance(time.Second)
			e.relaunch(t) // the prompt in the old process is never answered
			if applied != nil {
				select {
				case <-applied:
				case <-time.After(3 * time.Second):
					t.Fatal("the old process's config apply call must have ended with its daemon")
				}
			}
			settle()
			if got := e.logins(); got != before {
				t.Fatalf("a relaunch during an open prompt must not open another: %d login prompts (was %d)", got, before)
			}
			if _, ok := e.d.stager.Pending(); !ok {
				t.Fatal("the change must be staged again on the relaunched process")
			}
			if got := len(e.contentBlocked(t)); got < 1 {
				t.Fatal("the relaunched process must report the staged change blocked")
			}
			// The record of an open prompt reaches its timeout plus one
			// cooldown ahead, and a relaunch inherits at most one cooldown
			// from now: a full 60 s, however long the prompt had been open.
			_, p := e.apply(t)
			if p == nil || p.ExitCode() != control.ExitStaged || !fullCooldown.MatchString(p.Message) {
				t.Fatalf("config apply after a relaunch during an open prompt: want exit %d with one cooldown left (60 s), got %+v", control.ExitStaged, p)
			}
			if got := e.logins(); got != before {
				t.Fatalf("that refusal must not prompt: %d", got)
			}

			// Kill-relaunch again, still inside the cooldown: the same.
			e.f.Advance(10 * time.Second)
			e.relaunch(t)
			settle()
			if got := e.logins(); got != before {
				t.Fatalf("a second relaunch must not prompt either: %d", got)
			}
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
				t.Fatalf("config apply after the second relaunch: want exit %d, got %+v", control.ExitStaged, p)
			}

			// After the cooldown the suppression still holds: a newly staged
			// content gets no automatic prompt, only a blocked line. (The
			// vault record of the open prompt must say suppressed, not just
			// cooling down, or kill-relaunch-wait-rewrite would be a fresh
			// prompt per minute.)
			e.f.Advance(configApplyCooldown)
			blocked := len(e.contentBlocked(t))
			e.stage(t, rev(rules, 9), false)
			settle()
			if got := e.logins(); got != before {
				t.Fatalf("after the cooldown, a relaunch during an open prompt must still suppress automatic prompts: %d login prompts (was %d)", got, before)
			}
			if got := len(e.contentBlocked(t)); got != blocked+1 {
				t.Fatalf("the content staged after the cooldown must get one blocked line: %d (was %d)", got, blocked)
			}

			// Only config apply asks, exactly once.
			e.f.ScriptAuth(fake.Answer{Allow: false})
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitRefused {
				t.Fatalf("config apply after the cooldown: want exit %d, got %+v", control.ExitRefused, p)
			}
			if got := e.logins(); got != before+1 {
				t.Fatalf("config apply after the cooldown shows exactly one prompt: %d", got)
			}
		})
	}
}

// What happens while a background prompt is open must not erase the vault
// record of that prompt, or a kill-and-relaunch at that moment is a fresh
// prompt again (the restart bypass): neither a `config apply` refused
// because the prompt is open, nor a second content staged meanwhile, may
// touch the record. After the relaunch the staged change is reported
// blocked and no prompt opens; the prompt in the old process is never
// answered.
func TestRelaunchAfterActivityDuringOpenPromptStaysSuppressed(t *testing.T) {
	for _, via := range []string{"config apply", "second content"} {
		t.Run(via, func(t *testing.T) {
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.GateTimeout = func() time.Duration { return 30 * time.Second }
			})
			hold := make(chan struct{})
			t.Cleanup(func() { close(hold) })
			e.f.ScriptAuth(fake.Answer{Wait: hold})
			e.stage(t, rules, false)
			waitFor(t, func() bool { return e.logins() == 1 })
			content := rules
			if via == "config apply" {
				if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged {
					t.Fatalf("config apply while the prompt is open: want exit %d, got %+v", control.ExitStaged, p)
				}
			} else {
				content = rev(rules, 1)
				e.stage(t, content, false)
				waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
			}
			if got := e.logins(); got != 1 {
				t.Fatalf("setup: %d prompts", got)
			}
			if _, err := e.vault.Get(PromptsVaultItem); err != nil {
				t.Fatalf("the open prompt's vault record must survive a %s: %v", via, err)
			}

			e.f.Advance(time.Second)
			e.relaunch(t)
			e.stage(t, content, false) // already on disk; waits for the new process to stage it
			settle()
			if got := e.logins(); got != 1 {
				t.Fatalf("%s during an open prompt + relaunch gave a fresh prompt: %d", via, got)
			}
			if got := len(e.contentBlocked(t)); got < 1 {
				t.Fatal("the relaunched process must report the staged change blocked")
			}
			if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !fullCooldown.MatchString(p.Message) {
				t.Fatalf("config apply on the relaunched process: want exit %d with one cooldown left (60 s), got %+v", control.ExitStaged, p)
			}
			if got := e.logins(); got != 1 {
				t.Fatalf("that refusal must not prompt: %d", got)
			}
		})
	}
}

// When the vault refuses to record an opening prompt (a locked login
// Keychain, which a same-user process can arrange), no prompt is shown at
// all: a prompt the next process could not know about would be the
// restart loop again. The change stays staged, reported blocked; config
// apply fails with a clear error and exit 1; once the vault works again,
// config apply asks.
func TestVaultRefusingPromptRecordMeansNoPrompt(t *testing.T) {
	e := startWith(t, withClock)
	e.vault.SetFailPut(errors.New("keychain locked"))
	e.stage(t, rules, false)
	waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
	settle()
	if got := e.logins(); got != 0 {
		t.Fatalf("with the vault refusing the record, the background prompt must not open: %d", got)
	}
	if len(e.f.Warnings()) == 0 {
		t.Fatal("the change must be reported blocked with the warning")
	}
	_, p := e.apply(t)
	if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "vault") {
		t.Fatalf("config apply with the vault refusing the record: want exit %d naming the vault, got %+v", control.ExitError, p)
	}
	if got := e.logins(); got != 0 {
		t.Fatalf("that config apply must not prompt: %d", got)
	}
	if _, ok := e.d.stager.Pending(); !ok {
		t.Fatal("the change must stay staged")
	}

	e.vault.SetFailPut(nil)
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitRefused {
		t.Fatalf("config apply once the vault works: want the prompt, denied (exit %d), got %+v", control.ExitRefused, p)
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("config apply once the vault works shows exactly one prompt: %d", got)
	}
}
