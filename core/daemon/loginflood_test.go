package daemon

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The throttle covers every login prompt the daemon opens
// outside the agent socket, and an approval counts only when its change
// applied.
//
//   - An approval of a config change that was rewritten while the prompt
//     was open applies nothing (configstage.ErrStale). It must not re-arm
//     the automatic prompt: otherwise a process rewriting the file every
//     few hundred milliseconds gets one fresh prompt per approval, forever,
//     with nothing ever applied (worse than the denial loop: the user is
//     approving). The same for `ssh-key create`, which also re-reads the
//     file after its prompt.
//   - `ssh-key create`, `ssh-key delete`, `trust <path>` and `trust --app`
//     open the same login gate as `config apply`, so they get the same
//     throttle: one prompt open at a time, and a cooldown after any of them
//     ends without an approval that applied, shared between them and kept
//     in the vault across a relaunch. A looping `nazar ssh-key delete` is
//     otherwise a prompt per call toward a reflex approval that destroys
//     the key.

// cooldownMsg is the remaining cooldown as a refusal spells it when the
// clock did not move since the failed prompt (60 s) or moved one second.
var cooldownMsg = regexp.MustCompile(`\b(59|60) seconds\b`)

// blockedFor returns the audit lines for target with decision blocked.
func (e *env) blockedFor(t *testing.T, target string) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.auditFor(t, target) {
		if l["decision"] == string(audit.Blocked) {
			out = append(out, l)
		}
	}
	return out
}

// holdLogin scripts the next login prompt to block until the returned
// release is called (then answering allow), with release also run at
// cleanup.
func (e *env) holdLogin(t *testing.T, allow bool) (release func()) {
	t.Helper()
	hold := make(chan struct{})
	released := false
	release = func() {
		if !released {
			released = true
			close(hold)
		}
	}
	t.Cleanup(release)
	e.f.ScriptAuth(fake.Answer{Allow: allow, Wait: hold})
	return release
}

// An approved background config prompt whose content was rewritten while
// it was open applies nothing and must leave the automatic prompts
// suppressed: N more rewrites show no prompt, the vault still carries the
// suppression, the approval is audited as an error (not as approved), and
// a later `config apply` (after the cooldown) applies the current content
// with exactly one prompt.
func TestStaleApprovalDoesNotReopenAutoPrompts(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		o.GateTimeout = func() time.Duration { return 10 * time.Second }
	})
	release := e.holdLogin(t, true) // the user WILL approve
	e.stage(t, rules, false)
	waitFor(t, func() bool { return e.logins() == 1 })
	e.stage(t, rev(rules, 1), false) // the attacker rewrites while the prompt is open
	waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
	release() // the approval comes for a content that is gone
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Error)) == 1 })
	if got := e.configAudit(t, audit.Error)[0]["reason"]; !strings.Contains(got, "changed while the prompt was open") {
		t.Fatalf("a stale approval must be audited as applying nothing: %q", got)
	}
	if n := len(e.configAudit(t, audit.Approved)); n != 0 {
		t.Fatalf("a stale approval must not be audited as approved: %d approved lines", n)
	}
	if len(e.d.stager.Active().SSHAgent.Keys) != 0 {
		t.Fatal("a stale approval must apply nothing")
	}

	const n = 5
	for i := 2; i <= n; i++ {
		e.stage(t, rev(rules, i), i%2 == 0)
	}
	settle()
	if got := e.logins(); got != 1 {
		t.Fatalf("after an approval that applied nothing, %d rewrites must show no new prompt: %d login prompts", n-1, got)
	}
	if got := len(e.contentBlocked(t)); got != n {
		t.Fatalf("want one blocked line per content staged after the prompt opened (%d), got %d", n, got)
	}
	if _, err := e.vault.Get(PromptsVaultItem); err != nil {
		t.Fatalf("the suppression must still be in the vault after a stale approval: %v", err)
	}

	// The control socket can't drive the same loop: config apply is refused
	// for the cooldown, without a prompt.
	e.f.Advance(time.Second)
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !secondsLeft.MatchString(p.Message) {
		t.Fatalf("config apply after a stale approval: want exit %d with the cooldown left, got %+v", control.ExitStaged, p)
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("that refusal must not prompt: %d", got)
	}

	// After the cooldown, config apply asks once and applies what the file
	// says now.
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	diff, p := e.apply(t)
	if p != nil || !diff.Applied {
		t.Fatalf("config apply after the cooldown: %+v %+v", diff, p)
	}
	if got := e.logins(); got != 2 {
		t.Fatalf("config apply must show exactly one prompt: %d in all", got)
	}
	if !bytes.Equal(e.d.stager.Active().Raw, []byte(rev(rules, n))) {
		t.Fatal("config apply must apply the current content")
	}
	if _, err := e.vault.Get(PromptsVaultItem); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("an applied approval removes the vault record: %v", err)
	}
}

// The same through `config apply`: an approval that came after the file
// changed applies nothing, exits 4, and starts the cooldown, so a process
// looping `config apply` while rewriting the file gets one prompt per
// cooldown, not one per approval.
func TestStaleConfigApplyApprovalCoolsDown(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		o.GateTimeout = func() time.Duration { return 10 * time.Second }
	})
	e.denyFirst(t)
	e.f.Advance(configApplyCooldown + time.Second)
	release := e.holdLogin(t, true)
	done := make(chan *control.Problem, 1)
	go func() {
		_, p := e.apply(t)
		done <- p
	}()
	waitFor(t, func() bool { return e.logins() == 2 })
	e.stage(t, rev(rules, 1), false) // rewritten while the prompt is open
	release()
	p := <-done
	if p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("a stale config apply approval: want exit %d, got %+v", control.ExitStaged, p)
	}
	if len(e.d.stager.Active().SSHAgent.Keys) != 0 {
		t.Fatal("nothing may apply")
	}
	for i := 0; i < 3; i++ {
		if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !cooldownMsg.MatchString(p.Message) {
			t.Fatalf("config apply %d right after a stale approval: want exit %d with the cooldown, got %+v", i, control.ExitStaged, p)
		}
	}
	e.stage(t, rev(rules, 2), true)
	settle()
	if got := e.logins(); got != 2 {
		t.Fatalf("after a stale approval nothing prompts until the cooldown passed: %d", got)
	}
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if diff, p := e.apply(t); p != nil || !diff.Applied || e.logins() != 3 {
		t.Fatalf("config apply after the cooldown: %+v %+v, %d prompts", diff, p, e.logins())
	}
}

// `ssh-key create` re-reads config.yaml after its prompt and creates
// nothing if it changed. That approval, too, counts as not approved: the
// next create is refused for the cooldown without a prompt.
func TestStaleSSHKeyCreateApprovalCoolsDown(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		o.GateTimeout = func() time.Duration { return 10 * time.Second }
	})
	release := e.holdLogin(t, true)
	done := make(chan *control.Problem, 1)
	go func() {
		done <- control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{}))
	}()
	waitFor(t, func() bool { return e.logins() == 1 })
	// A rewrite that is no loosening, so it applies at once and is not
	// staged; the file is still not what the prompt was about.
	e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\n# edited while the prompt was open\n")
	waitFor(t, func() bool { return e.d.stager.Active().Raw != nil })
	release()
	if p := <-done; p == nil || p.ExitCode() != control.ExitStaged {
		t.Fatalf("stale ssh-key create approval: want exit %d, got %+v", control.ExitStaged, p)
	}
	if _, err := e.d.keys.Get("k"); err == nil {
		t.Fatal("nothing may be created")
	}
	lines := e.auditFor(t, "ssh:k")
	if len(lines) != 1 || lines[0]["decision"] != string(audit.Error) || !strings.Contains(lines[0]["reason"], "changed while the prompt was open") {
		t.Fatalf("a stale create approval is audited as an error, not as approved: %v", lines)
	}
	for i := 0; i < 3; i++ {
		p := control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{}))
		if p == nil || p.ExitCode() != control.ExitRefused || !cooldownMsg.MatchString(p.Message) {
			t.Fatalf("ssh-key create %d after a stale approval: want exit %d with the cooldown, got %+v", i, control.ExitRefused, p)
		}
	}
	if got := e.logins(); got != 1 {
		t.Fatalf("the refusals must not prompt: %d", got)
	}
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatalf("ssh-key create after the cooldown: %v", err)
	}
	if got := e.logins(); got != 2 {
		t.Fatalf("ssh-key create after the cooldown shows exactly one prompt: %d in all", got)
	}
}

// loosenCommand is one control command that opens the login gate.
type loosenCommand struct {
	name   string
	target string // its audit target
	setup  func(t *testing.T, e *env)
	call   func(t *testing.T, e *env) *control.Problem
	undone func(t *testing.T, e *env) bool // nothing was loosened
}

func loosenCommands(t *testing.T) []loosenCommand {
	return []loosenCommand{
		{
			name: "ssh-key delete", target: "ssh:github",
			setup: func(t *testing.T, e *env) {
				e.f.ScriptAuth(fake.Answer{Allow: true})
				if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
					t.Fatal(err)
				}
			},
			call: func(t *testing.T, e *env) *control.Problem {
				return control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
			},
			undone: func(t *testing.T, e *env) bool { _, err := e.d.keys.Get("github"); return err == nil },
		},
		{
			name: "ssh-key create", target: "ssh:x",
			setup: func(*testing.T, *env) {},
			call: func(t *testing.T, e *env) *control.Problem {
				return control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "x"}, control.KindSSHKey, &control.SSHKey{}))
			},
			undone: func(t *testing.T, e *env) bool { _, err := e.d.keys.Get("x"); return err != nil },
		},
		{
			name: "trust --app", target: "app:" + toolID,
			setup: func(t *testing.T, e *env) { e.f.InstallApp("/Applications/Tool.app", toolID, toolCode) },
			call: func(t *testing.T, e *env) *control.Problem {
				_, p := e.trustApp(t, toolID)
				return p
			},
			undone: func(t *testing.T, e *env) bool { return len(e.status(t).Pins) == 0 },
		},
	}
}

// N denied calls of a loosen command show exactly one prompt: the rest are
// refused with exit 3 naming the cooldown, audited as blocked with the
// caller's chain, and loosen nothing. After the cooldown exactly one
// prompt again.
func TestLoosenCommandsCannotFloodLoginPrompts(t *testing.T) {
	for _, c := range loosenCommands(t) {
		t.Run(c.name, func(t *testing.T) {
			e := startWith(t, withClock)
			c.setup(t, e)
			base := e.logins()
			const n = 8
			for i := 0; i < n; i++ {
				p := c.call(t, e) // the fake's default denies
				if p == nil || p.ExitCode() != control.ExitRefused {
					t.Fatalf("call %d: want exit %d, got %+v", i, control.ExitRefused, p)
				}
				if i > 0 && !cooldownMsg.MatchString(p.Message) {
					t.Fatalf("call %d must name the cooldown left: %q", i, p.Message)
				}
			}
			if got := e.logins() - base; got != 1 {
				t.Fatalf("%d denied calls must show exactly one login prompt, not %d", n, got)
			}
			if e.f.CountShown(fake.KindConfirm) != 0 {
				t.Fatal("a loosen command never uses the dialog gate")
			}
			if !c.undone(t, e) {
				t.Fatal("something was loosened")
			}
			var blocked int
			for _, l := range e.sink.Lines() {
				f, err := audit.ParseLine(l)
				if err == nil && strings.HasPrefix(f["target"], c.target) && f["decision"] == string(audit.Blocked) {
					blocked++
					if f["chain"] == "" && f["session"] == "" {
						t.Fatalf("a refused call must be audited with its caller: %s", l)
					}
				}
			}
			if blocked != n-1 {
				t.Fatalf("want %d blocked audit lines for the refused calls, got %d:\n%s", n-1, blocked, strings.Join(e.sink.Lines(), "\n"))
			}

			// Still refused just before the cooldown ends; exactly one prompt
			// after it; that denial starts the next cooldown.
			e.f.Advance(configApplyCooldown - time.Second)
			if p := c.call(t, e); p == nil || p.ExitCode() != control.ExitRefused || e.logins()-base != 1 {
				t.Fatalf("1 s before the cooldown ends: %+v, %d prompts", p, e.logins()-base)
			}
			e.f.Advance(time.Second)
			if p := c.call(t, e); p == nil || p.ExitCode() != control.ExitRefused {
				t.Fatalf("after the cooldown: %+v", p)
			}
			if got := e.logins() - base; got != 2 {
				t.Fatalf("after the cooldown exactly one prompt: %d", got)
			}
			if p := c.call(t, e); p == nil || !cooldownMsg.MatchString(p.Message) || e.logins()-base != 2 {
				t.Fatalf("the new denial starts a new cooldown: %+v, %d prompts", p, e.logins()-base)
			}
		})
	}
}

// The cooldown is one for all these prompts: a denied config prompt cools
// `ssh-key delete` down, a denied `ssh-key delete` cools `config apply`
// and `trust` down, and a relaunch inherits it from the vault. A timed-out
// and a failed prompt cool down like a denial.
func TestLoginCooldownIsSharedAndSurvivesRelaunch(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		o.GateTimeout = func() time.Duration { return 300 * time.Millisecond }
	})
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	del := func() *control.Problem {
		return control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
	}
	trust := func() *control.Problem { return e.probeLogin(t) }

	// A denied background config prompt cools the commands down.
	e.stage(t, rules, false) // the fake's default denies
	waitFor(t, func() bool { return e.logins() == 2 })
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Denied)) == 1 })
	if p := del(); p == nil || p.ExitCode() != control.ExitRefused || !cooldownMsg.MatchString(p.Message) {
		t.Fatalf("ssh-key delete after a denied config prompt: %+v", p)
	}
	if p := trust(); p == nil || p.ExitCode() != control.ExitRefused || !cooldownMsg.MatchString(p.Message) {
		t.Fatalf("trust after a denied config prompt: %+v", p)
	}
	if got := e.logins(); got != 2 {
		t.Fatalf("refused commands must not prompt: %d", got)
	}
	if _, err := e.d.keys.Get("github"); err != nil {
		t.Fatal("the key must still exist")
	}

	// A denied ssh-key delete cools config apply and trust down.
	e.f.Advance(configApplyCooldown)
	if p := del(); p == nil || p.ExitCode() != control.ExitRefused || e.logins() != 3 {
		t.Fatalf("ssh-key delete after the cooldown: %+v, %d prompts", p, e.logins())
	}
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !cooldownMsg.MatchString(p.Message) {
		t.Fatalf("config apply after a denied ssh-key delete: want exit %d with the cooldown, got %+v", control.ExitStaged, p)
	}
	if p := trust(); p == nil || p.ExitCode() != control.ExitRefused || !cooldownMsg.MatchString(p.Message) {
		t.Fatalf("trust after a denied ssh-key delete: %+v", p)
	}
	// ...and the automatic config prompt: a new loosening is reported
	// blocked, not asked about.
	e.stage(t, rev(rules, 1), false)
	settle()
	if got := e.logins(); got != 3 {
		t.Fatalf("no prompt may open during the cooldown: %d", got)
	}

	// The relaunched process inherits the cooldown from the vault.
	e.f.Advance(time.Second)
	e.relaunch(t)
	if p := del(); p == nil || p.ExitCode() != control.ExitRefused || !secondsLeft.MatchString(p.Message) {
		t.Fatalf("ssh-key delete after a relaunch must be refused with the cooldown left (59 s): %+v", p)
	}
	if got := e.logins(); got != 3 {
		t.Fatalf("the relaunched process must not prompt during the cooldown: %d", got)
	}

	// A timed-out and a failed prompt cool down too.
	e.f.Advance(configApplyCooldown)
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	e.f.ScriptAuth(fake.Answer{Wait: never})
	if p := trust(); p == nil || p.ExitCode() != control.ExitRefused || e.logins() != 4 {
		t.Fatalf("timed-out trust: %+v, %d prompts", p, e.logins())
	}
	if p := del(); p == nil || !cooldownMsg.MatchString(p.Message) || e.logins() != 4 {
		t.Fatalf("after a timed-out trust, ssh-key delete is refused for the cooldown: %+v", p)
	}
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Err: errors.New("LAContext: unexpected failure")})
	if p := del(); p == nil || p.ExitCode() != control.ExitRefused || e.logins() != 5 {
		t.Fatalf("failed ssh-key delete: %+v, %d prompts", p, e.logins())
	}
	if p := trust(); p == nil || !cooldownMsg.MatchString(p.Message) || e.logins() != 5 {
		t.Fatalf("after a failed prompt, trust is refused for the cooldown: %+v", p)
	}

	// An approved command ends nothing it should not: it neither lifts the
	// config suppression nor is followed by a cooldown.
	e.f.Advance(configApplyCooldown)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if p := trust(); p != nil || e.logins() != 6 {
		t.Fatalf("approved trust: %+v, %d prompts", p, e.logins())
	}
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if p := trust(); p != nil || e.logins() != 7 {
		t.Fatalf("trust right after an approved trust: %+v, %d prompts", p, e.logins())
	}
	e.stage(t, rev(rules, 2), true)
	settle()
	if got := e.logins(); got != 7 {
		t.Fatalf("an approved trust must not turn the automatic config prompt back on: %d", got)
	}
	if _, err := e.vault.Get(PromptsVaultItem); err != nil {
		t.Fatalf("the config suppression must still be in the vault: %v", err)
	}
}

// One of these prompts is open at a time, whatever command opened it:
// while an `ssh-key delete` prompt is on screen, `trust` and `config
// apply` are refused without a prompt, and a new loosening in the file is
// reported blocked. The command that holds the prompt completes normally.
func TestOneLoginPromptAtATimeAcrossCommands(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		o.GateTimeout = func() time.Duration { return 10 * time.Second }
	})
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	release := e.holdLogin(t, true)
	done := make(chan *control.Problem, 1)
	go func() {
		done <- control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
	}()
	waitFor(t, func() bool { return e.logins() == 2 })

	p := e.probeLogin(t)
	if p == nil || p.ExitCode() != control.ExitRefused || !strings.Contains(p.Message, "already open") {
		t.Fatalf("trust while a delete prompt is open: want exit %d naming the open prompt, got %+v", control.ExitRefused, p)
	}
	if p := control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "x"}, control.KindSSHKey, &control.SSHKey{})); p == nil || p.ExitCode() != control.ExitRefused {
		t.Fatalf("ssh-key create while a delete prompt is open: %+v", p)
	}
	e.stage(t, rules, false)
	if _, p := e.apply(t); p == nil || p.ExitCode() != control.ExitStaged || !strings.Contains(p.Message, "already open") {
		t.Fatalf("config apply while a delete prompt is open: want exit %d, got %+v", control.ExitStaged, p)
	}
	waitFor(t, func() bool { return len(e.contentBlocked(t)) == 1 })
	settle()
	if got := e.logins(); got != 2 {
		t.Fatalf("nothing may open a second prompt: %d", got)
	}

	release()
	if p := <-done; p != nil {
		t.Fatalf("the held delete must complete: %+v", p)
	}
	if _, err := e.d.keys.Get("github"); err == nil {
		t.Fatal("the approved delete must delete the key")
	}
	// Approved: no cooldown, so trust asks at once (and is denied).
	if p := e.probeLogin(t); p == nil || p.ExitCode() != control.ExitRefused || e.logins() != 3 {
		t.Fatalf("trust after the approved delete: %+v, %d prompts", p, e.logins())
	}
}

// When the vault refuses to record an opening prompt, the loosen commands
// show none either: exit 1 naming the vault, nothing loosened, and a
// prompt once the vault works again.
func TestVaultRefusingRecordMeansNoLoosenPrompt(t *testing.T) {
	e := startWith(t, withClock)
	e.vault.SetFailPut(errors.New("keychain locked"))
	p := e.probeLogin(t)
	if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "vault") {
		t.Fatalf("trust with the vault refusing the record: want exit %d naming the vault, got %+v", control.ExitError, p)
	}
	if e.logins() != 0 || len(e.d.trust.Pins()) != 0 {
		t.Fatalf("no prompt, nothing pinned: %d prompts, %v", e.logins(), e.d.trust.Pins())
	}
	e.vault.SetFailPut(nil)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if p := e.probeLogin(t); p != nil || e.logins() != 1 {
		t.Fatalf("trust once the vault works: %+v, %d prompts", p, e.logins())
	}
}
