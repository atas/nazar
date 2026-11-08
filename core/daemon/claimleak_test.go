package daemon

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
)

// A login prompt's claim is ended whatever happens after the
// approval. Every holder of the claim (`ssh-key create`, `ssh-key delete`,
// `trust --app`, `config apply` and the automatic config prompt)
// can fail between the user's approval and the change taking effect: the
// config file became unreadable while the prompt was open, the vault
// refuses the write, a file cannot be removed. Such a failure must end the
// claim as not applied (the approval applied nothing, so the cooldown
// runs) and be audited as an error; it must NOT leave the prompt counted
// as open, which would refuse every later login prompt with "an approval
// prompt is already open" until a relaunch. A same-user process can cause
// the create case at will (chmod 000 config.yaml during the user's
// prompt), so a leaked claim is a denial of service against every loosen
// command, the config prompt included.

// claimSite is one holder of the login-prompt claim with a failure that
// can be injected between the approval and the change.
type claimSite struct {
	name   string
	target string                                              // audit target of the command (prefix)
	setup  func(t *testing.T, e *env)                          // before the prompt
	start  func(t *testing.T, e *env) <-chan *control.Problem  // opens the prompt (held)
	inject func(t *testing.T, e *env)                          // the failure, while the prompt is open
	ok     func(t *testing.T, e *env, p *control.Problem) bool // the call reported the failure
	after  func(t *testing.T, e *env)                          // the site's own prompt works again
}

// callInBackground runs one control command on its own goroutine and
// returns its result on a channel.
func (e *env) callInBackground(t *testing.T, cmd string, args map[string]string, kind string, out any) <-chan *control.Problem {
	t.Helper()
	done := make(chan *control.Problem, 1)
	go func() { done <- control.AsProblem(e.call(t, cmd, args, kind, out)) }()
	return done
}

// unreadable makes path unreadable by its owner until the test ends.
func unreadable(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, st.Mode().Perm()) })
}

func claimSites() []claimSite {
	plainError := func(t *testing.T, e *env, p *control.Problem) bool {
		return p != nil && p.ExitCode() == control.ExitError
	}
	createX := func(t *testing.T, e *env) {
		e.f.ScriptAuth(fake.Answer{Allow: true})
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "x"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
			t.Fatalf("ssh-key create after the failure: %v", err)
		}
	}
	return []claimSite{
		{
			// The case a review raised: config.yaml cannot be re-read after the
			// approval (chmod 000 by any same-user process).
			name: "ssh-key create", target: "ssh:k",
			setup: func(t *testing.T, e *env) {
				e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\n")
				waitFor(t, func() bool { return e.d.stager.Active().Raw != nil })
			},
			start: func(t *testing.T, e *env) <-chan *control.Problem {
				return e.callInBackground(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{})
			},
			inject: func(t *testing.T, e *env) { unreadable(t, layout.ConfigFile(e.home)) },
			ok: func(t *testing.T, e *env, p *control.Problem) bool {
				_, err := e.d.keys.Get("k")
				return plainError(t, e, p) && err != nil
			},
			after: func(t *testing.T, e *env) {
				os.Chmod(layout.ConfigFile(e.home), 0o600)
				e.f.ScriptAuth(fake.Answer{Allow: true})
				if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "k"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
					t.Fatalf("ssh-key create once the file is readable again: %v", err)
				}
			},
		},
		{
			// The key's .pub file cannot be removed (the keys directory lost
			// its write bit while the prompt was open).
			name: "ssh-key delete", target: "ssh:github",
			setup: func(t *testing.T, e *env) {
				e.f.ScriptAuth(fake.Answer{Allow: true})
				if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
					t.Fatal(err)
				}
			},
			start: func(t *testing.T, e *env) <-chan *control.Problem {
				return e.callInBackground(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{})
			},
			inject: func(t *testing.T, e *env) {
				dir := layout.KeysDir(e.home)
				if err := os.Chmod(dir, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(dir, 0o700) })
			},
			ok: plainError,
			after: func(t *testing.T, e *env) {
				os.Chmod(layout.KeysDir(e.home), 0o700)
				createX(t, e)
			},
		},
		{
			// The pin cannot be written (the vault refuses).
			name: "trust --app", target: "app:" + toolID,
			setup: func(t *testing.T, e *env) { e.f.InstallApp("/Applications/Tool.app", toolID, toolCode) },
			start: func(t *testing.T, e *env) <-chan *control.Problem {
				return e.callInBackground(t, control.CmdTrustApp, map[string]string{"app": toolID}, control.KindAppPin, &control.AppPin{})
			},
			inject: func(t *testing.T, e *env) { e.vault.SetFailPut(errors.New("keychain locked")) },
			ok: func(t *testing.T, e *env, p *control.Problem) bool {
				return plainError(t, e, p) && len(e.status(t).Pins) == 0
			},
			after: func(t *testing.T, e *env) {
				e.vault.SetFailPut(nil)
				e.f.ScriptAuth(fake.Answer{Allow: true})
				if _, p := e.trustApp(t, toolID); p != nil {
					t.Fatalf("trust --app once the vault works: %+v", p)
				}
			},
		},
		{
			// The approved config cannot be recorded (the vault refuses).
			name: "config apply", target: "config",
			setup: func(t *testing.T, e *env) {
				e.denyFirst(t)
				e.f.Advance(configApplyCooldown)
			},
			start: func(t *testing.T, e *env) <-chan *control.Problem {
				return e.callInBackground(t, control.CmdConfigApply, nil, control.KindConfigDiff, &control.ConfigDiff{})
			},
			inject: func(t *testing.T, e *env) { e.vault.SetFailPut(errors.New("keychain locked")) },
			ok: func(t *testing.T, e *env, p *control.Problem) bool {
				return plainError(t, e, p) && len(e.d.stager.Active().SSHAgent.Keys) == 0
			},
			after: func(t *testing.T, e *env) {
				e.vault.SetFailPut(nil)
				e.f.ScriptAuth(fake.Answer{Allow: true})
				if diff, p := e.apply(t); p != nil || !diff.Applied {
					t.Fatalf("config apply once the vault works: %+v %+v", diff, p)
				}
			},
		},
		{
			// The same failure under the automatic prompt of a staged change.
			name: "automatic config prompt", target: "config",
			setup: func(*testing.T, *env) {},
			start: func(t *testing.T, e *env) <-chan *control.Problem {
				e.stage(t, rules, false)
				done := make(chan *control.Problem, 1)
				done <- nil
				return done
			},
			inject: func(t *testing.T, e *env) { e.vault.SetFailPut(errors.New("keychain locked")) },
			ok: func(t *testing.T, e *env, p *control.Problem) bool {
				waitFor(t, func() bool { return len(e.configAudit(t, audit.Error)) == 1 })
				return p == nil && len(e.d.stager.Active().SSHAgent.Keys) == 0
			},
			after: func(t *testing.T, e *env) {
				e.vault.SetFailPut(nil)
				e.f.ScriptAuth(fake.Answer{Allow: true})
				if diff, p := e.apply(t); p != nil || !diff.Applied {
					t.Fatalf("config apply once the vault works: %+v %+v", diff, p)
				}
			},
		},
	}
}

// For every holder of the login-prompt claim: a failure after the approval
// is reported to the caller and audited as an error naming the approval,
// the claim is ended (the next loosen command is refused for the cooldown,
// not as "already open"), and after the cooldown the next login prompt
// opens, for another command and for the failed one.
func TestFailureAfterApprovalEndsTheClaim(t *testing.T) {
	for _, s := range claimSites() {
		t.Run(s.name, func(t *testing.T) {
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.GateTimeout = func() time.Duration { return 10 * time.Second }
			})
			s.setup(t, e)
			base := e.logins()
			release := e.holdLogin(t, true) // the user WILL approve
			done := s.start(t, e)
			waitFor(t, func() bool { return e.logins() == base+1 })
			s.inject(t, e)
			release()
			if p := <-done; !s.ok(t, e, p) {
				t.Fatalf("the failure after the approval must be reported and apply nothing: %+v", p)
			}

			// The claim is ended: the next loosen command is refused for
			// the cooldown (an approval that applied nothing), not because a
			// prompt is still counted as open.
			e.vault.SetFailPut(nil)
			p := e.probeLogin(t)
			if p == nil || p.ExitCode() != control.ExitRefused || strings.Contains(p.Message, "already open") || !cooldownMsg.MatchString(p.Message) {
				t.Fatalf("trust right after the failure: want exit %d for the cooldown, got %+v", control.ExitRefused, p)
			}
			if got := e.logins(); got != base+1 {
				t.Fatalf("the refusal must not prompt: %d", got-base)
			}
			var errs []string
			for _, l := range e.auditFor(t, s.target) {
				if l["decision"] == string(audit.Error) && strings.Contains(l["reason"], "approved, but") {
					errs = append(errs, l["reason"])
				}
			}
			if len(errs) != 1 {
				t.Fatalf("want one audit error line naming the approval that applied nothing, got %v:\n%s", errs, strings.Join(e.sink.Lines(), "\n"))
			}

			// After the cooldown the next login prompt opens and works.
			e.f.Advance(configApplyCooldown)
			e.f.ScriptAuth(fake.Answer{Allow: true})
			if p := e.probeLogin(t); p != nil {
				t.Fatalf("trust after the cooldown: %+v", p)
			}
			if got := e.logins(); got != base+2 {
				t.Fatalf("trust after the cooldown shows exactly one prompt: %d", got-base)
			}
			// ...and so does the failed command itself (an approved trust
			// starts no cooldown).
			s.after(t, e)
			if got := e.logins(); got != base+3 {
				t.Fatalf("the failed command after the cooldown shows exactly one prompt: %d", got-base)
			}
		})
	}
}
