package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The create prompts' line on when the chip lets the new key work.
const (
	whileLockedLine      = "works while the Mac is locked too, once you have logged in since it started; fixed for the key's life"
	onlyWhenUnlockedLine = "works only while the Mac is unlocked; fixed for the key's life"
)

func promptHas(t *testing.T, f *fake.Fake, line string) {
	t.Helper()
	shown := f.Shown()
	if len(shown) == 0 {
		t.Fatal("no prompt")
	}
	if lines := shown[len(shown)-1].Prompt.Lines; !strings.Contains(strings.Join(lines, "\n"), line) {
		t.Fatalf("the prompt lacks %q:\n%s", line, strings.Join(lines, "\n"))
	}
}

// `ssh-key create` makes a key that works while the Mac is locked (once
// the user has logged in); `--only-when-unlocked` (onlyWhenUnlocked=true)
// one the chip refuses while it is locked. The prompt says which, the reply
// and the list say whileLocked, and the enclave itself behaves so.
func TestSSHKeyCreateAccess(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "bot"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if !k.WhileLocked {
		t.Fatalf("default key: %+v", k)
	}
	promptHas(t, e.f, whileLockedLine)
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github", "onlyWhenUnlocked": "true"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if k.WhileLocked {
		t.Fatalf("--only-when-unlocked key: %+v", k)
	}
	promptHas(t, e.f, onlyWhenUnlockedLine)
	for name, want := range map[string]platform.Access{"bot": platform.AccessAfterFirstUnlock, "github": platform.AccessWhenUnlocked} {
		if info, err := e.d.keys.Get(name); err != nil || info.Access != want {
			t.Fatalf("%s: %+v %v; want access %v", name, info, err, want)
		}
	}
	e.f.SetLocked(true)
	if _, err := e.f.Sign(e.enclaveHandle(t, "bot"), []byte("d"), 0); err != nil {
		t.Fatalf("the default key must sign while locked: %v", err)
	}
	if _, err := e.f.Sign(e.enclaveHandle(t, "github"), []byte("d"), 0); !errors.Is(err, platform.ErrLocked) {
		t.Fatalf("the --only-when-unlocked key must not sign while locked: %v", err)
	}
	var l control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l); err != nil || len(l.Items) != 2 {
		t.Fatalf("list: %+v %v", l, err)
	}
	for _, it := range l.Items {
		if it.WhileLocked != (it.Name == "bot") {
			t.Errorf("list: %s whileLocked=%v", it.Name, it.WhileLocked)
		}
	}
	if p := control.AsProblem(e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "x", "onlyWhenUnlocked": "yes"}, control.KindSSHKey, &k)); p.ExitCode() != control.ExitUsage {
		t.Fatalf("onlyWhenUnlocked=yes: %+v", p)
	}
}

// --always-ask makes a key that works only while the Mac is unlocked: it
// asks for Touch ID on every use, which a locked Mac can't give anyway,
// and keeps the locked screen's protection. So does a key whose entry
// calls for user presence. Both flags together are fine.
func TestAlwaysAskIsOnlyWhenUnlocked(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	for name, args := range map[string]map[string]string{
		"prod":  {"name": "prod", "alwaysAsk": "true"},
		"prod2": {"name": "prod2", "alwaysAsk": "true", "onlyWhenUnlocked": "true"},
	} {
		var k control.SSHKey
		if err := e.call(t, control.CmdSSHKeyCreate, args, control.KindSSHKey, &k); err != nil {
			t.Fatal(err)
		}
		if !k.UserPresence || k.WhileLocked {
			t.Fatalf("%s: %+v", name, k)
		}
		promptHas(t, e.f, onlyWhenUnlockedLine)
		if info, _ := e.d.keys.Get(name); info.Access != platform.AccessWhenUnlocked {
			t.Fatalf("%s: access %v", name, info.Access)
		}
	}
	// An entry that calls for user presence (every policy login + use).
	e.approved(t, "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\nssh_agent:\n  keys:\n    hydra:\n      gate: block\n      rules:\n        - apps: [iterm]\n          gate: login\n          scope: use\n")
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "hydra"}, control.KindSSHKey, &k); err != nil {
		t.Fatal(err)
	}
	if !k.UserPresence || k.WhileLocked {
		t.Fatalf("hydra: %+v", k)
	}
}

// A key made before Access existed has no access in its record: it is
// listed as one that works only while the Mac is unlocked, never as one
// that works while it is locked.
func TestLegacyKeyIsListedOnlyWhenUnlocked(t *testing.T) {
	e := start(t)
	if err := e.vault.Put(keys.VaultPrefix+"old", []byte("{")); err != nil { // broken: never claims to work while locked either
		t.Fatal(err)
	}
	reg := keys.NewRegistry(e.f, e.vault, layout.KeysDir(e.home), nil)
	if _, err := reg.Create("legacy", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	if b, _ := e.vault.Get(keys.VaultPrefix + "legacy"); strings.Contains(string(b), "access") {
		t.Fatalf("the record of a when-unlocked key names an access: %s", b)
	}
	var l control.SSHKeyList
	if err := e.call(t, control.CmdSSHKeyList, nil, control.KindSSHKeyList, &l); err != nil {
		t.Fatal(err)
	}
	for _, it := range l.Items {
		if it.WhileLocked {
			t.Errorf("%s is listed as working while locked", it.Name)
		}
	}
}

// `secret add` makes a secret whose key works while the Mac is locked;
// onlyWhenUnlocked=true one that opens only while it is unlocked. A locked
// `nazar get` of the latter says why, in its reply and its audit line.
func TestSecretAddAccess(t *testing.T) {
	e := startSecrets(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(cliProc("secret", "add", "BOT"))
	if s, p := e.addSecret(t, "BOT", testValue); p != nil || !s.WhileLocked {
		t.Fatalf("default secret: %+v %+v", s, p)
	}
	promptHas(t, e.f, whileLockedLine)
	var s control.Secret
	err := e.call(t, control.CmdSecretAdd, map[string]string{"name": "GH", "valueBase64": b64(testValue), "onlyWhenUnlocked": "true"}, control.KindSecret, &s)
	if err != nil || s.WhileLocked {
		t.Fatalf("--only-when-unlocked secret: %+v %v", s, err)
	}
	promptHas(t, e.f, onlyWhenUnlockedLine)
	if p := control.AsProblem(e.call(t, control.CmdSecretAdd, map[string]string{"name": "X", "valueBase64": b64(testValue), "onlyWhenUnlocked": "1"}, control.KindSecret, &s)); p.ExitCode() != control.ExitUsage {
		t.Fatalf("onlyWhenUnlocked=1: %+v", p)
	}
	var l control.SecretList
	if err := e.call(t, control.CmdSecretList, nil, control.KindSecretList, &l); err != nil {
		t.Fatal(err)
	}
	for _, it := range l.Items {
		if it.WhileLocked != (it.Name == "BOT") {
			t.Errorf("list: %s whileLocked=%v", it.Name, it.WhileLocked)
		}
	}
	e.f.SetLocked(true)
	e.asCLI(cliProc("get", "GH"))
	p := control.AsProblem(e.call(t, control.CmdSecretGet, map[string]string{"name": "GH"}, control.KindSecretValue, &control.SecretValue{}))
	const why = "secrets: the Mac is locked; GH opens only while it's unlocked"
	if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, why) {
		t.Fatalf("locked get: an error (exit 1), not a refusal: %+v", p)
	}
	if f := e.lastAudit(t); f["reason"] != why || f["target"] != "secret:GH" {
		t.Fatalf("audit %v", f)
	}
	e.asCLI(cliProc("get", "BOT"))
	var v control.SecretValue
	if err := e.call(t, control.CmdSecretGet, map[string]string{"name": "BOT"}, control.KindSecretValue, &v); err != nil || v.ValueBase64 != b64(testValue) {
		t.Fatalf("locked get of a while-locked secret: %v", err)
	}
}

// `k8s ca create` makes a CA that signs while the Mac is locked;
// onlyWhenUnlocked=true one that signs only while it is unlocked. Asking
// again for a context set up already answers at once only when the CA is
// what was asked for: a different access is refused, never ignored (it is
// fixed for the CA's life).
func TestK8sCACreateAccess(t *testing.T) {
	e := startAdmin(t)
	e.approved(t, e.noKubectl())
	c, p := e.caCreate(t, "bot")
	if p != nil || c.CA == nil || !c.CA.WhileLocked {
		t.Fatalf("default CA: %+v %+v", c, p)
	}
	promptHas(t, e.f, whileLockedLine)
	args := e.createArgs("hydra")
	args["onlyWhenUnlocked"] = "true"
	if c, p = e.create(t, args); p != nil || c.CA == nil || c.CA.WhileLocked {
		t.Fatalf("--only-when-unlocked CA: %+v %+v", c, p)
	}
	promptHas(t, e.f, onlyWhenUnlockedLine)
	if ca, err := e.d.k8sCA.Get("hydra"); err != nil || ca.Access != platform.AccessWhenUnlocked {
		t.Fatalf("hydra: %+v %v", ca, err)
	}
	logins := e.logins()
	if c, p = e.create(t, args); p != nil || e.logins() != logins {
		t.Fatalf("again, the same: %+v %+v", c, p)
	}
	for name, a := range map[string]map[string]string{"hydra": e.createArgs("hydra"), "bot": args} {
		a["name"] = name
		_, p := e.create(t, a)
		if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "nazar k8s forget "+name) || e.logins() != logins {
			t.Fatalf("%s again with the other access: %+v", name, p)
		}
	}
	var l control.K8sContextList
	if err := e.call(t, control.CmdK8sList, nil, control.KindK8sContextList, &l); err != nil {
		t.Fatal(err)
	}
	for _, it := range l.Items {
		if it.CA == nil || it.CA.WhileLocked != (it.Name == "bot") {
			t.Errorf("list: %s %+v", it.Name, it.CA)
		}
	}
	if _, p := e.create(t, map[string]string{"name": "x", "server": e.pin.Server, "caSHA256": e.pin.CASHA256, "onlyWhenUnlocked": "on"}); p.ExitCode() != control.ExitUsage {
		t.Fatalf("onlyWhenUnlocked=on: %+v", p)
	}
}

// While the Mac is locked the chip makes no key that works only while it
// is unlocked: `ssh-key create --only-when-unlocked` (and --always-ask,
// which implies it) fails after the prompt with an error that says so
// (exit 1, an error, not the user's refusal), and nothing is left behind:
// no key, no public key file, config.yaml as it was. A key that works while
// locked is made as usual.
func TestSSHKeyCreateOnlyWhenUnlockedWhileLocked(t *testing.T) {
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	before := e.readConfig(t)
	e.f.SetLocked(true)
	for _, args := range []map[string]string{
		{"name": "work", "onlyWhenUnlocked": "true"},
		{"name": "prod", "alwaysAsk": "true"},
	} {
		name := args["name"]
		e.f.Advance(2 * time.Minute) // out of the cooldown an approval that made nothing starts
		p := control.AsProblem(e.call(t, control.CmdSSHKeyCreate, args, control.KindSSHKey, &control.SSHKey{}))
		if p == nil || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "the Mac is locked") {
			t.Fatalf("%s while locked: %+v", name, p)
		}
		if _, err := e.d.keys.Get(name); !errors.Is(err, keys.ErrNotFound) {
			t.Fatalf("%s: a key was left: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(layout.KeysDir(e.home), name+".pub")); !os.IsNotExist(err) {
			t.Fatalf("%s: a public key file was left: %v", name, err)
		}
		if got := e.readConfig(t); got != before {
			t.Fatalf("%s: config.yaml changed:\n%s", name, got)
		}
		if f := e.lastAudit(t); f["decision"] != "error" || !strings.Contains(f["reason"], "the Mac is locked") {
			t.Fatalf("%s: audit %v", name, f)
		}
	}
	e.f.Advance(2 * time.Minute)
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "bot"}, control.KindSSHKey, &k); err != nil || !k.WhileLocked {
		t.Fatalf("a while-locked key while locked: %+v %v", k, err)
	}
}
