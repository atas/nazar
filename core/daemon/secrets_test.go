package daemon

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/trust"
)

// Secrets design 3.4, 7.1–7.3, 8: secret add, list and rm on the
// control socket; values only ever go to the genuine nazar CLI; audit lines,
// replies and errors never carry a value; vault health covers secret/
// items.

// testValue is a value that looks like nothing real. Tests print its
// length, never the value.
const testValue = "nazar-m8-03-test-value-0d1f"

var cliCode = platform.CodeIdentity{Signed: true, TeamID: "NAZARTEAM0", SigningID: "dev.nazar.cli", CDHash: []byte{0x9a}}

func cliProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Args: append([]string{"nazar"}, args...), Code: cliCode}
}

func scriptProc(args ...string) fake.Proc {
	return fake.Proc{Path: "/bin/bash", Args: append([]string{"bash"}, args...), Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.bash")}
}

// genuineCLI stands in for the bridge's code-signature check of the peer
// (Options.VerifyCLI): the fake's peer of fd must be signed as the CLI by
// the CLI's team.
func genuineCLI(f *fake.Fake) func(fd int) (platform.ProcessRef, error) {
	return func(fd int) (platform.ProcessRef, error) {
		ref, err := f.PeerOf(fd)
		if err != nil {
			return platform.ProcessRef{}, err
		}
		p, err := f.Process(ref)
		if err != nil {
			return platform.ProcessRef{}, err
		}
		if p.Code.Team() != cliCode.TeamID || p.Code.SigningID != cliCode.SigningID {
			return platform.ProcessRef{}, errors.New("not the nazar CLI")
		}
		return ref, nil
	}
}

func startSecrets(t *testing.T) *env {
	t.Helper()
	return startWith(t, func(f *fake.Fake, o *Options) { o.VerifyCLI = genuineCLI(f) })
}

// asCLI makes the next control connections come from the nazar CLI run in
// an iTerm2 tab by procs (outermost first); it returns the CLI's ref.
func (e *env) asCLI(procs ...fake.Proc) platform.ProcessRef {
	tab := e.f.ITermTab(platform.ProcessRef{}, procs...)
	e.f.SetDefaultPeer(tab.Peer())
	return tab.Peer()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func (e *env) addSecret(t *testing.T, name, value string) (control.Secret, *control.Problem) {
	t.Helper()
	var s control.Secret
	err := e.call(t, control.CmdSecretAdd, map[string]string{"name": name, "valueBase64": b64(value)}, control.KindSecret, &s)
	return s, control.AsProblem(err)
}

func (e *env) approved(t *testing.T, body string) {
	t.Helper()
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.writeConfig(t, body)
	// A loosening waits for config apply; a tightening applies at once.
	// The write's own background prompt may hold the claim when apply
	// runs; it is answered Allow too and applies the same body.
	if diff, p := e.apply(t); p != nil && !strings.Contains(p.Message, "prompt is already open") {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	waitFor(t, func() bool { return string(e.d.stager.Active().Raw) == body })
}

func (e *env) opened(t *testing.T, name string) string {
	t.Helper()
	v, err := e.d.secrets.Open(name, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	return string(v)
}

// From a terminal tab, add writes the secret's own gate block plus one
// login rule for the tab's app, pins its team, and asks once; the prompt
// names the deliver list the entry gets. The value is stored sealed.
func TestSecretAddWritesTheTerminalRuleOnOnePrompt(t *testing.T) {
	e := startSecrets(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(fake.ClaudeProc(), cliProc("secret", "add", "GH_TOKEN"))
	s, p := e.addSecret(t, "GH_TOKEN", testValue)
	if p != nil {
		t.Fatal(p)
	}
	if s.Name != "GH_TOKEN" || !s.Stored || !s.Configured || s.Broken || s.Created == nil || s.APIVersion != "nazar/v1" ||
		strings.Join(s.Deliver, ",") != "helper,stdout" {
		t.Fatalf("%+v", s)
	}
	wantRule := `1: apps=[app:"com.googlecode.iterm2":""] to=[] gate=login scope=session expire=8h0m0s`
	if len(s.Rules) != 2 || s.Rules[0] != wantRule || s.Rules[1] != "fallback: gate=block" {
		t.Fatalf("rules %q", s.Rules)
	}
	cfg := e.readConfig(t)
	for _, want := range []string{"secrets:", "GH_TOKEN:", "gate: block", "app: com.googlecode.iterm2", "scope: session", "gate: login", "expire: 8h"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config.yaml lacks %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "claude") {
		t.Fatalf("the tool that ran add must get no rule:\n%s", cfg)
	}
	if team, ok := e.d.trust.PinnedTeam("com.googlecode.iterm2"); !ok || team != "H7V7XYVQ7D" {
		t.Fatalf("the approval must pin the terminal's team: %q %v", team, ok)
	}
	shown := e.f.Shown()
	if len(shown) != 1 || shown[0].Kind != fake.KindAuthenticate {
		t.Fatalf("one login prompt, got %+v", shown)
	}
	pr := shown[0].Prompt
	if pr.Title != `Add secret "GH_TOKEN"?` || !strings.Contains(strings.Join(pr.Lines, "\n"), "deliver: helper, stdout (the default; edit config.yaml to change it)") {
		t.Fatalf("prompt %q %q", pr.Title, pr.Lines)
	}
	if got := e.opened(t, "GH_TOKEN"); got != testValue {
		t.Fatalf("stored value has %d bytes, want %d", len(got), len(testValue))
	}
	if diff, p := e.apply(t); p == nil && diff.Applied {
		t.Fatal("the written entry must already be in force, nothing staged")
	}
	if st := e.status(t); st.Staged != nil {
		t.Fatalf("nothing staged after add: %+v", st.Staged)
	}
}

// A name config.yaml already has an entry for keeps that entry as it is;
// the prompt names the entry's own deliver list.
func TestSecretAddKeepsAnExistingEntry(t *testing.T) {
	e := startSecrets(t)
	const body = "apiVersion: nazar/v1\nkind: Config\nsecrets:\n  GH_TOKEN:\n    deliver: [helper]\n    gate: block\n"
	e.approved(t, body)
	e.asCLI(cliProc("secret", "add", "GH_TOKEN"))
	before := e.logins()
	if _, p := e.addSecret(t, "GH_TOKEN", testValue); p != nil {
		t.Fatal(p)
	}
	if e.readConfig(t) != body {
		t.Fatalf("an existing entry is kept as it is:\n%s", e.readConfig(t))
	}
	shown := e.f.Shown()
	if e.logins() != before+1 || !strings.Contains(strings.Join(shown[len(shown)-1].Prompt.Lines, "\n"), "deliver: helper (its entry in config.yaml)") {
		t.Fatalf("prompt %+v", shown[len(shown)-1].Prompt)
	}
}

// Without a terminal app (launchd, Nazar UI.app) the entry is only the
// secret's own block, and the prompt says so.
func TestSecretAddWithoutATerminalBlocksEveryone(t *testing.T) {
	e := startSecrets(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.f.SetDefaultPeer(e.f.Launch(platform.ProcessRef{}, cliProc("secret", "add", "X")))
	s, p := e.addSecret(t, "X", testValue)
	if p != nil || len(s.Rules) != 1 || s.Rules[0] != "fallback: gate=block" {
		t.Fatalf("%+v %v", s, p)
	}
	if lines := strings.Join(e.f.Shown()[0].Prompt.Lines, "\n"); !strings.Contains(lines, "no rule yet") {
		t.Fatalf("prompt %q", lines)
	}
}

// Every refusal comes before any prompt, except the prompt's own denial,
// and none stores or writes anything.
func TestSecretAddRefusals(t *testing.T) {
	e := startSecrets(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(cliProc("secret", "add"))
	if _, p := e.addSecret(t, "gh_token", testValue); p != nil {
		t.Fatal(p)
	}
	cfg, logins := e.readConfig(t), e.logins()
	add := func(args map[string]string) *control.Problem {
		return control.AsProblem(e.call(t, control.CmdSecretAdd, args, control.KindSecret, &control.Secret{}))
	}
	for _, c := range []struct {
		args map[string]string
		code int
		msg  string
	}{
		{map[string]string{"name": "a b", "valueBase64": b64("x")}, control.ExitUsage, `invalid secret name "a b"`},
		{map[string]string{"name": "X", "valueBase64": ""}, control.ExitUsage, "the value is empty"},
		{map[string]string{"name": "X", "valueBase64": "not base64!"}, control.ExitUsage, "not base64"},
		{map[string]string{"name": "X", "valueBase64": b64(strings.Repeat("v", 32<<10+1))}, control.ExitUsage, "larger than 32 KiB"},
		{map[string]string{"name": "gh_token", "valueBase64": b64("x")}, control.ExitError, `a secret named "gh_token" already exists`},
		{map[string]string{"name": "GH_TOKEN", "valueBase64": b64("x")}, control.ExitError, `a secret named "gh_token" already exists`},
	} {
		p := add(c.args)
		if p.ExitCode() != c.code || !strings.Contains(p.Message, c.msg) {
			t.Errorf("%s: got %+v, want exit %d with %q", c.args["name"], p, c.code, c.msg)
		}
	}
	if e.logins() != logins || e.readConfig(t) != cfg {
		t.Fatal("a refused add must show no prompt and write nothing")
	}
	// A denied prompt stores nothing and writes nothing.
	e.f.ScriptAuth(fake.Answer{Allow: false})
	if _, p := e.addSecret(t, "OTHER", testValue); p.ExitCode() != control.ExitRefused {
		t.Fatalf("denied: %+v", p)
	}
	if _, err := e.d.secrets.Get("OTHER"); !errors.Is(err, secrets.ErrNotFound) || e.readConfig(t) != cfg {
		t.Fatalf("a denied add must store and write nothing: %v", err)
	}
	// Unapproved changes in config.yaml: refused, staged, before any prompt.
	e.writeConfig(t, cfg+"  PLANTED:\n    deliver: [helper]\n    rules:\n      - apps: [{signed: {team: EVILTEAM00}}]\n        gate: none\n")
	n := e.logins()
	if _, p := e.addSecret(t, "THIRD", testValue); p.ExitCode() != control.ExitStaged || e.logins() != n {
		t.Fatalf("pending changes: %+v (%d prompts)", p, e.logins()-n)
	}
}

// Secret values never reach the audit log, a reply, an error, status or
// config.yaml, by add, list, rm or a refused get.
func TestSecretValueNeverLeavesThroughAnythingButGet(t *testing.T) {
	e := startSecrets(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(scriptProc("x.sh"), cliProc("secret", "add", "V"))
	if _, p := e.addSecret(t, "V", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.ScriptAuth(fake.Answer{Allow: false})
	_, denied := e.addSecret(t, "W", testValue)
	var l control.SecretList
	if err := e.call(t, control.CmdSecretList, nil, control.KindSecretList, &l); err != nil {
		t.Fatal(err)
	}
	// An approved get from the genuine CLI: its reply is the one place the
	// value goes; its audit line is searched like every other.
	e.asCLI(scriptProc("x.sh"), cliProc("get", "V"))
	e.f.ScriptAuth(fake.Answer{Allow: true})
	var got control.SecretValue
	if err := e.call(t, control.CmdSecretGet, map[string]string{"name": "V"}, control.KindSecretValue, &got); err != nil || got.ValueBase64 != b64(testValue) {
		t.Fatalf("approved get: %v", err)
	}
	e.f.SetDefaultPeer(e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/fake-nazar", Code: fake.Unsigned}))
	getErr := e.call(t, control.CmdSecretGet, map[string]string{"name": "V"}, control.KindSecretValue, &control.SecretValue{})
	e.asCLI(cliProc("secret", "rm", "V"))
	e.f.ScriptAuth(fake.Answer{Allow: true})
	var rm control.Secret
	rmErr := e.call(t, control.CmdSecretDelete, map[string]string{"name": "V"}, control.KindSecret, &rm)
	st, _ := json.Marshal(e.status(t))
	list, _ := json.Marshal(l)
	rmJSON, _ := json.Marshal(rm)
	everything := strings.Join(append(e.sink.Lines(), string(st), string(list), string(rmJSON), e.readConfig(t),
		control.AsProblem(denied).Error(), control.AsProblem(getErr).Error(), control.AsProblem(rmErr).Error()), "\n")
	for _, form := range []string{testValue, b64(testValue), base64.RawStdEncoding.EncodeToString([]byte(testValue))} {
		if strings.Contains(everything, form) {
			t.Fatalf("a form of the value (%d bytes) leaked", len(form))
		}
	}
}

// list shows stored and configured secrets, never a value: a configured
// name with nothing stored, a broken record with its fix.
func TestSecretList(t *testing.T) {
	e := startSecrets(t)
	e.approved(t, "apiVersion: nazar/v1\nkind: Config\nsecrets:\n  WANTED: {gate: block}\n")
	e.asCLI(cliProc("secret", "add"))
	if _, p := e.addSecret(t, "HAVE", testValue); p != nil {
		t.Fatal(p)
	}
	e.vault.Put(secrets.VaultPrefix+"BROKEN", []byte("{not a record"))
	var l control.SecretList
	if err := e.call(t, control.CmdSecretList, nil, control.KindSecretList, &l); err != nil {
		t.Fatal(err)
	}
	got := map[string]control.Secret{}
	for _, s := range l.Items {
		got[s.Name] = s
	}
	if len(l.Items) != 3 || l.APIVersion != "nazar/v1" {
		t.Fatalf("items %+v", l.Items)
	}
	if s := got["HAVE"]; !s.Stored || !s.Configured || s.Broken || s.Created == nil || len(s.Rules) != 2 {
		t.Fatalf("HAVE %+v", s)
	}
	if s := got["WANTED"]; s.Stored || !s.Configured || s.Created != nil || s.Rules[0] != "fallback: gate=block" {
		t.Fatalf("WANTED %+v", s)
	}
	if s := got["BROKEN"]; !s.Stored || s.Configured || !s.Broken || s.UnusableReason == "" || s.Remedy != secretRemedy("BROKEN") {
		t.Fatalf("BROKEN %+v", s)
	}
}

// rm erases the secret behind the login gate, keeps config.yaml, and drops
// the secret's remembered approvals; an absent or unreadable secret is
// refused before any prompt.
func TestSecretRm(t *testing.T) {
	e, v := startAfterRebuildWith(t, func(string) string { return keyConfig })
	for _, item := range []string{PromptsVaultItem, trust.VaultItem, configstage.ApprovedVaultItem} {
		v.securityDelete(item)
	}
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply %+v %+v", diff, p)
	}
	e.asCLI(cliProc("secret", "add"))
	if _, p := e.addSecret(t, "GONE", testValue); p != nil {
		t.Fatal(p)
	}
	cfg := e.readConfig(t)
	rm := func(name string) (control.Secret, *control.Problem) {
		var s control.Secret
		err := e.call(t, control.CmdSecretDelete, map[string]string{"name": name}, control.KindSecret, &s)
		return s, control.AsProblem(err)
	}
	before := e.logins()
	s, p := rm("GONE")
	if p != nil || s.Name != "GONE" || s.Stored || !s.Configured {
		t.Fatalf("rm: %+v %+v", s, p)
	}
	if e.logins() != before+1 || e.f.Shown()[len(e.f.Shown())-1].Prompt.Title != `Delete secret "GONE"?` {
		t.Fatal("rm asks once on the login gate")
	}
	if _, err := e.d.secrets.Get("GONE"); !errors.Is(err, secrets.ErrNotFound) || e.readConfig(t) != cfg {
		t.Fatalf("rm erases the secret and keeps config.yaml: %v", err)
	}
	n := e.logins()
	if _, p := rm("GONE"); p.ExitCode() != control.ExitError ||
		p.Message != `no secret named "GONE"; config.yaml keeps its entry: nazar secret add GONE stores one for it` {
		t.Fatalf("rm of a gone secret with an entry: %+v", p)
	}
	if _, p := rm("NOPE"); p.ExitCode() != control.ExitError || p.Message != `no secret named "NOPE"` {
		t.Fatalf("rm of an unknown name: %+v", p)
	}
	// Another build's item: refused with the fix, nothing changed.
	v.Vault.Put(secrets.VaultPrefix+"OLD", []byte("written by the previous build"))
	v.mu.Lock()
	v.foreign[secrets.VaultPrefix+"OLD"] = true
	v.mu.Unlock()
	if _, p := rm("OLD"); p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "nothing was changed. To fix it: "+secretRemedy("OLD")) {
		t.Fatalf("rm of an unreadable secret: %+v", p)
	}
	if e.logins() != n {
		t.Fatal("refused rm must show no prompt")
	}
	if _, err := v.Vault.Get(secrets.VaultPrefix + "OLD"); err != nil {
		t.Fatal("the unreadable item must stay")
	}
}

const getConfig = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
secrets:
  NOTES:
    rules:
      - apps: [iterm]
        to: [{signed: {team: apple, id: com.apple.bash}}]
        scope: session
        gate: dialog
`

// secret.get answers only the genuine nazar CLI. Any other peer, even of
// the same user in the same tab, is refused before the pipeline: audited
// as blocked with the reason, no dialog, the secret never opened.
func TestSecretGetAnswersOnlyTheGenuineCLI(t *testing.T) {
	e := startSecrets(t)
	e.approved(t, getConfig)
	e.asCLI(cliProc("secret", "add", "NOTES"))
	if _, p := e.addSecret(t, "NOTES", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	get := func() (control.SecretValue, *control.Problem) {
		var v control.SecretValue
		err := e.call(t, control.CmdSecretGet, map[string]string{"name": "NOTES"}, control.KindSecretValue, &v)
		return v, control.AsProblem(err)
	}

	e.asCLI(scriptProc("deploy.sh"), cliProc("get", "NOTES"))
	v, p := get()
	if p != nil || v.Name != "NOTES" || v.ValueBase64 != b64(testValue) {
		t.Fatalf("the genuine CLI under a matching rule: %v (name %q, %d bytes)", p, v.Name, len(v.ValueBase64))
	}
	last := e.auditFor(t, "secret:NOTES")
	if f := last[len(last)-1]; f["decision"] != string(audit.Approved) || f["delivery"] != "stdout" || !strings.HasPrefix(f["receiver"], "bash ") {
		t.Fatalf("audit %v", f)
	}

	dialogs := e.f.CountShown(fake.KindConfirm)
	for _, fakeCLI := range []fake.Proc{
		{Path: "/Users/u/.local/bin/nazar", Args: []string{"nazar", "get", "NOTES"}, Code: fake.Unsigned},
		{Path: "/opt/evil/nazar", Args: []string{"nazar"}, Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "dev.nazar.cli"}},
		{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Code: platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "dev.nazar.cli"}},
	} {
		e.asCLI(scriptProc("deploy.sh"), fakeCLI)
		_, p := get()
		if p.ExitCode() != control.ExitRefused || p.Message != "peer is not the nazar CLI" {
			t.Fatalf("%s: %+v", fakeCLI.Path, p)
		}
		lines := e.auditFor(t, "secret:NOTES")
		if f := lines[len(lines)-1]; f["decision"] != string(audit.Blocked) || f["reason"] != "peer is not the nazar CLI" || f["delivery"] != "stdout" {
			t.Fatalf("%s: audit %v", fakeCLI.Path, f)
		}
	}
	if e.f.CountShown(fake.KindConfirm) != dialogs {
		t.Fatal("a peer that is not the CLI must never reach a dialog")
	}
}

// Without the bridge's check (VerifyCLI nil: every build but the agent's)
// no value is returned to anyone.
func TestSecretGetWithoutAPeerCheckReturnsNothing(t *testing.T) {
	e := start(t)
	e.approved(t, getConfig)
	e.asCLI(cliProc("secret", "add", "NOTES"))
	if _, p := e.addSecret(t, "NOTES", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.asCLI(scriptProc("deploy.sh"), cliProc("get", "NOTES"))
	err := e.call(t, control.CmdSecretGet, map[string]string{"name": "NOTES"}, control.KindSecretValue, &control.SecretValue{})
	if p := control.AsProblem(err); p.ExitCode() != control.ExitRefused || p.Message != "peer is not the nazar CLI" {
		t.Fatalf("%+v", p)
	}
}

// get follows the pipeline: the receiver is the CLI's parent, a refusal is
// exit 3 with nothing returned, a name without a stored secret is an error
// before any prompt.
func TestSecretGetRefusals(t *testing.T) {
	e := startSecrets(t)
	e.approved(t, strings.Replace(getConfig, "  NOTES:\n", "  EMPTY: {gate: block}\n  NOTES:\n", 1))
	e.asCLI(cliProc("secret", "add", "NOTES"))
	if _, p := e.addSecret(t, "NOTES", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	get := func(name string) *control.Problem {
		return control.AsProblem(e.call(t, control.CmdSecretGet, map[string]string{"name": name}, control.KindSecretValue, &control.SecretValue{}))
	}
	// python is not to: bash: blocked, exit 3.
	e.asCLI(fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "x.py"}, Code: fake.AppleCode("com.apple.python3")}, cliProc("get", "NOTES"))
	if p := get("NOTES"); p.ExitCode() != control.ExitRefused {
		t.Fatalf("receiver outside to:: %+v", p)
	}
	n := e.f.CountShown(fake.KindConfirm)
	e.asCLI(scriptProc("x.sh"), cliProc("get"))
	if p := get("EMPTY"); p.ExitCode() != control.ExitError || p.Message != `no secret named "EMPTY"` {
		t.Fatalf("configured, not stored: %+v", p)
	}
	if p := get("a b"); p.ExitCode() != control.ExitUsage {
		t.Fatalf("invalid name: %+v", p)
	}
	if e.f.CountShown(fake.KindConfirm) != n {
		t.Fatal("no prompt for a secret that is not stored")
	}
	e.f.ScriptConfirm(fake.Answer{Allow: false})
	if p := get("NOTES"); p.ExitCode() != control.ExitRefused {
		t.Fatalf("denied dialog: %+v", p)
	}
}

// A configured secret with nothing stored is a warning in config check and
// status that names the command that stores it.
func TestConfiguredButNotStoredIsAWarning(t *testing.T) {
	e := startSecrets(t)
	e.approved(t, "apiVersion: nazar/v1\nkind: Config\nsecrets:\n  WANTED: {gate: block}\n")
	want := "secret WANTED is configured but not stored; run `nazar secret add WANTED`"
	var cc control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &cc); err != nil {
		t.Fatal(err)
	}
	has := func(ps []control.ConfigProblem) bool {
		for _, p := range ps {
			if p.Message == want && p.Severity == "warning" && p.Path == "secrets.WANTED" {
				return true
			}
		}
		return false
	}
	if !cc.Valid || !has(cc.Problems) {
		t.Fatalf("config check %+v", cc.Problems)
	}
	if st := e.status(t); !has(st.Problems) {
		t.Fatalf("status %+v", st.Problems)
	}
	e.asCLI(cliProc("secret", "add"))
	if _, p := e.addSecret(t, "WANTED", testValue); p != nil {
		t.Fatal(p)
	}
	if st := e.status(t); has(st.Problems) {
		t.Fatal("stored now")
	}
}

var secretAddStep = regexp.MustCompile(`^nazar secret add ([A-Za-z0-9_./-]+)$`)

// Vault health covers secret/ items with the rules of keys (spec 9): the
// check that loses nothing first, then the item deleted by hand, then the
// secret added again; a name nazar can't make gets the delete only. The
// steps, followed top to bottom, make the secret usable with one prompt.
func TestVaultHealthCoversSecrets(t *testing.T) {
	e, v := startAfterRebuild(t)
	for _, item := range []string{PromptsVaultItem, trust.VaultItem, configstage.ApprovedVaultItem, "ssh-key/github"} {
		v.securityDelete(item)
	}
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply %+v %+v", diff, p)
	}
	for _, n := range []string{secrets.VaultPrefix + "OLD", secrets.VaultPrefix + "bad name"} {
		v.Vault.Put(n, []byte("written by the previous build"))
		v.mu.Lock()
		v.foreign[n] = true
		v.mu.Unlock()
	}
	st := e.status(t)
	byItem := map[string]control.VaultProblem{}
	for _, p := range st.Vault {
		byItem[p.Item] = p
	}
	old, ok := byItem[secrets.VaultPrefix+"OLD"]
	if !ok || old.Remedy != secretRemedy("OLD") || !strings.HasPrefix(old.Remedy, secretCheckFirst) ||
		!strings.HasSuffix(old.Remedy, "security delete-generic-password -s dev.nazar -a secret/OLD, then nazar secret add OLD") ||
		!strings.Contains(old.Effect, "OLD") {
		t.Fatalf("OLD %+v", old)
	}
	foreign, ok := byItem[`"secret/bad name"`]
	if !ok || strings.Contains(foreign.Remedy, "nazar secret") || strings.Contains(foreign.Remedy, "security delete") {
		t.Fatalf("a name nazar can't make gets no command: %+v (all: %+v)", foreign, st.Vault)
	}
	e.asCLI(cliProc("secret", "add"))
	before := e.logins()
	for _, step := range strings.Split(strings.TrimPrefix(old.Remedy, secretCheckFirst), ", then ") {
		if m := deleteStep.FindStringSubmatch(step); m != nil {
			if err := v.securityDelete(m[1]); err != nil {
				t.Fatal(err)
			}
		} else if m := secretAddStep.FindStringSubmatch(step); m != nil {
			if _, p := e.addSecret(t, m[1], testValue); p != nil {
				t.Fatalf("%s: %+v", step, p)
			}
		} else {
			t.Fatalf("remedy step %q is not one the user can follow", step)
		}
	}
	if e.logins()-before != 1 || e.opened(t, "OLD") != testValue {
		t.Fatal("the fix must make the secret usable with one prompt")
	}
	for _, p := range e.status(t).Vault {
		if p.Item == secrets.VaultPrefix+"OLD" {
			t.Fatalf("still reported: %+v", p)
		}
	}
}

// A rule naming an app gives the value to any child of it with no prompt and
// no to:; a program outside the app gets nothing, and no prompt either.
func TestSecretGetSilentForAChildOfTheNamedApp(t *testing.T) {
	e := startSecrets(t)
	e.approved(t, strings.Replace(strings.Replace(getConfig, "        to: [{signed: {team: apple, id: com.apple.bash}}]\n", "", 1), "        scope: session\n        gate: dialog\n", "        gate: none\n", 1))
	e.asCLI(cliProc("secret", "add", "NOTES"))
	if _, p := e.addSecret(t, "NOTES", testValue); p != nil {
		t.Fatal(p)
	}
	e.f.SetDefaults(fake.Answer{}, fake.Answer{}) // a prompt would be refused
	logins, dialogs := e.f.CountShown(fake.KindAuthenticate), e.f.CountShown(fake.KindConfirm)
	get := func() (control.SecretValue, *control.Problem) {
		var v control.SecretValue
		err := e.call(t, control.CmdSecretGet, map[string]string{"name": "NOTES"}, control.KindSecretValue, &v)
		return v, control.AsProblem(err)
	}

	e.asCLI(scriptProc("deploy.sh"), cliProc("get", "NOTES"))
	if v, p := get(); p != nil || v.ValueBase64 != b64(testValue) {
		t.Fatalf("a child of the named app: %v (%d bytes)", p, len(v.ValueBase64))
	}

	other := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Other.app/Contents/MacOS/Other", Code: platform.CodeIdentity{Signed: true, TeamID: "OTHERTEAM0", SigningID: "com.example.other"}, App: &fake.App{BundleID: "com.example.other", Name: "Other"}})
	e.f.SetDefaultPeer(e.f.Launch(other, cliProc("get", "NOTES")))
	if v, p := get(); p.ExitCode() != control.ExitRefused || v.ValueBase64 != "" {
		t.Fatalf("a program outside the app: %+v (%d bytes)", p, len(v.ValueBase64))
	}

	if e.f.CountShown(fake.KindAuthenticate) != logins || e.f.CountShown(fake.KindConfirm) != dialogs {
		t.Fatal("neither request may show a prompt")
	}
}
