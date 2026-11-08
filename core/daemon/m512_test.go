package daemon

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// What the final security review of Milestone 5 found.
//
// config.edit edits only a file that holds exactly the approved config. It
// used to observe the file first (staging whatever it held and marking it
// seen, so the background prompt for a hand edit never came) and then
// report Staged whenever the file as a whole was staged: a tightening or a
// no-op edit on a file that held someone else's loosening came back as
// "staged" (exit 4), the CLI told the user their change loosened access,
// and the window ran `nazar config apply` for it, putting the login prompt
// for the other change in front of the user as if it were theirs.

// handLoosened is editBase with hydra's own gate loosened (login → dialog),
// as a hand edit (or another process) would write it.
var handLoosened = strings.Replace(editBase, "      scope: use\n      gate: login\n", "      scope: use\n      gate: dialog\n", 1)

// handTightened is editBase with hydra blocked: a tightening.
var handTightened = strings.Replace(editBase, "      scope: use\n      gate: login\n", "      gate: block\n", 1)

// notApproved checks the refusal of an edit on a file that differs from
// the approved config: a plain error (exit 1), never exit 4, which the
// window answers with `nazar config apply`, and a message that names the
// pending change and both ways out.
func notApproved(t *testing.T, what string, res control.ConfigEdit, p *control.Problem) {
	t.Helper()
	if p == nil {
		t.Fatalf("%s: accepted (%+v); want a refusal: config.yaml has changes that are not approved yet", what, res)
	}
	if p.Code != control.CodeError || p.ExitCode() != control.ExitError {
		t.Fatalf("%s: %+v; want code %q (exit 1), never staged (exit 4)", what, p, control.CodeError)
	}
	for _, w := range []string{"not approved yet", "nazar config apply", "revert"} {
		if !strings.Contains(p.Message, w) {
			t.Fatalf("%s: message %q does not say %q", what, p.Message, w)
		}
	}
}

// pendingEdits are tightening, no-op and loosening edits of editBase.
var pendingEdits = []map[string]string{
	{"op": control.EditRuleRemove, "key": "github", "index": "1"},                                          // tightens
	{"op": control.EditRuleSet, "key": "github", "index": "1", "gate": "dialog"},                           // what the file already says
	{"op": control.EditRuleAdd, "key": "github", "apps": refs("kubectl"), "gate": "login", "scope": "use"}, // loosens
	{"op": control.EditKeySet, "key": "hydra", "gate": "block"},                                            // tightens
}

// A change someone else staged (a hand edit, or another process) blocks
// every edit: nothing is written, the staged change and the config in
// force stay exactly as they were, and the reply is never "staged".
func TestEditRefusedWhileAHandEditIsStaged(t *testing.T) {
	e := startEdit(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{}) // the background prompt for the hand edit is denied
	e.stage(t, handLoosened, false)
	waitFor(t, func() bool { return len(e.configAudit(t, audit.Denied)) == 1 })
	hash := e.pendingHash(t)
	active := e.d.stager.Active().Hash
	logins := e.logins()
	for _, args := range pendingEdits {
		res, p := e.edit(t, args)
		notApproved(t, args["op"]+" "+args["key"], res, p)
		if e.readConfig(t) != handLoosened {
			t.Fatalf("%v wrote config.yaml:\n%s", args, e.readConfig(t))
		}
		if e.pendingHash(t) != hash || e.d.stager.Active().Hash != active {
			t.Fatalf("%v changed what is staged or in force", args)
		}
	}
	// With the file's current hash as ifHash: still refused.
	args := map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block", "ifHash": contentHash([]byte(handLoosened))}
	res, p := e.edit(t, args)
	notApproved(t, "with a matching ifHash", res, p)
	if e.readConfig(t) != handLoosened {
		t.Fatal("a refused edit wrote config.yaml")
	}
	settle()
	if e.logins() != logins {
		t.Fatal("a refused edit must not open a prompt")
	}
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "login" {
		t.Fatalf("hydra gate in force: %s", g)
	}
}

// The edit's own staged loosening blocks the next edit too, until it is
// approved: each staged change is exactly one edit, so what `config apply`
// shows is what the user asked for.
func TestEditRefusedAfterItsOwnStagedLoosening(t *testing.T) {
	e := startEdit(t)
	res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
	if p != nil || res.Staged == nil || !res.Changed {
		t.Fatalf("stage a loosening: %+v %+v", res, p)
	}
	staged := e.readConfig(t)
	hash := e.pendingHash(t)
	for _, args := range pendingEdits {
		res, p := e.edit(t, args)
		notApproved(t, args["op"]+" "+args["key"]+" on a staged edit", res, p)
		if e.readConfig(t) != staged || e.pendingHash(t) != hash {
			t.Fatalf("%v changed config.yaml or the staged change", args)
		}
	}
	// The same loosening again is refused too (it is not "staged" by this
	// call: nothing was written).
	res, p = e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
	notApproved(t, "the staged loosening again", res, p)
	// Once approved, edits work again, and a tightening is in force at once.
	if diff, p := e.apply(t); p != nil || !diff.Applied {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	res, p = e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"})
	if p != nil || !res.Applied || res.Staged != nil || !res.Changed {
		t.Fatalf("tightening after the approval: %+v %+v", res, p)
	}
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "block" {
		t.Fatalf("hydra gate in force: %s", g)
	}
}

// startQuiet is startEdit with the file poller effectively off (one tick
// an hour), so the test decides when the daemon looks at config.yaml
// (e.d.Reload, as the poller's tick does).
func startQuiet(t *testing.T) *env {
	t.Helper()
	e := startWith(t, func(f *fake.Fake, o *Options) { o.Now = f.Now; o.PollInterval = time.Hour })
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.writeConfig(t, editBase)
	e.d.Reload()
	waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["github"] != nil })
	waitFor(t, func() bool { return !e.isOpen() })
	return e
}

// An edit never swallows the background prompt for a hand edit it hasn't
// seen yet: it neither stages the hand edit nor marks it seen, so the
// poller's next look prompts for it exactly as without the edit.
func TestEditNeverSwallowsTheHandEditPrompt(t *testing.T) {
	for _, args := range pendingEdits {
		t.Run(args["op"]+" "+args["key"], func(t *testing.T) {
			e := startQuiet(t)
			logins := e.logins()
			e.writeConfig(t, handLoosened) // not observed yet
			res, p := e.edit(t, args)
			notApproved(t, "an unobserved hand edit", res, p)
			if e.readConfig(t) != handLoosened {
				t.Fatalf("the edit wrote over the hand edit:\n%s", e.readConfig(t))
			}
			if _, ok := e.d.stager.Pending(); ok {
				t.Fatal("the edit staged the hand edit itself (without its prompt)")
			}
			if e.logins() != logins {
				t.Fatal("the edit opened a prompt")
			}
			e.d.Reload() // the poller's next tick
			waitFor(t, func() bool { return e.logins() == logins+1 })
			waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate == "dialog" })
		})
	}
}

// An unobserved hand tightening blocks the edit the same way (the file is
// not the approved config); once the daemon has seen it, it is in force
// without a prompt and the edit goes through.
func TestEditRefusedOnAnUnobservedTightening(t *testing.T) {
	e := startQuiet(t)
	logins := e.logins()
	e.writeConfig(t, handTightened)
	args := map[string]string{"op": control.EditRuleRemove, "key": "github", "index": "1"}
	res, p := e.edit(t, args)
	notApproved(t, "an unobserved tightening", res, p)
	if e.readConfig(t) != handTightened {
		t.Fatal("a refused edit wrote config.yaml")
	}
	e.d.Reload()
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "block" {
		t.Fatalf("the hand tightening is not in force: %s", g)
	}
	res, p = e.edit(t, args)
	if p != nil || !res.Applied || !res.Changed {
		t.Fatalf("after the tightening applied: %+v %+v", res, p)
	}
	if e.logins() != logins {
		t.Fatal("tightenings need no prompt")
	}
}

// After a rebuild the approved config can't be read, so the built-in
// default (every key blocked) is in force and config.yaml waits for the
// gate. An edit then is refused rather than staged: the staged change is
// the whole file, not the edit.
func TestEditRefusedWhileTheApprovedConfigIsUnreadable(t *testing.T) {
	e, _ := startAfterRebuild(t)
	res, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "github", "gate": "block"})
	notApproved(t, "approved config unreadable", res, p)
	if e.readConfig(t) != keyConfig {
		t.Fatal("a refused edit wrote config.yaml")
	}
}

// On a file that is the approved config, a loosening edit stages exactly
// its own change: every change and loosening the reply lists is about the
// key it edited.
func TestLooseningEditStagesOnlyItsOwnChange(t *testing.T) {
	e := startEdit(t)
	res, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "hydra", "apps": refs("iterm"), "gate": "dialog", "scope": "session"})
	if p != nil || res.Staged == nil || !res.Staged.Loosens || res.Applied {
		t.Fatalf("%+v %+v", res, p)
	}
	if len(res.Staged.Changes) == 0 || len(res.Staged.Loosening) == 0 {
		t.Fatalf("staged diff %+v", res.Staged)
	}
	for _, c := range append(append([]string{}, res.Staged.Changes...), res.Staged.Loosening...) {
		if !strings.Contains(c, "hydra") || strings.Contains(c, "github") {
			t.Errorf("the diff of an edit of hydra lists %q", c)
		}
	}
	if pend, ok := e.d.stager.Pending(); !ok || !bytes.Equal(pend.Config.Raw, []byte(e.readConfig(t))) || res.Staged.Hash != pend.Config.Hash {
		t.Fatal("the reply's diff is not the staged change")
	}
}

// A key made again under its existing entry (after its vault record was
// removed by hand, the remedy of an unreadable key) starts with no
// approvals: approvals remembered for the old key never sign with the new
// one. Approvals for other keys stay.
func TestRecreateRevokesApprovalsOfTheOldKey(t *testing.T) {
	e := start(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	now := e.f.Now()
	e.d.cache.Put(approval.Entry{Key: approval.Key{Target: "ssh:github", Rule: "fallback", ScopeID: "session:1"}, Scope: "session", Created: now})
	e.d.cache.Put(approval.Entry{Key: approval.Key{Target: "ssh:github", Rule: "1", ScopeID: "app:T:x"}, Scope: "app", Created: now})
	e.d.cache.Put(approval.Entry{Key: approval.Key{Target: "ssh:deploy", Rule: "1", ScopeID: "session:1"}, Scope: "session", Created: now})
	if err := e.vault.Delete(keys.VaultPrefix + "github"); err != nil { // `security delete-generic-password …`
		t.Fatal(err)
	}
	var k control.SSHKey
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &k); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	var left []string
	for _, en := range e.d.cache.List() {
		left = append(left, en.Key.Target)
	}
	if strings.Join(left, ",") != "ssh:deploy" {
		t.Fatalf("approvals after re-creating github: %v; want only ssh:deploy's", left)
	}
}

// deletedClaudePeer returns a control peer whose chain has a program at
// path, signed as code, running from a file that is gone since (Claude
// Code after its auto-update), with the CLI below it.
func deletedClaudePeer(e *env, path string, code platform.CodeIdentity) platform.ProcessRef {
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: path, Args: []string{"claude"}, Code: code}, fake.Proc{Path: "/x/Nazar.app/Contents/MacOS/nazar", Code: fake.Unsigned})
	info, _ := e.f.Process(tab.Procs[0])
	info.Path = ""
	e.f.SetProcess(info)
	return tab.Peer()
}

// Control commands are audited with the CLI's chain the same way the
// broker logs a sign: a deleted file is marked outside the name
// (name(pid, …, deleted)), so a binary literally named
// "claude-code (file deleted)" can't pass for it in `nazar log`.
func TestControlAuditMarksADeletedFileOutsideTheName(t *testing.T) {
	e := start(t)
	peer := deletedClaudePeer(e, "/Users/u/.local/share/claude/versions/2.1.299", fake.ClaudeCode)
	e.d.logOp("config", audit.Allowed, "m512 deleted probe", e.d.resolver.Resolve(peer))
	lit := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/claude-code (file deleted)", Code: fake.Unsigned})
	e.d.logOp("config", audit.Allowed, "m512 literal probe", e.d.resolver.Resolve(lit.Peer()))
	var deleted, literal map[string]string
	for _, l := range e.auditFor(t, "config") {
		switch l["reason"] {
		case "m512 deleted probe":
			deleted = l
		case "m512 literal probe":
			literal = l
		}
	}
	if deleted == nil || literal == nil {
		t.Fatal("probe lines missing")
	}
	if strings.Contains(deleted["chain"], "(file deleted)") {
		t.Fatalf("the mark is inside the name: %q", deleted["chain"])
	}
	procs, err := audit.ParseChain(deleted["chain"])
	if err != nil {
		t.Fatal(err)
	}
	var marked []audit.Proc
	for _, p := range procs {
		if p.Deleted {
			marked = append(marked, p)
		}
	}
	if len(marked) != 1 || marked[0].Name != "claude-code" || marked[0].Identity != "Q6L2SF6YDW:com.anthropic.claude-code" {
		t.Fatalf("deleted elements %+v in %q", marked, deleted["chain"])
	}
	lp, err := audit.ParseChain(literal["chain"])
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range lp {
		if p.Deleted {
			t.Fatalf("a live binary is marked deleted: %+v in %q", p, literal["chain"])
		}
	}
	if !strings.Contains(literal["chain"], `"claude-code (file deleted)"(`) {
		t.Fatalf("the literal name must be one quoted name: %q", literal["chain"])
	}
}

// The window's "last used" chain is the audit chain, built by the same
// code: names quoted (a process named "a > b" is one element, never two),
// PIDs and identities shown, the deleted mark outside the name.
func TestKeyUseChainIsTheAuditChain(t *testing.T) {
	var u keyUses
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	chain := []audit.Proc{{Name: "iTerm2", PID: 1}, {Name: "a > b", PID: 2}, {Name: "claude-code", PID: 3, Identity: "Q6L2SF6YDW:com.anthropic.claude-code", Deleted: true},
		{Name: "x\n‮", PID: 4}, {Name: "ssh", PID: 5}}
	u.record(audit.Event{Time: now, Decision: audit.Approved, Target: "ssh:github", Gate: "dialog", Chain: chain})
	use := u.last("github")
	if use == nil {
		t.Fatal("no use recorded")
	}
	if use.Chain != audit.FormatChain(chain) {
		t.Fatalf("chain %q, want the audit chain %q", use.Chain, audit.FormatChain(chain))
	}
	got, err := audit.ParseChain(use.Chain)
	if err != nil || len(got) != len(chain) {
		t.Fatalf("ParseChain(%q) = %+v, %v", use.Chain, got, err)
	}
	for i := range chain {
		if got[i] != chain[i] {
			t.Errorf("element %d = %+v, want %+v", i, got[i], chain[i])
		}
	}
}

// Milestone 6: the agent has no window, so the control command ui.show
// is gone: it is an unknown command like any other, exit 2.
func TestUIShowIsGone(t *testing.T) {
	e := start(t)
	p := control.AsProblem(e.call(t, "ui.show", nil, control.KindUI, &struct{}{}))
	if p == nil || p.ExitCode() != control.ExitUsage || !strings.Contains(p.Message, `unknown command "ui.show"`) {
		t.Fatalf("%+v", p)
	}
}

// Nothing of ui.show is left behind for an old CLI (or a forged request)
// to reach: no command constant, no reply type, no window hook in the
// options, in the control API or the daemon.
func TestNoWindowInTheCore(t *testing.T) {
	var srcs []string
	for _, g := range []string{"*.go", "../control/*.go"} {
		m, err := filepath.Glob(g)
		if err != nil || len(m) == 0 {
			t.Fatal(g, m, err)
		}
		srcs = append(srcs, m...)
	}
	for _, f := range srcs {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{`"ui.show"`, "CmdUIShow", "UIShown", "ShowWindow", "uiShow"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s still has %s", f, bad)
			}
		}
	}
}

// applyHash is `nazar config apply --hash want`.
func (e *env) applyHash(t *testing.T, want string) (control.ConfigDiff, *control.Problem) {
	t.Helper()
	var diff control.ConfigDiff
	err := e.call(t, control.CmdConfigApply, map[string]string{"hash": want}, control.KindConfigDiff, &diff)
	return diff, control.AsProblem(err)
}

// The CLI answers its own staged edit with a config.apply bound to the
// hash of the change the edit staged. A process that rewrites config.yaml between
// the two (a watcher of the file sees the edit land) must not get its own
// lines into the prompt the user expects for their edit, sorted ahead of
// them: with the hash bound, config apply observes the rewrite, asks
// nothing, applies nothing and says so with a plain error (exit 1, never 4,
// which the window would answer with config apply again). The rewrite stays
// staged, reported blocked once like any change nobody asked about. Once
// the file holds the edit's change again, the same call shows exactly one
// prompt and applies it; asked again, it says nothing is staged.
func TestConfigApplyIsBoundToTheStagedHash(t *testing.T) {
	e := startQuiet(t)
	res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
	if p != nil || res.Staged == nil {
		t.Fatalf("edit: %+v %+v", res, p)
	}
	want := res.Staged.Hash
	edited := e.readConfig(t)
	if want != contentHash([]byte(edited)) {
		t.Fatalf("the staged hash %s is not the edit's content hash", want)
	}
	attacker := strings.Replace(edited, "      scope: use\n      gate: login\n", "      scope: use\n      gate: dialog\n", 1)
	if attacker == edited {
		t.Fatal("the rewrite changed nothing")
	}
	logins := e.logins()
	warnings := len(e.f.Warnings())
	e.writeConfig(t, attacker) // lands between the window's edit and its config apply

	diff, p := e.applyHash(t, want)
	if p == nil {
		t.Fatalf("config apply --hash of the edit applied the rewrite: %+v", diff)
	}
	if p.Code != control.CodeError || p.ExitCode() != control.ExitError {
		t.Fatalf("%+v; want code %q (exit 1), never staged (4) or refused (3)", p, control.CodeError)
	}
	for _, w := range []string{"changed since", "nothing was asked", "nazar config check"} {
		if !strings.Contains(p.Message, w) {
			t.Fatalf("message %q does not say %q", p.Message, w)
		}
	}
	settle()
	if e.logins() != logins {
		t.Fatalf("a refused config apply --hash showed %d login prompt(s)", e.logins()-logins)
	}
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "login" {
		t.Fatalf("hydra gate in force: %s", g)
	}
	if pend, ok := e.d.stager.Pending(); !ok || string(pend.Config.Raw) != attacker {
		t.Fatal("the rewrite must stay staged, as it is")
	}
	var refused []map[string]string
	for _, l := range e.configAudit(t, audit.Blocked) {
		if l["reason"] == "config apply: the staged change is not the one asked for" {
			if l["chain"] == "" && l["session"] == "" {
				t.Fatalf("the refusal must name its caller: %v", l)
			}
			refused = append(refused, l)
		}
	}
	if len(refused) != 1 {
		t.Fatalf("%d refusal lines; want 1", len(refused))
	}
	if n := len(e.contentBlocked(t)); n != 1 {
		t.Fatalf("%d per-content blocked lines; want the rewrite's one", n)
	}
	if w := e.f.Warnings(); len(w) != warnings+1 || w[len(w)-1].ID != "config|staged" {
		t.Fatalf("warnings %+v; want one config|staged warning for the rewrite", w[warnings:])
	}
	// Not asked about later either, by the poller or a second call.
	e.d.Reload()
	if _, p := e.applyHash(t, want); p == nil || p.Code != control.CodeError {
		t.Fatalf("again: %+v", p)
	}
	settle()
	if e.logins() != logins || len(e.contentBlocked(t)) != 1 {
		t.Fatal("the rewrite was asked about or reported again")
	}

	// The file holds the edit's change again: exactly one prompt, applied.
	e.writeConfig(t, edited)
	diff, p = e.applyHash(t, want)
	if p != nil || !diff.Applied || diff.Hash != want {
		t.Fatalf("config apply --hash of the edit: %+v %+v", diff, p)
	}
	if e.logins() != logins+1 {
		t.Fatalf("%d login prompts; want exactly 1", e.logins()-logins)
	}
	shown := e.f.Shown()
	for _, l := range shown[len(shown)-1].Prompt.Lines {
		if strings.Contains(l, "hydra") {
			t.Fatalf("the prompt for the edit of github lists %q", l)
		}
	}
	a := e.d.stager.Active()
	if a.Hash != want || a.SSHAgent.Keys["hydra"].Own.Gate != "login" {
		t.Fatalf("in force: hash %s, hydra gate %s", a.Hash, a.SSHAgent.Keys["hydra"].Own.Gate)
	}
	// In force already: nothing is staged, nothing is asked.
	diff, p = e.applyHash(t, want)
	if p != nil || diff.Applied || diff.Hash != want || len(diff.Changes) != 0 {
		t.Fatalf("config apply --hash of the config in force: %+v %+v", diff, p)
	}
	// A hash that is neither staged nor in force: refused, nothing asked.
	if _, p := e.applyHash(t, strings.Repeat("0", 64)); p == nil || p.Code != control.CodeError {
		t.Fatalf("an unknown hash: %+v", p)
	}
	settle()
	if e.logins() != logins+1 {
		t.Fatal("config apply --hash prompted for nothing staged")
	}
}

// The binding holds while automatic prompts are suppressed too (after a
// denial, past the cooldown), when `config apply` is the only way to a
// prompt: the rewrite gets none.
func TestConfigApplyHashWhileSuppressed(t *testing.T) {
	e := startQuiet(t)
	res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
	if p != nil || res.Staged == nil {
		t.Fatalf("edit: %+v %+v", res, p)
	}
	e.f.ScriptAuth(fake.Answer{Allow: false})
	if _, p := e.applyHash(t, res.Staged.Hash); p == nil || p.Code != control.CodeRefused {
		t.Fatalf("denied: %+v", p)
	}
	e.f.Advance(configApplyCooldown + time.Second)
	edited := e.readConfig(t)
	attacker := strings.Replace(edited, "      scope: use\n      gate: login\n", "      scope: use\n      gate: dialog\n", 1)
	logins := e.logins()
	e.writeConfig(t, attacker)
	if _, p := e.applyHash(t, res.Staged.Hash); p == nil || p.Code != control.CodeError {
		t.Fatalf("after the rewrite: %+v", p)
	}
	settle()
	if e.logins() != logins {
		t.Fatal("the rewrite got a prompt")
	}
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "login" {
		t.Fatalf("hydra gate in force: %s", g)
	}
}

// The background prompt is held from the
// moment an edit stages a loosening until the window's (or the user's)
// `config apply` of it has been handled, or editHoldFor has passed. A
// process watching config.yaml sees the edit land and rewrites the file at
// once; without the hold, the poller's next tick (or the attacker's own
// `nazar config check`, which reloads) opened the login prompt for the
// rewrite exactly when the user expected the one for their own change,
// same title, the attacker's lines first.

// stageEdit makes the window's loosening edit (github's rule 2 → dialog)
// and returns its reply and the content it staged.
func (e *env) stageEdit(t *testing.T) (control.ConfigEdit, string) {
	t.Helper()
	res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
	if p != nil || res.Staged == nil {
		t.Fatalf("edit: %+v %+v", res, p)
	}
	return res, e.readConfig(t)
}

// loosenHydra is body with hydra's own gate loosened (login → dialog): the
// attacker's change.
func loosenHydra(t *testing.T, body string) string {
	t.Helper()
	out := strings.Replace(body, "      scope: use\n      gate: login\n", "      scope: use\n      gate: dialog\n", 1)
	if out == body {
		t.Fatal("the rewrite changed nothing")
	}
	return out
}

// heldOff checks that the rewrite got no prompt: logins unchanged, the
// rewrite reported blocked exactly once with the hold's reason, the
// CLI's bound config.apply of the edit refused with exit 1, and the
// attacker's hydra gate (dialog) not in force.
func heldOff(t *testing.T, e *env, want string, logins, blockedBefore, warnings int) {
	t.Helper()
	settle()
	if n := e.logins() - logins; n != 0 {
		shown := e.f.Shown()
		t.Fatalf("the rewrite got %d background prompt(s): %q", n, shown[len(shown)-1].Prompt.Lines)
	}
	if n := len(e.contentBlocked(t)) - blockedBefore; n != 1 {
		t.Fatalf("%d per-content blocked lines for the rewrite; want 1", n)
	}
	w := e.f.Warnings()
	if len(w) != warnings+1 || w[len(w)-1].ID != "config|staged" {
		t.Fatalf("warnings %+v; want one config|staged warning", w[warnings:])
	}
	if !strings.Contains(strings.Join(w[len(w)-1].Lines, "\n"), "while a change made with nazar") {
		t.Fatalf("the warning does not say why: %q", w[len(w)-1].Lines)
	}
	if _, p := e.applyHash(t, want); p == nil || p.Code != control.CodeError || p.ExitCode() != control.ExitError {
		t.Fatalf("the window's config apply --hash: %+v; want exit 1", p)
	}
	e.d.Reload()
	settle()
	if e.logins() != logins || len(e.contentBlocked(t))-blockedBefore != 1 {
		t.Fatal("the rewrite was asked about, or reported, again")
	}
	if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g == "dialog" {
		t.Fatalf("hydra gate in force: %s (the attacker's loosening applied)", g)
	}
}

// The round-2 proof, inverted: edit, rewrite, a Reload (the poller's tick,
// or the attacker's `config check`) before the window's apply arrives.
func TestEditHoldsTheBackgroundPromptForARewrite(t *testing.T) {
	for _, viaCheck := range []bool{false, true} {
		t.Run(map[bool]string{false: "poller", true: "config check"}[viaCheck], func(t *testing.T) {
			e := startQuiet(t)
			res, edited := e.stageEdit(t)
			logins, blocked, warnings := e.logins(), len(e.contentBlocked(t)), len(e.f.Warnings())
			e.writeConfig(t, loosenHydra(t, edited))
			if viaCheck {
				e.check(t)
			} else {
				e.d.Reload()
			}
			heldOff(t, e, res.Staged.Hash, logins, blocked, warnings)
		})
	}
}

// The hold is a time window, not a comparison with the previous staged
// content: undoing the edit, writing an invalid file or a tightening (which
// applies at once and changes the config in force) in between, each seen by
// a Reload, still gets the final rewrite no prompt.
func TestEditHoldSurvivesIntermediateContents(t *testing.T) {
	for name, between := range map[string]string{
		"undone":     editBase,
		"invalid":    "ssh_agent: [\n",
		"tightening": handTightened,
	} {
		t.Run(name, func(t *testing.T) {
			e := startQuiet(t)
			res, edited := e.stageEdit(t)
			logins, blocked, warnings := e.logins(), len(e.contentBlocked(t)), len(e.f.Warnings())
			e.writeConfig(t, between)
			e.d.Reload()
			// The final content loosens hydra against the config in force,
			// whichever that is now.
			e.writeConfig(t, loosenHydra(t, edited))
			e.d.Reload()
			heldOff(t, e, res.Staged.Hash, logins, blocked, warnings)
		})
	}
}

// While the hold lasts, `nazar config apply` of anything but the edit's
// change is refused too (exit 1, nothing asked): without `--hash`, or with
// the rewrite's own hash. Otherwise the attacker runs it right after its
// rewrite and its prompt is the one the user sees.
func TestEditHoldRefusesConfigApplyOfARewrite(t *testing.T) {
	e := startQuiet(t)
	res, edited := e.stageEdit(t)
	logins := e.logins()
	attacker := loosenHydra(t, edited)
	e.writeConfig(t, attacker)
	for _, h := range []string{"", contentHash([]byte(attacker))} {
		var p *control.Problem
		if h == "" {
			_, p = e.apply(t)
		} else {
			_, p = e.applyHash(t, h)
		}
		if p == nil || p.Code != control.CodeError || p.ExitCode() != control.ExitError {
			t.Fatalf("config apply %q of the rewrite: %+v; want exit 1", h, p)
		}
		if !strings.Contains(p.Message, "nothing was asked") {
			t.Fatalf("message %q", p.Message)
		}
	}
	settle()
	if e.logins() != logins {
		t.Fatal("config apply of the rewrite showed a prompt during the hold")
	}
	if n := len(e.contentBlocked(t)); n != 1 {
		t.Fatalf("%d per-content blocked lines; want 1", n)
	}
	// Each refused call leaves a line naming who made it (spec 4.6): the
	// per-content line names nobody.
	if n := len(heldRefusals(t, e)); n != 2 {
		t.Fatalf("%d hold refusal lines; want 2, one per call", n)
	}
	// The edit's own change is still what `config apply --hash` approves
	// once the file holds it again.
	e.writeConfig(t, edited)
	if diff, p := e.applyHash(t, res.Staged.Hash); p != nil || !diff.Applied {
		t.Fatalf("apply --hash of the edit: %+v %+v", diff, p)
	}
	if e.logins() != logins+1 {
		t.Fatalf("%d prompts; want 1", e.logins()-logins)
	}
}

// Undoing the edit and making one's own edit in its place is refused while
// the hold lasts: otherwise the attacker's edit takes the hold, and its own
// `config apply --hash` shows its change alone in the prompt the user is
// waiting for.
func TestEditRefusedWhileAnEditWaitsForApproval(t *testing.T) {
	e := startQuiet(t)
	res, _ := e.stageEdit(t)
	logins := e.logins()
	e.writeConfig(t, editBase) // the edit undone
	e.d.Reload()
	if _, ok := e.d.stager.Pending(); ok {
		t.Fatal("undoing the edit left something staged")
	}
	r2, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "dialog"})
	if p == nil || p.ExitCode() != control.ExitError || r2.Staged != nil {
		t.Fatalf("an edit during the hold: %+v %+v; want exit 1", r2, p)
	}
	if !strings.Contains(p.Message, "waiting for approval") {
		t.Fatalf("message %q", p.Message)
	}
	if e.readConfig(t) != editBase {
		t.Fatal("a refused edit wrote config.yaml")
	}
	if _, p := e.applyHash(t, res.Staged.Hash); p == nil || p.ExitCode() != control.ExitError {
		t.Fatalf("apply --hash of the undone edit: %+v", p)
	}
	settle()
	if e.logins() != logins {
		t.Fatal("a prompt was shown")
	}
	// Past the bound, edits work again.
	e.f.Advance(editHoldFor + time.Second)
	if r, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"}); p != nil || !r.Applied {
		t.Fatalf("an edit after the hold: %+v %+v", r, p)
	}
}

// The hold ends: once the edit's `config apply --hash` was handled (here
// approved), or once editHoldFor has passed without it, a hand edit gets
// its background prompt as always.
func TestEditHoldEnds(t *testing.T) {
	t.Run("after the apply", func(t *testing.T) {
		e := startQuiet(t)
		res, edited := e.stageEdit(t)
		if diff, p := e.applyHash(t, res.Staged.Hash); p != nil || !diff.Applied {
			t.Fatalf("apply --hash: %+v %+v", diff, p)
		}
		logins := e.logins()
		e.writeConfig(t, loosenHydra(t, edited))
		e.d.Reload()
		waitFor(t, func() bool { return e.logins() == logins+1 })
		waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate == "dialog" })
	})
	t.Run("after a denied apply", func(t *testing.T) {
		e := startQuiet(t)
		res, _ := e.stageEdit(t)
		e.f.ScriptAuth(fake.Answer{Allow: false})
		if _, p := e.applyHash(t, res.Staged.Hash); p == nil || p.Code != control.CodeRefused {
			t.Fatalf("denied: %+v", p)
		}
		e.f.Advance(configApplyCooldown + time.Second)
		// The edit can be undone and made again: the hold went with the apply.
		e.writeConfig(t, editBase)
		e.d.Reload()
		if r, p := e.edit(t, map[string]string{"op": control.EditKeySet, "key": "hydra", "gate": "block"}); p != nil || !r.Applied {
			t.Fatalf("an edit after the denied apply: %+v %+v", r, p)
		}
	})
	t.Run("after the bound", func(t *testing.T) {
		e := startQuiet(t)
		_, edited := e.stageEdit(t)
		e.f.Advance(editHoldFor + time.Second)
		logins := e.logins()
		e.writeConfig(t, loosenHydra(t, edited))
		e.d.Reload()
		waitFor(t, func() bool { return e.logins() == logins+1 })
	})
}

// putHookVault runs hook once, the first time the prompts record is
// written: inside claim, before any prompt is shown.
type putHookVault struct {
	platform.Vault
	hook atomic.Pointer[func()]
}

func (v *putHookVault) Put(name string, b []byte) error {
	if name == PromptsVaultItem {
		if h := v.hook.Swap(nil); h != nil {
			(*h)()
		}
	}
	return v.Vault.Put(name, b)
}

// An apply that showed no prompt has handled nothing, so the hold stays:
// a process's own `config apply` (no hash) right after the edit, ended
// before any prompt by a revert it makes while the prompt is being claimed
// (Approve then finds nothing staged), or refused because another prompt
// is open, must not end the hold, or its next rewrite gets the background
// prompt the moment the user expects the one for their edit.
func TestEditHoldSurvivesAnApplyThatShowedNothing(t *testing.T) {
	t.Run("nothing staged when asked", func(t *testing.T) {
		var hv *putHookVault
		e := startWith(t, func(f *fake.Fake, o *Options) {
			o.Now = f.Now
			o.PollInterval = time.Hour
			hv = &putHookVault{Vault: o.Vault}
			o.Vault = hv
		})
		e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
		e.writeConfig(t, editBase)
		e.d.Reload()
		waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["github"] != nil })
		waitFor(t, func() bool { return !e.isOpen() })
		res, edited := e.stageEdit(t)
		logins := e.logins()
		revert := func() { e.writeConfig(t, editBase); e.d.Reload() }
		hv.hook.Store(&revert)
		if _, p := e.apply(t); p == nil {
			t.Fatal("the reverted apply succeeded")
		}
		settle()
		if e.logins() != logins {
			t.Fatal("the reverted apply showed a prompt")
		}
		blocked, warnings := len(e.contentBlocked(t)), len(e.f.Warnings())
		e.writeConfig(t, loosenHydra(t, edited))
		e.d.Reload()
		heldOff(t, e, res.Staged.Hash, logins, blocked, warnings)
	})
	t.Run("a prompt open", func(t *testing.T) {
		e := startQuiet(t)
		res, edited := e.stageEdit(t)
		logins := e.logins()
		cl, err := e.d.prompts.claim(e.d.o.Now, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, p := e.apply(t); p == nil || p.Code != control.CodeStaged {
			t.Fatalf("apply with a prompt open: %+v; want exit 4", p)
		}
		cl.release()
		blocked, warnings := len(e.contentBlocked(t)), len(e.f.Warnings())
		e.writeConfig(t, loosenHydra(t, edited))
		e.d.Reload()
		heldOff(t, e, res.Staged.Hash, logins, blocked, warnings)
	})
}

// heldRefusals returns the audit lines of `config apply` refused during an
// edit's hold, each of which must name its caller.
func heldRefusals(t *testing.T, e *env) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.configAudit(t, audit.Blocked) {
		if l["reason"] == "config apply: a change made with nazar is waiting for approval; the staged change is not it" {
			if l["chain"] == "" && l["session"] == "" {
				t.Fatalf("the refusal must name its caller: %v", l)
			}
			out = append(out, l)
		}
	}
	return out
}

// No edit hold can start while a login prompt is claimed or on
// screen. Whoever claimed it read the hold before claiming, so its prompt
// would be shown during the new hold, for another change, exactly when the
// user expects the one for their edit. The edit is refused (exit 1) and
// writes nothing; once the prompt is over it goes through.
func TestEditRefusedWhileAPromptIsClaimed(t *testing.T) {
	for _, config := range []bool{false, true} {
		t.Run(map[bool]string{false: "a loosen command's prompt", true: "a config prompt"}[config], func(t *testing.T) {
			e := startQuiet(t)
			before := e.readConfig(t)
			cl, err := e.d.prompts.claim(e.d.o.Now, config)
			if err != nil {
				t.Fatal(err)
			}
			res, p := e.edit(t, map[string]string{"op": control.EditRuleSet, "key": "github", "index": "2", "gate": "dialog", "expire": ""})
			if p == nil || p.Code != control.CodeError || p.ExitCode() != control.ExitError || res.Staged != nil {
				t.Fatalf("an edit while a prompt is claimed: %+v %+v; want exit 1", res, p)
			}
			if !strings.Contains(p.Message, "approval prompt is open") {
				t.Fatalf("message %q", p.Message)
			}
			if e.readConfig(t) != before {
				t.Fatal("a refused edit wrote config.yaml")
			}
			e.d.reloadMu.Lock()
			h := e.d.heldLocked()
			e.d.reloadMu.Unlock()
			if h != "" {
				t.Fatalf("a refused edit took the hold (%s)", h)
			}
			cl.release()
			if _, edited := e.stageEdit(t); edited == before {
				t.Fatal("the edit after the prompt changed nothing")
			}
		})
	}
}

// The prompt claimed for a change Y read the hold before claiming
// (Y staged, no hold then). Meanwhile the attacker reverts the file, the
// user's edit stages X and takes the hold, and the attacker writes Y again
// (A → C0 → X → A, which Approve's hash check cannot see). Y must not be
// asked about during hold X: no prompt, Y reported blocked once with the
// hold's reason, its loosening not in force, no cooldown, and the window's
// `config apply --hash X` still shows X's prompt afterwards. Both callers
// that read the hold first: a hashless `config apply` and the background
// prompt of a Reload (the poller, or the attacker's `config check`).
//
// The race runs inside the claim's vault write (putHookVault). config.edit
// is refused there now (TestEditRefusedWhileAPromptIsClaimed), so the edit
// is made beforehand and its landing replayed in the hook (its bytes
// observed, the hold taken), which is what an edit landing in the gap
// between the read of the hold and the claim leaves behind.
func TestEditHoldAppliesToAPromptClaimedBeforeIt(t *testing.T) {
	for _, viaApply := range []bool{true, false} {
		t.Run(map[bool]string{true: "config apply", false: "background prompt"}[viaApply], func(t *testing.T) {
			var hv *putHookVault
			e := startWith(t, func(f *fake.Fake, o *Options) {
				o.Now = f.Now
				o.PollInterval = time.Hour
				hv = &putHookVault{Vault: o.Vault}
				o.Vault = hv
			})
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
			e.writeConfig(t, editBase)
			e.d.Reload()
			waitFor(t, func() bool { return e.d.stager.Active().SSHAgent.Keys["github"] != nil })
			waitFor(t, func() bool { return !e.isOpen() })
			// The user's edit X, made once to learn its bytes, undone, and
			// past its hold.
			res, x := e.stageEdit(t)
			xHash := res.Staged.Hash
			e.writeConfig(t, editBase)
			e.d.Reload()
			e.f.Advance(editHoldFor + time.Second)

			y := loosenHydra(t, editBase)
			logins, blocked, warnings := e.logins(), len(e.contentBlocked(t)), len(e.f.Warnings())
			refusals := len(heldRefusals(t, e))
			race := func() {
				e.writeConfig(t, editBase) // the attacker reverts
				e.d.syncConfig()           // observed: nothing pending
				e.writeConfig(t, x)        // the user's edit lands: X staged, hold X
				e.d.reloadMu.Lock()
				e.d.lastSeen = contentHash([]byte(x))
				e.d.stager.Observe([]byte(x))
				e.d.hold = editHold{hash: xHash, until: e.d.o.Now().Add(editHoldFor)}
				e.d.reloadMu.Unlock()
				e.writeConfig(t, y) // the attacker writes Y again
				e.d.syncConfig()    // observed, held off
			}
			hv.hook.Store(&race)
			if viaApply {
				e.writeConfig(t, y)
				_, p := e.apply(t) // the attacker's hashless apply
				if p == nil || p.Code != control.CodeError || p.ExitCode() != control.ExitError || !strings.Contains(p.Message, "nothing was asked") {
					t.Fatalf("config apply of Y during hold X: %+v; want exit 1, nothing asked", p)
				}
				if n := len(heldRefusals(t, e)) - refusals; n != 1 {
					t.Fatalf("%d hold refusal lines; want 1", n)
				}
			} else {
				e.writeConfig(t, y)
				e.d.Reload()
			}
			settle()
			waitFor(t, func() bool { return !e.isOpen() })
			if hv.hook.Load() != nil {
				t.Fatal("the race never ran: no prompt was claimed")
			}
			if n := e.logins() - logins; n != 0 {
				shown := e.f.Shown()
				t.Fatalf("a prompt for Y was shown during hold X: %q", shown[len(shown)-1].Prompt.Lines)
			}
			if g := e.d.stager.Active().SSHAgent.Keys["hydra"].Own.Gate; g != "login" {
				t.Fatalf("hydra gate in force: %s (the attacker's loosening applied)", g)
			}
			if n := len(e.contentBlocked(t)) - blocked; n != 1 {
				t.Fatalf("%d per-content blocked lines for Y; want 1", n)
			}
			w := e.f.Warnings()
			if len(w) != warnings+1 || w[len(w)-1].ID != "config|staged" || !strings.Contains(strings.Join(w[len(w)-1].Lines, "\n"), "while a change made with nazar") {
				t.Fatalf("warnings %+v; want one config|staged warning with the hold's reason", w[warnings:])
			}
			e.d.prompts.mu.Lock()
			left := e.d.prompts.left(e.d.o.Now())
			e.d.prompts.mu.Unlock()
			if left != 0 {
				t.Fatalf("a prompt that was never shown started a cooldown of %s", left)
			}
			// Not asked about later either.
			e.d.Reload()
			settle()
			if e.logins() != logins || len(e.contentBlocked(t))-blocked != 1 {
				t.Fatal("Y was asked about, or reported, again")
			}
			// The window's apply of the edit: exactly X's prompt.
			e.writeConfig(t, x)
			diff, p := e.applyHash(t, xHash)
			if p != nil || !diff.Applied {
				t.Fatalf("apply --hash of the edit: %+v %+v", diff, p)
			}
			if e.logins() != logins+1 {
				t.Fatalf("%d prompts; want 1", e.logins()-logins)
			}
			shown := e.f.Shown()
			for _, l := range shown[len(shown)-1].Prompt.Lines {
				if strings.Contains(l, "hydra") {
					t.Fatalf("the prompt for the edit of github lists %q", l)
				}
			}
			if a := e.d.stager.Active(); a.Hash != xHash || a.SSHAgent.Keys["hydra"].Own.Gate != "login" {
				t.Fatalf("in force: hash %s, hydra gate %s", a.Hash, a.SSHAgent.Keys["hydra"].Own.Gate)
			}
		})
	}
}
