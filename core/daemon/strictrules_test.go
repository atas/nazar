package daemon

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

// oldForms holds what builds before accepted and this one drops at start:
// scope next to gate: block, expire next to scope use, to: [any] on a
// secret's rule.
const oldForms = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm] # my terminal
          gate: dialog
          expire: 8h
      scope: session
      gate: block
secrets:
  T:
    rules:
      - apps: [iterm]
        to: [any]
        scope: session
        gate: dialog
`

// An approved config.yaml with old forms that meant nothing stays
// approved: the file and the vault item lose them (backup kept), the file
// is the approved config, nothing is staged, no prompt; a second start
// does nothing.
func TestOldFormsDroppedAtStartStayApproved(t *testing.T) {
	e := start(t)
	upgradeFrom(t, e, oldForms, oldForms, false)
	want := migratedOrFail(t, oldForms)
	logins := e.logins()
	e.launch(t)

	got := e.readConfig(t)
	if got != string(want) || strings.Contains(got, "expire") || strings.Contains(got, "any") || !strings.Contains(got, "# my terminal") {
		t.Fatalf("config.yaml:\n%s", got)
	}
	if b, err := os.ReadFile(layout.ConfigFile(e.home) + ".bak"); err != nil || string(b) != oldForms {
		t.Fatalf("backup: %q %v", b, err)
	}
	if !bytes.Equal(e.d.stager.Active().Raw, want) {
		t.Fatalf("active:\n%s", e.d.stager.Active().Raw)
	}
	if item, _ := e.vault.Get(configstage.ApprovedVaultItem); !bytes.Equal(item, want) {
		t.Fatalf("approved item:\n%s", item)
	}
	if _, staged := e.pending(); staged || e.logins() != logins {
		t.Fatal("staged or prompted")
	}
	e.relaunch(t)
	if e.readConfig(t) != string(want) || e.logins() != logins {
		t.Fatal("the second start changed something")
	}
}

// appleTeam is an approved config with a rule whose team is spelled Apple
// (it matches nothing; apple would match Apple's programs) next to a rule
// that works.
const appleTeam = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [{signed: {team: Apple, id: com.apple.openssh}}]
          gate: dialog
        - apps: [iterm]
          gate: login
`

// A team spelled Apple has no rewrite of the same meaning. The file is
// left as it is (no backup) and reported invalid with the fix, while the
// approved config, read as before, stays in force: no key falls to the
// built-in default, nothing is staged, no prompt.
func TestAppleTeamIsLeftForTheUser(t *testing.T) {
	e := start(t)
	upgradeFrom(t, e, appleTeam, appleTeam, false)
	logins := e.logins()
	e.launch(t)

	if e.readConfig(t) != appleTeam {
		t.Fatalf("config.yaml changed:\n%s", e.readConfig(t))
	}
	if _, err := os.Stat(layout.ConfigFile(e.home) + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("a backup was written: %v", err)
	}
	if a := e.d.stager.Active(); string(a.Raw) != appleTeam || len(a.SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatalf("the approved config is not in force:\n%s", a.Raw)
	}
	if item, _ := e.vault.Get(configstage.ApprovedVaultItem); string(item) != appleTeam {
		t.Fatalf("the vault item changed:\n%s", item)
	}
	var chk control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range chk.Problems {
		found = found || p.Severity == string(config.SevError) && strings.Contains(p.Message, `"Apple" matches nothing; Apple's team is written apple`)
	}
	if chk.Valid || !found || chk.Staged != nil {
		t.Fatalf("config check: %+v", chk)
	}
	if _, staged := e.pending(); staged || e.logins() != logins {
		t.Fatal("staged or prompted")
	}
}

// A file a process of the user wrote with an old form gains nothing: it is
// rewritten (the same rules) and judged against the approved config,
// staged, nothing of it in force, nothing recorded as approved.
func TestForgedOldFormGainsNothing(t *testing.T) {
	const approved = "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\nssh_agent:\n  keys:\n    github:\n      rules:\n        - apps: [iterm]\n          gate: login\n"
	forged := approved + "        - apps: [any]\n          to: [any]\n          gate: none\n          scope: app\n"
	e := start(t)
	upgradeFrom(t, e, approved, forged, false)
	e.launch(t)
	want := migratedOrFail(t, forged)
	if e.readConfig(t) != string(want) {
		t.Fatalf("config.yaml:\n%s", e.readConfig(t))
	}
	if a := e.d.stager.Active(); string(a.Raw) != approved || len(a.SSHAgent.Keys["github"].Rules) != 1 {
		t.Fatalf("the forged rule is in force:\n%s", a.Raw)
	}
	if p, staged := e.pending(); !staged || !bytes.Equal(p.Config.Raw, want) {
		t.Fatal("the rewritten file must wait for the gate")
	}
	if item, _ := e.vault.Get(configstage.ApprovedVaultItem); string(item) != approved {
		t.Fatalf("approved item:\n%s", item)
	}
}

// A rule edit reports the problems of the config as written, as config
// check does right after: the new rule's own path: warning included, once.
func TestRuleEditShowsTheWrittenConfigsWarnings(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write every file")
	}
	e := startEdit(t)
	opt, _ := brewTool(t)
	res, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "key": "github", "apps": refs("path:" + opt), "gate": "none", "at": "1"})
	if p != nil {
		t.Fatal(p)
	}
	want := "path:" + opt + " is writable by your user"
	n := 0
	seen := map[string]bool{}
	for _, pr := range res.Problems {
		if strings.Contains(pr.Message, want) {
			n++
		}
		k := pr.Severity + pr.Path + pr.Message
		if seen[k] {
			t.Errorf("shown twice: %+v", pr)
		}
		seen[k] = true
	}
	if n != 1 {
		t.Fatalf("want the new rule's warning once, got %d: %+v", n, res.Problems)
	}
	// What config check shows for the file now, the edit showed.
	var chk control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil {
		t.Fatal(err)
	}
	for _, c := range chk.Problems {
		if c.Severity == string(config.SevWarning) && strings.HasPrefix(c.Path, "ssh_agent") && !seen[c.Severity+c.Path+c.Message] {
			t.Errorf("config check shows %+v, the edit did not", c)
		}
	}
}
