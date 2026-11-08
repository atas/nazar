package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// brewTool lays out a Homebrew-style install under a fresh directory:
// Cellar/mytool/1.0/bin/mytool, and opt/mytool a symlink to its version.
// It returns the opt path a rule names and the Cellar file the kernel
// reports for the running program.
func brewTool(t *testing.T) (opt, cellar string) {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cellar = filepath.Join(d, "Cellar/mytool/1.0/bin/mytool")
	if err := os.MkdirAll(filepath.Dir(cellar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cellar, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(d, "Cellar/mytool/1.0"), filepath.Join(d, "opt/mytool")); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(d, "opt/mytool/bin/mytool"), cellar
}

// brewProc is a Homebrew binary as it runs: linker-signed ad hoc
// (identifier a.out, no team), at its Cellar path.
func brewProc(path string, args ...string) fake.Proc {
	return fake.Proc{Path: path, Args: append([]string{filepath.Base(path)}, args...),
		Code: platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "a.out", CDHash: []byte{0x7a}}}
}

// A Homebrew daemon launchd started (no app, no terminal: the chain is
// the program and the nazar CLI it runs) gets a k8s credential with no
// prompt from a path: rule under gate none, through its opt/ symlink. It
// is judged as its own caller only because nothing called it: the same
// program run from a terminal is judged on the terminal, and another
// program launchd started is not matched.
func TestK8sPathRuleForALaunchdDaemon(t *testing.T) {
	e := startK8s(t)
	opt, cellar := brewTool(t)
	rule := "        - apps: [{path: " + opt + "}]\n          gate: none\n"
	e.approved(t, e.body+rule)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{}) // a prompt would be refused
	shown := len(e.f.Shown())

	daemon := e.f.Launch(platform.ProcessRef{}, brewProc(cellar, "run"))
	e.f.SetDefaultPeer(e.f.Launch(daemon, credCLI("hydra")))
	c, p := e.credential(t, "hydra", e.ok(t))
	if p != nil || c.ClientCertificateData == "" {
		t.Fatalf("the launchd-started program must get the credential: %+v", p)
	}
	if len(e.f.Shown()) != shown {
		t.Fatal("gate none: nothing may be shown")
	}
	if f := e.lastAudit(t); f["decision"] != "allowed" || f["target"] != "k8s:hydra" {
		t.Fatalf("audit %v", f)
	}

	// Another unsigned program launchd started: no rule of its own.
	_, other := brewTool(t)
	o := e.f.Launch(platform.ProcessRef{}, brewProc(other))
	e.f.SetDefaultPeer(e.f.Launch(o, credCLI("hydra")))
	if _, p := e.credential(t, "hydra", e.ok(t)); p == nil || p.Code != control.CodeRefused {
		t.Fatalf("another program must not match the path: rule: %+v", p)
	}

	// The same program run from a terminal is judged on who called it: the
	// iTerm2 rule's dialog, not the silent path: rule.
	dialogs := e.f.CountShown(fake.KindConfirm)
	e.asCLI(brewProc(cellar, "run"), credCLI("hydra"))
	if _, p := e.credential(t, "hydra", e.ok(t)); p == nil || p.Code != control.CodeRefused {
		t.Fatalf("from a terminal the iTerm2 rule decides (its dialog, refused here): %+v", p)
	}
	if e.f.CountShown(fake.KindConfirm) != dialogs+1 {
		t.Fatal("from a terminal the iTerm2 rule's dialog must ask")
	}
}

// The block warning for an unsigned program with no app above it
// suggests a path: rule for it, by its stable opt/ path, not apps: unknown.
func TestBlockWarningSuggestsAPathRule(t *testing.T) {
	e := startK8s(t)
	opt, cellar := brewTool(t)
	daemon := e.f.Launch(platform.ProcessRef{}, brewProc(cellar, "run"))
	e.f.SetDefaultPeer(e.f.Launch(daemon, credCLI("hydra")))
	if _, p := e.credential(t, "hydra", e.ok(t)); p == nil {
		t.Fatal("no rule: refused")
	}
	w := e.f.Warnings()
	if len(w) == 0 || !strings.Contains(w[len(w)-1].SuggestedRule, "path: "+opt+"\n") {
		t.Fatalf("the suggestion must name %s: %+v", opt, w)
	}
}

// config check warns, without making the file invalid, about a path: rule
// whose file (or a folder above it) the user can write: any program of
// theirs can replace it and get the rule's access.
func TestConfigCheckWarnsAboutWritablePath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write every file")
	}
	e := start(t)
	opt, _ := brewTool(t)
	e.writeConfig(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    github:\n      rules:\n"+
		"        - apps: [{path: "+opt+"}]\n          gate: none\n"+
		"        - apps: [{path: /usr/bin/true}]\n          gate: login\n")
	var chk control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil {
		t.Fatal(err)
	}
	if !chk.Valid {
		t.Fatalf("a writable path is a warning, not an error: %+v", chk)
	}
	want := "path:" + opt + " is writable by your user; any program of yours can replace it and get this rule's access"
	var found []string
	for _, p := range chk.Problems {
		if strings.Contains(p.Message, "is writable by your user") {
			found = append(found, p.Path+": "+p.Message)
			if p.Severity != "warning" || p.Message != want || p.Path != "ssh_agent.keys.github.rules[1].apps" {
				t.Errorf("problem %+v, want %q", p, want)
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("one warning, for the writable path only (not /usr/bin/true): %v", found)
	}
}

// Migration: an approved config with a path: rule from a build where
// path: matched nothing must not start matching after the upgrade without
// the owner: the rest of it works as approved, the path: rule waits for
// `config apply` (Touch ID), and once approved it matches with no prompt.
func TestPathRuleApprovedWhileItMatchedNothingWaitsForApproval(t *testing.T) {
	e := startWith(t, withClock)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(cliProc("ssh-key", "create"))
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	opt, cellar := brewTool(t)
	body := "apiVersion: nazar/v1\nkind: Config\napps:\n  mytool: {path: " + opt + "}\nssh_agent:\n  keys:\n    github:\n      gate: block\n      rules:\n" +
		"        - apps: [mytool]\n          gate: none\n" +
		"        - apps: [{app: com.googlecode.iterm2}]\n          scope: session\n          gate: dialog\n"
	// What an older nazar-agent approved and the file it read; then this
	// build starts.
	if err := e.vault.Put(configstage.ApprovedVaultItem, []byte(body)); err != nil {
		t.Fatal(err)
	}
	e.writeConfig(t, body)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true}) // Touch ID refused until the owner says so
	e.relaunch(t)
	waitFor(t, func() bool { _, staged := e.d.stager.Pending(); return staged })
	if e.d.stager.Active().HasPathMatchers() {
		t.Fatal("the path: rule must not be in force before the approval")
	}
	// The iTerm2 rule works as approved: the key is not bricked.
	tool := brewProc(cellar)
	dialogs := e.f.CountShown(fake.KindConfirm)
	if err := e.signAs(t, e.f.ITermTab(platform.ProcessRef{}, tool, fake.SSHProc("git@github.com")).Peer()); err != nil {
		t.Fatalf("the key must still sign through its other rule: %v", err)
	}
	if e.f.CountShown(fake.KindConfirm) != dialogs+1 {
		t.Fatal("the iTerm2 rule's dialog must have asked, not the held path: rule")
	}
	bare := e.f.Launch(e.f.Launch(platform.ProcessRef{}, tool), fake.SSHProc("git@github.com"))
	if err := e.signAs(t, bare); err == nil {
		t.Fatal("outside iTerm2 the held path: rule must not sign")
	}
	// The owner approves: the path: rule matches, with no prompt.
	e.f.Advance(2 * time.Minute) // past the cooldown of the prompt refused at start
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	e.asCLI(cliProc("config", "apply"))
	if _, p := e.apply(t); p != nil && !strings.Contains(p.Message, "prompt is already open") {
		t.Fatalf("apply: %+v", p)
	}
	waitFor(t, func() bool { return e.d.stager.Active().HasPathMatchers() })
	shown := len(e.f.Shown())
	bare = e.f.Launch(e.f.Launch(platform.ProcessRef{}, tool), fake.SSHProc("git@github.com"))
	if err := e.signAs(t, bare); err != nil {
		t.Fatalf("approved, the path: rule signs: %v", err)
	}
	if len(e.f.Shown()) != shown {
		t.Fatal("gate none: nothing shown")
	}
	// A restart keeps it approved.
	e.relaunch(t)
	if !e.d.stager.Active().HasPathMatchers() {
		t.Fatal("after a restart the approved path: rule stays in force")
	}
	if _, staged := e.d.stager.Pending(); staged {
		t.Fatal("nothing to approve again")
	}
}

// `k8s rule add <ctx> --apps path:<file> --gate none --allow-loosen-access`
// is a loosening: staged until the owner's Touch ID (config apply), then
// in force; removing the rule tightens at once.
func TestK8sPathRuleEditIsALoosening(t *testing.T) {
	e := startK8sEdit(t)
	opt, _ := brewTool(t)
	logins := e.logins()
	res, p := e.edit(t, map[string]string{"op": control.EditRuleAdd, "context": "hydra", "apps": refs("path:" + opt), "gate": "none"})
	if p != nil {
		t.Fatal(p)
	}
	if res.Applied || res.Staged == nil || !res.Staged.Loosens || !strings.Contains(strings.Join(res.Staged.Loosening, "\n"), "k8s:hydra") {
		t.Fatalf("adding a path: rule must be staged as a loosening: %+v", res)
	}
	if e.d.stager.Active().HasPathMatchers() {
		t.Fatal("a loosening applied without approval")
	}
	if diff, p := e.apply(t); p != nil || !diff.Applied || e.logins() != logins+1 {
		t.Fatalf("apply: %+v %+v", diff, p)
	}
	rs := e.d.stager.Active().K8s["hydra"].Rules
	if len(rs) != 2 || rs[1].Apps[0].Path != opt || rs[1].Policy.Gate != "none" {
		t.Fatalf("not in force: %+v", rs)
	}
	res, p = e.edit(t, map[string]string{"op": control.EditRuleRemove, "context": "hydra", "index": "2"})
	if p != nil || !res.Applied || res.Staged != nil || e.logins() != logins+1 {
		t.Fatalf("removing the path: rule must apply at once: %+v %+v", res, p)
	}
}

// apps list shows a path: entry with the ref --apps takes and no problem;
// `nazar trust <path>` stays gone (a path: rule needs no trust).
func TestAppsListPathEntry(t *testing.T) {
	e := start(t)
	opt, _ := brewTool(t)
	e.approved(t, "apiVersion: nazar/v1\nkind: Config\napps:\n  mytool: {path: "+opt+"}\nssh_agent:\n  keys:\n    github:\n      rules:\n        - apps: [mytool]\n          gate: login\n")
	var l control.AppList
	if err := e.call(t, control.CmdAppsList, nil, control.KindAppList, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 1 || l.Items[0].Matcher.Ref != "mytool" || l.Items[0].Matcher.Kind != "path" || l.Items[0].Matcher.Path != opt || l.Items[0].Problem != "" {
		t.Fatalf("apps list: %+v", l.Items)
	}
	if p := control.AsProblem(e.call(t, "trust", map[string]string{"path": opt}, control.KindAppPin, &control.AppPin{})); p == nil || p.ExitCode() != control.ExitUsage {
		t.Fatalf("trust <path>: %+v", p)
	}
}
