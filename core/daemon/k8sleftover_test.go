package daemon

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The clients: list is gone (k8s design 2.1, "no client list"). An
// approved config of an older version can still have the line on a
// context: nazar-agent started with it keeps that config in force, so
// SSH keys sign exactly as approved, and only that context is off, with
// the fix in config check, until the line is removed and the loosening
// approved.
func TestK8sLeftoverClientsLineKeepsTheRestWorking(t *testing.T) {
	e := startK8s(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	e.asCLI(cliProc("ssh-key", "create"))
	if err := e.call(t, control.CmdSSHKeyCreate, map[string]string{"name": "github"}, control.KindSSHKey, &control.SSHKey{}); err != nil {
		t.Fatal(err)
	}
	key := "ssh_agent:\n  keys:\n    github:\n      gate: block\n      rules:\n        - apps: [iterm]\n          scope: session\n          gate: dialog\n"
	now := e.body + key
	old := strings.Replace(now, "      ttl_cert: 15m\n", "      ttl_cert: 15m\n      clients: [kubectl, helm, k9s]\n", 1)
	// What an older nazar-agent approved and the file it read, then the
	// new build starts.
	if err := e.vault.Put(configstage.ApprovedVaultItem, []byte(old)); err != nil {
		t.Fatal(err)
	}
	e.writeConfig(t, old)
	e.relaunch(t)
	active := e.d.stager.Active()
	if string(active.Raw) != old || active.K8s["hydra"] == nil || !active.K8s["hydra"].LeftoverClients || active.SSHAgent.Keys["github"] == nil {
		t.Fatalf("the approved config must stay in force:\n%s", active.Raw)
	}
	// The SSH key signs as approved.
	if err := e.signAs(t, e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com")).Peer()); err != nil {
		t.Fatalf("the key must still sign: %v", err)
	}
	// The context is refused, before any prompt, naming the fix.
	shown := len(e.f.Shown())
	e.asCLI(kubeProc("get", "pods"), credCLI("hydra"))
	c, p := e.credential(t, "hydra", e.ok(t))
	if p == nil || p.Code != control.CodeRefused || !strings.Contains(p.Message, "clients: line") || c.ClientKeyData != "" || len(e.f.Shown()) != shown {
		t.Fatalf("hydra must be off: %+v", p)
	}
	if f := e.lastAudit(t); f["decision"] != "blocked" || f["target"] != "k8s:hydra" || !strings.Contains(f["reason"], "clients: line") {
		t.Fatalf("audit %v", f)
	}
	var chk control.ConfigCheck
	if err := e.call(t, control.CmdConfigCheck, nil, control.KindConfigCheck, &chk); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pr := range chk.Problems {
		if pr.Path == "k8s.contexts.hydra.clients" && strings.Contains(pr.Message, "remove the line") {
			found = true
		}
	}
	if !chk.Valid || !found {
		t.Fatalf("config check must stay valid and name the fix: %+v", chk)
	}
	// The line removed: a loosening, staged until the login gate (Touch
	// ID) approves it; held open here to see it staged.
	release := e.holdLogin(t, true)
	e.writeConfig(t, now)
	waitFor(t, func() bool { return e.stillStaged() && e.isOpen() })
	if !e.d.stager.Active().K8s["hydra"].LeftoverClients {
		t.Fatal("staged, not in force")
	}
	if pend, _ := e.d.stager.Pending(); !strings.Contains(strings.Join(pend.Diff.Changes, "\n"), "clients: line removed") {
		t.Fatalf("the prompt must say what loosens: %+v", pend.Diff)
	}
	release()
	waitFor(t, func() bool { k := e.d.stager.Active().K8s["hydra"]; return k != nil && !k.LeftoverClients })
	if _, p := e.credential(t, "hydra", e.ok(t)); p != nil {
		t.Fatalf("approved, hydra works: %+v", p)
	}
}
