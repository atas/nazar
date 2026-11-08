package broker

import (
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/policy"
)

// Secrets design 5, 5.1, 8: a secret request runs the ssh pipeline:
// the same gates, cache, shared prompt and one audit line. The method is
// the approval's op, set by the broker; the receiver's chain is what the
// dialog's command line and the audit receiver show.

const secretCfg = cfgSrc + `secrets:
  GH_TOKEN:
    deliver: [helper]
    rules:
      - apps: [iterm]
        to: [{signed: {team: apple, id: com.apple.git-remote-http}}]
        scope: session
        gate: dialog
  NOTES:
    rules:
      - apps: [iterm]
        scope: session
        gate: dialog
`

var nazarCLI = platform.CodeIdentity{Signed: true, TeamID: "NAZARTEAM0", SigningID: "dev.nazar.cli", CDHash: []byte{0x9a}}

func fetchProc() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/bin/git", Args: []string{"git", "fetch", "origin"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git")}
}

func transportProc() fake.Proc {
	return fake.Proc{Path: "/Library/Developer/CommandLineTools/usr/libexec/git-core/git-remote-http", Args: []string{"git-remote-https", "origin", "https://github.com/atas/nazar.git"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git-remote-http")}
}

func scriptProc(path, id string, args ...string) fake.Proc {
	return fake.Proc{Path: path, Args: args, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode(id)}
}

func cliProc() fake.Proc {
	return fake.Proc{Path: "/Users/u/Library/nazar/nazar-agent.app/Contents/MacOS/nazar", Args: []string{"nazar"}, Code: nazarCLI}
}

func (e *env) secretReq(name string, d config.Delivery, peer platform.ProcessRef) Request {
	c := e.r.Resolve(peer)
	return Request{
		Secret: name, Delivery: d, Chain: c, Receiver: c.Parent(),
		Summary: "via " + string(d), Operation: "git credential fill",
		Do: func(platform.ApprovalRef) error { e.calls.Add(1); return nil },
	}
}

func TestSecretHelperRequestIsApprovedRememberedAndAudited(t *testing.T) {
	e := newEnvWith(t, secretCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fetchProc(), transportProc(), cliProc())
	if r := e.b.Handle(e.secretReq("GH_TOKEN", config.DeliverHelper, tab.Peer())); r.Decision != audit.Approved || r.Outcome.Target != "secret:GH_TOKEN" {
		t.Fatalf("first: %+v", r)
	}
	shown := e.f.Shown()
	if len(shown) != 1 {
		t.Fatalf("one dialog, got %d", len(shown))
	}
	if p := shown[0].Prompt; p.Title != `iTerm2 wants to use secret "GH_TOKEN"` || !strings.Contains(promptText(p), "Scope: this terminal session, for the credential helper only") {
		t.Fatalf("prompt:\n%s", promptText(p))
	}
	again := e.f.Launch(tab.Procs[1], cliProc()) // the same transport asks again
	if r := e.b.Handle(e.secretReq("GH_TOKEN", config.DeliverHelper, again)); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("same receiver, same tab: %+v", r)
	}
	if e.calls.Load() != 2 || e.f.CountShown(fake.KindConfirm) != 1 {
		t.Fatalf("Do ran %d times, %d dialogs", e.calls.Load(), e.f.CountShown(fake.KindConfirm))
	}
	f := e.lastLine(t)
	if f["target"] != "secret:GH_TOKEN" || f["delivery"] != "helper" || f["rule"] != "1" || f["gate"] != "dialog" || f["operation"] != "git credential fill" {
		t.Fatalf("audit %v", f)
	}
	if !strings.HasPrefix(f["receiver"], "git-remote-https ") || f["cwd"] != "~/projects/foo" {
		t.Fatalf("receiver= is the CLI's parent, not the CLI: %q (cwd %q)", f["receiver"], f["cwd"])
	}
}

func TestSecretApprovalCoversOneMethodAndOneReceiver(t *testing.T) {
	e := newEnvWith(t, secretCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc())
	first := e.secretReq("NOTES", config.DeliverStdout, tab.Peer())
	first.Op = approval.Op{ID: "login:SHA256:gh", Text: "github.com"} // a module can't choose what it covers
	if r := e.b.Handle(first); r.Decision != audit.Approved {
		t.Fatalf("first: %+v", r)
	}
	if r := e.b.Handle(e.secretReq("NOTES", config.DeliverStdout, e.f.Launch(tab.Procs[0], cliProc()))); r.Reason != "cached approval" {
		t.Fatalf("same script, same method: %+v", r)
	}
	e.b.Handle(e.secretReq("NOTES", config.DeliverHelper, tab.Peer())) // another method
	py := e.f.Launch(tab.Shell, scriptProc("/usr/bin/python3", "com.apple.python3", "python3", "b.py"))
	e.b.Handle(e.secretReq("NOTES", config.DeliverStdout, e.f.Launch(py, cliProc()))) // another receiver
	if n := e.f.CountShown(fake.KindConfirm); n != 3 {
		t.Fatalf("each method and each receiver is its own approval: %d dialogs, want 3", n)
	}
	covers := map[string]string{"deliver:stdout": "nazar get", "deliver:helper": "the credential helper"}
	entries := e.cache.List()
	if len(entries) != 3 {
		t.Fatalf("want 3 approvals, got %+v", entries)
	}
	for _, en := range entries {
		if en.Key.Target != "secret:NOTES" || covers[en.Key.Op] == "" || en.Covers != covers[en.Key.Op] || en.Key.Receiver == "" {
			t.Fatalf("approval %+v", en)
		}
	}
}

func TestSecretDeliveryNotAllowedIsBlockedWithoutAPrompt(t *testing.T) {
	e := newEnvWith(t, secretCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc())
	r := e.b.Handle(e.secretReq("GH_TOKEN", config.DeliverStdout, tab.Peer())) // deliver: [helper]
	if r.Decision != audit.Blocked || r.Reason != policy.ReasonDelivery || e.calls.Load() != 0 || len(e.f.Shown()) != 0 {
		t.Fatalf("must be blocked before any prompt: %+v", r)
	}
	w := e.f.Warnings()
	if len(w) != 1 || w[0].Title != `Blocked: iTerm2 tried to use secret "GH_TOKEN"` || !strings.Contains(strings.Join(w[0].Lines, "\n"), "deliver:") {
		t.Fatalf("warning %+v", w)
	}
	if f := e.lastLine(t); f["decision"] != "blocked" || f["delivery"] != "stdout" || f["target"] != "secret:GH_TOKEN" || f["reason"] != policy.ReasonDelivery {
		t.Fatalf("audit %v", f)
	}
}

func TestRefuseTakesASecretRequest(t *testing.T) {
	e := newEnvWith(t, secretCfg, 200*time.Millisecond)
	tab := e.f.ITermTab(platform.ProcessRef{}, fetchProc(), transportProc(), cliProc())
	c := e.r.Resolve(tab.Peer())
	r := e.b.Refuse(Request{Secret: "GH_TOKEN", Delivery: config.DeliverHelper, Chain: c, Receiver: c.Parent()}, "peer is not the nazar CLI")
	if r.Decision != audit.Blocked || r.Outcome.Target != "secret:GH_TOKEN" || r.Outcome.Key != "GH_TOKEN" {
		t.Fatalf("refuse: %+v", r)
	}
	if f := e.lastLine(t); f["target"] != "secret:GH_TOKEN" || f["delivery"] != "helper" || f["reason"] != "peer is not the nazar CLI" || !strings.HasPrefix(f["receiver"], "git-remote-https ") {
		t.Fatalf("audit %v", f)
	}
}

// Review: the asker of a secret request is always the nazar CLI, so
// a rule suggested for the CLI would match every secret request from any
// script. The suggestion is drafted from the chain above the CLI.
func TestBlockedSecretNeverSuggestsTheCLI(t *testing.T) {
	e := newEnvWith(t, secretCfg, 200*time.Millisecond)
	tab := e.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc())
	if r := e.b.Handle(e.secretReq("GH_TOKEN", config.DeliverHelper, tab.Peer())); r.Decision != audit.Blocked {
		t.Fatalf("bash is not git's transport: %+v", r)
	}
	w := e.f.Warnings()
	if len(w) != 1 {
		t.Fatalf("warnings %+v", w)
	}
	if s := w[0].SuggestedRule; strings.Contains(s, "dev.nazar.cli") || strings.Contains(s, nazarCLI.TeamID) || !strings.Contains(s, "app: com.googlecode.iterm2") {
		t.Fatalf("the suggestion must name the app, never the nazar CLI:\n%s", s)
	}
}

// No rule can allow a method deliver: does not list, so the warning offers
// none.
func TestDeliveryWarningOffersNoRule(t *testing.T) {
	e := newEnvWith(t, secretCfg, 200*time.Millisecond)
	tab := e.f.ITermTab(platform.ProcessRef{}, scriptProc("/bin/bash", "com.apple.bash", "bash", "a.sh"), cliProc())
	e.b.Handle(e.secretReq("GH_TOKEN", config.DeliverStdout, tab.Peer())) // deliver: [helper]
	w := e.f.Warnings()
	if len(w) != 1 || w[0].SuggestedRule != "" || strings.Contains(strings.Join(w[0].Lines, "\n"), "add a rule") {
		t.Fatalf("a delivery refusal must not offer a rule: %+v", w)
	}
}
