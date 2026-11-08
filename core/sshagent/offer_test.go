package sshagent

import (
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// twoKeysSrc gives the iTerm tab the github key and Claude Code the work
// key; each falls to the block fallback for the other.
const twoKeysSrc = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
    work:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
`

// Milestone 7: REQUEST_IDENTITIES lists only the keys the caller
// may use (spec 5). The tab gets github but not work; Claude Code in a tab
// gets both (the tab's app still matches iterm); a caller offered some key
// hears nothing about the rest; an approved rule change shows at once.
func TestIdentitiesOfferOnlyKeysTheCallerMayUse(t *testing.T) {
	e := newEnvWith(t, twoKeysSrc)
	if _, err := e.reg.Create("work", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	if got := e.listNames(t, e.peer); !equalNames(got, "github") {
		t.Fatalf("iTerm tab: identities %v, want [github]", got)
	}
	claude := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com")).Peer()
	if got := e.listNames(t, claude); !equalNames(got, "github", "work") {
		t.Fatalf("Claude Code in a tab: identities %v, want [github work]", got)
	}
	if len(e.sink.Lines()) != 0 || len(e.f.Warnings()) != 0 || len(e.f.Shown()) != 0 {
		t.Fatalf("a caller offered some key is told nothing about the rest: audit %q, warnings %d, prompts %d",
			e.sink.Lines(), len(e.f.Warnings()), len(e.f.Shown()))
	}
	e.reload(t, strings.Replace(twoKeysSrc, "- apps: [claude]", "- apps: [iterm, claude]", 1))
	if got := e.listNames(t, e.peer); !equalNames(got, "github", "work") {
		t.Fatalf("after the rule for the tab: identities %v, want [github work]", got)
	}
}

// A program outside every rule is offered nothing, and that is reported
// where ssh and ssh-keygen stop: one blocked audit line per key with
// operation "list keys", and the block warning per key. The listing is not
// the gate: a sign request with a withheld key (its public key is on disk)
// still runs the pipeline, is blocked with no prompt and no signature, and
// updates the same warning.
func TestCallerOfferedNothingIsReported(t *testing.T) {
	e := newEnvWith(t, twoKeysSrc)
	if _, err := e.reg.Create("work", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	stranger := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	c, _ := e.client(t, stranger)
	if ks, err := c.List(); err != nil || len(ks) != 0 {
		t.Fatalf("a caller no rule matches: identities %v %v, want none", ks, err)
	}
	lines := e.sink.Lines()
	if len(lines) != 2 {
		t.Fatalf("want one blocked line per withheld key, got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for i, target := range []string{"ssh:github", "ssh:work"} {
		f, err := audit.ParseLine(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		if f["decision"] != "blocked" || f["target"] != target || f["operation"] != "list keys" || f["reason"] != "no rule matched" || f["chain"] == "" {
			t.Fatalf("line %d: %v", i, f)
		}
	}
	if w := e.f.Warnings(); len(w) != 2 || !strings.HasPrefix(w[0].Title, "Blocked: ") || w[0].ID == w[1].ID {
		t.Fatalf("want one block warning per withheld key: %+v", w)
	}
	if _, err := c.Sign(e.pub, sshsig("git")); err == nil {
		t.Fatal("a withheld key must still refuse to sign for this caller")
	}
	if f := lastAudit(t, e); f["decision"] != "blocked" || f["target"] != "ssh:github" || f["operation"] != "sign git commit" {
		t.Fatalf("sign with a withheld key: %v", f)
	}
	if len(e.f.Shown()) != 0 || e.f.SignCalls() != 0 {
		t.Fatalf("withheld key: prompts %d, signatures %d, want none", len(e.f.Shown()), e.f.SignCalls())
	}
	if w := e.f.Warnings(); len(w) != 3 || w[2].ID != w[0].ID || w[2].Count != 2 {
		t.Fatalf("the sign attempt must update the listing's warning for that caller and key: %+v", w)
	}
}
