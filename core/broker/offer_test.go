package broker

import (
	"slices"
	"strings"
	"testing"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 7: REQUEST_IDENTITIES offers a caller only the keys it
// may use, as Offer decides. Under cfgSrc: github (claude: dialog, iterm:
// login), deploy (iterm: none), unk (unknown: dialog); everything else is
// the block fallback. A key the config does not name is never offered. A
// caller offered some key is told nothing about the rest: no warning, no
// audit line, and never a prompt.
func TestOfferFollowsPolicy(t *testing.T) {
	e := newEnv(t)
	keys := []string{"github", "deploy", "unk", "ghost"}
	for _, c := range []struct {
		name string
		peer platform.ProcessRef
		want []bool
	}{
		{"iTerm tab", e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")).Peer(), []bool{true, true, false, false}},
		{"Claude Code in a tab", e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h")).Peer(), []bool{true, true, false, false}},
		{"unknown chain", e.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]")), []bool{false, false, true, false}},
	} {
		if got := e.b.Offer(e.r.Resolve(c.peer), keys); !slices.Equal(got, c.want) {
			t.Errorf("%s: Offer = %v, want %v", c.name, got, c.want)
		}
	}
	if len(e.sink.Lines()) != 0 || len(e.f.Warnings()) != 0 || len(e.f.Shown()) != 0 {
		t.Fatalf("a caller offered some key is told nothing about the rest: audit %q, warnings %d, prompts %d",
			e.sink.Lines(), len(e.f.Warnings()), len(e.f.Shown()))
	}
}

// A caller outside every rule is reported at the listing, where ssh and
// ssh-keygen stop when the agent lists nothing: one blocked audit line per
// withheld key, operation "list keys", and the block warning per key,
// deduplicated with a later sign attempt by the same caller for the same
// key. No prompt: a listing is decided by the rules alone.
func TestOfferNothingIsReportedLikeABlock(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	term := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Code: fake.AppleCode("com.apple.Terminal"), App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"}})
	chain := e.r.Resolve(e.f.Launch(term, fake.SSHProc("h")))
	if got := e.b.Offer(chain, []string{"github", "deploy", "ghost"}); slices.Contains(got, true) {
		t.Fatalf("Offer = %v, want nothing for a caller no rule matches", got)
	}
	lines := e.sink.Lines()
	if len(lines) != 2 {
		t.Fatalf("want one blocked line per withheld configured key, got %d:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for i, target := range []string{"ssh:github", "ssh:deploy"} {
		f, err := audit.ParseLine(lines[i])
		if err != nil {
			t.Fatal(err)
		}
		if f["decision"] != "blocked" || f["target"] != target || f["operation"] != "list keys" || f["reason"] != "no rule matched" ||
			f["gate"] != "block" || f["rule"] != RuleFallback || f["app"] != "com.apple.Terminal" || f["destination"] != "" || f["chain"] == "" {
			t.Fatalf("line %d: %v", i, f)
		}
	}
	w := e.f.Warnings()
	if len(w) != 2 || w[0].ID == w[1].ID {
		t.Fatalf("want one warning per withheld key: %+v", w)
	}
	for _, x := range w {
		if !strings.HasPrefix(x.Title, `Blocked: Terminal tried to use key "`) || x.Lines[0] != "asked which keys it may use" || x.Count != 1 || x.SuggestedRule == "" {
			t.Fatalf("warning %+v", x)
		}
	}
	if len(e.f.Shown()) != 0 {
		t.Fatal("a listing never prompts")
	}
	// The same caller asking to sign with a withheld key (it read the public
	// key on disk) is blocked by the pipeline and updates the listing's
	// window, as a repeated block does.
	if r := e.b.Handle(e.req("github", e.f.Launch(term, fake.SSHProc("h")))); r.Decision != audit.Blocked {
		t.Fatalf("%+v", r)
	}
	if w := e.f.Warnings(); len(w) != 3 || w[2].ID != w[0].ID || w[2].Count != 2 {
		t.Fatalf("warnings %+v", w)
	}
}

// Without an active config nothing is offered and nothing is reported:
// there is no key to withhold. A nil chain is an unknown caller.
func TestOfferWithoutConfigOrChain(t *testing.T) {
	e := newEnv(t)
	if got := e.b.Offer(nil, []string{"unk", "github"}); !slices.Equal(got, []bool{true, false}) {
		t.Fatalf("a nil chain is judged as unknown: Offer = %v", got)
	}
	e.eng.Store(nil)
	if got := e.b.Offer(e.r.Resolve(e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")).Peer()), []string{"github"}); slices.Contains(got, true) {
		t.Fatalf("no config: Offer = %v", got)
	}
	if len(e.sink.Lines()) != 0 || len(e.f.Warnings()) != 0 {
		t.Fatalf("nothing to report: audit %q, warnings %d", e.sink.Lines(), len(e.f.Warnings()))
	}
}
