package policy

import (
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/trust"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

const cfgSrc = `apiVersion: nazar/v1
kind: Config
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
  ssh:
    signed: { team: apple, id: com.apple.openssh }
ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
        - apps: [iterm]
          scope: session
          gate: login
          expire: 8h
    deploy:
      rules:
        - apps: [iterm]
          to: [ssh]
          gate: none
    appkey:
      rules:
        - apps: [iterm]
          scope: app
          gate: dialog
    unk:
      rules:
        - apps: [unknown]
          gate: dialog
          scope: session
    hydra:
      gate: login
`

// cfgExtra covers orderings, fall-through, scopes without an identity and
// keys without rules.
const cfgExtra = `apiVersion: nazar/v1
kind: Config
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
  ssh:
    signed: { team: apple, id: com.apple.openssh }
ssh_agent:
  keys:
    order:
      rules:
        - apps: [iterm]
          gate: none
        - apps: [claude]
          scope: session
          gate: dialog
    fallthrough:
      rules:
        - apps: [iterm]
          to: [ssh]
          gate: none
        - apps: [iterm]
          scope: session
          gate: login
    silent:
      rules:
        - apps: [iterm]
          gate: none
    anyapp:
      rules:
        - apps: [any]
          scope: app
          gate: dialog
    anysession:
      rules:
        - apps: [any]
          scope: session
          gate: dialog
    usekey:
      rules:
        - apps: [iterm]
          scope: use
          gate: login
    ownsession:
      scope: session
      gate: login
      expire: 1h
    bare:
    blockrule:
      rules:
        - apps: [claude]
          gate: block
        - apps: [iterm]
          scope: session
          gate: dialog
`

type env struct {
	f  *fake.Fake
	r  *caller.Resolver
	e  *Engine
	st *trust.Store
}

func parse(t *testing.T, src string) *config.Config {
	t.Helper()
	cfg, probs := config.Parse([]byte(src), config.Env{Home: "/Users/u"})
	if probs.HasErrors() {
		t.Fatal(probs.Error())
	}
	return cfg
}

func newEnvSrc(t *testing.T, src string) *env {
	t.Helper()
	cfg := parse(t, src)
	f := fake.New(t0)
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	// As config approval does (spec 4.2): iTerm2's team is pinned from
	// the installed app when the config is approved, never while matching.
	if _, err := st.Pin("com.googlecode.iterm2", "H7V7XYVQ7D"); err != nil {
		t.Fatal(err)
	}
	return &env{f: f, r: &caller.Resolver{P: f}, e: New(cfg, &match.Evaluator{Trust: st}), st: st}
}

func newEnv(t *testing.T) *env { return newEnvSrc(t, cfgSrc) }

// evalSSH resolves peer and evaluates key for it.
func (en *env) eval(key string, peer platform.ProcessRef) Outcome {
	return en.e.EvaluateSSH(key, en.r.Resolve(peer))
}

// mustBeOneShot asserts the outcome may not be remembered.
func mustBeOneShot(t *testing.T, what string, out Outcome) {
	t.Helper()
	if !out.OneShot || out.ScopeID != "" {
		t.Fatalf("%s: must be one-shot with no scope id, got %+v", what, out)
	}
}

// mustBeBlockedFallback asserts the request fell through to a block fallback.
func mustBeBlockedFallback(t *testing.T, what string, out Outcome) {
	t.Helper()
	if out.RuleIndex != 0 || out.Policy.Gate != config.GateBlock || !strings.HasPrefix(out.RuleID, "fallback:") {
		t.Fatalf("%s: must fall back to block, got %+v", what, out)
	}
	mustBeOneShot(t, what, out)
}

// --- core behaviour ---

func TestFirstMatchWins(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	out := en.e.EvaluateSSH("github", en.r.Resolve(tab.Peer()))
	if out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog || out.Reason != "rule 1 matched" {
		t.Fatalf("claude in iTerm must get rule 1 (dialog), got %+v", out)
	}
	if out.OneShot || !strings.HasPrefix(out.ScopeID, "session:") || out.Target != "ssh:github" {
		t.Fatalf("scope %+v", out)
	}
	plain := en.f.ITermTab(tab.App, fake.SSHProc("h"))
	out2 := en.e.EvaluateSSH("github", en.r.Resolve(plain.Peer()))
	if out2.RuleIndex != 2 || out2.Policy.Gate != config.GateLogin || out2.Policy.Expire != 8*time.Hour {
		t.Fatalf("plain iTerm must get rule 2 (login), got %+v", out2)
	}
	if out.RuleID == out2.RuleID {
		t.Fatal("approvals are per rule: rule IDs must differ")
	}
}

func TestNoMatchFallsBackToBlock(t *testing.T) {
	en := newEnv(t)
	term := en.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Code: fake.AppleCode("com.apple.Terminal"), App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"}})
	peer := en.f.Launch(term, fake.SSHProc("h"))
	out := en.e.EvaluateSSH("github", en.r.Resolve(peer))
	if out.RuleIndex != 0 || out.Policy.Gate != config.GateBlock || out.Reason != "no rule matched" || !out.OneShot {
		t.Fatalf("got %+v", out)
	}
	if !strings.HasPrefix(out.RuleID, "fallback:") {
		t.Fatalf("rule id %q", out.RuleID)
	}
}

func TestUnconfiguredKeyGetsDefaultsFallback(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if out := en.e.EvaluateSSH("nosuchkey", en.r.Resolve(tab.Peer())); out.Policy.Gate != config.GateBlock {
		t.Fatalf("got %+v", out)
	}
}

func TestKeyOwnPolicyAppliesToEveryone(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	out := en.e.EvaluateSSH("hydra", en.r.Resolve(tab.Peer()))
	if out.Policy.Gate != config.GateLogin || out.Policy.Scope != config.ScopeUse || !out.OneShot {
		t.Fatalf("got %+v", out)
	}
}

func TestToMismatchFallsThrough(t *testing.T) {
	en := newEnv(t)
	other := fake.Proc{Path: "/opt/homebrew/bin/ssh", Code: platform.CodeIdentity{Signed: true, AdHoc: true}}
	tab := en.f.ITermTab(platform.ProcessRef{}, other)
	out := en.e.EvaluateSSH("deploy", en.r.Resolve(tab.Peer()))
	if out.Policy.Gate != config.GateBlock || out.Reason != "to: mismatch" {
		t.Fatalf("got %+v", out)
	}
	ok := en.f.ITermTab(tab.App, fake.SSHProc("h"))
	out2 := en.e.EvaluateSSH("deploy", en.r.Resolve(ok.Peer()))
	if out2.Policy.Gate != config.GateNone || out2.Receiver != "apple:com.apple.openssh" {
		t.Fatalf("got %+v", out2)
	}
}

func TestUnknownChainIsNeverCached(t *testing.T) {
	en := newEnv(t)
	peer := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	c := en.r.Resolve(peer)
	out := en.e.EvaluateSSH("unk", c)
	if out.RuleIndex != 1 || !out.OneShot || out.ScopeID != "" || !out.Unknown {
		t.Fatalf("unknown chain matched by apps: unknown must be one-shot, got %+v", out)
	}
	if out := en.e.EvaluateSSH("github", c); out.Policy.Gate != config.GateBlock {
		t.Fatalf("unknown chain must be blocked for github, got %+v", out)
	}
}

// A responsible-only chain does not match the iterm rule: the resolver keeps
// such a chain Unknown (responsibility is inherited across fork/exec, so it
// is display only), and spec 4.2 matches unknown chains only with
// any/unknown: the request must fall to the fallback instead.
func TestAppScopeAndResponsibleSession(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	out := en.e.EvaluateSSH("appkey", en.r.Resolve(tab.Peer()))
	if out.ScopeID != "app:H7V7XYVQ7D:com.googlecode.iterm2" || out.OneShot {
		t.Fatalf("got %+v", out)
	}
	mux := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	en.f.SetResponsible(mux, tab.App)
	out2 := en.e.EvaluateSSH("github", en.r.Resolve(mux))
	if !out2.Unknown || out2.Reason != "no rule matched" {
		t.Fatalf("responsible-only attribution is an unknown chain, got %+v", out2)
	}
	mustBeBlockedFallback(t, "responsible-only chain, github", out2)
	mustBeOneShot(t, "responsible-only chain, appkey", en.e.EvaluateSSH("appkey", en.r.Resolve(mux)))
}

func TestLiveRuleIDs(t *testing.T) {
	en := newEnv(t)
	live := LiveRuleIDs(en.e.Config())
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	out := en.e.EvaluateSSH("github", en.r.Resolve(tab.Peer()))
	if !live[out.Target+"|"+out.RuleID] {
		t.Fatalf("rule %s missing from %v", out.RuleID, live)
	}
	fb := en.e.EvaluateSSH("hydra", en.r.Resolve(tab.Peer()))
	if !live[fb.Target+"|"+fb.RuleID] {
		t.Fatal("fallback rule id missing")
	}
}

// --- additional behaviour, edge and attack cases ---

func TestEngineKeepsItsConfig(t *testing.T) {
	cfg := parse(t, cfgSrc)
	st, _ := trust.Open(fake.NewVault())
	e := New(cfg, &match.Evaluator{Trust: st})
	if e.Config() != cfg {
		t.Fatal("Config() must return the config the engine was built from")
	}
}

func TestOutcomeNamesTargetAndKey(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	for _, key := range []string{"github", "hydra", "nosuchkey"} {
		out := en.eval(key, tab.Peer())
		if out.Target != "ssh:"+key || out.Key != key {
			t.Fatalf("%s: target/key %q/%q", key, out.Target, out.Key)
		}
	}
}

// Rule IDs are what approvals are remembered under; they must be identical
// for an unchanged rule and must change when the rule's meaning or
// position changes, so an edited rule never inherits approvals.
func TestRuleIDsTrackRuleMeaning(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	base := en.eval("github", tab.Peer())
	if base.RuleIndex != 2 {
		t.Fatalf("setup: %+v", base)
	}

	again := newEnv(t)
	tab2 := again.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if got := again.eval("github", tab2.Peer()).RuleID; got != base.RuleID {
		t.Fatalf("same config must give the same rule id: %q vs %q", got, base.RuleID)
	}

	edited := newEnvSrc(t, strings.Replace(cfgSrc, "expire: 8h", "expire: 4h", 1))
	tab3 := edited.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	out := edited.eval("github", tab3.Peer())
	if out.RuleIndex != 2 || out.RuleID == base.RuleID {
		t.Fatalf("an edited rule must get a new id: %+v (old %q)", out, base.RuleID)
	}
	if LiveRuleIDs(edited.e.Config())[base.Target+"|"+base.RuleID] {
		t.Fatal("the edited rule's old id must not be live")
	}
	// Rule 1 is unchanged and keeps its id.
	if !LiveRuleIDs(edited.e.Config())["ssh:github|"+parse(t, cfgSrc).SSHAgent.Keys["github"].Rules[0].ID()] {
		t.Fatal("an unchanged rule must stay live after another rule is edited")
	}
}

func TestFallbackRuleIDTracksPolicyAndTarget(t *testing.T) {
	block := config.Policy{Scope: config.ScopeUse, Gate: config.GateBlock}
	login := config.Policy{Scope: config.ScopeUse, Gate: config.GateLogin}
	sess := config.Policy{Scope: config.ScopeSession, Gate: config.GateLogin, Expire: time.Hour}
	sess2 := config.Policy{Scope: config.ScopeSession, Gate: config.GateLogin, Expire: 2 * time.Hour}

	id := FallbackRuleID("ssh:a", block)
	if !regexp.MustCompile(`^fallback:[0-9a-f]{8}$`).MatchString(id) {
		t.Fatalf("fallback id %q, want fallback:<8 hex>", id)
	}
	if FallbackRuleID("ssh:a", block) != id {
		t.Fatal("fallback id must be deterministic")
	}
	seen := map[string]string{id: "a/block"}
	for name, got := range map[string]string{
		"b/block":  FallbackRuleID("ssh:b", block),
		"a/login":  FallbackRuleID("ssh:a", login),
		"a/sess1h": FallbackRuleID("ssh:a", sess),
		"a/sess2h": FallbackRuleID("ssh:a", sess2),
	} {
		if prev, dup := seen[got]; dup {
			t.Fatalf("fallback ids of %s and %s collide: %q", prev, name, got)
		}
		seen[got] = name
	}

	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	out := en.eval("hydra", tab.Peer())
	if out.RuleID != FallbackRuleID("ssh:hydra", out.Policy) {
		t.Fatalf("outcome fallback id %q != FallbackRuleID %q", out.RuleID, FallbackRuleID("ssh:hydra", out.Policy))
	}
	changed := newEnvSrc(t, strings.Replace(cfgSrc, "    hydra:\n      gate: login\n", "    hydra:\n      gate: dialog\n", 1))
	tab2 := changed.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if got := changed.eval("hydra", tab2.Peer()); got.Policy.Gate != config.GateDialog || got.RuleID == out.RuleID {
		t.Fatalf("changing a key's own policy must change its fallback id: %+v vs %q", got, out.RuleID)
	}
}

// LiveRuleIDs lists exactly every rule plus the fallback of every configured
// key, and nothing for unconfigured keys.
func TestLiveRuleIDsExact(t *testing.T) {
	cfg := parse(t, cfgSrc)
	live := LiveRuleIDs(cfg)
	want := map[string]bool{}
	for _, name := range cfg.KeyNames() {
		target := "ssh:" + name
		for _, r := range cfg.SSHAgent.Keys[name].Rules {
			want[target+"|"+r.ID()] = true
		}
		want[target+"|"+FallbackRuleID(target, cfg.Fallback(name))] = true
	}
	if len(live) != len(want) {
		t.Fatalf("live ids %v, want %v", live, want)
	}
	for k := range want {
		if !live[k] {
			t.Fatalf("missing %s in %v", k, live)
		}
	}
	for k, v := range live {
		if !v {
			t.Fatalf("live map holds a false entry %q", k)
		}
	}
	nk := "ssh:nosuchkey|" + FallbackRuleID("ssh:nosuchkey", cfg.Defaults.Fallback)
	if live[nk] {
		t.Fatal("approvals for unconfigured keys must not be live")
	}
	if got := LiveRuleIDs(config.Default(config.Env{Home: "/Users/u"})); len(got) != 0 {
		t.Fatalf("default config has no keys, got %v", got)
	}
}

// First match means order, not specificity: an earlier broader rule wins
// over a later, more specific one (spec 4.2 "order matters").
func TestFirstMatchIsByOrderNotSpecificity(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	out := en.eval("order", tab.Peer())
	if out.RuleIndex != 1 || out.Policy.Gate != config.GateNone || out.Reason != "rule 1 matched" {
		t.Fatalf("rule 1 comes first and matches, got %+v", out)
	}
}

// Anything Claude Code runs has Claude Code in its chain, however deep, and
// gets its rule (spec 4.2).
func TestDeepChainKeepsAncestorRule(t *testing.T) {
	en := newEnv(t)
	py := fake.Proc{Path: "/usr/bin/python3", Code: fake.AppleCode("com.apple.python3")}
	sh := fake.Proc{Path: "/bin/sh", Code: fake.AppleCode("com.apple.sh")}
	git := fake.Proc{Path: "/usr/bin/git", Code: fake.AppleCode("com.apple.git")}
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), sh, py, git, fake.SSHProc("h"))
	if out := en.eval("github", tab.Peer()); out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog {
		t.Fatalf("deep claude descendant must get the claude rule, got %+v", out)
	}
}

// A process that merely claims Claude Code's team and signing id (ad-hoc or
// unsigned) is not Claude Code.
func TestForgedSignatureDoesNotMatchSignedRule(t *testing.T) {
	en := newEnv(t)
	for name, code := range map[string]platform.CodeIdentity{
		"adhoc":     {Signed: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
		"unsigned":  {Signed: false, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"},
		"otherteam": {Signed: true, TeamID: "EVILTEAM00", SigningID: "com.anthropic.claude-code"},
	} {
		fakeClaude := fake.Proc{Path: "/tmp/claude", Code: code}
		tab := en.f.ITermTab(platform.ProcessRef{}, fakeClaude, fake.SSHProc("h"))
		out := en.eval("github", tab.Peer())
		if out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin {
			t.Fatalf("%s: forged claude must not get the dialog rule, got %+v", name, out)
		}
	}
}

// An app: matcher matches only the team pinned at config approval;
// an impostor app with the same bundle id but another (or no valid) team
// must not match, not even for a gate: none rule.
func TestImpostorAppDoesNotMatch(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	real := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if out := en.eval("silent", real.Peer()); out.Policy.Gate != config.GateNone || out.RuleIndex != 1 {
		t.Fatalf("setup: real iTerm must match, got %+v", out)
	}
	for name, code := range map[string]platform.CodeIdentity{
		"otherteam": {Signed: true, TeamID: "EVILTEAM00", SigningID: "com.googlecode.iterm2"},
		"adhoc":     {Signed: true, AdHoc: true, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2"},
		"unsigned":  {TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2"},
	} {
		app := en.f.Launch(platform.ProcessRef{}, fake.Proc{
			Path: "/tmp/iTerm.app/Contents/MacOS/iTerm2", Code: code,
			App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
		})
		sh := en.f.Launch(app, fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")})
		peer := en.f.Launch(sh, fake.SSHProc("h"))
		mustBeBlockedFallback(t, name+" impostor, silent", en.eval("silent", peer))
	}
}

// A to: miss falls through to later rules, not straight to the fallback.
func TestToMismatchFallsThroughToLaterRule(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	brew := fake.Proc{Path: "/opt/homebrew/bin/ssh", Code: platform.CodeIdentity{Signed: true, AdHoc: true}}
	tab := en.f.ITermTab(platform.ProcessRef{}, brew)
	out := en.eval("fallthrough", tab.Peer())
	if out.RuleIndex != 2 || out.Policy.Gate != config.GateLogin || out.Reason != "rule 2 matched" {
		t.Fatalf("to: miss on rule 1 must fall through to rule 2, got %+v", out)
	}
	if out.Receiver != "" {
		t.Fatalf("rule 2 has no to:, receiver must be empty, got %q", out.Receiver)
	}
	ok := en.f.ITermTab(tab.App, fake.SSHProc("h"))
	out2 := en.eval("fallthrough", ok.Peer())
	if out2.RuleIndex != 1 || out2.Policy.Gate != config.GateNone || out2.Receiver != "apple:com.apple.openssh" {
		t.Fatalf("apple ssh must match rule 1, got %+v", out2)
	}
}

// The receiver is the socket peer itself: Apple's ssh higher up in the chain
// does not make a different peer an acceptable receiver.
func TestToChecksThePeerNotTheChain(t *testing.T) {
	en := newEnv(t)
	evil := fake.Proc{Path: "/tmp/evil", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM00", SigningID: "evil"}}
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"), evil)
	out := en.eval("deploy", tab.Peer())
	mustBeBlockedFallback(t, "non-ssh peer under ssh", out)
	if out.Reason != "to: mismatch" || out.Receiver != "" {
		t.Fatalf("got %+v", out)
	}
}

func TestRulesWithoutToHaveNoReceiver(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	for _, key := range []string{"github", "appkey", "hydra", "nosuchkey"} {
		if out := en.eval(key, tab.Peer()); out.Receiver != "" {
			t.Fatalf("%s: receiver must be empty without to:, got %+v", key, out)
		}
	}
}

// Session approvals: same tab → same scope id; another tab → another one.
// The scope id is derived from the chain's session root.
func TestSessionScopeIdentity(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	out := en.e.EvaluateSSH("github", c)
	if out.ScopeID != "session:"+c.Session.String() || c.Session.IsZero() {
		t.Fatalf("scope id %q, session %q", out.ScopeID, c.Session.String())
	}
	// A second command in the same tab (same shell).
	second := en.f.Launch(tab.Shell, fake.SSHProc("h2"))
	if got := en.eval("github", second).ScopeID; got != out.ScopeID {
		t.Fatalf("same tab must share the session scope: %q vs %q", got, out.ScopeID)
	}
	other := en.f.ITermTab(tab.App, fake.SSHProc("h"))
	if got := en.eval("github", other.Peer()).ScopeID; got == out.ScopeID || !strings.HasPrefix(got, "session:") {
		t.Fatalf("another tab must get another session scope: %q vs %q", got, out.ScopeID)
	}
}

func TestAppScopeSharedAcrossTabs(t *testing.T) {
	en := newEnv(t)
	a := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	b := en.f.ITermTab(a.App, fake.SSHProc("h"))
	oa, ob := en.eval("appkey", a.Peer()), en.eval("appkey", b.Peer())
	if oa.ScopeID != ob.ScopeID || oa.OneShot || ob.OneShot {
		t.Fatalf("scope app must be shared by every tab of the app: %+v / %+v", oa, ob)
	}
}

// scope: use, gate: none and gate: block are never remembered.
func TestNonRememberedPolicies(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	plain := en.f.ITermTab(tab.App, fake.SSHProc("h"))

	use := en.eval("usekey", plain.Peer())
	if use.Policy.Gate != config.GateLogin || use.Policy.Scope != config.ScopeUse {
		t.Fatalf("setup: %+v", use)
	}
	mustBeOneShot(t, "scope use", use)

	none := en.eval("silent", plain.Peer())
	if none.Policy.Gate != config.GateNone {
		t.Fatalf("setup: %+v", none)
	}
	mustBeOneShot(t, "gate none", none)

	blk := en.eval("blockrule", tab.Peer())
	if blk.RuleIndex != 1 || blk.Policy.Gate != config.GateBlock || blk.Reason != "rule 1 matched" {
		t.Fatalf("an explicit block rule must match as a rule, got %+v", blk)
	}
	mustBeOneShot(t, "gate block rule", blk)
	if want := en.e.Config().SSHAgent.Keys["blockrule"].Rules[0].ID(); blk.RuleID != want {
		t.Fatalf("a matched rule's id is its own (%q), got %q", want, blk.RuleID)
	}

	if out := en.eval("blockrule", plain.Peer()); out.RuleIndex != 2 || out.OneShot {
		t.Fatalf("plain iTerm skips the claude block rule: %+v", out)
	}
}

// A key's own policy with a remembering scope is remembered for known
// chains, and never for unknown ones.
func TestOwnPolicyScope(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	out := en.eval("ownsession", tab.Peer())
	if out.RuleIndex != 0 || out.Policy.Gate != config.GateLogin || out.Policy.Scope != config.ScopeSession || out.Policy.Expire != time.Hour {
		t.Fatalf("got %+v", out)
	}
	if out.OneShot || !strings.HasPrefix(out.ScopeID, "session:") || !strings.HasPrefix(out.RuleID, "fallback:") {
		t.Fatalf("own scope session for a known chain is remembered: %+v", out)
	}
	unk := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	uo := en.eval("ownsession", unk)
	if !uo.Unknown || uo.Policy.Gate != config.GateLogin {
		t.Fatalf("got %+v", uo)
	}
	mustBeOneShot(t, "unknown chain under a key's own session scope", uo)
}

func TestKeyWithoutRulesOrPolicyUsesDefaults(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	out := en.eval("bare", tab.Peer())
	mustBeBlockedFallback(t, "bare key", out)
	if out.Reason != "no rule matched" {
		t.Fatalf("got %+v", out)
	}
}

func TestCustomDefaultsFallback(t *testing.T) {
	src := `apiVersion: nazar/v1
kind: Config
defaults:
  fallback:
    gate: login
ssh_agent:
  keys:
    k:
`
	en := newEnvSrc(t, src)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	for _, key := range []string{"k", "nosuchkey"} {
		out := en.eval(key, tab.Peer())
		if out.Policy.Gate != config.GateLogin || out.Policy.Scope != config.ScopeUse || out.RuleIndex != 0 {
			t.Fatalf("%s: defaults.fallback must apply, got %+v", key, out)
		}
		mustBeOneShot(t, key, out)
		if out.RuleID != FallbackRuleID("ssh:"+key, out.Policy) {
			t.Fatalf("%s: rule id %q", key, out.RuleID)
		}
	}
}

// Key names are matched exactly: a differently cased name is another
// (unconfigured) key and gets defaults.fallback.
func TestKeyNameIsExact(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	for _, key := range []string{"Silent", "SILENT", "silent ", " silent", "silent\x00", ""} {
		out := en.eval(key, tab.Peer())
		mustBeBlockedFallback(t, "key "+key, out)
	}
}

// Unknown chains match only any/unknown and are never remembered, whatever
// the rule's scope (spec 4.2).
func TestUnknownChainWithAnyRules(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	unk := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	c := en.r.Resolve(unk)
	if !c.Unknown {
		t.Fatal("setup: chain must be unknown")
	}
	for _, key := range []string{"anyapp", "anysession"} {
		out := en.e.EvaluateSSH(key, c)
		if out.RuleIndex != 1 || out.Policy.Gate != config.GateDialog || !out.Unknown {
			t.Fatalf("%s: apps: any must match an unknown chain, got %+v", key, out)
		}
		mustBeOneShot(t, key, out)
	}
	for _, key := range []string{"silent", "order", "fallthrough", "usekey", "blockrule"} {
		out := en.e.EvaluateSSH(key, c)
		if !out.Unknown {
			t.Fatalf("%s: outcome must carry Unknown, got %+v", key, out)
		}
		mustBeBlockedFallback(t, "unknown chain, "+key, out)
	}
}

// Known chains are reported as known.
func TestKnownChainIsNotUnknown(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	for _, key := range []string{"github", "hydra", "nosuchkey", "unk"} {
		if out := en.eval(key, tab.Peer()); out.Unknown {
			t.Fatalf("%s: known chain reported unknown: %+v", key, out)
		}
	}
	if out := en.eval("unk", tab.Peer()); out.RuleIndex != 0 || out.Policy.Gate != config.GateBlock {
		t.Fatalf("apps: unknown must not match a known chain, got %+v", out)
	}
}

// A peer that can't be identified (gone, recycled PID) yields an unknown
// chain with no processes: it must never satisfy to: and never be cached.
func TestUnidentifiablePeer(t *testing.T) {
	en := newEnv(t)
	gone := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	peer := gone.Peer()
	en.f.Exit(peer)
	c := en.r.Resolve(peer)
	if !c.Unknown || len(c.Procs) != 0 {
		t.Fatalf("setup: %+v", c)
	}
	out := en.e.EvaluateSSH("unk", c)
	if out.RuleIndex != 1 || !out.Unknown {
		t.Fatalf("got %+v", out)
	}
	mustBeOneShot(t, "unidentifiable peer, unk", out)
	for _, key := range []string{"github", "deploy", "appkey", "hydra"} {
		o := en.e.EvaluateSSH(key, c)
		mustBeOneShot(t, "unidentifiable peer, "+key, o)
		if o.RuleIndex != 0 || o.Receiver != "" {
			t.Fatalf("%s: got %+v", key, o)
		}
	}
	// An empty chain (no processes at all) is handled without panicking.
	empty := &caller.Chain{Unknown: true, Truncated: true}
	mustBeBlockedFallback(t, "empty chain, deploy", en.e.EvaluateSSH("deploy", empty))
}

// A detached process attributed to iTerm only through the responsible
// process must not take iTerm's silent rule (spec 4.1 step 5, 4.2).
func TestResponsibleAttributionCannotUnlockSilentRule(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	if out := en.eval("silent", tab.Peer()); out.Policy.Gate != config.GateNone {
		t.Fatalf("setup: %+v", out)
	}
	// Claude Code double-forks ssh so it ends up under launchd.
	detached := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("h"))
	en.f.SetResponsible(detached, tab.App)
	out := en.eval("silent", detached)
	if !out.Unknown {
		t.Fatalf("responsible-only chain must be unknown, got %+v", out)
	}
	mustBeBlockedFallback(t, "detached ssh, silent", out)
	mustBeBlockedFallback(t, "detached ssh, order", en.eval("order", detached))
}

// scope: app needs a verifiable app identity; an ad-hoc or unsigned app has
// none, so its approvals are one-shot.
func TestAppScopeWithoutIdentityIsOneShot(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	for name, code := range map[string]platform.CodeIdentity{
		"adhoc":    {Signed: true, AdHoc: true, TeamID: "H7V7XYVQ7D", SigningID: "com.example.term"},
		"unsigned": {TeamID: "H7V7XYVQ7D", SigningID: "com.example.term"},
	} {
		app := en.f.Launch(platform.ProcessRef{}, fake.Proc{
			Path: "/Applications/Term.app/Contents/MacOS/Term", Code: code,
			App: &fake.App{BundleID: "com.example.term", Name: "Term"},
		})
		sh := en.f.Launch(app, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
		peer := en.f.Launch(sh, fake.SSHProc("h"))
		out := en.eval("anyapp", peer)
		if out.RuleIndex != 1 || out.Unknown {
			t.Fatalf("%s: setup %+v", name, out)
		}
		mustBeOneShot(t, name+" app, scope app", out)
	}
}

// scope: session needs a session root; a request from the app itself (or
// one of its helpers) has none, so it is one-shot.
func TestSessionScopeWithoutSessionIsOneShot(t *testing.T) {
	en := newEnvSrc(t, cfgExtra)
	tab := en.f.ITermTab(platform.ProcessRef{})
	c := en.r.Resolve(tab.App)
	if c.Unknown || !c.Session.IsZero() {
		t.Fatalf("setup: app as peer must be known with no session: %+v", c)
	}
	out := en.e.EvaluateSSH("anysession", c)
	if out.RuleIndex != 1 {
		t.Fatalf("setup: %+v", out)
	}
	mustBeOneShot(t, "app itself, scope session", out)

	helper := en.r.Resolve(tab.Server)
	if !helper.Session.IsZero() {
		t.Fatalf("setup: helper must have no session: %+v", helper)
	}
	mustBeOneShot(t, "helper, scope session", en.e.EvaluateSSH("anysession", helper))
}

// The engine is immutable and safe for concurrent use.
func TestConcurrentEvaluation(t *testing.T) {
	en := newEnv(t)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	plain := en.f.ITermTab(tab.App, fake.SSHProc("h"))
	unk := en.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	chains := []*caller.Chain{en.r.Resolve(tab.Peer()), en.r.Resolve(plain.Peer()), en.r.Resolve(unk)}
	keys := []string{"github", "deploy", "appkey", "unk", "hydra", "nosuchkey"}
	want := map[[2]int]Outcome{}
	for ci, c := range chains {
		for ki, k := range keys {
			want[[2]int{ci, ki}] = en.e.EvaluateSSH(k, c)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				for ci, c := range chains {
					for ki, k := range keys {
						got := en.e.EvaluateSSH(k, c)
						w := want[[2]int{ci, ki}]
						if got != w {
							select {
							case errs <- k:
							default:
							}
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for k := range errs {
		t.Fatalf("concurrent evaluation of %s differs from serial", k)
	}
}

// The engine itself refuses to remember an approval for an unknown chain,
// even if the chain carries a session or app (defence in depth: spec 4.2
// "never covered by a remembered approval" must not rest on the resolver
// alone).
func TestUnknownChainNeverRememberedEvenWithSession(t *testing.T) {
	en := newEnvSrc(t, cfgExtra+`    unksession:
      rules:
        - apps: [unknown]
          scope: session
          gate: login
    unkapp:
      rules:
        - apps: [unknown]
          scope: app
          gate: dialog
`)
	app := platform.AppInfo{Ref: platform.ProcessRef{PID: 7, Generation: 7001}, BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: fake.ITermCode}
	peer := platform.ProcessInfo{Ref: platform.ProcessRef{PID: 42, Generation: 42001}, Parent: app.Ref, UID: 501, StartTime: t0, Path: "/usr/bin/ssh", Code: fake.AppleCode("com.apple.openssh")}
	c := &caller.Chain{
		Procs:       []platform.ProcessInfo{peer},
		App:         app,
		AppSource:   caller.AppFromResponsible,
		Session:     caller.SessionID{PID: 42, Start: t0},
		SessionRoot: peer.Ref,
		Unknown:     true,
	}
	for _, key := range []string{"unksession", "unkapp", "anysession", "anyapp", "ownsession"} {
		out := en.e.EvaluateSSH(key, c)
		if !out.Unknown || !out.Policy.Gate.Prompts() {
			t.Fatalf("%s: setup %+v", key, out)
		}
		mustBeOneShot(t, "unknown chain with a session, "+key, out)
	}
}

// gate none and gate block are never remembered, even if a policy reaching
// the engine still carries a remembering scope (Parse normalises it away;
// the engine must not depend on that).
func TestSilentAndBlockNeverRememberedEvenWithScope(t *testing.T) {
	anyM := []config.Matcher{{Kind: config.MatchAny, Name: "any"}}
	cfg := &config.Config{
		APIVersion: config.APIVersion,
		Kind:       config.KindConfig,
		Defaults:   config.Defaults{Timeout: config.DefaultTimeout, Fallback: config.Policy{Scope: config.ScopeSession, Gate: config.GateBlock, Expire: time.Hour}},
		Apps:       map[string]config.Matcher{},
		SSHAgent: config.SSHAgent{Keys: map[string]*config.Key{
			"none-session": {Name: "none-session", Rules: []config.Rule{{Index: 1, Apps: anyM, Policy: config.Policy{Scope: config.ScopeSession, Gate: config.GateNone, Expire: time.Hour}}}},
			"none-app":     {Name: "none-app", Rules: []config.Rule{{Index: 1, Apps: anyM, Policy: config.Policy{Scope: config.ScopeApp, Gate: config.GateNone}}}},
			"block-app":    {Name: "block-app", Rules: []config.Rule{{Index: 1, Apps: anyM, Policy: config.Policy{Scope: config.ScopeApp, Gate: config.GateBlock}}}},
			"own-block":    {Name: "own-block", Own: &config.Policy{Scope: config.ScopeSession, Gate: config.GateBlock}},
		}},
	}
	f := fake.New(t0)
	st, _ := trust.Open(fake.NewVault())
	r := &caller.Resolver{P: f}
	e := New(cfg, &match.Evaluator{Trust: st})
	tab := f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := r.Resolve(tab.Peer())
	if c.Unknown || c.Session.IsZero() || c.AppIdentity() == "" {
		t.Fatalf("setup: chain must be known with session and app identity: %+v", c)
	}
	for _, key := range []string{"none-session", "none-app", "block-app", "own-block", "nosuchkey"} {
		mustBeOneShot(t, key, e.EvaluateSSH(key, c))
	}
}

// cfgRun has the rules Milestone 7 tells apart: session rules a
// tool in the tab satisfies (claude and mytool, by signature), one the
// app satisfies (iterm), one Apple's ssh satisfies (by signature), and a
// scope: app rule.
const cfgRun = `apiVersion: nazar/v1
kind: Config
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
  ssh:
    signed: { team: apple, id: com.apple.openssh }
  mytool:
    signed: { team: TOOLTEAM01, id: mytool }
ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
        - apps: [iterm]
          scope: session
          gate: login
    tool:
      rules:
        - apps: [mytool]
          scope: session
          gate: dialog
    applessh:
      rules:
        - apps: [ssh]
          scope: session
          gate: dialog
    appkey:
      rules:
        - apps: [iterm]
          scope: app
          gate: dialog
`

// runOf is the session ID of a process's run, as a session root's.
func runOf(t *testing.T, f *fake.Fake, ref platform.ProcessRef) caller.SessionID {
	t.Helper()
	info, err := f.Process(ref)
	if err != nil {
		t.Fatal(err)
	}
	return caller.SessionID{PID: ref.PID, Start: info.StartTime}
}

// Milestone 7: a session approval for a rule a tool in the tab
// satisfied (a non-Apple signed: process below the session root)
// is the tool's run: the scope id, the session and the root the broker
// watches are that process's. Whatever the run starts shares it, a nested
// claude -p included; another run of the tool in the same tab is another
// scope.
func TestSessionScopeIsTheToolsRun(t *testing.T) {
	en := newEnvSrc(t, cfgRun)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	claude := tab.Procs[0]
	run := runOf(t, en.f, claude)
	out := en.eval("github", tab.Peer())
	if out.RuleIndex != 1 || out.OneShot || out.ScopeID != "session:"+run.String() || out.Session != run || out.Root != claude {
		t.Fatalf("claude in a tab: %+v, want the claude run %s rooted at %v", out, run, claude)
	}
	if c := en.r.Resolve(tab.Peer()); out.Session == c.Session || out.Root == c.SessionRoot {
		t.Fatal("control: the run must not be the tab's session")
	}
	if o := en.eval("github", en.f.Launch(claude, fake.SSHProc("h2"))); o.ScopeID != out.ScopeID || o.Root != claude {
		t.Fatalf("a second command under the same claude: %+v, want scope %q", o, out.ScopeID)
	}
	sh := fake.Proc{Path: "/bin/sh", Code: fake.AppleCode("com.apple.sh")}
	inner := en.f.Launch(en.f.Launch(claude, sh), fake.ClaudeProc())
	if o := en.eval("github", en.f.Launch(inner, fake.SSHProc("h"))); o.ScopeID != out.ScopeID || o.Root != claude {
		t.Fatalf("a nested claude: %+v, want the outer run %q", o, out.ScopeID)
	}
	second := en.f.Launch(tab.Shell, fake.ClaudeProc())
	o := en.eval("github", en.f.Launch(second, fake.SSHProc("h")))
	if o.ScopeID == out.ScopeID || o.ScopeID != "session:"+runOf(t, en.f, second).String() || o.Root != second || o.OneShot {
		t.Fatalf("another claude in the tab: %+v, want its own run", o)
	}
	// Any non-Apple signed tool is a run too.
	tool := fake.Proc{Path: "/opt/homebrew/bin/mytool", Code: platform.CodeIdentity{Signed: true, TeamID: "TOOLTEAM01", SigningID: "mytool", CDHash: []byte{0x7a}}}
	mt := en.f.Launch(tab.Shell, tool)
	if o := en.eval("tool", en.f.Launch(mt, fake.SSHProc("h"))); o.RuleIndex != 1 || o.OneShot || o.ScopeID != "session:"+runOf(t, en.f, mt).String() || o.Root != mt {
		t.Fatalf("a signed tool in the tab: %+v, want its run", o)
	}
}

// What stays the tab's shell (unchanged by Milestone 7): a rule the app satisfies
// (app:), one an Apple-signed process satisfies, by signature
// (the shells and ssh are the session, not a run in it), and one a tool
// above the session root satisfies (one the app started directly: the root
// is the shell below it, spec 4.1 step 4). A scope: app rule is rooted at
// the app and keeps the tab's session for the audit line.
func TestSessionScopeStaysTheTabForEverythingElse(t *testing.T) {
	en := newEnvSrc(t, cfgRun)
	tab := en.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	c := en.r.Resolve(tab.Peer())
	for key, rule := range map[string]int{"github": 2, "applessh": 1} {
		out := en.eval(key, tab.Peer())
		if out.RuleIndex != rule || out.OneShot || out.ScopeID != "session:"+c.Session.String() || out.Session != c.Session || out.Root != tab.Shell {
			t.Fatalf("%s: %+v, want rule %d in the tab's session %s rooted at the shell", key, out, rule, c.Session)
		}
	}
	if out := en.eval("appkey", tab.Peer()); out.ScopeID != "app:H7V7XYVQ7D:com.googlecode.iterm2" || out.Root != tab.App || out.Session != c.Session || out.OneShot {
		t.Fatalf("scope app: %+v, want the app's scope rooted at the app", out)
	}
	// Cursor's Claude extension: app → claude → sh → ssh. The root is sh.
	direct := en.f.Launch(tab.App, fake.ClaudeProc())
	sh := en.f.Launch(direct, fake.Proc{Path: "/bin/sh", Code: fake.AppleCode("com.apple.sh")})
	peer := en.f.Launch(sh, fake.SSHProc("h"))
	dc := en.r.Resolve(peer)
	if dc.SessionRoot != sh {
		t.Fatalf("control: root %v, want sh %v", dc.SessionRoot, sh)
	}
	if out := en.eval("github", peer); out.RuleIndex != 1 || out.OneShot || out.ScopeID != "session:"+dc.Session.String() || out.Root != sh {
		t.Fatalf("a tool above the root: %+v, want the shell's session", out)
	}
}

// cfgExample is an example config's github key: Claude Code silent, the
// terminal and other apps with Touch ID, everything else at the end.
const cfgExample = `apiVersion: nazar/v1
kind: Config
apps:
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }
  iterm:
    app: com.googlecode.iterm2
  cursor:
    app: com.todesktop.230313mzl4w4u92
ssh_agent:
  keys:
    github:
      rules:
        - apps: [claude]
          gate: none
        - apps: [iterm]
          scope: session
          gate: login
        - apps: [cursor]
          scope: session
          gate: login
        - apps: [any]
          scope: session
          gate: login
    claudesession:
      rules:
        - apps: [claude]
          scope: session
          gate: dialog
        - apps: [any]
          gate: block
    claudeapp:
      rules:
        - apps: [claude]
          scope: app
          gate: login
`

// An example chain: Claude Code in an iTerm2 tab whose
// iTermServer was orphaned before nazar-agent saw it (an unknown chain)
// gets rule 1, Claude Code's (gate none), not rule 4 (apps: any, a Touch
// ID prompt on every git fetch). It stays unknown, and names claude as the
// process that matched.
func TestOrphanedClaudeTabGetsTheClaudeRule(t *testing.T) {
	en := newEnvSrc(t, cfgExample)
	tab := en.f.OrphanedClaudeTab()
	out := en.eval("github", tab.Peer())
	if out.RuleIndex != 1 || out.Policy.Gate != config.GateNone || !out.Unknown || out.Matched != tab.Procs[0] {
		t.Fatalf("orphaned claude tab: %+v, want rule 1 (gate none) matched by claude %v", out, tab.Procs[0])
	}
	mustBeOneShot(t, "orphaned claude tab", out)
	// The bare shell of such a tab: no claude, rule 4, one-shot.
	bare := en.f.OrphanedITermTab(fake.SSHProc("git@github.com"))
	o := en.eval("github", bare.Peer())
	if o.RuleIndex != 4 || !o.Unknown || !o.Matched.IsZero() {
		t.Fatalf("bare orphaned tab: %+v, want rule 4", o)
	}
	mustBeOneShot(t, "bare orphaned tab", o)
}

// A signed: match in an unknown chain is never remembered (spec 4.2): the
// chain has no session root and no app identity, and a tool's run
// is a run inside a session only when there is one. scope: session and
// scope: app are one-shot there, with no session and no root to watch.
func TestUnknownChainSignedMatchIsOneShot(t *testing.T) {
	en := newEnvSrc(t, cfgExample)
	tab := en.f.OrphanedClaudeTab()
	for _, key := range []string{"claudesession", "claudeapp"} {
		out := en.eval(key, tab.Peer())
		if out.RuleIndex != 1 || !out.Unknown || !out.Policy.Gate.Prompts() || out.Matched != tab.Procs[0] {
			t.Fatalf("%s: %+v, want rule 1 matched by claude", key, out)
		}
		mustBeOneShot(t, key, out)
		if !out.Session.IsZero() || !out.Root.IsZero() {
			t.Fatalf("%s: an unknown chain got a session %v or root %v", key, out.Session, out.Root)
		}
	}
	// Defence in depth: a chain that carries a session root with the tool
	// below it stays one-shot when it is unknown.
	c := en.r.Resolve(tab.Peer())
	c.SessionRoot, c.Session = tab.Shell, runOf(t, en.f, tab.Shell)
	out := en.e.EvaluateSSH("claudesession", c)
	if out.RuleIndex != 1 {
		t.Fatalf("setup: %+v", out)
	}
	mustBeOneShot(t, "unknown chain with a session root", out)
}

// An unknown chain that may be missing processes (truncated), or holds only
// an impostor of Claude Code, does not get Claude Code's rule.
func TestUnknownChainWithoutAVerifiedToolFallsThrough(t *testing.T) {
	en := newEnvSrc(t, cfgExample)
	bash := fake.Proc{Path: "/bin/bash", Code: fake.AppleCode("com.apple.bash")}
	parent := en.f.Launch(platform.ProcessRef{}, bash)
	for i := 0; i < caller.DefaultMaxDepth; i++ {
		parent = en.f.Launch(parent, bash)
	}
	deep := en.f.Launch(en.f.Launch(parent, fake.ClaudeProc()), fake.SSHProc("h"))
	if c := en.r.Resolve(deep); !c.Unknown || !c.Truncated {
		t.Fatalf("setup: want a truncated unknown chain: %+v", c)
	}
	if out := en.eval("github", deep); out.RuleIndex != 4 {
		t.Fatalf("truncated unknown chain with claude: %+v, want rule 4", out)
	}
	adhoc := fake.Proc{Path: "/Users/u/.local/bin/claude", Code: platform.CodeIdentity{Signed: true, AdHoc: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code"}}
	imp := en.f.OrphanedITermTab(adhoc, fake.SSHProc("h"))
	if out := en.eval("github", imp.Peer()); out.RuleIndex != 4 {
		t.Fatalf("ad-hoc claude in an unknown chain: %+v, want rule 4", out)
	}
}
