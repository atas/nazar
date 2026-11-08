package broker

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/approval"
	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// ---------------------------------------------------------------------------
// Spec 5 "Session-bind and forwarding": forwarded connections never
// use a remembered approval, and under gate: none they get a one-time dialog
// instead of being silent, so a remote host can't sign quietly.
// ---------------------------------------------------------------------------

// fwdReq is e.req for a request that came through a forwarded agent.
func (e *env) fwdReq(key string, peer platform.ProcessRef) Request {
	r := e.req(key, peer)
	r.Forwarded = true
	return r
}

// A forwarded request whose rule is gate: none shows the dialog (never the
// login prompt), every time: it is approved for that one request only,
// nothing is remembered, and the audit line names the gate that actually
// ran (dialog) with a one-shot scope.
func TestForwardedGateNoneGetsOneTimeDialog(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	var refs []platform.ApprovalRef
	for i := 1; i <= 2; i++ {
		req := e.fwdReq("deploy", tab.Peer()) // deploy: apps iterm, gate none
		inner := req.Do
		req.Do = func(ref platform.ApprovalRef) error { refs = append(refs, ref); return inner(ref) }
		r := e.b.Handle(req)
		if !r.Allowed() || r.Decision != audit.Approved {
			t.Fatalf("forwarded request %d under gate none: %+v, want approved through a dialog", i, r)
		}
		if n := e.f.CountShown(fake.KindConfirm); n != i {
			t.Fatalf("forwarded request %d: %d dialogs shown, want %d (one per forwarded request, never silent)", i, n, i)
		}
		if n := e.f.CountShown(fake.KindAuthenticate); n != 0 {
			t.Fatalf("forwarded gate none must use the dialog, not the login prompt (%d shown)", n)
		}
		if got := e.calls.Load(); got != int32(i) {
			t.Fatalf("Do ran %d times after %d approved requests", got, i)
		}
		f := e.lastLine(t)
		if f["decision"] != "approved" || f["gate"] != "dialog" || f["scope"] != "use" {
			t.Fatalf("forwarded gate none audit %v, want decision=approved gate=dialog scope=use", f)
		}
	}
	for _, ref := range refs {
		if ref != 0 {
			t.Fatalf("a dialog issues no approval ref; Do got %v", ref)
		}
	}
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("a forwarded approval must never be remembered: %+v", l)
	}
	if e.f.LiveApprovals() != 0 {
		t.Fatal("no approval may be left live")
	}
	// The same caller locally is still governed by gate none: silent.
	shown := len(e.f.Shown())
	if r := e.b.Handle(e.req("deploy", tab.Peer())); r.Decision != audit.Allowed || len(e.f.Shown()) != shown {
		t.Fatalf("a local gate none request must stay silent: %+v (prompts %d -> %d)", r, shown, len(e.f.Shown()))
	}
	if f := e.lastLine(t); f["gate"] != "none" || f["decision"] != "allowed" {
		t.Fatalf("local gate none audit %v", f)
	}
}

// Denying (or ignoring) the one-time dialog refuses the forwarded request:
// gate none never turns a "no" into a silent yes.
func TestForwardedGateNoneDenialAndTimeoutRefuse(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))

	e.f.ScriptConfirm(fake.Answer{Allow: false})
	r := e.b.Handle(e.fwdReq("deploy", tab.Peer()))
	if r.Allowed() || r.Decision != audit.Denied {
		t.Fatalf("denied dialog: %+v", r)
	}
	if f := e.lastLine(t); f["decision"] != "denied" || f["gate"] != "dialog" {
		t.Fatalf("audit %v", f)
	}

	release := make(chan struct{})
	defer close(release)
	e.f.ScriptConfirm(fake.Answer{Allow: true, Wait: release})
	r = e.b.Handle(e.fwdReq("deploy", tab.Peer())) // env timeout is 200ms
	if r.Allowed() || r.Decision != audit.Timeout {
		t.Fatalf("unanswered dialog: %+v", r)
	}
	if e.calls.Load() != 0 {
		t.Fatalf("Do ran %d times for refused forwarded requests", e.calls.Load())
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 2 {
		t.Fatalf("dialogs %d, want 2", n)
	}
	if len(e.cache.List()) != 0 {
		t.Fatal("nothing may be remembered")
	}
}

// A local approval never lets a forwarded gate-none request through
// quietly either, and a forwarded one-time dialog never seeds the cache
// for concurrent forwarded requests: each one asks.
func TestConcurrentForwardedGateNoneEachAsk(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	var wg sync.WaitGroup
	results := make([]Result, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = e.b.Handle(e.fwdReq("deploy", tab.Peer())) }(i)
	}
	wg.Wait()
	for i, r := range results {
		if r.Decision != audit.Approved {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if n := e.f.CountShown(fake.KindConfirm); n != len(results) {
		t.Fatalf("%d dialogs for %d forwarded requests: forwarded requests never share or reuse an approval", n, len(results))
	}
}

// ---------------------------------------------------------------------------
// A shared-prompt leader that panics, or any path that ends with no
// decision, is logged as decision=error (a line audit.ParseLine accepts) and
// the request is refused. Spec 4.4 (shared prompts), 4.6 (every request is
// logged with one of the six decisions), 9 (fail closed).
// ---------------------------------------------------------------------------

// panicExitPlatform is the fake whose OnProcessExit panics while panicking
// is set. The broker installs the session-exit watcher inside the shared
// prompt, after the user answered, so this makes the prompt's leader panic.
type panicExitPlatform struct {
	*fake.Fake
	panicking atomic.Bool
}

func (p *panicExitPlatform) OnProcessExit(ref platform.ProcessRef, fn func()) {
	if p.panicking.Load() {
		panic("exit watcher crashed")
	}
	p.Fake.OnProcessExit(ref, fn)
}

// withPanickingExitWatch rebuilds e's broker over a panicExitPlatform.
func withPanickingExitWatch(e *env) *panicExitPlatform {
	pp := &panicExitPlatform{Fake: e.f}
	o := e.b.o
	o.Platform = pp
	e.b = New(o)
	return pp
}

// handleRecovering runs Handle and reports a panic instead of crashing the
// test binary: a panic escaping Handle would take the whole agent down.
func handleRecovering(b *Broker, req Request) (r Result, panicked any) {
	defer func() { panicked = recover() }()
	return b.Handle(req), nil
}

func TestPanickingSharedPromptLeaderFailsClosed(t *testing.T) {
	e := newEnv(t)
	pp := withPanickingExitWatch(e)
	pp.panicking.Store(true)
	release := make(chan struct{})
	e.f.ScriptConfirm(fake.Answer{Allow: true, Wait: release})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc()) // github rule 1: dialog, scope session
	const n = 3
	results := make([]Result, n)
	panics := make([]any, n)
	var wg sync.WaitGroup
	for i := range n {
		peer := e.f.Launch(tab.Procs[0], fake.SSHProc("h"))
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], panics[i] = handleRecovering(e.b, e.req("github", peer)) }(i)
	}
	waitFor(t, "the shared dialog was not shown", func() bool { return e.f.CountShown(fake.KindConfirm) == 1 })
	time.Sleep(50 * time.Millisecond) // let the others queue on the shared prompt
	close(release)
	wg.Wait()

	if c := e.f.CountShown(fake.KindConfirm); c != 1 {
		t.Fatalf("%d dialogs, want one shared dialog", c)
	}
	for i := range n {
		if panics[i] != nil {
			t.Errorf("request %d: Handle let a panic escape: %v", i, panics[i])
			continue
		}
		if results[i].Allowed() || results[i].Decision != audit.Error {
			t.Errorf("request %d: %+v, want refused with decision error", i, results[i])
		}
	}
	if c := e.calls.Load(); c != 0 {
		t.Fatalf("Do ran %d times after the prompt crashed", c)
	}
	lines := e.sink.Lines()
	if len(lines) != n {
		t.Fatalf("%d audit lines for %d requests:\n%v", len(lines), n, lines)
	}
	for _, l := range lines {
		f, err := audit.ParseLine(l)
		if err != nil {
			t.Fatalf("audit line does not parse (%v): %q", err, l)
		}
		if f["decision"] != "error" || f["reason"] == "" {
			t.Fatalf("audit %v, want decision=error with a reason", f)
		}
	}
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("a refused request must not leave its approval remembered (its session watcher never started): %+v", l)
	}

	// The failure is not sticky: the key is free, the next request asks
	// again, and its approval still ends with the session (a crashed
	// watcher must not leave the session marked as already watched).
	pp.panicking.Store(false)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	r, p := handleRecovering(e.b, e.req("github", e.f.Launch(tab.Procs[0], fake.SSHProc("h"))))
	if p != nil || r.Decision != audit.Approved {
		t.Fatalf("after the crash: %+v (panic %v)", r, p)
	}
	if c := e.f.CountShown(fake.KindConfirm); c != 2 {
		t.Fatalf("dialogs %d, want a new one", c)
	}
	if len(e.cache.List()) != 1 {
		t.Fatalf("cache %+v", e.cache.List())
	}
	e.f.Exit(tab.Procs[0]) // the claude run ends (the approval is the run's)
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("the run ending must still end the approval: %+v", l)
	}
}

// A request that is alone in its prompt is no different: a panic after the
// user said yes is an error, logged and refused, not a crash and not a pass.
func TestPanickingLonePromptFailsClosed(t *testing.T) {
	e := newEnv(t)
	pp := withPanickingExitWatch(e)
	pp.panicking.Store(true)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")) // github rule 2: login, scope session
	r, p := handleRecovering(e.b, e.req("github", tab.Peer()))
	if p != nil {
		t.Fatalf("Handle let a panic escape: %v", p)
	}
	if r.Allowed() || r.Decision != audit.Error || e.calls.Load() != 0 {
		t.Fatalf("%+v (Do ran %d times)", r, e.calls.Load())
	}
	if f := e.lastLine(t); f["decision"] != "error" {
		t.Fatalf("audit %v", f)
	}
	if len(e.cache.List()) != 0 {
		t.Fatalf("cache %+v", e.cache.List())
	}
	waitFor(t, "the login approval of the refused request was not released", func() bool { return e.f.LiveApprovals() == 0 })
}

// Every audit line the broker writes carries one of the six decisions of
// spec 4.6, whatever the request ran into; an empty decision would make the
// line unreadable by `nazar log` (audit.ParseLine refuses it).
func TestEveryAuditLineHasAKnownDecision(t *testing.T) {
	e := newEnv(t)
	pp := withPanickingExitWatch(e)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	stray := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/tmp/stray", Code: fake.Unsigned})
	pp.panicking.Store(true)
	handleRecovering(e.b, e.req("github", tab.Peer())) // crashes in the prompt
	pp.panicking.Store(false)
	handleRecovering(e.b, e.req("github", tab.Peer()))    // approved
	handleRecovering(e.b, e.req("github", tab.Peer()))    // cached
	handleRecovering(e.b, e.req("github", stray))         // blocked
	handleRecovering(e.b, e.fwdReq("deploy", tab.Peer())) // forwarded none: dialog
	known := map[string]bool{"allowed": true, "approved": true, "denied": true, "timeout": true, "blocked": true, "error": true}
	lines := e.sink.Lines()
	if len(lines) != 5 {
		t.Fatalf("%d audit lines, want 5: %v", len(lines), lines)
	}
	for _, l := range lines {
		f, err := audit.ParseLine(l)
		if err != nil || !known[f["decision"]] {
			t.Fatalf("audit line %q: %v %v", l, f, err)
		}
	}
}

// The leader of a shared prompt really panics (not in a place the broker
// recovers on its own): Flight hands every waiter the zero gateResult. A
// zero result is neither ok nor a decision, and must be refused as
// decision=error rather than treated as anything else. The leader here is
// the test itself, holding the exact Flight key that Handle computes for
// the request, so the waiter queues on it as it would on another request's
// prompt.
func TestSharedPromptWaiterRefusesLeaderPanic(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc()) // github rule 1: dialog, scope session
	peer := e.f.Launch(tab.Procs[0], fake.SSHProc("h"))
	req := e.req("github", peer)
	out := e.eng.Load().EvaluateSSH("github", req.Chain)
	// The key the broker shares the prompt under, op included (Milestone 7).
	key := approval.Key{Target: out.Target, Rule: out.RuleID, ScopeID: out.ScopeID, Receiver: out.Receiver, Op: req.Op.ID}

	started := make(chan struct{})
	release := make(chan struct{})
	var leaderPanic atomic.Value
	var leader sync.WaitGroup
	leader.Add(1)
	go func() {
		defer leader.Done()
		defer func() { leaderPanic.Store(recover()) }()
		e.b.flight.Do(key, func() gateResult {
			close(started)
			<-release
			panic("prompt leader crashed")
		})
	}()
	<-started

	var waiter sync.WaitGroup
	var r Result
	var panicked any
	waiter.Add(1)
	go func() { defer waiter.Done(); r, panicked = handleRecovering(e.b, req) }()
	time.Sleep(50 * time.Millisecond) // let the waiter queue on the leader's key
	close(release)
	leader.Wait()
	waiter.Wait()

	if leaderPanic.Load() == nil {
		t.Fatal("the leader's panic must propagate to the leader (Flight does not swallow it)")
	}
	if panicked != nil {
		t.Fatalf("Handle let a panic escape: %v", panicked)
	}
	if r.Allowed() || r.Decision != audit.Error || r.Reason == "" {
		t.Fatalf("%+v, want refused with decision error and a reason", r)
	}
	if c := e.calls.Load(); c != 0 {
		t.Fatalf("Do ran %d times after the shared prompt crashed", c)
	}
	if n := len(e.f.Shown()); n != 0 {
		t.Fatalf("%d prompts shown: the waiter must not have run its own prompt", n)
	}
	lines := e.sink.Lines()
	if len(lines) != 1 {
		t.Fatalf("%d audit lines, want 1:\n%v", len(lines), lines)
	}
	f, err := audit.ParseLine(lines[0])
	if err != nil {
		t.Fatalf("audit line does not parse (%v): %q", err, lines[0])
	}
	if f["decision"] != "error" || f["reason"] == "" || f["target"] != "ssh:github" {
		t.Fatalf("audit %v, want decision=error with a reason", f)
	}
	if l := e.cache.List(); len(l) != 0 {
		t.Fatalf("nothing may be remembered: %+v", l)
	}
	// The key is free again: a fresh request runs its own prompt.
	if r := e.b.Handle(e.req("github", e.f.Launch(tab.Procs[0], fake.SSHProc("h")))); r.Decision != audit.Approved {
		t.Fatalf("after the crash: %+v", r)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("dialogs %d, want 1", n)
	}
}

// panicGatePlatform is the fake whose gates themselves panic (a platform
// bug in the prompt), on the broker's gate goroutine.
type panicGatePlatform struct{ *fake.Fake }

func (p *panicGatePlatform) Authenticate(platform.AuthPolicy, platform.Prompt) (platform.ApprovalRef, error) {
	panic("login prompt crashed")
}

func (p *panicGatePlatform) Confirm(platform.Prompt) (bool, error) { panic("dialog crashed") }

// A gate that panics is an error for that request: logged as
// decision=error, refused, no approval left live or remembered, and the
// agent process survives (the panic is on the gate goroutine, where no
// caller's recover could reach it).
func TestPanickingGateFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		req       func(e *env) Request
		gate      string
		forwarded bool
	}{
		{name: "dialog", gate: "dialog", req: func(e *env) Request {
			tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h")) // github rule 1: dialog
			return e.req("github", tab.Peer())
		}},
		{name: "login", gate: "login", req: func(e *env) Request {
			tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")) // github rule 2: login
			return e.req("github", tab.Peer())
		}},
		{name: "one-shot dialog", gate: "dialog", forwarded: true, req: func(e *env) Request {
			tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")) // deploy: gate none, forwarded → dialog
			return e.fwdReq("deploy", tab.Peer())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
			o := e.b.o
			o.Platform = &panicGatePlatform{Fake: e.f}
			e.b = New(o)
			req := tc.req(e)
			r, p := handleRecovering(e.b, req)
			if p != nil {
				t.Fatalf("Handle let a panic escape: %v", p)
			}
			if r.Allowed() || r.Decision != audit.Error || !strings.Contains(r.Reason, tc.gate+" gate failed") {
				t.Fatalf("%+v, want refused with decision error naming the %s gate", r, tc.gate)
			}
			if c := e.calls.Load(); c != 0 {
				t.Fatalf("Do ran %d times after the gate crashed", c)
			}
			lines := e.sink.Lines()
			if len(lines) != 1 {
				t.Fatalf("%d audit lines, want 1:\n%v", len(lines), lines)
			}
			f, err := audit.ParseLine(lines[0])
			if err != nil {
				t.Fatalf("audit line does not parse (%v): %q", err, lines[0])
			}
			if f["decision"] != "error" || f["gate"] != tc.gate {
				t.Fatalf("audit %v, want decision=error gate=%s", f, tc.gate)
			}
			if l := e.cache.List(); len(l) != 0 {
				t.Fatalf("nothing may be remembered: %+v", l)
			}
			if e.f.LiveApprovals() != 0 {
				t.Fatal("no approval may be left live")
			}
			if !tc.forwarded {
				// Not sticky: the key is free for the next request.
				r, p := handleRecovering(e.b, req)
				if p != nil || r.Decision != audit.Error {
					t.Fatalf("second request: %+v (panic %v)", r, p)
				}
			}
		})
	}
}

// The enclave operation itself panics (under gate none, where nothing else
// stands between the policy and the operation): the request is refused as
// decision=error with exactly one audit line, and Handle returns rather
// than letting the panic take the agent down.
func TestPanickingOperationFailsClosed(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h")) // deploy: gate none
	req := e.req("deploy", tab.Peer())
	req.Do = func(platform.ApprovalRef) error { panic("sign crashed") }
	r, p := handleRecovering(e.b, req)
	if p != nil {
		t.Fatalf("Handle let a panic escape: %v", p)
	}
	if r.Allowed() || r.Decision != audit.Error || !strings.Contains(r.Reason, "sign crashed") {
		t.Fatalf("%+v, want refused with decision error carrying the panic", r)
	}
	lines := e.sink.Lines()
	if len(lines) != 1 {
		t.Fatalf("%d audit lines, want exactly 1:\n%v", len(lines), lines)
	}
	f, err := audit.ParseLine(lines[0])
	if err != nil {
		t.Fatalf("audit line does not parse (%v): %q", err, lines[0])
	}
	if f["decision"] != "error" || f["gate"] != "none" || f["target"] != "ssh:deploy" {
		t.Fatalf("audit %v, want decision=error gate=none target=ssh:deploy", f)
	}
	// The next request on the same key is judged afresh.
	if r := e.b.Handle(e.req("deploy", tab.Peer())); r.Decision != audit.Allowed {
		t.Fatalf("after the crash: %+v", r)
	}
}
