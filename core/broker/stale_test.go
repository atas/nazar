package broker

// Stale remembered approvals are dropped and re-asked once (spec 4.3,
// 4.4; spike S1: LocalAuthentication approval reuse expires after 6-10
// minutes, so a cached LAContext WILL stop being accepted on macOS).
//
// When the operation fails with platform.ErrAuthRequired for an approval
// ref that came from the cache (or was shared from another request's
// prompt), the broker must:
//   - remove that cache entry and release its ref;
//   - audit it: decision=error, reason "remembered approval no longer accepted";
//   - run the rule's gate again ONCE for this request (one fresh prompt) and,
//     if approved, remember the new ref as usual;
//   - never loop: ErrAuthRequired on the fresh ref fails the request with
//     decision=error;
//   - share one fresh prompt among concurrent requests that held the same
//     stale entry.
// One-shot paths (forwarded agents, scope: use, unknown chains) never use a
// remembered approval, so they are unaffected.

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

const staleReason = "remembered approval no longer accepted"

// staleSigner stands in for the Secure Enclave signing with a key created
// with user presence. It signs through the fake enclave, so a released or
// unknown ref (or 0) is ErrAuthRequired, and on top of that it rejects refs
// marked dead: an LAContext that macOS stopped honouring behind the
// broker's back while it is still allocated (so releasing it is still the
// broker's job).
type staleSigner struct {
	f      *fake.Fake
	handle []byte

	mu        sync.Mutex
	dead      map[platform.ApprovalRef]bool
	rejectAll bool
	seen      []platform.ApprovalRef // every ref the operation ran with
	ok        atomic.Int32           // successful signatures
}

func newStaleSigner(t *testing.T, f *fake.Fake) *staleSigner {
	t.Helper()
	h, _, err := f.CreateKey(platform.PurposeSign, platform.AuthUserPresence, platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	return &staleSigner{f: f, handle: h, dead: map[platform.ApprovalRef]bool{}}
}

// kill makes ref unusable without releasing it.
func (s *staleSigner) kill(ref platform.ApprovalRef) {
	s.mu.Lock()
	s.dead[ref] = true
	s.mu.Unlock()
}

// killAll makes the platform reject every approval from now on.
func (s *staleSigner) killAll() {
	s.mu.Lock()
	s.rejectAll = true
	s.mu.Unlock()
}

func (s *staleSigner) calls() []platform.ApprovalRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]platform.ApprovalRef(nil), s.seen...)
}

func (s *staleSigner) do(ref platform.ApprovalRef) error {
	s.mu.Lock()
	s.seen = append(s.seen, ref)
	dead := s.dead[ref] || s.rejectAll
	s.mu.Unlock()
	if dead {
		// The real platform wraps the sentinel (errSecAuthFailed and the like).
		return fmt.Errorf("SecKeyCreateSignature: %w", platform.ErrAuthRequired)
	}
	if _, err := s.f.Sign(s.handle, []byte("session-id+userauth"), ref); err != nil {
		return err
	}
	s.ok.Add(1)
	return nil
}

func (e *env) staleReq(key string, peer platform.ProcessRef, s *staleSigner) Request {
	r := e.req(key, peer)
	r.Do = s.do
	return r
}

// auditLines parses every audit line written so far.
func (e *env) auditLines(t *testing.T) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, l := range e.sink.Lines() {
		f, err := audit.ParseLine(l)
		if err != nil {
			t.Fatalf("unparseable audit line %q: %v", l, err)
		}
		out = append(out, f)
	}
	return out
}

// staleLines returns the audit lines that report a dropped stale approval.
func (e *env) staleLines(t *testing.T) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, f := range e.auditLines(t) {
		if f["reason"] == staleReason {
			out = append(out, f)
		}
	}
	return out
}

// handleWithin runs Handle and fails the test if it does not return: a
// broker that re-asks in a loop would never return while the gate keeps
// approving.
func handleWithin(t *testing.T, b *Broker, req Request) Result {
	t.Helper()
	ch := make(chan Result, 1)
	go func() { ch <- b.Handle(req) }()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return: re-asking must not loop")
		return Result{}
	}
}

// approveOnce fills the cache with a login approval for tab (cfgSrc: key
// github, iTerm2 rule 2, scope session, gate login) and returns its ref.
func approveOnce(t *testing.T, e *env, s *staleSigner, tab fake.Chain) platform.ApprovalRef {
	t.Helper()
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Approved {
		t.Fatalf("first request: %+v", r)
	}
	list := e.cache.List()
	if len(list) != 1 || list[0].Ref == 0 {
		t.Fatalf("want one cached login approval with a ref, got %+v", list)
	}
	return list[0].Ref
}

func cachedRefs(e *env) []platform.ApprovalRef {
	var out []platform.ApprovalRef
	for _, en := range e.cache.List() {
		out = append(out, en.Ref)
	}
	return out
}

func countRef(refs []platform.ApprovalRef, ref platform.ApprovalRef) int {
	n := 0
	for _, r := range refs {
		if r == ref {
			n++
		}
	}
	return n
}

// The core case: the platform stops honouring a remembered login approval.
// The next request drops it (released, audited) and prompts exactly once,
// signs with the fresh approval, and remembers that one as usual.
func TestStaleRememberedApprovalIsReaskedOnce(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	stale := approveOnce(t, e, s, tab)
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Allowed {
		t.Fatalf("a live remembered approval is used without a prompt: %+v", r)
	}
	linesBefore := len(e.sink.Lines())

	s.kill(stale) // macOS stopped honouring the LAContext (spike S1)

	again := e.f.Launch(tab.Shell, fake.SSHProc("git@github.com"))
	r := handleWithin(t, e.b, e.staleReq("github", again, s))
	if !r.Allowed() || r.Decision != audit.Approved {
		t.Fatalf("a stale approval must be re-asked and the fresh one used: %+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 2 {
		t.Fatalf("login prompts %d, want 2 (the first approval and exactly one re-ask)", n)
	}
	if e.f.CountShown(fake.KindConfirm) != 0 {
		t.Fatal("the rule's gate is login; no dialog may be shown")
	}

	// The operation ran with the stale ref once, then with a fresh one.
	calls := s.calls()
	if len(calls) != 4 || calls[2] != stale || calls[3] == stale || calls[3] == 0 {
		t.Fatalf("operation refs %v: want [first, first(cached), stale, fresh]", calls)
	}
	fresh := calls[3]
	if s.ok.Load() != 3 {
		t.Fatalf("successful signatures %d, want 3", s.ok.Load())
	}

	// The stale entry is gone and its ref released exactly once; the fresh
	// approval is remembered in its place.
	if got := countRef(e.f.Released(), stale); got != 1 {
		t.Fatalf("stale ref released %d times, want 1 (released %v)", got, e.f.Released())
	}
	if refs := cachedRefs(e); len(refs) != 1 || refs[0] != fresh {
		t.Fatalf("cache holds %v, want only the fresh ref %v", refs, fresh)
	}
	if e.f.LiveApprovals() != 1 {
		t.Fatalf("live approvals %d, want 1 (the fresh one)", e.f.LiveApprovals())
	}

	// Audit: the drop is one error line with the fixed reason, then the
	// request's own line says approved.
	lines := e.auditLines(t)[linesBefore:]
	if len(lines) != 2 {
		t.Fatalf("audit lines for the re-asked request: %d, want 2 (stale drop + approved): %v", len(lines), lines)
	}
	drop, final := lines[0], lines[1]
	if drop["decision"] != "error" || drop["reason"] != staleReason {
		t.Fatalf("stale drop line %v: want decision=error reason=%q", drop, staleReason)
	}
	if drop["target"] != "ssh:github" || drop["rule"] != "2" || drop["scope"] != "session" || drop["gate"] != "login" {
		t.Fatalf("stale drop line must name the approval it dropped: %v", drop)
	}
	if final["decision"] != "approved" || final["target"] != "ssh:github" {
		t.Fatalf("final line %v", final)
	}

	// The fresh approval is remembered as usual: the next request uses it.
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Allowed || r.Reason != "cached approval" {
		t.Fatalf("the fresh approval must be remembered: %+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 2 {
		t.Fatalf("login prompts %d after reuse, want 2", n)
	}
	if got := len(e.staleLines(t)); got != 1 {
		t.Fatalf("stale lines %d, want 1", got)
	}
}

// The re-asked approval still ends with its scope: closing the tab revokes
// it and releases the fresh ref.
func TestReaskedApprovalEndsWithItsScope(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	s.kill(approveOnce(t, e, s, tab))
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	if len(e.cache.List()) != 1 {
		t.Fatal("fresh approval not remembered")
	}
	e.f.Exit(tab.Shell)
	if len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 {
		t.Fatalf("closing the tab must revoke the re-asked approval (cache %d live %d)", len(e.cache.List()), e.f.LiveApprovals())
	}
}

// The re-asked approval keeps the rule's expire, counted from the re-ask.
func TestReaskedApprovalKeepsExpire(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	stale := approveOnce(t, e, s, tab)
	e.f.Advance(10 * time.Minute)
	s.kill(stale)
	reask := e.f.Now()
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	list := e.cache.List()
	if len(list) != 1 {
		t.Fatalf("cache %+v", list)
	}
	if want := reask.Add(8 * time.Hour); !list[0].Expires.Equal(want) {
		t.Fatalf("fresh approval expires %v, want %v (8h from the re-ask)", list[0].Expires, want)
	}
}

// Never loop: if the platform also rejects the fresh approval, the request
// fails with decision=error after exactly one re-ask, and the rejected
// fresh approval is neither kept nor left live.
func TestFreshApprovalAlsoRejectedFailsWithoutLooping(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	stale := approveOnce(t, e, s, tab)
	s.killAll()

	r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s))
	if r.Decision != audit.Error || r.Allowed() {
		t.Fatalf("a rejected fresh approval must fail the request with error: %+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 2 {
		t.Fatalf("login prompts %d, want 2 (one re-ask, no loop)", n)
	}
	calls := s.calls()
	if len(calls) != 3 || calls[1] != stale || calls[2] == stale || calls[2] == 0 {
		t.Fatalf("operation refs %v: want [first, stale, fresh] and nothing more", calls)
	}
	fresh := calls[2]
	if countRef(cachedRefs(e), fresh) != 0 || countRef(cachedRefs(e), stale) != 0 {
		t.Fatalf("a rejected approval must not stay remembered: cache %v", cachedRefs(e))
	}
	if e.f.LiveApprovals() != 0 {
		t.Fatalf("live approvals %d, want 0 (both rejected refs released)", e.f.LiveApprovals())
	}
	if got := len(e.staleLines(t)); got != 1 {
		t.Fatalf("stale lines %d, want 1 (only the remembered approval was stale)", got)
	}
	if f := e.lastLine(t); f["decision"] != "error" {
		t.Fatalf("final line %v", f)
	}
	if s.ok.Load() != 1 {
		t.Fatalf("signatures %d, want only the first", s.ok.Load())
	}
}

// The fresh prompt is a real gate: a denial after a stale drop is a denial,
// nothing is remembered, and the stale ref is still released.
func TestReaskDeniedAfterStaleDrop(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	stale := approveOnce(t, e, s, tab)
	s.kill(stale)
	e.f.ScriptAuth(fake.Answer{Allow: false})

	r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s))
	if r.Decision != audit.Denied || r.Allowed() {
		t.Fatalf("a denied re-ask must be denied: %+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 2 {
		t.Fatalf("login prompts %d, want 2", n)
	}
	if len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 || countRef(e.f.Released(), stale) != 1 {
		t.Fatalf("cache %v live %d released %v", cachedRefs(e), e.f.LiveApprovals(), e.f.Released())
	}
	if got := len(e.staleLines(t)); got != 1 {
		t.Fatalf("stale lines %d, want 1", got)
	}
	if f := e.lastLine(t); f["decision"] != "denied" {
		t.Fatalf("final line %v", f)
	}
	if s.ok.Load() != 1 {
		t.Fatalf("signatures %d, want 1", s.ok.Load())
	}
	// The next request asks normally.
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
}

// The fresh prompt keeps the gate's timeout: no answer is a timeout, not a
// pass and not a second prompt.
func TestReaskTimesOutAfterStaleDrop(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	s.kill(approveOnce(t, e, s, tab))
	release := make(chan struct{})
	e.f.ScriptAuth(fake.Answer{Allow: true, Wait: release})

	r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s))
	close(release)
	if r.Decision != audit.Timeout || r.Allowed() {
		t.Fatalf("an unanswered re-ask must time out: %+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 2 {
		t.Fatalf("login prompts %d, want 2", n)
	}
	waitFor(t, "the late fresh approval must be released, never remembered", func() bool {
		return e.f.LiveApprovals() == 0 && len(e.cache.List()) == 0
	})
	if s.ok.Load() != 1 {
		t.Fatalf("signatures %d, want 1", s.ok.Load())
	}
}

// Concurrent requests that all held the same stale entry share one fresh
// prompt (spec 4.4: requests waiting on the same scope share one dialog).
func TestConcurrentStaleRequestsShareOneReask(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	stale := approveOnce(t, e, s, tab)
	s.kill(stale)
	release := make(chan struct{})
	e.f.ScriptAuth(fake.Answer{Allow: true, Wait: release})

	const n = 6
	results := make([]Result, n)
	var wg sync.WaitGroup
	for i := range results {
		peer := e.f.Launch(tab.Shell, fake.SSHProc("h"))
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = e.b.Handle(e.staleReq("github", peer, s)) }(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent stale requests did not finish")
	}

	for i, r := range results {
		if !r.Allowed() {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	if got := e.f.CountShown(fake.KindAuthenticate); got != 2 {
		t.Fatalf("login prompts %d, want 2 (one shared re-ask)", got)
	}
	if int(s.ok.Load()) != 1+n {
		t.Fatalf("signatures %d, want %d", s.ok.Load(), 1+n)
	}
	refs := cachedRefs(e)
	if len(refs) != 1 || refs[0] == stale {
		t.Fatalf("cache %v: want one fresh entry", refs)
	}
	if e.f.LiveApprovals() != 1 || countRef(e.f.Released(), stale) != 1 {
		t.Fatalf("live %d, stale released %d times", e.f.LiveApprovals(), countRef(e.f.Released(), stale))
	}
	if got := len(e.staleLines(t)); got < 1 || got > n {
		t.Fatalf("stale lines %d, want between 1 and %d", got, n)
	}
	// Every operation after the drop used the one fresh ref.
	for _, ref := range s.calls()[1:] {
		if ref != stale && ref != refs[0] {
			t.Fatalf("an operation used ref %v, neither the stale nor the shared fresh one", ref)
		}
	}
}

// Concurrent and all rejected: one shared re-ask, every request fails with
// error, nobody prompts again.
func TestConcurrentStaleRequestsAllRejectedDoNotLoop(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	approveOnce(t, e, s, tab)
	s.killAll()
	release := make(chan struct{})
	e.f.ScriptAuth(fake.Answer{Allow: true, Wait: release})

	const n = 4
	results := make([]Result, n)
	var wg sync.WaitGroup
	for i := range results {
		peer := e.f.Launch(tab.Shell, fake.SSHProc("h"))
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = e.b.Handle(e.staleReq("github", peer, s)) }(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("re-asking must not loop")
	}
	for i, r := range results {
		if r.Decision != audit.Error {
			t.Fatalf("request %d: %+v, want error", i, r)
		}
	}
	if got := e.f.CountShown(fake.KindAuthenticate); got != 2 {
		t.Fatalf("login prompts %d, want 2", got)
	}
	if len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 {
		t.Fatalf("cache %v live %d: rejected approvals must not be kept", cachedRefs(e), e.f.LiveApprovals())
	}
}

// A request that held the stale ref but fails only after another request
// already replaced it must not drop the fresh, valid entry, and must not
// prompt again: it signs with the fresh approval.
func TestLateStaleFailureKeepsTheFreshApproval(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	stale := approveOnce(t, e, s, tab)
	s.kill(stale)

	// B looked up the stale entry and is slow to hear back from the enclave.
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	slow := e.staleReq("github", e.f.Launch(tab.Shell, fake.SSHProc("h")), s)
	slow.Do = func(ref platform.ApprovalRef) error {
		if ref == stale {
			once.Do(func() { close(entered) })
			<-unblock
		}
		return s.do(ref)
	}
	bres := make(chan Result, 1)
	go func() { bres <- e.b.Handle(slow) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("B never ran with the stale ref")
	}

	// A drops the stale entry and re-asks; the fresh approval is remembered.
	if r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s)); r.Decision != audit.Approved {
		t.Fatalf("A: %+v", r)
	}
	refs := cachedRefs(e)
	if len(refs) != 1 || refs[0] == stale {
		t.Fatalf("cache after A: %v", refs)
	}
	fresh := refs[0]

	close(unblock)
	var b Result
	select {
	case b = <-bres:
	case <-time.After(5 * time.Second):
		t.Fatal("B did not return")
	}
	if !b.Allowed() {
		t.Fatalf("B must sign with the fresh approval: %+v", b)
	}
	if got := e.f.CountShown(fake.KindAuthenticate); got != 2 {
		t.Fatalf("login prompts %d, want 2 (B shares A's re-ask)", got)
	}
	if refs := cachedRefs(e); len(refs) != 1 || refs[0] != fresh {
		t.Fatalf("B dropped or replaced the fresh approval: cache %v, want [%v]", refs, fresh)
	}
	if e.f.LiveApprovals() != 1 || countRef(e.f.Released(), fresh) != 0 {
		t.Fatalf("the fresh approval must stay live (live %d, released %v)", e.f.LiveApprovals(), e.f.Released())
	}
	if countRef(e.f.Released(), stale) != 1 {
		t.Fatalf("stale ref released %d times, want 1", countRef(e.f.Released(), stale))
	}
}

// Only ErrAuthRequired means "approval no longer accepted". Any other
// failure of the operation is an error that neither drops the approval nor
// prompts.
func TestOtherSignErrorsKeepTheApproval(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	ref := approveOnce(t, e, s, tab)

	req := e.req("github", tab.Peer())
	req.Do = func(platform.ApprovalRef) error { return errors.New("enclave busy") }
	if r := handleWithin(t, e.b, req); r.Decision != audit.Error {
		t.Fatalf("%+v", r)
	}
	if e.f.CountShown(fake.KindAuthenticate) != 1 {
		t.Fatal("a non-auth failure must not prompt")
	}
	if refs := cachedRefs(e); len(refs) != 1 || refs[0] != ref || e.f.LiveApprovals() != 1 {
		t.Fatalf("a non-auth failure must not drop the approval: cache %v", refs)
	}
	if len(e.staleLines(t)) != 0 {
		t.Fatal("a non-auth failure is not a stale approval")
	}
}

// Forwarded requests are one-shot: an ErrAuthRequired on their fresh
// approval fails them at once, with no re-ask and no stale line, and the
// local tab's remembered approval is left alone.
func TestForwardedAuthRequiredIsNotReasked(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	local := approveOnce(t, e, s, tab)
	s.killAll()

	fwd := e.staleReq("github", tab.Peer(), s)
	fwd.Forwarded = true
	r := handleWithin(t, e.b, fwd)
	if r.Decision != audit.Error || r.Allowed() {
		t.Fatalf("%+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 2 {
		t.Fatalf("login prompts %d, want 2 (local + one forwarded, no re-ask)", n)
	}
	if calls := s.calls(); len(calls) != 2 || calls[1] == local {
		t.Fatalf("forwarded operation refs %v: one try with its own approval", calls)
	}
	if len(e.staleLines(t)) != 0 {
		t.Fatal("a forwarded one-shot approval is not a remembered one")
	}
	if refs := cachedRefs(e); len(refs) != 1 || refs[0] != local {
		t.Fatalf("the local tab's approval must be untouched: %v", refs)
	}
	if e.f.LiveApprovals() != 1 {
		t.Fatalf("live %d: the forwarded one-shot ref must be released", e.f.LiveApprovals())
	}
	if f := e.lastLine(t); f["decision"] != "error" || f["scope"] != "use" {
		t.Fatalf("%v", f)
	}
}

// scope: use is one-shot: ErrAuthRequired fails the request once, no re-ask.
func TestOneShotAuthRequiredIsNotReasked(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	s.killAll()
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	r := handleWithin(t, e.b, e.staleReq("userkey", tab.Peer(), s))
	if r.Decision != audit.Error || r.Allowed() {
		t.Fatalf("%+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 1 {
		t.Fatalf("login prompts %d, want 1", n)
	}
	if len(s.calls()) != 1 || len(e.staleLines(t)) != 0 || len(e.cache.List()) != 0 || e.f.LiveApprovals() != 0 {
		t.Fatalf("calls %v stale lines %d cache %d live %d", s.calls(), len(e.staleLines(t)), len(e.cache.List()), e.f.LiveApprovals())
	}
	if lines := e.auditLines(t); len(lines) != 1 {
		t.Fatalf("one-shot request wrote %d audit lines, want 1", len(lines))
	}
}

// A request whose own fresh prompt just produced the ref (not a remembered
// one) is not re-asked either: the first prompt's ref being rejected is an
// error, with exactly one prompt.
func TestFirstApprovalRejectedIsNotReasked(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{})
	s := newStaleSigner(t, e.f)
	s.killAll()
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	r := handleWithin(t, e.b, e.staleReq("github", tab.Peer(), s))
	if r.Decision != audit.Error || r.Allowed() {
		t.Fatalf("%+v", r)
	}
	if n := e.f.CountShown(fake.KindAuthenticate); n != 1 {
		t.Fatalf("login prompts %d, want 1", n)
	}
	if len(s.calls()) != 1 || len(e.staleLines(t)) != 0 {
		t.Fatalf("calls %v stale lines %d", s.calls(), len(e.staleLines(t)))
	}
}

// Dialog approvals carry no login approval (ref 0): a key that needs user
// presence fails under them with the existing "requires the login gate"
// error. A second dialog cannot fix that, so none is shown.
func TestDialogApprovalWithUserPresenceKeyIsNotReasked(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fake.SSHProc("h"))
	if r := handleWithin(t, e.b, e.req("github", tab.Peer())); r.Decision != audit.Approved {
		t.Fatalf("%+v", r)
	}
	req := e.req("github", tab.Peer())
	var tries atomic.Int32
	req.Do = func(platform.ApprovalRef) error { tries.Add(1); return platform.ErrAuthRequired }
	r := handleWithin(t, e.b, req)
	if r.Decision != audit.Error {
		t.Fatalf("%+v", r)
	}
	if n := e.f.CountShown(fake.KindConfirm); n != 1 {
		t.Fatalf("dialogs %d, want 1: a dialog cannot produce a login approval", n)
	}
	if tries.Load() != 1 {
		t.Fatalf("operation ran %d times, want 1", tries.Load())
	}
}

// Gate none never has an approval; ErrAuthRequired there stays the existing
// error with no prompt.
func TestGateNoneAuthRequiredIsNotReasked(t *testing.T) {
	e := newEnv(t)
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("h"))
	req := e.req("deploy", tab.Peer())
	req.Do = func(platform.ApprovalRef) error { return platform.ErrAuthRequired }
	if r := handleWithin(t, e.b, req); r.Decision != audit.Error {
		t.Fatalf("%+v", r)
	}
	if len(e.f.Shown()) != 0 || len(e.staleLines(t)) != 0 {
		t.Fatal("gate none must not prompt or report a stale approval")
	}
}
