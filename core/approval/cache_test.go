package approval

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
)

// These tests specify core/approval (spec 4.3 ApprovalCache, 4.4 concurrency):
// approvals keyed by (target, rule, scope_id, receiver), wall-clock expiry,
// revocation, release of every LAContext ref exactly once, change events for
// `nazar status --follow`, and one shared prompt per key.

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newCache() (*Cache, *clock, *[]platform.ApprovalRef) {
	ck := &clock{t: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)}
	var released []platform.ApprovalRef
	var mu sync.Mutex
	c := New(ck.now, func(r platform.ApprovalRef) { mu.Lock(); released = append(released, r); mu.Unlock() })
	return c, ck, &released
}

// releases counts ReleaseApproval calls per ref; safe for concurrent use.
type releases struct {
	mu sync.Mutex
	n  map[platform.ApprovalRef]int
}

func (r *releases) release(ref platform.ApprovalRef) {
	r.mu.Lock()
	if r.n == nil {
		r.n = map[platform.ApprovalRef]int{}
	}
	r.n[ref]++
	r.mu.Unlock()
}

func (r *releases) count(ref platform.ApprovalRef) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n[ref]
}

func (r *releases) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := 0
	for _, n := range r.n {
		t += n
	}
	return t
}

func newRecCache() (*Cache, *clock, *releases) {
	ck := &clock{t: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)}
	rec := &releases{}
	return New(ck.now, rec.release), ck, rec
}

// next reads one event or fails after a second.
func next(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("event channel closed early")
		}
		return ev
	case <-time.After(time.Second):
		t.Fatal("no event within 1s")
	}
	return Event{}
}

// noEvent fails if an event is already waiting.
func noEvent(t *testing.T, ch <-chan Event) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("unexpected event %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}
}

var k1 = Key{Target: "ssh:github", Rule: "1:aa", ScopeID: "session:4120@1", Receiver: ""}

// ---- Expiry (spec 4.3: removed when `expire` runs out) ----

func TestExpiry(t *testing.T) {
	c, ck, rel := newCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(8 * time.Hour), Ref: 7})
	if _, ok := c.Lookup(k1); !ok {
		t.Fatal("fresh entry missing")
	}
	ck.add(8*time.Hour - time.Second)
	if _, ok := c.Lookup(k1); !ok {
		t.Fatal("entry gone before expiry")
	}
	ck.add(time.Second)
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("entry still there at expiry")
	}
	if len(*rel) != 1 || (*rel)[0] != 7 {
		t.Fatalf("released %v", *rel)
	}
}

func TestZeroExpiresLastsUntilRevoked(t *testing.T) {
	c, ck, rec := newRecCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 3})
	ck.add(10 * 365 * 24 * time.Hour)
	if _, ok := c.Lookup(k1); !ok {
		t.Fatal("an entry without expire must last until its scope ends or a revoke")
	}
	if n := c.Sweep(); n != 0 {
		t.Fatalf("Sweep removed %d entries without expire", n)
	}
	if rec.total() != 0 {
		t.Fatal("ref released while the entry is still live")
	}
}

func TestAlreadyExpiredEntryIsNeverReturned(t *testing.T) {
	c, ck, rec := newRecCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(-time.Second), Ref: 9})
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("entry that expired before Put was returned")
	}
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("expired entry returned on second lookup")
	}
	if len(c.List()) != 0 {
		t.Fatal("expired entry listed")
	}
	if rec.count(9) != 1 {
		t.Fatalf("ref 9 released %d times, want exactly 1", rec.count(9))
	}
}

func TestLookupDoesNotExtendExpiry(t *testing.T) {
	c, ck, _ := newRecCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(time.Hour)})
	for i := 0; i < 59; i++ {
		ck.add(time.Minute)
		if _, ok := c.Lookup(k1); !ok {
			t.Fatalf("entry gone after %d minutes", i+1)
		}
	}
	ck.add(time.Minute)
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("frequent use must not extend an approval past its expire")
	}
}

func TestExpiryComparesInstantsAcrossTimeZones(t *testing.T) {
	c, ck, _ := newRecCache()
	mst := time.FixedZone("MST", -7*3600)
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(time.Hour).In(mst)})
	ck.add(time.Hour - time.Second)
	if _, ok := c.Lookup(k1); !ok {
		t.Fatal("entry expired early when Expires is in another zone")
	}
	ck.add(time.Second)
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("entry outlived its expire when Expires is in another zone")
	}
}

// A Mac asleep through an approval's expire. Go compares
// monotonic readings when both times carry one, and the monotonic clock
// stops during sleep; the cache must store wall-clock times only.
func TestTimesAreWallClock(t *testing.T) {
	c := New(time.Now, nil)
	c.Put(Entry{Key: k1, Created: time.Now(), Expires: time.Now().Add(time.Hour)})
	e, ok := c.Lookup(k1)
	if !ok {
		t.Fatal("missing")
	}
	// A time with a monotonic reading prints "m=+..."; the cache must not keep one,
	// or expiry would ignore time the Mac spent asleep.
	if strings.Contains(e.Expires.String(), "m=") || strings.Contains(e.Created.String(), "m=") {
		t.Fatalf("monotonic reading kept: %v", e.Expires)
	}
	for _, l := range c.List() {
		if strings.Contains(l.Expires.String(), "m=") || strings.Contains(l.Created.String(), "m=") {
			t.Fatalf("List returned a monotonic reading: %v", l.Expires)
		}
	}
}

func TestWallClockExpiryWithMonotonicNow(t *testing.T) {
	// now() returns times that carry a monotonic reading (time.Now does).
	// Expiry must still follow the wall clock the injected now reports.
	base := time.Now()
	var off atomic.Int64
	now := func() time.Time { return base.Add(time.Duration(off.Load())) }
	c := New(now, nil)
	c.Put(Entry{Key: k1, Created: now(), Expires: now().Add(time.Hour)})
	off.Store(int64(time.Hour - time.Second))
	if _, ok := c.Lookup(k1); !ok {
		t.Fatal("entry gone before expiry")
	}
	off.Store(int64(time.Hour))
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("entry still there at expiry")
	}
}

// ---- Keys (spec 4.3: indexed by (target, rule, scope_id, receiver)) ----

func TestKeyPartsAreAllSignificant(t *testing.T) {
	c, ck, _ := newCache()
	c.Put(Entry{Key: k1, Created: ck.now()})
	for _, k := range []Key{
		{Target: "ssh:other", Rule: k1.Rule, ScopeID: k1.ScopeID},
		{Target: k1.Target, Rule: "2:bb", ScopeID: k1.ScopeID},
		{Target: k1.Target, Rule: k1.Rule, ScopeID: "session:9@1"},
		{Target: k1.Target, Rule: k1.Rule, ScopeID: k1.ScopeID, Receiver: "apple:com.apple.openssh"},
		{Target: "ssh:GitHub", Rule: k1.Rule, ScopeID: k1.ScopeID},
		{Target: k1.Target, Rule: k1.Rule, ScopeID: "session:4120@10"},
		{Target: k1.Target, Rule: k1.Rule, ScopeID: "session:4120"},
		{Target: k1.Target, Rule: k1.Rule, ScopeID: ""},
		{Target: k1.Target, Rule: "", ScopeID: k1.ScopeID},
		{Target: "", Rule: k1.Rule, ScopeID: k1.ScopeID},
		{},
	} {
		if _, ok := c.Lookup(k); ok {
			t.Errorf("approval leaked to %+v", k)
		}
	}
	if _, ok := c.Lookup(k1); !ok {
		t.Fatal("exact key must still match")
	}
}

// Milestone 7: what an approval covers is part of its key. An
// approval for one server (its host key), for an unbound login, or for one
// kind of signature covers nothing else; "" is a value like any other, and
// every op of one scope is listed and revoked with the scope.
func TestOpIsPartOfTheKey(t *testing.T) {
	c, ck, _ := newCache()
	gh := k1
	gh.Op = "login:SHA256:gh"
	c.Put(Entry{Key: gh, Covers: "github.com", Created: ck.now()})
	for _, op := range []string{"", "login:SHA256:gl", "login:unbound", "sign:git", "sign:data", "login:SHA256:GH", "login:SHA256:gh "} {
		k := gh
		k.Op = op
		if _, ok := c.Lookup(k); ok {
			t.Errorf("approval for %q leaked to %q", gh.Op, op)
		}
	}
	e, ok := c.Lookup(gh)
	if !ok || e.Covers != "github.com" {
		t.Fatalf("exact key: %+v %v", e, ok)
	}
	ck.add(time.Minute) // "oldest first" needs two creation times
	git := gh
	git.Op = "sign:git"
	c.Put(Entry{Key: git, Covers: "git commits and tags", Created: ck.now()})
	if l := c.List(); len(l) != 2 || l[0].Covers != "github.com" || l[1].Covers != "git commits and tags" {
		t.Fatalf("List() = %+v, want both ops, oldest first", l)
	}
	if n := c.RevokeScope(gh.ScopeID, "session ended"); n != 2 {
		t.Fatalf("RevokeScope revoked %d, want both ops of the scope", n)
	}
	if l := c.List(); len(l) != 0 {
		t.Fatalf("after RevokeScope: %+v", l)
	}
}

func TestReceiverApprovalDoesNotCoverOtherReceivers(t *testing.T) {
	c, ck, _ := newRecCache()
	withTo := Key{Target: "ssh:github", Rule: "2:cc", ScopeID: "session:1@1", Receiver: "signed:TEAM1"}
	c.Put(Entry{Key: withTo, Created: ck.now()})
	for _, r := range []string{"", "signed:TEAM2", "signed:team1", "signed:TEAM1 "} {
		k := withTo
		k.Receiver = r
		if _, ok := c.Lookup(k); ok {
			t.Errorf("approval for receiver %q leaked to receiver %q", withTo.Receiver, r)
		}
	}
}

func TestLookupReturnsStoredEntry(t *testing.T) {
	c, ck, _ := newRecCache()
	want := Entry{
		Key:     k1,
		Scope:   "session",
		Created: ck.now(),
		Expires: ck.now().Add(8 * time.Hour),
		Chain:   "iTerm2 → bash → git → ssh",
		App:     "com.googlecode.iterm2",
		Ref:     42,
	}
	c.Put(want)
	got, ok := c.Lookup(k1)
	if !ok {
		t.Fatal("missing")
	}
	if got.Key != want.Key || got.Scope != want.Scope || got.Chain != want.Chain ||
		got.App != want.App || got.Ref != want.Ref ||
		!got.Created.Equal(want.Created) || !got.Expires.Equal(want.Expires) {
		t.Fatalf("Lookup = %+v, want %+v", got, want)
	}
}

// ---- Put ----

func TestPutReplacesAndReleasesOld(t *testing.T) {
	c, ck, rel := newCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 1})
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 2})
	if len(*rel) != 1 || (*rel)[0] != 1 {
		t.Fatalf("released %v", *rel)
	}
	e, ok := c.Lookup(k1)
	if !ok || e.Ref != 2 {
		t.Fatalf("Lookup after replace = %+v, %v; want Ref 2", e, ok)
	}
	if len(c.List()) != 1 {
		t.Fatalf("replace left %d entries", len(c.List()))
	}
}

func TestZeroRefIsNeverReleased(t *testing.T) {
	c, ck, rec := newRecCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(time.Minute)}) // dialog gate: no ref
	c.Put(Entry{Key: k1, Created: ck.now()})                                     // replace
	c.Put(Entry{Key: Key{Target: "ssh:b"}, Created: ck.now(), Expires: ck.now().Add(time.Minute)})
	ck.add(time.Hour)
	c.Sweep()
	c.RevokeAll("revoked")
	if rec.count(0) != 0 {
		t.Fatalf("zero ref released %d times", rec.count(0))
	}
}

func TestNilReleaseIsAllowed(t *testing.T) {
	ck := &clock{t: time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC)}
	c := New(ck.now, nil)
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(time.Minute), Ref: 1})
	c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(time.Minute), Ref: 2})
	ck.add(time.Hour)
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("expired entry returned")
	}
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 3})
	c.RevokeAll("revoked")
}

// ---- Revocation (spec 4.3: session root exits, app quits, `nazar revoke`) ----

func TestRevokes(t *testing.T) {
	c, ck, rel := newCache()
	put := func(target, scope, app string, ref platform.ApprovalRef) {
		c.Put(Entry{Key: Key{Target: target, Rule: "1:aa", ScopeID: scope}, App: app, Created: ck.now(), Ref: ref})
	}
	put("ssh:a", "session:1@1", "com.googlecode.iterm2", 1)
	put("ssh:b", "session:1@1", "com.googlecode.iterm2", 2)
	put("ssh:a", "session:2@1", "com.googlecode.iterm2", 3)
	put("ssh:a", "app:T:com.x", "com.x", 4)
	if n := c.RevokeScope("session:1@1", "session ended"); n != 2 {
		t.Fatalf("RevokeScope removed %d", n)
	}
	if n := c.RevokeTarget("ssh:a", "revoked"); n != 2 {
		t.Fatalf("RevokeTarget removed %d", n)
	}
	if len(c.List()) != 0 || len(*rel) != 4 {
		t.Fatalf("left %d released %d", len(c.List()), len(*rel))
	}
	put("ssh:a", "app:T:com.x", "com.x", 5)
	if c.RevokeApp("com.x", "revoked") != 1 || c.RevokeAll("revoked") != 0 {
		t.Fatal("RevokeApp/RevokeAll")
	}
}

func TestRevokesMatchExactlyNotByPrefix(t *testing.T) {
	c, ck, rec := newRecCache()
	put := func(target, scope, app string, ref platform.ApprovalRef) {
		c.Put(Entry{Key: Key{Target: target, Rule: "1:aa", ScopeID: scope}, App: app, Created: ck.now(), Ref: ref})
	}
	put("ssh:a", "session:1@1", "com.x", 1)
	put("ssh:ab", "session:1@10", "com.xy", 2)
	put("ssh:a", "session:1@10", "com.x.helper", 3)

	if n := c.RevokeScope("session:1@1", "session ended"); n != 1 {
		t.Fatalf("RevokeScope(session:1@1) removed %d, want 1 (session:1@10 is another session)", n)
	}
	if n := c.RevokeTarget("ssh:a", "revoked"); n != 1 {
		t.Fatalf("RevokeTarget(ssh:a) removed %d, want 1 (ssh:ab is another key)", n)
	}
	if n := c.RevokeApp("com.x", "revoked"); n != 0 {
		t.Fatalf("RevokeApp(com.x) removed %d, want 0 (com.xy is another app)", n)
	}
	if rec.count(1) != 1 || rec.count(3) != 1 || rec.count(2) != 0 {
		t.Fatalf("releases: 1→%d 2→%d 3→%d", rec.count(1), rec.count(2), rec.count(3))
	}
	if _, ok := c.Lookup(Key{Target: "ssh:ab", Rule: "1:aa", ScopeID: "session:1@10"}); !ok {
		t.Fatal("unrelated approval was revoked")
	}
}

func TestRevokeAppCoversEveryScopeOfThatApp(t *testing.T) {
	c, ck, _ := newRecCache()
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "session:1@1"}, App: "com.googlecode.iterm2", Created: ck.now()})
	c.Put(Entry{Key: Key{Target: "ssh:b", Rule: "1:aa", ScopeID: "app:T:com.googlecode.iterm2"}, App: "com.googlecode.iterm2", Created: ck.now()})
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "session:2@1"}, App: "com.apple.Terminal", Created: ck.now()})
	if n := c.RevokeApp("com.googlecode.iterm2", "app quit"); n != 2 {
		t.Fatalf("RevokeApp removed %d, want 2", n)
	}
	if l := c.List(); len(l) != 1 || l[0].App != "com.apple.Terminal" {
		t.Fatalf("left %+v", l)
	}
}

func TestRevokeWhere(t *testing.T) {
	c, ck, rec := newRecCache()
	for i := 1; i <= 6; i++ {
		c.Put(Entry{Key: Key{Target: fmt.Sprintf("ssh:%d", i), Rule: "1:aa", ScopeID: "s"}, Created: ck.now(), Ref: platform.ApprovalRef(i)})
	}
	n := c.RevokeWhere("custom", func(e Entry) bool { return e.Ref%2 == 0 })
	if n != 3 {
		t.Fatalf("RevokeWhere removed %d, want 3", n)
	}
	for i := 1; i <= 6; i++ {
		want := 0
		if i%2 == 0 {
			want = 1
		}
		if rec.count(platform.ApprovalRef(i)) != want {
			t.Errorf("ref %d released %d times, want %d", i, rec.count(platform.ApprovalRef(i)), want)
		}
	}
	if n := c.RevokeWhere("none", func(Entry) bool { return false }); n != 0 {
		t.Fatalf("RevokeWhere(false) removed %d", n)
	}
	if len(c.List()) != 3 {
		t.Fatalf("left %d, want 3", len(c.List()))
	}
}

func TestRevokeOnEmptyCache(t *testing.T) {
	c, _, rec := newRecCache()
	ch, cancel := c.Subscribe()
	defer cancel()
	if c.RevokeAll("x")+c.RevokeTarget("ssh:a", "x")+c.RevokeScope("s", "x")+c.RevokeApp("a", "x")+
		c.RetainRules(nil, "x")+c.Sweep() != 0 {
		t.Fatal("revoking an empty cache removed something")
	}
	if rec.total() != 0 {
		t.Fatal("released refs from an empty cache")
	}
	noEvent(t, ch)
}

func TestRevokedEntryIsGoneForGood(t *testing.T) {
	c, ck, rec := newRecCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 8})
	c.RevokeAll("revoked")
	if _, ok := c.Lookup(k1); ok {
		t.Fatal("revoked approval still returned")
	}
	c.RevokeAll("revoked")
	c.Sweep()
	if rec.count(8) != 1 {
		t.Fatalf("ref 8 released %d times, want 1", rec.count(8))
	}
}

// ---- RetainRules (config change drops approvals of rules that are gone) ----

func TestRetainRules(t *testing.T) {
	c, ck, _ := newCache()
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "s"}, Created: ck.now()})
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "2:bb", ScopeID: "s"}, Created: ck.now()})
	if n := c.RetainRules(map[string]bool{"ssh:a|2:bb": true}, "config changed"); n != 1 {
		t.Fatalf("removed %d", n)
	}
}

func TestRetainRulesIsPerTargetAndKeepsAllScopes(t *testing.T) {
	c, ck, rec := newRecCache()
	// Rule IDs can repeat across keys; a live rule of ssh:a must not keep
	// an approval of ssh:b alive.
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "session:1@1"}, Created: ck.now(), Ref: 1})
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "app:T:com.x", Receiver: "signed:T"}, Created: ck.now(), Ref: 2})
	c.Put(Entry{Key: Key{Target: "ssh:b", Rule: "1:aa", ScopeID: "session:1@1"}, Created: ck.now(), Ref: 3})
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:ab", ScopeID: "session:1@1"}, Created: ck.now(), Ref: 4})
	if n := c.RetainRules(map[string]bool{"ssh:a|1:aa": true}, "config changed"); n != 2 {
		t.Fatalf("RetainRules removed %d, want 2", n)
	}
	if rec.count(1) != 0 || rec.count(2) != 0 || rec.count(3) != 1 || rec.count(4) != 1 {
		t.Fatalf("releases 1→%d 2→%d 3→%d 4→%d", rec.count(1), rec.count(2), rec.count(3), rec.count(4))
	}
	if len(c.List()) != 2 {
		t.Fatalf("left %d, want 2", len(c.List()))
	}
}

func TestRetainRulesFalseValueIsNotLive(t *testing.T) {
	c, ck, _ := newRecCache()
	c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "s"}, Created: ck.now()})
	if n := c.RetainRules(map[string]bool{"ssh:a|1:aa": false}, "config changed"); n != 1 {
		t.Fatalf("an entry mapped to false must be dropped; removed %d", n)
	}
}

func TestRetainRulesEmptyDropsEverything(t *testing.T) {
	for name, live := range map[string]map[string]bool{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			c, ck, rec := newRecCache()
			c.Put(Entry{Key: Key{Target: "ssh:a", Rule: "1:aa", ScopeID: "s"}, Created: ck.now(), Ref: 1})
			c.Put(Entry{Key: Key{Target: "ssh:b", Rule: "1:aa", ScopeID: "s"}, Created: ck.now(), Ref: 2})
			if n := c.RetainRules(live, "config changed"); n != 2 {
				t.Fatalf("removed %d, want 2", n)
			}
			if rec.total() != 2 {
				t.Fatalf("released %d, want 2", rec.total())
			}
		})
	}
}

// ---- Sweep and List ----

func TestSweep(t *testing.T) {
	c, ck, rec := newRecCache()
	c.Put(Entry{Key: Key{Target: "ssh:a"}, Created: ck.now(), Expires: ck.now().Add(time.Minute), Ref: 1})
	c.Put(Entry{Key: Key{Target: "ssh:b"}, Created: ck.now(), Expires: ck.now().Add(time.Hour), Ref: 2})
	c.Put(Entry{Key: Key{Target: "ssh:c"}, Created: ck.now(), Ref: 3})
	ck.add(time.Minute)
	if n := c.Sweep(); n != 1 {
		t.Fatalf("Sweep removed %d, want 1", n)
	}
	if n := c.Sweep(); n != 0 {
		t.Fatalf("second Sweep removed %d, want 0", n)
	}
	if rec.count(1) != 1 || rec.count(2) != 0 || rec.count(3) != 0 {
		t.Fatalf("releases 1→%d 2→%d 3→%d", rec.count(1), rec.count(2), rec.count(3))
	}
	if _, ok := c.Lookup(Key{Target: "ssh:a"}); ok {
		t.Fatal("swept entry still returned")
	}
}

func TestListIsLiveOldestFirst(t *testing.T) {
	c, ck, rec := newRecCache()
	t0 := ck.now()
	c.Put(Entry{Key: Key{Target: "ssh:c"}, Created: t0.Add(2 * time.Minute)})
	c.Put(Entry{Key: Key{Target: "ssh:a"}, Created: t0})
	c.Put(Entry{Key: Key{Target: "ssh:x"}, Created: t0.Add(time.Minute), Expires: t0.Add(30 * time.Second), Ref: 4})
	c.Put(Entry{Key: Key{Target: "ssh:b"}, Created: t0.Add(time.Minute)})
	ck.add(time.Minute)
	l := c.List()
	var got []string
	for _, e := range l {
		got = append(got, e.Key.Target)
	}
	if strings.Join(got, ",") != "ssh:a,ssh:b,ssh:c" {
		t.Fatalf("List order = %v, want [ssh:a ssh:b ssh:c] (expired ssh:x excluded)", got)
	}
	if rec.count(4) != 1 {
		t.Fatalf("expired entry's ref released %d times by List, want 1", rec.count(4))
	}
	// The returned slice is a copy.
	l[0].Key.Target = "mutated"
	l[0].Ref = 99
	if _, ok := c.Lookup(Key{Target: "ssh:a"}); !ok {
		t.Fatal("mutating List's result changed the cache")
	}
}

// ---- Subscriptions (`nazar status --follow`) ----

func TestSubscribe(t *testing.T) {
	c, ck, _ := newCache()
	ch, cancel := c.Subscribe()
	c.Put(Entry{Key: k1, Created: ck.now()})
	c.RevokeAll("revoked")
	if ev := <-ch; ev.Type != Added {
		t.Fatalf("got %+v", ev)
	}
	if ev := <-ch; ev.Type != Removed || ev.Reason != "revoked" {
		t.Fatalf("got %+v", ev)
	}
	cancel()
	cancel()
	if _, open := <-ch; open {
		t.Fatal("channel must be closed after cancel")
	}
}

func TestEventTypeValues(t *testing.T) {
	if Added != "added" || Removed != "removed" {
		t.Fatalf("Added=%q Removed=%q", Added, Removed)
	}
}

func TestEventsCarryTheEntry(t *testing.T) {
	c, ck, _ := newRecCache()
	ch, cancel := c.Subscribe()
	defer cancel()
	e := Entry{Key: k1, Scope: "session", Created: ck.now(), Chain: "iTerm2 → ssh", App: "com.googlecode.iterm2", Ref: 11}
	c.Put(e)
	if ev := next(t, ch); ev.Type != Added || ev.Entry.Key != k1 || ev.Entry.Ref != 11 || ev.Entry.Chain != e.Chain {
		t.Fatalf("added event %+v", ev)
	}
	c.RevokeScope(k1.ScopeID, "session ended")
	if ev := next(t, ch); ev.Type != Removed || ev.Entry.Key != k1 || ev.Entry.Ref != 11 || ev.Reason != "session ended" {
		t.Fatalf("removed event %+v", ev)
	}
	noEvent(t, ch)
}

func TestExpiryEmitsRemovedExpired(t *testing.T) {
	for name, trigger := range map[string]func(*Cache){
		"Lookup": func(c *Cache) { c.Lookup(k1) },
		"Sweep":  func(c *Cache) { c.Sweep() },
		"List":   func(c *Cache) { c.List() },
	} {
		t.Run(name, func(t *testing.T) {
			c, ck, _ := newRecCache()
			c.Put(Entry{Key: k1, Created: ck.now(), Expires: ck.now().Add(time.Minute)})
			ch, cancel := c.Subscribe()
			defer cancel()
			ck.add(time.Minute)
			trigger(c)
			ev := next(t, ch)
			if ev.Type != Removed || ev.Entry.Key != k1 || ev.Reason != "expired" {
				t.Fatalf("got %+v, want removed/expired", ev)
			}
			trigger(c)
			noEvent(t, ch)
		})
	}
}

func TestReplaceEmitsRemovedThenAdded(t *testing.T) {
	c, ck, _ := newRecCache()
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 1})
	ch, cancel := c.Subscribe()
	defer cancel()
	c.Put(Entry{Key: k1, Created: ck.now(), Ref: 2})
	if ev := next(t, ch); ev.Type != Removed || ev.Entry.Ref != 1 || ev.Reason == "" {
		t.Fatalf("first event %+v, want removed of ref 1 with a reason", ev)
	}
	if ev := next(t, ch); ev.Type != Added || ev.Entry.Ref != 2 {
		t.Fatalf("second event %+v, want added of ref 2", ev)
	}
}

func TestEveryRevokedEntryEmitsOneEvent(t *testing.T) {
	c, ck, _ := newRecCache()
	for i := 0; i < 5; i++ {
		c.Put(Entry{Key: Key{Target: fmt.Sprintf("ssh:%d", i)}, Created: ck.now()})
	}
	ch, cancel := c.Subscribe()
	defer cancel()
	if n := c.RevokeAll("revoked"); n != 5 {
		t.Fatalf("RevokeAll removed %d", n)
	}
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		ev := next(t, ch)
		if ev.Type != Removed || ev.Reason != "revoked" || seen[ev.Entry.Key.Target] {
			t.Fatalf("event %+v (seen %v)", ev, seen)
		}
		seen[ev.Entry.Key.Target] = true
	}
	noEvent(t, ch)
}

func TestMultipleSubscribersEachGetEvents(t *testing.T) {
	c, ck, _ := newRecCache()
	ch1, cancel1 := c.Subscribe()
	ch2, cancel2 := c.Subscribe()
	defer cancel2()
	c.Put(Entry{Key: k1, Created: ck.now()})
	if next(t, ch1).Type != Added || next(t, ch2).Type != Added {
		t.Fatal("both subscribers must see the add")
	}
	cancel1()
	c.RevokeAll("revoked")
	if ev := next(t, ch2); ev.Type != Removed {
		t.Fatalf("remaining subscriber got %+v", ev)
	}
	if _, open := <-ch1; open {
		t.Fatal("cancelled subscriber received an event")
	}
}

func TestSlowSubscriberDoesNotBlockCache(t *testing.T) {
	c, ck, _ := newRecCache()
	_, cancel := c.Subscribe() // never read
	defer cancel()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			k := Key{Target: fmt.Sprintf("ssh:%d", i)}
			c.Put(Entry{Key: k, Created: ck.now()})
			c.Lookup(k)
		}
		c.RevokeAll("revoked")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a subscriber that doesn't read blocked the cache")
	}
}

func TestUseAfterCancelIsSafe(t *testing.T) {
	c, ck, _ := newRecCache()
	_, cancel := c.Subscribe()
	cancel()
	// Sending on a closed channel would panic.
	c.Put(Entry{Key: k1, Created: ck.now()})
	c.RevokeAll("revoked")
}

func TestConcurrentSubscribeCancelAndChanges(t *testing.T) {
	c, ck, _ := newRecCache()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			k := Key{Target: fmt.Sprintf("ssh:%d", i%10)}
			c.Put(Entry{Key: k, Created: ck.now()})
			c.RevokeTarget(k.Target, "revoked")
		}
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ch, cancel := c.Subscribe()
				select {
				case <-ch:
				default:
				}
				cancel()
				cancel()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// ---- Concurrency: every LAContext ref released exactly once ----

func TestReleaseExactlyOnceUnderConcurrency(t *testing.T) {
	c, ck, rec := newRecCache()
	const n = 3000
	var wg sync.WaitGroup
	var nextRef atomic.Uint64
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				r := nextRef.Add(1)
				if r > n {
					return
				}
				e := Entry{
					Key:     Key{Target: fmt.Sprintf("ssh:%d", r%5), Rule: "1:aa", ScopeID: fmt.Sprintf("session:%d@1", r%4), Receiver: []string{"", "signed:T"}[r%2]},
					Created: ck.now(),
					App:     fmt.Sprintf("app.%d", r%3),
					Ref:     platform.ApprovalRef(r),
				}
				if r%3 != 0 {
					e.Expires = ck.now().Add(time.Duration(r%3) * time.Millisecond)
				}
				c.Put(e)
			}
		}()
	}
	stop := make(chan struct{})
	ops := []func(i int){
		func(i int) {
			c.Lookup(Key{Target: fmt.Sprintf("ssh:%d", i%5), Rule: "1:aa", ScopeID: fmt.Sprintf("session:%d@1", i%4)})
		},
		func(i int) { c.Sweep() },
		func(i int) { c.List() },
		func(i int) { c.RevokeScope(fmt.Sprintf("session:%d@1", i%4), "session ended") },
		func(i int) { c.RevokeTarget(fmt.Sprintf("ssh:%d", i%5), "revoked") },
		func(i int) { c.RevokeApp(fmt.Sprintf("app.%d", i%3), "app quit") },
		func(i int) { c.RetainRules(map[string]bool{"ssh:1|1:aa": true, "ssh:2|1:aa": true}, "config changed") },
		func(i int) { ck.add(time.Millisecond) },
	}
	var bg sync.WaitGroup
	for _, op := range ops {
		bg.Add(1)
		go func(op func(int)) {
			defer bg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				op(i)
			}
		}(op)
	}
	wg.Wait()
	close(stop)
	bg.Wait()
	c.RevokeAll("shutdown")
	if l := c.List(); len(l) != 0 {
		t.Fatalf("%d entries left after RevokeAll", len(l))
	}
	for r := platform.ApprovalRef(1); r <= n; r++ {
		if got := rec.count(r); got != 1 {
			t.Fatalf("ref %d released %d times, want exactly 1", r, got)
		}
	}
	if rec.total() != n {
		t.Fatalf("total releases %d, want %d", rec.total(), n)
	}
}

// ---- Flight (spec 4.4: one shared prompt per key) ----

func TestFlightSharesOneCall(t *testing.T) {
	var f Flight[int]
	var calls atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 10)
	sharedN := atomic.Int32{}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, shared := f.Do(k1, func() int {
				calls.Add(1)
				close(started)
				<-release
				return 42
			})
			results[i] = v
			if shared {
				sharedN.Add(1)
			}
		}(i)
	}
	<-started
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 || sharedN.Load() != 9 {
		t.Fatalf("calls %d shared %d", calls.Load(), sharedN.Load())
	}
	for _, r := range results {
		if r != 42 {
			t.Fatal("every caller must get the result")
		}
	}
	// A later call runs again.
	if v, shared := f.Do(k1, func() int { return 1 }); v != 1 || shared {
		t.Fatal("later call must run fn")
	}
}

func TestFlightDifferentKeysRunIndependently(t *testing.T) {
	var f Flight[int]
	block := make(chan struct{})
	go f.Do(k1, func() int { <-block; return 0 })
	time.Sleep(10 * time.Millisecond)
	done := make(chan struct{})
	go func() { f.Do(Key{Target: "other"}, func() int { return 0 }); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("other key blocked behind k1")
	}
	close(block)
}

// Another tab, rule, key or receiver must never ride on a pending prompt's
// answer: each key part separates flights.
func TestFlightDoesNotShareAcrossKeyParts(t *testing.T) {
	for name, other := range map[string]Key{
		"target":   {Target: "ssh:other", Rule: k1.Rule, ScopeID: k1.ScopeID},
		"rule":     {Target: k1.Target, Rule: "2:bb", ScopeID: k1.ScopeID},
		"scope":    {Target: k1.Target, Rule: k1.Rule, ScopeID: "session:9@1"},
		"receiver": {Target: k1.Target, Rule: k1.Rule, ScopeID: k1.ScopeID, Receiver: "signed:T"},
		"op":       {Target: k1.Target, Rule: k1.Rule, ScopeID: k1.ScopeID, Op: "sign:git"},
	} {
		t.Run(name, func(t *testing.T) {
			var f Flight[string]
			started := make(chan struct{})
			release := make(chan struct{})
			leader := make(chan string, 1)
			go func() {
				v, _ := f.Do(k1, func() string { close(started); <-release; return "approved-k1" })
				leader <- v
			}()
			<-started
			type res struct {
				v      string
				shared bool
			}
			got := make(chan res, 1)
			go func() {
				v, s := f.Do(other, func() string { return "own-prompt" })
				got <- res{v, s}
			}()
			select {
			case r := <-got:
				if r.v != "own-prompt" || r.shared {
					t.Fatalf("key differing in %s got %+v; want its own prompt", name, r)
				}
			case <-time.After(time.Second):
				t.Fatalf("key differing in %s waited on k1's prompt", name)
			}
			close(release)
			if v := <-leader; v != "approved-k1" {
				t.Fatalf("leader got %q", v)
			}
		})
	}
}

func TestFlightLeaderIsNotShared(t *testing.T) {
	var f Flight[int]
	v, shared := f.Do(k1, func() int { return 7 })
	if v != 7 || shared {
		t.Fatalf("Do = %d, %v; want 7, false", v, shared)
	}
}

func TestFlightResultIsNotRemembered(t *testing.T) {
	// A denied prompt must not deny later requests, and an approved one must
	// not approve them: the cache, not the flight, remembers approvals.
	var f Flight[bool]
	if v, _ := f.Do(k1, func() bool { return false }); v {
		t.Fatal("first call")
	}
	ran := false
	if v, shared := f.Do(k1, func() bool { ran = true; return true }); !v || shared || !ran {
		t.Fatalf("second call: v=%v shared=%v ran=%v", v, shared, ran)
	}
}

// A gate that panics must not wedge the key: later requests for it would
// otherwise hang until restart. Waiters must not see a value fn never
// returned (the zero value is the broker's "not ok").
func TestFlightPanicDoesNotWedgeKey(t *testing.T) {
	var f Flight[int]
	started := make(chan struct{})
	release := make(chan struct{})
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		defer func() { _ = recover() }()
		f.Do(k1, func() int { close(started); <-release; panic("gate crashed") })
	}()
	<-started
	type res struct {
		v      int
		shared bool
	}
	waiter := make(chan res, 1)
	go func() {
		v, s := f.Do(k1, func() int { return 99 })
		waiter <- res{v, s}
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)
	<-leaderDone
	select {
	case r := <-waiter:
		if r.shared && r.v != 0 {
			t.Fatalf("waiter shared a value the panicking fn never returned: %d", r.v)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter hung after the leader panicked")
	}
	done := make(chan int, 1)
	go func() { v, _ := f.Do(k1, func() int { return 5 }); done <- v }()
	select {
	case v := <-done:
		if v != 5 {
			t.Fatalf("call after panic got %d, want 5", v)
		}
	case <-time.After(time.Second):
		t.Fatal("key wedged after a panic")
	}
}

func TestFlightManyKeysConcurrently(t *testing.T) {
	var f Flight[int]
	var calls [8]atomic.Int32
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := 0; i < 8*16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := Key{Target: "ssh:a", Rule: "1:aa", ScopeID: fmt.Sprintf("session:%d@1", i%8)}
			v, _ := f.Do(k, func() int {
				calls[i%8].Add(1)
				<-gate
				return i % 8
			})
			if v != i%8 {
				t.Errorf("key %d got result of key %d", i%8, v)
			}
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	for i := range calls {
		if n := calls[i].Load(); n < 1 {
			t.Errorf("key %d: fn ran %d times", i, n)
		}
	}
}
