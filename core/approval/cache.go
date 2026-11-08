// Package approval holds remembered approvals (spec 4.3) and makes
// concurrent requests for the same approval share one prompt (spec 4.4).
// Everything is in memory: nothing survives a restart.
package approval

import (
	"sort"
	"sync"
	"time"

	"github.com/atas/nazar/core/platform"
)

// Key indexes an approval: (target, rule, scope_id, receiver, op). Every
// part is compared exactly; no part is optional or matched by prefix.
type Key struct {
	Target   string // "ssh:github", "secret:GH_TOKEN"
	Rule     string // policy.Outcome.RuleID
	ScopeID  string // "session:<id>" or "app:<team:bundle>"
	Receiver string // identity matched by to:, "" for a rule without to: (a secret always has one)
	// Op is what the approval covers (spec 4.3, Milestone 7): Op.ID as the
	// module that asked chose it. For ssh, a login to one server by the
	// host key its session-bind proved ("login:SHA256:…"), a login nothing
	// proved ("login:unbound"), or one kind of signature ("sign:git",
	// "sign:ns:<namespace>", "sign:nsx:<sha256>", "sign:data"). For a
	// secret, its delivery method ("deliver:helper", "deliver:stdout"), set
	// by the broker. The broker never remembers a request whose op is "".
	Op string
}

// Op is what one request does, as an approval covers it: ID is the exact
// form the cache keys on (Key.Op), Text is how the dialog and `nazar
// status` say it ("github.com", "git commits and tags"). The module that
// asks chooses both; Text is shown only through the broker's and the CLI's
// cleaning, like every other caller-derived string.
type Op struct {
	ID   string
	Text string
}

// Entry is one remembered approval.
type Entry struct {
	Key     Key
	Scope   string // "session" or "app"
	Created time.Time
	Expires time.Time // zero = until the scope ends or a revoke
	Chain   string    // chain summary shown when it was approved
	App     string    // bundle id, for `nazar revoke --app`
	Covers  string    // Op.Text when it was approved, for `nazar status` and the dialog
	Ref     platform.ApprovalRef
}

// EventType is the kind of a change notification.
type EventType string

const (
	Added   EventType = "added"
	Removed EventType = "removed"
)

// Event is sent to subscribers on every change.
type Event struct {
	Type   EventType
	Entry  Entry
	Reason string // "expired", "revoked", "session ended", "replaced", ...
}

// Cache is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	now     func() time.Time
	release func(platform.ApprovalRef)
	entries map[Key]Entry
	subs    map[int]chan Event
	nextSub int
}

// New returns an empty cache. now supplies the current time; release is
// called exactly once for every non-zero Ref that leaves the cache and may
// be nil.
func New(now func() time.Time, release func(platform.ApprovalRef)) *Cache {
	return &Cache{now: now, release: release, entries: map[Key]Entry{}, subs: map[int]chan Event{}}
}

// Lookup returns a live entry; an expired one is removed and not returned.
// Looking an entry up never extends it.
func (c *Cache) Lookup(k Key) (Entry, bool) {
	c.mu.Lock()
	e, ok := c.entries[k]
	var gone []platform.ApprovalRef
	if ok && c.expiredLocked(e) {
		gone = c.removeLocked(k, "expired", gone)
		e, ok = Entry{}, false
	}
	c.mu.Unlock()
	c.releaseAll(gone)
	return e, ok
}

// expiredLocked compares wall-clock instants. Go's monotonic clock stops
// while a Mac sleeps, so an 8h approval compared monotonically would
// outlive a night with the lid closed. Entries are stored without a
// monotonic reading (see Put) and now is stripped of its reading here, so
// Before compares wall clocks only. An entry expires at its Expires instant.
func (c *Cache) expiredLocked(e Entry) bool {
	return !e.Expires.IsZero() && !c.now().Round(0).Before(e.Expires)
}

// Put stores e, replacing (and releasing) any entry with the same key.
// Times are stored without their monotonic reading (see expiredLocked).
func (c *Cache) Put(e Entry) {
	e.Created, e.Expires = e.Created.Round(0), e.Expires.Round(0)
	c.mu.Lock()
	var gone []platform.ApprovalRef
	if _, ok := c.entries[e.Key]; ok {
		gone = c.removeLocked(e.Key, "replaced", gone)
	}
	c.entries[e.Key] = e
	c.publishLocked(Event{Type: Added, Entry: e})
	c.mu.Unlock()
	c.releaseAll(gone)
}

// RevokeWhere removes every entry for which pred is true and returns how many.
func (c *Cache) RevokeWhere(reason string, pred func(Entry) bool) int {
	c.mu.Lock()
	var gone []platform.ApprovalRef
	n := 0
	for k, e := range c.entries {
		if pred(e) {
			gone = c.removeLocked(k, reason, gone)
			n++
		}
	}
	c.mu.Unlock()
	c.releaseAll(gone)
	return n
}

// RevokeAll removes everything (`nazar revoke --all`).
func (c *Cache) RevokeAll(reason string) int {
	return c.RevokeWhere(reason, func(Entry) bool { return true })
}

// RevokeTarget removes approvals for one target (`nazar revoke --key`).
func (c *Cache) RevokeTarget(target, reason string) int {
	return c.RevokeWhere(reason, func(e Entry) bool { return e.Key.Target == target })
}

// RevokeScope removes approvals for one scope: a session that ended, an
// app that quit, `nazar revoke --session/--app`.
func (c *Cache) RevokeScope(scopeID, reason string) int {
	return c.RevokeWhere(reason, func(e Entry) bool { return e.Key.ScopeID == scopeID })
}

// RevokeApp removes approvals whose app bundle id is bundleID, in any scope.
func (c *Cache) RevokeApp(bundleID, reason string) int {
	return c.RevokeWhere(reason, func(e Entry) bool { return e.App == bundleID })
}

// RetainRules drops entries whose "target|rule" is not mapped to true in
// live (after a config change). A nil or empty live drops everything.
func (c *Cache) RetainRules(live map[string]bool, reason string) int {
	return c.RevokeWhere(reason, func(e Entry) bool { return !live[e.Key.Target+"|"+e.Key.Rule] })
}

// Sweep removes expired entries and returns how many.
func (c *Cache) Sweep() int {
	return c.RevokeWhere("expired", c.expiredLocked)
}

// List returns copies of the live entries, oldest first (ties by target).
func (c *Cache) List() []Entry {
	c.mu.Lock()
	var gone []platform.ApprovalRef
	for k, e := range c.entries {
		if c.expiredLocked(e) {
			gone = c.removeLocked(k, "expired", gone)
		}
	}
	out := make([]Entry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	c.mu.Unlock()
	c.releaseAll(gone)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].Key.Target < out[j].Key.Target
	})
	return out
}

// Subscribe returns a channel of change events and a cancel function that
// closes the channel; calling cancel more than once is safe. A subscriber
// that doesn't keep up loses events rather than blocking the cache.
func (c *Cache) Subscribe() (<-chan Event, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextSub
	c.nextSub++
	ch := make(chan Event, 64)
	c.subs[id] = ch
	return ch, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if s, ok := c.subs[id]; ok {
			delete(c.subs, id)
			close(s)
		}
	}
}

// removeLocked deletes k, publishes its removal and appends its ref (if
// any) to gone for release once the lock is dropped. Deleting under the
// lock is what makes each ref leave the cache, and so be released, once.
func (c *Cache) removeLocked(k Key, reason string, gone []platform.ApprovalRef) []platform.ApprovalRef {
	e := c.entries[k]
	delete(c.entries, k)
	c.publishLocked(Event{Type: Removed, Entry: e, Reason: reason})
	if e.Ref != 0 {
		gone = append(gone, e.Ref)
	}
	return gone
}

// releaseAll calls release for each ref, outside the lock so a release
// that blocks or re-enters the cache can't wedge it.
func (c *Cache) releaseAll(refs []platform.ApprovalRef) {
	if c.release == nil {
		return
	}
	for _, r := range refs {
		c.release(r)
	}
}

func (c *Cache) publishLocked(ev Event) {
	for _, s := range c.subs {
		select {
		case s <- ev:
		default:
		}
	}
}
