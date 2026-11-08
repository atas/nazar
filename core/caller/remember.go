package caller

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/atas/nazar/core/platform"
)

// HelpersVaultItem is the vault item that keeps the helpers a Resolver
// witnessed (witness) across nazar-agent's restarts (THREAT-MODEL 5.14).
const HelpersVaultItem = "state/helpers"

// helpersVersion is the format of HelpersVaultItem, and of the rule that
// made its records: bump it whenever witness (or helperApp) changes what
// may be recorded, so that an install drops records an older rule made
// (live() can re-check a record's process, not that it was once directly
// below its app). An item of another version is a fresh start,
// overwritten by the next change.
//
// Records are refs, which name one process only while generations are
// unique across boots: on macOS a start time in microseconds is. On Linux
// (start ticks since boot) a persisted ref would need a boot ID; nothing is
// recorded there today (no team signs a process, so witness keeps nothing).
const helpersVersion = 1

type helpersItem struct {
	V       int            `json:"v"`
	Helpers []helperRecord `json:"helpers"`
}

// helperRecord is one seenHelper under its full ref.
type helperRecord struct {
	PID        int    `json:"pid"`
	Generation uint64 `json:"generation"`
	Team       string `json:"team"`
	BundleID   string `json:"bundleID"`
}

// Remember makes r keep the helpers it witnesses in v, so that a helper
// one nazar-agent saw below its app still stands for that app in the next
// one (an install or a crash restarts the agent; spec 4.1 step 3).
// It loads what a previous agent kept there and must be called once,
// before r is used. logf (nil: none) gets one line when the item can't be
// used.
//
// Why the vault: only nazar-agent can write its items (THREAT-MODEL 4.1,
// 4.10: the access list trusts only the agent's signature, and securityd's
// partition check refuses an item another program created, even one with
// the agent's own access list; "another program" being code not signed by
// nazar's team, 4.10), so no other process can add a record. A
// record it could add would let a detached copy of a helper (iTermServer
// is an iTerm2-signed binary any process can start) head a chain that
// stands for iTerm2 and shed its ancestors' stricter rules. The item is
// as hard to forge as config/approved and state/trust, which decide far
// more. Removing or corrupting it only forgets helpers (fail closed).
//
// A record is kept at load only for a live process with exactly its full
// ref (PID and start time: a recycled PID is another process) that is
// still signed by the team it was seen under; helperApp checks the rest
// on every use, as for a helper this agent saw itself. An item that can't
// be read (another build's, a planted one, a locked keychain) is logged
// once, leaves r with what it witnesses itself, is reported by
// HelpersUnreadable and is never written over; one that reads but can't be
// parsed is a fresh start. Writes happen in the background (changed), at
// most one per minWriteInterval, so a request never waits for the
// Keychain (only HelpersUnreadable, for `nazar status`, reads it again).
func (r *Resolver) Remember(v platform.Vault, logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	r.mu.Lock()
	r.vault, r.logf = v, logf
	r.mu.Unlock()
	r.read(true)
}

// HelpersUnreadable is why the helpers item can't be read ("" when it can,
// or there is none). It retries the read first, so it clears once the
// item reads again or has been removed.
func (r *Resolver) HelpersUnreadable() string {
	r.mu.Lock()
	unread := r.vault != nil && r.unreadable != ""
	r.mu.Unlock()
	if unread {
		r.read(false)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unreadable
}

// read loads the item and merges its records into r.seen (those r saw
// itself win), dropping the ones no live process matches. It is the load
// of Remember (first) and the retry of an unreadable item. It never holds
// r.mu across the vault or the platform.
func (r *Resolver) read(first bool) bool {
	r.mu.Lock()
	v, logf := r.vault, r.logf
	r.mu.Unlock()
	b, err := v.Get(HelpersVaultItem)
	if errors.Is(err, platform.ErrNotFound) {
		r.mu.Lock()
		r.unreadable = ""
		if len(r.seen) > 0 {
			r.changed()
		}
		r.mu.Unlock()
		return true
	}
	if err != nil {
		r.mu.Lock()
		r.unreadable = err.Error()
		r.mu.Unlock()
		if first {
			logf("caller: %s can't be read, helpers seen before this start are forgotten: %v", HelpersVaultItem, err)
		}
		return false
	}
	recs, err := decodeHelpers(b)
	if err != nil && first {
		logf("caller: %s is not a helper list this build reads, starting without it: %v", HelpersVaultItem, err)
	}
	kept := r.live(recs)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unreadable = ""
	if r.seen == nil {
		r.seen = map[platform.ProcessRef]seenHelper{}
	}
	for ref, h := range kept {
		if _, ok := r.seen[ref]; !ok && len(r.seen) < maxSeen {
			r.seen[ref] = h
		}
	}
	if err != nil || len(kept) != len(recs) || len(r.seen) != len(kept) {
		r.changed() // drop what did not survive, add what r saw meanwhile
	}
	return true
}

// decodeHelpers parses the item; another format is an error.
func decodeHelpers(b []byte) ([]helperRecord, error) {
	var it helpersItem
	if err := json.Unmarshal(b, &it); err != nil {
		return nil, err
	}
	if it.V != helpersVersion {
		return nil, fmt.Errorf("format %d, want %d", it.V, helpersVersion)
	}
	return it.Helpers, nil
}

// live keeps the records witness could have made (a full ref, a non-Apple
// team, a bundle ID) whose ref is a live process still signed by that
// team, at most maxSeen of them.
func (r *Resolver) live(recs []helperRecord) map[platform.ProcessRef]seenHelper {
	out := map[platform.ProcessRef]seenHelper{}
	for _, h := range recs {
		if len(out) >= maxSeen {
			break
		}
		ref := platform.ProcessRef{PID: h.PID, Generation: h.Generation}
		if h.PID <= 0 || h.Generation == 0 || h.Team == "" || h.Team == "apple" || h.BundleID == "" {
			continue
		}
		info, err := r.P.Process(ref)
		if err != nil || info.Ref != ref || info.Code.Team() != h.Team {
			continue
		}
		out[ref] = seenHelper{team: h.Team, bundleID: h.BundleID}
	}
	return out
}

// changed schedules a write of r.seen when r remembers (Remember). The
// caller holds r.mu. One writer runs at a time and writes the latest set
// until nothing changed since its last write, so writes are ordered and
// coalesce, and the caller never waits for the vault.
func (r *Resolver) changed() {
	if r.vault == nil {
		return
	}
	r.dirty = true
	if r.saving {
		return
	}
	r.saving = true
	r.writes.Add(1)
	go r.save()
}

// save is the writer started by changed. While the item can't be read it
// writes nothing (that would replace records no agent has seen yet, or
// fail on an item that is not the agent's): it retries the read instead,
// and writes once that succeeds.
func (r *Resolver) save() {
	defer r.writes.Done()
	for {
		r.mu.Lock()
		if !r.dirty {
			r.saving = false
			r.mu.Unlock()
			return
		}
		unread := r.unreadable != ""
		r.mu.Unlock()
		if unread && !r.read(false) {
			r.mu.Lock()
			r.dirty, r.saving = false, false // the next change, or HelpersUnreadable, tries again
			r.mu.Unlock()
			return
		}
		r.mu.Lock()
		if wait := minWriteInterval - time.Since(r.lastPut); !r.lastPut.IsZero() && wait > 0 {
			r.mu.Unlock()
			time.Sleep(wait) // what changes meanwhile goes into the one write after it
			continue
		}
		r.dirty = false
		b := encodeHelpers(r.seen)
		v, logf := r.vault, r.logf
		r.mu.Unlock()
		err := v.Put(HelpersVaultItem, b)
		r.mu.Lock()
		r.lastPut = time.Now()
		if err != nil && !r.putFailed {
			logf("caller: can't write %s, helpers seen now may be forgotten at the next start: %v", HelpersVaultItem, err)
		}
		r.putFailed = err != nil
		r.mu.Unlock()
	}
}

// minWriteInterval spaces the writes of the helpers item: more live
// helpers of one team than maxSeen change the set on every witness, and
// each change must not be a Keychain write of its own.
const minWriteInterval = time.Second

// encodeHelpers is the item for seen, in a stable order.
func encodeHelpers(seen map[platform.ProcessRef]seenHelper) []byte {
	it := helpersItem{V: helpersVersion, Helpers: make([]helperRecord, 0, len(seen))}
	for ref, h := range seen {
		it.Helpers = append(it.Helpers, helperRecord{PID: ref.PID, Generation: ref.Generation, Team: h.team, BundleID: h.bundleID})
	}
	sort.Slice(it.Helpers, func(i, j int) bool {
		a, b := it.Helpers[i], it.Helpers[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		return a.Generation < b.Generation
	})
	b, _ := json.Marshal(it) // plain structs: never fails
	return b
}
