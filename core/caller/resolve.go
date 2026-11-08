package caller

import (
	"strings"
	"sync"
	"time"

	"github.com/atas/nazar/core/platform"
)

// DefaultMaxDepth bounds the parent walk when Resolver.MaxDepth is unset.
const DefaultMaxDepth = 64

// maxSeen bounds the helpers a Resolver remembers (see witness).
const maxSeen = 256

// Resolver builds Chains from the platform. It is safe for concurrent use
// and must not be copied after first use.
type Resolver struct {
	P        platform.Platform
	MaxDepth int // processes kept at most; <= 0 means DefaultMaxDepth

	mu   sync.Mutex
	seen map[platform.ProcessRef]seenHelper // see witness

	// Set by Remember: the vault the helpers are kept in across restarts.
	vault      platform.Vault
	logf       func(string, ...any)
	unreadable string         // why the item can't be read ("" = it can, or there is none)
	dirty      bool           // seen changed since the writer last copied it
	saving     bool           // a writer runs (changed)
	putFailed  bool           // the last write failed (logged once until one succeeds)
	lastPut    time.Time      // when the last write ended (minWriteInterval)
	writes     sync.WaitGroup // the running writer, for tests
}

// seenHelper is the app a helper was seen directly below.
type seenHelper struct{ team, bundleID string }

// ResolveFD resolves the peer of a connected socket. It never fails: a peer
// that can't be identified yields an unknown chain with no processes.
func (r *Resolver) ResolveFD(fd int) *Chain {
	ref, err := r.P.PeerOf(fd)
	if err != nil {
		return &Chain{Unknown: true, Truncated: true}
	}
	return r.Resolve(ref)
}

// Resolve walks from peer up to launchd and derives the app and session
// (spec 4.1). It never fails: a peer that is gone, or whose generation no
// longer matches (recycled PID), yields an unknown chain with no processes.
// The generation is checked here, not left to the platform: a Process()
// that looks up by PID alone (KERN_PROC_PID) returns whatever now holds the
// PID, and that process must never inherit the peer's chain, app or session.
//
// The peer must be a full ref: PeerOf identifies it by its audit token, so a
// PID-only peer ref (generation 0) is exactly the PID-reuse hole the token
// closes, and is unknown even though the platform would answer it with the
// PID's live occupant.
func (r *Resolver) Resolve(peer platform.ProcessRef) *Chain {
	c := &Chain{}
	if peer.Generation == 0 {
		c.Unknown, c.Truncated = true, true
		return c
	}
	info, err := r.P.Process(peer)
	if err != nil || info.Ref != peer {
		c.Unknown, c.Truncated = true, true
		return c
	}
	c.Procs, c.Truncated = r.walk(info)

	// Step 3: the app is the first GUI app bundle in the chain, peer first.
	// The platform decides what an app is; the chain decides whether the
	// answer is one of its own processes.
	if app, ok := r.P.AppFor(c.Procs); ok && indexOf(c.Procs, app.Ref) >= 0 {
		k := indexOf(c.Procs, app.Ref)
		c.App, c.AppSource = app, AppFromChain
		c.SessionRoot, c.Session = sessionRoot(c.Procs, k)
		if k > 0 {
			r.witness(c.Procs[k-1], app)
		}
		return c
	}

	// Step 3, orphaned helpers (Milestone 7): iTerm2 keeps a tab's processes
	// alive across its own restart (an update) under its helper iTermServer,
	// which launchd then parents; the tab is still iTerm2's. When the chain
	// reached launchd with no app in it, the process at its top may stand
	// for a running app (helperApp says when, and why that is safe); the
	// session root is then found below the helper as it is below an app.
	if !c.Truncated && len(c.Procs) > 0 {
		if app, ok := r.helperApp(c.Procs[len(c.Procs)-1]); ok {
			c.App, c.AppSource = app, AppFromHelper
			c.SessionRoot, c.Session = sessionRoot(c.Procs, len(c.Procs)-1)
			return c
		}
	}

	// Step 5: no app in the chain, so the chain is unknown (ssh ControlPersist
	// masters, detached tools, a chain cut off before the app). The responsible
	// process (spike S3) is looked up for display only: it must be a live GUI
	// app other than the peer itself, and it never provides a session.
	//
	// It is deliberately not an identity. macOS responsibility is inherited
	// across fork/exec, so every process a tab ever started stays "responsible
	// to" the tab's app, whatever else was in its chain. If a responsible
	// chain matched app:/signed: rules, any process could drop the stricter
	// rules of its ancestors (a `apps: claude` rule, spec 4.2 "has Claude Code
	// in its chain") by double-forking or nesting past the depth limit, and
	// take the app's own rule, including a silent `gate: none`. So the chain
	// stays Unknown: no app: rule matches it (signed: still matches the
	// processes that are in it, never the responsible app), it is never
	// remembered, and it is always prompted with the Unknown-app warning
	// (spec 4.1 step 5, 4.2).
	//
	// On macOS the lookup returns a bare PID (a PID-only ref), so the app is
	// resolved and checked like a parent: the record must be the live
	// occupant of that PID with a full ref, and it must have started no later
	// than the peer (responsibility is inherited at fork, so a younger
	// process can only be a newer occupant of a recycled PID).
	c.Unknown = true
	if resp, ok := r.P.ResponsibleFor(peer); ok && !resp.IsZero() && resp.PID != peer.PID {
		if rinfo, ok := r.lookup(resp, info); ok {
			if app, ok := r.P.AppFor([]platform.ProcessInfo{rinfo}); ok && app.Ref == rinfo.Ref {
				c.App, c.AppSource = app, AppFromResponsible
			}
		}
	}
	return c
}

// helperApp finds the app an orphaned helper stands for (spec 4.1 step 3,
// Milestone 7). top is the process launchd parents at the top of a chain
// that reached launchd with no app in it. It stands for an app when all of
// these hold, and the chain stays unknown otherwise:
//
//   - this Resolver, or a previous nazar-agent whose record it kept
//     (Remember), saw top directly below a running app (witness), under
//     its full ref, so a recycled PID is never it, and top is still signed
//     by that app's team, a non-Apple one;
//   - top is responsible for itself: macOS makes a process answer for
//     itself once the process responsible for it has exited (observed
//     on an orphaned iTermServer and its tabs);
//   - exactly one running GUI app has the bundle ID and team top was seen
//     under, runs as the same user and started after top: the app
//     restarted, the helper is older. Each candidate from Apps is accepted
//     only as AppFor accepts its live record under its full ref, so a stale
//     or recycled ref, or a record the platform would not call an app, is
//     never the app.
//
// Why this is safe (THREAT-MODEL 5.14). Only a process the app itself
// started can have been seen directly below it, so a process that leaves
// a chain (double fork, the depth limit) heads a chain whose top was never
// seen there, and stays unknown even after the app restarts: a detached
// copy of the app's own helper, or a detached claude, never sheds its
// ancestors' rules this way. A session is never shared with a real tab
// (the root is below the helper). What is left is what the app itself
// runs, which `open -a <app>` already gives any process, with a window
// (5.1). What was seen is kept in the vault (Remember), which only
// nazar-agent can write, so it outlives the agent's own restarts (an
// install: otherwise every install would leave the tabs that had
// outlived an iTerm2 update unknown) and adds nothing an agent that never
// restarted would not have known. The cost: a helper no nazar-agent saw
// below its app (no request came through it before the app restarted, or
// the vault item could not be kept) stays unknown until its tabs are
// reopened.
func (r *Resolver) helperApp(top platform.ProcessInfo) (platform.AppInfo, bool) {
	r.mu.Lock()
	seen, ok := r.seen[top.Ref]
	r.mu.Unlock()
	if !ok || top.Code.Team() != seen.team {
		return platform.AppInfo{}, false
	}
	if resp, ok := r.P.ResponsibleFor(top.Ref); !ok || resp.PID != top.Ref.PID {
		return platform.AppInfo{}, false
	}
	var found platform.AppInfo
	n := 0
	for _, cand := range r.P.Apps() {
		if cand.Ref.IsZero() || cand.Ref.IsPIDOnly() || cand.BundleID != seen.bundleID {
			continue // the listing is only a hint; the live record below decides
		}
		info, err := r.P.Process(cand.Ref)
		if err != nil || info.Ref != cand.Ref {
			continue
		}
		app, ok := r.P.AppFor([]platform.ProcessInfo{info})
		if !ok || app.Ref != info.Ref || app.BundleID != seen.bundleID || app.Code.Team() != seen.team || info.UID != top.UID || !info.StartTime.After(top.StartTime) {
			continue
		}
		found, n = app, n+1
	}
	if n != 1 {
		return platform.AppInfo{}, false
	}
	return found, true
}

// witness remembers h, the process directly below app in a chain, as a
// helper that may later stand for app (helperApp): it must be signed by
// app's own team, a non-Apple one (iTermServer under iTerm2). It is called
// on every chain with an app in it, as nazar-agent resolves each
// connection, so a tab's server is seen as soon as anything in any of its
// tabs talks to the agent. At most maxSeen helpers are kept: when full,
// those no longer running are dropped first, then an arbitrary one (a
// helper forgotten stays unknown once orphaned; it is never misattributed).
func (r *Resolver) witness(h platform.ProcessInfo, app platform.AppInfo) {
	team := h.Code.Team()
	if team == "" || team == "apple" || team != app.Code.Team() || app.BundleID == "" || h.Ref.IsPIDOnly() {
		return
	}
	rec := seenHelper{team: team, bundleID: app.BundleID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[platform.ProcessRef]seenHelper{}
	}
	if old, ok := r.seen[h.Ref]; ok && old == rec {
		return // nothing new, nothing to write
	}
	if _, ok := r.seen[h.Ref]; !ok && len(r.seen) >= maxSeen {
		for ref := range r.seen {
			if info, err := r.P.Process(ref); err != nil || info.Ref != ref {
				delete(r.seen, ref)
			}
		}
		for ref := range r.seen {
			if len(r.seen) < maxSeen {
				break
			}
			delete(r.seen, ref)
		}
	}
	r.seen[h.Ref] = rec
	r.changed()
}

// lookup resolves ref, which may be a full ref or a PID-only ref (generation
// 0, as KERN_PROC_PID's ppid and the responsible-process lookup give on
// macOS), to the record of a live process that child points at. It fails
// closed when the platform has no such process; when the record is for
// another PID or comes back without a generation (it could not be told from
// a later occupant, and session roots and exit watches are keyed by the
// full ref); when a full ref does not match the record exactly (the PID was
// recycled); or when the process started after child (a PID-only ref can
// only be trusted for a process at least as old as the one naming it).
func (r *Resolver) lookup(ref platform.ProcessRef, child platform.ProcessInfo) (platform.ProcessInfo, bool) {
	info, err := r.P.Process(ref)
	if err != nil || info.Ref.PID != ref.PID || info.Ref.Generation == 0 {
		return platform.ProcessInfo{}, false
	}
	if ref.Generation != 0 && info.Ref != ref {
		return platform.ProcessInfo{}, false
	}
	if info.StartTime.After(child.StartTime) {
		return platform.ProcessInfo{}, false
	}
	return info, true
}

// walk returns the chain from peer up to (not including) launchd, and
// whether it stopped early. It stops, marking the chain truncated, when a
// parent is gone or its generation differs from the recorded parent ref,
// when a parent started after its child (the parent PID was recycled), on a
// loop, or at the depth limit. Loops are detected by PID: a live chain never
// holds one PID twice, and a PID-only parent ref carries nothing else.
func (r *Resolver) walk(peer platform.ProcessInfo) ([]platform.ProcessInfo, bool) {
	max := r.MaxDepth
	if max <= 0 {
		max = DefaultMaxDepth
	}
	procs := []platform.ProcessInfo{peer}
	seen := map[int]bool{peer.Ref.PID: true}
	cur := peer
	for {
		if cur.Parent.IsZero() || cur.Parent.PID == 1 {
			return procs, false // reached launchd
		}
		if len(procs) >= max || seen[cur.Parent.PID] {
			return procs, true
		}
		parent, ok := r.lookup(cur.Parent, cur)
		if !ok {
			return procs, true
		}
		seen[parent.Ref.PID] = true
		procs = append(procs, parent)
		cur = parent
	}
}

// sessionRoot finds the session root below procs[k], the app or the helper
// standing for it (spec 4.1 step 4): the process closest to the app that
// is neither signed by a third-party team
// (an app's helpers, such as iTermServer, which hosts every tab of iTerm2,
// or VS Code's terminal host; any process inside the app's bundle; a
// non-Apple process whose file is gone) nor running as another user than the app (the
// root-owned /usr/bin/login). In iTerm2 and Terminal that is the tab's
// login shell. Skipping can only move the root deeper, to a narrower
// session; the one mistake that matters is a root shared by several tabs,
// and a helper is that. The app's own signature is not consulted, so an app
// whose running code no longer verifies (updated on disk, not restarted)
// still gets per-tab sessions. Apple-signed processes are never skipped:
// shells are Apple's, and they are the sessions. Without such a process
// (the peer is the app or one of its helpers) there is no session.
func sessionRoot(procs []platform.ProcessInfo, k int) (platform.ProcessRef, SessionID) {
	if k < 0 || k >= len(procs) {
		return platform.ProcessRef{}, SessionID{}
	}
	appUID := procs[k].UID
	bundle := bundleDir(procs[k].Path)
	for i := k - 1; i >= 0; i-- {
		p := procs[i]
		if t := p.Code.Team(); t != "" && t != "apple" {
			continue
		}
		if bundle != "" && strings.HasPrefix(p.Path, bundle) {
			continue // inside the app's own bundle: a helper, verified or not
		}
		if p.Path == "" && p.Code.Team() != "apple" {
			continue // its file is gone (deleted by an update): can't be told from a helper
		}
		if p.UID != appUID {
			continue
		}
		return p.Ref, SessionID{PID: p.Ref.PID, Start: p.StartTime}
	}
	return platform.ProcessRef{}, SessionID{}
}

// bundleDir is the "<…>.app/" folder an app's executable lives in (the
// outermost one, with its trailing slash), or "" when the path is not inside
// an app bundle.
func bundleDir(path string) string {
	if i := strings.Index(path, ".app/"); i >= 0 {
		return path[:i+len(".app/")]
	}
	return ""
}

func indexOf(procs []platform.ProcessInfo, ref platform.ProcessRef) int {
	for i, p := range procs {
		if p.Ref == ref {
			return i
		}
	}
	return -1
}
