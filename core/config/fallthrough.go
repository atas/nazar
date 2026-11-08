package config

// The `to:` fall-through (spec 4.2): a rule matches only if both apps: and
// to: match, so a request whose caller rule i matches but whose receiver is
// not in i's to: falls through to the rules after i. A later rule j with a
// weaker gate then gives that caller, through another receiver, an easier
// approval than rule i meant to. The config stays valid (a risky-but-valid
// config is the user's choice); config check warns on
// rule j, naming rule i.

// gateStrength orders the gates by what they prove (spec 4.2): block
// refuses, login proves it's you, dialog proves someone is there, none
// proves nothing. A rule is weaker than another when its gate proves less.
func gateStrength(g Gate) int {
	switch g {
	case GateBlock:
		return 3
	case GateLogin:
		return 2
	case GateDialog:
		return 1
	}
	return 0
}

// ftRule is a rule reduced to what the fall-through check needs, with the
// matchers interned so that a file at MaxFileSize costs integer compares.
type ftRule struct {
	strength int
	// apps: classes. A chain matcher (signed, app, path) can co-occur with
	// any other chain matcher in one caller chain (Claude Code inside iTerm);
	// an unknown chain is matched by unknown and any, and by a process
	// matcher (signed, path) for a process in it, never by app: (spec 4.2).
	any, unknown, named, proc bool
	toOpen                    bool // no to:, or to: any: every receiver
	apps, to                  []int32
}

// overlaps reports whether one request could match both rules' apps:.
func (a ftRule) overlaps(b ftRule) bool {
	return a.any || b.any || (a.named && b.named) || (a.unknown && (b.unknown || b.proc)) || (b.unknown && a.proc)
}

// reachableFrom reports whether a receiver outside i's to: can match j's
// to: (or j accepts every receiver).
func (j ftRule) reachableFrom(i ftRule) bool {
	if j.toOpen {
		return true
	}
	for _, t := range j.to {
		if !has(i.to, t) {
			return true
		}
	}
	return false
}

// catches reports whether k takes every request that falls through i:
// every caller i matches, with any receiver.
func (k ftRule) catches(i ftRule) bool {
	return k.toOpen && (k.any || (len(i.apps) > 0 && subset(i.apps, k.apps)))
}

// fallThroughs returns, per rule position, the position in rules of the
// earliest to:-restricted earlier rule whose fall-through reaches this rule
// with a weaker gate, or -1. It is a position, not a Rule.Index: key() drops
// rules that fail to parse, so the two differ as soon as an earlier rule is
// invalid, and a caller must index rules by position. shadowed is
// shadowedBy(rules): a rule that can never match neither falls through nor
// catches anything. One warning per later rule keeps the output (and the
// work) bounded by the number of rules.
func fallThroughs(rules []Rule, shadowed []int) []int {
	ids := map[string]int32{}
	intern := func(ms []Matcher) []int32 {
		out := make([]int32, 0, len(ms))
		for _, m := range ms {
			c := m.Canonical()
			id, ok := ids[c]
			if !ok {
				id = int32(len(ids))
				ids[c] = id
			}
			out = append(out, id)
		}
		return out
	}
	x := make([]ftRule, len(rules))
	for k, r := range rules {
		f := ftRule{strength: gateStrength(r.Policy.Gate), toOpen: len(r.To) == 0 || hasKind(r.To, MatchAny), apps: intern(r.Apps), to: intern(r.To)}
		for _, m := range r.Apps {
			switch m.Kind {
			case MatchAny:
				f.any = true
			case MatchUnknown:
				f.unknown = true
			case MatchSigned, MatchPath:
				f.named, f.proc = true, true
			default:
				f.named = true
			}
		}
		x[k] = f
	}
	out := make([]int, len(rules))
	for j := range out {
		out[j] = -1
	}
	var live []int // positions of restricted rules whose fall-through is still open
	for j := range rules {
		if shadowed[j] > 0 {
			continue
		}
		rj := x[j]
		keep := live[:0]
		for _, i := range live {
			ri := x[i]
			if out[j] < 0 && rj.strength < ri.strength && ri.overlaps(rj) && rj.reachableFrom(ri) {
				out[j] = i
			}
			if !rj.catches(ri) {
				keep = append(keep, i)
			}
		}
		live = keep
		if !rj.toOpen {
			live = append(live, j)
		}
	}
	return out
}

// aboveUnknown returns, per rule position, the position of the nearest later
// `apps: unknown` rule with a stronger gate when the rule has a signed: or
// path: matcher, or -1. Such a rule matches an unknown chain its program is
// in (spec 4.2), so it takes, at its weaker gate, unknown callers the later
// rule was written for; a config approved before that matching changed got
// looser without an edit. Shadowed rules (shadowedBy) take nothing and are
// skipped on both sides. One pass from the end: next[s] is the nearest
// unknown rule seen so far whose gate strength is s.
func aboveUnknown(rules []Rule, shadowed []int) []int {
	out := make([]int, len(rules))
	next := [4]int{-1, -1, -1, -1}
	for j := len(rules) - 1; j >= 0; j-- {
		out[j] = -1
		if shadowed[j] > 0 {
			continue
		}
		r := rules[j]
		s := gateStrength(r.Policy.Gate)
		if hasKind(r.Apps, MatchSigned) || hasKind(r.Apps, MatchPath) {
			for t := s + 1; t < len(next); t++ {
				if next[t] >= 0 && (out[j] < 0 || next[t] < out[j]) {
					out[j] = next[t]
				}
			}
		}
		if hasKind(r.Apps, MatchUnknown) {
			next[s] = j
		}
	}
	return out
}
