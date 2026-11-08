package config

// Covers reports whether every request rule b matches is also matched by
// rule a, judged from the matchers alone (Canonical forms, so names don't
// matter). It is conservative: false means "can't tell", never "definitely
// not". Later tasks use it for shadowing warnings and tighten/loosen checks.
func Covers(a, b Rule) bool {
	return coversApps(a.Apps, b.Apps) && coversTo(a.To, b.To)
}

// CoversAll reports whether a matches every request (apps: any, no to:).
func CoversAll(a Rule) bool {
	return hasKind(a.Apps, MatchAny) && len(a.To) == 0
}

// coversApps: "any" covers every caller, unknown chains included (spec 4.2).
// Otherwise every matcher of b must appear in a. A rule with no apps: matches
// nothing, and nothing covers it (it can't exist after Parse).
func coversApps(a, b []Matcher) bool {
	if hasKind(a, MatchAny) {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, m := range b {
		if !contains(a, m) {
			return false
		}
	}
	return true
}

// coversTo: no to: (or to: any) accepts every receiver. A restricted a never
// covers an unrestricted b.
func coversTo(a, b []Matcher) bool {
	if len(a) == 0 || hasKind(a, MatchAny) {
		return true
	}
	if len(b) == 0 {
		return false
	}
	for _, m := range b {
		if !contains(a, m) {
			return false
		}
	}
	return true
}

// shadowedBy returns, for each rule, the Index of the first earlier rule that
// Covers it, or 0. It is exactly Covers applied pairwise under first-match,
// but with the matchers interned once and candidates found through posting
// lists, so a file at MaxFileSize (about 22k rules) takes milliseconds where
// the naive loop took over a minute (Canonical rebuilds strings each call).
func shadowedBy(rules []Rule) []int {
	x := newCoverIndex(rules)
	out := make([]int, len(rules))
	for j := range rules {
		if i := x.firstCovering(j); i >= 0 {
			out[j] = rules[i].Index
		}
	}
	return out
}

// ruleSets is a rule's matchers as interned atom ids, for repeated checks.
type ruleSets struct {
	appsAny, toOpen bool
	apps, to        []int32
}

// coverIndex holds each rule's interned matchers plus ascending position
// lists. A rule a covers rule b only if (a has apps: any, or every atom of
// b.apps) and (a has an open to:, none or any, or every atom of b.to). The
// four combinations give the candidate lists below; three of them do not
// depend on b beyond one atom and are built once.
type coverIndex struct {
	sets     []ruleSets
	coverAll []int // apps: any and open to: — covers every rule
	// Per atom: rules whose apps:/to: contain it, and the subsets of those
	// with an open to: / with apps: any.
	postApps, postAppsOpen map[int32][]int
	postTo, postToAny      map[int32][]int
}

func newCoverIndex(rules []Rule) *coverIndex {
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
	x := &coverIndex{
		sets:     make([]ruleSets, len(rules)),
		postApps: map[int32][]int{}, postAppsOpen: map[int32][]int{},
		postTo: map[int32][]int{}, postToAny: map[int32][]int{},
	}
	for k, r := range rules {
		s := ruleSets{appsAny: hasKind(r.Apps, MatchAny), toOpen: len(r.To) == 0 || hasKind(r.To, MatchAny), apps: intern(r.Apps), to: intern(r.To)}
		x.sets[k] = s
		if s.appsAny && s.toOpen {
			x.coverAll = append(x.coverAll, k)
		}
		for _, a := range s.apps {
			x.postApps[a] = append(x.postApps[a], k)
			if s.toOpen {
				x.postAppsOpen[a] = append(x.postAppsOpen[a], k)
			}
		}
		for _, a := range s.to {
			x.postTo[a] = append(x.postTo[a], k)
			if s.appsAny {
				x.postToAny[a] = append(x.postToAny[a], k)
			}
		}
	}
	return x
}

// firstCovering returns the lowest position i < j whose rule covers rule j,
// or -1. Candidates come from the rarest atom of j's apps: and of its to:,
// so the lists are short for any realistic file; coversSets confirms each.
func (x *coverIndex) firstCovering(j int) int {
	b := x.sets[j]
	sApps, aApps := rarest(x.postApps, b.apps)
	sTo, aTo := rarest(x.postTo, b.to)
	always := func(int) bool { return true }
	best := x.scan(x.coverAll, j, -1, b, always)
	best = x.scan(x.postToAny[aTo], j, best, b, always)
	best = x.scan(x.postAppsOpen[aApps], j, best, b, always)
	// Rules with both atoms: scan the shorter list, test the other atom.
	if len(sTo) < len(sApps) {
		return x.scan(sTo, j, best, b, func(i int) bool { return has(x.sets[i].apps, aApps) })
	}
	return x.scan(sApps, j, best, b, func(i int) bool { return has(x.sets[i].to, aTo) })
}

// scan walks an ascending candidate list and returns the first position
// below j and below best (or -1) that passes member and covers b; else best.
func (x *coverIndex) scan(list []int, j, best int, b ruleSets, member func(int) bool) int {
	for _, i := range list {
		if i >= j || (best >= 0 && i >= best) {
			break
		}
		if member(i) && coversSets(x.sets[i], b) {
			return i
		}
	}
	return best
}

// coversSets is Covers on interned rules: see coversApps and coversTo.
func coversSets(a, b ruleSets) bool {
	if !a.appsAny && (len(b.apps) == 0 || !subset(b.apps, a.apps)) {
		return false
	}
	return a.toOpen || (len(b.to) > 0 && subset(b.to, a.to))
}

func subset(b, a []int32) bool {
	for _, x := range b {
		if !has(a, x) {
			return false
		}
	}
	return true
}

func has(a []int32, x int32) bool {
	for _, y := range a {
		if y == x {
			return true
		}
	}
	return false
}

// rarest returns the shortest posting list among atoms and its atom; nil
// and -1 when there are no atoms (the maps then yield nil lists too).
func rarest(post map[int32][]int, atoms []int32) ([]int, int32) {
	var best []int
	bestAtom := int32(-1)
	for i, a := range atoms {
		if l := post[a]; i == 0 || len(l) < len(best) {
			best, bestAtom = l, a
		}
	}
	return best, bestAtom
}

func hasKind(ms []Matcher, k MatcherKind) bool {
	for _, m := range ms {
		if m.Kind == k {
			return true
		}
	}
	return false
}

func contains(ms []Matcher, m Matcher) bool {
	want := m.Canonical()
	for _, x := range ms {
		if x.Canonical() == want {
			return true
		}
	}
	return false
}
