package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ArgsMode mirrors config audit.args: "redacted" (default) or "none".
// Any value other than ArgsNone redacts: a full command line is never logged.
type ArgsMode string

const (
	ArgsRedacted ArgsMode = "redacted"
	ArgsNone     ArgsMode = "none"
)

// MaxLine is the longest message text Format returns, in bytes. The unified
// log stores roughly 1015 bytes of a message and replaces the rest with
// "<…>" (measured on macOS 27), which would make an entry unparseable and
// let a caller hide its own entry from `nazar log` by padding argv, cwd or a
// process name. Caller-derived fields are therefore clipped (see Clipped)
// before the line is assembled and, when the line is still too long,
// receiver, command, chain, cwd, destination, operation and matched are
// shortened in that order. decision, reason, target, delivery, rule, scope,
// gate, app and session are never shortened to fit the line.
const MaxLine = 1000

// Clipping budgets, in bytes of the formatted (quoted) value. The fields
// that are never shortened to fit the line add up to well under MaxLine at
// these caps, so the squeeze in Format always succeeds.
const (
	maxShort     = 64  // decision, rule, scope, gate
	maxDelivery  = 16  // delivery (helper, stdout, late-env, …)
	maxIdent     = 100 // app, session
	maxField     = 160 // reason, target, destination, operation, cwd
	maxChain     = 400 // whole chain value
	maxChainPart = 64  // one chain name or identity
	maxReceiver  = 400 // whole receiver value, and the command value
	maxArg       = 128 // the receiver's program name, rendered (arguments are plain words or Elided)
)

// Clipped is the marker that ends every shortened value: "…+N" where N is
// what was dropped: bytes of a string, arguments of the receiver, elements
// of the chain. A caller can put the same text inside its own value, which
// can only ever claim that something was dropped, never hide a field.
const Clipped = "…+"

// Formatter renders events as `key=value` lines.
type Formatter struct {
	Args ArgsMode
	Home string // replaced by ~ in cwd
}

var (
	// bareRE is the only shape a value may have unquoted: no space, quote,
	// backslash or `=`, so a bare value can never look like another field.
	bareRE = regexp.MustCompile(`^[A-Za-z0-9._:/@+,~\-]+$`)
	// keyRE is the shape of a field name.
	keyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	// chainNameRE is the only shape a chain name may have unquoted: no
	// space, paren, comma, quote or `>`, so a name can never read as part
	// of another element, as a PID or as a signing identity.
	chainNameRE = regexp.MustCompile(`^[A-Za-z0-9._+\-]+$`)
	// chainIdentityRE is the only shape an identity ("TEAMID:signing.id")
	// may have unquoted.
	chainIdentityRE = regexp.MustCompile(`^[A-Z0-9]+:[A-Za-z0-9._\-]+$`)
	// chainElisionRE is the element Format puts where chain elements were
	// dropped. A process name can never be bare "…", so it is unforgeable.
	chainElisionRE = regexp.MustCompile(`^…\+[0-9]+$`)
)

// ellipsis (U+2026) is the one non-ASCII rune a line may contain raw. Format
// writes it itself in the Elided and Clipped markers; every other non-ASCII
// rune of a line is a caller's and is escaped.
const ellipsis = "…"

// quote returns v bare when that is unambiguous, otherwise quoted as
// strconv.QuoteToASCII would, except that an ellipsis stays raw. So a value
// can never contain a raw newline, a quote or a `key=` that forges a field;
// every control, separator and format rune (C0/C1, U+2028/2029, bidi
// overrides), invalid UTF-8 and every other non-ASCII rune shows as an
// escape, so that a blank-looking (U+2800, U+3164, U+00A0), zero-width
// (U+200B) or look-alike (Cyrillic "і", fullwidth "．") rune in a bundle
// ID, cwd, destination or operation can never make it read as a different
// one, in the raw line or once `nazar log` unquotes it. ParseLine inverts
// this with strconv.Unquote, so values round trip unchanged. `nazar log`
// must render a value through quote (or an ASCII-only %q), never print the
// unquoted text, or the escapes are undone for the reader.
//
// A caller's own ellipsis in a directly quoted field (reason, target,
// destination, operation, rule, scope, gate, app, session, cwd) therefore
// shows raw too. That is harmless: in those fields it can only ever claim
// that something was dropped (see Clipped). Inside the receiver and chain
// values, where "…" is a token, every caller rune goes through argQuote or
// chainComponent first and is escaped, so a raw "…" there is always
// Format's own.
func quote(v string) string {
	if bareRE.MatchString(v) {
		return v
	}
	return `"` + quoteBody(v) + `"`
}

// quoteBody is the text between the quotes of quote(v) for a quoted v: the
// strconv.QuoteToASCII escaping of each run between ellipses, and the
// ellipses themselves. Splitting on the ellipsis bytes is sound in any byte
// string: UTF-8 is self-synchronizing, so E2 80 A6 decodes as U+2026 wherever
// it occurs, and a caller's literal backslash text (`…`) is escaped to
// `\\u2026` by QuoteToASCII and never pasted together with a raw ellipsis.
// The result is additive per rune, which clip relies on.
func quoteBody(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	for i, run := range strings.Split(v, ellipsis) {
		if i > 0 {
			b.WriteString(ellipsis)
		}
		if run != "" {
			q := strconv.QuoteToASCII(run)
			b.WriteString(q[1 : len(q)-1])
		}
	}
	return b.String()
}

// field is one key=value pair of a line. val is already quoted; shrink, when
// set, re-renders the field so that its value is at most limit bytes (or as
// short as it can get).
type field struct {
	key    string
	val    string
	shrink func(limit int) string
}

// Format returns the message text for e in the field order of spec 4.6,
// with matched= after chain= and command= after receiver= (spec 4.4: the
// command the user ran and the matched hop the chain does not show). Empty
// fields are omitted. There is no timestamp: the log adds it. The result is
// at most MaxLine bytes.
func (f Formatter) Format(e Event) string {
	fixed := func(k, v string, limit int) field {
		return field{key: k, val: quote(clip(v, limit, quote))}
	}
	soft := func(k, v string, limit int) field {
		return field{key: k, val: quote(clip(v, limit, quote)), shrink: func(limit int) string { return quote(clip(v, limit, quote)) }}
	}
	argv := func(k string, argv []string) field {
		prog, args, hidden := f.receiverParts(argv) // redacted once; argv may be 1 MB
		return field{key: k, val: quote(receiverFrom(prog, args, hidden, maxReceiver)), shrink: func(limit int) string { return quote(receiverFrom(prog, args, hidden, limit)) }}
	}
	chain := func(k string, procs []Proc) field {
		return field{key: k, val: quote(formatChain(procs, maxChain)), shrink: func(limit int) string { return quote(formatChain(procs, limit)) }}
	}
	var matched []Proc
	if e.Matched != (Proc{}) {
		matched = []Proc{e.Matched}
	}
	fields := []field{
		fixed("decision", string(e.Decision), maxShort),
		fixed("reason", e.Reason, maxField),
		fixed("target", e.Target, maxField),
		fixed("delivery", e.Delivery, maxDelivery),
		fixed("env_passed", strings.Join(e.EnvPassed, ","), maxField),
		soft("destination", e.Destination, maxField),
		soft("operation", e.Operation, maxField),
		fixed("rule", e.Rule, maxShort),
		fixed("scope", e.Scope, maxShort),
		fixed("gate", e.Gate, maxShort),
		fixed("app", e.App, maxIdent),
		fixed("session", e.Session, maxIdent),
		chain("chain", e.Chain),
		chain("matched", matched),
		argv("receiver", e.Receiver),
		argv("command", e.Command),
		soft("cwd", f.cwd(e.Cwd), maxField),
	}
	for i := range fields {
		if fields[i].val == `""` {
			fields[i].val = "" // empty fields are omitted
		}
	}
	line := joinFields(fields)
	for _, k := range []string{"receiver", "command", "chain", "cwd", "destination", "operation", "matched"} {
		over := len(line) - MaxLine
		if over <= 0 {
			break
		}
		for i := range fields {
			if fields[i].key != k || fields[i].val == "" {
				continue
			}
			fields[i].val = fields[i].shrink(max(len(fields[i].val)-over, 0))
			line = joinFields(fields)
		}
	}
	return line
}

func joinFields(fields []field) string {
	var b strings.Builder
	for _, fl := range fields {
		if fl.val == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(fl.key)
		b.WriteByte('=')
		b.WriteString(fl.val)
	}
	return b.String()
}

// clipMarker returns the Clipped marker for n dropped units.
func clipMarker(n int) string {
	return Clipped + strconv.Itoa(n)
}

// clip returns v, or the longest prefix of v (on a rune boundary) plus a
// Clipped marker, such that q(result) is at most limit bytes. When not even
// the marker fits, the marker alone is returned. q must be additive per rune
// (quote and chainComponent are), so the search is monotonic.
func clip(v string, limit int, q func(string) string) string {
	if len(q(v)) <= limit {
		return v
	}
	fits := func(n int) bool { return len(q(v[:n]+clipMarker(len(v)-n))) <= limit }
	// Candidate cuts are the rune boundaries in [1, min(len(v)-1, limit)]:
	// a cut inside a rune would leave a byte that quotes longer than the
	// rune. Over rune boundaries fits is monotone, so binary search for
	// the last one that fits.
	var cuts []int
	for i := 1; i <= min(len(v)-1, limit); i++ {
		if utf8.RuneStart(v[i]) {
			cuts = append(cuts, i)
		}
	}
	n := sort.Search(len(cuts), func(i int) bool { return !fits(cuts[i]) })
	if n == 0 {
		return clipMarker(len(v))
	}
	return v[:cuts[n-1]] + clipMarker(len(v)-cuts[n-1])
}

// chainComponent renders a chain name or identity: bare when it has the safe
// (ASCII) shape, otherwise quoted with every non-ASCII rune escaped and `>`
// escaped as well, so a quoted component never contains the " > " separator
// and a caller-controlled process name can never read as extra chain
// elements, as a signing identity, or (through a blank-looking or look-alike
// rune such as U+2800 or Cyrillic "ѕ") as a different name.
func chainComponent(s string, bare *regexp.Regexp) string {
	if bare.MatchString(s) {
		return s
	}
	return strings.ReplaceAll(strconv.QuoteToASCII(s), ">", `\x3e`)
}

func chainElement(p Proc) string {
	nameQ := func(s string) string { return chainComponent(s, chainNameRE) }
	name := nameQ(clip(p.Name, maxChainPart, nameQ))
	var b strings.Builder
	fmt.Fprintf(&b, "%s(%d", name, p.PID)
	if p.Identity != "" {
		idQ := func(s string) string { return chainComponent(s, chainIdentityRE) }
		b.WriteString(", " + idQ(clip(p.Identity, maxChainPart, idQ)))
	}
	if p.Deleted {
		// Bare and last: no identity is bare without a colon, and a name
		// or identity that is not a plain word is quoted, so nothing a
		// caller chooses can read as this marker.
		b.WriteString(", " + chainDeleted)
	}
	b.WriteByte(')')
	return b.String()
}

// chainDeleted is the marker of a process whose executable file is gone.
const chainDeleted = "deleted"

// FormatChain is the chain field's value exactly as Format writes it (and
// ParseLine returns it, unquoted) for a line with room for the whole field:
// the same quoting, the deleted mark outside the name, and the same bound
// and drop order for a long chain. Every other view of a chain (the
// window's "last used") is built with it.
func FormatChain(chain []Proc) string {
	return formatChain(chain, maxChain)
}

// formatChain renders chain as "name(pid[, team:id][, deleted]) > ...", at most limit
// bytes once quoted. When that is too long, elements are dropped and each
// run of dropped elements is replaced in place by one "…+N" element.
//
// The drop order is fixed so that a caller cannot choose what its own entry
// omits: the chain inside a caller (its descendants, which it spawns and
// names) is under its control, the chain outside it is not. Kept first are
// the innermost element (the direct caller) and the outermost (the session
// root), then every signed element, outermost first, then the unsigned ones,
// outermost first. So the signed element a rule matched on is never dropped
// while an unsigned element between it and the caller remains, and a caller
// that pads its own chain with long or self-signed elements only ever
// pushes those out of the entry.
func formatChain(chain []Proc, limit int) string {
	n := len(chain)
	if n == 0 {
		return ""
	}
	elems := make([]string, n)
	cost := make([]int, n) // quoted bytes of each element's contents
	for i, p := range chain {
		elems[i] = chainElement(p)
		cost[i] = len(quoteBody(elems[i]))
	}
	if s := strings.Join(elems, " > "); len(quote(s)) <= limit {
		return s
	}
	order := make([]int, 0, n)
	order = append(order, n-1)
	if n > 1 {
		order = append(order, 0)
	}
	for _, signed := range []bool{true, false} {
		for i := 1; i < n-1; i++ {
			if (chain[i].Identity != "") == signed {
				order = append(order, i)
			}
		}
	}
	// Keep the longest prefix of order that fits. Size is not quite
	// monotonic in the number kept ("…+1" is one byte longer than "x(1)"),
	// so every count is checked rather than searched.
	keep := make([]bool, n)
	for k := n - 1; k >= 0; k-- {
		clear(keep)
		for _, i := range order[:k] {
			keep[i] = true
		}
		if chainSize(cost, keep) <= limit || k == 0 {
			return renderChain(elems, keep)
		}
	}
	return clipMarker(n) // unreachable: k == 0 always returns
}

// chainSize is the quoted size of renderChain(elems, keep) given the quoted
// size of each element's contents: the kept elements, one marker per run of
// dropped ones, " > " between them and the quotes.
func chainSize(cost []int, keep []bool) int {
	size, parts := 2, 0
	for i := 0; i < len(keep); i++ {
		if keep[i] {
			size += cost[i]
		} else {
			j := i
			for j+1 < len(keep) && !keep[j+1] {
				j++
			}
			size += len(clipMarker(j - i + 1))
			i = j
		}
		parts++
	}
	return size + 3*(parts-1)
}

// renderChain joins the kept elements, with each run of dropped elements
// replaced in place by one "…+N" element.
func renderChain(elems []string, keep []bool) string {
	parts := make([]string, 0, len(elems))
	for i := 0; i < len(elems); i++ {
		if keep[i] {
			parts = append(parts, elems[i])
			continue
		}
		j := i
		for j+1 < len(elems) && !keep[j+1] {
			j++
		}
		parts = append(parts, clipMarker(j-i+1))
		i = j
	}
	return strings.Join(parts, " > ")
}

// ParseChain is the inverse of formatChain for the value of the chain field
// (as returned by ParseLine): outermost element first. Elements Format
// dropped ("…+N") are skipped. Anything that Format could not have produced
// is an error. `nazar log` must use this rather than splitting the string,
// because a quoted name may contain "(", ")", "," or spaces.
func ParseChain(s string) ([]Proc, error) {
	if s == "" {
		return nil, nil
	}
	var out []Proc
	for _, el := range strings.Split(s, " > ") {
		if chainElisionRE.MatchString(el) {
			continue
		}
		name, rest, err := chainToken(el, chainNameRE)
		if err != nil || !strings.HasPrefix(rest, "(") {
			return nil, fmt.Errorf("audit: malformed chain element %q", el)
		}
		rest = rest[1:]
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		pid, err := strconv.Atoi(rest[:i])
		if err != nil {
			return nil, fmt.Errorf("audit: malformed chain element %q", el)
		}
		rest = rest[i:]
		var id string
		const mark = ", " + chainDeleted + ")"
		if strings.HasPrefix(rest, ", ") && !strings.HasPrefix(rest, mark) {
			if id, rest, err = chainToken(rest[2:], chainIdentityRE); err != nil || id == "" {
				return nil, fmt.Errorf("audit: malformed chain element %q", el)
			}
		}
		// The deleted mark is bare, last and only once; a quoted
		// "deleted" is an identity (read above), never the mark.
		deleted := rest == mark
		if deleted {
			rest = ")"
		}
		if rest != ")" {
			return nil, fmt.Errorf("audit: malformed chain element %q", el)
		}
		out = append(out, Proc{Name: name, PID: pid, Identity: id, Deleted: deleted})
	}
	return out, nil
}

// chainToken reads one bare or quoted chain component from the start of s
// and returns it with the remainder.
func chainToken(s string, bare *regexp.Regexp) (string, string, error) {
	if strings.HasPrefix(s, `"`) {
		q, err := strconv.QuotedPrefix(s)
		if err != nil {
			return "", "", err
		}
		v, err := strconv.Unquote(q)
		if err != nil {
			return "", "", err
		}
		return v, s[len(q):], nil
	}
	end := strings.IndexAny(s, "(,)")
	if end < 0 {
		end = len(s)
	}
	if end == 0 || !bare.MatchString(s[:end]) {
		return "", "", fmt.Errorf("audit: bad chain token %q", s)
	}
	return s[:end], s[end:], nil
}

// receiverParts splits argv into what the receiver field is built from: the
// program (argv[0]'s base name, not yet rendered), the rendered arguments
// and the number of arguments left out entirely. Full, unredacted command
// lines are never logged: ArgsNone keeps only the program name and the
// argument count; every other mode keeps the program name and the arguments
// RedactArgs allows (the rest show as Elided).
func (f Formatter) receiverParts(argv []string) (prog string, args []string, hidden int) {
	if len(argv) == 0 {
		return "", nil, 0
	}
	if f.Args == ArgsNone {
		return Program(argv[0]), nil, len(argv) - 1
	}
	parts := RedactArgs(argv)
	return parts[0], parts[1:], 0
}

// argQuote renders the receiver's program name, the one caller-chosen token
// of the receiver value (kept arguments are plain words, the rest are
// Elided). It is bare if and only if it is a PlainWord, so that it can never
// be mistaken for several arguments, for an Elided argument or a Clipped
// marker, or for a different program: anything else, including every
// non-ASCII rune, is quoted with strconv.QuoteToASCII. A blank-looking rune
// (U+2800, U+3164), a look-alike letter (Cyrillic "ѕ" in "ѕѕh") or a
// fullwidth "．" therefore shows as \uXXXX, and "ssh⠀git@github.com" can no
// longer be read as the real `ssh git@github.com`.
func argQuote(a string) string {
	if PlainWord(a) {
		return a
	}
	return strconv.QuoteToASCII(a)
}

// receiverFrom renders the receiver value in at most limit bytes once
// quoted: the program, the arguments that fit, and, when any argument is
// hidden or dropped, one "…+N" marker at the end. The program is clipped to
// maxArg so that it can never push the arguments off the line, and clipped
// further when it does not fit on its own.
func receiverFrom(prog string, args []string, hidden, limit int) string {
	if prog == "" {
		return "" // no receiver (Program never returns "" for an argv)
	}
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, argQuote(clip(prog, maxArg, argQuote)))
	parts = append(parts, args...)
	// Quoted size of the joined parts is additive: 2 + contents + separators.
	size, keep := 2, 0
	for keep < len(parts) {
		next := size + len(quoteBody(parts[keep]))
		if keep > 0 {
			next++ // the space before this part
		}
		if next > limit {
			break
		}
		size, keep = next, keep+1
	}
	if keep == len(parts) && hidden == 0 {
		return strings.Join(parts, " ")
	}
	// Dropping the tail adds " …+N": back off until that fits too.
	for ; keep > 0; keep-- {
		s := strings.Join(parts[:keep], " ") + " " + clipMarker(hidden+len(parts)-keep)
		if len(quote(s)) <= limit {
			return s
		}
	}
	// Not even the program fits: clip it, measuring exactly what will be
	// logged (the rendered program plus the marker, quoted as a value).
	tail := ""
	if n := hidden + len(parts) - 1; n > 0 {
		tail = " " + clipMarker(n)
	}
	q := func(s string) string { return quote(argQuote(s) + tail) }
	return argQuote(clip(prog, limit, q)) + tail
}

// cwd shortens p with ~ when it is Home or lies under it. A sibling that
// merely shares Home as a string prefix (/Users/uevil) is left alone.
func (f Formatter) cwd(p string) string {
	home := f.Home
	if home != "" && home != "/" {
		home = strings.TrimRight(home, "/")
	}
	if home == "" || home == "/" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}

// ParseLine is the inverse of Format: it returns the fields of one message
// (used by `nazar log`). It accepts exactly what Format produces: `key=value`
// pairs separated by spaces, each value either bare or Go-quoted with no raw
// rune outside printable ASCII other than the ellipsis, no duplicate keys,
// and a non-empty decision. Anything else is an error.
func ParseLine(s string) (map[string]string, error) {
	out := map[string]string{}
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			break
		}
		k, rest, ok := strings.Cut(s, "=")
		if !ok || !keyRE.MatchString(k) {
			return nil, fmt.Errorf("audit: malformed field near %q", s)
		}
		var v string
		if strings.HasPrefix(rest, `"`) {
			q, err := strconv.QuotedPrefix(rest)
			if err != nil {
				return nil, fmt.Errorf("audit: bad quoted value for %s", k)
			}
			if !lineClean(q) {
				return nil, fmt.Errorf("audit: raw non-ASCII in quoted value for %s", k)
			}
			v, err = strconv.Unquote(q)
			if err != nil {
				return nil, fmt.Errorf("audit: bad quoted value for %s", k)
			}
			rest = rest[len(q):]
		} else {
			end := strings.IndexByte(rest, ' ')
			if end < 0 {
				end = len(rest)
			}
			v, rest = rest[:end], rest[end:]
			if !bareRE.MatchString(v) {
				return nil, fmt.Errorf("audit: malformed value for %s", k)
			}
		}
		if rest != "" && rest[0] != ' ' {
			return nil, fmt.Errorf("audit: trailing data after %s", k)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("audit: duplicate field %s", k)
		}
		out[k] = v
		s = rest
	}
	if out["decision"] == "" {
		return nil, fmt.Errorf("audit: no decision field")
	}
	return out, nil
}

// lineClean reports whether s is what Format writes: printable ASCII and
// the ellipsis, nothing else raw.
func lineClean(s string) bool {
	for _, r := range s {
		if (r < 0x20 || r > 0x7e) && r != '…' {
			return false
		}
	}
	return true
}
