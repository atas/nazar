package broker

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/policy"
)

// Display budgets, in runes. Caller-controlled text (app names, command
// lines, folders, chain summaries, the module's summary) is cut so that
// nothing can push the approval line off a dialog.
const (
	maxName    = 64
	maxSummary = 160 // "login to " + every name of a server (100) + " (via a forwarded agent) as " + user
	maxCommand = 120
	maxFolder  = 80
	maxChain   = 200
	maxLine    = 400
)

// clean makes s safe for one line on screen: every rune that is not
// printable (C0/C1 controls, newlines, ESC, bidi overrides and other format
// characters) becomes '?', and the text is cut to max runes with an
// ellipsis. Nothing a caller chooses can add a line, move the cursor or
// reverse the reading direction of a prompt.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			b.WriteString("…")
			break
		}
		if !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// tilde shortens p with ~ when it is Home or lies under it. A sibling that
// merely shares Home as a string prefix (/Users/uevil) is left alone.
func (b *Broker) tilde(p string) string {
	home := strings.TrimRight(b.o.Home, "/")
	if home == "" {
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

// appName is the chain's app name, cut and cleaned for a headline.
func appName(c *caller.Chain) string {
	return clean(c.AppName(), maxName)
}

// commandLine is what the user ran (spec 4.4: caller.Chain.Command, the
// command behind the ssh or ssh-keygen that connected), redacted, plus its
// folder. Arguments go through the audit allowlist, so a token, URL or
// script never reaches the screen; the program name is rendered by
// programText so that it cannot read as a different command; the folder is
// caller controlled and cleaned.
func (b *Broker) commandLine(c *caller.Chain) string {
	if c == nil {
		return "(process could not be identified)"
	}
	if c.Synthetic {
		// A nazar run receiver: what runs, by its full pinned realpath (a
		// caller chooses argv[0] freely), with the redacted tail.
		p, _ := c.Peer()
		parts := audit.RedactArgs(p.Args)
		if len(parts) > 0 {
			parts[0] = clean(b.tilde(p.Path), maxFolder)
		}
		return clean(strings.Join(parts, " "), maxCommand) + "    in " + clean(p.Cwd, maxFolder)
	}
	cmd, ok := c.Command()
	if !ok {
		return "(process could not be identified)"
	}
	parts := audit.RedactArgs(cmd.Args)
	if len(parts) > 0 {
		parts[0] = programText(parts[0])
	}
	line := clean(strings.Join(parts, " "), maxCommand)
	if cmd.Cwd != "" {
		line += "    in " + clean(b.tilde(cmd.Cwd), maxFolder)
	}
	return line
}

// matchedLine names the process that satisfied the rule's apps: matcher
// when the chain line does not show it (hiddenMatch), so the user sees why
// the rule applied: "matched: claude (rule 1, above Foo)". It is "" when the
// chain line already shows that process, or no rule matched.
func matchedLine(out policy.Outcome, c *caller.Chain) string {
	p, where, ok := hiddenMatch(out, c)
	if !ok {
		return ""
	}
	name, deleted := caller.ProcName(p)
	shown := programText(name)
	if deleted {
		shown += caller.DeletedMark
	}
	return fmt.Sprintf("matched: %s (rule %d, %s)", shown, out.RuleIndex, where)
}

// hiddenMatch returns the process out.Matched names when it is in the chain
// but not in the chain line (the app and Chain.Below): above the app
// (claude → Foo.app → ssh, matched by `apps: claude`), or between the app
// and its session root (one of the app's helpers). In an unknown chain it
// is always named, though the chain line shows it: a rule other than any
// or unknown matched a chain with no app only because of that process
// (spec 4.2), and the dialog and the audit line say which. It is judged
// by process ref, so a process that merely has the matched name is never
// it. The second result says where it sits, for the dialog.
func hiddenMatch(out policy.Outcome, c *caller.Chain) (platform.ProcessInfo, string, bool) {
	if out.Matched.IsZero() || (c.HasApp() && out.Matched == c.App.Ref) {
		return platform.ProcessInfo{}, "", false
	}
	if c.Unknown {
		for _, p := range c.Procs {
			if p.Ref == out.Matched {
				return p, "in the chain", true
			}
		}
		return platform.ProcessInfo{}, "", false
	}
	for _, p := range c.Below() {
		if p.Ref == out.Matched {
			return platform.ProcessInfo{}, "", false
		}
	}
	// Procs is peer first: hops before the app sit between it and the
	// session (its helpers), hops after it sit above it.
	where := "between " + appName(c) + " and the session"
	for _, p := range c.Procs {
		if c.AppSource == caller.AppFromChain && p.Ref == c.App.Ref {
			where = "above " + appName(c)
		}
		if p.Ref == out.Matched {
			return p, where, true
		}
	}
	return platform.ProcessInfo{}, "", false
}

// programText renders a caller-chosen program name (argv[0]'s base name, or
// an executable's) for a prompt the same way the audit log does (spec
// 4.6): bare if and only if it is a plain word, otherwise
// quoted with strconv.QuoteToASCII, so that "git push origin main" shows as
// `"git push origin main"` and never as the command `git push origin main`,
// a name with a newline or a terminal escape cannot add a line, and a
// blank-looking (U+2800), zero-width or look-alike rune shows as \uXXXX
// rather than making "ssh⠀git@github.com" read as the real `ssh
// git@github.com`. The rendered program is at most maxName runes, cut before
// it is quoted, so that it can never push the arguments or the folder off
// the line.
func programText(prog string) string {
	if audit.PlainWord(prog) {
		return prog
	}
	r := []rune(prog)
	for n := min(len(r), maxName); ; n-- {
		q := strconv.QuoteToASCII(string(r[:n]))
		if n < len(r) {
			q += "…"
		}
		if utf8.RuneCountInString(q) <= maxName || n == 0 {
			return q
		}
	}
}

// scopeNoun names what an approval would be remembered for: the run of the
// tool that satisfied the rule ("this claude run", Milestone 7), the tab,
// the app, or nothing. The tool's name is rendered like a program name.
func scopeNoun(out policy.Outcome, c *caller.Chain) string {
	switch out.Policy.Scope {
	case config.ScopeSession:
		if p, ok := c.Tool(out.Matched); ok {
			name, _ := caller.ProcName(p)
			return "this " + programText(name) + " run"
		}
		return "this terminal session"
	case config.ScopeApp:
		return "this app (" + appName(c) + ")"
	}
	return "this request only"
}

// scopeText says what an approval would cover (the "Scope:" line): the
// scope, and within it only what this request does (spec 4.3, Milestone 7:
// "this terminal session, for github.com only").
func scopeText(out policy.Outcome, c *caller.Chain, covers string) string {
	if out.OneShot {
		return "this request only"
	}
	s := scopeNoun(out, c)
	if covers != "" {
		s += ", for " + covers + " only"
	}
	if out.Policy.Expire > 0 {
		s += fmt.Sprintf(" (expires in %s)", out.Policy.Expire)
	}
	return s
}

// alsoCovered lists what the same scope already holds under this rule and
// receiver for other ops (Milestone 7), oldest first, so that a prompt in
// an approved tab says it is for a new destination or kind of signature.
// Nothing for a one-shot request.
func (b *Broker) alsoCovered(req Request, out policy.Outcome) []string {
	if out.OneShot {
		return nil
	}
	key := approvalKey(req, out)
	var also []string
	for _, e := range b.o.Cache.List() {
		k := e.Key
		k.Op = key.Op
		if k == key && e.Key.Op != key.Op {
			also = append(also, e.Covers)
		}
	}
	return also
}

// prompt builds the dialog of spec 4.4. Every line is cleaned as a whole,
// so exactly one line starts with "Scope:" whatever a caller names its
// app, command, folder, matched process or destination, and the "Already
// approved" line is one line whatever the scope's approvals are named.
func (b *Broker) prompt(req Request, out policy.Outcome, timeout time.Duration) platform.Prompt {
	c := req.Chain
	lines := []string{
		clean(req.Summary, maxSummary),
		b.commandLine(req.receiverChain()),
		"chain: " + clean(c.Summary(), maxChain),
	}
	if m := matchedLine(out, c); m != "" {
		lines = append(lines, m)
	}
	lines = append(lines, "Scope: "+scopeText(out, c, req.Op.Text))
	if also := b.alsoCovered(req, out); len(also) > 0 {
		lines = append(lines, "Already approved for "+scopeNoun(out, c)+": "+strings.Join(also, ", "))
	}
	command := 2 // the command line's number: after the summary
	if c.Unknown {
		lines = append([]string{"Unknown app: nazar could not tell which app started this."}, lines...)
		command++
	}
	for i, l := range lines {
		lines[i] = clean(l, maxLine)
	}
	return platform.Prompt{
		Title:       clean(fmt.Sprintf("%s wants to use %s", appName(c), req.noun()), maxLine),
		Lines:       lines,
		CommandLine: command,
		Unknown:     c.Unknown,
		Reason:      clean(fmt.Sprintf("use %s for %s (%s)", req.noun(), clean(req.Summary, maxFolder), appName(c)), maxLine),
		Timeout:     timeout,
	}
}

// The audit `rule` field (spec 4.6) when no rule of the key matched: the
// key's own scope/gate/expire (a key without rules, like `hydra`, or a
// caller none of its rules match) is RuleKeyGate, and defaults.fallback is
// RuleFallback. Before Milestone 5 both were "fallback".
const (
	RuleKeyGate  = "key-gate"
	RuleFallback = "fallback"
)

// event fills everything but Decision, Reason and Time: who asked (callerEvent)
// and what the policy decided (rule, gate, scope, and the matched process
// when the chain field does not show it).
func (b *Broker) event(req Request, out policy.Outcome) audit.Event {
	e := b.callerEvent(req, out.Target)
	e.Session = out.Session.String() // the run's, when a tool in the tab satisfied the rule
	e.Rule, e.Gate = RuleFallback, string(out.Policy.Gate)
	switch {
	case out.RuleIndex > 0:
		e.Rule = strconv.Itoa(out.RuleIndex)
	case out.KeyGate:
		e.Rule = RuleKeyGate
	}
	if p, _, ok := hiddenMatch(out, req.Chain); ok {
		e.Matched = AuditProc(p)
	}
	if out.Policy.Gate.Prompts() {
		e.Scope = string(out.Policy.Scope)
		if out.OneShot {
			e.Scope = string(config.ScopeUse)
		}
	}
	return e
}

// callerEvent is the part of an audit entry that says who asked and for
// what (spec 4.6): target, destination, operation, app, session, chain,
// receiver (the socket peer for a key, the receiving process for a secret),
// command (what the user ran, when it is not the receiver) and cwd (the
// command's folder). The argvs and cwd go in raw:
// the audit formatter redacts and quotes them.
func (b *Broker) callerEvent(req Request, target string) audit.Event {
	c := req.Chain
	e := audit.Event{
		Target: target, Destination: req.Destination, Operation: req.Operation,
		Session: c.Session.String(),
	}
	if req.Secret != "" {
		e.Delivery = string(req.Delivery)
		e.EnvPassed = req.EnvPassed
	}
	if c.HasApp() {
		e.App = c.App.BundleID
	}
	e.Chain = AuditChain(c)
	if rc := req.receiverChain(); rc != nil && rc.Synthetic {
		// A nazar run receiver: its argv starts with the pinned realpath
		// (Program logs its base name); command= and cwd= say what the
		// user ran and where, as for every other request (spec 4.6).
		if peer, ok := rc.Peer(); ok && len(peer.Args) > 0 {
			e.Receiver = append([]string{peer.Path}, peer.Args[1:]...)
		}
		if cmd, ok := c.Parent().Command(); ok {
			e.Command, e.Cwd = cmd.Args, cmd.Cwd
		}
	} else if rc != nil {
		if peer, ok := rc.Peer(); ok {
			e.Receiver = peer.Args
			cmd, _ := rc.Command() // the peer when nothing else is there
			if cmd.Ref != peer.Ref {
				e.Command = cmd.Args
			}
			e.Cwd = cmd.Cwd
		}
	}
	return e
}

// AuditProc is p as a chain element of the audit line: its name
// (caller.ProcName), its PID, for non-Apple signed code its identity, and
// whether its executable file is gone. The deleted mark is a field of its
// own, outside the name (audit.Proc.Deleted), so a binary literally named
// "claude-code (file deleted)" never reads as a deleted claude-code. Every
// audit chain (the broker's, the control commands') is built with it.
func AuditProc(p platform.ProcessInfo) audit.Proc {
	name, deleted := caller.ProcName(p)
	ap := audit.Proc{Name: name, PID: p.Ref.PID, Deleted: deleted}
	if t := p.Code.Team(); t != "" && t != "apple" {
		ap.Identity = t + ":" + p.Code.SigningID
	}
	return ap
}

// AuditChain is the audit chain field for c (spec 4.6): what the user
// thinks of as the command (Below, outermost first), preceded by the helper
// standing for the app when there is one (Milestone 7), so the line says
// the chain reached its app through an orphaned helper, and which, as the
// dialog's chain line does with "(via …)".
func AuditChain(c *caller.Chain) []audit.Proc {
	var out []audit.Proc
	if h, ok := c.Helper(); ok {
		out = append(out, AuditProc(h))
	}
	for _, p := range c.Below() {
		out = append(out, AuditProc(p))
	}
	return out
}

// warn shows the block warning (no allow button). The same caller hitting
// the same target within WarnWindow updates one window with a counter; a
// later attempt starts a new window with its own ID.
func (b *Broker) warn(req Request, out policy.Outcome) {
	c := req.Chain
	who := c.AppIdentity()
	if who == "" {
		who = c.Summary()
	}
	now := b.o.Now()
	b.mu.Lock()
	for k, st := range b.warns {
		if now.Sub(st.first) >= b.o.WarnWindow {
			delete(b.warns, k)
		}
	}
	dedup := out.Target + "|" + who
	st := b.warns[dedup]
	if st == nil {
		st = &warnState{first: now}
		b.warns[dedup] = st
	}
	st.count++
	count := st.count
	id := fmt.Sprintf("%s|%d", dedup, st.first.UnixNano())
	b.mu.Unlock()

	why := blockedWhy(out, c)
	lines := []string{
		clean(req.Summary, maxSummary),
		b.commandLine(req.receiverChain()),
		"chain: " + clean(c.Summary(), maxChain),
	}
	if m := matchedLine(out, c); m != "" {
		lines = append(lines, m)
	}
	lines = append(lines, why)
	// No rule allows a method deliver: does not list. A secret's asker is
	// always the nazar CLI, so a rule is drafted from the chain above it: a
	// rule for the CLI would match every secret request from any script.
	// A k8s or aws check (the program that ran nazar, the cluster, the
	// entry) is no rule's to allow either. Their rules are judged above that
	// program, so a rule is drafted from there.
	suggest := ""
	if out.Reason != policy.ReasonDelivery && !(req.K8s != "" && k8sCheck(out.Reason)) && !(req.AWS != "" && awsCheck(out.Reason)) {
		lines = append(lines, "To allow it, add a rule to "+layout.ConfigFileTilde+".")
		switch {
		case req.K8s != "" || req.AWS != "":
			suggest = SuggestRule(c.Callers())
		case req.Secret != "":
			suggest = SuggestRule(c.Parent())
		default:
			suggest = SuggestRule(c)
		}
	}
	for i, l := range lines {
		lines[i] = clean(l, maxLine)
	}
	b.o.Platform.ShowWarning(platform.Warning{
		ID:            id,
		Title:         clean(fmt.Sprintf("Blocked: %s tried to use %s", appName(c), req.noun()), maxLine),
		Lines:         lines,
		CommandLine:   2, // after the summary
		Count:         count,
		SuggestedRule: suggest,
	})
}

// yamlPlainRE is the only shape a caller-derived value takes unquoted in a
// suggested rule: no space, quote, '#', ':' or flow indicator, so it can
// never end the matcher, add a key or start a comment, and starting with a
// letter or '/', so it can never read as a number (123, 0x10, 1e3, 1_000) or
// a YAML date or timestamp rather than the string it is.
var yamlPlainRE = regexp.MustCompile(`^[A-Za-z/][A-Za-z0-9._/-]*$`)

// yamlScalar renders v for a suggested rule: bare when it is plainly a
// string, otherwise double-quoted with Go escapes, which YAML reads back as
// the same value. Newlines, '#', ':' and braces in an executable path or a
// signing ID therefore stay inside one scalar.
func yamlScalar(v string) string {
	if yamlPlainRE.MatchString(v) && len(v) <= 256 {
		switch strings.ToLower(v) {
		case "true", "false", "yes", "no", "on", "off", "null", "y", "n":
		default:
			return v
		}
	}
	return strconv.Quote(v)
}

// SuggestRule drafts a rule for the "Copy suggested rule" button: the
// strongest matcher available for this caller (spec 4.4). It always keeps
// a person in the loop (gate: login) and never widens to apps: any. An
// unknown chain (no app above it) whose innermost program that is not
// Apple's is unsigned or ad hoc (a Homebrew tool or daemon) gets a
// one-shot path: rule for that file, by its stable opt/ path when it runs
// from a Homebrew Cellar (HomebrewOptPath); any other unknown chain gets
// apps: unknown, one-shot: a signed: rule for a tool in it would match it
// too, but would also be remembered for that tool in every terminal tab,
// which this request never showed the user. An interpreter (node, python)
// gets no path: rule: it would cover every script. A signed non-Apple
// program below the app gets signed:, and a GUI app gets app:.
// Apple-signed matchers are never suggested: they match nearly every
// chain.
func SuggestRule(c *caller.Chain) string {
	const tail = "\n  scope: session\n  gate: login"
	const unknown = "- apps: [unknown]\n  scope: use\n  gate: login"
	if c == nil {
		return unknown
	}
	if c.Unknown {
		if p, ok := unsignedProgram(c); ok {
			return fmt.Sprintf("- apps:\n    - path: %s\n  scope: use\n  gate: login", yamlScalar(HomebrewOptPath(p)))
		}
		return unknown
	}
	below := c.Below()
	for i := len(below) - 1; i >= 0; i-- { // innermost first: the program that asked
		p := below[i]
		if t := p.Code.Team(); t != "" && t != "apple" && p.Code.SigningID != "" {
			return fmt.Sprintf("- apps:\n    - signed:\n        team: %s\n        id: %s%s", yamlScalar(t), yamlScalar(p.Code.SigningID), tail)
		}
	}
	if c.HasApp() && c.App.BundleID != "" {
		return fmt.Sprintf("- apps:\n    - app: %s%s", yamlScalar(c.App.BundleID), tail)
	}
	return unknown
}

// unsignedProgram is the path of the innermost process of an unknown
// chain that is not Apple's, when it has no team (unsigned or ad hoc), a
// clean absolute path and is no interpreter. A chain cut off before
// launchd matches no path: rule (match.Evaluator), so it has none.
func unsignedProgram(c *caller.Chain) (string, bool) {
	if c.Truncated {
		return "", false
	}
	for _, p := range c.Procs { // peer first: the program that asked
		switch p.Code.Team() {
		case "apple":
			continue
		case "":
			if filepath.IsAbs(p.Path) && filepath.Clean(p.Path) == p.Path && !config.SystemPath(p.Path) && !config.Interpreter(filepath.Base(p.Path)) {
				return p.Path, true
			}
		}
		return "", false
	}
	return "", false
}

// HomebrewOptPath is the stable path of an executable p that runs from a
// Homebrew Cellar (<prefix>/Cellar/<formula>/<version>/<rest>): the
// <prefix>/opt/<formula>/<rest> link, when it resolves to p now, so a rule
// on it follows `brew upgrade`. Any other p is returned as it is.
func HomebrewOptPath(p string) string {
	prefix, rest, ok := strings.Cut(p, "/Cellar/")
	if !ok {
		return p
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return p
	}
	opt := prefix + "/opt/" + parts[0] + "/" + parts[2]
	if r, err := filepath.EvalSymlinks(opt); err != nil || r != p {
		return p
	}
	return opt
}

// blockedWhy is the block warning's reason line. An app whose running code
// no longer verifies (it updated itself on disk and was not restarted)
// matches no app: rule and gets no session; the fix is a restart, not a
// new rule, so the warning says so.
func blockedWhy(out policy.Outcome, c *caller.Chain) string {
	if strings.HasPrefix(out.Target, "k8s:") {
		if why := k8sWhy(out, c); why != "" {
			return why
		}
	}
	if strings.HasPrefix(out.Target, "aws:") {
		if why := awsWhy(out); why != "" {
			return why
		}
	}
	switch {
	case out.Reason == policy.ReasonDelivery:
		return "This secret's deliver: does not allow this method."
	case out.Reason == "to: mismatch":
		return "A rule matches this caller, but not the program that would receive the result (to:)."
	case out.RuleIndex > 0:
		return fmt.Sprintf("Rule %d blocks this caller.", out.RuleIndex)
	case c != nil && c.HasApp() && c.App.Code.Team() == "":
		name := clean(c.App.Name, 64)
		return name + "'s running code doesn't pass its signature check, so no app: rule can match it. If it updated itself, quit and reopen " + name + "."
	}
	return "This caller has no rule. If you didn't expect this, something may be wrong."
}
