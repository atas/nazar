package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
)

// The commands behind the Nazar window (spec 6, 6.1; Milestone 5): reading
// a key's rules and the top-level apps, editing rules and a key's own gate,
// and opening the window. An edit is made by Nazar.app (config.edit), which
// writes config.yaml and stages it: a tightening is in force at once (exit
// 0); a loosening is written only with --allow-loosen-access, and then the
// CLI sends at once the config.apply bound to it that shows the login gate
// (one command, one Touch ID, from any caller). Without the flag nazar-agent
// refuses it (exit 2) and says what it would loosen, and the CLI prints the
// command to run. Nothing here decides: nazar-agent classifies and gates.

// refsFlag collects matcher references for --apps / --to. Each value is a
// comma-separated list. The flag may be given more than once; set tells
// "given empty" from "not given".
type refsFlag struct {
	refs []string
	set  bool
}

func (f *refsFlag) String() string { return strings.Join(f.refs, ",") }

func (f *refsFlag) Set(v string) error {
	f.set = true
	for v != "" {
		ref, rest, _ := strings.Cut(v, ",")
		f.refs = append(f.refs, ref)
		v = rest
	}
	return nil
}

// boolFlag is a flag that takes no value (--no-to, --no-expire).
type boolFlag struct{ set bool }

func (f *boolFlag) String() string   { return strconv.FormatBool(f.set) }
func (f *boolFlag) Set(string) error { f.set = true; return nil }
func (f *boolFlag) IsBoolFlag() bool { return true }

// policyFlags are --scope, --gate and --expire, checked locally.
type policyFlags struct {
	scope, gate, expire onceFlag
	noExpire            boolFlag
}

// args checks the flags that were given and adds them to m (expire "" for
// --no-expire). allowNone says whether --gate none is allowed (rules yes,
// a key's own gate no).
func (p *policyFlags) args(cmd string, m map[string]string, allowNone bool) error {
	usage := func(format string, a ...any) error {
		return control.NewProblem(control.CodeUsage, cmd+": "+format, a...)
	}
	if p.scope.set {
		switch config.Scope(p.scope.value) {
		case config.ScopeUse, config.ScopeSession, config.ScopeApp:
		default:
			return usage("--scope must be use, session or app, not %q", p.scope.value)
		}
		m["scope"] = p.scope.value
	}
	if p.gate.set {
		switch config.Gate(p.gate.value) {
		case config.GateLogin, config.GateDialog, config.GateBlock:
		case config.GateNone:
			if !allowNone {
				return usage("a key's own gate applies to every caller, so it can't be none; add a rule with --apps instead")
			}
		default:
			return usage("--gate must be login, dialog, none or block, not %q", p.gate.value)
		}
		m["gate"] = p.gate.value
	}
	switch {
	case p.expire.set && p.noExpire.set:
		return usage("give --expire or --no-expire, not both")
	case p.expire.set:
		if _, err := config.ParseDuration(p.expire.value); err != nil {
			return usage("--expire: %v", err)
		}
		m["expire"] = p.expire.value
	case p.noExpire.set:
		m["expire"] = ""
	}
	return nil
}

// refsArg checks matcher references and encodes them for config.edit.
func refsArg(cmd, name string, refs []string) (string, error) {
	for _, r := range refs {
		if _, err := config.ParseMatcherRef(r); err != nil {
			return "", control.NewProblem(control.CodeUsage, "%s: --%s: %v", cmd, name, err)
		}
	}
	if refs == nil {
		refs = []string{}
	}
	b, err := json.Marshal(refs)
	return string(b), err
}

// ruleIndex parses a 1-based rule number.
func ruleIndex(cmd, what, v string) (string, error) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return "", control.NewProblem(control.CodeUsage, "%s: %s must be a rule number from 1, not %q", cmd, what, v)
	}
	return strconv.Itoa(n), nil
}

// sshKeyRules is `nazar ssh-key rules <name>`.
func (a *app) sshKeyRules(args []string) int {
	pos, err := a.parse(a.flags("ssh-key rules"), args, 1)
	if err != nil {
		return a.fail(err)
	}
	if !config.ValidKeyName(pos[0]) {
		return a.usageError("ssh-key rules: invalid key name %q", pos[0])
	}
	var r control.SSHKeyRules
	if err := a.call(control.CmdSSHKeyRules, map[string]string{"name": pos[0]}, control.KindSSHKeyRules, &r); err != nil {
		return a.fail(err)
	}
	return a.emit(r, func() { a.printRules(r) })
}

// printRules is the human view of a key's rules; every value is
// config-derived and printed through term.
func (a *app) printRules(r control.SSHKeyRules) {
	if r.Staged {
		fmt.Fprintln(a.stdout, "config.yaml has a staged change: these rules apply once it is approved (`nazar config apply`)")
	}
	if !r.Configured {
		fmt.Fprintf(a.stdout, "%s has no entry in config.yaml\n", term(r.Name))
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tAPPS\tTO\tSCOPE\tGATE\tEXPIRE")
	for _, rule := range r.Rules {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", rule.Index, term(refList(rule.Apps)), term(refList(rule.To)),
			term(rule.Policy.Scope), term(rule.Policy.Gate), term(rule.Policy.Expire))
	}
	fmt.Fprintf(tw, "others\t\t\t%s\t%s\t%s\n", term(r.Fallback.Scope), term(r.Fallback.Gate), term(r.Fallback.Expire))
	tw.Flush()
	fmt.Fprintf(a.stdout, "others: callers no rule matches get %s\n", term(r.FallbackSource))
}

// refList shows matchers the way --apps takes them.
func refList(ms []control.MatcherInfo) string {
	var parts []string
	for _, m := range ms {
		if m.Ref != "" {
			parts = append(parts, m.Ref)
		} else {
			parts = append(parts, m.Kind)
		}
	}
	return strings.Join(parts, ",")
}

// ruleTarget is what a rule command edits: an SSH key's rules, a secret's,
// a k8s context's or an aws entry's, with one implementation. noun is
// also config.edit's arg that names the entry, unless arg names it. noTo,
// when set, is why --to and --no-to are refused.
type ruleTarget struct {
	cmd, noun string // "ssh-key", "key"; "secret", "secret"; "k8s", "context"; "aws", "entry"
	valid     func(string) bool
	noTo      string
	arg       string // config.edit's arg when it is not noun: "aws"
}

// editArg is config.edit's arg that names t's entry.
func (t ruleTarget) editArg() string {
	if t.arg != "" {
		return t.arg
	}
	return t.noun
}

var (
	keyTarget    = ruleTarget{"ssh-key", "key", config.ValidKeyName, "", ""}
	secretTarget = ruleTarget{"secret", "secret", config.ValidSecretName, "", ""}
	k8sTarget    = ruleTarget{"k8s", "context", config.ValidK8sContextName,
		"k8s rules take no --to: the program that runs the plugin (kubectl, helm …) receives the credential", ""}
	awsTarget = ruleTarget{"aws", "entry", config.ValidAWSName,
		"aws rules take no --to: the program that runs credential_process receives the credential", "aws"}
)

// ruleEdit is `nazar ssh-key rule add|set|remove`, `nazar secret rule
// add|set|remove`, `nazar k8s rule add|set|remove` and `nazar aws rule
// add|set|remove`.
func (a *app) ruleEdit(t ruleTarget, args []string) int {
	if len(args) == 0 {
		return a.usageError("%s rule needs a subcommand: add, set, remove", t.cmd)
	}
	sub, args := args[0], args[1:]
	cmd := t.cmd + " rule " + sub
	fs := a.flags(cmd)
	var apps, to refsFlag
	var noTo boolFlag
	var at, ifHash onceFlag
	var pol policyFlags
	fs.Var(&ifHash, "if-hash", "")
	allowLoosen := fs.Bool("allow-loosen-access", false, "") // =false is not given
	switch sub {
	case "add", "set":
		fs.Var(&apps, "apps", "")
		fs.Var(&to, "to", "")
		fs.Var(&pol.scope, "scope", "")
		fs.Var(&pol.gate, "gate", "")
		fs.Var(&pol.expire, "expire", "")
		fs.Var(&pol.noExpire, "no-expire", "")
		if sub == "add" {
			fs.Var(&at, "at", "")
		}
		if sub == "set" || t.noTo != "" { // for k8s and aws, registered to be refused with the reason
			fs.Var(&noTo, "no-to", "")
		}
	case "remove":
	default:
		return a.usageError("unknown %s rule subcommand %q", t.cmd, sub)
	}
	want := 2
	if sub == "add" {
		want = 1
	}
	pos, err := a.parse(fs, args, want)
	if err != nil {
		return a.fail(err)
	}
	name := pos[0]
	if !t.valid(name) {
		return a.usageError("%s: invalid %s name %q", cmd, t.noun, name)
	}
	if t.noTo != "" && (to.set || noTo.set) {
		return a.usageError("%s: %s", cmd, t.noTo)
	}
	m := map[string]string{t.editArg(): name}
	if ifHash.set {
		m["ifHash"] = ifHash.value
	}
	if *allowLoosen {
		m["allowLoosen"] = "true"
	}
	switch sub {
	case "add":
		m["op"] = control.EditRuleAdd
		if len(apps.refs) == 0 || !pol.gate.set {
			return a.usageError("%s: --apps and --gate are required", cmd)
		}
		if pol.noExpire.set {
			return a.usageError("%s: --no-expire is for rule set", cmd)
		}
		if at.set {
			if m["at"], err = ruleIndex(cmd, "--at", at.value); err != nil {
				return a.fail(err)
			}
		}
	case "set":
		m["op"] = control.EditRuleSet
		if m["index"], err = ruleIndex(cmd, "the rule number", pos[1]); err != nil {
			return a.fail(err)
		}
		if !apps.set && !to.set && !noTo.set && !pol.scope.set && !pol.gate.set && !pol.expire.set && !pol.noExpire.set {
			flags := "--apps, --to, --no-to, --scope, --gate, --expire, --no-expire"
			if t.noTo != "" {
				flags = "--apps, --scope, --gate, --expire, --no-expire"
			}
			return a.usageError("%s: give at least one of %s", cmd, flags)
		}
		if apps.set && len(apps.refs) == 0 {
			return a.usageError("%s: --apps needs at least one matcher", cmd)
		}
		if to.set && noTo.set {
			return a.usageError("%s: give --to or --no-to, not both", cmd)
		}
	case "remove":
		m["op"] = control.EditRuleRemove
		if m["index"], err = ruleIndex(cmd, "the rule number", pos[1]); err != nil {
			return a.fail(err)
		}
	}
	if apps.set {
		if m["apps"], err = refsArg(cmd, "apps", apps.refs); err != nil {
			return a.fail(err)
		}
	}
	if to.set {
		if m["to"], err = refsArg(cmd, "to", to.refs); err != nil {
			return a.fail(err)
		}
	}
	if noTo.set {
		m["to"] = ""
	}
	if err := pol.args(cmd, m, true); err != nil {
		return a.fail(err)
	}
	return a.configEdit(m, *allowLoosen)
}

// sshKeySet is `nazar ssh-key set <key>`: the key's own scope, gate and
// expire (what callers no rule matches get).
func (a *app) sshKeySet(args []string) int {
	cmd := "ssh-key set"
	fs := a.flags(cmd)
	var pol policyFlags
	var ifHash onceFlag
	fs.Var(&pol.scope, "scope", "")
	fs.Var(&pol.gate, "gate", "")
	fs.Var(&pol.expire, "expire", "")
	fs.Var(&pol.noExpire, "no-expire", "")
	fs.Var(&ifHash, "if-hash", "")
	allowLoosen := fs.Bool("allow-loosen-access", false, "") // =false is not given
	pos, err := a.parse(fs, args, 1)
	if err != nil {
		return a.fail(err)
	}
	if !config.ValidKeyName(pos[0]) {
		return a.usageError("%s: invalid key name %q", cmd, pos[0])
	}
	if !pol.scope.set && !pol.gate.set && !pol.expire.set && !pol.noExpire.set {
		return a.usageError("%s: give at least one of --scope, --gate, --expire, --no-expire", cmd)
	}
	m := map[string]string{"op": control.EditKeySet, "key": pos[0]}
	if ifHash.set {
		m["ifHash"] = ifHash.value
	}
	if *allowLoosen {
		m["allowLoosen"] = "true"
	}
	if err := pol.args(cmd, m, false); err != nil {
		return a.fail(err)
	}
	return a.configEdit(m, *allowLoosen)
}

// allowLoosenFlag is the flag that lets an edit loosen access.
const allowLoosenFlag = "--allow-loosen-access"

// configEdit sends one edit and reports it: exit 0 when the change is in
// force (or there was none). nazar-agent refuses a loosening sent without
// --allow-loosen-access (allowLoosen) and says what it would loosen: the
// CLI prints that and the command to run (refusedLoosening, exit 2). With
// the flag, nazar-agent writes and stages it, and the CLI at once sends the
// config.apply bound to exactly that change (approveEdit), so a person, a
// script, an agent or the window approves in one step, with one Touch ID;
// --json gets the ConfigEdit, then the ConfigDiff or the Problem. A staged
// reply to an edit sent without the flag (nazar-agent did not refuse it) is
// never approved here: exit 4, and `nazar config apply` asks.
func (a *app) configEdit(m map[string]string, allowLoosen bool) int {
	var r control.ConfigEdit
	if err := a.call(control.CmdConfigEdit, m, control.KindConfigEdit, &r); err != nil {
		if p := control.AsProblem(err); p.Code == control.CodeUsage && p.Message == control.LoosensRefusal {
			return a.refusedLoosening(p)
		}
		return a.fail(err)
	}
	if r.Staged != nil && allowLoosen {
		if rc := a.emit(r, func() { a.printEdit(r) }); rc != control.ExitOK {
			return rc
		}
		return a.approveEdit(r.Staged.Hash)
	}
	if rc := a.emit(r, func() {
		a.printEdit(r)
		if r.Staged != nil {
			a.applyHint()
		}
	}); rc != control.ExitOK {
		return rc
	}
	if r.Staged != nil {
		return control.ExitStaged
	}
	return control.ExitOK
}

func (a *app) printEdit(r control.ConfigEdit) {
	for _, p := range r.Problems {
		fmt.Fprintf(a.stdout, "%s: %s: %s\n", term(p.Severity), term(p.Path), term(p.Message))
	}
	switch {
	case !r.Changed:
		fmt.Fprintln(a.stdout, "config.yaml already says that; nothing changed")
	case r.Staged != nil:
		fmt.Fprintf(a.stdout, "%s updated; the change loosens access, so it needs your approval:\n", term(r.Path))
		for _, c := range r.Staged.Changes {
			fmt.Fprintf(a.stdout, "  %s\n", term(c))
		}
		for _, l := range r.Staged.Loosening {
			fmt.Fprintf(a.stdout, "  loosens: %s\n", term(l))
		}
	default:
		fmt.Fprintf(a.stdout, "%s updated; the change is in force\n", term(r.Path))
	}
}

// applyHint is how a change left staged in config.yaml is approved later.
func (a *app) applyHint() {
	fmt.Fprintf(a.stdout, "run `nazar config apply` to approve it (%s)\n", a.approval())
}

// refusedLoosening reports nazar-agent's refusal of an edit sent without
// --allow-loosen-access: what the change is and what it loosens (the
// Problem's details, the lines the login prompt would show), then the
// command that makes it: this run's own command line with the flag, or,
// when that can't be written safely for a shell, just the flag to add.
// With --json the Problem is printed with that command as fix. Exit 2, as
// for any usage error, but without the usage text: the command is right,
// only the flag is missing.
func (a *app) refusedLoosening(p *control.Problem) int {
	fix := suggestedCommand(a.argv)
	if a.json {
		p.Fix = fix
		if err := json.NewEncoder(a.stdout).Encode(p); err != nil {
			return control.ExitError
		}
		return p.ExitCode()
	}
	fmt.Fprintf(a.stderr, "nazar: %s:\n", term(p.Message))
	for _, d := range p.Details {
		fmt.Fprintf(a.stderr, "  %s\n", term(d))
	}
	if fix == "" {
		fmt.Fprintf(a.stderr, "to make it, add %s to the command (%s)\n", allowLoosenFlag, a.traits().LoginGate)
	} else {
		fmt.Fprintf(a.stderr, "to make it, run (%s):\n  %s\n", a.traits().LoginGate, term(fix))
	}
	return p.ExitCode()
}

// suggestedCommand is argv (this run's command line after the program
// name) as a nazar command with --allow-loosen-access appended, for a
// person to paste into a shell: --json and --yes, a script's flags, are
// dropped. Each word is written bare when every shell reads it as itself
// (plainShellWord), else single-quoted (configstage.ShellWord). "" when no
// quoting is safe in every shell the person may paste into: a word with a
// character that doesn't print (the terminal would not show what runs), or
// `!`, which tcsh and csh expand even inside single quotes, or `\`, which
// fish unescapes inside them (`\\`, `\'`); the caller then says only which
// flag to add.
func suggestedCommand(argv []string) string {
	words := []string{"nazar"}
	for _, w := range argv {
		switch {
		case w == "--json" || w == "--yes" || w == "-y":
			continue
		case w == allowLoosenFlag || strings.HasPrefix(w, allowLoosenFlag+"="):
			continue // given as =false (or already there): once, at the end
		}
		if !utf8.ValidString(w) || strings.ContainsAny(w, `!\`) || strings.IndexFunc(w, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
			return ""
		}
		if plainShellWord(w) {
			words = append(words, w)
		} else {
			words = append(words, configstage.ShellWord(w))
		}
	}
	return strings.Join(append(words, allowLoosenFlag), " ")
}

// plainShellWord reports whether w reads as itself in bash, zsh, fish, tcsh
// and sh: letters, digits and . _ - / : , @ + = only (matcher references
// and flag values are made of these), and not starting with = (zsh's
// =command expansion).
func plainShellWord(w string) bool {
	if w == "" || w[0] == '=' {
		return false
	}
	for _, r := range w {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-/:,@+=", r)) {
			return false
		}
	}
	return true
}

// approveEdit is the config.apply the edit that staged hash sends at once
// (--allow-loosen-access): one command, one Touch ID, from any caller.
// nazar-agent receives the same request a `nazar config apply` of that
// change sends: the hash binding (nothing is asked when config.yaml no
// longer holds exactly this change), the gate, the throttle and the audit
// line. Exit 0 once the change is in force; 3 when the person denied it
// (config.yaml still holds the change, staged, as a denied `config apply`
// leaves it); 4 when the prompt could not be shown (another prompt open,
// the cooldown) and 5 when nazar-agent went away after the edit, both with
// `nazar config apply` as the way to ask again (the edit is in config.yaml,
// staged, either way). The hash comes from the agent's reply and is never
// printed: one that is not the content hash of a staged edit ("missing" is
// `config check`'s hash for no file; an edit always writes one) is refused
// here and never sent back.
func (a *app) approveEdit(hash string) int {
	if !validConfigHash(hash) || hash == "missing" {
		return a.fail(control.NewProblem(control.CodeError, "nazar-agent staged the change under an invalid hash; run `nazar config check`"))
	}
	if !a.json {
		fmt.Fprintf(a.stdout, "approve it with %s\n", a.approval())
	}
	var d control.ConfigDiff
	if err := a.call(control.CmdConfigApply, map[string]string{"hash": hash}, control.KindConfigDiff, &d); err != nil {
		rc := a.fail(err)
		if a.json {
			return rc
		}
		switch rc {
		case control.ExitRefused:
			fmt.Fprintln(a.stdout, "denied; config.yaml still holds the change: `nazar config apply` asks again, or undo it by editing the rule back")
		case control.ExitStaged, control.ExitUnavailable:
			a.applyHint()
		}
		return rc
	}
	return a.emit(d, func() {
		if d.Applied {
			fmt.Fprintln(a.stdout, "approved; the change is in force")
		} else {
			fmt.Fprintln(a.stdout, "the change is already in force")
		}
	})
}

// apps is `nazar apps list`.
func (a *app) apps(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		return a.usageError("apps needs a subcommand: list")
	}
	if _, err := a.parse(a.flags("apps list"), args[1:], 0); err != nil {
		return a.fail(err)
	}
	var l control.AppList
	if err := a.call(control.CmdAppsList, nil, control.KindAppList, &l); err != nil {
		return a.fail(err)
	}
	return a.emit(l, func() {
		if l.Staged {
			fmt.Fprintln(a.stdout, "config.yaml has a staged change: these apps apply once it is approved (`nazar config apply`)")
		}
		tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tMATCHER\tPINNED TEAM\tUSED BY")
		name := func(e control.AppEntry) string {
			if e.Name == "" {
				return "-" // written inline in a rule
			}
			return e.Name
		}
		for _, e := range l.Items {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", term(name(e)), term(matcherText(e.Matcher)), term(e.PinnedTeam), term(strings.Join(e.UsedBy, ", ")))
		}
		tw.Flush()
		for _, e := range l.Items {
			if e.Problem != "" {
				what := e.Name
				if what == "" {
					what = matcherText(e.Matcher)
				}
				fmt.Fprintf(a.stdout, "%s: %s\n", term(what), term(e.Problem))
				if e.Fix != "" {
					fmt.Fprintf(a.stdout, "  fix: %s\n", term(e.Fix))
				}
			}
		}
	})
}

// matcherText is a matcher in the form --apps takes, or its kind.
func matcherText(m control.MatcherInfo) string {
	switch m.Kind {
	case string(config.MatchApp):
		return "app:" + m.ID
	case string(config.MatchSigned):
		if m.ID != "" {
			return "signed:" + m.Team + ":" + m.ID
		}
		return "signed:" + m.Team
	case string(config.MatchPath):
		return "path:" + m.Path
	case string(config.MatchCommand):
		return "command:" + strings.Join(m.Command, " ")
	}
	return m.Kind
}

// UIOpened is `nazar ui`'s --json reply.
type UIOpened struct {
	control.TypeMeta
	App    string `json:"app"`
	Opened bool   `json:"opened"`
}

// uiInstallHint is what `nazar ui` says when Nazar UI.app isn't installed.
const uiInstallHint = "Nazar UI.app is not installed; it is optional (everything it does is a nazar command). Install it with: brew install --cask atas/tap/nazar-ui"

// errUINotInstalled: Launch Services knows no app with bundle id
// dev.nazar.ui.
var errUINotInstalled = errors.New("no app with bundle id " + uiBundleID)

// ui is `nazar ui`: it opens Nazar UI.app through Launch Services, by
// bundle id dev.nazar.ui (spec 6.1, Milestone 6), and nothing else: it
// talks to no agent and starts no other program. Nazar UI.app is an
// ordinary app the user may or may not have installed: when Launch
// Services knows none, exit 1 with how to install it.
func (a *app) ui(args []string) int {
	if a.linux {
		return a.fail(control.NewProblem(control.CodeError, "ui: %s", uiOnLinux))
	}
	if _, err := a.parse(a.flags("ui"), args, 0); err != nil {
		return a.fail(err)
	}
	if a.openUI == nil {
		return a.fail(control.NewProblem(control.CodeError, "ui: not available in this build"))
	}
	path, err := a.openUI(uiBundleID)
	if errors.Is(err, errUINotInstalled) {
		return a.fail(control.NewProblem(control.CodeError, "%s", uiInstallHint))
	}
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "opening Nazar UI.app: %v", err))
	}
	return a.emit(UIOpened{TypeMeta: control.Meta(control.KindUI), App: path, Opened: true}, func() {
		fmt.Fprintf(a.stdout, "opened %s\n", term(path))
	})
}
