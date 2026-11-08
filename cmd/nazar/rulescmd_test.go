package main

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform/fake"
)

// stubStagedHash is the hash the stub's staged edits carry: what the CLI
// sends back, unseen, as config.apply's hash.
var stubStagedHash = strings.Repeat("ab", 32)

// stubRefusal is nazar-agent's refusal of a loosening sent without
// --allow-loosen-access, as the stub gives it.
func stubRefusal() *control.Problem {
	p := control.NewProblem(control.CodeUsage, "%s", control.LoosensRefusal)
	p.Details = []string{"ssh:github: added rule 1: apps=[claude] to=[] gate=dialog", "loosens ssh:github: requests that got gate=block (fallback) can now get gate=dialog (rule 1)"}
	return p
}

// editReply answers config.edit as nazar-agent does for a loosening
// (rule.add and rule.set here): refused without allowLoosen, staged with
// it; applied otherwise; config.apply applied; the rules and apps commands
// with fixed objects.
func editReply(req control.Request, out control.Emitter) {
	switch req.Command {
	case control.CmdConfigEdit:
		r := control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Op: req.Args["op"], Key: req.Args["key"],
			Path: "/x/config.yaml", Changed: true, Problems: []control.ConfigProblem{}}
		if req.Args["op"] == control.EditRuleAdd || req.Args["op"] == control.EditRuleSet {
			if req.Args["allowLoosen"] != "true" {
				out.Emit(stubRefusal())
				return
			}
			r.Staged = &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: stubStagedHash, Loosens: true, Changes: []string{"ssh:github: rule added"}}
		} else {
			r.Applied = true
		}
		out.Emit(r)
	case control.CmdConfigApply:
		out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: req.Args["hash"], Applied: true, Changes: []string{"ssh:github: rule added"}})
	case control.CmdSSHKeyRules:
		out.Emit(control.SSHKeyRules{TypeMeta: control.Meta(control.KindSSHKeyRules), Name: req.Args["name"], Configured: true,
			Rules: []control.RuleInfo{{Index: 1, Apps: []control.MatcherInfo{{Name: "claude", Kind: "signed", Ref: "claude"}}, To: []control.MatcherInfo{},
				Policy: control.PolicyInfo{Scope: "session", Gate: "dialog"}}},
			Fallback: control.PolicyInfo{Scope: "use", Gate: "block"}, FallbackSource: "defaults.fallback"})
	case control.CmdAppsList:
		out.Emit(control.AppList{TypeMeta: control.Meta(control.KindAppList), Items: []control.AppEntry{
			{Name: "mytool", Matcher: control.MatcherInfo{Name: "mytool", Kind: "path", Path: "/opt/homebrew/opt/mytool/bin/mytool", Ref: "mytool"},
				UsedBy: []string{"github rule 2"}}}})
	default:
		replyFor(req, out)
	}
}

// Each command line becomes one config.edit request with these args (apps
// and to as JSON lists; allowLoosen "true" only for --allow-loosen-access),
// and the exit code says applied (0), refused because it loosens and the
// flag was not given (2: one Problem, nothing else sent), or, with the
// flag, approved through the config.apply the CLI sends next (0: the
// ConfigEdit, then the ConfigDiff).
func TestRuleCommandsMapToConfigEdit(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { editReply(req, out) })
	cases := []struct {
		args  []string
		want  map[string]string
		exit  int
		kinds []string // the objects on stdout
	}{
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog", "--scope", "session"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["claude"]`, "gate": "dialog", "scope": "session"}, control.ExitUsage, []string{control.KindProblem}},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog", "--scope", "session", "--allow-loosen-access"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["claude"]`, "gate": "dialog", "scope": "session", "allowLoosen": "true"}, control.ExitOK, []string{control.KindConfigEdit, control.KindConfigDiff}},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "iterm,cursor", "--apps", "app:com.x", "--to", "signed:apple", "--gate", "login", "--expire", "8h", "--at", "2", "--if-hash", "abc"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["iterm","cursor","app:com.x"]`, "to": `["signed:apple"]`, "gate": "login", "expire": "8h", "at": "2", "ifHash": "abc"}, control.ExitUsage, []string{control.KindProblem}},
		{[]string{"ssh-key", "rule", "add", "github", "--apps=signed:Q6L2SF6YDW:com.anthropic.claude-code", "--gate=none", "--allow-loosen-access"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["signed:Q6L2SF6YDW:com.anthropic.claude-code"]`, "gate": "none", "allowLoosen": "true"}, control.ExitOK, []string{control.KindConfigEdit, control.KindConfigDiff}},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "path:/opt/homebrew/opt/mytool/bin/mytool", "--to", "path:/usr/local/bin/ssh", "--gate", "none", "--allow-loosen-access"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["path:/opt/homebrew/opt/mytool/bin/mytool"]`, "to": `["path:/usr/local/bin/ssh"]`, "gate": "none", "allowLoosen": "true"}, control.ExitOK, []string{control.KindConfigEdit, control.KindConfigDiff}},
		{[]string{"ssh-key", "rule", "set", "github", "2", "--gate", "login", "--no-expire", "--no-to"},
			map[string]string{"op": "rule.set", "key": "github", "index": "2", "gate": "login", "expire": "", "to": ""}, control.ExitUsage, []string{control.KindProblem}},
		{[]string{"ssh-key", "rule", "set", "github", "1", "--allow-loosen-access", "--apps", "app:com.googlecode.iterm2"},
			map[string]string{"op": "rule.set", "key": "github", "index": "1", "apps": `["app:com.googlecode.iterm2"]`, "allowLoosen": "true"}, control.ExitOK, []string{control.KindConfigEdit, control.KindConfigDiff}},
		{[]string{"ssh-key", "rule", "remove", "github", "1", "--if-hash", "h1"},
			map[string]string{"op": "rule.remove", "key": "github", "index": "1", "ifHash": "h1"}, control.ExitOK, []string{control.KindConfigEdit}},
		{[]string{"ssh-key", "rule", "remove", "github", "1", "--allow-loosen-access"}, // harmless on a tightening
			map[string]string{"op": "rule.remove", "key": "github", "index": "1", "allowLoosen": "true"}, control.ExitOK, []string{control.KindConfigEdit}},
		{[]string{"ssh-key", "set", "hydra", "--gate", "block"},
			map[string]string{"op": "key.set", "key": "hydra", "gate": "block"}, control.ExitOK, []string{control.KindConfigEdit}},
		{[]string{"ssh-key", "set", "hydra", "--scope", "session", "--expire", "7d", "--allow-loosen-access"},
			map[string]string{"op": "key.set", "key": "hydra", "scope": "session", "expire": "7d", "allowLoosen": "true"}, control.ExitOK, []string{control.KindConfigEdit}},
	}
	for _, c := range cases {
		before := len(h.requests())
		if code := h.run(append([]string{"--json"}, c.args...)...); code != c.exit {
			t.Fatalf("%v: exit %d, want %d (%s %s)", c.args, code, c.exit, h.out, h.errb)
		}
		reqs := h.requests()[before:]
		if len(reqs) == 0 || reqs[0].Command != control.CmdConfigEdit || !reflect.DeepEqual(reqs[0].Args, c.want) {
			t.Fatalf("%v: request %+v, want %v", c.args, reqs, c.want)
		}
		if len(c.kinds) == 2 { // approved: the config.apply bound to the staged change, and nothing else
			if len(reqs) != 2 || reqs[1].Command != control.CmdConfigApply || reqs[1].Args["hash"] != stubStagedHash {
				t.Fatalf("%v: requests %+v, want config.edit then config.apply with the staged hash", c.args, reqs)
			}
		} else if len(reqs) != 1 {
			t.Fatalf("%v: %d requests, want 1: %+v", c.args, len(reqs), reqs)
		}
		objs := jsonLines(t, h.out.String())
		var kinds []string
		for _, o := range objs {
			kinds = append(kinds, o["kind"].(string))
		}
		if !reflect.DeepEqual(kinds, c.kinds) {
			t.Fatalf("%v: stdout kinds %v, want %v: %s", c.args, kinds, c.kinds, h.out)
		}
	}
}

// Refused because it loosens access (nazar-agent's answer to an edit
// without --allow-loosen-access): the person reads what the change is and
// what it loosens, then the command to run, which is their own command line
// with the flag; a script gets the Problem with that command as fix. Exit
// 2, no usage text (the command is right), nothing else sent.
func TestRefusedLooseningPrintsTheCommandToRun(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { editReply(req, out) })
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog"); code != control.ExitUsage {
		t.Fatalf("exit %d, want 2\n%s%s", code, h.out, h.errb)
	}
	want := "nazar: this change loosens access; nothing was changed:\n" +
		"  ssh:github: added rule 1: apps=[claude] to=[] gate=dialog\n" +
		"  loosens ssh:github: requests that got gate=block (fallback) can now get gate=dialog (rule 1)\n" +
		"to make it, run (Touch ID):\n" +
		"  nazar ssh-key rule add github --apps claude --gate dialog --allow-loosen-access\n"
	if h.errb.String() != want || h.out.Len() != 0 {
		t.Fatalf("stderr:\n%s\nwant:\n%s\nstdout: %q", h.errb, want, h.out)
	}
	if r := h.requests(); len(r) != 1 {
		t.Fatalf("a refused edit must send nothing else: %+v", r)
	}
	// --json: the Problem, with the command as fix and without --json in it;
	// global flags anywhere are dropped, the rest kept in order.
	if code := h.run("ssh-key", "rule", "add", "--json", "github", "--apps", "claude", "--yes", "--gate", "dialog"); code != control.ExitUsage {
		t.Fatalf("--json: exit %d, want 2", code)
	}
	objs := jsonLines(t, h.out.String())
	if len(objs) != 1 || objs[0]["kind"] != control.KindProblem || objs[0]["code"] != control.CodeUsage || objs[0]["message"] != control.LoosensRefusal {
		t.Fatalf("--json stdout %s", h.out)
	}
	if fix := objs[0]["fix"]; fix != "nazar ssh-key rule add github --apps claude --gate dialog --allow-loosen-access" {
		t.Fatalf("fix %q", fix)
	}
	if d, _ := objs[0]["details"].([]any); len(d) != 2 {
		t.Fatalf("details %v", objs[0]["details"])
	}
	if h.errb.Len() != 0 {
		t.Fatalf("--json: stderr %q", h.errb)
	}
	// A word no shell reads safely (here: a matcher with a `!`): the lines,
	// then only which flag to add; the JSON has no fix.
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "app:com.x!y", "--gate", "dialog"); code != control.ExitUsage {
		t.Fatalf("exit %d, want 2", code)
	}
	if s := h.errb.String(); !strings.Contains(s, "to make it, add --allow-loosen-access to the command (Touch ID)") || strings.Contains(s, "nazar ssh-key rule add") {
		t.Fatalf("stderr %q", s)
	}
	if code := h.run("--json", "ssh-key", "rule", "add", "github", "--apps", "app:com.x!y", "--gate", "dialog"); code != control.ExitUsage {
		t.Fatalf("exit %d, want 2", code)
	}
	if _, ok := jsonLines(t, h.out.String())[0]["fix"]; ok {
		t.Fatalf("an unquotable command must not be suggested: %s", h.out)
	}
}

// The suggested command is the caller's own words, quoted for a shell:
// plain words bare, anything else single-quoted (a quote closed, escaped
// and reopened), never --json/--yes, the flag once at the end; none at all
// when a word has a `!` or a character that doesn't print.
func TestSuggestedCommandQuoting(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"k8s", "rule", "add", "mycluster-nazar", "--apps", "signed:Q6L2SF6YDW:com.anthropic.claude-code", "--gate", "none"},
			"nazar k8s rule add mycluster-nazar --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate none --allow-loosen-access"},
		{[]string{"--json", "ssh-key", "rule", "add", "github", "--apps=app:com.googlecode.iterm2,iterm", "--gate", "dialog", "--expire", "8h", "--at", "1", "-y"},
			"nazar ssh-key rule add github --apps=app:com.googlecode.iterm2,iterm --gate dialog --expire 8h --at 1 --allow-loosen-access"},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "app:my tools.x", "--gate", "none"},
			"nazar ssh-key rule add github --apps 'app:my tools.x' --gate none --allow-loosen-access"},
		{[]string{"ssh-key", "set", "github", "--gate", "dialog", "--allow-loosen-access"}, // already there: not repeated
			"nazar ssh-key set github --gate dialog --allow-loosen-access"},
		{[]string{"secret", "rule", "add", "GH_TOKEN", "--apps", "$(evil)", "--to", "`x`", "--gate", "none"},
			"nazar secret rule add GH_TOKEN --apps '$(evil)' --to '`x`' --gate none --allow-loosen-access"},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "app:o'k", "--gate", "none"},
			`nazar ssh-key rule add github --apps 'app:o'\''k' --gate none --allow-loosen-access`},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "=x", "--gate", "none"}, // zsh's =command at the start of a word
			"nazar ssh-key rule add github --apps '=x' --gate none --allow-loosen-access"},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "~/x", "--gate", "none"},
			"nazar ssh-key rule add github --apps '~/x' --gate none --allow-loosen-access"},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "a*b", "--to", "", "--gate", "none"},
			"nazar ssh-key rule add github --apps 'a*b' --to '' --gate none --allow-loosen-access"},
	} {
		if got := suggestedCommand(c.argv); got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.argv, got, c.want)
		}
	}
	for _, bad := range [][]string{
		{"ssh-key", "rule", "add", "github", "--apps", "app:x!y", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:x\ny", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:x\x1b[0my", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:x\u202ey", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:x\xffy", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", `app:x\\y`, "--gate", "none"}, // fish unescapes \\ and \' inside single quotes
	} {
		if got := suggestedCommand(bad); got != "" {
			t.Errorf("%q: suggested %q, want nothing", bad, got)
		}
	}
}

// Usage errors are decided locally and send nothing.
func TestRuleCommandUsageErrors(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { editReply(req, out) })
	for _, args := range [][]string{
		{"ssh-key", "rule"},
		{"ssh-key", "rule", "move", "github", "1"},
		{"ssh-key", "rule", "add", "github", "--gate", "login"},                     // no --apps
		{"ssh-key", "rule", "add", "github", "--apps", "claude"},                    // no --gate
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "maybe"}, // bad gate
		{"ssh-key", "rule", "add", "github", "--apps", "x: y", "--gate", "login"},   // not a matcher
		{"ssh-key", "rule", "add", "github", "--apps", "path:rel", "--gate", "login"},
		{"ssh-key", "rule", "add", "github", "--apps", "path:/opt/a/../b", "--gate", "login"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--to", "path:usr/bin/ssh", "--gate", "login"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "login", "--at", "0"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "login", "--expire", "soon"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "login", "--no-expire"},
		{"ssh-key", "rule", "add", "../x", "--apps", "claude", "--gate", "login"},
		{"ssh-key", "rule", "set", "github", "1"},                                  // nothing to change
		{"ssh-key", "rule", "set", "github", "x", "--gate", "login"},               // bad index
		{"ssh-key", "rule", "set", "github", "1", "--to", "iterm", "--no-to"},      // both
		{"ssh-key", "rule", "set", "github", "1", "--expire", "1h", "--no-expire"}, // both
		{"ssh-key", "rule", "set", "github", "1", "--apps", ""},                    // empty apps
		{"ssh-key", "rule", "remove", "github"},                                    // no index
		{"ssh-key", "rule", "remove", "github", "-1"},
		{"ssh-key", "set", "hydra"},                   // nothing to change
		{"ssh-key", "set", "hydra", "--gate", "none"}, // a key's own gate can't be none
		{"ssh-key", "set", "hydra", "--scope", "tab"}, // bad scope
		{"ssh-key", "rules"},        // no name
		{"ssh-key", "rules", "a/b"}, // bad name
		{"apps"},                    // no subcommand
		{"apps", "list", "x"},       // extra argument
		{"ui", "now"},               // extra argument
	} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, h.errb)
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("usage errors reached Nazar.app: %+v", r)
	}
}

func TestRulesAndAppsHumanOutput(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { editReply(req, out) })
	if code := h.run("ssh-key", "rules", "github"); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"claude", "session", "dialog", "others", "defaults.fallback"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("rules output lacks %q:\n%s", want, h.out)
		}
	}
	if code := h.run("apps", "list"); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"mytool", "path:/opt/homebrew/opt/mytool/bin/mytool", "github rule 2"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("apps output lacks %q:\n%s", want, h.out)
		}
	}
	if strings.Contains(h.out.String(), "nazar trust") || strings.Contains(h.out.String(), "gone") {
		t.Errorf("a path: entry has nothing to fix:\n%s", h.out)
	}
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog"); code != control.ExitUsage {
		t.Fatal(code)
	}
	if !strings.Contains(h.errb.String(), "nazar ssh-key rule add github --apps claude --gate dialog --allow-loosen-access") {
		t.Fatalf("a refused loosening must say how to make it:\n%s", h.errb)
	}
}

// Reply fields are config-derived: the human views escape them.
func TestRuleViewsEscapeHostileReplies(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		switch req.Command {
		case control.CmdSSHKeyRules:
			out.Emit(control.SSHKeyRules{TypeMeta: control.Meta(control.KindSSHKeyRules), Name: hostile, Configured: true,
				Rules:    []control.RuleInfo{{Index: 1, Apps: []control.MatcherInfo{{Kind: "app", Ref: hostile}}, Policy: control.PolicyInfo{Gate: hostile}}},
				Fallback: control.PolicyInfo{Gate: hostile}, FallbackSource: hostile})
		case control.CmdAppsList:
			out.Emit(control.AppList{TypeMeta: control.Meta(control.KindAppList), Items: []control.AppEntry{{Name: hostile,
				Matcher: control.MatcherInfo{Kind: "app", ID: hostile}, PinnedTeam: hostile, UsedBy: []string{hostile}, Problem: hostile, Fix: hostile}}})
		case control.CmdConfigEdit:
			out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Path: hostile, Changed: true,
				Staged: &control.ConfigDiff{Changes: []string{hostile}, Loosening: []string{hostile}}, Problems: []control.ConfigProblem{{Severity: hostile, Path: hostile, Message: hostile}}})
		}
	})
	h.run("ssh-key", "rules", "github")
	assertEscaped(t, "ssh-key rules", h, false)
	h.run("apps", "list")
	assertEscaped(t, "apps list", h, false)
	h.run("ssh-key", "rule", "remove", "github", "1")
	assertEscaped(t, "ssh-key rule remove", h, false)
}

// End to end against the real daemon (fake platform): list, a loosening
// rule refused without --allow-loosen-access (shown, nothing written, no
// prompt) and made with it (one Touch ID, in force), a tightening.
func TestRuleCommandsAgainstDaemon(t *testing.T) {
	h := newHarness(t)
	f, _ := startDaemon(t, h)
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	cfg := layout.ConfigFile(h.home)
	if code := h.run("ssh-key", "create", "github"); code != 0 {
		t.Fatalf("create: %d %s", code, h.errb)
	}
	if code := h.run("--json", "ssh-key", "rules", "github"); code != 0 {
		t.Fatalf("rules: %d %s", code, h.errb)
	}
	r := jsonLines(t, h.out.String())[0]
	hash, _ := r["configHash"].(string)
	if r["fallbackSource"] != "key-gate" || hash == "" {
		t.Fatalf("rules %v", r)
	}
	logins := f.CountShown(fake.KindAuthenticate)
	before, _ := os.ReadFile(cfg)
	// gate none for iTerm2 (block before, from the key's own gate) loosens.
	// The daemon's peer here is the tab's shell itself: no session lies
	// between the app and the caller, so create wrote no rule.
	add := []string{"ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none", "--if-hash", hash}
	if code := h.run(add...); code != control.ExitUsage {
		t.Fatalf("rule add without the flag: exit %d, want 2\n%s%s", code, h.out, h.errb)
	}
	for _, want := range []string{"this change loosens access; nothing was changed:", "added rule 1", "loosens ssh:github: ",
		"to make it, run (Touch ID):\n  nazar " + strings.Join(add, " ") + " --allow-loosen-access\n"} {
		if !strings.Contains(h.errb.String(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, h.errb)
		}
	}
	if after, _ := os.ReadFile(cfg); string(after) != string(before) {
		t.Fatal("a refused edit wrote config.yaml")
	}
	if f.CountShown(fake.KindAuthenticate) != logins {
		t.Fatal("a refused edit must not prompt")
	}
	if code := h.run(append(add, "--allow-loosen-access")...); code != 0 {
		t.Fatalf("rule add with the flag: exit %d\n%s%s", code, h.out, h.errb)
	}
	if f.CountShown(fake.KindAuthenticate) != logins+1 {
		t.Fatalf("%d prompts for one edit, want 1", f.CountShown(fake.KindAuthenticate)-logins)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "com.googlecode.iterm2") {
		t.Fatalf("config.yaml:\n%s", b)
	}
	if code := h.run("ssh-key", "rule", "remove", "github", "1", "--if-hash", hash); code != control.ExitError {
		t.Fatalf("a stale --if-hash must be refused: exit %d", code)
	}
	if code := h.run("config", "apply"); code != 0 || !strings.Contains(h.out.String(), "nothing is staged") {
		t.Fatalf("config apply with nothing staged: %d %s %s", code, h.out, h.errb)
	}
	if code := h.run("ssh-key", "rule", "remove", "github", "1"); code != 0 {
		t.Fatalf("rule remove (a tightening): exit %d %s", code, h.errb)
	}
	if code := h.run("--json", "ssh-key", "rules", "github"); code != 0 {
		t.Fatal(code)
	}
	if rules, _ := jsonLines(t, h.out.String())[0]["rules"].([]any); len(rules) != 0 {
		t.Fatalf("rules after remove: %v", rules)
	}
	if code := h.run("--json", "apps", "list"); code != 0 {
		t.Fatal(code)
	}
}

// --- Additional cases (test author) ---

// The usage text lists every new command.
func TestUsageListsRuleCommands(t *testing.T) {
	h := newHarness(t)
	if code := h.run("help"); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"ssh-key rules <name>", "ssh-key rule add", "ssh-key rule set", "ssh-key rule remove",
		"ssh-key set", "--if-hash", "apps list", "\n  ui"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, h.out)
		}
	}
}

// --apps / --to split at commas, path: or not (a path with a comma is
// written in config.yaml); "given empty" is told apart from "not given".
func TestRefsFlagSplitting(t *testing.T) {
	cases := []struct {
		values []string
		want   []string
	}{
		{[]string{"claude"}, []string{"claude"}},
		{[]string{"a,b", "c"}, []string{"a", "b", "c"}},
		{[]string{"path:/opt/a,b/c"}, []string{"path:/opt/a", "b/c"}},
		{[]string{"signed:Q6L2SF6YDW:com.anthropic.claude-code,app:com.x"}, []string{"signed:Q6L2SF6YDW:com.anthropic.claude-code", "app:com.x"}},
	}
	for _, c := range cases {
		var f refsFlag
		for _, v := range c.values {
			if err := f.Set(v); err != nil {
				t.Fatalf("%v: %v", c.values, err)
			}
		}
		if !f.set || !reflect.DeepEqual(f.refs, c.want) {
			t.Errorf("%v: refs %q set %v, want %q", c.values, f.refs, f.set, c.want)
		}
	}
	var empty refsFlag
	if err := empty.Set(""); err != nil || !empty.set || len(empty.refs) != 0 {
		t.Fatalf("empty value: %+v %v", empty, err)
	}
	var unset refsFlag
	if unset.set {
		t.Fatal("an unset flag must say so")
	}
}

// The local checks behind the edit commands.
func TestRuleIndexAndRefsArg(t *testing.T) {
	for _, v := range []string{"1", "2", "17", "007"} {
		if s, err := ruleIndex("c", "n", v); err != nil || s == "" || s[0] == '0' {
			t.Errorf("ruleIndex(%q) = %q, %v", v, s, err)
		}
	}
	for _, v := range []string{"", "0", "-1", "x", "1.5", " 1", "1e3", "+"} {
		if _, err := ruleIndex("c", "n", v); err == nil || control.AsProblem(err).ExitCode() != control.ExitUsage {
			t.Errorf("ruleIndex(%q) accepted or not a usage error: %v", v, err)
		}
	}
	if s, err := refsArg("c", "apps", []string{"claude", "app:com.x"}); err != nil || s != `["claude","app:com.x"]` {
		t.Fatalf("refsArg = %q, %v", s, err)
	}
	if s, err := refsArg("c", "to", nil); err != nil || s != `[]` {
		t.Fatalf("refsArg(nil) = %q, %v (a JSON list, never null)", s, err)
	}
	for _, bad := range []string{"claude\nkeys:", "app:", "signed:", "signed:TEAM:", "path:rel", "path:/a/../b", "path:/a/", "nope:x", "a\x7fb", "x: y"} {
		if _, err := refsArg("c", "apps", []string{"claude", bad}); err == nil || control.AsProblem(err).ExitCode() != control.ExitUsage {
			t.Errorf("refsArg accepted %q: %v", bad, err)
		}
	}
}

// Hostile or malformed input is refused locally: nothing reaches Nazar.app,
// and the usage error escapes what it echoes.
func TestRuleCommandAttackInputsSendNothing(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { editReply(req, out) })
	for _, args := range [][]string{
		// a newline or control character in a matcher could end a YAML line
		{"ssh-key", "rule", "add", "github", "--apps", "claude\n- any", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:com.x\x1b[2K", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--to", "signed:apple\r", "--gate", "none"},
		// a trailing colon would widen signed:<team>:<id> to the whole team
		{"ssh-key", "rule", "add", "github", "--apps", "signed:Q6L2SF6YDW:", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "path:/opt/../etc/x", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "none", "--gate", "block"}, // repeated
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "none", "--if-hash", "a", "--if-hash", "b"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate="},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "login", "--scope="},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "login", "--at", "-1"},
		{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "login", "--no-to"}, // set only
		{"ssh-key", "rule", "add", "github", "extra", "--apps", "claude", "--gate", "login"},
		{"ssh-key", "rule", "add", "--apps", "claude", "--gate", "login"}, // no key
		{"ssh-key", "rule", "add", hostile, "--apps", "claude", "--gate", "login"},
		{"ssh-key", "rule", "set", "github", "1", "--at", "2"},              // add only
		{"ssh-key", "rule", "set", "github", "0", "--gate", "login"},        // rules count from 1
		{"ssh-key", "rule", "set", "github", "1", "2", "--gate", "login"},   // extra
		{"ssh-key", "rule", "set", "github", "1", "--apps", ","},            // empty refs
		{"ssh-key", "rule", "set", "github", "1", "--to", "x\x00y"},         // NUL
		{"ssh-key", "rule", "remove", "github", "1", "--gate", "login"},     // remove takes no policy
		{"ssh-key", "rule", "remove", "github", "1", "--apps", "claude"},    // nor matchers
		{"ssh-key", "rule", "remove", "github", "1", "2"},                   // extra
		{"ssh-key", "set", "hydra", "--apps", "claude", "--gate", "login"},  // set has no matchers
		{"ssh-key", "set", "hydra", "--expire", "1h", "--no-expire"},        // both
		{"ssh-key", "set", "hydra", "--gate", "login", "--expire", "never"}, // bad duration
		{"ssh-key", "set", "hydra", "extra", "--gate", "login"},
		{"ssh-key", "set", "../hydra", "--gate", "login"},
		{"ssh-key", "rules", "github", "extra"},
		{"ssh-key", "rules", hostile},
		{"apps", "remove"},
		{"apps", "list", "--all"},
		{"ui", "--app", "/Applications/Evil.app"}, // ui opens only the bundle the CLI runs from
	} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Errorf("%q: exit %d, want 2 (%s)", args, code, h.errb)
		}
		for _, r := range h.out.String() + h.errb.String() {
			if r != '\n' && !unicode.IsPrint(r) {
				t.Errorf("%q: raw non-printing rune %U reached the output: %q", args, r, h.errb)
				break
			}
		}
	}
	if r := h.requests(); len(r) != 0 {
		t.Fatalf("refused input reached Nazar.app: %+v", r)
	}
	// --json: the usage error is one Problem object on stdout.
	if code := h.run("--json", "ssh-key", "rule", "add", "github", "--apps", "claude"); code != control.ExitUsage {
		t.Fatalf("exit %d", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindProblem {
		t.Fatalf("stdout %q", h.out)
	}
}

// More flag forms map to the right config.edit args.
func TestRuleCommandsMoreMappings(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) { editReply(req, out) })
	cases := []struct {
		args []string
		want map[string]string
		exit int
	}{
		{[]string{"ssh-key", "set", "hydra", "--no-expire", "--if-hash", "h2"},
			map[string]string{"op": "key.set", "key": "hydra", "expire": "", "ifHash": "h2"}, control.ExitOK},
		{[]string{"ssh-key", "set", "hydra", "--gate", "login", "--scope", "app", "--expire", "30m"},
			map[string]string{"op": "key.set", "key": "hydra", "gate": "login", "scope": "app", "expire": "30m"}, control.ExitOK},
		// (the stub refuses every rule.add and rule.set sent without the flag, as a loosening: exit 2)
		{[]string{"ssh-key", "rule", "set", "github", "3", "--to", "signed:apple,app:com.apple.Terminal", "--scope", "use"},
			map[string]string{"op": "rule.set", "key": "github", "index": "3", "to": `["signed:apple","app:com.apple.Terminal"]`, "scope": "use"}, control.ExitUsage},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "any", "--gate", "block", "--at", "1"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["any"]`, "gate": "block", "at": "1"}, control.ExitUsage},
		{[]string{"ssh-key", "rule", "add", "github", "--apps", "unknown", "--gate", "login", "--scope", "use", "--expire", "1h"},
			map[string]string{"op": "rule.add", "key": "github", "apps": `["unknown"]`, "gate": "login", "scope": "use", "expire": "1h"}, control.ExitUsage},
		// flags after the positional arguments, and the "--" terminator
		{[]string{"ssh-key", "rule", "remove", "--if-hash", "h3", "github", "2"},
			map[string]string{"op": "rule.remove", "key": "github", "index": "2", "ifHash": "h3"}, control.ExitOK},
		{[]string{"ssh-key", "rule", "remove", "github", "--", "2"},
			map[string]string{"op": "rule.remove", "key": "github", "index": "2"}, control.ExitOK},
	}
	for i, c := range cases {
		if code := h.run(append([]string{"--json"}, c.args...)...); code != c.exit {
			t.Fatalf("%v: exit %d, want %d (%s %s)", c.args, code, c.exit, h.out, h.errb)
		}
		reqs := h.requests()
		if len(reqs) != i+1 || reqs[i].Command != control.CmdConfigEdit || !reflect.DeepEqual(reqs[i].Args, c.want) {
			t.Fatalf("%v: requests %+v, want one more with %v", c.args, reqs, c.want)
		}
	}
}

// The human view of an edit: in force, unchanged, staged (with what it
// loosens), and problems; a refused edit (stale --if-hash) is exit 1.
func TestEditHumanOutputAndRefusal(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var current any
	setReply := func(v any) { mu.Lock(); current = v; mu.Unlock() }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		mu.Lock()
		v := current
		mu.Unlock()
		out.Emit(v)
	})
	base := control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Path: "/x/config.yaml", Problems: []control.ConfigProblem{}}

	applied := base
	applied.Changed, applied.Applied = true, true
	setReply(applied)
	if code := h.run("ssh-key", "rule", "remove", "github", "1"); code != control.ExitOK || !strings.Contains(h.out.String(), "in force") {
		t.Fatalf("applied: exit %d %q", code, h.out)
	}

	same := base
	setReply(same)
	if code := h.run("ssh-key", "set", "hydra", "--gate", "block"); code != control.ExitOK || !strings.Contains(h.out.String(), "nothing changed") {
		t.Fatalf("unchanged: exit %d %q", code, h.out)
	}

	staged := base
	staged.Changed = true
	staged.Staged = &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Loosens: true,
		Changes: []string{"ssh:github: rule 1 added"}, Loosening: []string{"ssh:github: iterm gate none"}}
	staged.Problems = []control.ConfigProblem{{Severity: "warning", Path: "apps.kubectl", Message: "not trusted yet"}}
	setReply(staged)
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "none"); code != control.ExitStaged {
		t.Fatalf("staged: exit %d", code)
	}
	for _, want := range []string{"rule 1 added", "loosens: ssh:github: iterm gate none", "nazar config apply", "warning", "apps.kubectl", "not trusted yet"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("staged view lacks %q:\n%s", want, h.out)
		}
	}
	// --json exits 4 too, with the reply as the only line.
	if code := h.run("--json", "ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "none"); code != control.ExitStaged {
		t.Fatalf("--json staged: exit %d", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["staged"] == nil {
		t.Fatalf("stdout %q", h.out)
	}

	setReply(control.NewProblem(control.CodeError, "config.yaml changed since it was read (--if-hash)"))
	if code := h.run("ssh-key", "rule", "remove", "github", "1", "--if-hash", "old"); code != control.ExitError || !strings.Contains(h.errb.String(), "changed since") {
		t.Fatalf("refused: exit %d %q", code, h.errb)
	}
}

// End to end: while config.yaml holds a staged change (here: an edit whose
// prompt was denied), an edit is refused with exit 1 (never 4, and never
// 2 with the loosening lines: the other change is not this edit's), says
// what to do, and writes nothing.
func TestEditRefusedWhileStagedEndToEnd(t *testing.T) {
	h := newHarness(t)
	f, _ := startDaemon(t, h)
	f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true}) // the login prompt is denied
	cfg := layout.ConfigFile(h.home)
	f.ScriptAuth(fake.Answer{Allow: true})
	if code := h.run("ssh-key", "create", "github"); code != 0 {
		t.Fatalf("create: %d %s", code, h.errb)
	}
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none", "--allow-loosen-access"); code != control.ExitRefused {
		t.Fatalf("rule add, denied: exit %d, want 3 %s %s", code, h.out, h.errb)
	}
	before, _ := os.ReadFile(cfg)
	logins := f.CountShown(fake.KindAuthenticate)
	for _, args := range [][]string{
		{"ssh-key", "rule", "remove", "github", "1"},
		{"ssh-key", "set", "github", "--gate", "block"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none"},
		{"ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none", "--allow-loosen-access"},
	} {
		code := h.run(args...)
		if code != control.ExitError {
			t.Fatalf("%v on a staged file: exit %d, want 1 (%s %s)", args, code, h.out, h.errb)
		}
		if !strings.Contains(h.errb.String(), "not approved yet") || !strings.Contains(h.errb.String(), "nazar config apply") {
			t.Fatalf("%v: stderr %q", args, h.errb)
		}
		if strings.Contains(h.out.String(), "loosens") {
			t.Fatalf("%v: a refused edit must not say it loosens access: %q", args, h.out)
		}
		after, _ := os.ReadFile(cfg)
		if string(after) != string(before) {
			t.Fatalf("%v wrote config.yaml", args)
		}
	}
	if f.CountShown(fake.KindAuthenticate) != logins {
		t.Fatal("a refused edit must not prompt")
	}
}

// `nazar config apply` first asks what is staged (status: a read that
// observes nothing, so no background prompt starts) and shows it, then
// sends the config.apply bound to that change's hash, which it never
// prints; with nothing staged it sends no hash. A staged hash that is not
// a content hash is refused in the CLI and never sent back. The old
// `--hash` flag is gone: a usage error that reaches Nazar.app not at all.
func TestConfigApplyShowsAndBindsTheStagedChange(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var staged *control.ConfigDiff
	setStaged := func(d *control.ConfigDiff) { mu.Lock(); staged = d; mu.Unlock() }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		mu.Lock()
		s := staged
		mu.Unlock()
		switch req.Command {
		case control.CmdStatus:
			out.Emit(control.Status{TypeMeta: control.Meta(control.KindStatus), Staged: s, Approvals: []control.Approval{}})
		case control.CmdConfigApply:
			out.Emit(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: req.Args["hash"], Applied: s != nil, Changes: []string{"ssh:github: added rule 1"}})
		default:
			replyFor(req, out)
		}
	})
	good := strings.Repeat("ab", 32)
	setStaged(&control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: good, Loosens: true,
		Changes: []string{"ssh:github: added rule 1: apps=[claude] to=[] gate=dialog"}, Loosening: []string{"ssh:github: requests that got gate=block can now get gate=dialog (rule 1)"}})
	if code := h.run("config", "apply"); code != 0 {
		t.Fatalf("exit %d %s %s", code, h.out, h.errb)
	}
	r := h.requests()
	if len(r) != 2 || r[0].Command != control.CmdStatus || r[1].Command != control.CmdConfigApply || r[1].Args["hash"] != good {
		t.Fatalf("requests %+v, want status then config.apply bound to %s", r, good)
	}
	out := h.out.String()
	shown, applied := strings.Index(out, "added rule 1: apps=[claude]"), strings.Index(out, "config change approved and applied")
	if shown < 0 || applied < 0 || shown > applied || !strings.Contains(out, "loosens: ssh:github: requests") || !strings.Contains(out, "waiting for your approval") {
		t.Fatalf("the staged change must be shown before the prompt:\n%s", out)
	}
	if strings.Contains(out, good) || strings.Contains(h.errb.String(), good) {
		t.Fatalf("a person never sees the hash:\n%s", out)
	}
	// --json: the ConfigDiff only (the check is the CLI's own read).
	if code := h.run("--json", "config", "apply"); code != 0 {
		t.Fatalf("--json: exit %d", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 1 || objs[0]["kind"] != control.KindConfigDiff || objs[0]["applied"] != true {
		t.Fatalf("--json stdout %s", h.out)
	}
	// Nothing staged: no hash, "nothing is staged".
	setStaged(nil)
	before := len(h.requests())
	if code := h.run("config", "apply"); code != 0 || !strings.Contains(h.out.String(), "nothing is staged") {
		t.Fatalf("nothing staged: exit %d %s", code, h.out)
	}
	if r := h.requests()[before:]; len(r) != 2 || r[1].Command != control.CmdConfigApply || r[1].Args != nil {
		t.Fatalf("nothing staged: requests %+v, want an apply without a hash", r)
	}
	// A hash that is not a content hash of a staged change (a hostile agent,
	// or "missing", which only a file that does not exist has): refused in the
	// CLI, nothing sent back, nothing non-printing on the terminal.
	for _, bad := range []string{hostile, "missing", good[:63], strings.ToUpper(good)} {
		setStaged(&control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: bad, Changes: []string{hostile}})
		before = len(h.requests())
		if code := h.run("config", "apply"); code != control.ExitError || !strings.Contains(h.errb.String(), "invalid hash") {
			t.Fatalf("hash %q: exit %d, want 1 (%s)", bad, code, h.errb)
		}
		if r := h.requests()[before:]; len(r) != 1 {
			t.Fatalf("hash %q must not be sent back: %+v", bad, r)
		}
		// The hash is never printed, and the hostile change lines were not
		// reached: nothing non-printing on the terminal.
		for _, r := range h.out.String() + h.errb.String() {
			if r != '\n' && !unicode.IsPrint(r) {
				t.Fatalf("hash %q: raw non-printing rune %U reached the output: stdout %q stderr %q", bad, r, h.out, h.errb)
			}
		}
	}
	before = len(h.requests())
	for _, args := range [][]string{
		{"config", "apply", "--hash", good},
		{"config", "apply", "--hash"},
		{"config", "apply", good},
		{"config", "check", "--hash", good},
	} {
		if code := h.run(args...); code != control.ExitUsage {
			t.Fatalf("%v: exit %d, want 2 (%s)", args, code, h.errb)
		}
	}
	if r := h.requests(); len(r) != before {
		t.Fatalf("usage errors reached Nazar.app: %+v", r[before:])
	}
}

// End to end: a change an edit left staged (its prompt denied) is what
// `nazar config apply` shows and approves: the change lines before the
// prompt, one prompt, exit 0, never a hash on the screen; asked again,
// nothing is staged and nothing is asked.
func TestConfigApplyShowsTheChangeAgainstDaemon(t *testing.T) {
	h := newHarness(t)
	f, _ := startDaemon(t, h)
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if code := h.run("ssh-key", "create", "github"); code != 0 {
		t.Fatalf("create: %d %s", code, h.errb)
	}
	f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none", "--allow-loosen-access"); code != control.ExitRefused {
		t.Fatalf("rule add, denied: exit %d, want 3\n%s%s", code, h.out, h.errb)
	}
	if !strings.Contains(h.errb.String(), "not approved") || !strings.Contains(h.out.String(), "config.yaml still holds the change: `nazar config apply` asks again") {
		t.Fatalf("denied: stdout %q stderr %q", h.out, h.errb)
	}
	if code := h.run("--json", "config", "check"); code != control.ExitStaged {
		t.Fatalf("the denied change must stay staged: config check exits %d", code)
	}
	f.Advance(daemon.ConfigApplyCooldown)
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	logins := f.CountShown(fake.KindAuthenticate)
	if code := h.run("config", "apply"); code != 0 {
		t.Fatalf("config apply: exit %d\n%s%s", code, h.out, h.errb)
	}
	out := h.out.String()
	shown, applied := strings.Index(out, "added rule 1"), strings.Index(out, "config change approved and applied")
	if shown < 0 || applied < 0 || shown > applied || !strings.Contains(out, "loosens: ssh:github") {
		t.Fatalf("config apply must show the change before asking:\n%s", out)
	}
	if hex64.MatchString(out) || hex64.MatchString(h.errb.String()) {
		t.Fatalf("a person never sees a hash:\n%s%s", out, h.errb)
	}
	if f.CountShown(fake.KindAuthenticate) != logins+1 {
		t.Fatalf("%d prompts; want exactly 1", f.CountShown(fake.KindAuthenticate)-logins)
	}
	if code := h.run("config", "check"); code != 0 {
		t.Fatalf("config check after the approval: exit %d %s", code, h.out)
	}
	if code := h.run("config", "apply"); code != 0 || !strings.Contains(h.out.String(), "nothing is staged") || f.CountShown(fake.KindAuthenticate) != logins+1 {
		t.Fatalf("config apply with nothing staged: exit %d %s (prompts %d)", code, h.out, f.CountShown(fake.KindAuthenticate)-logins)
	}
}

// hex64 matches a config content hash as nazar-agent writes them.
var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

// With --allow-loosen-access a loosening edit is approved in one step,
// from any caller: the CLI sends the edit, then the config.apply bound to
// exactly the change it staged, and the exit code is the apply's. The
// person is shown the diff and told the change is in force; a script gets
// the ConfigEdit, then the ConfigDiff or the Problem. Without the flag,
// nazar-agent refuses the edit and nothing else is sent (exit 2).
func TestEditWithTheFlagAppliesInOneStep(t *testing.T) {
	h := newHarness(t)
	var mu sync.Mutex
	var applyReply any = control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: stubStagedHash, Applied: true, Changes: []string{"ssh:github: rule added"}}
	setApply := func(v any) { mu.Lock(); applyReply = v; mu.Unlock() }
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		if req.Command != control.CmdConfigApply {
			editReply(req, out)
			return
		}
		mu.Lock()
		v := applyReply
		mu.Unlock()
		out.Emit(v)
	})
	add := []string{"ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog", "--allow-loosen-access"}

	if code := h.run(add...); code != control.ExitOK {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, h.out, h.errb)
	}
	reqs := h.requests()
	if len(reqs) != 2 || reqs[0].Command != control.CmdConfigEdit || reqs[0].Args["allowLoosen"] != "true" || reqs[1].Command != control.CmdConfigApply || reqs[1].Args["hash"] != stubStagedHash {
		t.Fatalf("requests %+v, want config.edit (allowLoosen) then config.apply with hash %s", reqs, stubStagedHash)
	}
	for _, want := range []string{"rule added", "approve it with Touch ID", "in force"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("view lacks %q:\n%s", want, h.out)
		}
	}
	if strings.Contains(h.out.String(), "config apply") || strings.Contains(h.out.String(), stubStagedHash) {
		t.Errorf("an approved edit must not tell the person to run config apply, or show a hash:\n%s", h.out)
	}

	// --json: the same two requests; the ConfigEdit, then the ConfigDiff.
	if code := h.run(append([]string{"--json"}, add...)...); code != control.ExitOK {
		t.Fatalf("--json: exit %d, want 0 (%s)", code, h.out)
	}
	if r := h.requests(); len(r) != 4 || r[2].Command != control.CmdConfigEdit || r[3].Command != control.CmdConfigApply {
		t.Fatalf("--json must send the edit then the apply: %+v", r[2:])
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 2 || objs[0]["kind"] != control.KindConfigEdit || objs[0]["staged"] == nil || objs[1]["kind"] != control.KindConfigDiff || objs[1]["applied"] != true {
		t.Fatalf("--json stdout %q", h.out)
	}

	// Without the flag nazar-agent refuses it: one request, exit 2.
	before := len(h.requests())
	if code := h.run(add[:len(add)-1]...); code != control.ExitUsage {
		t.Fatalf("without the flag: exit %d, want 2", code)
	}
	if r := h.requests(); len(r) != before+1 || r[before].Command != control.CmdConfigEdit {
		t.Fatalf("without the flag the edit alone is sent: %+v", r[before:])
	}

	// The prompt could not be shown (another prompt open, the cooldown):
	// exit 4, and the person is told `nazar config apply` asks again, with
	// no hash. Whatever the apply answers, it is asked exactly once per
	// edit: never a retry (AGENTS.md: never run config apply repeatedly).
	oneApply := func(what string) {
		t.Helper()
		r := h.requests()
		if len(r) < 2 || r[len(r)-2].Command != control.CmdConfigEdit || r[len(r)-1].Command != control.CmdConfigApply {
			t.Fatalf("%s: want one config.edit then one config.apply: %+v", what, r)
		}
	}
	setApply(control.NewProblem(control.CodeStaged, "an approval prompt is already open (the change stays staged)"))
	before = len(h.requests())
	if code := h.run(add...); code != control.ExitStaged {
		t.Fatalf("not asked: exit %d, want 4", code)
	}
	if !strings.Contains(h.errb.String(), "already open") || !strings.Contains(h.out.String(), "run `nazar config apply` to approve it") || hex64.MatchString(h.out.String()) {
		t.Fatalf("not asked: stdout %q stderr %q", h.out, h.errb)
	}
	if len(h.requests()) != before+2 {
		t.Fatalf("not asked: %d requests for one edit, want 2", len(h.requests())-before)
	}
	oneApply("not asked")
	// With --json: the ConfigEdit, then the Problem (code staged).
	if code := h.run(append([]string{"--json"}, add...)...); code != control.ExitStaged {
		t.Fatalf("--json not asked: exit %d, want 4", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 2 || objs[0]["kind"] != control.KindConfigEdit || objs[1]["kind"] != control.KindProblem || objs[1]["code"] != control.CodeStaged {
		t.Fatalf("--json not asked: stdout %q", h.out)
	}

	// nazar-agent went away after the edit (exit 5): the edit is in
	// config.yaml, staged, so the person is told how to ask again.
	setApply(control.NewProblem(control.CodeUnavailable, "nazar-agent isn't running"))
	before = len(h.requests())
	if code := h.run(add...); code != control.ExitUnavailable {
		t.Fatalf("agent gone: exit %d, want 5", code)
	}
	if !strings.Contains(h.out.String(), "run `nazar config apply` to approve it") || len(h.requests()) != before+2 {
		t.Fatalf("agent gone: stdout %q, %d requests", h.out, len(h.requests())-before)
	}

	// Denied: exit 3; config.yaml still holds the change, and the person is
	// told how to ask again or undo it, with no hash.
	setApply(control.NewProblem(control.CodeRefused, "the config change was not approved; it stays staged"))
	before = len(h.requests())
	if code := h.run(add...); code != control.ExitRefused || !strings.Contains(h.errb.String(), "not approved") {
		t.Fatalf("denied: exit %d, want 3 (%s)", code, h.errb)
	}
	if !strings.Contains(h.out.String(), "denied; config.yaml still holds the change: `nazar config apply` asks again, or undo it by editing the rule back") {
		t.Fatalf("denied: stdout %q", h.out)
	}
	if len(h.requests()) != before+2 {
		t.Fatalf("denied: %d requests for one edit, want 2", len(h.requests())-before)
	}
	oneApply("denied")
	if code := h.run(append([]string{"--json"}, add...)...); code != control.ExitRefused {
		t.Fatalf("--json denied: exit %d, want 3", code)
	}
	if objs := jsonLines(t, h.out.String()); len(objs) != 2 || objs[0]["kind"] != control.KindConfigEdit || objs[1]["kind"] != control.KindProblem || objs[1]["code"] != control.CodeRefused {
		t.Fatalf("--json denied: stdout %q", h.out)
	}

	// Already in force when the apply arrives (the agent answers "nothing
	// is staged" for an active hash): exit 0, in force.
	setApply(control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: stubStagedHash, Changes: []string{}})
	before = len(h.requests())
	if code := h.run(add...); code != control.ExitOK || !strings.Contains(h.out.String(), "in force") {
		t.Fatalf("already in force: exit %d %q", code, h.out)
	}
	if len(h.requests()) != before+2 {
		t.Fatalf("already in force: %d requests for one edit, want 2", len(h.requests())-before)
	}
	oneApply("already in force")

	// A tightening, with or without the flag: nothing to approve, one request.
	for _, args := range [][]string{{"ssh-key", "rule", "remove", "github", "1"}, {"ssh-key", "rule", "remove", "github", "1", "--allow-loosen-access"}} {
		before = len(h.requests())
		if code := h.run(args...); code != control.ExitOK {
			t.Fatalf("%v: exit %d", args, code)
		}
		if r := h.requests(); len(r) != before+1 || r[before].Command != control.CmdConfigEdit {
			t.Fatalf("a tightening must send the edit only: %+v", r[before:])
		}
	}
}

// The hash the one-step path sends comes from the agent's reply. One that
// is not the content hash of a staged edit is refused in the CLI (defence
// in depth: the peer is verified before the edit is sent): a hostile
// string, and "missing" (a content hash only `config check` reports, for no
// file; an edit always writes one). No apply is sent, exit 1, the person is
// told why, and nothing non-printing reaches the terminal (the diff,
// hostile too, is escaped).
func TestEditRefusesAHostileHash(t *testing.T) {
	for _, bad := range []string{hostile, "missing"} {
		h := newHarness(t)
		h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
			out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Path: "/x/config.yaml", Changed: true,
				Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: bad, Loosens: true, Changes: []string{hostile}}, Problems: []control.ConfigProblem{}})
		})
		if code := h.run("ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog", "--allow-loosen-access"); code != control.ExitError {
			t.Fatalf("hash %q: exit %d, want 1 (%s)", bad, code, h.errb)
		}
		if r := h.requests(); len(r) != 1 {
			t.Fatalf("hash %q must not be sent back: %+v", bad, r)
		}
		if !strings.Contains(h.errb.String(), "invalid hash") {
			t.Errorf("hash %q: stderr must say the staged hash is invalid: %q", bad, h.errb)
		}
		assertEscaped(t, "staged hash "+bad, h, false)
	}
}

// A staged reply to an edit sent without the flag (nazar-agent did not
// refuse it: an older agent) is never approved by the CLI on its own: exit
// 4, the diff, and `nazar config apply` as the way to approve it.
func TestStagedReplyWithoutTheFlagIsNotApproved(t *testing.T) {
	h := newHarness(t)
	h.serve(t, func(_ context.Context, req control.Request, out control.Emitter) {
		out.Emit(control.ConfigEdit{TypeMeta: control.Meta(control.KindConfigEdit), Path: "/x/config.yaml", Changed: true,
			Staged: &control.ConfigDiff{TypeMeta: control.Meta(control.KindConfigDiff), Hash: stubStagedHash, Loosens: true, Changes: []string{"ssh:github: rule added"}}, Problems: []control.ConfigProblem{}})
	})
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "claude", "--gate", "dialog"); code != control.ExitStaged {
		t.Fatalf("exit %d, want 4 (%s %s)", code, h.out, h.errb)
	}
	if r := h.requests(); len(r) != 1 {
		t.Fatalf("no apply may be sent without the flag: %+v", r)
	}
	if !strings.Contains(h.out.String(), "run `nazar config apply` to approve it") || strings.Contains(h.out.String(), stubStagedHash) {
		t.Fatalf("stdout %q", h.out)
	}
}

// End to end against the real daemon (fake platform): a loosening edit
// with --allow-loosen-access is one command and one Touch ID, from a
// caller with no terminal (the harness's stdout is a buffer). The change is
// in force when the command returns (exit 0), nothing is left staged, the
// prompt showed this edit's diff, and the audit log has the approval under
// the caller's chain, like a `config apply`. Denied, it is exit 3 and the
// change stays in config.yaml exactly as a denied `config apply` leaves it:
// `config check` shows it and, after the cooldown, `config apply` approves
// it. No hash is ever shown.
func TestEditWithTheFlagAgainstDaemon(t *testing.T) {
	h := newHarness(t)
	f, sink := startDaemon(t, h)
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if code := h.run("ssh-key", "create", "github"); code != 0 {
		t.Fatalf("create: %d %s", code, h.errb)
	}
	logins := f.CountShown(fake.KindAuthenticate)
	approved := configLines(sink, audit.Approved)
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "app:com.googlecode.iterm2", "--gate", "none", "--allow-loosen-access"); code != 0 {
		t.Fatalf("rule add: exit %d\nstdout %s\nstderr %s", code, h.out, h.errb)
	}
	if n := f.CountShown(fake.KindAuthenticate) - logins; n != 1 {
		t.Fatalf("%d login prompts for one edit, want exactly 1", n)
	}
	shown := f.Shown()
	if p := shown[len(shown)-1]; p.Kind != fake.KindAuthenticate || !strings.Contains(strings.Join(p.Prompt.Lines, "\n"), "added rule 1") {
		t.Fatalf("the prompt did not show the edit's diff: %+v", p.Prompt)
	}
	for _, want := range []string{"added rule 1", "in force"} {
		if !strings.Contains(h.out.String(), want) {
			t.Errorf("view lacks %q:\n%s", want, h.out)
		}
	}
	if strings.Contains(h.out.String(), "config apply") || hex64.MatchString(h.out.String()) {
		t.Errorf("an approved edit must not tell the person to run config apply, or show a hash:\n%s", h.out)
	}
	if code := h.run("config", "check"); code != 0 {
		t.Fatalf("after the edit, config check exits %d (still staged?)\n%s", code, h.out)
	}
	if n := configLines(sink, audit.Approved) - approved; n != 1 {
		t.Fatalf("%d approved config lines, want 1:\n%s", n, strings.Join(sink.Lines(), "\n"))
	}
	for _, l := range sink.Lines() {
		if fs, err := audit.ParseLine(l); err == nil && fs["target"] == "config" && fs["decision"] == string(audit.Approved) && fs["chain"] == "" && fs["session"] == "" {
			t.Fatalf("the approval must be audited with its caller: %s", l)
		}
	}

	// Denied: exit 3, staged, no hash to copy; `config apply` approves it
	// once the cooldown has passed.
	f.SetDefaults(fake.Answer{}, fake.Answer{Allow: true})
	// (gate none loosens: callers no rule matches are blocked.)
	if code := h.run("ssh-key", "rule", "add", "github", "--apps", "signed:Q6L2SF6YDW:com.anthropic.claude-code", "--gate", "none", "--allow-loosen-access"); code != control.ExitRefused {
		t.Fatalf("denied: exit %d, want 3\nstdout %s\nstderr %s", code, h.out, h.errb)
	}
	if !strings.Contains(h.errb.String(), "not approved") || hex64.MatchString(h.out.String()) || hex64.MatchString(h.errb.String()) {
		t.Fatalf("denied: stdout %q stderr %q", h.out, h.errb)
	}
	if code := h.run("--json", "config", "check"); code != control.ExitStaged {
		t.Fatalf("the denied change must stay staged: config check exits %d", code)
	}
	f.Advance(daemon.ConfigApplyCooldown)
	f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	if code := h.run("config", "apply"); code != 0 {
		t.Fatalf("config apply after the denial: exit %d %s", code, h.errb)
	}
	if code := h.run("config", "check"); code != 0 {
		t.Fatalf("config check after the approval: exit %d %s", code, h.out)
	}
}
