package config

import (
	"slices"
	"strings"
	"testing"
)

// Late-env, defaults.trustedPath, command: receivers for nazar run and
// envAllow (secrets design 4, 6.3.3, 6.3.4, 6.3.7; 6.3 D3–D6).

const braveEntry = `  BRAVE_API_KEY:
    deliver: [late-env]
    rules:
      - apps: [claude]
        to: [brave-mcp]
        scope: session
        gate: dialog
`

func lateHdr(apps string) string {
	return hdr + "apps:\n  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}\n  iterm: {app: com.googlecode.iterm2}\n" +
		"  brave-mcp: {command: [npx, -y, \"@brave/brave-search-mcp-server\"]}\n" + apps + "secrets:\n"
}

func TestLateEnvEntryParses(t *testing.T) {
	c, probs := mustParse(t, lateHdr("")+braveEntry)
	if len(probs) != 0 {
		t.Fatalf("the README's entry draws no problem:\n%s", probs.Error())
	}
	s := c.Secrets["BRAVE_API_KEY"]
	if !slices.Equal(s.Deliver, []Delivery{DeliverLateEnv}) || !DeliverLateEnv.Built() {
		t.Fatalf("deliver = %v", s.Deliver)
	}
	to := s.Rules[0].To[0]
	if to.Kind != MatchCommand || !slices.Equal(to.Command, []string{"npx", "-y", "@brave/brave-search-mcp-server"}) {
		t.Fatalf("to = %+v", to)
	}
	if len(s.EnvAllow) != 0 {
		t.Fatalf("no envAllow by default, got %v", s.EnvAllow)
	}
}

// file and env are still for later; late-env is listed with the built ones.
func TestDeliverMessagesNameTheBuiltMethods(t *testing.T) {
	for _, m := range []string{"file", "env"} {
		wantError(t, secretsHdr+"  X:\n    deliver: [helper, "+m+"]\n", m+" is not in this version (helper, late-env and stdout are)")
	}
	wantError(t, secretsHdr+"  X:\n    deliver: [Late-Env]\n", `unknown delivery "Late-Env" (helper, late-env or stdout)`)
}

func TestTrustedPath(t *testing.T) {
	c, _ := mustParse(t, hdr)
	if want := []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/opt/homebrew/bin", "/usr/local/bin"}; !slices.Equal(c.Defaults.TrustedPath, want) {
		t.Fatalf("default trustedPath = %v, want %v", c.Defaults.TrustedPath, want)
	}
	c, probs := mustParse(t, hdr+"defaults:\n  trustedPath: [/usr/bin, ~/.local/share/mise/installs/node/24.0.0/bin, /bin]\n")
	if len(probs) != 0 || !slices.Equal(c.Defaults.TrustedPath, []string{"/usr/bin", "/Users/u/.local/share/mise/installs/node/24.0.0/bin", "/bin"}) {
		t.Fatalf("trustedPath = %v (%v)", c.Defaults.TrustedPath, probs)
	}
	for body, want := range map[string]string{
		"[]":                    "non-empty list",
		"/usr/bin":              "non-empty list",
		"[usr/bin]":             "clean absolute path",
		"[/usr/bin/]":           "clean absolute path",
		"[/usr/../tmp]":         "clean absolute path",
		"[\"/a:/b\"]":           "\":\"",
		"[/usr/bin, /usr/bin]":  "listed twice",
		"[\"~root/bin\"]":       "clean absolute path",
		"[/usr/bin, [x]]":       "defaults.trustedPath",
		"[\"/usr/bin\\n/tmp\"]": "clean absolute path",
	} {
		wantError(t, hdr+"defaults:\n  trustedPath: "+body+"\n", want)
	}
}

// A command: matcher names an executable through trustedPath or by absolute
// path; a relative path with a slash and NUL are refused, and a relative
// file element is refused because the receiver runs in / (D6).
func TestCommandMatcherShapes(t *testing.T) {
	h := hdr + "apps:\n"
	for _, ok := range []string{
		`[npx, -y, "@brave/brave-search-mcp-server"]`,
		`[/opt/homebrew/bin/node, /Users/u/srv/server.js]`,
		`[node, -r, /Users/u/srv/setup.cjs, /Users/u/srv/server.js]`,
		`[node, --require=/Users/u/x.cjs, /Users/u/srv/server.js]`,
		`[python3, -m, mod]`,
		`[python3, -c, "print(1)"]`,
		`[python3, -X, dev, /Users/u/app.py]`,
		`[node, -e, "require('./x')"]`,
		`[npx, -y, "@brave/brave-search-mcp-server", --port=8080]`,
	} {
		if _, probs := mustParse(t, h+"  a: {command: "+ok+"}\n"); probs.HasErrors() {
			t.Errorf("%s: %v", ok, probs)
		}
	}
	for body, want := range map[string]string{
		`[./bin/server]`:                 "argv[0]",
		`[bin/server]`:                   "argv[0]",
		`[/usr/../bin/node]`:             "argv[0]",
		`[""]`:                           "argv[0]",
		`[node, ""]`:                     "empty argument",
		`[node, "a\0b"]`:                 "NUL",
		`[node, server.js]`:              `"server.js" is relative`,
		`[node, ./server.js]`:            `"./server.js" is relative`,
		`[node, ../x/server.mjs]`:        `"../x/server.mjs" is relative`,
		`[node, -r, ./setup.cjs, /a.js]`: `"./setup.cjs" is relative`,
		`[node, --require=./x.cjs, /a]`:  `"./x.cjs" is relative`,
		`[node, --import, x.mjs, /a.js]`: `"x.mjs" is relative`,
		`[node, --env-file=.env, /a.js]`: `".env" is relative`,
		`[python3, app.py]`:              `"app.py" is relative`,
		`[python3, -X, dev, app]`:        `"app" is relative`,
		`[python3.14, -u, server]`:       `"server" is relative`,
		`[npx, -y, ./pkg.tgz]`:           `"./pkg.tgz" is relative`,
		`[sh, ./run.sh]`:                 `"./run.sh" is relative`,
	} {
		wantError(t, h+"  a: {command: "+body+"}\n", want)
	}
}

// cwd: is for a later version: refused by name on an apps: entry.
func TestCwdIsNotInThisVersion(t *testing.T) {
	wantError(t, hdr+"apps:\n  a: {command: [node, /a.js], cwd: /Users/u}\n", "the cwd: field is not in this version")
}

// A command: receiver only ever matches a nazar run receiver, so it needs
// late-env in deliver; ssh keys still refuse it.
func TestCommandReceiversNeedLateEnv(t *testing.T) {
	wantError(t, lateHdr("")+strings.Replace(braveEntry, "[late-env]", "[helper]", 1), "command: receivers are for nazar run; add late-env to deliver")
	wantError(t, lateHdr("")+strings.Replace(braveEntry, "    deliver: [late-env]\n", "", 1), "command: receivers are for nazar run; add late-env to deliver")
	wantError(t, rulesHdr+"        - apps: [iterm]\n          to: [{command: [printenv]}]\n          gate: login\n", "not to ssh keys")
}

// A silent rule on a late-env secret needs no to:: naming an app covers any
// child of it. Files are still pinned and checked per request. A matcher for
// every caller stays refused.
func TestLateEnvGateNoneForAnApp(t *testing.T) {
	c, probs := mustParse(t, lateHdr("")+"  X:\n    deliver: [late-env]\n    rules:\n      - apps: [claude]\n        gate: none\n")
	if probs.HasErrors() || c.Secrets["X"].Rules[0].Policy.Gate != GateNone {
		t.Fatalf("a silent late-env rule for an app is valid: %v", probs)
	}
	wantError(t, lateHdr("")+"  X:\n    deliver: [late-env]\n    rules:\n      - apps: [any]\n        gate: none\n", "rule 1 would give this secret")
	silent := strings.Replace(braveEntry, "        scope: session\n        gate: dialog\n", "        gate: none\n", 1)
	c, probs = mustParse(t, lateHdr("")+silent)
	if probs.HasErrors() {
		t.Fatal(probs)
	}
	if got := c.Secrets["BRAVE_API_KEY"].Rules[0].Policy.Gate; got != GateNone {
		t.Fatalf("gate = %q", got)
	}
	// The own gate and defaults.fallback can't be none anyway; block is fine.
	if _, probs := mustParse(t, lateHdr("")+"  X:\n    deliver: [late-env]\n    rules:\n      - apps: [claude]\n        to: [brave-mcp]\n        gate: block\n"); probs.HasErrors() {
		t.Fatal(probs)
	}
}

// A launcher receiver (by the name typed: what the text alone shows) with
// scope: app is warned about (secrets design 4, 6.3.4).
func TestLauncherScopeAppWarns(t *testing.T) {
	_, probs := mustParse(t, lateHdr("")+strings.Replace(braveEntry, "scope: session", "scope: app", 1))
	if !strings.Contains(probs.Error(), "brave-mcp is a launcher") {
		t.Fatalf("want the launcher warning:\n%s", probs.Error())
	}
	_, probs = mustParse(t, lateHdr("")+braveEntry)
	if strings.Contains(probs.Error(), "launcher") {
		t.Fatalf("scope: session draws no warning:\n%s", probs.Error())
	}
	_, probs = mustParse(t, lateHdr("  srv: {command: [node, /Users/u/srv/server.js]}\n")+
		strings.Replace(strings.Replace(braveEntry, "scope: session", "scope: app", 1), "to: [brave-mcp]", "to: [srv]", 1))
	if strings.Contains(probs.Error(), "launcher") {
		t.Fatalf("node with an absolute script is no launcher:\n%s", probs.Error())
	}
}

func TestEnvAllow(t *testing.T) {
	c, probs := mustParse(t, lateHdr("")+strings.Replace(braveEntry, "    deliver: [late-env]\n", "    deliver: [late-env]\n    envAllow: [HTTPS_PROXY, NODE_ENV]\n", 1))
	if len(probs) != 0 || !slices.Equal(c.Secrets["BRAVE_API_KEY"].EnvAllow, []string{"HTTPS_PROXY", "NODE_ENV"}) {
		t.Fatalf("envAllow = %v (%v)", c.Secrets["BRAVE_API_KEY"].EnvAllow, probs)
	}
	with := func(list string) string {
		return lateHdr("") + strings.Replace(braveEntry, "    deliver: [late-env]\n", "    deliver: [late-env]\n    envAllow: "+list+"\n", 1)
	}
	for list, want := range map[string]string{
		"[NODE_OPTIONS]":             "NODE_OPTIONS can never be passed to a receiver",
		"[npm_config_registry]":      "npm_config_registry can never be passed to a receiver (npm_config_*)",
		"[Npm_Config_Registry]":      "(npm_config_*)",
		"[XDG_CONFIG_HOME]":          "(XDG_*)",
		"[GIT_SSH_COMMAND]":          "(GIT_*)",
		"[NODE_EXTRA_CA_CERTS]":      "NODE_EXTRA_CA_CERTS can never be passed",
		"[HOME]":                     "HOME is set by nazar",
		"[PATH]":                     "PATH is set by nazar",
		"[LC_ALL]":                   "LC_ALL is set by nazar",
		"[A-B]":                      "not a variable name",
		"[HTTPS_PROXY, HTTPS_PROXY]": "listed twice",
		"[]":                         "non-empty list",
		"HTTPS_PROXY":                "non-empty list",
	} {
		wantError(t, with(list), want)
	}
	// envAllow is only read by nazar run.
	wantError(t, secretsHdr+"  X:\n    deliver: [helper]\n    envAllow: [HTTPS_PROXY]\n", "envAllow is for late-env; add late-env to deliver")
}

// Review: an interpreter with no script, with "-" for its script,
// or with -i reads code from its standard input, which is the caller's.
func TestInterpreterStdinIsRefused(t *testing.T) {
	for _, body := range []string{`[node]`, `[python3]`, `[python3, -]`, `[node, -]`, `[node, -i]`, `[node, --interactive, -e, "1"]`,
		`[python3, -i, /abs/s.py]`, `[python3, -ui, /abs/s.py]`, `[python3, -u]`, `[NODE]`, `[python3.14t]`, `[node, --, -]`} {
		wantError(t, hdr+"apps:\n  a: {command: "+body+"}\n", "standard input")
	}
	for _, ok := range []string{`[node, -e, "1"]`, `[node, -p, "1"]`, `[python3, -c, x]`, `[python3, -m, mod]`, `[python3, -I, -c, x]`, `[node, /abs/s.js]`} {
		if _, probs := mustParse(t, hdr+"apps:\n  a: {command: "+ok+"}\n"); probs.HasErrors() {
			t.Errorf("%s: %v", ok, probs)
		}
	}
}

// Review: flags that load a file are file elements in both spellings, and
// so is the path value of any --flag=value, so an absolute one is pinned
// and a relative one refused.
func TestFileElements(t *testing.T) {
	for _, tc := range []struct {
		argv   []string
		interp bool
		want   []FileElement
	}{
		{[]string{"node", "-r", "/s.cjs", "/abs/app.js"}, true, []FileElement{{2, "/s.cjs"}, {3, "/abs/app.js"}}},
		{[]string{"node", "--require=/x.cjs", "/a.js"}, true, []FileElement{{1, "/x.cjs"}, {2, "/a.js"}}},
		{[]string{"node", "--import=./x.mjs", "/a.js"}, true, []FileElement{{1, "./x.mjs"}, {2, "/a.js"}}},
		{[]string{"node", "--loader", "/l.mjs", "--experimental-loader=/m.mjs", "/a.js"}, true, []FileElement{{2, "/l.mjs"}, {3, "/m.mjs"}, {4, "/a.js"}}},
		{[]string{"node", "--env-file-if-exists=/Users/u/.env", "/a.js"}, true, []FileElement{{1, "/Users/u/.env"}, {2, "/a.js"}}},
		{[]string{"node", "--openssl-config", "/o.cnf", "/a.js"}, true, []FileElement{{2, "/o.cnf"}, {3, "/a.js"}}},
		{[]string{"node", "--experimental-config-file=/c.json", "--snapshot-blob", "/s.blob", "/a.js"}, true, []FileElement{{1, "/c.json"}, {3, "/s.blob"}, {4, "/a.js"}}},
		{[]string{"node", "--frobnicate=./x", "/a.js"}, true, []FileElement{{1, "./x"}, {2, "/a.js"}}},
		{[]string{"node", "--port=8080", "/a.js"}, true, []FileElement{{2, "/a.js"}}},
		{[]string{"python3", "-m", "mod"}, true, nil},
		{[]string{"python3", "-X", "dev", "/a.py"}, true, []FileElement{{3, "/a.py"}}},
		{[]string{"python3", "-X", "pycache_prefix=/tmp/x", "/a.py"}, true, []FileElement{{2, "/tmp/x"}, {3, "/a.py"}}},
		{[]string{"python3", "-W", "ignore", "--", "/a.py"}, true, []FileElement{{4, "/a.py"}}},
		{[]string{"npx", "-y", "@brave/brave-search-mcp-server"}, false, nil},
		{[]string{"npx", "--package=/Users/u/pkg", "x"}, false, []FileElement{{1, "/Users/u/pkg"}}},
		{[]string{"node", "-r"}, true, nil},
	} {
		if got := FileElements(tc.argv, tc.interp); !slices.Equal(got, tc.want) {
			t.Errorf("FileElements(%q, %v) = %v, want %v", tc.argv, tc.interp, got, tc.want)
		}
	}
}

func TestCommandMatcherReviewCases(t *testing.T) {
	h := hdr + "apps:\n"
	for body, want := range map[string]string{
		`[node, --import=./x.mjs, /a.js]`:            `"./x.mjs" is relative`,
		`[node, --loader, ./l.mjs, /a.js]`:           `"./l.mjs" is relative`,
		`[node, --experimental-loader=l.mjs, /a.js]`: `"l.mjs" is relative`,
		`[node, --frobnicate=./x, /a.js]`:            `"./x" is relative`,
		`[node, --env-file-if-exists=.env, /a.js]`:   `".env" is relative`,
		`[.]`:                "argv[0]",
		`[..]`:               "argv[0]",
		`[node, ~/srv/s.js]`: "~ is not expanded in command:",
	} {
		wantError(t, h+"  a: {command: "+body+"}\n", want)
	}
	// The error names the element's own line.
	_, probs := Parse([]byte(h+"  a:\n    command:\n      - node\n      - ./x.js\n"), env)
	if !strings.Contains(probs.Error(), "line 7") {
		t.Fatalf("want the element's line (7):\n%s", probs.Error())
	}
}

func TestLauncherWarningOtherNames(t *testing.T) {
	for _, l := range []string{"uvx", "pipx", "NPX", "/opt/node/lib/node_modules/npm/bin/npx-cli.js"} {
		_, probs := mustParse(t, lateHdr("  l: {command: ["+l+", x]}\n")+
			strings.Replace(strings.Replace(braveEntry, "scope: session", "scope: app", 1), "to: [brave-mcp]", "to: [l]", 1))
		if !strings.Contains(probs.Error(), "is a launcher") {
			t.Errorf("%s: want the launcher warning:\n%s", l, probs.Error())
		}
	}
}
