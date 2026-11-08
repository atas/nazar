package broker

// The prompt and the audit line show what the user ran (spec 4.4, 4.6).
//
// The socket peer of an ssh-agent request is almost always ssh or
// ssh-keygen, started by git (directly or through an `sh -c` wrapper), so
// showing the peer's argv (`ssh -o … …`) says nothing about what the user
// did. The dialog of spec 4.4 shows the nearest meaningful command instead:
//
//	iTerm2 wants to use key "github"
//	  login to github.com                      <- the destination line, kept
//	  git push origin main    in ~/projects/foo <- the command and its folder
//	  chain: iTerm2 → bash → git → ssh
//	  Scope: this terminal session (expires in 8h)
//
// The contract these tests pin:
//
//   - The command is found by walking up from the socket peer, within the
//     part of the chain the user thinks of as the command (from the session
//     root, or the process below the app, down to the peer), past ssh,
//     ssh-keygen and shell (sh, bash, zsh) wrappers, to the first other
//     process. Wrappers are recognised by the executable the kernel reports
//     (the base name of ProcessInfo.Path), never by argv[0], which the
//     process chooses freely. When every process on the way is a wrapper
//     (ssh typed at the prompt), the command is the peer itself.
//   - The folder shown after the command ("    in ~/…") is that command's
//     current folder.
//   - The command goes through the same redaction allowlist as before
//     (audit.RedactArgs) and its program name is quoted unless it is a plain
//     word, in the dialog, the block warning and the audit line.
//   - The audit line keeps receiver= as the socket peer (who received the
//     result, spec 4.6) and adds command= with the command; cwd= is the
//     command's folder. When the command is the peer itself, command= may be
//     omitted (it would repeat receiver=).
//   - When the rule's matched process sits above the chain's app (claude →
//     Foo.app → ssh, matched by `apps: claude`), the dialog names that hop
//     and the audit line carries matched= naming it, so the user sees why
//     the rule applied although the chain line (Foo → ssh) does not show it.
//     The matched hop is the process that satisfied the matcher, judged by
//     its code identity, not a process that merely has the matched name.

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// Executables of the fake chains.
const (
	gitPath    = "/Library/Developer/CommandLineTools/usr/bin/git"
	keygenPath = "/usr/bin/ssh-keygen"
	fooTeam    = "FOOTEAM001"
)

var fooCode = platform.CodeIdentity{Signed: true, TeamID: fooTeam, SigningID: "com.foo.app", CDHash: []byte{0xf0}}

// gitProc is git run in dir with argv args (argv[0] included).
func gitProc(dir string, args ...string) fake.Proc {
	return fake.Proc{Path: gitPath, Args: args, Cwd: dir, Code: fake.AppleCode("com.apple.git")}
}

// gitSSH is the ssh git starts for a push: an argv that says nothing about
// what the user ran.
func gitSSH(dir string) fake.Proc {
	return fake.Proc{
		Path: "/usr/bin/ssh", Cwd: dir, Code: fake.AppleCode("com.apple.openssh"),
		Args: []string{"ssh", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-receive-pack 'atas/nazar.git'"},
	}
}

func zshProc(args ...string) fake.Proc {
	if len(args) == 0 {
		args = []string{"zsh"}
	}
	return fake.Proc{Path: "/bin/zsh", Args: args, Cwd: "/Users/u/projects/foo", Code: fake.AppleCode("com.apple.zsh")}
}

func fooApp() fake.Proc {
	return fake.Proc{
		Path: "/Applications/Foo.app/Contents/MacOS/Foo", Args: []string{"/Applications/Foo.app/Contents/MacOS/Foo"},
		Cwd: "/", Code: fooCode, App: &fake.App{BundleID: "com.foo.app", Name: "Foo"},
	}
}

// itermZshTab is an iTerm2 tab whose login shell is zsh (the macOS default):
// iTerm2 → iTermServer → login → zsh → extra (outermost first). It returns
// the peer (the last extra process).
func (e *env) itermZshTab(extra ...fake.Proc) platform.ProcessRef {
	app := e.f.Launch(platform.ProcessRef{}, fake.Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: fake.ITermCode,
		App: &fake.App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	server := e.f.Launch(app, fake.Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTermServer-3.6", Code: fake.ITermCode})
	login := e.f.Launch(server, fake.Proc{Path: "/usr/bin/login", Root: true, Code: fake.AppleCode("com.apple.login")})
	parent := e.f.Launch(login, fake.Proc{Path: "/bin/zsh", Args: []string{"-zsh"}, Cwd: "/Users/u", Code: fake.AppleCode("com.apple.zsh")})
	for _, p := range extra {
		parent = e.f.Launch(parent, p)
	}
	return parent
}

// chainUnder launches extra as a chain of children under parent and returns
// the last one.
func (e *env) chainUnder(parent platform.ProcessRef, extra ...fake.Proc) platform.ProcessRef {
	for _, p := range extra {
		parent = e.f.Launch(parent, p)
	}
	return parent
}

// handleShown runs one request that must reach the gate and returns the
// prompt the user saw and the request's audit line.
func (e *env) handleShown(t *testing.T, req Request) (platform.Prompt, map[string]string) {
	t.Helper()
	e.f.SetDefaults(fake.Answer{Allow: true}, fake.Answer{Allow: true})
	before := len(e.f.Shown())
	if r := e.b.Handle(req); r.Decision != audit.Approved {
		t.Fatalf("want approved, got %+v", r)
	}
	shown := e.f.Shown()
	if len(shown) != before+1 {
		t.Fatalf("want exactly one prompt, %d shown", len(shown)-before)
	}
	return shown[len(shown)-1].Prompt, e.lastLine(t)
}

// commandOf returns the dialog's command line: the line right after the
// destination line (the request's summary), which must be there.
func commandOf(t *testing.T, lines []string, summary string) string {
	t.Helper()
	for i, l := range lines {
		if l == summary {
			if i+1 >= len(lines) {
				t.Fatalf("no command line after the destination line %q: %q", summary, lines)
			}
			return lines[i+1]
		}
	}
	t.Fatalf("the destination line %q is missing: %q", summary, lines)
	return ""
}

// splitFolder splits a command line into the command and its folder.
func splitFolder(line string) (cmd, folder string) {
	cmd, folder, _ = strings.Cut(line, "    in ")
	return cmd, folder
}

const sum = "login to github.com as git"

// The three fake chains of the task: the dialog and the audit line show what
// the user ran, in its folder, while the destination line, the chain line
// and the audit receiver stay as they were.
//
// In every case here the process that satisfied the rule is on the chain
// line (the app iTerm2 for `apps: iterm`, claude below the session root for
// `apps: claude`), so the dialog has no "matched:" line and the audit line no
// matched= field (spec 4.4: the matched hop is named only when the chain line
// does not show it). wantRule pins which rule that is.
func TestCommandIsWhatTheUserRan(t *testing.T) {
	const foo = "/Users/u/projects/foo"
	cases := []struct {
		name      string
		key       string
		build     func(e *env) platform.ProcessRef
		wantCmd   string // the dialog's command, without the folder
		wantDir   string // the folder after it, "" for none
		wantChain string // the dialog's chain line
		wantAudit string // command= in the audit line ("" = may be omitted)
		wantRule  string // rule= in the audit line
	}{
		{
			name: "iTerm2 → zsh → git → ssh", key: "github",
			build: func(e *env) platform.ProcessRef {
				return e.itermZshTab(gitProc(foo, "git", "push", "origin", "main"), gitSSH(foo))
			},
			wantCmd: "git push origin main", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → zsh → git → ssh", wantAudit: "git push origin main", wantRule: "2",
		},
		{
			name: "iTerm2 → bash → claude → zsh → git → ssh", key: "github",
			build: func(e *env) platform.ProcessRef {
				tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), zshProc(), gitProc(foo, "git", "push", "origin", "main"), gitSSH(foo))
				return tab.Peer()
			},
			wantCmd: "git push origin main", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → bash → claude → zsh → git → ssh", wantAudit: "git push origin main", wantRule: "1",
		},
		{
			// git runs GIT_SSH_COMMAND through `sh -c`: the sh wrapper is
			// skipped like ssh.
			name: "git → sh -c → ssh", key: "github",
			build: func(e *env) platform.ProcessRef {
				tab := e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "fetch", "upstream"),
					fake.Proc{Path: "/bin/sh", Args: []string{"sh", "-c", `ssh -i ~/.ssh/k "$@"`, "ssh -i ~/.ssh/k", "git@github.com", "git-upload-pack 'a/b.git'"}, Cwd: foo, Code: fake.AppleCode("com.apple.sh")},
					gitSSH(foo))
				return tab.Peer()
			},
			wantCmd: "git fetch upstream", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → bash → git → sh → ssh", wantAudit: "git fetch upstream", wantRule: "2",
		},
		{
			// Commit signing: git runs ssh-keygen -Y sign (spike S8).
			name: "git commit → ssh-keygen", key: "github",
			build: func(e *env) platform.ProcessRef {
				tab := e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "commit", "-S", "-m", "fix: rotate the prod token"),
					fake.Proc{Path: keygenPath, Args: []string{"ssh-keygen", "-Y", "sign", "-n", "git", "-f", "/Users/u/.nazar/keys/github.pub", "/var/folders/xy/T//.git_signing_buffer_tmpAbc"}, Cwd: foo, Code: fake.AppleCode("com.apple.ssh-keygen")})
				return tab.Peer()
			},
			wantCmd: "git commit -S -m …", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → bash → git → ssh-keygen", wantAudit: "git commit -S -m …", wantRule: "2",
		},
		{
			// ProxyJump: the peer is the inner `ssh -W`, started by the outer
			// ssh, started by git. Both are wrappers.
			name: "git → ssh → ssh -W", key: "github",
			build: func(e *env) platform.ProcessRef {
				tab := e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "pull"), gitSSH(foo),
					fake.Proc{Path: "/usr/bin/ssh", Args: []string{"ssh", "-W", "[github.com]:22", "bastion"}, Cwd: foo, Code: fake.AppleCode("com.apple.openssh")})
				return tab.Peer()
			},
			wantCmd: "git pull", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → bash → git → ssh → ssh", wantAudit: "git pull", wantRule: "2",
		},
		{
			// Homebrew's ssh is not Apple-signed; it is still ssh.
			name: "git → Homebrew ssh", key: "github",
			build: func(e *env) platform.ProcessRef {
				tab := e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "push"),
					fake.Proc{Path: "/opt/homebrew/Cellar/openssh/10.0p1/bin/ssh", Args: []string{"ssh", "git@github.com", "git-receive-pack 'a/b.git'"}, Cwd: foo, Code: fake.Unsigned})
				return tab.Peer()
			},
			wantCmd: "git push", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → bash → git → ssh", wantAudit: "git push", wantRule: "2",
		},
		{
			// ssh typed at the prompt: everything above it is a shell, so the
			// command is ssh itself, never the login shell or the app.
			name: "ssh typed in the shell", key: "github",
			build: func(e *env) platform.ProcessRef {
				tab := e.f.ITermTab(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/ssh", Args: []string{"ssh", "deploy@prod", "uptime"}, Cwd: foo, Code: fake.AppleCode("com.apple.openssh")})
				return tab.Peer()
			},
			wantCmd: "ssh … uptime", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → bash → ssh", wantRule: "2",
		},
		{
			// The same under zsh, the macOS default login shell: the walk
			// steps past zsh exactly as it does past bash and sh, so the
			// command is the ssh the user typed, never the login shell.
			name: "ssh typed in zsh", key: "github",
			build: func(e *env) platform.ProcessRef {
				return e.itermZshTab(fake.Proc{Path: "/usr/bin/ssh", Args: []string{"ssh", "deploy@prod", "uptime"}, Cwd: foo, Code: fake.AppleCode("com.apple.openssh")})
			},
			wantCmd: "ssh … uptime", wantDir: "~/projects/foo",
			wantChain: "chain: iTerm2 → zsh → ssh", wantRule: "2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			peer := tc.build(e)
			req := e.req(tc.key, peer)
			p, f := e.handleShown(t, req)
			cmd, dir := splitFolder(commandOf(t, p.Lines, sum))
			if cmd != tc.wantCmd || dir != tc.wantDir {
				t.Errorf("command line = %q in %q, want %q in %q\n%s", cmd, dir, tc.wantCmd, tc.wantDir, promptText(p))
			}
			if !containsLine(p.Lines, tc.wantChain) {
				t.Errorf("chain line %q missing:\n%s", tc.wantChain, promptText(p))
			}
			for _, l := range p.Lines {
				if strings.Contains(l, "git-receive-pack") || strings.Contains(l, "SendEnv") || strings.Contains(l, "rotate the prod token") || strings.Contains(l, "github.pub") {
					t.Errorf("dialog shows the wrapper's or an elided argument: %q", l)
				}
			}
			// Audit: receiver= is still the socket peer, command= what the
			// user ran, cwd= its folder.
			chain := e.r.Resolve(peer)
			rp, _ := chain.Peer()
			if want := audit.Program(rp.Args[0]); !strings.HasPrefix(f["receiver"], want) {
				t.Errorf("receiver = %q, want the socket peer (%s …)", f["receiver"], want)
			}
			switch {
			case tc.wantAudit != "" && f["command"] != tc.wantAudit:
				t.Errorf("audit command = %q, want %q (line %s)", f["command"], tc.wantAudit, e.sink.Lines()[len(e.sink.Lines())-1])
			case tc.wantAudit == "" && f["command"] != "" && f["command"] != f["receiver"]:
				t.Errorf("audit command = %q: when the peer is the command it is the receiver (%q) or omitted", f["command"], f["receiver"])
			}
			if f["cwd"] != tc.wantDir {
				t.Errorf("audit cwd = %q, want %q", f["cwd"], tc.wantDir)
			}
			// The matched process is on the chain line, so nothing names it
			// again: no matched= field, no "matched:" line.
			if f["rule"] != tc.wantRule {
				t.Errorf("audit rule = %q, want %q", f["rule"], tc.wantRule)
			}
			assertNoMatchedHop(t, p, f)
		})
	}
}

// assertNoMatchedHop fails when the dialog has a "matched:" line or the audit
// line a matched= field.
func assertNoMatchedHop(t *testing.T, p platform.Prompt, f map[string]string) {
	t.Helper()
	if m, ok := f["matched"]; ok || m != "" {
		t.Errorf("audit line names a matched hop (%q) although the chain line shows it", m)
	}
	for _, l := range p.Lines {
		if strings.HasPrefix(strings.TrimSpace(l), "matched:") {
			t.Errorf("dialog names a matched hop although the chain line shows it: %q\n%s", l, promptText(p))
		}
	}
}

func containsLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// The folder is the command's, not the wrapper's: git ran in ~/projects/foo
// even though the ssh it started reports another folder.
func TestCommandFolderIsTheCommands(t *testing.T) {
	e := newEnv(t)
	peer := e.itermZshTab(gitProc("/Users/u/projects/foo", "git", "push"), gitSSH("/Users/u/projects/foo/sub"))
	p, f := e.handleShown(t, e.req("github", peer))
	if cmd, dir := splitFolder(commandOf(t, p.Lines, sum)); cmd != "git push" || dir != "~/projects/foo" {
		t.Fatalf("command line %q in %q, want git push in ~/projects/foo", cmd, dir)
	}
	if f["cwd"] != "~/projects/foo" {
		t.Fatalf("audit cwd = %q, want the command's folder ~/projects/foo", f["cwd"])
	}
}

// An unknown chain (no app: a detached tool) still shows the command that
// started ssh; the Unknown app header stays first.
func TestCommandInUnknownChain(t *testing.T) {
	e := newEnv(t)
	py := e.f.Launch(platform.ProcessRef{}, fake.Proc{Path: "/usr/bin/python3", Args: []string{"python3", "deploy.py", "--env", "prod"}, Cwd: "/Users/u/ops", Code: fake.AppleCode("com.apple.python3")})
	peer := e.chainUnder(py, fake.SSHProc("deploy@prod"))
	p, f := e.handleShown(t, e.req("unk", peer))
	if !p.Unknown || !strings.Contains(p.Lines[0], "Unknown app") {
		t.Fatalf("unknown header lost: %q", p.Lines)
	}
	if cmd, dir := splitFolder(commandOf(t, p.Lines, sum)); cmd != "python3 deploy.py --env prod" || dir != "~/ops" {
		t.Fatalf("command line %q in %q", cmd, dir)
	}
	if f["command"] != "python3 deploy.py --env prod" {
		t.Fatalf("audit command = %q", f["command"])
	}
}

// The block warning (spec 4.4) shows the same command line as the dialog.
func TestBlockWarningShowsCommand(t *testing.T) {
	e := newEnvWith(t, moreCfg, 200*time.Millisecond)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), zshProc(), gitProc("/Users/u/projects/foo", "git", "push", "origin", "main"), gitSSH("/Users/u/projects/foo"))
	if r := e.b.Handle(e.req("guarded", tab.Peer())); r.Decision != audit.Blocked {
		t.Fatalf("%+v", r)
	}
	w := e.f.Warnings()[0]
	cmd, dir := splitFolder(commandOf(t, w.Lines, sum))
	if cmd != "git push origin main" || dir != "~/projects/foo" {
		t.Fatalf("warning command line %q in %q:\n%s", cmd, dir, strings.Join(w.Lines, "\n"))
	}
	if f := e.lastLine(t); f["command"] != "git push origin main" || f["decision"] != "blocked" {
		t.Fatalf("audit %v", f)
	}
}

// Attack: wrappers are recognised by the executable, never by argv[0]. A
// program that calls itself "ssh" or "-zsh" is not skipped, so it cannot
// hide behind the command that started it (a core.sshCommand or GIT_SSH
// pointing at a dropped binary): the dialog shows its own argv, not
// `git push origin main`.
func TestSpoofedWrapperNameIsNotSkipped(t *testing.T) {
	foo := "/Users/u/projects/foo"
	evilAs := func(argv0 string) fake.Proc {
		return fake.Proc{Path: "/Users/u/Downloads/evil", Args: []string{argv0, "-T", "git@github.com"}, Cwd: foo, Code: fake.Unsigned}
	}
	cases := map[string]func(e *env) platform.ProcessRef{
		"peer claims ssh": func(e *env) platform.ProcessRef {
			return e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "push", "origin", "main"), evilAs("ssh")).Peer()
		},
		"peer claims ssh-keygen": func(e *env) platform.ProcessRef {
			return e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "push", "origin", "main"), evilAs("/usr/bin/ssh-keygen")).Peer()
		},
		"middle hop claims zsh": func(e *env) platform.ProcessRef {
			return e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "push", "origin", "main"), evilAs("-zsh"), gitSSH(foo)).Peer()
		},
		"middle hop claims sh": func(e *env) platform.ProcessRef {
			return e.f.ITermTab(platform.ProcessRef{}, gitProc(foo, "git", "push", "origin", "main"), evilAs("sh"), gitSSH(foo)).Peer()
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			p, f := e.handleShown(t, e.req("github", build(e)))
			cmd, _ := splitFolder(commandOf(t, p.Lines, sum))
			if strings.Contains(cmd, "push") || strings.Contains(cmd, "origin") {
				t.Fatalf("a process named like a wrapper was skipped; command line %q", cmd)
			}
			if !strings.HasSuffix(cmd, " -T …") {
				t.Fatalf("command line %q: want the impostor's own (redacted) argv", cmd)
			}
			if strings.Contains(f["command"], "push") {
				t.Fatalf("audit command %q skipped the impostor", f["command"])
			}
			if !containsLine(p.Lines, "chain: iTerm2 → bash → git → evil") && !strings.Contains(strings.Join(p.Lines, "\n"), "→ evil") {
				t.Fatalf("chain must show the real executable: %q", p.Lines)
			}
		})
	}
}

// Attack: the command's arguments are user- or attacker-chosen and go through
// the redaction allowlist (spec 4.6) in the dialog and
// the audit line alike: only short plain words survive; values, URLs,
// --flag=value, user:pass, glued short options, quoted strings, scripts and
// long tokens become "…". No pattern-based detection: the token below is
// dropped because it is not a plain word, not because it looks like one.
func TestCommandArgsAreRedacted(t *testing.T) {
	foo := "/Users/u/projects/foo"
	argv := []string{
		"git", "-c", "credential.helper=!f() { echo password=hunter2; }; f",
		"push", "https://alice:ghp_0123456789abcdefghij@github.com/a/b.git",
		"--repo=secret-repo", "-pSECRET", "main", strings.Repeat("Z", 40), "'quoted'", "a b",
		"alice:s3cret", "user@host", "x?y", "x&y", "--force",
	}
	const want = "git -c … push … … … main … … … … … … … --force"
	e := newEnv(t)
	peer := e.itermZshTab(gitProc(foo, argv...), gitSSH(foo))
	p, f := e.handleShown(t, e.req("github", peer))
	cmd, _ := splitFolder(commandOf(t, p.Lines, sum))
	if cmd != want {
		t.Errorf("dialog command\n got %q\nwant %q", cmd, want)
	}
	if f["command"] != want {
		t.Errorf("audit command\n got %q\nwant %q", f["command"], want)
	}
	line := e.sink.Lines()[len(e.sink.Lines())-1]
	text := promptText(p) + "\n" + p.Reason
	for _, secret := range []string{"hunter2", "ghp_0123", "alice", "secret-repo", "SECRET", "ZZZZ", "quoted", "s3cret", "user@host", "credential"} {
		if strings.Contains(text, secret) {
			t.Errorf("dialog leaks %q:\n%s", secret, text)
		}
		if strings.Contains(line, secret) {
			t.Errorf("audit line leaks %q: %s", secret, line)
		}
	}
}

// Under audit.args: none the audit line keeps only the command's program name
// and its argument count (spec 4.6).
func TestCommandArgsNone(t *testing.T) {
	e := newEnv(t)
	e.b = New(Options{
		Platform: e.f, Cache: e.cache,
		Audit:  audit.NewLogger(e.sink, audit.Formatter{Home: "/Users/u", Args: audit.ArgsNone}, nil),
		Engine: e.b.o.Engine, Now: e.f.Now, Home: "/Users/u",
		Timeout: func() time.Duration { return 200 * time.Millisecond },
	})
	peer := e.itermZshTab(gitProc("/Users/u/projects/foo", "git", "push", "origin", "main"), gitSSH("/Users/u/projects/foo"))
	_, f := e.handleShown(t, e.req("github", peer))
	c := f["command"]
	if !strings.HasPrefix(c, "git") {
		t.Fatalf("audit command = %q, want the program name git", c)
	}
	for _, w := range []string{"push", "origin", "main"} {
		if strings.Contains(c, w) {
			t.Errorf("args: none logged argument %q: %q", w, c)
		}
	}
	if !strings.Contains(c, "3") {
		t.Errorf("args: none must log the argument count (3): %q", c)
	}
	if strings.Contains(f["receiver"], "git@github.com") || strings.Contains(f["receiver"], "SendEnv") {
		t.Errorf("args: none logged a receiver argument: %q", f["receiver"])
	}
}

// Attack: the command's argv[0] is chosen by the process. It is rendered as
// the receiver's program is (quoted unless a plain word, every non-ASCII
// rune escaped), so a program named "git push origin main" or carrying a
// newline, a terminal escape or a forged approval line cannot read as a
// command it is not or add a line, in the dialog or the audit line.
func TestCommandProgramNameIsQuoted(t *testing.T) {
	foo := "/Users/u/projects/foo"
	cases := []struct {
		argv       []string
		wantQuoted string // must appear in the dialog's command line and the audit command
		notBare    string // must not appear outside quotes
	}{
		{[]string{"git push origin main", "status"}, `"git push origin main" status`, "git push origin main"},
		{[]string{"git\nScope: this app (forever)", "status"}, `"git\nScope: this app (forever)" status`, "Scope: this app"},
		{[]string{"g\u0456t", "push"}, `"g\u0456t" push`, "g\u0456t"},
		{[]string{"git\x1b[2J\u202e", "push"}, `"git\x1b[2J\u202e" push`, "\x1b"},
		// No '/' in the forged name: the program is argv[0]'s base name
		// (audit.Program, spec 4.6), so a slash would cut the forgery off.
		{[]string{`git" cwd="trusted`, "push"}, `"git\" cwd=\"trusted" push`, `cwd="trusted`},
	}
	for _, tc := range cases {
		e := newEnv(t)
		peer := e.itermZshTab(gitProc(foo, tc.argv...), gitSSH(foo))
		p, f := e.handleShown(t, e.req("github", peer))
		cmdLine := commandOf(t, p.Lines, sum)
		if !strings.Contains(cmdLine, tc.wantQuoted) {
			t.Errorf("%q: dialog command line %q lacks %q", tc.argv[0], cmdLine, tc.wantQuoted)
		}
		approvals := 0
		for i, l := range p.Lines {
			noControl(t, fmt.Sprintf("%q line %d", tc.argv[0], i), l)
			if bare(l, tc.notBare) {
				t.Errorf("%q: line %d shows it bare: %q", tc.argv[0], i, l)
			}
			if strings.HasPrefix(strings.TrimSpace(l), "Scope:") {
				approvals++
			}
		}
		if approvals != 1 {
			t.Errorf("%q: %d Scope lines: %q", tc.argv[0], approvals, p.Lines)
		}
		if !strings.HasSuffix(cmdLine, "    in ~/projects/foo") {
			t.Errorf("%q: folder lost or forged: %q", tc.argv[0], cmdLine)
		}
		// Audit: the line parses (ParseLine refuses raw controls), no field
		// is forged, and command= renders the program the same way.
		if !strings.Contains(f["command"], tc.wantQuoted) {
			t.Errorf("%q: audit command %q lacks %q", tc.argv[0], f["command"], tc.wantQuoted)
		}
		if f["cwd"] != "~/projects/foo" || f["app"] != "com.googlecode.iterm2" {
			t.Errorf("%q: audit fields forged: %v", tc.argv[0], f)
		}
	}
}

// Attack: a padded command cannot push the fields that matter off the audit
// line or the dialog off the screen.
func TestCommandCannotOverflow(t *testing.T) {
	foo := "/Users/u/projects/foo"
	argv := []string{strings.Repeat("g", 5000)}
	for i := 0; i < 3000; i++ {
		argv = append(argv, "push")
	}
	e := newEnv(t)
	peer := e.itermZshTab(gitProc(foo, argv...), gitSSH(foo))
	p, f := e.handleShown(t, e.req("github", peer))
	for i, l := range p.Lines {
		if n := utf8.RuneCountInString(l); n > maxLine {
			t.Errorf("dialog line %d is %d runes (max %d)", i, n, maxLine)
		}
	}
	if !containsLine(p.Lines, "chain: iTerm2 → zsh → git → ssh") {
		t.Errorf("the chain line was pushed off: %q", p.Lines)
	}
	line := e.sink.Lines()[len(e.sink.Lines())-1]
	if len(line) > audit.MaxLine {
		t.Fatalf("audit line is %d bytes (max %d)", len(line), audit.MaxLine)
	}
	for k, want := range map[string]string{"decision": "approved", "target": "ssh:github", "rule": "2", "gate": "login", "app": "com.googlecode.iterm2"} {
		if f[k] != want {
			t.Errorf("%s = %q, want %q (line %s)", k, f[k], want, line)
		}
	}
	if f["command"] == "" {
		t.Errorf("command dropped entirely: %s", line)
	}
}

// ---------------------------------------------------------------------------
// The matched hop above the app.
// ---------------------------------------------------------------------------

// claude → Foo.app → ssh: the chain's app is Foo, so the chain line reads
// "Foo → ssh", yet `apps: claude` (signed:) matched claude above the app.
// The dialog names that hop and the audit line says matched=claude(…).
func TestMatchedHopAboveAppIsNamed(t *testing.T) {
	e := newEnv(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), fooApp(), fake.SSHProc("git@github.com"))
	p, f := e.handleShown(t, e.req("github", tab.Peer()))
	if f["rule"] != "1" {
		t.Fatalf("want rule 1 (apps: claude), got %v", f)
	}
	if !strings.HasPrefix(p.Title, "Foo wants") {
		t.Fatalf("title %q: the chain's app is Foo", p.Title)
	}
	named := false
	for _, l := range p.Lines {
		if strings.HasPrefix(l, "chain:") {
			continue
		}
		if strings.Contains(l, "claude") {
			named = true
		}
	}
	if !named {
		t.Errorf("the dialog does not name the matched hop claude:\n%s", promptText(p))
	}
	procs, err := audit.ParseChain(f["matched"])
	if err != nil || len(procs) != 1 || procs[0].Name != "claude" || procs[0].Identity != "Q6L2SF6YDW:com.anthropic.claude-code" {
		t.Fatalf("matched = %q (%v): want one chain element claude(pid, Q6L2SF6YDW:com.anthropic.claude-code)", f["matched"], err)
	}
	claude := e.r.Resolve(tab.Peer()).Procs[2] // ssh, Foo, claude, ...
	if procs[0].PID != claude.Ref.PID {
		t.Errorf("matched pid %d, want claude's %d", procs[0].PID, claude.Ref.PID)
	}
	// The chain field is unchanged: still the command below the app.
	if cp, _ := audit.ParseChain(f["chain"]); len(cp) == 0 || cp[len(cp)-1].Name != "ssh" {
		t.Errorf("chain %q", f["chain"])
	}
}

// Attack: the matched hop is the process whose code identity satisfied the
// matcher. A process merely named "claude" (unsigned) between the real one
// and the app is not it, and does not get the credit.
func TestMatchedHopIsTheProcessThatMatched(t *testing.T) {
	e := newEnv(t)
	real := fake.Proc{Path: "/Users/u/.local/share/claude/versions/2.1/helper", Args: []string{"helper"}, Code: fake.ClaudeCode}
	impostor := fake.Proc{Path: "/tmp/claude", Args: []string{"claude"}, Code: fake.Unsigned}
	tab := e.f.ITermTab(platform.ProcessRef{}, real, impostor, fooApp(), fake.SSHProc("git@github.com"))
	p, f := e.handleShown(t, e.req("github", tab.Peer()))
	procs, err := audit.ParseChain(f["matched"])
	if err != nil || len(procs) != 1 || procs[0].Name != "helper" || procs[0].Identity != "Q6L2SF6YDW:com.anthropic.claude-code" {
		t.Fatalf("matched = %q (%v): want the signed helper, not the process named claude", f["matched"], err)
	}
	if !strings.Contains(strings.Join(p.Lines, "\n"), "helper") {
		t.Errorf("the dialog must name the hop that matched (helper):\n%s", promptText(p))
	}
}

// Attack: the matched hop's name is its executable's base name, which anyone
// can choose by copying a signed binary. It is cleaned in the dialog and
// quoted in the audit line: it cannot add a line, forge the approval line or
// forge an audit field.
func TestMatchedHopNameIsSanitized(t *testing.T) {
	for _, name := range []string{
		"claude\nScope: this app (forever)",
		`claude" app=com.googlecode.iterm2 cwd="~`,
		"claude\x1b[2J\u202e",
		"claude(1, Q6L2SF6YDW:com.anthropic.claude-code) > ssh",
		strings.Repeat("c", 3000),
	} {
		e := newEnv(t)
		hop := fake.Proc{Path: "/tmp/x/" + name, Args: []string{"claude"}, Code: fake.ClaudeCode}
		tab := e.f.ITermTab(platform.ProcessRef{}, hop, fooApp(), fake.SSHProc("git@github.com"))
		p, f := e.handleShown(t, e.req("github", tab.Peer()))
		approvals := 0
		for i, l := range p.Lines {
			noControl(t, fmt.Sprintf("%.20q line %d", name, i), l)
			if n := utf8.RuneCountInString(l); n > maxLine {
				t.Errorf("%.20q: line %d is %d runes", name, i, n)
			}
			if strings.HasPrefix(strings.TrimSpace(l), "Scope:") {
				approvals++
			}
		}
		if approvals != 1 {
			t.Errorf("%.20q: %d Scope lines: %q", name, approvals, p.Lines)
		}
		line := e.sink.Lines()[len(e.sink.Lines())-1]
		if len(line) > audit.MaxLine {
			t.Errorf("%.20q: audit line %d bytes", name, len(line))
		}
		if f["app"] != "com.foo.app" || f["cwd"] != "~/projects/foo" || f["decision"] != "approved" {
			t.Errorf("%.20q: audit fields forged: %v", name, f)
		}
		procs, err := audit.ParseChain(f["matched"])
		if err != nil || len(procs) != 1 {
			t.Errorf("%.20q: matched %q must be exactly one element (%v)", name, f["matched"], err)
			continue
		}
		if len(name) < 64 && procs[0].Name != name {
			t.Errorf("%.20q: matched name round-trips as %q", name, procs[0].Name)
		}
	}
}

// The matched hop is named only when the chain line does not show it (spec
// 4.4). When the process that satisfied the rule is the chain's app (iTerm2
// for `apps: iterm`, every terminal request) or sits below the session root
// (claude → zsh → git → ssh for `apps: claude`), it is already on the chain
// line: the dialog has no "matched:" line and the audit line no matched=
// field. A false "matched: … (above iTerm2)" or "between iTerm2 and the
// session" here would explain every request with something untrue.
func TestNoMatchedHopWhenChainLineShowsIt(t *testing.T) {
	const foo = "/Users/u/projects/foo"
	cases := []struct {
		name     string
		build    func(e *env) platform.ProcessRef
		wantRule string
		shown    string // the chain line that already shows the matched process
	}{
		{
			name: "the app matched: iTerm2 → zsh → git → ssh by apps: [iterm]",
			build: func(e *env) platform.ProcessRef {
				return e.itermZshTab(gitProc(foo, "git", "push", "origin", "main"), gitSSH(foo))
			},
			wantRule: "2", shown: "chain: iTerm2 → zsh → git → ssh",
		},
		{
			name: "a process below the session root matched: iTerm2 → bash → claude → zsh → git → ssh by apps: [claude]",
			build: func(e *env) platform.ProcessRef {
				return e.f.ITermTab(platform.ProcessRef{}, fake.ClaudeProc(), zshProc(), gitProc(foo, "git", "push", "origin", "main"), gitSSH(foo)).Peer()
			},
			wantRule: "1", shown: "chain: iTerm2 → bash → claude → zsh → git → ssh",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			p, f := e.handleShown(t, e.req("github", tc.build(e)))
			if f["rule"] != tc.wantRule {
				t.Fatalf("rule = %q, want %q: %v", f["rule"], tc.wantRule, f)
			}
			if !containsLine(p.Lines, tc.shown) {
				t.Fatalf("chain line %q missing:\n%s", tc.shown, promptText(p))
			}
			assertNoMatchedHop(t, p, f)
			if strings.Contains(promptText(p), "above ") || strings.Contains(promptText(p), "and the session") {
				t.Errorf("dialog explains a hop that is not hidden:\n%s", promptText(p))
			}
		})
	}
}

// No rule matched: there is no matched hop to name.
func TestNoMatchedHopWithoutRule(t *testing.T) {
	e := newEnv(t)
	stray := e.f.Launch(platform.ProcessRef{}, fooApp())
	peer := e.chainUnder(stray, fake.SSHProc("git@github.com"))
	if r := e.b.Handle(e.req("github", peer)); r.Decision != audit.Blocked {
		t.Fatalf("%+v", r)
	}
	if f := e.lastLine(t); f["rule"] != "fallback" || f["matched"] != "" {
		t.Fatalf("fallback decision must not name a matched hop: %v", f)
	}
}
