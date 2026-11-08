package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/ssh/agentproto"
)

// sshGText renders what `ssh -G` prints for a host, in ssh's spelling: one
// lowercase keyword per line; identityfile keeps `~`; identityagent is the
// expanded path, or the words SSH_AUTH_SOCK or none as configured, or
// absent when unset; controlmaster is false, true, auto, ask or autoask.
func sshGText(host, agent, only, master string, files ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "host %s\nhostname %s\nuser git\ncontrolmaster %s\nidentitiesonly %s\n", host, strings.ToLower(host), master, only)
	if agent != "" {
		fmt.Fprintf(&b, "identityagent %s\n", agent)
	}
	for _, f := range files {
		fmt.Fprintf(&b, "identityfile %s\n", f)
	}
	return b.String()
}

// fakeOutput answers the setup checks' programs from a table keyed by the
// command line (the program and its arguments joined by spaces); an absent
// entry is an error, as a program that exits non-zero is. A program named
// through $PATH is a test failure.
func fakeOutput(t *testing.T, table map[string]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(_ context.Context, argv0 string, args ...string) ([]byte, error) {
		if !filepath.IsAbs(argv0) {
			t.Errorf("a setup check ran %q through $PATH", argv0)
		}
		line := strings.Join(append([]string{argv0}, args...), " ")
		out, ok := table[line]
		if !ok {
			return nil, fmt.Errorf("%s: exit status 1: not in this test's table", line)
		}
		return []byte(out), nil
	}
}

// recording wraps a runner and appends every program it is asked to run
// to ran.
func recording(run func(context.Context, string, ...string) ([]byte, error), ran *[]string) func(context.Context, string, ...string) ([]byte, error) {
	return func(ctx context.Context, argv0 string, args ...string) ([]byte, error) {
		*ran = append(*ran, argv0)
		return run(ctx, argv0, args...)
	}
}

// fakeAgent serves an ssh agent at path that answers REQUEST_IDENTITIES
// with ids, and counts the connections it got.
func fakeAgent(t *testing.T, path string, ids []agentproto.Identity) *atomic.Int32 {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	var conns atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer c.Close()
				if body, err := agentproto.ReadMessage(c); err == nil && body[0] == agentproto.MsgRequestIdentities {
					_ = agentproto.WriteMessage(c, agentproto.MarshalIdentities(ids))
				}
			}()
		}
	}()
	return &conns
}

func testIdentity(t *testing.T, comment string) agentproto.Identity {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return agentproto.Identity{Blob: pk.Marshal(), Comment: comment}
}

const devDir = "/Applications/Xcode.app/Contents/Developer"

// gitLine is the one git command the checks run: --includes, because
// git's --global reader follows include.* and includeIf.* only when asked.
const gitLine = devDir + "/usr/bin/git config --global --includes --get-regexp " + gitKeys

// Milestone 7: `nazar status` checks the client side, in the CLI
// and read-only: how ssh would reach each host ~/.ssh/config names (and
// github.com), git's signing program and key, and the keys another agent
// on SSH_AUTH_SOCK holds. Each finding is one `setup:` line ending with
// its fix, and the `setup` field of the Status object with --json. All is
// well: no line and no field. nazar's own socket is never asked for its
// keys, and a check that cannot run is silence, never a failure.
func TestStatusChecksTheClientSide(t *testing.T) {
	h := newHarness(t)
	sock := defaultSock(h)
	h.serve(t, statusWith(sock))
	sshDir := filepath.Join(h.home, ".ssh")
	for _, d := range []string{filepath.Dir(sock), filepath.Join(sshDir, "conf.d"), filepath.Join(h.home, ".local", "bin")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(h.home, ".local", "bin", signGitName)
	if err := os.Symlink(h.app.CLI, link); err != nil {
		t.Fatal(err)
	}
	// Patterns and negations are not destinations; `Host=` is accepted; a
	// host may come from an Include; github.com is always asked about.
	writeFile(t, filepath.Join(sshDir, "config"), "Host github.com\n  IdentityAgent ~/.nazar/run/agent.sock\n\nHost *.example.com !bastion\n\nHost old\nHost=cm\nHost bare\nInclude conf.d/*\n")
	writeFile(t, filepath.Join(sshDir, "conf.d", "work"), "Host work\n")
	apple := filepath.Join(h.home, "apple.sock")
	h.env["SSH_AUTH_SOCK"] = apple
	conns := fakeAgent(t, apple, []agentproto.Identity{testIdentity(t, "old laptop key"), testIdentity(t, "")})
	h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\ngpg.ssh.program nazar-sign-git\nuser.signingkey ~/.nazar/keys/github.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", sock, "no", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- old":        sshGText("old", "", "yes", "false", "~/.nazar/keys/old.pub"),
		"/usr/bin/ssh -T -G -- cm":         sshGText("cm", sock, "yes", "auto", "~/.nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- bare":       sshGText("bare", sock, "no", "false", "~/.ssh/id_ed25519"),
		"/usr/bin/ssh -T -G -- work":       sshGText("work", "none", "no", "false", "~/.ssh/id_ed25519"),
	})
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	for _, want := range []string{
		// A host naming nazar's key needs only IdentitiesOnly; one naming
		// no key of nazar's needs the IdentityFile too, or IdentitiesOnly
		// alone would drop nazar's keys.
		"setup: warning: ~/.ssh/config: github.com goes through nazar without `IdentitiesOnly yes`, so ssh also offers every other key it finds, each with its own prompt; add `IdentitiesOnly yes` to its Host block\n",
		"setup: warning: ~/.ssh/config: bare goes through nazar without `IdentitiesOnly yes`, so ssh also offers every other key it finds, each with its own prompt; add `IdentityFile ~/.nazar/keys/<name>.pub` and `IdentitiesOnly yes` to its Host block\n",
		"setup: error: ~/.ssh/config: old names nazar's key old (IdentityFile) but ssh asks $SSH_AUTH_SOCK (" + apple + ") for it; add `IdentityAgent " + sock + "` to its Host block",
		"setup: warning: ~/.ssh/config: cm goes through nazar with ControlMaster auto",
		"set `ControlMaster no` for it",
		"setup: error: git config --global: git signs with nazar's key github but gpg.ssh.program is `nazar-sign-git`, a name found through $PATH",
		"set it with `git config --global gpg.ssh.program " + link + "`",
		"setup: warning: SSH_AUTH_SOCK: another agent at " + apple + " holds 2 key(s): ssh-ed25519 SHA256:",
		"(old laptop key)", "unload them with `ssh-add -D`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, " work ") || strings.Contains(out, "example.com") || strings.Contains(out, "bastion") {
		t.Errorf("a host that is not nazar's, or a pattern, was reported:\n%s", out)
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("the other agent got %d connections, want 1", n)
	}
	if code := h.run("--json", "status"); code != 0 {
		t.Fatal(code)
	}
	objs := jsonLines(t, h.out.String())
	setup, _ := objs[0]["setup"].([]any)
	if len(setup) != 6 {
		t.Fatalf("--json setup: %v", objs[0]["setup"])
	}
	if first, _ := setup[0].(map[string]any); first["severity"] != "warning" || first["path"] != "~/.ssh/config" || first["message"] == "" {
		t.Fatalf("--json setup[0]: %v", setup[0])
	}

	// All is well (every host of nazar's routed to it, IdentitiesOnly, no
	// ControlMaster, git's link and key, SSH_AUTH_SOCK nazar's own): no
	// line, no field, and nazar is never asked for its keys.
	nazar := fakeAgent(t, sock, []agentproto.Identity{testIdentity(t, "github")})
	h.env["SSH_AUTH_SOCK"] = sock
	h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\ngpg.ssh.program " + link + "\nuser.signingkey ~/.nazar/keys/github.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", sock, "yes", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- old":        sshGText("old", "none", "no", "auto", "~/.ssh/id_ed25519"),
		"/usr/bin/ssh -T -G -- cm":         sshGText("cm", "SSH_AUTH_SOCK", "yes", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- bare":       sshGText("bare", "none", "no", "false", "~/.ssh/id_ed25519"),
		"/usr/bin/ssh -T -G -- work":       sshGText("work", "none", "no", "false", "~/.ssh/id_ed25519"),
	})
	if code := h.run("status"); code != 0 || strings.Contains(h.out.String(), "setup:") {
		t.Fatalf("all well: exit %d\n%s", code, h.out)
	}
	if code := h.run("--json", "status"); code != 0 {
		t.Fatal(code)
	}
	if _, has := jsonLines(t, h.out.String())[0]["setup"]; has {
		t.Fatalf("all well: --json has a setup field:\n%s", h.out)
	}
	if n := nazar.Load(); n != 0 {
		t.Fatalf("nazar's own agent was asked for its keys %d time(s)", n)
	}

	// Nothing runs (no developer tools, ssh failing on the file): status
	// still exits 0, says once that ssh can't read the file, and nothing
	// about git. No git is ever run without a developer directory from
	// xcode-select (/usr/bin/git is the shim with the install dialog),
	// whether xcode-select fails or prints nothing.
	h.env["SSH_AUTH_SOCK"] = apple
	for _, xcode := range []map[string]string{{}, {"/usr/bin/xcode-select -p": "\n"}} {
		var ran []string
		h.a.output = recording(fakeOutput(t, xcode), &ran)
		if code := h.run("status"); code != 0 {
			t.Fatalf("exit %d %s", code, h.errb)
		}
		out = h.out.String()
		if n := strings.Count(out, "setup: error: ~/.ssh/config: ssh can't evaluate it"); n != 1 || strings.Contains(out, "git config") {
			t.Fatalf("failing programs:\n%s", out)
		}
		if !slices.Contains(ran, xcodeSelectExe) || slices.ContainsFunc(ran, func(p string) bool { return filepath.Base(p) == "git" }) {
			t.Fatalf("xcode-select %v: ran %v", xcode, ran)
		}
	}
	if n := conns.Load(); n != 4 {
		t.Errorf("the other agent got %d connections in all, want 4 (two in the first part, one per run here)", n)
	}

	// No runner (nothing to run with): no check, no line.
	h.a.output = nil
	if code := h.run("status"); code != 0 || strings.Contains(h.out.String(), "setup:") {
		t.Fatalf("no runner: exit %d\n%s", code, h.out)
	}
}

// git's program and key, the other direction: nazar's link with a key that
// is not nazar's; and git that signs with gpg, which is not nazar's
// business.
func TestStatusChecksGitTheOtherWay(t *testing.T) {
	h := newHarness(t)
	sock := defaultSock(h)
	h.serve(t, statusWith(sock))
	if err := os.MkdirAll(filepath.Join(h.home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(h.home, ".local", "bin", signGitName)
	if err := os.Symlink(h.app.CLI, link); err != nil {
		t.Fatal(err)
	}
	table := map[string]string{
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\ngpg.ssh.program " + link + "\nuser.signingkey ~/.ssh/id_ed25519.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", "", "no", "false", "~/.ssh/id_ed25519"),
	}
	h.a.output = fakeOutput(t, table)
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if out := h.out.String(); !strings.Contains(out, "setup: warning: git config --global: git signs through nazar but user.signingkey is `~/.ssh/id_ed25519.pub`, not a key in ~/.nazar/keys; set it with `git config --global user.signingkey ~/.nazar/keys/<name>.pub`") || strings.Count(out, "setup:") != 1 {
		t.Fatalf("other key:\n%s", out)
	}
	// An absolute program that is not named nazar-sign-git (ssh-keygen,
	// which signs against $SSH_AUTH_SOCK): git does not sign through nazar.
	other := filepath.Join(h.home, ".local", "bin", "ssh-keygen")
	writeFile(t, other, "#!/bin/sh\n")
	if err := os.Chmod(other, 0o700); err != nil {
		t.Fatal(err)
	}
	table[gitLine] = "gpg.format ssh\ngpg.ssh.program " + other + "\nuser.signingkey ~/.nazar/keys/github.pub\n"
	if code := h.run("status"); code != 0 {
		t.Fatal(code)
	}
	if out := h.out.String(); !strings.Contains(out, "setup: error: git config --global: git signs with nazar's key github but gpg.ssh.program is `"+other+"`, not a link named nazar-sign-git (git signs through nazar only by that name); set it with `git config --global gpg.ssh.program "+link+"`") {
		t.Fatalf("another program:\n%s", out)
	}
	// The link written as `~/.local/bin/nazar-sign-git` in the file: git
	// expands `~/` for this key (and for user.signingkey), so it is the
	// link, and all is well.
	table[gitLine] = "gpg.format ssh\ngpg.ssh.program ~/.local/bin/" + signGitName + "\nuser.signingkey ~/.nazar/keys/github.pub\n"
	if code := h.run("status"); code != 0 || strings.Contains(h.out.String(), "setup:") {
		t.Fatalf("program with ~/: exit %d\n%s", code, h.out)
	}
	// A dangling link (the app moved): the error names it and says to
	// run install again.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	table[gitLine] = "gpg.format ssh\ngpg.ssh.program " + link + "\nuser.signingkey ~/.nazar/keys/github.pub\n"
	if code := h.run("status"); code != 0 {
		t.Fatal(code)
	}
	// The fix is install (no link anywhere) or, on a Mac that has the cask's
	// link in Homebrew's bin, that link.
	if out := h.out.String(); !strings.Contains(out, "gpg.ssh.program is `"+link+"`, which doesn't exist or isn't executable") ||
		!(strings.Contains(out, "run `nazar install` (it makes the nazar-sign-git link)") || strings.Contains(out, "set it with `git config --global gpg.ssh.program /")) {
		t.Fatalf("dangling link:\n%s", out)
	}
	// gpg.format openpgp: git does not sign through ssh at all.
	table[gitLine] = "gpg.format openpgp\ngpg.ssh.program nazar-sign-git\nuser.signingkey ABCDEF\n"
	if code := h.run("status"); code != 0 || strings.Contains(h.out.String(), "git config") {
		t.Fatalf("openpgp: exit %d\n%s", code, h.out)
	}
}

// The budget spent while ssh runs (a slow `Match exec`, a loaded Mac) is
// silence: ssh killed is not a broken ~/.ssh/config. A later host ssh
// fails on is skipped, not reported as the file, and the hosts after it
// are still checked.
func TestStatusSetupBudgetIsSilence(t *testing.T) {
	h := newHarness(t)
	sock := defaultSock(h)
	ctx, spend := context.WithCancel(context.Background())
	h.a.output = func(context.Context, string, ...string) ([]byte, error) {
		spend() // the budget runs out while ssh runs; ssh is killed
		return nil, errors.New("signal: killed")
	}
	if found := h.a.setupChecks(ctx, sock); len(found) != 0 {
		t.Fatalf("budget spent: %+v", found)
	}

	h.serve(t, statusWith(sock))
	if err := os.MkdirAll(filepath.Join(h.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.home, ".ssh", "config"), "Host one\nHost two\n")
	h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/ssh -T -G -- one":        sshGText("one", "", "no", "false", "~/.ssh/id_ed25519"),
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", "none", "yes", "false", "~/.nazar/keys/github.pub"),
	})
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if out := h.out.String(); strings.Contains(out, "can't evaluate") || !strings.Contains(out, "setup: error: ~/.ssh/config: github.com names nazar's key github (IdentityFile) but ssh uses no agent for it") {
		t.Fatalf("a later host failing:\n%s", out)
	}
}

// ssh reads the account's ~/.ssh/config (getpwuid), not $HOME's. When
// $HOME is another folder (a test's world, `HOME=… nazar status`), ssh is
// never run: it would evaluate a config the CLI didn't read, run its
// `Match exec` commands, and the finding would mix the two homes. git and
// the other agent are still checked; an account home that can't be looked
// up is the same silence.
func TestStatusSSHChecksOnlyInTheAccountsHome(t *testing.T) {
	h := newHarness(t)
	sock := defaultSock(h)
	h.serve(t, statusWith(sock))
	if err := os.MkdirAll(filepath.Join(h.home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.home, ".ssh", "config"), "Host one\n")
	table := map[string]string{
		"/usr/bin/ssh -T -G -- one":        sshGText("one", "", "no", "false", "~/.nazar/keys/one.pub"),
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", "none", "yes", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\nuser.signingkey ~/.nazar/keys/github.pub\n",
	}
	other := t.TempDir()
	for _, account := range []string{other, ""} {
		h.a.accountHome = func() string { return account }
		var ran []string
		h.a.output = recording(fakeOutput(t, table), &ran)
		if code := h.run("status"); code != 0 {
			t.Fatalf("exit %d %s", code, h.errb)
		}
		out := h.out.String()
		if slices.Contains(ran, sshExe) || strings.Contains(out, sshConfigPath) {
			t.Fatalf("account home %q, HOME %q: ssh ran (%v):\n%s", account, h.home, ran, out)
		}
		if !strings.Contains(out, "setup: error: git config --global: git signs with nazar's key github") {
			t.Fatalf("account home %q: git not checked:\n%s", account, out)
		}
	}

	// $HOME is the account's home (here through a symlink): ssh is asked.
	link := filepath.Join(other, "home")
	if err := os.Symlink(h.home, link); err != nil {
		t.Fatal(err)
	}
	h.a.accountHome = func() string { return link }
	h.a.output = fakeOutput(t, table)
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	if out := h.out.String(); !strings.Contains(out, "setup: error: ~/.ssh/config: one names nazar's key one (IdentityFile)") {
		t.Fatalf("the account's home: ssh not checked:\n%s", out)
	}
}

// accountHome is the user database's, never $HOME: with HOME set
// elsewhere it still names the account's own folder.
func TestAccountHomeIsNotHOME(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	got := accountHome()
	if got == "" || !filepath.IsAbs(got) || samePath(got, os.Getenv("HOME")) {
		t.Fatalf("accountHome() = %q with HOME=%q", got, os.Getenv("HOME"))
	}
}

// Two spellings of one socket are one place: through a link, and through
// the APFS firmlink /System/Volumes/Data, which no symlink walk unifies.
func TestSamePathThroughLinksAndFirmlinks(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	writeFile(t, sock, "")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if !samePath(sock, filepath.Join(link, "agent.sock")) || samePath(sock, filepath.Join(dir, "other.sock")) {
		t.Fatal("samePath through a link")
	}
	real, err := filepath.EvalSymlinks(sock) // /var is a link to /private/var
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("/System/Volumes/Data" + real); err != nil {
		t.Skip("no /System/Volumes/Data firmlink")
	}
	if !samePath(sock, "/System/Volumes/Data"+real) {
		t.Fatal("samePath through the firmlink")
	}
}

// Every finding is printed through term: a key comment, an agent path or a
// git value with escape sequences is Go-quoted, and nothing non-printing
// reaches the terminal.
func TestStatusSetupEscapesHostileText(t *testing.T) {
	h := newHarness(t)
	sock := defaultSock(h)
	h.serve(t, statusWith(sock))
	apple := filepath.Join(h.home, "apple.sock")
	h.env["SSH_AUTH_SOCK"] = apple
	fakeAgent(t, apple, []agentproto.Identity{testIdentity(t, hostile)})
	h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\ngpg.ssh.program " + hostile + "\nuser.signingkey ~/.nazar/keys/github.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", hostile, "yes", "false", "~/.nazar/keys/github.pub"),
	})
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	assertEscaped(t, "setup findings", h, false)
	if n := strings.Count(h.out.String(), hostileEscaped); n != 3 {
		t.Fatalf("%d escaped values, want 3 (agent path, git program, key comment):\n%s", n, h.out)
	}
}

// The hosts asked about: literal names on Host lines, in file order, no
// duplicates, from the file and what it includes (globs, ~/, paths
// relative to ~/.ssh, bounded depth); never a pattern, a negation, a
// quoted phrase that is not a name, or anything ssh could read as an
// option.
func TestSSHConfigHosts(t *testing.T) {
	home := t.TempDir()
	d := filepath.Join(home, ".ssh", "conf.d")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".ssh", "config")
	writeFile(t, cfg, "# comment\nHost github.com GitHub.com gitlab.com\n  User git\nHost *.example.com !bastion ? \"a b\"\nHost \"quoted\"\nHost=eq\n\tHost my_server\nInclude conf.d/* ~/other missing-*\nMatch host nope\nHost -oProxyCommand=x --flag\n")
	writeFile(t, filepath.Join(d, "a"), "Host a1 a2\nInclude config\n") // a loop: bounded by depth
	writeFile(t, filepath.Join(home, "other"), "Host ok.host github.com\n")
	got := sshConfigHosts(cfg, home)
	want := []string{"github.com", "gitlab.com", "quoted", "eq", "my_server", "a1", "a2", "ok.host"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, h := range got {
		if !hostNameRE.MatchString(h) {
			t.Errorf("%q would be passed to ssh", h)
		}
	}
	if got := sshConfigHosts(filepath.Join(home, "none"), home); got != nil {
		t.Fatalf("missing file: %v", got)
	}
	var many strings.Builder
	for i := 0; i < 2*maxSetupHosts; i++ {
		fmt.Fprintf(&many, "Host h%d\n", i)
	}
	writeFile(t, cfg, many.String())
	if got := sshConfigHosts(cfg, home); len(got) != maxSetupHosts || got[0] != "h0" {
		t.Fatalf("cap: %d hosts, first %v", len(got), got[:1])
	}
}

// A command ssh starts for `Match exec` keeps ssh's stderr open: the
// runner still returns soon after the budget, not when that command ends.
func TestRunOutputStopsAtTheBudget(t *testing.T) {
	if _, err := os.Stat(sshExe); err != nil {
		t.Skip("no /usr/bin/ssh")
	}
	cfg := filepath.Join(t.TempDir(), "config")
	writeFile(t, cfg, "Match exec \"/bin/sleep 2\"\n  User x\n")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runOutput(ctx, sshExe, "-T", "-G", "-F", cfg, "--", "one")
	// ~400 ms (the budget, then WaitDelay); the bound leaves room for a
	// loaded Mac, and the stray sleep is gone within 2 s either way.
	if d := time.Since(start); err == nil || d > 1500*time.Millisecond {
		t.Fatalf("returned after %v (%v), want an error well before the command's 2 s", d, err)
	}
}

// A setting in a file the global config includes (`[include] path = …`,
// a common dotfiles layout) is git's setting too: the real git under the
// developer directory reads it through gitConfigArgs. Scratch files only:
// GIT_CONFIG_GLOBAL names the file, so no gitconfig of the user's is read.
func TestGitConfigArgsFollowIncludes(t *testing.T) {
	dev, err := runOutput(context.Background(), xcodeSelectExe, "-p")
	if err != nil || strings.TrimSpace(string(dev)) == "" {
		t.Skip("no developer tools")
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "local"), "[gpg \"ssh\"]\n\tprogram = /x/nazar-sign-git\n")
	writeFile(t, filepath.Join(dir, "gitconfig"), "[gpg]\n\tformat = ssh\n[include]\n\tpath = "+filepath.Join(dir, "local")+"\n")
	t.Setenv("HOME", dir)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(dir, "gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	git := filepath.Join(strings.TrimSpace(string(dev)), "usr", "bin", "git")
	out, err := runOutput(context.Background(), git, gitConfigArgs...)
	if err != nil || !strings.Contains(string(out), "gpg.ssh.program /x/nazar-sign-git\n") {
		t.Fatalf("got %q (%v); want the included gpg.ssh.program", out, err)
	}
}

// What the checks parse is ssh's own answer: the real /usr/bin/ssh on a
// config of its own (-F: no file of the user's is read; -G: nothing
// connects; -T: no pty, so no stderr noise) through the production
// runner, parsed by parseSSHG.
func TestSSHGParsesTheRealSSH(t *testing.T) {
	if _, err := os.Stat(sshExe); err != nil {
		t.Skip("no /usr/bin/ssh")
	}
	cfg := filepath.Join(t.TempDir(), "config")
	writeFile(t, cfg, "Host one\n  IdentityAgent ~/.nazar/run/agent.sock\n  IdentitiesOnly yes\n  ControlMaster auto\n  IdentityFile ~/.nazar/keys/one.pub\nHost two\n  IdentityAgent SSH_AUTH_SOCK\nHost three\n  IdentityAgent none\n")
	ctx := context.Background()
	out, err := runOutput(ctx, sshExe, "-T", "-G", "-F", cfg, "--", "one")
	if err != nil {
		t.Fatal(err)
	}
	g := parseSSHG(out)
	if !strings.HasSuffix(g.first("identityagent"), "/.nazar/run/agent.sock") || g.first("identitiesonly") != "yes" || g.first("controlmaster") != "auto" ||
		!slices.Contains(g["identityfile"], "~/.nazar/keys/one.pub") || g.first("hostname") != "one" {
		t.Fatalf("one: %v", g)
	}
	for host, want := range map[string]string{"two": "SSH_AUTH_SOCK", "three": "none"} {
		out, err := runOutput(ctx, sshExe, "-T", "-G", "-F", cfg, "--", host)
		if err != nil {
			t.Fatal(err)
		}
		if g := parseSSHG(out); g.first("identityagent") != want || g.first("controlmaster") != "false" {
			t.Fatalf("%s: %v", host, g)
		}
	}
	// A host nothing configures: no identityagent line at all.
	out, err = runOutput(ctx, sshExe, "-T", "-G", "-F", cfg, "--", "four")
	if err != nil {
		t.Fatal(err)
	}
	if g := parseSSHG(out); g.first("identityagent") != "" || g.first("identitiesonly") != "no" {
		t.Fatalf("four: %v", g)
	}
	// A name ssh refuses is an error carrying ssh's words, not an answer.
	if _, err := runOutput(ctx, sshExe, "-T", "-G", "-F", cfg, "--", "-oProxyCommand=x"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("option as host: %v", err)
	}
}

// The layout before ~/.nazar/{config,keys,run}: an IdentityAgent, an
// IdentityFile, git's user.signingkey and SSH_AUTH_SOCK that still name
// ~/.nazar/agent.sock or ~/.config/nazar/keys each get the exact line that
// replaces them, once per line (with its hosts), and nothing else is said
// about them. A ~/.config/nazar left behind is named too. status writes
// none of these files.
func TestStatusNamesTheOldLayout(t *testing.T) {
	h := newHarness(t)
	sock := defaultSock(h)
	h.serve(t, statusWith(sock))
	for _, d := range []string{filepath.Join(h.home, ".ssh"), filepath.Join(h.home, ".local", "bin"), filepath.Join(layout.OldConfigDir(h.home), "keys")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(h.home, ".local", "bin", signGitName)
	if err := os.Symlink(h.app.CLI, link); err != nil {
		t.Fatal(err)
	}
	sshConfig := "Host github.com work\n  IdentityAgent ~/.nazar/agent.sock\n  IdentityFile ~/.config/nazar/keys/github.pub\n  IdentitiesOnly yes\nHost plain\n"
	writeFile(t, filepath.Join(h.home, ".ssh", "config"), sshConfig)
	writeFile(t, filepath.Join(layout.OldConfigDir(h.home), "keys", "github.pub"), "ecdsa github\n")
	old := filepath.Join(h.home, ".nazar", "agent.sock")
	h.env["SSH_AUTH_SOCK"] = old
	h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\ngpg.ssh.program " + link + "\nuser.signingkey ~/.config/nazar/keys/github.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", old, "yes", "false", "~/.config/nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- work":       sshGText("work", old, "yes", "false", "~/.config/nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- plain":      sshGText("plain", "", "yes", "false", "~/.nazar/keys/github.pub"),
	})
	if code := h.run("status"); code != 0 {
		t.Fatalf("exit %d %s", code, h.errb)
	}
	out := h.out.String()
	want := []string{
		"setup: error: ~/.ssh/config: `IdentityAgent ~/.nazar/agent.sock` (github.com, work) is nazar's old socket; replace it with `IdentityAgent ~/.nazar/run/agent.sock`\n",
		"setup: error: ~/.ssh/config: `IdentityFile ~/.config/nazar/keys/github.pub` (github.com, work) is nazar's key github at its old path; replace it with `IdentityFile ~/.nazar/keys/github.pub`\n",
		"setup: error: git config --global: user.signingkey `~/.config/nazar/keys/github.pub` is nazar's key github at its old path; set it with `git config --global user.signingkey ~/.nazar/keys/github.pub`\n",
		"setup: error: SSH_AUTH_SOCK: " + old + " is nazar's old socket; where you set it, replace it with `export SSH_AUTH_SOCK=$HOME/.nazar/run/agent.sock`\n",
		"setup: warning: ~/.config/nazar: nazar no longer reads it: its files are in ~/.nazar now, and what is left here was not moved; compare it with ~/.nazar and remove it\n",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("status lacks %q:\n%s", w, out)
		}
	}
	if n := strings.Count(out, "setup:"); n != len(want) {
		t.Errorf("%d setup lines, want %d:\n%s", n, len(want), out)
	}
	if b, err := os.ReadFile(filepath.Join(h.home, ".ssh", "config")); err != nil || string(b) != sshConfig {
		t.Errorf("~/.ssh/config changed: %q %v", b, err)
	}

	// All moved: no line about the old layout.
	if err := os.RemoveAll(layout.OldConfigDir(h.home)); err != nil {
		t.Fatal(err)
	}
	h.env["SSH_AUTH_SOCK"] = sock
	h.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/xcode-select -p":         devDir + "\n",
		gitLine:                            "gpg.format ssh\ngpg.ssh.program " + link + "\nuser.signingkey ~/.nazar/keys/github.pub\n",
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", sock, "yes", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- work":       sshGText("work", sock, "yes", "false", "~/.nazar/keys/github.pub"),
		"/usr/bin/ssh -T -G -- plain":      sshGText("plain", "", "yes", "false", "~/.nazar/keys/github.pub"),
	})
	if code := h.run("status"); code != 0 || strings.Contains(h.out.String(), "setup:") {
		t.Fatalf("all moved: exit %d\n%s", code, h.out)
	}

	// A config that still sets ssh_agent.socket: ~/.nazar/agent.sock keeps
	// that socket: it is nazar's, not an old one.
	h2 := newHarness(t)
	old2 := filepath.Join(h2.home, ".nazar", "agent.sock")
	h2.serve(t, statusWith(old2))
	h2.env["SSH_AUTH_SOCK"] = old2
	h2.a.output = fakeOutput(t, map[string]string{
		"/usr/bin/ssh -T -G -- github.com": sshGText("github.com", old2, "yes", "false", "~/.nazar/keys/github.pub"),
	})
	if code := h2.run("status"); code != 0 || strings.Contains(h2.out.String(), "setup:") {
		t.Fatalf("socket set to the old path: exit %d\n%s", code, h2.out)
	}
}
