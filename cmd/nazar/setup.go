package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/ssh/agentproto"
)

// The programs the client-side checks run, by absolute path, never via
// $PATH. git is run under the developer directory xcode-select names:
// /usr/bin/git is Apple's shim, which puts the "install the command line
// developer tools" dialog on the screen when none is installed.
const (
	sshExe         = "/usr/bin/ssh"
	xcodeSelectExe = "/usr/bin/xcode-select"
)

// setupTimeout bounds all the client-side checks of one `nazar status`: a
// stalled `Match exec` in ~/.ssh/config or a hung agent must not hang
// status, a script or the window's stream. Past it, what is left is
// skipped.
const setupTimeout = 3 * time.Second

// maxSetupHosts caps how many hosts ssh is asked about.
const maxSetupHosts = 32

// hostNameRE is what ssh -G may be asked about: a literal host name, never
// a pattern (`*`, `?`, `!`) and never anything ssh could read as an
// option (ssh itself refuses other characters: "hostname contains invalid
// characters").
var hostNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)

// gitKeys are the global git settings the signing check reads, and the
// only ones: nothing else of git's config is read into the CLI.
const gitKeys = `^(gpg\.format|gpg\.ssh\.program|user\.signingkey)$`

// gitConfigArgs read them as git itself does: with --includes, since the
// --global reader follows include.* and includeIf.* only when asked.
var gitConfigArgs = []string{"config", "--global", "--includes", "--get-regexp", gitKeys}

// Where each finding is, for the `setup:` line and the JSON path field.
const (
	sshConfigPath = "~/.ssh/config"
	gitConfigPath = "git config --global"
	keysDirTilde  = layout.KeysDirTilde
)

// runOutput runs argv0 with the CLI's environment and returns its stdout;
// stdin is /dev/null, and the first line of stderr goes into the error.
// Once ctx is done the program is killed and its pipes are closed soon
// after (WaitDelay): a command ssh started for `Match exec` keeps ssh's
// stderr open, and must not hold status past the budget.
func runOutput(ctx context.Context, argv0 string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv0, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if msg, _, _ := strings.Cut(strings.TrimSpace(string(ee.Stderr)), "\n"); msg != "" {
			return out, fmt.Errorf("%v: %s", err, msg)
		}
	}
	return out, err
}

// accountHome is the home directory the user database has for this
// account: the one ssh reads ~/.ssh/config from (getpwuid, never $HOME);
// "" when it can't be looked up. LookupId, not Current: Current may fall
// back to $HOME.
func accountHome() string {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return ""
	}
	return u.HomeDir
}

// setup is the client side of one `nazar status`: how ssh would
// reach each host ~/.ssh/config names, git's signing program and key, and
// the keys another agent holds. Everything is read; nothing is written
// (THREAT-MODEL 5.15).
type setup struct {
	a     *app
	ctx   context.Context
	sock  string // nazar's agent socket, as nazar-agent reported it
	found []control.ConfigProblem
}

// setupChecks returns what is wrong on the client side, each finding
// ending with its fix; nil when all is well, or when the checks cannot run
// (no runner, no absolute socket path). They never fail status.
func (a *app) setupChecks(ctx context.Context, sock string) []control.ConfigProblem {
	if a.output == nil || !filepath.IsAbs(sock) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	s := &setup{a: a, ctx: ctx, sock: sock}
	s.sshHosts()
	s.git()
	s.otherAgent()
	s.oldFolder()
	return s.found
}

func (s *setup) add(sev config.Severity, path, format string, args ...any) {
	s.found = append(s.found, control.ConfigProblem{Severity: string(sev), Path: path, Message: fmt.Sprintf(format, args...)})
}

// sshHosts asks ssh how it would connect to every host ~/.ssh/config
// names literally, and to github.com (`ssh -G`: the config evaluated,
// nothing connects), and reports the hosts that are nazar's but not wired
// right. A host is nazar's when ssh would ask nazar's socket for it, or
// when one of its IdentityFiles is a key of nazar's. ssh reads the
// account's ~/.ssh/config, not $HOME's: when $HOME is another folder (a
// test's world, another user's environment) ssh is not run at all, so
// nothing of that config is evaluated and nothing mixed up is said.
func (s *setup) sshHosts() {
	if s.a.accountHome == nil || !samePath(s.a.accountHome(), s.a.home()) {
		return
	}
	hosts := sshConfigHosts(filepath.Join(s.a.home(), ".ssh", "config"), s.a.home())
	if !slices.Contains(hosts, "github.com") {
		hosts = append(hosts, "github.com")
	}
	env := s.a.getenv("SSH_AUTH_SOCK")
	// Lines that still name the layout before ~/.nazar/{config,keys,run}:
	// one finding per line, naming its hosts.
	var old oldLines
	defer func() {
		for _, l := range old {
			s.add(config.SevError, sshConfigPath, "`%s` (%s) is %s; replace it with `%s`", l.line, strings.Join(l.hosts, ", "), l.what, l.fix)
		}
	}()
	for i, h := range hosts {
		if s.ctx.Err() != nil {
			return
		}
		out, err := s.a.output(s.ctx, sshExe, "-T", "-G", "--", h)
		if err != nil {
			// Only ssh failing on the first host, within the budget, is the
			// file; ssh killed at the budget, or one later host, is not.
			if i == 0 && s.ctx.Err() == nil {
				s.add(config.SevError, sshConfigPath, "ssh can't evaluate it (%v); until it can, ssh and git fail for every host", err)
				return
			}
			continue
		}
		g := parseSSHG(out)
		agent := g.first("identityagent")
		viaEnv := agent == "" || agent == "SSH_AUTH_SOCK"
		viaNazar := samePath(agent, s.sock) || (viaEnv && samePath(env, s.sock))
		if !viaNazar && s.oldSock(agent) {
			old.add("IdentityAgent "+s.short(agent), h, "nazar's old socket", "IdentityAgent "+s.short(s.sock))
			viaNazar = true
		}
		viaNazar = viaNazar || (viaEnv && s.oldSock(env) && !samePath(env, s.sock)) // otherAgent says it
		var key string
		for _, f := range g["identityfile"] {
			if n, ok := s.nazarKey(f); ok {
				key = n
				break
			}
			if n, ok := s.oldKey(f); ok {
				old.add("IdentityFile "+f, h, "nazar's key "+n+" at its old path", "IdentityFile "+keysDirTilde+"/"+n+".pub")
				key = n
				break
			}
		}
		switch {
		case key != "" && !viaNazar:
			s.add(config.SevError, sshConfigPath, "%s names nazar's key %s (IdentityFile) but %s; add `IdentityAgent %s` to its Host block", h, key, agentWords(agent, env), s.sock)
		case viaNazar && g.first("identitiesonly") != "yes":
			// IdentitiesOnly limits ssh to the key files it is configured
			// with: alone, on a host naming no key of nazar's, it would
			// drop nazar's keys (ssh_config(5)).
			fix := "add `IdentitiesOnly yes` to its Host block"
			if key == "" {
				fix = "add `IdentityFile " + keysDirTilde + "/<name>.pub` and `IdentitiesOnly yes` to its Host block"
			}
			s.add(config.SevWarning, sshConfigPath, "%s goes through nazar without `IdentitiesOnly yes`, so ssh also offers every other key it finds, each with its own prompt; %s", h, fix)
		}
		if cm := g.first("controlmaster"); viaNazar && cm != "" && cm != "false" {
			s.add(config.SevWarning, sshConfigPath, "%s goes through nazar with ControlMaster %s: the shared connection detaches from your terminal, so later uses have no app and none of the programs you ran in their chain, and match only any/unknown rules or a rule for ssh itself; set `ControlMaster no` for it", h, cm)
		}
	}
}

// agentWords says which agent ssh would ask for a host's keys instead of
// nazar, from ssh's identityagent value and $SSH_AUTH_SOCK.
func agentWords(agent, env string) string {
	switch {
	case agent == "none":
		return "ssh uses no agent for it"
	case agent == "" || agent == "SSH_AUTH_SOCK":
		if env == "" {
			return "ssh has no agent for it (SSH_AUTH_SOCK is not set)"
		}
		return "ssh asks $SSH_AUTH_SOCK (" + env + ") for it"
	}
	return "ssh asks the agent at " + agent + " for it"
}

// sshConfigHosts returns the host names ~/.ssh/config, and the files its
// Include lines name, give literally on Host lines, in file order and
// without duplicates, at most maxSetupHosts. Patterns (`*`, `?`, `!`) and
// anything ssh could read as an option are left out: they are not
// destinations ssh -G can be asked about. Includes are globs, `~/` or
// relative to ~/.ssh, followed three levels deep; a missing file is no
// hosts.
func sshConfigHosts(path, home string) []string {
	var hosts []string
	seen := map[string]bool{}
	var walk func(p string, depth int)
	walk = func(p string, depth int) {
		b, err := os.ReadFile(p)
		if err != nil || depth > 3 {
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			// `Keyword value…` or `Keyword=value…` (ssh_config(5)).
			line = strings.TrimSpace(line)
			i := strings.IndexAny(line, " \t=")
			if i < 0 || strings.HasPrefix(line, "#") {
				continue
			}
			kw, args := strings.ToLower(line[:i]), strings.Fields(strings.TrimLeft(line[i:], " \t="))
			switch kw {
			case "host":
				for _, h := range args {
					if h, ok := unquoted(h); ok && hostNameRE.MatchString(h) && !seen[strings.ToLower(h)] && len(hosts) < maxSetupHosts {
						seen[strings.ToLower(h)] = true
						hosts = append(hosts, h)
					}
				}
			case "include":
				for _, inc := range args {
					inc, ok := unquoted(inc)
					if !ok {
						continue
					}
					if strings.HasPrefix(inc, "~/") {
						inc = filepath.Join(home, inc[2:])
					} else if !filepath.IsAbs(inc) {
						inc = filepath.Join(home, ".ssh", inc)
					}
					matches, _ := filepath.Glob(inc)
					for _, m := range matches {
						walk(m, depth+1)
					}
				}
			}
		}
	}
	walk(path, 0)
	return hosts
}

// unquoted strips one pair of double quotes; a token that is part of a
// quoted phrase (`"a b"` split on spaces) is not a name and is dropped.
func unquoted(tok string) (string, bool) {
	if !strings.Contains(tok, `"`) {
		return tok, true
	}
	if len(tok) >= 2 && tok[0] == '"' && tok[len(tok)-1] == '"' {
		return tok[1 : len(tok)-1], true
	}
	return "", false
}

// sshG is what `ssh -G` printed: one lowercase keyword per line, its value
// after the first space; a keyword printed several times (identityfile)
// keeps every value in order.
type sshG map[string][]string

func parseSSHG(out []byte) sshG {
	g := sshG{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok {
			g[k] = append(g[k], v)
		}
	}
	return g
}

func (g sshG) first(k string) string {
	if v := g[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// samePath reports whether two paths name the same place: equal once
// cleaned, or the same file (os.SameFile: through links, and through the
// APFS firmlink /System/Volumes/Data, which no symlink walk unifies).
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

// tilde expands a leading `~/` as ssh does for IdentityFile and git for
// user.signingkey and gpg.ssh.program.
func (s *setup) tilde(p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(s.a.home(), p[2:])
	}
	return p
}

// nazarKey reports whether an IdentityFile or user.signingkey value names
// a key of nazar's (a file in ~/.nazar/keys, the folder nazar-agent
// writes the public keys to), and which.
func (s *setup) nazarKey(p string) (string, bool) {
	return keyIn(s.tilde(p), layout.KeysDir(s.a.home()))
}

// oldKey is nazarKey for ~/.config/nazar/keys, the folder of the keys
// before ~/.nazar/keys.
func (s *setup) oldKey(p string) (string, bool) {
	return keyIn(s.tilde(p), filepath.Join(layout.OldConfigDir(s.a.home()), "keys"))
}

func keyIn(p, dir string) (string, bool) {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) || filepath.Dir(p) != dir {
		return "", false
	}
	return strings.TrimSuffix(filepath.Base(p), ".pub"), true
}

// oldSock reports whether p is ~/.nazar/agent.sock, the agent socket before
// ~/.nazar/run.
func (s *setup) oldSock(p string) bool {
	return p != "" && filepath.Clean(s.tilde(p)) == filepath.Join(layout.Root(s.a.home()), "agent.sock")
}

// short writes a path in the home as ~/..., as the files status points at
// spell it.
func (s *setup) short(p string) string {
	if rel, ok := strings.CutPrefix(p, s.a.home()+"/"); ok {
		return "~/" + rel
	}
	return p
}

// oldLines are the lines of ~/.ssh/config that name the old layout, each
// with the hosts it is used for, in the order they were found.
type oldLines []*oldLine

type oldLine struct {
	line, what, fix string
	hosts           []string
}

func (o *oldLines) add(line, host, what, fix string) {
	for _, l := range *o {
		if l.line == line {
			l.hosts = append(l.hosts, host)
			return
		}
	}
	*o = append(*o, &oldLine{line: line, what: what, fix: fix, hosts: []string{host}})
}

// oldFolder says that ~/.config/nazar is still there: nazar-agent moves
// its files into ~/.nazar at start (layout.Migrate), so what is left was
// not moved (a clash, a link) and nazar no longer reads it.
func (s *setup) oldFolder() {
	if _, err := os.Lstat(layout.OldConfigDir(s.a.home())); err == nil {
		s.add(config.SevWarning, "~/.config/nazar", "nazar no longer reads it: its files are in ~/.nazar now, and what is left here was not moved; compare it with ~/.nazar and remove it")
	}
}

// git checks that git signs through nazar when it signs with a key of
// nazar's, and with a key of nazar's when it signs through nazar. Nothing
// is said when git does not sign through ssh at all (gpg.format), or when
// no developer tools are installed, or when git has none of the three
// settings (--get-regexp exits 1).
func (s *setup) git() {
	dev, err := s.a.output(s.ctx, xcodeSelectExe, "-p")
	if err != nil || strings.TrimSpace(string(dev)) == "" {
		return
	}
	git := filepath.Join(strings.TrimSpace(string(dev)), "usr", "bin", "git")
	out, err := s.a.output(s.ctx, git, gitConfigArgs...)
	if err != nil {
		return
	}
	v := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, val, ok := strings.Cut(line, " "); ok {
			v[k] = val
		}
	}
	if v["gpg.format"] != "ssh" {
		return
	}
	program := s.tilde(v["gpg.ssh.program"])
	key, keyIsNazar := s.nazarKey(v["user.signingkey"])
	if n, ok := s.oldKey(v["user.signingkey"]); ok {
		s.add(config.SevError, gitConfigPath, "user.signingkey `%s` is nazar's key %s at its old path; set it with `git config --global user.signingkey %s/%s.pub`", v["user.signingkey"], n, keysDirTilde, n)
		key, keyIsNazar = n, true
	}
	programOK := filepath.IsAbs(program) && filepath.Base(program) == signGitName && isExecutable(program)
	switch {
	case keyIsNazar && !programOK:
		s.add(config.SevError, gitConfigPath, "git signs with nazar's key %s but gpg.ssh.program %s; %s", key, programWords(program), s.programFix())
	case programOK && !keyIsNazar:
		have := "not set"
		if k := v["user.signingkey"]; k != "" {
			have = "`" + k + "`"
		}
		s.add(config.SevWarning, gitConfigPath, "git signs through nazar but user.signingkey is %s, not a key in %s; set it with `git config --global user.signingkey %s/<name>.pub`", have, keysDirTilde, keysDirTilde)
	}
}

// programWords says what is wrong with gpg.ssh.program.
func programWords(p string) string {
	switch {
	case p == "":
		return "is not set, so git runs ssh-keygen against $SSH_AUTH_SOCK, not nazar"
	case !filepath.IsAbs(p):
		return "is `" + p + "`, a name found through $PATH, which anything running as you can change"
	case filepath.Base(p) != signGitName:
		return "is `" + p + "`, not a link named " + signGitName + " (git signs through nazar only by that name)"
	}
	return "is `" + p + "`, which doesn't exist or isn't executable (a dangling link after a move?)"
}

// brewBinDirs are Homebrew's link folders (Apple silicon, Intel), where the
// cask links nazar-sign-git. A variable so tests never read this Mac's.
var brewBinDirs = []string{"/opt/homebrew/bin", "/usr/local/bin"}

// programFix is the setting to make: the nazar-sign-git link install made,
// in the folder this CLI links into or Homebrew's; else install first.
func (s *setup) programFix() string {
	for _, dir := range append([]string{s.a.defaultBinDir()}, brewBinDirs...) {
		if l := filepath.Join(dir, signGitName); isExecutable(l) {
			return "set it with `git config --global gpg.ssh.program " + l + "`"
		}
	}
	return "run `nazar install` (it makes the " + signGitName + " link), then set it with `git config --global gpg.ssh.program <that link>`"
}

// isExecutable: a regular file (through any link) with an execute bit.
func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// otherAgent names the keys the agent $SSH_AUTH_SOCK points at holds, when
// that agent is not nazar: ssh uses them for every host without an
// IdentityAgent, under no rule of nazar's. nazar's own socket is never
// asked: there the CLI is a caller like any other, and a caller offered
// nothing is reported as blocked, with the warning window (spec 5), which
// status must not cause. A socket that does not answer is silence.
func (s *setup) otherAgent() {
	path := s.a.getenv("SSH_AUTH_SOCK")
	if path == "" || samePath(path, s.sock) {
		return
	}
	if s.oldSock(path) {
		sock := s.sock
		if rel, ok := strings.CutPrefix(sock, s.a.home()+"/"); ok {
			sock = "$HOME/" + rel
		}
		s.add(config.SevError, "SSH_AUTH_SOCK", "%s is nazar's old socket; where you set it, replace it with `export SSH_AUTH_SOCK=%s`", path, sock)
		return
	}
	ids, err := listIdentities(s.ctx, path)
	if err != nil || len(ids) == 0 {
		return
	}
	var names []string
	for i, id := range ids {
		if i == 3 {
			names = append(names, fmt.Sprintf("and %d more", len(ids)-3))
			break
		}
		names = append(names, describeKey(id))
	}
	s.add(config.SevWarning, "SSH_AUTH_SOCK", "another agent at %s holds %d key(s): %s; ssh uses them for every host without `IdentityAgent`, outside nazar's rules; unload them with `ssh-add -D`, or keep them knowingly", path, len(ids), strings.Join(names, ", "))
}

// listIdentities asks the agent at path which keys it holds: one
// REQUEST_IDENTITIES, one bounded reply.
func listIdentities(ctx context.Context, path string) ([]agentproto.Identity, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := agentproto.WriteMessage(c, []byte{agentproto.MsgRequestIdentities}); err != nil {
		return nil, err
	}
	body, err := agentproto.ReadMessage(c)
	if err != nil {
		return nil, err
	}
	return agentproto.ParseIdentities(body)
}

// describeKey names one key of another agent: type and fingerprint, and
// its comment (untrusted text; the whole message goes through term).
func describeKey(id agentproto.Identity) string {
	pk, err := ssh.ParsePublicKey(id.Blob)
	if err != nil {
		return "an unreadable key (" + id.Comment + ")"
	}
	s := pk.Type() + " " + ssh.FingerprintSHA256(pk)
	if id.Comment != "" {
		s += " (" + id.Comment + ")"
	}
	return s
}
