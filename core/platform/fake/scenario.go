package fake

import "github.com/atas/nazar/core/platform"

// Well-known identities used across tests (values from spec 4.2 and spike S3).
var (
	ITermCode  = platform.CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D", SigningID: "com.googlecode.iterm2", CDHash: []byte{0x17}}
	ClaudeCode = platform.CodeIdentity{Signed: true, TeamID: "Q6L2SF6YDW", SigningID: "com.anthropic.claude-code", CDHash: []byte{0xc1}}
	AppleCode  = func(id string) platform.CodeIdentity {
		return platform.CodeIdentity{Signed: true, Apple: true, SigningID: id, CDHash: []byte(id)}
	}
	Unsigned = platform.CodeIdentity{}
)

// Chain is the shape spike S3 observed for a command in an iTerm2 tab:
// iTerm2 → iTermServer → /usr/bin/login (root) → bash (login shell) → extra
// processes (outermost first).
type Chain struct {
	App, Server, Login, Shell platform.ProcessRef
	Procs                     []platform.ProcessRef // extra processes, outermost first
}

// Peer is the innermost process.
func (c Chain) Peer() platform.ProcessRef {
	if len(c.Procs) == 0 {
		return c.Shell
	}
	return c.Procs[len(c.Procs)-1]
}

// ITermTab launches a fresh iTerm-style tab (reusing app when non-zero) and
// then extra processes under its shell, each a child of the previous one.
func (f *Fake) ITermTab(app platform.ProcessRef, extra ...Proc) Chain {
	if app.IsZero() {
		app = f.Launch(platform.ProcessRef{}, Proc{
			Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: ITermCode,
			App: &App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
		})
	}
	c := Chain{App: app}
	c.Server = f.Launch(app, Proc{Path: "/Applications/iTerm.app/Contents/MacOS/iTermServer-3.6", Code: ITermCode})
	c.Login = f.Launch(c.Server, Proc{Path: "/usr/bin/login", Root: true, Code: AppleCode("com.apple.login")})
	c.Shell = f.Launch(c.Login, Proc{Path: "/bin/bash", Args: []string{"-bash"}, Cwd: "/Users/u/projects/foo", Code: AppleCode("com.apple.bash")})
	parent := c.Shell
	for _, p := range extra {
		parent = f.Launch(parent, p)
		c.Procs = append(c.Procs, parent)
	}
	return c
}

// SSHProc is Apple's /usr/bin/ssh as a peer.
func SSHProc(args ...string) Proc {
	return Proc{Path: "/usr/bin/ssh", Args: append([]string{"ssh"}, args...), Cwd: "/Users/u/projects/foo", Code: AppleCode("com.apple.openssh")}
}

// ClaudeProc is Claude Code's CLI.
func ClaudeProc() Proc {
	return Proc{Path: "/Users/u/.local/bin/claude", Args: []string{"claude"}, Code: ClaudeCode}
}

// GitProc is Apple's git, a step between a tool and ssh.
func GitProc(args ...string) Proc {
	return Proc{Path: "/usr/bin/git", Args: append([]string{"git"}, args...), Cwd: "/Users/u/projects/foo", Code: AppleCode("com.apple.git")}
}

// OrphanedITermTab is a tab nazar-agent never saw below its iTerm2: the tab
// was opened and iTerm2 updated and restarted before anything in the tab
// used the agent. Its server (iTermServer copied to Application Support,
// signed by iTerm2's team) is parented by launchd and answers for itself,
// and a new iTerm2 runs. Server is the orphaned helper, App the new iTerm2;
// extra runs under the tab's login shell as in ITermTab. No Resolver saw the
// server below an app, so the chain is unknown (THREAT-MODEL 5.14).
func (f *Fake) OrphanedITermTab(extra ...Proc) Chain {
	old := f.Launch(platform.ProcessRef{}, Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: ITermCode,
		App: &App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	var c Chain
	c.Server = f.Launch(old, Proc{
		Path: "/Users/u/Library/Application Support/iTerm2/iTermServer-3.7.4",
		Code: platform.CodeIdentity{Signed: true, TeamID: "H7V7XYVQ7D", SigningID: "iTermServer", CDHash: []byte{0x5e}},
	})
	c.Login = f.Launch(c.Server, Proc{Path: "/usr/bin/login", Root: true, Code: AppleCode("com.apple.login")})
	c.Shell = f.Launch(c.Login, Proc{Path: "/bin/bash", Args: []string{"-bash"}, Cwd: "/Users/u/projects/foo", Code: AppleCode("com.apple.bash")})
	parent := c.Shell
	for _, p := range extra {
		parent = f.Launch(parent, p)
		c.Procs = append(c.Procs, parent)
	}
	f.Exit(old) // the update restarted iTerm2: the server is re-parented to launchd
	c.App = f.Launch(platform.ProcessRef{}, Proc{
		Path: "/Applications/iTerm.app/Contents/MacOS/iTerm2", Code: ITermCode,
		App: &App{BundleID: "com.googlecode.iterm2", Name: "iTerm2"},
	})
	return c
}

// OrphanedClaudeTab is Claude Code in an orphaned iTerm2 tab:
// iTermServer-3.7.4 (orphaned, never seen) > login > bash > claude > bash >
// git > ssh. Procs[0] is claude; the peer is ssh.
func (f *Fake) OrphanedClaudeTab() Chain {
	bash := Proc{Path: "/bin/bash", Args: []string{"bash", "-c", "git fetch"}, Cwd: "/Users/u/projects/foo", Code: AppleCode("com.apple.bash")}
	return f.OrphanedITermTab(ClaudeProc(), bash, GitProc("fetch"), SSHProc("git@github.com"))
}
