//go:build integration

package integration

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// gitWorld is a world with key gitsign (dialog for iTerm, session scope)
// and an empty repo. git ignores the user's global and system config.
type gitWorld struct {
	*world
	pub  string
	repo string
}

func newGitWorld(t *testing.T) *gitWorld {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	w := newWorld(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`)
	pub := w.createKey("gitsign")
	w.approveConfig(strings.Replace(itermRule, "itest:", "gitsign:", 1))
	g := &gitWorld{world: w, pub: pub, repo: filepath.Join(w.home, "repo")}
	if out, code := w.run(nil, "git", "init", "-q", g.repo); code != 0 {
		t.Fatalf("git init: %d %s", code, out)
	}
	return g
}

// git runs git in the repo, signing with the nazar key through
// nazar-sign-git. env is added to the world's environment (which has no
// SSH_AUTH_SOCK).
func (g *gitWorld) git(env []string, args ...string) (string, int) {
	g.t.Helper()
	base := []string{"-C", g.repo,
		"-c", "user.name=nazar test", "-c", "user.email=test@example.invalid",
		"-c", "gpg.format=ssh", "-c", "user.signingkey=" + g.pub,
		"-c", "gpg.ssh.program=" + filepath.Join(bin, "nazar-sign-git")}
	return g.run(env, "git", append(base, args...)...)
}

func (g *gitWorld) allowedSigners() string {
	g.t.Helper()
	key, err := os.ReadFile(g.pub)
	if err != nil {
		g.t.Fatal(err)
	}
	allowed := filepath.Join(g.home, "allowed_signers")
	if err := os.WriteFile(allowed, []byte("test@example.invalid "+string(key)), 0o600); err != nil {
		g.t.Fatal(err)
	}
	return allowed
}

func TestGitCommitSigningThroughSignGit(t *testing.T) {
	g := newGitWorld(t)
	// No SSH_AUTH_SOCK in the environment: the wrapper must supply it.
	if out, code := g.git([]string{"NAZAR_AGENT_SOCK=" + g.sock}, "commit", "-q", "-S", "--allow-empty", "-m", "signed by nazar"); code != 0 {
		t.Fatalf("signed commit failed: %d\n%s", code, out)
	}
	allowed := g.allowedSigners()
	if out, code := g.git(nil, "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "HEAD"); code != 0 || !strings.Contains(out, `Good "git" signature`) {
		t.Fatalf("verify-commit: %d\n%s", code, out)
	}
	if !g.auditHas("decision=approved", "target=ssh:gitsign", `operation="sign git commit"`) {
		t.Fatalf("signing not audited:\n%s", g.auditDump())
	}
	// A signer the allowed-signers file doesn't list is not accepted: the
	// signature really is the nazar key's.
	other := filepath.Join(g.home, "other_signers")
	throwaway := filepath.Join(g.home, "throwaway")
	if out, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", throwaway).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	tk, _ := os.ReadFile(throwaway + ".pub")
	os.WriteFile(other, []byte("test@example.invalid "+string(tk)), 0o600)
	if out, code := g.git(nil, "-c", "gpg.ssh.allowedSignersFile="+other, "verify-commit", "HEAD"); code == 0 {
		t.Fatalf("verify-commit accepted the commit for a different key:\n%s", out)
	}
}

// Without NAZAR_AGENT_SOCK the wrapper finds the agent at ~/.nazar/run/agent.sock
// (the default socket), and git tags are signed the same way.
func TestGitTagSigningUsesDefaultSocket(t *testing.T) {
	g := newGitWorld(t)
	if out, code := g.git(nil, "commit", "-q", "--allow-empty", "-m", "unsigned"); code != 0 {
		t.Fatalf("commit: %d %s", code, out)
	}
	if out, code := g.git(nil, "tag", "-s", "-m", "signed tag", "v1"); code != 0 {
		t.Fatalf("signed tag failed: %d\n%s", code, out)
	}
	allowed := g.allowedSigners()
	if out, code := g.git(nil, "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-tag", "v1"); code != 0 || !strings.Contains(out, `Good "git" signature`) {
		t.Fatalf("verify-tag: %d\n%s", code, out)
	}
	if !g.auditHas("target=ssh:gitsign", `operation="sign git commit"`) {
		t.Fatalf("tag signing not audited:\n%s", g.auditDump())
	}
}

// SSH_AUTH_SOCK pointing at some other agent (a decoy socket here) never
// receives git's signing request: the wrapper always uses nazar's agent.
func TestSignGitIgnoresInheritedAgent(t *testing.T) {
	g := newGitWorld(t)
	decoy := filepath.Join(g.home, "decoy.sock")
	l, err := net.Listen("unix", decoy)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var hits atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close() // refuse everything
		}
	}()
	if out, code := g.git([]string{"SSH_AUTH_SOCK=" + decoy}, "commit", "-q", "-S", "--allow-empty", "-m", "signed despite a decoy agent"); code != 0 {
		t.Fatalf("signed commit with a decoy SSH_AUTH_SOCK failed: %d\n%s", code, out)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the decoy agent in SSH_AUTH_SOCK was contacted %d times", n)
	}
	allowed := g.allowedSigners()
	if out, code := g.git(nil, "-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "HEAD"); code != 0 {
		t.Fatalf("verify-commit: %d\n%s", code, out)
	}
	if !g.auditHas("decision=approved", "target=ssh:gitsign") {
		t.Fatalf("signing not audited:\n%s", g.auditDump())
	}
}

// A denied dialog fails the commit and leaves no commit behind; an unknown
// caller is blocked.
func TestGitSigningDeniedOrBlockedFailsCommit(t *testing.T) {
	g := newGitWorld(t)
	g.setScript(`{"chain":"iterm","auth":"allow","confirm":"deny"}`)
	if out, code := g.git(nil, "commit", "-q", "-S", "--allow-empty", "-m", "must not exist"); code == 0 {
		t.Fatalf("a denied signature still committed:\n%s", out)
	}
	if out, code := g.git(nil, "rev-parse", "-q", "--verify", "HEAD"); code == 0 {
		t.Fatalf("a commit exists after a denied signature: %s", out)
	}
	if !g.auditHas("decision=denied", "target=ssh:gitsign", `operation="sign git commit"`) {
		t.Fatalf("denial not audited:\n%s", g.auditDump())
	}
	g.setScript(`{"chain":"unknown","auth":"allow","confirm":"allow"}`)
	if out, code := g.git(nil, "commit", "-q", "-S", "--allow-empty", "-m", "must not exist"); code == 0 {
		t.Fatalf("an unknown caller signed a commit:\n%s", out)
	}
	if !g.auditHas("decision=blocked", "target=ssh:gitsign") {
		t.Fatalf("block not audited:\n%s", g.auditDump())
	}
	if g.auditHas("decision=approved", "operation=") || g.auditHas("decision=allowed", "operation=") {
		t.Fatalf("nothing was approved, yet the audit says so:\n%s", g.auditDump())
	}
}
