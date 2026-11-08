//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/layout"
)

const itermRule = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    itest:
      rules:
        - apps: [iterm]
          scope: session
          gate: dialog
`

// ruleConfig is a config with one rule for key itest.
func ruleConfig(apps, scope, gate string) string {
	s := "apiVersion: nazar/v1\nkind: Config\napps:\n  iterm: {app: com.googlecode.iterm2}\nssh_agent:\n  keys:\n    itest:\n      rules:\n        - apps: " + apps + "\n"
	if scope != "" {
		s += "          scope: " + scope + "\n"
	}
	return s + "          gate: " + gate + "\n"
}

// loggedIn sets up a world with key itest, the given config approved and
// an sshd that trusts the key.
func loggedIn(t *testing.T, script, config string) (*world, string, *sshd) {
	t.Helper()
	w := newWorld(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`)
	pub := w.createKey("itest")
	w.approveConfig(config)
	s := w.startSSHD(pub)
	w.setScript(script)
	return w, pub, s
}

func TestSSHLoginThroughNazar(t *testing.T) {
	w := newWorld(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`)
	pub := w.createKey("itest")
	w.approveConfig(itermRule)
	s := w.startSSHD(pub)

	out, code := w.ssh(s, pub, "echo nazar-ok")
	if code != 0 || !strings.Contains(out, "nazar-ok") {
		t.Fatalf("ssh exit %d: %s", code, out)
	}
	dest := fmt.Sprintf(`destination="[127.0.0.1]:%d"`, s.port)
	if !w.auditHas("decision=approved", "target=ssh:itest", dest, "gate=dialog") {
		t.Fatalf("no approved audit line naming %s:\n%s", dest, w.auditDump())
	}
	// Same session: remembered, no second dialog. The script now denies
	// every dialog, so only the cache can let this login through.
	w.setScript(`{"chain":"iterm","auth":"deny","confirm":"deny"}`)
	if out, code := w.ssh(s, pub, "true"); code != 0 {
		t.Fatalf("second ssh: %d %s", code, out)
	}
	if !w.auditHas("decision=allowed", `reason="cached approval"`, "target=ssh:itest", dest) {
		t.Fatalf("second login was not served from the approval cache:\n%s", w.auditDump())
	}
	if n := w.auditCount("decision=approved", "target=ssh:itest", "destination="); n != 1 {
		t.Fatalf("want exactly one dialog-approved login, got %d:\n%s", n, w.auditDump())
	}
	status, code := w.nazar("--json", "status")
	if code != 0 || !strings.Contains(status, `"target":"ssh:itest"`) {
		t.Fatalf("status: %d %s", code, status)
	}
	if out, code := w.nazar("revoke", "--all"); code != 0 || !strings.Contains(out, "revoked 1") {
		t.Fatalf("revoke: %d %s", code, out)
	}
	// Revoked: the next login asks again, and the (denying) dialog decides.
	if out, code := w.ssh(s, pub, "true"); code == 0 {
		t.Fatalf("login after revoke must ask again and be denied: %s", out)
	}
	if !w.auditHas("decision=denied", "target=ssh:itest") {
		t.Fatalf("login after revoke was not denied by the dialog:\n%s", w.auditDump())
	}
	if status, _ := w.nazar("--json", "status"); strings.Contains(status, `"target":"ssh:itest"`) {
		t.Fatalf("approval still listed after revoke: %s", status)
	}
}

// The socket folder is the user's with 0700 and the sockets 0600 (spec 5,
// Phase 0 S6): another local user can never connect to the agent.
func TestSocketsArePrivate(t *testing.T) {
	w := newWorld(t, `{"chain":"iterm"}`)
	check := func(p string, want os.FileMode) {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s is a symlink", p)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Fatalf("%s mode %o, want %o", p, got, want)
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
			t.Fatalf("%s owned by uid %d, want %d", p, st.Uid, os.Getuid())
		}
	}
	check(layout.Root(w.home), 0o700)
	check(layout.RunDir(w.home), 0o700)
	check(w.sock, 0o600)
	check(w.ctlSock, 0o600)
}

func TestDeniedAndBlockedLoginsFail(t *testing.T) {
	w := newWorld(t, `{"chain":"iterm","auth":"allow","confirm":"deny"}`)
	pub := w.createKey("itest")
	w.approveConfig(itermRule)
	s := w.startSSHD(pub)
	if out, code := w.ssh(s, pub, "echo must-not-run"); code == 0 || strings.Contains(out, "must-not-run") {
		t.Fatalf("denied dialog must fail the login: %s", out)
	}
	if !w.auditHas("decision=denied", "target=ssh:itest") {
		t.Fatal("denial not audited")
	}
	w.setScript(`{"chain":"unknown","auth":"allow","confirm":"allow"}`)
	if out, code := w.ssh(s, pub, "echo must-not-run"); code == 0 || strings.Contains(out, "must-not-run") {
		t.Fatalf("an unknown caller must be blocked: %s", out)
	}
	if !w.auditHas("decision=blocked", `reason="no rule matched"`, "target=ssh:itest") {
		t.Fatalf("block not audited:\n%s", w.auditDump())
	}
	w.setScript(`{"chain":"iterm","auth":"allow","confirm":"hang"}`)
	start := time.Now()
	if out, code := w.ssh(s, pub, "echo must-not-run"); code == 0 || strings.Contains(out, "must-not-run") {
		t.Fatalf("an unanswered dialog must fail: %s", out)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("the 3s gate timeout took %s", time.Since(start))
	}
	if !w.auditHas("decision=timeout", "target=ssh:itest") {
		t.Fatalf("timeout not audited:\n%s", w.auditDump())
	}
	if w.auditHas("decision=approved", "destination=") || w.auditHas("decision=allowed", "destination=") {
		t.Fatalf("no login was approved, yet the audit says so:\n%s", w.auditDump())
	}
	// Nothing above was remembered: a dialog that says yes still decides.
	w.setScript(`{"chain":"iterm","auth":"allow","confirm":"allow"}`)
	if out, code := w.ssh(s, pub, "echo nazar-ok"); code != 0 || !strings.Contains(out, "nazar-ok") {
		t.Fatalf("login after the failures: %d %s", code, out)
	}
}

// A session approval belongs to one terminal tab: a second tab of the same
// app asks again (spec 4.3, the manual test "a new tab prompting again").
func TestNewTabPromptsAgain(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`, itermRule)
	if out, code := w.ssh(s, pub, "true"); code != 0 {
		t.Fatalf("first tab: %d %s", code, out)
	}
	w.setScript(`{"chain":"iterm-claude","auth":"allow","confirm":"deny"}`)
	if out, code := w.ssh(s, pub, "echo must-not-run"); code == 0 || strings.Contains(out, "must-not-run") {
		t.Fatalf("another tab rode on the first tab's approval: %s", out)
	}
	if !w.auditHas("decision=denied", "target=ssh:itest") {
		t.Fatalf("the second tab was not asked:\n%s", w.auditDump())
	}
	// The first tab is still remembered.
	w.setScript(`{"chain":"iterm","auth":"deny","confirm":"deny"}`)
	if out, code := w.ssh(s, pub, "true"); code != 0 {
		t.Fatalf("first tab lost its approval: %d %s", code, out)
	}
}

// scope: use remembers nothing: every login asks.
func TestScopeUsePromptsEveryTime(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`, ruleConfig("[iterm]", "use", "dialog"))
	for i := 0; i < 2; i++ {
		if out, code := w.ssh(s, pub, "true"); code != 0 {
			t.Fatalf("login %d: %d %s", i, code, out)
		}
	}
	if n := w.auditCount("decision=approved", "target=ssh:itest", "destination="); n != 2 {
		t.Fatalf("scope use: want 2 prompted logins, got %d:\n%s", n, w.auditDump())
	}
	if w.auditHas("decision=allowed", "target=ssh:") {
		t.Fatalf("scope use must never be served from a cache:\n%s", w.auditDump())
	}
	w.setScript(`{"chain":"iterm","auth":"allow","confirm":"deny"}`)
	if out, code := w.ssh(s, pub, "true"); code == 0 {
		t.Fatalf("scope use: a denied third login succeeded: %s", out)
	}
}

// An unknown chain may be let through by an apps: unknown rule, but never
// by a remembered approval (spec 4.2), even with scope: session.
func TestUnknownCallerIsNeverCached(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"unknown","auth":"allow","confirm":"allow"}`, ruleConfig("[unknown]", "session", "dialog"))
	for i := 0; i < 2; i++ {
		if out, code := w.ssh(s, pub, "true"); code != 0 {
			t.Fatalf("login %d: %d %s", i, code, out)
		}
	}
	if n := w.auditCount("decision=approved", "target=ssh:itest", "destination="); n != 2 {
		t.Fatalf("unknown caller: want 2 prompted logins, got %d:\n%s", n, w.auditDump())
	}
	if w.auditHas("decision=allowed", "target=ssh:") {
		t.Fatalf("an unknown caller was served from the cache:\n%s", w.auditDump())
	}
	w.setScript(`{"chain":"unknown","auth":"allow","confirm":"deny"}`)
	if out, code := w.ssh(s, pub, "true"); code == 0 {
		t.Fatalf("unknown caller logged in on a denied dialog: %s", out)
	}
}

func TestGateBlockRuleRefuses(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`, ruleConfig("[iterm]", "", "block"))
	if out, code := w.ssh(s, pub, "echo must-not-run"); code == 0 || strings.Contains(out, "must-not-run") {
		t.Fatalf("gate: block let a login through: %s", out)
	}
	if !w.auditHas("decision=blocked", "target=ssh:itest") {
		t.Fatalf("block not audited:\n%s", w.auditDump())
	}
}

// gate: none with an app: matcher is silent: no login gate, no dialog. The
// unknown chain is still blocked by the fallback.
func TestGateNoneAppRuleIsSilent(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"deny","confirm":"deny"}`, ruleConfig("[iterm]", "", "none"))
	for i := 0; i < 2; i++ {
		if out, code := w.ssh(s, pub, "echo nazar-ok"); code != 0 || !strings.Contains(out, "nazar-ok") {
			t.Fatalf("gate: none login %d: %d %s", i, code, out)
		}
	}
	if n := w.auditCount("decision=allowed", "target=ssh:itest", "gate=none"); n != 2 {
		t.Fatalf("want 2 silent allowed logins, got %d:\n%s", n, w.auditDump())
	}
	w.setScript(`{"chain":"unknown","auth":"allow","confirm":"allow"}`)
	if out, code := w.ssh(s, pub, "true"); code == 0 {
		t.Fatalf("gate: none for iterm let an unknown caller in: %s", out)
	}
}

// Spec 4.2: gate: none refuses
// Apple-signed matchers and paths of Apple's programs. A config that puts
// one under gate: none is invalid: it is refused even when the login gate
// would pass, and the last approved config stays in force. any and unknown
// are the user's explicit "every program, no prompt": they pass, with a
// warning that says so.
func TestGateNoneRefusesFakeableMatchers(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`, itermRule)
	if out, code := w.ssh(s, pub, "true"); code != 0 { // remembers this session
		t.Fatalf("login: %d %s", code, out)
	}
	if out, code := w.nazar("revoke", "--all"); code != 0 {
		t.Fatalf("revoke: %d %s", code, out)
	}
	active := w.activeHash()
	// The login gate says yes to anything from here on, the dialog says no:
	// only an applied gate: none rule could let a login through.
	w.setScript(`{"chain":"unknown","auth":"allow","confirm":"deny"}`)
	cases := map[string]string{
		"apple signed": "apiVersion: nazar/v1\nkind: Config\napps:\n  ssh: {signed: {team: apple, id: com.apple.openssh}}\nssh_agent:\n  keys:\n    itest:\n      rules:\n" +
			"        - apps: [ssh]\n          gate: none\n",
		"apple signed, no id": "apiVersion: nazar/v1\nkind: Config\napps:\n  apple: {signed: {team: apple}}\nssh_agent:\n  keys:\n    itest:\n      rules:\n" +
			"        - apps: [apple]\n          gate: none\n",
		"Apple, capitalised": "apiVersion: nazar/v1\nkind: Config\napps:\n  ssh: {signed: {team: Apple, id: com.apple.openssh}}\nssh_agent:\n  keys:\n    itest:\n      rules:\n" +
			"        - apps: [ssh]\n          gate: none\n",
		"path of Apple's ssh": "apiVersion: nazar/v1\nkind: Config\napps:\n  ssh: {path: /usr/bin/ssh}\nssh_agent:\n  keys:\n    itest:\n      rules:\n" +
			"        - apps: [ssh]\n          gate: none\n",
	}
	for name, body := range cases {
		w.writeConfig(body)
		out, code := w.nazar("config", "check")
		why := "none"
		if name == "Apple, capitalised" {
			why = "Apple's team is written apple" // a team that matches nothing is refused first
		}
		if code != 1 || !strings.Contains(out, why) {
			t.Fatalf("%s: gate: none config must be invalid (exit 1, naming %q), got %d:\n%s", name, why, code, out)
		}
		time.Sleep(400 * time.Millisecond) // several daemon polls
		if got := w.activeHash(); got != active {
			t.Fatalf("%s: an invalid gate: none config became active", name)
		}
		blocked := w.auditCount("decision=blocked", "target=ssh:itest")
		if out, code := w.ssh(s, pub, "echo must-not-run"); code == 0 || strings.Contains(out, "must-not-run") {
			t.Fatalf("%s: login went through under a refused gate: none config: %s", name, out)
		}
		if got := w.auditCount("decision=blocked", "target=ssh:itest"); got != blocked+1 {
			t.Fatalf("%s: the login did not reach nazar's policy and get blocked by the old config:\n%s", name, w.auditDump())
		}
	}
	if w.auditHas("decision=allowed", "target=ssh:") || w.auditHas("gate=none") {
		t.Fatalf("a refused gate: none rule was used:\n%s", w.auditDump())
	}
	// Each is valid: the daemon stages it and the script's login gate
	// approves it, so wait for that (a check in between reports it staged).
	for _, apps := range []string{"[any]", "[unknown]", "[iterm, any]"} {
		w.approveConfig(ruleConfig(apps, "", "none"))
		if out, code := w.nazar("config", "check"); code != 0 || !strings.Contains(out, "every program on this Mac use this key without asking") {
			t.Fatalf("apps %s gate none: want valid with the every-program warning, got %d:\n%s", apps, code, out)
		}
	}
}

// A host nazar's known_hosts doesn't list is named by its host key
// fingerprint (spec 5), never by a name the client could choose.
func TestUnknownHostNamedByFingerprint(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`, itermRule)
	sshKH := filepath.Join(w.home, "ssh_known_hosts")
	b, err := os.ReadFile(w.kh)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sshKH, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.kh, nil, 0o600); err != nil { // nazar knows no host now
		t.Fatal(err)
	}
	if out, code := w.sshWith(s, pub, sshOpts{knownHosts: sshKH}, "true"); code != 0 {
		t.Fatalf("login: %d %s", code, out)
	}
	fp := s.hostFingerprint(t)
	if !w.auditHas("decision=approved", "target=ssh:itest", fp) {
		t.Fatalf("destination does not carry the host key fingerprint %s:\n%s", fp, w.auditDump())
	}
	if w.auditHas("target=ssh:itest", `destination="[127.0.0.1]`) {
		t.Fatalf("destination named from a known_hosts nazar does not have:\n%s", w.auditDump())
	}
}

// Agent forwarding (ssh -A): a far host signing through the forwarded agent
// never rides on the local tab's remembered approval, and is never
// remembered itself.
func TestForwardedAgentPromptsEveryTime(t *testing.T) {
	w, pub, s := loggedIn(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`, itermRule)
	if out, code := w.ssh(s, pub, "true"); code != 0 { // the tab is now remembered
		t.Fatalf("login: %d %s", code, out)
	}
	user := currentUser(t)
	// The "remote" command runs an ssh that can only use the forwarded
	// agent (no IdentityAgent): its sign requests reach nazar through the
	// outer ssh's forwarded connection.
	inner := fmt.Sprintf(`printf 'fwd=%%s\n' "$SSH_AUTH_SOCK"; /usr/bin/ssh -F /dev/null -T -o IdentitiesOnly=yes -i %s -o UserKnownHostsFile=%s -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o BatchMode=yes -o ControlMaster=no -o ControlPath=none -p %d %s@127.0.0.1 echo inner-ok`,
		pub, w.kh, s.port, user)
	fwd := sshOpts{extra: []string{"-o", "ForwardAgent=" + w.sock}}

	approvedBefore := w.auditCount("decision=approved", "target=ssh:itest", "destination=")
	out, code := w.sshWith(s, pub, fwd, inner)
	if strings.Contains(out, "fwd=\n") || !strings.Contains(out, "fwd=") {
		t.Skipf("sshd did not forward the agent: %s", out)
	}
	if code != 0 || !strings.Contains(out, "inner-ok") {
		t.Fatalf("forwarded login with an allowing dialog failed: %d %s", code, out)
	}
	if got := w.auditCount("decision=approved", "target=ssh:itest", "destination="); got != approvedBefore+1 {
		t.Fatalf("the forwarded sign request was not prompted (approved %d -> %d):\n%s", approvedBefore, got, w.auditDump())
	}
	// Again: still prompted, never remembered.
	if out, code := w.sshWith(s, pub, fwd, inner); code != 0 || !strings.Contains(out, "inner-ok") {
		t.Fatalf("second forwarded login: %d %s", code, out)
	}
	if got := w.auditCount("decision=approved", "target=ssh:itest", "destination="); got != approvedBefore+2 {
		t.Fatalf("a forwarded sign request was served from a cache (approved %d -> %d):\n%s", approvedBefore, got, w.auditDump())
	}
	// Dialog now says no: the local tab still logs in from its approval,
	// the forwarded hop is refused.
	w.setScript(`{"chain":"iterm","auth":"allow","confirm":"deny"}`)
	if out, code := w.ssh(s, pub, "true"); code != 0 {
		t.Fatalf("the local tab lost its approval: %d %s", code, out)
	}
	deniedBefore := w.auditCount("decision=denied", "target=ssh:itest")
	if out, _ := w.sshWith(s, pub, fwd, inner); strings.Contains(out, "inner-ok") {
		t.Fatalf("a forwarded login rode on the local tab's approval: %s", out)
	}
	if got := w.auditCount("decision=denied", "target=ssh:itest"); got != deniedBefore+1 {
		t.Fatalf("the forwarded request was not put to the dialog:\n%s", w.auditDump())
	}
}

func TestAgentRefusesKeyManagement(t *testing.T) {
	w := newWorld(t, `{"chain":"iterm","auth":"allow"}`)
	pub := w.createKey("itest")
	askpass := filepath.Join(w.home, "askpass")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho nazar-lock-pw\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, int) {
		t.Helper()
		return w.run([]string{"SSH_AUTH_SOCK=" + w.sock, "SSH_ASKPASS=" + askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=none"}, "/usr/bin/ssh-add", args...)
	}
	if out, code := run("-l"); code != 0 || !strings.Contains(out, "itest (ECDSA)") {
		t.Fatalf("ssh-add -l: %d %s", code, out)
	}
	pubLine, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	pf := strings.Fields(string(pubLine))
	if len(pf) < 2 || pf[0] != "ecdsa-sha2-nistp256" {
		t.Fatalf(".pub is not an ecdsa-sha2-nistp256 key: %q", pubLine)
	}
	if out, code := run("-L"); code != 0 || !strings.Contains(out, pf[1]) {
		t.Fatalf("ssh-add -L does not list the exported key: %d %s", code, out)
	}
	throwaway := filepath.Join(w.home, "throwaway")
	if out, err := exec.Command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", throwaway).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, code := run(throwaway); code == 0 {
		t.Fatalf("ADD_IDENTITY must be refused: %s", out)
	}
	if out, code := run("-d", pub); code == 0 {
		t.Fatalf("REMOVE_IDENTITY must be refused: %s", out)
	}
	if out, code := run("-D"); code == 0 {
		t.Fatalf("REMOVE_ALL must be refused: %s", out)
	}
	if out, code := run("-x"); code == 0 {
		t.Fatalf("LOCK must be refused: %s", out)
	}
	if out, code := run("-X"); code == 0 {
		t.Fatalf("UNLOCK must be refused: %s", out)
	}
	// Nothing changed: the one nazar key, unlocked, no throwaway key.
	if out, _ := run("-l"); strings.Count(out, "(ECDSA)") != 1 || strings.Contains(out, "ED25519") || !strings.Contains(out, "itest (ECDSA)") {
		t.Fatalf("key set changed: %s", out)
	}
	if _, err := os.Stat(throwaway); err != nil {
		t.Fatal(err)
	}
	// The key's private half never lands in a plain file (spec 3, 4.5).
	filepath.Walk(w.home, func(p string, fi os.FileInfo, err error) error {
		if err != nil || !fi.Mode().IsRegular() || strings.HasPrefix(p, throwaway) {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil && bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Errorf("private key material in %s", p)
		}
		return nil
	})
	// Milestone 7: a program outside every rule is offered nothing, and
	// that is reported where ssh stops: a blocked audit line per key with
	// operation "list keys" and the policy's reason. The key's own gate
	// (login, from create) applies to every caller, so give itest a rule
	// for iterm alone: everything else falls to the block fallback.
	w.approveConfig(itermRule)
	if out, code := run("-l"); code != 0 || !strings.Contains(out, "itest (ECDSA)") {
		t.Fatalf("ssh-add -l from the tab its rule names: %d %s", code, out)
	}
	if n := w.auditCount(`operation="list keys"`); n != 0 {
		t.Fatalf("a caller offered its key is told nothing: %d list-keys lines:\n%s", n, w.auditDump())
	}
	w.setScript(`{"chain":"unknown","auth":"allow"}`)
	if out, code := run("-l"); code != 1 || !strings.Contains(out, "The agent has no identities.") {
		t.Fatalf("ssh-add -l outside every rule: %d %s", code, out)
	}
	if !w.auditHas("decision=blocked", `operation="list keys"`, "target=ssh:itest", `reason="no rule matched"`) {
		t.Fatalf("the withheld key was not audited:\n%s", w.auditDump())
	}
}

// sshsign signs msg with ssh-keygen -Y sign through the nazar agent and
// returns the output and exit code. stdin is /dev/null.
func (w *world) sshsign(pub, namespace, msg string) (string, int) {
	w.t.Helper()
	return w.run([]string{"SSH_AUTH_SOCK=" + w.sock}, "/usr/bin/ssh-keygen", "-Y", "sign", "-f", pub, "-n", namespace, msg)
}

// A signature made through the agent is a valid SSHSIG that ssh-keygen -Y
// verify accepts (spec 10), the audit names the namespace, and the
// signature itself is never logged (spec 4.6).
func TestSSHSIGThroughAgentVerifies(t *testing.T) {
	w := newWorld(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`)
	pub := w.createKey("itest")
	w.approveConfig(itermRule)
	msg := filepath.Join(w.home, "msg.txt")
	os.WriteFile(msg, []byte("nazar integration message\n"), 0o600)
	if out, code := w.sshsign(pub, "file", msg); code != 0 {
		t.Fatalf("ssh-keygen -Y sign: %d %s", code, out)
	}
	key, _ := os.ReadFile(pub)
	allowed := filepath.Join(w.home, "allowed_signers")
	os.WriteFile(allowed, []byte("tester "+string(key)), 0o600)
	verify := func(namespace string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "tester", "-n", namespace, "-s", msg+".sig")
		cmd.Env = w.env()
		in, _ := os.Open(msg)
		defer in.Close()
		cmd.Stdin = in
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := verify("file"); err != nil || !strings.Contains(out, `Good "file" signature for tester`) {
		t.Fatalf("verify: %v %s", err, out)
	}
	if out, err := verify("git"); err == nil {
		t.Fatalf("a file signature verified as a git one: %s", out)
	}
	if !w.auditHas("decision=approved", "target=ssh:itest", "namespace=file") {
		t.Fatalf("SSHSIG sign not audited with its namespace:\n%s", w.auditDump())
	}
	sig, _ := os.ReadFile(msg + ".sig")
	audit, _ := os.ReadFile(w.audit)
	for _, l := range strings.Split(string(sig), "\n") {
		if len(l) >= 20 && !strings.HasPrefix(l, "-----") && bytes.Contains(audit, []byte(l)) {
			t.Fatalf("signature bytes in the audit log: %q", l)
		}
	}
}

// A namespace is caller-chosen text that reaches the audit log: crafted
// namespaces (quotes, key=value, newlines) must not forge fields or lines.
func TestCraftedNamespaceCannotForgeAuditFields(t *testing.T) {
	w := newWorld(t, `{"chain":"iterm","auth":"allow","confirm":"allow"}`)
	pub := w.createKey("itest")
	// scope: use, so every sign is put to the dialog and its real decision
	// is "approved", never the forged "allowed".
	w.approveConfig(ruleConfig("[iterm]", "use", "dialog"))
	namespaces := []string{
		`x" decision=allowed target=ssh:forged reason="cached approval`,
		"y\ndecision=allowed target=ssh:forged2 gate=none",
		`z decision=allowed target=ssh:forged3`,
	}
	for i, ns := range namespaces {
		msg := filepath.Join(w.home, fmt.Sprintf("m%d", i))
		os.WriteFile(msg, []byte("data\n"), 0o600)
		before := len(w.auditLines())
		out, code := w.sshsign(pub, ns, msg)
		lines := w.auditLines()
		if len(lines) != before+1 {
			t.Fatalf("namespace %q: want exactly one new audit line, got %d (ssh-keygen %d %s):\n%s", ns, len(lines)-before, code, out, w.auditDump())
		}
	}
	signs := 0
	for _, l := range w.auditLines() {
		fields := auditFields(t, l)
		if len(fields) == 0 || fields[0][0] != "decision" {
			t.Fatalf("line does not start with decision=: %s", l)
		}
		count := map[string]int{}
		get := map[string]string{}
		for _, f := range fields {
			count[f[0]]++
			get[f[0]] = f[1]
			if strings.Contains(f[1], "forged") && f[0] != "operation" {
				t.Fatalf("crafted namespace text in field %s: %s", f[0], l)
			}
		}
		for k, n := range count {
			if n != 1 {
				t.Fatalf("field %s appears %d times in: %s", k, n, l)
			}
		}
		if count["operation"] == 1 {
			signs++
			if get["target"] != "ssh:itest" || get["decision"] != "approved" || get["gate"] != "dialog" {
				t.Fatalf("sign line fields were forged: %s", l)
			}
		}
	}
	if signs != len(namespaces) {
		t.Fatalf("want %d sign lines, got %d:\n%s", len(namespaces), signs, w.auditDump())
	}
}
