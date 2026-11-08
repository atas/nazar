//go:build integration && swiftplatform

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/atas/nazar/core/layout"
)

// These tests run the real Go core on the real Swift platform
// (NazarSmokeHost): real Secure Enclave keys WITHOUT user presence,
// real caller resolution, a temporary keychain in the test home (never the
// login keychain, never under a Library/Keychains folder, never on the
// search list), scripted login and dialog gates, audit lines in the unified
// log under a random dev.nazar.test.* subsystem. Nothing here can show a
// window or a dialog: the host refuses user-presence keys and its gates are
// scripted. Only `make integration-swift` (NAZAR_SMOKE_HOST) runs them.

// smokeHost is the NazarSmokeHost binary, or a skip when it is not set.
func smokeHost(t *testing.T) string {
	t.Helper()
	host := os.Getenv("NAZAR_SMOKE_HOST")
	if host == "" {
		t.Skip("NAZAR_SMOKE_HOST is not set (make integration-swift sets it)")
	}
	if st, err := os.Stat(host); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		t.Fatalf("NAZAR_SMOKE_HOST %s is not an executable: %v", host, err)
	}
	return host
}

// consoleLockedRE matches the IORegistry root's IOConsoleLocked = true in
// `ioreg -a` output.
var consoleLockedRE = regexp.MustCompile(`<key>IOConsoleLocked</key>\s*<true/>`)

// skipIfScreenLocked skips a test that creates a Secure Enclave key while
// the screen is locked: the chip refuses to create a
// WhenUnlockedThisDeviceOnly key then (errSecInteractionNotAllowed, -25308),
// as in the Swift EnclaveStoreTests. Keys made with nazar's default access
// (AfterFirstUnlockThisDeviceOnly) are made while locked too; the skip
// stays for the tests that make the other kind. The lock state is read passively (ioreg, no
// prompt, no keychain access). Unlocked, the test runs unchanged.
func skipIfScreenLocked(t *testing.T) {
	t.Helper()
	out, err := exec.Command("/usr/sbin/ioreg", "-n", "Root", "-d1", "-a").Output()
	if err == nil && consoleLockedRE.Match(out) {
		t.Skip("screen locked: Secure Enclave key creation is refused; re-run unlocked")
	}
}

// userSearchList is `security list-keychains -d user` (read only).
func userSearchList(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/security", "list-keychains", "-d", "user").Output()
	if err != nil {
		t.Fatalf("security list-keychains: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// newSwiftWorld is a world whose daemon is NazarSmokeHost: the real Go core
// through the C ABI on the real Swift platform (real Secure Enclave keys
// without user presence, real caller resolution, a temporary keychain,
// scripted gates that allow, audit lines in the unified log under a test
// subsystem). It returns the world and that subsystem.
func newSwiftWorld(t *testing.T) (*world, string) {
	t.Helper()
	host := smokeHost(t)
	searchBefore := userSearchList(t)
	home, err := os.MkdirTemp("/tmp", "nzsw") // short: sun_path is 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	trackDir(home)
	var n [6]byte
	rand.Read(n[:])
	sub := "dev.nazar.test." + hex.EncodeToString(n[:])
	w := &world{t: t, home: home, kh: filepath.Join(home, "known_hosts"),
		sock: layout.AgentSocket(home), ctlSock: layout.ControlSocket(home)}
	os.WriteFile(w.kh, nil, 0o600)
	w.daemon = exec.Command(host, "--home", home, "--keychain-dir", filepath.Join(home, "kc"), "--log-subsystem", sub)
	w.daemon.Env = w.env()
	logf, _ := os.Create(filepath.Join(home, "host.log"))
	w.daemon.Stdout, w.daemon.Stderr = logf, logf
	if err := w.daemon.Start(); err != nil {
		t.Fatal(err)
	}
	track(w.daemon)
	t.Cleanup(func() {
		w.daemon.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { w.daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			w.daemon.Process.Kill()
			<-done
		}
		logf.Close()
		if _, err := os.Stat(filepath.Join(home, "kc")); !os.IsNotExist(err) {
			t.Errorf("the smoke host left its temporary keychain behind")
		}
		if after := userSearchList(t); after != searchBefore {
			t.Errorf("the user's keychain search list changed:\nbefore %s\nafter  %s", searchBefore, after)
		}
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(home, "host.log"))
			t.Logf("smoke host log:\n%s", b)
		}
		os.RemoveAll(home)
	})
	w.waitFor(func() bool { _, err := os.Stat(w.sock); return err == nil })
	w.waitFor(func() bool { _, err := os.Stat(w.ctlSock); return err == nil })
	return w, sub
}

// logShow returns the messages of the last 5 min matching predicate.
func logShow(t *testing.T, predicate string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/log", "show", "--last", "5m", "--style", "ndjson",
		"--predicate", predicate).Output()
	if err != nil {
		t.Fatalf("log show: %v", err)
	}
	var msgs []string
	for _, l := range strings.Split(string(out), "\n") {
		var e struct {
			EventMessage string `json:"eventMessage"`
		}
		if json.Unmarshal([]byte(l), &e) == nil && e.EventMessage != "" {
			msgs = append(msgs, e.EventMessage)
		}
	}
	return msgs
}

// unifiedLog returns the messages logged under subsystem in the last 5 min.
func unifiedLog(t *testing.T, subsystem string) []string {
	t.Helper()
	return logShow(t, `subsystem == "`+subsystem+`" AND category == "audit"`)
}

func waitForLog(t *testing.T, subsystem string, parts ...string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		msgs := unifiedLog(t, subsystem)
		for _, m := range msgs {
			if lineHas(m, parts) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit entry with %q in the unified log; have:\n%s", parts, strings.Join(msgs, "\n"))
		}
		time.Sleep(time.Second)
	}
}

// keyListed reports whether `nazar ssh-key list` names key, and fails the
// test on a broken or unreadable list.
func keyListed(w *world, name string) (listed bool, userPresence bool) {
	w.t.Helper()
	out, code := w.nazar("--json", "ssh-key", "list")
	if code != 0 {
		w.t.Fatalf("key list: %d %s", code, out)
	}
	var l struct {
		Items []struct {
			Name         string `json:"name"`
			Broken       bool   `json:"broken"`
			UserPresence bool   `json:"userPresence"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &l); err != nil {
		w.t.Fatalf("key list output %q: %v", out, err)
	}
	for _, k := range l.Items {
		if k.Name == name {
			if k.Broken {
				w.t.Fatalf("key %s is broken: %s", name, out)
			}
			return true, k.UserPresence
		}
	}
	return false, false
}

// TestSwiftPlatformEndToEnd: a Secure Enclave key made through the CLI,
// an ssh login and a signed git commit, all through Nazar's real stack.
func TestSwiftPlatformEndToEnd(t *testing.T) {
	smokeHost(t)
	skipIfScreenLocked(t)
	w, sub := newSwiftWorld(t)
	// The entry first, then the key under it (create takes no gate;
	// the test's own process chain is no terminal, so the entry create
	// would write blocks every caller). The login gate is scripted to allow.
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    work:\n      scope: session\n      gate: dialog\n")
	pub := w.createKey("work")
	if out, code := w.nazar("--json", "ssh-key", "list"); code != 0 || !strings.Contains(out, `"name":"work"`) || strings.Contains(out, `"broken":true`) {
		t.Fatalf("key list: %d %s", code, out)
	}
	if listed, presence := keyListed(w, "work"); !listed || presence {
		t.Fatalf("key work: listed %v, userPresence %v (want listed, no user presence)", listed, presence)
	}
	// A Secure Enclave key is P-256.
	if b, err := os.ReadFile(pub); err != nil || !strings.HasPrefix(string(b), "ecdsa-sha2-nistp256 ") {
		t.Fatalf("public key %s: %v %q", pub, err, b)
	}
	s := w.startSSHD(pub)
	out, code := w.ssh(s, pub, "echo nazar-swift-ok")
	if code != 0 || !strings.Contains(out, "nazar-swift-ok") {
		t.Fatalf("ssh through the Secure Enclave key: exit %d\n%s", code, out)
	}
	waitForLog(t, sub, "decision=approved", "target=ssh:work", "gate=dialog")

	// git commit signing through nazar-sign-git with the same key.
	repo := filepath.Join(w.home, "repo")
	if out, code := w.run(nil, "git", "init", "-q", repo); code != 0 {
		t.Fatalf("git init: %s", out)
	}
	git := func(args ...string) (string, int) {
		base := []string{"-C", repo, "-c", "user.name=nazar test", "-c", "user.email=test@example.invalid",
			"-c", "gpg.format=ssh", "-c", "user.signingkey=" + pub, "-c", "gpg.ssh.program=" + filepath.Join(bin, "nazar-sign-git")}
		return w.run(nil, "git", append(base, args...)...)
	}
	if out, code := git("commit", "-q", "-S", "--allow-empty", "-m", "signed in the Secure Enclave"); code != 0 {
		t.Fatalf("signed commit: %d %s", code, out)
	}
	key, _ := os.ReadFile(pub)
	allowed := filepath.Join(w.home, "allowed_signers")
	os.WriteFile(allowed, []byte("test@example.invalid "+string(key)), 0o600)
	if out, code := git("-c", "gpg.ssh.allowedSignersFile="+allowed, "verify-commit", "HEAD"); code != 0 || !strings.Contains(out, `Good "git" signature`) {
		t.Fatalf("verify-commit: %d %s", code, out)
	}
	waitForLog(t, sub, "decision=approved", "target=ssh:work", `operation="sign git commit"`)

	// Deleting the key removes it from the Vault (the temporary keychain).
	if out, code := w.nazar("--json", "ssh-key", "delete", "work"); code != 0 {
		t.Fatalf("delete: %d %s", code, out)
	}
	if out, _ := w.nazar("--json", "ssh-key", "list"); strings.Contains(out, `"name":"work"`) {
		t.Fatalf("key still listed after delete: %s", out)
	}
	// ...and the agent no longer offers or signs with it.
	if out, code := w.ssh(s, pub, "echo nazar-swift-after-delete"); code == 0 || strings.Contains(out, "nazar-swift-after-delete") {
		t.Fatalf("ssh still works with a deleted key: exit %d\n%s", code, out)
	}

	// The smoke host never writes under the real dev.nazar subsystem.
	if msgs := logShow(t, `subsystem == "dev.nazar" AND process == "NazarSmokeHost"`); len(msgs) != 0 {
		t.Fatalf("the smoke host logged under the real dev.nazar subsystem:\n%s", strings.Join(msgs, "\n"))
	}
}

// A key behind the login gate with a session scope has no chip-level user
// presence (spec 4.5: only login + scope: use does), so the
// smoke host makes it on the chip, and the scripted login gate approves it.
func TestSwiftPlatformLoginGateSessionKey(t *testing.T) {
	smokeHost(t)
	skipIfScreenLocked(t)
	w, sub := newSwiftWorld(t)
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    sess:\n      scope: session\n      gate: login\n")
	out, code := w.nazar("--json", "ssh-key", "create", "sess")
	if code != 0 {
		t.Fatalf("create login/session key: exit %d %s", code, out)
	}
	pub := filepath.Join(layout.KeysDir(w.home), "sess.pub")
	if listed, presence := keyListed(w, "sess"); !listed || presence {
		t.Fatalf("key sess: listed %v, userPresence %v (want listed, no user presence)", listed, presence)
	}
	s := w.startSSHD(pub)
	if out, code := w.ssh(s, pub, "echo nazar-swift-login"); code != 0 || !strings.Contains(out, "nazar-swift-login") {
		t.Fatalf("ssh through the login-gated Secure Enclave key: exit %d\n%s", code, out)
	}
	waitForLog(t, sub, "decision=approved", "target=ssh:sess", "gate=login")
}

// A user-presence key can't be made in an automated run: the smoke host
// refuses it, so nothing can ever prompt.
func TestSwiftPlatformRefusesUserPresenceKeys(t *testing.T) {
	w, _ := newSwiftWorld(t)
	w.approveConfig("apiVersion: nazar/v1\nkind: Config\nssh_agent:\n  keys:\n    strict:\n      scope: use\n      gate: login\n")
	if out, code := w.nazar("--json", "ssh-key", "create", "strict"); code == 0 {
		t.Fatalf("a user-presence key was created in an automated run: %s", out)
	}
	// The refusal leaves nothing behind and the host keeps serving.
	if listed, _ := keyListed(w, "strict"); listed {
		t.Fatalf("the refused key is listed")
	}
	if _, err := os.Stat(filepath.Join(layout.KeysDir(w.home), "strict.pub")); !os.IsNotExist(err) {
		t.Fatalf("the refused key left a public key file: %v", err)
	}
	// --always-ask on a new name is refused the same way, and leaves no entry.
	if out, code := w.nazar("--json", "ssh-key", "create", "prod", "--always-ask"); code == 0 {
		t.Fatalf("an always-ask key was created in an automated run: %s", out)
	}
	if listed, _ := keyListed(w, "prod"); listed {
		t.Fatalf("the refused always-ask key is listed")
	}
	if b, err := os.ReadFile(layout.ConfigFile(w.home)); err != nil || strings.Contains(string(b), "prod") {
		t.Fatalf("the refused always-ask key left an entry (%v):\n%s", err, b)
	}
	if out, code := w.nazar("--json", "status"); code != 0 {
		t.Fatalf("status after the refusal: exit %d %s", code, out)
	}
	if err := w.daemon.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the smoke host is gone after the refusal: %v", err)
	}
}

// The smoke host refuses arguments that could reach the user's real data:
// the real dev.nazar log subsystem (or anything outside dev.nazar.test.*),
// relative folders, missing options. It exits before it creates a keychain
// or a socket.
func TestSwiftPlatformSmokeHostRefusesUnsafeArguments(t *testing.T) {
	host := smokeHost(t)
	searchBefore := userSearchList(t)
	home, err := os.MkdirTemp("/tmp", "nzsa")
	if err != nil {
		t.Fatal(err)
	}
	trackDir(home)
	defer os.RemoveAll(home)
	kc := filepath.Join(home, "kc")
	good := "dev.nazar.test.args"
	cases := map[string][]string{
		"the real subsystem":           {"--home", home, "--keychain-dir", kc, "--log-subsystem", "dev.nazar"},
		"a subsystem beside dev.nazar": {"--home", home, "--keychain-dir", kc, "--log-subsystem", "dev.nazar.testing"},
		"a foreign subsystem":          {"--home", home, "--keychain-dir", kc, "--log-subsystem", "com.example.test.x"},
		"no subsystem":                 {"--home", home, "--keychain-dir", kc},
		"a relative home":              {"--home", "nzsa-rel", "--keychain-dir", kc, "--log-subsystem", good},
		"a relative keychain folder":   {"--home", home, "--keychain-dir", "kc", "--log-subsystem", good},
		"no keychain folder":           {"--home", home, "--log-subsystem", good},
		"no home":                      {"--keychain-dir", kc, "--log-subsystem", good},
		"a dangling option":            {"--home", home, "--keychain-dir", kc, "--log-subsystem"},
		"no arguments":                 {},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, host, args...)
			cmd.Dir = home // a relative path would land here
			cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("the smoke host kept running with %q: %s", args, out)
			}
			// A refusal is a normal non-zero exit, not a crash or a signal.
			ee, ok := err.(*exec.ExitError)
			if !ok || ee.ExitCode() <= 0 {
				t.Fatalf("the smoke host did not refuse %q with an exit status (%v): %s", args, err, out)
			}
			for _, p := range []string{kc, layout.Root(home), filepath.Join(home, "nzsa-rel")} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Fatalf("the smoke host created %s before refusing %q", p, args)
				}
			}
		})
	}
	if after := userSearchList(t); after != searchBefore {
		t.Errorf("the user's keychain search list changed:\nbefore %s\nafter  %s", searchBefore, after)
	}
}
