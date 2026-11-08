package daemon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/layout"
)

// legacyRules writes apps: and to: as one matcher each, as builds before
// list-only accepted and approved them, with a path: rule an older build
// recorded as approved (config/approved-paths).
const legacyRules = `apiVersion: nazar/v1
kind: Config
apps:
  iterm: {app: com.googlecode.iterm2}
ssh_agent:
  keys:
    github:
      rules:
        - apps: iterm   # my terminal
          scope: session
          gate: dialog
        - apps: {path: /opt/homebrew/opt/mytool/bin/mytool}
          to: {signed: {team: apple, id: com.apple.openssh}}
          gate: login
      gate: block
`

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// upgradeFrom stops the daemon and leaves what an older build left: the
// approved config in the vault (with its path: record when paths) and
// body as config.yaml.
func upgradeFrom(t *testing.T, e *env, approved, body string, paths bool) {
	t.Helper()
	e.halt()
	e.halt = nil
	if err := e.vault.Put(configstage.ApprovedVaultItem, []byte(approved)); err != nil {
		t.Fatal(err)
	}
	if paths {
		e.vault.Put(configstage.PathsApprovedVaultItem, []byte(sum([]byte(approved))))
	}
	e.writeConfig(t, body)
}

func (e *env) pending() (configstage.Pending, bool) { return e.d.stager.Pending() }

func migratedOrFail(t *testing.T, b string) []byte {
	t.Helper()
	out, ok := config.Migrate([]byte(b), config.Env{Home: "/Users/u"})
	if !ok {
		t.Fatal("the fixture is not migrated")
	}
	return out
}

// The approved config.yaml in the old shape stays approved after the
// upgrade: nazar-agent rewrites the file in lists (same rules, old file in
// config.yaml.bak), the approved config in the vault is rewritten the same
// way, so the file is the approved config: in force, nothing staged, no
// prompt. The path: record follows. A second start does nothing.
func TestLegacyApprovedConfigIsRewrittenAndStaysApproved(t *testing.T) {
	e := start(t)
	upgradeFrom(t, e, legacyRules, legacyRules, true)
	want := migratedOrFail(t, legacyRules)
	logins := e.logins()
	e.launch(t)

	if got := e.readConfig(t); got != string(want) {
		t.Fatalf("config.yaml:\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(e.readConfig(t), "# my terminal") {
		t.Fatal("a comment was lost")
	}
	bak := layout.ConfigFile(e.home) + ".bak"
	if b, err := os.ReadFile(bak); err != nil || string(b) != legacyRules {
		t.Fatalf("backup: %q %v", b, err)
	}
	if fi, err := os.Stat(bak); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode: %v %v", fi, err)
	}
	if !bytes.Equal(e.d.stager.Active().Raw, want) || !e.d.stager.Active().HasPathMatchers() {
		t.Fatalf("active:\n%s", e.d.stager.Active().Raw)
	}
	if item, _ := e.vault.Get(configstage.ApprovedVaultItem); !bytes.Equal(item, want) {
		t.Fatalf("approved item:\n%s", item)
	}
	if mark, _ := e.vault.Get(configstage.PathsApprovedVaultItem); string(mark) != sum(want) {
		t.Fatalf("approved-paths names %q", mark)
	}
	if _, staged := e.pending(); staged || e.stillStaged() {
		t.Fatal("the rewritten file is staged")
	}
	if n := e.logins() - logins; n != 0 {
		t.Fatalf("%d prompts, want none", n)
	}

	// A second start finds nothing to do: the backup keeps the old file.
	e.relaunch(t)
	if got := e.readConfig(t); got != string(want) {
		t.Fatalf("config.yaml changed on the second start:\n%s", got)
	}
	if b, _ := os.ReadFile(bak); string(b) != legacyRules {
		t.Fatalf("the backup was replaced: %q", b)
	}
	if _, staged := e.pending(); staged || e.logins() != logins {
		t.Fatal("the second start staged or prompted")
	}
}

// A config.yaml in the old shape that is not the approved config (an edit
// left staged, or a file a process of the user wrote) is rewritten too,
// and stays exactly what it was: a change waiting for the login gate.
// Nothing it says becomes approved, its path: matchers get no record, and
// the approved config is the vault's, rewritten.
func TestLegacyUnapprovedFileStaysStaged(t *testing.T) {
	forged := strings.Replace(legacyRules, "          gate: dialog\n", "          gate: none\n", 1) +
		"    deploy:\n      rules:\n        - apps: {path: /Users/u/bin/evil}\n          gate: none\n"
	approved := strings.Replace(legacyRules, "        - apps: {path: /opt/homebrew/opt/mytool/bin/mytool}\n          to: {signed: {team: apple, id: com.apple.openssh}}\n          gate: login\n", "", 1)
	if approved == legacyRules {
		t.Fatal("fixture")
	}
	e := start(t)
	upgradeFrom(t, e, approved, forged, false)
	wantFile, wantApproved := migratedOrFail(t, forged), migratedOrFail(t, approved)
	e.launch(t)

	if got := e.readConfig(t); got != string(wantFile) {
		t.Fatalf("config.yaml:\n%s", got)
	}
	if b, _ := os.ReadFile(layout.ConfigFile(e.home) + ".bak"); string(b) != forged {
		t.Fatalf("backup: %q", b)
	}
	if !bytes.Equal(e.d.stager.Active().Raw, wantApproved) {
		t.Fatalf("active:\n%s", e.d.stager.Active().Raw)
	}
	if e.d.stager.Active().SSHAgent.Keys["deploy"] != nil || e.d.stager.Active().HasPathMatchers() {
		t.Fatal("the unapproved file's rules are in force")
	}
	p, staged := e.pending()
	if !staged || !bytes.Equal(p.Config.Raw, wantFile) {
		t.Fatalf("the rewritten file must be staged: %v", staged)
	}
	if item, _ := e.vault.Get(configstage.ApprovedVaultItem); !bytes.Equal(item, wantApproved) {
		t.Fatalf("approved item:\n%s", item)
	}
	if _, err := e.vault.Get(configstage.PathsApprovedVaultItem); err == nil {
		t.Fatal("a path: record was written")
	}
}

// A file that is invalid read the old way too is left alone, with no backup.
func TestLegacyInvalidFileIsLeftAlone(t *testing.T) {
	bad := strings.Replace(legacyRules, "apps: iterm", "apps: nosuchapp", 1)
	e := start(t)
	upgradeFrom(t, e, legacyRules, bad, false)
	e.launch(t)
	if got := e.readConfig(t); got != bad {
		t.Fatalf("config.yaml changed:\n%s", got)
	}
	if _, err := os.Stat(layout.ConfigFile(e.home) + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("a backup was written: %v", err)
	}
}
