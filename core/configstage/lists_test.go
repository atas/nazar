package configstage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform/fake"
)

// legacyApproved writes apps: and to: as one matcher on its own, as a
// build before list-only approved it (and stored it, byte for byte).
var legacyApproved = src(`ssh_agent:
  keys:
    github:
      rules:
        - apps: claude
          scope: session
          gate: dialog
        - apps: {path: /opt/homebrew/opt/mytool/bin/mytool}
          to: {signed: {team: apple, id: com.apple.openssh}}
          gate: none
      gate: block
`)

func hexHash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func migrated(t *testing.T, b []byte) []byte {
	t.Helper()
	out, ok := config.Migrate(b, env)
	if !ok {
		t.Fatal("not migrated")
	}
	return out
}

// An approved config in the old shape stays approved: Open rewrites the
// vault item into lists (same meaning, no prompt: nothing loosens) and the
// approval of its path: matchers follows it, so the file rewritten the
// same way is the approved config and nothing is staged.
func TestApprovedLegacyConfigStaysApproved(t *testing.T) {
	if _, probs := config.Parse(legacyApproved, env); !probs.HasErrors() {
		t.Fatal("the fixture parses strictly: this test would prove nothing")
	}
	want := migrated(t, legacyApproved)
	v := fake.NewVault()
	v.Put(ApprovedVaultItem, legacyApproved)
	v.Put(PathsApprovedVaultItem, []byte(hexHash(legacyApproved)))
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Active().Raw, want) || !s.Active().HasPathMatchers() || len(s.Active().SSHAgent.Keys["github"].Rules) != 2 {
		t.Fatalf("active after Open:\n%s", s.Active().Raw)
	}
	if item, _ := v.Get(ApprovedVaultItem); !bytes.Equal(item, want) {
		t.Fatalf("the vault item is not the rewrite:\n%s", item)
	}
	if mark, _ := v.Get(PathsApprovedVaultItem); string(mark) != hexHash(want) {
		t.Fatalf("approved-paths names %q, want the rewrite's hash", mark)
	}
	if r := s.Observe(want); r.Staged || r.Applied || r.Invalid {
		t.Fatalf("the rewritten file is the approved config: %+v", r)
	}
	// The old shape itself is a config error now; the approved config stays.
	if r := s.Observe(legacyApproved); !r.Invalid {
		t.Fatalf("the old shape must be refused: %+v", r)
	}
	// A second start finds nothing to do.
	s2, err := Open(env, v, nil)
	if err != nil || !bytes.Equal(s2.Active().Raw, want) || !s2.Active().HasPathMatchers() {
		t.Fatalf("second start: %v\n%s", err, s2.Active().Raw)
	}
}

// The rewrite never approves path: matchers that were not approved: with
// no record, or a record naming something else, they stay held and the
// record is not written.
func TestLegacyMigrationKeepsPathMatchersHeld(t *testing.T) {
	for name, mark := range map[string][]byte{"no record": nil, "another config": []byte(hexHash([]byte("other")))} {
		t.Run(name, func(t *testing.T) {
			v := fake.NewVault()
			v.Put(ApprovedVaultItem, legacyApproved)
			if mark != nil {
				v.Put(PathsApprovedVaultItem, mark)
			}
			s, err := Open(env, v, nil)
			if err != nil {
				t.Fatal(err)
			}
			if s.Active().HasPathMatchers() {
				t.Fatal("path: matchers never approved are in force")
			}
			got, err := v.Get(PathsApprovedVaultItem)
			if mark == nil && err == nil {
				t.Fatalf("a record was written: %q", got)
			}
			if mark != nil && !bytes.Equal(got, mark) {
				t.Fatalf("the record changed: %q", got)
			}
			if r := s.Observe(migrated(t, legacyApproved)); !r.Staged || r.Applied {
				t.Fatalf("the file with them must wait for approval: %+v", r)
			}
		})
	}
}

// A start that stopped between the record and the config (the record is
// written first) finishes the rewrite next time, still approved.
func TestLegacyMigrationInterrupted(t *testing.T) {
	want := migrated(t, legacyApproved)
	v := fake.NewVault()
	v.Put(ApprovedVaultItem, legacyApproved)
	v.Put(PathsApprovedVaultItem, []byte(hexHash(want)))
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Active().HasPathMatchers() || !bytes.Equal(s.Active().Raw, want) {
		t.Fatalf("active:\n%s", s.Active().Raw)
	}
	if item, _ := v.Get(ApprovedVaultItem); !bytes.Equal(item, want) {
		t.Fatalf("vault item:\n%s", item)
	}
}

// A vault that can't be written still starts with the approved config,
// rewritten in memory (same meaning), and tries again next start.
func TestLegacyMigrationVaultReadOnly(t *testing.T) {
	want := migrated(t, legacyApproved)
	v := fake.NewVault()
	v.Put(ApprovedVaultItem, legacyApproved)
	v.Put(PathsApprovedVaultItem, []byte(hexHash(legacyApproved)))
	v.SetFailPut(errors.New("locked"))
	s, err := Open(env, v, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Active().Raw, want) || !s.Active().HasPathMatchers() {
		t.Fatalf("active:\n%s", s.Active().Raw)
	}
	if r := s.Observe(want); r.Staged || r.Applied || r.Invalid {
		t.Fatalf("the rewritten file is the approved config: %+v", r)
	}
	if item, _ := v.Get(ApprovedVaultItem); !bytes.Equal(item, legacyApproved) {
		t.Fatal("the vault changed")
	}
}

// An approved config already in lists, or one that is invalid either way,
// is left as it is.
func TestOpenLeavesOtherApprovedItemsAlone(t *testing.T) {
	strict := migrated(t, legacyApproved)
	for _, b := range [][]byte{strict, []byte("apiVersion: nazar/v1\nkind: Config\nssh_agent: {keys: {k: {rules: [{apps: nope, gate: login}]}}}\n")} {
		v := fake.NewVault()
		v.Put(ApprovedVaultItem, b)
		if _, err := Open(env, v, nil); err != nil {
			t.Fatal(err)
		}
		if item, _ := v.Get(ApprovedVaultItem); !bytes.Equal(item, b) {
			t.Fatalf("changed:\n%s", item)
		}
	}
}
