package keys

import (
	"errors"
	"strings"
	"testing"

	"github.com/atas/nazar/core/platform"
)

// Milestone 5: a record the Vault refuses (an item of another build
// of Nazar.app) is listed as broken AND unreadable, with what failed, and
// can still be deleted so the key can be re-created.
func TestUnreadableRecordSaysWhy(t *testing.T) {
	r, _, v, _ := newReg(t)
	mustCreate(t, r, "github", platform.AuthNone)
	mustCreate(t, r, "deploy", platform.AuthNone)
	v.FailGetOf = map[string]error{VaultPrefix + "github": errors.New("platform: vault get failed (status 1)")}
	list, err := r.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("%+v %v", list, err)
	}
	gh := list[1]
	if gh.Name != "github" || !gh.Broken || !gh.Unreadable || !strings.Contains(gh.Problem, "status 1") {
		t.Fatalf("github = %+v", gh)
	}
	if d := list[0]; d.Broken || d.Unreadable || d.Problem != "" {
		t.Fatalf("deploy must be unaffected: %+v", d)
	}
	if err := r.Delete("github"); err != nil {
		t.Fatalf("an unreadable key must still be deletable: %v", err)
	}
	if _, err := v.Vault.Get(VaultPrefix + "github"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("the vault item must be gone after delete: %v", err)
	}
}

// A record that reads but does not decode is broken, not unreadable.
func TestCorruptRecordIsNotUnreadable(t *testing.T) {
	r, _, v, _ := newReg(t)
	v.Vault.Put(VaultPrefix+"bad", []byte("{not json"))
	info, err := r.Get("bad")
	if err != nil || !info.Broken || info.Unreadable || info.Problem == "" {
		t.Fatalf("%+v %v", info, err)
	}
}
