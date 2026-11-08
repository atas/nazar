package configstage

import (
	"errors"
	"testing"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/platform/fake"
)

// Milestone 5: an approved config the vault can't read (an item of
// another build of Nazar.app) is "no approved config yet": the built-in
// default is active, the file is staged against it, and nothing applies
// without the gate.
func TestOpenOrDefaultTreatsAnUnreadableApprovedConfigAsNone(t *testing.T) {
	inner := fake.NewVault()
	inner.Put(ApprovedVaultItem, src(base))
	otherBuild := errors.New("platform: vault get failed (status 1)")
	var applied []*config.Config
	s := OpenOrDefault(env, getFailVault{inner, otherBuild}, nil, nil, func(c *config.Config) { applied = append(applied, c) })
	if s.Unreadable() == "" {
		t.Fatal("Unreadable must say why")
	}
	a := s.Active()
	if len(a.SSHAgent.Keys) != 0 || a.Defaults.Fallback.Gate != config.GateBlock || len(applied) != 1 {
		t.Fatalf("want the built-in default (every key blocked), got %+v", a)
	}
	// The file that was approved before is a loosening now: staged.
	r := s.Observe(src(base))
	if !r.Staged || r.Applied || !r.Diff.Loosens() {
		t.Fatalf("the old config must wait for the gate again: %+v", r)
	}
	if len(s.Active().SSHAgent.Keys) != 0 {
		t.Fatal("applied without approval")
	}
}

// Approving needs a writable item; once one is saved the reason clears.
func TestOpenOrDefaultClearsOnceAConfigIsSaved(t *testing.T) {
	inner := fake.NewVault()
	v := &flipVault{Vault: inner, fail: errors.New("platform: vault get failed (status 1)")}
	s := OpenOrDefault(env, v, nil, nil, nil)
	s.Observe(src(base))
	ok, err := s.Approve("", func(Pending) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("approve: %v %v", ok, err)
	}
	if s.Unreadable() != "" {
		t.Fatalf("still unreadable after saving: %q", s.Unreadable())
	}
	if got, _ := inner.Get(ApprovedVaultItem); string(got) != string(src(base)) {
		t.Fatal("approved config not saved")
	}
}

func TestOpenOrDefaultReadsAWorkingItem(t *testing.T) {
	v := fake.NewVault()
	v.Put(ApprovedVaultItem, src(base))
	s := OpenOrDefault(env, v, nil, nil, nil)
	if s.Unreadable() != "" || len(s.Active().SSHAgent.Keys) != 1 {
		t.Fatalf("%q %+v", s.Unreadable(), s.Active())
	}
}

// flipVault fails Get only; Put and Delete work (the user deleted the
// item of the other build, so a new one can be added).
type flipVault struct {
	*fake.Vault
	fail error
}

func (v *flipVault) Get(name string) ([]byte, error) { return nil, v.fail }
