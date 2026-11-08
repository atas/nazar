package trust

import (
	"errors"
	"sync"
	"testing"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// switchVault is a fake vault whose reads of the trust item fail while
// refuse is set: the item of another build of Nazar.app, which the
// Keychain no longer lets this build read.
type switchVault struct {
	*fake.Vault
	mu     sync.Mutex
	refuse error
}

func (v *switchVault) set(err error) {
	v.mu.Lock()
	v.refuse = err
	v.mu.Unlock()
}

func (v *switchVault) Get(name string) ([]byte, error) {
	v.mu.Lock()
	err := v.refuse
	v.mu.Unlock()
	if err != nil && name == VaultItem {
		return nil, err
	}
	return v.Vault.Get(name)
}

var errOtherBuild = errors.New("platform: vault get failed (status 1)")

func TestOpenOrDegradeReadsAWorkingItem(t *testing.T) {
	v := fake.NewVault()
	s1, _ := Open(v)
	s1.Pin("com.googlecode.iterm2", "H7V7XYVQ7D")
	s := OpenOrDegrade(v)
	if s.Unreadable() != "" {
		t.Fatalf("unreadable %q", s.Unreadable())
	}
	if team, ok := s.PinnedTeam("com.googlecode.iterm2"); !ok || team != "H7V7XYVQ7D" {
		t.Fatal("pin lost")
	}
}

// An unreadable item knows nothing (nothing matches), refuses every change
// and never writes over the item it could not read.
func TestUnreadableStoreFailsClosedAndWritesNothing(t *testing.T) {
	v := &switchVault{Vault: fake.NewVault()}
	s1, _ := Open(v)
	s1.Pin("com.googlecode.iterm2", "H7V7XYVQ7D")
	before, _ := v.Vault.Get(VaultItem)
	v.set(errOtherBuild)

	s := OpenOrDegrade(v)
	if s.Unreadable() == "" {
		t.Fatal("Unreadable must say why")
	}
	if _, ok := s.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatal("an unreadable store must not know pins")
	}
	if len(s.Pins()) != 0 {
		t.Fatal("an unreadable store must know nothing")
	}
	if _, err := s.Pin("com.evil.iterm2", "EVILTEAM01"); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Pin: %v, want ErrUnreadable", err)
	}
	if err := s.SetPin("com.googlecode.iterm2", "EVILTEAM01"); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("SetPin: %v", err)
	}
	after, _ := v.Vault.Get(VaultItem)
	if string(after) != string(before) {
		t.Fatal("the unread item was overwritten")
	}
}

// Once the user deleted the item (to start over), the store works again
// without a restart, empty.
func TestUnreadableStoreRecoversWhenTheItemIsGone(t *testing.T) {
	v := &switchVault{Vault: fake.NewVault()}
	v.Vault.Put(VaultItem, []byte(`{"pins":{"com.x":"T1"}}`))
	v.set(errOtherBuild)
	s := OpenOrDegrade(v)
	if s.Unreadable() == "" {
		t.Fatal("setup")
	}
	v.Vault.Delete(VaultItem)
	v.set(nil)
	if got := s.Unreadable(); got != "" {
		t.Fatalf("still unreadable after the item was deleted: %q", got)
	}
	if team, err := s.Pin("com.y", "T2"); err != nil || team != "T2" {
		t.Fatalf("pin after recovery: %q %v", team, err)
	}
	if _, ok := s.PinnedTeam("com.x"); ok {
		t.Fatal("the deleted state came back")
	}
}

// When the item reads again (an unlocked keychain), the store loads it
// before the first change, so first-writer-wins still holds.
func TestUnreadableStoreRecoversTheRealState(t *testing.T) {
	v := &switchVault{Vault: fake.NewVault()}
	v.Vault.Put(VaultItem, []byte(`{"pins":{"com.x":"T1"}}`))
	v.set(errOtherBuild)
	s := OpenOrDegrade(v)
	v.set(nil)
	if team, err := s.Pin("com.x", "T2"); err != nil || team != "T1" {
		t.Fatalf("Pin after recovery = %q %v, want the recorded T1", team, err)
	}
}

func TestCorruptItemDegradesToo(t *testing.T) {
	v := fake.NewVault()
	v.Put(VaultItem, []byte("{not json"))
	s := OpenOrDegrade(v)
	if s.Unreadable() == "" {
		t.Fatal("a corrupt item must be reported")
	}
	if _, err := s.Pin("com.x", "T1"); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("Pin over a corrupt item: %v", err)
	}
	if _, err := v.Get(VaultItem); errors.Is(err, platform.ErrNotFound) {
		t.Fatal("the corrupt item must be left for the user")
	}
}
