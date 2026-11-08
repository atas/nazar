package trust

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

func TestPinIsFirstWriterWinsAndPersists(t *testing.T) {
	v := fake.NewVault()
	s, err := Open(v)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Pin("com.x", "TEAM1"); got != "TEAM1" {
		t.Fatalf("pin %q", got)
	}
	if got, _ := s.Pin("com.x", "EVIL"); got != "TEAM1" {
		t.Fatal("an existing pin must not be replaced")
	}
	if _, err := s.Pin("com.y", ""); err == nil {
		t.Fatal("empty team must not pin")
	}
	s2, _ := Open(v)
	if team, ok := s2.PinnedTeam("com.x"); !ok || team != "TEAM1" {
		t.Fatal("pin not persisted")
	}
}

func TestVaultFailureRollsBack(t *testing.T) {
	v := fake.NewVault()
	s, _ := Open(v)
	v.FailPut = errors.New("keychain locked")
	if _, err := s.Pin("com.x", "T"); err == nil {
		t.Fatal("want error")
	}
	if _, ok := s.PinnedTeam("com.x"); ok {
		t.Fatal("failed pin must not stick in memory")
	}
}

func TestCorruptStateIsAnError(t *testing.T) {
	v := fake.NewVault()
	v.Put(VaultItem, []byte("{not json"))
	if _, err := Open(v); err == nil {
		t.Fatal("corrupt state must not silently reset pins")
	}
}

// ---- Additional behaviour, edge and attack cases ----

func TestVaultItemName(t *testing.T) {
	if VaultItem != "state/trust" {
		t.Fatalf("VaultItem = %q", VaultItem)
	}
	v := fake.NewVault()
	s, _ := Open(v)
	if _, err := s.Pin("com.x", "TEAM1"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("state/trust"); err != nil {
		t.Fatalf("state must be stored under state/trust: %v", err)
	}
}

func TestEmptyVaultOpensEmpty(t *testing.T) {
	s, err := Open(fake.NewVault())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.PinnedTeam("com.googlecode.iterm2"); ok {
		t.Fatal("no pins expected")
	}
	if len(s.Pins()) != 0 {
		t.Fatal("empty store expected")
	}
}

// failingGetVault is a Vault whose reads fail (a locked or unreachable
// Keychain), not with ErrNotFound.
type failingGetVault struct{ *fake.Vault }

func (failingGetVault) Get(string) ([]byte, error) {
	return nil, errors.New("keychain: interaction not allowed")
}

// A vault read error is not "no state": opening empty would forget every
// team pin, and the next impostor with a pinned bundle id would get pinned.
func TestVaultReadErrorIsAnError(t *testing.T) {
	if _, err := Open(failingGetVault{fake.NewVault()}); err == nil {
		t.Fatal("a vault read error must fail Open, not start with no pins")
	}
}

func TestRepinningTheSameTeamIsANoOp(t *testing.T) {
	s, _ := Open(fake.NewVault())
	if got, err := s.Pin("com.x", "TEAM1"); err != nil || got != "TEAM1" {
		t.Fatalf("pin %q %v", got, err)
	}
	if got, err := s.Pin("com.x", "TEAM1"); err != nil || got != "TEAM1" {
		t.Fatalf("repin %q %v", got, err)
	}
	if got, err := s.Pin("com.x", ""); got != "TEAM1" {
		t.Fatalf("empty team after a pin must report the existing pin, got %q %v", got, err)
	}
	if team, ok := s.PinnedTeam("com.x"); !ok || team != "TEAM1" {
		t.Fatal("pin lost")
	}
}

// Many concurrent first matches with different teams: exactly one pin wins,
// every caller is told the same winner, and it is what persisted.
func TestConcurrentPinsAgreeOnOneWinner(t *testing.T) {
	v := fake.NewVault()
	s, _ := Open(v)
	const n = 32
	got := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			team, err := s.Pin("com.race", fmt.Sprintf("TEAM%02d", i))
			if err != nil {
				t.Errorf("pin %d: %v", i, err)
			}
			got[i] = team
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if got[i] != got[0] {
			t.Fatalf("callers disagree on the pin: %q vs %q", got[0], got[i])
		}
	}
	s2, _ := Open(v)
	if team, _ := s2.PinnedTeam("com.race"); team != got[0] {
		t.Fatalf("persisted %q, callers told %q", team, got[0])
	}
}

// The store hands out its own copies: a caller mutating the map it got
// back can't change a pin.
func TestStoreDoesNotAliasCallerMemory(t *testing.T) {
	s, _ := Open(fake.NewVault())
	if _, err := s.Pin("com.x", "TEAM1"); err != nil {
		t.Fatal(err)
	}
	pins := s.Pins()
	pins["com.x"] = "EVIL"
	pins["com.y"] = "EVIL"
	if team, _ := s.PinnedTeam("com.x"); team != "TEAM1" {
		t.Fatal("Pins() must return a copy")
	}
	if _, ok := s.PinnedTeam("com.y"); ok {
		t.Fatal("Pins() must return a copy")
	}
}

func TestPinsListed(t *testing.T) {
	s, _ := Open(fake.NewVault())
	s.Pin("com.a", "A")
	s.Pin("com.b", "B")
	if pins := s.Pins(); len(pins) != 2 || pins["com.a"] != "A" || pins["com.b"] != "B" {
		t.Fatalf("pins %v", pins)
	}
}

// Pins survive a reopen together (one item holds them all).
func TestPinsPersistTogether(t *testing.T) {
	v := fake.NewVault()
	s, _ := Open(v)
	s.Pin("com.googlecode.iterm2", "H7V7XYVQ7D")
	s.Pin("com.apple.Terminal", "apple")
	s2, err := Open(v)
	if err != nil {
		t.Fatal(err)
	}
	if team, _ := s2.PinnedTeam("com.googlecode.iterm2"); team != "H7V7XYVQ7D" {
		t.Fatal("pin lost")
	}
	if team, _ := s2.PinnedTeam("com.apple.Terminal"); team != "apple" {
		t.Fatal("pin lost")
	}
}

var _ platform.Vault = failingGetVault{}

// Pin (first writer wins) is how config approval records a new pin.
// SetPin replaces a pin; it is used only by `nazar trust --app` after the
// login gate (an app update that changed its team, spec 4.8). Matching
// never writes pins at all (core/match). SetPin persists before the change
// is visible and keeps the old pin when the vault refuses the write.
func TestSetPinReplacesAndPersists(t *testing.T) {
	v := fake.NewVault()
	s, _ := Open(v)
	if err := s.SetPin("com.googlecode.iterm2", "NEWTEAM000"); err != nil {
		t.Fatal(err)
	}
	if team, ok := s.PinnedTeam("com.googlecode.iterm2"); !ok || team != "NEWTEAM000" {
		t.Fatalf("new pin = %q %v", team, ok)
	}
	s.Pin("com.apple.Terminal", "apple")
	if err := s.SetPin("com.googlecode.iterm2", "H7V7XYVQ7D"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Pin("com.googlecode.iterm2", "EVILTEAM00"); got != "H7V7XYVQ7D" {
		t.Fatalf("Pin after SetPin must still be first-writer-wins, got %q", got)
	}
	s2, err := Open(v)
	if err != nil {
		t.Fatal(err)
	}
	if team, _ := s2.PinnedTeam("com.googlecode.iterm2"); team != "H7V7XYVQ7D" {
		t.Fatalf("replaced pin not persisted: %q", team)
	}
	if team, _ := s2.PinnedTeam("com.apple.Terminal"); team != "apple" {
		t.Fatalf("other pins must be kept: %q", team)
	}
}

func TestSetPinRefusesEmpty(t *testing.T) {
	v := fake.NewVault()
	s, _ := Open(v)
	s.Pin("com.x", "TEAM1")
	if err := s.SetPin("com.x", ""); err == nil {
		t.Fatal("an empty team must never be pinned")
	}
	if err := s.SetPin("", "TEAM1"); err == nil {
		t.Fatal("an empty bundle id must never be pinned")
	}
	if team, _ := s.PinnedTeam("com.x"); team != "TEAM1" {
		t.Fatalf("refused SetPin changed the pin: %q", team)
	}
	if _, ok := s.PinnedTeam(""); ok {
		t.Fatal("empty bundle id pinned")
	}
}

func TestSetPinKeepsOldPinWhenVaultFails(t *testing.T) {
	v := fake.NewVault()
	s, _ := Open(v)
	s.Pin("com.x", "TEAM1")
	v.FailPut = errors.New("keychain locked")
	if err := s.SetPin("com.x", "TEAM2"); err == nil {
		t.Fatal("SetPin must report the vault failure")
	}
	if err := s.SetPin("com.new", "TEAM3"); err == nil {
		t.Fatal("SetPin must report the vault failure")
	}
	if team, _ := s.PinnedTeam("com.x"); team != "TEAM1" {
		t.Fatalf("unsaved SetPin must not be visible: %q", team)
	}
	if _, ok := s.PinnedTeam("com.new"); ok {
		t.Fatal("unsaved new pin must not be visible")
	}
	v.FailPut = nil
	s2, _ := Open(v)
	if team, _ := s2.PinnedTeam("com.x"); team != "TEAM1" {
		t.Fatalf("vault content changed: %q", team)
	}
}
