// Package trust keeps nazar's pinned state: app team pins (`app:` matchers,
// spec 4.2). It is persisted in the platform Vault, which only Nazar.app
// can read or write, so no other process can add a pin.
//
// An older version also recorded binaries there for path: matchers, which
// are gone: such records are ignored when the item is read and dropped by
// the next write, so an existing item keeps working as it is.
package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/atas/nazar/core/platform"
)

// VaultItem is the Vault name the state is stored under.
const VaultItem = "state/trust"

// state is the vault item. An older version's "paths" field is not read
// (json skips unknown fields) and so not written back.
type state struct {
	Pins map[string]string `json:"pins"`
}

// Store is the in-memory view of the persisted state. Every change is
// written to the Vault before it becomes visible; a failed write leaves
// both the Vault and the Store as they were. It is safe for concurrent use.
type Store struct {
	mu sync.Mutex
	v  platform.Vault
	s  state
	// unreadable is why the vault item could not be read when the store
	// was opened with OpenOrDegrade ("" = it was read, or there was none).
	// Such a store knows no pins and refuses every change
	// until the item reads again or is gone (recover).
	unreadable string
}

// ErrUnreadable is returned by every change to a store whose vault item
// could not be read (OpenOrDegrade): writing would replace a state nazar
// never saw, and pin whatever app is installed now.
var ErrUnreadable = errors.New("trust: the trust store can't be read")

// Open loads the store from v. A missing item is an empty store; a read
// error or unparsable item is an error, never an empty store, because
// forgetting the pins would let the next impostor pin itself.
func Open(v platform.Vault) (*Store, error) {
	st := &Store{v: v, s: state{Pins: map[string]string{}}}
	b, err := v.Get(VaultItem)
	if errors.Is(err, platform.ErrNotFound) {
		return st, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust: reading %s: %w", VaultItem, err)
	}
	if err := json.Unmarshal(b, &st.s); err != nil {
		return nil, fmt.Errorf("trust: %s is corrupt: %w", VaultItem, err)
	}
	if st.s.Pins == nil {
		st.s.Pins = map[string]string{}
	}
	return st, nil
}

// OpenOrDegrade is Open for Nazar.app's start (since Milestone 5): an item
// that can't be read or parsed (an item of another build of Nazar.app,
// which the Keychain no longer lets this build read; a locked keychain; a
// corrupt value) does not stop the app. It
// gives a store that knows no pins, so no app: matcher it would have
// satisfied matches (fail closed), and that
// refuses every change with ErrUnreadable, so nothing is written over the
// unread state and no app is pinned from what happens to be installed.
// Unreadable says why. The store recovers by itself once the item reads
// again or has been deleted (the user starting over): each change, and
// Unreadable, first try to read it again.
func OpenOrDegrade(v platform.Vault) *Store {
	st, err := Open(v)
	if err == nil {
		return st
	}
	return &Store{v: v, s: state{Pins: map[string]string{}}, unreadable: err.Error()}
}

// recover retries the read of an unreadable store; the caller holds s.mu.
// It returns nil once the store is usable (the item read, or is gone).
func (s *Store) recover() error {
	if s.unreadable == "" {
		return nil
	}
	fresh, err := Open(s.v)
	if err != nil {
		s.unreadable = err.Error()
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	s.s, s.unreadable = fresh.s, ""
	return nil
}

// Unreadable reports why the vault item could not be read, or "" when the
// store is usable. It retries the read first.
func (s *Store) Unreadable() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recover()
	return s.unreadable
}

// save writes the state; the caller holds s.mu.
func (s *Store) save() error {
	b, err := json.Marshal(s.s)
	if err != nil {
		return fmt.Errorf("trust: encoding state: %w", err)
	}
	if err := s.v.Put(VaultItem, b); err != nil {
		return fmt.Errorf("trust: writing %s: %w", VaultItem, err)
	}
	return nil
}

// PinnedTeam returns the team pinned for bundleID.
func (s *Store) PinnedTeam(bundleID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.s.Pins[bundleID]
	return t, ok
}

// Pin records team for bundleID unless a pin already exists, and returns the
// team now pinned: the first writer wins, later calls are told the winner.
// It is how an approved config change records the pins it showed (spec
// 4.2: pinned on first load). An empty team is never pinned. If the pin
// can't be persisted it is not kept in memory either.
func (s *Store) Pin(bundleID, team string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.recover(); err != nil {
		return "", err
	}
	if t, ok := s.s.Pins[bundleID]; ok {
		return t, nil
	}
	if bundleID == "" {
		return "", errors.New("trust: refusing to pin an empty bundle id")
	}
	if team == "" {
		return "", errors.New("trust: refusing to pin an empty team")
	}
	s.s.Pins[bundleID] = team
	if err := s.save(); err != nil {
		delete(s.s.Pins, bundleID)
		return "", err
	}
	return team, nil
}

// SetPin records team for bundleID, replacing any existing pin. Only
// `nazar trust --app`, behind the login gate, uses it (an app update that
// changed its signing team, spec 4.8); config approval uses Pin and
// matching never writes. Empty values are refused. If the change can't be
// persisted the previous pin (or its absence) is kept.
func (s *Store) SetPin(bundleID, team string) error {
	if bundleID == "" {
		return errors.New("trust: refusing to pin an empty bundle id")
	}
	if team == "" {
		return errors.New("trust: refusing to pin an empty team")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.recover(); err != nil {
		return err
	}
	old, had := s.s.Pins[bundleID]
	s.s.Pins[bundleID] = team
	if err := s.save(); err != nil {
		if had {
			s.s.Pins[bundleID] = old
		} else {
			delete(s.s.Pins, bundleID)
		}
		return err
	}
	return nil
}

// Pins returns a copy of all pins, bundle ID → team.
func (s *Store) Pins() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.s.Pins))
	for k, v := range s.s.Pins {
		out[k] = v
	}
	return out
}
