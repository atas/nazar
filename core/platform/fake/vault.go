package fake

import (
	"sort"
	"strings"
	"sync"

	"github.com/atas/nazar/core/platform"
)

var _ platform.Vault = (*Vault)(nil)

// Vault is an in-memory platform.Vault. Values are copied on the way in and
// out, so callers never share memory with the store.
type Vault struct {
	mu    sync.Mutex
	items map[string][]byte
	// FailPut, when set, makes Put return it without storing anything
	// (a locked Keychain).
	FailPut error
}

// SetFailPut sets FailPut under the vault's lock, for tests whose code
// under test writes from another goroutine (nazar-agent's helpers,
// core/caller Remember).
func (v *Vault) SetFailPut(err error) {
	v.mu.Lock()
	v.FailPut = err
	v.mu.Unlock()
}

// NewVault returns an empty Vault.
func NewVault() *Vault { return &Vault{items: map[string][]byte{}} }

// Get returns a copy of the item, or ErrNotFound.
func (v *Vault) Get(name string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, ok := v.items[name]
	if !ok {
		return nil, platform.ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

// Put stores a copy of value under name, replacing any previous item.
func (v *Vault) Put(name string, value []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.FailPut != nil {
		return v.FailPut
	}
	v.items[name] = append([]byte(nil), value...)
	return nil
}

// Delete removes the item, or returns ErrNotFound.
func (v *Vault) Delete(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.items[name]; !ok {
		return platform.ErrNotFound
	}
	delete(v.items, name)
	return nil
}

// List returns the names starting with prefix, sorted.
func (v *Vault) List(prefix string) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for k := range v.items {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}
