package secrets

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/atas/nazar/core/platform"
)

// linuxSpy is the spy platform describing itself as Linux.
type linuxSpy struct{ *spyPlatform }

func (linuxSpy) Traits() platform.Traits { return platform.LinuxTraits }

func newLinuxStore(t *testing.T) (*Store, *spyPlatform, *spyVault) {
	t.Helper()
	_, p, v := newStore(t)
	return NewStore(linuxSpy{p}, v, p.Now), p, v
}

// On Linux a when-unlocked secret says the screen is locked, not the Mac,
// at Add and at Open, and still matches platform.ErrLocked. Portable: runs
// on every OS.
func TestLinuxLockedSecretMessages(t *testing.T) {
	s, p, _ := newLinuxStore(t)
	mustAdd(t, s, "GH", "v")
	p.SetLocked(true)
	_, err := s.Open("GH", 0)
	if want := "secrets: the screen is locked; GH opens only while it's unlocked"; !errors.Is(err, platform.ErrLocked) || err.Error() != want {
		t.Errorf("Open while locked = %v, want %q", err, want)
	}
	_, err = s.Add("BOT", []byte("w"), platform.AccessWhenUnlocked)
	if want := "secrets: the screen is locked; a secret that opens only while it's unlocked can't be added now"; !errors.Is(err, platform.ErrLocked) || err.Error() != want {
		t.Errorf("Add while locked = %v, want %q", err, want)
	}
}

// A record without a key handle names the platform's chip: the enclave on
// macOS, the TPM on Linux.
func TestBrokenRecordNamesTheChip(t *testing.T) {
	for _, tc := range []struct {
		linux bool
		want  string
	}{{false, "no enclave handle"}, {true, "no TPM handle"}} {
		s, _, v := newStore(t)
		if tc.linux {
			s, _, v = newLinuxStore(t)
		}
		mustAdd(t, s, "GH", "v")
		b, err := v.Vault.Get(VaultPrefix + "GH")
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "handle")
		b, _ = json.Marshal(m)
		if err := v.Vault.Put(VaultPrefix+"GH", b); err != nil {
			t.Fatal(err)
		}
		list, err := s.List()
		if err != nil || len(list) != 1 || !list[0].Broken || !strings.Contains(list[0].Problem, tc.want) {
			t.Errorf("linux %v: %+v, %v; want a broken record naming %q", tc.linux, list, err, tc.want)
		}
	}
}
