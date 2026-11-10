package keys

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// linuxFake is the fake platform describing itself as Linux.
type linuxFake struct{ *fake.Fake }

func (linuxFake) Traits() platform.Traits { return platform.LinuxTraits }

// On Linux a when-unlocked key used while the screen is locked says the
// screen, not the Mac, and still matches platform.ErrLocked.
func TestLinuxLockedMessage(t *testing.T) {
	f := fake.New(time.Now())
	r := NewRegistry(linuxFake{f}, fake.NewVault(), filepath.Join(t.TempDir(), "keys"), f.Now)
	if _, err := r.Create("github", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
		t.Fatal(err)
	}
	f.SetLocked(true)
	_, err := r.Sign("github", []byte("d"), 0)
	if !errors.Is(err, platform.ErrLocked) || err.Error() != "keys: the screen is locked; github signs only while it's unlocked" {
		t.Fatalf("Sign while locked = %v", err)
	}
	_, err = r.Create("other", platform.AuthNone, platform.AccessWhenUnlocked)
	if !errors.Is(err, platform.ErrLocked) || err.Error() != "keys: the screen is locked; a key that works only while it's unlocked can't be made now" {
		t.Fatalf("Create while locked = %v", err)
	}
}

// A record without a key handle names the platform's chip: the enclave on
// macOS, the TPM on Linux.
func TestBrokenRecordNamesTheChip(t *testing.T) {
	for _, tc := range []struct {
		linux bool
		want  string
	}{{false, "no enclave handle"}, {true, "no TPM handle"}} {
		f := fake.New(time.Now())
		var p platform.Platform = f
		if tc.linux {
			p = linuxFake{f}
		}
		v := fake.NewVault()
		r := NewRegistry(p, v, filepath.Join(t.TempDir(), "keys"), f.Now)
		if _, err := r.Create("github", platform.AuthNone, platform.AccessWhenUnlocked); err != nil {
			t.Fatal(err)
		}
		b, err := v.Get(VaultPrefix + "github")
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "handle")
		b, _ = json.Marshal(m)
		if err := v.Put(VaultPrefix+"github", b); err != nil {
			t.Fatal(err)
		}
		got, err := r.Get("github")
		if err != nil || !got.Broken || !strings.Contains(got.Problem, tc.want) {
			t.Errorf("linux %v: %+v, %v; want a broken record naming %q", tc.linux, got, err, tc.want)
		}
	}
}

// failingCreate is a platform whose CreateKey fails.
type failingCreate struct{ platform.Platform }

func (failingCreate) CreateKey(platform.Purpose, platform.AuthPolicy, platform.Access) ([]byte, []byte, error) {
	return nil, nil, errors.New("no room")
}

type linuxFailingCreate struct{ failingCreate }

func (linuxFailingCreate) Traits() platform.Traits { return platform.LinuxTraits }

// A failed key creation names the platform's chip.
func TestCreateFailureNamesTheChip(t *testing.T) {
	f := fake.New(time.Now())
	for _, tc := range []struct {
		p    platform.Platform
		want string
	}{
		{failingCreate{f}, "keys: create enclave key: no room"},
		{linuxFailingCreate{failingCreate{f}}, "keys: create TPM key: no room"},
	} {
		r := NewRegistry(tc.p, fake.NewVault(), filepath.Join(t.TempDir(), "keys"), f.Now)
		if _, err := r.Create("github", platform.AuthNone, platform.AccessWhenUnlocked); err == nil || err.Error() != tc.want {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
}
