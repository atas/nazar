package certs

import (
	"errors"
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// linuxSpy is the spy platform describing itself as Linux.
type linuxSpy struct{ *spyPlatform }

func (linuxSpy) Traits() platform.Traits { return platform.LinuxTraits }

// On Linux a when-unlocked CA says the screen is locked, not the Mac, and
// still matches platform.ErrLocked. Portable: runs on every OS.
func TestLinuxLockedCAMessages(t *testing.T) {
	k := k8sKind()
	spy := newSpy(t)
	p := linuxSpy{spy}
	s := NewStore(k, p, &spyVault{Vault: fake.NewVault()}, func() time.Time { return t0 })
	hydra, err := s.Create("hydra", platform.AccessWhenUnlocked)
	if err != nil {
		t.Fatal(err)
	}
	spy.SetLocked(true)
	_, err = s.Create("other", platform.AccessWhenUnlocked)
	if want := "k8s: the screen is locked; a CA that signs only while it's unlocked can't be made now"; !errors.Is(err, platform.ErrLocked) || err.Error() != want {
		t.Errorf("Create while locked = %v, want %q", err, want)
	}
	_, err = hydra.Issue(p, leafFor("x", t0), t0, 0)
	if want := "k8s: the screen is locked; the CA of hydra signs only while it's unlocked"; !errors.Is(err, platform.ErrLocked) || err.Error() != want {
		t.Errorf("Issue while locked = %v, want %q", err, want)
	}
}

// badPub is a platform whose new keys come with a public key that does not
// parse.
type badPub struct{ *spyPlatform }

func (b badPub) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) ([]byte, []byte, error) {
	h, _, err := b.spyPlatform.CreateKey(purpose, auth, access)
	return h, []byte{4, 1, 2}, err
}

type linuxBadPub struct{ badPub }

func (linuxBadPub) Traits() platform.Traits { return platform.LinuxTraits }

// The chip's name in error texts: "enclave" on macOS, "TPM" on Linux.
func TestLinuxUnusablePublicKeyMessage(t *testing.T) {
	for _, tc := range []struct {
		linux bool
		want  string
	}{{false, "k8s: the enclave returned an unusable public key: "}, {true, "k8s: the TPM returned an unusable public key: "}} {
		var p platform.Platform = badPub{newSpy(t)}
		if tc.linux {
			p = linuxBadPub{badPub{newSpy(t)}}
		}
		s := NewStore(k8sKind(), p, &spyVault{Vault: fake.NewVault()}, func() time.Time { return t0 })
		_, err := s.Create("hydra", platform.AccessWhenUnlocked)
		if err == nil || len(err.Error()) < len(tc.want) || err.Error()[:len(tc.want)] != tc.want {
			t.Errorf("linux %v: %v, want prefix %q", tc.linux, err, tc.want)
		}
	}
}
