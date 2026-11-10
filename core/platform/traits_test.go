package platform_test

import (
	"testing"
	"time"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// A platform that does not describe itself is macOS: every Platform before
// Linux (the Swift bridge, the fake) keeps its wording and code signing.
func TestTraitsOfDefaultsToMac(t *testing.T) {
	if got := platform.TraitsOf(fake.New(time.Now())); got != platform.MacTraits {
		t.Fatalf("TraitsOf(fake) = %+v, want MacTraits", got)
	}
}

type linuxFake struct{ *fake.Fake }

func (linuxFake) Traits() platform.Traits { return platform.LinuxTraits }

func TestTraitsOfDescriber(t *testing.T) {
	if got := platform.TraitsOf(linuxFake{fake.New(time.Now())}); got != platform.LinuxTraits {
		t.Fatalf("TraitsOf(describer) = %+v, want LinuxTraits", got)
	}
}

// The two sets are what the messages are built from: a changed word is a
// changed message on one platform, so they are pinned here.
func TestTraitsValues(t *testing.T) {
	mac := platform.Traits{CodeSigning: true, Enforcer: "the chip", LoginGate: "Touch ID", Machine: "the Mac", Chip: "the Secure Enclave", PinWord: "team"}
	linux := platform.Traits{CodeSigning: false, Enforcer: "nazar", LoginGate: "your password", Machine: "the screen", Chip: "the TPM", PinWord: "executable hash"}
	if platform.MacTraits != mac {
		t.Errorf("MacTraits = %+v", platform.MacTraits)
	}
	if platform.LinuxTraits != linux {
		t.Errorf("LinuxTraits = %+v", platform.LinuxTraits)
	}
	if platform.TraitsOf(nil) != platform.MacTraits {
		t.Error("TraitsOf(nil) must be MacTraits")
	}
}

func TestTraitsKeyChip(t *testing.T) {
	if got := platform.MacTraits.KeyChip(); got != "enclave" {
		t.Errorf("mac: %q", got)
	}
	if got := platform.LinuxTraits.KeyChip(); got != "TPM" {
		t.Errorf("linux: %q", got)
	}
}

func TestTraitsPresence(t *testing.T) {
	if got := platform.MacTraits.Presence(); got != "Secure Enclave user presence" {
		t.Errorf("mac: %q", got)
	}
	if got := platform.LinuxTraits.Presence(); got != "user presence enforced by nazar" {
		t.Errorf("linux: %q", got)
	}
}
