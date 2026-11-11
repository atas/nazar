package platform

import "strings"

// Traits are what differs between platforms in what nazar can match and in
// the words its messages use. The core builds every such message from the
// traits of the platform it runs on, so a Linux user never reads about a
// chip or a Mac they don't have, and a macOS message stays as it was.
type Traits struct {
	// CodeSigning: the platform has code signatures, so signed: and
	// app: with team: can match (macOS). Without it config check refuses
	// them, since they could never match anything.
	CodeSigning bool
	// Enforcer is who enforces an always-ask or when-unlocked key:
	// "the chip" (macOS) or "nazar" (Linux).
	Enforcer string
	// LoginGate is what the login gate asks for: "Touch ID" or
	// "your password".
	LoginGate string
	// Machine is what is locked: "the Mac" or "the screen"
	// ("the screen is locked").
	Machine string
	// Chip is where keys are made: "the Secure Enclave" or "the TPM".
	Chip string
	// PinWord is what an app: pin records: "team" or "executable hash".
	PinWord string
}

var (
	MacTraits   = Traits{CodeSigning: true, Enforcer: "the chip", LoginGate: "Touch ID", Machine: "the Mac", Chip: "the Secure Enclave", PinWord: "team"}
	LinuxTraits = Traits{CodeSigning: false, Enforcer: "nazar", LoginGate: "your password", Machine: "the screen", Chip: "the TPM", PinWord: "executable hash"}
)

// Describer is a Platform that says which traits it has. One that is not
// (the Swift bridge, the fake) is macOS.
type Describer interface{ Traits() Traits }

// Presence names what a key made with AuthUserPresence has, for messages
// such as "created with Secure Enclave user presence": the chip's own on
// macOS, nazar's prompt on every use elsewhere.
func (t Traits) Presence() string {
	if t.Enforcer == MacTraits.Enforcer {
		return strings.TrimPrefix(t.Chip, "the ") + " user presence"
	}
	return "user presence enforced by " + t.Enforcer
}

// KeyChip names the chip in the core's error texts, as in "create
// enclave key": "enclave" on macOS, "TPM" on Linux.
func (t Traits) KeyChip() string {
	if t.Chip == MacTraits.Chip {
		return "enclave"
	}
	return strings.TrimPrefix(t.Chip, "the ")
}

// TraitsOf returns p's Traits when it is a Describer, else MacTraits.
func TraitsOf(p Platform) Traits {
	if d, ok := p.(Describer); ok {
		return d.Traits()
	}
	return MacTraits
}
