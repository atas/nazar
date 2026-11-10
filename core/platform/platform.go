// Package platform defines the boundary between the portable Go core and the
// OS-specific layer (spec 4.7). On macOS it is implemented in Swift (Milestone 3)
// and reached through a C shim; tests use core/platform/fake.
package platform

import (
	"errors"
	"fmt"
	"time"
)

// Errors every Platform implementation returns for the matching situation.
var (
	ErrNotFound     = errors.New("platform: not found")
	ErrNoProcess    = errors.New("platform: no such process")
	ErrDenied       = errors.New("platform: user denied")
	ErrAuthRequired = errors.New("platform: key requires an authenticated approval")
	// ErrLocked: the chip refused a key made with AccessWhenUnlocked
	// because the Mac is locked. The platform may tell it only from an
	// operation that already failed; it never decides anything by it.
	// Its text names the Mac: a platform that is not the Mac returns
	// Locked worded with its own Traits().Machine, never this bare.
	ErrLocked = errors.New("platform: the Mac is locked")
	// ErrAmbiguous: InstalledApp found several bundles for the bundle ID
	// signed by different teams, so there is no one team to pin.
	ErrAmbiguous = errors.New("platform: ambiguous")
)

// Locked is ErrLocked worded for one key, as the audit line and the
// caller show it ("keys: the Mac is locked; github signs only while it's
// unlocked"): its message is msg alone, and errors.Is(err, ErrLocked) holds.
func Locked(msg string) error { return lockedError(msg) }

type lockedError string

func (e lockedError) Error() string        { return string(e) }
func (e lockedError) Is(target error) bool { return target == ErrLocked }

// NotFoundError is ErrNotFound with the reason, when the platform knows
// one and the user needs it: an app whose entry exists but whose program
// cannot be matched to any process (on Linux a desktop entry that runs a
// launcher or a script). errors.Is(err, ErrNotFound) holds, so every
// caller that handles ErrNotFound still does; a caller that words the
// refusal shows Reason in place of "not installed". Reason is one plain
// sentence about the app ("its program ... is a shell ..."), with any
// path or name from disk quoted ASCII-only, as the core shows them. The
// macOS platform never returns one.
type NotFoundError struct{ Reason string }

func (e *NotFoundError) Error() string        { return e.Reason }
func (e *NotFoundError) Is(target error) bool { return target == ErrNotFound }

// DialogHow says how a `dialog` gate ended without an Allow, for the audit
// log (since Milestone 5). The values cross the C bridge as the `allowed`
// output of confirm (nazar_bridge.h) next to 0 (denied, no reason given)
// and 1 (allowed), and are part of the contract: 1 is the only value that
// allows, and an unknown value is a plain denial.
type DialogHow int

const (
	DialogNoReason   DialogHow = 0 // denied; the platform did not say how
	DialogDenyButton DialogHow = 2 // the Deny button
	DialogEscape     DialogHow = 3 // the Esc key
	DialogTimedOut   DialogHow = 4 // the dialog's own countdown ran out
	DialogClosed     DialogHow = 5 // closed without an answer (another dialog took its place, the UI was stuck)
)

// String names how the dialog ended, for the audit reason.
func (h DialogHow) String() string {
	switch h {
	case DialogDenyButton:
		return "Deny button"
	case DialogEscape:
		return "Esc"
	case DialogTimedOut:
		return "the dialog timed out"
	case DialogClosed:
		return "the dialog closed without an answer"
	}
	return "no reason given"
}

// DialogDenied is the error Confirm may return, with false, to say how the
// dialog ended. It wraps ErrDenied, so code that only asks "denied?" keeps
// working; a platform that can't tell returns (false, nil) as before.
type DialogDenied struct{ How DialogHow }

func (e DialogDenied) Error() string { return "platform: user denied (" + e.How.String() + ")" }
func (e DialogDenied) Unwrap() error { return ErrDenied }

// Purpose is what a key is for. The numeric values cross the C bridge to
// Swift and are part of the contract.
type Purpose int

const (
	PurposeSign         Purpose = 1 // ssh (ecdsa-sha2-nistp256)
	PurposeKeyAgreement Purpose = 2 // secrets (Phase 2)
)

// String names the purpose; an out-of-range value is printed as
// "purpose(N)" so a corrupt record never reads like a valid one.
func (p Purpose) String() string {
	switch p {
	case PurposeSign:
		return "sign"
	case PurposeKeyAgreement:
		return "key-agreement"
	}
	return fmt.Sprintf("purpose(%d)", int(p))
}

// AuthPolicy is the hardware-level protection of a key (spec 4.5) and the
// policy passed to Authenticate. The numeric values cross the C bridge.
type AuthPolicy int

const (
	// AuthNone: no Secure Enclave user-presence requirement; nazar's own gate is the only check.
	AuthNone AuthPolicy = 0
	// AuthUserPresence: .privateKeyUsage + .userPresence. Sign needs an ApprovalRef from Authenticate.
	AuthUserPresence AuthPolicy = 1
)

// Access is when the chip lets a key work at all (its keychain
// accessibility class), fixed for the key's life. The numeric values cross
// the C bridge, and the zero value is the stricter one: every key made
// before Access existed is AccessWhenUnlocked.
type Access int

const (
	// AccessWhenUnlocked: kSecAttrAccessibleWhenUnlockedThisDeviceOnly. The
	// key works only while the Mac is unlocked; while it is locked Sign and
	// KeyAgreement return ErrLocked.
	AccessWhenUnlocked Access = 0
	// AccessAfterFirstUnlock: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.
	// The key also works while the screen is locked, once the user has
	// logged in since the Mac started.
	AccessAfterFirstUnlock Access = 1
)

// String names the access; an out-of-range value is printed as "access(N)".
func (a Access) String() string {
	switch a {
	case AccessWhenUnlocked:
		return "when-unlocked"
	case AccessAfterFirstUnlock:
		return "after-first-unlock"
	}
	return fmt.Sprintf("access(%d)", int(a))
}

// Valid reports whether a is one of the defined values.
func (a Access) Valid() bool { return a == AccessWhenUnlocked || a == AccessAfterFirstUnlock }

// Fits reports whether a key with auth may be made with access: a key
// that asks for the user on every use can't work while the Mac is
// locked, so AuthUserPresence takes AccessWhenUnlocked only.
func (a Access) Fits(auth AuthPolicy) bool {
	return a.Valid() && (auth != AuthUserPresence || a == AccessWhenUnlocked)
}

// String names the policy; an out-of-range value is printed as "auth(N)".
func (a AuthPolicy) String() string {
	switch a {
	case AuthNone:
		return "none"
	case AuthUserPresence:
		return "user-presence"
	}
	return fmt.Sprintf("auth(%d)", int(a))
}

// ApprovalRef is an opaque handle to an authenticated context kept on the
// platform side (an LAContext on macOS). Zero means "no approval".
//
// Contract for every implementation (spec 4.7):
//   - a ref value is never reused within a process, even after it has been
//     released, so a stale ref held by core code can never name a newer
//     approval;
//   - an unknown ref (never issued, forged, or a value next to a live one)
//     and a released ref both mean "no approval": Sign and KeyAgreement on
//     an AuthUserPresence key return ErrAuthRequired, and the platform must
//     never crash or panic on such a value;
//   - ReleaseApproval of zero, of an unknown ref or of an already-released
//     ref is a no-op, and releasing one ref leaves every other ref live;
//   - a denied Authenticate returns ErrDenied with a zero ref.
type ApprovalRef uint64

// Prompt is what a login prompt or confirm dialog shows (spec 4.4).
type Prompt struct {
	Title string   // `iTerm2 wants to use key "github"`
	Lines []string // body lines, already redacted
	// CommandLine is the line number (1-based) in Lines of what the user
	// ran, which the platform shows as code (monospaced, in a box); 0, the
	// zero value, when there is none.
	CommandLine int
	Unknown     bool          // show the prominent "Unknown app" header
	Reason      string        // LocalAuthentication reason text
	Timeout     time.Duration // the platform dismisses the prompt after this
}

// ProcessRef identifies one process instance. Generation distinguishes a
// recycled PID from the process that held it before.
//
// What Generation is (spike S3): on macOS it is the process's start time
// (kinfo_proc p_starttime from sysctl KERN_PROC_PID, as microseconds since
// the Unix epoch), because that is the one value every lookup route can
// provide. The peer of a socket is identified by its audit token
// (LOCAL_PEERTOKEN: PID plus pidversion), and the platform turns that into
// a full ref by reading the KERN_PROC_PID record of that PID while the
// token's pidversion still matches; a parent found while walking the chain
// is named by KERN_PROC_PID's ppid, a bare PID, and the responsible-process
// lookup also returns a bare PID. On Linux it is the start ticks from
// /proc/<pid>/stat plus one, so it is never zero. The fake uses any number
// unique per launch. Core code never interprets the value; it only
// compares refs for equality.
//
// Generation 0 means a PID-only ref: the platform knows the PID but not
// which instance holds it. ProcessInfo.Parent and ResponsibleFor may return
// PID-only refs; Process accepts one and answers with the live occupant's
// full ref. PeerOf never returns a PID-only ref, and core/caller refuses a
// PID-only peer and validates every PID-only parent or responsible ref
// against the full ref and start time of what Process answers.
type ProcessRef struct {
	PID        int
	Generation uint64
}

// IsZero reports whether r is the zero ref ("no process"). A ref with only
// one field set still names a process instance: {PID, 0} is a PID-only ref.
func (r ProcessRef) IsZero() bool { return r.PID == 0 && r.Generation == 0 }

// IsPIDOnly reports whether r names a PID without saying which process
// instance holds it (Generation 0 with a non-zero PID).
func (r ProcessRef) IsPIDOnly() bool { return r.PID != 0 && r.Generation == 0 }

// String formats r as "pid/generation".
func (r ProcessRef) String() string { return fmt.Sprintf("%d/%d", r.PID, r.Generation) }

// CodeIdentity is a process's code signature as verified by the platform.
type CodeIdentity struct {
	Signed    bool   // a valid signature that the running code satisfies
	TeamID    string // empty for Apple platform binaries and ad-hoc code
	SigningID string // e.g. com.anthropic.claude-code
	Apple     bool   // Apple-signed (anchor apple)
	AdHoc     bool   // ad-hoc signed: proves nothing about the author
	CDHash    []byte // code directory hash of the running code
}

// Team returns the identity used by `signed:`/`app:` matchers: "apple" for
// Apple-signed code, the team ID for Developer ID code, "" otherwise.
// Unsigned and ad-hoc code yields "" whatever the other fields claim, so it
// can never match a team or "apple".
func (c CodeIdentity) Team() string {
	if !c.Signed || c.AdHoc {
		return ""
	}
	if c.Apple {
		return "apple"
	}
	return c.TeamID
}

// ProcessInfo is one record of the caller chain (spec 4.1 step 2). Ref is
// always a full ref (non-zero Generation) for a live process.
type ProcessInfo struct {
	Ref ProcessRef
	// Parent is zero at the top of the tree. It may be a PID-only ref
	// (Generation 0): on macOS KERN_PROC_PID gives only the parent's PID.
	// The parent, when live, started no later than this process.
	Parent    ProcessRef
	UID       int
	StartTime time.Time
	Path      string
	Args      []string
	Cwd       string
	Code      CodeIdentity
	// Comm is the kernel's short name for the process (macOS p_comm, at
	// most 16 bytes): the file name the executable was started under. It
	// is for display only, when Path is empty because the executable's
	// file is gone (deleted by an update while the process runs).
	Comm string
}

// AppInfo is a GUI app bundle found in (or responsible for) a chain.
type AppInfo struct {
	Ref      ProcessRef
	BundleID string
	Name     string
	Code     CodeIdentity
}

// AppBundle is an app installed on disk, as found by InstalledApp: the
// bundle's path and the static code signature of the bundle at that path.
// Code.Team() is what an `app:` pin records; an ad-hoc or unsigned bundle
// has no team and can't be pinned.
type AppBundle struct {
	BundleID string
	Path     string
	Code     CodeIdentity
}

// Warning is the non-modal block warning with no allow button (spec 4.4).
// Showing a Warning with an ID already on screen updates that window.
type Warning struct {
	ID            string
	Title         string
	Lines         []string
	CommandLine   int // line number (1-based) in Lines of what the user ran, shown as code; 0 for none
	Count         int
	SuggestedRule string
}

// Platform is the OS/hardware layer (spec 4.7). Every method may be called
// from any goroutine; blocking methods block only the calling goroutine.
//
// The contract below is checked by core/platform/conformance, which every
// implementation (the fake now, Swift in Milestone 3) runs.
type Platform interface {
	// Keys. Handles are opaque bytes. publicKey is the X9.63 uncompressed
	// point (0x04||X||Y). Sign hashes digestInput with SHA-256 and returns an
	// ASN.1 DER ECDSA signature. An unknown, empty or deleted handle is
	// ErrNotFound; a key works only for the purpose it was created with; an
	// out-of-range purpose, policy or access is refused, never silently
	// weakened, and AuthUserPresence takes AccessWhenUnlocked only
	// (Access.Fits). An AuthNone key ignores the approval argument. A key
	// made with AccessWhenUnlocked can't be made or used while the Mac is
	// locked: ErrLocked.
	CreateKey(purpose Purpose, auth AuthPolicy, access Access) (handle, publicKey []byte, err error)
	Sign(handle, digestInput []byte, approval ApprovalRef) ([]byte, error)
	KeyAgreement(handle, peerPublicKey []byte, approval ApprovalRef) ([]byte, error)
	DeleteKey(handle []byte) error

	// Approvals. Authenticate is the `login` gate; it returns ErrDenied (and
	// a zero ref) when the user cancels. Confirm is the hardware-input-only
	// `dialog` gate and returns exactly what the user answered: true only
	// for Allow; a denial is false with a nil error or with a DialogDenied
	// saying how the dialog ended (Deny, Esc, its countdown, closed).
	//
	// Approval refs (see ApprovalRef): a ref value is never reused within a
	// process; an unknown or released ref means "no approval", so Sign and
	// KeyAgreement with it on an AuthUserPresence key return ErrAuthRequired
	// and must never crash; ReleaseApproval of zero, unknown or released
	// refs is a no-op.
	Authenticate(policy AuthPolicy, prompt Prompt) (ApprovalRef, error)
	Confirm(prompt Prompt) (bool, error)
	ReleaseApproval(ref ApprovalRef)

	// Callers. PeerOf uses the audit token (LOCAL_PEERTOKEN), never a bare
	// PID, and always returns a full ref (non-zero Generation). Process
	// walks with sysctl KERN_PROC_PID (spike S3): given a full ref it
	// answers only that instance (a tampered Generation, an exited process,
	// the zero ref and a negative or absent PID are ErrNoProcess); given a
	// PID-only ref it answers the live occupant of the PID with its full
	// ref. AppFor returns the first GUI app bundle in chain (peer first),
	// decided from the platform's own knowledge of the process (never from
	// the record's path), so a forged record is never an app. CodeHash of a
	// path with no file is ErrNotFound.
	PeerOf(socketFD int) (ProcessRef, error)
	Process(ref ProcessRef) (ProcessInfo, error)
	AppFor(chain []ProcessInfo) (AppInfo, bool)
	// Apps lists the running GUI apps: for each, what AppFor answers for
	// that process's own record (a full ref, the live code identity), in no
	// particular order; nil when there are none or the platform can't list
	// them. core/caller uses it to find the app an orphaned helper stands
	// for (spec 4.1 step 3, Milestone 7) and re-checks every entry through
	// Process and AppFor, so the list is a set of candidates, never an
	// answer in itself.
	Apps() []AppInfo
	CodeHash(path string) ([]byte, error)
	// ResponsibleFor is the responsible-process lookup (spike S3) used when a
	// chain ends at launchd without an app: to show the app for an unknown
	// chain, and to refuse a helper that is still responsible to a live
	// process (core/caller; macOS makes a process answer for itself once
	// the process responsible for it has exited). ok is false when unknown.
	// On macOS the answer is a PID-only ref (responsibility_get_pid_
	// responsible_for_pid gives a bare PID); core/caller resolves and
	// checks it.
	ResponsibleFor(ref ProcessRef) (ProcessRef, bool)
	// InstalledApp resolves the app bundle INSTALLED for bundleID (on macOS:
	// the LaunchServices registration in /Applications or ~/Applications
	// and the static code signature of that bundle; Milestone 3). It is
	// what config approval and `nazar trust --app` pin an `app:` matcher's
	// team from (spec 4.2); matching never calls it and never pins. It
	// returns ErrNotFound when no bundle is installed and ErrAmbiguous when
	// the installed bundles are signed by different teams.
	InstalledApp(bundleID string) (AppBundle, error)

	// Events. fn runs exactly once, on any goroutine, after the process
	// named by the full ref exits; if that process is already gone, or never
	// existed, fn runs promptly. OnScreenLock registers fn for every lock;
	// both return without blocking.
	OnProcessExit(ref ProcessRef, fn func())
	OnScreenLock(fn func())

	// ShowWarning shows or updates the block warning (non-modal, returns at once).
	ShowWarning(w Warning)
}

// Vault stores small values that only Nazar.app can read: on macOS a login
// Keychain item whose access list trusts only Nazar.app (spec 4.5, 4.8).
// Get returns ErrNotFound for a missing name.
type Vault interface {
	Get(name string) ([]byte, error)
	Put(name string, value []byte) error
	Delete(name string) error
	List(prefix string) ([]string, error)
}
