//go:build linux

// Package linux is platform.Platform on a Linux desktop, put together from
// its parts: keys in the TPM (tpm), the file vault the caller opens
// (vault), the login gate through polkit (polkit), the dialog gate through
// zenity or kdialog (dialog), the lock state and warnings through logind
// and the notification server (session), processes from /proc (procfs) and
// desktop apps from their .desktop entries (desktop). It adds only what
// the parts share: the approval refs the login gate issues and the
// user-presence keys check (approvals.go), and the Traits that word the
// core's messages for Linux.
//
// New takes every outside thing explicitly: the TPM transport, the vault,
// the bus connections, the dialog program. Nothing here names
// /dev/tpmrm0 or opens a bus; only cmd/nazar-agent does, so a test is
// never on the host's TPM or desktop.
package linux

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/desktop"
	"github.com/atas/nazar/core/platform/linux/dialog"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/core/platform/linux/session"
	"github.com/atas/nazar/core/platform/linux/tpm"
)

// Options is everything a Platform is made of. TPM, Vault and Logind are
// required. Logind because with no connection no screen lock is ever seen
// and OnScreenLock's callbacks never run, which the design does not allow
// (an unknown state counts as locked: "Weaker than macOS" 3). A connection
// that is there but cannot reach logind is fine: the state is unknown, and
// package session runs the callbacks for it. The rest may be left out, and
// then that part fails closed: no Polkit means the login gate errors, no
// Notify means warnings are dropped, a zero Dialog means the dialog gate
// errors.
type Options struct {
	// Home is the user's home folder, for the default DataDirs.
	Home string
	// TPM is the open TPM transport (/dev/tpmrm0 in production, a swtpm
	// socket in tests). Required: there is no default device. The
	// Platform owns it from New on and closes it with Close.
	TPM transport.TPMCloser
	// Vault holds the TPM key blobs (tpm.VaultPrefix). Required.
	Vault platform.Vault
	// Polkit is the connection polkit is reached on: the system bus.
	Polkit *dbus.Conn
	// Logind is the connection logind is reached on: the system bus in
	// production, a private bus with a fake in tests. Required.
	Logind *dbus.Conn
	// Notify is the connection the notification server is reached on:
	// the session bus. nil: no warnings.
	Notify *dbus.Conn
	// Subject names who asks polkit, resolved on every Authenticate. nil:
	// polkit.SessionSubject of the user's display session (Session.DisplaySession).
	Subject func() (polkit.Subject, error)
	// Dialog is the dialog program (dialog.Find in production).
	Dialog dialog.Dialog
	// DataDirs are the data dirs whose applications folders hold the
	// desktop entries. nil: desktop.DefaultDataDirs(Home).
	DataDirs []string
	// UID is the user's uid, whose sessions logind is asked about.
	UID int
}

// Platform is platform.Platform on Linux. Every method may be called from
// any goroutine.
type Platform struct {
	keys      *tpm.Keys
	auth      *polkit.Authority // nil: no connection to polkit
	dialog    dialog.Dialog
	session   *session.Session
	procs     *procfs.Procs
	apps      *desktop.Index
	approvals approvals
}

var (
	_ platform.Platform  = (*Platform)(nil)
	_ platform.Describer = (*Platform)(nil)
)

// New makes the Platform. It creates the TPM's storage root key, so it
// fails when the TPM cannot be used; nothing else is touched until a
// method is called.
func New(o Options) (*Platform, error) {
	if o.TPM == nil {
		return nil, errors.New("linux: New needs a TPM transport")
	}
	if o.Vault == nil {
		return nil, errors.New("linux: New needs a vault")
	}
	if o.Logind == nil {
		return nil, errors.New("linux: New needs a connection to logind: without one no screen lock can be seen")
	}
	p := &Platform{
		dialog:  o.Dialog,
		session: session.New(o.Logind, o.Notify, o.UID),
		procs:   procfs.New(),
	}
	dataDirs := o.DataDirs
	if dataDirs == nil {
		dataDirs = desktop.DefaultDataDirs(o.Home)
	}
	p.apps = desktop.NewIndex(dataDirs, p.procs)
	if o.Polkit != nil {
		subject := o.Subject
		if subject == nil {
			subject = p.displaySubject
		}
		p.auth = polkit.New(o.Polkit, subject)
	}
	keys, err := tpm.Open(o.TPM, o.Vault, p.session.Locked, p.approvals.isLive)
	if err != nil {
		p.session.Close()
		return nil, fmt.Errorf("linux: %w", err)
	}
	p.keys = keys
	return p, nil
}

// displaySubject is the default polkit subject: the user's display
// session, looked up on every check because it may not exist when the
// agent starts.
func (p *Platform) displaySubject() (polkit.Subject, error) {
	id, err := p.session.DisplaySession()
	if err != nil {
		return polkit.Subject{}, err
	}
	return polkit.SessionSubject(id), nil
}

// Close flushes the storage root key, closes the TPM and stops the
// session's goroutines. The bus connections stay the caller's to close.
func (p *Platform) Close() error {
	p.session.Close()
	return p.keys.Close()
}

// Traits says this is Linux: no code signatures, and messages that name
// nazar, the password, the screen and the TPM.
func (p *Platform) Traits() platform.Traits { return platform.LinuxTraits }

// Keys (tpm.Keys).

func (p *Platform) CreateKey(purpose platform.Purpose, auth platform.AuthPolicy, access platform.Access) (handle, publicKey []byte, err error) {
	return p.keys.CreateKey(purpose, auth, access)
}

func (p *Platform) Sign(handle, digestInput []byte, approval platform.ApprovalRef) ([]byte, error) {
	return p.keys.Sign(handle, digestInput, approval)
}

func (p *Platform) KeyAgreement(handle, peerPublicKey []byte, approval platform.ApprovalRef) ([]byte, error) {
	return p.keys.KeyAgreement(handle, peerPublicKey, approval)
}

func (p *Platform) DeleteKey(handle []byte) error { return p.keys.DeleteKey(handle) }

// Callers (procfs.Procs and desktop.Index).

func (p *Platform) PeerOf(socketFD int) (platform.ProcessRef, error) { return p.procs.PeerOf(socketFD) }

func (p *Platform) Process(ref platform.ProcessRef) (platform.ProcessInfo, error) {
	return p.procs.Process(ref)
}

func (p *Platform) AppFor(chain []platform.ProcessInfo) (platform.AppInfo, bool) {
	return p.apps.AppFor(chain)
}

func (p *Platform) Apps() []platform.AppInfo { return p.apps.Apps() }

func (p *Platform) CodeHash(path string) ([]byte, error) { return p.procs.CodeHash(path) }

func (p *Platform) ResponsibleFor(ref platform.ProcessRef) (platform.ProcessRef, bool) {
	return p.procs.ResponsibleFor(ref)
}

func (p *Platform) InstalledApp(bundleID string) (platform.AppBundle, error) {
	return p.apps.InstalledApp(bundleID)
}

// Events (procfs.Procs and session.Session).

func (p *Platform) OnProcessExit(ref platform.ProcessRef, fn func()) { p.procs.OnProcessExit(ref, fn) }

func (p *Platform) OnScreenLock(fn func()) { p.session.OnScreenLock(fn) }

func (p *Platform) ShowWarning(w platform.Warning) { p.session.ShowWarning(w) }
