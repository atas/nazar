//go:build linux

package peertrust

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

// ErrCLIMismatch: the process on the agent's control socket is not the CLI
// the record names.
var ErrCLIMismatch = errors.New("the process on the control socket is not the nazar that nazar install recorded (it was upgraded or replaced); run nazar install")

// ErrAgentMismatch: the process listening on the control socket is not
// the agent the record names.
var ErrAgentMismatch = errors.New("the agent on the control socket is not the nazar-agent nazar install recorded (it was upgraded or replaced); run nazar install")

// ErrSelfMismatch: this CLI is not the nazar the record names, so the agent
// would refuse it.
var ErrSelfMismatch = errors.New("this nazar is not the nazar that nazar install recorded (it was upgraded or replaced); run nazar install")

// CLIVerifier is the agent's side: the function the control server
// resolves a connection's peer with. The peer must run as uid (SO_PEERCRED,
// recorded by the kernel at connect), be a live process with a full ref
// (procs.PeerOf), and run an image whose SHA-256 (procs.ExeHash, which
// checks the ref before and after the read) is the record's CLI hash,
// read from ~/.nazar/install.json on every call. It returns the peer's
// full ref, for the caller chain; on refusal it returns the zero ref and
// the reason, and says the reason through logf when there is one.
func CLIVerifier(home string, procs *procfs.Procs, uid int, logf func(string, ...any)) func(fd int) (platform.ProcessRef, error) {
	return func(fd int) (platform.ProcessRef, error) {
		ref, err := verify(fd, home, procs, uid, func(r Record) string { return r.CLI.SHA256 }, ErrCLIMismatch)
		if err != nil && logf != nil {
			logf("control: refused a connection: %v", err)
		}
		return ref, err
	}
}

// CheckAgent is the CLI's side: the process at the other end of fd (the
// connection to the control socket) must run as this user and run an
// image whose SHA-256 is the record's agent hash. A mismatch is
// ErrAgentMismatch; no record is ErrNotInstalled.
func CheckAgent(fd int, home string, procs *procfs.Procs) error {
	_, err := verify(fd, home, procs, os.Getuid(), func(r Record) string { return r.Agent.SHA256 }, ErrAgentMismatch)
	return err
}

// CheckSelf is the CLI's check of itself, made before it sends anything:
// the image it runs must hash to the record's CLI. A package upgrade
// replaces both binaries while the old agent keeps running; that agent
// still passes CheckAgent, and refuses the new CLI with CLIVerifier, whose
// reason only the agent's log sees. The running image, /proc/self/exe, is
// what CLIVerifier hashes, whatever now sits at the path. A mismatch is
// ErrSelfMismatch; no record is ErrNotInstalled.
func CheckSelf(home string) error {
	rec, err := Read(home)
	if err != nil {
		return err
	}
	hash, err := HashFile("/proc/self/exe")
	if err != nil {
		return err
	}
	if hash != rec.CLI.SHA256 {
		return ErrSelfMismatch
	}
	return nil
}

// verify is both checks: the uid first, so a stranger's process costs
// nothing more than a getsockopt, then the identity and the hash. The ref
// comes back only when every check passed.
func verify(fd int, home string, procs *procfs.Procs, uid int, want func(Record) string, mismatch error) (platform.ProcessRef, error) {
	if fd < 0 {
		return platform.ProcessRef{}, errors.New("peertrust: bad socket")
	}
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return platform.ProcessRef{}, fmt.Errorf("peertrust: peer credentials: %w", err)
	}
	if int(cred.Uid) != uid {
		return platform.ProcessRef{}, fmt.Errorf("peertrust: peer uid %d is not %d", cred.Uid, uid)
	}
	ref, err := procs.PeerOf(fd)
	if err != nil {
		return platform.ProcessRef{}, fmt.Errorf("peertrust: %w", err)
	}
	hash, err := procs.ExeHash(ref)
	if err != nil {
		return platform.ProcessRef{}, fmt.Errorf("peertrust: %w", err)
	}
	rec, err := Read(home)
	if err != nil {
		return platform.ProcessRef{}, err
	}
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(hash)), []byte(want(rec))) != 1 {
		return platform.ProcessRef{}, mismatch
	}
	return ref, nil
}
