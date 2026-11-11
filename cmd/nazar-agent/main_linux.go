//go:build linux

// Command nazar-agent is nazar's agent on Linux: the unchanged core
// (core/daemon) on the Linux platform (core/platform/linux), as
// nazar-agent.app hosts it on macOS through bridge/. `nazar install` runs
// it as a systemd user service (nazar-agent.service); it listens on
// ~/.nazar/run/agent.sock and ~/.nazar/run/control.sock until SIGTERM or
// SIGINT.
//
// This is the one program that names the real outside things: /dev/tpmrm0,
// the system bus (polkit, logind), the session bus (notifications), the
// user's display session and the desktop's zenity or kdialog
// (seams_release.go). The nazartest build takes each from a NAZAR_TEST_*
// variable instead, for the end-to-end test (seams_nazartest.go); the
// release build reads none of them. The agent refuses to run as root
// (polkit approves root without asking, and the keys would be root's),
// and its home is the user database's, never $HOME.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/atas/nazar/core/audit"
	"github.com/atas/nazar/core/aws"
	"github.com/atas/nazar/core/daemon"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/peertrust"
	"github.com/atas/nazar/core/platform/linux"
	"github.com/atas/nazar/core/platform/linux/dialog"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/procfs"
	"github.com/atas/nazar/core/platform/linux/vault"
	"github.com/atas/nazar/core/platform/pipes"
)

// tpmDevice is the kernel's resource-managed TPM, which `nazar install
// --system` makes readable to the user (the tss group and a udev rule).
const tpmDevice = "/dev/tpmrm0"

// errRoot: the agent must run as the user whose keys it guards.
var errRoot = errors.New("refusing to run as root: run nazar-agent as the user whose keys it guards (nazar install sets up the user service)")

// getuid and lookupHome are the process's uid and the home of a uid in
// the user database. Variables for the tests, and the nazartest build
// wraps lookupHome.
var (
	getuid     = os.Getuid
	lookupHome = passwdHome
)

// passwdHome is the home folder of uid in the user database (getpwuid),
// never $HOME: the sockets, the vault and the audit log are the account's.
func passwdHome(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("looking up uid %d: %w", uid, err)
	}
	if !filepath.IsAbs(u.HomeDir) {
		return "", fmt.Errorf("the home of uid %d in the user database is %q, not an absolute path", uid, u.HomeDir)
	}
	return u.HomeDir, nil
}

// parts is everything the Platform is made of that lives outside this
// process: openParts (one per build) opens them. Notify may be nil (no
// warnings), Subject nil (the display session), Dialog zero (the dialog
// gate errors).
type parts struct {
	TPM                    transport.TPMCloser
	Polkit, Logind, Notify *dbus.Conn
	Subject                func() (polkit.Subject, error)
	Dialog                 dialog.Dialog
	// AWS is the Roles Anywhere client; nil is AWS itself. Only the
	// nazartest build sets it, to the test's fake endpoint.
	AWS *aws.Client
}

// closeBuses closes the bus connections. The TPM is the platform's to
// close once linux.New has it.
func (p *parts) closeBuses() {
	for _, c := range []*dbus.Conn{p.Polkit, p.Logind, p.Notify} {
		if c != nil {
			c.Close()
		}
	}
}

// tpmError words a failure to open the device: the one fix is the
// one-time system install, run with sudo, then a fresh login so the tss
// group applies.
func tpmError(err error) error {
	return fmt.Errorf("can't open %s: %v; run once, then log out and back in: sudo %s install --system", tpmDevice, err, cliPath())
}

// cliPath is the nazar CLI installed next to this binary (the tarball and
// install.sh put both in one folder), for the messages; "nazar" when this
// binary's path cannot be read.
func cliPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "nazar"
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), "nazar")
}

var logger = log.New(os.Stderr, "nazar-agent: ", log.LstdFlags)

func main() { os.Exit(agentMain(os.Stderr)) }

// agentMain is main as the tests call it: uid, home, the parts, then run
// until a signal. Every refusal is one line on stderr and exit 1.
func agentMain(stderr io.Writer) int {
	uid := getuid()
	if uid == 0 {
		fmt.Fprintln(stderr, "nazar-agent:", errRoot)
		return 1
	}
	home, err := lookupHome(uid)
	if err != nil {
		fmt.Fprintln(stderr, "nazar-agent:", err)
		return 1
	}
	p, err := openParts(home, uid)
	if err != nil {
		fmt.Fprintln(stderr, "nazar-agent:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logger.SetOutput(stderr)
	if err := run(ctx, home, uid, p, logger.Printf); err != nil {
		fmt.Fprintln(stderr, "nazar-agent:", err)
		return 1
	}
	return 0
}

// run builds the platform and the daemon on p and serves until ctx ends,
// then closes the platform (the TPM with it) and the buses. The vault is
// the file vault under ~/.nazar/vault, the audit log the file under
// ~/.nazar/log, and the control socket trusts the CLI `nazar install`
// recorded (core/peertrust). Exec, Mounts and LoaderDir stay unset: nazar
// run is not in Linux v1.
func run(ctx context.Context, home string, uid int, p parts, logf func(string, ...any)) error {
	defer p.closeBuses()
	if err := layout.Prepare(home); err != nil {
		p.TPM.Close()
		return err
	}
	v, err := vault.Open(layout.VaultDir(home))
	if err != nil {
		p.TPM.Close()
		return err
	}
	plat, err := linux.New(linux.Options{
		Home:    home,
		TPM:     p.TPM,
		Vault:   v,
		Polkit:  p.Polkit,
		Logind:  p.Logind,
		Notify:  p.Notify,
		Subject: p.Subject,
		Dialog:  p.Dialog,
		UID:     uid,
	})
	if err != nil {
		p.TPM.Close()
		return err
	}
	defer func() {
		if err := plat.Close(); err != nil {
			logf("close: %v", err)
		}
	}()
	d, err := daemon.New(daemon.Options{
		Platform:  plat,
		Vault:     v,
		AuditSink: &audit.FileSink{Path: layout.AuditLog(home), MaxBytes: audit.DefaultFileMax},
		Home:      home,
		Logf:      logf,
		VerifyCLI: peertrust.CLIVerifier(home, procfs.New(), uid, logf),
		Pipes:     pipes.New(),
		AWS:       p.AWS,
	})
	if err != nil {
		return err
	}
	// A screen lock ends every remembered approval (design, "Weaker than
	// macOS" 3): logind's Lock signal, a locked hint, or a lock state
	// that became unknown.
	plat.OnScreenLock(d.ScreenLocked)
	logf("serving %s as uid %d", layout.Root(home), uid)
	return d.Run(ctx)
}
