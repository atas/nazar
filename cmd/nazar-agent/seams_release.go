//go:build linux && !nazartest

package main

// The release build's outside things: the real device, the real buses,
// the display session and the desktop's dialog program. No NAZAR_TEST_*
// variable is read here or anywhere else in this build.

import (
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/atas/nazar/core/platform/linux/dialog"
)

// openParts opens /dev/tpmrm0 first (the one failure a person has to fix
// by hand, so it is the one reported when nothing else is up), then one
// system bus connection each for polkit and logind (both required), the
// session bus for the notification server (optional: no warnings without
// it) and the dialog program (optional: without one the dialog gate says
// what to install, and looks again at each prompt). The polkit subject
// stays nil: the user's display session, looked up on every check.
func openParts(home string, uid int) (parts, error) {
	tr, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return parts{}, tpmError(err)
	}
	p := parts{TPM: tr}
	fail := func(err error) (parts, error) {
		p.closeBuses()
		tr.Close()
		return parts{}, err
	}
	if p.Polkit, err = dbus.ConnectSystemBus(); err != nil {
		return fail(fmt.Errorf("can't reach the system bus, where polkit is: %v", err))
	}
	if p.Logind, err = dbus.ConnectSystemBus(); err != nil {
		return fail(fmt.Errorf("can't reach the system bus, where logind is: %v", err))
	}
	if p.Notify, err = dbus.ConnectSessionBus(); err != nil {
		logger.Printf("no session bus (%v): block warnings will not be shown", err)
		p.Notify = nil
	}
	if p.Dialog, err = dialog.Find(os.Getenv("XDG_CURRENT_DESKTOP"), os.Environ); err != nil {
		logger.Printf("%v: every dialog gate will fail until one is installed", err)
	}
	return p, nil
}
