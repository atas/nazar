//go:build linux && nazartest

package main

// The nazartest build's outside things, for the end-to-end test
// (test/linux/e2e): a software TPM, private buses with fakes for logind
// and the notification server, a stand-in for zenity, and a home of the
// test's choosing, each named by a NAZAR_TEST_* variable. polkit is still
// the system bus's, the test image's polkitd with the test agent answering
// for this process, so the subject is this process itself. Nothing here is
// in the release build (seams_release.go), and this binary is not the
// agent `nazar install` records, so it gains nothing against a real one.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/godbus/dbus/v5"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/atas/nazar/core/aws"
	"github.com/atas/nazar/core/platform/linux/dialog"
	"github.com/atas/nazar/core/platform/linux/polkit"
	"github.com/atas/nazar/core/platform/linux/procfs"
)

const (
	envHome    = "NAZAR_TEST_HOME"        // the home, in place of the user database's
	envSwtpm   = "NAZAR_TEST_SWTPM"       // the swtpm command socket
	envLogind  = "NAZAR_TEST_LOGIND_BUS"  // the bus address logind is on
	envSession = "NAZAR_TEST_SESSION_BUS" // the bus address the notification server is on
	envDialog  = "NAZAR_TEST_DIALOG"      // the dialog program, run as zenity
	// The Roles Anywhere endpoint and the PEM file of the roots that sign
	// its certificate (core/aws/awstest), both or neither: without them
	// the daemon's AWS client is AWS itself, as in the release build.
	envAWSEndpoint = "NAZAR_TEST_AWS_ENDPOINT"
	envAWSRoots    = "NAZAR_TEST_AWS_ROOTS"
)

func init() {
	passwd := lookupHome
	lookupHome = func(uid int) (string, error) {
		if h := os.Getenv(envHome); h != "" {
			return h, nil
		}
		return passwd(uid)
	}
}

func openParts(home string, uid int) (parts, error) {
	sock := os.Getenv(envSwtpm)
	if sock == "" {
		return parts{}, errors.New(envSwtpm + " is not set (nazartest build)")
	}
	tr, err := linuxudstpm.Open(sock)
	if err != nil {
		return parts{}, fmt.Errorf("can't open the swtpm at %s: %v", sock, err)
	}
	p := parts{TPM: tr}
	fail := func(err error) (parts, error) {
		p.closeBuses()
		tr.Close()
		return parts{}, err
	}
	logindBus := os.Getenv(envLogind)
	if logindBus == "" {
		return fail(errors.New(envLogind + " is not set (nazartest build)"))
	}
	if p.Logind, err = dbus.Connect(logindBus); err != nil {
		return fail(fmt.Errorf("can't reach the logind bus %s: %v", logindBus, err))
	}
	if sessionBus := os.Getenv(envSession); sessionBus != "" {
		if p.Notify, err = dbus.Connect(sessionBus); err != nil {
			return fail(fmt.Errorf("can't reach the session bus %s: %v", sessionBus, err))
		}
	}
	if p.Polkit, err = dbus.ConnectSystemBus(); err != nil {
		return fail(fmt.Errorf("can't reach the system bus, where polkit is: %v", err))
	}
	st, err := procfs.ReadStat(os.Getpid())
	if err != nil {
		return fail(fmt.Errorf("reading this process's start time: %v", err))
	}
	subject := polkit.ProcessSubject(os.Getpid(), st.StartTicks, uid)
	p.Subject = func() (polkit.Subject, error) { return subject, nil }
	if program := os.Getenv(envDialog); program != "" {
		p.Dialog = dialog.Dialog{Program: program, Kind: dialog.Zenity, Env: os.Environ}
	}
	if endpoint, roots := os.Getenv(envAWSEndpoint), os.Getenv(envAWSRoots); endpoint != "" || roots != "" {
		if endpoint == "" || roots == "" {
			return fail(errors.New(envAWSEndpoint + " and " + envAWSRoots + " go together (nazartest build)"))
		}
		pemBytes, err := os.ReadFile(roots)
		if err != nil {
			return fail(fmt.Errorf("can't read the AWS test roots: %v", err))
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return fail(fmt.Errorf("%s holds no certificate", roots))
		}
		p.AWS = &aws.Client{Endpoint: endpoint, RootCAs: pool}
	}
	return p, nil
}
