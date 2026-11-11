// Command nazar is the CLI for Nazar.app (spec 6). It is a thin client of
// the control socket: it never touches keys, and reads stdin only for the
// value of `nazar secret add`, git's request to its credential helper and
// the answers `nazar k8s ca create` asks for at a terminal.
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func main() {
	a := &app{
		linux:  runtime.GOOS == "linux",
		stdout: os.Stdout,
		stderr: os.Stderr,
		stdin:  os.Stdin,

		stdinTerminal: stdinIsTerminal,
		readHidden:    readHiddenLine,

		noHiddenPrompt: noHiddenPromptOn(runtime.GOOS),

		getenv:       os.Getenv,
		environ:      os.Environ,
		exec:         syscall.Exec,
		resetForExec: resetForExec,
		runLog:       runSystemLog,

		executable:   selfExecutable,
		plistProgram: plistProgram,
		selfTeam:     selfTeamID,
		designated:   designatedRequirement,
		imageUUID:    machoUUID,
		launchctl:    runLaunchctl,
		uid:          os.Getuid,
		openUI:       openUIApp,
		output:       runOutput,
		accountHome:  accountHome,
		selfPath:     os.Executable,
	}
	if a.linux {
		a.systemctl = runSystemctl
		a.sysCommand = runSysCommand
		a.tpmAccess = openTPM
		a.euid = os.Geteuid
		// /proc/self/exe is the versioned file an upgrade removes; the
		// kubeconfig and ~/.aws/config must name the link the user ran.
		a.selfPath = linuxSelfPath
	}
	// Installed as gpg.ssh.program via a symlink named nazar-sign-git
	// (spike S8): git's arguments are ssh-keygen's, never nazar's.
	if filepath.Base(os.Args[0]) == "nazar-sign-git" {
		os.Exit(a.signGit(os.Args[1:]))
	}
	// git-credential-nazar: git's credential helper; git's
	// arguments and stdin are its protocol, never nazar's.
	if filepath.Base(os.Args[0]) == gitCredentialName {
		os.Exit(a.gitCredential(os.Args[1:]))
	}
	os.Exit(a.run(os.Args[1:]))
}
