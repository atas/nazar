// Command nazar is the CLI for Nazar.app (spec 6). It is a thin client of
// the control socket: it never touches keys, and reads stdin only for the
// value of `nazar secret add`, git's request to its credential helper and
// the answers `nazar k8s ca create` asks for at a terminal.
package main

import (
	"os"
	"path/filepath"
	"syscall"
)

func main() {
	a := &app{
		stdout: os.Stdout,
		stderr: os.Stderr,
		stdin:  os.Stdin,

		stdinTerminal: stdinIsTerminal,
		readHidden:    readHiddenLine,
		getenv:        os.Getenv,
		environ:       os.Environ,
		exec:          syscall.Exec,
		resetForExec:  resetForExec,
		runLog:        runSystemLog,

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
