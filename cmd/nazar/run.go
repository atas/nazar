package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/secrets/envpolicy"
)

// `nazar run --secret NAME -- command…` (secrets design 6.3, D3):
// the CLI sends the command line and its own environment, nazar-agent
// resolves, asks and replies with the plan, and the CLI execs exactly the
// plan in place. The value never passes through the CLI: the program's
// loader takes it from nazar-agent after the exec.

// errGotPlan ends the control exchange once the plan arrived: Do returns
// and closes the connection; the agent watches the exec, not the socket.
var errGotPlan = errors.New("got the plan")

func (a *app) runSecret(args []string) int {
	sep := slices.Index(args, "--")
	if sep < 0 {
		return a.usageError("run: the command goes after --: nazar run --secret NAME -- command")
	}
	fs := a.flags("run")
	var name onceFlag
	fs.Var(&name, "secret", "")
	if _, err := a.parse(fs, args[:sep], 0); err != nil {
		return a.fail(err)
	}
	if !name.set || name.value == "" {
		return a.usageError("run: --secret NAME is required")
	}
	if !config.ValidSecretName(name.value) {
		return a.usageError("run: invalid secret name %q", name.value)
	}
	argv := args[sep+1:]
	if len(argv) == 0 {
		return a.usageError("run: a command is required after --")
	}
	if a.resetForExec == nil {
		// Before the agent is asked: a prompt for a run that can't happen
		// would be one for nothing.
		return a.fail(control.NewProblem(control.CodeError, "run: not available in this build yet"))
	}
	plan, err := a.requestRun(name.value, argv)
	if err != nil {
		return a.fail(err)
	}
	return a.fail(a.execPlan(plan)) // returns only when the exec did not happen
}

// requestRun sends secret.run and returns the plan nazar-agent replied with.
func (a *app) requestRun(name string, argv []string) (control.RunPlan, error) {
	av, err := json.Marshal(argv)
	if err != nil {
		return control.RunPlan{}, err
	}
	env, err := json.Marshal(callerEnv(a.environ()))
	if err != nil {
		return control.RunPlan{}, err
	}
	// Each is a JSON string inside the request's JSON: escaped again.
	if n := 2*(len(av)+len(env)) + 1024; n > control.MaxLargeRequestSize {
		return control.RunPlan{}, control.NewProblem(control.CodeError, "run: the command line and environment are too large to send (about %d KiB, at most %d KiB)", n/1024, control.MaxLargeRequestSize/1024)
	}
	var plan control.RunPlan
	err = a.client().Do(context.Background(), control.NewRequest(control.CmdSecretRun, map[string]string{"name": name, "argv": string(av), "callerEnv": string(env)}),
		func(kind string, raw json.RawMessage) error {
			if kind != control.KindRunPlan {
				return control.NewProblem(control.CodeError, "control: expected a %s reply, got %s", control.KindRunPlan, kind)
			}
			if err := json.Unmarshal(raw, &plan); err != nil {
				return control.NewProblem(control.CodeError, "control: bad %s reply: %v", control.KindRunPlan, err)
			}
			return errGotPlan
		})
	switch {
	case errors.Is(err, errGotPlan):
		return plan, nil
	case err != nil:
		return control.RunPlan{}, err
	}
	return control.RunPlan{}, control.NewProblem(control.CodeError, "control: no %s in reply", control.KindRunPlan)
}

// callerEnv is the CLI's environment as sent to the agent: the candidates
// for LANG, LC_*, TERM and the secret's envAllow (6.3.4). A variable the
// agent never passes on (envpolicy.Denied) is not sent at all.
func callerEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if _, denied := envpolicy.Denied(k); ok && k != "" && !denied {
			out = append(out, kv)
		}
	}
	return out
}

// errPlan is a plan the CLI can't use as sent.
var errPlan = control.NewProblem(control.CodeError, "run: the plan nazar-agent sent can't be used; nothing was run")

// cleanAbs reports whether p is a clean absolute path.
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// checkPlan checks the plan's shape: what runs, by an absolute path the
// agent pinned, in /, with named variables only.
func checkPlan(p control.RunPlan) error {
	if !cleanAbs(p.ExecPath) || len(p.ExecArgv) == 0 || p.Cwd != "/" {
		return errPlan
	}
	pinned := false
	for _, f := range p.Files {
		if !cleanAbs(f.Path) {
			return errPlan
		}
		pinned = pinned || f.Path == p.ExecPath
	}
	if !pinned {
		return errPlan
	}
	for _, kv := range p.Env {
		if k, _, ok := strings.Cut(kv, "="); !ok || k == "" {
			return errPlan
		}
	}
	return nil
}

// changed is the error for a file or folder that is not what nazar-agent
// checked.
func changed(name string) error {
	return control.NewProblem(control.CodeError, "run: %s changed since nazar-agent checked it; nothing was run", name)
}

// checkFile opens f.Path, a regular file by lstat (no device is ever
// opened), without following a final symlink, blocking on a FIFO or taking
// a terminal, and compares its fstat with the identity the agent pinned.
func checkFile(f control.RunFile) error {
	var lst unix.Stat_t
	if err := unix.Lstat(f.Path, &lst); err != nil || lst.Mode&unix.S_IFMT != unix.S_IFREG {
		return changed(filepath.Base(f.Path))
	}
	fd, err := unix.Open(f.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return changed(filepath.Base(f.Path))
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		uint64(st.Dev) != f.Dev || uint64(st.Ino) != f.Ino || st.Size != f.Size || st.Mtim.Nano() != f.MtimeNs || st.Ctim.Nano() != f.CtimeNs {
		return changed(filepath.Base(f.Path))
	}
	return nil
}

// execPlan checks the plan against the CLI's own view of the files and of
// /, resets the process and execs. It returns only when nothing was run.
func (a *app) execPlan(p control.RunPlan) error {
	if err := checkPlan(p); err != nil {
		return err
	}
	for _, f := range p.Files {
		if err := checkFile(f); err != nil {
			return err
		}
	}
	dir, err := unix.Open(p.Cwd, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return changed(p.Cwd)
	}
	defer unix.Close(dir)
	var st unix.Stat_t
	if err := unix.Fstat(dir, &st); err != nil || uint64(st.Dev) != p.CwdDev || uint64(st.Ino) != p.CwdIno {
		return changed(p.Cwd)
	}
	if err := a.resetForExec(dir); err != nil {
		return control.NewProblem(control.CodeError, "run: %v; nothing was run", err)
	}
	err = a.exec(p.ExecPath, p.ExecArgv, p.Env)
	return control.NewProblem(control.CodeError, "run: exec %s: %v", p.ExecPath, err)
}
