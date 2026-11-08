package main

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/layout"
)

// sshKeygen is run by absolute path, never via $PATH.
const sshKeygen = "/usr/bin/ssh-keygen"

// statusTimeout bounds the one-shot status call that asks Nazar.app for its
// agent socket: a stalled app must not hang `git commit`.
const statusTimeout = 3 * time.Second

// signGit is the gpg.ssh.program wrapper (spike S8): git runs it with
// ssh-keygen's arguments (-Y sign / verify / find-principals ...); it points
// SSH_AUTH_SOCK at nazar's agent and execs ssh-keygen with the same
// arguments, byte for byte, so ssh-keygen itself is the agent's caller.
// It returns only if the exec failed.
func (a *app) signGit(args []string) int {
	env := []string{"SSH_AUTH_SOCK=" + a.agentSocket()}
	for _, kv := range a.environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			env = append(env, kv)
		}
	}
	err := a.exec(sshKeygen, append([]string{"ssh-keygen"}, args...), env)
	return a.fail(control.NewProblem(control.CodeError, "could not run %s: %v", sshKeygen, err))
}

// agentSocket is $NAZAR_AGENT_SOCK, else the agent socket the running
// Nazar.app reports (Status.AgentPath over the verified control socket: the
// socket of the approved config), else ~/.nazar/run/agent.sock. The config file
// on disk is never read for it: that file is not approved (spec 4.8), so
// anything able to write it could point git's signing at its own agent. No
// app, a peer that fails verification, a problem, a reply of another kind,
// an empty or relative path, or no answer in time all fall back to the
// default; nothing is written to stdout, which git reads the signature from.
func (a *app) agentSocket() string {
	if s := a.getenv("NAZAR_AGENT_SOCK"); s != "" {
		return s
	}
	ctx, cancel := context.WithTimeout(context.Background(), statusTimeout)
	defer cancel()
	var st control.Status
	err := a.client().Call(ctx, control.NewRequest(control.CmdStatus, nil), control.KindStatus, &st)
	if err == nil && filepath.IsAbs(st.AgentPath) {
		return st.AgentPath
	}
	return layout.AgentSocket(a.home())
}
