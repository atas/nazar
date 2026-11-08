package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/layout"
)

// k8sCredential is `nazar k8s credential <context>`, client-go's exec
// credential plugin (k8s design 1.1, 1.2, 7). It is a pipe: it hands
// KUBERNETES_EXEC_INFO to nazar-agent unparsed and writes the
// ExecCredential it gets back to stdout in one write, nothing else; on any
// failure exactly one line to stderr (kubectl shows it) and the exit code.
//
// client-go passes the kubeconfig's exec env: entries to the plugin, so its
// environment is attacker-writable: KUBERNETES_EXEC_INFO is the only
// variable read, and that is data nazar-agent checks. The control socket is
// <home from the user database>/.nazar/run/control.sock, never $HOME or
// NAZAR_CONTROL_SOCKET; no config file is read; the agent is checked by its
// signature, never with NAZAR_TEST_PEER.
func (a *app) k8sCredential(args []string) int {
	if a.json {
		return a.credFail(control.NewProblem(control.CodeUsage, "k8s credential takes no --json: its stdout is the ExecCredential"))
	}
	pos, err := a.parse(a.flags("k8s credential"), args, 1)
	if err != nil {
		return a.credFail(err)
	}
	name := pos[0]
	if !config.ValidK8sContextName(name) {
		return a.credFail(control.NewProblem(control.CodeUsage, "k8s credential: invalid context name %q", name))
	}
	info := a.getenv("KUBERNETES_EXEC_INFO")
	switch {
	case info == "":
		return a.credFail(control.NewProblem(control.CodeUsage, "%s", k8s.NoExecInfo))
	case len(info) > k8s.MaxExecInfo:
		return a.credFail(control.NewProblem(control.CodeUsage, "KUBERNETES_EXEC_INFO is larger than 48 KiB"))
	}
	c, err := a.credentialClient()
	if err != nil {
		return a.credFail(err)
	}
	var cred control.K8sCredential
	if err := c.Call(context.Background(), control.NewRequest(control.CmdK8sCredential, map[string]string{"name": name, "execInfo": info}), control.KindK8sCredential, &cred); err != nil {
		return a.credFail(err)
	}
	if cred.Name != name {
		return a.credFail(control.NewProblem(control.CodeError, "k8s credential: a credential for another context came back"))
	}
	keyPEM := []byte(cred.ClientKeyData)
	defer clear(keyPEM)
	out, err := k8s.EncodeExecCredential([]byte(cred.ClientCertificateData), keyPEM, cred.ExpirationTimestamp)
	if err != nil {
		return a.credFail(control.NewProblem(control.CodeError, "k8s credential: a malformed credential came back"))
	}
	defer clear(out)
	if _, err := a.stdout.Write(out); err != nil {
		return control.ExitError
	}
	return control.ExitOK
}

// credFail prints one line to stderr, never usage text or JSON, and
// returns the problem's exit code.
func (a *app) credFail(err error) int {
	p := control.AsProblem(err)
	fmt.Fprintf(a.stderr, "nazar: %s\n", term(p.Message))
	return p.ExitCode()
}

// errNoHome: the user database gave no usable home; there is no fallback.
var errNoHome = control.NewProblem(control.CodeError, "cannot find your home directory")

// testCredentialSocket is set only in the nazartest build
// (k8scred_testsock.go), for the integration tests: there, and only for
// k8s credential and aws credential, the socket may come from
// NAZAR_TEST_CONTROL_SOCKET. The
// release build never sets it (TestReleaseBuildHasNoTestSocket).
var testCredentialSocket func(getenv func(string) string) (string, bool)

// credentialClient is the control client of k8s credential and aws
// credential: the socket in
// the passwd home, the agent checked by its signature (a.verifier only in
// tests).
func (a *app) credentialClient() (*control.Client, error) {
	if testCredentialSocket != nil {
		if s, ok := testCredentialSocket(a.getenv); ok {
			return &control.Client{Socket: s, Verifier: control.SameUserVerifier{}}, nil
		}
	}
	// accountHome is the user database's home (getpwuid), never $HOME.
	home := ""
	if a.accountHome != nil {
		home = a.accountHome()
	}
	if home == "" || !filepath.IsAbs(home) {
		return nil, errNoHome
	}
	v := a.verifier
	if v == nil {
		v = a.agentVerifier()
	}
	return &control.Client{Socket: layout.ControlSocket(filepath.Clean(home)), Verifier: v}, nil
}
