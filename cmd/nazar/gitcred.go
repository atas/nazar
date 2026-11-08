package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

// gitCredentialName is git's credential helper (secrets design 6.1):
// git runs it for `credential.<url>.helper = nazar`, through
// `git credential-nazar <action>`. It is a link to this CLI; main
// dispatches on it, as on nazar-sign-git.
const gitCredentialName = "git-credential-nazar"

// maxCredentialRequest bounds git's request on stdin.
const maxCredentialRequest = 64 << 10

// gitCredential speaks git's credential protocol. get: git's request on
// stdin (key=value lines up to a blank line or EOF), the answer on stdout
// (username= and password= lines); on any refusal nothing on stdout, the
// reason on stderr and exit 3, so git falls through to its next helper or
// its own prompt. store, erase and any other action do nothing and ask
// nothing: nazar is the source of truth, and an action git adds later must
// not break git.
func (a *app) gitCredential(args []string) int {
	if len(args) != 1 {
		return a.usageError("%s: expected one action (get, store or erase), got %d arguments", gitCredentialName, len(args))
	}
	if args[0] != "get" {
		return control.ExitOK
	}
	req, err := a.readCredential()
	if err != nil {
		return a.fail(err)
	}
	if req["protocol"] != "https" {
		return a.fail(control.NewProblem(control.CodeRefused, "%s: only https is answered", gitCredentialName))
	}
	callArgs := map[string]string{"protocol": "https", "host": req["host"]}
	if u := req["username"]; u != "" {
		callArgs["username"] = u
	}
	var v control.SecretValue
	if err := a.call(control.CmdSecretHelper, callArgs, control.KindSecretValue, &v); err != nil {
		return a.fail(err)
	}
	value, err := base64.StdEncoding.DecodeString(v.ValueBase64)
	defer clear(value)
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "%s: a malformed value came back", gitCredentialName))
	}
	// A newline or NUL would add lines to git's protocol.
	if bytes.ContainsAny(value, "\n\r\x00") || strings.ContainsAny(v.Username, "\n\r\x00") {
		return a.fail(control.NewProblem(control.CodeError, "%s: the secret holds a newline or NUL, which git's credential protocol can't carry", gitCredentialName))
	}
	var out bytes.Buffer
	if v.Username != "" {
		out.WriteString("username=" + v.Username + "\n")
	}
	out.WriteString("password=")
	out.Write(value)
	out.WriteString("\n")
	_, err = a.stdout.Write(out.Bytes())
	clear(out.Bytes())
	if err != nil {
		return control.ExitError
	}
	return control.ExitOK
}

// readCredential reads git's request: key=value lines up to a blank line or
// EOF, at most maxCredentialRequest bytes. protocol and host must each be
// given once; other keys (path, wwwauth[], capability[], …) are ignored,
// and a line without "=" is refused.
func (a *app) readCredential() (map[string]string, error) {
	refuse := func(why string) error {
		return control.NewProblem(control.CodeRefused, "%s: %s", gitCredentialName, why)
	}
	if a.stdin == nil {
		return nil, refuse("no request on stdin")
	}
	got := map[string]string{}
	sc := bufio.NewScanner(io.LimitReader(a.stdin, maxCredentialRequest))
	sc.Buffer(make([]byte, 4096), maxCredentialRequest)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, refuse("a request line without =")
		}
		if k == "protocol" || k == "host" || k == "username" {
			if _, dup := got[k]; dup {
				return nil, refuse(k + " given twice")
			}
			got[k] = v
		}
	}
	if err := sc.Err(); err != nil {
		return nil, refuse("the request could not be read")
	}
	if got["protocol"] == "" || got["host"] == "" {
		return nil, refuse("the request has no protocol or host")
	}
	return got, nil
}

// get is `nazar get NAME` (secrets design 6.5): the value and a newline
// on stdout, nothing else, ever. --json changes only the failure path (a
// Problem): no JSON kind carries a value.
func (a *app) get(args []string) int {
	pos, err := a.parse(a.flags("get"), args, 1)
	if err != nil {
		return a.fail(err)
	}
	if !config.ValidSecretName(pos[0]) {
		return a.usageError("get: invalid secret name %q", pos[0])
	}
	var v control.SecretValue
	if err := a.call(control.CmdSecretGet, map[string]string{"name": pos[0]}, control.KindSecretValue, &v); err != nil {
		return a.fail(err)
	}
	value, err := base64.StdEncoding.DecodeString(v.ValueBase64)
	defer clear(value)
	if err != nil {
		return a.fail(control.NewProblem(control.CodeError, "get: a malformed value came back"))
	}
	if _, err := fmt.Fprintf(a.stdout, "%s\n", value); err != nil {
		return control.ExitError
	}
	return control.ExitOK
}
