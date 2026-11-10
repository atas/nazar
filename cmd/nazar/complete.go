package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/control"
)

// Shell completion: `nazar __complete <args>` (cobra's protocol, run by the
// script `nazar completion <shell>` prints). It never runs a command and
// never prompts. The names it offers come from nazar-agent through
// completionCommands only, the read-only list calls of `nazar ssh-key
// list`, `secret list`, `k8s list`, `aws list` and `apps list`, over the same verified
// control socket, each bounded by completionTimeout; any error (no agent,
// a refused peer, a timeout, a malformed reply) offers no names and prints
// nothing. It reads no file, runs no program (no ssh -G, no git), writes
// nothing and stages nothing.

// completionTimeout bounds each list call, so a stalled agent can't hang
// the shell.
const completionTimeout = 500 * time.Millisecond

// completionCommands are the only control commands completion sends:
// read-only lists (TestCompletionSendsOnlyReadOnlyLists).
var completionCommands = map[string]string{
	control.CmdSSHKeyList: control.KindSSHKeyList,
	control.CmdSecretList: control.KindSecretList,
	control.CmdK8sList:    control.KindK8sContextList,
	control.CmdAWSList:    control.KindAWSEntryList,
	control.CmdAppsList:   control.KindAppList,
}

// complete serves `nazar __complete …`: cobra's completion of args, on
// stdout, nothing on stderr. Exit 0 always: the shell reads stdout only.
func (a *app) complete(args []string) int {
	defer func(w io.Writer) { a.stderr = w }(a.stderr)
	a.stderr = io.Discard // the NAZAR_TEST_PEER warning, say
	// cobra appends its debug lines to this file when it is set.
	os.Unsetenv("BASH_COMP_DEBUG_FILE")
	root := a.commands(true)
	root.SetArgs(args)
	root.SetOut(a.stdout)
	root.SetErr(io.Discard)
	root.SetIn(strings.NewReader(""))
	_ = root.Execute()
	return control.ExitOK
}

// completionList sends one read-only list call and decodes its reply into
// out; false on any error.
func (a *app) completionList(cmd string, out any) bool {
	kind, ok := completionCommands[cmd]
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), completionTimeout)
	defer cancel()
	return a.client().Call(ctx, control.NewRequest(cmd, nil), kind, out) == nil
}

// completionText is a reply string as a completion description: one line,
// no tab (cobra's separator), escaped as the human views escape it.
func completionText(s string) string {
	return strings.ReplaceAll(term(s), "\t", " ")
}

func (a *app) keyList() []control.SSHKey {
	var l control.SSHKeyList
	if !a.completionList(control.CmdSSHKeyList, &l) {
		return nil
	}
	return l.Items
}

// keyNames, secretNames and contextNames offer only names their validator
// accepts: a reply is never trusted to be one word for the shell.
func (a *app) keyNames() []string {
	var out []string
	for _, k := range a.keyList() {
		if config.ValidKeyName(k.Name) {
			out = append(out, k.Name+"\t"+completionText(k.Fingerprint))
		}
	}
	return out
}

func (a *app) secretList() []control.Secret {
	var l control.SecretList
	if !a.completionList(control.CmdSecretList, &l) {
		return nil
	}
	return l.Items
}

func (a *app) secretNames() []string {
	var out []string
	for _, s := range a.secretList() {
		if config.ValidSecretName(s.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}

func (a *app) contextList() []control.K8sContext {
	var l control.K8sContextList
	if !a.completionList(control.CmdK8sList, &l) {
		return nil
	}
	return l.Items
}

func (a *app) contextNames() []string {
	var out []string
	for _, c := range a.contextList() {
		if config.ValidK8sContextName(c.Name) {
			out = append(out, c.Name)
		}
	}
	return out
}

func (a *app) awsEntries() []control.AWSEntry {
	var l control.AWSEntryList
	if !a.completionList(control.CmdAWSList, &l) {
		return nil
	}
	return l.Items
}

func (a *app) awsNames() []string {
	var out []string
	for _, e := range a.awsEntries() {
		if config.ValidAWSName(e.Name) {
			out = append(out, e.Name)
		}
	}
	return out
}

// ruleNumbers offers the rule numbers of a key's, secret's or context's
// rules, each described by its apps, gate and scope.
func (a *app) ruleNumbers(t ruleTarget, name string) []string {
	var policy *control.SSHKeyRules
	switch t.cmd {
	case "ssh-key":
		for _, k := range a.keyList() {
			if k.Name == name {
				policy = k.Policy
			}
		}
	case "secret":
		for _, s := range a.secretList() {
			if s.Name == name {
				policy = s.Policy
			}
		}
	case "k8s":
		for _, c := range a.contextList() {
			if c.Name == name {
				policy = c.Policy
			}
		}
	case "aws":
		for _, e := range a.awsEntries() {
			if e.Name == name {
				policy = e.Policy
			}
		}
	}
	if policy == nil {
		return nil
	}
	var out []string
	for _, r := range policy.Rules {
		if r.Index > 0 {
			out = append(out, fmt.Sprintf("%d\t%s", r.Index, completionText(fmt.Sprintf("apps %s, gate %s, scope %s", refList(r.Apps), r.Policy.Gate, r.Policy.Scope))))
		}
	}
	return out
}

// completeMatchers completes the last item of a --apps or --to list: any,
// unknown, the apps: names and inline matchers nazar-agent knows, and the
// app:, signed: and path: prefixes.
func (a *app) completeMatchers(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	prefix := ""
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		prefix = toComplete[:i+1]
	}
	refs := []string{"any\tany caller", "unknown\ta chain with no app", "app:\tapp:<bundle-id>", "signed:\tsigned:<team>[:<id>]", "path:\tpath:<absolute path>"}
	if a.linux { // no code signatures: no signed:, and app: names a desktop app id
		refs = []string{"any\tany caller", "unknown\ta chain with no app", "app:\tapp:<app-id>", "path:\tpath:<absolute path>"}
	}
	var l control.AppList
	if a.completionList(control.CmdAppsList, &l) {
		seen := map[string]bool{}
		for _, e := range l.Items {
			r := e.Matcher.Ref
			if r == "" || seen[r] || term(r) != r || strings.ContainsAny(r, " \t,") {
				continue
			}
			if _, err := config.ParseMatcherRef(r); err == nil {
				seen[r] = true
				refs = append(refs, r+"\t"+completionText(matcherText(e.Matcher)))
			}
		}
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, prefix+r)
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

// completeBundleIDs offers the bundle ids of the app: matchers nazar-agent
// knows (trust --app, revoke --app).
func (a *app) completeBundleIDs(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var l control.AppList
	if !a.completionList(control.CmdAppsList, &l) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range l.Items {
		id := e.Matcher.ID
		if e.Matcher.Kind != string(config.MatchApp) || id == "" || seen[id] || term(id) != id || strings.ContainsAny(id, " \t") {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeTargets offers log --target values: ssh:<key>, secret:<name>,
// k8s:<context> and aws:<name>.
func (a *app) completeTargets(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var out []string
	for _, k := range a.keyNames() {
		name, _, _ := strings.Cut(k, "\t")
		out = append(out, "ssh:"+name)
	}
	for _, s := range a.secretNames() {
		out = append(out, "secret:"+s)
	}
	for _, c := range a.contextNames() {
		out = append(out, "k8s:"+c)
	}
	for _, e := range a.awsNames() {
		out = append(out, "aws:"+e)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
