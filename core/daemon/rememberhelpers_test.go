package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/platform/fake"
)

// The orphaned-tab bug end to end: a request from an iTerm2 tab lets
// nazar-agent see the tab's iTermServer below iTerm2; iTerm2 restarts (an
// update) and the tab lives on under the old server; nazar-agent restarts
// (an install). The new agent still knows the server, so the tab is
// iTerm2's (through its helper), not unknown.
func TestAgentRemembersHelpersAcrossRestarts(t *testing.T) {
	e := start(t)
	tab := e.f.ITermTab(platform.ProcessRef{}, fake.SSHProc("git@github.com"))
	e.f.SetDefaultPeer(tab.Peer())
	e.status(t) // any request from the tab
	waitFor(t, func() bool { _, err := e.vault.Get(caller.HelpersVaultItem); return err == nil })
	e.f.Exit(tab.App)
	fresh := e.f.ITermTab(platform.ProcessRef{})

	e.relaunch(t)
	c := e.d.resolver.Resolve(tab.Peer())
	if c.Unknown || c.AppSource != caller.AppFromHelper || c.App.Ref != fresh.App || c.SessionRoot != tab.Shell {
		t.Fatalf("after the restart: unknown=%v source=%v app=%v root=%v", c.Unknown, c.AppSource, c.App.Ref, c.SessionRoot)
	}
}

// A helpers item the agent can't read (another build's, or one another
// program planted) is reported with the command that removes it, and the
// agent runs on without it.
func TestUnreadableHelpersItemIsReported(t *testing.T) {
	var v *otherBuildVault
	e := startWith(t, func(f *fake.Fake, o *Options) {
		inner := o.Vault.(*fake.Vault)
		inner.Put(caller.HelpersVaultItem, []byte("written by the previous build"))
		v = &otherBuildVault{Vault: inner, foreign: map[string]bool{caller.HelpersVaultItem: true}}
		o.Vault = v
	})
	st := e.status(t)
	if len(st.Vault) != 1 || st.Vault[0].Item != caller.HelpersVaultItem ||
		!strings.Contains(st.Vault[0].Reason, "another signature of the agent") || st.Vault[0].Effect == "" {
		t.Fatalf("vault problems %+v", st.Vault)
	}
	e.followRemedies(t, v, st.Vault)
	if st := e.status(t); len(st.Vault) != 0 {
		t.Fatalf("still reported after the remedy: %+v", st.Vault)
	}
	waitFor(t, func() bool { _, err := v.Get(caller.HelpersVaultItem); return !errors.Is(err, platform.ErrNotFound) })
}
