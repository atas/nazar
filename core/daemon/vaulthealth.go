package daemon

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/trust"
)

// VaultService is the Keychain service of the agent's vault items (the
// Swift KeychainVault's productionService). The remedies below name it.
const VaultService = "dev.nazar"

// unreadableReason words why a vault item can't be used. With ad-hoc
// signing every rebuild of the agent is a new program to the Keychain, which
// then refuses the items the previous build made, and so is a build
// signed by another certificate (the old Nazar.app, dev.nazar, after the
// Milestone 6 migration); a locked login keychain looks the same from here.
func unreadableReason(item, err string) string {
	return fmt.Sprintf("Keychain item %s can't be read by this nazar-agent: it belongs to another signature of the agent "+
		"(every ad-hoc rebuild, and the old Nazar.app, is a new program to the Keychain), to another program, or the login keychain is locked (%s)", item, err)
}

// deleteItem is the command that removes a vault item by hand, typed by
// the user: nazar-agent itself can't delete an item of another signature
// (securityd refuses its delete as it refuses its read). item must be a
// plain word (pasteable); every caller checks it or passes a constant.
func deleteItem(item string) string {
	return fmt.Sprintf("security delete-generic-password -s %s -a %s", VaultService, item)
}

// plainWordRE is the only alphabet a name may have to go into a pasteable
// command: the bytes of a valid key name (config.ValidKeyName) plus the
// "/" of the vault prefix. A shell reads such a word as itself in every
// macOS shell (sh, bash, zsh, tcsh/csh, fish), so no quoting is ever
// needed. Quoting can't be made safe for all of them: tcsh and csh expand
// ! even inside single quotes, so a quoted attacker-chosen account could
// still run a command when pasted.
var plainWordRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// plainWord reports whether s may go into a pasteable command unquoted.
func plainWord(s string) bool { return plainWordRE.MatchString(s) }

// keyRemedy is what fixes a key whose record can't be used, as steps that
// each work after the one before, after keyCheckFirst: remove its Keychain item by hand
// (nazar-agent can't delete an item of another signature, and an
// unreadable record has no handle nazar could free), then create the key
// again under the same name, which keeps its config entry and rules, then
// put the new public key where the old one was. The steps are joined with
// ", then ", never &&: once the item is gone there is no key left to
// delete, and a step that finds nothing to do must not stop the next.
//
// A name that is not a valid key name is an item nazar did not make: any
// same-user process (a sandboxed one too) can add one under nazar's
// Keychain service, with any account. Such a name never goes into a nazar
// command (nazar can't delete or create it): the only remedy is deleting
// that one item. A command is printed only when its account is a plain
// word (plainWord); any other account (a quote, !, $, a backtick, a
// newline, a NUL, a bidi override, any non-ASCII byte) gets no command at
// all, only the way to remove it by hand, the account shown Go-quoted.
func keyRemedy(name string) string {
	account := keys.VaultPrefix + name
	if !config.ValidKeyName(name) || !plainWord(name) {
		if !plainWord(account) {
			return removeByHand(name)
		}
		return deleteItem(account)
	}
	return fmt.Sprintf("%s%s, then nazar ssh-key create %s, then add the new public key ("+layout.KeysDirTilde+"/%s.pub) where the old one was",
		keyCheckFirst, deleteItem(account), name, name)
}

// keyCheckFirst opens the remedy for a key nazar made. A locked login
// keychain and a nazar-agent installed under the wrong signature read as
// the same unreadable item as one of an old signature, but the key is
// still good: deleting the item would destroy it for good. So the check
// that loses nothing comes first.
const keyCheckFirst = "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
	"and run nazar status again (deleting the item destroys the key for good); if the key is still unreadable: "

// removeByHand is the remedy for a planted item whose account can't go
// into a pasteable command: no command, only where to find it.
func removeByHand(name string) string { return removeItemByHand(keys.VaultPrefix + name) }

func removeItemByHand(item string) string {
	return fmt.Sprintf("remove it by hand in Keychain Access: service %s, account shown as %s", VaultService, strconv.QuoteToASCII(item))
}

// foreignItem is how text for reading names the vault item of a key
// record under a name nazar can't make: Go-quoted, ASCII only, so no
// control character, terminal escape or bidi override in it reaches the
// terminal or the window, and no shell syntax in it reads as a command.
func foreignItem(name string) string { return strconv.QuoteToASCII(keys.VaultPrefix + name) }

// secretCheckFirst opens the remedy for a secret nazar made, as
// keyCheckFirst does for a key: the check that loses nothing comes first.
const secretCheckFirst = "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, " +
	"and run nazar status again (deleting the item destroys the secret for good); if the secret is still unreadable: "

// secretRemedy is keyRemedy for a secret/<name> item (spec 9): the
// check first, then the item removed by hand, then the secret added again
// (from wherever its value is kept). A name nazar can't make gets only the
// delete, and only when its account is a plain word.
func secretRemedy(name string) string {
	account := secrets.VaultPrefix + name
	if !config.ValidSecretName(name) { // a valid secret name is a plain word
		if !plainWord(account) {
			return removeItemByHand(account)
		}
		return deleteItem(account)
	}
	return fmt.Sprintf("%s%s, then nazar secret add %s", secretCheckFirst, deleteItem(account), name)
}

// secretReason says why a secret is unusable.
func secretReason(s secrets.Info) string {
	if !config.ValidSecretName(s.Name) {
		return fmt.Sprintf("Keychain item %s is an item under nazar's Keychain service (%s) that is not a secret nazar made: "+
			"its name is not one nazar accepts for a secret, so nazar never made it and never uses it", strconv.QuoteToASCII(secrets.VaultPrefix+s.Name), VaultService)
	}
	if s.Unreadable {
		return unreadableReason(secrets.VaultPrefix+s.Name, s.Problem)
	}
	return fmt.Sprintf("the record of secret %s can't be used: %s", s.Name, s.Problem)
}

// retrust is the step that pins the config's app: matchers again once the
// trust store is new: `nazar apps list` names, for every app: matcher that
// matches nothing, the command that fixes it.
const retrust = "run the fix nazar apps list names for each app: matcher it shows as not trusted " +
	"(nazar trust --app <bundle-id>)"

// vaultProblems lists the vault items Nazar.app runs without in the order
// that fixes them when followed top to bottom (every item of another
// build, after an ad-hoc rebuild):
//
//  1. config/prompts: every login prompt writes it first (claimLogin), so
//     until it is deleted no gated command (config apply, trust, key
//     delete or create) can run.
//  2. state/trust, deleted only: approving a config records the pins of
//     its app: matchers in the trust store (configstage recordPins), which
//     refuses every write while its item is unreadable, so a config apply
//     before this step fails after the user approved it.
//  3. config/approved: deleted, then `nazar config apply` (which pins the
//     installed apps' teams again), then the matchers are trusted again
//     (`nazar trust --app` needs no config, but only now does `nazar apps list`
//     show what is left). When only state/trust is unreadable, its own
//     remedy carries the re-trust step.
//  4. the keys: `nazar ssh-key create` of an existing entry needs the
//     config in force, nothing staged (sshKeyRecreate), so after step 3.
//     Planted items are listed with the keys; deleting one depends on
//     nothing.
//  5. the secrets: `nazar secret add` needs the config in force
//     too; planted secret/ items as for keys.
//  6. the k8s CAs, then the aws ones, with the remedy `nazar k8s list`
//     and `nazar aws list` give: forget needs the config in force too.
//  7. state/helpers (THREAT-MODEL 5.14): deleted only; removing it depends
//     on nothing, and the agent writes it again by itself.
func (d *Daemon) vaultProblems() []control.VaultProblem {
	var out []control.VaultProblem
	if why := d.prompts.unreadableReason(); why != "" {
		out = append(out, control.VaultProblem{Item: PromptsVaultItem, Reason: unreadableReason(PromptsVaultItem, why),
			Effect: "no approval prompt can open (config changes, key creation and deletion, trust are refused) until it is fixed",
			Remedy: deleteItem(PromptsVaultItem)})
	}
	approvedWhy, trustWhy := d.stager.Unreadable(), d.trust.Unreadable()
	if trustWhy != "" {
		remedy := deleteItem(trust.VaultItem)
		if approvedWhy == "" {
			remedy += ", then " + retrust
		}
		out = append(out, control.VaultProblem{Item: trust.VaultItem, Reason: unreadableReason(trust.VaultItem, trustWhy),
			Effect: "app: matchers match nothing, and no app can be trusted (nor can a config that pins an app be applied)",
			Remedy: remedy})
	}
	if approvedWhy != "" {
		remedy := deleteItem(configstage.ApprovedVaultItem) + ", then nazar config apply"
		if trustWhy != "" {
			remedy += ", then " + retrust
		}
		out = append(out, control.VaultProblem{Item: configstage.ApprovedVaultItem, Reason: unreadableReason(configstage.ApprovedVaultItem, approvedWhy),
			Effect: "nazar runs on the built-in default config (every key blocked) and config.yaml waits for approval",
			Remedy: remedy})
	}
	out = append(out, d.keyProblems()...)
	out = append(out, d.secretProblems()...)
	out = append(out, d.k8sCAProblems()...)
	out = append(out, d.awsCAProblems()...)
	if why := d.resolver.HelpersUnreadable(); why != "" {
		out = append(out, control.VaultProblem{Item: caller.HelpersVaultItem, Reason: unreadableReason(caller.HelpersVaultItem, why),
			Effect: "tabs that outlive their app's restart (iTerm2's, under its old iTermServer) are unknown after nazar-agent restarts, until they are reopened",
			Remedy: deleteItem(caller.HelpersVaultItem)})
	}
	return out
}

// k8sCAProblems lists the unusable k8s-ca/ items, with the reason and the
// remedy `nazar k8s list` gives each.
func (d *Daemon) k8sCAProblems() []control.VaultProblem {
	list, err := d.k8sCA.List()
	if err != nil {
		d.o.Logf("k8s: %v", err)
		return nil
	}
	var out []control.VaultProblem
	for _, i := range list {
		if !i.Broken {
			continue
		}
		why := k8s.ErrBroken
		if i.Unreadable {
			why = k8s.ErrUnreadable
		}
		p := control.VaultProblem{Item: k8s.VaultPrefix + i.Name, Reason: i.Problem,
			Effect: fmt.Sprintf("kubectl gets no credential for context %s", i.Name), Remedy: k8sCAFix(i.Name, why)}
		if !config.ValidK8sContextName(i.Name) {
			p.Item, p.Effect = strconv.QuoteToASCII(p.Item), "none: nazar never uses it as a CA; it is listed so that it can be removed"
		}
		out = append(out, p)
	}
	return out
}

// secretProblems lists the unusable secret/ items, after the keys: adding a
// secret again needs the config in force, nothing staged.
func (d *Daemon) secretProblems() []control.VaultProblem {
	list, err := d.secrets.List()
	if err != nil {
		d.o.Logf("secrets: %v", err)
		return nil
	}
	var out []control.VaultProblem
	for _, s := range list {
		switch {
		case s.Broken && !config.ValidSecretName(s.Name):
			out = append(out, control.VaultProblem{Item: strconv.QuoteToASCII(secrets.VaultPrefix + s.Name), Reason: secretReason(s),
				Effect: "none: nazar never uses it as a secret; it is listed so that it can be removed", Remedy: secretRemedy(s.Name)})
		case s.Broken:
			out = append(out, control.VaultProblem{Item: secrets.VaultPrefix + s.Name, Reason: secretReason(s),
				Effect: fmt.Sprintf("secret %s can't be delivered", s.Name), Remedy: secretRemedy(s.Name)})
		}
	}
	return out
}

// keyProblems lists the unusable ssh-key/ items.
func (d *Daemon) keyProblems() []control.VaultProblem {
	var out []control.VaultProblem
	list, err := d.keys.List()
	if err != nil {
		d.o.Logf("keys: %v", err)
		return out
	}
	for _, k := range list {
		switch {
		case k.Broken && !config.ValidKeyName(k.Name):
			out = append(out, control.VaultProblem{Item: foreignItem(k.Name), Reason: keyReason(k),
				Effect: "none: nazar never uses it as a key; it is listed so that it can be removed", Remedy: keyRemedy(k.Name)})
		case k.Broken:
			out = append(out, control.VaultProblem{Item: keys.VaultPrefix + k.Name, Reason: keyReason(k),
				Effect: fmt.Sprintf("SSH key %s can't sign", k.Name), Remedy: keyRemedy(k.Name)})
		}
	}
	return out
}

// keyReason says why a key is unusable.
func keyReason(k keys.Info) string {
	if !config.ValidKeyName(k.Name) {
		return fmt.Sprintf("Keychain item %s is an item under nazar's Keychain service (%s) that is not a key nazar made: "+
			"its name is not one nazar accepts for a key, so nazar never made it and never uses it", foreignItem(k.Name), VaultService)
	}
	if k.Unreadable {
		return unreadableReason(keys.VaultPrefix+k.Name, k.Problem)
	}
	return fmt.Sprintf("the record of SSH key %s can't be used: %s", k.Name, k.Problem)
}
