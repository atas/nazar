package daemon

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/atas/nazar/core/caller"
	"github.com/atas/nazar/core/config"
	"github.com/atas/nazar/core/configstage"
	"github.com/atas/nazar/core/control"
	"github.com/atas/nazar/core/k8s"
	"github.com/atas/nazar/core/keys"
	"github.com/atas/nazar/core/layout"
	"github.com/atas/nazar/core/platform"
	"github.com/atas/nazar/core/secrets"
	"github.com/atas/nazar/core/trust"
)

// VaultService is the Keychain service of the agent's vault items (the
// Swift KeychainVault's productionService). The remedies below name it.
const VaultService = "dev.nazar"

// vaultWords words the vault's reasons and remedies for where the vault
// is: the login Keychain on macOS (files false), one file per item under
// ~/.nazar/vault elsewhere (Linux's file vault: <hex of the item name>.item,
// mode 0600, in a 0700 folder). The package-level functions below are the
// macOS words; the daemon uses d.vault, the words of its platform.
type vaultWords struct{ files bool }

// keychainWords are macOS's.
var keychainWords = vaultWords{}

// vaultWordsOf is the words for a platform with traits tr: only macOS
// keeps the vault in the Keychain.
func vaultWordsOf(tr platform.Traits) vaultWords {
	return vaultWords{files: tr.Chip != platform.MacTraits.Chip}
}

// fileVaultDir is the file vault's folder, as a pasteable path.
const fileVaultDir = "~/.nazar/vault"

// maxHexItemName is the longest item name the file vault files as its hex
// (core/platform/linux/vault, maxHexName); a longer one is filed as its
// sha256.
const maxHexItemName = 116

// itemFile is the file of a file-vault item, as the vault names it: the
// name in hex, or its sha256 in hex when the name is too long for a file
// name. Either way the path is a plain word whatever the item is called.
func itemFile(item string) string {
	if len(item) > maxHexItemName {
		return fmt.Sprintf("%s/%x.item", fileVaultDir, sha256.Sum256([]byte(item)))
	}
	return fmt.Sprintf("%s/%x.item", fileVaultDir, item)
}

// deleted is a delete prompt's line about what is lost. mac is the macOS
// line: the Secure Enclave key is destroyed. In the file vault nothing is
// destroyed: nazar deletes its file, and a copy of the folder made earlier
// still works on the same TPM, so the prompt must not promise otherwise.
func (d *Daemon) deleted(mac, thing string) string {
	if d.traits.Enforcer == platform.MacTraits.Enforcer {
		return mac
	}
	return "nazar deletes its copy of the " + thing + ". A copy of " + fileVaultDir + " made earlier, such as a backup, still works on this TPM."
}

// unreadable is how a refusal says a key's or secret's item can't be read.
func (w vaultWords) unreadable() string {
	if w.files {
		return "its vault item can't be read"
	}
	return "its Keychain item belongs to another signature of the agent, or the login keychain is locked"
}

// caUnreadable is unreadable for a CA's item, which may also be a planted
// one.
func (w vaultWords) caUnreadable() string {
	if w.files {
		return "its vault item can't be read, or the item is not one nazar made"
	}
	return "its Keychain item belongs to another signature of the agent, " +
		"the login keychain is locked, or the item is not one nazar made"
}

// cantRecord is the parenthesis of a vault write that failed: the likely
// cause.
func (w vaultWords) cantRecord() string {
	if w.files {
		return "(can nazar-agent write " + fileVaultDir + "?)"
	}
	return "(is the login keychain locked?)"
}

// unreadableReason words why a vault item can't be used. With ad-hoc
// signing every rebuild of the agent is a new program to the Keychain, which
// then refuses the items the previous build made, and so is a build
// signed by another certificate (the old Nazar.app, dev.nazar, after the
// Milestone 6 migration); a locked login keychain looks the same from here.
// In the file vault no signature is involved: the file is not a regular
// file of the user's, or reading it failed.
func (w vaultWords) unreadableReason(item, err string) string {
	if w.files {
		return fmt.Sprintf("vault item %s can't be read by this nazar-agent: its file %s is not a regular file of yours that it may read "+
			"(a symlink, another owner or a changed mode), or reading it failed (%s)", strconv.QuoteToASCII(item), itemFile(item), err)
	}
	return fmt.Sprintf("Keychain item %s can't be read by this nazar-agent: it belongs to another signature of the agent "+
		"(every ad-hoc rebuild, and the old Nazar.app, is a new program to the Keychain), to another program, or the login keychain is locked (%s)", item, err)
}

// deleteItem is the command that removes a vault item by hand, typed by
// the user: nazar-agent itself can't delete an item of another signature
// (securityd refuses its delete as it refuses its read). item must be a
// plain word (pasteable); every caller checks it or passes a constant.
func deleteItem(item string) string { return keychainWords.deleteItem(item) }

// deleteItem in the file vault removes the item's file, whose name is
// always a plain word.
func (w vaultWords) deleteItem(item string) string {
	if w.files {
		return "rm " + itemFile(item)
	}
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
func keyRemedy(name string) string { return keychainWords.keyRemedy(name) }

func (w vaultWords) keyRemedy(name string) string {
	account := keys.VaultPrefix + name
	if !config.ValidKeyName(name) || !plainWord(name) {
		if !plainWord(account) {
			return w.removeItemByHand(account)
		}
		return w.deleteItem(account)
	}
	return fmt.Sprintf("%s%s, then nazar ssh-key create %s, then add the new public key ("+layout.KeysDirTilde+"/%s.pub) where the old one was",
		w.checkFirst(keyCheckRest, account), w.deleteItem(account), name, name)
}

// checkFirst is the check that loses nothing, before a remedy deletes the
// item: rest is what follows the platform's own step. On macOS a locked
// keychain or the wrong nazar-agent; with the file vault, a file that is
// a symlink, another user's or of a changed mode.
func (w vaultWords) checkFirst(rest, item string) string {
	if w.files {
		return "first, if " + itemFile(item) + " is not a regular file you own with mode 0600 (a symlink, another owner, a changed mode), fix that, " + rest
	}
	return keychainCheck + rest
}

// keyCheckFirst opens the remedy for a key nazar made. A locked login
// keychain and a nazar-agent installed under the wrong signature read as
// the same unreadable item as one of an old signature, but the key is
// still good: deleting the item would destroy it for good. So the check
// that loses nothing comes first.
const keyCheckFirst = keychainCheck + keyCheckRest

// keychainCheck opens every macOS check that comes first.
const keychainCheck = "first, if the login keychain is locked, unlock it, and if this nazar-agent is not the one you installed, reinstall that one, "

const keyCheckRest = "and run nazar status again (deleting the item destroys the key for good); if the key is still unreadable: "

// removeByHand is the remedy for a planted item whose account can't go
// into a pasteable command: no command, only where to find it.
func removeByHand(name string) string { return keychainWords.removeItemByHand(keys.VaultPrefix + name) }

// removeItemByHand in the file vault is still a command: the file's name
// is hex, a plain word, whatever the item is called.
func (w vaultWords) removeItemByHand(item string) string {
	if w.files {
		return fmt.Sprintf("remove its file by hand: %s (item %s)", w.deleteItem(item), strconv.QuoteToASCII(item))
	}
	return fmt.Sprintf("remove it by hand in Keychain Access: service %s, account shown as %s", VaultService, strconv.QuoteToASCII(item))
}

// foreignItem is how text for reading names the vault item of a key
// record under a name nazar can't make: Go-quoted, ASCII only, so no
// control character, terminal escape or bidi override in it reaches the
// terminal or the window, and no shell syntax in it reads as a command.
func foreignItem(name string) string { return strconv.QuoteToASCII(keys.VaultPrefix + name) }

// secretCheckFirst opens the remedy for a secret nazar made, as
// keyCheckFirst does for a key: the check that loses nothing comes first.
const secretCheckFirst = keychainCheck + secretCheckRest

const secretCheckRest = "and run nazar status again (deleting the item destroys the secret for good); if the secret is still unreadable: "

// secretRemedy is keyRemedy for a secret/<name> item (spec 9): the
// check first, then the item removed by hand, then the secret added again
// (from wherever its value is kept). A name nazar can't make gets only the
// delete, and only when its account is a plain word.
func secretRemedy(name string) string { return keychainWords.secretRemedy(name) }

func (w vaultWords) secretRemedy(name string) string {
	account := secrets.VaultPrefix + name
	if !config.ValidSecretName(name) { // a valid secret name is a plain word
		if !plainWord(account) {
			return w.removeItemByHand(account)
		}
		return w.deleteItem(account)
	}
	return fmt.Sprintf("%s%s, then nazar secret add %s", w.checkFirst(secretCheckRest, account), w.deleteItem(account), name)
}

// secretReason says why a secret is unusable.
func (w vaultWords) secretReason(s secrets.Info) string {
	if !config.ValidSecretName(s.Name) && w.files {
		return fmt.Sprintf("vault item %s is an item in nazar's vault (%s) that is not a secret nazar made: "+
			"its name is not one nazar accepts for a secret, so nazar never made it and never uses it", strconv.QuoteToASCII(secrets.VaultPrefix+s.Name), fileVaultDir)
	}
	if !config.ValidSecretName(s.Name) {
		return fmt.Sprintf("Keychain item %s is an item under nazar's Keychain service (%s) that is not a secret nazar made: "+
			"its name is not one nazar accepts for a secret, so nazar never made it and never uses it", strconv.QuoteToASCII(secrets.VaultPrefix+s.Name), VaultService)
	}
	if s.Unreadable {
		return w.unreadableReason(secrets.VaultPrefix+s.Name, s.Problem)
	}
	return fmt.Sprintf("the record of secret %s can't be used: %s", s.Name, s.Problem)
}

// retrust is the step that pins the config's app: matchers again once the
// trust store is new: `nazar apps list` names, for every app: matcher that
// matches nothing, the command that fixes it.
const retrust = "run the fix nazar apps list names for each app: matcher it shows as not trusted " +
	"(nazar trust --app <bundle-id>)"

// retrust is the step worded for the platform: an app id, not a bundle id,
// off macOS.
func (w vaultWords) retrust() string {
	if w.files {
		return strings.Replace(retrust, "<bundle-id>", "<app-id>", 1)
	}
	return retrust
}

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
	w := d.vault
	if why := d.prompts.unreadableReason(); why != "" {
		out = append(out, control.VaultProblem{Item: PromptsVaultItem, Reason: w.unreadableReason(PromptsVaultItem, why),
			Effect: "no approval prompt can open (config changes, key creation and deletion, trust are refused) until it is fixed",
			Remedy: w.deleteItem(PromptsVaultItem)})
	}
	approvedWhy, trustWhy := d.stager.Unreadable(), d.trust.Unreadable()
	if trustWhy != "" {
		remedy := w.deleteItem(trust.VaultItem)
		if approvedWhy == "" {
			remedy += ", then " + w.retrust()
		}
		out = append(out, control.VaultProblem{Item: trust.VaultItem, Reason: w.unreadableReason(trust.VaultItem, trustWhy),
			Effect: "app: matchers match nothing, and no app can be trusted (nor can a config that pins an app be applied)",
			Remedy: remedy})
	}
	if approvedWhy != "" {
		remedy := w.deleteItem(configstage.ApprovedVaultItem) + ", then nazar config apply"
		if trustWhy != "" {
			remedy += ", then " + w.retrust()
		}
		out = append(out, control.VaultProblem{Item: configstage.ApprovedVaultItem, Reason: w.unreadableReason(configstage.ApprovedVaultItem, approvedWhy),
			Effect: "nazar runs on the built-in default config (every key blocked) and config.yaml waits for approval",
			Remedy: remedy})
	}
	out = append(out, d.keyProblems()...)
	out = append(out, d.secretProblems()...)
	out = append(out, d.k8sCAProblems()...)
	out = append(out, d.awsCAProblems()...)
	if why := d.resolver.HelpersUnreadable(); why != "" {
		effect := "tabs that outlive their app's restart (iTerm2's, under its old iTermServer) are unknown after nazar-agent restarts, until they are reopened"
		if w.files {
			effect = "programs that outlive their app's restart are unknown after nazar-agent restarts, until they are started again"
		}
		out = append(out, control.VaultProblem{Item: caller.HelpersVaultItem, Reason: w.unreadableReason(caller.HelpersVaultItem, why),
			Effect: effect, Remedy: w.deleteItem(caller.HelpersVaultItem)})
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
			Effect: fmt.Sprintf("kubectl gets no credential for context %s", i.Name), Remedy: d.vault.k8sCAFix(i.Name, why)}
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
			out = append(out, control.VaultProblem{Item: strconv.QuoteToASCII(secrets.VaultPrefix + s.Name), Reason: d.vault.secretReason(s),
				Effect: "none: nazar never uses it as a secret; it is listed so that it can be removed", Remedy: d.vault.secretRemedy(s.Name)})
		case s.Broken:
			out = append(out, control.VaultProblem{Item: secrets.VaultPrefix + s.Name, Reason: d.vault.secretReason(s),
				Effect: fmt.Sprintf("secret %s can't be delivered", s.Name), Remedy: d.vault.secretRemedy(s.Name)})
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
			out = append(out, control.VaultProblem{Item: foreignItem(k.Name), Reason: d.vault.keyReason(k),
				Effect: "none: nazar never uses it as a key; it is listed so that it can be removed", Remedy: d.vault.keyRemedy(k.Name)})
		case k.Broken:
			out = append(out, control.VaultProblem{Item: keys.VaultPrefix + k.Name, Reason: d.vault.keyReason(k),
				Effect: fmt.Sprintf("SSH key %s can't sign", k.Name), Remedy: d.vault.keyRemedy(k.Name)})
		}
	}
	return out
}

// keyReason says why a key is unusable.
func (w vaultWords) keyReason(k keys.Info) string {
	if !config.ValidKeyName(k.Name) && w.files {
		return fmt.Sprintf("vault item %s is an item in nazar's vault (%s) that is not a key nazar made: "+
			"its name is not one nazar accepts for a key, so nazar never made it and never uses it", foreignItem(k.Name), fileVaultDir)
	}
	if !config.ValidKeyName(k.Name) {
		return fmt.Sprintf("Keychain item %s is an item under nazar's Keychain service (%s) that is not a key nazar made: "+
			"its name is not one nazar accepts for a key, so nazar never made it and never uses it", foreignItem(k.Name), VaultService)
	}
	if k.Unreadable {
		return w.unreadableReason(keys.VaultPrefix+k.Name, k.Problem)
	}
	return fmt.Sprintf("the record of SSH key %s can't be used: %s", k.Name, k.Problem)
}
