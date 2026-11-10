# nazar: the full guide

*A watchful eye on every key.*

nazar is a macOS SSH agent whose keys are created inside the Secure Enclave and never leave it.
Every key has its own rules: **which apps** may use it (matched by code signature, never by
name), **how long** one approval lasts (one use, one terminal session, one app run), and **how**
you approve (Touch ID / Apple Watch / Mac password, or an Allow/Deny dialog).
Callers no rule covers are **blocked** with a warning that has no allow button. Opening access
means editing the config, and that edit itself needs Touch ID / Watch / password.

Later phases turn the same core into a broker for API tokens (`secrets`), Kubernetes
credentials (`k8s`) and AWS session credentials through IAM Roles Anywhere (`aws`).

This guide is written for macOS. For Linux, a preview with keys in the TPM, see
[Linux (preview)](#linux-preview).

> **Status: under development, in daily use by its author.** nazar is two packages: **`nazar`**,
> the product (the `nazar-agent` background service with the Secure Enclave keys, the Touch ID /
> password and Allow/Deny prompts and the LaunchAgent, plus the `nazar` CLI), and the optional
> **`nazar-ui`** (Nazar UI.app, a window that runs the CLI). Some attended checks are still in
> progress. See [Project status](#project-status).
>
> Design: [docs/design/nazar-design.md](design/nazar-design.md)
> · Threat model: [docs/THREAT-MODEL.md](THREAT-MODEL.md)
>
> For AI agents: the [nazar skill](../skills/nazar/SKILL.md) (Claude Code: `/plugin marketplace add atas/nazar`,
> then `/plugin install nazar@nazar`; Codex: [docs/CLI.md](CLI.md#using-nazar-from-claude-code-or-codex))
> and [llms.txt](../llms.txt).

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [Example config](#example-config)
- [Quick start](#quick-start)
- [Secrets: the GitHub token](#secrets-the-github-token)
- [Secrets: an MCP server's key (Brave Search)](#secrets-an-mcp-servers-key-brave-search)
- [Linux (preview)](#linux-preview)
- [Comparison](#comparison)
- [Threat model](#threat-model)
- [Project status](#project-status)
- [Development](#development)
- [License](#license)

## Why

**Plain key files.** On macOS, SSH keys normally sit in `~/.ssh` as files. A key without a
passphrase can be copied by any script you run and used forever, from anywhere.

**A Keychain passphrase only protects the file at rest.** If you use
`ssh-add --apple-use-keychain`, any program running as you can still get the *whole private key*
back, without root and without a dialog:

1. start its own fake agent on a socket of its choosing;
2. run Apple's `/usr/bin/ssh-add --apple-load-keychain` with `SSH_AUTH_SOCK` pointing at it.

`ssh-add` may read the passphrase from the Keychain without asking, decrypts the key file, and
sends the full private key to the fake agent (`SSH_AGENTC_ADD_IDENTITY`). We verified this on
macOS 27 with a throwaway key: no terminal, no askpass, no dialog, and the fake
agent then produced signatures that `ssh-keygen -Y verify` accepted. (`security
find-generic-password` can't even see where that passphrase is stored.) Details:
[threat model, section 3](THREAT-MODEL.md#3-the-attack-that-motivated-nazar).

**1Password's agent** adds approval prompts, but the keys sync to every device and are held in
1Password's memory, there are no per-key caller rules, and approving needs Touch ID, an Apple
Watch or the 1Password password, not the Mac password.

**A Secure Enclave key has no file to steal.** The chip signs; the key is never in memory, on
disk, in a backup or in a disk image. What's left is deciding *who may ask the chip to sign*,
and that's what nazar's rules are for. One caveat: the key's *handle* (CryptoKit's
`dataRepresentation`) is itself a credential. Any process on the same Mac that gets hold of the
handle of a key created without chip-level user presence can sign with it directly, with no
prompt and without going through nazar (Phase 0 spike S5: another binary signed in 6 ms). So
nazar never writes handles to plain files; they live in a Keychain item whose access list trusts
only the agent (by its code signature, never its path), and for `dialog`/`none`-gated keys that
access list is the whole protection.
Checked by hand on 0.1.1 (Developer ID, 7 Nov 2026; [spec 10.1](design/nazar-design.md#101-attended-checks)):
another process that reads the item gets a Keychain dialog, never the value silently, so click
Deny on a Keychain dialog that names `dev.nazar`. Another process can still delete or replace
the item without a dialog: that destroys the key, but never gives anyone its handle.

## How it works

```
 ssh / git ──agent socket──▶ nazar-agent (background: no Dock icon, no menu bar item, no window)
 nazar CLI ─control socket─▶   Go core: who is asking → which rule → approval → audit
     ▲                         Swift layer: Secure Enclave, Touch ID / dialogs, process info
     └── Nazar UI.app (optional; runs only the nazar CLI, only while its window is open)
```

1. **Who is asking.** For each request nazar takes the peer's audit token from the socket (not
   a bare PID, which can be recycled) and walks the parent chain up to `launchd`: executable,
   arguments, folder and code signature of every process. The **app** is the first GUI app
   bundle in the chain (iTerm2, Cursor…); the **session** is that terminal tab's login shell, or,
   for a rule a tool in the tab satisfies (Claude Code), that run of the tool. A
   chain with no app is `unknown`. A tab whose app has restarted (iTerm2 keeps its tabs
   alive across an update through its `iTermServer` helper) stays the app's: a helper nazar saw
   below the app stands for the app running now, and the dialog says so
   (`iTerm2 (via iTermServer-3.7.6) → bash → git → ssh`). A helper nazar never saw leaves the
   tab `unknown`, but the programs in it are still themselves: Claude Code there still matches
   Claude Code's rule.
2. **Which rule.** Each key has a list of `rules`, checked top to bottom; the first match wins.
   A rule matches when one of its `apps:` matches the chain and, if set, its `to:` matches the
   receiver. `signed:` and `path:` matchers match **any process in the chain**, ancestors
   included (so `claude` covers every script Claude Code runs, and anything that *starts*
   `claude`, in that tab or with no app above it, is covered too; see the threat model), also in
   an `unknown` chain unless its walk was cut short. `app:` matchers match only the
   chain's **app**, the first GUI app bundle, so a terminal nested inside another app matches
   the outer one. Rules only ever *allow*.
   - `apps:` matchers can't be faked by name: `signed: {team, id}` (code signature),
     `app: <bundle id>` (team ID pinned when the config is approved), plus `any` and `unknown`.
     There is no `name:` matcher. `path: <file>` matches a process running that exact file
     (symlinks resolved each time, so a Homebrew `opt/` path survives an upgrade): it is for an
     unsigned program with no app above it, such as a daemon launchd starts, and it is only as
     safe as who can write that file (`nazar config check` warns when you can).
3. **`scope`: how far one approval reaches.** `use` (asks every time), `session` (once per
   terminal tab, until its shell exits; for a rule matched by a tool in the tab, such as Claude
   Code, that run of the tool until it exits: a second `claude` in the tab asks again), `app`
   (this app until it quits). `expire` caps it.
   Approvals live in memory only and are per rule, and each covers only what was approved: one
   server (by the host key its `session-bind` proved) or one kind of signature (git commits and
   tags). The first push to another server, or the first commit signature, in an approved tab
   asks once more, and the dialog says what the tab already has; `nazar status` lists what each
   approval covers. Requests from an `unknown` chain or through a
   forwarded agent (`ssh -A`) are never covered by a remembered approval. nazar knows a request
   is forwarded only because the *local* ssh said so (`session-bind@openssh.com` with
   `is_forwarding`, OpenSSH 8.9+); a forwarding client that doesn't send that looks local and is
   judged by the local tab's chain and approvals.
4. **`gate`: what has to happen.**

   | Gate | What happens | Proves |
   |---|---|---|
   | `login` | macOS `deviceOwnerAuthentication`: Touch ID, Apple Watch or Mac password (works with the lid closed) | It's **you** |
   | `dialog` | nazar's dialog: click Allow with the mouse or trackpad (enabled after 1 s); Secure Event Input is on while it's shown | **Someone** is at the keyboard |
   | `none` | Silent | Only the `apps:` / `to:` match |
   | `block` | Refused at once, with a warning that has no allow button | — |

   `gate: none` accepts `app:` matchers, non-Apple `signed:` matchers, and `any` / `unknown`.
   A rule like `apps: [{signed: {team: apple, id: com.apple.zsh}}], gate: none` would mean
   "anything" by accident, so `config check` rejects it; if you do mean every program, write `apps: [any]` (`config check`
   warns, and the key still never leaves the Secure Enclave). A forwarded agent request that hits a `gate: none` rule gets a one-time `dialog`
   instead, so a remote host can't sign quietly (again, only when the local client announces
   the forwarding with `session-bind`).
5. **Blocked by default.** A caller no rule matches gets the key's own `scope`/`gate`, or
   `defaults.fallback`, which is `gate: block`. Such a caller isn't even offered the key: ssh
   reports `Permission denied (publickey)` without trying it (a client that asks to sign
   anyway gets `SSH_AGENT_FAILURE`), and a non-modal warning shows who tried and what for, with
   **Copy suggested rule**, **Open config** and **Dismiss**. Nothing in it allows the request.
   Repeats from the same caller update one window's counter instead of opening new ones.
6. **Config changes need approval.** The config file is the real lock, and malware running as
   you could edit it. So a change that **loosens** anything (a new rule or app, a weaker gate,
   `trust --app`, `ssh-key create`/`delete`) is staged: nazar shows the diff and asks for Touch ID /
   Watch / password before it takes effect. Until then the last approved config stays active.
   nazar's own rule commands make such a change only with `--allow-loosen-access` (and ask at
   once); without it they refuse and print what it would loosen. Changes that only **tighten**
   apply at once.
7. **The dialog says who and what.**
   ```
   iTerm2 wants to use key "github"
     login to github.com
     git push origin main          in ~/projects/foo
     chain: iTerm2 → bash → git → ssh
     Scope: this terminal session, for github.com only (expires in 8h)
   ```
   The destination comes from OpenSSH's `session-bind@openssh.com` host key, looked up in
   `~/.ssh/known_hosts`, with every name it has there (`login to hydra.example (also
   192.0.2.7)`, the name you typed first if it is one); a connection that sends no bind is "an
   unidentified server". Git
   signing payloads (`SSHSIG`, namespace `git`) show as "sign a git commit/tag". When the tab
   already holds approvals for other servers or signatures, one more line lists them:
   `Already approved for this terminal session: git commits and tags`.
8. **Audit in the macOS log.** One line per request (allowed, approved, denied, timeout,
   blocked, error) in the unified log, subsystem `dev.nazar`, category `audit`. nazar keeps no
   log files. The log store is owned by root, so entries already written can't be edited or
   erased without root, but that is not a tamper-proof audit trail: any process can *add*
   entries under subsystem `dev.nazar`/category `audit`. `nazar log` and `nazar log summary`
   keep only entries written by the agent's own executable (today's build, or an earlier build
   that ran from the same installed path); Console.app and `log show` show everything. A process
   can also flood the log so real entries age out sooner. Read it with `nazar log` (needs an
   admin account), `log show` or Console.app.
   Secret values, signatures and payloads are never logged; command lines go through an
   allowlist redaction (`audit.args`).

The agent answers only `REQUEST_IDENTITIES`, `SIGN_REQUEST` and the `session-bind` extension.
`ADD_IDENTITY`, `REMOVE_*`, `LOCK`/`UNLOCK` and unknown extensions all get `SSH_AGENT_FAILURE`,
so nothing can load a key into it or remove one. It lists for each program only the keys its
rules let it use: `ssh-add -L` in a Claude Code tab shows what Claude Code may use, and a
program outside every rule gets an empty list, the block warning and an audit line per key.

Keys are `ecdsa-sha2-nistp256` only (the only type the Secure Enclave supports), tied to this
Mac: no import, export, backup or sync. A new Mac gets new keys.

## Example config

`~/.nazar/config/config.yaml`:

```yaml
apiVersion: nazar/v1              # required; unknown versions/kinds are refused
kind: Config

defaults:
  timeout: 60s                    # an unanswered dialog becomes a refusal
  fallback:                       # callers no rule matches
    gate: block                   # refused + warning popup with NO allow button

audit:
  args: redacted                  # or `none`: log only the program name and arg count

apps:                             # named matchers, reused by every rule
  claude:                         # Claude Code CLI
    signed:
      team: Q6L2SF6YDW
      id: com.anthropic.claude-code
  iterm:
    app: com.googlecode.iterm2    # team ID pinned when this config is approved
  cursor:
    app: com.todesktop.230313mzl4w4u92

ssh_agent:
  socket: ~/.nazar/run/agent.sock     # IdentityAgent / SSH_AUTH_SOCK point here
  keys:
    github:                       # GitHub account key: every repo
      rules:                      # top to bottom; first match wins
        - apps: [claude]          # Claude Code anywhere in the chain, incl. scripts it runs
          scope: session          # once per Claude Code run
          gate: dialog            # the Allow/Deny dialog
        - apps:                   # you, in your terminal or editor
            - iterm
            - cursor
          scope: session
          gate: login             # Touch ID / Apple Watch / Mac password
          expire: 8h
      # anything else → blocked, with a warning

    myrepo-deploy:                # read-only deploy key for one repo
      rules:
        - apps:
            - iterm
            - cursor
          gate: none              # deliberate: no prompt at all. NOTE this lets ANY program on
                                  # the Mac use the key silently (`open -a iTerm evil.command`
                                  # really is iTerm2); fine for a read-only deploy key, see the
                                  # threat model. `scope: session` + `gate: dialog` is the safer shape.
      # anything else → blocked

    hydra:                         # production server: no easy path for anyone
      scope: use                  # no `rules`: applies to every caller
      gate: login
```

`nazar config check` validates the file without applying it, and warns about rules that can
never match because an earlier one always wins, and about keys whose protection, fixed when
they were created, no longer matches their gates (see [Threat model](#threat-model) and `4.8`
in the full version).

## Quick start

Requires an Apple silicon Mac on macOS 26 or later. On Linux, see [Linux (preview)](#linux-preview).

```bash
# 1a. With Homebrew (pre-built, Developer ID-signed and notarized). The `nazar` cask installs
#     nazar-agent.app and the CLI and runs `nazar install`: the LaunchAgent dev.nazar.agent,
#     ~/.nazar (0700), and the links $(brew --prefix)/bin/nazar and nazar-sign-git. Upgrades
#     keep your keys: they belong to the agent's signature, not its folder.
brew install --cask atas/tap/nazar
brew install --cask atas/tap/nazar-ui      # optional: the Nazar UI window app
nazar status
```

```bash
# 1b. Or from source (Go 1.26 and Xcode's command-line tools). `make agent` builds
#     build/nazar-agent.app ad hoc; put it anywhere (here ~/Library/nazar) and run its CLI's
#     install, which links ~/.local/bin/nazar and ~/.local/bin/nazar-sign-git (add ~/.local/bin
#     to PATH if it isn't). Every ad-hoc rebuild is a new program to the Keychain; see "Your
#     own builds" below to keep keys across rebuilds.
make agent
mkdir -p ~/Library/nazar && ditto build/nazar-agent.app ~/Library/nazar/nazar-agent.app
~/Library/nazar/nazar-agent.app/Contents/MacOS/nazar install
nazar status
make ui                                    # optional: build/Nazar UI.app, runs only this CLI build
ditto "build/Nazar UI.app" "/Applications/Nazar UI.app"

# 2. Create a key: one Touch ID / Watch / password. config.yaml gets a `github` entry that
#    blocks every caller except the terminal app you typed this in (iTerm2 here: Touch ID
#    once per tab, for at most 8 hours); the public key is exported next to it.
nazar ssh-key create github
nazar ssh-key pubkey github        # paste into GitHub → Settings → SSH keys
```

```
# 3. ~/.ssh/config
Host github.com
  IdentityAgent ~/.nazar/run/agent.sock
  IdentityFile ~/.nazar/keys/github.pub
  IdentitiesOnly yes
  ControlMaster no      # see note below
```

If you use `ControlMaster`/`ControlPersist`, the persisted master detaches to `launchd`, so its
chain is just that `ssh`, with no app, and is `unknown`: it matches no `app:` rule, no `signed:`
rule for the programs you ran (Claude Code, git), and never gets a remembered approval. Unless
the key has an `apps: [any]` or `apps: [unknown]` rule (or one naming `ssh` itself), it gets the key's
own gate if the key has one (the example's `hydra` key: a one-shot `login` prompt headed "Unknown
app"), otherwise `defaults.fallback` (blocked, in the example). Set `ControlMaster no` for hosts
that use nazar keys, or add such a rule knowingly.

```bash
# 4. Git commit signing through nazar. `nazar sign-git` points SSH_AUTH_SOCK at
#    nazar's agent and execs /usr/bin/ssh-keygen with git's arguments. git must
#    run it through a symlink *named* nazar-sign-git (that's how it tells), and
#    gpg.ssh.program should be the symlink's ABSOLUTE path: a bare name is
#    resolved through $PATH, which anything running as you can prepend to.
#    The cask linked $(brew --prefix)/bin/nazar-sign-git; from source, `nazar install`
#    linked ~/.local/bin/nazar-sign-git. Use the one you have.
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(brew --prefix)/bin/nazar-sign-git"   # or "$HOME/.local/bin/nazar-sign-git"
git config --global user.signingkey ~/.nazar/keys/github.pub
git config --global commit.gpgsign true
```

`nazar status` checks steps 3 and 4 for you (and whether Apple's `ssh-agent` still holds old
keys): each `setup:` line names what is missing, with the exact line to add. Nothing is edited.
That covers lines from an older nazar, whose files were in `~/.config/nazar` and whose socket was
`~/.nazar/agent.sock`: nazar-agent moves the files when it starts, your config stays approved, and
each `setup:` line gives the replacement.

Then let Claude Code use the key too, as the example config does, with an Allow dialog once per
run, ahead of the terminal rule step 2 wrote (`--at 1`). A rule loosens access, so the command
takes `--allow-loosen-access`: it shows the change and asks for Touch ID / Watch / password
before it is in force. Without the flag (an AI agent proposing the rule, say) nazar refuses it,
prints what it would loosen and the command to run, and changes nothing. nazar accepts no
other edit while one waits, so approve each rule as it asks:

```bash
nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --scope session --gate dialog --at 1 --allow-loosen-access   # Touch ID
```

**Identity is the signature.** The agent's Keychain items, the CLI's check of the agent and Nazar
UI's check of the CLI all go by code signature, never by path: moving the agent or upgrading it
(Homebrew puts every version in a new folder) keeps the keys; a different signature is a
different program.

**After a new signature** (an ad-hoc rebuild, moving from the old Nazar.app, or between your own
build and the Homebrew release), the agent can't read the items the previous one wrote, nor
delete them. It still starts; `nazar status` lists each item it can't read, what that means, and
the commands that fix it, in the order to run them. For a key, first unlock the login keychain if it
is locked, or reinstall the nazar-agent you had if this one is signed differently, and look again:
deleting a key's item destroys the key for good. Then delete the item with `security
delete-generic-password -s dev.nazar -a <item>` (for a key, `-a ssh-key/<name>`), then, for a key,
`nazar ssh-key create <name>` (a new key under its entry in `config.yaml`, rules kept) and upload
the new public key.

**Moving from Nazar.app** (Milestones 1–5). Install nazar-agent and run its `nazar install` (the
cask does): it boots out and removes the old LaunchAgent `dev.nazar` and the old links, and never
touches keys, config or Keychain items. Follow `nazar status` once (the keys are re-created and
re-added where they were used), then delete the old `Nazar.app`. The cask links the CLI itself, so
its install removes the old `~/.local/bin/nazar-sign-git` link: if git signs through it, install
prints the line to run, `git config --global gpg.ssh.program "$(brew --prefix)/bin/nazar-sign-git"`.

**Your own builds.** Sign your installed copy with your Apple Development certificate and rebuilds
keep their keys (same certificate, same program). The CLI first, then the bundle; Nazar UI the
same way (a team-signed UI trusts the CLI of its own team, not a pinned build):

```
codesign --force --options runtime --sign "Apple Development" --identifier dev.nazar.cli build/nazar-agent.app/Contents/MacOS/nazar
codesign --force --options runtime --sign "Apple Development" build/nazar-agent.app
codesign --force --options runtime --sign "Apple Development" "build/Nazar UI.app"
```

**Chip-level protection** is fixed for good when a key is created, and the key's rules decide it:
when every rule that can reach the key is `login` with `scope: use` or `block` (at least one
`login`), the Secure Enclave itself requires your authentication for every signature, which holds
even against a compromised nazar. A key made with `nazar ssh-key create <name>` from a terminal
(a `session` rule) or from Nazar UI (no rule yet) gets no chip-level protection, so any rule can
be added later. For a key the chip guards, like a production root login, run `nazar ssh-key
create hydra --always-ask` (one Touch ID): its rule for your terminal is `login` with `scope: use`,
so every signature asks. The prompt's last line says which (`Touch ID on every use, enforced by
the chip: …` or `Secure Enclave user presence: off`), and `nazar ssh-key list` marks such a key
`asks every time (chip)`. On it a `dialog` or `none` rule, or `login` with `scope:
session`/`app`, can't work, and nazar's own edits refuse it: `hydra asks on every use (enforced by
the chip); create another key for a looser rule`. `nazar config check` and `nazar status` warn
when a hand-edited file and a key's protection disagree.

**While the Mac is locked** a key still works for the rules that need no prompt (once you have
logged in since the Mac started), so background jobs keep signing. For a key nothing may use
while the Mac is locked, add `--only-when-unlocked` to `ssh-key create`, `secret add`, `k8s ca
create` or `aws ca create`; the chip enforces it for good. `--always-ask` keys, and every key made before nazar had
the choice, are like that; the lists mark them `only when unlocked`.

**Day to day:**

```
nazar ui                            # open Nazar UI.app (optional, installed separately)
nazar ssh-key create <name>         # one Touch ID: blocked for every app but the terminal you type it in
nazar ssh-key create <name> --always-ask   # the same, and the chip asks for Touch ID on every use, for good
nazar ssh-key create <name> --only-when-unlocked   # the same, and the chip refuses it while the Mac is locked, for good
nazar ssh-key list                  # name, fingerprint, rules summary; --json adds rules, last use, userPresence, whileLocked
nazar ssh-key rules <key>           # a key's rules, numbered
nazar ssh-key rule add <key> --apps M[,M] --gate G [--scope S] [--expire D] [--at N]
nazar ssh-key rule set <key> <n> [--apps …] [--gate …] … | rule remove <key> <n>
nazar ssh-key set <key> --gate G [--scope S]      # what callers no rule matches get
nazar secret rule add|set|remove <name> …         # a secret's rules, with the flags of ssh-key rule
nazar apps list                     # apps: matchers, pinned teams, what keeps one from matching
nazar status [--follow]             # current approvals, config warnings; and what's not wired to
                                    # nazar on this Mac (~/.ssh/config, git signing, keys in another agent), with the fix
nazar revoke --all | --key K | --session ID | --app BUNDLE-ID
nazar trust --app <bundle-id>       # pin an app's team ID again, after it changed (login gate)
nazar config check | apply          # apply shows the change staged in config.yaml (a hand edit, or one
                                    # whose prompt was denied or not shown) and asks for Touch ID;
                                    # nothing applies without it
nazar log [--follow] [--since 24h] [--target github] [--caller claude] [--decision blocked]
nazar log summary [--since 7d]      # both read the system log: needs an admin account
```

Every command except `sign-git` takes `--json` (objects carry `apiVersion: nazar/v1` and a
`kind`; `sign-git` passes its arguments to `ssh-keygen` untouched), never asks for approval
on stdin (`secret add` reads only the value there), and has stable exit codes: `0` ok, `1` error, `2` usage, `3` refused, `4` staged
(the prompt could not be shown; `nazar config apply` asks), `5` nazar-agent not running. A change
that loosens access is made only with `--allow-loosen-access`, which asks you at once; without it
the command refuses, prints what it would loosen and the command to run, and changes nothing. So
an AI agent can inspect everything, propose a change (the command it prints for you to run) and
tighten access, but only the person at the Mac can open it.

**Help and completion:** `nazar <command> --help` (or `nazar help <command>`) shows a command's
flags, the values each takes, and examples; `nazar --help` lists every command. For tab
completion of commands, flags, their values and your key, secret and context names, add the
line for your shell to its startup file (nazar never edits it):

```bash
source <(nazar completion zsh)       # ~/.zshrc, after compinit
source <(nazar completion bash)      # ~/.bashrc (needs the bash-completion package)
nazar completion fish | source       # ~/.config/fish/config.fish
```

Completion reads names only through the read-only lists `nazar ssh-key list`, `secret list`,
`k8s list`, `aws list` and `apps list` use: it never asks for Touch ID, shows no dialog and changes nothing,
and offers no names while nazar-agent isn't running.

## Secrets: the GitHub token

nazar keeps API tokens too, each sealed to its own Secure Enclave key, given out under the same
kind of rules as keys. git (and `gh`, which pushes and pulls through git) asks for the GitHub
token through git's credential helper protocol: nazar answers only for `https` and only for the
host the secret names, only when git's HTTPS transport is the receiver, and only to the genuine
nazar CLI. Moving `GITHUB_PERSONAL_ACCESS_TOKEN` out of `~/.bash_profile`:

```bash
# 1. Store it (one Touch ID), in a terminal tab where the variable is still exported. The value
#    goes through stdin, never the command line. config.yaml gets an entry for it: blocked,
#    plus a login rule for the terminal app you typed this in.
printf '%s' "$GITHUB_PERSONAL_ACCESS_TOKEN" | nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN
```

```yaml
# 2. In ~/.nazar/config/config.yaml, tell nazar which host the token is for and who receives it
#    (the entry step 1 wrote, with the lines marked "add"; git-https goes under your existing
#    apps:, if you have one). Then `nazar config apply` (Touch ID).
apps:
  git-https: {signed: {team: apple, id: com.apple.git-remote-http}}   # add: git's HTTPS transport
secrets:
  GITHUB_PERSONAL_ACCESS_TOKEN:
    gate: block
    deliver: [helper]                                         # add: only git's helper, no `nazar get`
    helper:                                                   # add
      git: {host: github.com, username: <your GitHub login>}  # add: git needs a username too
    rules:
      - apps:
          - app: com.googlecode.iterm2                          # what step 1 wrote: your terminal
        to: [git-https]                                       # add
        scope: session
        gate: login
        expire: 8h
```

```bash
# 3. Make nazar git's only helper for github.com. The empty helper clears the ones set before
#    (Xcode's git sets osxkeychain for every host, which would answer first with an old copy).
#    An install from before this version has no git-credential-nazar link yet: run
#    `nazar install` again first (the cask makes the link itself).
git config --global --replace-all credential.https://github.com.helper ""
git config --global --add credential.https://github.com.helper nazar
printf 'protocol=https\nhost=github.com\n\n' | git credential-osxkeychain erase   # an old copy, if any
#    Check: nazar must be the last helper git uses for github.com. A helper after it (a later
#    `[credential] helper = store`, a repository's own) is handed the token and keeps it.
git config --show-origin --get-regexp '^credential\..*helper$'

# 4. Delete the `export GITHUB_PERSONAL_ACCESS_TOKEN=…` line from ~/.bash_profile, then open a
#    new tab and check: the variable is gone, and a fetch asks for Touch ID once in the tab.
env | grep -c GITHUB_PERSONAL_ACCESS_TOKEN            # 0
git -C ~/projects/<a GitHub repo> fetch

# 5. Rotate the token (GitHub → Settings → Developer settings → Personal access tokens): the old
#    value was in plain text in ~/.bash_profile, in backups and in shell history. Then store the
#    new one (two Touch IDs; the config entry and its rules are kept):
nazar secret rm GITHUB_PERSONAL_ACCESS_TOKEN
nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN         # macOS: paste the new token at the hidden prompt
```

`git-credential-nazar` is a link to the CLI that `nazar install` (or the cask) puts next to
`nazar-sign-git`; git runs it for the helper named `nazar`, so it must be on git's `PATH` (a git
started by a GUI app may not have `~/.local/bin` there: name the link by its absolute path in the
helper line instead). What the receiver check is worth: it stops the token going to a program
that is not git's HTTPS transport, but not to whoever controls how git runs: a genuine
transport prints it when asked to (`GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0`), and a helper command
of the caller's choosing can send the helper's output to a file. For a token that matters use
`scope: use` (Touch ID for every fetch). `gh api` and other gh commands use gh's own login, not this token. A Homebrew
git is not Apple-signed, so the `to:` above does not match its transport: use Apple's
`/usr/bin/git` for the remotes nazar answers, or name the transport by path
(`to: [{path: /opt/homebrew/opt/git/libexec/git-core/git-remote-http}]`), which is only as safe as
who can write that file (any program of yours, under `/opt/homebrew`). A script reads a secret with `nazar get NAME` (the value
on stdout) when its entry lists `stdout` in `deliver` and a rule names the script's interpreter
in `to:`.

## Secrets: an MCP server's key (Brave Search)

An MCP server usually gets its API key from the `env` block of `~/.claude.json`: plain text on
disk, and in the startup environment of every process its launcher starts. `nazar run` starts
the server instead and hands the key to the server alone: never on disk, never on a command
line, never in the startup environment of nazar, `npx` or the server, and in the server's
`process.env` before its first line runs. (Processes the server itself starts inherit it, as
they would any variable.)

> **Status (M10):** built, and tested end to end with real `npx` and the real loaders: on the Mac
> on nazar-agent's own process seams with the CLI and loaders of the built nazar-agent.app
> (`make integration-run`), and on Linux with a test platform. `nazar run` is macOS only: on Linux
> it refuses and runs nothing, so this section does not apply there. A release with it is next.
> With an older nazar-agent `nazar run` refuses, asks nothing and runs nothing,
> so **keep the `env` block on the Mac until you have installed that release** (step 4 would stop
> the server starting).

```bash
# 1. Store it (one Touch ID). Copy the value from the "brave-search" entry's env block in
#    ~/.claude.json and paste it at the hidden prompt (this section is macOS only).
#    config.yaml gets an entry for it:
#    blocked, plus a login rule for the terminal app you typed this in (replaced in step 3).
nazar secret add BRAVE_API_KEY

# 2. Only if node comes from mise or asdf: the folder that really holds node. A shim is
#    refused (it picks the interpreter when it runs). Homebrew's /opt/homebrew/bin needs nothing.
dirname "$(mise which node)"                     # asdf: dirname "$(asdf which node)"
```

```yaml
# 3. In ~/.nazar/config/config.yaml, then `nazar config apply` (Touch ID). Replace the rule step 1
#    wrote (your terminal, with no `to:`: it would hand the key to any node or python3 command you
#    run there) with the one below, and add the marked lines.
defaults:
  trustedPath: [~/.local/share/mise/installs/node/24.0.0/bin, /usr/bin, /bin]  # add, only for step 2
secrets:
  BRAVE_API_KEY:
    gate: block
    deliver: [late-env]                                  # add: only `nazar run`
    rules:
      - apps: [{signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}] # Claude Code
        to: [{command: [npx, -y, "@brave/brave-search-mcp-server"]}]         # this command line only
        scope: session                                   # one dialog per Claude Code run
        gate: dialog
```

```jsonc
// 4. Replace the "brave-search" entry in ~/.claude.json (the env block goes; `claude mcp add`
//    puts a new one under projects.<folder> unless you pass --scope user). "command" is nazar's
//    absolute path (`command -v nazar`): Claude Code's PATH is not your shell's.
"brave-search": {
  "command": "/Users/<you>/.local/bin/nazar",
  "args": ["run", "--secret", "BRAVE_API_KEY", "--", "npx", "-y", "@brave/brave-search-mcp-server"]
}
```

```bash
# 5. Restart Claude Code: one dialog when it starts the server. Then check that no copy is left
#    (also in a project's .mcp.json, ~/.claude.json.backup*, Claude Desktop's config and your
#    shell profile) and that the run was approved.
grep -c '"BRAVE_API_KEY": *"' ~/.claude.json      # 0
nazar log --since 10m --target secret:BRAVE_API_KEY   # decision=approved delivery=late-env

# 6. Rotate the key at https://api-dashboard.search.brave.com/app/keys (the old value sat in
#    plain text in ~/.claude.json and in backups), then store the new one (two Touch IDs):
nazar secret rm BRAVE_API_KEY && nazar secret add BRAVE_API_KEY
```

**How it works.** `nazar run` sends the command line to nazar-agent, which finds `npx` itself
through `trustedPath` (never your `PATH`), shows the dialog, and replies with exactly what to
exec. The server runs in `/` with an environment nazar builds: `PATH` from `trustedPath`, your
home, user name, temp folder, `LANG`, `LC_*` and `TERM`, a variable of yours only when the
secret's `envAllow:` names it, and the loader's variables (Node's `--require` of nazar's
loader, and `--disable-sigusr1` so a signal can't open Node's debugger: Node 22.14 or later). After the exec nazar-agent checks the process against the plan (program and its code,
arguments, folder, every variable, the pinned files), and the loader takes the key over a
one-time socket only in the package's own bin below `npx`, sets `process.env.BRAVE_API_KEY` and
removes nazar's variables before the server starts. Another process that connects, `npx` itself
or a plain install script, is refused and logged. If nazar refuses at the dialog or before it,
`nazar run` exits 3 and nothing runs; if it refuses after the exec (a file or variable changed,
or a disk was mounted or ejected meanwhile), the server runs without the key and prints `nazar: secret BRAVE_API_KEY not delivered: …`.
`node`, `python3` and `npx` are supported (`python3` from mise, say: Apple's, Xcode's and Homebrew's
start themselves again, which nazar refuses before asking); `uvx`, `pnpm dlx`, `bunx` and `cwd:` are
not yet.

**What it does not do.**
- It does not pin what `npx` runs. Pinned: the `node` binary (by code identity), npm's
  `npx-cli.js` entry file and absolute files on the command line; changing one asks again, with
  the same dialog (it does not say what changed). Not pinned: the rest of npm, its config
  (`~/.npmrc`, `<node>/etc/npmrc`), its cache, the package and its dependencies, whatever the
  server loads. A compromised package or dependency, or a process of yours that edits npm's
  cache or config, runs with the key. Writing the version in the command line and the rule
  (`@brave/brave-search-mcp-server@2.0.1`) narrows the package itself, not its dependencies.
- The dialog shows the command line with its arguments redacted (`…/npx-cli.js -y …`): the
  package is the one the rule names, which the dialog does not repeat.
- A remembered approval (`scope: session`) covers the same command line for the rest of that
  Claude Code run, whoever in the run starts it; `scope: use` asks every time.
- Pins are taken per request, not recorded: a later version records them and shows what changed.

## Linux (preview)

The same `nazar` CLI and agent run on Linux desktops (systemd, amd64 and arm64), with keys in the TPM,
`login` as your password at the system's polkit prompt (a fingerprint where fprintd is set up) and
`dialog` as a zenity or kdialog window. It is a preview: tested in containers with a software TPM, not
yet on real hardware.

It is weaker than macOS. Any program running as you can use your keys and read every secret without
a prompt, so nazar on Linux keeps keys on the machine and puts rules on the tools that ask, but does
not stop hostile code running as you; and whoever holds the machine can use every key unless the
disk is encrypted. Rules use `app:` and `path:` (`signed:` is macOS only), an `app:` pin breaks on every
update of the app, `secret add` has no hidden prompt, and `nazar run` and `nazar ui` are not there.

Install, upgrade and every difference: [docs/CLI.md, Linux](CLI.md#linux). Where it is weaker:
[threat model, section 7](THREAT-MODEL.md#7-linux-preview).

## Comparison

| | Keychain + `ssh-agent` | 1Password SSH agent | Secretive | **nazar** |
|---|---|---|---|---|
| Where the private key lives | File in `~/.ssh` | 1Password vault, synced to every device | Secure Enclave | Secure Enclave |
| Can user-level malware export it | **Yes** (fake agent + `ssh-add --apple-load-keychain`) | Not via a key file; it's held in 1Password's memory | No | No |
| Approval granularity | None by default once loaded (`ssh-add -c` asks on every use) | Per request, per terminal session, per app | Every use, or a timed unlock | Per use, per terminal session, per app, with `expire` |
| Per-key caller rules | No | No | No | Yes: `apps` / `to` / `scope` / `gate` per key |
| Callers identified by | — | App | — | Code signature, bundle ID + pinned team, or path + content hash, across the whole process chain |
| Unknown callers | Sign silently | Prompt | Prompt, or nothing during a timed unlock | **Blocked**, warning with no allow button |
| Approve with | — | Touch ID, Apple Watch, 1Password password | macOS authentication prompt | Touch ID, Apple Watch, **Mac password**, or an Allow/Deny dialog (hardware-only click still being verified, S4) |
| Config changes need auth | — | — | — | Yes, loosening changes need `login` |
| Visibility | — | — | Notifications | Block warnings, plus an audit line per request in the macOS unified log (`dev.nazar`) |
| Sync / backup | Whatever backs up `~/.ssh` | Yes | No | No, by design |

Sources: nazar's [design spec §1, §11 and §13](design/nazar-design.md)
and the [threat model](THREAT-MODEL.md). Secretive is MIT
and lives at <https://github.com/maxgoedjen/secretive>; its open issues
[#46](https://github.com/maxgoedjen/secretive/issues/46),
[#355](https://github.com/maxgoedjen/secretive/issues/355),
[#400](https://github.com/maxgoedjen/secretive/issues/400) and
[#818](https://github.com/maxgoedjen/secretive/issues/818) ask for per-app/per-key rules. The
1Password column reflects our reading of its agent, not a test.

## Threat model

Short version, for macOS; the full one is in [docs/THREAT-MODEL.md](THREAT-MODEL.md), and Linux is
[its section 7](THREAT-MODEL.md#7-linux-preview). To report a flaw, see [SECURITY.md](../SECURITY.md).

**nazar protects against**

- **Key theft** by any process, backup or disk image: the key never exists outside the Secure
  Enclave, so the Keychain export attack above has nothing to export. The key's *handle* is
  another matter: any process holding the handle of a `dialog`/`none`-gated key can sign with it
  directly, bypassing nazar (S5). Handles therefore sit in a Keychain item only the agent may
  read (known by its signature, not its path); that cross-process read check is still pending
  (see "does not protect against").
- **Silent use outside an approved scope:** other tabs, other apps and background malware get a
  prompt or a refusal.
- **A compromised nazar process signing on its own**, for keys whose entry, when they were
  created, allowed only `login` with `scope: use` or `block` (see "Chip-level protection"):
  those keys carry the Secure Enclave's own user-presence requirement, fixed at creation, so
  the chip refuses without your authentication. Keys with a `dialog`, `none` or `session`/`app`
  rule don't get this, and such a rule on a presence key is refused by nazar's commands and
  fails closed from a hand edit until the key is re-created. With `scope: session`/`app` on a
  presence key, the chip re-asks every 6–10 minutes regardless of nazar's remembered approval
  (S1).
- **Callers pretending to be an allowed app by name:** rules match code signatures, pinned team
  IDs or content hashes.
- **Ordinary processes faking an approval:** `login` is macOS's own authentication; `dialog`
  needs a hardware click on Allow, which is enabled only after the dialog has had focus for
  1 second (see the caveat below).
- **Malware granting itself access by editing the config:** loosening changes wait for
  Touch ID / Watch / password, and the prompt shows the diff.
- **Agents forwarded to remote hosts** riding on your local approval: forwarded requests are
  never remembered, and `gate: none` becomes a one-time dialog for them. This relies on the
  local ssh announcing the forwarding (`session-bind@openssh.com`, OpenSSH 8.9+); see below.
- **Unexpected callers going unnoticed:** they're blocked, shown, and logged (with the forgery
  caveat below).

**nazar does not protect against**

- **A terminal or IDE rule with `gate: none` or `scope: app`.** Any program can run
  `open -a Terminal evil.command`, and the new window really is Terminal. So such a rule
  effectively covers *any* program on the Mac. nazar allows this on purpose, without a warning:
  it's your choice. The safer pattern for terminals is `scope: session`, since a new window is a
  new session and gets a prompt.
- **Anything running inside an approved scope.** Claude Code and the scripts it writes sign
  silently in an approved run of it, by design, for the server or kind of signature that was
  approved there: an approval for github.com covers every github.com repository. Narrow it with
  per-caller rules and `scope: session`.
- **Rules on tools that run arbitrary commands.** `signed:` and `path:` match any process in the
  chain, ancestors included. A `gate: none` rule on `claude` therefore covers anything that can
  *start* `claude -p …` (a stray script in a tab), and one on a non-Apple-signed interpreter
  (python.org Python, a signed Node) silently covers every script it runs. Match the narrowest
  tool you can. (With `scope: session` a stray `claude -p` is a new run and asks.)
- **Forwarding clients that don't say so.** nazar detects a forwarded agent only from the local
  client's `session-bind` with `is_forwarding`. OpenSSH before 8.9, Go `x/crypto/ssh`, Paramiko
  and some IDE SSH clients send none, so their forwarded requests look local and can ride the
  tab's remembered approvals.
- **Forged or flooded audit entries.** Any process can write `dev.nazar`/`audit` lines to the
  unified log. `nazar log` keeps only those written by the agent's own executable at its
  installed path (after an upgrade, earlier versions' entries are in `log show` only); Console.app
  shows them all. Any process can also flood the log so that real
  entries age out sooner.
- **A window drawn over the dialog.** Any process can put a window of its own over the nazar
  dialog so that your genuine click lands on Allow; the 1-second focus arming stops an overlay
  that takes focus, not one that doesn't. Read the dialog before you click; use `login` for keys
  that matter.
- **You allowing a Keychain dialog.** Another process reading a key's item gets a Keychain
  dialog (S5, checked); if you allow it, that process gets the handle and can use a
  `dialog`/`none`-gated key directly. Only `login`/`block` keys stay safe then.
- **Deleting a key.** Any process running as you can delete or replace nazar's Keychain items
  without a dialog (S5, checked): the key is destroyed, not stolen.
- **Malware driving an approved app** (for example AppleScript typing into iTerm); macOS asks
  you before granting Automation control.
- **Root or kernel compromise.**
- **What a server does with access.** A GitHub account key reaches every repo the account can;
  use deploy keys to limit that.
- **`dialog` identifying the person.** It proves someone is at the keyboard, not who. Telling
  hardware clicks from synthetic ones on macOS 27 is still being verified (spike S4, at risk);
  if it doesn't hold, the "other processes can't press it" claim is dropped: a process with the
  Accessibility permission alone could then click Allow.
- **Secrets in audit lines that look like plain words.** Redaction keeps arguments that are short
  plain words (`git push origin main`), so `--password hunter2` or a 20-character AWS access key
  ID survives. Use `audit.args: none` if your command lines carry such values.

## Project status

| Phase | What | State |
|---|---|---|
| Phase 0 | Spikes: Swift ↔ Go bridge, Secure Enclave approval reuse, handle portability, caller attribution, agent socket, `session-bind`, git signing, the Keychain export test | **Done** (automated parts; a few attended checks such as S4 still open) |
| Phase 1 · M1 | Go core: config, caller chains, policy, approval cache, config staging, audit | **Done** |
| Phase 1 · M2 | SSH agent, control socket, `nazar` CLI, `nazar sign-git`; integration tests with real `ssh`, `sshd`, `ssh-add` and `git` | **Done** |
| Phase 1 · M3 | Swift platform layer: Secure Enclave, LocalAuthentication, dialogs, process info; the c-archive bridge | **Done** (attended checks in progress) |
| Phase 1 · M4 | Nazar.app packaging, `nazar install`, LaunchAgent | **Done** (attended checks in progress) |
| Phase 1 · M5 | Fixes from the attended run; CLI for rules and apps; the Nazar window | **Done** (attended checks in progress) |
| Phase 1 · M6 | nazar-agent.app with no UI; Nazar UI.app as a separate app; identity by signature; two Homebrew casks | In progress |
| Phase 2 | `secrets`: API tokens encrypted to a Secure Enclave key, delivered by credential helper, named pipe, late env var or stdout | In progress (M8: storage, the `secrets:` section of config.yaml, `nazar secret add/list/rm`, git's credential helper, `nazar get`; M10: `nazar run`, late-env for MCP servers, built and tested on Linux, the macOS seams next; M11: `nazar secret rule add/set/remove` and the Secrets tab in Nazar UI.app) |
| Phase 3 | `k8s`: kubectl exec credential plugin gated on who called kubectl | In progress (M12: `ca-cert`: a Secure Enclave CA per context mints 15-minute client certificates; `nazar k8s ca`, `list`, `forget`; M13: `nazar k8s rule add/set/remove` and the Kubernetes tab in Nazar UI.app; one guided `nazar k8s ca create` sets a context up without the kubeconfig's credential; see [docs/CLI.md](CLI.md#kubernetes)) |
| Phase 3 · AWS | `aws`: `credential_process` for the AWS CLI and SDKs, sessions minted through IAM Roles Anywhere with a certificate from a Secure Enclave CA per entry | In progress (`nazar aws ca create`, `list`, `rule add/set/remove`, `forget`, `credential`; no Nazar UI.app tab yet; see [docs/CLI.md](CLI.md#aws)) |
| Linux | The same CLI and agent on the TPM, polkit, zenity or kdialog and `/proc` (`core/platform/linux`, `cmd/nazar-agent`), tested in containers with a software TPM on every PR | Preview: not yet run on real hardware; see [Linux (preview)](#linux-preview) |

## Development

| Path | What |
|---|---|
| `core/` | Go core: config, caller chains, policy, approvals, audit, SSH agent, control socket, secrets storage (`core/secrets`) |
| `core/platform/` | The platform interface (Secure Enclave, prompts, process info) and a fake for tests |
| `core/platform/linux/` | The Linux platform: TPM keys, a file vault, polkit, the dialog program, logind, `/proc`, desktop apps |
| `cmd/nazar/` | The `nazar` CLI (also `install` / `uninstall`) |
| `cmd/nazar-agent/` | `nazar-agent` on Linux (on macOS it is `bridge/` and `macos/`) |
| `loaders/` | The Node and Python loaders `nazar run` gives a program (`node --test loaders/node/env_test.cjs`, `python3 -m unittest discover -s loaders/python -p '*_test.py'`) |
| `bridge/` | The Go core as a C archive for nazar-agent, and the conformance host's archive |
| `macos/` | Swift: the platform layer (Secure Enclave, Keychain, prompts, callers), nazar-agent.app, Nazar UI.app (`NazarUI`, `NazarUIApp`), test hosts |
| `scripts/` | Bundle checks (`check-agent.sh`, `check-ui.sh`) and the release tooling (`release.sh`, `release-sign.sh`; [RELEASING.md](RELEASING.md)) |
| `packaging/homebrew/` | The two cask templates (`nazar`, `nazar-ui`) and the `nazar-linux` formula template the release renders |
| `packaging/linux/` | The polkit action and the udev rule `nazar install --system` installs |
| `test/linux/` | The Linux test image (swtpm, D-Bus, polkit) and the end-to-end test |
| `internal/cmd/nazar-testd/` | The core on the fake platform, for integration tests only |
| `test/integration/` | Tests that drive real `ssh`, `sshd` and `git` |

```bash
make check        # everything automated: gofmt/vet, go test -race, swift test,
                  # platform conformance on the real Swift platform, integration
                  # tests (fake and real platform), both bundles, and nazar run end to end
make test         # Go unit tests (fake platform, no prompts)
make swift-test   # Swift unit tests (real Secure Enclave without user presence, temp keychains)
make conformance  # core/platform/conformance against the Swift platform via the C ABI
make integration  # real ssh/sshd/git, and every nazar k8s command with the real kubectl, against nazar-testd (macOS)
make integration-swift  # real ssh/sshd/git against the real core on the real platform
make integration-run    # nazar run and the k8s plugin end to end on the real process seams (real npx, real kubectl)
make agent        # build/nazar-agent.app, ad-hoc signed
make ui           # build/Nazar UI.app, ad-hoc signed, pinned to that agent's CLI build
make release      # a person, with the Developer ID certificate: sign, notarize, staple, zip, render
                  # the casks (docs/RELEASING.md); NAZAR_SIGN_ID=- DRY_RUN=1 runs it ad hoc, no notary
make release-tap TAP=../homebrew-tap   # the signed release's casks into a tap checkout, not committed
make check-launchd      # opt-in: install/uninstall against launchd under a test label
make linux              # the whole Linux suite in a container (Docker): software TPM, D-Bus, polkit
make linux-run CMD='make test'   # one command in that container
make fuzz         # short fuzz runs of the untrusted-input parsers (FUZZTIME=10m for a longer hunt)
```

Nothing automated needs a person: no Touch ID or password prompt, no Keychain
dialog, no TCC prompt. What only a person can check (real prompts and dialogs, Keychain
behaviour across processes, the real LaunchAgent, signing and notarizing a release) is listed in
[spec 10.1, Attended checks](design/nazar-design.md#101-attended-checks).

## Client setup

```
# ~/.ssh/config
Host github.com
  IdentityAgent ~/.nazar/run/agent.sock
  IdentityFile ~/.nazar/keys/github.pub
  IdentitiesOnly yes
```

Git commit signing goes through `nazar sign-git`, installed as the symlink `nazar-sign-git` (by the
cask in `$(brew --prefix)/bin`, by `nazar install` from source in `~/.local/bin`) and set as
`gpg.ssh.program` (absolute path).

`nazar status` checks both, read-only, and says what to change: a `Host` block with nazar's key
file but no `IdentityAgent`, `IdentitiesOnly` left at `no`, `ControlMaster` on, `gpg.ssh.program`
unset, a bare name or a dangling link, and keys still loaded in Apple's `ssh-agent`.

## License

Apache-2.0. See [LICENSE](../LICENSE).
