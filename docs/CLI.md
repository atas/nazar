# Using nazar 🧿

nazar keeps your SSH keys inside the Mac's Secure Enclave and decides, per app, who may use
them. You drive it with one command, `nazar`, and one file, `~/.nazar/config/config.yaml`.
Nazar UI.app is optional: it only shows and edits what the CLI can.

## The picture

```
  you, your terminal, your AI agents
        │
        │  nazar <command>                      ssh, git push, git commit -S
        ▼                                                │
  ┌───────────┐   control socket                         │  agent socket
  │ nazar CLI │ ──────────────────┐    ┌─────────────────┘  ~/.nazar/run/agent.sock
  └───────────┘                   ▼    ▼
  Nazar UI.app ── runs the CLI ─▶ ┌──────────────────────────────────────────────┐
  (optional)                      │ nazar-agent (background, no window, no icon) │
                                  │  1. who is asking?   app + signature + tab   │
  ~/.nazar/config/config.yaml ──▶ │  2. which rule?      first match wins        │
  (loosening edits wait for       │  3. gate             Touch ID / dialog / none│
   your Touch ID)                 │  4. Secure Enclave signs; the key never leaves│
                                  │  5. one line in the macOS log (nazar log)    │
                                  └──────────────────────────────────────────────┘
```

## Setup

nazar edits none of the files below: you add each line yourself, and `nazar status` checks them.

**1. Install.** An Apple silicon Mac on macOS 26 or later:

```bash
brew install atas/tap/nazar        # the agent and the CLI; starts the agent
brew install atas/tap/nazar-ui     # optional: the window
nazar status                       # the agent answers
```

The cask links `nazar`, `nazar-sign-git` and `git-credential-nazar` in `$(brew --prefix)/bin`.
From source instead, see the [guide's Quick start](GUIDE.md#quick-start); a source build is a
different signature, so its keys don't carry over to the Homebrew one.

**2. A key.** One Touch ID; usable from the terminal app you type it in, blocked for everything else:

```bash
nazar ssh-key create github
nazar ssh-key pubkey github | pbcopy          # add it on https://github.com/settings/keys
                                              # (as Authentication key, and again as Signing key)
```

**3. ssh.** In `~/.ssh/config`:

```
Host github.com
  IdentityAgent ~/.nazar/run/agent.sock
  IdentityFile ~/.nazar/keys/github.pub
  IdentitiesOnly yes
  ControlMaster no
```

`ControlMaster no`: a persisted master connection detaches from your terminal, so it has no app
and matches only `any` or `unknown` rules. Then `ssh -T git@github.com`: a prompt, then "Hi <you>!".

**4. Signed commits** (optional). `gpg.ssh.program` is the link's absolute path
(`$(brew --prefix)/bin/nazar-sign-git` from the cask):

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$HOME/.local/bin/nazar-sign-git"
git config --global user.signingkey ~/.nazar/keys/github.pub
git config --global commit.gpgsign true
```

**5. HTTPS tokens for git** (optional). Store the token with `nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN`
(hidden prompt), give its entry the host and receiver ([Secrets](#secrets)), and make nazar git's
helper for the host:

```bash
git config --global --replace-all credential.https://github.com.helper ""
git config --global --add credential.https://github.com.helper nazar
```

The [guide's "Secrets: the GitHub token"](GUIDE.md#secrets-the-github-token) has every step.

**6. Shell completion.** One line in your shell's startup file:

```bash
source <(nazar completion bash)      # ~/.bash_profile or ~/.bashrc (needs the bash-completion package)
source <(nazar completion zsh)       # ~/.zshrc, after compinit
nazar completion fish | source       # ~/.config/fish/config.fish
```

**7. Check.** `nazar status` prints a `setup:` line for each thing in steps 3 and 4 that isn't
wired to nazar (and for keys still in Apple's `ssh-agent`), each with the exact fix. None when all
is well.

Coming from an older nazar: nazar-agent moves `~/.config/nazar` into `~/.nazar` when it starts,
and your config stays approved. nazar never edits `~/.ssh/config` or git's settings: `nazar status`
prints the replacement for each line that still names `~/.nazar/agent.sock` or
`~/.nazar/keys`.

### Using nazar from Claude Code or Codex

The nazar skill tells an agent how to help you with nazar: what it may run, and that every
approval stays yours (it shows you the lines to add; it never edits these files or works around
a refusal).

- **Claude Code**: `/plugin marketplace add atas/nazar`, then `/plugin install nazar@nazar`.
- **Codex**: link (or copy) the skill folder into `~/.agents/skills`, from the clone of step 1:
  `mkdir -p ~/.agents/skills && ln -s "$PWD/skills/nazar" ~/.agents/skills/nazar`. Claude Code
  without the plugin takes the same link in `~/.claude/skills`.
- **Any other agent**: tell it "read https://github.com/atas/nazar/blob/main/llms.txt and help me set nazar up".

To let the agent use a key, add a rule for it (Touch ID). For Claude Code, an Allow dialog once per run:

```bash
nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session --at 1
```

## Everyday tasks

| I want to… | Command |
|---|---|
| See what's running and what's approved | `nazar status` |
| Check that ssh and git go through nazar | `nazar status` (the `setup:` lines, each with its fix; none when all is well) |
| Fix a key `nazar status` says it can't read (after a new signature) | its `fix:` line: first unlock the login keychain if it is locked, or reinstall the nazar-agent you had if this one is signed differently, and look again (deleting the item destroys the key for good); if it is still unreadable, `security delete-generic-password -s dev.nazar -a ssh-key/github`, then `nazar ssh-key create github`, then upload the new public key |
| List my keys | `nazar ssh-key list` |
| See who may use a key | `nazar ssh-key rules github` |
| Let an app use a key | `nazar ssh-key rule add github --apps app:com.googlecode.iterm2 --gate login --scope session` |
| Let Claude Code use a key, asking once per run | `nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session` |
| Make a key the chip itself guards (Touch ID on every use, even if nazar is compromised) | `nazar ssh-key create hydra --always-ask` (see [Very sensitive keys](#very-sensitive-keys)) |
| Make a key nothing can use while the Mac is locked | `nazar ssh-key create deploy --only-when-unlocked` (see [While the Mac is locked](#while-the-mac-is-locked)) |
| Change a rule | `nazar ssh-key rule set github 2 --gate login` (2 = the `#` column of `rules`) |
| Remove a rule | `nazar ssh-key rule remove github 2` |
| Store an API token (Touch ID once) | `printf '%s' "$TOKEN" \| nazar secret add NAME` (or type it at the hidden prompt) |
| Let an app receive a secret | `nazar secret rule add NAME --apps app:com.googlecode.iterm2 --to signed:apple:com.apple.git-remote-http --gate login --scope session` (`rule set` and `rule remove` as for a key; the rule numbers are the ones `nazar --json secret list` shows) |
| Let git push and pull with a stored GitHub token | the [guide's "Secrets: the GitHub token"](GUIDE.md#secrets-the-github-token) steps |
| Give a script a secret | `nazar get NAME` (needs `stdout` in its `deliver` and a rule naming the script's interpreter in `to:`) |
| Approve a change left waiting (edited by hand, or an edit whose prompt was denied or could not be shown) | `nazar config apply` (shows the change, then asks) |
| Make a change an agent proposed | run the command it printed, ending in `--allow-loosen-access` (it asks for Touch ID at once) |
| See who used my keys | `nazar log --since 24h` or `nazar log summary --since 7d` |
| Forget every remembered approval now | `nazar revoke --all` |
| Find the apps nazar has seen | `nazar apps list` |
| Check the config file without applying it | `nazar config check` |
| Open the window | `nazar ui` |

## Very sensitive keys

For a key that must never sign without you, such as the root login of a production microk8s
node, ask the chip itself to guard it:

```bash
nazar ssh-key create hydra --always-ask        # one Touch ID now; then Touch ID on every use
nazar ssh-key pubkey hydra | ssh ubuntu@hydra 'sudo tee -a /root/.ssh/authorized_keys'
ssh root@hydra                                 # the prompt appears, every time
```

The key is made with Secure Enclave user presence: nazar asks for Touch ID, Apple Watch or your
password on every signature, and the chip refuses to sign unless you authenticated to nazar in
the last few minutes, so even a compromised nazar could only sign right after a prompt you
answered. Its entry is the key's own `gate: block` plus one rule for the terminal you typed it
in, `login` with `scope: use`. Made somewhere that is not a terminal (Nazar UI.app's checkbox "Ask
for Touch ID on every use"), the key gets no rule: it is blocked for every app until you add one,
and only a rule that asks on every use (`--gate login --scope use`) can be added. `nazar ssh-key
list` marks it `asks every time (chip)` (`"userPresence": true` with `--json`).

nazar's own commands never loosen it: a `dialog` or `none` rule, or `login` with `scope: session`
or `app`, is refused, even behind another rule (`hydra asks on every use (enforced by the chip);
create another key for a looser rule`). Only a hand edit of `config.yaml` that you approve with
`nazar config apply` can add one, and `nazar config check` then warns about it. For a name
`config.yaml` already has an entry for, `--always-ask` never rewrites it: it is refused unless
that entry's rules are already all `login` with `scope: use` or `block`.

## While the Mac is locked

A key works while the screen is locked, once you have logged in since the Mac started: a gate
`none` rule lets a background job (a cron job, an agent's `git push`, GitHub Desktop's fetch) sign,
open a secret or get a Kubernetes or AWS credential while you are away. Rules that ask (`login`,
`dialog`) still wait for you. For a key, secret or CA nothing may use while the Mac is locked,
whatever its rules say, make it with `--only-when-unlocked`:

```bash
nazar ssh-key create deploy --only-when-unlocked
nazar secret add NOTES --only-when-unlocked
nazar k8s ca create hydra-nazar --only-when-unlocked
nazar aws ca create prod --only-when-unlocked
```

The chip enforces it, for the key's life: it can't be turned on or off later; make a new key
instead. Nazar UI.app's New key and New secret sheets have the same checkbox, "Only while the Mac
is unlocked" (on, and fixed, while "Ask for Touch ID on every use" is on). A key made with
`--always-ask` is always like this (it needs Touch ID, which a locked Mac can't give), and so is
every key made before nazar had the choice. `ssh-key list`, `secret list`, `k8s list` and
`aws list` mark these `only when unlocked` (`"whileLocked": false` with `--json`). Used while the
Mac is locked, such a key fails with an error, not a refusal (`nazar get`, kubectl's plugin and
`nazar aws credential` exit 1, ssh shows `agent refused operation`), and `nazar log` says `the
Mac is locked; github signs only while it's unlocked`; it works again once you unlock. To let an
old key work while locked, make a new one and replace it where the old public key was.

## Secrets

nazar also keeps API tokens: each is sealed to its own Secure Enclave key, and the same rules
decide who may receive it.

```bash
printf '%s' "$GITHUB_PERSONAL_ACCESS_TOKEN" | nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN
nazar secret add NOTES             # typed at a hidden prompt instead
nazar secret list                  # names, never values
nazar secret rm NOTES              # erased for good; config.yaml keeps its entry
```

The value comes from stdin or a hidden prompt, never from an argument (an argument is visible
in `ps`). `secret add` asks for Touch ID once and writes the secret's entry in
`config.yaml` under `secrets:`: blocked, plus a login rule for the terminal app you typed it in.
Like a key, the secret can be opened while the Mac is locked unless you add it with
`--only-when-unlocked` ([While the Mac is locked](#while-the-mac-is-locked)).
`config check` then warns "no to:" until you name who receives it (`to:`). Added from Nazar UI.app
(its Secrets tab) or anything else that is not a terminal, the secret gets no rule: it is blocked
for every app until you add one; the tab opens its rule editor next. A secret's rules are edited
like a key's, with the same flags and the same Touch ID for a change that loosens access:
`nazar secret rule add|set|remove NAME …`. Its own gate stays `block` (there is no `secret set`).
To change a value,
`nazar secret rm` it and add it again. A value only ever goes to the genuine nazar CLI, never to
another program on the control socket. The hidden prompt takes one line of at most about 1000
bytes; anything longer or with several lines (a key file, JSON) is piped:
`nazar secret add NAME < file`. Exit codes as for every command: 2 for a bad name or value,
3 when the prompt was denied, 4 when `config.yaml` has changes waiting for approval.

**git and gh** get a token through git's credential helper: give the secret
`helper: {git: {host: github.com, username: <your login>}}` (git needs a username too), a rule with `to:` git's HTTPS transport
(`{signed: {team: apple, id: com.apple.git-remote-http}}`), and run
`git config --global --replace-all credential.https://github.com.helper ""` then
`git config --global --add credential.https://github.com.helper nazar` (the [guide](GUIDE.md#secrets-the-github-token) has the whole
migration). Only `https`, and only the host the secret names, is answered. **Scripts** use
`nazar get NAME`: the value and a newline on stdout, nothing else; exit 3 and nothing printed when
refused. It needs `stdout` in the secret's `deliver` and a rule whose `to:` names what runs the
script; `$(nazar get NAME)` keeps the value in the shell, so prefer giving it to the one command
that needs it.

**Keeping a secret out of `ps`.** Any program running as you can read every command line
(`ps -ww`) and every process's startup environment (`ps eww`). So a secret never goes on a command
line or into an exported variable; each delivery hands it over privately:

```
# helper: git asks git-credential-nazar over its credential protocol (stdin/stdout)
git push

# stdout, into a tool's stdin
nazar get API_TOKEN | sed 's/^/Authorization: Bearer /' | curl -H @- https://api.example.com
nazar get DB_PASSWORD | tool --password-stdin

# late-env: the program sees $BRAVE_API_KEY, set inside it before its first line
nazar run --secret BRAVE_API_KEY -- npx -y @brave/brave-search-mcp-server
```

Not `tool --token "$(nazar get NAME)"` (the value is on the command line for every `ps`), not
`export TOKEN=$(nazar get NAME)` (it is in the startup environment of every child), and not a file.
A tool that saves what it reads in its own store keeps a copy nazar no longer guards.

**MCP servers and other Node or Python programs** use `nazar run --secret NAME -- command…`
(late-env): the value is never on disk, on a command line or in the startup environment of nazar,
`npx` or the program, and is in the program's environment before its first line runs (its own
child processes inherit it). The secret needs `late-env` in `deliver` and a rule whose `to:`
names that exact command line, for example `to: [{command: [npx, -y, "@brave/brave-search-mcp-server"]}]`
(a rule without `to:` is accepted with a warning and gives the value to any
`node` or `python3` command line its callers run). nazar finds `npx`, `node` or `python3` through
`defaults.trustedPath` (a list of folders, default `/usr/bin /bin /usr/sbin /sbin /opt/homebrew/bin
/usr/local/bin`; never your `PATH`, never a mise or asdf shim), runs the program in `/` with an
environment it builds itself (`PATH` from `trustedPath`, your home, user, temp folder, `LANG`,
`LC_*`, `TERM`), and passes on another variable of yours only when the secret's `envAllow:` lists
it (`envAllow: [HTTPS_PROXY]`; variables that load code, such as `NODE_OPTIONS` or `DYLD_*`,
never). One `--secret` per run; `node`, `python3` and `npx` only (not Apple's, Xcode's or Homebrew's
`python3`, which start themselves again), and not from a disk image or share you mounted; under `gate: none` it runs with no prompt for any child of the app the rule names (and `npx` picks what it runs from files you can edit). Refused at the prompt or before it: `nazar run` exits 3 and nothing runs.
Refused after the exec (a pinned file or a variable changed, or a volume was mounted or unmounted
during the run): the program runs without the value
and prints `nazar: secret NAME not delivered: <why>`; `nazar log --target secret:NAME` has the
reason (`receiver changed at exec: …`, `unexpected environment: NAME`). The [guide](GUIDE.md#secrets-an-mcp-servers-key-brave-search) has the Brave
Search migration. **Status:** on the Mac `nazar run` needs a nazar-agent.app with its loaders
inside (the next release); with an older one it refuses, asks nothing and runs nothing.

## The three words in every rule

**apps: who asks.** A rule matches when one of its matchers matches the process chain. In
config.yaml `apps:` and `to:` are always lists, even of one: `apps: [iterm]`, or one `- app: …`
per line. `to: [any]` is an error: leave `to:` out. Apple's team is `apple`, in lower case
(`Apple` matches nothing, so it is an error too). (A file from an older nazar that writes one
matcher alone, `to: [any]`, or a `scope` or `expire` that does nothing is rewritten when nazar-agent
starts, same rules, the old file kept as `config.yaml.bak`. A team written `Apple` is left for
you to fix: `nazar config check` names it, and the approved config stays in force meanwhile.)

| Matcher | Matches | Example |
|---|---|---|
| `app:<bundle-id>` | the GUI app the request came from (team ID pinned on approval) | `app:com.googlecode.iterm2` |
| `signed:<team>[:<id>]` | any process in the chain with this code signature | `signed:Q6L2SF6YDW:com.anthropic.claude-code` |
| `path:<absolute path>` | any process in the chain running that exact file | `path:/opt/homebrew/opt/mytool/bin/mytool` |
| a name | a named matcher from `apps:` in the config | `claude` |
| `any` / `unknown` | anything / a chain with no app | |

`path:` is for an unsigned program with no app above it, such as a Homebrew daemon that launchd
starts. Symlinks in the path are resolved each time, so `/opt/homebrew/opt/<formula>/bin/<x>`
keeps working after `brew upgrade`; nothing is pinned and there is nothing to trust. It is only as
safe as who can write that file: anything under `/opt/homebrew` can be replaced by any program
you run, and `nazar config check` warns about that. It is narrower than `unknown`, weaker than
`signed:`. When a signed app or tool runs the program (your terminal, Claude Code), name that
instead. A path of Apple's (`/bin`, `/usr`, `/System`) is refused under `gate: none`.

**gate: what has to happen.**

| Gate | Effect |
|---|---|
| `login` | Touch ID, Apple Watch or Mac password: proves it's you |
| `dialog` | Allow / Deny dialog: proves someone is at the Mac |
| `none` | silent: the `apps:` match is the only check |
| `block` | refused at once, with a warning; the key isn't even listed to such a program (`ssh-add -L` shows what a program may use) |

**scope: how long one approval lasts.** `use` (asks every time), `session` (once per terminal
tab, until its shell exits; for a rule matched by a tool in the tab such as Claude Code, that
run of the tool, until it exits), `app` (until the app quits). `--expire 8h` caps it. `scope` and
`expire` go only where they do something: with `login` or `dialog`, and `expire` with `session`
or `app`; anywhere else they are an error (remove them). Within its
scope an approval covers one thing: one server (by host key) or one kind of signature (git
commits and tags), so the first push elsewhere, or the first commit signature, asks once more.
`nazar status` shows what each approval covers.

Callers no rule matches get the key's own gate, `block` unless you chose otherwise.
Changes that **loosen** anything need your Touch ID. A rule or gate edit that loosens access is
made only with `--allow-loosen-access`: it is written and asks at once (exit 0 once in force, 3 if
you deny it, 4 if the prompt could not be shown; the change then stays in `config.yaml` and
`nazar config apply` asks again). Without the flag nazar refuses it, prints what it would loosen
and the command to run (exit 2), and changes nothing: an agent proposes a rule that way, and you
run the printed command. `trust --app` and `ssh-key create`/`delete` ask at once either way. Changes
that **tighten** apply at once.

## Kubernetes

nazar can stand in for a self-managed cluster's admin credential (microk8s, kubeadm). It keeps a
certificate authority for the context in the Secure Enclave and gives kubectl a fresh client
certificate, valid 15 minutes, each time your rules allow it. nazar never reads, copies or
rewrites the credential your kubeconfig has now: it adds a context of its own beside it.

```bash
nazar k8s ca create                  # asks for the context, the server and its CA; Touch ID once
nazar k8s ca show hydra-nazar --microk8s   # the node steps again, if you need them
kubectl --context hydra-nazar get pods     # Touch ID once per tab (8 hours at most); a new certificate each run
```

- At a terminal `ca create` asks three things, each with a default in [brackets] from your
  kubeconfig's current context (Enter takes it): the context name (`hydra-nazar` when the current
  context is `hydra`), the server, and the server's CA, shown as its fingerprint. On a microk8s node
  `sudo openssl x509 -in /var/snap/microk8s/current/certs/ca.crt -noout -fingerprint -sha256` prints
  the same fingerprint: compare them. You can give the path of a copy of that file instead.
- Without a terminal (scripts, agents) give both: `nazar k8s ca create hydra-nazar https://hydra.example:16443`;
  the CA is then the one of the kubeconfig cluster with exactly that server. Nothing else is read.
- One Touch ID covers it all: the CA in the Secure Enclave
  (`~/.nazar/keys/k8s-ca-<context>.crt`), the context's entry under `k8s.contexts` in
  `config.yaml` (identity `CN=<your user name>-nazar`, no groups; blocked, plus a login rule for the
  terminal app you typed it in). No program is pinned: kubectl, helm, k9s or any other program
  that runs the plugin gets the credential when your rules allow whoever ran it, so a `brew
  upgrade` changes nothing. Then nazar adds three entries to the kubeconfig: the
  context, and the cluster and user `nazar-<context>`. It changes nothing else there, keeps the old
  file once (`<kubeconfig>.nazar-backup-<time>`), and never switches your current context.
- The CA signs while the Mac is locked too, unless you add `--only-when-unlocked`
  ([While the Mac is locked](#while-the-mac-is-locked)). Run again for a context set up already, it
  needs the same choice: the CA's is fixed.
- It then prints the steps that make the cluster trust the CA (run them on the node; nazar never
  touches the cluster), and the role binding to run with your current admin access:
  `kubectl create clusterrolebinding <user>-nazar --clusterrole=cluster-admin --user=<user>-nazar`.
  A binding can be removed later; a certificate in `system:masters` could not.
- Every other caller is refused until you add a rule: `nazar k8s rule add hydra-nazar --apps <app>
  --gate login --scope session` (Touch ID), with the flags of `ssh-key rule` except `--to` (the
  program that runs the plugin receives the credential). Rules are judged on whoever ran that
  program (your terminal, Claude Code, …), never on kubectl itself, as for an SSH key; a rule
  naming kubectl is refused. A program launchd started that runs the plugin itself (a daemon:
  nothing ran it) is judged as itself, so it can have a rule of its own, such as
  `nazar k8s rule add hydra-nazar --apps path:/opt/homebrew/opt/mytool/bin/mytool --gate none
  --allow-loosen-access`.
  `rule set` and `rule remove` take the rule's number. An approval
  covers one program: one for kubectl in a tab does not cover helm there.
- kubectl runs `nazar k8s credential <context>`; you don't. It refuses a cluster other than the
  one recorded, a plugin whose output goes anywhere but straight to the program that ran it (never
  a file, a terminal or another process), a program it can't identify, and a request no rule
  allows: kubectl shows nazar's one line and `exit code 3`, and `nazar log --target
  k8s:hydra-nazar` says why.
- There is no `clients:` list any more. A context that still has a `clients:` line (from an older
  nazar) is off, and only that context: `nazar config check` and `nazar status` say
  `k8s.contexts.<context>.clients: no longer used; remove the line`. Delete the line and approve
  the change with Touch ID (`nazar config apply`); SSH keys and secrets keep working meanwhile.
- `nazar k8s list` shows the contexts and their CAs; `nazar status` names a CA this nazar-agent
  can't use (after a new signature, say) on a `vault:` line with its fix. `nazar k8s forget
  hydra-nazar` (Touch ID) deletes the CA and the entry, then removes nazar's three kubeconfig entries
  while they are exactly as it wrote them (it names any others for you to remove). Certificates
  already handed out stay valid until they end.
- Nazar UI.app's Kubernetes tab shows what `nazar k8s list` shows and each context's last 24 hours
  of `nazar log`, edits its rules (a new or looser rule asks for Touch ID, as here) and forgets
  it. It doesn't set a context up: run `nazar k8s ca create` in a terminal.

## AWS

nazar can give the AWS CLI and SDKs short-lived session credentials through IAM Roles Anywhere,
with no long-lived AWS key anywhere: not in `~/.aws`, not in nazar. It keeps a certificate
authority per entry in the Secure Enclave; each time your rules allow it, nazar-agent mints a
certificate for one `CreateSession` call to Roles Anywhere and hands the session to the client.
nazar never edits `~/.aws` and never calls AWS for setup: it prints the steps, you run them.

```bash
nazar aws ca create dev                    # the CA and the entry; Touch ID once; prints the AWS steps
aws sts get-caller-identity --profile dev  # Touch ID once per tab (8 hours at most); a new session each run
```

- One Touch ID covers it all: the CA in the Secure Enclave
  (`~/.nazar/keys/aws-ca-<name>.crt`), the entry under `aws:` in `config.yaml` (identity
  `CN=<your user name>-nazar`; blocked, plus a login rule for the terminal app you typed it in).
  No program is pinned: the AWS CLI (the v2 package or Homebrew's `awscli`), boto3, terraform or
  any other program that runs `credential_process` gets the credential when your rules allow
  whoever ran it, so a `brew upgrade` changes nothing and no `aws` is needed on `PATH`.
- The CA signs while the Mac is locked too, unless you add `--only-when-unlocked`
  ([While the Mac is locked](#while-the-mac-is-locked)); it is fixed for the CA's life.
- It then prints the AWS-side steps, filled in, to run with your current AWS admin access: a
  trust anchor holding the CA, a role whose trust policy accepts only that trust anchor and that
  identity (`aws:PrincipalTag/x509Subject/CN` and `x509Issuer/CN`), and a profile naming the role.
  The first step needs `jq` (`brew install jq`). Attach the permissions the role should have
  yourself.
- Then connect the entry: add the three ARNs to it in `config.yaml`. That loosens access, so it
  waits for `nazar config apply` and Touch ID. Until then `nazar aws list` says `aws.dev is not
  connected yet: add trustAnchorArn, profileArn and roleArn …` under the entry (with `--json`, its
  `state` is `not-connected`).

  ```yaml
  aws:
    dev:
      identity: {user: you-nazar}        # written by ca create
      trustAnchorArn: arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/<id>
      profileArn: arn:aws:rolesanywhere:us-east-1:123456789012:profile/<id>
      roleArn: arn:aws:iam::123456789012:role/dev
      duration: 1h                       # optional: the session's length, 15m to 1h
      gate: block                        # written by ca create, with one rule
  ```

- And add the profile to `~/.aws/config`, with the path `ca create` printed:

  ```ini
  [profile dev]
  credential_process = /Users/you/.local/bin/nazar aws credential dev
  ```

- Every other caller is refused until you add a rule: `nazar aws rule add dev --apps <app>
  --gate login --scope session`, with the flags of `k8s rule` (no `--to`: the program that runs
  `credential_process` receives the credential). Rules are judged on whoever ran that program
  (your terminal, Claude Code, …), never on aws itself, as for an SSH key; a rule naming aws is
  refused. A program launchd started that runs `credential_process` itself is judged as itself,
  as for k8s. An approval covers one program: one for aws in a tab does not cover terraform there.
- The AWS CLI and SDKs run `nazar aws credential <name>`; you don't. It refuses an output that
  goes anywhere but straight to the program that ran it (never a file, a terminal or another
  process), a program it can't identify, and a request no rule allows (exit 3). A failure on AWS's side (a trust policy that doesn't match, say)
  is exit 1 with AWS's error code, such as `AccessDeniedException`. `nazar log --target aws:dev`
  says why; each line names the session (`aws credential session <serial>`), which is the role
  session name CloudTrail shows (`assumed-role/dev/<serial>`).
- A session lasts `duration` (1 hour by default) and works from anywhere until then: revoking an
  approval in nazar stops new sessions at once, not one already handed out. Any program a rule
  lets run `aws` can print the session (`aws configure export-credentials`); the rules are what
  decide who gets one.
- `nazar aws list` shows the entries and their CAs; `nazar aws ca show dev` prints the CA
  certificate. `nazar aws forget dev` (Touch ID) deletes the CA and the entry; disable or delete
  the trust anchor in AWS and remove the profile's `credential_process` line yourself.
- Nazar UI.app has no AWS tab yet: use the CLI.

## Help and shell completion

`nazar --help` lists every command. `nazar <command> --help` (or `-h`, or `nazar help <command>`)
shows one command's usage, its flags with the values each takes, and examples, at every level:
`nazar ssh-key --help` lists the ssh-key commands, `nazar ssh-key rule add --help` shows that
one. Help goes to stdout and exits 0. Two commands never show it, because their arguments
belong to another program: `sign-git` (ssh-keygen's), `k8s credential` (kubectl's) and
`aws credential` (the AWS CLI's); and
after `run`'s `--`, `-h` and `--help` are the program's. A mistyped command is still a usage
error (exit 2), with a suggestion (`Did you mean this?`).

Shell completion covers commands, flags, the values `--gate`, `--scope`, `--decision` and the
others take, and the names of your keys, secrets, contexts, aws entries, rules and apps. Add the line for
your shell to its startup file ([Setup](#setup), step 6); nazar never edits it.

Names come from nazar-agent through the read-only list calls of `nazar ssh-key list`,
`secret list`, `k8s list`, `aws list` and `apps list`, half a second at most each. Completing never asks for
Touch ID, shows no dialog, writes nothing and changes nothing; with nazar-agent not running it
offers no names.

## Commands

```
nazar [--json] [--yes] <command>

ssh-key create <name> [--always-ask] [--only-when-unlocked]
                                  (the terminal it is typed in gets a login rule; --always-ask: the chip asks on every use;
                                   --only-when-unlocked: the chip refuses it while the Mac is locked)
ssh-key list | pubkey <name> | delete <name> | rules <name>
ssh-key rule add <key> --apps M[,M] [--to M[,M]] --gate G [--scope S] [--expire D] [--at N]
ssh-key rule set <key> <n> [--apps ...] [--to ... | --no-to] [--scope S] [--gate G] [--expire D | --no-expire]
ssh-key rule remove <key> <n>
ssh-key set <key> [--scope S] [--gate G] [--expire D | --no-expire]
secret add <name> [--only-when-unlocked]   (the value on stdin or at a hidden prompt; never an argument)
secret list | rm <name>
secret rule add|set|remove <name> …   (the flags of ssh-key rule; a secret's own gate stays block)
get <name>                        (the value on stdout; git uses git-credential-nazar instead)
run --secret <name> -- <command>  (the program gets the value in its environment; nothing on disk or argv)
k8s ca create [<context> [<server>]] [--only-when-unlocked]   (asks at a terminal; one Touch ID; adds its kubeconfig entries)
k8s ca show <context> [--microk8s] | list | forget <context>
k8s rule add|set|remove <context> …   (the flags of ssh-key rule, without --to or --no-to; the context's own gate stays block)
k8s credential <context>          (kubectl's exec plugin; run by kubectl, not by people)
aws ca create <name> [--only-when-unlocked]   (one Touch ID; prints the AWS steps and the ~/.aws/config lines)
aws ca show <name> | list | forget <name>
aws rule add|set|remove <name> …   (the flags of k8s rule; the entry's own gate stays block)
aws credential <name>             (credential_process; run by the AWS CLI and SDKs, not by people)
apps list
status [--follow]
revoke --all | --key <name> | --session <id> | --app <bundle-id>
config check | config apply
trust --app <bundle-id>
log [--follow] [--since 24h] [--target T] [--caller C] [--decision D] | log summary [--since 7d]
sign-git <ssh-keygen args>        (git's gpg.ssh.program, through ~/.local/bin/nazar-sign-git)
install [--bin-dir DIR] | uninstall [--bin-dir DIR]
ui | version
completion bash|zsh|fish          (the shell completion script)
help [<command>]                  (also <command> --help: a command's flags, values and examples)
```

`--json` prints machine-readable output for scripts and agents. `--to` limits who receives the
result (for SSH keys, the process on the agent socket, normally `/usr/bin/ssh`).

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | ok | |
| 1 | error | read the message |
| 2 | usage | check the command; a change that loosens access, refused because `--allow-loosen-access` was not given, prints what it would loosen and the command to run |
| 3 | refused | a rule or a person said no; don't retry |
| 4 | staged | the change is in config.yaml but its prompt could not be shown (another prompt open, or the cooldown after a denied one): run `nazar config apply` |
| 5 | nazar-agent not running | `nazar install` |
