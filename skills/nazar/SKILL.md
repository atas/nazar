---
name: nazar
description: >-
  Set up and use nazar, the macOS agent that keeps SSH keys, API tokens, Kubernetes CAs and AWS
  CAs in the Secure Enclave and asks the user (Touch ID or an Allow dialog) before each use. Use
  when the user mentions nazar, SSH keys or ssh-agent, ~/.ssh/config, git commit signing, git or
  ssh failing with "agent refused operation" or "Permission denied (publickey)", API keys or
  tokens for scripts, git HTTPS or MCP servers, kubectl credentials for a self-managed cluster,
  AWS credentials through IAM Roles Anywhere or credential_process, or a nazar command that
  exits 2 (a change that loosens access, refused), 3 (refused) or 4 (staged). Covers setup, keys, rules, secrets, nazar run, Kubernetes,
  AWS and the log, and what an agent must never do to get around a refusal.
---

# nazar

nazar is a macOS SSH agent (`nazar-agent`) and a CLI (`nazar`). Its SSH keys are made inside
the Secure Enclave and never leave it; it also keeps API tokens and Kubernetes and AWS CAs the
same way. Each key, secret, context or aws entry has rules: which apps may use it (by code signature, never by name),
how one approves (`login`: Touch ID / Watch / password, `dialog`: Allow/Deny, `none`, `block`)
and how long an approval lasts (`use`, `session`, `app`). Callers no rule covers are blocked.

**Trust model: you drive the commands; the user approves.** Every approval is a prompt on the
user's screen, and nazar guards the keys from you too. A refusal is the user's decision, not a
bug to work around. The full rules are in
[AGENTS.md](https://github.com/atas/nazar/blob/main/AGENTS.md) ("If you are an agent on a Mac
that uses nazar"), which wins where this file and it differ; the user guide is
[docs/CLI.md](https://github.com/atas/nazar/blob/main/docs/CLI.md).

## Rules you must follow

**Safe any time** (read-only; add `--json`): `nazar status`, `nazar ssh-key list`,
`nazar ssh-key rules <key>`, `nazar secret list`, `nazar k8s list`, `nazar k8s ca show <context>`,
`nazar aws list`, `nazar aws ca show <name>`, `nazar apps list`, `nazar log --since 1h`, `nazar config check`, `nazar version`,
`nazar <command> --help`.

**When something is refused** (`agent refused operation`, `sign_and_send_pubkey: signing failed`,
`Couldn't sign message`, exit 3; or `Permission denied (publickey)` / `Couldn't find key in agent`
when `ssh-add -L` doesn't list the key: nazar offers a program only the keys its rules allow):
- Stop. Don't retry in a loop: each retry may put a dialog on the user's screen.
- Don't switch to another key, edit `~/.ssh/config` or `~/.nazar/config/config.yaml`, set
  `SSH_AUTH_SOCK` to another agent, or disable signing (`-c commit.gpgsign=false`) to get past it.
- Tell the user what was refused and why (`nazar log --since 10m --decision blocked`), and
  suggest the rule they could add, e.g.
  `nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session`.
- `the Mac is locked; <name> signs only while it's unlocked` (exit 1, `decision=error`) is not a
  refusal: the key waits for the Mac to be unlocked. Say so; don't retry or switch keys.

**Commands that loosen access**: never run them yourself; print the command for the user.
- A rule or gate edit (`ssh-key rule add`, `secret rule add`, `k8s rule add`, `aws rule add`, `rule set`, or
  `ssh-key set` with a weaker gate) that loosens access is made only with `--allow-loosen-access`:
  it writes the change and asks for the user's Touch ID at once (exit 0 in force, 3 denied, 4 the
  prompt could not be shown: `nazar config apply` asks). Give the user the full command with the
  flag, to run at their terminal. Without the flag it refuses (exit 2), changes nothing and prints
  what it would loosen and the command to run, so you may run it that way, with `--json`, to
  preview a rule. Never run `config apply` yourself repeatedly or in the background. nazar takes
  no other edit while one waits: one loosening edit at a time.
- `trust --app`, `ssh-key create`/`delete`, `secret add`/`rm`, `k8s ca create`/`forget`, `aws ca create`/`forget`
  put the Touch ID
  prompt on the user's screen at once (exit 3 if refused). `k8s ca create` and `k8s forget` also
  write the user's kubeconfig; nazar never writes `~/.aws`.
- `--always-ask` and `--only-when-unlocked` only when the user asks for them: both are fixed for
  the key's life. A looser rule on an `--always-ask` key is refused
  (`<name> asks on every use (enforced by the chip)`); don't work around it, suggest another key.
- Tightening (`revoke`, a stronger gate, `rule remove`) applies at once and is always safe.

**Secrets**:
- Never put a secret value on a command line, in a file, a log, a commit or your output. Never ask
  the user to paste one to you. Prefer telling the user to run `nazar secret add NAME` themselves
  (a hidden prompt); never add a secret the user did not ask you to store.
- Moving a secret out of a shell profile or `.env` file: never read or print the file's lines.
  Find only the line number (`grep -n '^export NAME=' ~/.zshrc | cut -d: -f1`). The user runs
  `printf '%s' "$NAME" | nazar secret add NAME` in a shell that has it, then deletes that line
  themselves.
- A value `nazar get` gives you goes to the one command that needs it (`nazar get NAME | tool --token-stdin`).
- A refused secret (exit 3 from `nazar get`; from git, `could not read Username for 'https://…'`
  or `Authentication failed`) is the user's decision: don't retry, read it another way, or set
  another `credential.helper`.
- `nazar run --secret NAME -- cmd…` is the user's wiring. If it is refused (exit 3, or
  `nazar: secret NAME not delivered: <why>`), don't change the command line, the `apps:`,
  `trustedPath` or `envAllow` entries, `~/.claude.json`, `~/.npmrc`, `~/.npm` or nazar's loaders,
  and don't put the value in an `env` block. Show `nazar log --since 10m --target secret:NAME`.
  Never run `nazar run --secret NAME` for a secret you were not asked to wire, not even to test.

**Kubernetes**: a refused `kubectl` (`getting credentials: exec: … failed with exit code 3`): don't
retry, edit the kubeconfig, change `KUBECONFIG` or use another credential; show
`nazar log --target k8s:<context> --since 10m`. Never run `nazar k8s credential` yourself.

**AWS**: a refused AWS credential (the AWS CLI or an SDK says `credential_process` failed;
`nazar aws credential` exited 3): don't retry, edit `~/.aws/config` or its `credential_process`
line, set `AWS_PROFILE` or other `AWS_*` variables, or use another credential; show
`nazar log --target aws:<name> --since 10m`. Exit 1 with an AWS error code (`AccessDeniedException`, …)
or `is not connected yet` is setup, not a refusal: say what AWS said. Never run
`nazar aws credential` yourself, and never print or pass on a session (`aws configure export-credentials`).

**Files you never edit**: `~/.ssh/config`, `~/.gitconfig` (no `git config --global`), shell rc
files, `~/.nazar/config/config.yaml`, `~/.claude.json`, `~/.aws/config`. Show the user the exact lines to add and
let them apply them. `nazar status` prints `setup:` lines with fixes: show them, don't apply them.

**Exit codes**: 0 ok, 1 error, 2 usage (also a loosening refused without `--allow-loosen-access`:
it prints the command to run), 3 refused (don't retry), 4 staged (the prompt could not be shown;
the user runs `nazar config apply`), 5 nazar-agent not running (`nazar install`).

## Setup checklist

Walk the user through these; they run the commands that prompt and make the edits.

1. **Install** (Apple silicon, macOS 26 or later; the user runs it):
   ```bash
   brew install atas/tap/nazar        # the agent and CLI; starts the agent, no brew services needed
   brew install atas/tap/nazar-ui     # optional window
   ```
   Upgrades (`brew upgrade nazar`) keep keys. A build from source is a different signature, so
   its keys don't carry over to the Homebrew one or back
   ([guide, Quick start](https://github.com/atas/nazar/blob/main/docs/GUIDE.md#quick-start)).
2. **Check**: `nazar status` (or `nazar --json status`, field `setup`). Each `setup:` line names
   what of ssh and git isn't wired to nazar, with the fix. Run it again after each step. Lines
   from an older nazar (`~/.nazar/agent.sock`, `~/.config/nazar/keys`) get their replacement.
3. **A key** (the user, at a terminal: one Touch ID): `nazar ssh-key create github`. Then
   `nazar ssh-key pubkey github | pbcopy` and add it at https://github.com/settings/keys, as an
   Authentication key and again as a Signing key.
4. **`~/.ssh/config`** (show it; the user adds it):
   ```
   Host github.com
     IdentityAgent ~/.nazar/run/agent.sock
     IdentityFile ~/.nazar/keys/github.pub
     IdentitiesOnly yes
     ControlMaster no
   ```
   `ControlMaster no`: a persisted master connection detaches from the terminal, so its requests
   have no app and match only `any`/`unknown` rules. Test with `ssh -T git@github.com`.
5. **Git commit signing** (show it; the user runs it). Use the absolute path of the link
   (from a source build, `$HOME/.local/bin/nazar-sign-git`):
   ```bash
   git config --global gpg.format ssh
   git config --global gpg.ssh.program "$(brew --prefix)/bin/nazar-sign-git"
   git config --global user.signingkey ~/.nazar/keys/github.pub
   git config --global commit.gpgsign true
   ```
6. **HTTPS tokens for git** (optional): the user stores the token (`nazar secret add GITHUB_PERSONAL_ACCESS_TOKEN`,
   hidden prompt), adds `deliver: [helper]`, `helper: {git: {host: github.com, username: <login>}}`
   and a rule with `to:` git's HTTPS transport (`signed:apple:com.apple.git-remote-http`) to its
   entry in `config.yaml`, runs `nazar config apply` (Touch ID), and makes nazar git's helper:
   ```bash
   git config --global --replace-all credential.https://github.com.helper ""
   git config --global --add credential.https://github.com.helper nazar
   ```
   The [guide's "Secrets: the GitHub token"](https://github.com/atas/nazar/blob/main/docs/GUIDE.md#secrets-the-github-token)
   has every step, including removing the old copy.
7. **Shell completion** (the user adds one line; nazar never edits it):
   ```bash
   source <(nazar completion bash)      # ~/.bash_profile or ~/.bashrc (needs bash-completion)
   source <(nazar completion zsh)       # ~/.zshrc, after compinit
   nazar completion fish | source       # ~/.config/fish/config.fish
   ```
8. **Let you (the agent) use the key**: a rule for your app, which the user makes and approves.
   Print this for the user to run at their terminal (for Claude Code, ahead of the terminal's rule;
   it asks for Touch ID at once):
   `nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session --at 1 --allow-loosen-access`
   (to preview what it loosens, run it yourself without the flag and with `--json`: it refuses,
   changes nothing, and prints the lines and the command). For another agent, find
   its signature from the block: `nazar log --since 10m --decision blocked` names the caller, and
   the warning on screen has **Copy suggested rule**.

## config.yaml reference

`~/.nazar/config/config.yaml`. Read it to explain the setup; never edit it (show the user the
lines; a loosening needs their `nazar config apply`). `nazar config check` validates it. Every
field nazar accepts:

```yaml
apiVersion: nazar/v1
kind: Config

defaults:
  timeout: 60s                  # an unanswered prompt becomes a refusal
  fallback: {gate: block}       # what callers no rule matches get
  trustedPath: [/usr/bin, /bin, /usr/sbin, /sbin, /opt/homebrew/bin, /usr/local/bin]
                                # where `nazar run` finds commands; add a mise/asdf node bin here
audit:
  args: redacted                # or none: log only the program name and argument count

apps:                           # named matchers, used as `apps: [claude]`
  claude: {signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}}   # any process in the chain
  iterm: {app: com.googlecode.iterm2}                                   # the GUI app; team pinned on approval
  mydaemon: {path: /opt/homebrew/opt/x/bin/x}                           # an unsigned program launchd starts

ssh_agent:
  socket: ~/.nazar/run/agent.sock
  keys:
    github:                     # a key: rules, or scope/gate/expire for every caller
      rules:                    # top to bottom, first match wins; rules only allow
        - apps: [claude]        # always a list; also any, unknown, or inline matchers
          to: [{signed: {team: apple, id: com.apple.git-remote-http}}]   # optional: the receiver
          scope: session        # use | session | app
          gate: dialog          # login | dialog | none | block
          expire: 8h            # optional cap on one approval

secrets:
  GITHUB_TOKEN:                 # git over HTTPS
    deliver: [helper]           # default [helper, stdout]; late-env for nazar run; file/env not built
    helper: {git: {host: github.com, username: octocat}}
    rules:
      - apps: [iterm]
        to: [{signed: {team: apple, id: com.apple.git-remote-http}}]   # git's HTTPS transport
        scope: session
        gate: login
  MCP_KEY:                      # an MCP server, through nazar run
    deliver: [late-env]
    envAllow: [HTTPS_PROXY]     # extra variables nazar run passes on (never NODE_OPTIONS, DYLD_*)
    rules:
      - apps: [claude]
        to: [{command: [npx, -y, "@scope/mcp-server"]}]   # the exact command line it goes to
        gate: none

k8s:
  contexts:
    mycluster-nazar:            # written by nazar k8s ca create
      credential: ca-cert       # the only kind
      identity: {user: me-nazar, groups: [system:masters]}   # the certificate's CN and O
      ttl_cert: 15m             # 1m to 1h
      cluster:
        server: https://k8s.example:16443
        ca_sha256: 3f8c000000000000000000000000000000000000000000000000000000000000
      rules:                    # no to:
        - apps: [iterm]
          scope: session
          gate: login
          expire: 8h

aws:
  dev:                          # written by nazar aws ca create; the ARNs added by the user
    identity: {user: me-nazar}  # the certificate's CN (AWS's source identity)
    trustAnchorArn: arn:aws:rolesanywhere:eu-west-1:123456789012:trust-anchor/0a1b2c3d-0000-0000-0000-000000000000
    profileArn: arn:aws:rolesanywhere:eu-west-1:123456789012:profile/0a1b2c3d-0000-0000-0000-000000000001
    roleArn: arn:aws:iam::123456789012:role/nazar-dev
    duration: 1h                # session length, 15m to 1h
    rules:                      # no to:
      - apps: [iterm]
        scope: session
        gate: login
```

Refused by name, so nothing is approved to work later: `clients:` (k8s, aws; remove it),
`cwd:` in a matcher, and the not-yet-built `ttl`, `credential_ref`, `kubeconfig_context`,
`issuer`, `ttl_token`, `file:`.

## Tasks

**Keys.** `nazar ssh-key create <name>` writes the key's entry: blocked, plus a `login` rule
(`scope: session`) for the app the command runs in, which covers you too if you run inside that
app. The public key is `~/.nazar/keys/<name>.pub`; `nazar ssh-key pubkey <name>` prints it
(for GitHub, a server's `authorized_keys`, etc.).
- `--always-ask`: the chip asks for Touch ID on every signature, even with nazar compromised; only
  `login` with `scope: use` rules can be added. For keys that matter most (a production root login).
- `--only-when-unlocked`: the chip refuses the key while the Mac is locked. Off by default: a new
  key also works while locked (once the user has logged in), so `gate: none` rules let background
  jobs sign. `--always-ask` implies it; keys made before the choice existed are like that too
  (`ssh-key list` shows `only when unlocked`, `"whileLocked": false`).
- Neither can be changed later. To change one: create a new key (`nazar ssh-key create deploy2 --only-when-unlocked`),
  put its public key where the old one was, move the rules, then `nazar ssh-key delete <old>`.
- `nazar ssh-key list` (with `--json`: rules, last use, `userPresence`, `whileLocked`);
  `ssh-add -L` shows the keys the calling program may use.

**Rules** (the same flags for `ssh-key`, `secret`, `k8s` and `aws`; numbers from `nazar ssh-key rules <key>`
or `nazar --json secret list`; first match wins):
- `nazar ssh-key rule add <key> --apps M[,M] --gate G [--scope S] [--expire D] [--at N] [--to M[,M]]`
- `nazar ssh-key rule set <key> <n> [--apps …] [--gate …] [--scope …] [--expire D | --no-expire] [--to … | --no-to]`
- `nazar ssh-key rule remove <key> <n>`
- `nazar ssh-key set <key> --gate login|dialog|block [--scope S]`: what callers no rule matches get.
- Matchers `M`: `app:<bundle-id>` (the GUI app, team pinned on approval, e.g.
  `app:com.googlecode.iterm2`), `signed:<team>[:<id>]` (any process in the chain with that
  signature, e.g. `signed:Q6L2SF6YDW:com.anthropic.claude-code`), a name from `apps:` in the
  config, `any`, `unknown`, and `path:<absolute path>` (a process running that exact file, for an
  unsigned program with no app above it, such as a Homebrew daemon; only as safe as who can write
  the file). For an unsigned tool run from a terminal, name the terminal or signed tool instead.
- Gates: `login`, `dialog`, `none`, `block`. Scopes: `use` (asks every time), `session` (once per
  terminal tab, or per run of a tool such as Claude Code), `app` (until the app quits). `--expire 8h` caps it.
- A `gate: none` or `scope: app` rule on a terminal or IDE covers any program on the Mac
  (`open -a Terminal x.command` really is Terminal). Suggest `scope: session` instead.

**Secrets.**
- Store: the user runs `nazar secret add NAME` (hidden prompt) or pipes it
  (`nazar secret add NAME < file`); `--only-when-unlocked` as for keys. `nazar secret rm NAME`
  erases it (config entry kept); to change a value, `rm` and `add` again.
- **Keep the value out of the process table.** Any program running as the user can read every
  command line (`ps -ww`) and every process's startup environment (`ps eww`). So a secret never
  goes on argv or into an exported variable. Pick the delivery that hands it over privately:

  | Delivery (`deliver:`) | Use | Example |
  |---|---|---|
  | `helper` | git and gh over HTTPS | git asks `git-credential-nazar` through its credential protocol (stdin/stdout) |
  | `stdout` | an HTTP header | `nazar get API_TOKEN \| sed 's/^/Authorization: Bearer /' \| curl -H @- https://api.example.com` |
  | `stdout` | a tool with a `--…-stdin` option | `nazar get DB_PASSWORD \| tool --password-stdin` (if the tool saves it in its own store, that copy is outside nazar) |
  | `late-env` | MCP servers, `node`/`python3`/`npx` programs | `nazar run --secret BRAVE_API_KEY -- npx -y <package>`: the program sees `$BRAVE_API_KEY` (the variable is the secret's name), set inside it before its first line and never in its startup environment, so `ps eww` doesn't show it |

  Never: `tool --token "$(nazar get NAME)"` (on argv for every `ps`), `export TOKEN=$(nazar get NAME)`
  (in every child's startup environment), or writing it to a file, a log or your output.
- A script: `nazar get NAME` prints the value; the entry needs `stdout` in `deliver` and a rule
  whose `to:` names the script's interpreter.
- An MCP server (or any `node`, `python3`, `npx` program): `nazar run --secret NAME -- npx -y <package>`
  as the server's command, with nazar's absolute path (`command -v nazar`) as `"command"` in
  `~/.claude.json` and no `env` block. The entry needs `deliver: [late-env]` and a rule with
  `to: [{command: [npx, -y, "<package>"]}]`; if node comes from mise or asdf, its real folder in
  `defaults.trustedPath`. These are `config.yaml` and `~/.claude.json` edits: show them to the
  user, who applies them (`nazar config apply`). The [guide's Brave Search
  example](https://github.com/atas/nazar/blob/main/docs/GUIDE.md#secrets-an-mcp-servers-key-brave-search) is the worked one.
- `nazar secret rule add NAME --apps app:com.googlecode.iterm2 --to signed:apple:com.apple.git-remote-http --gate login --scope session`
  (rules as above).

**Kubernetes** (self-managed clusters: microk8s, kubeadm). nazar keeps a CA per context in the
Secure Enclave and gives kubectl a 15-minute client certificate each time the rules allow it.
- Set up (the user asks; one Touch ID; writes the kubeconfig): at a terminal `nazar k8s ca create`
  asks for everything; without one, `nazar k8s ca create hydra-nazar https://hydra.example:16443`
  (the CA is taken from the kubeconfig cluster with exactly that server; the user compares its
  fingerprint on the prompt). It prints the node steps (`nazar k8s ca show hydra-nazar --microk8s`
  again) and a `kubectl create clusterrolebinding` line to run with the current admin access.
- kubectl runs nazar as its exec credential plugin: `kubectl --context hydra-nazar get pods`.
- Rules: `nazar k8s rule add hydra-nazar --apps … --gate dialog --scope session` (no `--to`: the
  program that runs the plugin, kubectl, helm or k9s, receives it; rules judge whoever ran that
  program, as for SSH, or the program itself when launchd started it, such as a Homebrew
  daemon: `--apps path:<its file>`). Nothing is pinned, so upgrades need nothing. A leftover
  `clients:` line turns that one context off until the user removes it and approves.
- `nazar k8s list`; `nazar k8s forget hydra-nazar` (Touch ID) removes the CA, its entry and
  nazar's kubeconfig entries.

**AWS** (IAM Roles Anywhere; no long-lived AWS key anywhere). nazar keeps a CA per entry in the
Secure Enclave; each run of the AWS CLI's `credential_process` gets a fresh session (1 hour by
default, 15 minutes to 1 hour) when the rules allow it.
- Set up (the user asks; one Touch ID): `nazar aws ca create dev` makes the CA and the `aws.dev`
  entry; no program is pinned. It prints the AWS-side steps (trust anchor, role, profile; the
  first needs `jq`) for the user to run with their own AWS admin access, and the `~/.aws/config`
  lines: `[profile dev]` with `credential_process = <nazar's path> aws credential dev`.
- The user then adds `trustAnchorArn`, `profileArn` and `roleArn` to `aws.dev` in `config.yaml`
  (a loosening: `nazar config apply`, Touch ID). Until then `nazar aws list` says the entry is not
  connected yet (`--json`: `"state": "not-connected"`).
- Use: `aws sts get-caller-identity --profile dev`. `nazar log --target aws:dev` names each session
  by its serial, which CloudTrail shows as the role session name.
- Rules: `nazar aws rule add dev --apps … --gate dialog --scope session` (no `--to`: the program
  that runs `credential_process`, the AWS CLI, boto3 or terraform, receives it; rules judge
  whoever ran that program, as for SSH). Nothing is pinned, so upgrades need nothing.
- `nazar aws list`; `nazar aws forget dev` (Touch ID) removes the CA and the entry; the user
  disables the trust anchor in AWS and removes the profile.

**Apps.** `nazar apps list` shows the `apps:` matchers, pinned teams and what keeps one from
matching. `nazar trust --app <bundle-id>` pins an app's team again, after an update that changed
it: find out why first (`codesign -dvv` of the installed app, the vendor's announcement), tell the
user, and print the command only if the change is explained; if it isn't, suggest reinstalling
from the vendor. `nazar revoke --all` (or `--key <name>`, `--session <id>`, `--app <bundle-id>`)
forgets remembered approvals at once.

**Why was this refused?** `nazar log --since 10m --decision blocked`, or
`nazar log --since 1h --target github` (`ssh:<key>`, `secret:<name>`, `k8s:<context>`, `aws:<name>`),
`--caller claude`, `--decision denied|timeout|error`; `nazar log summary --since 7d`. The log
needs an admin account. `nazar status` shows current approvals, a staged change and config
warnings; `nazar config check` validates `config.yaml` without applying it. After an upgrade it
may report `"Apple" matches nothing; Apple's team is written apple`: that matcher never matched,
and `apple` would match every Apple program, so tell the user and let them choose; don't fix it.
