# AGENTS.md

Two audiences: agents running on a Mac that **uses** nazar, and agents **working on** this repo.
The full user guide is [docs/CLI.md](docs/CLI.md).

## If you are an agent on a Mac that uses nazar

nazar guards the user's SSH keys, including from you. A refusal is the user's decision, not a
bug to work around.

These rules also ship as an Agent Skill, [skills/nazar/SKILL.md](skills/nazar/SKILL.md) (a Claude
Code plugin and a Codex skill), with a setup checklist; this file stays the source of truth.

```
 your ssh / git ──▶ nazar-agent ──▶ rule for your app? ──▶ gate ──▶ Secure Enclave signs
                                        │                    │
                                        no → refused (3)     dialog / Touch ID on the
                                                             user's screen; 60 s, then refused
```

**Safe to run any time** (read-only; add `--json`):
`nazar status`, `nazar ssh-key list`, `nazar ssh-key rules <key>`, `nazar secret list`,
`nazar k8s list`, `nazar k8s ca show <context>`, `nazar aws list`, `nazar aws ca show <name>`,
`nazar apps list`, `nazar log --since 1h`, `nazar config check`, `nazar version`, and
`nazar <command> --help` (a command's flags, values and examples).
`nazar status` also runs `ssh -G` on the hosts of `~/.ssh/config` (so a `Match exec` there runs
its command), reads git's global signing settings and asks the agent `$SSH_AUTH_SOCK` names, when
it is not nazar's, for its key list (an agent that prompts for that prompts here too); all
read-only. It prints `setup:` lines (the `setup` field with `--json`) naming what is not wired to
nazar and the fix. Show them to the user; never apply them yourself. `nazar config check` may
report `"Apple" matches nothing; Apple's team is written apple` after an upgrade: that matcher
never matched, and `apple` would match every Apple program; tell the user, don't fix it.

**When something is refused** (`agent refused operation`, `sign_and_send_pubkey: signing failed`,
`Couldn't sign message`, exit 3; or `Permission denied (publickey)` / `Couldn't find key in agent`
when `ssh-add -L` doesn't list the key: nazar offers you only the keys your rules allow):
- Stop. Do not retry in a loop: each retry may put a dialog on the user's screen.
- Do not switch to another key, edit `~/.ssh/config` or `~/.nazar/config/config.yaml`, or set
  `SSH_AUTH_SOCK` to another agent to get around it.
- Tell the user what was refused and why (`nazar log --since 10m --decision blocked` shows it),
  and suggest the rule they could add, for example
  `nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session`.
  For an unsigned program with no app above it (a Homebrew daemon launchd starts), the rule names
  its file: `--apps path:/opt/homebrew/opt/<formula>/bin/<program>`; a path rule is only as safe
  as who can write that file, so say so (`nazar config check` warns).

**Commands that loosen access**: never run them yourself. A rule or gate edit (`ssh-key rule
add`, `secret rule add`, `k8s rule add`, `aws rule add`, `rule set` or `ssh-key set` with a weaker gate) that
loosens access is made only with `--allow-loosen-access`, which writes it and asks for the user's
Touch ID at once (exit 0 in force, 3 denied, 4 the prompt could not be shown: `nazar config
apply` asks). Print the full command, with the flag, for the user to run at their terminal, e.g.
`nazar ssh-key rule add github --apps signed:Q6L2SF6YDW:com.anthropic.claude-code --gate dialog --scope session --allow-loosen-access`.
Without the flag the command refuses (exit 2), changes nothing, and prints what it would loosen
and the command to run: you may run it that way, with `--json`, to preview a rule. `trust --app` and
`ssh-key create`/`delete` put the Touch ID prompt on the user's screen at once (exit 3 if refused).
`ssh-key create <name>` takes two flags, `--always-ask` and `--only-when-unlocked`: the agent writes the key's entry itself (blocked, plus a
login rule for the app the command runs in, which covers you too if you run inside that app; the prompt shows the rule), and the key's rules decide
its Secure Enclave protection. With `--always-ask` (only when the user asks for it) that rule is
`login` with `scope: use` and the chip asks for Touch ID on every signature, for good: a looser
rule for that key is refused (`<name> asks on every use (enforced by the chip)`); don't try to
get around it, suggest another key.
A new key works while the Mac is locked too (once the user has logged in); with
`--only-when-unlocked` (only when the user asks for it; `--always-ask` implies it) the chip refuses
it while the Mac is locked, for good. Every key made before that choice existed is like that:
`ssh-key list` marks them `only when unlocked` (`"whileLocked": false`). Used while the Mac is
locked, such a key fails with an error, not the user's refusal (exit 1 from `nazar get` and
kubectl's plugin, `agent refused operation` from ssh; `nazar log` says `decision=error` and `the
Mac is locked; <name> signs only while it's unlocked`): tell the user it waits for the Mac to be
unlocked, and don't retry in a loop or switch keys. A new key is the only way to change it.
`secret add <name>` and `secret rm <name>` also put the Touch ID prompt on the user's screen at
once. `secret add` reads the value from stdin: never put a value on a command line, and never
add a secret the user did not ask you to store. Like `ssh-key create`, it writes a login rule for
the app the command runs in, which covers you too if you run inside that app, and takes
`--only-when-unlocked`.
Moving a secret out of a shell profile or `.env` file: never read or print the file's lines; find
only the line number (`grep -n '^export NAME=' ~/.zshrc | cut -d: -f1`). The user runs
`printf '%s' "$NAME" | nazar secret add NAME` in a shell that has it, then deletes that line.
`k8s ca create` and `k8s forget` put the Touch ID prompt on the user's screen at once too, and
write the user's kubeconfig (ca create adds a context, a cluster and a user, and keeps one backup
of the file; forget removes them), so run them only when the user asks. Without a terminal,
`k8s ca create <context> <server>` needs both arguments and takes the server's CA from the
kubeconfig cluster with exactly that server; the user compares its fingerprint on the prompt.
It takes `--only-when-unlocked` too; run again for a context set up already, it needs the same
choice (a different one is refused: the CA's is fixed).
`aws ca create <name>` and `aws forget <name>` put the Touch ID prompt on the user's screen at
once too; ca create pins no program (there is no `clients:` list: whatever runs
`credential_process` gets the session when the rules allow whoever ran it) and takes
`--only-when-unlocked` (the same choice when run again for an entry set up already). nazar never edits `~/.aws` or calls AWS for
setup: ca create prints the AWS-side steps; they are the user's to run, as is adding the three
ARNs to the entry (a loosening: staged, `nazar config apply`).
Never run `config apply` repeatedly or in the background.
When an app's signing team changed (`nazar apps list` shows the problem and the fix; its `app:`
rule matches nothing until then), find out why first: `codesign -dvv` of the installed app and the
vendor's announcement. Then tell the user. Print `nazar trust --app <bundle-id>` for them only if
the change is explained; if it isn't, suggest reinstalling from the vendor.

**Secrets** are guarded like keys: a refused secret (exit 3 from `nazar get`; from git,
`could not read Username for 'https://…'` or `Authentication failed` when nazar's credential
helper refused) is the user's decision; do not retry it, read it some other
way, set another `credential.helper`, or ask the user to paste it to you. A value `nazar get` gives
you goes to the one command that needs it, never into a file, a log, a commit or your output.

**`nazar run --secret NAME -- cmd…`** (an MCP server's key, for example) is the user's wiring.
Refused at the prompt or before it, it exits 3 and the program does not start; refused after the
exec, the program runs without the value and prints `nazar: secret NAME not delivered: <why>`.
Either way: do not retry it in a loop, change the command line, the `apps:`/`trustedPath`/
`envAllow` entries or `~/.claude.json` to get past it, or put the value in an `env` block; tell
the user (`nazar log --since 10m --target secret:NAME`) and suggest the rule. A changed file or
variable is refused on purpose (`receiver changed at exec`, `unexpected environment`). Never run
`nazar run --secret` for a secret you were not asked to wire, not even to test a server, and
never edit `~/.npm`, `~/.npmrc`, the node or npm folders `trustedPath` names, or nazar's loaders:
each would get the value past the rule without a new dialog.

**Kubernetes**: a refused `kubectl` (`getting credentials: exec: … failed with exit code 3`) is
the same: do not retry it, edit the kubeconfig, point `KUBECONFIG` elsewhere, or use another
credential; `nazar log --target k8s:<context> --since 10m` says why, and you can suggest the rule
(`nazar k8s rule add <context> --apps … --gate dialog --scope session`; there is no `--to`). Never run
`nazar k8s credential` yourself. There is no `clients:` list: the program that runs the plugin
(kubectl, helm, k9s) gets the credential when the rules allow whoever ran it (or the program
itself, when launchd started it). A context that still
has a `clients:` line is off (`k8s.contexts.<context>.clients: no longer used`): tell the user to
remove the line and approve; don't edit `config.yaml` yourself.

**AWS**: a refused AWS credential (the AWS CLI or an SDK reports that `credential_process`
failed; `nazar aws credential` exited 3) is the user's decision: do not retry it, edit
`~/.aws/config` or its `credential_process` line, set `AWS_PROFILE` or other `AWS_*` variables,
or use another credential to get around it; `nazar log --target aws:<name> --since 10m` says
why, and you can suggest the rule (`nazar aws rule add <name> --apps … --gate dialog --scope session`;
there is no `--to`). Exit 1 with an AWS error code (`AccessDeniedException`, `ValidationException`,
…) or `is not connected yet` is setup, not a refusal: tell the user what AWS said. Never run
`nazar aws credential` yourself, and never print, store or pass on a session it gave
(`aws configure export-credentials` included).

**Tightening** (`revoke`, a stronger gate, removing a rule) applies at once and is always safe.

**Git signing** goes through `nazar-sign-git` (`$(brew --prefix)/bin/nazar-sign-git`, or `~/.local/bin/` from a source build). If a commit fails to sign, report it;
don't commit with `-c commit.gpgsign=false` unless the user says so.

## If you are working on this repo

- Read the spec first: [docs/design/nazar-design.md](docs/design/nazar-design.md),
  then the module designs next to it ([secrets](docs/design/secrets-design.md),
  [k8s](docs/design/k8s-design.md)). The threat model is
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- Layout: `core/` (Go core), `cmd/nazar/` (CLI), `bridge/` (Go as a C archive), `macos/` (Swift:
  Secure Enclave, Keychain, dialogs, nazar-agent.app, Nazar UI.app), `test/integration/`.
- Test: `make test` (Go, fake platform), `make swift-test`, `make integration`, `make check`
  (everything). Run one `make check` at a time: it is heavy.
- Keep the user surface small: one way to do a thing, short plain messages, no new flags or
  config keys unless they remove complexity elsewhere.

**Hard rules** (security software; these protect the developer's real keys):
- Tests never trigger Touch ID, Keychain, TCC or any window. Human-only paths go through seams;
  any test touching keychain APIs calls `SecKeychainSetUserInteractionAllowed(false)` first.
- Never read, write or delete a keychain item your process isn't already trusted for, never create
  a keychain under `~/Library/Keychains`, never change the keychain search list.
- Never touch the developer's installed nazar: `~/.nazar`, an older install's `~/.config/nazar`, the installed apps,
  the LaunchAgents `dev.nazar` / `dev.nazar.agent`.
- Sign builds ad hoc (`codesign -s -`) only.
- Never weaken or skip a test to make it pass; a security fix comes with a test that fails without it.
