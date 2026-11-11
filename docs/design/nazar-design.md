# nazar 🧿 — design spec

- **Status:** Design spec.
- **Name:** `nazar` (CLI `nazar`, app `Nazar.app`), after the nazar amulet 🧿 (Unicode "NAZAR
  AMULET") that watches the door. Tagline: *a watchful eye on every key.* Renamed from the working
  name `keygate`; `openclave` was rejected as one letter away from the Open Enclave
  SDK.
- **Scope of this spec:**
  - **Fully designed:** the core plus the **`ssh` module** (Phase 1).
  - **Designed at module level** (section 7), each to be refined in its own spec before it's
    built:
    - the **`secrets` module** (Phase 2);
    - the **`k8s` module** (Phase 3), of which only the `stored` credential type is built.

## 1. Why

On macOS, SSH keys normally sit in `~/.ssh` as files. If the file has no passphrase, any script
can copy the key and use it forever, from anywhere. A passphrase stored in the Keychain only
protects the file *at rest*. **Any program running as the user can still export the full private
key:** it starts its own fake agent and runs Apple's `/usr/bin/ssh-add --apple-load-keychain`
with `SSH_AUTH_SOCK` pointing at it. `ssh-add` is allowed to read the passphrase from the
Keychain without a dialog, decrypts the key, and sends the whole private key to the fake agent
(`ADD_IDENTITY`). This was verified on a test Mac with a throwaway key: no
terminal, no askpass, no dialog, and the fake agent then signed with the key. 1Password's agent adds approval prompts, but the key syncs to every device
and approving needs Touch ID, an Apple Watch or the 1Password password.

nazar is a macOS SSH agent, later a general credential broker, where:

- keys are created **inside the Secure Enclave** and never leave it: not to disk, not to
  memory, not to the caller;
- **every key has its own rules** in a YAML file: how long one approval lasts (per use, per
  terminal session, per app), how the user approves (Touch ID / Apple Watch / Mac password, or a
  dialog that other processes can't press), and which apps get an easier approval;
- the approval dialog shows **who is really asking** (app → process chain → command → folder)
  and **what for** (for example "login to github.com", "sign a git commit");
- inside an approved scope, tools like Claude Code and scripts sign **silently**; anything
  outside it is **blocked** with a warning popup that has no allow button. Letting a new caller
  in means adding a rule to the config, and that config change needs Touch ID / Watch / password.

## 2. Agreed understanding

**Requirements:**
- A Secure Enclave–backed SSH agent that works like 1Password's agent: it signs, and never
  hands out the key.
- A YAML config with rules per key:
  - **`scope`**: `use` | `session` (terminal tab / session / process tree) | `app`;
  - **`gate`** (renamed from `gate`): `login` (Touch ID / Apple Watch / Mac password), `dialog`
    (a dialog other processes can't press), `none` (silent) or `block`.
- Requesting apps (git etc.) **pause** until the user answers the dialog.
- The dialog **shows which app is asking**. If that can't be determined, it says
  "**Unknown app**" and shows everything that *is* known.
- Several keys with different levels of access, for example a strict full-access key and a
  relaxed read-only deploy key.
- **Command line first** for v1, with a window as a thin client of the CLI (section 6.1).
  **The product is the UI-less `nazar` CLI and the `nazar-agent` background service**; the UI is a separate,
  optional Mac app, **Nazar UI.app**, installed on its own, that never runs in the background or
  in the menu bar (section 6.1). Everything it does is a CLI command.
- Published through Homebrew.
- Architecture: **one background service, `nazar-agent`,** that holds the core and all modules,
  plus a small CLI (`nazar`). Both ship in one Homebrew package; Nazar UI.app in another
  (section 12).
- Modules:
  - **`ssh`** first.
  - Then **`secrets`**: GitHub PATs and API keys, encrypted with a Secure Enclave key, released
    only to allowed callers in an allowed scope after approval. Env var piping, env var passing
    and file serving are delivery methods *within* this one module, not separate modules.
  - Then **`k8s`**: a kubectl exec credential plugin, limited by *who called kubectl*. The
    credential type is configurable per context: `ca-cert` (B) is built first (Milestone 12);
    `stored` (A) is the fallback, not built yet; `jwt` (C) is not planned.

**Assumptions:**
- One repo. The **core is Go**, a library reused by a Linux version later. The **macOS app is
  Swift**: it owns the main thread, dialogs, CryptoKit and LocalAuthentication, and links the
  Go core as a static library. The two meet at a **platform interface** (section 4.7).
- Apple silicon or T2 Macs (they have a Secure Enclave). **macOS 26 and later**; developed and
  tested on macOS 27.
- v1 covers `ssh`, `git` over SSH, and git commit signing over SSH.
- Callers that no rule covers are **denied**, never silently allowed.
- Success for Phase 1: the user replaces their GitHub key with a nazar key and uses it daily.
  Claude Code in an approved iTerm tab pushes without prompts, and a script outside that tab
  gets a dialog or a refusal.

## 3. Non-goals (Phase 1)

- No GUI beyond the approval dialogs in Milestones 1-4. Milestone 5 adds the Nazar window, a
  client of the CLI with no access of its own; Milestone 6 moves it out of the agent into the
  separate, optional Nazar UI.app (section 6.1). There is no menu bar item and no settings store.
- No Ed25519 or RSA keys. The Secure Enclave only supports P-256 (`ecdsa-sha2-nistp256`).
- No key import, export or backup. Keys are tied to the device by design; a new Mac gets new
  keys.
- No syncing between Macs.
- No Linux or Windows build. Linux is planned later as a pure-Go build of the same core with a
  TPM 2.0 platform layer (section 4.7); Phase 1 only keeps the platform interface clean enough
  for that.
- No `secrets` or `k8s` modules (Phases 2 and 3).

## 4. Architecture

```
                     nazar-agent  (Swift; background agent app, launched at login)
                       ┌─────────────────────────────────────────────────────────┐
                       │  libnazar-core.a  (Go, linked as a C archive)         │
 ssh / git ──socket──▶ │    ssh module        SSH agent protocol                 │
 nazar CLI ─socket─▶ │    control module    CLI commands: keys, status, revoke │
                       │    CallerResolver    who is asking (process chain, app) │
                       │    PolicyEngine      YAML rules → decision              │
                       │    ApprovalCache     remembered approvals per scope     │
                       │    Approver          when/what to ask (logic only)      │
                       │    AuditLog          one line per decision              │
                       │──────────────── platform interface (C ABI) ─────────────│
                       │  Swift platform layer                                   │
                       │    EnclaveStore      CryptoKit Secure Enclave keys      │
                       │    Prompts           LocalAuthentication, AppKit dialog │
                       │    ProcessInfo       peer token, process tree, codesign │
                       │    SystemEvents      process exit, screen lock          │
                       └─────────────────────────────────────────────────────────┘
```

- **`nazar-agent`** (`nazar-agent.app`, bundle id `dev.nazar.agent`; called "Nazar.app" in
  sections written before Milestone 6)
  - A background app with no Dock icon, **no menu bar item and no window** (`LSUIElement`),
    started at login by a user LaunchAgent (`dev.nazar.agent`). The only things it ever puts on
    screen are the ones a request needs: the login prompt, the Allow/Deny dialog and the block
    warning (sections 4.4, 4.8).
  - It has to be an app bundle, for two reasons: it shows those dialogs, and the public release
    must be signed and notarized. It is not installed in `/Applications`: it lives in its
    Homebrew package (section 12), and `nazar install` registers whatever place it runs from.
  - It is the only process that touches Secure Enclave keys.
  - **Identity is the signature, not the place** (Milestone 6). Its Keychain items, the
    socket check of the CLI and the vault's own "is this my item" check trust its designated
    requirement (bundle id and signing certificate) only, never its path: Homebrew installs
    each version into a new folder, and a move must never orphan the keys. A program at the
    same path with another signature is a different program; one with the same signature at
    another path is the same one.
- **Nazar UI.app** (bundle id `dev.nazar.ui`, optional, section 6.1)
  - A normal Mac app: a Dock icon while it is open, Cmd+Q quits it, and quitting it never
    affects the agent. It never runs in the background and has no menu bar item.
  - It runs the `nazar` CLI and nothing else, after checking the CLI's signature.
- **`nazar` CLI**
  - A thin client that talks to the agent over a control socket. It is a plain Go binary and
    the same on every platform. It ships inside `nazar-agent.app` (`Contents/MacOS/nazar`),
    linked onto `$PATH` by the package.
  - The CLI has no key access of its own.
- **Module interface.** A module turns an external request into a core **Request** and turns
  the core's answer back into its own protocol:
  - **Request:** `{ key, caller (resolved by core), operation (sign | unlock),
    payload_summary (for example "login to github.com"), raw_payload }`.
  - **Decision:** `allow` | `deny(reason)`. On allow, the core performs the Secure Enclave
    operation and returns the result: a signature for ssh, plaintext for secrets.

### 4.1 CallerResolver

Input: a connected socket. Output: a **CallerChain**.

1. **Identify the peer.** Get the connecting process's audit token from the socket
   (`LOCAL_PEERTOKEN`, which also covers `LOCAL_PEERPID`). Use the audit token rather than the
   bare process ID, so a recycled process ID can't impersonate the original.
2. **Walk up the parent chain** to `launchd`. For each process record:
   - process ID and start time;
   - executable path;
   - arguments (`KERN_PROCARGS2`);
   - current folder;
   - code signature: team ID, signing identifier, and whether it's Apple-signed or ad-hoc.
3. **Find the app.** The **app** is the first process in the chain that is a GUI app bundle,
   for example iTerm2, Cursor or VS Code. Spike S3 also evaluates macOS's "responsible process"
   lookup as a fallback for chains that end at `launchd`; it is **display only** (decided in
   Milestone 1): responsibility is inherited by every process a tab ever started, so a
   process could shed the stricter rules of its ancestors by leaving its chain (a double fork)
   if it were an identity.
   - **An orphaned helper stands for its app** iTerm2 keeps a
     tab's processes alive across its own restart (an update) under its helper `iTermServer`,
     which `launchd` then parents, so the tab's chain ended at `launchd` with no app and was
     `unknown`: the user's rules stopped matching. When a chain reaches `launchd` (not cut off)
     with no app in it, its top process stands for an app, and the chain's app is that app, if
     **all** hold:
     nazar-agent **saw that very process** (same PID and start) **directly below a running app**
     signed by its own non-Apple team, in a chain it resolved (every connection is resolved, so
     any use of the agent from any tab of that helper counts); it is not itself an app and is
     **responsible for itself** (macOS makes a process answer for itself once the process
     responsible for it has exited); and **exactly one** running GUI app has the **bundle ID and
     team** it was seen under, runs as the same user and **started after** the helper (the app
     restarted; the helper is older). Only a process the app itself started can be seen directly
     below it, so a process that leaves its chain (a double fork) never stands for an app, even
     after the app restarts. The app is read fresh from the platform (never from the chain's
     records), so a recycled PID is never the app. What the agent saw is kept in its vault
     (`state/helpers`), so it survives the agent's own restarts (an
     install); a record counts only for a live process with that exact PID and start, still of
     its team. Anything else stays `unknown`, including a helper no agent ever saw below its app
     (nothing used the agent through that helper before the app restarted): those tabs work
     again once reopened. The
     app is then the chain's identity like an app in the chain: `app:` rules match it, `scope:
     app` remembers under it; the dialog says `iTerm2 (via iTermServer-3.7.4) → bash → git →
     ssh`, the audit chain starts with the helper. Why this is safe is in THREAT-MODEL 5.14.
4. **Find the session.** The **session root** is the first process in the chain whose parent is
   the app, or the helper standing for it. In iTerm that is the tab's login shell. The session ID is
   `(pid, start_time)` of that root. Every third-party-signed process right below the app (its
   helpers: `iTermServer`, which hosts every tab, VS Code's terminal host), every process inside
   the app's own bundle whatever its signature (a helper that stopped verifying after the app
   updated on disk), every non-Apple process whose file is gone (no path: an update deleted it), and processes of another user (root-owned `login`) are skipped;
   Apple-signed processes (the shells) are not. A third-party-signed shell, or a tool such as
   Claude Code started directly by the app, is skipped too, so the root falls deeper and
   session scope can act like `use`: narrower, never wider.
   Skipping can only move the root deeper, to a narrower session; the mistake that matters is a
   root shared by several tabs. The app's own signature is not consulted, so an app whose
   running code no longer verifies (updated on disk, not restarted) still gets per-tab sessions
   (it still matches no `app:` rule).
   - **A tool's run is its own session.** When a
     `scope: session` rule is satisfied by a `signed:` process **below** the session
     root that is not Apple's (Claude Code in a tab), the approval is remembered for that
     process's run: the session ID is that process's `(pid, start_time)`, the approval ends when
     the process exits (the same `NOTE_EXIT` watch as for a shell), and the audit line's
     `session=` names it. Everything the run starts (its scripts, a nested `claude -p`) is
     inside it, so the outermost such process in the tab is the run; a second run of the tool
     in the same tab asks again. The shells, `ssh` and `git` are Apple's and are the session,
     not a run in it, so a rule they satisfy stays the tab's; a tool above the root (one the
     app started directly) keeps the root below it, as above. An approval is never wider than
     the tab's: the run is inside the tab.
5. **Unknown chains.** If no app is found (the chain ends at `launchd` without an app, and no
   helper stands for one), the chain is marked `unknown`. Typical causes:
   - ssh `ControlMaster` background processes;
   - tools that start ssh detached from their app;
   - a tab whose app has quit and not come back (an orphaned helper with no running app of its
     bundle ID, or with two), or whose helper nazar-agent never saw below its app.

   An unknown chain has no app and no session, but its processes are still the kernel's parent
   links, each recorded and verified as in step 2: `signed:` rules still match a
   process that is in it, unless the walk was cut off (section 4.2, "Unknown chains").

### 4.2 Config (YAML)

- **Location:** `~/.nazar/config/config.yaml`.
- **Why `~/.nazar/{config,keys,run}`:** one 0700 home, like `~/.gnupg`. `config/` holds the files
  you approve (more may come); `keys/` holds what nazar writes for other tools to read (ssh, git,
  GitHub); `run/` is recreated on every start (the sockets, the secret FIFOs), so backups can skip
  it. Not `~/Library/Containers` (Secretive #839, section 5). `core/layout` is the one definition.
- **Moving from `~/.config/nazar`:** nazar-agent, at start, when `config/config.yaml` is missing
  and `~/.config/nazar/config.yaml` exists, renames the keys, then the config and its `.bak*` files,
  into the home; only regular files, never over an existing one, leaving and logging the rest. The
  approved config is kept by content (4.8), so a moved file needs no new approval. Stale
  `~/.nazar/agent.sock` and `control.sock` are removed. No links are left, and nazar never edits
  `~/.ssh/config` or git's settings: `nazar status` names each old line and its replacement.
- **Reloading:** the app reloads the file when it changes. If the new file is invalid, it keeps
  the last valid config and logs the error. `nazar config check` validates the file without
  applying it.
- **Versioning (Kubernetes style):** every file starts with `apiVersion: nazar/<version>` and
  `kind:`. `kind: Config` is the only kind for now.
  - **A missing or unknown `apiVersion` or `kind` is refused:** nazar keeps the last approved config and the
    block warning explains why. It never guesses at a schema it doesn't know.
  - **A breaking schema change bumps the version.** `nazar config migrate` prints the file
    rewritten for the new version (it never edits the file itself). The migrated file then goes
    through the normal approval for config changes (section 4.8).

```yaml
apiVersion: nazar/v1              # schema version, Kubernetes style (required)
kind: Config

defaults:
  timeout: 60s                    # an unanswered dialog becomes a refusal
  fallback:                       # apps no rule matches
    gate: block                   # refused + a warning popup with NO allow button;
                                  # allowing means editing this file (section 4.8)

apps:                             # named app matchers, reused by every rule below
  claude:
    signed: { team: Q6L2SF6YDW, id: com.anthropic.claude-code }   # Claude Code
  iterm:
    app: com.googlecode.iterm2    # team ID (H7V7XYVQ7D) pinned on first load
  cursor:
    app: com.todesktop.230313mzl4w4u92
  ghostty:
    app: com.mitchellh.ghostty
  zed:
    app: dev.zed.Zed

ssh_agent:
  socket: ~/.nazar/run/agent.sock     # where ssh/git connect (IdentityAgent / SSH_AUTH_SOCK)
  keys:
    github:                         # GitHub account key: all repos
      rules:                        # checked top to bottom; first match wins
        - apps: [claude]            # Claude Code anywhere in the chain, including
          scope: session            # scripts it writes and runs: once per Claude Code run
          gate: dialog              # just the Allow/Deny dialog
        - apps: [iterm, cursor]   # you, in your terminal or editor
          scope: session
          gate: login               # Touch ID / Apple Watch / Mac password
          expire: 8h
      # anything else → blocked, with a warning popup

    myrepo-deploy:                  # GitHub deploy key: one repo, read-only
      rules:
        - apps: [iterm, cursor]
          gate: none                # low risk: no prompt at all
      # anything else → blocked

    hydra:                           # production server: no easy path for anyone,
      scope: use                    # Claude Code included
      gate: login
```

**`apps`: who is asking.** These are named matchers that rules refer to by name. A rule may
also write a matcher inline. A matcher matches a request if **any process in the caller chain**
matches it, so `claude` covers every command Claude Code runs, however deep in the chain.

| Matcher | Matches | Can it be faked? | Allowed in |
|---|---|---|---|
| `signed: {team, id}` | A process whose code signature has this team ID and signing identifier, for example Developer ID–signed CLIs like Claude Code | No. Survives upgrades | Any rule |
| `app: <bundle id>` | A GUI app with this bundle ID. Its team ID is **pinned on first load** and kept in nazar's state; a later mismatch doesn't match, and is logged. `team:` can be given explicitly instead | No, after pinning | Any rule |
| `path: <abs path>` | A process running that exact file: its executable as the kernel reports it (never argv[0]) equals the path with its symlinks resolved **at each match**, or the path as written. No hash, nothing to trust | By whoever can write the file or a folder above it (under `/opt/homebrew`, every program of the user) | Any rule; under `none` not on the system volume |
| `any` | Every request, including `unknown` chains | — | Any rule; usually last |
| `unknown` | Only requests whose app couldn't be determined (section 4.1) | — | Any rule |
| `command: [argv…]` | A receiver started with exactly this command line, for example `[npx, -y, "@brave/brave-search-mcp-server"]` | The command can't be faked, because nazar starts it itself; but what a launcher like `npx` downloads and runs isn't pinned | **Only `to:`** |

A rule's `apps:` (and `to:`) is a list, always, even of one: `[iterm, cursor]` matches if any of
them does; each item is a name or an inline matcher (`[{app: com.googlecode.iterm2}]`, or one
`- app: …` per line). One shape only (the owner's decision, 2026-11-06): a name or a matcher on its
own is a config error that says how to write it. Files from builds that accepted the single form
are rewritten at nazar-agent's start (4.8, "Migration to today's form"). Apple's team is
written `apple`, in lower case only (2026-11-07): teams are matched exactly, so `Apple` matched
nothing while the `gate: none` check folded case; any other spelling is a config error.

**`path:`, without a pin (the owner's decision, 2026-11-05; it replaces the "no `path:` matcher"
decision of 2026-11-01).** Some programs have no signed caller to name: a Homebrew daemon that
launchd starts (ad-hoc, linker-signed, no team ID, no app above it) matched only `unknown`,
which is every program. `path:` names that file:
- **Matching.** A process matches when its executable, as the kernel reports it (never argv[0]),
  equals the rule's path with its symlinks resolved at that match, or the path as written. So
  `/opt/homebrew/opt/<formula>/bin/<x>` follows `brew upgrade` (the `opt/` link moves to the new
  Cellar version; the old one no longer matches). Exact file only: no prefix, glob or folder. A
  path that does not resolve matches nothing. Like `signed:`, any process in the chain (4.1), and
  the receiver itself in `to:`; never a `nazar run` receiver (only `command:` matches one).
- **No hash, no `nazar trust <path>`, no trust records.** The pin broke at every upgrade and
  added little: whoever can replace the file can also run the pinned binary with inputs of their
  choosing. A path rule is only as safe as who can write that file; `nazar config check` warns,
  `path:<p> is writable by your user; any program of yours can replace it and get this rule's
  access`, when the user can write or own the file or a folder above it (THREAT-MODEL 4.3).
- **Under `gate: none`** a `path:` is allowed except on the system volume (`/System`, `/bin`,
  `/sbin`, `/usr` outside `/usr/local`), which holds the shells and tools in every chain.
- **Adding or broadening a `path:` is a loosening** (4.8), compared like any matcher; removing one
  tightens.
- **Migration.** A config approved while `path:` matched nothing must not start matching on the
  upgrade by itself. When this build saves an approved config with `path:` matchers, it also
  writes the vault item `config/approved-paths` with that config's hash. An approved config with
  `path:` matchers that this item does not name is held in force **without** its `path:`
  matchers (a rule left with no `apps:`, or whose `to:` had only `path:`, goes: it matched
  nothing), so everything else keeps working, and `config.yaml` is staged against that, the
  `path:` rules a loosening until `nazar config apply`. The record is never read from the config
  itself: the approved item is `config.yaml` byte for byte, and an older build saved a new
  `path:` rule without a prompt, so anything in the file could have been written by any process
  of the user. An older build ignores the item; after a downgrade and an upgrade the config it
  approved is held again. Old `state/trust` path records stay ignored.
- **Copy suggested rule** proposes `path:` for an unsigned program with no app above it (by its
  `opt/` link when it runs from a Homebrew Cellar and the link resolves to it), never for an
  interpreter.

**`to:`: who receives the result.** `apps:` checks **who asks**; `to:` checks **who gets it**.
Without `to:`, an allowed caller could pass a secret to any program, for example `nazar run --env
BRAVE_API_KEY -- printenv` run by Claude Code. The receiver is:

| Target | Receiver checked by `to:` |
|---|---|
| ssh key | The process connected to the agent socket, for example Apple's `/usr/bin/ssh` (`signed: {team: apple}`) |
| secret via `nazar run` (`late-env`, `env`) | The command `nazar run` starts (the argv after `--`) |
| secret via `file` (named pipe) | The process that opened the pipe |
| secret via `helper` | The tool that asked, for example `git` |
| secret via `stdout` (`nazar get`) | The caller itself, since it prints the secret |
| k8s credential | The program that ran the plugin (kubectl, helm, k9s …), whatever it is; a context's rules take no `to:` (k8s design 2.1) |

- **A rule matches only if both `apps:` and `to:` match.** If `to:` doesn't match, the request falls
  through to later rules and finally to the fallback, which blocks it by default. The block
  warning then says, for example, "Claude Code tried to give BRAVE_API_KEY to `printenv`".
- **Approvals are remembered per receiver too.** An approval for the Brave server in a tab
  doesn't cover a different program in that tab.
- **`config check` warns** about secret rules without `to:`.
- **No `to: [any]`** (2026-11-07): `any` matches every receiver, as no `to:` does, so `any` in a
  `to:` list is a config error that says to leave `to:` out. (On a key's rule that remembers
  approvals it also tied each approval to the receiver, so there it is left for the user, 4.8.)
- **Receivers that are launchers** (`npx`, `uvx`, `pipx`) can only be matched with `command:`.
  That stops a key from being handed to `printenv`, but it doesn't protect against a malicious
  update of the package the launcher fetches. `signed:` receivers are much stronger.

**`rules`: who gets an easier approval.** Rules only **allow**; there is no deny. Each rule sets
`scope`, `gate` and optionally `expire` for the callers it matches. Rules are checked **from
top to bottom, and the first one that matches wins**.

So the same key can be "dialog only" for Claude Code and "Touch ID / Watch / password" for
everything else, as in `github` above. Anything Claude Code runs, including Python or shell
scripts it wrote, has Claude Code in its chain, so it gets Claude Code's rule. That is
intentional.

- **No match → blocked.** A caller that no rule matches gets the key's own `scope` / `gate` /
  `expire` if set, otherwise `defaults.fallback`, which defaults to **`gate: block`**: the
  request is refused at once and a **warning popup with no allow button** appears (section
  4.4). The only way to let that caller in is to add a rule to the config, and a config change
  itself needs Touch ID / Watch / password to take effect (section 4.8). Allowing a new caller is
  meant to be deliberate, never a reflex click. A key or `fallback` can instead be set to a
  prompt (for example `scope: use`, `gate: login`) for anyone who prefers that.
- **No `rules` at all:** a key without `rules` uses its own `scope` / `gate` / `expire` for
  every caller, as `hydra` does above.
- **Order matters:** put more specific callers first. `config check` warns about rules that can
  never match because an earlier rule always matches first.
- **Only matchers that can't be faked by name** (`signed:`, `app:`, `path:`) can appear in rules,
  because a rule makes approval *easier*. There is no `name:` matcher.

**`scope`: how far one approval reaches**
- **`use`:** every request asks. Nothing is remembered.
- **`session`:** one approval covers every request whose chain contains the same session root,
  until the session root process exits, `expire` runs out, or the user revokes it. When the
  rule was satisfied by a tool in the tab (a non-Apple `signed:` process below the
  session root, such as Claude Code), the session is that tool's run: the approval ends when
  its process exits, and a second run in the same tab asks again (4.1 step 4, Milestone 7).
- **`app`:** one approval covers every request from the same app, identified by code signature
  (team ID plus bundle ID), until the app quits, the user logs out, `expire` runs out, or the
  user revokes it.
- **Approvals are per rule, and cover only what was approved** (Milestone 7). Approving the
  Claude Code rule in a tab doesn't approve the `apps: [any]` rule for the same tab, and the other
  way round; and approving a login to github.com doesn't approve a login to any other server,
  nor git signing, in that tab. Each is remembered on its own after its own prompt (4.3).

**Unknown chains:** a request with an `unknown` chain is matched by `apps: [any]`, `apps: [unknown]`,
and a `signed:` matcher that a process **in the chain** satisfies; never
by `app:`, and never through the responsible app (4.1 step 3). Otherwise it
falls to the fallback, so it's **blocked** by default. If a rule does match it, it is **never**
covered by a remembered approval: a prompting gate always shows a dialog with an **Unknown app**
warning, and approving it covers only that one request. A rule with `gate: none` lets it through
silently, like everything else it covers, and each use is still logged: `apps: [any]` or `apps:
[unknown]` (allowed, with a `config check` warning), or a non-Apple `signed:` rule
whose program is in the chain.
- **Why `signed:` still matches.** The
  unknown flag says that nazar can't tell which **app** the chain belongs to, so `app:`, `scope:
  app`, the session and remembered approvals have nothing to stand on. A `signed:`
  match says something else: that a process with that verified code identity is an ancestor of
  the requester, by the kernel's parent links (each one checked against PID reuse, 4.1 step 2).
  That holds whatever sits at the top of the chain. It is not proof that the program started the
  requester (a process can fork its client and exec the program over itself), which is why such
  a rule means "whatever can run that program" in any chain (THREAT-MODEL 5.12). The case that
  forced it: Claude Code in an iTerm2 tab whose `iTermServer` was orphaned by an iTerm2 update
  before nazar-agent ever saw it (4.1 step 3) got the `apps: [any]` rule's Touch ID prompt on every
  `git fetch` instead of its own silent rule. What it concedes is in THREAT-MODEL 5.12 and 5.14:
  a rule on a tool already covers whatever can start that tool, and now also from outside any app
  without the Dock icon a hidden app of its own cost, and from a process that left a chain whose
  ancestors an earlier, stricter rule names.
- **A chain that was cut off** (`truncated`: a parent vanished, a recycled PID, a loop, the depth
  limit) and has no app may be missing exactly the ancestors a stricter rule names, so it is
  matched only by `any` and `unknown`, as before.
- The dialog and the audit line name the process that matched (`matched: claude (rule 1, in the
  chain)`, `matched=claude(…)`); the audit line has no `app=`.
- **Rule order decides, as everywhere:** a `signed:` rule above an `apps: [unknown]` rule now takes
  unknown chains its program is in. To refuse unknown chains whatever is in them, put `apps:
  [unknown]` first. `config check` warns on a `signed:` rule above an `apps: [unknown]` rule
  with a stronger gate (a config approved before this matching got looser that way without
  an edit), and about a weaker rule a `to:` fall-through reaches across the two.

**`gate`: what has to happen before the request goes through**

| Gate | What happens | Proves |
|---|---|---|
| **`login`** | The operating system checks it's you, the same way it unlocks your computer. On **macOS** that's LocalAuthentication `deviceOwnerAuthentication`: Touch ID, Apple Watch or Mac password, whichever is available, so it still works with the lid closed. On **Linux** (later) it's a fingerprint (fprintd) or your login password (polkit) | It's **you** |
| **`dialog`** | nazar's own dialog: click Allow with the mouse or trackpad, once it's enabled (section 4.4) | **Someone** is at the keyboard, not who |
| **`none`** | Goes through **silently**, with no prompt | Nothing; the rule's `apps:` / `to:` match is the only check |
| **`block`** | Refused immediately, with the block warning and no allow button (section 4.4). It's the default for `defaults.fallback` | — |

- `scope` and `expire` only matter for `login` and `dialog`, and `expire` only with `scope:
  session` or `app`. Anywhere else they would do nothing, so they are a config error ("does
  nothing with gate: block; remove it"; until 2026-11-07 a warning, and dropped).
- **`none` is for low-risk combinations** where asking adds nothing, for example a read-only
  deploy key used by git in your own terminal.
- **`gate: none` accepts `app:` matchers, `signed:` matchers whose team is not Apple, `path:`
  matchers off the system volume, and `any` / `unknown`**.
  - **Not allowed under `none`:** any Apple-signed matcher (with or without
    `id`), and a `path:` under `/System`, `/bin`, `/sbin` or `/usr` (outside `/usr/local`).
    `nazar config check` rejects them.
  - **`any` and `unknown` under `none`** say "every program, no prompt" outright, so they are the
    user's choice, not a mistake: `config check` accepts them with a warning naming that effect.
    The key still never leaves the Secure Enclave, and every use is still logged.
  - **Why:** shells, `login`, interpreters and other system binaries appear in almost every
    caller chain, so a rule like `apps: [{signed: {team: apple, id: com.apple.zsh}}]` with `gate: none` would silently mean
    "anything, no prompt". Restricting `none` to the identity of an app, or of a third-party
    signed tool, removes that whole class of mistakes. Blocking individual spellings would
    always miss one.
  - **The same matchers stay allowed under `login` and `dialog`,** because those still put a
    person in the loop.

**Keys without a config entry** get `defaults.fallback`, so they are blocked until configured.
`nazar ssh-key create <name>` takes no gate or scope:
for a name without an entry it writes the key's own `gate: block` plus one rule for the terminal
app the command was typed in (`app: <its bundle id>`, `scope: session`, `gate: login`, `expire:
8h`, the team pinned by the same approval), shows the change on the `login` gate exactly as
`config apply` shows one, and writes it only after approval. The terminal is the chain's app
(4.1) when it has a team and a session lies between it and the CLI; an unknown chain, an app
that runs the CLI directly (Nazar UI.app) or an app without a team gets the `block` entry and
no rule, and the prompt says so. For a name that has an entry already (hand-written, or the
remedy for an unusable key) the key is created under that entry, unchanged. The entry's
policies decide the key's Secure Enclave protection (4.5), so there is nothing to choose at
creation and nothing to re-create later for the usual rules. The one choice is
`--always-ask`: a key the chip asks for on every use. For a
name without an entry the rule for the terminal is then `scope: use`, `gate: login`, no expiry;
with no terminal the entry is the key's own `gate: block` alone, as without the flag (the flag
never widens who may ask for the key). With the flag
the key gets user presence whenever every policy that can reach it fits the chip
(`PresenceFits`: `block`, or `login` with `scope: use`), a `block`-only entry included, and
the agent checks that before the prompt (`createAuth`). For a name with an entry,
`--always-ask` never rewrites it: it is refused (usage) unless every policy of the entry already
fits. The flag is a request argument (`alwaysAsk: "true"`, nothing else is accepted); the agent
writes the entry and decides, and the CLI fails if the reply says the key came back without
presence. The other choice, `--only-when-unlocked`, is whether the chip lets the key work while
the Mac is locked (4.5); it is a request argument the same way (`onlyWhenUnlocked: "true"`), and
the CLI fails if the reply says `whileLocked`.

### 4.3 ApprovalCache

- **Storage:** in memory only, so nothing survives an app restart.
- **Keys:** entries are indexed by `(target, rule, scope_id, receiver, op)`. `target` is the key,
  secret or k8s context. `scope_id` is the session ID (the tab's shell, or the run of the tool
  that satisfied the rule, 4.1 step 4) or the app's signature identity.
  `receiver` is the identity matched by `to:`, or empty for a rule without `to:`. `op` is
  **what the approval covers** (Milestone 7), chosen by the module that asks; for ssh:
  - `login:<SHA256 fingerprint>`: a login to the server whose host key the connection's
    verified `session-bind` proved (section 5). The fingerprint, never the name `known_hosts`
    gives it: that file is the user's, and anything running as the user can rename a server in
    it. A server with several host keys is one destination per key the client sees.
  - `login:unbound`: a login on a connection with no `session-bind` (a client that doesn't send
    one). Nothing proved who the server is, so such logins are their own kind, apart from every
    proved server. A host key the userauth itself carries (`publickey-hostbound`) without a bind
    is the client's own word and names nothing.
  - `sign:git`, `sign:ns:<namespace>`, `sign:data`: an SSHSIG signature by namespace, or data
    nazar doesn't recognise. A namespace has its own prefix, so none (`data`, or `git\0`, which
    prints as `git`) can name git commits or unrecognised data. A namespace the dialog can't
    show in full (a dropped rune, or past 64 characters) is keyed by its SHA-256
    (`sign:nsx:<hex>`), so two that print alike are never one approval.
  A request that names no `op` is never remembered (one-shot). Every part of the key is compared
  exactly.
- **Each entry holds:**
  - when it was created and when it expires;
  - the chain summary shown when it was approved, and what it covers as shown then
    ("github.com", "git commits and tags"), for `nazar status` and the dialog;
  - for LocalAuthentication-based keys, the authenticated **LAContext** used for later signing
    (see S1).
- **Entries are removed when:**
  - the session root exits (watched with a process-exit notification, `NOTE_EXIT`): the tab's
    shell, or the tool's process for an approval given to a run (4.1 step 4);
  - the app quits;
  - `expire` runs out;
  - the user runs `nazar revoke`.

### 4.4 Approver and dialog

**Concurrency**
- Requests that need approval are queued per `(target, rule, scope_id, receiver, op)`.
- Requests that are waiting on the same key share one dialog. The others wait for its result.
  A login to another server, or a signature, in an approved tab is a new key: its own dialog.

**Timeout:** `defaults.timeout`, 60 s by default; when it runs out, the request is denied. The
default stays under typical server login grace times.

**Dialog content**
```
iTerm2 wants to use key "github"
  login to github.com
  git push origin main          in ~/projects/foo
  chain: iTerm2 → bash → git → ssh
  Scope: this terminal session, for github.com only (expires in 8h)
  Already approved for this terminal session: git commits and tags
```
- The **Scope** line says what the approval would cover: the scope, and within it only this
  destination or kind of signature (4.3, Milestone 7). For a tool's run the noun is the tool:
  `Scope: this claude run, for github.com only` (4.1 step 4). The **Already approved** line appears
  only when the same scope already holds approvals under this rule for other destinations or
  signatures, oldest first: the tab was approved before, and this prompt is for something new.
- For an `unknown` chain, the dialog has a prominent **Unknown app** header and shows the
  partial chain.

**`dialog` gate**
- The dialog has two buttons, **Deny** and **Allow** (on the right). Allow is greyed out until the
  dialog has been the focused window for **1 second** without a break. If focus leaves the
  dialog, Allow greys out again and the 1 second starts over. So a click or typing meant for
  another window, landing just as the dialog appears, can't allow.
- Only a click from a real mouse or trackpad on Allow counts, and only if the button went down
  after that 1 second. Both the press and the release must come from hardware: an event whose
  `kCGEventSourceUnixProcessID` isn't 0, or whose source isn't the hardware (HID) source, is
  ignored, and the dialog says how many clicks it ignored. To be confirmed by spike S4.
- An Accessibility press never counts as Allow: the button refuses `AXPress`, and a press that
  reached its action anyway has no hardware mouse-down, so it is ignored and counted like a
  posted click. Allow never takes keyboard focus and has no keyboard shortcut. No key presses a
  button: Esc denies, and every other key is ignored.
- Deny, Esc and the timeout all deny.
- The dialog turns on Secure Event Input while it's shown, which stops other processes reading
  keystrokes.
- **Residual risk (S4, at risk):** if a synthetic click can pass the hardware check, a process
  with the Accessibility permission alone could click Allow once it's enabled. The earlier
  random-key dialog also needed Screen Recording to read the key; the buttons don't.
- **Residual risk (UI redress):** a same-user process can draw its own window over the dialog
  (a transparent or look-alike overlay) so that the user's genuine hardware click lands on Allow
  while they think they click something else. The 1-second arming disarms Allow whenever the
  dialog loses focus, which defeats an overlay that takes focus, but not a non-activating one.

**`login` gate:** `LAContext.evaluatePolicy(.deviceOwnerAuthentication)` is called for the
rule's `gate` (`login`). The reason text includes the app, the key and the destination.

**`block` warning (no allow button)**
```
🧿 Blocked: python3 tried to read secret "GITHUB_PERSONAL_ACCESS_TOKEN"
  chain: Terminal → zsh → python3 sync.py      in ~/projects/foo
  This caller has no rule. If you didn't expect this, something may be wrong.
  To allow it, add a rule to ~/.nazar/config/config.yaml.
  [ Copy suggested rule ]  [ Open config ]  [ Dismiss ]
```
- **Nothing in the window allows the request.** The requester was already refused before the
  window appeared. It isn't kept waiting:
  - ssh gets `SSH_AGENT_FAILURE`;
  - a named-pipe reader sees an empty file;
  - `nazar run`/`get` exits with an error;
  - the k8s plugin returns an error.
- **The window doesn't block other work** (it isn't modal), and the attempt is written to the
  audit log.
- **Copy suggested rule** puts a ready-made rule on the clipboard, with the right `signed:` or
  `app:` matcher for this caller, a one-shot `path:` for an unsigned program with no app above it,
  and `apps: [unknown]`, one-shot, otherwise. The user still has to paste it into the config,
  and the config change still needs authentication (section 4.8).
- **Repeated attempts don't flood the screen:** the same caller hitting the same target again
  within 10 minutes updates one window with a counter ("blocked 14 times") rather than opening
  new ones. Every attempt is still logged.
- **A caller outside every rule gets the warning when it asks which keys it may use**
  (`REQUEST_IDENTITIES`, section 5, Milestone 7), one per key withheld, under the same
  deduplication: that is where ssh and `ssh-keygen` stop, so it is the attempt. A caller offered
  some key is not warned about the keys it isn't offered.

### 4.5 EnclaveStore (macOS platform layer, Swift)

**Key creation**
- Keys are created with CryptoKit:
  - `SecureEnclave.P256.Signing.PrivateKey` for ssh;
  - `SecureEnclave.P256.KeyAgreement.PrivateKey` for secrets, in Phase 2, created without user
    presence until spike S13 has run (secrets design 3.5; Milestone 8).
- **Chip-level protection depends on the key's gates** (amended after spike S1). If **every**
  policy that can apply to the key (all its rules, plus the key's own gate or `defaults.fallback`) is `block`, or `login` with `scope:
  use`, **and at least one of them is `login` with `scope: use`**, the key is created with Secure
  Enclave access control `.privateKeyUsage` plus `.userPresence`. Each signature then uses the
  LAContext of that request's own fresh approval. That way **even a compromised nazar process
  can't sign without the user's authentication.** An entry only `block` reaches is a key nobody
  may use yet: nothing decides its protection, so it gets none and the rules added later decide
  (with presence, the first `dialog` or `session` rule would need the key re-created). The
  entry is the one `nazar ssh-key create` writes or finds (4.2); `config.NeedsUserPresence`.
- **Why only `scope: use`:** spike S1 measured that the Secure Enclave honours one authenticated
  LAContext for at least 6 but less than 10 minutes, not for a terminal session or an app's
  lifetime. A `login` rule with `scope: session` or `app` remembers its approval for hours, so a
  user-presence key behind it would start failing minutes later. Such keys get no Secure
  Enclave–level user presence, and nazar's own remembered approval is the check, as for `dialog`
  and `none`. Nazar.app marks an authenticated LAContext as non-interactive, so a signature after
  the chip's window has passed fails with "authentication required" instead of showing a prompt
  out of context.
- **If any rule can use `dialog` or `none`,** the key gets no Secure Enclave–level user-presence
  requirement, and nazar's own gate is the only check. This is a documented trade-off, made by
  the key's rules when it is created (the create prompt's last line says `Touch ID on every use,
  enforced by the chip: this key can never get a session, dialog or no-prompt rule` or `Secure
  Enclave user presence: off (…)`; Milestone 7), so `config check` does not warn about it on
  every run (a warning about a deliberate choice read as a problem).
  A chip-protected key is made with `nazar ssh-key create <name> --always-ask` (4.2).
  `nazar ssh-key list` marks it (`asks every time (chip)`; `userPresence` with `--json`, read from
  the key's vault record, which keeps the access control the key was created with, never from
  config.yaml).
- **When the chip lets a key work at all** is fixed at creation too. Every key nazar makes (ssh,
  k8s CA, secret) is `AfterFirstUnlockThisDeviceOnly` by default: it works while the screen is
  locked, once the user has logged in since boot, so `gate: none` rules serve background jobs on a
  locked Mac. `--only-when-unlocked` (`ssh-key create`, `secret add`, `k8s ca create`; request
  argument `onlyWhenUnlocked: "true"`) makes it `WhenUnlockedThisDeviceOnly`, and so does user
  presence (a key that asks on every use can't be used while locked anyway). The vault record
  keeps it as `access` (`platform.Access`), omitted for when-unlocked, so every key made before
  the choice existed reads as when-unlocked and is listed `only when unlocked` (`whileLocked:
  false` with `--json`). No config key or rule touches it; recreating the key is the only change.
  While the Mac is locked the chip answers a when-unlocked key with `errSecInteractionNotAllowed`
  (-25308, for creating, signing and key agreement; measured on macOS 27): Nazar.app maps it to
  `platform.ErrLocked` (`NZ_LOCKED`), and the audit line and the caller's error say `the Mac is
  locked; <key> signs only while it's unlocked`. `nazar config check` and `nazar status` do warn about a key that *was* created
  with user presence but that a `dialog`/`none` gate, or a `login` gate with `scope:
  session`/`app`, can reach; nazar's own edits (`rule add`, `rule set`, `ssh-key set`) that
  would give such a key such a gate are refused outright: `SSH key "<name>" asks on every use
  (enforced by the chip); create another key for a looser rule` (Milestone 7), whether or not
  the edit loosens access when it is made (a rule behind a shadowing rule included).

**Handle storage**
- A key's `dataRepresentation` is an encrypted handle that only this Mac's Secure Enclave can
  use. It is stored in a **login Keychain item whose access list trusts only the agent** (its
  designated requirement, not its path: section 4), not as a plain file.
- Reason: if the handle can be used by any process on the same Mac (spike S5), a plain file
  would let malware use `dialog`-gated keys directly, skipping nazar.

**Public keys** are exported to `~/.nazar/keys/<name>.pub` (OpenSSH format) for
`IdentityFile` and `user.signingkey`.

### 4.6 AuditLog

Every request is logged: who asked, for what, who received it, and what happened. This covers
allowed, approved, denied, blocked and timed-out requests, for ssh keys, secrets, named-pipe
files and k8s credentials. It's meant for answering "what touched my GitHub key this week?"

**One place only: the macOS unified log.** nazar keeps no log files of its own.
- **Subsystem:** `dev.nazar`, category `audit`, one entry per request, at `default` level so
  macOS keeps it on disk. `info` and `debug` aren't persisted.
- **Viewing:** Console.app, `log show`, or `nazar log`.
- **Why this one place:**
  - macOS handles storage, rotation and cleanup, so there's nothing for nazar to clean up;
  - the log store is owned by root, so malware running as the user can't edit or erase
    entries (`log erase` needs root). That's stronger tamper resistance than a file in the
    user's home, without a hash chain.
- **Retention is decided by macOS, by size and by age.** It isn't configurable per subsystem
  without root or a configuration profile, so old entries age out on macOS's schedule, not
  nazar's. That is the trade-off for not managing a log folder.
- **Measured on a test Mac:** the oldest entry still in the store was about three weeks
  old. That's the oldest of *any* entry; how long `dev.nazar` entries
  survive depends on overall log volume. Phase 1 checks this again with real `dev.nazar`
  entries. If it turns out too short, a later option is an opt-in export
  (`nazar log export --since …`) that the user runs or schedules themselves.

**One entry** (message text, all fields marked public so macOS doesn't replace them with
`<private>`)
```
decision=allowed reason="cached approval" target=secret:BRAVE_API_KEY delivery=late-env
rule=1 scope=app gate=dialog app=com.googlecode.iterm2 session=4120@1791072112
chain="bash(4120) > claude(4188, Q6L2SF6YDW:com.anthropic.claude-code)"
receiver="npx -y @brave/brave-search-mcp-server" cwd=~/projects/foo
```
- **`decision`** is one of `allowed` (covered by a remembered approval), `approved`, `denied`,
  `timeout`, `blocked` or `error`. **`reason`** says why, for example "no rule matched", "to:
  mismatch" or "cluster mismatch". A denied `dialog` says how (Milestone 5): "user denied (Deny
  button)", "user denied (Esc)" or "the dialog closed without an answer"; its countdown running
  out is `decision=timeout`.
- **`rule`** is the matched rule's number (1-based), `key-gate` when no rule matched and the
  key's own `scope`/`gate`/`expire` applied (a key without rules, like `hydra`), or `fallback`
  when `defaults.fallback` applied (Milestone 5; before, both were `fallback`).
- **`session`** is the session the request was judged in: the tab's shell, or the run of the
  tool that satisfied a `scope: session` rule (4.1 step 4, Milestone 7). It is the id `nazar
  status` shows and `nazar revoke --session` takes.
- **Destination:**
  - ssh entries add `destination` ("github.com") or `operation` ("sign git commit"; `"list keys"`
    for a key withheld from a caller that was offered none, section 5);
  - k8s entries add the context and the kubectl command line.
- **Never logged:** secret values, signatures, or payloads.
- **Command lines are redacted with an allowlist, not by hunting for secrets** (decided in
  review).
  - **What `redacted` keeps:** each argument is kept only if it is a short **plain word**: up
    to 32 characters of letters, digits, `.`, `_`, `-` and `/`, not starting with `-` unless
    it is a single bare flag without a value (`-v`, `--force`; clusters like `-la` and attached
    values like `-p2222` are dropped), and with no `:`, `=`, `@`, `?`, `&`, whitespace or quotes.
    `:` is excluded so `user:pass` and `host:port` shapes never survive.
  - **What it drops:** everything else is replaced by `…`: values, URLs, `--flag=value`,
    `user:pass`, quoted strings, `sh -c` scripts, long tokens.
  - **Example:** `git push origin main` and `kubectl get pods -n prod` stay readable, while
    `curl -u alice:… https://…` keeps no secret. Pattern-based secret detection was rejected,
    because it always misses some shape.
  - **`none`** logs only the program name (`argv[0]`'s base name) and the argument count.
  - **Hard to forge:** every logged value is quoted and escaped, so a crafted program name such
    as `"ssh git@github.com"` can't be made to look like a different command.
  - `audit.args` is `redacted` (the default) or `none`. Full, unredacted command lines are
    never logged.
  - **Known limit of the allowlist:** a secret that is itself a short plain word is kept.
    Examples: a value passed as a separate argument after a bare flag (`--password hunter2`,
    `sshpass -p hunter2`), or a word-shaped token such as a 20-character AWS access key ID.
    Use `audit.args: none` if your command lines carry such values.

**Reading it**
```
nazar log [--follow] [--since 24h] [--target github] [--caller claude] [--decision blocked]
nazar log summary [--since 7d]      # per target: who used it, how often, blocks
```
- **How it works:** `nazar log` wraps `log show` / `log stream` with the `dev.nazar` predicate
  and parses the fields.
- **`--json`** prints one JSON object per entry, for `jq`.
- **Who can read it:** reading the system log needs an admin account. The user's account is
  one.

### 4.7 Languages, platform interface and repo layout

**Split**
- **Go core:** everything that isn't OS-specific. That means:
  - the ssh, secrets and k8s modules;
  - the control socket and the CLI;
  - the YAML config and PolicyEngine;
  - ApprovalCache and AuditLog;
  - the *logic* of CallerResolver and Approver (what to check, when to ask, what to show).
- **Platform layer, one implementation per OS:** everything that touches the OS or hardware:
  - **macOS:** Swift — CryptoKit, LocalAuthentication, AppKit, `Security.framework` code-signing
    checks, libproc and sysctl.
  - **Linux (later):** Go — go-tpm, polkit or a desktop prompt, `/proc`, `SO_PEERCRED`.
- **Why Swift owns the Mac app** rather than Go:
  - macOS requires dialogs on the main thread, which is natural in Swift and awkward in Go;
  - CryptoKit gives Secure Enclave key handles as plain bytes (S5);
  - a future menu bar app is easy in SwiftUI.
- **Precedent:** WireGuard's Apple app embeds its Go core the same way
  ([wireguard-apple](https://github.com/WireGuard/wireguard-apple), `Sources/WireGuardKitGo`).

**Platform interface.** It is defined once in Go (`core/platform`). Go code calls it as an
ordinary interface; on macOS it is backed by Swift functions reached through a small C shim.
```go
// Contract for every implementation (Swift on macOS, TPM on Linux):
// approval refs are never reused within a process, and an unknown or released ref
// means "no approval" (Sign returns an auth-required error) and never crashes.
type Platform interface {
    // Keys (Secure Enclave on macOS, TPM 2.0 on Linux). Handles are opaque bytes.
    CreateKey(purpose Purpose /* Sign | KeyAgreement */, auth AuthPolicy) (handle, publicKey []byte, err error)
    Sign(handle, digestInput []byte, approval ApprovalRef) ([]byte, error)
    KeyAgreement(handle, peerPublicKey []byte, approval ApprovalRef) ([]byte, error)
    DeleteKey(handle []byte) error

    // Approvals. Authenticate returns an opaque ref: an LAContext kept on the Swift side,
    // reused for later Sign/KeyAgreement calls (S1); on Linux, a TPM session or a plain
    // software token. Confirm is the hardware-input-only dialog (S4).
    Authenticate(policy AuthPolicy, prompt Prompt) (ApprovalRef, error)
    Confirm(prompt Prompt) (bool, error)
    ReleaseApproval(ApprovalRef)

    // Callers.
    PeerOf(socketFD int) (ProcessRef, error)          // audit token / SO_PEERCRED
    Process(ref ProcessRef) (ProcessInfo, error)      // ppid, start time, path, args, cwd, code identity
    AppFor(chain []ProcessInfo) (AppInfo, bool)       // first GUI app bundle in the chain
    CodeHash(path string) ([]byte, error)             // cdhash of a `nazar run` receiver

    // Events.
    OnProcessExit(ref ProcessRef, fn func())
    OnScreenLock(fn func())
}
```

**How calls cross the boundary on macOS**
- **Swift → Go:** the Swift app starts the core with `NazarCoreStart(config, callbacks)`.
  `callbacks` is a C struct of function pointers to `@_cdecl` Swift functions, one per
  platform method.
- **Go → Swift:** the Go side wraps those function pointers in a type that implements
  `Platform`.
- **Threading:** a call into Swift blocks only the calling goroutine. Swift dispatches UI work
  to the main thread and returns when the user answers.
- **Data across the boundary:** byte buffers plus a length, UTF-8 strings, and integer error
  codes. **The side that allocates memory frees it**, through exported `Free` functions on both
  sides. No Go pointers are kept by Swift after a call returns.
- **One Go runtime per process:** the app links exactly one Go archive.

**Repo layout (single repo)**
```
nazar/
  go.mod
  core/                 Go: modules (ssh, secrets, k8s), policy, cache, config, audit, control
    platform/           Go: the Platform interface, types, and a fake for tests
  cmd/nazar/          Go: the CLI (same on all platforms)
  bridge/               Go + C: cgo exports for -buildmode=c-archive, header, callback shim
  macos/                Swift: nazar-agent.app (LSUIElement) and Nazar UI.app, Swift
                        Platform implementation, SwiftPM package
  linux/                (later) Go: TPM platform implementation, cmd/nazard
  docs/
```

**Build on macOS**
1. `go build -buildmode=c-archive -o build/libnazar-core.a ./bridge` produces the library
   plus `libnazar-core.h`.
2. `swift build` (the SwiftPM package in `macos/`) builds the agent's executable (target
   `NazarAgent`) and links that library; `make agent` assembles and ad-hoc signs
   `build/nazar-agent.app` (SwiftPM instead of an Xcode project, so the whole
   build runs from the command line; renamed from `make app` / `Nazar.app` in Milestone 6). The
   agent's executable is `Contents/MacOS/nazar-agent`: never a name that differs from the bundled
   CLI's `Contents/MacOS/nazar` only by case, which a case-insensitive volume (the APFS default)
   would make one file.
3. `go build ./cmd/nazar` builds the CLI, which is copied into the agent bundle and signed with
   identifier `dev.nazar.cli`.

### 4.8 Config changes need approval

Rules decide who gets in, so the config file is the real lock. It's an ordinary file in the
user's home, though, and malware running as the user could add a rule for itself. So:
- **Edits are staged:** when `config.yaml` changes, nazar validates it and shows the **diff**,
  meaning the rules added, removed or loosened.
- **Then it asks for Touch ID / Watch / Mac password** (the `login` gate, never `dialog`). Only
  after that does the new config take effect. Until then the last approved config stays active.
- **No prompt for changes that only tighten** the config (removing rules, stricter `gate`,
  shorter `expire`). They apply at once.
- **`nazar trust --app <bundle-id>`** (pinning an installed app's team) needs the same authentication.
- **Where the approved config lives:** inside the Nazar.app process, plus a copy whose hash is
  stored in the Keychain item that only Nazar.app can read. On restart, nazar loads the last
  approved config and stages any differences from the file on disk.
- **Migration to today's form (2026-11-06, extended 2026-11-07).** `apps:` and `to:` take only
  lists (4.2), and `to: [any]`, a team spelled `Apple` and a `scope` or `expire` that does nothing
  are errors; builds before accepted them. An approved config must not turn invalid (every key
  would be blocked), so at start two rewrites run (`config.Migrate`): one matcher alone becomes a
  list of one; a `scope` or `expire` that did nothing is removed; `to: [any]` is removed where no
  `to:` means the same (a secret's rule; a key's rule that remembers nothing). Each rewrite is
  kept only when it parses to exactly the config the old reading gives (every entry, rule and
  matcher): (1) the approved
  config in the vault, rewritten in place without a prompt, since nothing loosens and its input
  is the vault's own item; `config/approved-paths` is moved to the rewrite's hash only when it
  named the old item, and is written first, so a start that stops in between is still approved;
  (2) `config.yaml`, written atomically with the old file kept as `config.yaml.bak`. The
  rewrite is deterministic, so a file that was the approved config becomes the rewritten approved
  config and stays in force; any other file (a staged edit, a file another process wrote) is
  judged against the approved config as before and waits for the gate. Nothing read from
  `config.yaml` is ever recorded as approved by the migration. A file that the old reading also
  refuses is left alone. Two old forms have no rewrite of the same meaning and are left as they
  are: a team spelled `Apple` (it matches nothing; `apple` would match Apple's programs) and
  `to: [any]` on a key's rule that remembers approvals (no `to:` would stop tying them to the
  receiver). The approved config that holds them is read the old way (`config.ParseApproved`,
  for the vault's item only) and stays in force; `config.yaml` holding them is invalid, so
  `config check` names the fix and nothing it says takes effect until the user fixes it. Writing
  `apple`, or removing such a `to: [any]`, loosens, so it asks for Touch ID (the classifier never
  counts a rule with `to: [any]` as covering one without `to:`). Never a rewrite that approves what the user did not, and
  never every key blocked. The old reading exists only for these two readers.

## 5. SSH module

**Socket**
- Path: `~/.nazar/run/agent.sock` by default; set with `ssh_agent.socket` in the config, a user-owned folder with permissions 0700. It is deliberately
  **not** under `~/Library/Containers/…`, because of Secretive issue #839, where macOS 27 blocks
  that location. Spike S6 confirms the path works.
- Users point to it per host with `IdentityAgent ~/.nazar/run/agent.sock`, or globally with
  `SSH_AUTH_SOCK`.

**Supported agent protocol** ([draft-miller-ssh-agent](https://datatracker.ietf.org/doc/draft-miller-ssh-agent/))
- **`REQUEST_IDENTITIES`:** returns the configured keys **this caller may use** (Milestone 7):
  every key of the active config whose policy for the caller's chain (the rules, else the key's
  own gate, else `defaults.fallback`) is not `block`. ssh and `ssh-keygen -Y sign` never ask to
  sign with a key the agent did not list, so a program outside a key's rules stops here
  (`Permission denied (publickey)`, `Couldn't find key in agent`) instead of at a refused
  `SIGN_REQUEST`, and `ssh-add -L` tells a program, an agent say, exactly what it has.
  - A caller that would be offered **nothing** is reported as if it had asked to use each
    withheld key: one `decision=blocked` audit line per key, `operation="list keys"`, and the
    block warning (4.4), so a program outside every rule is as visible as before (THREAT-MODEL
    4.9).
  - A caller offered at least one key is told nothing about the others: no entry, no warning,
    no audit line. It did not ask to use them, and the keys it was never meant to touch cost it
    nothing (an ssh without `IdentitiesOnly` no longer trips over them).
  - The listing is not the gate: a `SIGN_REQUEST` with a withheld key (its public key is
    readable in `~/.nazar/keys`) runs the whole pipeline and is blocked and reported as
    before.
  Which of the offered keys ssh tries first is still the client's `~/.ssh/config`
  (`IdentityFile` + `IdentitiesOnly`).
- **`SIGN_REQUEST`:** runs the pipeline: caller rules → ApprovalCache → Approver → Secure
  Enclave signature. The reply is an `ecdsa-sha2-nistp256` signature.
- **Extension `session-bind@openssh.com`** (OpenSSH 8.9 and later): records the server's host
  key for this connection. nazar looks that host key up in `~/.ssh/known_hosts` to name the
  destination in the dialog ("login to github.com"). A server listed under several names shows
  them all, up to four and then a count, within 100 characters:
  `[hydra.example]:2222 (also hydra.lan, [192.0.2.7]:2222, [198.51.100.4]:2222, +1 more)`. So
  a server reached through a new alias does not look like the older alias that comes first in
  the file. The name ssh was given (from the caller's command line, `[host]:port` before
  `host`) comes first when it is one of them; otherwise file order. The command line only
  reorders: every name shown is on a `known_hosts` line for the proved host key, and hashed
  entries name the key only through a name from the command line (or a well-known host) that
  they confirm. If it isn't found, it shows the host key fingerprint instead. That proved host
  key is also what a remembered approval for the login covers (4.3, Milestone 7): the same tab
  logging in to a server with another host key asks again. A connection with no bind is "login
  to an unidentified server", remembered apart from every proved server; a host key the
  userauth carries on its own (`publickey-hostbound` with no bind) names nothing, since nothing
  proved it.
- **Detecting git commit signing:** a payload that starts with the `SSHSIG` magic and has the
  namespace `git` is shown as "sign a git commit/tag". Other namespaces are shown verbatim.
- **Everything else** (`ADD_IDENTITY`, `REMOVE_*`, `LOCK`/`UNLOCK`, unknown extensions):
  `SSH_AGENT_FAILURE`.
- **Session-bind and forwarding** (built in Milestone 2, aligned with OpenSSH `ssh-agent`):
  - **Refused binds:** a session-bind that doesn't parse or verify, a duplicate session ID, or
    one past the bind limit is refused, and that connection then signs **nothing**.
  - **Forwarded connections** (`ssh -A`) never use a remembered approval. Under `gate: none`
    they get a **one-time `dialog`** instead of being silent, so a remote host can't sign
    quietly.
  - **Audit:** sign requests the agent refuses before the gate are still written to the audit
    log, with a fixed reason.

**Client setup (documented in the README)**
```
# ~/.ssh/config
Host github.com
  IdentityAgent ~/.nazar/run/agent.sock
  IdentityFile ~/.nazar/keys/github.pub
  IdentitiesOnly yes
```
```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.nazar/keys/github.pub
git config --global commit.gpgsign true
# git signs through the agent; SSH_AUTH_SOCK must point at nazar for signing,
# or gpg.ssh.program is set to a wrapper that sets it (spike S8)
```

## 6. CLI (Phase 1)

```
nazar ssh-key create <name> [--always-ask] [--only-when-unlocked]   # (Milestone 7): writes the entry (gate block, plus a login rule for the terminal
                                        # app it is typed in), shows it on the login gate, and gives the key the protection its
                                        # entry calls for (4.5); for a name config.yaml already has an entry for: its key, under that entry.
                                        # --always-ask: the rule is login + scope use (no terminal: no rule, blocked), so the chip
                                        # asks on every use; never rewrites an existing entry (4.2). --only-when-unlocked: the chip
                                        # refuses the key while the Mac is locked (4.5; implied by --always-ask)
nazar ssh-key list                      # name, type, public key fingerprint, rules summary; --json adds each key's
                                        # rules (policy), warnings, last use (lastUsed, since Nazar.app started), usable/unusableReason/remedy,
                                        # userPresence (created with Secure Enclave user presence; the human list says "asks every time (chip)"),
                                        # whileLocked (works while the Mac is locked; false: the human list says "only when unlocked")
nazar ssh-key pubkey <name>             # print OpenSSH public key
nazar ssh-key delete <name>             # asks for confirmation (login gate)
nazar ssh-key rules <name>              # the key's rules, numbered from 1, and what callers no rule matches get
nazar ssh-key rule add <key> --apps M[,M…] [--to M[,M…]] --gate login|dialog|none|block [--scope use|session|app] [--expire D] [--at N]
nazar ssh-key rule set <key> <n> [--apps M[,M…]] [--to M[,M…] | --no-to] [--scope S] [--gate G] [--expire D | --no-expire]
nazar ssh-key rule remove <key> <n>
nazar ssh-key set <key> [--scope S] [--gate login|dialog|block] [--expire D | --no-expire]   # the key's own gate
                                        # rule add/set/remove and set also take --allow-loosen-access (a change that
                                        # loosens access is written and approved on the login gate at once; without it
                                        # it is refused, exit 2, and what it would loosen is printed with the command to
                                        # run) and --if-hash H (configHash of `ssh-key rules`): the edit is refused if
                                        # config.yaml changed since
                                        # M is an apps: name, any, unknown, app:<bundle-id>, signed:<team>[:<id>] or path:<path>
                                        # (--apps/--to split at commas)
nazar apps list                     # top-level apps: matchers, pinned teams, what keeps one from
                                    # matching and its fix, the rules that use it
nazar status [--follow]             # current approvals: key, scope, what each covers, chain, expires; staged config; vault items
                                    # Nazar.app can't read, with their effect and fix; and the client side (Milestone 7): hosts of
                                    # ~/.ssh/config not wired to nazar, git's signing program and key, keys another agent holds,
                                    # each `setup:` line ending with its fix (read-only; the CLI checks, never nazar-agent)
nazar revoke [--all | --key <name> | --session <id> | --app <bundle-id>]
nazar config check | apply          # apply shows the change staged in config.yaml, then the login gate for exactly it
nazar trust --app <bundle-id>       # pin an installed app's team
nazar install [--bin-dir D | --no-links] | uninstall
                                    # LaunchAgent dev.nazar.agent + socket dir + links; install
                                    # also removes an old Nazar.app install (dev.nazar), never keys
nazar log [--follow] [filters] | summary          # reads the macOS log, see section 4.6
nazar ui                            # open Nazar UI.app if it is installed (section 6.1)
nazar completion bash|zsh|fish      # the shell completion script (the user sources it; nazar edits no shell file)
nazar help [<command>]              # also <command> --help / -h: usage, flags with their values, examples
```

- **Help and completion** come from a command tree built with `spf13/cobra` (and its
  `spf13/pflag`), and nothing else does: every command still runs through the CLI's own
  dispatch and its own `flag.FlagSet`, so arguments, messages and exit codes are unchanged
  (`TestCLIContract` pins them; `TestTreeMirrorsTheParsers` checks the tree declares exactly each
  parser's flags). `-h`/`--help` is help only where that parser would have stopped at it as a
  flag (not as a flag's value, not after `--`); never for `sign-git` (ssh-keygen's arguments) or
  `k8s credential` (kubectl's, from the kubeconfig), nor after `run`'s `--`. Completion
  (`nazar __complete`, cobra's protocol) offers names only from the read-only control commands
  `ssh-key.list`, `secret.list`, `k8s.list` and `apps.list` over the verified socket, each bounded
  by a short timeout; it runs no other program, reads no file, writes nothing (cobra's
  `BASH_COMP_DEBUG_FILE` is ignored), prints nothing on stderr and offers nothing on any error.
  The dependencies are cobra (Apache-2.0) and pflag (BSD-3-Clause); cobra's
  `inconshreveable/mousetrap` (Apache-2.0) is compiled only into Windows builds.

- **Rule edits** (Milestone 5) are made by Nazar.app on request of the CLI (control command
  `config.edit`): it edits `config.yaml` keeping comments and order and writes the whole file in one format (block style: one field per line, every list item on its own `- ` line; a flow-style `{…}`/`[…]` part a hand edit left is rewritten too), refuses an edit that would
  leave the file invalid, and observes the result at once like any edit of the file (section
  4.8): a tightening is in force (exit `0`). A loosening is written only when the edit carries
  `allowLoosen` (the CLI's `--allow-loosen-access`): nazar-agent classifies the edited file
  before writing it (`Stager.Preview`, which judges the written file exactly as `Observe` does,
  since the file is the approved config with nothing pending) and, without the flag, refuses it
  with what it would loosen (`control.LoosensRefusal`, exit `2`, the change and the
  `loosens …` lines of the prompt in the Problem's details, audited blocked with the caller),
  nothing written and **no prompt**, so an agent can show a rule to the person without touching
  the file; the CLI prints those lines and the caller's own command line with the flag appended
  (each word bare when every shell reads it as itself, else single-quoted; no command at all, just
  the flag to add, for a word with a `!` or a character that doesn't print; the `fix` field with
  `--json`). With the flag the loosening is staged and the CLI at once sends the `config.apply`
  bound to the edit's hash (the hash comes from the agent's reply and is never printed), so a
  person, a script, an agent or the window approves in one step, from any caller, terminal or
  not: the request, the hash binding, the gate, the throttle and the audit line are those of a
  `config apply`; exit `0` once the change is in force, `3` when denied (it stays staged;
  `nazar config apply` asks again), `4` only when the prompt could not be shown (then `nazar
  config apply` is the line printed, no hash), `5` when nazar-agent went away after the edit.
  With `--json` the ConfigEdit is printed, then the ConfigDiff or the Problem. The flag on an
  edit that does not loosen is harmless. The edit is audited with the caller's chain. Only a file
  that holds exactly the approved config is edited: while `config.yaml` has a change
  that is not approved yet (staged, or a hand edit not observed yet) the edit is refused (exit
  `1`, "run `nazar config apply` or revert them first") and writes nothing, so what is staged
  is always exactly the edit's own change, and an edit never observes, stages or swallows the
  background prompt for a hand edit.

- **Client-side checks** (Milestone 7). `nazar status` also says what is wrong
  *outside* nazar-agent, where most first-day failures are. After nazar-agent has answered, the
  CLI (never the agent, which must not run `ssh` or `git`) asks `/usr/bin/ssh -T -G -- <host>`
  how ssh would reach every host `~/.ssh/config` (and its `Include`s) names literally, plus
  github.com (only when `$HOME` is the account's home, the one ssh reads the config from;
  otherwise ssh is not run), and reports the hosts that are nazar's (routed to the agent
  socket, or naming a key file in `~/.nazar/keys`) but not wired right: nazar's key with
  another agent (`error`), no `IdentitiesOnly yes`, `ControlMaster` on (`warning`); reads
  `gpg.format`/`gpg.ssh.program`/`user.signingkey` (`--includes`: as git reads them) through
  Apple's git under the developer directory `xcode-select -p` names (never `/usr/bin/git`,
  whose shim shows a dialog when no tools are installed) and reports a key of nazar's without
  an absolute `nazar-sign-git` link as the program, or that link with a key that is not
  nazar's; and asks the agent `$SSH_AUTH_SOCK` names, when it is not nazar's own socket, which
  keys it holds (`REQUEST_IDENTITIES` on the wire, one bounded reply), naming them. Each
  finding is one `setup: <severity>: <where>: <what>; <fix>` line, printed with the `config:`
  lines, and the `setup` field of the `Status` object with `--json` (filled by the CLI, absent
  when all is well); Nazar UI.app shows them in a banner, read when the window is shown or
  comes forward and after each change it makes, never on its few-second timer (which reads
  only `config check`). Nothing is written; nazar's own socket is never asked for its keys (the
  CLI would be a caller offered nothing, reported and warned about); the checks stop at 3 s and
  skip the rest; a check that cannot run (no developer tools, a dead socket, ssh failing on the
  file, which is itself one `error` line) is silence, never a failure of `status`. Only literal
  `Host` names are asked about, so a key only a wildcard block or `ssh -i` uses is not reported.
  Lines still naming the layout before `~/.nazar/{config,keys,run}` (an `IdentityAgent`,
  `IdentityFile`, `user.signingkey` or `SSH_AUTH_SOCK`) are `error`s giving the exact replacement,
  and a `~/.config/nazar` still there is a `warning`.

- **Control socket:** `~/.nazar/run/control.sock`. **Only the `nazar` CLI talks to it.** Nothing
  else (the UI included) has a private API.

**The CLI is the one interface, for people, scripts, AI agents and the UI.**
- **Machine-readable output.** Every command accepts `--json`. Output is versioned the
  Kubernetes way: each object carries `apiVersion: nazar/v1` and a `kind` (`SSHKey`,
  `SSHKeyList`, `Secret` (metadata only, never the value), `Approval`, `AuditEvent`, `Problem`,
  …). Breaking changes bump the version, as for the config file.
- **Streaming commands** (`nazar status --follow --json`, `nazar log --follow --json`) print
  one JSON object per line, so live views and agents can follow along.
- **Stable exit codes:**
  - `0` ok;
  - `1` error;
  - `2` usage (also an edit that loosens access made without `--allow-loosen-access`: refused,
    with what it would loosen and the command to run);
  - `3` refused because the gate wasn't passed (denied, timed out or blocked);
  - `4` the config change is staged and waiting for approval: its prompt could not be shown
    (another prompt open, the cooldown), or a command was refused because config.yaml has a
    change waiting; `nazar config apply` asks;
  - `5` the agent (nazar-agent) isn't running.
- **Never prompts in the terminal.** With `--json` (or `--yes`) a command never asks a question
  on stdin. Human approval always happens through nazar's own gate on the screen, so agents
  can't answer it by typing.

**Who may do what. This is fixed and can't be made weaker in the config:**

| Kind of command | Examples | Needs |
|---|---|---|
| **Read** | `list`, `status`, `log`, `config check`, `ssh-key pubkey`, `ssh-key rules`, `apps list` | Nothing |
| **Tighten** | `revoke`, removing a rule (`ssh-key rule remove`), a stricter `gate`, a shorter `expire` | Nothing: applies at once |
| **Loosen** | adding a rule or app (`ssh-key rule add`), `gate: dialog`/`none`, `trust`, `secret add`/replace, `ssh-key create`/`delete`, `k8s ca create` (replaced `k8s import --write`), `config migrate` applied | The **`login` gate** on screen, showing the diff (section 4.8) |

So an AI agent can inspect everything, propose changes (without `--allow-loosen-access` the
command shows what it would loosen, exits `2` and changes nothing; the agent prints the command
with the flag for the person, whose Touch ID it asks for), and lock things down, but only the
person at the Mac can **open** access.

### 6.1 UI: Nazar UI.app (Milestone 5; a separate app since Milestone 6)

**Nazar UI.app** is an optional Mac app for people who prefer clicking, installed separately
(`brew install --cask nazar-ui`, section 12). Nazar works fully without it. Its rules:
- **A normal app, never in the background:** a Dock icon while it is open, Cmd+Q quits it,
  closing its last window quits it, and quitting it never affects the agent. It has **no menu
  bar item** and nothing of it runs when it is closed. The agent has no window of its own.
- **It runs the CLI and nothing else.** Every action runs the `nazar` CLI with `--json`, by
  absolute path, never via `$PATH`, and displays the result. It finds the CLI at the agent's
  known install locations (the package's `nazar-agent.app/Contents/MacOS/nazar`), and before
  running it checks that the binary is validly signed by **the same team as Nazar UI.app** with
  identifier `dev.nazar.cli`; a CLI that fails the check is never run, and the window says
  what it found instead.
- **It has no other access:** no reading of `config.yaml` or the sockets, and no Go-core calls.
- **A value goes only to the CLI's stdin** (Milestone 11): `nazar secret add NAME`, the one
  command that reads stdin, gets the value there, written only after the running CLI passed the
  check above; then the pipe is closed and the app's copy wiped. No command gets a value as an
  argument, a file or a variable, and the window never shows, copies or keeps one.
- **Live views** (Approvals, Activity) run the `--follow --json` streams while the window is
  open, and stop when it closes.
- **Same rules as anyone else:** a change made in the UI needs the same `login` gate: a rule
  edit from the window carries `--allow-loosen-access`, so the CLI writes it and shows the gate on
  the agent's screen at once, and the window reads the exit code: `0` in force, `3` denied (the
  change stays staged), `4` the prompt could not be shown. A change left staged, or a hand edit of
  `config.yaml`, is shown in a banner whose Approve… runs `nazar config apply` (no hash: the CLI
  reads what is staged and binds the approval to it). Its caller chain shows `Nazar UI → nazar`,
  so the audit log records it like any other change. Inside the CLI the hash binds the approval
  to the change the edit staged: when `config.yaml` changed after the edit, nothing is asked,
  nothing applies and the command fails (exit `1`, not `4`), so a process rewriting the file in
  between can't ride on the approval the user gives for their own change. Nor can it get a prompt
  of its own at that moment: from
  the moment an edit stages a loosening until the prompt for that change has been shown (at
  most 30 seconds; an apply that showed no prompt, for any reason, does not end it), no other
  content gets the background prompt (each is reported
  blocked once, never asked about on its own later), `config apply` of any other content is
  refused (exit `1`), and another edit is refused (exit `1`).
- **Untrusted text is shown as plain text only:** app names, command lines, chains and reasons
  from the audit log, and matcher values from `config.yaml`, are shown verbatim (no Markdown,
  no links) with control, format and separator characters replaced and long values cut.
- **`nazar ui`** opens Nazar UI.app through Launch Services by bundle id (`dev.nazar.ui`); when
  it is not installed it says so and how to install it (exit `1`). The control command
  `ui.show` and the agent's window are removed.
- **Development builds of the UI** (`make ui`, ad hoc) have no team to name: such a build pins the
  cdhash of the one CLI build made with it (`NazarDevCLICDHash` in its Info.plist, under its own
  seal) and runs only that CLI; a team-signed build ignores the pin. The UI checks the running
  CLI process, not only the file, so a file swapped in between is never run: it starts the
  CLI suspended, checks the running process's signature and resumes it only when that matches,
  otherwise kills it before its first instruction (Milestone 6). No run waits without end: a
  CLI that has not started 30 s after the resume is killed and started once more (checked
  again), and one that has not finished after 15 minutes (longer than any prompt) is killed; the
  window shows why.
- **Contract tests:** the window's models decode fixtures produced by the real CLI and core,
  and every command line the window can run is pinned in a list that the Go tests run against
  the real CLI, so a UI action that is not a CLI command fails a test.
- **What this buys:** everything the UI can do, a person or an agent can do in the terminal.
  Testing the CLI tests the UI's capabilities, and the UI can't drift into features that skip
  the rules.

| Tab | Shows | Actions (= CLI commands) |
|---|---|---|
| SSH keys | keys, fingerprints, rules (apps, receivers, scope, gate, expiry), last used, why a key is unusable | create (the name only: the agent writes the entry, blocked with no rule from the window, and decides the protection; Milestone 7), delete (an unusable key shows its reason and the `fix:` line `nazar status` prints), copy public key, add / edit / remove rules, the key's own gate (`ssh-key create/delete/pubkey`, `ssh-key rule add/set/remove`, `ssh-key set`) |
| Approvals | what's approved right now, for which tab or app, until when | revoke one / all (`revoke`) |
| Activity | audit log, including blocks, live; blocked lines that repeat with only the pids or session changed fold into one (`blocked ×4`, with the time span; `nazar log` keeps every line) | filter by text and decision (`log --since`, `log --follow`) |
| Apps | `apps:` matchers, pinned teams, what keeps one from matching and the command that fixes it, the rules using each | none: read-only (an app whose team changed is handled at the terminal with `trust --app`, usually by a coding agent that first finds out why) |
| Secrets (Phase 2, Milestone 11) | names, state (unreadable after a new signature, with the `fix:` line `nazar status` prints; no value stored; no rule yet), created, delivery methods, rules, warnings, its audit lines of the last 24 hours (`secret list`, `log --since 24h --target secret:NAME`; never values) | add (a name and a hidden value, written to the CLI's stdin; the window is not a terminal, so the agent writes the entry blocked with no rule, and the tab opens its rule editor next), delete, add / edit / remove rules in the SSH keys tab's rule sheet (`secret add/rm`, `secret rule add/set/remove`; a secret's own gate stays `block`; nothing reveals or copies a value) |
| Kubernetes (Phase 3, Milestone 13) | contexts and their state (CA present, missing or unreadable after a new signature, with the fix `nazar status` prints; a CA never imported), the cluster (server, TLS server name), the CA (fingerprint, expiry), the identity, the certificate lifetime, rules, warnings, its audit lines of the last 24 hours (`k8s list`, `log --since 24h --target k8s:NAME`; never a key, certificate or kubeconfig content) | add / edit / remove rules in the SSH keys tab's rule sheet without a receiver field (`k8s rule add/set/remove`; no `--to` or `--no-to` is ever sent; a context's own gate stays `block`), forget, after an alert that says the CLI then removes the kubeconfig entries nazar added and certificates already handed out stay valid until they end (`k8s forget`, Touch ID). No set-up: `k8s ca create` asks at a terminal and writes the kubeconfig, so with no contexts the tab shows the CLI steps of docs/CLI.md (a test keeps them identical); it never runs `k8s ca` or `k8s credential` |

Above the tabs the window shows a change waiting for the `login` gate, a staged config change
with "Approve…" (`nazar config apply`, which shows and binds the change staged), and the vault items Nazar.app runs without, with their fixes
(section 9). Milestone 5 builds the first four tabs; "draft a rule for this" from an Activity
line and adding an app by picking a running one come later.

## 7. Modules

Every module is a front end on the same core (section 4). The core traces the caller, applies
the rules, gets approval and does the Secure Enclave work. A module only translates its own
protocol into a core Request and back.

| Module | Phase | Secure Enclave operation | How programs reach it | Status in this spec |
|---|---|---|---|---|
| `ssh` | 1 | Sign | SSH agent socket | Full design (section 5) |
| `secrets` | 2 | Key agreement → decrypt | `nazar run` / `get`, named-pipe files, credential-helper commands | Design below |
| `k8s` | 3 | Sign (`ca-cert`); decrypt (`stored`, later) | kubectl exec credential plugin | Design below; `ca-cert` is built (Milestone 12) |

Env var piping, env var passing and file serving are **not** separate modules. They are
delivery methods of the `secrets` module: one store, one set of rules, different ways for a
secret to reach a program.

### 7.1 `secrets` module (Phase 2)

**Storage**
(The details are the
[secrets design](secrets-design.md), sections 3.1–3.5.)
- **Encryption:** each secret (GitHub PAT, API key or similar) is sealed with HPKE (RFC 9180,
  DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, base mode) to **its own** Secure
  Enclave key-agreement key, through Go's standard `crypto/hpke`; the enclave does only the
  ECDH (`Platform.KeyAgreement`). Neither CryptoKit's HPKE nor a hand-written one is used.
- **Where it lives:** in the Vault item `secret/<name>`, beside the key's handle; no file is
  written. A copy of the Keychain database off this Mac cannot open it; a copy restored on
  this Mac can, even after `nazar secret rm` (there is no enclave-side erase with CryptoKit).
  Values up to 32 KiB.
- **No Secure Enclave user presence yet:** secret keys are created without it until spike S13
  shows `KeyAgreement` honours a reused LAContext; nazar's gate is the check.
- **Later, several Macs:** not built. A value can be sealed to several Macs' public keys, like
  `age` or `sops`, as an additive change.
- **Pipeline (same as SSH):** caller rules → scope → approval → Secure Enclave key agreement →
  decrypt → deliver.

**Config**
```yaml
apps:                             # added to the top-level apps from section 4.2
  git-https:
    signed: { team: apple, id: com.apple.git-remote-http }   # git's HTTPS transport
  github-mcp:
    command: [npx, -y, "@modelcontextprotocol/server-github"]
secrets:
  GITHUB_PERSONAL_ACCESS_TOKEN:
    deliver: [late-env, helper]   # delivery methods this secret may use
    rules:
      - apps: [iterm, cursor]   # you: once per tab
        to: [git-https, github-mcp] # receivers: git (helper) and the GitHub MCP server (late-env)
        scope: session
        gate: login
        expire: 8h
    # Claude Code and everything else → blocked, with a warning popup
  DEPLOY_TOKEN:
    scope: session              # no `rules`: same for every caller
    gate: dialog
    deliver: [env]
```
- `rules`, `apps`, `to`, `scope`, `gate` and `expire` mean exactly what they mean for SSH keys
  (section 4.2), and use the same top-level `apps`.
- **`deliver`** lists the delivery methods this secret may use. A request through any other
  method is refused. This lets you forbid the weak `env` method for important secrets.
  - **Default** when `deliver` is missing: `[helper, stdout]`, and it never grows (secrets
    design 4): `file`, `late-env` and `env` must be listed, so a method a later version
    adds never reaches a secret whose approved entry did not name it. A method or field a
    version does not build yet is refused by `config check` ("not in this version"), never
    ignored.
  - **Approval of config changes** (4.8) treats a secret like an ssh key: its rules by the same
    first-match proof, and a method added to `deliver` loosens.

**Environment variables leak to other processes.** This was measured on macOS 27.0.1:
- **The test:** a Homebrew `bash` was started with `NAZAR_TEST_SECRET` in its environment.
- **The result:** another process of the same user read the secret with `ps eww <pid>`, and also
  through the `KERN_PROCARGS2` system call.
- **Apple's own programs** (`/bin/sleep`) were protected. Non-Apple programs (`bash`, `node`,
  `python`, MCP servers) are **not**.
- **What leaks:** the environment and arguments a process was **started** with. Variables set
  after startup don't show.
- **Consequence:** a secret passed as an env var at startup is readable by any of the user's
  processes for as long as the target runs. Secrets must **never** be passed as arguments.

**Delivery methods,** in order of preference. The method id is what goes in `deliver`.

1. **`helper`: credential-helper pipes.** The secret travels over a pipe to a tool that asks for
   it, and never appears in an env var or an argument:
   - git credential helper (`git` over HTTPS, and `gh` via git);
   - Docker credential helper;
   - AWS `credential_process`;
   - tools that accept `--token-file /dev/fd/N` or a token on stdin.
   The caller is nazar's parent process: the tool that asked.
2. **`file`: named-pipe files (FIFOs).**
   - **Setup:** nazar creates `~/.nazar/run/files/<name>` as a FIFO, mode 0600. Tools are pointed
     at that path like an ordinary file (token files, `.netrc`, cloud credential files).
   - **When a program opens it:** the program blocks, as if the disk were slow. nazar
     identifies the reader by finding the process that has the FIFO open (spike S9), then runs
     the pipeline.
   - **On allow:** nazar writes the plaintext and closes the pipe.
   - **On deny or timeout:** nazar closes the pipe without writing, so the reader sees an empty
     file.
   - **Afterwards:** the FIFO is recreated for the next reader. Concurrent readers are served one
     at a time.
   - **Benefits:** nothing is stored in plain text on disk and nothing appears in `ps`.
   - **Limits:** programs that `stat` the size first, seek, or `mmap` the file break. S9 lists
     which common tools work.
3. **`late-env`: setting the variable after startup.** The secret is set inside the program
   *after* it starts, so `ps eww` (which shows only the startup environment) never sees it.
   - **Where the secret comes from:** Nazar.app, never a file or a startup variable.
     1. `nazar run --late-env NAME -- <cmd>` asks Nazar.app for the secret. Rules apply to whoever
        ran `nazar run` (`apps:`) and to `<cmd>` (`to:`).
     2. After approval, Nazar.app decrypts the secret with the Secure Enclave and sends it to
        `nazar run` over the control socket.
     3. `nazar run` writes the secret into a pipe, then `exec`s `<cmd>` with the pipe's read end as
        file descriptor 3. Only harmless values go into the startup environment: the loader
        setting, `NAZAR_SECRET_FD=3`, the variable name and the `--target` pattern.
        Because of `exec`, `nazar run` is replaced by `<cmd>`, so no nazar process keeps the
        plaintext.
     4. Inside the target, the **loader** reads fd 3, sets the variable in the process's own
        environment (`process.env` / `os.environ`), closes fd 3, and removes the `NAZAR_*` and
        loader entries from the environment.
   - **Where the loader lives:**
     - **In the repo:** `loaders/node/env.js` and `loaders/python/sitecustomize.py`.
     - **When installed:** `nazar-agent.app/Contents/Resources/loaders/`, copied by `make agent`
       before the bundle is signed, and pinned by nazar-agent itself on every run (as built:
       `env.cjs`, secrets design 6.3.1).
     - **How `nazar run` injects it:**
       - Node: `NODE_OPTIONS=--require <loaders>/node/env.js`.
       - Python: puts `<loaders>/python` first on `PYTHONPATH`. That `sitecustomize.py` runs the
         loader, then hands over to any `sitecustomize` that was already installed.
   - **Launchers (`npx`, `uvx`, `pipx`):** these are Node or Python programs themselves, and the
     real target is their **child**. If the launcher read the secret, it would pass it to the
     child as an ordinary startup variable, visible in `ps` again. So:
     - **`--target <pattern>`** names the real target, for example `--target
       brave-search-mcp-server`.
     - **Processes that don't match skip the loader:** a Node or Python process whose command
       line doesn't match the pattern leaves fd 3 open and inherited, and doesn't set anything.
     - **Only the matching descendant reads the secret.**
     - **If no matching process reads it,** the pipe is closed when the process tree exits.
     - **To be verified:** whether fd 3 really survives `npx` and npm's child-process handling,
       and the same for `uvx` and `pipx`. That's spike S12. If it doesn't, servers started
       through a launcher use `env`.
   - **Without `--target`,** the first Node or Python process reads the secret. That's correct
     for `node server.js` or `python3 app.py`.
   - **Documented limit:** processes that the target *itself* starts later inherit the variable
     as a normal startup variable. The loader can't prevent that.
   - **Automatic choice: `nazar run --secret NAME -- <cmd>`.** nazar uses `late-env` when a
     loader can reach the target: it's `node`, `python3` or a Node launcher such as `npx`.
     Otherwise it uses `env` if the secret's `deliver` allows it, and fails with a clear message
     if not. `--late-env` and `--env` force one method.
4. **`env`: `nazar run --env NAME -- <cmd>` (last resort).** It works with anything, but the
   secret is readable through `ps eww` while `<cmd>` runs. It must be listed in `deliver`
   explicitly, and the CLI prints a one-line warning the first time it's used for each secret.
   It's still far better than a shell `export`, which puts the secret into every process.
5. **`stdout`: `nazar get <name>`** prints the secret for scripts, subject to caller rules.
   The caller is the script that ran `nazar get`.

Other ways of hooking file reads were considered and rejected:
- **macFUSE:** it reports the reading process, but needs a kernel extension, which on Apple
  silicon means lowering the Mac's security settings. Unacceptable for a security tool.
- **FUSE-T and Apple FSKit:** no kernel extension, but believed not to report which process is
  reading, which the rules need. Not verified; revisit if FSKit gains that.
- **Endpoint Security file-open authorization:** needs an Apple-granted permission and root, has a
  short fixed response deadline that doesn't fit a dialog, and needs the plaintext on disk.

**Moving tokens out of shell config files.** This is the motivating case: a shell
profile such as `~/.bash_profile` that exports a token like `GITHUB_PERSONAL_ACCESS_TOKEN` in
plain text, so every process in every tab inherits it.
- **`nazar secret add <NAME>`** reads the value from stdin (never from an argument), encrypts
  it, and the user deletes the `export` line.
- **`nazar secret migrate <file>`** finds `export NAME=<literal>` lines in a shell file, imports
  each value, and prints the replacement for each line. It does **not** edit the file itself.
- **Replacements, depending on how the consumer reads the secret:**
  ```bash
  # CLI that only reads an env var: shell function wrapper (env; or late-env if a loader exists)
  deploytool() { nazar run --env DEPLOY_TOKEN -- command deploytool "$@"; }
  ```
  ```jsonc
  // MCP server started by Claude Code: wrap its command (late-env for Node servers)
  "command": "nazar",
  "args": ["run", "--late-env", "GITHUB_PERSONAL_ACCESS_TOKEN", "--", "node", "-r", "nazar/env", "server.js"]
  ```
- **Rotate afterwards:** a token that sat in a shell file in plain text may also exist in
  backups and shell history, so `migrate` reminds you to rotate each imported token.

**Moving tokens out of Claude Code's config.** Claude Code keeps its own login in the macOS
Keychain, not in a file. MCP server keys, though, are often stored in plain text in
`~/.claude.json` under `mcpServers.<name>.env`, or in a project's `.mcp.json`. That file is
readable by every process the user runs.
- **`nazar secret migrate-mcp [file]`** finds `env` values in `mcpServers` entries, imports each
  one as a secret, and prints the replacement entry. Like `migrate`, it doesn't edit the file
  itself; Claude Code rewrites `~/.claude.json` often, so the user applies the change through
  `claude mcp` or by hand.
- **Example** (a Brave Search entry, key removed):
  ```jsonc
  // before — key in plain text in ~/.claude.json
  "brave-search": { "type": "stdio", "command": "npx",
                    "args": ["-y", "@brave/brave-search-mcp-server"],
                    "env": { "BRAVE_API_KEY": "BSA…" } }
  // after — no secret in the file
  "brave-search": { "type": "stdio", "command": "nazar",
                    "args": ["run", "--late-env", "BRAVE_API_KEY",
                             "--target", "brave-search-mcp-server", "--",
                             "npx", "-y", "@brave/brave-search-mcp-server"] }
  ```
  ```yaml
  apps:
    brave-mcp:
      command: [npx, -y, "@brave/brave-search-mcp-server"]
  secrets:
    BRAVE_API_KEY:
      deliver: [late-env]
      rules:
        - apps: [claude]          # who asks: Claude Code starts its MCP servers
          to: [brave-mcp]         # who receives: only this exact command
          scope: app              # once per Claude Code run
          gate: dialog
      # anything else, including Claude Code giving the key to another program → blocked
  ```
- **What this doesn't cover:** files that Claude Code itself must read and write as ordinary
  JSON can't be turned into named pipes, so nazar can't gate `~/.claude.json` itself. The fix is
  to keep secrets *out* of it.

**Documented limit:** once a secret is delivered, the receiver can copy it. The rules control
*who receives* it, not what the receiver does with it afterwards.

### 7.2 `k8s` module (Phase 3)

**How kubectl reaches it.** Each kubeconfig user entry that nazar protects is replaced by a
[client-go exec credential plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
entry:
```yaml
users:
- name: hydra-admin
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: nazar
      args: [k8s, credential, hydra]
      provideClusterInfo: true     # server + CA arrive in KUBERNETES_EXEC_INFO
      interactiveMode: Never       # nazar shows its own dialog
```
Every tool built on client-go (kubectl, k9s, helm and others) runs this command whenever it
needs credentials for the context. Reading the kubeconfig itself (`kubectl config
get-contexts`) contains no secrets and is not gated.

**Checks, in order:**
1. **Can the direct caller be identified?** The parent of `nazar k8s credential` (kubectl,
   helm, k9s or any other program) must be a live process with a verified code signature: it is
   the receiver of the credential and of the approval. There is no list of client programs and
   nothing is pinned (since 2026-10-31, k8s design 2.1 "no client list": the caller chain is the
   boundary, as for SSH). A parent that exited or can't be identified is **blocked**.
2. **The cluster must be the right one.** The server URL and CA in `KUBERNETES_EXEC_INFO` must
   match what was recorded at import. Otherwise the request is refused and logged, so a
   kubeconfig pointing a real kubectl at a fake server gets nothing.
3. **Scope and caller rules apply to whoever called that program.** For example
   `iTerm2 → bash → claude → kubectl delete pod …` is judged as Claude Code in that tab and gets
   Claude Code's rule.
4. **Approval.** The dialog shows the context, the client's full command line (for example
   "`kubectl delete pod web-1 --context hydra`") and the process chain.

**Config**
```yaml
k8s:                              # Kubernetes
  contexts:
    hydra:
      credential: ca-cert         # ca-cert (Milestone 12) | stored (later) | jwt (not planned)
      cluster:                    # recorded by `nazar k8s import`
        server: https://hydra.example:16443
        ca_sha256: "<sha256 of the cluster CA certificate>"
      rules:                      # judged on whoever ran kubectl, helm, k9s …
        - apps: [claude]
          scope: use            # Claude Code: ask on every kubectl call
          gate: dialog
        - apps: [any]
          scope: session
          gate: login
          expire: 8h
```

**Credential types.** `credential` picks a provider behind one interface,
`CredentialProvider.issue(context, approval) → ExecCredential status`, so new types can be
added without touching the checks above.

| Type | What the plugin returns | Cluster change | Status |
|---|---|---|---|
| **`stored`** (A) | The context's existing client cert + key, or token, decrypted from the `secrets` store (entry `k8s/<context>`) | None; works with any cluster | The fallback; not in Milestone 12, `config check` rejects it as not in this version |
| **`ca-cert`** (B) | A fresh client cert valid `ttl_cert` (default 15 min) for a throwaway key, issued by a certificate-authority key in the Secure Enclave | The cluster must trust that CA (possible on self-run clusters such as microk8s; not on managed EKS/GKE/AKS) | **The first and default provider; built in Milestone 12** (k8s design 6.1) |
| `jwt` (C) | A token valid ~5 min, signed by a Secure Enclave key | The API server must trust the issuer (structured authentication config on self-run clusters; OIDC provider association on EKS), and the issuer's public keys (JWKS) must be served over HTTPS | Not planned; `config check` rejects it |

**The `ExecCredential` reply** (`client.authentication.k8s.io/v1`) carries `token`, or
`clientCertificateData` + `clientKeyData`, plus an `expirationTimestamp` of **now + 5 minutes,
or the end of the approval if sooner**. Long-running tools like k9s cache credentials until that
timestamp, so the short expiry makes them come back and pass the checks again regularly. With
`stored`, the credential itself stays valid on the server; only the client's cached copy
expires. That is the documented weakness of option A, and what B and C fix.

**Importing a context**
- **`nazar k8s import <context>`** reads the kubeconfig (`$KUBECONFIG` or `~/.kube/config`).
  It extracts the context user's credential: inline `client-certificate-data` /
  `client-key-data`, `token`, or the files they point to. It stores the credential encrypted
  as `k8s/<context>`, records the server and CA hash, and **prints a diff** that replaces the
  user entry with the exec entry above.
- **`--write`** applies the diff. nazar never writes a backup that contains the plaintext
  credential.
- **After import:** nazar warns to **rotate the credential**. It existed in plain text and may
  be in backups. On microk8s, for example, that means regenerating that user's certificate or
  token.
- **`nazar k8s audit`** lists contexts that still carry credentials directly in the
  kubeconfig. Those contexts skip nazar entirely, which is the main gap for anyone adopting
  this gradually.

### 7.3 Fit with the core

None of the modules need changes to the core. Each adds a front end, uses the `sign` or `unlock`
operation, and supplies its own payload summary for the dialog:
- `ssh`: "login to github.com", "sign a git commit";
- `secrets`: "GITHUB_PERSONAL_ACCESS_TOKEN via late-env";
- `k8s`: "kubectl delete pod web-1 on hydra".

## 8. Threat model

**What nazar protects against**
- **Key theft by any process, backup or disk image.** The key never exists outside the Secure
  Enclave.
- **Silent use outside an approved scope.** Other tabs, other apps and background malware get a
  dialog or a refusal.
- **Callers pretending to be an allowed app by name.** Allow rules check code signatures.
- **Ordinary processes faking an approval.** The `login` gate (Touch ID / Watch / password) can't be faked. `dialog`
  accepts only a hardware click on Allow, made after the dialog has had focus for 1 second;
  posted clicks and keys are ignored, and an Accessibility press never counts as Allow. Whether a
  posted click can pass for hardware on macOS 27 is still unverified (S4). If it can, a process
  with the Accessibility permission alone could approve a `dialog`; macOS asks the user before
  granting that.
- **A compromised nazar process signing on its own,** for keys whose gates are all `login`. The Secure Enclave
  still requires the LAContext.

- **Malware granting itself access by editing the config.** A loosening change to
  `config.yaml` takes effect only after Touch ID / Watch / password, and the change dialog shows
  the new rule (section 4.8).
- **Unexpected callers going unnoticed.** Callers with no rule are blocked, and the block
  warning shows exactly who tried and what they wanted.

**What it doesn't protect against**
- **Programs that open a terminal or IDE window running their own script.** For example,
  `open -a Terminal evil.command` needs no permission, and the new window really is Terminal.
  A rule on a terminal or IDE app (iTerm2, Terminal, Ghostty, Warp, VS Code, Cursor…) with
  `gate: none` or `scope: app` therefore effectively covers *any* program on the Mac.
  - **nazar allows this on purpose:** it's the user's choice (decided in review), with no
    restriction and no warning.
  - **The safer pattern for terminals is `scope: session`:** a new window is a new session, so
    the trick gets a prompt.
- **Anything running inside an approved scope.** By design, Claude Code and the scripts it
  runs sign silently inside an approved run of it (an approved tab, for a rule the terminal
  satisfied). Per-caller rules, and keeping `scope: session` rather than `app`, are how you
  narrow that.
- **Malware that drives an approved app**, for example AppleScript sending "write text" to
  iTerm. macOS asks the user before allowing Automation control of iTerm.
- **Root or kernel compromise.**
- **What servers do with access.** A GitHub account key reaches every repo the account can.
  Limiting access is done on the server side, for example with deploy keys.
- **`dialog` gate doesn't identify the person,** only that someone is physically present.
- **A window drawn over the `dialog` gate (UI redress).** Any process of the user can place a
  window of its own over the dialog, without a permission prompt, so that the user's own
  hardware click lands on Allow while they think they are clicking something else. The 1-second
  focus arming defeats an overlay that takes focus, not a non-activating one (section 4.4).
- **Delivered secrets (Phase 2).** Once delivered, the receiver can copy a secret. If it was
  delivered with the `env` method, any process of the user can read it through `ps eww` while
  the receiver runs (section 7).

## 9. Error handling

| Situation | Behaviour |
|---|---|
| Dialog not answered | Deny when `timeout` runs out; ssh gets `SSH_AGENT_FAILURE` |
| Caller blocked (`gate: block` or no matching rule under the default fallback) | Refused immediately; block warning shown (deduplicated); logged |
| `config.yaml` changed | Validated; loosening changes wait for authentication, and the previous approved config stays active meanwhile; tightening changes apply at once |
| Nazar.app not running | ssh reports that it can't connect to the agent; `nazar status` explains and suggests `nazar install` |
| ssh or git not wired to nazar (a `Host` block with nazar's key file but no `IdentityAgent`, `IdentitiesOnly no`, `ControlMaster auto`, `gpg.ssh.program` unset, a bare name or a dangling link, keys still loaded in Apple's `ssh-agent`; Milestone 7) | ssh fails with `Permission denied (publickey)`, git with `Couldn't find key in agent`, or the key is used past nazar; `nazar status` lists each as a `setup:` line ending with the exact fix (a `git config --global` line, words to add to the `Host` block, `ssh-add -D`, `nazar install`), checked by the CLI read-only (section 6); nothing is edited for the user |
| Config invalid on reload | Keep the last valid config, log the error, `config check` shows details |
| Key handle missing or unusable (wiped, other Mac) | Key listed as `broken`; sign requests fail with a log line |
| A vault item this build of Nazar.app can't read (an item of another ad-hoc build, a locked keychain; Milestone 5) | Nazar.app still starts; each item degrades on its own and fails closed: an unreadable approved config is "none approved yet" (built-in default, `config.yaml` staged behind the login gate), an unreadable trust store matches no `app:` matcher and refuses changes, an unreadable prompt record suppresses prompts until it is fixed, an unreadable key is listed as `broken` (`usable: false`); `nazar status` lists each with its effect and the command that fixes it (`security delete-generic-password -s dev.nazar -a <item>`, `nazar config apply`, the fixes `nazar apps list` names for the matchers, or, for a key, first "unlock the login keychain, or reinstall the nazar-agent you had, and look again", because a locked keychain or a wrongly signed agent reads as the same unreadable item and deleting it destroys a good key for good, then `security delete-generic-password -s dev.nazar -a ssh-key/<name>`, then `nazar ssh-key create <name>`, which re-creates the key under its existing config entry, then the new public key added where the old one was), in the order that works when followed top to bottom: `config/prompts` (every login prompt writes it first), then `state/trust` deleted (approving a config pins its `app:` matchers there, which fails while the item is unreadable), then `config/approved` deleted + `nazar config apply` + the matchers trusted again, then the keys (re-creating needs the entry in force). The agent can't delete an item it can't read (securityd refuses its delete as it refuses its read; Milestone 7), so a key's item is always removed by hand: `nazar ssh-key delete` of an unreadable key is refused before any prompt with that fix, nothing changed; a delete of a name with no key whose entry `config.yaml` keeps says so and names `nazar ssh-key create <name>`; and no remedy chains steps with `&&`, since a step that finds nothing left to do would stop the rest. An `ssh-key/` item whose name is not a valid key name was not made by nazar (any same-user process can add one): it is listed as not a key, named only Go-quoted, and its name never goes into a `nazar` command. Its remedy is the command `security delete-generic-password -s dev.nazar -a ssh-key/<name>` only when the whole account is a plain word (`^[A-Za-z0-9._/-]+$`, the key-name alphabet plus `/`), which every macOS shell reads as itself; any other account gets no command at all, only "remove it by hand in Keychain Access: service dev.nazar, account shown as <Go-quoted account>", because no quoting is safe in every shell the user may paste into (tcsh and csh expand `!` even inside single quotes, and no shell can pass a NUL) |
| Caller chain can't be resolved at all | Treated as `unknown`: it matches only `any` and `unknown` rules, through their gate (a dialog with a warning, one-time approval; under `gate: none`, which the user chose with a `config check` warning, no prompt) |
| Screen locked while a dialog is open | Dialog stays; it times out normally |
| Screen locked, a key made `--only-when-unlocked` (or before the choice existed) asked for | The chip refuses the key, not the user: an error, not a refusal. ssh gets `SSH_AGENT_FAILURE`, `nazar get` and kubectl's plugin exit 1 (not 3), and the audit line is `decision=error` with `the Mac is locked; <key> signs only while it's unlocked` (4.5). It works again once the Mac is unlocked; a caller should wait, not retry in a loop. Creating such a key while locked fails the same way after the prompt, leaving nothing behind. A key made without the flag works for rules that need no prompt |
| k8s: server/CA in `KUBERNETES_EXEC_INFO` don't match the recorded cluster | Refused without a dialog, logged as a possible fake-server attempt |
| k8s: `credential` set to a type this version does not build (`stored`, `jwt`; Milestone 12 builds `ca-cert`) | `config check` fails naming it; the whole file is invalid, so the last approved config stays in force |
| k8s: a context's CA Vault item (`k8s-ca/<context>`) can't be read | Listed by `nazar k8s list` with the remedy of the items above (`security delete-generic-password -s dev.nazar -a k8s-ca/<context>` only for a plain-word account, then `nazar k8s ca create <context>`, whose new CA the cluster must trust again); never deleted by the agent; its credential requests fail closed |

## 10. Testing

- **The Go core is tested against the fake platform** (`core/platform/fake`). The fake scripts
  process chains, approvals, denials, timeouts, process exits and screen locks, so all rule and
  scope logic is tested with `go test` and no Mac hardware or dialogs.
- **Platform conformance tests:** one suite in Go runs against every real `Platform`
  implementation (macOS, and Linux as a preview), so both behave the same at the interface. Tests that
  need a person to answer a dialog are tagged and run manually. Its `keys/k8s-ca` subtest
  (Milestone 12) makes a Kubernetes CA on the platform's own keys (`CAStore.Create`, one client
  certificate from `Issue`, both verified with the CA's public key alone, then
  `CAStore.Delete`); on the Mac that is the real Secure Enclave, with an `AuthNone` key and
  nothing on screen.
- **Unit tests:**
  - PolicyEngine (first match wins, fallback for unmatched callers, unknown chains);
  - ApprovalCache (expiry, revoke, session exit);
  - YAML parsing and validation;
  - SSH wire encoding and decoding.
- **Signature checks:** test vectors verified with `ssh-keygen -Y verify` and by an `sshd` in a
  test container.
- **Integration tests:**
  - spawn real process chains (shell → git → ssh) against the agent and assert the resolved
    chain, app and session;
  - `ssh -T` against a local `sshd` with nazar keys;
  - `git commit -S` followed by `git verify-commit` using an allowed-signers file;
  - `nazar run` end to end on the Mac (`make integration-run`, Phase 2 Milestone 10): the
    CLI and loaders of the built nazar-agent.app, real `npx` installing a test package from a
    registry the test serves on 127.0.0.1, against the core in the conformance host on the Swift
    platform's real process seams (exec watch, `KERN_PROCARGS2`, socket peers, code identity);
    keys, gates and the vault are the fake's;
  - the Kubernetes exec plugin on the same seams (`make integration-run`, Phase 3 Milestone
    12): the real `kubectl` runs the test build of the CLI, and the genuine-CLI check, the
    trusted-client check and the stdout check judge the chain the kernel reports;
  - every `nazar k8s` command of the test build against `nazar-testd` in a temp home, in
    docs/CLI.md's order, and the real `kubectl` on the kubeconfig `import --write` wrote
    (`make integration`, Milestone 12); the phrases the docs quote are checked against what the
    commands print.
- **Manual test script** (dialogs and auth can't be fully automated):
  - per-tab approval and a new tab prompting again;
  - closing a tab removes its approval;
  - Claude Code, and a Python script Claude Code wrote and ran, get the `dialog` gate from
    Claude Code's rule, while an unmatched caller gets the fallback prompt every time;
  - a synthetic click (via `osascript` with Accessibility permission granted) is ignored by the
    `dialog` gate;
  - an unknown caller is blocked, the block window has no allow button, and repeats update one
    window's counter;
  - editing `config.yaml` to add a rule does nothing until Touch ID / Watch / password is
    given, while removing a rule applies at once.

### 10.1 Attended checks

Nothing automated needs a person: no test raises a prompt, a dialog, a Keychain or TCC window,
or signs with a real identity. What only a person at the Mac can confirm is this list; until an
item passes, nothing claims what it would prove.

- **Install and LaunchAgent.** Install the agent bundle and run `nazar install`: the LaunchAgent
  runs, both sockets exist (0600 in a 0700 folder), `nazar status` verifies the agent; an
  `uninstall` / `install` round trip and a reinstall over a running agent both work.
- **The login gate from a LaunchAgent app (S2).** Touch ID, Apple Watch and the Mac password,
  lid open and closed; Cancel refuses; the cooldown after a denial.
- **One approval per use (S1).** A user-presence key signs one ssh login with exactly one
  prompt; a stale context never prompts.
- **The dialog gate with real input (4.4).** Allow arms after 1 second and again after the panel
  loses focus; Deny, Esc and the timeout deny; Return, Space and letters do nothing; typing
  through never allows; Secure Event Input is on while the panel is up.
- **Synthetic clicks and Accessibility presses (S4).** A click injected by a process with only
  the Accessibility permission, and an `AXPress` on Allow, are ignored and counted.
- **Keychain items closed to other processes (S5).** Another process reading, rewriting or
  planting an item under `dev.nazar` gets a dialog or a silent refusal, never the value; the
  agent's own process never shows a Keychain dialog; a locked login keychain fails without an
  unlock dialog; and the partition securityd records for the agent's items.
  *Run on 0.1.1 (Developer ID), 7 Nov 2026, with a throwaway key:* reading → Keychain dialog
  (pass; Allow gives the handle away); rewriting (`add-generic-password -U`) → silent, the item
  is replaced and the key destroyed, not read (fails the wording above: a denial of service, not
  a leak); planting → not trusted, `nazar status` flags it; locked keychain → fails, no unlock
  dialog (pass); no Keychain dialog from the agent in daily use. The partition was not checked.
- **Rebuilds and the signing identity.** An ad-hoc rebuild can't read the previous build's items
  and `nazar status` names each with its fix; with a stable signing identity a rebuild keeps
  them.
- **The block window, unknown chains and real callers (S3).** The block window has no allow
  button, copies the suggested rule and keeps one counter; a ControlPersist master shows the
  responsible app for display only; iTerm2, Terminal, Cursor and VS Code terminals resolve to
  their app with one session per tab, and closing a tab ends its approval.
- **Nazar UI.app.** It opens, shows the real state in every tab, a rule added from it raises the
  login gate, Revoke ends an approval, it refuses a CLI that is not nazar's, macOS offers no
  password AutoFill on the Secrets tab's hidden field, and the agent shows nothing in the menu
  bar or the Dock.
- **Audit retention (4.6).** How far back `dev.nazar` entries survive in the unified log; entries
  another program writes under `dev.nazar` stay out of `nazar log`.
- **The CLI's peer check on a real install (observe only).** An impostor listening on
  `control.sock` is refused before the CLI sends anything; every claim stays "the listen-owner is
  nazar-agent", never "the peer is nazar-agent".
- **The loaders' bundle (secrets design 6.3).** With a team-signed, notarized nazar-agent.app
  installed, macOS's App Management stops a process without that permission from changing a file
  under `nazar-agent.app/Contents/Resources/` (THREAT-MODEL 5.9).
- **A release (12).** Signing with the Developer ID identity, notarizing and stapling, the zips
  and casks, and an install and upgrade on a clean user account.

## 11. Phase 0 — spikes before building

Each spike is throwaway code that answers one question. If a spike fails, the design changes
before any real code is written.

| # | Question | Fallback if it fails |
|---|---|---|
| S1 | Can one authenticated `LAContext` be reused for many Secure Enclave signatures over hours, without a new prompt? | Keys get no Secure Enclave–level user presence; nazar's own approval is the gate (weaker against a compromised nazar) |
| S2 | Do LocalAuthentication prompts and AppKit dialogs appear reliably from an `LSUIElement` app started by a LaunchAgent, including with the lid closed (Mac password / Watch)? | Use a small helper app for prompts |
| S3 | Is caller attribution reliable for iTerm, Terminal, Cursor/VS Code terminals, Claude Code's Bash tool, git → ssh, `ControlMaster`? Does the responsible-process lookup help? | Accept more `unknown` results; document the limits |
| S4 | Can the `dialog` gate reliably tell hardware input from synthetic input on macOS 27? | Say plainly that a process with Accessibility alone could click Allow; keep the 2-second arming and Secure Event Input |
| S5 | Can any process on the same Mac use a CryptoKit Secure Enclave key handle? Does a Keychain item whose access list trusts only nazar protect it with ad-hoc signing (personal) and with Developer ID (public)? | Store handles via the data-protection keychain with a keychain access group (needs Developer ID) |
| S6 | Is `~/.nazar/agent.sock` reachable by ssh and git on macOS 27 (Secretive #839)? | Pick another location |
| S7 | Does `session-bind@openssh.com` arrive from OpenSSH 10.x, and can host keys be matched to `known_hosts` names (including hashed entries)? | Show only the fingerprint |
| S8 | Does git commit signing (`ssh-keygen -Y sign` with a `.pub` signing key) use the agent from `SSH_AUTH_SOCK` with an ECDSA Secure Enclave key? | Ship a `gpg.ssh.program` wrapper that sets `SSH_AUTH_SOCK` |
| S9 (Phase 2) | Can nazar reliably identify which process opened a named-pipe file (for example by scanning open files with `proc_pidinfo`), including with several readers at once, and which common tools (kubectl, gcloud, aws, `curl --netrc-file`, Node/Python/Go file reads) work with a pipe in place of a file? | Offer named-pipe files only for tools known to work; otherwise use `helper`, `late-env` or `env` |
| S10 (Phase 3) | With client-go exec plugins: does `provideClusterInfo` deliver the server and CA reliably? Do kubectl, k9s and helm re-run the plugin when `expirationTimestamp` passes? Does `interactiveMode: Never` behave correctly while nazar's dialog is open? | Fall back to a fixed short expiry; document which tools cache longer |
| S11 (Phase 1, run first) | Can a minimal Swift `LSUIElement` app link a Go c-archive and make calls in both directions: Swift → Go start, Go → Swift `Sign` via a function-pointer callback that shows a LocalAuthentication prompt on the main thread while the goroutine waits? Does it hold up under concurrent calls, with no memory leaks across the boundary? | Run the Go core as a separate process that talks to a Swift helper over a local socket, with peer checks on both ends |
| S12 (Phase 2) | For `late-env`: does an inherited fd 3 survive `npx` (npm's child processes), `uvx` and `pipx` down to the real server, with only the `--target` process reading it? Do `NODE_OPTIONS --require` and the `sitecustomize` hand-over work with common Node and Python versions and virtualenvs? | Use `env` for servers started through launchers; keep `late-env` for direct `node` / `python3` targets |

## 12. Packaging and release

**Two packages**, installed and removed independently:

| Package | Contents | Needed |
|---|---|---|
| `nazar` | `nazar-agent.app` (the background service) with the `nazar` CLI inside it, linked onto `$PATH` | yes: this is the product |
| `nazar-ui` | `Nazar UI.app` in `/Applications` | no: it only shows and edits what the CLI can |

- **Pre-built and signed, not built from source.** Every unsigned or ad-hoc build is a new
  program to the Keychain, so a source build on each `brew upgrade` would orphan the keys. Both
  packages ship as Developer ID–signed, notarized downloads: Homebrew casks in the user's
  existing tap (`atas/homebrew-tap`). Upgrades keep the keys because identity is the
  signature, not the path (section 4).
- **Installing** `nazar` runs `nazar install` (LaunchAgent `dev.nazar.agent`, `~/.nazar`, the
  links); uninstalling runs `nazar uninstall`, which keeps keys, config and Keychain items.
- **Development builds:** `make agent` and `make ui` build both bundles ad hoc; the developer's
  installed copies are signed with their Apple Development identity so that rebuilds keep
  their keys (section 4: same certificate, same identity). An Apple Development build and the
  Developer ID release are two signatures, so two programs to the Keychain: keys do not move
  between them.
- **Release tooling** ([RELEASING.md](../RELEASING.md)): `make release`, run by a person with
  the team's Developer ID certificate, copies both bundles for signing (`release-prepare`), signs
  them inside out (the CLI inside the agent first, so the agent's seal covers it, then the agent
  and the UI; hardened runtime, secure timestamp, no entitlements), notarizes and staples both,
  verifies them (`codesign --verify --strict --deep`, `spctl`, `stapler validate`), zips both and
  renders the two casks from `packaging/homebrew/*.rb.in` (`release-zips`, which refuses anything
  not signed that way). It refuses to run without the identity, without a notary profile, or off
  the tag `vX.Y.Z` with a clean tree; `DRY_RUN=1` with `NAZAR_SIGN_ID=-` runs the path ad hoc and
  never notarizes. `make release-tap TAP=…` renders the casks into a tap checkout and commits
  nothing. CI and the tests never sign with a real identity. Then, by hand: publish the zips as a
  GitHub release, push the tap, and install and upgrade once on a clean user account, checking
  that the keys survive the upgrade (same signature, new path).
- License: **Apache-2.0**.
- A README covering the threat model (section 8) and the comparison with 1Password and
  Secretive.

## 13. Prior art

- **[Secretive](https://github.com/maxgoedjen/secretive)** (MIT)
  - **What it does:** Secure Enclave SSH keys, approval on every use or a timed unlock, and
    notifications.
  - **What it lacks:** approval per app or per session, per-key rules, caller rules. Open issues
    ask for these: #46, #355, #400, #818. #274 shows the caller-attribution problem.
  - **Reuse:** its SSH agent protocol code (`SecretAgentKit`) is a good reference.
- **1Password SSH agent**
  - **What it does:** approval per app, per terminal session or per request.
  - **How nazar differs:** 1Password keys sync and are held in its memory, there are no
    per-key caller rules, and there's no Mac-password approval.
- **macOS `sc_auth create-ctk-identity` + `ssh-keychain.dylib`**
  - Built in, but key protection is only `bio` or `none`, with no approval scopes.

## 14. Superseded decisions

Decisions taken in review while Phase 1 was built that replaced an earlier design.
The sections above already say the new behaviour; this list says what changed and why.

- **The responsible process is display only (4.1).** An earlier design fell back to the app
  macOS names as responsible when the chain had none. Now an app found only through
  `ResponsibleFor` is shown in the summary as `(responsible)` but the chain stays unknown: it is
  not an identity, `app:`/`signed:` never match it, nothing is remembered under it and there is
  no session. macOS responsibility is inherited across fork/exec, so a process that sheds its
  chain (double fork, nesting past the depth limit) must not take the app's own rules. On macOS
  the lookup returns a bare PID, which the caller resolver resolves and checks (full ref, same
  PID, started no later than the peer).
- **Audit redaction is an allowlist (4.6).** Pattern-based secret redaction is replaced: with
  `args: redacted`, an argv element is kept only if it is a short plain word (≤32 chars of
  `[A-Za-z0-9._/-]`, not starting with `-` unless it is a bare flag without a value, no `=`,
  `@`, `?`, `&`, `:`, whitespace or quotes); everything else becomes `…`. `args: none` logs only
  `basename(argv[0])` and the argument count. Every logged value is quoted and escaped so a
  crafted argv[0] can't impersonate another command. No pattern-based secret detection.
- **The `gate: none` matcher rule (4.2).** `gate: none` accepts only `app:` matchers or `signed:`
  matchers whose team is not Apple. Any Apple-signed matcher (with or without `id:`),
  `any` and `unknown` are rejected under `gate: none` by config validation (`login` and `dialog`
  still accept them). Individual binaries or spellings are not blocked. (Amended later:
  `any` and `unknown` under `gate: none` are the user's choice and accepted with a warning, see
  4.2.)
- **The `app:` team is pinned at config load, never while matching (4.2, 4.8).** An earlier
  design pinned the team on the first match. Now `match` is read-only: a staged loosening
  resolves every unpinned `app:` matcher through `Platform.InstalledApp` (the installed bundle's
  static signature) and shows the pin in the approval diff; a bundle ID new to the config forces
  the login gate by itself. An unpinned bundle ID matches nothing; a team mismatch is noted and
  never re-pins.
- **`nazar trust --app <bundle id>`.** New command: replaces or records an `app:` pin from the
  installed app behind the login gate (a pin is a loosening). Refused before any prompt when the
  app is not installed, ambiguous or not validly signed; a no-op without a prompt when the
  installed team is already pinned.
- **A refused session-bind fails closed (5).** A session-bind that doesn't parse or verify, or
  one past the bind limit, marks the connection and no `SIGN_REQUEST` on it is served (refused
  before any prompt, signature or audit line, as `ssh-agent` does); a later successful bind does
  not lift the mark. `REQUEST_IDENTITIES` is still answered.
- **Duplicate session IDs are refused (5).** A session ID is recorded once per connection; a
  second bind for it (under another key or the same one) fails and marks the connection; an
  authentication bind (`is_forwarding` false) is final; a userauth for the session of a
  forwarding bind is refused; past the first hop a userauth must carry the host key.
