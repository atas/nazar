# nazar 🧿 — `secrets` module design (Phase 2)

- **Status:** Being built, task by task, in Milestone 8. Refines section 7.1 of
  [the design spec](nazar-design.md) into something that can be built task by task.
  Where this document and section 7.1 disagree, this document wins; section 7.1 is updated
  with the deltas listed in section 14 (the storage ones were applied in Milestone 8).
- **Depends on:** Phase 1 as merged on `main` (Milestones 1–7): the Go core (`core/broker`,
  `core/policy`, `core/approval`, `core/audit`, `core/control`, `core/caller`, `core/match`,
  `core/keys`, `core/platform`, `core/configstage`, `core/trust`) and the Swift platform layer,
  whose `CreateKey(PurposeKeyAgreement)`, `KeyAgreement` and `DeleteKey` exist since Milestone 3
  and are run on the real Secure Enclave by `make conformance`.
- **Read it against the current architecture** (the passages below were written before
  Milestones 3–7 and are amended where they matter; where one was missed, these rules win):
  - **`path:` matches again, without a pin** (the owner's decision of 2026-11-05, spec 4.2,
    replacing that of 2026-11-01): a `path:` in `apps:` or `to:` names the file its path resolves
    to at each request; there is no `nazar trust <path>` and no trust record (wherever a passage
    below names one, there is none). In `to:` it matches the receiver itself, as `signed:` does,
    so Homebrew's git transport can be named
    (`{path: /opt/homebrew/opt/git/libexec/git-core/git-remote-http}`), only as safe as who can
    write that file. A `nazar run` receiver is matched only by `command:`, whose argv[0] is
    resolved through `defaults.trustedPath` and pinned (6.3); `path:` never matches one.
  - **"Nazar.app" and "the app" mean `nazar-agent`** (`nazar-agent.app`, bundle id
    `dev.nazar.agent`, spec 4, Milestone 6): the background service with no window that
    holds the core, the Vault and every secret. **Nazar UI.app** is a client of the CLI like any other (THREAT-MODEL 5.13):
    it never holds, seals, opens or shows a secret value. The bundled CLI is
    `nazar-agent.app/Contents/MacOS/nazar`, linked as `~/.local/bin/nazar` by `nazar install`;
    the agent is identified by its **signature, never its path** (spec 4, THREAT-MODEL 4.10),
    and so is the genuine CLI (7.3).
  - **Approvals are keyed by what they cover** (`op`, spec 4.3): a secret's delivery
    method is its `op` (`deliver:late-env`, …), so nothing is added to the approval key for it
    (5.1).
  - **A tool's run is its own session** (spec 4.1 step 4): a `scope: session` rule that
    a non-Apple tool in the tab satisfies (`apps: [claude]`) is remembered for that tool's run,
    not the tab (9.1).
  - **Offer** (spec 5) has no secrets counterpart: no protocol lets a caller list the
    secrets it may ask for; `secret list` is metadata for the person.
  - **Loosening commands typed at a terminal apply in one step** (spec 6):
    `secret add` and `secret rm` gate exactly as `ssh-key create` and `ssh-key delete` do.
  - **Vault items and their remedies** follow spec 9 (Milestones 5 and 7): an item the agent
    cannot read is listed and never deleted by nazar; the person deletes it by hand (3.4).
  - **Storage is one Vault item per secret, no blob file** (3.3), sealed with the Go
    standard library's `crypto/hpke` (3.2), and **no secret key has Secure Enclave user
    presence yet** (3.5: spike S13 has not run).
  - **The `secrets:` section of `config.yaml` is parsed, classified and evaluated since M8**
    (section 4, 5.1): it is no longer an "unimplemented" section that makes every change need
    approval. Only the `helper` and `stdout` methods exist; every other method and the
    `helper:`, `file:` and `envAllow:` fields are refused by `config check` as "not in this
    version" until the task that builds them. The default `deliver` is `[helper, stdout]` and
    never grows: every other method is listed by hand.
- **Non-goals:** multi-Mac sync (nothing implements it; 3.3 says what it would take), a GUI
  for secrets, Linux, anything the `k8s` module needs beyond `k8s/<context>` being an ordinary
  secret name.

## 1. Summary of decisions

| Topic | Decision |
|---|---|
| Key per secret | One Secure Enclave P-256 **key-agreement** key per secret, created with `Platform.CreateKey(PurposeKeyAgreement, AuthNone)`: **no Secure Enclave user presence** until spike S13 has run (3.5); nazar's gate is the check. |
| Cipher | **HPKE base mode, RFC 9180**, DHKEM(P-256, HKDF-SHA256) `0x0010` / HKDF-SHA256 `0x0001` / AES-256-GCM `0x0002`, through the **Go standard library's `crypto/hpke`** (Go 1.26) in `core/secrets/seal`. The enclave only does the raw ECDH (`Platform.KeyAgreement`, behind an `ecdh.KeyExchanger`); `crypto/hpke` does the KEM, the key schedule and the AEAD. Neither CryptoKit's HPKE nor a hand-written HPKE is used (3.2). |
| Storage | **One Vault item `secret/<NAME>`** holding the key's handle, its public key and the sealed value together (3.3). No file is written; the Vault (a login Keychain item only `nazar-agent` can read) is the only copy. Values up to 32 KiB. |
| Deletion | **Handle erase**: `Platform.DeleteKey(handle)`, then `Vault.Delete("secret/<NAME>")` (which removes the sealed value with the handle), then the FIFO (3.4). With CryptoKit there is no enclave-side object to destroy, so a backup of the Keychain database restored **on this Mac** is the one copy nazar cannot reach. An item nazar cannot read is never deleted by nazar (spec 9). |
| Config | `secrets.<NAME>` with `deliver`, optional `helper`/`file` settings, and `rules`/`scope`/`gate`/`expire` with exactly the SSH meaning. Default `deliver`: `[helper, stdout]`, fixed for good: `file`, `late-env` and `env` are opt-in, so a method a later version adds never reaches a secret whose approved entry did not list it. |
| Receiver (`to:`) | Checked **on the live process** wherever a live process exists (file reader, helper's parent, the exec'd `nazar run` target), through the same `match.Evaluator.Receiver` as ssh. `command:` matchers are bound to a **pinned executable** resolved through a trusted PATH, never to `argv[0]` (5.1, 6.3.3). For `nazar run` the **app** resolves the command to an absolute realpath before the prompt, checks `to:` against that file, and the CLI `execve`s **exactly that path** (a script's shebang is expanded by the CLI to the pinned interpreter); the caller's `$PATH` is never used for execution (6.3.6). For `env` the post-exec live check does not exist, so the CLI verifies the file's identity right before `execve` and the residual window is stated (6.4); `stdout` checks the CLI's parent. |
| Target environment | The receiver's startup environment is an **allowlist built by the app**, never by the caller: a fixed base (`PATH` = `defaults.trustedPath`, `HOME`/`USER`/`LOGNAME` from the passwd entry, `TMPDIR` from the per-user Darwin temp dir, shape-checked `LANG`/`LC_*`/`TERM`), the variables a secret's `envAllow:` list names (approved config, a loosening change), and the loader variables the app computes from its own bundle. Everything else in the caller's environment is dropped; a **deny set** (`NODE_OPTIONS`, `PYTHONPATH`, `DYLD_*`, `npm_config_*`, `PIP_*`, `UV_*`, `BASH_ENV`, `XDG_*`, TLS-trust variables, …) can never be named by `envAllow` or `--as`. There is no CLI flag that adds a variable. After exec the app compares the **whole** startup environment with the plan and refuses to write on any difference **or when it cannot be read** (6.3.4). What stays open: launchers read config files under the real `HOME` (6.3.4, section 10). |
| Target working directory and process state | The receiver's working directory is **chosen by the app**, never inherited from the caller: `/` by default (the sealed, read-only system root: nothing can be planted in it and it has no ancestors for `npm`/`uv` to walk up into), or the directory an approved `apps.<name>.cwd:` names (an absolute path, pinned by identity, a loosening change; `cwd: caller` only for binary receivers such as `gh`). Every file named in a `command:` argv (`server.js`) is resolved against that directory and pinned by content hash like the executable; a relative file without a `cwd:` is a config error. The CLI enters the directory by `fchdir` on an `fstat`-verified fd, closes every inherited fd above 2 (`FD_CLOEXEC` sweep), resets `umask`, `RLIMIT_CORE`, the signal mask and the Mach exception ports before `execve`; the app checks the working directory after exec and that the handover pipe reached exactly the exec'd process, and does **not** count the receiver's fds, which it could not tell from the ones the new image opens itself (6.3.7, 6.3.8). **As built in M10:** always `/`, no `cwd:`; the CLI's resets as listed in 6.3 "As built in M10". |
| `file` FIFOs | **One FIFO per delivery.** When a reader opens the FIFO, nazar first swaps a fresh FIFO into the path (`renamex_np(RENAME_SWAP)`), so the pipe it serves can no longer be opened by name; then it identifies the one reader, writes once, closes. A reader that keeps its fd open sees EOF and never a second value or a second prompt (6.2). |
| Control peer | Every value-returning control command (`secret.get`, `secret.helper`, `secret.run`) is served **only to the genuine signed `nazar` CLI** (peer code identity checked server side by signature, the requirement Nazar UI.app already uses for the CLI, 7.3). Same user is not enough. |
| `nazar run` handover | `nazar run` **never holds plaintext** for `late-env`: it passes the write end of a pipe to nazar-agent over the control socket (`SCM_RIGHTS`), execs the target, and the agent writes the secret only after it has watched the exec (`NOTE_EXEC`) and re-verified the receiver. Launchers (`npx`, `uvx`, `pipx`, …) get a **per-run unix socket** instead of fd 3, because `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT` (libuv) and `close_fds=True` (Python) drop inherited fds. **As built in M10:** the per-run socket only, for every receiver (D1); see 6.3. |
| Loaders | `loaders/node/env.cjs` via `NODE_OPTIONS=--require`, `loaders/python/sitecustomize.py` via `PYTHONPATH`, shipped in `nazar-agent.app/Contents/Resources/loaders/`. `--target` is a case-sensitive substring of the target's command line. **As built in M10:** no `--target`; the target rule of D2 (6.3 "As built in M10"); the loader sets only the names in `NAZAR_SECRET_NAMES`. |
| CLI | `nazar secret add|rm|list|migrate|migrate-mcp|helper`, `nazar run`, `nazar get`. New `--json` kinds: `Secret`, `SecretList`, `RunPlan`, `Migration`, `HelperResult`. No new exit codes. (As built in M10: `nazar run --secret NAME -- cmd…` only; no `migrate`/`migrate-mcp` yet.) (`--rekey`, `--no-user-presence` and `secret reformat` were dropped in M8: no secret key has user presence to choose, and there is no blob file to reformat.) |
| Spikes | Before the task that needs each: S9 (FIFO reader identification and the per-delivery swap), S12 (loader handover), S14 (`SCM_RIGHTS` + `NOTE_EXEC` across the Swift/Go bridge, and which processes' argv/environment `KERN_PROCARGS2` can read), S16 (can a Mach-O binary be exec'd through `/dev/fd/N`, to close the `env` TOCTOU window). Not before Milestone 8's storage: S13 (enclave key agreement under `userPresence` with a reused LAContext; until it runs, secret keys are made without user presence, 3.5) and S15 (is there any enclave-side key destruction with CryptoKit; 3.4 assumes none). Pass/fail criteria in section 12. |

## 2. Why these secrets, and what "protected" means here

The motivating case is a typical developer machine:

| Secret | Where it is today | Who reads it |
|---|---|---|
| `BRAVE_API_KEY` | `~/.claude.json` → `mcpServers.brave-search.env`, plain text; the server is `npx -y @brave/brave-search-mcp-server` | Claude Code starts the server with the key in its startup environment |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | `~/.bash_profile`, `export …=<literal>` | Every process in every terminal tab inherits it |
| `DEPLOY_TOKEN` | `~/.bash_profile`, `export …=<literal>` | Same |

Both files are readable by anything running as the user, and the exported variables are visible
to every process the user runs through `ps eww` and `KERN_PROCARGS2` (measured, spec
7.1). The goal of Phase 2 is: **no plaintext secret in any file, and no secret in a process's
startup environment unless the user explicitly chose `env`.** Rules decide *who receives* a
secret; what the receiver does with it afterwards is out of scope (section 10).

## 3. Storage

### 3.1 One enclave key per secret

- `nazar secret add NAME` makes nazar-agent call `CreateKey(PurposeKeyAgreement, AuthNone)`
  (3.5), seal the value to the new key (3.2), **open it again through the enclave** and only
  then write the Vault record `secret/<NAME>` (3.3):
  ```json
  {"version":1,"name":"BRAVE_API_KEY","handle":"<base64>","publicKey":"<base64, 65 bytes X9.63>",
   "auth":0,"created":"2026-10-11T00:00:00Z","enc":"<base64, 65 bytes>","sealed":"<base64>"}
  ```
  The record mirrors `core/keys.record`; `core/secrets.Store` is its own small type rather
  than `keys.Registry`, because that one is SSH-shaped (OpenSSH public keys, `.pub` export,
  signature verification). The open-after-seal check is the secrets twin of `keys.Registry`
  verifying every signature against the stored public key: a platform whose public key is not
  its handle's would otherwise lose the value for good, and nothing is stored (the new key is
  deleted again) when it fails. `kind` (`raw`/`aws`) joins the record with the `aws` helper
  task, which is the first to need it.
- **Why one key per secret, not one key for the store.** Deletion removes the handle of
  *that* secret only (3.4); a compromised approval reaches one secret; the `userPresence`
  decision (3.5, once S13 has run) is per secret because it depends on that secret's gates;
  and the enclave key count is not a resource worth saving (a few dozen secrets at most).
- **Why key agreement and not a sign-then-derive trick.** `PurposeKeyAgreement` exists in the
  platform contract already and the conformance suite checks that `KeyAgreement` equals a local
  ECDH on the same point (`core/platform/conformance`, `keys/key-agreement`) and, since M8,
  that a value sealed to the key opens through it and through nothing else
  (`keys/sealed-secret`), on the fake, through the C ABI and on the real Secure Enclave
  (`make conformance`). Nothing new crosses the bridge.
- **The public key is kept in the Vault record and nowhere else.** `nazar secret add
  --replace` seals to it and then checks the result opens through the enclave; nothing
  exposes it (no `kid` in any output: no feature names recipients yet).

### 3.2 HPKE, in Go's standard library

- **Suite:** `DHKEM(P-256, HKDF-SHA256)` (KEM id `0x0010`), `HKDF-SHA256` (KDF id `0x0001`),
  `AES-256-GCM` (AEAD id `0x0002`), **mode_base**, no PSK, no sender authentication, one
  message per context (sequence number 0). `info` is the bytes `nazar/v1 secret`, a NUL, and
  the secret's name, so a value sealed for one name never opens under another; the AEAD `aad`
  is empty (everything else in the record is authenticated by where it lives, 3.3).
- **Split of work:**
  - **Seal** (on `add`/`replace`): pure Go, a fresh ephemeral key per seal, no enclave. Runs
    in nazar-agent (the value travels CLI → agent over the control socket, 7.3); the CLI never
    seals.
  - **Open** (on every delivery): `crypto/hpke.NewRecipient` with a recipient key whose
    `ECDH` is `Platform.KeyAgreement(handle, enc, ref)` (the raw 32-byte X coordinate, as the
    conformance suite requires). Go 1.26's `hpke.NewDHKEMPrivateKey` takes any
    `ecdh.KeyExchanger` for exactly this ("an ECDH key kept in a hardware module"), and
    returns the exchanger's error unchanged, so `ErrAuthRequired` or `ErrNotFound` from the
    enclave reaches the caller as itself. The enclave never sees the ciphertext and Go never
    sees the private key.
  - That *is* RFC 9180 DHKEM: `shared_secret = ExtractAndExpand(DH(skR, pkE), enc || pkRm)`.
    So a sealed value is wire-compatible with any HPKE library given the same suite and
    `info`, which the tests check in both directions.
- **Why the standard library and not a hand-written HPKE or CryptoKit's.** An earlier draft
  planned ~250 lines of HPKE in `core/secrets/hpke`; Go 1.26 ships `crypto/hpke`, tested
  against the RFC 9180 and CFRG vectors upstream, so nazar writes none of it: less code, no
  third-party dependency, and no home-made composition of KDF and AEAD to get wrong.
  CryptoKit's HPKE would put the whole open behind the bridge as one opaque call, duplicate
  the AEAD on the Swift side, and still needs a Secure Enclave recipient verified (spec 7.1
  flagged this). The Go path uses only what the Platform already promises.
- **Implementation:** `core/secrets/seal` (~90 lines): `Seal(pub, name, value) (enc, ct)`,
  `Open(pub, agree, name, enc, ct)`, `Check(value)`, and the `KeyExchanger` adapter. Its test
  opens RFC 9180 Appendix A.3.1's first encryption (P-256 / HKDF-SHA256 / AES-128-GCM) through
  the adapter, which is what the adapter adds to `crypto/hpke`'s own vectors.
- **Limits:** plaintext ≤ **32 KiB** (`seal.MaxValue`, `ErrTooLarge`; empty is `ErrEmpty`): the
  largest value whose Vault record, beside the largest enclave handle, stays under the 64 KiB
  a Keychain item is tested with, and whose `secret.add` request fits the ordinary
  `control.MaxRequestSize`. That holds API tokens, AWS credential JSON and kubeconfig-sized
  values with room to spare; `file` delivery additionally caps at 16 KiB (6.2). A secret is a
  byte string; nazar never trims, re-encodes or inspects it, except where a helper format
  requires it (6.1).

### 3.3 Where a secret lives: one Vault item

The record of 3.1 **is** the stored secret: the Vault item `secret/<NAME>` (service
`dev.nazar`, the same login Keychain item kind as `ssh-key/<name>`, whose access list trusts
only nazar-agent by its signature, spec 4.5) holds the enclave handle, the public key and the
sealed value together. Nothing is written to disk.

- **Why not a blob file** (the earlier draft had
  `~/.config/nazar/secrets/<name>.hpke`, an age-style JSON `SecretBlob` with a wrapped file
  key per recipient, an RFC 8785 canonical header as AAD, a header MAC, and a `version` +
  `blobHash` rollback guard in the Vault record). With the Vault the only copy:
  - **Rollback is gone as a problem**, not guarded: there is no second copy on disk that a
    `git checkout`, a dotfile sync or a Time Machine restore of one file could put back, so
    the `version`/`blobHash` guard, its refusal message and its `--replace` remedy are not
    needed. (A restore of the whole login Keychain database rolls back every item at once,
    config and keys included; that is the Keychain's own behaviour and is accepted.)
  - **The header MAC and canonical JSON are not needed**: their job was to authenticate the
    file's metadata against an attacker who can edit the file. The Vault item can be written
    only by nazar-agent (S5, THREAT-MODEL 4.1), and the one binding that matters across
    records, the name, is in the HPKE `info` (3.2), so a record copied to another name does
    not open.
  - **The states that need explaining shrink** to the ones every Vault item already has (spec
    9): a record that is missing, unreadable or unusable. There is no "blob without record",
    "record without blob", "blob encrypted to a key this Mac doesn't have", or blob directory
    to keep at 0700; `secret reformat` (an `apiVersion` bump for files) is not needed.
  - **The security argument is unchanged**: the value is sealed to an enclave key, so a copy
    of the Keychain database taken off this Mac (a backup, a disk image) does not open, as a
    copied blob would not have. The Keychain item now also hides that the ciphertext exists,
    which a file did not.
  - **What is given up**: "copy the blob into a git repo or dotfiles", which nothing needed,
    and a file format ready for several recipients (multi-Mac), a non-goal. If either is
    wanted later it is additive: each extra recipient is one more HPKE seal of the value to
    that Mac's public key, and an export is a file with the same `enc`/`sealed` fields; the
    record's `version` is bumped when its shape changes, and an unknown version is refused,
    never guessed, as for `config.yaml`.
- **Size:** at most 32 KiB of value (3.2), so the record (the value base64 inside JSON, the
  handle, the keys) stays under the 64 KiB a Keychain item round-trips in
  `KeychainVaultTests.binaryValuesRoundTripExactly`.
- **What is checked when a record is read** (`core/secrets`, `decode`): `version` is 1, `name`
  equals the item's name, a handle is present, `auth` is a known policy, `publicKey` is an
  uncompressed P-256 point, `enc` and `sealed` are present. Anything else is **broken** (listed,
  never used, deletable), as an `ssh-key/` record is (spec 9).
- **Name rules:** `^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`, at most 64
  bytes, no `..` (`config.ValidSecretName`): ASCII only, no leading `-`, `.` or `/`, no empty
  or dot-led part. `/` is allowed so the `k8s` module can use `k8s/<context>`; the Vault item
  is `secret/k8s/hydra` (the Vault accepts `/` in names), and the default FIFO path maps `/` to
  `%2F` (`~/.nazar/run/files/k8s%2Fhydra`), which no valid name can contain, so no name creates a
  subdirectory and two names never share a path. Two names that are equal ignoring ASCII case
  (`github_token` and `GITHUB_TOKEN`) are **refused** at `add` (`ErrExists`) and by `config
  check` ("name collides with X"), as `ssh-key create` does: FIFO paths live on a
  case-insensitive volume, and two secrets a person cannot tell apart are a mistake either way.
  Delivery through `env`/`late-env` additionally needs the name to be env-shaped
  (`^[A-Za-z_][A-Za-z0-9_]*$`) **or** `--as NAME=VAR` on the command line.

### 3.4 Deletion: what "crypto-erase" honestly means here

With CryptoKit, a `SecureEnclave.P256.KeyAgreement.PrivateKey` is a **wrapped key**: its
`dataRepresentation` is the handle, the enclave re-derives the private key from it on every
use, and spike S5 showed that *any* process holding the handle can use it. There is no
enclave-side object that a delete could destroy, so **the only thing that makes a secret
unreadable is removing every copy of the handle**, and the copy nazar controls is the Keychain
item `secret/<NAME>`, which also holds the sealed value (3.3). The platform contract keeps the
two operations apart all the same: `Platform.DeleteKey(handle []byte)` takes a handle and
knows nothing about Vault item names (the Swift `EnclaveStore.deleteKey` records the handle
as deleted for the process, since Milestone 3), and `keys.Registry.Delete` calls `DeleteKey`
and then removes the `ssh-key/<name>` Vault record itself. `secrets.Store.Delete` does the
same two steps. Spike S15 (section 12) checks whether CryptoKit offers anything stronger.
Consequences, stated plainly:

- After `rm`, the value is gone from this Mac for anything that has no copy of the Vault item.
- A surviving copy of the item (a Time Machine backup of the login Keychain database)
  restored **on this Mac** still opens the deleted secret. Off this Mac it opens nothing (the
  enclave key is this Mac's). nazar does not claim to defeat a same-Mac restore, and the
  README says so.

`nazar secret rm NAME` (no alias since M8), gated as `ssh-key delete` is (spec 6, 4.8):

1. **Read the record.** If the Vault refuses to return it (another build's item, a locked
   keychain: `ErrUnreadable`), **nothing is deleted** and the command is refused before any
   prompt with the remedy of spec 9 ("unlock the login keychain, or reinstall the nazar-agent
   you had, and look again", then `security delete-generic-password -s dev.nazar -a
   secret/<NAME>`): a locked keychain and a lost item read the same, and deleting a good
   secret cannot be undone. nazar-agent could not delete an item it cannot read anyway
   (securityd refuses both, Milestone 7). A record that reads but is unusable (broken, 3.3) is
   deleted like a good one: what parsed of its handle is freed by step 2.
2. `Platform.DeleteKey(handle)`, unless another Vault record carries the same handle (the
   `handleShared` guard of `keys.Registry.Delete`: a duplicated Keychain item from a restore
   must never let one `rm` kill another secret's key). Anything but `nil` or `ErrNotFound` →
   nothing else happens, the record is untouched, exit 1.
3. `Vault.Delete("secret/<NAME>")`, same rule: anything but `nil` or `ErrNotFound` → stop,
   exit 1. The order is key first, record second, so a crash between the two leaves a record
   whose handle is dead (`Open` fails with `ErrNotFound`, a second `rm` finishes the job) and
   never a live handle without a record.
4. Remove the `file` FIFO for this secret if one exists (6.2).
5. Audit line: `target=secret:NAME operation=delete decision=approved`.

A `secret/` item whose name is not a valid secret name (any same-user process can add one)
is listed as not a secret, named only Go-quoted, and its name never goes into a `nazar`
command; its remedy follows spec 9's rule for `ssh-key/` items (a `security
delete-generic-password` line only when the account is a plain word).

`--replace` on `secret add` is **not** a delete: it seals a new value to the **same** key (and
checks it opens through the enclave first), so rules, approvals and the key survive; only
`enc` and `sealed` change. To get a new enclave key, `rm` and `add` again.

### 3.5 Secure Enclave user presence

**Slice 1 (Milestone 8): every secret key is created with `AuthNone`.** Spike S13 (does
`KeyAgreement` honour one authenticated LAContext for the 6–10 minutes S1 measured for
`Sign`?) has not run, and a user-presence key that fails after the first use would fail
closed in a way the user cannot fix without re-adding the secret. So nazar's gate is the
check for every secret, as it is for every ssh key a `dialog`, `none` or `session`/`app` rule
can reach, and a compromised nazar-agent can open every secret (THREAT-MODEL 4.8). There is no
flag to choose otherwise (`--no-user-presence` and `--rekey` are gone from 7.1): nothing would
be chosen.

**After S13**, if it passes, the ssh rule of spec 4.5 applies per secret: the key is created
with `AuthUserPresence` when every policy that can reach the secret (each rule, its own
policy, `defaults.fallback`) is `block` or `login` with `scope: use` and at least one is
`login` with `scope: use` (`config.NeedsUserPresence`), decided from the entry as it will be
after the command, as `ssh-key create` does since Milestone 7; drift between a key's protection and
its gates is warned about and nazar's own edits that would cause it are refused, as for ssh
keys (`core/daemon/keyadvice.go`). The re-create path is `rm` + `add`. If S13 fails, slice 1
stays the rule and this paragraph is deleted.

**While the Mac is locked** a secret opens as an ssh key signs (spec 4.5): its key is made
`AfterFirstUnlockThisDeviceOnly` unless `secret add --only-when-unlocked` asks for
`WhenUnlockedThisDeviceOnly`. The record keeps it as `access`, absent for when-unlocked, so a
record written before the choice existed reads as when-unlocked; `secret list` says `whileLocked`.

## 4. Config schema

```yaml
apiVersion: nazar/v1
kind: Config

apps:
  git-https:  { signed: { team: apple, id: com.apple.git-remote-http } }  # the HTTPS transport, which is what starts the credential helper (6.1)
  gh:         { path: /opt/homebrew/bin/gh, cwd: caller }        # pinned by cdhash; matched on its realpath (…/Cellar/gh/<ver>/bin/gh); runs in the caller's folder (`gh pr view` needs the repo, 6.3.7)
  brave-mcp:  { command: [npx, -y, "@brave/brave-search-mcp-server"] }  # npx pinned via trustedPath (6.3.3); no cwd:, so it runs in / (6.3.7)
  deploytool: { path: /Applications/Deploy.app/Contents/MacOS/deploytool, cwd: caller }  # the 9.2 wrapper passes this absolute path
  # my-server: { command: [node, server.js], cwd: /Users/you/projects/foo }  # server.js is resolved against cwd and pinned by hash (6.3.7)

defaults:
  trustedPath: [/usr/bin, /bin, /opt/homebrew/bin, ~/.local/share/mise/installs/node/24.0.0/bin]

secrets:
  BRAVE_API_KEY:
    deliver: [late-env]
    # envAllow: [HTTPS_PROXY]   # only if the server must use a proxy: the caller's value of this one variable passes through (6.3.4)
    rules:
      - apps: [claude]          # who asks: Claude Code starts the MCP server
        to: [brave-mcp]         # who receives: this pinned executable with this argv
        scope: session          # once per Claude Code run (claude satisfies the rule, so its run is the session: spec 4.1); `app` would warn for a launcher receiver (6.3.4, 9.1)
        gate: dialog

  GITHUB_PERSONAL_ACCESS_TOKEN:
    deliver: [helper, late-env]
    helper:
      git: { host: github.com, username: you }   # answers `git credential fill` for this host
    rules:
      - apps: [iterm, cursor]
        to: [git-https]         # helper: git's own credential protocol; gh pushes/pulls via git
        scope: session
        gate: login
        expire: 8h              # the terminal satisfies the rule, so the session is the tab; nazar remembers the approval (secret keys have no enclave user presence yet, 3.5)

  DEPLOY_TOKEN:
    deliver: [env]            # deploytool only reads an env var; env is explicit
    rules:
      - apps: [iterm]
        to: [deploytool]        # the app resolves the command and the CLI execs exactly that file (6.3.6, 6.4)
        scope: session
        gate: dialog

  k8s/hydra:                   # reserved shape for Phase 3; ordinary secret otherwise
    deliver: [stdout]
    gate: block
```

**Fields of `secrets.<NAME>`**

| Field | Type | Meaning | Validation (`config check`) |
|---|---|---|---|
| `deliver` | list of `helper` \| `file` \| `late-env` \| `env` \| `stdout` | Methods this secret may use. A request through any other method is refused as `blocked`, reason `delivery not allowed`, before any prompt | A non-empty list. Default `[helper, stdout]` (it never grows, so an approved entry without `deliver:` never comes to mean a method a later version adds): `file`, `late-env` and `env` only when listed. Duplicates are an error. **In M8** only `helper` and `stdout` exist: `file`, `late-env` and `env` are an error, "late-env is not in this version (helper and stdout are)", until their tasks, and so are the `file:` and `envAllow:` fields ("the file: field is not in this version"; `helper:` is built since M8, with only `helper.git`): refused by name, never ignored, so nothing is approved now to work later. **Since M10** `late-env` and `envAllow:` are built (`gate: none` on a `late-env` secret needs `to:` naming the exact command line); `file` and `env` are still an error, "file is not in this version (helper, late-env and stdout are)". |
| `helper.git` | `{host, username?}` (as built in M8: no `protocol`, only https; 6.1) | Answer `git credential fill` when `protocol` (default `https`) and `host` match; `username` is returned too | Two secrets mapping the same `protocol://host` is an error. Only valid if `helper` is in `deliver` |
| `helper.docker` | `{registry, username?}` | Answer `docker-credential-nazar get` for this `ServerURL` host; `username` is returned too | Same uniqueness rule |
| `helper.aws` | `true` | The value is an AWS credential JSON (6.1) | Value shape checked at `add` with `--kind aws` |
| `file` | path, default `~/.nazar/run/files/<name with / as %2F>` | Where the FIFO is created | Must be inside `~/.nazar/run/files/` after `~` expansion (no symlinks, no `..`), unique across secrets case-insensitively. Changing it is a **loosen** (it names where a secret appears) |
| `envAllow` | list of variable names, default `[]` | Variables of the **caller's** environment that `nazar run` passes to the receiver, in addition to the fixed base the app builds itself (6.3.4). Listing a name means "I trust whatever the caller puts in it" | Each name env-shaped; **error** if it is in the deny set of 6.3.4 (`envAllow: [NODE_OPTIONS]` → "NODE_OPTIONS can never be passed to a receiver") or is a name the base sets (`PATH`, `HOME`, `USER`, `LOGNAME`, `TMPDIR`, `LANG`, `LC_*`, `TERM`: "set by nazar"). Adding a name **loosens** (as built in M10: also while every rule blocks; `SHELL` and the M10 additions are in the deny set, 6.3) |
| `rules`, `scope`, `gate`, `expire` | as spec 4.2 | Identical semantics, same top-level `apps`, first match wins, `apps:` and `to:` must both match | Same checks as ssh keys, plus: it is an **error** if `deliver` contains `env` or `stdout` **and** any rule, the secret's own policy or `defaults.fallback` that can reach the secret has `gate: none` (silent delivery into `ps`-visible or printed form is never acceptable; the own policy and `defaults.fallback` can never be `none` anyway, and the default `deliver` contains `stdout`, so a silent rule needs `deliver:` written without it); `apps: [any]` or `apps: [unknown]` under `gate: none` is an **error** for a secret, where an ssh key only warns (the key never leaves the enclave, a secret's value does: "any with gate: none would give this secret to every program without a prompt"); an entry in `rules:` without `to:` is a **warning**, except under `gate: block`, which hands the value to nobody (spec 4.2; an own policy is not a rule and does not warn); `command:` matchers allowed only in `to:` and must resolve through `defaults.trustedPath` (6.3.3); a **warning** when a rule whose `to:` is a **launcher receiver** (a `command:` that resolves to the launcher table of 6.3 step 3: `npx`, `npm`, `pnpm`, `bunx`, `uvx`, `uv`, `pipx`) has `gate: none` or `scope: app`: "brave-mcp is a launcher; what it runs is chosen by files under your home directory (~/.npmrc) that any process of yours can edit, and this rule would deliver BRAVE_API_KEY to it silently [forever / until iTerm2 quits]; use `scope: session` or `use`, or a `path:`/`signed:` receiver" (6.3.4, section 10); the same warning, with "…and by `node_modules/` and `.npmrc` in /Users/you/projects/foo", when a launcher receiver has a `cwd:` (6.3.7) |

**Fields of `apps.<name>` read by `nazar run`** (an `apps:` entry is otherwise as in spec 4.2):

| Field | Type | Meaning | Validation (`config check`) |
|---|---|---|---|
| `cwd` | `caller` \| absolute path (`~` allowed), default none | The receiver's **working directory** (6.3.7). Absent: the receiver runs in `/`. An absolute path: the receiver runs there, and every relative file element of a `command:` argv is resolved against it and pinned by hash. `caller`: the receiver runs in the caller's directory, taken from the control peer's `ProcessInfo.Cwd`, never from the request | Read only when the entry is the `to:` of a `nazar run` delivery (ignored for callers and for `file`/`helper` receivers). A relative path is an **error**. An absolute path is realpath'd and its `{dev, ino}` recorded; one that does not exist or is not a directory **at load** is a **warning** that leaves the entry **stale** (6.3.7: its recorded pin stays in force and runs are refused; nothing on disk can make the config invalid, because `Parse` never touches the filesystem). `caller` on an entry whose resolved kind (6.3.6 step 7) is `interpreter` or `launcher` is a **warning** that leaves the entry inactive ("node runs whatever the caller's directory holds; pin a directory with `cwd: /…` or an absolute script"; a warning because the kind comes from the filesystem), and the run is refused before any prompt for every matcher kind, `signed:` included, whose kind is known only then. A `path:`/`signed:` receiver of a `nazar run` rule whose resolved kind is `interpreter` or `launcher` draws a **warning** too (6.3.7, "What remains"): the caller then chooses the script. A `command:` with a **relative file element** (6.3.7: `./x`, `../x`, `*.js`/`*.py`/…, the interpreter's script argument, the argument of `-r`/`--require`/`--import`/`--env-file`/`--loader`/`--experimental-loader`, in the separate and the `=` spelling) and no absolute `cwd:` is an **error** ("`server.js` is relative: the receiver runs in `/` unless the entry has `cwd: /…`; pin a directory or write the absolute path"); a file element that does not exist as a regular file at load is a **warning** that leaves the entry stale (as for `cwd:` above). A `command:` whose `argv[0]` is relative with a slash (`./bin/server`) is an **error**: `argv[0]` is a bare name (through `trustedPath`) or absolute. Setting or changing `cwd` **loosens**; removing it tightens. **As built in M10:** `cwd:` is refused by name, "not in this version" (D6): the receiver always runs in `/` |

- **Secrets parsed, now implemented (M8):** `core/config` no longer reports the `secrets`
  section as `Unimplemented` (only `k8s` is). `Config.Secrets map[string]*Secret` with
  `Secret{Name, Deliver []Delivery, Rules []Rule, Own *Policy}`; `Config.SecretNames`,
  `SecretFallback` (own policy, else `defaults.fallback`) and `Deliver` (the entry's list, else
  `DefaultDeliver()`); `Delivery.Built()` says which methods this version has. Names follow
  `ValidSecretName` and must differ in more than letter case (the store compares names
  case-insensitively). `rules`, `scope`, `gate` and `expire` are read by the code that
  reads them for ssh keys, with the shadowing and `to:` fall-through warnings, and `app:`
  matchers in a secret's rules are pinned on approval like a key's. A `command:` receiver is an
  error until `nazar run` exists ("command: receivers need nazar run, which is not in this
  version"). Later tasks add `Helper`, `FilePath`, `EnvAllow` and `App.Cwd` (`""`, `"caller"`,
  or an absolute realpath), each with its classification below.
- **What M8 classifies, exactly:** a secret is compared like an ssh key, by the first-match
  proof over its slots (target `secret:<NAME>`), so a bare entry or `{gate: block}` is not a
  loosening and removing a shadowing `gate: block` rule is. Its `deliver` list is compared on
  top: a method added **loosens** when some request can get past the new slots (a slot whose
  gate is not `block`), and a method removed tightens. A secret without an entry has the
  default `deliver`, so adding or removing an entry is judged by its slots and its list, not
  as a blanket loosening. The exception for removing a method while `env` or `stdout` stays
  (below) protects `--secret`'s automatic choice (6.3.5) and is added with it; until then
  removing a method only narrows what can be asked for.
- **Tighten/loosen classification (`core/configstage/classify.go`):** **rules** are classified
  by the first-match proof `classify.go` already applies to ssh-key rules (`loosenings` over
  (old slot, new slot) pairs; the slot list is the secret's rules followed by its own policy
  or `defaults.fallback`), so removing a shadowing `gate: block` rule that exposes a later
  `gate: none` rule is a loosening and adding a rule at least as strict as the slot it shadows
  is not; nothing here is per field. The per-field rules are for the other keys: adding a
  secret entry, a method to `deliver`, a name to `envAllow`, or any `helper.*` mapping
  **loosens**; removing any of them **tightens**, with one exception: removing a method from `deliver`
  while `env` or `stdout` **stays** listed **loosens** (`deliver: [late-env, env]` →
  `[env]`), because `--secret`'s automatic choice (6.3.5) would then fall through to the
  `ps`-visible method under an approval that was given for `late-env`; the finding reads
  "BRAVE_API_KEY would now be delivered by env, which is visible in ps". The broker's cache key
  includes the delivery method (5.1), so a cached `late-env` approval never serves `env` even
  when the config allows both. Adding or changing `file` **loosens** too (a malware edit
  must not be able to move a FIFO at once); removing it tightens. Setting or changing an
  entry's `cwd` **loosens** (it names a new directory whose contents the receiver will load,
  6.3.7); removing it tightens. **Receiver pins are compared, never adopted:** every load
  (app start, a file-change reload, `nazar config reload`) recomputes the pins of each
  receiver entry from the files as they are now and compares them with the **recorded pin
  set** in the Vault (6.3.7, "Recording and refreshing the pins"). Any difference in **any**
  pin (the executable's realpath, `cdhash`/`sha256` and file identity, the interpreter's, a
  file element's `sha256`, the `cwd:` directory's `{dev, ino}`, the context-pin marker sets)
  **loosens** even when the YAML text is unchanged, because other bytes will receive the
  secret; the active matcher keeps the recorded pin meanwhile, so runs are refused rather than
  served, and the diff names the entry, the file and the old and new value. A receiver entry
  with no recorded pins (new to the config, or first start after an upgrade) is **new trust**:
  it matches nothing until the gate has shown its pins in a pin-only change, never in the text
  change that introduces it (unlike an `app:` bundle id, 6.3.7 says why). A pin
  difference never delays a text change that tightens: the tightening applies at once and the
  pin change is staged on its own (6.3.7, "Two kinds of staged change"). Changing
  `defaults.trustedPath` loosens: it is both where receivers are resolved (6.3.6) and the
  receiver's `PATH` (6.3.4). The `login` dialog for a loosening change shows the diff, so a new
  `envAllow` name, `cwd:` directory or pin is seen by the user before it ever reaches a receiver.
- **A stored secret without a config entry** behaves like an unconfigured ssh key:
  `defaults.fallback` (block). `nazar secret add` writes the entry `ssh-key create` writes for
  a key since Milestone 7: `NAME: {gate: block}` plus one `login`/`session`/`8h` rule for the
  terminal app the command was typed in, without `to:` (so `config check` warns until the
  receiver is named), and keeps an existing entry unchanged; that is a loosening change, shown
  on the same `login` approval as the add.
- **A config entry with no stored secret** is a warning in `config check` and `status` ("secret X is
  configured but not stored; run `nazar secret add X`"); requests for it are refused with
  `error`, reason `no such secret`.

## 5. How a request flows through the core

```
module front end          core (existing)                    platform
───────────────           ─────────────────────────────────  ──────────────────
helper / get / run  ──▶   control.Server (new commands)
file (FIFO)         ──▶   secrets.FileServer
                          │
                          ▼
                    caller.Resolver.Resolve(peer) ──────────▶ PeerOf / Process / AppFor
                          │
                          ▼
                    policy.Engine.EvaluateSecret(name, delivery, askChain, recvChain)
                          │
                          ▼
                    broker.Handle(Request{Target: "secret:NAME", Do: open})
                          │  cache → gate → Do → audit
                          ▼
                    secrets.Store.Open(name, ref) ─────────▶ KeyAgreement(handle, enc, ref)
                          │
                          ▼
                    delivery writes plaintext to the receiver, zeroes its copy
```

### 5.1 Changes to existing packages

| Package | Change |
|---|---|
| `core/config` | `Secrets` section (section 4); `Delivery` type; `Secret.EnvAllow`, validated against `envpolicy.Deny` and `envpolicy.BaseNames` (6.3.4); `App.Cwd` with the rules of section 4 (6.3.7); `Defaults.TrustedPath`; validation rules above, including the launcher-receiver warning. `command:` matchers gain a resolved form `config.ReceiverPins` `{path, code{cdhash|sha256}, file{dev,ino,size,mtime}, interpreter?{path, code, file}, kind, cwd?{path, dev, ino}, files[], context?}` (6.3.3, 6.3.7): `kind` ∈ `binary`/`interpreter`/`launcher` from the table of 6.3 step 3, `files` the pinned file elements `{arg, path, sha256, file}`, `context` the launcher's marker-file pin for an absolute `cwd`. `Parse` never touches the filesystem; `config.ResolveReceivers(c, fs) (map[ReceiverKey]ReceiverPins, Problems)` computes the **observed** pins of every receiver entry (6.3.7 defines `ReceiverKey`), and `configstage` installs the **recorded** pins on the active config (`Config.SetReceiverPins`), so what `core/match` and `core/secrets/run` read is always what the login gate approved. `path:` entries resolve their `kind` at load too (for the `cwd: caller` rule). |
| `core/trust` | `ReceiverPinStore` (6.3.7): the receiver pin set in the Vault item `state/receiver-pins`, beside `state/trust`. `Load() (ReceiverPinSet, error)`, `Replace(ReceiverPinSet) error`; a missing item is the empty set, a corrupt or newer-than-known item is `ErrUnreadable` (the store still opens, the stager fails closed on it). Only an approval writes it. |
| `core/configstage` | `receiverpins.go` beside `pins.go`: `stageReceiverPins` (compare observed with recorded, add findings and the set to record to `Diff`), `recordReceiverPins` (write exactly the set the dialog showed), `ReceiverProblems` (unpinned, stale, unresolvable entries for `config check`/`status`), `Stager.Reload()` for `config.reload`. `Pending` gains `Hash` (text + pin set), `ReceiverPins` and `PinOnly` (a change whose text equals the active text); `Approve` is keyed on `Pending.Hash` (7.3); `Observe`'s equal-text early return runs the comparison instead of clearing the slot, and a tightening is followed by the comparison against the new active text (6.3.7, "Every load compares"). `core/daemon`: the pending guard on `ssh-key create`/`secret add` ignores a `PinOnly` change; `config.check`/`status` add `ReceiverProblems`. |
| `core/policy` | `EvaluateSecret(name string, d config.Delivery, ask, recv *caller.Chain) Outcome`. `apps:` is evaluated on `ask`; `to:` on `recv.Peer()`; `deliver` is checked first and short-circuits to `Blocked`. Target string `secret:<name>`. `Outcome.Receiver` is `match.Identity(recv peer)`, or `"command:"+pinned path+canonical argv[1:]` when a `command:` matcher matched. `FallbackRuleID` reused unchanged. `LiveRuleIDs` (`core/policy/policy.go`, not `core/config`) includes `secret:<name>` targets. **Built in M8** (without the `command:` case, which comes with `nazar run`): `EvaluateSSH` and `EvaluateSecret` share one first-match walk; the receiver's identity is in **every** remembered secret approval, with or without `to:` (an approval for one receiver never hands the value to another in the same scope), and a request whose receiver nazar cannot identify is one-shot; a method the secret's `deliver` does not list, or this version does not build, is blocked with `policy.ReasonDelivery` (`delivery not allowed`) before any rule is read. **As built in M10:** for a synthetic receiver (`caller.Chain.Synthetic`) `Outcome.Receiver` is `match.RunIdentity(peer)` (the realpath plus a digest of the resolution and the stable environment), not `"command:"+path+argv`. |
| `core/match` | `Receiver` gains the `MatchCommand` case (6.3.3): the peer's **executable path** (`ProcessInfo.Path`, from `proc_pidpath`, realpath'd) equals the matcher's pinned path (itself a realpath) and its code matches the pin (cdhash, or sha256 for an unsigned script), **and** the normalised argv tail equals the matcher's `argv[1:]` byte for byte, **and** every pinned file element of the tail (6.3.7) still resolves, against the matcher's `cwd`, to a regular file with the pinned hash. `argv[0]` is never compared: it is chosen by whoever called `execve`. For the static pre-check the app builds a synthetic one-process `caller.Chain` from a `ProcessInfo{Path: <resolvedPath, 6.3.6>, Argv: <sent argv>, Cwd: <plan cwd>, Code: InspectCode(resolvedPath)}` (`caller.Synthetic(info)`); `match.Receiver` is unchanged in signature. `path:` matchers already accept the trust record's realpath as well as the literal path (`core/match/match.go:123`), which is what makes `/opt/homebrew/bin/gh` match its Cellar realpath. **As built in M10:** `Evaluator.Command` (bound per config to `run.Resolver.Locate` with that config's `trustedPath`) resolves the matcher's `argv[0]`; a synthetic chain is matched only by `command:` and `any`, a live chain never by `command:`; no per-file check in the matcher (the pins are in the approval identity, 6.3). |
| `core/broker` | **As built in M8:** `Request` gains `Secret` (the name; `Key` stays the ssh key's, so no rename is needed), `Delivery config.Delivery` and `Receiver *caller.Chain` (the receiving process's chain; nil when unknown); the broker sets `Op` itself from `Delivery` (`deliver:helper` covering "the credential helper", `deliver:stdout` covering "nazar get"), so no module can make an approval cover more; the prompt reads `iTerm2 wants to use secret "GH_TOKEN"`, its command line and the audit `receiver=`/`command=`/`cwd=` come from the receiver's chain, and `Refuse` takes secrets too. `Handover` and `Verify` come with `nazar run`. **As built in M10:** neither; `Do` returns a `broker.DeniedError` for a refusal after the gate (`decision=denied`, and the approval is dropped), and `EnvPassed` goes to the audit line. **The design:** `Request` gains `Delivery string`, `Handover string` and a `Verify func(ctx) error` hook run **after** `Do` and before the audit line; a `Verify` failure logs `decision=denied reason=<err>` (not `audit.Error`, which `finish` uses for a failing `Do` today), so a `late-env` request writes one line after the post-exec verdict (section 8). `Request.Key` is renamed `Target` in a mechanical refactor (`"ssh:"` / `"secret:"` prefixes are decided by the module). The delivery method is the request's **`op`** (`approval.Op`, spec 4.3): `deliver:helper`, `deliver:file`, `deliver:late-env`, `deliver:env` or `deliver:stdout`, so the approval key `(target, rule, scope_id, receiver, op)` already keeps methods apart and nothing is added to it: a `late-env` approval never serves an `env` or `stdout` request for the same receiver (section 4, `deliver` classification). One shared prompt, deadline, fail-closed are unchanged; the dialog's Scope line says what the approval covers, as for ssh (`Scope: this claude run, via late-env only`). `Broker.Offer` stays ssh-only: no secrets protocol lists what a caller may ask for. The prompt's first line becomes `iTerm2 wants secret "GITHUB_PERSONAL_ACCESS_TOKEN"` and the summary line names the method, `via helper → git fetch origin`, `via late-env → npx -y …`, `via env (visible in ps) → deploytool …`; the audit line carries `delivery=`. |
| `core/audit` | (`Delivery` built in M8: `delivery=` right after `target=`, never shortened, at most 16 bytes.) New fields `Delivery`, `Handover`, `EnvPassed` (the `envAllow` **names** the caller actually supplied for this run, never values; empty when none), `ReceiverCwd` (the directory the receiver ran in, 6.3.7; `Cwd` keeps meaning the caller's); `Receiver` already exists. The value is never in the event: `Event` has no field that could hold it, by construction. **As built in M10:** `EnvPassed` only, logged as `env_passed=` (keys are lower case); no `Handover` or `ReceiverCwd` (always the socket and `/`). |
| `core/control` | New commands and kinds (section 7.3). `Server` learns to receive one file descriptor with the request (`ReadMsgUnix` + `ParseUnixRights`) for `secret.run`; a request carrying an fd for any other command is refused. `Server` gains a per-command **peer requirement**: the existing `peerCheck` hook (`server.go`) is extended so value-returning commands require `PeerIsNazarCLI` (7.3), while `RequireSameUser` remains enough for read/loosen commands. `MaxRequestSize` stays 64 KiB except for `secret.run`, which may be up to `MaxLargeRequestSize = 128 KiB` for the caller's environment (7.3); `secret.add` fits the ordinary bound (a 32 KiB value is under 44 KiB in base64, 3.2). **As built in M10:** no fd is received; `secret.run` and `RunPlan` as in 7.3 "As built in M10"; `MaxLargeRequestSize` 128 KiB for `secret.run`. |
| `core/platform` | Five additive methods: `OnProcessExec(ref ProcessRef, fn func(ProcessInfo)) (cancel func())` (kqueue `EVFILT_PROC`/`NOTE_EXEC`; fn is called on **every** exec of the pid until cancelled or the pid exits, which is reported with `ProcessInfo{Exited: true}`), `InspectCode(path string) (CodeIdentity, error)` (static signature of a file; for an unsigned file `CodeIdentity.SHA256` of the bytes), `OpenersOf(fd int) ([]Opener, error)` (6.2; `Opener{Ref ProcessRef, Flags int}` for every fd of the user's processes that refers to the same vnode or pipe as **our** fd, by `fstat`, read and write ends alike), `Environment(ref ProcessRef) ([]string, error)` (the **startup** environment of a live full ref from `KERN_PROCARGS2`; `ErrUnreadable` when the kernel hides it, as it does for Apple platform binaries, main spec 7.1; **never** an empty slice for "hidden", 6.3.4), and `VerifyPeer(conn) (CodeIdentity, error)` (7.3). `ProcessInfo.Cwd` (already there, from `PROC_PIDVNODEPATHINFO`) is what the post-exec working-directory check compares (6.3.7). `ProcessInfo` gets no `Env` field: the environment is read once, for the final hop only. There is deliberately **no** method that lists a process's fd table: the fd table is not recorded at exec the way argv and the environment are, so nothing read after exec can separate inherited descriptors from the image's own, and macOS exposes no open-file-description identity to compare by (6.3.8); the fd sweep is the CLI's, and `OpenersOf` on the handover pipe is the one fd fact the app verifies. `CodeHash` **stays** as it is: `InspectCode` is a new method beside it; the task that adds the five methods adds them to the fake, the conformance suite and the Swift layer together, and only then may `CodeHash` be expressed through `InspectCode`. (`CreateKey(PurposeKeyAgreement)`, `KeyAgreement` and `DeleteKey` need no change: they exist on every layer since Milestone 3.) **As built in M10:** an optional `platform.Exec` with `OnProcessExec` and `Environment` only (D8); no `InspectCode`, `OpenersOf` or `VerifyPeer`; a test-only `/proc` implementation lives in `core/daemon/procfs_linux_test.go`; on macOS it is `ExecWatcher` (6.3 "As built in M10"). On Linux (later): `OpenersOf` walks `/proc/*/fd`, `Environment` reads `/proc/<pid>/environ`, `OnProcessExec` uses `PROC_EVENT_EXEC` on the netlink connector, `VerifyPeer` is `SO_PEERCRED` plus a hash of `/proc/<pid>/exe`; the fake stays the reference. |
| `core/caller` | `Resolver.Resolve(ref)` is already enough: file readers and post-exec targets are resolved from a `ProcessRef`, not a socket fd. `Chain.Parent()` returns the chain with the peer removed (the helper's and `get`'s receiver view; built in M8). `caller.Synthetic(info ProcessInfo) *Chain` builds the one-process chain for static pre-checks. |

`core/secrets` is new: `seal/` (HPKE through `crypto/hpke`, 3.2), `store.go` (the Vault records of 3.1–3.4), `fileserver.go`
(FIFO), `run.go` (two-phase handover), `envpolicy/` (the base set, the deny set and the
environment builder of 6.3.4, one package imported by both the app and the CLI so the two can
never disagree on a name), `helper.go` (protocol formats), `migrate.go`.
`loaders/node/env.cjs` and `loaders/python/sitecustomize.py` are new top-level directories,
copied into `nazar-agent.app/Contents/Resources/loaders/` by `make agent`.

### 5.2 Who is the caller, who is the receiver

Since M8, `apps:` is judged on the `ask` chain **without its peer** (the chain above the `nazar` CLI): the CLI asks for every secret, whoever runs it, so a rule naming the CLI's own identity would otherwise match every program. A request whose name is not a valid secret name, or matches an entry only ignoring letter case, is blocked (`invalid secret name`) before any rule, and a receiver that is the asker itself is treated as unidentified (one-shot).

| Delivery | `ask` chain (`apps:`) | `recv` chain (`to:`) | When `to:` is checked |
|---|---|---|---|
| `helper` | The `nazar` CLI's chain | The CLI's parent: the **transport** that started the helper (`git-remote-http`, `docker`, the AWS SDK's process), 6.1 | Live, before the prompt |
| `file` | The FIFO reader's chain | Same chain (reader = receiver) | Live, before the prompt |
| `late-env` via `nazar run` | The CLI's chain | **Static pre-check:** the app resolves the sent `argv[0]` to an absolute realpath itself (6.3.6; the CLI sends argv as typed and never resolves anything for execution), pins its code, chooses the working directory and re-checks the file elements pinned against it (6.3.7), and matches a synthetic chain (5.1); a mismatch is refused **before any prompt**. **Live check:** the exec'd process (6.3.3), re-resolved from `NOTE_EXEC`, which must be that very file, in that directory, with exactly the planned fds (6.3.8) | Twice: static pre-check before the prompt, live check before the write |
| `env` via `nazar run` | The CLI's chain | **Static pre-check** as for `late-env`, and the CLI `execve`s exactly `RunPlan.resolvedPath` from `RunPlan.cwd` after checking the file and the directory are still the ones the app pinned (6.4). No live check exists, because the plaintext is in the CLI's hands before the exec | Before the prompt, and the file and directory identities again right before `execve` |
| `stdout` via `nazar get` | The CLI's chain | The CLI's parent (the script) | Live, before the prompt |

Approvals are remembered per receiver identity, so an approval for `git` in a tab does not
cover `gh` in the same tab (spec 4.3).

## 6. Delivery methods in depth

### 6.1 `helper`: credential-helper pipes

The tool asks; nazar answers over the tool's own protocol on stdout; the secret is never an
argument or an environment variable. The `nazar` binary is run by the tool, so the tool is the
CLI's parent and therefore the receiver. The app answers only the genuine `nazar` binary
(7.3), so a program cannot claim a helper parent it does not have.

**Who the receiver is for git, and what that does and does not buy.** During a real HTTPS
`fetch`/`push`/`clone`/`ls-remote`, the process that runs the credential helper is the
**transport**, `git-remote-https` (a symlink to `git-remote-http`), not `git` itself. Measured
on Xcode's git: `/usr/bin/git` is the `xcode_select` shim (signing identifier
`com.apple.dt.xcode_select.tool-shim-public`), which execs `<DEVELOPER_DIR>/usr/bin/git`
(`com.apple.git`), which starts `…/libexec/git-core/git-remote-http` (**`com.apple.git-remote-http`**,
team `59GAB85EFG`). So the receiver matcher for a helper-fed secret names the transport:
`git-https: {signed: {team: apple, id: com.apple.git-remote-http}}` in section 4 (a Homebrew git
pins `…/libexec/git-core/git-remote-http` with `path:`). `config check` warns when a secret with
`helper.git` has a `to:` whose `signed:` id is `com.apple.git`: "the helper is started by
`git-remote-http`, not `git`; this rule will never match a fetch". There is **no** argv
narrowing: `printf 'protocol=https\nhost=github.com\n' | git credential fill` from a shell has
`git` (`com.apple.git`) as the helper's parent, which is simply not `to: [git-https]`, and the
refusal reason says so (as built in M8 the refusal is the ordinary `to: mismatch` block; no special wording).
An earlier draft accepted a parent `git` whose `argv[1]` was `fetch`/`push`/…; that rule was dead
(the parent during a transport is never `git`) and wrong for every real invocation with global
options (`git -C dir fetch`, `git -c k=v push`, what VS Code and GUIs run). For `aws`, the parent
is the SDK's process and its argv must not be `configure export-credentials`.

**What this is honestly worth.** It stops the token going to a program that is not git's HTTPS
transport. It does **not** make an approved scope safe against a shell that wants the token,
because a **genuine** transport leaks it on request: `GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0 git
ls-remote https://github.com/x/y` prints the `Authorization` header to stderr, and `git -c
http.sslVerify=false -c http.proxy=http://127.0.0.1:8080 fetch` sends it to a local proxy. In
both cases the helper's parent is Apple's genuine `git-remote-http` and `to:` passes; nazar
cannot read the transport's environment or git's config to tell. Likewise a program git itself
starts during a transport (`credential.helper='!…'`, an alias, a hook) can ask nazar with git as
its parent. For `helper`, therefore, **the protection is `apps:` (who may run git at all) plus
`scope: use` with `gate: login` for a token that matters**; the receiver check is a guard against
mistakes and casual extraction, and section 10 says exactly that.

**As built in M8.** One entry point, `git-credential-nazar` (a link to the CLI, made by `nazar
install` and the cask next to `nazar-sign-git`, dispatched on `argv[0]`); there is no `nazar secret
helper git` subcommand. `helper.git` is `{host, username?}` with no `protocol` field (only https
exists): the host is lower-cased, may carry a `:port`, and has no scheme, path or user; the
username is printable ASCII without `=`; two secrets for one host, a `helper:` without `helper` in
`deliver`, and `helper.docker`/`helper.aws` ("not in this version") are errors; adding a mapping or
changing its host or username loosens. The CLI asks nothing for a protocol other than `https`;
nazar-agent answers `secret.helper` (`protocol`, `host`, `username?`) only for `https` and a host a
`helper.git` names, before any prompt. For `helper = nazar` git runs `git credential-nazar get`,
which runs the helper as its **child** (git's dashed-external dispatch), so the receiver is the
CLI's parent except that a parent which is Apple's `git` (`signed: apple`, `com.apple.git`)
running exactly `git credential-nazar …` is skipped once and its parent, the transport, is the
receiver; any other process, a look-alike `git` included, is the receiver itself. The setup lines
are `git config --global --replace-all credential.https://github.com.helper ""` (clearing a helper
set before, such as Xcode's system-wide osxkeychain, which would answer first) and `git config
--global --add credential.https://github.com.helper nazar`; `useHttpPath` stays at git's default.
A value or username with a newline or NUL is refused (it would add protocol lines). git needs a
username from somewhere, the secret's `helper.git.username` or the remote URL (`https://you@…`):
with a password alone it asks the terminal, or fails with no terminal.

**git** (the original design; superseded where the as-built note above differs: the setup lines
there clear earlier helpers, and `useHttpPath` stays at git's default). Installed as a symlink
`git-credential-nazar → nazar` next to `nazar-sign-git`
(`cmd/nazar/main.go` dispatches on `argv[0]`, as it does for `nazar-sign-git`). Setup:
```bash
git config --global credential.https://github.com.helper nazar
git config --global credential.https://github.com.useHttpPath false
```
- `get`: reads the `key=value` block from stdin (`protocol`, `host`, `path?`, `username?`);
  finds the secret whose `helper.git` matches `protocol`+`host` (and `username`, if the request
  has one and the config sets one); runs the pipeline with delivery `helper` (receiver: the
  CLI's parent, normally `git-remote-http`); prints `username=<cfg>\npassword=<secret>\n`. On
  refusal prints nothing and exits 3; git then falls through to its next helper or prompts,
  which is the behaviour the user expects from a declined credential.
- `store` and `erase`: exit 0, do nothing. nazar is the source of truth; git must not try to
  cache the token elsewhere, so the README also recommends not configuring a second helper.
- The `gh` CLI uses git for pushes/pulls, so it is covered; `gh api` uses its own token store
  and is **not** covered unless `GH_TOKEN` is delivered through `nazar run` (`to: [gh]`).

**docker.** `docker-credential-nazar` symlink; `~/.docker/config.json` gets
`"credHelpers": {"ghcr.io": "nazar"}`. Protocol: `get` reads the server URL on stdin, prints
`{"ServerURL":"ghcr.io","Username":"atas","Secret":"<token>"}`; `store`/`erase`/`list` behave
as `git`'s (`list` prints `{}`). The secret's `helper.docker.registry` selects it; `username` is
stored alongside in the config, never in the blob.

**AWS `credential_process`.** `~/.aws/config`:
```ini
[profile dev]
credential_process = /opt/homebrew/bin/nazar secret helper aws AWS_DEV
```
The secret's value is the JSON `{"AccessKeyId":"AKIA…","SecretAccessKey":"…","SessionToken":"…"?}`,
validated at `nazar secret add AWS_DEV --kind aws`. The helper adds `"Version": 1` and
`"Expiration"` = now + 15 min, so the SDK comes back regularly and hits the scope cache
rather than keeping a copy for hours. `aws` runs the process with its own stdin/stdout; the
receiver is `aws` (Python, `signed:` by Amazon's team or `path:`-pinned).

**`--token-file /dev/fd/N` tools** are not a helper protocol; they are a `file` or `late-env`
case. The README shows `nazar run --late-env X -- tool --token "$X"` is **wrong** (argument →
`ps`), and `tool --token-file ~/.nazar/run/files/X` with `file` is right.

**Dialog text for helpers:**
```
iTerm2 wants secret "GITHUB_PERSONAL_ACCESS_TOKEN"
  via helper → git fetch origin          in ~/projects/foo
  chain: iTerm2 → bash → git → git-remote-https → git-credential-nazar
  Scope: this terminal session, via helper only (expires in 8h)
```

### 6.2 `file`: named-pipe files (FIFOs)

**Setup.** On config load, for every secret with `file` in `deliver`, `secrets.FileServer`
makes sure `~/.nazar/run/files/` is 0700 and `<path>` (always inside that directory, section 4) is
a FIFO with mode 0600 (`mkfifo`). **nazar never unlinks anything that is not already its own
FIFO**: if `<path>` exists and is not a user-owned FIFO, the FileServer refuses to serve that
secret, `config check`/`status` warn ("`<path>` exists and is not a FIFO; move it away"), and
nothing is deleted. Tools are pointed at the path as if it were a regular file.

**One FIFO per delivery.** A FIFO that stays at its path while nazar serves it cannot deliver
exactly once: `open(path, O_WRONLY)` returns immediately whenever *any* process still holds a
read end, so a reader that keeps its fd open after the value (a stream reader, anything that
opens early and reads late) would make the loop re-open at once, find the same reader, hit the
scope cache (or show a second dialog under `scope: use`) and write the value **again**, as many
times as the reader lingers; and the reader itself would never see EOF while a writer is
present. So the pipe nazar writes into is **detached from the path before anything else
happens**, and every delivery goes to a pipe that no process will ever be able to open by name
again.

**Serving loop, one goroutine per FIFO:**
1. `open(path, O_WRONLY)` on a dedicated OS thread (`runtime.LockOSThread`): the open blocks
   until some process opens the FIFO for reading. Returning from `open` is the "a reader is
   here" event. Call the FIFO nazar now holds **P**.
2. **Detach P from the path.** `mkfifo(<path>.<16 hex>, 0600)` in the same directory, then
   `renamex_np(<tmp>, <path>, RENAME_SWAP)` (atomic exchange, APFS): the fresh FIFO is now at
   `<path>` and whatever was at `<path>` is at `<tmp>`. `lstat(<tmp>)` must have the `st_dev`/
   `st_ino` of `fstat(P)`, be a FIFO and be owned by the user; then `unlink(<tmp>)`. If it is
   anything else, something replaced the path between steps 1 and 2: `<tmp>` is left exactly
   where it is (**nazar never unlinks a file that is not its own FIFO**, and the swap destroyed
   nothing), P is closed without writing, the secret stops being served until the user cleans
   up, and `status`/`config check` say "`<tmp>` is not nazar's FIFO; move it away". From here on
   **no process can obtain a read end of P by name**; the only read ends that will ever exist
   are the ones open right now and copies the holder makes itself (`dup`, `fork`,
   `SCM_RIGHTS`).
3. **Identify the openers of P** (spike S9). Scan the user's processes with `proc_listpids(
   PROC_UID_ONLY)`; for each, `proc_pidinfo(PROC_PIDLISTFDS)` and, for each `PROX_FDTYPE_VNODE`,
   `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`; a match is `vip_vi.vi_stat.vst_dev` and
   `vst_ino` equal to the **`fstat` of P** (never a `stat` of the path, which now names a
   different FIFO anyway). This goes behind `Platform.OpenersOf(fd int) ([]Opener, error)`
   (Swift, libproc), returning full refs **with their open flags**, read and write ends alike.
   nazar-agent's own write end is excluded by pid.
4. **Exactly one reader process, no other writer, or nothing happens.** Zero readers (it
   opened and died): close P, go to 1. **Two or more** distinct processes holding a read end, or
   **any other process holding a write end** (it could feed the reader forged data before or
   after our write): close P **without writing**, audit `decision=blocked reason="ambiguous
   openers" chain=<first> extra=<pids>`, show the block warning naming every opener, go to 1.
   A reader that `fork`s with the fd open counts as two processes and is refused too; that is
   deliberate. Every refused opener sees EOF (an empty file).
5. Resolve the reader's chain, run `EvaluateSecret(name, file, chain, chain)`, then
   `broker.Handle`. Readers waiting behind a dialog are simply blocked in their `read`, "as if
   the disk were slow".
6. **Re-scan P immediately before writing.** If the opener set changed (the reader forked or
   passed its fd on), refuse as in 4. Then one `write` of the whole value (≤ 16 KiB, below
   macOS's 64 KiB FIFO buffer so the write is complete before the reader can consume any of
   it), then `close`. The reader reads the value and then EOF. Because P is detached and nazar
   held its only write end, **every later `read` on that fd returns 0** and nothing can ever be
   written into it: a reader that keeps the fd open gets no second value and causes no second
   prompt. Reading the secret again means `open(path)` again, which is a new FIFO, a new
   request and a new decision (the scope cache makes it silent when the rule allows).
7. On deny/timeout/block: `close` P without writing. The reader sees an empty file. Go to 1,
   which blocks on the fresh FIFO until the next reader.

The swap costs one `mkfifo` and one `renamex_np` per delivery. The path is a FIFO at every
instant (the exchange is atomic), so a tool that `stat`s or opens it concurrently sees either
the old or the new FIFO, never a missing file. A reader that opened the **old** FIFO in the
microseconds between step 1 and step 2 is an opener of P and is handled by step 4
(ambiguous, refused, sees EOF); a reader that opens after step 2 blocks on the new FIFO until
nazar returns to step 1. `renamex_np` is macOS 10.12+; Linux has `renameat2(RENAME_EXCHANGE)`.

**Races and what is accepted:**
- *Reader appears, opens, and before step 2 another reader opens:* refused as ambiguous. Both
  retry on their own; a tool that reads once at startup fails once visibly. Accepted. The
  window is step 1 → step 2 (two syscalls), no longer the whole evaluation.
- *A read end of P that no process holds while the scan runs:* a read end opened before step 2
  and parked in flight in an `SCM_RIGHTS` message is not seen by steps 3 or 6. After step 2 no
  new read end can be created by name, so the attacker must have opened P in the step 1 → 2
  window **and** hidden the fd in flight across both scans; the reader's own copies (`fork`,
  `dup` to a child) are caught by step 6. This is the residual gap, documented in section 10;
  `scope: use` + `login` keeps a human in the loop for sensitive `file` secrets. Accepted.
- *Reader opened, our scan is in flight, reader exits, pid reused:* the match is on vnode, and
  the ref is a full `(pid, start time)` ref; `Resolve` of a dead ref fails and the loop
  restarts. Accepted.
- *Reader does `stat` first:* `st_size` is 0 for a FIFO; tools that pre-allocate from size read
  nothing; tools that `read` until EOF work. `mmap` and `lseek` fail with `ESPIPE`/`ENODEV`.
  S9 produces the compatibility table; the hypothesis is: Go `os.ReadFile` ✓ (reads until EOF
  when size is 0), Python `open().read()` ✓, Node `fs.readFileSync` ✓ (chunked read on size 0),
  `curl --netrc-file` ✓ (sequential parse), `kubectl --token-file`/`tokenFile` ✓ (`os.ReadFile`),
  `aws` with `AWS_SHARED_CREDENTIALS_FILE` ✓ but reads on every command (cache absorbs it),
  `gcloud` unknown, anything using `mmap` ✗.
- *Non-blocking readers* (`O_NONBLOCK`) get `EAGAIN` until the value is written; they poll and
  work, or give up early and see an empty file. Accepted.
- *Multiple opens in a row by one tool* are independent requests; the scope cache makes the
  second silent when the rule allows. Multiple `read`s on one open fd are one delivery: value,
  then EOF forever.

**Nothing is on disk in plain text and nothing is in `ps`.** The FIFO survives app restarts;
with the app down, a reader blocks until the app is back or the user interrupts it, which is
the same failure mode as an SSH agent being down and is documented.

### 6.3 `late-env`: set the variable after the program starts

**As built in M10** (decisions D1–D12, below; spike S12, run on Linux and re-checked on macOS by
S14: the per-run socket reached the target behind every launcher tried, fd 3 none behind `npx`,
`pnpm dlx` or `bunx`; `NODE_OPTIONS=--require` fired for CommonJS and ESM targets on Node 20, 22
and 24, under `npx`'s nested `node` too; a dependency's `postinstall` and uv's build hooks ran
the loader before the target, so "the first loader wins" would hand the value to the wrong
process; every launcher worked from `/` and none changed its directory). Where this section and
its subsections say otherwise, this paragraph wins until the deferred parts are built:

- **One form (6.3.5, D3):** `nazar run --secret NAME -- command…`, one `--secret`; `--` is
  required and everything after it is the command's. No `--late-env`, `--env`, `--as`,
  `--target`, `--loader`, `--handover`, `--handover-timeout`, `--dry-run`; no `migrate-mcp`
  (9.1: the README shows the two edits).
- **One handover (D1):** the per-run socket `~/.nazar/run/<32 hex>.sock` (0600 in a 0700 folder
  the agent owns; at most 103 bytes) for interpreters and launchers alike. No pipe, no fd 3, no
  `SCM_RIGHTS`, no `OpenersOf`. Wire: `NAME\tbase64(value)\n`, then EOF, one peer per run.
- **The target (D2):** an interpreter's target is the exec'd process itself (same pid and
  generation, read again at connect: path, code, argv, cwd, environment); `npx`'s is a strict
  descendant running the pinned `node` whose main script is a `bin` of the package the command
  line names (`run.IsBinOf`, the loader's rule in Go). No `--target` and no "first loader wins".
  The rule is a selector, not a boundary (section 10).
- **Kinds (6.3.6, D7):** interpreter `node`, `python3`, `python3.N`; launcher `npx`
  (`npx-cli.js` under `node`). `pipx` and `bun` are refused (S12: `pipx` strips `PYTHONPATH`,
  Bun ignores `NODE_OPTIONS`, so `bunx` is refused too); `uvx`, `uv run`, `pnpm dlx` and `npm`
  are "not in this version"; a binary is refused ("late-env needs node or python"); so are
  `python3 -I`/`-E`/`-S` and `--inspect*`. The npx grammar is `npx [-y|--yes] <package>[@version]
  [args…]`. Shims (mise, asdf, a folder named `shims`, Apple's `xcode-select` shims in
  `/usr/bin`) are refused, never resolved; so is a framework build of Python (a realpath
  `<X>.framework/Versions/<v>/bin/<python>`: Xcode's, Homebrew's), which execs itself again
  (S14). A shebang is `#!/usr/bin/env NAME` without flags or an
  absolute interpreter with at most one argument. `ExecArgv[0]` is the absolute entry path.
- **Receivers (5.1, D4):** the receivers of a rule a run is judged by are `command:` matchers,
  or no `to:` (with the existing warning). A `path:` or `signed:` matcher never
  matches a run's receiver: those are for binary receivers, which have no loader and come with
  `env`; a `command:` matcher pins the interpreter or launcher and the argv tail.
- **Pins (6.3.7, D5):** taken at request time: the image by its code identity and file identity,
  the script and every absolute file element by SHA-256 (64 MiB cap) and identity; a file
  element may not be a symlink. They are part of the approval's receiver identity
  (`match.RunIdentity`: realpath, a digest of the resolution and of the stable environment, the
  argv tail), so changed bytes, another argument or another `envAllow` value ask again. No pin is
  recorded in the Vault, no `config reload`, no two-phase `config apply`. `gate: none` on a secret
  whose `deliver` has `late-env` covers any child of the app the rule names, and warns when `to:` names a launcher: files are still pinned and checked per request, only the prompt goes (owner decision: the dialog showed the same text either way). A pinned file or folder on a volume a process of
  the user mounted (statfs `f_owner` not root: a disk image, a share, a file-system extension)
  is refused, at every pin and re-pin (D12).
- **Folder (6.3.7, D6):** always `/`; `cwd:` is refused by name; a relative file element in a
  `command:` argv is a config error.
- **Environment (6.3.4):** `envpolicy.Build`: `PATH` from `trustedPath`; `HOME`, `USER`,
  `LOGNAME`, `TMPDIR` from the agent's own sources; `LANG`, `LC_*`, `TERM` from the caller when
  plain names; the secret's `envAllow` names with the caller's values; then the loader variables
  `NODE_OPTIONS=--require "<loaders>/node/env.cjs"` or `PYTHONPATH=<loaders>/python` with
  `PYTHONDONTWRITEBYTECODE=1` (Python would otherwise write `__pycache__` beside the
  loader, into the signed bundle; the loader removes it again), `NAZAR_SECRET_NAMES`, `NAZAR_SECRET_SOCK`, `NAZAR_RUN_PID` (the CLI's pid: it execs in place)
  and, for `npx`, `NAZAR_TARGET` (6.3.1; no `NAZAR_SECRET_FD`). The deny set gained `SHELL`,
  `BROWSER`, `EDITOR`, `VISUAL`, `PAGER`, `MANPAGER`, `OPENSSL_*` paths, `SSLKEYLOGFILE` and the
  prefixes `PYTHON`, `NODE_` (but `NODE_ENV`), `VOLTA_`, `NVM_`, `FNM_`, `NODENV_`; names compare
  case-insensitively; a name the caller sends twice is not copied. The CLI does not send denied
  names at all.
- **Flow (6.3 steps 2–7):** the agent resolves, refuses before any prompt what it can, asks
  (`broker.Handle` with `caller.Synthetic(res.Receiver(env))`), and in `Do` opens the value,
  listens, watches the CLI's exec and exit (`platform.Exec.OnProcessExec`, registered before the
  plan is sent), sends the `RunPlan`, and waits 10 s for the exec. The process **as read at the
  exec event** (D10: npm rewrites its argv 42–57 ms later on Linux; on macOS the agent's read came
  first by at least 20 ms in 250 of 250 runs, S14) must be the plan: path, code identity,
  argv, `/`; its startup environment must equal the plan's as a set; every pinned file must be
  unchanged; and no volume may have been mounted or unmounted anywhere on the Mac since a moment
  before the first pin was taken (D12: a mount over a folder hides what it holds without
  changing a pin; `platform.Mounts`, armed in `secretRun`). Then it serves for 120 s: before it
  judges each connection, the CLI's process must still be its one exec (its environment read
  again, which takes any exec still queued); right before the write, the pinned files, the mount
  watch and that again; a
  refused peer is closed unanswered (one `blocked` line per pid, at most 16, then a count) and
  does not consume the handover; a second exec of the CLI or a config change during the prompt
  ends the run. A refusal after the gate is `broker.DeniedError`: `decision=denied`, and the
  approval it ran under is dropped (no `Verify` hook).
- **The CLI (6.3 step 5, 6.3.8):** checks the plan's shape, `lstat`s and opens every pinned file
  `O_NOFOLLOW|O_NONBLOCK|O_NOCTTY` and compares its `fstat`; opens `/` and compares dev/ino, then
  `fchdir`s to it; marks every fd ≥ 3 close-on-exec (`/dev/fd`); `umask 022`; `RLIMIT_CORE` 0/0;
  every signal back to its default (on Linux `signal.Notify` on all and raw `SIG_DFL` for those
  Go never handles; on macOS `SIG_DFL` on every signal still ignored, since `execve` resets the
  handled ones); an empty signal mask on the locked exec thread; on macOS also no Mach
  exception port on the task or the exec thread (`EXC_MASK_ALL | EXC_MASK_CRASH |
  EXC_MASK_CORPSE_NOTIFY` set to `MACH_PORT_NULL` and read back, one cgo call); then `execve`s
  exactly the plan. A step that fails refuses the run. A macOS build without cgo has no reset
  and refuses `nazar run` before asking the agent.
- **Seam (5.1, D8):** an optional `platform.Exec` (`OnProcessExec`, `Environment`), not five
  methods on `Platform`; `LoaderDir` is a daemon option (D9). A daemon without either refuses
  `late-env` before any prompt. **On macOS:** `ExecWatcher`, one kqueue with an `EVFILT_PROC`
  `NOTE_EXEC|NOTE_EXIT` knote per watched process, drained on one serial queue (a poll a signal
  interrupted is retried; one that fails makes `Environment` `ErrUnreadable`; an exec whose
  process can no longer be read at the event is reported as an exec of nothing, which matches no plan). A watch is armed
  first and checked second (the ref's start time must still be the PID's live occupant), so a
  recycled PID is never watched; a PID-only ref is never watched. At every exec the handler
  reads the process before it takes the next event: `KERN_PROCARGS2` first (argv and the
  environment from one read), then `proc_pidpath`, the working directory and the live code
  identity, with the start time checked before and after. The environment parsed from that read
  is kept until the next exec, the exit or the last cancel, and answered only while a watch is
  on: an exec no watch saw is `ErrUnreadable`, never a stale list. `Environment` drains pending
  events before it answers (the kernel posts `NOTE_EXEC` inside `execve`), so an exec that came
  first is always read first. An empty environment cannot be told from a hidden one and is
  `ErrUnreadable` too; so is one over 4096 entries or with an entry over 16 KiB (never cut). The
  kernel's own strings (`apple[]`, `pfz=…` first) follow the environment in that read, with no
  empty string between them when the environment ends on the 8-byte boundary the kernel pads to
  (measured on macOS 27): the environment ends at the last `pfz=…` on that boundary, with only
  padding before it and no run of NULs after it (libSystem zero-fills `pfz=…` as the image
  starts, so such a run means the one found is the environment's own); once `pfz=…` is
  zero-filled, at its first empty string, with only the kernel's string names after it. An empty
  entry never hides the entries after it: anything else there is `ErrUnreadable`. Two
  execs in one moment may be reported as one, read after the later; every record describes the
  image the process runs when read. The C ABI is version 3: three optional callbacks
  (`watch_exec`, `cancel_exec`, `environment`), the status `NZ_UNREADABLE`, and the Go export
  `NazarProcessExecd` that carries each record to Go, where it is queued and given to `fn` in
  order on a goroutine, never after `cancel` returned; a record that does not decode or names
  another instance counts as an exec of nothing. A table without all three callbacks leaves
  `Exec` nil. `LoaderDir` is `<agent>.app/Contents/Resources/loaders`, found from the realpath of
  the agent's own executable, and only when that folder is a real directory. `make agent` copies
  the two loaders there before it signs the bundle. **Mounts (D12):** a second
  optional seam, `platform.Mounts` (`WatchMounts() (changed, stop, err)`), in Go
  (`core/platform/mounts`: one `kqueue` per run with an `EVFILT_FS` knote, `VQ_MOUNT|VQ_UNMOUNT`,
  which the kernel posts inside `mount(2)` and `unmount(2)`); no C ABI change. A daemon without it
  refuses `late-env` before any prompt, as without `Exec`.
- **The mount watch (D12):** a run is refused if any volume was mounted or unmounted on the Mac
  between a moment before its first pin and the write, or if a pinned file or folder is on a
  volume a process of the user mounted (statfs `f_owner` not root). A mount over a folder hides
  what it holds without changing a pin (measured: every pin identical after a disk image was
  attached and detached over the folder), and the folders above a pinned path are not pinned,
  so the watch is global, not per folder. It is armed before the first pin, so it covers every
  moment a pin is relied on without trusting what a user-space file system reports as device
  and inode. `f_owner` is what the kernel recorded when the volume was mounted, which no rename
  changes. A failed `kevent` counts as a change. Cost: any mount during a run (a disk image, a
  Time Machine snapshot) refuses that run; the program starts without the value.
- **Request size (7.3, D11):** `secret.run` may carry up to 128 KiB (`MaxLargeRequestSize`: the
  caller's candidate environment); every other control command keeps 64 KiB.

**Goal:** the secret appears in the target's `process.env`/`os.environ` only after exec, so
`ps eww` and `KERN_PROCARGS2`, which show the *startup* environment, never see it.

**Flow of `nazar run --late-env BRAVE_API_KEY --target brave-search-mcp-server -- npx -y @brave/brave-search-mcp-server`:**

1. The CLI parses its flags. It does **not** resolve `argv[0]`: what runs is decided by the
   app (6.3.6), and the caller's `$PATH` plays no part in it. It does **not** build the target's
   environment either: that is the app's (6.3.4). Nor does it choose, or send, the target's
   working directory: the app does (6.3.7), from the matched receiver entry, and when that entry
   says `cwd: caller` the app reads the CLI's directory from `ProcessInfo.Cwd`, not from the
   request. It collects its own environment as **input**
   for the app, minus the deny set and the base names of 6.3.4, which the app would ignore in
   any case (`envpolicy.CandidateEnv`). `--loader` and `--handover` are sent as overrides for
   the app to apply; `--dry-run` asks the app for the plan without a gate (`go: false`) and
   prints it, including what the caller's `$PATH` *would* have picked when that differs
   (`note: your PATH has /tmp/x/npx first; nazar would run
   /Users/you/.local/share/mise/installs/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js`) and
   the environment the target will get (`env:` the full list, `envDropped:` the caller's
   variables that are not passed), the directory it will run in (`cwd: /`, or the pinned one
   with its source) and the files pinned against it (`pinnedFiles`).
2. The CLI creates `pipe()` and sends `secret.run` over the control socket with `{names, as,
   method: late-env, argv, target, callerEnv: <candidate environment>, loaderOverride?,
   handoverOverride?, handoverTimeout?}` **and the pipe's write end as an `SCM_RIGHTS`
   ancillary fd**. The pipe is always created, because the handover is the app's decision; if
   the plan says `socket`, both sides close their ends.
3. The app verifies the control peer is the genuine `nazar` CLI (7.3), resolves its chain
   (`apps:`), **resolves the receiver** (6.3.6): `argv[0]` → `resolvedPath` (absolute realpath),
   `resolvedCode` (`InspectCode`), `resolvedFile` (`st_dev`, `st_ino`, `st_size`, `st_mtim`), and
   for a script its pinned interpreter with its own `interpreterFile`; classifies the receiver
   (`receiverKind`) by the **realpath base name** of what it resolved, through a fixed table in
   `core/secrets/run`, never by the typed `argv[0]`: **launcher** = `npx-cli.js`, `npm-cli.js`
   (the realpaths of npm's `bin/npx` and `bin/npm`), `pnpm.cjs`, `bun` when the `trustedPath`
   entry that resolved was named `bunx` or `argv[1]` is `x`, `uv`, `uvx`, `pipx`; otherwise
   **interpreter** = `node` and `python3*`/`python*` binaries, or a script whose pinned
   interpreter is one (the launcher table is consulted first, so `npx-cli.js` under `node` is a
   launcher, `server.js` under `node` is not); otherwise **binary** (`deploytool`, `gh`). The loader
   set follows the family (Node for `node`,
   `npx-cli.js`, `npm-cli.js`, `pnpm.cjs`, `bun`; Python for `python*`, `uv`, `uvx`, `pipx`), and the
   **handover** is `fd` for an interpreter, `socket` for a launcher (6.3.2). Then it pre-checks
   `to:` statically against `resolvedPath` + `resolvedCode` + the argv tail (5.2). A `mismatch`
   is refused **here, before any prompt** (`blocked`, reason `receiver /tmp/x/npx does not match
   to: [brave-mcp]`, block warning), so the user is never asked to approve a run the app already
   knows it would deny. With the receiver entry known it **chooses the working directory**
   (6.3.7): `/` unless the entry has `cwd:`; the entry's pinned directory; or, for `cwd:
   caller` on a `binary` receiver, the peer's `ProcessInfo.Cwd` realpath'd (`cwd: caller` on
   anything else is refused here: `blocked`, reason `cwd: caller is not allowed for an
   interpreter`). It re-checks every pin the matcher carries, which are the **recorded** pins
   of 6.3.7, against the files as they are now: the executable and interpreter (`resolvedPath`
   and its code and identity must equal the recorded ones; `blocked reason="receiver changed:
   npx-cli.js"` otherwise), every **file element** pinned against that directory (`server.js`
   must still be the regular file with the pinned hash; `blocked reason="receiver changed:
   server.js"` otherwise) and, for a launcher with an absolute `cwd:`, the **context pin**
   (`blocked reason="receiver context changed: node_modules appeared in /Users/you"`). An entry
   with **no recorded pins** matches nothing (`blocked reason="receiver brave-mcp has no
   recorded pins; run nazar config apply"`). All of this happens before the approval cache is
   read, so a cached `scope: session` approval never serves changed bytes.
   Then it **builds the target's environment** (6.3.4) from its own base
   set, the matched secrets' `envAllow` lists applied to `callerEnv`, and the loader variables
   from its own bundle; evaluates `deliver`; prompts if needed (the summary line names the
   `envAllow` variables the caller supplied, if any, and the directory: `in /`, `in
   ~/projects/foo`, or `in ~/projects/foo (the caller's folder)`); opens the secret into
   memory. Refusal → `Problem{refused}` → CLI exits 3 with the reason on stderr; nothing is
   exec'd.
4. The app replies `RunPlan{go: true, receiverKind, resolvedPath, resolvedFile,
   pinnedInterpreter?, interpreterFile?, execArgv, cwd, cwdFile, cwdSource, pinnedFiles,
   handover, loaders, env, envDropped, deadline, socket?}`. `execArgv` is the argv the CLI must
   exec: `[<name of the entry that resolved>, <argv[1:]…>]` for a binary, or `[<interpreter
   name>, <shebang flags…>, <resolvedPath>, <argv[1:]…>]` for a script (6.3.6); `execArgv[0]`
   is derived by the app (6.3.8), never the caller's string. `cwd` is the **absolute realpath
   of the working directory** the CLI must enter (6.3.7), `cwdFile` its `{dev, ino}`,
   `cwdSource` ∈ `default`/`receiver`/`caller`, and `pinnedFiles` the file elements with their
   hashes, for `--dry-run` and the dialog.
   `env` is the **complete** environment the CLI must exec, every entry chosen by the app
   (6.3.4): the base (`PATH`, `HOME`, `USER`, `LOGNAME`, `TMPDIR`, `LANG`/`LC_*`/`TERM` when the
   caller had valid ones), the `envAllow` variables with the caller's values, and the loader
   variables: `NAZAR_SECRET_NAMES=BRAVE_API_KEY` (comma-separated when several),
   `NAZAR_TARGET=<pattern>` (if given), `NAZAR_SECRET_FD=3` or `NAZAR_SECRET_SOCK=<path>`, and
   `NODE_OPTIONS=--require <nazar-agent.app>/Contents/Resources/loaders/node/env.cjs` and/or
   `PYTHONPATH=<nazar-agent.app>/Contents/Resources/loaders/python`, with the paths of the **app's own
   bundle**, never taken from the request. For `socket` the app has created and is listening on
   `~/.nazar/run/<32 hex>.sock` (0600) until `deadline` (6.3.2).
5. The CLI refuses to continue unless `go` is true and `resolvedPath` (and `pinnedInterpreter`,
   if any) and `cwd` are absolute. It **enters the working directory first**: `open(cwd,
   O_RDONLY|O_DIRECTORY|O_CLOEXEC)`, `fstat` must equal `cwdFile` (`exit 1: working directory
   changed between approval and exec` otherwise), `fchdir(fd)`, `close` (6.3.7); the process
   is now in the directory the app approved, not in one swapped in behind the name. It
   `open`s the file it is about to exec with
   `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` (6.3.7, "Reading attacker-writable files
   safely"), `fstat`s it, requires `S_IFREG` and requires `st_dev`, `st_ino`, `st_size` and
   `st_mtim` to equal the plan's values: for a binary, `resolvedPath` against `resolvedFile`;
   for a script, **both** the interpreter (`pinnedInterpreter` against `interpreterFile`) and
   the script (`resolvedPath` against `resolvedFile`, the file the interpreter will read). A
   difference in either is `exit 1: receiver changed between approval and exec`. It then
   **resets the inherited process state** (6.3.8): `FD_CLOEXEC` on every fd ≥ 3 except the
   pipe read end it `dup2`s to 3 for an `fd` handover (clearing `CLOEXEC` on that one only),
   `umask(022)`, `RLIMIT_CORE` to `{0, 0}`, an empty signal mask with every catchable signal
   at `SIG_DFL`, and null Mach exception ports. It passes
   **`RunPlan.env` as the environment, verbatim and complete** (it adds nothing; `--as` renames
   are already applied by the app in `NAZAR_SECRET_NAMES`), closes the pipe's write end, and
   `execve`s **that absolute path** with
   `execArgv`: never `execvp`, never a bare name, so neither the CLI nor the kernel ever
   consults `$PATH`. `nazar run` is gone; no nazar process outside the app ever held the
   plaintext. macOS has no `fexecve`, so the opened fd cannot itself be exec'd; the window
   between the `fstat` and the kernel's own open is microseconds, and for `late-env` step 6
   closes it anyway. (S16 checks whether `execve("/dev/fd/N")` works for Mach-O binaries; if it
   does, the CLI uses it for binary receivers and the window is gone for `env` too.)
6. The app, which registered `OnProcessExec(cliRef)` before replying, watches the **exec
   chain** of that pid (6.3.3). Because the CLI expands the shebang itself and shims are refused
   at resolution, the first exec is normally the final hop. When the chain settles it
   re-resolves the chain from that ref, evaluates `to:` **live** with `match.Evaluator.Receiver`
   against the pinned file (for a script receiver this includes **re-hashing the script's bytes**
   and re-`stat`ing it against `resolvedFile`, 6.3.3 (b); for every pinned file element and the
   context pin, the same re-hash and re-walk, 6.3.7), requires the process's working directory
   (`ProcessInfo.Cwd`, realpath'd) to equal `RunPlan.cwd`, compares the process's **whole**
   startup environment (`Platform.Environment`) with `RunPlan.env`: the same names, the same
   values, nothing missing and nothing extra (6.3.4), and for `fd` checks with
   `OpenersOf(writeEnd)` that the pipe's read end is held by **exactly the exec'd pid** (a
   malicious client that forked a child keeping the read end, or passed it on, is caught here;
   pipe identity is exact, which is why this is the one fd fact the app verifies, 6.3.8). It
   does **not** count or list the receiver's other fds: by now the image has opened its own
   (libuv's kqueue and wakeup pipe before any JS runs), and nothing read after exec tells those
   from inherited ones; the inherited ones are gone by the CLI's `FD_CLOEXEC` sweep (6.3.8).
   Any mismatch, **including an argv, environment or directory that cannot be read**,
   → close the write
   end/stop listening without writing, audit `denied reason="receiver changed at exec"` (or
   `"unexpected environment: npm_config_script_shell"`, naming the first differing variable,
   `"receiver changed at exec: cwd /tmp/e"`, `"receiver context changed: …"`, `"pipe
   shared"`), block warning. A match → write and close (`fd`), or accept the
   verified connection and write (`socket`, 6.3.2).
7. The app zeroes its plaintext copy. If the chain does not settle within 10 s (the CLI died,
   or was not really going to exec), the pipe is closed unwritten and the audit line says
   `error reason="target never exec'd"`.

**Wire format on the fd or socket:** one line per secret, `NAME\tbase64(value)\n`, then EOF.
Base64 keeps newlines and arbitrary bytes safe; several `--late-env` flags are one handover.

#### 6.3.1 Loaders

**As built in M10** (6.3 "As built in M10"): the variables are `NAZAR_SECRET_NAMES`, `NAZAR_SECRET_SOCK`, `NAZAR_RUN_PID` and, for `npx`, `NAZAR_TARGET`; no `NAZAR_SECRET_FD` and no `--target` substring. The loader takes **only the names asked for** (`NAZAR_SECRET_NAMES`), each once, and refuses a value that is not strict UTF-8 or holds a NUL.
**Where they are:** `nazar-agent.app/Contents/Resources/loaders/node/env.cjs` and `…/python/sitecustomize.py`, copied by `make agent` before the bundle is signed, so its seal covers them; `scripts/check-agent.sh` refuses a bundle whose `loaders` folder is not exactly those two plain files, byte-identical to the repository's. nazar-agent does not rely on that seal when a receiver runs (macOS checks a bundle's resources only when Gatekeeper first assesses it): its own code embeds both loaders (`package loaders`), and for every run it requires the loader file to be byte for byte its copy and the loader's folder to hold nothing else (CPython imports a package, an extension or cached bytecode found beside its loader first), and pins every folder above the loader's that a process of the user can move, one in a folder the user can write or owns (`loaders`, `Resources`, `Contents`, `nazar-agent.app`, `~/Library/nazar`, `~/Library`; not `~`, in root's `/Users`): moving a folder changes only its own ctime, so a loader swapped by moving a folder above it aside and back would otherwise still match, and the swap needs to land only between the check at the exec and the interpreter's read of its loader, with the put-back left to the attacker's loader, which is the one that connects. It checks the file and all those folders again at the exec and right before the write, as it does the receiver's own files; a change is `receiver changed at exec: nazar's loader changed`. The Python loader takes its folder off `sys.path` before any import of its own, so a module put there after that last check is never imported. A Python receiver also gets `PYTHONDONTWRITEBYTECODE=1`, which the loader removes with the `NAZAR_*` variables, so the receiver writes no bytecode of its own and its children write theirs as usual.

Both loaders are tiny, dependency-free, and copied into
`nazar-agent.app/Contents/Resources/loaders/`. They are plain files, not a package the target has to
install; `nazar run` injects them by absolute path.

**Node — `loaders/node/env.cjs`** (CommonJS so `--require` works for ESM and CJS targets):
0. `if (!require("worker_threads").isMainThread) return;` — the worker thread used in step 3
   inherits `execArgv`/`NODE_OPTIONS`, and must not run the loader again and race for the
   single accepted connection. The worker is also started with `env: SHARE_ENV` so the main
   thread's `delete process.env.NAZAR_*` is what it sees.
1. Read `NAZAR_SECRET_NAMES`, `NAZAR_TARGET`, `NAZAR_SECRET_FD`, `NAZAR_SECRET_SOCK`. If none,
   return.
2. **Target match:** `cmdline = [process.argv[1] ?? "", ...process.argv.slice(2)].join(" ")`,
   plus `process.execPath` base name. The process **matches** if `NAZAR_TARGET` is unset, or is
   a substring of `cmdline`. A non-matching process (`npx` itself) does nothing: it leaves the
   `NAZAR_*` variables and `NODE_OPTIONS` intact so its child gets them, and leaves fd 3 alone.
3. **Read:** `fd` → `fs.readFileSync(fd)` (blocks until the app writes, at most the broker
   timeout), then `fs.closeSync(fd)`. `socket` → `net.connect(path)` with a synchronous drain
   via `Atomics.wait` on a `SharedArrayBuffer` fed by a worker thread, so the value is in
   `process.env` **before the target's first line runs** (an async loader would race the
   server's startup). Any read error → write one line to stderr (`nazar: secret X not
   delivered: <reason>`), **do not** set the variable, continue starting the program.
4. Set `process.env[NAME] = value` for each line; delete `NAZAR_SECRET_NAMES`, `NAZAR_TARGET`,
   `NAZAR_SECRET_FD`, `NAZAR_SECRET_SOCK`; remove `--require <this file>` from
   `process.env.NODE_OPTIONS` (delete it if empty), so children of the target do not run the
   loader again.
5. Overwrite the buffer, drop references.

**Python — `loaders/python/sitecustomize.py`:**
1. Same variables, same match rule on `" ".join(sys.orig_argv[1:])` (`sys.orig_argv`, 3.10+;
   falls back to `sys.argv`).
2. `fd` → `os.read` loop until EOF, `os.close`. `socket` → `socket.socket(AF_UNIX)`,
   `connect`, `recv` loop. Blocking is natural here; `site` runs before `__main__`.
3. `os.environ[NAME] = value` (which also `putenv`s, so C extensions see it); delete the
   `NAZAR_*` entries; strip `<loaders>/python` from `PYTHONPATH` and `sys.path`.
4. **Hand-over:** remove this directory from `sys.path`, `del sys.modules["sitecustomize"]`,
   `importlib.import_module("sitecustomize")` inside `try/except ImportError`, so a
   virtualenv's or distro's `sitecustomize` still runs.
5. Limits: `-S` skips `site` (so no `sitecustomize`), and `-E` and `-I` (which implies `-E`
   and `-s`) ignore `PYTHONPATH`, so with any of the three the loader never loads.
   `PYTHONNOUSERSITE`/`-s` do not matter (the loader is not in user site). `nazar run` scans
   the interpreter flags in argv for `-S`, `-E`, `-I` (also combined, `-ES`, `-IS`) and
   refuses `late-env` with a clear message; such targets fall back to `env`. Flags inside a
   script's shebang (`#!/usr/bin/python3 -I`) are not visible in argv: the app's post-exec
   check reads the final hop's real argv (6.3.3), where the kernel has appended the shebang
   flags, and refuses there with `receiver changed at exec: interpreter flag -I`.

**Interpreter versions:** Node ≥ 18 (`--require` with `NODE_OPTIONS`, `Atomics.wait` on the
main thread), CPython ≥ 3.9. Tested with Node 24 and Python 3.14.

#### 6.3.2 Launchers: `npx`, `uvx`, `pipx`, `uv run`, `pnpm dlx`, `bunx`

**As built in M10:** only `npx` (D7); `pipx` is refused (it strips `PYTHONPATH`), `uvx`, `uv run`, `pnpm dlx` are "not in this version", `bunx`/`bun` are refused as Bun ("Bun ignores NODE_OPTIONS"). The npx target grammar is `npx [-y|--yes] <package>[@version] [args…]` (a scoped or plain npm name; the version does not start with `.`); the target is the package name without its version (D2).

A launcher is a Node or Python program whose **child** is the real target. If the launcher read
the secret it would hand it to the child as a startup variable, visible again. Hence
`--target`, and hence the handover question:

| Launcher | How it starts the child | Does an inherited fd 3 survive? (S12 verifies) |
|---|---|---|
| `npx`/`npm exec` (Node, libuv) | `uv_spawn` → `posix_spawn` with `POSIX_SPAWN_CLOEXEC_DEFAULT` on macOS (libuv ≥ 1.45) | **Expected no**: every fd not in `stdio` is closed |
| `pipx run` (Python) | `subprocess` with `close_fds=True` (default since 3.2) | **No** |
| `uvx`/`uv run` (Rust) | `std::process::Command` → `posix_spawn` without `CLOEXEC_DEFAULT`; Rust marks only its own fds `CLOEXEC` | **Expected yes**, but not relied on |
| `pnpm dlx`, `bunx` | libuv / Bun's own spawner | Unknown |

**Decision:** the app chooses the **`socket` handover whenever the resolved receiver (6.3.6)
is a known launcher** (list above, extendable with `--handover socket`), and `fd` for a direct
interpreter. The socket survives any spawner because it is a *path*, found through the
environment, which launchers pass through. The environment entry `NAZAR_SECRET_SOCK` is not a
capability: the app **writes to exactly one connection**, and only if the connecting peer's
chain **contains the exec'd pid** (so it is a descendant of this run, or that process itself),
its argv **matches `--target`**, and the peer **passes `to:`** (a `command:` matcher on the
launcher's argv is satisfied by the launcher being in the chain; a `signed:`/`path:` matcher is
evaluated on the connecting process). **A rejected peer does not consume the accept**: its
connection is closed, one audit `blocked reason="unexpected socket peer" chain=<peer>` line is
written (coalesced per pid, with a count, so a connect loop is one line), and the app keeps
accepting until a peer verifies or the deadline passes. Otherwise any process of the user that
watches `~/.nazar/run/` and connects first could deny the target its secret every time. After
the one verified write the socket is closed and unlinked; later connects fail with `ECONNREFUSED`/`ENOENT`.

**What the socket rules do not check:** the connecting descendant's environment and the
program it is. The launcher built that process: its argv, its `PATH` (`node_modules/.bin`
prepended: the `node_modules` of the project the launcher found by walking up from **its
working directory**), its `npm_*` variables, and which package it runs. The environment,
working-directory and fd checks of 6.3.4, 6.3.7 and 6.3.8 apply to the **launcher** (the
exec'd pid), so everything the launcher decides is decided from inputs nazar fixes (its startup
environment, allowlisted; its working directory, `/` unless the receiver entry pins another;
its fd table, stdio only, by the CLI's `FD_CLOEXEC` sweep; its argv, the pinned tail) or does not control and says so (its
config files under `HOME` and inside its own install tree, and, when the entry has a `cwd:`,
that directory's `node_modules`; 6.3.7, section 10). That is why `--target` is a substring
filter, not a security boundary, and why a `command:` receiver through a launcher is weaker
than a `path:`/`signed:` receiver on the program itself.

**Deadline.** The handover `deadline` is a `RunPlan` field, default **120 s** (not
`defaults.timeout`, which is the dialog deadline: a cold `npx -y` download of the Brave server
on first run can take longer than a dialog should), overridable with `--handover-timeout <dur>`
up to 10 min. The CLI's own flag only lengthens how long the app holds the opened plaintext in
memory for this run; nothing else depends on it. At the deadline the app zeroes the value,
unlinks the socket and audits `error reason="target never connected"`; the loader in the target
then reports `nazar: secret X not delivered: connection refused` on stderr and the program
starts without the variable. The 10 s limit of step 7 is separate: it bounds the time until the
CLI's `execve` is seen, which does not depend on any download.

**Without `--target`,** the first loader to run reads the handover. For `node server.js` and
`python3 app.py` that is right. For a launcher without `--target`, `nazar run` warns on stderr
(`npx will receive the secret itself and pass it to its child in the startup environment; add
--target`) and proceeds only if `env` is in the secret's `deliver`, because that is what the
result amounts to.

**Documented limit:** processes that the *target* starts later inherit the variable as an
ordinary startup variable. The loader cannot prevent that, and `ps eww` on those children
shows it.

#### 6.3.3 `command:` receivers: pinned executable and the exec chain

`argv`, including `argv[0]`, is chosen entirely by whoever calls `execve`
(`exec -a npx /tmp/evil`, or a `/tmp/x/npx` earlier on `PATH`). So a `command:` matcher is
**never** satisfied by argv alone; it is bound to an executable the way `path:` apps are:

- **Resolution at config load.** `command: [npx, -y, pkg]` resolves `npx` with the **same
  resolver `nazar run` uses at request time (6.3.6)**: through `defaults.trustedPath` (default
  `/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin`; the user adds directories
  such as a mise install's `bin/`; the caller's `PATH` is never consulted), then `realpath`, so
  the **pinned path is always the realpath of a regular file**
  (`…/node/24.0.0/bin/npx` → `…/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js`). The pin
  is `cdhash` for a signed binary, `sha256` of the file for an unsigned file (scripts). If the
  pinned file is a script, its shebang is parsed (6.3.6), the interpreter (`/usr/bin/env node`
  → `node` through `trustedPath`) is resolved and pinned the same way. A `command:` whose
  `argv[0]` is an absolute path skips the PATH step; a relative `argv[0]` with a slash
  (`./bin/server`) is a config error, because there is no caller directory to resolve it
  against (6.3.7). **File elements** of `argv[1:]` (`server.js`, `./setup.cjs`, 6.3.7) are
  resolved against the entry's `cwd:` and pinned by realpath and `sha256` alongside the
  executable; a relative one without an absolute `cwd:` is a config error. **Shims are
  refused**: if resolution lands
  on a symlink to `mise`, `asdf` or `rtx`, `config check` warns "npx resolves to a mise shim;
  use `mise which npx` and pin the real path or add its directory to `defaults.trustedPath`"
  and the entry is unresolvable (stale or, with no record, inactive; 6.3.7), like any other
  filesystem finding: the text stays valid, the entry matches nothing until it resolves.
  `migrate-mcp` does this de-shimming itself (it runs `mise which`/`asdf which` when it sees a
  shim) and prints the real path in the suggested `trustedPath` and `command:`. What this
  step produces is the **observed** pin set of the entry. The pin that is **in force** is the
  one **recorded** in the Vault for the entry's key when a `login` dialog showed it (6.3.7,
  "Recording and refreshing the pins"); a load compares the two and a difference, the
  executable's and the interpreter's included, is a loosening change. Nothing about `npx-cli.js`
  or `node` is ever pinned because a load saw it; it is pinned because the user approved it.
- **Exec chain.** The CLI `execve`s the pinned file directly, or, for a script, the pinned
  interpreter with the script's realpath as its argument (6.3.6), so the `/usr/bin/env` hop of
  a `#!/usr/bin/env node` script **never occurs** and the kernel's shebang handling is not
  involved. The app therefore expects the **first exec** of the watched pid to be the final
  hop and accepts it only if: (a) for a binary receiver, `ProcessInfo.Path` (realpath, from
  `proc_pidpath`) equals the pinned path and the code identity equals the pin; (b) for a
  script receiver, `ProcessInfo.Path` equals the pinned interpreter's realpath, its code
  identity equals the interpreter's pin, and argv is `[*, <shebang flags…>, <script path>,
  <matcher argv[1:]>…]` where the **script path element is `realpath`'d before comparison**
  with the pinned path (an element that does not resolve is a mismatch), **the script's bytes
  are read and hashed again at this moment** and must equal the `sha256` pin, its `stat` must
  equal `resolvedFile` (the pre-check of 6.3 step 3 happened before the dialog; this check is
  the last thing before the write, so the window in which a swapped script could receive the
  value shrinks from the whole dialog to the interpreter's own read of the file, section 10),
  and the shebang flags are checked against the loader's flag rules (6.3.1). The **normalised
  argv tail** is the
  argv elements after the script path (script) or after `argv[0]` (binary), compared byte for
  byte to `matcher argv[1:]`: no re-quoting, no trimming, no globbing, no case folding. Any
  other image at the first exec (`/usr/bin/env`, a shim, anything else), a pid exit, or **an
  argv that cannot be read** is `receiver changed at exec`. `OnProcessExec` keeps firing until
  cancelled (5.1); a *second* exec of the same pid before the handover completes is a mismatch
  for `fd` (the pipe would reach something unverified) and, for `socket`, is accepted only if
  the new image passes the socket-peer rules of 6.3.2 like any descendant would (a launcher
  that `exec`s its tool rather than spawning it).
- **What the audit line shows:** `receiver="/Users/you/.local/share/mise/installs/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js -y @brave/brave-search-mcp-server"`,
  the pinned realpath and the tail. It is the same string however the user spelled the
  command (`npx`, `…/bin/npx`, the realpath), because both the pin and the comparison are on
  realpaths.
- **What this closes:** a prompt-injected Claude Code or malware editing `~/.claude.json`
  cannot point the rule at another program by naming it `npx`; the file at the pinned path,
  with the pinned hash, must be what runs. **What it does not close:** what that genuine `npx`
  decides to run, which it reads from its startup environment (allowlisted, 6.3.4), its
  working directory (`/` unless the entry pins one, 6.3.7) and its config files under the
  user's home and inside its own install tree (`~/.npmrc`: `registry`, `script-shell`; not
  pinned, section 10).

#### 6.3.4 The target's startup environment

The caller's environment is the one input to the receiver that a caller in an approved scope
controls completely, and it can hook the receiver in more ways than any list of names covers:
code loading (`NODE_OPTIONS=--require`, a `sitecustomize` on `PYTHONPATH`,
`DYLD_INSERT_LIBRARIES` on a non-hardened `node`, `PYTHONSTARTUP`, `BASH_ENV`), and, for a
launcher, **the launcher's own configuration namespace**: `npm_config_script_shell=/tmp/x.sh`
makes the genuine pinned `npx` run the package bin through `/tmp/x.sh`, which then connects to
the handover socket as a descendant of the exec'd pid with the target substring in its argv and
passes every socket rule of 6.3.2; `npm_config_registry=http://127.0.0.1:4873` (npm reads
`npm_config_*` and `NPM_CONFIG_*` alike) makes `-y` fetch "latest" from the caller's registry;
`HOME=/tmp/h` with a planted `.npmrc` does both; `XDG_CONFIG_HOME` redirects `pip.conf` and
`uv.toml`; `PIP_INDEX_URL`, `UV_INDEX_URL`, `PIPX_HOME`, `UV_PYTHON`, `VIRTUAL_ENV` are the
Python equivalents. A denylist is always one variable short of this. So the receiver's
environment is an **allowlist, and the app builds it**; the caller's environment is input the
app picks from, never a base the app corrects.

- **The base set, built by the app** (`envpolicy.Base`). Each entry is there because receivers
  break without it, and each value comes from a source the caller does not control:
  - `PATH` = `defaults.trustedPath` joined with `:`, in order. The receiver and its children
    find programs through it (`npx` runs the package bin with `sh -c`, `pipx` finds `python`);
    a caller-chosen `PATH` would make `/tmp/x/node` what the genuine `npx` spawns. These are
    the directories the user already declared trustworthy for exactly this purpose (6.3.6),
    which is why changing `trustedPath` is a loosening change (section 4). A receiver that
    needs a program from elsewhere fails with the program's own "command not found"; the fix
    is adding that directory to `trustedPath`, with its `login` gate.
  - `HOME` = the home directory of the peer's uid from `getpwuid`, never the caller's value.
    Nearly every program fails or misbehaves without it, and a caller-chosen `HOME` is a
    universal configuration redirect (`.npmrc`, `pip.conf`, `uv.toml`, `.gitconfig`). The
    consequence is stated below: the receiver reads **the user's real** config files.
  - `USER`, `LOGNAME` = the passwd name of the same uid. Tools use them for cache paths and
    identity; pinned, they cannot name another user.
  - `TMPDIR` = `confstr(_CS_DARWIN_USER_TEMP_DIR)` as the app sees it (the control socket
    requires the same uid, so it is the caller's user's directory): a 0700 per-user directory.
    A caller-chosen `TMPDIR` would put the receiver's temporary files (Python `tempfile`, `uv`
    build directories) in a directory the caller prepared.
  - `LANG`, `LC_*` and `TERM`: **copied from the caller** only if the value matches
    `^[A-Za-z0-9_.@+-]{1,32}$` (or is `C`/`POSIX`); otherwise omitted. They decide message
    encoding, Python's filesystem encoding and terminal rendering for the `deploytool`/`gh`-style
    wrappers; their only consumers are libc's locale tables and terminfo, so a shape-checked
    value cannot name code. (ncurses also reads `~/.terminfo`, which is a `HOME` file like the
    others below.)
  - Nothing else. Not `SHELL` (a program that runs commands through `$SHELL` is the class this
    section closes), not `SSH_AUTH_SOCK`, not `HTTP(S)_PROXY`, not `NODE_ENV`, not `__CF_*`
    or `XPC_*`. A receiver that needs one of these gets it through `envAllow`, so the need is
    written in the approved config.
- **Per-secret additions, `envAllow:`** (section 4). The variables listed on a secret are
  copied from the caller's environment **with the caller's value**; the list is approved
  config, adding a name is a loosening change shown in the `login` diff, and the `nazar run`
  dialog's summary line names the ones the caller actually supplied (`env from caller:
  HTTPS_PROXY`), as does the audit line (`envPassed=`, names only). When one run delivers
  several secrets, a variable passes only if **every** requested secret allows it: a secret
  must never be delivered into an environment its own entry did not sanction. `envAllow` can
  never name a member of the deny set or a base name (config error), and `--as` refuses to
  target an `envAllow` name (7.1), so one variable has one source. There is no
  CLI flag that adds a variable, so a caller cannot widen the list, and `migrate-mcp` never
  emits one: a server definition's `env` block that holds a non-secret (`BRAVE_MCP_LOG_LEVEL`)
  is printed as a **suggested** `envAllow` line with a comment, for the user to accept.
- **The deny set** (`envpolicy.Deny`): names that no mechanism, `envAllow` or `--as`, may put
  in a receiver's environment, because each one loads code, changes which program runs, or
  redirects configuration or TLS trust. By prefix: `NAZAR_`, `DYLD_`, `LD_`, `npm_config_`,
  `NPM_CONFIG_`, `PNPM_`, `BUN_`, `COREPACK_`, `YARN_`, `PIP_`, `PIPX_`, `UV_` (libuv's
  `UV_THREADPOOL_SIZE` is collateral, accepted), `PYENV_`, `MISE_`, `ASDF_`, `RTX_`, `XDG_`,
  `GIT_`, `SSL_CERT_`. By name: `NODE_OPTIONS`, `NODE_PATH`, `NODE_REPL_EXTERNAL_MODULE`,
  `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONPATH`, `PYTHONHOME`,
  `PYTHONSTARTUP`, `PYTHONINSPECT`, `PYTHONEXECUTABLE`, `PYTHONUSERBASE`,
  `PYTHONPYCACHEPREFIX`, `PYTHONPLATLIBDIR`, `PYTHONHTTPSVERIFY`, `VIRTUAL_ENV`,
  `CONDA_PREFIX`, `BASH_ENV`, `ENV`, `ZDOTDIR`, `SHELLOPTS`, `BASHOPTS`, `PERL5OPT`,
  `PERL5LIB`, `PERLLIB`, `RUBYOPT`, `RUBYLIB`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
  `JDK_JAVA_OPTIONS`, `CLASSPATH`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`. Matching is
  **case-insensitive** (npm itself reads its namespace that way, and over-refusing is free).
  The set is a Go constant in `core/secrets/envpolicy`, shared by app and CLI; `config check`
  names the entry an `envAllow` name matched. Because the environment is an allowlist, the deny
  set is not what protects the receiver; it is what stops the user from being talked into an
  `envAllow` line that would. What a target legitimately needs from these variables goes into
  **argv** instead (`node --max-old-space-size=4096 server.js`, `python3 -X dev app.py`, `-r
  ./setup.cjs`), where it is part of the pinned command line, shown in the prompt and in the
  audit line. The virtualenv's own `sitecustomize` still runs because it lives in
  `site-packages`, not on `PYTHONPATH`.
- **Proxies and TLS trust.** `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` are not in the
  base, so by default the receiver's outbound path is the receiver's own business, read from
  its config files like everything else. A user who lists `HTTPS_PROXY` in `envAllow` accepts
  that the caller chooses the proxy; the TLS-trust variables that would let that proxy read the
  traffic (`NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `SSL_CERT_*`,
  `REQUESTS_CA_BUNDLE`, `PYTHONHTTPSVERIFY`, `GIT_SSL_NO_VERIFY`, `npm_config_strict_ssl`,
  `UV_INSECURE_HOST`) are in the deny set, so a caller cannot turn an allowed proxy into an
  interception point through the environment. Through `~/.npmrc` (`strict-ssl=false`,
  `cafile=`) it can, which is the config-file limit below.
- **The app checks, three times.** (1) At config load, `envAllow` is validated against the
  deny set and the base names (section 4); a bad entry is an **error**, so the active config
  can never carry one. (2) The plan's `env` is computed entirely by the app: base values from
  passwd/`confstr`/`trustedPath`, pass-through values after the shape check, `envAllow`
  values from `callerEnv`, loader variables from its **own bundle path**; nothing in the
  request chooses a name, and the CLI execs `RunPlan.env` verbatim (6.3 step 5). The CLI
  applies the same filter to what it sends (`envpolicy.CandidateEnv`, dropping the deny set
  and the base names), as a courtesy to the request size, and the app never relies on it. A
  caller variable that is not passed is dropped **silently**: a `NODE_OPTIONS` set by `direnv`
  in the shell Claude Code runs in must not make every MCP server start fail; `--dry-run`
  lists them in `envDropped`. (3) After the final exec hop the app reads the target's startup
  environment with `Platform.Environment(ref)` and refuses to write unless it equals
  `RunPlan.env` **as a whole**: the same set of names, each with the plan's value, nothing
  missing, nothing extra; `denied reason="unexpected environment: <first differing name>"`.
  Nothing on macOS adds to an `execve`d environment, so an exact comparison is the right one;
  the launcher's descendants build their own environments and are not the exec'd pid (6.3.2).
- **What remains open, stated plainly.** A launcher receiver reads configuration files under
  the real `HOME` that the allowlist deliberately keeps real: `~/.npmrc` (`registry`,
  `script-shell`, `cafile`, `strict-ssl`), `~/.config/pip/pip.conf`, `~/.config/uv/uv.toml`,
  `~/.pypirc`, `~/.gitconfig`, `~/.terminfo`, and the npm cache `~/.npm/_npx`; and its
  **global** configuration inside its own install tree (`npm config get globalconfig` →
  `<node prefix>/etc/npmrc`, for example
  `~/.local/share/mise/installs/node/24.0.0/etc/npmrc`; npm's bundled
  `lib/node_modules/npm/npmrc`), a tree that is user-writable for a mise or Homebrew install
  and of which only `npx-cli.js` and the `node` it runs under are pinned (recorded pins, 6.3.7:
  editing either of those two needs a dialog; editing the rest does not). Any process of
  the user can edit them, and after an edit the genuine pinned `npx` runs the attacker's code
  **as the receiver**, with nothing in argv, the pin, the environment or the working directory
  changed. nazar does not
  pin or inspect these files (pinning `~/.npmrc` would still leave `~/.npm/_npx` and the
  registry; pointing `HOME` at an empty directory would break every cache and every legitimate
  registry login). The working directory, which used to be a second such input, is not one
  any more: the receiver runs in `/` unless its entry pins a directory (6.3.7). What it does
  instead: for important secrets the README recommends a
  `path:`/`signed:` receiver on the program itself, where the pin is the code that reads the
  secret; `config check` **warns** when a secret with a launcher receiver has `gate: none` or
  `scope: app` (section 4), because those make a config-file edit pay off silently, forever
  or until the terminal app quits; `scope: session` (per tab) or `scope: use` keeps a dialog
  in the loop, with the limit that the dialog shows the pinned `npx` and the package name,
  not what `npx` will fetch. Section 10 lists this under "what it does not protect against".
- **Unreadable means refuse.** `KERN_PROCARGS2` is readable for the user's own non-Apple
  processes and **hidden for Apple platform binaries** (main spec 7.1, measured on
  `/bin/sleep`). The rule is fail-closed and explicit: `Environment` returning `ErrUnreadable`
  (or anything but a list the app can compare) → `denied reason="unexpected environment: not
  readable"`; argv of a hop not readable → `denied reason="receiver changed at exec: argv not
  readable"`. An implementation that treats "nothing read" as "no difference" would be fail-open
  on exactly the binaries that cannot be inspected, and the fake platform's conformance tests
  include an `ErrUnreadable` case for this reason (section 11). Consequence: a final hop whose
  environment macOS hides cannot be a `late-env` receiver; `nazar run` reports `late-env is not
  possible for /usr/bin/python3: macOS hides its environment, so nazar cannot verify it after
  exec; use a non-Apple interpreter (mise, Homebrew) or env`, and `migrate-mcp` chooses `env`
  for such commands with the `ps eww` warning. Measured by S14 (macOS 27):

  | Class (images measured) | argv | Environment |
  |---|---|---|
  | (i) Apple platform binaries (`/usr/bin/env`, `/bin/sleep`, `/bin/sh`, `/usr/bin/python3`) | readable | **hidden** |
  | (ii) Apple team-signed Xcode tools (Xcode's `python3`, `git`) | readable | readable |
  | (iii) non-Apple hardened (mise's `node`) | readable | readable |
  | (iv) ad hoc or unsigned (mise's `python3.14`/`3.13`, Homebrew's `python3` and `uv`, a `cc` build) | readable | readable |

  Readable is not enough for Python: every framework build (Xcode's, Homebrew's) execs
  `Python.app` in the same process, which the agent refuses as a second exec. **As built
  in M10:** the resolver refuses both before any prompt: `/usr/bin` interpreters with
  `python3 is Apple's xcode-select shim; Apple's python3 can't take a secret by late-env: use
  another python3, such as mise's, and add its folder to defaults.trustedPath`, and a framework
  build with `python3.15 is a framework build of Python, which starts itself again, so it can't
  take a secret by late-env: …` (the same advice).

#### 6.3.5 Automatic method choice: `nazar run --secret NAME`

**As built in M10:** `nazar run --secret NAME -- command…` always means `late-env`; no `--late-env`, `--env`, `--as`, `--dry-run` (D3).

The app decides, from its own resolution (6.3.6): `late-env` if a loader can reach the
resolved receiver (interpreter or launcher list), its environment is verifiable after exec
(6.3.4) and `late-env` is allowed; else `env` if allowed; else `Problem{usage}` → exit 1 with
`secret X allows [helper, file] only; add late-env or env to its deliver list`.
`--late-env`/`--env` force one method. `nazar run --json --dry-run` asks the app for the plan
without evaluating any gate (`go: false`) and prints the `RunPlan`; it needs the app running
(exit 5 otherwise) because resolution uses the active config.

#### 6.3.6 What the CLI execs: the app resolves, the CLI obeys

**As built in M10:** `run.Resolution` carries the spec's `resolvedPath` as `Script` (the script argv[0] resolved to, e.g. `npx-cli.js`) and `pinnedInterpreter` as `Image` (the file execve runs); the plan's `execPath` is `Image.Path`, `execArgv[0]` the absolute entry path. A binary is refused ("late-env needs node or python"); `python3 -I`/`-E`/`-S` are refused (the loader would never run); `--inspect*` is refused. See 6.3 "As built in M10" for the kinds, shims and shebang grammar.

The path the CLI passes to `execve` is **always** `RunPlan.resolvedPath` (or the plan's
`pinnedInterpreter`, for a script), an absolute realpath the **app** computed; the CLI never
searches `$PATH`, never execs a bare name, and the kernel is never asked to resolve a shebang.
Otherwise the receiver the user approved (the dialog names the pinned `deploytool`) and the receiver
that gets the secret (whatever `$PATH` gives for `deploytool`, say `/tmp/x/deploytool`) could be two
different programs, and for `env` nothing would ever notice.

**Resolution**, the same function at config load (6.3.3) and at request time:

1. `argv[0]` **absolute** → `realpath`. Must be a regular file. No search.
2. `argv[0]` **contains a slash but is relative** (`./bin/server`) → **refused**
   (`Problem{usage}` at request time, a config error in a `command:` matcher): the receiver
   does not run in the caller's directory (6.3.7), so there is nothing to resolve it against;
   the message says `pass the absolute path`. The caller's `ProcessInfo.Cwd` is used for one
   thing only, `cwd: caller` on a binary receiver.
3. `argv[0]` **bare** → the first regular file of that name in `defaults.trustedPath`, in
   order; the caller's `PATH` is **never** consulted. Not found → `Problem{refused}`,
   `deploytool not found in defaults.trustedPath [/usr/bin, /bin, /opt/homebrew/bin, …]; pass an
   absolute path or add its directory`. Then `realpath`.
4. **Shims.** A `mise`/`asdf`/`rtx` shim is refused as in 6.3.3. An Apple `xcode_select` tool
   shim (`/usr/bin/git`, `/usr/bin/python3`, …; signing identifier
   `com.apple.dt.xcode_select.tool-shim-public`) is resolved to
   `<DEVELOPER_DIR>/usr/bin/<name>`, where `DEVELOPER_DIR` is `readlink
   /var/db/xcode_select_link` (what the shim and `xcrun --find` do; the `DEVELOPER_DIR`
   environment variable is deliberately ignored), and that file is realpath'd and pinned. The
   real tool is what runs and what is matched; the shim never does.
5. **Code identity**: `InspectCode(resolvedPath)` → `resolvedCode`; `stat` → `resolvedFile`
   `{dev, ino, size, mtime}`.
6. **Scripts.** If the file is not Mach-O and starts with `#!`, the shebang is parsed by
   nazar: `#!/usr/bin/env NAME [flags…]` → `NAME` through steps 3–5 (so a `node` planted
   earlier on the caller's `PATH` is never what `env` would have found, because `env` is not
   run); `#!/abs/path [flags…]` → steps 1, 4, 5. The interpreter's own identity is recorded
   separately as `pinnedInterpreter` (realpath), its code pin, and `interpreterFile` `{dev,
   ino, size, mtime}`; `resolvedPath`/`resolvedCode`/`resolvedFile` keep describing the
   **script**, so the plan carries both files and the CLI checks both (6.3 step 5). Anything
   else (a relative interpreter, `env -S`, `env -i`, a second level of script) is refused:
   `unsupported shebang`. The plan's `execArgv` becomes `[NAME, flags…, resolvedPath,
   argv[1:]…]`, which is what the kernel would have built, minus the `PATH` search.
7. **Kind.** The realpath base name (and, for a script, the pinned interpreter's) is looked up
   in the launcher/interpreter table of 6.3 step 3 → `receiverKind` ∈ `binary`, `interpreter`,
   `launcher`. The typed `argv[0]` (`npx`) plays no part: after realpath it is `npx-cli.js`,
   and the table is written in realpath names. Config load stores the same `kind` on the
   resolved `command:` matcher, which is what the launcher-receiver warning of section 4 reads.
8. **Directory and file elements** (6.3.7, config load only, for `command:` matchers). The
   entry's `cwd:` is realpath'd and its `{dev, ino}` recorded. Each file element of `argv[1:]`
   is resolved against it (absolute elements as they are), must be a regular file, and is
   pinned by realpath and `sha256` (cdhash if Mach-O). For a launcher with an absolute `cwd:`,
   the context pin is computed. Steps 1–8 at load produce the entry's **observed** pins; the
   pins the active matcher carries, and that request time **re-checks** (never recomputes),
   are the **recorded** ones the login gate approved (6.3.7, "Recording and refreshing the
   pins"). The plan carries the recorded pins, and a difference from the files as they are at
   request time refuses before the prompt and before the approval cache is consulted. A load
   whose observed pins differ from the recorded ones stages a pin change for the login gate;
   nothing moves a pin but an approval.

**Matching** (5.2) is done against `resolvedPath` + `resolvedCode` (+ argv tail for
`command:`), for all three matcher kinds: `path:` (the trust record's realpath, as
`core/match` already does), `signed:` (the static identity of that file), `command:` (6.3.3).
So in section 4, `deploytool() { nazar run --env DEPLOY_TOKEN -- /Applications/Deploy.app/…/deploytool "$@"; }`
resolves by step 1 and matches `to: [deploytool]` by `path:`; a bare `deploytool` would fail step 3 with
the message above, because Xcode's `usr/bin` is not in the example's `trustedPath`, which is
why the 9.2 wrapper prints the absolute path. A `receiverPrecheck` of `mismatch` is refused
before the prompt (6.3 step 3); `not-applicable` means the matched rule has no `to:`.

**Exec**: 6.3 step 5. The CLI enters `RunPlan.cwd` by `fchdir` on an fd whose `fstat` equals
`cwdFile` (6.3.7), checks `resolvedFile` (and `interpreterFile` for a script)
against an `fstat` of each file it opens right before `execve` and refuses on any difference.
That is the strongest check available without `fexecve`, which macOS lacks; `/dev/fd/N` cannot
stand in for scripts (its realpath is `/dev/fd/N`, so `npx-cli.js` would not find its own
`lib/`), and S16 settles whether it works for Mach-O binaries. For `late-env` the live check of
step 6 verifies the running interpreter and re-hashes the script right before the write; for
`env` the residual is the microseconds between `fstat` and the kernel's open of a file inside
a directory the user declared trusted, and for a script receiver the interpreter's own read of
the script a moment later (6.4, section 10).

#### 6.3.7 The receiver's working directory

**As built in M10:** the receiver always runs in `/`; `cwd:` is refused by name; no pin is recorded and there is no `config reload` (D5, D6). Pins are taken per request and are part of the approval identity.

The working directory is the second input that a caller in an approved scope controls
completely, and for a launcher it selects what runs as surely as `npm_config_*` did. `npm exec`
finds its project by walking **up from the cwd** until a directory holds `package.json` or
`node_modules` (measured: `npm prefix` from `/tmp/e/sub` with a planted
`node_modules` prints `/tmp/e/sub`), runs `node_modules/<pkg>` from that project without
fetching anything, and reads `<project>/.npmrc` as its **project-level** config
(`script-shell`, `registry`), with `~/.npmrc` untouched; `uv`/`uvx` read `uv.toml` and
`pyproject.toml` from the cwd or the nearest parent, and `uv run` syncs the project at the cwd,
which runs its build backend; `pnpm dlx` and `bunx` do the same with `pnpm-workspace.yaml`,
`.npmrc` and `bunfig.toml`; and an interpreter receiver with a relative script
(`command: [node, server.js]`, `[python3, app.py]`) pins `node`, not `server.js`, which is
whatever the cwd holds, as `sys.path[0]` is the cwd for `python3 -m`/`-c`. With the receiver
inheriting the caller's directory, `cd /tmp/e && nazar run …` ran the caller's code inside a
pinned, hashed, environment-checked `npx` under a cached approval, with no prompt. So, like the
environment, **the working directory is part of the plan and the app chooses it**. The
caller's directory is never the receiver's unless an approved receiver entry says `cwd: caller`,
and the request carries no directory at all (7.3).

**Default: `/`.** With no `cwd:` on the matched receiver entry the receiver runs in `/`, the
root of the sealed system volume. In order of weight:

- It is the one directory on this platform that neither the caller, nor any other process of
  the user, nor root without disabling SIP and rebooting can write to: `/` is the signed
  system snapshot, mounted `sealed, read-only` (measured; `touch /x` fails with
  `EROFS`, for root as well). Nothing can be planted in it: no `package.json`, `node_modules`,
  `.npmrc`, `pyproject.toml`, `uv.toml`, `bunfig.toml`, `sitecustomize.py`, `foo.py` for
  `-m foo`.
- It has **no ancestors**, so every walk-up search ends where it starts: `npm prefix` from `/`
  prints `/` (measured), `uv` finds no project, and nothing under `HOME` or `/var/folders` is
  ever on the path of a search that begins at `/`.
- A nazar-created private directory (`~/.nazar/run/<id>/cwd`, 0700) or the Darwin per-user
  temp dir would **not** give this. Both are owned by the user, and the caller runs as the
  user: it can write into them the moment they exist (watch `~/.nazar/run/`, `mkdir
  node_modules` inside, in the hundreds of milliseconds between creation and the launcher's
  walk-up), `chflags uchg` is as reversible for the owner as the mode is, and their ancestors
  (`~/.nazar`, `~`, or `/var/folders/<xx>/<yyy>/T`) are user-writable too, so a
  `~/node_modules/@brave/…` or a `T/package.json` would become the launcher's project.
  Policing those directories at reply time leaves a race; `/` leaves none. `/private/var/empty`
  (root-owned, 0755, root-owned ancestors, the empty directory sshd uses) would also do and is
  the fallback if a receiver family turns out to choke on `/`; S12 runs `npx`, `uvx`, `pipx`,
  `pnpm dlx` and `bunx` from `/` (section 12).
- A receiver that writes relative files (`./logs`, `./.cache`) fails loudly with `EROFS`. That
  is the right outcome: such a receiver needs a directory, and the fix is an approved `cwd:`,
  not a silently caller-chosen one.

**Approved `cwd:` on the receiver entry.** `apps.<name>.cwd` is `caller` or an absolute path
(`~` expands to the config owner's home). It lives on the `apps:` entry, not on the rule,
because the directory is part of what the receiver *is*: a relative file in a `command:` argv
can only be pinned together with the directory it is relative to, and that pin is computed at
config load (6.3.3) and recorded per entry ("Recording and refreshing the pins" below), where
no rule is in view; a rule approves the receiver, directory
included. The field is read only when the entry is the `to:` of a `nazar run` delivery and is
ignored for an entry used as a caller or as a `file`/`helper` receiver. Setting or changing it
**loosens** (section 4), so the `login` dialog shows the new directory before any receiver runs
there; removing it tightens.

- **`cwd: /abs/dir`**, the receiver's project directory. At load it is realpath'd (the
  realpath is what is pinned and shown) and its `{dev, ino}` recorded; one that does not exist
  or is not a directory leaves the entry stale (a warning, section 4). At run the CLI opens it (`O_RDONLY|O_DIRECTORY|O_CLOEXEC`), `fstat`s the fd,
  requires `{dev, ino}` to equal the plan's `cwdFile`, then `fchdir(fd)` and closes it (6.3
  step 5): the process enters the directory the app approved, not one swapped or symlinked in
  behind the name after the check. After exec the app requires the final hop's
  `ProcessInfo.Cwd` to be that realpath (6.3 step 6).
- **`cwd: caller`**: the receiver runs in the caller's directory, taken from the control
  peer's `ProcessInfo.Cwd` (`proc_pidinfo`, realpath'd, must be a directory), **never from a
  string in the request**; the plan carries it as `cwd` with `cwdSource: caller` and the CLI
  verifies `{dev, ino}` and `fchdir`s exactly as above. This exists for wrapper-style
  receivers whose job *is* the caller's project: `gh pr view`, `git`, `deploytool push
  --file ./x.json`. It is allowed only for a receiver whose kind (6.3.6 step 7) is `binary`.
  The **enforcement is at run time for every matcher kind**: the app refuses the run before
  any prompt when the resolved kind is `interpreter` or `launcher` ("node runs whatever the
  caller's directory holds; pin a directory with `cwd: /…` or an absolute script"). For a
  `path:` or `command:` entry the kind is also resolved at load and `config check` **warns**
  with the same text and marks the entry inactive; it is a warning, not an error, because the
  kind comes from the filesystem and nothing on disk may make the config invalid (section 4).
  What a binary reads from its directory is still caller-chosen (`.git/config` with
  `core.hooksPath` or `core.sshCommand`; a `.ckconfig`), which is the receiver's business
  (section 2) and is said in the dialog: `in ~/projects/foo (the caller's folder)`.

**Pinning what runs from an approved directory.** With `cwd: /abs/dir` the app pins what it
can name, at config load, and re-checks it before the prompt and again right before the write
(6.3 steps 3 and 6; for `env`, before the prompt and, by the CLI's `fstat`, before `execve`):

- **File elements of `command:` argv.** An element of `argv[1:]` is a **file element** if it
  is (a) an absolute path, (b) a relative path starting with `./` or `../`, (c) a relative name
  ending in a script extension (`.js`, `.mjs`, `.cjs`, `.ts`, `.py`, `.pyw`, `.sh`, `.rb`,
  `.pl`), (d) the argument of `-r`, `--require`, `--import`, `--env-file`, `--loader` or
  `--experimental-loader`, as a separate element or after `=` (`--require=./x.cjs`; Node loads
  these; an unrecognised `--flag=./relative` is a `config check` warning naming the element),
  or (e) for an `interpreter` receiver, the first element after the interpreter's own flags
  unless that flag was `-m`, `-c`, `-e`, `-p`, `--eval` or `--print` (the script argument). A
  relative file element is resolved against `cwd:`; with no `cwd:` or with `cwd: caller` it is
  a **config error** ("`server.js` is relative: the receiver runs in `/` unless the entry has
  `cwd: /…`; pin a directory or write the absolute path"). Each file element must be a regular
  file at load (a warning and a stale entry otherwise, section 4) and is pinned by realpath and `sha256` (cdhash when it is
  Mach-O), recorded on the resolved matcher as `files: [{arg, path, sha256, file}]` and in the plan
  as `pinnedFiles`. At run the app re-resolves each one from its `arg` against the verified
  directory, requires the realpath to be the recorded one, and re-hashes it ("Reading
  attacker-writable files safely" below), refusing on any difference (`blocked reason="receiver changed: server.js"` before the prompt, `denied
  reason="receiver changed at exec: server.js"` before the write). The `-e`/`-c` code strings
  and `-m` module names are already part of the byte-exact argv tail (6.3.3); what `-m foo`
  resolves to under `cwd:` is the directory's business, below. Elements of no such shape
  (`-y`, `@brave/brave-search-mcp-server`, `--port=8080`) are opaque and compared byte for
  byte as before.
- **The launcher's project files.** For a **launcher** receiver with `cwd: /abs/dir` the app
  records a **context pin** at load, in two parts, both by **presence**, never by hash:
  - in the directory itself, the *set* of markers of the launcher's family that exist (Node:
    `package.json`, `node_modules`, `.npmrc`, `pnpm-workspace.yaml`, `.yarnrc.yml`,
    `bunfig.toml`; Python: `pyproject.toml`, `uv.toml`, `.venv`, `.python-version`), because
    each of them is read from the project directory and a planted one changes what runs
    (`.npmrc` with `script-shell`, a `node_modules` where there was none);
  - in each ancestor up to `/`, the existence of the **root-moving markers only**: the files
    and directories whose appearance moves the launcher's project root, because every
    launcher takes the *nearest* one walking up (Node: `package.json`, `node_modules`,
    `pnpm-workspace.yaml`; Python: `pyproject.toml`, `uv.toml`, `.venv`). A `~/node_modules/@brave/…`
    created after approval is caught (`receiver context changed: node_modules appeared in
    /Users/you`) although `~` is not nazar's directory.

  **User-level configuration files are not in the ancestor set, and nothing is hashed.** For
  a `cwd:` under the home directory the walk passes `~`, and `~/.npmrc`, `~/.python-version`,
  `~/.yarnrc.yml` and `~/.bunfig.toml` are the launcher's **user** configuration, which it reads
  from `HOME` whatever the working directory is and which the user changes legitimately (`npm
  login` creates or rewrites `~/.npmrc`; `npm config set registry …` edits it; `pyenv global`
  writes `~/.python-version`). Pinning them here would make a `cwd: ~/projects/foo` entry refuse
  every run after `npm login` while the same file stays unpinned for the default `/`, and 6.3.4,
  section 10 and the section 11 positive all say that `~/.npmrc` is **not** pinned: that
  statement holds for every `cwd:`. An `.npmrc` in a non-root ancestor is not read by npm at
  all (npm reads the project root's `.npmrc`, the user's, the global one and its builtin, nothing
  in between), so its appearance is not a change in what runs either. The ancestor pin is
  presence-only because presence is what moves the root; the bytes of a `package.json` that
  *is* the root are the project, which is the documented limit below, whether that root is the
  pinned directory or, when the directory holds no marker of its own, an ancestor (`config
  check` warns in that case: "`~/projects/foo/sub` has no package.json; npm's project would be
  `~/projects/foo`").

  At run the same walk is repeated and any difference refuses (`receiver context changed:
  node_modules appeared in /Users/you`, `…: package.json appeared in /Users/you/projects`,
  `…: .npmrc appeared in /Users/you/projects/foo`). What is **not**
  pinned, and cannot be: the *contents* of `node_modules/` and `.venv/` inside the approved
  directory (a tree, changed by every install), the bytes of the directory's own markers (its
  `package.json` is the project), the user-level files above, and the files the pinned elements
  load (`require("./lib")`, `import x`, `-m foo`). An approved `cwd:` is a statement that this
  project is the receiver, and a secret delivered to a project is delivered to whatever that
  project contains; the `config check` warning of section 4 says so for a launcher with a
  `cwd:`.
- **The default `/` needs none of this.** Nothing can be named in it, nothing can be planted,
  there is no ancestor. The context pin and the warning exist only for `cwd: /abs/dir`.

**Recording and refreshing the pins.** A pin is only worth something if it survives the
process that computed it. The approved config is stored as raw YAML (`config/approved`,
`core/configstage/stager.go`) and re-parsed at every app start, so a pin that existed only
inside the parsed config would be recomputed from the files **as they are then**, and a
same-user `kill` of nazar-agent (the LaunchAgent `dev.nazar.agent` relaunches it at once) would re-pin
every receiver onto whatever bytes a caller had planted, with nothing to compare against and no
dialog. The receiver pins therefore get exactly the treatment the `app:` team pins already have
(`core/configstage/pins.go`: "a config change never changes an existing pin"; `core/trust`:
persisted in the Vault, which only nazar-agent can write): they are **recorded** in the Vault
when a `login` dialog showed them, every load **compares** against the record, and nothing but
an approval writes the record.

- **What is recorded: the receiver pin set.** The set is consulted by **`nazar run`
  deliveries only** (`late-env` and `env`, the two where the app resolves files and the CLI
  execs them); `helper`, `file` and `stdout` receivers are live processes matched by their own
  identity (`signed:`, or the `path:` trust record) and never read it. A **receiver entry** is
  defined by **matcher**, not by `apps:` name: every `command:` matcher that appears in the
  `to:` of some `secrets.*` rule, inline or through an `apps:` entry (the matchers in force, as
  `appIDs` in `pins.go` pins only those), and every `path:` or `signed:` matcher of an `apps:`
  entry **with an absolute `cwd:`** (its only pin is the directory; the executable is pinned by
  the trust record or the signature already). An inline matcher cannot carry a `cwd:`, so its
  key ends in `cwd:/`. An `apps:` entry no rule names is not a receiver entry, has no record
  and gets no dialog line: adding one is a no-op, and naming it in a `to:` is a rule change
  `Classify` gates. A `path:`/`signed:` matcher without an absolute `cwd:` has nothing to
  record (not even `kind`: the run-time `cwd: caller` refusal uses the kind resolved then,
  never a recorded one) and is active without a record; so after the upgrade `git credential
  fill` and FIFO reads keep working and
  only `nazar run` through `command:` entries and `cwd:`-pinned entries waits for the one
  approval. For each receiver entry the set holds every pin 6.3.3 and this section define,
  under a **key** that is the entry's canonical matcher text plus its **configured** `cwd:`
  string after `~` expansion and `filepath.Clean` (so `foo/`, `foo/.` and `projects//foo` are
  one key, and the same cleaned form is what the `cwd` classification of section 4 compares),
  not its realpath (`config.ReceiverKey`, e.g.
  `command:["npx","-y","@brave/brave-search-mcp-server"] cwd:/`,
  `command:["node","server.js"] cwd:"/Users/you/projects/foo"`, `path:"/opt/homebrew/bin/gh"
  cwd:"/Users/you/projects/foo"`): renaming an entry is not new trust, changing its argv or
  directory is, and a retargeted symlink shows up as a **changed** `cwd` pin
  (`~/projects/foo now resolves to /tmp/x`) rather than as a new key. The key, every path,
  hash and marker name in a finding or `Changes` line is quoted with the `q()` of `pins.go`
  (`strconv.QuoteToASCII`), so a crafted directory or file name cannot forge a second line, a
  terminal escape or a bidi override in the dialog. The set holds:
  - the executable: `path` (realpath), `code` (`cdhash` for Mach-O, `sha256` otherwise),
    `file` `{dev, ino, size, mtime}` (the `resolvedFile` the CLI's `fstat` compares, 6.3.6);
  - the interpreter of a script receiver: `path`, `code`, `file` likewise;
  - `kind` (6.3.6 step 7; `null` for a `signed:` entry, whose kind is only known at run time,
    section 4);
  - `cwd`: `{path, dev, ino}` of an absolute `cwd:`, `path` its realpath (absent for `/` and
    `caller`);
  - `files[]`: each file element `{arg, path, sha256|cdhash, file}`;
  - `context`: the marker set in the directory and the root-moving-marker set per ancestor,
    for a launcher with an absolute `cwd:`.

  For a `path:` or `signed:` receiver entry (one with an absolute `cwd:`) the set records only
  `kind` (`null` for `signed:`) and the `cwd` pin. The
  pins are **values**, not references: the set is complete on its own and a config text change
  cannot alter a pin without the key changing.
- **Storage.** Vault item `state/receiver-pins` (beside `state/trust`; the Vault ACL means no
  other process can read or write it, section 10), JSON:

  ```json
  {"version": 1,
   "configHash": "<sha256 hex of the approved config text, config.Config.Hash>",
   "recordedAt": "2026-10-11T00:00:00Z",
   "receivers": {
     "command:[\"npx\",\"-y\",\"@brave/brave-search-mcp-server\"] cwd:/": {
       "kind": "launcher",
       "path": "/Users/you/.local/share/mise/installs/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js",
       "code": {"sha256": "3f2a…"}, "file": {"dev": 16777234, "ino": 9123456, "size": 54321, "mtime": "…"},
       "interpreter": {"path": "/Users/you/.local/share/mise/installs/node/24.0.0/bin/node",
                       "code": {"cdhash": "9c01…"}, "file": {…}},
       "files": [], "cwd": null, "context": null},
     "command:[\"node\",\"server.js\"] cwd:/Users/you/projects/foo": {
       "kind": "interpreter", "path": "…/bin/node", "code": {"cdhash": "9c01…"}, "file": {…},
       "cwd": {"path": "/Users/you/projects/foo", "dev": 16777234, "ino": 7788},
       "files": [{"arg": 1, "path": "/Users/you/projects/foo/server.js", "sha256": "ab12…", "file": {…}}],
       "context": null}}}
  ```

  `version` is the format version; a build reads the versions it knows and **refuses** a
  higher one as unreadable (never "best effort"). `configHash` is the hash of the config text
  the set was last written with, for the audit trail only: tightenings and `ApplyAuthenticated`
  change the approved text without writing the set, so it legitimately differs from the
  active hash most of the time and nothing warns on it. Every pin in the set was approved on
  its own key and is valid for that key whatever text surrounds it. The whole item is
  rewritten at each write; there is no per-key write.
- **Who holds it.** `trust.ReceiverPinStore` (`core/trust/receivers.go`): `Load()` returns the
  set, the **empty set** for a missing item, and `ErrUnreadable` with the cause for a corrupt
  item, an unknown `version` or a Vault read error (the store opens either way; it is the
  stager that fails closed, below). `Replace(set)` writes the whole set, and keeps the previous
  one in memory if the write fails, as `trust.Store` does. `configstage.ReceiverPinStore` is
  the interface the stager takes, beside `PinStore`, and `Stager.OpenWithTrust` gets it with
  a `config.ReceiverResolver` (the resolver of 6.3.6 over the real filesystem; the fake for
  tests).
- **Two kinds of staged change, and pins never hold a tightening hostage.** A pending change
  is either a **text change** (the file differs from the active text; `Classify` decides
  whether it loosens, as today) or a **pin change** (the text equals the active text and only
  the pin set differs: `Pending.PinOnly`). The stager keeps one pending slot and a text change
  takes precedence: when the file differs from the active text, that is what is staged or
  applied; whenever the file equals the active text, the slot holds the pin change if there is
  one. The two are classified **independently**:
  - A text change that `Classify` proves to tighten **applies at once**, as `stager.go`
    insists ("the one failure mode this package exists to prevent"), whatever the receiver
    pins say: the new active config's receiver matchers get the **recorded** pins for the keys
    the text keeps, a key whose files differ stays stale (runs refused), a key without a
    record stays inactive. It writes **nothing** to the pin store. Otherwise an attacker who
    `touch`ed `npx-cli.js` could keep the user's `gate: block` from taking effect until the
    user approved a dialog that lists the attacker's re-pin beside their own tightening.
  - A text change, loosening or not, **never carries receiver pins**: its `ReceiverPins` is
    empty, its approval writes nothing to the pin store, and the keys it keeps use their
    records, the keys it adds or re-keys are **inactive** until a pin change has shown them.
    This differs from `app:` team pins, which ride on the loosening that introduces the
    bundle id, and deliberately so: a receiver key is cheap to change from the config file
    (`cwd: /x/foo` → `/x/foo/` before `Clean`, `server.js` → `./server.js`, remove the entry
    in a tightening and re-add it later), and letting a record-less key ride on the user's
    own loosening would let an attacker who edits `config.yaml` while the user's edit is
    pending put `pinned (new): server.js sha256 <attacker bytes>` among the user's lines. So a
    new receiver costs two approvals: the rule, then its pins (`secret add`, `migrate-mcp`
    and the refusal text say so: `brave-mcp has no recorded pins; run nazar config apply`).
  - A pin change is staged when the text equals the active text and the observed pins of some
    receiver entry differ from its record (or an entry has none). Approving it records the
    observed set; it changes no text. It loosens by definition, because other bytes will
    receive the secret. It comes in **two kinds that are never mixed in one dialog**, because
    the user's own workflow forces the first one (a new receiver needs it) and an attacker
    who had edited `npx-cli.js` earlier would otherwise ride that forced approval:
    - **new trust** (`Pending.PinKind = new`): only keys **without a record**; title `Pin new
      receiver my-server?` / `config.yaml named it; these are the files it resolves to now`;
    - **re-pin** (`Pending.PinKind = changed`): only keys whose record **differs**; title
      `Trust changed receiver files?` / `config.yaml did not change; the files behind these
      receivers did`.

    When both exist, new trust is staged first and the re-pin after its approval; a user who
    expected one dialog for `my-server` never sees a `brave-mcp` line in it. Each has its own
    `Pending.Hash`, lists only pins, and its `ConfigDiff` carries `pinOnly: true` and
    `pinKind`, so neither can be mistaken for the text change the user just wrote.
  - **A pin change is never prompted in the background.** A staged loosening of the text is
    prompted by the app when the user saved the file (main spec 4.2); a pin change is shown
    **only** by `nazar config apply`. `config.apply` becomes **two-phase** (7.3): called
    without `hash` it replies with the staged `ConfigDiff` and opens no prompt, runs no
    `Reload()` and no `autoPrompt`; the CLI prints it and calls again with `hash =
    ConfigDiff.hash` (`Pending.Hash`), which the daemon passes to `Stager.Approve`, so a slot
    flip between the print and the dialog is `ErrStale`. The two daemon sites that start a
    background prompt today, `configApply`'s blocked path (`handlers.go`, `d.autoPrompt`) and
    `Reload()` from the poller and `configCheck` (`daemon.go`, `autoPrompt`), **skip a
    `PinOnly` change**; the text-change behaviour is unchanged. Otherwise `vi server.js` from
    any process would put a Touch ID on the user's screen at the attacker's moment, and a pin
    change re-staged right after the user's own approval would read as "the same dialog
    again". `status` and the menu bar show a pending pin change as `receiver pins waiting for
    approval: nazar config apply`.
- **Every load compares.** There are three loads, plus **every apply**, and they all run the
  same function, `stageReceiverPins(recorded, observed, active, &d)`, after the text has been
  dealt with. "Every apply" means: `Approve` of a text change, the tightening path of
  `Observe`, and `ApplyAuthenticated` each run the comparison against the **new** active text
  right after `activate`, so the pin change for an entry the user just added is staged the
  moment its rule is approved and `nazar config apply` finds it (the second approval of a new
  receiver never depends on the file changing again). The observed set carries the hash of
  the config it was computed for; if the active config differs when `applyMu` is taken (a
  tightening or `ApplyAuthenticated` landed meanwhile), the comparison is skipped and
  resolution runs again, so a stale observation is never compared, let alone recorded.
  1. **App start** (`OpenWithTrust`): the approved text is parsed, the recorded set loaded, and
     the active config's receiver matchers are given the **recorded** pins for their keys
     (`SetReceiverPins`). Then the observed pins are computed from the files as they are now
     and compared. A difference stages a **pin change**, so `status` shows it and `nazar config
     apply` opens the dialog; the active matchers keep the recorded pins meanwhile. An entry
     whose key has no record is **inactive** (matches nothing), reported by `ReceiverProblems`,
     and part of the pin change as new trust. An entry whose files cannot be resolved now (a
     missing `server.js`, a shim where a file was) stages nothing and is reported as stale; its
     recorded pin stays in force, so a run is refused with `receiver changed: server.js`.
  2. **Every observation of the file** (`Observe`, which the daemon runs on each poll and on
     each change). Today `Observe` returns early when the file equals the active text and
     **clears the pending slot** (`stager.go`: `bytes.Equal(nw.Raw, active.Raw) → s.pending =
     nil`); that early return would wipe the pin change of step 1 on the first poll after
     start. It changes to: file equals active text → run the comparison and **stage or keep**
     the pin change (clear the slot only when nothing differs). File differs → `Classify` →
     a loosening is staged (without any pins, above) or a tightening applied, and the
     comparison runs again against the **new** active text, so a pin change the tightening did
     not resolve is re-staged immediately rather than lost. `ApplyAuthenticated` (`secret
     add`, `ssh-key create`) does the same after `activate`: it installs recorded pins, writes
     nothing to the pin store (those commands passed the gate for their own change, not for
     pins) and re-stages any pin change. The daemon's guard that refuses `ssh-key create` and
     `secret add` while something is pending (`handlers.go`) is relaxed to **text** changes:
     a pending pin change does not block them, or the first start after the upgrade would be
     a dead end in which nothing can be added until the pins are approved.
  3. **`nazar config reload`** (7.1; control `config.reload`; `Stager.Reload()`): the active
     text is kept and the comparison is run against the files as they are now. No difference →
     `nothing changed` and no write; a difference → a staged pin change with the observed pins.
     It exists for the legitimate cases that make the recorded pins stale: a `server.js` edit
     during development, a `git checkout` or `rm -rf && clone` that recreates the directory's
     inode, a `pyproject.toml` added to the project, a `mise`/Homebrew upgrade of `node` or
     `npm`. Any same-user process can run it, which is precisely why it never adopts anything:
     a prompt-injected caller that edited `npx-cli.js` (user-writable under mise and Homebrew,
     6.3.4) or `server.js` and then ran `nazar config reload` gets a `login` dialog on the
     user's screen naming the file and both hashes, not a re-pin. The daemon's poller
     short-circuits on unchanged file bytes today (`observe()` in `daemon.go` compares a
     content hash before calling `Stager.Observe`); that stays for the text, but when the
     bytes are unchanged the poller calls the comparison (`Stager.Reload()`) at most once per
     `ReceiverCompareInterval` (30 s) rather than hashing every pinned file on every poll, and
     immediately after any apply (above). `config reload` makes the comparison happen *now*
     and prints the result; it stays because a poll interval is not a contract.

  **Keys the text drops** are pruned from the set at the next approval that writes it (a
  tightening never writes); until then they linger, unread, because the set is only consulted
  by key for entries the active config has. An entry re-added later with the same key reuses
  the lingering record when the observed pins match it (the same approved bytes; the dialog
  for the text change says `re-using pins approved on <date>`), and is a pin change
  otherwise.

  **Comparison is field by field** over the whole record: executable `path`, `code` and `file`;
  interpreter `path`, `code` and `file`; `kind`; `cwd` `{path, dev, ino}`; every `files[]`
  element; the `context` sets. Any difference is a `Finding` with `Target` the entry's key
  and `Why` naming the file and the old and new value, and a `Changes` line the dialog shows:
  - `brave-mcp: npx-cli.js re-pinned: sha256 3f2a… → 9c01…`
  - `brave-mcp: interpreter node re-pinned: cdhash 9c01… → 77ef…`
  - `brave-mcp: executable moved: …/node/24.0.0/…/npx-cli.js → …/node/24.1.0/…/npx-cli.js`
  - `my-server: server.js re-pinned: sha256 ab12… → cd34…`
  - `my-server: ~/projects/foo re-created ({dev, ino} 16777234/7788 → 16777234/9001)`
  - `my-server: context changed: node_modules appeared in /Users/you`
  - `my-server: npx-cli.js same bytes, new file identity (mtime 2026-10-11T00:00Z → 00:30Z)`
    (an identity-only difference is still gated, because the CLI's `fstat` check and the
    executable pin must agree; the line says the bytes are the same so the user can judge)
  - `brave-mcp: pinned (new): /…/npx-cli.js sha256 9c01…, interpreter /…/node cdhash 77ef…,
    runs in /` for an entry without a record.
- **Approval records what was shown.** `Pending` carries `ReceiverPins`, the full set to
  record: for a pin change, the recorded set with the changed and record-less keys replaced by
  the **observed values the dialog showed** and the keys the active text does not have pruned;
  for a text change it is empty and nothing is written. `Approve` writes it with `Replace` **before** it
  saves the config, mirroring `recordPins` (a config whose receivers cannot be pinned must not
  take effect with them silently inactive; a pin set without its config is harmless, the user
  approved it behind the gate), and the new active config's matchers get exactly that set
  (`SetReceiverPins`). Nothing is re-read after the dialog: a file swapped while the prompt was
  open is caught by the request-time re-check (`receiver changed: server.js`), never adopted,
  which is the `Approve(hash)` rule of `stager.go` applied to pins.
- **One hash per staged change.** Two reloads with the same text and different observed pins
  are two different changes, so `Pending.Hash` is the SHA-256 of the config text **and** the
  canonical JSON of `Pending.ReceiverPins`, `ConfigDiff.hash` carries it, `config.apply`
  passes it back and `Approve` compares it, before the dialog and again before applying
  (`ErrStale` otherwise). **Every place the daemon identifies a pending change by hash uses
  `Pending.Hash`**: `diffObj`, `approveStaged`, `autoPrompt` and the prompt throttle's
  `seen`/`mark` (`core/daemon`), not `Config.Hash`, which every pin change shares with the
  active text; otherwise a denied re-pin would mark the active text as denied and throttle
  later, different pin changes. (`lastSeen`, the poller's hash of the file bytes, is not a
  pending-change identifier and is unchanged.) A hash of the text alone would let an
  approval meant for one pin set apply another with the same text.
- **Fail closed, and the upgrade.** With the record missing or unreadable, no receiver entry
  has a pin in force: each matches nothing, `nazar run` is refused before any prompt (`blocked
  reason="receiver brave-mcp has no recorded pins; run nazar config apply"`), and
  `ReceiverProblems` says why in `config check` and `status` (`receiver brave-mcp: no recorded
  pins (state/receiver-pins is corrupt: …); run nazar config reload and approve the pins`).
  Recovery is always the same: `nazar config reload` stages every receiver as new trust, the
  dialog lists each pin, one Touch ID records the set; before writing a recovery set
  `Approve` calls `Load()` once more and, if the record reads now (a transient Keychain
  error), compares against it instead of replacing it, so a momentary failure never turns
  into "forget the pins and start over" (`trust.Store.Open` refuses to open on the same
  condition for the same reason). This is also the **upgrade path**: the
  first start of a build with this design on an approved config that already names receivers
  finds no `state/receiver-pins`, pins nothing silently (the gate was passed for the config
  text, not for the files as they are now), reports every receiver as unpinned and stages the
  loosening; the release note says to run `nazar config reload` once. A set with a known older
  `version` is migrated in memory and rewritten in the current format at the next approval;
  a tightening never writes it. `ApplyAuthenticated` (`secret add`, `ssh-key create` editing
  the file themselves) installs the recorded pins for the keys the new text has and **never
  writes** the pin store: those commands passed the gate for their own change, not for pins,
  and a stale or missing pin is staged afterwards as its own change.
- **Ordering, and what survives a failure.** `Approve` writes the pin set, then the approved
  config. Pin set written and config save failed: the change stays staged, the retry shows the
  same pins and writes the same set, and until then the record's `configHash` names a text
  that is not the approved one; `status` reports it and the keys still in the active config
  use their recorded pins, which the user did approve. Neither written: nothing changed. A
  pin set is never written for a tightening, so a transient Vault read failure at start cannot
  be followed by a write that forgets pins: an unreadable record is reported and kept as it is
  until an approval replaces it with a set the user saw.
- **What the user sees between a change and its approval.** The run is refused with the
  reason and the fix (`blocked reason="receiver changed: server.js"`; on stderr, `server.js
  changed since its pin was approved; if that was you, run nazar config reload and approve the
  new pin` or, when the change is already staged, `…; run nazar config apply`), `config check`
  and `status` list the stale, unpinned and pending entries without waiting for a run, and the
  menu bar shows a pending pin change as waiting for `nazar config apply` (never as a prompt,
  above). A reload with no text change and no pin change is a no-op (`nothing changed`), so
  the command is safe to script.
- **Reading attacker-writable files safely.** `ResolveReceivers` runs over user-writable
  files on every poll, so it must not be stoppable from them: each file is opened
  `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, its `fstat` must say `S_IFREG` (a FIFO at
  `server.js` would block the read forever; it is "unresolvable, stale"), and at most
  `MaxPinnedFileSize` = 64 MiB is hashed (a sparse 200 GB file is likewise unresolvable,
  stale). The resolution runs **outside** `applyMu`; the lock is taken only to compare and
  stage, so a slow or hostile file never keeps `Observe`, `Approve` or `ApplyAuthenticated`
  from running and a tightening from applying. **The same rule governs every other read of a
  pinned file**: the app's re-check before the prompt (6.3 step 3) and before the write (step
  6), and the CLI's open before `execve` (step 5, which therefore adds `O_NONBLOCK` to its
  flags): the same open flags, the same `S_IFREG` test, the same size cap; a failure is
  `receiver changed: <file>`, never a blocked goroutine holding a plaintext. **File elements
  are re-resolved, not re-opened by recorded path:** at every check the element is resolved
  again from its `arg` against the verified `cwd` (`openat` on the directory fd the CLI
  verified, `O_NOFOLLOW` on the final component), the resulting realpath must equal the
  recorded `path`, and only then is it hashed; so a `server.js` that was a regular file at
  approval and is a symlink to `/tmp/evil.js` now is `receiver changed: server.js`, and an
  element that was a symlink at load is unresolvable (stale) rather than pinned by target.

**What remains, exactly.**
- With the default `/`: nothing from the working directory. A launcher's remaining inputs are
  the config files under the real `HOME` and inside its own install tree, and its caches
  (6.3.4 lists them; `~/.npm/_npx`, `~/.cache/uv`, `~/.local/pipx`). An interpreter with an
  **absolute** script (`command: [node, /abs/server.js]`, no `cwd:`) still loads from the
  script's **own** directory tree: Node's `require('x')` walks up from the script's directory
  (`…/foo/node_modules`, `~/node_modules`), Python's `sys.path[0]` is the script's directory;
  those are user-writable and not pinned (the context pin exists only for a launcher with a
  `cwd:`). The pinned script is the receiver; what it imports is the project, as section 10
  says for `cwd:`.
- Interpreters outside the Node/Python table of 6.3 step 3 (`sh`, `bash`, `zsh`, `ruby`,
  `perl`, `osascript`, `deno`) are `binary` to nazar: no loader, so no `late-env`, and no
  interpreter warning. `config check` warns on a `nazar run` rule whose `to:` resolves to one
  of these names ("bash runs whatever the caller passes; pin a script with `command:`") and
  `cwd: caller` is refused for them like for an interpreter.
- With `cwd: /abs/dir`: the directory's own tree beyond the pinned elements and markers,
  `node_modules`/`.venv` included, and the walk-up to `/` as pinned above. `migrate-mcp` emits
  a `cwd:` only for a server command with a relative file element, with the project path the
  entry belongs to (9.1).
- With `cwd: caller`: whatever the binary reads from the caller's directory.
- `config check` **errors** on what the text alone shows: a relative file element without an
  absolute `cwd:`, a relative `argv[0]`, a relative `cwd:`. It **warns**, and the entry is
  stale or inactive, on what only the filesystem shows: `cwd: caller` for an entry that
  resolves to an interpreter or launcher, a `cwd:` or file element that does not exist, a
  shim, a pinned file that is not a regular file or is over `MaxPinnedFileSize`; and it
  **warns** on a launcher receiver with a `cwd:` (section 4) and on a `path:`/`signed:`
  receiver of a `nazar run` rule whose resolved kind is `interpreter` or `launcher` (`to:
  [{path: /opt/homebrew/bin/node}]` delivers the secret to whatever script the caller names on
  the command line: "node is an interpreter; this rule delivers X to any script the caller
  passes; pin the script with `command: [node, /abs/server.js]`"). The launcher warning of
  section 4 and the context pin above apply by **resolved kind**, whatever the matcher kind,
  so a `path:` entry on `npx-cli.js` with a `cwd:` gets both; for a `signed:` entry the kind
  is run-time and the warning is printed on the run's stderr instead.
  The README's advice is now complete: for important secrets use a `path:`/`signed:` receiver
  on the program that reads the secret, no `cwd:` unless the program needs the project, and
  `scope: session`/`use` with a dialog.

#### 6.3.8 Everything else the receiver inherits, and what the CLI does with it

`execve` replaces the image and keeps the process. Everything the caller set up in the process
it started as `nazar run`, and that the exec does not replace, is an input to the receiver, so
each is listed here with its treatment. The CLI applies the resets below unconditionally, after
the plan arrives and before `execve`, for `late-env` and `env` alike. They are constants, not
plan fields, because there is nothing to choose; they are the CLI's duty under the genuine-peer
trust of 7.3, the same trust that `env` delivery and the `fstat` checks already rest on. What the app
verifies after exec is what the kernel **records at exec** and so reflects the inherited input
and nothing else: the image, argv and the startup environment (`KERN_PROCARGS2`), plus the
working directory, which is observed live but which none of the receiver families changes
during startup (a receiver that `chdir`s before its loader runs would be refused with a named,
deterministic reason, not a race; S12 (f) checks every launcher family for a startup `chdir`). The fd
table is **not** verified after exec, for the reason given in its row: nothing read after exec
can tell an inherited descriptor from one the new image opened itself. The rest the integration
tests read back from inside the target (section 11).

| Inherited | Does the caller control it, and what could it do with it? | What nazar does |
|---|---|---|
| **argv** | `argv[0]` is free text to `execve` and some programs branch on it (`bun` reads `bunx` from its own name; multi-call binaries; anything that logs it). The tail is the pinned `command:` tail (6.3.3) or, for a `path:`/`signed:` receiver, the caller's command line | The app sets `execArgv[0]` to the base name of the **entry that resolved** (`npx`, `bunx`, `deploytool`: the `trustedPath` entry, or the last element of the typed absolute path, before realpath), a derived value and never the caller's string, so there is no `exec -a` equivalent; for a script the first element is the shebang's interpreter name. The tail of a `path:`/`signed:` receiver is by design the caller's (`gh "$@"`), shown in the dialog and the audit line; `command:` is the matcher for a tail that must be fixed |
| **Environment** | Entirely | Allowlist built by the app, verified after exec (6.3.4) |
| **Working directory** | Entirely | `/`, or the approved `cwd:`, entered by `fchdir` on a verified fd and checked after exec (6.3.7) |
| **Open file descriptors** | Every fd of the caller without `FD_CLOEXEC` survives into `nazar run` and would survive into the receiver: a socket on 4, a file on 7, the caller's own pipes. A program that trusts inherited fds (`LISTEN_FDS`-style activation, Node's `--inspect` on an fd, anything told to read `/dev/fd/N`) would read what the caller planted, and a stray fd is one more place a receiver might write | **The mechanism is the CLI's sweep.** Before `execve` the CLI lists its own fds (`proc_pidinfo(PROC_PIDLISTFDS)` on itself) and sets `FD_CLOEXEC` on every fd ≥ 3 except the pipe read end it `dup2`s to 3 for an `fd` handover (clearing `CLOEXEC` on that one only); the kernel closes the flagged ones atomically at exec, so for `socket` and `env` nothing above 2 survives and for `fd` only 3 does. The Go runtime opens its own descriptors (netpoll kqueue, the signal pipe, the control connection) with `CLOEXEC` already; S14 checks from inside an exec'd probe that the sweep leaves nothing (section 12). **The app does not check the fd table after exec, by design.** An earlier draft had it refuse any fd beyond `{0, 1, 2}` (+3). That check cannot work: unlike argv and the environment, the fd table is not recorded at exec, and by the time the chain settles (after the chain resolve, `InspectCode`, the re-hash and the `KERN_PROCARGS2` read) the image has opened its own descriptors: `node` has run `uv_default_loop()`, which opens a kqueue and its wakeup pipe before any JS, loader included, runs; `python3` holds the script or its `.pyc` and `/dev/urandom` during startup. A count check therefore races on every legitimate run and, for the `fd` handover, fails deterministically, because the loader can only block in `readFileSync(3)` after libuv is up. Comparing by identity instead (snapshot the CLI's fd objects before the plan reply, refuse a receiver fd that refers to one of them) is exact only for pipes and sockets: macOS has no `kcmp`, and `proc_pidfdinfo` names the **vnode** (`{dev, ino}`), not the open file description, so a receiver that itself opens a file the caller also holds (`/dev/null`, a shared log, the node binary) would be a false refusal. A check that is partial by construction, that an implementer would loosen until the integration tests pass, and that second-guesses code the app already trusts to exec `RunPlan.env` verbatim and the right file, is worse than none; the sweep is enforced by the genuine CLI under the 7.3 peer trust like `umask`, `RLIMIT_CORE`, the signals and the exception ports in this table. **What the app does verify** is the one fd whose identity is exact and that matters most: for `fd` the handover pipe's read end must be held by exactly the exec'd pid (`OpenersOf(writeEnd)`, 6.3 step 6: pipe identity is the pipe object, which no new image can re-open by name), and for `socket` nothing is passed at all. The integration test asserts the sweep by identity from inside the target, not by count (section 11). `stdin`/`stdout`/`stderr` are the caller's by definition (an MCP server talks to Claude Code through them); nazar never writes a value to them and the loaders never read from them |
| **`umask`** | Yes | Set to `022`, the macOS login default: a caller's `umask 000` must not make the files the receiver creates (caches, logs, a token file of its own) world-readable. A receiver that wants stricter modes sets them, as it would under any shell |
| **Resource limits** | Yes; soft and hard limits survive exec. Most can only make the receiver fail (`RLIMIT_NOFILE`, `RLIMIT_AS`), which is visible. `RLIMIT_CORE` is different: the default is soft 0, hard unlimited, with `kern.coredump=1` and `kern.corefile=/cores/core.%P` (measured), so `ulimit -c unlimited; nazar run …` followed by `kill -SEGV <pid>` writes the receiver's memory, secret included, to `/cores` wherever that directory is writable (root-owned on a default install, made writable by many developer setups) | `setrlimit(RLIMIT_CORE, {0, 0})`, soft and hard, so neither the caller nor the receiver can raise it. Every other limit is left alone: lowering one is a denial of service, which nazar does not try to prevent, and raising one is harmless |
| **Signal mask and ignored signals** | Yes: `execve` keeps the blocked set and `SIG_IGN` dispositions (handlers reset to default). A caller that blocks or ignores `SIGCHLD`, `SIGPIPE`, `SIGTERM` or `SIGALRM` before spawning `nazar` changes how the receiver reaps children (npm's spawner on `ECHILD`), notices a closed pipe, or stops. Failure modes, not code selection | `sigprocmask(SIG_SETMASK, ∅)` and `SIG_DFL` for every catchable signal before `execve`, so the receiver starts the way a login shell would start it |
| **Mach exception ports** | A task inherits its parent's exception ports at `fork`, and keeps the task-level ones across `execve`, into a hardened-runtime image too (S14, macOS 27; the kernel clears the thread-level ones). A caller that registers itself as the `EXC_CRASH`/`EXC_BAD_ACCESS` handler of its own task before spawning `nazar` would be sent the crashed receiver's task port, memory included, after a `kill -SEGV` of a non-hardened receiver (Homebrew's `node`, `python3`, `uv` and `gh` are ad-hoc signed without the hardened runtime, as measured; mise's `node` has it) | The CLI sets the exception ports of its task and of the thread that calls `execve` to `MACH_PORT_NULL` for `EXC_MASK_ALL \| EXC_MASK_CRASH \| EXC_MASK_CORPSE_NOTIFY` (`EXC_MASK_ALL` leaves out a crash, whose message carries the task, and a corpse, a copy of its memory; `task_set_exception_ports`/`thread_set_exception_ports`, which need no privilege), reads them back, and refuses the run if a port is left; the hardened CLI itself cannot be attached to in the first place (7.3). S14 confirms the inheritance behaviour for hardened and non-hardened images (section 12). **As built in M10:** `cmd/nazar/runreset_darwin.go`; `TestRunResetsTheProcessBeforeExecOnMacOS` seeds a task port with `posix_spawnattr_setexceptionports_np`, logs whether a plain `execve` passes it to an ad-hoc and to a hardened image, and finds none in either through `nazar run` |
| **Controlling terminal, session, process group, audit session** | Yes, and by design: the receiver is the caller's child (an MCP server must be; a `gh` wrapper must keep its terminal and job control, `Ctrl-C` included), and the audit session is what `scope: session` keys on | Unchanged. Nothing of nazar's reads from the terminal: the loaders use only the fd or socket, and the CLI never prompts (7.1). A `setsid` would break job control for no gain |
| **Scheduling priority, QoS class, `sandbox-exec` profile, Mach bootstrap namespace** | Yes. The first three can only take something away from the receiver (CPU, file or network access) or slow it; none can redirect a path or add code. The bootstrap port is different (corrected in M10): a caller that starts `nazar` with a bootstrap port of its own (`posix_spawnattr_setspecialport_np`) answers every Mach service lookup of the receiver in launchd's place. nazar's own trust path, the control socket with `LOCAL_PEERTOKEN` and code identity (7.3), and the handover (a Unix socket path in the plan, checked by the kernel's peer identity) use none of them; a receiver that checks TLS through macOS's trust service (trustd), as Go and Swift programs do, would ask the caller's stand-in, while Node and Homebrew's or mise's Python check against their own CA files by default | Unchanged; a receiver that cannot reach its registry or the handover socket fails visibly (`target never connected`, 6.3.2). The bootstrap port is not reset: the CLI has no trusted port to put in its place (its own came from the caller); a check that the port is launchd's is a later milestone, with the binary receivers it matters to |
| **Attaching afterwards** | A receiver without the hardened runtime can be debugged by a process of the same user where Developer Mode allows it (`lldb -p`), once the value is in its memory | Not something a handover can detect or prevent: it is the main spec's same-user memory limit, restated in section 10. The hardened runtime closes it (the official Node builds mise installs have it; Homebrew's binaries do not); `config check` does not try to tell them apart |
| **`--target`, `--loader`, `--handover`, `--handover-timeout`, `--as`** | The CLI's own flags, all caller-chosen | `--target` is a substring filter, not a boundary (6.3.2). `--handover` may only choose `socket` (the broader handover; `fd` for a launcher is `usage`), `--loader` may only select a subset of the resolved family's loaders, `--handover-timeout` is bounded (6.3.2), `--as` is validated by CLI and app (7.1). No flag adds a variable, a directory, an fd or an argv element |

### 6.4 `env`: startup environment, last resort

`nazar run --env NAME [--as NAME=VAR] -- cmd…`. The app resolves and pre-checks the receiver
exactly as for `late-env` (6.3.6; a `to:` mismatch is refused before the prompt), chooses the
working directory and re-checks the pinned file elements (6.3.7), prompts, and
returns the plaintext to the CLI (a `SecretValue` object on the control socket, never printed).
The CLI enters `RunPlan.cwd` (`fchdir` on an fd whose `fstat` matches `cwdFile`), verifies the
file identity (`fstat` against `RunPlan.resolvedFile`, and
`interpreterFile` for a script), resets the inherited process state (6.3.8), appends
`VAR=value` to **`RunPlan.env`**, the app-built
allowlisted environment of 6.3.4 (the one entry the CLI ever adds, and only for `env`), and
`execve`s **`RunPlan.resolvedPath`** (6.3 step 5). The secret
is readable through `ps eww` and `KERN_PROCARGS2` by every process of the user while `cmd`
runs, and by every child of `cmd`.

- **What `to:` guarantees for `env`, and what it does not.** The file that is exec'd *is* the
  file the app matched against `to:` and named in the dialog: the CLI execs the app's absolute
  realpath, never a `$PATH` lookup, and checks the file's identity just before `execve`. What
  is missing, compared with `late-env`, is the **live** check after exec: the plaintext is in
  the CLI's environment before the exec, so a file swapped inside a `trustedPath` directory in
  the microseconds between the CLI's `fstat` and the kernel's open would receive it, and so
  would anything the receiver does afterwards. The genuine-CLI peer check (7.3) is what makes
  the CLI's part of this trustworthy. The audit line for `env` carries
  `receiver=<resolvedPath + tail> handover=none`.
- Must be listed in `deliver`. `config check` refuses `gate: none` with `env`.
- **Warning:** the first use per secret per day prints `nazar: DEPLOY_TOKEN is delivered
  as a startup environment variable; other processes can read it while deploytool runs` to stderr.
  State: `~/.nazar/state/env-warned.json` `{name: lastWarnedDate}`, CLI-side, best effort.
- Still far better than a shell `export`: the window is one process tree for the duration of
  one command, not every process in every tab forever.

### 6.5 `stdout`: `nazar get NAME`

Prints the value and a trailing newline to stdout (no `--raw` since M8: `$(nazar get X)` drops
the newline anyway). Nothing else is
written to stdout, ever; errors go to stderr. `--json` is accepted (spec 6: every command
accepts it) and changes only the failure path: a failure prints a `Problem` object; success
still prints the raw value, because no JSON kind carries a value, by design (`Secret` is
metadata only). This is the one documented exception to "success output is JSON" and section 14
amends spec 6 accordingly. The receiver is the
CLI's parent (the script), so a rule `to: [{signed: …}]` on the script's interpreter or `to:
[any]` is needed. The README says plainly: `$(nazar get X)` puts the value in the shell's memory
and in anything the shell then passes it to; prefer `run`.

## 7. CLI

### 7.1 Commands

```
nazar secret add <NAME> [--replace] [--kind raw|aws] [--keep-newline]     # value on stdin; loosen
nazar secret rm <NAME>                                                    # handle erase (3.4); loosen
nazar secret list [--json]                                                # read
nazar secret migrate <shell-file> [--only NAME]... [--all] [--dry-run]    # loosen (one approval for the batch)
nazar secret migrate-mcp [<json-file>] [--server NAME]... [--rename ENV=NAME]... [--dry-run]
git-credential-nazar get|store|erase                                      # git's helper (git since M8; docker/aws later)
nazar run [--secret N | --late-env N | --env N]... [--as N=VAR]... [--target PATTERN]
          [--handover fd|socket] [--loader node,python] [--handover-timeout DUR] [--dry-run] -- <cmd> [args...]
                                                                          # as built in M10: nazar run --secret N -- <cmd> [args...] (6.3)
nazar get <NAME> [--json]                                                 # no --raw (since M8)
nazar config reload                                                       # (not built in M10, D5) recompute the receiver pins of 6.3.7 and compare with the recorded set; loosen when any differs, never adopts
```

- `--replace` re-seals to the same key (3.4). A new key is `rm` then `add`. (`--rekey`,
  `--no-user-presence` and `secret reformat` were dropped in M8: every secret key is
  `AuthNone` until S13 has run, 3.5, and there is no blob file to reformat, 3.3.)
- `--as NAME=VAR` renames one named secret in the target's environment (repeatable; `--as VAR`
  alone is accepted only when exactly one secret is requested). The variable name must be
  env-shaped and must not be in the deny set of 6.3.4 (`NODE_OPTIONS`, `DYLD_*`, `PYTHONPATH`,
  `npm_config_*`, `NAZAR_*`, …), nor a base name (`PATH`, `HOME`, `USER`, `LOGNAME`, `TMPDIR`,
  `LANG`, `LC_*`, `TERM`), nor `SHELL`, nor a name in any requested secret's `envAllow` (one
  variable, one source): usage error, checked by the CLI and again by the app.
- There is **no flag that adds a variable to the target's environment** (6.3.4), **and no flag
  or argument that chooses its working directory** (6.3.7): what the target gets is the app's
  base set, the approved `envAllow` lists, and the loader variables, and it runs in `/` or in
  the directory the matched receiver entry's `cwd:` names. `--handover-timeout` only lengthens
  the socket deadline (6.3.2), up to 10 min. `<cmd>` is a bare name (resolved through
  `defaults.trustedPath`) or an absolute path; `./relative` is a usage error (6.3.6).

- **As built in M8:** `--replace`, `--kind` and `--keep-newline` are not built (rotation is
  `rm` then `add`; `aws` comes with its helper; one trailing `\n` is always stripped from piped
  input), there is no `delete` alias, and the prompt reads `Add secret "NAME"?` with the line
  `deliver: helper, stdout (the default; edit config.yaml to change it)` (or the entry's own
  list) and the config change as `config apply` shows it. A new name's entry is written as
  `ssh-key create` writes a key's since Milestone 7: the secret's own `gate: block`, plus a
  `login`/`session`/`8h` rule for the terminal app it was typed in (no `to:`, so `config check`
  warns until the receiver is named); an existing entry is kept. The terminal prompt is one
  line (at most the terminal's 1024-byte line limit; a longer value is piped).
- **As built in M11:** `nazar secret rule add|set|remove NAME …` edit `secrets.NAME.rules`
  with exactly the flags, staging, Touch ID and `ConfigEdit` reply of `ssh-key rule` (one
  implementation; `config.edit` names the entry with `secret` in place of `key`). There is no
  `secret set` (a secret's own gate stays what `secret add` wrote, `block`) and no `secret rules`
  (`secret list --json` carries them as `policy`). `secret add` from a caller that is not a
  terminal (Nazar UI.app, which writes the value to the CLI's stdin) writes the entry blocked with
  no rule; its prompt says `no rule yet: every caller is blocked until one is added (nazar secret
  rule add NAME …)`.
- **`add` reads the value from stdin, never from an argument.** If stdin is a terminal: echo
  off, one line, trailing newline stripped, `Ctrl-D` ends. If stdin is a pipe or file: read
  to EOF, strip exactly one trailing `\n` (`--keep-newline` to keep it). Empty value → usage
  error. The value goes to the app over the control socket as `args.valueBase64` (a JSON
  string cannot carry arbitrary bytes: non-UTF-8 would silently become U+FFFD); the CLI zeroes
  its buffer after the reply. `--kind aws` validates the JSON shape (6.1). `add` of an existing
  name without `--replace` → exit 1, `secret X exists; use --replace to re-seal it`.
- **`add` is a loosening command:** the on-screen `login` prompt reads `Add secret
  "BRAVE_API_KEY" (deliver: helper, stdout — the default; edit config.yaml to
  change it)`, naming exactly the `deliver` list the entry it writes gets (section 4), and
  covers the config entry written for a new secret. With `--json` it never asks on stdin; the
  approval happens on screen. It prints `the receiver pins of any new to: entry need a second
  approval: nazar config apply` when the active config has an unpinned receiver (6.3.7).
- **`rm`** needs `login` on screen (`Delete secret "X"?`, "This can't be undone; config.yaml keeps its entry.", as built in M8), gated as
  `ssh-key delete` is; a record the agent cannot read is refused before any prompt with the
  remedy of 3.4. It does **not** edit `config.yaml`; `config check` warns about
  the orphaned entry.
- **`list`** shows name, created, `deliver`, rules summary, `file` path if any, `userPresence`,
  `broken` (the Vault record is unreadable or unusable, with what failed and the fix of spec
  9), and `configured`.
- **`run`** is `exec`: when the command starts, `nazar run`'s exit status *is* the command's.
  Before exec, exit codes are nazar's: 3 refused, 1 error (including `receiver changed between
  approval and exec`), 2 usage, 5 app not running. `--dry-run` with `--json` prints the
  `RunPlan` the app computed (`go: false`) and exits 0 without evaluating any gate. The command
  that runs is always the plan's `resolvedPath` (6.3.6), never a `$PATH` lookup, in the plan's
  `cwd` (6.3.7), with the inherited process state reset (6.3.8); `exit 1` also covers `working
  directory changed between approval and exec`.
- **`get`** exits 3 on refusal (nothing printed), 1 on error, 5 when the app is down.
- **`helper`** subcommands speak the tool's protocol on stdin/stdout exactly (6.1) and exit 3
  on refusal with nothing on stdout. Symlinks `git-credential-nazar` and `docker-credential-
  nazar` dispatch to them; `nazar install` creates the symlinks next to the binary.
- **`config reload`** asks the app to recompute the receiver pins of 6.3.7 from the files as
  they are now and compare them with the **recorded** set in the Vault; it never adopts a pin.
  Every difference, the executable's and the interpreter's included, is shown (file, old → new
  hash) and approved as a loosening change on screen (`nazar config apply` opens the dialog,
  keyed on the change's hash, which covers text and pins, 7.3); until then the recorded pins
  stay in force and runs against the changed files are refused. Nothing changed → `nothing
  changed`, exit 0; an invalid file → the last valid config stays, exit 1 with the error, as
  for a file-change reload (main spec 4.2). `config check` and `status` list stale, unpinned and
  pending receivers (`server.js changed since its pin was approved; run nazar config reload`,
  `receiver brave-mcp has no recorded pins; run nazar config apply`, `re-pin of server.js
  waiting for approval; run nazar config apply`). A receiver with no recorded pins (first start
  after an upgrade, a corrupt `state/receiver-pins`) matches nothing until this command's
  change is approved.
- **No command ever prompts in the terminal** for approval (spec 6). `add`'s stdin read is
  input, not approval.

### 7.2 `--json` kinds

All carry `apiVersion: nazar/v1`.

| Kind | Printed by | Fields |
|---|---|---|
| `Secret` | `secret list` (items), `secret add`, `secret rm` | `name`, `created`, `deliver[]`, `rules[]` (summaries), `file?`, `helper?` (`{git:{host,username}, docker:{registry}, aws:bool}`), `userPresence`, `configured`, `broken`, `stored`; as built: `unusableReason`, `remedy`, and (since M11) `policy` (the rules as `ssh-key list` gives a key's: an `SSHKeyRules` object, `fallbackSource: secret-gate` for the secret's own gate, `configHash` for `--if-hash`) and `warnings[]` (the config warnings of the secret's own entry). **Never a value.** |
| `SecretList` | `secret list` | `items[]` |
| `RunPlan` | `run --dry-run`, and on the wire as the app's go-ahead | `go` (bool; always `false` for `--dry-run`), `names[]`, `as?` (map name→var), `method` (`late-env`/`env`), `handover` (`fd`/`socket`/`none`), `loaders[]`, `target?`, `argv[]` (as typed), `receiverKind` (`binary`/`interpreter`/`launcher`, 6.3.6 step 7), `resolvedPath` (the app's absolute realpath, 6.3.6: what is exec'd, or the script for a script receiver), `resolvedFile` (`{dev, ino, size, mtime}` of `resolvedPath`), `pinnedInterpreter?` (absolute realpath, for a script), `interpreterFile?` (`{dev, ino, size, mtime}` of the interpreter), `execArgv[]` (what the CLI passes to `execve`; `execArgv[0]` derived by the app, 6.3.8), `cwd` (absolute realpath of the working directory the CLI enters, 6.3.7), `cwdFile` (`{dev, ino}` of it), `cwdSource` (`default`/`receiver`/`caller`), `pinnedFiles[]` (`{arg, path, sha256}`: the file elements of the argv pinned against `cwd`), `env[]` (`NAME=value`: the **complete** environment the CLI execs, built by the app, 6.3.4), `envPassed[]` (the `envAllow` names the caller supplied), `envDropped[]` (`--dry-run` only: names from the caller's environment that are not passed), `deadline` (seconds), `receiverPrecheck` (`matched`/`mismatch`/`not-applicable`; a plan with `mismatch` never has `go: true`), `pathNote?` (`--dry-run` only: what the caller's `$PATH` would have run, when different), `socket?` (wire only) |
| `Migration` | `secret migrate`, `secret migrate-mcp` | `source` (path), `items[]` of `{name, line?, server?, envKey?, imported: bool, skipped?: reason, replacement: {kind: shell|mcp, text}}`, `rules` (YAML text to paste), `rotate[]` (names to rotate) |
| `HelperResult` (not built: there is no `secret helper` subcommand since M8) | `secret helper … --json` (diagnostics only; the real protocol output is never JSON) | `protocol`, `matchedSecret?`, `decision`, `reason` |
| `Problem` | any failure | as today |

Wire-only objects on the control socket, never printed: `SecretValue{name, value}` (for
`env`, `stdout`, `helper`), and the `secret.run` request's ancillary fd.

### 7.3 Control protocol additions

**As built in M10:** `secret.run` takes exactly `name`, `argv` (a JSON list, as typed) and
`callerEnv` (a JSON list of `NAME=VALUE`, the CLI's environment without the deny set's names);
any other argument is a usage error (a `cwd` names why). No fd travels. It is a value command
(genuine CLI only) and may be up to 128 KiB; every other command keeps 64 KiB. The reply is
`RunPlan{execPath, execArgv, env, cwd, cwdDev, cwdIno, files[{path, dev, ino, size, mtimeNs,
ctimeNs}]}` (the image first, then the script, then file elements), or a `Problem`; after the
plan the agent says nothing more on the connection (the CLI execs; the outcome is the audit
line). No `config.reload` and no two-phase `config.apply` (D5).

| Command | Args | Class | Peer | Reply |
|---|---|---|---|---|
| `secret.add` | `name`, `valueBase64`, `kind`, `replace` | loosen | same user | `Secret` or `Problem` |
| `secret.delete` | `name` | loosen | same user | `Secret` (with `stored: false`) or `Problem` |
| `secret.list` | — | read | same user | `SecretList` |
| `secret.get` | `name` | gated | **genuine CLI** | `SecretValue` or `Problem` |
| `secret.helper` | `name`, `protocol` (`git`/`docker`/`aws`), `host`/`registry` | gated | **genuine CLI** | `SecretValue` or `Problem` |
| `secret.run` | `names`, `as`, `method`, `argv` (as typed; the app resolves it, 6.3.6), `target`, `callerEnv` (the caller's environment minus the deny set and the base names: **input** the app picks `LANG`/`LC_*`/`TERM` and the `envAllow` values from, never a base; anything else in it is ignored, 6.3.4), `loaderOverride?`, `handoverOverride?`, `handoverTimeout?`, `dryRun` + **one fd** (the pipe's write end; always sent, closed by the app when the plan says `socket`). There is **no `cwd` argument**: the working directory comes from the receiver entry, or for `cwd: caller` from the peer's `ProcessInfo.Cwd` (6.3.7); a request carrying one is `Problem{usage}` | gated | **genuine CLI** | `RunPlan` (then, for `env`, a `SecretValue`) or `Problem` |
| `config.reload` | — | loosen (when any receiver pin differs from the recorded set, or a receiver has no record; otherwise a no-op) | same user | the config-load result the app already reports for a file-change reload (staged with the `ConfigDiff` naming each changed pin / nothing changed / kept last valid with the error), or `Problem`. It never applies anything by itself |
| `config.apply` (existing, **changed**) | `hash?` (**new**) | loosen | same user | **Two-phase.** Without `hash`: replies with the staged `ConfigDiff` (`hash`, `pinOnly`, `pinKind`, `changes`, `loosening`) and does nothing else: no prompt, no `Reload()`, no `autoPrompt` (today's handler reads no argument and prompts for whatever is pending; that changes). With `hash`: `Stager.Approve(hash, …)`, and the dialog opens only if `hash` equals the current `Pending.Hash`, the SHA-256 over the config text **and** the canonical JSON of the pin set the change would record (6.3.7), as `ConfigDiff.hash` reports it; `ErrStale` → `Problem{staged}` "the staged change is not the one you were shown; run `nazar config apply` again". The CLI always does both calls and prints the diff between them. An approval for one pin set can therefore never apply another with the same text, and a slot flip between the print and the dialog is caught |

**As built in M11:** `config.edit` (Milestone 5) takes `secret` (a secret name) in place of
`key` for `rule.add`, `rule.set` and `rule.remove`, exactly one of the two; `key.set` takes `key`
only. The reply's `ConfigEdit` carries `secret` instead of `key`.

`Args` stays `map[string]string`; list arguments are JSON-encoded strings inside it (`argv`,
`callerEnv`), and binary values are base64 (`valueBase64`; `SecretValue.valueBase64` likewise),
which keeps the `Request` type unchanged. "Gated" commands run the broker and return
`Problem{refused}` (exit 3) on deny/timeout/block. The `Server` reads the request with
`ReadMsgUnix` so it can receive at most one fd; an fd on any command but `secret.run`, or more
than one fd, closes the connection with `Problem{usage}`.

**Request size.** `control.MaxRequestSize` (64 KiB, `server.go`) bounds the whole request line.
A `secret.add` of the largest value (32 KiB, 3.2) is under 44 KiB in base64 and fits it.
`secret.run` (the caller's environment) may use `MaxLargeRequestSize = 128 KiB` (the server
peeks the command name before enforcing the bound); every other command keeps 64 KiB.

**As built in M8.** The check lives in the bridge (`bridge/clipeer_darwin.go`), the one
place that is nazar-agent and nothing else, and uses the CLI's own machinery
(`codesign.PeerAuditToken` + `codesign.CheckPeer`) with `codesign.CLIRequirement(team, pin)`,
Nazar UI.app's rule in Go. The ad-hoc pin is not read from any file (any process of the user
can replace a file under `~/Library/nazar` before the agent starts): `make agent` signs the CLI
first and compiles its cdhash into the Go core the agent links (`-X main.devCLIPin`), so the pin
is in the agent's code pages, which the kernel holds to its signature. The verifier returns the
process it checked and the server requires it to be the peer of the caller chain it resolved.
The hardened-runtime and `get-task-allow` clauses below are **not** built (an untested clause
could refuse every genuine CLI; every build nazar makes signs the CLI with the hardened runtime
and no entitlements). **Known limit:** the audit token names the last process that touched the
client socket, so a same-user process that shares the connection with a genuine CLI (an
inherited descriptor, or the CLI exec'd over the process that connected) and stops it can pass
the check and read the reply (THREAT-MODEL 4.10); closing it needs a per-message kernel identity
(an XPC/Mach channel for value commands); a check of every process holding the connection does
not, since a reference to a socket can be held outside every descriptor table (tried in Milestone 9 and dropped). The
server runs the check only for `control.ValueCommand`s and passes the verdict to the handler
through the request context (`control.PeerIsNazarCLI`); `daemon.Serve` refuses every
value command without it (`Problem{refused}` "peer is not the nazar CLI", audited blocked with
`broker.Refuse`). No `Platform.VerifyPeer` was added: it would have computed in Swift, across
the bridge, what `core/codesign` already computes in the same process. `Secret` (7.2) is built
as `name`, `created` (when stored), `deliver[]`, `rules[]`, `userPresence`, `configured`,
`stored`, `broken`, `unusableReason`, `remedy` (`file` and `helper` join with their tasks).

**Peer verification (the client side of the trust).** Today `Server.checkPeer` only requires
the same uid (`unixsock.RequireSameUser`); the `PeerVerifier` built in Phase 1 is the CLI
verifying the *app*. That is not enough for commands that hand out plaintext or trust what the
client says about its exec plan: a fake `nazar` earlier on `PATH` would otherwise be a valid
peer. For the three **genuine CLI** rows nazar-agent resolves the peer with `LOCAL_PEERTOKEN` →
`SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` and requires the code requirement
Nazar UI.app already uses for the CLI (`CLIRequirement`, Milestone 6): signing identifier
`dev.nazar.cli` signed by the agent's own certificate (`anchor apple generic and certificate
leaf[subject.OU] = <the agent's team>`), plus hardened runtime with no `get-task-allow`;
identity is the signature, never the path (spec 4), so a Homebrew upgrade that moves the
bundle changes nothing. Failure → `Problem{refused}` with reason `peer is not the nazar CLI`,
audited as `blocked`. Dev builds (ad-hoc signed) accept the exact cdhash of the CLI inside the
agent's own bundle (`Contents/MacOS/nazar`), as Nazar UI.app's dev requirement does. The Go side exposes this as `control.PeerIsNazarCLI`,
backed by a new `Platform.VerifyPeer(conn) (CodeIdentity, error)`; the fake accepts a test
identity. Consequence for MCP configs: `migrate-mcp` writes the **absolute path of the link `nazar
install` made** (`~/.local/bin/nazar`, written out in full: JSON does not expand `~`), which
follows the agent across upgrades, never bare `nazar`, so no `PATH` entry is consulted. The
link is the user's file and can be replaced by any process of the user; what protects the
value is the signature check above, not the path, so a replaced link can deny service
(visibly) and nothing more (9.1).

The approved-config rule (spec 4.8) applies unchanged: the app evaluates against the **active**
config, never the file on disk.

## 8. Audit

**As built in M10:** one line per run, written when the run ends: `delivery=late-env`,
`operation="nazar run"`, `env_passed=HTTPS_PROXY` (lower case like every key; names only, when
the caller supplied `envAllow` variables) and `receiver=` with the realpath's base name and the
redacted tail (`receiver="npx-cli.js -y …"`). No `handover=` or `receiverCwd=` (always the
socket and `/`). Outcomes: `approved`/`allowed` after the write; `denied` with `receiver changed
at exec: …` or `unexpected environment: NAME` (the approval is dropped); `error` with `target
never exec'd` or `target never connected`; a refused socket peer is its own `blocked` line,
`unexpected socket peer`.

One line per request, as today, with two new fields:

```
decision=approved reason="rule 1 matched" target=secret:BRAVE_API_KEY delivery=late-env handover=socket
rule=1 scope=session gate=dialog app=com.googlecode.iterm2
chain="iTerm2(612, H7V7XYVQ7D:com.googlecode.iterm2) > login(4100) > bash(4102) > claude(4188, Q6L2SF6YDW:com.anthropic.claude-code) > nazar(4201)"
receiver="/Users/you/.local/share/mise/installs/node/24.0.0/lib/node_modules/npm/bin/npx-cli.js -y @brave/brave-search-mcp-server" cwd=~/projects/foo receiverCwd=/
```

(S3 found that Claude Code's chain resolves to the terminal app that owns it, here iTerm2;
`claude` is a signed CLI in the chain, not the `app=`. `receiver` for a `command:` match is the
pinned path plus the argv tail, 6.3.3. `cwd=` is the **caller's** directory, as for ssh;
`receiverCwd=` is where the receiver ran, 6.3.7.)

- `delivery` ∈ `helper file late-env env stdout`; `handover` ∈ `fd socket none` (only for
  `late-env`); `envPassed=HTTPS_PROXY,NODE_ENV` only when the caller supplied `envAllow`
  variables (names, never values; 6.3.4); `receiverCwd=` for `late-env` and `env`: `/`, the
  pinned directory, or the caller's directory followed by `receiverCwdSource=caller`.
- For `file`, `receiver` is the reader's redacted argv; for an ambiguous-reader refusal,
  `extra="python3(5120) curl(5131)"` lists the others.
- Phase-2 events of `nazar run` (post-exec verification) are the **same** audit line: the
  decision is final only once the write happened or was refused, so a `late-env` request logs
  once, after the handover, with `decision=approved` or `decision=denied reason="receiver
  changed at exec"` (or `"unexpected environment"`, `"pipe shared"`). This needs the broker's
  `Verify` hook (5.1): today a failing `Do` is logged as `audit.Error`, and a post-exec refusal
  is a decision, not an error. A `blocked` or `denied` before exec logs once, before.
- Secret values, file keys, `enc`, and the plaintext length are never logged. `nazar log
  --target secret:X` and `nazar log summary` work unchanged; `--delivery` is a new filter.

## 9. Migration of existing secrets

### 9.1 `BRAVE_API_KEY` in `~/.claude.json`

**As built in M10:** no `migrate-mcp` (one server needs no tool): the README's "Secrets: an MCP
server's key (Brave Search)" shows the steps by hand: `nazar secret add BRAVE_API_KEY`; the
config entry (`defaults.trustedPath` naming the real node folder, `apps.brave-mcp.command`,
`deliver: [late-env]`, a `claude` rule `to: [brave-mcp]`, `scope: session`, `gate: dialog`); the
`~/.claude.json` entry `"command": "<abs>/nazar", "args": ["run", "--secret", "BRAVE_API_KEY",
"--", "npx", "-y", "@brave/brave-search-mcp-server"]` without its `env` block; rotating the key.
No `--late-env` or `--target` (6.3, D2, D3). The rest of this section is the design for later.

```
$ nazar secret migrate-mcp ~/.claude.json
Found 1 server with secrets in its env:
  brave-search  (npx -y @brave/brave-search-mcp-server)  env: BRAVE_API_KEY
```
After one on-screen `login` approval ("Import 1 secret from ~/.claude.json: BRAVE_API_KEY"), it
prints, and never edits the file:

```jsonc
// Replace the "brave-search" entry in ~/.claude.json (or run:
//   claude mcp remove brave-search && claude mcp add brave-search -- /Users/you/.local/bin/nazar run --late-env BRAVE_API_KEY --target brave-search-mcp-server -- npx -y @brave/brave-search-mcp-server )
"brave-search": {
  "type": "stdio",
  "command": "/Users/you/.local/bin/nazar",
  "args": ["run", "--late-env", "BRAVE_API_KEY", "--target", "brave-search-mcp-server",
           "--", "npx", "-y", "@brave/brave-search-mcp-server"]
}
```
```yaml
# Paste into ~/.nazar/config/config.yaml (this change needs Touch ID when it loads):
# npx on your PATH is a mise shim; `mise which npx` resolved it to the path below (6.3.3).
defaults:
  trustedPath: [/usr/bin, /bin, /opt/homebrew/bin, /Users/you/.local/share/mise/installs/node/24.0.0/bin]
apps:
  brave-mcp:
    command: [npx, -y, "@brave/brave-search-mcp-server"]
secrets:
  BRAVE_API_KEY:
    deliver: [late-env]
    # (Had the server's env block held non-secret entries, they would be suggested here,
    #  commented out, e.g. `# envAllow: [BRAVE_MCP_LOG_LEVEL]`; listing one is your decision.)
    rules:
      - apps: [claude]
        to: [brave-mcp]
        scope: session   # one dialog per terminal tab; `app` is allowed but warns for a launcher (6.3.4)
        gate: dialog
```
```
Rotate BRAVE_API_KEY at https://api-dashboard.search.brave.com/app/keys : the old value sat in
plain text in ~/.claude.json and may be in backups.
```
- The handover is `socket` (launcher `npx`), the loader is Node, `--target` is the package's
  bin name. `migrate-mcp` derives `--target` from the last `@scope/name` argument's bare name
  (`brave-search-mcp-server`), falling back to the package name; the user can edit it. The
  server starts with the app-built environment of 6.3.4, not Claude Code's: any non-secret
  entry of the server's `env` block is printed as a commented `envAllow` suggestion, never
  written, because listing it is the user's loosening decision. It also starts in `/`, not in
  the directory Claude Code runs in (6.3.7): `npx -y <pkg>` needs no project, and a
  `node_modules/@brave/…` or `.npmrc` in Claude Code's directory must not decide what runs.
  `migrate-mcp` emits a `cwd:` on the `apps:` entry only when the server command has a
  **relative file element** (`node ./build/index.js`), with the absolute project path the
  entry belongs to (the `projects.<path>` key of `~/.claude.json`, or the directory of a
  `.mcp.json`), and the relative element is then pinned against it; a command whose relative
  element cannot be placed is printed with a `# set cwd:` comment and skipped.
- Why `scope: session` + `dialog`: Claude Code starts the server once per run, so the intended
  ergonomics is one dialog per place Claude Code runs. **What the scopes key on:** `session` is
  the terminal tab's login session; `app` is `Chain.AppIdentity` (`core/caller/chain.go`), the
  GUI app bundle, and S3 found that Claude Code's chain resolves to the terminal that owns it
  (iTerm2, Cursor), not to `claude`. Since Milestone 7 a `session` rule that `claude` satisfies (a
  non-Apple tool below the tab's shell) is remembered for **that Claude Code run**: the first
  Brave search of a run shows one dialog, the rest of the run none, and restarting Claude Code
  (or a second run in another tab) asks again; the approval ends when that `claude` exits.
  With `app`
  the approval would last for the iTerm2 process and cover every tab until iTerm2 quits, which
  for a **launcher** receiver is what `config check` warns about (6.3.4): an edit to `~/.npmrc`
  by any process of the user would then be served silently for days. `scope: use` is the
  strict option (a dialog per server start). `to: [brave-mcp]` means Claude Code cannot hand the
  key to any other program; what it cannot mean is pinning what `npx` downloads (section 10).
- The imported key is `AuthNone`, as every secret key is in slice 1 (3.5), so the pasted rule
  loads without a warning.
- `migrate-mcp` handles `~/.claude.json` (`mcpServers` at the top level **and** under each
  `projects.<path>.mcpServers`), a project's `.mcp.json`, and `~/.cursor/mcp.json`: anything
  with a `mcpServers` map. Non-literal values (`${VAR}`) are skipped with a reason. A `command`
  that is not Node/Python/launcher gets an `env` replacement plus the `ps eww` warning in the
  output. Env keys that collide with an existing secret need `--rename KEY=NAME`.

### 9.2 `GITHUB_PERSONAL_ACCESS_TOKEN` and `DEPLOY_TOKEN` in `~/.bash_profile`

```
$ nazar secret migrate ~/.bash_profile
Found 2 literal exports:
  :12  export GITHUB_PERSONAL_ACCESS_TOKEN=…
  :13  export DEPLOY_TOKEN=…
```
One `login` approval imports both. The output (file untouched):

```bash
# ~/.bash_profile line 12 — delete the export line. Replacements, pick what the consumers need:
#   git over HTTPS / gh push+pull:  git config --global credential.https://github.com.helper nazar
#   gh api (a Go binary: no loader, so this needs `env` in deliver and `gh` in to:, both commented out below):
#     gh() { nazar run --env GITHUB_PERSONAL_ACCESS_TOKEN --as GITHUB_PERSONAL_ACCESS_TOKEN=GH_TOKEN -- command gh "$@"; }
#   a Node MCP server: add an apps: entry with its command: and list it in to:, then
#     "command": "/Users/you/.local/bin/nazar",
#     "args": ["run", "--late-env", "GITHUB_PERSONAL_ACCESS_TOKEN", "--target", "<bin name>", "--", "npx", "-y", "<pkg>"]
# ~/.bash_profile line 13 — delete the export line. deploytool only reads an env var. The path is
# where its app installs it; nazar execs exactly this file (6.3.6), never a PATH lookup,
# and `cwd: caller` below lets it see the files you name on its command line (6.3.7):
deploytool() { nazar run --env DEPLOY_TOKEN -- /Applications/Deploy.app/Contents/MacOS/deploytool "$@"; }
```
```yaml
apps:
  git-https: { signed: { team: apple, id: com.apple.git-remote-http } }  # git's HTTPS transport runs the helper (6.1)
  deploytool: { path: /Applications/Deploy.app/Contents/MacOS/deploytool, cwd: caller }  # a binary: cwd: caller is allowed (6.3.7)
  # gh:      { path: /opt/homebrew/bin/gh, cwd: caller }   # for the gh() wrapper: `gh pr view` needs the repo it is run in
secrets:
  GITHUB_PERSONAL_ACCESS_TOKEN:
    deliver: [helper, late-env]   # add env to allow the gh() wrapper above
    helper:
      git: { host: github.com }
    rules:
      - apps: [iterm, cursor]
        to: [git-https]         # add gh (apps.gh: {path: /opt/homebrew/bin/gh, cwd: caller}) for the wrapper
        scope: session
        gate: login
        expire: 8h
  DEPLOY_TOKEN:
    deliver: [env]
    rules:
      - apps: [iterm, cursor]
        to: [deploytool]
        scope: session
        gate: dialog
```
```
Rotate both tokens: GitHub → Settings → Developer settings → Personal access tokens;
the deploy service's token settings. The old values are in plain text in ~/.bash_profile,
and probably in backups and shell history.
```
- **Parser:** lines matching `^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$` where the value
  is a bare word, a single-quoted string, or a double-quoted string **without** `$`, backticks
  or `\` escapes beyond `\"` and `\\`. Anything else (`$(…)`, `$OTHER`, heredocs, `read`) is
  listed as skipped with the reason. Only names that look like secrets are offered by default
  (contains `TOKEN`, `SECRET`, `KEY`, `PASSWORD`, `PASS`, `CREDENTIAL`, `AUTH`, case-insensitive);
  `--all` offers every literal export; `--only NAME` restricts.
- The `apps: [iterm, cursor]` names are taken from the active config's `apps` if they exist;
  otherwise the snippet uses `apps: [any]` with a comment to narrow it. `migrate` prints the
  absolute realpath for every wrapper command (it resolves with 6.3.6 and says so in a comment),
  adds `cwd: caller` to the `apps:` entry of a `binary` receiver used from a shell wrapper
  (`gh`, `deploytool`: without it the tool would run in `/` and not see the user's repo or files,
  6.3.7), and never emits `cwd:` for an interpreter or launcher,
  and the `git-https` receiver with the transport's signing identifier it reads with
  `InspectCode` from the installed git (`com.apple.git-remote-http` for Xcode/CLT git; a
  `path:` pin for a Homebrew git).

## 10. Threat model for secrets

**As built in M10:** where this section describes `nazar run` (recorded pins, `config reload`,
the pipe-sharing check, `OpenersOf`, `migrate-mcp`, `--late-env`, reading the chain "after the
last NOTE_EXEC"), 6.3 "As built in M10" wins: pins are per request and in the approval identity,
the handover is the per-run socket, the exec'd process is read at the exec event, and the README
shows the migration by hand. THREAT-MODEL 5.9 lists what `late-env` as built does not cover.

**What Phase 2 protects against**
- **Reading secrets from files.** No plaintext file exists, and no sealed one either: the
  value lives sealed in its Vault item only (3.3). A copy of the Keychain database off this
  Mac (a backup, a disk image) is useless without this Mac's enclave.
- **Reading secrets from `ps eww` / `KERN_PROCARGS2`.** `helper`, `file` and `late-env` never
  put the value in a startup environment or an argument. Only `env` does, explicitly.
- **An allowed caller handing a secret to an arbitrary program.** `to:` is checked on the live
  receiver for `file` and `late-env`, on the helper's parent (the transport, 6.1), and for
  `env` on the file the CLI then execs by absolute realpath (6.3.6); `nazar run --late-env X --
  printenv` from Claude Code is `blocked` with the warning "Claude Code tried to give X to
  printenv". For `helper` this holds against a program that is not git's transport, not against
  what a genuine transport can be told to do (limit below).
- **A planted binary on the caller's `PATH`** (`/tmp/x/npx`, `/tmp/x/deploytool`, or a `node` that
  `/usr/bin/env` would find first). The CLI never resolves or execs through `$PATH`: the app
  resolves the command through `defaults.trustedPath` to an absolute realpath, matches `to:`
  against that file, refuses a mismatch before any prompt, and the CLI `execve`s exactly that
  path, expanding a script's shebang to the pinned interpreter itself (6.3.6). This holds for
  `env` as well as `late-env`.
- **Not protected for `helper`:** the receiver check proves who the
  CLI's parent is, not where the CLI's stdout goes. Whoever can run git with a configuration of
  its choosing (`git -c 'credential.helper=!exec git credential-nazar get >FILE #' fetch`, a
  `GIT_CONFIG_COUNT` variable) gets the token in a file with the genuine transport as the
  receiver, the same power as `GIT_TRACE_CURL=1` (6.1). A helper listed after nazar (a later
  `[credential] helper = store`) is sent `store` with the token and keeps it. For a token that
  matters, `scope: use` with `gate: login` is the protection; a check that the receiver holds the
  read end of the CLI's stdout pipe (`OpenersOf`, build-order step 5) would close the first.
- **A sniffer on a FIFO.** Each delivery goes to a FIFO that is detached from its path before
  the reader is identified (6.2), so a sniffer must already hold a read end opened in the
  microseconds between the reader's open and the swap, and even then the one-reader/no-other-
  writer rule refuses the delivery visibly. A lingering reader never gets a second value.
- **A fake `nazar` on `$PATH`.** The app serves plaintext and `secret.run` only to the genuine
  signed CLI (7.3), and MCP configs written by `migrate-mcp` start the bundled binary by
  absolute path. A fake can deny service, which is visible, and can still be a *caller* of the
  genuine CLI, in which case it is subject to `apps:`/`to:` like any other caller.
- **Edits to `~/.claude.json` or `.mcp.json` by malware.** After migration the file holds no
  secret. The `command:` receiver is pinned to an executable resolved through
  `defaults.trustedPath` and verified at exec (6.3.3), so pointing the entry at another
  program, naming it `npx`, or putting a `/tmp/x/npx` earlier on `PATH` fails `to:`. Keeping
  the same argv but poisoning what the genuine `npx` downloads is the launcher limit below.
- **Moving a receiver pin without a dialog: editing the pinned file and restarting the app, or
  editing it and running `nazar config reload`.** The pins of every receiver (executable,
  interpreter, file elements, directory, context) are recorded in the Vault when a `login`
  dialog showed them and compared, never adopted, at every load (6.3.7). `vi npx-cli.js;
  kill $(pgrep -x nazar-agent); nazar run …` (the LaunchAgent restarts the agent at once)
  starts it with the recorded pin in force and
  the edit as a staged pin change, and the run is refused before the approval cache or any
  prompt (`receiver changed: npx-cli.js`); `vi server.js; nazar config reload` puts a dialog
  naming `server.js` and both hashes on the user's screen and changes nothing until it is
  approved. A receiver with no record (an upgrade, a deleted or corrupt item) matches nothing.
  What is guaranteed, exactly: a pin is never adopted without a dialog; a text change never
  carries pins, so an attacker's edit to `config.yaml` (a re-keyed `cwd:`, a removed and
  re-added entry, an unreferenced entry) cannot put attacker bytes into the user's own dialog;
  a pin change is shown only by `nazar config apply`, under its own title, after the CLI
  printed it, never as a background prompt, so an attacker cannot put a Touch ID on the
  screen at a moment of their choosing; and a pin difference never delays a tightening, so a
  `touch`ed `npx-cli.js` can refuse runs but not keep a `gate: block` from taking effect
  (6.3.7). What is not: a user who approves a pin-change dialog without reading the file name
  and the hashes on it.
- **Downgrading a secret to the `ps`-visible method by editing `deliver`.** `deliver:
  [late-env, env]` → `[env]` is a loosening change (section 4), not the tightening its shape
  suggests, and the approval cache is keyed by method (5.1), so a `scope: session` approval
  given for `late-env` is never spent on an `env` run of the same receiver; `--secret`'s
  fall-through to `env` (6.3.5) therefore always meets a dialog that says `via env (visible in
  ps)`.
  Approval records the pins the dialog showed, so a file swapped while the prompt was open is
  refused at run time rather than pinned. The `nazar` CLI, `npx-cli.js` and `server.js` are
  all user-writable; the record is not (Vault ACL, S5).
  Adding `--env` instead of `--late-env` fails on `deliver`. Adding environment entries to the
  server definition does nothing: they are not in the allowlist (next bullet). Adding a `cwd`
  to the server definition, or starting the server from a prepared directory, does nothing
  either: the receiver runs in `/` (bullet after next).
- **Hooking or steering the receiver through its environment.** The receiver's startup
  environment is built by the app from an allowlist (6.3.4): a fixed base whose values come
  from passwd, `confstr` and `defaults.trustedPath`, the approved `envAllow` names, and the
  loader variables from the app's own bundle. Nothing else of the caller's environment reaches
  the receiver, so `NODE_OPTIONS=--require /tmp/steal.js`, `PYTHONSTARTUP`,
  `DYLD_INSERT_LIBRARIES`, and equally `npm_config_script_shell=/tmp/x.sh`,
  `npm_config_registry=http://127.0.0.1:4873`, `HOME=/tmp/h`, `XDG_CONFIG_HOME`,
  `PIP_INDEX_URL`, `UV_INDEX_URL`, `VIRTUAL_ENV` set by a caller in an approved scope are
  dropped, and the whole startup environment is compared with the plan after exec, refusing
  when it differs **or cannot be read**. The deny set keeps `envAllow` and `--as` from ever
  naming one of these; `envAllow` itself is a loosening change behind the `login` gate. (An
  earlier draft had a denylist scrub with a caller-controlled `--keep-env`; both are gone,
  because a caller who controls one unlisted variable owns a launcher receiver.)
- **Steering the receiver through its working directory.** The receiver runs in `/`, the
  sealed read-only system root, unless its approved entry pins a directory (6.3.7). `cd /tmp/e
  && nazar run … -- npx -y @brave/brave-search-mcp-server` with a planted
  `/tmp/e/node_modules/@brave/brave-search-mcp-server` and a `/tmp/e/.npmrc` carrying
  `script-shell=/tmp/e/x.sh` runs the genuine package from the registry cache through `sh`:
  `npm`'s walk-up starts and ends at `/`, where nothing can be planted by anyone. The same for
  `uv.toml`/`pyproject.toml` in the caller's directory, and for `python3 -m`/`-c` with
  `sys.path[0]`. A `command: [node, server.js]` without a `cwd:` is a config error, so a
  relative script is never resolved in a caller's directory; with `cwd: /abs/dir` the script is
  pinned by hash against that directory and the directory by identity, the CLI enters it by
  `fchdir` on a verified fd, and the app checks the final hop's `ProcessInfo.Cwd`. (An earlier
  draft inherited the caller's directory, which made every launcher receiver's choice of
  program caller-controlled with no file under `HOME` touched.)
- **Inherited process state as a side channel into the receiver.** The CLI closes every fd
  above 2 at exec (`FD_CLOEXEC` sweep; the app verifies the one fd it can identify exactly,
  the handover pipe, through `OpenersOf`, and does not count the receiver's fds, which it could
  not tell from the image's own), sets `umask 022`, pins `RLIMIT_CORE` to
  0/0 so a `ulimit -c unlimited` followed by `kill -SEGV` cannot write the receiver's memory to
  `/cores`, resets the signal mask and dispositions, nulls the Mach exception ports of the task
  and the exec thread (crash and corpse included) a non-hardened receiver would otherwise
  inherit from the caller (a crash would hand the caller the task port), and derives
  `execArgv[0]` itself (6.3.8). The bootstrap port is not reset (6.3.8).
- **A compromised nazar process**: **not in slice 1.** No secret key has Secure Enclave user
  presence yet (3.5), so a compromised nazar-agent opens every secret; the Vault ACL (S5)
  keeps every other process away from the items. After S13, secrets whose gates are all
  `block` or `login` with `scope: use` get the chip's check, as such ssh keys do.
- **TOCTOU between checking and exec'ing a receiver.** Closed for `late-env` by verifying the
  live process after the last `NOTE_EXEC`, plus the pipe-sharing check. For `env` the CLI
  re-checks the file's identity (`fstat`) immediately before `execve` of the app's realpath
  (6.3.6); what remains is the microsecond window below, which is why `env` is last resort.
- **Rolling a secret back from an old file.** There is no file to restore: the Vault item is
  the only copy (3.3).

**What it does not protect against**
- **The receiver itself.** Once delivered, the receiver can copy, log, or send the secret.
  Rules choose *who* receives it, nothing more.
- **Children of the receiver** inherit a late-env variable as an ordinary startup variable;
  `ps eww` on them shows it.
- **Launcher supply chain, including the launcher's config files.** `to: [{command: [npx, …]}]`
  pins the command line, not the package `npx` fetches, and not how `npx` runs it. The
  environment is allowlisted (6.3.4) and the working directory is `/` (6.3.7), but the real
  `HOME` is kept, so the genuine pinned
  launcher reads `~/.npmrc` (`registry`, `script-shell`, `cafile`, `strict-ssl`),
  `~/.config/pip/pip.conf`, `~/.config/uv/uv.toml`, `~/.pypirc`, its cache (`~/.npm/_npx`),
  and the global config inside its own install tree (`<node prefix>/etc/npmrc`, npm's bundled
  `npmrc`; user-writable under mise and Homebrew, of which only `npx-cli.js` and the `node`
  it runs under are pinned), all writable by any process of the user. One edit there runs
  attacker code *as the receiver*, with the pinned path, the pinned hash, the argv tail, the
  environment and the working directory all unchanged, and the dialog (if one is shown) naming
  the genuine `npx` and the genuine package. (An edit to a **pinned** file, `npx-cli.js` or
  `node` itself, is not in this list: it is caught by the recorded pin and needs a dialog,
  6.3.7.)
  nazar does not pin these files. Mitigations, in order of strength: a `path:`/`signed:`
  receiver on the program itself for secrets that matter (the pin is then on the code that
  reads the secret); `scope: use` or `session` so a config-file edit does not pay off silently
  for days (`config check` warns on `gate: none` or `scope: app` with a launcher receiver,
  section 4); `envAllow` kept empty and no `cwd:`, so the caller cannot add a second way in.
  The README says all of this next to the `npx` example.
- **What an approved `cwd:` opens.** A receiver entry with `cwd: /abs/dir` runs in a directory
  the user, and so every process of the user, can write to. nazar pins the directory's
  identity, the files named in the argv, and (for a launcher) the presence of the project
  markers in it and of the root-moving markers in its ancestors (6.3.7), but not the
  contents of `node_modules/` or `.venv/`, the project's own `package.json`/`pyproject.toml`
  bytes, the user-level files under `HOME` (`~/.npmrc`, `~/.python-version`: never pinned,
  for any `cwd:`), or what the pinned script `require`s: a secret delivered to a project is delivered to
  whatever that project contains, and `config check` warns for a launcher with a `cwd:`. With
  `cwd: caller` (binary receivers only) whatever the binary reads from the caller's directory
  (`.git/config`, a repo's hooks) is the caller's. Neither is the default; the default is `/`,
  which opens nothing.
- **The receiver's outbound path.** Proxy variables are not passed unless the user lists them
  in `envAllow`; TLS-trust variables can never be passed (deny set). The receiver's own config
  files can still set a proxy and disable certificate checks (`~/.npmrc` `proxy=`,
  `strict-ssl=false`), which is the config-file limit above; what a receiver sends where is the
  receiver's business (section 2).
- **`env` while the command runs**, by any process of the user, as measured. And for `env`
  only: a file replaced inside a `defaults.trustedPath` directory in the microseconds between
  the CLI's `fstat` and the kernel's open in `execve` receives the value; macOS has no
  `fexecve` to close this (6.3.6, S16).
- **A script receiver's bytes between the last hash and the interpreter's read.** For
  `late-env` the app re-hashes the script right before the write (6.3.3), and the CLI checks the
  script's identity right before `execve`, but the interpreter reads the file after the
  loader has already delivered the value; a swap inside a `trustedPath` directory in that
  moment is not seen. The directories in `trustedPath` are user-writable by nature (mise,
  Homebrew), which is a stated trust assumption of `command:` receivers, not a guarantee.
- **`stdout` consumers.** `$(nazar get X)` puts the value in the shell and everything the shell
  passes it to; shell `set -x` or history of a command containing the expanded value leaks it.
- **Memory.** Go cannot `mlock`; plaintext may be copied by the GC or swapped. Buffers are
  zeroed after use as a best effort; a core dump of nazar-agent can contain values (the
  target's `RLIMIT_CORE` is pinned to 0, 6.3.8; nazar-agent's own is the agent's). A receiver without the
  hardened runtime (Homebrew's `node`, `python3`, `gh`, `uv`, as measured) can be
  debugged by a process of the same user where Developer Mode allows it, after the value is in
  its memory; mise's official Node builds have the hardened runtime and cannot.
- **Root, kernel, or a Secure Enclave compromise**, as in spec 8.
- **Approval scope misuse.** Anything inside an approved `session`/`app` scope with a
  matching `to:` is silent, by design; `scope: use` is the strict option.
- **FIFO denial of service.** A process that opens the FIFO for reading alongside every
  legitimate reader makes every delivery ambiguous (it has to keep re-opening: a lingering fd
  on an already-served FIFO affects nothing, 6.2). It is audited and shown with the sniffer's
  pid; it is not prevented.
- **FIFO timing attacks.** A read end opened in the microseconds between the reader's open and
  nazar's swap, then hidden in an in-flight `SCM_RIGHTS` message during both scans, is not seen
  (6.2). After the swap no read end can be created by name.
- **What a genuine git transport can be told to do.** `GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0`
  prints the `Authorization` header; `-c http.proxy=… -c http.sslVerify=false` sends it to a
  local proxy; `credential.helper='!…'`, aliases and hooks run programs with git as their
  parent. In all of these the helper's parent is the real `git-remote-http` and `to:` passes;
  nazar cannot read the transport's environment or config (6.1). `apps:` and `scope: use` with
  `gate: login` are the mitigation; the receiver check for `helper` is a guard against mistakes,
  not against a hostile shell in an approved scope.
- **A surviving copy of the Vault item** (the login Keychain database in a backup, restored on
  this Mac) opens the secret after `rm` (3.4). There is no enclave-side erase with CryptoKit;
  S15 checks.
- **Who owns the Vault ACL.** With `AuthNone` keys (every secret key in slice 1, 3.5),
  whatever can use the Vault item (nazar-agent, by its signature: spec 4, S5) can open every
  secret; the agent is the trust boundary.

## 11. Testing strategy

**Unit (Go, fake platform, no hardware):**
- `core/secrets/seal`: RFC 9180 A.3.1's first encryption (P-256 / HKDF-SHA256 /
  AES-128-GCM) opened through the `KeyExchanger` adapter with an `Agree` callback, asked once
  with `enc`; the wire format in both directions against `crypto/hpke` built from the suite
  ids `0x0010`/`0x0001`/`0x0002` and the `info` string; another name, another key, a flipped
  bit, a malformed `enc` (never reaching the enclave) and a truncated ciphertext all fail with
  `ErrOpen`; the enclave's error comes back unchanged; a wrong-sized agreement is an error;
  empty and over-32-KiB values are refused.
- `core/secrets` store: add, open, replace (same key, same `created`, new `enc`),
  the record holds no plaintext and exactly its eight fields; slice 1 creates only
  `key-agreement/none` keys; names (`config.ValidSecretName`, incl. `k8s/hydra`) and
  case-insensitive collisions refused before any key is made; a vault that cannot be read
  refuses `add`; the largest value's record fits a Keychain item; nothing is left behind when
  the vault write fails or the platform's public key is not its handle's; a record copied to
  another name is broken, and with its name rewritten does not open; broken, unreadable,
  future-version and non-secret-named items are listed without disturbing the rest; `rm` order
  (`DeleteKey(handle)` then `Vault.Delete("secret/<NAME>")`; `DeleteKey` failing → record
  untouched; `Vault.Delete` failing after a successful `DeleteKey` → the secret no longer opens
  and a second `rm` finishes; a handle shared with another record is not deleted; an
  unreadable record is never touched; a corrupt one is removed).
- `core/config`: every validation row of section 4; classify loosen/tighten for each field
  (`file` loosens, adding an `envAllow` name loosens and removing one tightens);
  `envAllow` validation: `[NODE_OPTIONS]`, `[npm_config_registry]`, `[Npm_Config_Registry]`,
  `[XDG_CONFIG_HOME]`, `[GIT_SSH_COMMAND]`, `[NODE_EXTRA_CA_CERTS]` are errors naming the deny
  entry matched; `[HOME]`, `[PATH]`, `[LC_ALL]` are errors ("set by nazar"); `[HTTPS_PROXY,
  NODE_ENV]` is accepted; the launcher-receiver warning fires for `to:` resolving to
  `npx-cli.js`/`pipx`/`uvx` with `gate: none` or `scope: app` and not for `scope: session`,
  not for a `path:` receiver, and not for `node /abs/server.js`, and fires for a launcher with
  any `cwd:`; **`deliver` downgrade:** `deliver: [late-env, env]` → `[env]` classifies as
  **loosening** naming the secret and `env`, `[late-env, env]` → `[late-env]` tightens,
  `[helper, stdout]` → `[stdout]` loosens; `core/broker`: a cached `late-env` approval does not
  serve an `env` request for the same `(target, rule, scopeID, receiver)`; **`cwd` validation
  (6.3.7):** `cwd: relative/dir` error; `cwd: /nonexistent` is a **warning** and the entry is
  stale (the config parses, `Parse` is given no filesystem and the test asserts it makes no
  `stat`); `cwd: ~/projects/foo` expands and realpaths (a symlinked `foo` pins the target's
  `{dev, ino}`); `cwd: caller` accepted on `{path: /opt/homebrew/bin/gh}` and on
  `{command: [deploytool, …]}`, a warning leaving the entry inactive on `{command: [node,
  /abs/server.js]}` and on `{command: [npx, …]}` (and the run refused before the gate for all
  three matcher kinds); **rules by first-match proof:** removing a `gate: block` rule that
  shadowed a `gate: none` rule on the same secret is a loosening; adding a stricter rule in
  front is not; **`path:` receiver resolving to an interpreter:** `to: {path:
  /opt/homebrew/bin/node}` on a `nazar run` rule warns naming `command:`; a `path:` entry on
  `npx-cli.js` with `cwd:` gets the launcher warning and the context pin; **file elements:** `[node, server.js]` without `cwd:` is an error naming
  `server.js`, with `cwd: /abs/dir` it is pinned (`files: [{arg: 1, path:
  /abs/dir/server.js, sha256, file}]`) and an absent `server.js` is a warning that leaves the
  entry stale; `[node, -r, ./setup.cjs, /abs/app.js]` pins two files, as do `[node,
  --require=./setup.cjs, /abs/app.js]` and `[node, --import=./x.mjs, …]`; `[node,
  --frobnicate=./x, /abs/app.js]` warns naming `--frobnicate=./x`; `[python3, -m, mod]` pins none; `[npx, -y,
  "@brave/brave-search-mcp-server"]` pins none (`@brave/…` is not a file element even when a
  file of that relative path exists under a `cwd:`); `[./bin/server]` as `argv[0]` is an
  error; `cwd:` on a caller-position entry (`apps: [iterm]`) is ignored; classify: setting and
  changing `cwd` loosens, removing tightens; **context pin** for a launcher with `cwd:` built
  over the directory and its ancestors from a fake filesystem tree (marker set in the
  directory; presence of the root-moving markers only in the ancestors; no hashes; `~/.npmrc`,
  `~/.python-version` and a non-root ancestor's `.npmrc` absent from the pin whatever their
  state); `config check` warns when the directory holds no marker and an ancestor would be the
  project root; **recorded receiver pins** (6.3.7, `core/configstage` with a fake
  `ReceiverPinStore` and a fake filesystem): a reload with unchanged text and a changed
  `server.js` classifies as **loosening** with the diff naming the entry, the file and both
  hashes, and the active matcher still carries the **old** hash until approval; the same for a
  changed `npx-cli.js` (the executable pin), a changed `node` (the interpreter pin, cdhash), an
  executable that now resolves to another realpath, a recreated `cwd:` directory, a changed
  context set, and an identity-only change (same bytes, new mtime: gated, with the "same bytes"
  line); unchanged pins → no change, no dialog, **no write** to the pin store; **the restart
  attack:** `server.js` (and separately `npx-cli.js`) rewritten, then `OpenWithTrust` on the
  same `config/approved` bytes → the active matcher carries the recorded hash, a loosening is
  staged, `match.Receiver` against a synthetic chain built from the new bytes is a mismatch, and
  `ReceiverProblems` names the file; **the reload attack:** file rewritten, `Stager.Reload()` →
  staged, nothing applied, the store untouched; **approval records what was shown:** stage,
  rewrite the file again, approve → the set written is the one the dialog showed, not the
  third version, and the pin store's `Replace` is called exactly once, before `config/approved`
  is written; **hash discipline:** two reloads with the same text and different pins have
  different `Pending.Hash` values and `Approve` with the first hash after the second reload is
  `ErrStale`; **new trust:** a receiver entry whose key has no record is inactive until a
  dialog showed its pins in a pin change, never in the text change that adds it;
  renaming an entry while keeping its command and `cwd:` is not a new key; changing argv or
  `cwd:` is; a retargeted `cwd:` symlink is a changed `cwd` pin under the same key; a key the
  text dropped lingers until the next approval writes the set and is reused, with the
  `re-using pins approved on …` line, when the entry comes back with matching observed pins;
  **pins never hold a tightening hostage:** with `npx-cli.js` `touch`ed (identity-only
  difference) a text change that tightens (`gate: block` on the secret) **applies at once**
  with the recorded pins installed and the pin store untouched, and a pin change is staged
  right after against the new text; with the same stale pin a text change that loosens is
  staged **without** the re-pin in its diff or its `ReceiverPins`, and after its approval the
  re-pin is staged as its own pin change; **text changes never carry pins:** a loosening that
  adds a new `to:` entry, re-keys an existing one (`cwd: /x/foo` → `/x/foo/./`, which `Clean`
  folds to the same key, and `server.js` → `./server.js`, which does not) or re-adds an entry
  a tightening removed has an empty `ReceiverPins`, no `pinned (new)` line, writes nothing on
  approval, leaves the entry inactive, and the pin change staged right after is what records
  it; adding an `apps:` entry no rule names produces no finding, no record and no line;
  **no background prompt:** a staged pin change never triggers the app's prompt; neither
  `autoPrompt` site (the poller's `Reload()` and `configApply`'s blocked path) fires for a
  `PinOnly` change, `config.apply` without `hash` returns the `ConfigDiff` and opens nothing,
  `config.apply` with the printed `Pending.Hash` shows it under the pin-change title and
  `ConfigDiff.pinOnly` is true; a text change saved while the pin change is staged takes the
  slot and `config.apply` with the pin change's hash is `ErrStale`; **two pin-change kinds:**
  with `npx-cli.js` edited (a re-pin pending for `brave-mcp`) and `my-server` newly added and
  its rule approved, the pin change staged right after that approval (no file change, no
  poll needed: `Approve` runs the comparison) is `pinKind: new`, lists `my-server` only and
  contains no `brave-mcp` line; after it is approved the re-pin is staged as `pinKind:
  changed` with `brave-mcp` only; **re-resolved file elements:** `server.js` replaced by a
  symlink to `/tmp/evil.js` with the same bytes at the target → `receiver changed: server.js`
  before the prompt and before the write, and the CLI's `openat`-on-verified-directory open
  refuses it for `env`; a `server.js` that is a symlink at load is unresolvable, not pinned
  by target; **poller interval:** with unchanged bytes the comparison runs at most once per
  `ReceiverCompareInterval` and once immediately after each apply (the fake filesystem counts
  its `stat`/`open` calls); **stale observation:** an observed set computed for config A is
  not compared when config B is active by the time the lock is taken, and resolution reruns;
  **recovery re-load:** `Approve` of a recovery set whose `Load()` now succeeds compares
  against the loaded record instead of replacing it; **hostile pinned files:** a FIFO at `server.js`, a 200 GB
  sparse file and a symlink to a FIFO each leave the entry stale within the poll's deadline,
  `Observe` returns, and a tightening saved meanwhile applies; **the equal-text poll:** `Observe` with bytes equal
  to the active text keeps a staged pin change (and stages one when the files changed since
  the last poll), and clears the slot only when nothing differs; `ApplyAuthenticated` installs
  recorded pins, writes nothing to the pin store and re-stages the pin change; the daemon's
  pending guard lets `secret add` and `ssh-key create` through with a `PinOnly` change pending
  and refuses with a text change pending; **quoting:** a `cwd:` directory named
  `foo\n~/evil re-pinned: ok` and a file element with a bidi override produce one `Changes`
  line each, ASCII-only; **fail closed:**
  the store returning `ErrUnreadable` (corrupt item, `version: 2`) leaves every receiver
  matching nothing, `ReceiverProblems` carries the cause, nothing is written until an approval,
  and `Reload()` then stages every receiver as new trust; a missing item behaves the same minus
  the cause; a `version: 0` item is read and rewritten as `version: 1` at the next approval; a
  tightening never writes; `ApplyAuthenticated` installs recorded pins and never writes;
  **ordering:** `Replace` failing leaves the change staged and `config/approved` unwritten;
  `config/approved` failing after a successful `Replace` leaves the change staged and the
  retry writes the same set; an unresolvable file at start (deleted `server.js`, a `cwd:`
  directory removed, `npx` now a mise shim) stages nothing, keeps the recorded pin, is
  reported as stale, and leaves the **rest of the config active** (the ssh keys and the other
  secrets still work; the config never falls back to the built-in default because of the
  filesystem), and the same deletion observed by `Observe` is not `Invalid` and does not clear
  a staged change; `config check`/`status` list
  stale, unpinned and pending entries by name with the fix; `trustedPath` resolution,
  shebang pinning, shim refusal, `kind` on the resolved matcher; `core/policy` `LiveRuleIDs`
  for secrets; user-presence decision from the post-command config (3.5).
- `core/policy`: `EvaluateSecret` for each delivery's `ask`/`recv` split; `deliver` miss →
  `blocked` before any rule; `command:` receiver: pinned path + code identity + byte-exact
  argv tail, `argv[0]` ignored; synthetic chain for the static pre-check built from the app's
  resolution, never from a path in the request; first-match and `to:` fall-through as for ssh;
  helper receiver is the transport (parent `git-remote-http` with `com.apple.git-remote-http`
  matches `to: [git-https]`; parent `git` running `credential fill` does not, with the shell
  hint in the reason; `aws configure export-credentials` refused); `config check` warns on
  `helper.git` with a `to:` of `com.apple.git`.
- `core/broker`: cache key includes receiver identity; prompt text for each delivery; audit
  fields `delivery`/`handover`; `Verify` hook → one audit line after the post-exec verdict with
  `decision=denied`, not `error`.
- `core/secrets/fileserver` with a fake `OpenersOf` and a fake swap: zero/one/two readers, a
  foreign writer, re-scan before write detecting a new opener, dead-ref reader, value ≤ 16 KiB
  in one write, nothing written on deny, existing non-FIFO at the path refused and **not**
  unlinked; **one reader, one write, then EOF**: a reader that keeps its fd open after the value
  reads 0 forever, the loop's next `open` blocks on the fresh FIFO, `EvaluateSecret` is called
  exactly once and nothing is written twice (this test fails against a loop that re-opens the
  same FIFO); a second `open(path)` by the same process is a second request; the swap guard: a
  foreign file at the path at detach time is left in place, nothing is unlinked, the secret
  stops being served and the warning names the file.
- `core/secrets/run`: `RunPlan` decisions (`receiverKind` from the realpath table of 6.3 step
  3: `…/npm/bin/npx-cli.js` and `npm-cli.js` → `launcher`/`socket` although the typed `argv[0]`
  was `npx`/`npm`, `pipx` and `uvx` console scripts → `launcher`, `bun` with `argv[1] == x` or
  resolved from a `bunx` entry → `launcher`, `node`/`python3.14` → `interpreter`/`fd`, `deploytool`
  → `binary`; the typed name is never consulted; `-S`/`-E`/`-I` refused; `--secret`
  auto-choice; `late-env` refused when the final hop's environment is unreadable);
  **resolution** (6.3.6: absolute, relative-with-slash (`./bin/server`) refused as `usage`
  with the peer's cwd never consulted, bare name
  through `trustedPath` only with a planted earlier `$PATH` entry never used, not found →
  refused, mise shim refused, `xcode_select` shim → `DEVELOPER_DIR`, symlink → realpath,
  shebang `#!/usr/bin/env node` → pinned interpreter + `execArgv`, with `resolvedFile` the
  script's stat and `interpreterFile` the interpreter's, unsupported shebang refused;
  `execArgv[0]` is the resolved entry's base name whatever `argv[0]` the request carried,
  `exec -a evil npx` style included);
  `receiverPrecheck: mismatch` refused before the gate is ever consulted (the fake `Confirm` is
  not called); **working directory** (6.3.7): the plan's `cwd` is `/` with `cwdSource:
  default` for an entry without `cwd:` **whatever the peer's `ProcessInfo.Cwd` is**; the
  entry's realpath with `cwdFile` for `cwd: /abs/dir`; the peer's `ProcessInfo.Cwd` for `cwd:
  caller` on a binary, and `blocked` before the gate for `cwd: caller` when the resolved kind
  is `interpreter` or `launcher` (a `signed:` entry resolving to `node`); a `cwd` string in the
  request is `usage`; pinned file element changed after load → `blocked reason="receiver
  changed: server.js"` before the gate; context pin: `node_modules` or `package.json` appearing in an ancestor,
  a marker (`.npmrc`, `node_modules`) appearing in the directory → `blocked
  reason="receiver context changed: …"`, while a changed `package.json` **inside** the
  directory, a new file under its `node_modules/`, and `~/.npmrc` created, edited or removed
  with the `cwd:` under `~` are **not** refused (the documented limits, asserted as such);
  a `blocked reason="receiver changed: server.js"` refusal carries the `config reload` hint; `--handover fd` for a launcher and `--loader python` for a Node receiver
  are `usage`; **environment** (`envpolicy`, 6.3.4): the plan's `env` is built from the fake
  passwd entry, `confstr` and `trustedPath` whatever `callerEnv` says (`callerEnv` with
  `HOME=/tmp/h`, `PATH=/tmp/x:/usr/bin`, `USER=root`, `TMPDIR=/tmp/t` → the plan has the
  user's home, `trustedPath`, the user's name, the Darwin temp dir); `LANG=en_US.UTF-8` and
  `TERM=xterm-256color` pass, `LANG=../x` and a 40-byte `TERM` are omitted; **negative
  cases, each asserting the name is absent from `RunPlan.env` and present in `envDropped`:**
  `npm_config_script_shell`, `npm_config_registry`, `NPM_CONFIG_REGISTRY`, `XDG_CONFIG_HOME`,
  `PIP_INDEX_URL`, `UV_INDEX_URL`, `PIPX_HOME`, `VIRTUAL_ENV`, `NODE_OPTIONS`,
  `PYTHONSTARTUP`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `SHELL`, `HTTPS_PROXY`, `NAZAR_X`, and a
  made-up `FOO`; the app applies the filter even when a `callerEnv` built by hand (not through
  `CandidateEnv`) carries `NODE_OPTIONS`; `envAllow: [HTTPS_PROXY]` on the secret passes the
  caller's value and sets `envPassed`; two secrets in one run pass a variable only when both
  allow it; an `envAllow` name absent from `callerEnv` is simply absent; the loader variables
  use the app's bundle path whatever the request says; `--as NAME=VAR` with `VAR` in the deny
  set, a base name, `SHELL`, or an `envAllow` name is `usage`); **exec-chain acceptance**
  (binary hop, interpreter hop with realpath'd script element and the script re-hashed before
  the write, a script whose bytes changed after the pre-check → denied, `/usr/bin/env` hop
  refused, foreign hop, shebang `-I`, second exec under `fd` refused); **whole-environment
  comparison**: equal → served; one extra variable (`npm_config_script_shell`) → `denied
  reason="unexpected environment: npm_config_script_shell"`; one missing → denied; an allowed
  variable with a changed value → denied; `ErrUnreadable` → `denied reason="unexpected
  environment: not readable"`; unreadable argv → denied; **post-exec directory**: the
  final hop's `ProcessInfo.Cwd` ≠ `RunPlan.cwd` → `denied reason="receiver changed at exec:
  cwd /tmp/e"`; a pinned file element re-hashed before the write and changed → denied;
  **pipe-sharing check** (the one fd check, 6.3.8): fake `OpenersOf(writeEnd)` returning
  exactly the exec'd pid → served, the exec'd pid plus another → `denied reason="pipe
  shared"`, a pid that is not the exec'd one → denied, an error → denied; and, asserted as
  the design rather than left implicit, the fake's fd table for the exec'd ref is **never
  consulted** (the fake records every `Platform` call and the test fails on any fd-listing
  call);
  CLI-side `fstat` identity mismatch on
  the binary, on the interpreter, on the script, or on the directory (`cwdFile`) → exit 1
  without exec, `fchdir` happening before the file opens; the CLI's process-state reset
  (6.3.8) unit-tested against a helper child: fds ≥ 3 marked `FD_CLOEXEC` except 3 for `fd`
  (checked twice: `F_GETFD` on each fd before the exec, and by identity after it, with the
  helper exec'ing a probe that `fstat`s every entry of `/dev/fd` and finds none of the
  planted objects), `umask` 022, `RLIMIT_CORE` 0/0 soft and hard, empty signal mask, `SIG_IGN`
  dispositions reset, exception ports null;
  socket handover: a rejected peer does not consume the accept and the verified peer is still
  served, one coalesced audit line per rejected pid, deadline from the plan; wire format with
  several secrets.
- `core/control`: peer requirement per command with a fake `VerifyPeer`; `secret.add` at
  100 KiB accepted, `secret.get` at 65 KiB refused; `valueBase64` round-trips non-UTF-8 bytes.
- `cmd/nazar`: stdin reading rules, `--json` kinds, exit codes, `migrate` parser on fixture
  files modelled on the two lines of 9.2 (literal, quoted, `$(…)` skipped), `migrate-mcp` on a
  fixture modelled on `~/.claude.json` (top-level and per-project `mcpServers`), git/docker/aws
  protocol encoders.

**Integration (`internal/testd` scenarios, real processes, fake enclave):**
- A real FIFO with a real `cat` reader, two concurrent `cat`s (ambiguous), and `python3 -c
  open().read()`; asserts the resolved reader chain. `exec 3<~/.nazar/run/files/X; read -u 3 a;
  read -u 3 b` gets the value once and then EOF with no second audit line; two sequential
  `cat`s are two requests; after a delivery `stat -f %i` of the path differs from the served
  FIFO's inode and the path is still a FIFO.
- `nazar run --late-env` with a real `node -e` and `python3 -c` target against the test daemon:
  the target prints `process.env.X`/`os.environ["X"]` after start; a parallel `ps eww <pid>`
  does **not** contain the value; fd 3 is closed in the target afterwards; the exec'd
  executable (`proc_pidpath`) is the plan's `resolvedPath` even with a `PATH` whose first entry
  holds a planted `node`; a `#!/usr/bin/env node` script is started as `node <realpath>`
  with no `/usr/bin/env` process ever appearing; `NODE_OPTIONS=--require /tmp/x.cjs nazar run …`
  starts the target with the app's `NODE_OPTIONS` only and `/tmp/x.cjs` is never loaded (a
  marker file it would write does not appear); the target's own environment dump equals the
  `--dry-run` plan's `env` exactly, with `HOME` the real home and `PATH` equal to
  `trustedPath` although the caller had `HOME=/tmp/h` and `PATH=/tmp/x:…`; the target reports
  `process.cwd()`/`os.getcwd()` as `/` although `nazar run` was started from a temp dir,
  no inherited fd, asserted **by identity, not by count**: the caller held fds 4–9 open
  without `CLOEXEC` on a regular file, a FIFO, a Unix socket, a pipe and `/dev/null`, each of
  known identity; inside the target every entry of `/dev/fd` is `fstat`ed (and `getsockname`d
  when it is a socket) and none has a planted identity, fd 3 is the handover pipe for `fd`
  and `EBADF` for `socket`, and fds 4–9 are each either `EBADF` or an object the target opened
  itself (the Python target additionally lists exactly `0 1 2 3`, which Node cannot promise:
  libuv's kqueue and wakeup pipe are open before any JS runs, the reason the app does not count
  fds, 6.3.8), `os.umask()` 022
  although the caller had `umask 000`, `resource.getrlimit(RLIMIT_CORE)` as `(0, 0)` although
  the caller had `ulimit -c unlimited`, `signal.pthread_sigmask(SIG_BLOCK, [])` empty and
  `SIGPIPE`/`SIGCHLD` at `SIG_DFL` although the caller blocked and ignored them; `python3 -c
  'import foo'` with a planted `foo.py` in the caller's directory fails with
  `ModuleNotFoundError`; a `command: [node, server.js]` entry with `cwd: <fixture dir>` runs
  the fixture's `server.js` although the caller's directory holds another `server.js`, and
  with the fixture's `server.js` rewritten after config load the run is refused before any
  dialog; **restart and reload against the real daemon:** the fixture's `server.js` rewritten,
  the test daemon stopped and started on the same Vault → `status` reports the pending re-pin,
  the run is refused before any dialog (the fake `Confirm` is never called, the cached
  `session` approval from before the restart is not consulted) and the Vault's
  `state/receiver-pins` item is byte-identical to before; then `nazar config reload` → `status`
  shows the staged change naming `server.js` and both hashes, the run is still refused, and
  only `nazar config apply` with the approval makes the new bytes run; the same sequence with
  the fixture's `npx-cli.js` (a copy of npm under a fixture `trustedPath`) for the executable
  pin.
- The same through `npx --no-install` of a local package and `uvx --from ./pkg`, with
  `--target`; asserts the launcher never had the value (`ps eww` on the launcher, plus the
  launcher's own `env` dump) and the child did. **Launcher-config negatives:**
  `npm_config_script_shell=/tmp/x.sh nazar run … -- npx …` runs the package bin through `sh`
  (`x.sh` leaves no marker, the child's environment has no `npm_config_script_shell`);
  `npm_config_registry=http://127.0.0.1:1 nazar run … -- npx -y <pkg>` resolves against the
  real registry (the local port is never connected to, checked with a listener that records
  connections); `PIP_INDEX_URL`/`UV_INDEX_URL` likewise for `uvx`; `HOME=/tmp/h` with a
  planted `/tmp/h/.npmrc` is ignored (`npm config get registry` inside the child shows the
  default). **Working-directory negatives (6.3.7):** `nazar run` started from a prepared
  directory holding `node_modules/@brave/brave-search-mcp-server` (a `package.json` with a
  `bin` pointing at `evil.js` that writes a marker) and a `.npmrc` with `script-shell=./x.sh`
  and `registry=http://127.0.0.1:1` runs the real package (no marker, the child's
  `process.cwd()` is `/`, `npm prefix` inside the child prints `/`, the local port is never
  connected to); the same directory holding `uv.toml`/`pyproject.toml` with `index-url` does
  not change what `uvx` resolves; a `cwd: caller` entry for a binary (`/bin/pwd` pinned by
  `path:`) prints the caller's directory, and the same entry's `cwd:` set to a fixture
  directory prints the fixture's. The honest positives: a `registry=` line written into the
  real `~/.npmrc` **is** honoured by the child, and a `node_modules/<pkg>` planted **inside**
  an approved `cwd:` directory **is** what a launcher receiver with that `cwd:` runs, which
  are the documented limits of section 10 and are asserted as such so the test suite states
  them rather than hides them.
- `SCM_RIGHTS` fd passing and `NOTE_EXEC` detection with a `sleep`-then-`exec` test child.
- `git credential fill` against `git-credential-nazar` with the test daemon; `docker-credential-
  nazar get`; `aws` `credential_process` JSON shape checked with `jq`.

**As built in M10:** `nazar run --secret NAME -- npx -y <pkg>` and `-- python3 /abs/x.py`
end to end with the real CLI, the real loaders and real `npx`, which installs test packages from a
registry the test serves on 127.0.0.1 (the receiver's `~/.npmrc` names it; on the Mac every other
host goes to a closed proxy port). Each proves: the target has the value in `process.env`/
`os.environ` and no `NAZAR_*` left; no process of the run's tree shows it in its startup
environment or command line (Linux: `/proc/<pid>/environ` and `cmdline`; the Mac: `ps eww` and
`KERN_PROCARGS2`, read only for the run's own processes), with positive controls; npx's own
process never connects; a dependency's `postinstall` that connects first is refused, audited and
does not consume the handover; the caller's `NODE_OPTIONS`, `PYTHONPATH` and
`npm_config_registry` never reach the receiver; no file left holds the value. On Linux
(`core/daemon/lateenv_e2e_linux_test.go`) the process seams are a test-only `/proc` platform. On
the Mac (`make integration-run`, `bridge/conformancehost/rune2e.go`) they are nazar-agent's own
Swift seams through the C ABI, the CLI and loaders are those of the built `nazar-agent.app` (whose
seal is checked unchanged afterwards), and a changed pinned file is refused three ways: the
script changed while the dialog is open (the CLI's `fstat`), nazar's loader changed while the
dialog is open (the check at the `NOTE_EXEC` record: `receiver changed at exec: nazar's loader
changed`, the program runs without the value), and the loader changed at rest (refused before
any prompt). The Mac test runs in the conformance host, not in a smoke host of the real agent,
because the receiver's home must be a test folder, which only a test daemon may choose: the
shipped core takes it from the user database.

**Conformance (`core/platform/conformance`, Swift once Milestone 3 lands):** `OpenersOf`
returns exactly the openers (with flags) of a FIFO and of a pipe the test opens;
`OnProcessExec` fires on **each** exec of a `sh -c 'exec env node …'` child, in order, and
reports the exit; `InspectCode` of `$(xcrun --find git)` is Apple-signed with `com.apple.git`,
of `…/libexec/git-core/git-remote-http` with `com.apple.git-remote-http`, of `/usr/bin/git`
with `com.apple.dt.xcode_select.tool-shim-public`, and of an unsigned script yields its SHA-256;
`Environment` of a child the test started with a marker variable returns it, and of
`/usr/bin/env sleep 30` (an Apple platform binary) returns `ErrUnreadable`, never an empty
list; the fake has an `ErrUnreadable` switch and the `run` tests use it; `OpenersOf` of a
pipe's write end whose read end was inherited by a child names exactly that child (and the
test itself while it still holds the read end), and `Process(ref).Cwd` of a
child started in a temp dir is that dir's realpath; `VerifyPeer` on a
same-user unsigned client fails; `KeyAgreement` on an `AuthUserPresence` key with a live ref
works and with a released ref returns `ErrAuthRequired` (already there); `keys/sealed-secret`: a value sealed to a key-agreement key opens through `KeyAgreement`, not through
another key, and not after `DeleteKey`.

**Manual script (dialogs):** import `BRAVE_API_KEY` for real; start Claude Code; the first
Brave search shows one dialog, the second none; `nazar run --late-env BRAVE_API_KEY -- printenv`
from Claude Code is blocked with the warning; `ps eww` on the Brave server process shows no key;
`ps eww` also shows `HOME` as the real home and `PATH` as `trustedPath`, and no variable from
the terminal's environment beyond the base set; `lsof -p <pid>` of the Brave server shows `cwd`
as `/` and, compared with `lsof -p` of Claude Code, no file, pipe or socket in common above
fd 2 (its own kqueue, pipes and sockets are expected); restart Claude Code in the same tab → one
dialog again (the `session` scope is the Claude Code run, 9.1); editing the rule to
`scope: app` makes `config check` print the launcher-receiver warning. `git fetch` over HTTPS
in iTerm → Touch ID once per tab;
`cat ~/.nazar/run/files/X` in a second tab → prompt; `cat` twice at once → block warning naming
both. Rotate the Brave key afterwards and confirm the old value is nowhere on disk
(`rg -a <old value> ~ -g '!Library/Caches'` finds nothing).

## 12. Open questions and spikes

| # | Question | Pass criterion | Fallback |
|---|---|---|---|
| **S9** FIFO reader identification | Does `proc_pidinfo(PROC_PIDLISTFDS)` + `PROC_PIDFDVNODEPATHINFO` find every process holding a read end of a FIFO, for one and for several readers, within 50 ms on this Mac, including readers inside App Sandbox-less but hardened apps? Does `renamex_np(RENAME_SWAP)` exchange two FIFOs inside `~/.nazar/run/files/` atomically on APFS while a reader is blocked on one of them, with the blocked reader unaffected and new openers landing on the new FIFO (6.2)? Which of `curl --netrc-file`, `kubectl --token`-file, `aws` shared credentials, `gcloud`, Go `os.ReadFile`, Node `readFileSync`, Python `open().read()`, `cat`, `jq -R` read a FIFO correctly? | 100 % identification over 200 trials with 1–3 readers; 1000 swaps with a blocked reader, none lost, none double-served; a written table of tools | Offer `file` only for tools in the table; `config check` warns for others. If identification is unreliable, `file` ships disabled by default (`deliver` must list it). If the swap fails, `mkfifo` at a temp name + `rename` over the path after the write, accepting the brief window in which a reader could open the old FIFO |
| **S12** loader handover | (a) Does fd 3 reach the child of `npx -y <pkg>`, `pipx run`, `uvx`, `uv run`, `pnpm dlx`, `bunx`? (b) Does the `socket` handover reach it in every case, and can `net.connect` be drained synchronously in the Node loader before the target's first line? (c) Does `NODE_OPTIONS --require` fire for ESM entry points and under `npx`'s nested `node`? (d) Does the `sitecustomize` hand-over work inside a `uv`-managed venv, a `pipx` venv and the mise Python 3.14? (e) Do `npx -y <pkg>`, `pipx run`, `uvx`, `pnpm dlx` and `bunx` start their tool normally with the working directory `/` (6.3.7), with a cold and a warm cache, and does each of them, started from a directory holding a planted `node_modules/<pkg>`/`.npmrc`/`uv.toml`, ignore that directory once `nazar run` has `chdir`ed to `/`? (f) Is `ProcessInfo.Cwd` of each exec'd launcher still `/` at the moment the chain settles, i.e. does none of them `chdir` during startup (the post-exec directory check of 6.3 step 6 observes the live directory, 6.3.8)? | (a) a table; (b) yes in all; (c) yes; (d) yes; (e) yes for all five, with `npm prefix` inside the child printing `/`; (f) yes for all five | If (b) fails for a launcher, that launcher is served with `env` and listed; if (c) fails for ESM, use `--import` for Node ≥ 20.6; if (d) fails, a `.pth` file in a temp site dir instead of `sitecustomize`; if (e) fails for a family, the default directory becomes `/private/var/empty` (root-owned, root-owned ancestors) and 6.3.7 says so; if (f) fails for a family, that launcher's directory check runs on the `NOTE_EXEC` callback's first `ProcessInfo` read instead of at settle time, and 6.3.8 names the family |
| **S13** enclave key agreement under `userPresence` | Does `SecureEnclave.P256.KeyAgreement.PrivateKey` with `.privateKeyUsage + .userPresence` accept a reused, authenticated `LAContext` for the same 6–10 minute window S1 measured for signing? (S1 found no reuse past 10 minutes, so "hours" is not the question.) | 20 agreements over 6 min with one context, no prompt; a prompt reappears after 10 min, as in S1 | Every secret key stays `AuthNone`, which is already slice 1's rule (3.5) |
| **S14** fd passing + exec detection across the bridge | Can the Go `control.Server` receive an `SCM_RIGHTS` fd on the socket the Swift app owns? Does `kqueue` `NOTE_EXEC` fire on **every** exec of a watched pid (including a `sh -c 'exec env node …'` chain used as a stress case), with each post-exec path and argv readable before the target runs user code? **Readability:** for each of (i) an Apple platform binary (`/usr/bin/env`, `/bin/sleep`), (ii) an Apple team-signed Xcode tool (`xcrun --find python3`, `xcrun --find git`), (iii) a non-Apple hardened-runtime binary (mise `node`, Homebrew `python3`), (iv) an unsigned script interpreter, can the user's own process read **argv** and **environment** through `KERN_PROCARGS2`, separately? Can `OpenersOf` find the read end of a pipe by `fstat` identity? **Sweep completeness (6.3.8):** after the CLI's `FD_CLOEXEC` sweep, does an `execve`d probe see any fd above 2 (+3) left by the Go CLI itself (runtime kqueue, signal pipe, the control connection), with the caller having passed fds 4–9 on a file, a FIFO, a socket and a pipe? **Inherited state (6.3.8):** does a task exception port set by the parent before `fork` survive `execve` of (iii) a hardened-runtime image and (iv) an ad-hoc one, and does `task_set_exception_ports(mach_task_self(), EXC_MASK_ALL, MACH_PORT_NULL, …)` in the child before `execve` clear it in both? | 200/200 runs, every hop seen in order; no leaked fds (`lsof` count stable); the probe sees exactly `0 1 2` (+3) in 200/200 runs; a four-row table of argv/environment readability, which fixes the README's list of interpreters that cannot take `late-env` (6.3.4); a two-row table of exception-port inheritance with the CLI's reset shown effective | Fall back to polling `proc_pidpath`+argv every 5 ms for 10 s; if fd passing fails, the app opens the FIFO-style path `~/.nazar/run/<id>` as the pipe; if the environment of class (ii) is unreadable, `migrate-mcp` and `--secret` choose `env` for Xcode interpreters and say why; if the exception-port reset is not effective for an ad-hoc image, 6.3.8 and section 10 say so and the README recommends hardened interpreters; if the probe sees a Go-runtime fd, the CLI closes it explicitly after the sweep (it is about to exec) and the sweep test pins that fd |
| **S15** enclave-side erase | Does CryptoKit (or `SecKey` with `kSecAttrTokenIDSecureEnclave`) offer any operation after which a saved `dataRepresentation` stops working, or is "delete" only the Keychain item? Does a Keychain item restored from a backup copy of the login keychain database still open old blobs? | A written answer with a reproduction either way | Section 3.4 wording stands (handle erase); if an erase exists, 3.4 adopts it and the Deletion row says crypto-erase again |
| **S16** exec by fd | Does `execve("/dev/fd/N", …)` of an opened Mach-O binary work on this macOS, does the resulting process report the binary's real path through `proc_pidpath`, and does its code identity verify (library validation, hardened runtime)? | 100/100 runs for a Homebrew binary (`gh`) and an Xcode tool (`deploytool`); `proc_pidpath` equals the realpath | `env` keeps the `fstat`-then-`execve(path)` sequence of 6.3.6 and section 10 keeps the stated microsecond window |
| Vault item count | Does one Keychain item per secret (plus one per ssh key), each up to ~45 KiB (3.3), stay fast and silent with ~50 items? | `secret list` < 200 ms | One Vault item `secrets/index` holding every record |
| `aws` helper shape | Is one JSON-valued secret acceptable, or should access key id and secret be two secrets with one approval? | Open | Two secrets, same rule, scope cache makes the second silent |
| `gate: none` with `file` | Allow it (a trusted app reading a token file silently) or refuse like `env`/`stdout`? **Proposed: allow**, since the reader is checked live and nothing is printed or `ps`-visible | Review | Refuse |

Spikes S9, S12, S14 and S16 are throwaway code under `spikes/` and run **before** the task
that needs each (S9 before `file`, S12 and S14 before `nazar run`, S16 before `env`); S13 and
S15 before any change to 3.5 or 3.4; their results are recorded in this document (S12 in 6.3
"As built in M10", S14 below and in 6.3.4) and the fallback column is applied to this document
where a spike fails. The main spec's section 11 table gains these rows (section 14).

**S14 as run in M10** (on the Mac): the `SCM_RIGHTS` and
`OpenersOf` questions and the "(+3)" of the sweep criterion are void, since nothing is passed
and every fd from 3 up closes (6.3, D1). "Every exec seen in order" is a contract of
`platform.Exec`, held on the real platform by the `exec/` conformance group. What ran: the
time from `NOTE_EXEC` to the agent's argv read against npm's argv rewrite, through the shipped
`ExecWatcher` (200 runs; the fallback is the launcher's hold: `npx`'s own loader waits until the
agent has checked the exec); the readability table; the CLI's sweep and resets through
`TestRunResetsTheProcessBeforeExecOnMacOS` (200 runs) with the exception-port table; and the
re-checks on macOS of what S12 had measured only on Linux. Outcome: the
read came first in 250 of 250 runs by at least 20 ms, so the hold is not built; framework-build
pythons exec again and are refused at resolve; the resets held 200 of 200 times; S12's results
hold on macOS.

## 13. Build order

1. `core/secrets/seal` (HPKE through `crypto/hpke`, the RFC 9180 A.3.1 vector through the
   adapter) and `core/secrets.Store` (the Vault records of 3.1–3.4, handle erase), plus the
   `keys/sealed-secret` conformance subtest: Milestone 8. Pure Go; the platform needs no change.
2. `core/config` secrets section + classify; `core/policy.EvaluateSecret` and
   `LiveRuleIDs`; `caller.Chain.Parent`; `core/broker` secret/delivery/receiver fields and
   prompt text; the audit `delivery` field: Milestone 8, for `helper` and `stdout` only.
   `defaults.trustedPath`, `core/match` pinned command receivers, `caller.Synthetic`, the
   `Verify` hook and the other audit fields move to step 6, which is the first to need them.
3. **Built in Milestone 8:** the genuine-CLI peer check (`control.Server.VerifyCLI` and
   `PeerIsNazarCLI`, built in the bridge with `core/codesign` and the compiled-in pin; no
   `Platform.VerifyPeer`, 7.3), control commands `secret.add/list/delete/get`, CLI `secret
   add|list|rm`, vault health and the "configured but not stored" warning. `nazar get` moves to
   step 4 with the git helper.
4. **Built in Milestone 8, for git:** `secret.helper`, `helper.git`, the `git-credential-nazar` front end
   with transport narrowing (https, the configured host, git's HTTPS transport as the receiver),
   the link in `nazar install` and the cask, and `nazar get`. `docker` and `aws` come later.
5. Platform additions (`OnProcessExec` multi-hop, `InspectCode`, `OpenersOf`, `Environment`
   with `ErrUnreadable`; `VerifyPeer` is not needed since Milestone 8, 7.3) in the fake, the conformance suite and the Swift layer
   together (`CodeHash` untouched, 5.1).
6. `nazar run`: the resolver of 6.3.6 (shared with config load, with `receiverKind`, the
   `cwd:` rules and the file-element and context pins of 6.3.7) and
   `RunPlan` first, with the recorded receiver pin set (`trust.ReceiverPinStore`,
   `configstage/receiverpins.go`, `Pending.Hash`, `Stager.Reload()`), `config reload` and the
   loosening classification of a changed or unrecorded pin, with the restart and reload attacks
   of section 11 as the first tests;
   `core/secrets/envpolicy` (base set, deny set, `Build`, `CandidateEnv`),
   shared by app and CLI; the CLI's exec prologue of 6.3.8 (`fchdir` on the verified
   directory, fd sweep, `umask`, `RLIMIT_CORE`, signals, exception ports) as one function with
   its own tests; then `env` (exec of `resolvedPath` with `RunPlan.env` after the
   `fstat` checks), then `late-env` with `fd`, then `socket`; the whole-environment post-exec
   check of 6.3.4, the directory check of 6.3.7, the pipe-sharing check and the script and
   file-element re-hash of 6.3.3/6.3.7; exec-chain verification; loaders;
   integration tests with real node/python, including a mise shim (refused), an `xcode_select`
   shim, a `#!/usr/bin/env node` script, a planted `PATH` entry, the launcher-config
   negatives of section 11 (`npm_config_script_shell`, `npm_config_registry`, `HOME`), and the
   working-directory and process-state negatives (a prepared caller directory, `ulimit -c`,
   stray fds, `umask 000`).
7. `file` server with the per-delivery swap.
8. `migrate`, `migrate-mcp` (with de-shimming and the absolute bundled path); README migration
   guide; the manual script in section 11 run on the three secrets of section 2.

## 14. Deltas to the main spec once this is accepted

Edits to `nazar-design.md` that this document implies; they are applied in the same
PR that accepts it, so the two never disagree for long:

1. **7.1 Storage** (applied in Milestone 8): HPKE RFC 9180 through Go's `crypto/hpke` on top of
   `Platform.KeyAgreement`; CryptoKit HPKE and the ECIES fallback are dropped (3.2). One
   enclave key **per secret**, not one per store. The sealed value lives in the Vault item
   `secret/<name>`, not in a file (3.3), with the same-Mac restore caveat of 3.4; no secret key
   has user presence yet (3.5).
2. **7.1 Config example:** `to: [git, github-mcp]` is split as in section 4 (helper receiver and
   late-env receiver are different rules or the same rule with `command:` pinned through
   `defaults.trustedPath`); `DEPLOY_TOKEN` gets a rule with `to: [deploytool]`; the comment
   "you: once per tab" stays (the terminal satisfies that rule), and a rule `claude` satisfies
   is once per Claude Code run (spec 4.1 step 4); `scope: app` would be once per owning
   GUI app and warns for a launcher receiver, see secrets design 9.1 and 6.3.4.
3. **7.1 `late-env`:** plaintext no longer passes through `nazar run`; the app writes it after
   `NOTE_EXEC` (6.3). The loader is `loaders/node/env.cjs`, not `env.js`; the example
   `node -r nazar/env server.js` becomes `nazar run --late-env X -- node server.js` (the loader
   is injected by absolute path, not installed as a package). `--target` and the exec-chain
   rule (6.3.3) are referenced. Step 3's "Only harmless values go into the startup environment:
   the loader setting, `NAZAR_SECRET_FD=3`, the variable name and the `--target` pattern"
   becomes "The startup environment is built by nazar-agent from an allowlist (secrets design
   6.3.4): a fixed base (`PATH` from `defaults.trustedPath`, `HOME`/`USER`/`LOGNAME`/`TMPDIR`
   from the system, `LANG`/`LC_*`/`TERM`), the variables the secret's `envAllow:` names, and
   the loader variables. Nothing else of the caller's environment reaches the target, and
   nazar-agent checks the whole environment after exec before it writes the value."
4. **7.1 helper:** the receiver of a git helper request is the transport `git-remote-http`
   (signing identifier `com.apple.git-remote-http`), named as such in the config example, and
   the main spec's "checked on the live receiver" wording for helpers points to the limit of
   6.1 (what a genuine transport can be told to do).
5. **4.2 matcher table, `command:` row:** "can't be faked, because nazar starts it itself" →
   "bound to an executable resolved through `defaults.trustedPath` and verified across the exec
   chain; argv alone never matches; files named in the argv are pinned by hash against the
   entry's `cwd:`" (6.3.3, 6.3.7). `defaults.trustedPath` is added to 4.2, and `apps.<name>`
   gains the optional `cwd:` field with its one-line meaning ("where a `nazar run` receiver
   runs: `/` by default, an absolute directory, or `caller` for binaries; a loosening change").
6. **4.5 user presence:** done for ssh keys (Milestone 7). For secrets 4.5's second
   bullet ("`SecureEnclave.P256.KeyAgreement.PrivateKey` for secrets") gains "created without
   user presence until spike S13 has run (secrets design 3.5)"; applied in Milestone 8.
7. **6 CLI:** "Every command accepts `--json`" gains the `nazar get` exception (6.5): success
   output is the raw value, failure is a `Problem`.
8. **4.8 / control protocol:** value-returning secret commands require the genuine CLI as peer
   (7.3), beside the existing same-user rule; `MaxLargeRequestSize` for `secret.run`.
9. **11 spikes table:** S12's fallback "launchers use `env`" is replaced by the per-run socket
   handover (6.3.2); S13, S14, S15 and S16 rows are added with the criteria of section 12; the
   S9 fallback reads "`file` ships disabled by default if identification is unreliable".
10. **7.1 "Deletion"**: any "crypto-erase" wording follows 3.4 (handle erase, honest about
    Keychain backups), and the two steps are `DeleteKey(handle)` then the Vault record.
11. **4.7 Platform interface:** the Go snippet gains the five Phase 2 methods of 5.1
    (`OnProcessExec`, `InspectCode`, `OpenersOf`, `Environment`, `VerifyPeer`) with
    their one-line contracts, and the Linux note says what each means there (`/proc/*/fd`
    for `OpenersOf`, `/proc/<pid>/environ`, the netlink process connector, `SO_PEERCRED`
    plus a hash of `/proc/<pid>/exe`), so the "TPM platform layer" sentence stays true.
12. **7.3 "Fit with the core":** "None of the modules need changes to the core" is no longer
    true and is replaced by: "The `ssh` module needed none. The `secrets` module changes the
    core in the ways its design lists in 5.1: `broker` (`Target`, `Delivery`, `Handover`,
    `Verify`), `control` (fd passing, per-command peer requirement, `secret.add` request size),
    `caller` (`Parent`, `Synthetic`), `match` (`command:` receivers), `policy`
    (`EvaluateSecret`), `audit` (`Delivery`, `Handover`), `config` (`secrets`, `trustedPath`)."
    The payload-summary bullet for `secrets` stays.
13. **8 "What it doesn't protect against":** the "Delivered secrets (Phase 2)" bullet points at
    section 10 of this document for the secrets-specific list (launcher supply chain including
    the launcher's config files under `HOME` and in its install tree, what an approved `cwd:`
    opens, the FIFO timing window, what a genuine git transport can be told to do, the `env`
    exec window, same-user debugging of a non-hardened receiver), rather than repeating it.
14. **7.1 `file`:** "Afterwards: the FIFO is recreated for the next reader. Concurrent readers
    are served one at a time" becomes "a fresh FIFO is swapped into the path before each
    delivery, so a value reaches exactly one reader exactly once; concurrent readers are refused
    as ambiguous and retry" (6.2).
15. **7.1 `helper`:** "The caller is nazar's parent process: the tool that asked" becomes "the
    tool's *transport* that asked (`git-remote-http` for git)", with the honest limit of 6.1.
16. **4.2 secrets fields and `to:`:** `envAllow` is added next to `deliver` with its one-line
    meaning ("caller variables passed to the receiver; adding one is a loosening change; never
    a member of the deny set", 6.3.4), and the `to:` row gains "a `command:` receiver through a
    launcher (`npx`, `uvx`, `pipx`) pins the launcher, not what it runs or the config files it
    reads under `HOME`; `config check` warns when such a rule has `gate: none` or `scope: app`,
    or when the receiver has a `cwd:`".
17. **7.1 `late-env` and `nazar run`:** a sentence after the environment one: "The receiver
    runs in `/`, never in the caller's directory, unless its `apps:` entry pins a `cwd:`; the
    CLI enters that directory by `fchdir` on a verified fd, closes every inherited fd above 2,
    resets `umask`, `RLIMIT_CORE`, signals and Mach exception ports before `execve`, and
    nazar-agent checks the working directory after exec and that the handover pipe reached only
    the exec'd process (secrets design 6.3.7, 6.3.8)." The 7.1 config example's `gh`/`deploytool`-style entries, where present, gain `cwd:
    caller`.
18. **4.1 `ProcessInfo`:** `Cwd` is noted as also used for the receiver's post-exec check and
    for `cwd: caller`, never for resolving a relative `argv[0]`.
19. **4.2 "Reloading" and 7.1 commands:** "the app reloads the file when it changes" gains
    "and `nazar config reload` recomputes the receiver pins of the secrets design (6.3.7) when
    it has not; every load compares the pins with the recorded set and a pin that comes out
    different is a loosening change even with the text unchanged; nothing re-pins silently".
    `nazar config reload` joins the command list, `config.reload` the control table,
    `config.apply`'s `hash` is documented as covering text and pins, and `config check`/`status`
    report stale, unpinned and pending receivers.
20. **4.2 "pinned on first load" and 4.8 approved config:** the sentence on `app:` team pins
    gains its sibling: "Receiver pins (the executable, interpreter, file elements, directory
    and context of a `nazar run` receiver, secrets design 6.3.3/6.3.7) are recorded the same
    way, in the Vault item `state/receiver-pins` beside `state/trust`, when a `login` dialog
    shows them; a config load compares and never adopts; a receiver without a record matches
    nothing." 4.8's "the approved config is stored in the Vault" gains "beside the receiver
    pin set, which is approved on its own (a text change never carries pins; a new receiver is
    two approvals); the first start after upgrading to Phase 2 reports every receiver as
    unpinned until `nazar config apply` has approved its pins once". `config.apply` is noted
    as two-phase (`hash` new, 7.3). The 4.7 Platform/Vault item list, where present, gains
    `state/receiver-pins`.
