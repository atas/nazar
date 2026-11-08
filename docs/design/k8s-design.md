# nazar 🧿 — `k8s` module design (Phase 3)

**Status:** design, refreshed for Milestone 12 (`ca-cert` first). Refines section 7.2 of
[`nazar-design.md`](nazar-design.md) (the main spec). Where this
document is more specific than the main spec, this document wins for the `k8s` module; where
it is silent, the main spec applies unchanged (caller chains 4.1, config 4.2, approval cache
4.3, dialog 4.4, audit 4.6, config staging 4.8, CLI model 6, threat model 8).

**One sentence:** a kubectl exec credential plugin that hands a Kubernetes credential to the
program that ran it only when the *right cluster* asked and the *person or tool behind that
program* passed the context's rules, with the credential itself kept by the Secure Enclave in
the meantime.

> **Decision (2026-11-05, the owner's): `path:` again, without a pin** (spec 4.2). It replaces
> the "no `path:` matcher" decision of 2026-11-01. A `path:` rule matches the file its path
> resolves to at each request, with no hash and no `nazar trust <path>` (ignore those below). A
> `path:` to a file called kubectl is the "rule names kubectl" error again. Rules are still judged
> on whoever called the client (`chain[2:]`), except that a client **launchd started** (its parent
> is launchd: a daemon, nothing called it) is judged as its own caller (`chain[1:]`,
> `caller.Chain.Callers`): that is how a Homebrew daemon that runs the plugin itself gets a rule
> (`apps: [{path: /opt/homebrew/opt/<formula>/bin/<x>}]`, under `gate: none` too) instead of only
> `unknown`. It gives a rule naming that program nothing it lacked, since the program could run
> the plugin through kubectl, where the rule already matched it.
>
> **Decision (2026-11-01, the owner's): no `path:` matcher** (spec 4.2), replaced by the block
> above.
>
> **Decision (2026-10-31, the owner's): no client list.** This block wins over every mention of
> `clients`, "trusted client", "check 1: is the direct caller a trusted client", client pins,
> `nazar trust` of kubectl, `apps.kubectl` written by `ca create`, the client-overlap rule and the
> client fingerprint of the rule ids anywhere below.
> - **What changed.** A context names no program that may receive its credential. Whatever runs
>   `nazar k8s credential` (`chain[1]`: kubectl, helm, k9s, a krew plugin, python3 with the
>   Kubernetes client, a shell's `$(…)`) receives it when the chain above it (`chain[2:]`, as
>   before) passes the context's rules. Nothing is pinned by hash and no `nazar trust` is needed,
>   so `brew upgrade kubernetes-cli` (or helm, or k9s) breaks nothing. Check 1 is now only "is
>   `chain[1]` identified": a live, full process record (not PID-only, not exited) whose code
>   signature verified and gives it an identity (a team, or a cdhash for ad-hoc code such as
>   Homebrew's); refused otherwise with `the program that ran nazar can't be identified`. That
>   identity (`match.Identity`) stays the receiver of every approval, so an approval for kubectl
>   in a tab never covers helm there. The rule ids no longer carry a client fingerprint (an
>   upgrade ended every k8s approval once).
> - **Why.** The caller chain is the security boundary, as for SSH keys: iTerm2 or Claude Code
>   versus some other app outside the session. A program inside an allowed chain can already use
>   the cluster through kubectl, so restricting the receiving program only narrowed what it could
>   exfiltrate, a credential of at most `ttl_cert` (15 minutes by default), at the price of a
>   concept, a config key and a re-trust after every upgrade (helm and k9s refused until listed
>   and trusted). One way to do a thing, the SSH way.
> - **The residual risk, accepted.** Any program in an allowed chain can hold a certificate
>   itself for up to `ttl_cert` and use it, or send it elsewhere, without going through kubectl.
>   It could drive kubectl for the same 15 minutes anyway.
> - **Kept, unchanged:** check 0 (the genuine CLI), check 2 (the cluster pin), the stdout check
>   (the reply goes only to a fresh close-on-exec pipe `chain[1]` alone reads: never a file, a
>   terminal, a relay or another process, THREAT-MODEL 5.16), unknown and truncated chains (the
>   main spec's `unknown` handling on `chain[2:]`; no `chain[1]` at all is check 1's refusal),
>   gates, scopes, the approval key `(k8s:<ctx>, rule, scope, receiver, op)`, staging of
>   loosening edits, re-checking the context at mint time, and the audit line.
> - **Rules naming kubectl** are still refused (`rule N names kubectl; rules are judged on who
>   called it, …`): a matcher named `kubectl`, a `path:` to a file called `kubectl`, or a
>   `signed:` of identifier `kubectl`. Such a rule never matches kubectl asking, and would pass
>   every program kubectl runs, such as a `kubectl-<name>` plugin anyone can put on PATH.
> - **Migration.** A context without `clients:` (what `ca create` wrote) meant `[kubectl]` and now
>   means any identified program: that is the decision, and it needs no edit. A context that still
>   has a `clients:` line is **off**: parsed and kept, but every request for it is refused (`the
>   context still has a clients: line, which is no longer used: remove it and approve the
>   change`, with a block warning naming the fix), and `config check`/`status` warn
>   `k8s.contexts.<name>.clients: no longer used; remove the line (any program your rules allow
>   now gets the credential); until then this context is off`. It is a warning, not an error, so
>   an approved config (in the Vault) or a `config.yaml` with the line stays valid and in force:
>   SSH keys, secrets and every other context keep working exactly as approved. Reading the line
>   as absent would loosen without a prompt; refusing the file would leave the whole config
>   unapproved (and an approved one that no longer parses falls back to the built-in default,
>   blocking every key). Removing the line is classified as loosening (the off context is one
>   block slot, as an absent one, plus `clients: line removed`) and is staged for Touch ID;
>   adding it back tightens at once. A rule naming kubectl in an off context is not reported
>   until the line goes (it was valid beside `clients: [helm]`).
> - **`nazar k8s ca create`** writes no `clients:`, no `apps.kubectl` and no trust record, sends
>   no kubectl path, and needs no kubectl on PATH; its prompt says the program that runs the
>   plugin gets the credential when the rules allow whoever ran it.
> - **AWS** takes the same decision ([aws design](aws-design.md), the block at the top): no
>   `clients:`, check 1 the same `identified`, a rule naming `aws` refused.

> **Decision: one guided `nazar k8s ca create` replaces `import`.**
> Where a section below (5.2, 7, 8) still describes `nazar k8s import`, this block wins.
> - nazar does not need or touch the kubeconfig's existing credential. `nazar k8s ca create
>   [<context> [<server>]]` asks at a terminal for the context name, the server and the
>   server's CA (shown as its fingerprint, `openssl x509 -fingerprint -sha256` format), with
>   defaults read only from the current context's `contexts:` and `clusters:` entries, never a
>   user entry. Without a terminal both arguments are required and the CA must come from the
>   kubeconfig cluster entry with exactly that server. No new flags.
> - One login prompt covers the CA (Secure Enclave key and certificate file), the
>   `k8s.contexts.<context>` entry (credential ca-cert, the cluster pin, the terminal's login
>   rule) and the kubectl pin (`nazar trust` of the kubectl on PATH, and `apps.kubectl:
>   {path: …}` when absent); config.yaml changed during the prompt makes nothing, and a later
>   step that fails undoes the earlier ones. After it the CLI adds three kubeconfig entries
>   (cluster and user `nazar-<context>`, context `<context>`) as lines of text, never changing
>   or removing another; `k8s forget` removes them while they are still exactly nazar's.
> - The identity is `CN=<macOS short user name>-nazar` with no groups, read by nazar-agent, not
>   copied from the old client certificate. The user grants it a role with a ClusterRoleBinding
>   (`kubectl create clusterrolebinding <user>-nazar --clusterrole=cluster-admin
>   --user=<user>-nazar`, run with their current admin access). `system:masters` is avoided: it
>   bypasses RBAC entirely, and a certificate in it can't be revoked, while a binding can be
>   deleted at any time.

> **Decisions that supersede the build order below.**
> - **`ca-cert` (6.1) is the first and default provider.** nazar keeps a Secure Enclave CA key
>   per context and mints a fresh 15-minute client certificate with a throwaway key for each
>   request. No long-lived credential exists anywhere: not on disk, not in nazar's memory, not
>   in kubectl. It fits every cluster where the user can add a client CA (`hydra` on microk8s,
>   kubeadm).
> - **`stored` (5) is the fallback**, for a self-managed cluster whose client CA can't be
>   changed. It may follow `ca-cert` and is not required for the first milestone.
> - **`jwt` (6.2) is not planned.** On clusters the user runs, `ca-cert` does the same job with
>   less setup. Its only extra reach is managed clusters that accept an extra OIDC issuer
>   (EKS), and it needs hosted JWKS documents.
> - **Managed clusters (EKS, GKE, AKS) are out of scope.** Their own exec plugins
>   (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`) already mint short-lived
>   tokens. The weak point there is the cloud login (`~/.aws`, gcloud's and the Azure CLI's
>   token caches), which is a different module (13.1).
> - Why not "sign each connection" as for SSH: client-go's exec plugin can only return a
>   finished credential (a token, or a certificate and key) and has no signing callback, and
>   kubectl can't use a hardware key. Minting short-lived credentials from an enclave key is
>   the equivalent.
> - Paths in this document written before Milestone 6 (`/Applications/Nazar.app/...`) mean
>   today's nazar CLI (`nazar` on the PATH, from `~/Library/nazar/nazar-agent.app` or the
>   cask).

> **Refresh for Milestone 12 (Phase 3's first slice).** Milestones 3 to 8 changed
> the ground this document was written on. Read the rest against these points; where a section
> below still says otherwise, this block wins.
> - **Which program is which.** "Nazar.app" means **nazar-agent** (`~/Library/nazar/nazar-agent.app`,
>   bundle id `dev.nazar.agent`, a background app since Milestone 6). **Nazar UI.app** is a client
>   like any other and never receives a credential. The **CLI** is
>   `nazar-agent.app/Contents/MacOS/nazar` (signing identifier `dev.nazar.cli`), linked as
>   `~/.local/bin/nazar` by `nazar install`, or into Homebrew's `bin` by the cask's `binary`
>   stanzas; `/Applications/Nazar.app/...` paths below mean that binary.
> - **Check 0 is Milestone 8's genuine-CLI check, as built** (secrets design 7.3):
>   `k8s.credential` is a `control.ValueCommand`, so the control server runs `Server.VerifyCLI`
>   on the connection (the CLI's audit token checked against `identifier "dev.nazar.cli"` plus
>   the agent's own team in a team build, or the cdhash of the CLI that `make agent` links into
>   the agent's own code, `-X main.devCLIPin`, in an ad-hoc build) and the daemon refuses every value command whose
>   peer it did not vouch for, before the command's handler, with one blocked audit line. No
>   `RequireBundledCLI` option and no new platform method are needed (2.0, 12.1). The check's
>   known limit is Milestone 8's: a pass means "the process the token names is the genuine CLI".
> - **Approvals are keyed by op (since Milestone 7).** A k8s approval is remembered under (target
>   `k8s:<context>`, rule, scope, receiver = the client's identity, op `k8s:<context>`): an
>   approval for one context never covers another, and one for kubectl never covers k9s (2.4).
> - **Vault items follow main spec 9.** The CA key's handle lives in the Vault item
>   `k8s-ca/<context>`. An item this agent can't read is listed, never deleted by the agent, and
>   its remedy names `security delete-generic-password -s dev.nazar -a k8s-ca/<context>` only
>   when the account is a plain word, as for `ssh-key/` and `secret/` items.
> - **A config entry is written as `ssh-key create` writes a key's.** `nazar k8s import`
>   writes the context's entry with its own `gate: block` plus one login rule (`scope:
>   session`, `expire: 8h`) for the terminal app the command was typed in, shown and approved
>   on one login prompt (5.2 step 7, section 7).
> - **Section 12.1's dependencies are on `main`:** the secrets store and the genuine-CLI
>   peer check, both of Milestone 8. `ca-cert` needs neither the store nor key agreement: it
>   signs with an enclave P-256 key through `Platform.Sign`, which exists since Milestone 3.
> - **What Milestone 12 builds:** `credential: ca-cert` only (6.1, refreshed); the plugin
>   (`nazar k8s credential`), check 0 and the three checks; `nazar k8s ca create | show`,
>   `nazar k8s import`, `nazar k8s list`, `nazar k8s forget` (section 7, refreshed); kubeconfig
>   rewriting (section 8, with the backup of 8 for `ca-cert`); the fake TLS API server driven
>   by a real `kubectl`. **Not in Milestone 12**, refused by name where a config key or flag
>   would name them: `credential: stored` and everything that only serves it (section 5,
>   `rotate`, `audit`, `ttl`, `credential_ref`, the `credential-rejected` counter of 1.4),
>   `import --as` and `kubeconfig_context` (a kubeconfig context whose name is not a valid
>   nazar name is renamed with `kubectl config rename-context` first), `--kubeconfig` (the set
>   is `$KUBECONFIG` or `~/.kube/config`), and `app:` clients (GUI clients such as Lens, 2.1).

**Phase 3 builds:** (the original design, superseded by the two blocks above) the plugin flow,
check 0 and the three checks, the `stored` provider, `nazar k8s import | rotate | audit |
credential | list | forget`, kubeconfig rewriting, the core changes of section 12.1, and the test
harness with a fake TLS API server. `ca-cert` and `jwt` were designed (section 6) so their seams
exist.

**Dependencies.** Both are on `main` since Milestone 8 (refresh above): the secrets store
(`core/secrets`) and the genuine-CLI peer check (`control.Server.VerifyCLI`). The UID-only
verifier this paragraph once described is gone for value commands.

---

## 1. How the plugin is reached

### 1.1 The kubeconfig entry

`nazar k8s import` replaces the credential in a kubeconfig user entry with exactly this:

```yaml
users:
- name: hydra-admin
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /Users/you/Library/nazar/nazar-agent.app/Contents/MacOS/nazar   # absolute; see 1.5
      args: [k8s, credential, hydra]                           # hydra = nazar context name
      provideClusterInfo: true
      interactiveMode: Never
      installHint: "nazar is not installed at this path; reinstall nazar and run nazar k8s import hydra --write: https://github.com/atas/nazar"
```

- **`apiVersion`: `client.authentication.k8s.io/v1` only.** It is GA since Kubernetes 1.22 and
  every kubectl, k9s and helm a user runs today speaks it. If `KUBERNETES_EXEC_INFO` arrives
  with `v1beta1` (someone edited the entry by hand), the plugin refuses with exit code 2 and
  the message `nazar needs exec.apiVersion client.authentication.k8s.io/v1; run nazar k8s
  import <context> --write to fix the kubeconfig`. The plugin never answers in a version it
  was not asked in: client-go rejects a reply whose `apiVersion` differs from the request's.
  (M12: the CLI passes `KUBERNETES_EXEC_INFO` to nazar-agent unparsed, at most 48 KiB, and the
  agent parses and judges it; the CLI is a pipe in both directions. The message names
  `nazar k8s import <context> --write`, which rewrites the entry.)
- **`provideClusterInfo: true` is mandatory.** It makes client-go put `spec.cluster` (server,
  CA, TLS server name, proxy) into the `KUBERNETES_EXEC_INFO` environment variable. Without it
  nazar cannot run check 2 (section 2), so a plugin invocation with no `spec.cluster` is
  **refused**, exit 3, reason `no cluster info: exec.provideClusterInfo must be true` (exit 3,
  not 2: the entry is a check that could not run, and the section 7 table and the integration
  test agree). The plugin never falls back to "trust whatever server".
- **`interactiveMode: Never`.** nazar never reads the terminal; approval happens through
  nazar's own gate on screen (login or dialog, main spec 4.4). client-go therefore does not
  attach stdin, and kubectl does not wait for the plugin to read anything. The plugin blocks
  until the gate answers or `defaults.timeout` runs out, which kubectl tolerates (client-go has
  no exec timeout of its own; kubectl's `--request-timeout` applies to the HTTP request, not to
  the plugin). While the dialog is open the terminal shows nothing; the dialog itself shows the
  kubectl command line, so the user knows why it appeared.
- **`installHint`** is what kubectl prints **only when `command` cannot be executed at all**
  (file missing, not executable). It is not shown for any nazar exit code, so its text speaks
  only about the missing binary. When nazar exits 5 (Nazar.app not running) kubectl shows
  nazar's own stderr line instead. The hint must never be relied on for security.
- **No `env:` block, and the environment is not trusted.** client-go passes `exec.env` entries
  into the plugin's environment, so everything in the environment of `nazar k8s credential` is
  attacker-writable through the kubeconfig. The existing CLI honours `NAZAR_CONTROL_SOCKET`,
  `NAZAR_CONFIG` and `HOME` (`cmd/nazar/app.go`); **`k8s credential` ignores all three**: it
  resolves the control socket as `<passwd home of getuid()>/.nazar/run/control.sock` (`getpwuid`,
  never `$HOME`), reads no config file, and verifies the socket peer with the CLI's own agent
  check (`agentRequirement`, the code requirement of nazar-agent), never `SameUserVerifier` and
  never `NAZAR_TEST_PEER` (M12: that variable is ignored by `k8s credential` too). The only environment
  variable it reads is `KUBERNETES_EXEC_INFO`, and that is untrusted data checked by the daemon
  (check 2). `nazar k8s audit` reports an exec entry with an `env:` block as `exec-env` (error)
  and `import --write` removes it. Injection into the CLI through `DYLD_INSERT_LIBRARIES` and
  friends is stopped by the **hardened runtime** on the CLI binary (section 1.5).
- **How the home is found.** `credentialSocket()` calls
  `user.LookupId(strconv.Itoa(os.Getuid()))` (libSystem's `getpwuid_r` on darwin) and uses its
  `HomeDir`. It never calls `user.Current()`, whose pure-Go implementation
  (`os/user/lookup_stubs.go`, selected by the `osusergo` tag, which the release build never
  sets) fills `HomeDir` from `$HOME`. A failed lookup or an empty or relative `HomeDir` is exit
  1 (`nazar: cannot find your home directory`); there is no fallback.
- **How the tests reach `nazar-testd` without that hole.** The integration harness today points
  the CLI at the test daemon through `HOME` and `NAZAR_CONTROL_SOCKET`
  (`test/integration/harness_test.go`, `world.env`), which `k8s credential` ignores by design.
  The test CLI is therefore built with the **build tag `nazartest`**
  (`go build -tags nazartest ./cmd/nazar`), which compiles in one extra file,
  `cmd/nazar/k8scred_testsock.go` (`//go:build nazartest`). In that build, and only for
  `k8s credential`, the socket path comes from `NAZAR_TEST_CONTROL_SOCKET`. `HOME`,
  `NAZAR_CONTROL_SOCKET` and `NAZAR_CONFIG` stay ignored in that build too, so the decoy tests
  of section 11 run against the same code path. The release build (`go build ./cmd/nazar` in the
  bundle build, main spec 4.7) never sets the tag, and the release check in section 11 fails
  if the shipped binary contains the string `NAZAR_TEST_CONTROL_SOCKET`. Even a tagged binary
  gains an attacker nothing against a real Nazar.app: it is not the signed bundled CLI, so
  check 0 refuses it.

### 1.2 The exec credential flow

```
kubectl (or k9s, helm …)                 nazar CLI                      Nazar.app (Go core)
───────────────────────                  ─────────                      ───────────────────
needs a credential for context
  exec: nazar k8s credential hydra ──▶ 1. read KUBERNETES_EXEC_INFO
  KUBERNETES_EXEC_INFO={…spec.cluster…}  2. parse ExecCredential (v1)
                                         3. connect ~/.nazar/run/control.sock
                                         4. send k8s.credential
                                            {context, cluster}  ───────▶ 5. CallerResolver on the socket peer:
                                                                           chain = nazar ◂ kubectl ◂ bash ◂ claude ◂ iTerm2
                                                                           check 0: peer is the bundled nazar CLI?
                                                                        6. check 1: chain[1] (kubectl, helm …) identified?
                                                                        7. check 2: cluster == recorded?
                                                                        8. check 3: rules on chain[2:], above the client
                                                                        9. ApprovalCache / gate (login | dialog)
                                                                       10. provider.Issue → credential + expiry
                                                                       11. one audit line
                                        12. ◀──── {credential, expirationTimestamp}
  ◀── stdout: ExecCredential JSON      13. print ExecCredential status; exit 0
  caches it until expirationTimestamp
  (in memory only), then runs the plugin again
```

- **Step 1 happens before anything else and never touches the network.** Reading the
  kubeconfig itself (`kubectl config get-contexts`, `kubectl config view`) never runs the plugin
  and contains no secret after import.
- **The CLI is a pipe, not a judge, but it is a pipe that receives plaintext.** Every check
  runs inside Nazar.app against the caller chain it resolved itself from the socket's peer audit
  token (main spec 4.1). The CLI's only claims are the context name (from `argv`) and the cluster
  info (from the env var), and both are verified against nazar's own records in steps 6 to 8.
  Unlike every Phase 1 request, however, `k8s.credential` **returns a long-lived plaintext
  credential to the socket peer**. An impostor CLI (`command: /tmp/fake-nazar` in a kubeconfig
  the attacker edited; the real kubectl is still the parent, the real cluster info still
  arrives) would therefore pass checks 1 to 3 inside an approved scope and could write the
  credential to disk, which is worse than malware merely driving kubectl. So the peer itself is
  checked first: **check 0** (section 2.0) requires the socket peer to be the genuine bundled
  `nazar` CLI, and fails closed.
- **Where the chain starts.** The socket peer is the `nazar` CLI process (check 0). Its parent
  is the **client**: the client-go program that executed the plugin. Everything above the client
  is **who called the client**. The core resolves one chain and the k8s module reads it in three
  slices: `chain[0]` = nazar CLI (check 0, never matched by a rule), `chain[1]` = client (check 1
  and the receiver), `chain[2:]` = **who called the client**, the slice rules are judged on
  (check 3). Rules are judged on `chain[2:]`, not `chain[1:]`, because `chain[1]` is by
  construction always a trusted client: a rule `apps: [kubectl]` judged on `chain[1:]` would
  match every caller including malware driving kubectl, which is the attack check 3 exists to
  stop (main spec 7.2 item 3, "rules apply to whoever called the client"). `apps: [kubectl]`
  inside a context's rules is therefore an error (section 3).
- **No shell hops.** client-go runs the plugin with `exec.Command` directly, so the parent of
  `nazar` is the client itself. If the parent is a shell or any process that is not in
  `clients`, that is check 1 failing, not a case to special-case. (Security review: a
  kubeconfig written by malware can make the hops `exec` (`bash -c "exec env … nazar …"`), so
  the CLI is still kubectl's child while `KUBERNETES_EXEC_INFO` is forged and stdout is copied;
  check 2 then checks a claim, not the connection. THREAT-MODEL 5.16. Closed by the stdout
  check of section 2.1: the reply reaches only `chain[1]`, so a forged claim
  sends the certificate to the server kubectl was told about, and its key nowhere else.)

### 1.3 The reply

```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "token": "…",                                  // stored token, or jwt (later)
    "clientCertificateData": "-----BEGIN CERTIFICATE-----…",   // stored x509, or ca-cert (later)
    "clientKeyData": "-----BEGIN EC PRIVATE KEY-----…",
    "expirationTimestamp": "2026-10-11T00:15:00Z"
  }
}
```
Exactly one of `token` or the `clientCertificateData` + `clientKeyData` pair is set, never both.
The `spec` field is omitted in the reply. The document is written to stdout in one `write`,
followed by exit 0. Nothing else is ever written to stdout; diagnostics go to stderr.

The write begins with a line break and a YAML document-start marker (`\n---\n`); the JSON
above follows it, and client-go reads it as a YAML document. The marker closes a framing leak
(THREAT-MODEL 5.16): a wrapper that keeps kubectl the plugin's parent cannot read the reply off
the pipe or write to it while the CLI runs (the stdout check, section 2.1), but it can write
bytes before the CLI runs, and a prefix such as `status:\n  token: >-\n    ` would otherwise
make a YAML folded scalar that captures the whole reply as the value of `status.token`, which
kubectl sends to the server as a bearer token, key included. `---` is a marker only at column 0,
so the line break comes first, whatever line a prefix left open; the marker then ends any block
scalar the prefix opened, and inside a flow or quoted scalar it is a decoding error. The reply
decodes as nazar's own document or not at all. The stdout check keeps the key off every other
reader and every co-writer off the pipe; this keeps a prefixed reply from carrying it to the
server.

### 1.4 `expirationTimestamp` policy

> **`ca-cert` (Milestone 12):** `expirationTimestamp` is the minted certificate's own
> `notAfter` (`now + ttl_cert`, 6.1), read back from the certificate as encoded (whole
> seconds). There is no separate `ttl` for `ca-cert`: the certificate ends on the server at the
> same moment kubectl stops using it, so one horizon replaces the `min` below. An approval that
> ends (its `expire`, the tab closing, `nazar revoke`) stops new certificates at once; the last
> one minted ends at most `ttl_cert` later. The rest of this section is about `stored`.

`expirationTimestamp = min(now + ttl, approval.Expires, credential.NotAfter)` where:

- **`ttl`** is `k8s.contexts.NAME.ttl`, default **`5m`**, allowed range `30s` to `1h`.
  `config check` rejects values outside the range. The default keeps long-running tools
  coming back every five minutes to pass the three checks again; `1h` is the ceiling because
  beyond it a revoked approval would stay usable for too long in a running k9s.
- **`approval.Expires`** is the end of the remembered approval that covered this request (the
  rule's `expire` from the approval time; the session's actual end is not knowable when the
  timestamp is computed and is covered by `min` with `ttl`). For `scope: use` and for one-shot
  approvals of unknown chains it is `now + ttl`, so a single `kubectl apply -f dir/` making
  dozens of API calls needs one approval, not dozens.
- **Stale login-gated approvals.** A `gate: login` approval is remembered together with its
  `LAContext`; when macOS invalidates that context the broker drops the entry (`reasonStale`,
  "remembered approval no longer accepted") and the next plugin run prompts again. A k9s under
  `scope: session` with a `gate: login` rule will therefore occasionally re-prompt within
  `expire`; this is the broker's behaviour, not a k8s bug, and the manual script checks it.
- **`credential.NotAfter`** is the client certificate's `notAfter` for `stored` x509
  credentials, so a tool is never told to cache a certificate past its own validity. Tokens
  have no inherent end; `stored` tokens use `now + ttl`.
- **`expirationTimestamp` is never omitted.** Without it client-go caches the credential for the
  life of the process, which for k9s is hours; nazar always sets it.
- **Revocation is best effort for running tools (documented).** `nazar revoke` empties the
  approval cache, but a tool that already holds a credential keeps using it until its own copy
  expires, at most `ttl` later. With `stored` the credential is also still valid on the server
  (main spec 7.2, "the documented weakness of option A"); `ca-cert` and `jwt` bound the server
  side too (section 6).
- **401 from the API server.** client-go re-runs the plugin at once when a request returns 401,
  regardless of the cached expiry. nazar handles that like any other call: within a remembered
  approval it answers silently, under `scope: use` it prompts again. A context whose stored
  credential is rejected by the server therefore shows up as repeated identical audit lines
  with `decision=allowed`. Counting allowed runs alone would also count a healthy k9s start
  (several runs from one pid within a second, section 9), and the plugin cannot tell a 401
  re-run from a parallel start run: client-go does not say why it ran the plugin. So the daemon
  counts only **early re-runs**, kept in memory per `(context, client pid)`:
  - the daemon remembers the pair's **first run** `F` and the `expirationTimestamp` `E` of the
    last credential it handed to that pair;
  - a run is an early re-run when it arrives **after** a credential was handed to the pair,
    **before** that credential's `E`, and **more than 15 s after `F`**. client-go caches a
    credential until `E` and shares one exec authenticator per exec config and cluster across
    the process, so outside the start burst a healthy client never asks again before `E`; only
    a 401 makes it do that. Runs at or after `E` and every run of the start burst never count;
  - **three early re-runs of one pair within 10 minutes** raise `credential-rejected`, reported
    through `k8s.list` and shown by `nazar k8s audit` (warning: "the server keeps rejecting the
    stored credential; rotate it and run `nazar k8s rotate <context>`").
  The 15 s burst window is checked against S10 (section 13), which measures how many runs k9s
  starts and how far apart they land: if any lands later than 5 s after the first, the window
  becomes three times the measured spread. A one-shot `kubectl` whose single 401 re-run falls
  inside the burst window is not counted. That loses nothing, because kubectl already prints
  `error: You must be logged in to the server (Unauthorized)`. The warning is meant for
  long-running tools that loop on 401 without saying so. The detection needs no read of the
  unified log, no decryption and no prompt.

### 1.5 Which `nazar` binary the kubeconfig runs

`import` writes the **absolute path of the `nazar` binary inside nazar-agent.app**
(M12: the absolute path the running CLI was started by, links not resolved: `~/.local/bin/nazar`
of `nazar install` or the cask's link in Homebrew's `bin` both survive an upgrade, where the
Caskroom path a resolved link names is removed by `brew upgrade`; the path is not the boundary,
check 0 is), never a bare `nazar` found on `$PATH`. A bare name would let anything earlier on `$PATH`
(a user-writable `/opt/homebrew/bin`, a project-local `bin/`) stand in for nazar and capture the
exec environment. The path is **not** the security boundary: the kubeconfig is user-writable, so
the attacker can point `command` anywhere. The boundary is **check 0** (section 2.0): the daemon
accepts `k8s.credential` only from a peer whose code identity is the bundled CLI, and that CLI
is built with the **hardened runtime** (no `DYLD_INSERT_LIBRARIES`, no unsigned dylibs, no
debugger attach without the entitlement) so a kubeconfig `env:` block cannot inject into the
genuine binary either. `nazar k8s audit` reports an exec entry that names nazar by another path
as `exec-wrong-path` (for example after moving the app) and `import --write` rewrites it.

---

## 2. The checks, in order

All of them run inside Nazar.app, before any gate and before any prompt. A failure at check 0,
1 or 2 is **refused without a dialog** and audited; a failure at check 3 goes to the fallback
like every other request (main spec 4.2: `defaults.fallback`, `gate: block` by default, with the
block warning).

### 2.0 Check 0: is the socket peer the genuine nazar CLI?

`chain[0]`, the socket peer, must be the **genuine nazar CLI of this install**. As built in
Milestone 8 (secrets design 7.3) and reused unchanged for `k8s.credential`:

- `k8s.credential` is a **value command** (`control.ValueCommand`), like `secret.get` and
  `secret.helper`. For a value command the control server calls `Server.VerifyCLI(fd)`: the
  connection's audit token (`codesign.PeerAuditToken`) checked with `SecCodeCheckValidity`
  against `codesign.CLIRequirement`, which is `identifier "dev.nazar.cli"` plus the agent's own
  team in a team build, or plus the cdhash of the CLI that `make agent` links into the agent's
  code (`-ldflags -X main.devCLIPin`, in the code rather than `Info.plist`, so the kernel
  holds it to the agent's signature) in an ad-hoc build. The process it vouched for must be
  the resolved chain's peer. The team is the agent's own, never read from config.
- **Fails closed.** Without a verifier (Linux, the fake, `ServeConn`) no peer is ever the CLI.
  A peer that fails is refused by `daemon.Serve` before the command's handler runs:
  `decision=blocked reason="peer is not the nazar CLI"`, one audit line with the caller's
  chain, no prompt, nothing minted, exit 3. (The block warning is not shown for check 0, as for
  secrets: the refusal happens before any policy is read.)
- **Why a requirement and not a cdhash** (team builds): a running agent keeps accepting a CLI
  replaced on disk by an in-place update until it restarts; the team + identifier requirement
  allows that while excluding every foreign binary.
- **Tests on the fake platform** inject `VerifyCLI` (the in-process daemon of the kubectl test
  accepts the scripted peer and refuses it for the check-0 case).

### 2.1 Check 1: is the direct caller a trusted client?

> **Superseded (2026-10-31): there is no client list** (decision block at the top). Check 1 is
> "is `chain[1]` identified" (`policy.EvaluateK8s`, `identified` in `core/policy/k8s.go`); what
> follows on `clients`, `path:`/`signed:`/`app:` clients, the default `[kubectl]` and `nazar
> trust` is history. The fail-closed cases of the first bullet and the stdout check below are
> unchanged.

`chain[1]` (the parent of the `nazar` CLI) must match one of the context's `clients`.

- **Fails closed when there is no `chain[1]` to judge.** If the chain holds the peer alone (the
  parent exited before the request: on macOS the CLI is then launchd's child, where the walk
  ends, so the chain is the CLI and nothing else; checked on real processes, section 11),
  if it is `Truncated` after the peer (`proc_pidinfo` failed, a recycled parent PID), if
  `chain[1]` is a PID-only reference, or if its code identity is unverified or ad-hoc, check 1
  fails with reason `not a trusted k8s client (parent unknown)` (M12: every check-1 failure has the
  one reason `not a trusted k8s client`; the block warning adds the `nazar trust` hint, and the
  stale cdhash is the match package's audit note). There is no "unknown chain"
  path at this step: the main spec's `unknown` handling applies to the caller slice (check 3),
  never to the client.
- **`clients`** is a list of names from the top-level `apps`. Allowed matcher kinds for a
  client: **`path:`** (a CLI binary, pinned by path plus cdhash with `nazar trust`; this is how
  Homebrew's ad-hoc-signed `kubectl` is trusted: the pinned cdhash is its identity, so "ad hoc
  fails" above applies to `signed:`), **`signed:`** (a Developer-ID-signed CLI, for example a
  vendor-signed `kubectl`), and **`app:`** (a GUI client such as Lens or Headlamp, which runs
  the plugin from inside its bundle). **Milestone 12 builds `path:` and `signed:` only**;
  `app:` clients (and the bundle-helper rule of `match.Client` below) are refused by `config check` as "not in this
  version" until a later milestone. `any`,
  `unknown` and `command:` are rejected by `config check` for `clients`: `any`/`unknown` would
  defeat the check, and `command:` only applies to receivers that nazar starts itself.
- **`signed:` clients must name a non-Apple team.** `signed: {team: apple}` would turn `perl`,
  `ruby`, `osascript`, `curl` and every other Apple-signed system binary into a trusted client;
  `config check` rejects it with the same error `gate: none` already uses for Apple matchers
  (main spec 4.2), see section 3.
- **`app:` clients mean a helper inside the bundle, not the chain's app.** `match.Evaluator`'s
  `apps:` semantics for `app:` ("the chain's GUI app matches") would let *any* process under
  Lens, such as `python3` in Lens's built-in terminal, pass check 1; and `Receiver()`'s
  `App.Ref == peer` test would never match, because the process that runs the plugin is a helper,
  not the app's main process. For `clients`, therefore, an `app:` matcher is defined as:
  **`chain[1]` is a process whose executable lies inside the bundle of that app (`.app/Contents/`
  prefix of the bundle found through the matcher's bundle id), is validly signed by the pinned
  team, and whose own signing identifier is listed by the bundle (main executable or an
  embedded helper/XPC service)**. This is a new matcher evaluation, `match.Client`, used only
  here (section 12.1). Lens's embedded terminal spawning `kubectl` is then judged as `kubectl`
  (the client) called by Lens (the caller), which is right.
- **Default when `clients` is missing:** `[kubectl]`, which requires an `apps.kubectl` entry;
  `config check` fails with `k8s.contexts.hydra: clients defaults to [kubectl] but apps.kubectl is
  not defined` if there is none.
- **Clients double as the default `to:`.** A context's rules carry no `to:` of their own (the
  receiver of a k8s credential is always the client); `config check` rejects `to:` inside
  `k8s.contexts.*.rules`, `nazar k8s rule add|set` refuses `--to` and `--no-to` as usage, and
  nazar-agent refuses a `to` in a context's `config.edit` whatever the CLI checked (Milestone
  13). The policy `Outcome.Receiver` is the identity of the matched client so approvals are remembered per client, exactly as main spec 4.3 requires: an approval given
  to kubectl in a tab does not cover k9s in the same tab.
- **On failure:** refused, no dialog, audit `decision=blocked reason="not a trusted k8s
  client"`, and the **block warning** (main spec 4.4) says, for example, `python3 evil.py
  tried to get the hydra credential: not a trusted k8s client`. Repeats within the warning
  window update one window. A stale cdhash after a `brew upgrade kubernetes-cli` is the same
  failure with reason `trusted binary changed; run nazar trust /opt/homebrew/bin/kubectl`,
  which `nazar status` and `nazar k8s audit` also list.
- **The reply goes straight to the client** (THREAT-MODEL 5.16). client-go
  runs the plugin with its stdout the write end of a pipe whose read end it holds. When check 0
  has passed and `chain[1]` is a full reference, nazar-agent asks the platform
  (`platform.Pipes`, an optional seam like `Mounts`; on macOS `proc_pidfdinfo`
  `PROC_PIDFDPIPEINFO` on the CLI's fd 1 and on `chain[1]`'s fds, the pipe matched by its kernel
  handles, both processes checked against their refs' start times around the reads) that the
  CLI's fd 1 is that pipe, before the broker and so before any rule, prompt or cached approval,
  and asks again at mint time. Anything else (an exec-hop wrapper relaying stdout through `tee`
  or `cat`, a file, a terminal, a socket, the read end, a closed fd 1, a check that errors, no
  check on this platform) is refused, no dialog, audit `decision=blocked reason="the plugin's
  output does not go straight to the program that ran it"`. A chain with no full `chain[1]` is
  left to check 1 above, with its own reason and the block warning. The CLI's fd 1 must be the
  write end's only reference (not `PROC_FP_SHARED`), so no co-writer, such as a background job a
  wrapper left, can write around the reply (os/exec closes kubectl's copy once the plugin has
  started). kubectl's fd must be the read end's only reference (not `PROC_FP_SHARED`) and close-on-exec (`PROC_FP_CLEXEC`): a pipe
  kubectl opened itself, never one it inherited such as its stdin. So a launcher that gave
  kubectl a pipe is refused whether it kept a copy or closed it; only kubectl can copy the read
  end after the check, and a client that hands it on leaks by itself (section 10). This matches
  how client-go (Go `os/exec`) makes the plugin's stdout: a fresh close-on-exec pipe. A client
  that instead gives the plugin a socketpair for stdout (libuv/Node) or a pipe end without
  close-on-exec (some JVMs) is refused, fail-closed; such clients are not supported in this
  version, as the `app:` GUI clients that tend to use them are not (section 9).
- **Plugins of kubectl (krew).** `kubectl foo` executes a separate `kubectl-foo` binary. If that
  binary uses client-go itself, *it* is the parent of `nazar` and must be trusted on its own
  (`nazar trust ~/.krew/bin/kubectl-foo`, then add it to `clients`). This is intended: a krew
  plugin is arbitrary third-party code.

### 2.2 Check 2: is it the right cluster?

`spec.cluster` from `KUBERNETES_EXEC_INFO` must match the context's recorded `cluster`.

- **Compared fields**
  - **`server`**, after normalisation: scheme and host lower-cased, an explicit `:443` dropped
    for `https`, a trailing `/` removed, no query or fragment allowed. Anything else about the
    URL (a path prefix such as `/k8s/clusters/c-abc` behind Rancher, a non-default port) must
    match byte for byte.
  - **CA**, as `ca_sha256`: `certificate-authority-data` is base64-decoded, split into PEM
    blocks, each block DER-decoded and re-encoded, the DER blobs sorted lexicographically and
    concatenated, then SHA-256. Hashing the canonical DER set makes whitespace, block order and
    PEM comments irrelevant while still binding the exact set of trust anchors.
  - **`tls-server-name`**, if recorded (empty matches only empty).
- **Refused regardless of the record**
  - `insecure-skip-tls-verify: true` in `spec.cluster`: with TLS verification off, "the right
    server URL" proves nothing. `import` also refuses such clusters outright (section 5).
  - no `certificate-authority-data` at all: a cluster that relies on the system trust store
    gets no `ca_sha256` to match. `import` refuses these too, with the advice to add the CA
    explicitly. (Managed clusters always ship their CA inline.)
  - a `proxy-url` that differs from the recorded one: a proxy terminates nothing (TLS passes
    through), but a changed proxy is a changed kubeconfig, which is exactly what this check is
    for. `proxy-url` is recorded at import as `proxy_url` and compared like `tls-server-name`.
- **Ignored:** `disable-compression`, and `spec.cluster.config` (nazar passes nothing through it).
- **On failure** (M12: one reason field, `reason="cluster mismatch: server: expected \"…\", got
  \"…\""`; the original text follows): refused, no dialog, audit `decision=blocked reason="cluster mismatch"
  expected="https://hydra.example:16443 ca=sha256:ab12…" got="https://10.0.0.9:16443
  ca=sha256:ff00…"`, and a block warning `kubectl asked for the hydra credential for a different
  server ("https://10.0.0.9:16443"). Your kubeconfig may have been changed.` The `got=` values
  are attacker-supplied: they are **quoted and escaped** like every other logged value (main
  spec 4.6), truncated to 256 bytes, and rendered through the dialog's plain-text label, never
  as a link. They are kept (not redacted) because they are the evidence.

### 2.3 Check 3: rules, on whoever called the client

`k8s.contexts.NAME.rules` are evaluated by a new `policy.Engine.EvaluateK8s(ctx, chain, view,
receiver)` on the **caller view** `chain[2:]` (a `caller.Chain` value that shares the resolved
processes but starts at the client's parent, keeps `Session`, `App`, `Unknown` and `Truncated`
of the full chain, and whose `Peer()` for display purposes is `chain[1]`), with `Target =
"k8s:<context>"`, `Receiver` = the matched client identity from check 1, and the context's own
`scope`/`gate`/`expire` (or `defaults.fallback`) as the fallback. Within that view the rules
behave as in the main spec: the first rule whose `apps:` matches any process in the view wins;
unknown chains match `any`, `unknown`, and (unless truncated) a `signed:` or
`path:` matcher for a process in the view, never `app:`, and are never cached; a `gate: none` rule only
accepts `app:` or non-Apple `signed:` matchers (main spec 4.2). `iTerm2 ▸ zsh ▸ claude ▸ kubectl
▸ nazar` is judged as Claude Code in that tab and gets Claude Code's rule. The nazar CLI and the
client are never matched by a rule. `config check` errors when a rule's matcher is **equal to a
`path:` or `signed:` client matcher** of the same context (section 3): such a rule never
matches the client itself, and wherever it does match, it matches the client binary sitting
*above* another client (`malware ▸ kubectl ▸ kubectl-foo ▸ nazar` under a rule
`apps: [kubectl]`), which is the hole check 3 closes. The comparison is on the **resolved
matchers**, not on the names, so an inline `apps: [{path: /opt/homebrew/bin/kubectl}]` is caught
like `apps: [kubectl]`.
**`app:` clients are exempt:** for them the client is a helper inside the bundle (2.1) while a
rule's `app:` matcher matches the chain's app, the app's main process in `chain[2:]`, so
`apps: [lens]` next to `clients: [lens]` is the intended way to write rules for a GUI client
(section 9). Like `apps: [iterm]` for every iTerm tab, it also covers a `kubectl` run from Lens's
built-in terminal.

(M12, as built: `EvaluateK8s(name, chain, got *cluster.Info)`, section 12.1; the scope is computed
on the full chain, so a client that is its own session root gets a session per run; the rule
ids carry a fingerprint of the context's cluster, identity, clients, kind and `ttl_cert`, so an
approved change of any of them ends the approvals given for the old credential; an Apple-signed
process is never a client, whatever matcher names it.) This is **not** the existing `EvaluateSSH`: today `policy.Outcome.Receiver` is set only for
rules with `to:`, `Target` is hard-wired to `ssh:`, and `LiveRuleIDs` enumerates only SSH
keys. Section 12.1 lists the core changes.

### 2.4 Approval

Through `broker.Broker` (section 12.1), keyed `(target "k8s:hydra", rule, scope_id, receiver,
op "k8s:hydra")` (since Milestone 7 the op is part of every remembered approval; the broker sets it from the
context, never the module). The receiver is the client's identity (`match.Identity` of
`chain[1]`), always, so an approval for kubectl never covers k9s. The prompt is:

```
Title:  iTerm2 wants to use Kubernetes credential "hydra"     (M12, as built; Scope line: "… for the Kubernetes credential for hydra only")
Lines:  kubectl delete pod web-1 -n prod            ← client command line, redacted (4.6)
        for https://hydra.example:16443
        iTerm2 ▸ zsh ▸ claude(Q6L2SF6YDW) ▸ kubectl   ← chain, app first
        remembered for this tab until <time>          ← scope summary
```

Several plugin runs that arrive together for the same **remembered** scope (`scope: session`
or `app`; k9s starts three informers at once) share one dialog through the broker's in-flight
dedup (`approval.Flight`); the others wait and reuse its answer. Under **`scope: use`** there is
no dedup and none is wanted: the broker's `OneShot` path asks on every request (main spec 4.2,
"use: every request asks"), so a k9s start with three informers under `scope: use` gets three
dialogs. Section 9 says so; `scope: use` is for kubectl, not for k9s.

---

## 3. Config schema

```yaml
apps:
  kubectl:
    path: /opt/homebrew/bin/kubectl         # pinned with `nazar trust`
  k9s:
    path: /opt/homebrew/bin/k9s
  helm:
    path: /opt/homebrew/bin/helm
  lens:
    app: com.k8slens.lens                   # GUI client: an app: matcher is fine here

k8s:
  contexts:
    hydra:                                   # nazar context name == kubeconfig context name
      credential: stored                    # stored | ca-cert | jwt   (only stored is built)
      cluster:                              # written by `nazar k8s import`; hand edits allowed
        server: https://hydra.example:16443
        ca_sha256: 3f8c…e1                  # hex, 64 chars, canonical DER set (2.2)
        tls_server_name: ""                 # optional
        proxy_url: ""                       # optional
      clients: [kubectl, k9s, helm]         # allowed direct callers; default [kubectl]
      ttl: 5m                               # expirationTimestamp horizon; default 5m, 30s..1h
      rules:                                # judged on chain[2:], above the client; no `to:`
        - apps: [claude]
          scope: use
          gate: dialog
        - apps: [iterm, cursor]
          scope: session
          gate: login
          expire: 8h
      # anything else → defaults.fallback (block)
    hydra-readonly:
      credential: stored
      cluster: { server: https://hydra.example:16443, ca_sha256: 3f8c…e1 }
      scope: session                        # no rules: own policy for every caller
      gate: dialog
      expire: 8h
    openshift-admin:                        # nazar name chosen with `import --as`
      credential: stored
      kubeconfig_context: default/api-x:6443/kube:admin   # the kubeconfig's own name
      cluster: { server: https://api-x:6443, ca_sha256: 9a01…77 }
    staging:
      credential: stored
      credential_ref: hydra                  # shares hydra's store entry (5.2 step 6); login-gated
      cluster: { server: https://hydra.example:16443, ca_sha256: 3f8c…e1 }
```

**As built in Milestone 12 (`ca-cert` only).** A context entry is:

```yaml
k8s:
  contexts:
    hydra:                                   # == the kubeconfig context name
      credential: ca-cert                   # the only kind built; stored/jwt are refused by name
      identity:                             # the minted certificate's subject
        user: admin                         # CN
        groups: [system:masters]            # O, one per group; optional
      ttl_cert: 15m                         # optional; default 15m, 1m..1h
      cluster:                              # written by `nazar k8s import`
        server: https://hydra.example:16443
        ca_sha256: 3f8c…e1
        tls_server_name: ""                 # optional
        proxy_url: ""                       # optional
      gate: block                           # what import writes: blocked for everyone…
      rules:                                # …but the terminal it was typed in
        - apps: [iterm]                     # apps: {iterm: {app: com.googlecode.iterm2}}
          scope: session
          gate: login
          expire: 8h
```

Validation of a `ca-cert` context, on top of the table below where it applies (the context name,
`cluster`, `rules[*].to`; since 2026-10-31 nothing of `clients`):

| Rule | Error or warning |
|---|---|
| `credential: stored` | error `stored is not in this version (ca-cert is)` |
| the context's own `gate: none` | error (it would apply to every caller) |
| a rule matcher named `kubectl`, a `path:` to a file called `kubectl`, or a `signed:` of identifier `kubectl` (not reported while the context is off) | error `rule N names kubectl; rules are judged on who called it …` |
| a `clients:` line (the list is gone) | warning `k8s.contexts.<name>.clients: no longer used; remove the line …`; the context is off (every request refused), the rest of the config in force |
| `cluster.tls_server_name` not a host name or IP; `cluster.proxy_url` not an http/https/socks5 URL with a host, or with a user, query or fragment | error |
| `credential: jwt` | error `jwt is not planned; use ca-cert` |
| `identity.user` missing or not 1 to 128 bytes of `[A-Za-z0-9._@:+=/-]` | error |
| `identity.groups` not a list of such strings, more than 16, or one listed twice | error |
| `ttl_cert` outside `1m`..`1h` | error |
| `ttl`, `credential_ref`, `kubeconfig_context`, `issuer`, `ttl_token` | error `the <field>: field is not in this version` |
| `apps: [any]` or `apps: [unknown]` with `gate: none` | error (as for secrets: the credential leaves nazar) |
| `cluster.server` on `*.eks.amazonaws.com`, `*.gke.goog`, `*.azmk8s.io` | warning `managed clusters can't trust a nazar CA` |
| two context names that differ only in letter case | error (the CA certificate file `k8s-ca-<name>.crt` lives on a case-insensitive file system) |

The context name is the kubeconfig context name; the CA's Vault item is `k8s-ca/<name>` and its
certificate `~/.nazar/keys/k8s-ca-<name>.crt`.

**Loosen vs tighten, as built in Milestone 12** (`configstage`, target `k8s:<name>`): the rules
and the fallback are compared by the slot proof, as for a key; a context added loosens unless
every slot blocks, and one removed tightens; any change to `cluster` (any field), to
`identity` (any field), to `credential`, and removing a leftover `clients:` line (an off
context is one block slot) loosens, whatever the slots say; a shorter `ttl_cert` tightens and a longer one loosens. A context added loosens
even when every slot blocks (security review: otherwise a context removed and added back
would carry a new cluster or identity in silently), and its prompt lists them. `app:` matchers in k8s rules
are pinned on approval, as for keys. The `k8s:` section stops being "unimplemented": a tightening
edit elsewhere in a file that carries it applies at once.

**As built in Milestone 13: rules edited from the CLI.** `nazar k8s rule add|set|remove
<context> …` edits `k8s.contexts.<context>.rules` with the code that edits a key's and a secret's
(`config.edit` with `context`, `config.Entry` of kind k8s), so the same checks and the same
classification apply: only an approved file with nothing pending is edited, `--if-hash`, the
result must parse (a rule naming kubectl, `any`/`unknown` under `none`, `to:` are refused with
the parse error), and a loosening is written only with `--allow-loosen-access` and then approved
at once on the login gate (the CLI sends the bound `config.apply`; refused with exit 2, nothing
written, without the flag) while a tightening applies at once. Only a context the approved config has is edited (an edit never
creates one: `import` writes the cluster and identity on its own prompt). No op touches the
context's own gate (`block`, as import writes it), `identity`, `cluster`, `ttl_cert`
or `credential`; those stay hand edits of `config.yaml`, staged as always.

**Validation (`nazar config check`), in addition to the generic rule checks of main spec 4.2**
(the original table, for the full module)

| Rule | Error or warning |
|---|---|
| `credential` missing or not one of `stored`, `ca-cert`, `jwt` | error `credential must be stored, ca-cert or jwt` |
| `credential: ca-cert` or `jwt` | error `not implemented yet`; the context is refused at run time (main spec 9) |
| `cluster.server` missing, not `https://`, has a query/fragment | error |
| `cluster.ca_sha256` missing or not 64 hex chars | error `run nazar k8s import <context> to record the cluster` |
| `clients` names an unknown app, or a matcher of kind `any`/`unknown`/`command` | error |
| `clients` names a `signed:` matcher whose team is Apple (`team: apple` or an Apple anchor) | error `an Apple-signed matcher can't be a k8s client: it would trust every system binary` (same rule as `gate: none`, main spec 4.2) |
| `clients` names an `app:` matcher whose app has no pinned team | error (the client check needs the team; `nazar trust --app` pins it) |
| `clients` empty list `[]` | error `a context needs at least one client` (omit the key for the default) |
| `rules[*].to` present | error `k8s rules take no to:; the program that runs the plugin receives the credential` |
| a matcher in `rules[*].apps` (named or inline) is equal to a `path:` or `signed:` matcher of the context's `clients` (or of `kubectl` when `clients` is defaulted); compared on the resolved matcher (same kind, same cleaned path, or same team and identifier), not on the name | error `rule N names kubectl, a client of this context; rules are judged on who called the client (2.3)`. `app:` clients are exempt: `apps: [lens]` with `lens` in `clients` is valid (2.3, section 9) |
| `scope: session` on a rule whose `apps:` names an `app:` client of the same context, or as the context's own `scope` when every client is an `app:` matcher | error `GUI clients have no session: use scope: app` (section 9) |
| `ttl` outside `30s`..`1h` | error |
| context name not matching `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`, or containing `..` | error. The name is the secrets-store key `k8s/<name>` and the audit target `k8s:<name>`, so `/`, `:`, `..` and whitespace are refused (`:` would make `nazar log --target k8s:<name>` ambiguous). `@` and `.` are allowed (`admin@hydra`). A kubeconfig context whose name does not fit (OpenShift `default/api-x:6443/kube:admin`, EKS ARNs) is imported with `nazar k8s import <kubeconfig-context> --as <name>`; the kubeconfig name is kept in `kubeconfig_context` and the exec entry's `args` carry the nazar name |
| `kubeconfig_context` set and equal to the context name, or two contexts with the same `kubeconfig_context` | error |
| `credential_ref: X` where `X` is not a `stored` context with the same `cluster.server` and `ca_sha256`, or is itself a `credential_ref` | error `credential_ref must name a stored context for the same cluster` |
| `credential: stored` and no `k8s/<context>` entry in the secrets store | warning `no stored credential; run nazar k8s import` (the context is refused at run time with that reason) |
| stored x509 credential expiring within 30 days, or expired | warning / error |

**Loosen vs tighten (main spec 4.8, 6).** The rule is the main spec's: a change applies at
once only when `configstage` can **prove** it tightens; everything else waits for the login
gate. For `k8s`, proven tightening is limited to: removing a context, removing a client,
removing a rule whose slot is replaced by a stricter one (the existing slot proof, run on the
context's rules and fallback), a stricter gate/narrower scope/shorter `expire` on the same
rule, and a shorter `ttl`. **Everything else is loosening**, in particular: adding a context or
a client; adding or reordering rules; weakening a gate; lengthening `ttl` or `expire`; **any
change to any `cluster` field** (`server`, `ca_sha256`, `tls_server_name`, `proxy_url`), which
re-points a credential at a different server, the attack check 2 exists to stop; **any change
to a `clients` matcher** (including editing the `apps.kubectl` entry a context relies on, which
the existing pin proof already catches for `app:` and which is extended to `path:`/`signed:`
entries referenced by `clients`); a `credential` kind change; adding, changing or removing
`credential_ref` or `kubeconfig_context`; and `import --write` / `rotate` / `forget` of the
store entry. `core/configstage/classify.go` today treats `k8s` as `Unimplemented` ("never
approved silently"); once `k8s` becomes `Config.K8s` it gains these k8s-aware rules
(`slotsK8s`, `clusterChanged`, `clientsChanged`) and a test per row of this paragraph. Until
those rules exist, a non-empty `k8s:` section must keep classifying as loosening.

**Parsing.** `k8s` leaves `config.Config.Unimplemented` and becomes `Config.K8s`
(`map[string]*K8sContext`). The parser reuses the rule, matcher and policy code the SSH keys
use; the only k8s-specific code is the `cluster`, `clients`, `credential`, `credential_ref`,
`kubeconfig_context` and `ttl` fields and the validation table above.

---

## 4. The `CredentialProvider` interface

```go
// core/k8s/provider.go
package k8s

// Provider issues the credential for one context once the request is allowed.
// Implementations must be safe for concurrent use and must never log or
// return the credential anywhere but in Credential.
type Provider interface {
    // Kind is the config value this provider serves: "stored", "ca-cert", "jwt".
    Kind() config.CredentialKind

    // Check validates a context's config for this provider at config-check
    // time (for example: a stored entry exists, the CA key exists). Problems
    // are reported through the normal config check, never at run time only.
    Check(ctx *config.K8sContext, deps Deps) []config.Problem

    // Issue returns the credential and its hard end. in.Approval is the
    // broker's approval ref (0 for dialog/none gates): providers backed by a
    // Secure Enclave operation pass it to platform.Sign / KeyAgreement.
    Issue(in IssueInput) (Credential, error)
}

type IssueInput struct {
    Context  *config.K8sContext
    Cluster  ClusterInfo          // the verified spec.cluster (check 2 already passed)
    Chain    *caller.Chain        // for the token subject / cert CN (jwt, ca-cert)
    Approval platform.ApprovalRef
    Now      time.Time
    TTL      time.Duration        // the context's ttl; the provider may return a shorter NotAfter
}

type Credential struct {
    Token    string   // exactly one of Token or (CertPEM, KeyPEM) is set
    CertPEM  []byte
    KeyPEM   []byte
    NotAfter time.Time // hard end of the credential itself; zero = none (token)
}

// Deps is what providers may use: the secrets store and the platform.
type Deps struct {
    Secrets  secrets.Store       // Phase 2 store (HPKE to a Secure Enclave key)
    Platform platform.Platform
    Vault    platform.Vault      // key handles for ca-cert / jwt
}
```

- **Providers are registered by kind** in `k8s.Module` (`map[config.CredentialKind]Provider`),
  and an unregistered kind refuses with `not implemented yet`. Phase 3 registers only `stored`.
- **The module, not the provider, computes `expirationTimestamp`** (section 1.4) from
  `Credential.NotAfter`, the approval and `ttl`, so every provider gets the same policy.
- **Zeroisation.** `Credential` buffers are overwritten by the module after the reply is
  encoded; the CLI overwrites its copy after writing stdout. This is hygiene against core dumps
  and swap, not a security boundary (the client receives the plaintext by design).

---

## 5. The `stored` provider in full

### 5.1 What is stored

One secrets-store entry per context, named **`k8s/<context>`**, encrypted exactly like any
Phase 2 secret (HPKE to the Secure Enclave key-agreement key, blob at
`~/.config/nazar/secrets/k8s/<context>.hpke`). The blob directory is user-writable (and the
main spec 7.1 even allows blobs in dotfiles or git), so **the entry name is bound into the
ciphertext**: the HPKE `info` is `nazar/v1 SecretBlob k8s/<context>` and the canonical blob
header (name, `v`, `type`) is the AEAD `aad`, as the Phase 2 spec (3.2, 3.3) already requires
for every secret. Copying `k8s/hydra.hpke` over `k8s/hydra-readonly.hpke` therefore fails to
decrypt (`reason="blob does not belong to k8s/hydra-readonly"`, audited as a possible blob swap)
instead of handing the admin credential to the readonly context's laxer rules. The plaintext is
a small JSON document:

```json
{ "v": 1, "type": "x509",
  "cert_pem": "-----BEGIN CERTIFICATE-----…", "key_pem": "-----BEGIN EC PRIVATE KEY-----…",
  "not_after": "2027-02-28T00:00:00Z", "subject": "CN=admin,O=system:masters",
  "imported": "2026-10-11T00:00:00Z", "source": "~/.kube/config#users/hydra-admin" }
```
or
```json
{ "v": 1, "type": "token", "token": "eyJ…", "imported": "…", "source": "…" }
```

- `type` is `x509` or `token`. `not_after` and `subject` are copied from the parsed certificate
  at import so `audit` and `list` can show them without decrypting.
- The entry is **not listed under `secrets:` in the config** and has no delivery methods; it is
  reachable only through the k8s module. `nazar secret list` shows it as `k8s/hydra (k8s
  module)` and `nazar secret delete k8s/hydra` is refused with "use `nazar k8s forget hydra`".
- **Metadata that is safe to show** (`type`, `subject`, `not_after`, `imported`, `source`) is
  duplicated in a plaintext sidecar `~/.config/nazar/secrets/k8s/<context>.meta.json` so
  `nazar k8s list` and `audit` need no Secure Enclave operation and no approval. The sidecar
  never holds the credential and **is never consulted for a security decision**: it is
  user-writable, so nothing in it (least of all which entry a context decrypts) may steer
  `Issue`. Which store entry a context uses is decided by the login-gated config alone
  (`credential_ref`, section 5.2 step 6); a sidecar is display data.

### 5.2 Import: what `nazar k8s import <context>` reads

**Who reads what.** The **CLI** (running as the user, in the terminal) locates, parses and
rewrites kubeconfigs and reads the certificate/key/token files they point to; it is the process
that already has the user's files and `$KUBECONFIG`. It sends the plaintext credential, the
recorded cluster and the metadata to **Nazar.app** over the control socket in a `k8s.import`
request, exactly as `nazar secret add` does in Phase 2 (the value travels CLI → app; the app
seals it; the CLI never seals and never keeps a copy after the reply). Nazar.app validates the
credential again (step 4) and, under **one** login approval, stores it and applies the config
entry (step 7); the CLI then rewrites the kubeconfig. Every `k8s` command that reads
kubeconfigs (`import`, `rotate`, `audit`, `list`, `forget`) finds them the same way, through
`--kubeconfig`, `$KUBECONFIG` and `$HOME` (step 1); only `credential` ignores the environment
(1.1).

**Without `--write`, `import` is a dry run:** it runs steps 1 to 6 in the CLI, asks Nazar.app
to validate (no prompt, nothing sealed, nothing kept), prints the kubeconfig diff and the config
entry it would add, and exits 0. Nothing is stored, no config change is staged, no file is
written. Only `import --write` is the loosening command of main spec 6.

1. **Locate the kubeconfig set:** `--kubeconfig PATH` if given, else `$KUBECONFIG` split on
   `:` (empty elements skipped, `~` expanded), else `~/.kube/config`. Files are merged for
   lookup with client-go's rules (first definition of a name wins) but **never merged on
   disk**: nazar remembers which file defined the user entry and writes only that file.
2. **Resolve the context:** `contexts[<context>]` → its `user` and `cluster` names → the
   `users[]` and `clusters[]` entries. A missing context, user or cluster is exit 1 with a
   message naming the file searched.
3. **Extract the credential from the user entry.** Exactly one credential kind must be present:
   - `client-certificate-data` + `client-key-data` (base64 inline) → `x509`;
   - `client-certificate` + `client-key` (file paths, relative paths resolved against the
     kubeconfig file's directory, as client-go does) → `x509`, read from the files;
   - `token` → `token`;
   - `tokenFile` → `token`, read from the file.
   - **Both a certificate and a token** in one entry: client-go would send both (mTLS plus a
     bearer header), and the reply format carries exactly one (1.3), so the entry is refused
     with `user hydra-admin has both a client certificate and a token; nazar returns one
     credential; remove the one the cluster does not use (kubectl config unset
     users.hydra-admin.token)`. Inline and file forms of the same kind together are refused the
     same way.
   - A user entry with **`exec`** already (another plugin: `aws eks get-token`,
     `gke-gcloud-auth-plugin`, `kubelogin`, or nazar itself) is refused: `user hydra-admin
     already uses an exec plugin (aws); nazar does not wrap other plugins`. Wrapping other
     plugins is listed as an open question (section 13).
   - `auth-provider` is refused as unsupported: the in-tree `gcp` and `azure` providers were
     removed in client-go 1.26 and the remaining `oidc` provider is a token-refresh flow
     (`id-token`/`refresh-token` against an issuer) that nazar would have to drive, which is
     the exec-wrapping question (Q1) in another form. `username`/`password` (basic auth,
     removed server-side in 1.19) is refused as unsupported.
   - A key that is encrypted (`ENCRYPTED PRIVATE KEY` PEM) is refused: nazar has no way to ask
     for its passphrase without a terminal.
   - **Impersonation fields are preserved, never dropped.** `as`, `as-uid`, `as-groups` and
     `as-user-extra` restrict what the credential does (an admin certificate used `as:
     readonly` is read-only). The rewrite (section 8) replaces only the credential keys of the
     `user:` mapping and keeps every other key (`as*`, `exec` is new, unknown keys verbatim), so
     the entry stays impersonating after import. The diff shows them as unchanged context
     lines and `audit` has no finding for them.
4. **Validate the credential:** the certificate must parse, the key must match the
   certificate's public key, and the certificate must not be expired (a warning if it expires
   within 30 days). The token is taken as an opaque string, with a warning if it looks like a
   JWT whose `exp` has passed.
5. **Record the cluster:** `server`, canonical `ca_sha256` (section 2.2), `tls-server-name`,
   `proxy-url`. `certificate-authority: path` is read from the file (relative to the
   kubeconfig). Refused: `insecure-skip-tls-verify: true` (`nazar cannot protect a cluster whose
   server certificate is not checked; add certificate-authority-data`), and a cluster with no
   CA at all.
6. **Shared user entries.** If other contexts reference the same user entry:
   - same cluster (same server and CA): they all become nazar contexts in one import, each
     under its own kubeconfig context name but sharing the one `k8s/<first>` store entry. The
     indirection is recorded as **`credential_ref: <first>` in the config** (section 3), where
     it is validated (same cluster, target is a plain `stored` context) and where changing it
     is a loosening change behind the login gate. It is never read from the sidecar or any
     other user-writable file: a sidecar `credential_ref` would let malware repoint
     `hydra-readonly` at the `hydra` entry, and since both share a cluster check 2 would pass. The
     config gets one `k8s.contexts` entry per kubeconfig context so each can have its own
     rules;
   - a different cluster: refused with `user hydra-admin is shared by contexts hydra (…:16443)
     and staging (…:6443); split it with kubectl config set-credentials first`. One credential
     for two servers is exactly what check 2 cannot reason about.
7. **One approval, then store and apply together** (`--write` only). This follows the
   existing `ssh-key create` handler (`core/daemon/handlers.go`, `sshKeyCreate`) and Phase 2's
   `secret add`, where the blob and its config entry ride on one approval:
   1. Before any prompt the CLI renders the rewritten kubeconfig into its `0600` temp file
      (section 8), so an unwritable kubeconfig fails before anything is stored. Nazar.app
      refuses with **exit 4**, storing nothing, if `config.yaml` already holds changes that are
      not approved yet (`config.yaml has changes that aren't approved yet; run nazar config
      check`): approving the import must not also approve someone else's pending edit.
   2. **One login prompt** covers the store write and the config entry. It shows the context,
      the cluster, the source file and the `k8s.contexts.<context>` entry to be added (one
      prompt for all contexts of step 6).
   3. After approval Nazar.app re-reads `config.yaml`. If it changed while the prompt was open,
      that is **exit 4** and nothing is stored, as in `sshKeyCreate`. Otherwise it seals and
      writes `k8s/<context>`, writes the config entry (`credential: stored`, the recorded
      `cluster`, no `rules`, so the context is blocked for everyone until the user writes
      rules, like a freshly created SSH key) and applies it as the approved config
      (`ApplyAuthenticated`). Adding rules afterwards is its own loosening change.
   4. Denied, timed out, or in the cooldown after a denied config prompt: **exit 3**, nothing
      stored, nothing applied.

   Nothing is ever left **staged** by `import`: a staged import would have to keep the
   plaintext credential waiting in memory or on disk, so exit 4 means "nothing done, the
   config file was busy". `--json` changes only the output format, never the order: the
   approval always happens on screen (main spec 6), and `--json` waits for it like the human
   form does.
8. **Rewrite the kubeconfig** only after step 7 succeeded: the CLI renames its temp file over
   the kubeconfig (section 8) and exits 0. On exit 3 or 4 the temp file is unlinked and the
   kubeconfig is untouched, so it never names a context that has no store entry or no approved
   config. If the rename itself fails after a successful step 7 (the disk filled up, say), the
   CLI exits 1 with `hydra is stored and configured but <file> could not be rewritten: …; run
   nazar k8s rotate hydra --write to finish`. If `apps.kubectl` does not exist, import prints
   the `nazar trust /path/to/kubectl` command to run and the `apps:` entry to add.
9. **Re-import.** `import` of a context that is already in the approved `k8s.contexts` (or of a
   name already used by another context) is refused with **exit 1**, `hydra is already
   imported; use nazar k8s rotate hydra to replace its credential`, before any prompt. `rotate`
   reads the credential from the same kubeconfig set, so it also finishes an import whose
   kubeconfig rewrite failed. A store entry with **no** config entry (a crash between the blob
   write and the config write) does not block `import`: the prompt says `replaces an
   unconfigured stored credential` and the entry is overwritten.

### 5.3 Rotation advice

Import always ends with:

```
The hydra credential sat in plain text in ~/.kube/config and may also be in backups,
Time Machine, dotfile repos or shell history. Rotate it, then re-import with
`nazar k8s rotate hydra`:
  microk8s:  regenerate the client certificate (refresh-certs or a new CSR signed by the
             cluster CA) and remove the old one from any bundle; or for a token user,
             delete and recreate the ServiceAccount token.
  kubeadm:   kubeadm kubeconfig user --client-name admin   (then rotate the old cert out)
  EKS/GKE/AKS: these already use short-lived exec plugins; nazar does not wrap them (yet).
```

`nazar k8s rotate <context>` re-runs steps 3 to 8 against a kubeconfig that holds the *new*
credential (or reads a certificate + key pair from `--cert FILE --key FILE`, or a token from
stdin with `--token-stdin`), replaces the store entry, keeps the rules, and prints the same diff
and advice. Replacing a credential is a loosening change: one login prompt, as in step 7.
Without `--write` it is a dry run like `import`'s. It writes no config entry, so a pending
`config.yaml` edit does not block it and it never exits 4. It refuses (exit 1) a context
that is not in the approved `k8s.contexts`, and points to `import`. It also refuses a
kubeconfig whose cluster differs from the recorded `cluster`, because changing `cluster` is a
config edit (section 3), not a rotation.

### 5.4 Issue

`stored.Issue` decrypts `k8s/<context>` through the secrets store (Secure Enclave key
agreement, with the broker's approval ref) and returns the credential with `NotAfter` =
certificate `notAfter` (x509) or zero (token). It refuses with `stored certificate expired on
…; rotate it` if the certificate has expired, so an expired credential never reaches a tool
that would then loop on 401.

---

## 6. Later providers: design sketches

Both providers keep every check and the whole flow of sections 1 to 4; they differ only in
`Issue` and in what the cluster has to trust. Both make the "`nazar revoke` cannot pull back a
credential already handed out" weakness of `stored` short-lived on the **server** side.

### 6.1 `ca-cert` (B): a Secure Enclave certificate authority per context (built in Milestone 12)

- **Keys.** One Secure Enclave P-256 signing key per context, created by `nazar k8s ca create
  <context>` behind the login gate (`CreateKey(PurposeSign, AuthNone)`: as for every secret key
  since Milestone 8, nazar's gate is the check and the chip adds no user presence of its own; a CA key
  with user presence is a later decision, because rules that later allow a dialog or a session
  would make it unusable and re-creating a CA means re-adding it to the cluster). It signs while
  the Mac is locked too (`AfterFirstUnlockThisDeviceOnly`) unless `k8s ca create
  --only-when-unlocked` asks otherwise (spec 4.5); the choice is fixed for the CA's life, so a
  `ca create` for a context set up already with the other one is refused. The Vault item
  `k8s-ca/<context>` holds `{version, name, handle, publicKey, created, certDER, access}` (`access`
  absent for when-unlocked, so an older record reads as when-unlocked): the handle,
  the public key and the **CA certificate itself**, so issuing never reads a user-writable file.
  The CA certificate is self-signed through `Platform.Sign`: subject `CN=nazar k8s CA
  <context>`, `basicConstraints CA:TRUE, pathlen 0` (critical), `keyUsage keyCertSign`
  (critical), a random 128-bit serial, a subject key id, valid from one minute ago for 10 years.
  A copy is written to `~/.nazar/keys/k8s-ca-<context>.crt` (0644) for the cluster
  steps; nazar never reads it back.
- **Issue.** Inside nazar-agent, after check 0 and the three checks and the gate: generate an
  ephemeral P-256 key in software, build a client certificate with `CN=<identity.user>` and
  one `O=<group>` per `identity.groups` entry, issuer = the CA certificate's subject, authority
  key id = its subject key id, `notBefore = now - 1m`, `notAfter = min(now + ttl_cert, the CA's
  notAfter)`, `keyUsage digitalSignature` (critical), `extendedKeyUsage clientAuth` only,
  `basicConstraints CA:FALSE` (critical), a random 128-bit serial, no SAN. It is signed by
  `x509.CreateCertificate` through a `crypto.MessageSigner` over the platform: `SignMessage`
  receives the TBS bytes and calls `Platform.Sign(handle, tbs, approval)`, which hashes with
  SHA-256 (`ecdsa-with-SHA256`); the `crypto.Signer` `Sign(digest)` path is refused, so no
  caller can make the enclave sign a digest it did not see. The minted certificate is parsed
  back and checked (signature from the CA, not a CA, client auth only, `notAfter` within
  `ttl_cert`, the CA's issuer and key id) before it leaves; a failure mints nothing. The reply
  is the certificate and the ephemeral key as PEM (`EC PRIVATE KEY`), `NotAfter` = the parsed
  `notAfter`. **The ephemeral key and the certificate are never stored, logged or audited**
  (the audit line has the context, the server and the decision), and the agent and the CLI
  zero their copies of the key bytes after use (hygiene, 4).
- **Before signing, the context is read again** from the config in force: if it differs in any
  way from the one the request was checked and shown against (rules, clients, identity,
  `ttl_cert`, cluster, the fallback), nothing is minted (fail closed; the user
  runs the command again), and check 2 is run again against it.
- **Why an ephemeral key per issue.** The client holds a key that dies in `ttl_cert`; nothing
  long-lived ever leaves the Secure Enclave. Issuing is one SE signature.
- **What the cluster needs:** the API server's **client CA bundle** must include the nazar CA
  certificate. The client CA file is a bundle; kube-apiserver accepts several CAs in it.
  - **microk8s:** not `/var/snap/microk8s/current/certs/ca.crt` (the *cluster* CA that also
    signs serving certs; `microk8s refresh-certs` rewrites it). Instead a separate bundle,
    `client-ca.crt` = the existing `ca.crt` plus every nazar CA saved on the node
    (`certs/nazar-ca-*.crt`, one per context, so adding a second context keeps the first),
    named by `--client-ca-file=${SNAP_DATA}/certs/client-ca.crt` in
    `/var/snap/microk8s/current/args/kube-apiserver`, then
    `sudo snap restart microk8s.daemon-kubelite` (the control plane restarts; `microk8s stop`
    would stop every pod too).
    `nazar k8s ca show <context> --microk8s` prints exactly these steps with the certificate,
    and how to stop trusting a CA (delete its file, rebuild the bundle, restart); nazar itself
    never touches the cluster.
  - **kubeadm:** the same with `/etc/kubernetes/pki/ca.crt` → a separate bundle and the
    `--client-ca-file` flag in the static pod manifest.
  - **Managed clusters (EKS, GKE, AKS):** not possible; out of scope (decisions above).
    `config check` warns when a context's server looks like one.
- **Authorisation** stays in the cluster: bind `CN`/`O` with RBAC as for any x509 user. The
  nazar CA can mint any `O=system:masters` certificate: that is the point (it replaces the
  stored admin cert), and it is why the CA key lives in the Secure Enclave and every issue
  passes the checks and the gate.
- **Revocation:** none needed; `ttl_cert` is the revocation. Deleting the CA
  (`nazar k8s forget`) and removing it from the cluster's bundle ends the context for good.
- **Config:** `credential: ca-cert`, `identity: {user, groups}`, `ttl_cert` (section 3).

### 6.2 `jwt` (C): tokens signed by a Secure Enclave key (not planned; kept for later brainstorming)

- **Keys.** One Secure Enclave P-256 signing key per context, Vault handle `k8s-jwt/<context>`,
  `kid` = base64url(SHA-256(public key DER))[:16]. `nazar k8s jwks export <context>` prints the
  JWKS document (`{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":…,
  "x":…,"y":…}]}`), and `nazar k8s jwt rotate-key` adds a new key while keeping the old one
  in the JWKS for `ttl_token` so in-flight tokens stay valid.
- **Issue.** `ES256` JWT with `iss = k8s.contexts.NAME.issuer`, `sub = identity.user`,
  `aud = [cluster.server]` (so a token for hydra is useless against staging even if both trust
  the same issuer), `groups = identity.groups`, `iat = now`, `nbf = now - 30s`, `exp = now +
  ttl_token` (default 5m, max 1h), `jti` 128-bit random, header `kid`. Signed with
  `platform.Sign` using the approval ref. Return `Token`, `NotAfter = exp`.
- **What the cluster needs:** the API server must trust the issuer through **structured
  authentication configuration** (`--authentication-config` with
  `apiVersion: apiserver.config.k8s.io/v1, kind: AuthenticationConfiguration`, GA in 1.34):
  ```yaml
  jwt:
  - issuer:
      url: https://nazar.example.com/hydra          # == iss
      discoveryURL: https://nazar.example.com/hydra/.well-known/openid-configuration  # optional
      audiences: ["https://hydra.example:16443"]
      audienceMatchPolicy: MatchAny
    claimMappings:
      username: { claim: sub, prefix: "nazar:" }
      groups:   { claim: groups, prefix: "" }
    claimValidationRules:
    - expression: 'claims.exp - claims.iat <= 3600'
      message: token lifetime too long
  ```
  - **JWKS hosting.** The API server fetches `<issuer>/.well-known/openid-configuration` and
    the `jwks_uri` it names **over HTTPS with a certificate it trusts**; a plain file or a
    Mac-local URL does not work because the API server runs on the cluster. The two documents
    are static JSON that only change on key rotation, so any static host works: GitHub Pages,
    a Cloudflare Pages site, an object-storage bucket behind a CDN, or a tiny `nginx` in the
    cluster behind the cluster's own ingress (then `certificateAuthority:` in the issuer block
    carries the ingress CA). `nazar k8s jwks export --dir out/` writes both documents ready to
    upload; nazar never uploads anything itself.
  - **microk8s:** `--authentication-config=/var/snap/microk8s/current/args/authn.yaml` in
    `args/kube-apiserver`, then restart. `StructuredAuthenticationConfiguration` is beta and
    on by default from 1.30 (the file format is `v1beta1` there) and GA in 1.34 (`v1`); no
    feature gate is needed on 1.30+, only the right `apiVersion` in the file.
  - **EKS:** associate the issuer as an OIDC identity provider on the cluster
    (`aws eks associate-identity-provider-config`), which gives the same effect with a hosted
    JWKS; the issuer must then be reachable from AWS.
- **Why both the CA and JWT keys are per context:** a context's public key is handed to one
  cluster; losing or rotating one context's trust never affects another.
- **Config:** `credential: jwt`, `issuer: https://…`, `identity: {user, groups}`,
  `ttl_token: 5m`.

### 6.3 Why these are reserved and not built in Phase 3

Both need a cluster-side change and a way to test it (section 9 covers this with the fake API
server: it can verify client certs against a test CA and JWTs against a test JWKS, so the
providers are testable without a real cluster when they are built). The `stored` provider
delivers the whole value of caller rules today, with no cluster changes, and S10 (section 10)
must be answered before any provider's expiry behaviour is tuned. `config check` rejecting the
two kinds with `not implemented yet` keeps a reserved value from silently meaning "refuse
everything" at run time with no explanation.

---

## 7. CLI

**As built in Milestone 12:**

```
nazar k8s ca create <context>              # loosen: login prompt; makes the CA key and certificate
nazar k8s ca show <context> [--microk8s]   # read: the CA certificate PEM, or the microk8s steps
nazar k8s import <context> [--write]       # dry run without --write; loosen: one login prompt
nazar k8s list                             # read
nazar k8s forget <context>                 # login prompt; deletes the CA and the config entry
nazar k8s credential <context>             # the plugin; run by kubectl, not by people
nazar k8s rule add|set|remove <context> …  # Milestone 13; the flags of ssh-key rule without --to (3, as built in M13)
```

- **`ca create`** refuses an invalid name, an existing CA (or one whose Vault item this agent
  can't read, with the spec 9 remedy), and makes the key, the self-signed CA certificate, the
  Vault item and the `.crt` file after one login prompt. It writes no config entry (that needs
  the cluster, which `import` reads). Output: the certificate's path and SHA-256 fingerprint,
  and the next step (`nazar k8s ca show <context> --microk8s`).
- **`ca show`** prints the CA certificate PEM from the Vault item (never the file). With
  `--microk8s` it prints the steps of 6.1 with the certificate inline, ready to paste on the
  cluster's node. Read-only, no prompt.
- **`import`** reads the kubeconfig set (`$KUBECONFIG` split on `:`, else `~/.kube/config`),
  resolves `contexts[<context>]`, its user and its cluster, and refuses (exit 1, before any
  prompt): a context name that is not a valid nazar name (rename it with `kubectl config
  rename-context`), no CA for the context yet (`nazar k8s ca create` first), a cluster with
  `insecure-skip-tls-verify` or without a CA, a user entry without a client certificate to copy
  the identity from (`identity.user` = its CN, `identity.groups` = its O values), a user entry
  that already runs another exec plugin, an `auth-provider`, and a user entry that another
  context also uses (rewriting it would change that context too; `kubectl config
  set-credentials` gives each its own). It also refuses a file it could not rewrite faithfully
  (more than one YAML document; anchors, aliases or merge keys) and a user entry that runs
  `… k8s credential <context>` but not exactly as `import` writes it (a bare `nazar` on the
  PATH, an `env:` block, another `interactiveMode`) or through another nazar binary than the one
  running: only this nazar's own entry is "already imported". `$KUBECONFIG`
  gets no `~` expansion, as client-go gives none. It prints the redacted kubeconfig diff and the
  config entry it would write.
  With `--write`: the CLI renders the rewritten file into its `0600` temp file first; then one
  login prompt in nazar-agent shows the context, identity, cluster and the config change; after
  approval nazar-agent re-reads `config.yaml` (exit 4 if it changed or held unapproved changes)
  and writes and applies the entry; then the CLI writes the backup (8) and renames the temp file
  over the kubeconfig. Re-running `import --write` for a context already configured with the
  same cluster and identity, and with a usable CA (checked first), needs no
  prompt and only rewrites the kubeconfig (so a failed
  rewrite is finished by running it again); a configured context with another cluster or
  identity is refused (exit 1: edit `config.yaml`, which is a loosening change, or `forget`).
- **`list`**: every configured context and every CA, `K8sContextList` with `--json`. Since
  Milestone 13 each context also carries `state` (`ok`, `not-imported`: a CA and no entry, `no-ca`,
  `ca-unusable`, `absent`: the reply of `forget`) with its `remedy`, `policy` (the `SSHKeyRules`
  of a key, `fallbackSource: context-gate`, from the config as shown, so its `configHash` is
  what `--if-hash` checks; absent without an entry) and `warnings` (the parse warnings of its own
  entry). `nazar status` lists an unusable `k8s-ca/<context>` Vault item with the same remedy.
  Nazar UI.app's Kubernetes tab (Milestone 13) shows this object and runs `k8s rule add|set|remove`
  (never with `--to` or `--no-to`), `k8s forget` and `log --target k8s:<context>`, nothing else.
- **`forget`**: one login prompt; deletes the CA key (Secure Enclave and Vault item), its
  `.crt` file and the `k8s.contexts` entry (removing an entry is tightening; it is written
  under the same approval, refused with exit 4 if `config.yaml` held unapproved changes or
  changed while the prompt was open), and drops the context's remembered approvals. A CA item
  this agent can't read is refused before any prompt with its remedy (spec 9); a record that
  reads but can't be used (a bad format, another name) is nazar's own and `forget` deletes it,
  which is the fix every command names for it. The prompt names only what exists (the CA, the
  entry). The kubeconfig is not touched; the output says to restore the backup or remove the
  user entry.
- **Exit codes of `credential`**: 0 ExecCredential; 2 usage (no `KUBERNETES_EXEC_INFO`, junk
  JSON, wrong `apiVersion`, an unknown context name, more than 48 KiB); 3 refused (check 0,
  1, 2 or 3, no `spec.cluster`, `insecure-skip-tls-verify`, denied, timed out, no CA for the
  context); 5 nazar-agent not running; 1 anything else (a CA this agent can't use, with its
  fix; the context changed while the prompt was open).
- **`--json` kinds of Milestone 12**: `K8sContext {name, credential, identity{user, groups},
  ttlCert, cluster{server, caSHA256, tlsServerName, proxyURL}, clients, rules, configured,
  ca{fingerprint, created, certFile} | null, caBroken, unusableReason, remedy}` (Milestone 13
  adds `state`, `policy`, `warnings`; the rule commands reply `ConfigEdit` with `context`),
  `K8sContextList {items}`, `K8sImport {context, file, diff, config{changes}, written, backup}`.
  `K8sCredential` is wire only (the reply to `k8s.credential`, a value command), never printed
  by a `--json` command.

**The original design of the full module** (stored, rotate, audit), kept for later:

```
nazar k8s import <kubeconfig-context> [--as NAME] [--kubeconfig PATH] [--write] [--json]
nazar k8s rotate <context> [--kubeconfig PATH | --cert FILE --key FILE | --token-stdin] [--write] [--json]
nazar k8s audit  [--kubeconfig PATH] [--json]
nazar k8s list   [--json]
nazar k8s forget <context> [--kubeconfig PATH] [--write] [--json]
nazar k8s credential <context>            # the plugin; run by kubectl, not by people
```

**Exit codes** are the main spec's (`0` ok, `1` error, `2` usage, `3` refused by the gate or a
check, `4` staged and waiting for approval, `5` Nazar.app not running). Specifics:

| Command | Exit | When |
|---|---|---|
| `import`, `rotate` | 0 | with `--write`: one login approval passed, credential stored, config applied (`import`), kubeconfig rewritten, in that order (5.2 steps 7 and 8). Without `--write`: dry run, diff printed, nothing stored or staged |
| | 4 | `import` only, nothing done: `config.yaml` already held unapproved changes, or it changed while the prompt was open (5.2 step 7). `import` never leaves anything staged, with or without `--json` |
| | 3 | the login gate was refused, timed out or is in its cooldown; nothing stored, nothing applied, kubeconfig untouched |
| | 1 | context not found, already imported (`import`; use `rotate`), not imported (`rotate`), unsupported credential, cluster refused (insecure, no CA), shared user with different clusters, kubeconfig unwritable (checked before the prompt), or the rewrite failed after a successful store (5.2 step 8) |
| `audit` | 0 | nothing to report |
| | 1 | at least one finding (so scripts can gate on it); `--json` lists them either way |
| `list` | 0 | always |
| `forget` | 0 / 3 / 1 | like `import`. It deletes the `k8s/<context>` store entry and the `k8s.contexts` entry; deleting a credential is irreversible, so it needs the login gate like `ssh-key delete` (exit 3 if refused). Removing the config entry is tightening and applies at once, so `forget` never exits 4 |
| `credential` | 0 | ExecCredential on stdout |
| | 3 | refused: not the nazar CLI (check 0), not a trusted client, cluster mismatch, **no `spec.cluster`** (check 2 cannot run, 1.1), blob does not belong to the context, no rule matched / blocked, denied, timeout |
| | 2 | usage: unknown context name, no `KUBERNETES_EXEC_INFO`, wrong `apiVersion`, junk JSON |
| | 5 | Nazar.app not running (kubectl shows nazar's one stderr line; `installHint` is not shown for this, 1.1) |
| | 1 | anything else (store unreadable, provider error) |

`nazar k8s credential` has **no `--json` flag**: its stdout is already the machine-readable
ExecCredential, and it prints exactly one line to stderr on failure (`nazar: refused: not a
trusted k8s client (python3)`), which kubectl surfaces as `Unable to connect to the server:
getting credentials: exec: executable … failed with exit code 3`. The user then runs `nazar
log --target k8s:hydra` for the full story.

**`--json` kinds** (`apiVersion: nazar/v1`):
- `K8sContext`: `{name, credential, cluster{server, ca_sha256, tls_server_name, proxy_url},
  clients, ttl, rules_summary, stored{type, subject, not_after, imported, source} | null,
  kubeconfig{file, user, exec_ok}}`.
- `K8sContextList`: `items: [K8sContext]`.
- `K8sAudit`: `items: [{context, file, severity: error|warning, code, message}]` with codes
  `plaintext-credential`, `exec-wrong-path`, `exec-wrong-apiversion`, `exec-missing-cluster-info`,
  `exec-interactive`, `exec-env` (an `env:` block, 1.1), `client-stale-hash`, `cert-expiring`,
  `cert-expired`, `cluster-insecure`, `credential-rejected` (early re-runs of the plugin,
  1.4), `shadowed-user` (the same user name defined in two `KUBECONFIG` files, section 8),
  `context-not-in-kubeconfig` (a `k8s.contexts` entry whose `kubeconfig_context`, or name, is
  in no kubeconfig of the set) and `context-not-configured` (a kubeconfig exec entry running
  `nazar k8s credential X` where `X` is not in `k8s.contexts`).
- `K8sImport`: `{context, stored: K8sContext.stored, config: ConfigDiff, kubeconfig{file,
  diff, written}}`. `diff` is the redacted unified diff as a string.
- Errors are `Problem` (existing kind) with `code` one of the audit codes or
  `unsupported-credential`, `shared-user`, `not-found`.

**`nazar k8s audit`** walks every kubeconfig in the set and reports:
- user entries still holding a credential inline or by file (`plaintext-credential`): the main
  gap for gradual adoption;
- nazar exec entries that are wrong (`exec-wrong-path`, `exec-wrong-apiversion`,
  `exec-missing-cluster-info`, `exec-interactive` for anything but `Never`);
- clients whose cdhash no longer matches (`client-stale-hash`), with the `nazar trust` command;
- stored certificates expiring within 30 days (`cert-expiring`) or expired (`cert-expired`);
- clusters with `insecure-skip-tls-verify` (`cluster-insecure`);
- a stored credential the server keeps rejecting (`credential-rejected`, from the daemon's
  counter via `k8s.list`, 1.4) and user names defined twice across the set (`shadowed-user`);
- contexts in `k8s.contexts` with no kubeconfig counterpart (`context-not-in-kubeconfig`) and
  kubeconfig exec entries naming an unconfigured context (`context-not-configured`).
It never decrypts anything, never prompts and never reads the unified log: everything comes
from the kubeconfigs, the config, the sidecars and one `k8s.list` request to the daemon.

---

## 8. Kubeconfig rewriting

- **Diff first, always.** `import`, `rotate` and `forget` print a unified diff of the file they
  would change, with the file path as header. **Every credential value is redacted in every
  printed line**, not only in removed lines: a context line of the diff can show a
  neighbouring, not yet imported user's `client-key-data` or `token`. The redaction runs over
  the whole file before diffing, replacing the value of every `client-certificate-data`,
  `client-key-data`, `token`, `password`, `refresh-token`, `id-token`,
  `auth-provider.config.*` and **`exec.env[*].value`** key, and the `args` of every exec entry
  but nazar's own, with `<redacted: N bytes>`, and every comment with `# <comment: N bytes>`
  (an old credential is often kept commented out), so
  `-    client-key-data: <redacted: 1 679 bytes>` and `     token: <redacted: 42 bytes>` both
  appear redacted. `exec.env` values are redacted because users put cloud keys in the `env:`
  blocks of other plugins' exec entries (`aws eks get-token` with inline keys); nazar never
  writes an `env:` block itself (1.1), so redacting them hides nothing nazar needs to show.
  `kubeconfig_test.go` greps the output for every plaintext in the corpus, other users'
  included. The diff of a file is the only thing ever printed about it; nazar never echoes a
  credential it just read.
- **Nothing from a kubeconfig or a sidecar reaches the terminal raw.** Both files are
  attacker-writable (threat model, section 10; sidecar, 5.1), and so is `KUBERNETES_EXEC_INFO`.
  Every string taken from them and printed by `import`, `rotate`, `forget`, `audit` or `list`
  goes through the audit log's escaping (main spec 4.6, `quote` in `core/audit/format.go`,
  `strconv.QuoteToASCII` per value): context, user and cluster names, server URLs, proxy URLs,
  file paths, the sidecar's `subject` and `source`, and audit finding messages that embed any
  of them. The same applies to the dialog lines of the import and rotate prompts. Diff lines
  cannot be quoted whole without making the YAML unreadable, so each one is escaped rune by
  rune: every rune that `strconv.IsGraphic` rejects (C0 and C1 controls such as `ESC` and `CSI`,
  `DEL`, tab) and every Unicode format character (category `Cf`, such as `U+202E` and the other
  bidi overrides) is printed as `\x1b` / `‮`, a literal backslash as `\\`, and everything
  else as is. `--json` output relies on `encoding/json`, which escapes control characters
  itself. The rule covers comments, unknown keys and other users' entries too, since all of
  them appear as context lines.
- **`--write` applies it**, otherwise nothing is written. `--write` is accepted together with
  `--json`; the JSON then carries `written: true`. For `import` and `rotate` the rename over the
  kubeconfig happens only after Nazar.app has stored the credential (and, for `import`,
  applied the config) under the login approval. The temp file is prepared before the prompt
  and unlinked on refusal (5.2 steps 7 and 8).
- **No backup, ever** (for `stored`). A backup of the pre-import file would hold the plaintext
  credential, so none is written, and `import` says so. Users who want a copy make one
  themselves *before* running import, knowing it holds the secret.
- **`ca-cert` imports write one backup (Milestone 12).** A
  `ca-cert` import keeps no copy of the old credential anywhere (unlike `stored`, whose store
  entry keeps it), so a rewrite before the cluster trusts the nazar CA would leave the user
  without a working credential. `import --write` therefore writes the original file, byte for
  byte, to `<file>.nazar-backup-<UTC time>` beside the path the user named (beside a symlink,
  never in its target's directory, which may be a dotfiles repository; `O_CREAT|O_EXCL`, mode
  `0600`, `fsync`ed) after the approval and before the rename, and prints its path with the
  warning that it holds the old credential in plain text and that credential still works on the
  cluster: delete it once kubectl works through nazar. (A client certificate can't be revoked;
  only a new cluster CA ends it, and that changes the CA the context pins, so docs/CLI.md puts it
  before the import. Milestone 12 dropped the earlier "rotate it on the cluster" advice, which after a
  `ca-cert` import leads to `cluster mismatch`.) A backup that
  cannot be written stops the rewrite (exit 1; the config entry stays, and `import --write`
  run again finishes).
- **Only the file that defines the user entry is changed.** With several `KUBECONFIG` files,
  the context, cluster and user may live in different files; nazar edits the one with the
  `users[]` entry and leaves the others alone. If the same user name is defined in two files,
  client-go uses the first and so does nazar; the second is reported by `audit` as
  `shadowed-user` (warning, with both paths) but not edited.
- **Edits are node-level, not regenerate-and-dump.** The file is parsed into a `yaml.v3` node
  tree; inside the one `user:` mapping the credential keys (`client-certificate-data`,
  `client-key-data`, `client-certificate`, `client-key`, `token`, `tokenFile`) are removed and
  an `exec:` mapping is added, **every other key of the mapping is kept** (`as`, `as-uid`,
  `as-groups`, `as-user-extra`, unknown keys), and the tree is encoded back, which keeps
  comments, key order and the other entries' formatting. Indentation is normalised to two
  spaces (yaml.v3 does not preserve the original width), which is what kubectl itself writes.
- **Atomic and permission-preserving, and the temp file is a secret.** The rewritten file is a
  full copy of the kubeconfig and still holds the plaintext credentials of **every other, not
  yet imported user entry**, so it is treated as a credential file: created with
  `O_CREAT|O_EXCL`, **mode `0600` always** (the final file gets the original's mode, a stricter
  one such as `0400` included, or `0600` if the original was open to the group or others, with
  the note `it is now 0600`), written, `fsync`ed, then `rename`d over the original. The rename
  is made holding client-go's own lock, `<file>.lock` (`O_EXCL`), so kubectl writing the same
  file at that moment makes the rewrite fail rather than lose either write. If the kubeconfig is a symlink (dotfile managers), the link target is resolved
  with `realpath` and the temp file is created **in the target's directory** (an atomic rename
  needs the same filesystem and directory), the target is rewritten and the link kept. The
  temp file is named `.<basename>.nazar-tmp.<random>` and is **always removed**: on success by
  the rename, on any error by a deferred unlink, and a stale one left by a crash is unlinked
  on the next run once it is a minute old (a younger one may be another run's, waiting on its
  prompt); a symlink with that name is never nazar's and is unlinked whatever its age (never
  parsed or followed, never kept; its contents are at best a copy of the current file and at
  worst older plaintext).
- **`forget --write`** removes the exec entry and leaves an empty `user: {}`; it never writes
  the credential back. The user re-creates credentials from the cluster side.
- **Never touched:** `~/.kube/cache`, `~/.kube/http-cache` (client-go discovery caches; they
  hold no credentials), and any file the kubeconfig points at (`client-certificate: path`
  files are read, never deleted; the advice names them so the user can shred them after
  rotating).

---

## 9. Interaction with k9s, helm and other long-running tools

| Tool | How it calls the plugin | Effect under nazar |
|---|---|---|
| **kubectl** | Once per invocation (several concurrent informers in `apply`/`wait` share one in-process cache); again on 401 | One approval per command under `scope: use`; silent within a session approval |
| **k9s** | At start, then whenever the cached credential passes `expirationTimestamp` (every `ttl`, 5 min); several parallel runs at start | `scope: session` + `expire: 8h`: one prompt at start (parallel runs share it through the in-flight dedup), then silent; `scope: use`: **one dialog per plugin run**, so three informers at start mean three dialogs and then one every 5 minutes. That is the meaning of `use` (main spec 4.2); do not use it for k9s |
| **helm** | Per invocation like kubectl; `helm` must be in `clients` (it is its own binary) | Same as kubectl |
| **kubectl plugins (krew)** | The plugin binary is the client | Must be trusted and listed itself (2.1) |
| **Lens, Headlamp, other GUI clients** | From a helper inside the app bundle; `app:` matcher in `clients` (2.1: the helper must be a signed member of the bundle) | The *client* is the bundle's helper; the *caller* view `chain[2:]` is the app's main process and its launch chain (Finder/launchd), so rules for GUI clients use `apps: [lens]`, which `config check` accepts (2.3: `app:` clients are exempt from the client-overlap error because the matched client is the helper, not the app's main process). **GUI clients need `scope: app`** (or `use`). They have no session: the session root is the first process below the app that is not one of the app's own same-team helpers (`sessionRoot`, `core/caller/resolve.go`, refining main spec 4.1 step 4), so for `Lens ▸ Lens Helper ▸ nazar` it is the `nazar` CLI itself (or the helper, if it is not signed by Lens's team), a process that exits with the plugin run. A `session` approval would end with every run and the user would be prompted every `ttl`. `config check` therefore rejects `scope: session` on a rule naming an `app:` client and on a context whose clients are all `app:` matchers (section 3); a `session` rule reached by a GUI client anyway (through `apps: [any]`) behaves as one session per plugin run, which is `use` in effect |
| **Tools that shell out to kubectl** (scripts, Claude Code, Makefiles, Tilt, Skaffold) | kubectl is the client; the tool is in the chain above it | Judged by rules on the tool, which is the whole point |
| **`kubectl proxy`, `port-forward`, `logs -f`, `exec -it`, `watch`** | Long-lived single invocation; the credential is used on the first request; `exec`/`port-forward` upgrade to SPDY/WebSocket once | One approval; the stream keeps running after `expirationTimestamp` (the connection is already authenticated); a reconnect runs the plugin again |
| **Tools with their own kubeconfig parsing** that ignore `exec` (rare, old) | Never reach nazar | `audit` cannot see them; they simply fail to authenticate |

**Credential caching outside the process.** client-go keeps exec credentials in memory only;
nothing is written to `~/.kube/cache`. Verbose client-go logging (`-v=8`+) masks the
`Authorization` header. A tool that dumps its own memory or writes credentials to disk is a tool
problem, outside nazar's control (section 10, documented limit).

**Background and detached runs.** A kubectl started by `nohup`, `launchd`, cron or an SSH
session into the Mac has an `unknown` chain (main spec 4.1). It matches only `apps: [any]` /
`apps: [unknown]` rules, gets a dialog with the Unknown app warning (unless the user made such a
rule `gate: none`), and its approval is never remembered, so a k9s running detached would prompt
every `ttl`. That is intended.

---

## 10. Threat model additions

**What the module protects against**

| Threat | Defence |
|---|---|
| **Fake API server.** Malware edits the kubeconfig (or sets `KUBECONFIG`) so a real kubectl talks to an attacker's server with the attacker's CA, hoping the plugin hands over the admin cert | Check 2: `server`, `ca_sha256`, `tls-server-name`, `proxy-url` must equal the record in nazar's approved config, which malware cannot change without the login gate (4.8). Refused without a dialog, audited as a possible fake-server attempt, block warning shown |
| **Fake client.** `python3 evil.py` (or a replaced `/opt/homebrew/bin/kubectl`) runs `nazar k8s credential hydra` itself, with a correct `KUBERNETES_EXEC_INFO` copied from a real run | Check 1: the parent must match `clients` by cdhash or signature. Refused without a dialog, block warning |
| **Wrapped plugin.** Malware edits the kubeconfig so the exec entry is `bash -c 'exec > >(tee leak); exec nazar …'`: kubectl stays the CLI's parent, the reply is copied | The stdout check (2.1): the CLI's fd 1 must be the pipe it alone writes to and whose read end kubectl opened and alone holds. Refused without a dialog, before any cached approval, audited (THREAT-MODEL 5.16) |
| **Untrusted caller behind a real client.** Malware runs the real kubectl against the real cluster | Check 3: the chain above kubectl has no matching rule → `defaults.fallback` → blocked, with the chain in the warning. Only a config change (login gate) can allow it |
| **Credential theft from disk, backups, dotfile repos** | After import the kubeconfig holds no credential; the store entry is HPKE-encrypted to a Secure Enclave key and useless off this Mac. With `ca-cert` (M12) nothing long-lived exists outside the enclave, except the `.nazar-backup-*` file `import --write` leaves (section 8): it holds the old credential in plain text until the user deletes it and rotates that credential |
| **Silent use at 3 am by a tool left running** | `scope: session` dies with the tab; `expire` bounds it; `ttl` makes every tool come back within 5 minutes to re-check; everything is audited with the kubectl command line |
| **A revoked approval still being usable for hours** | Bounded by `ttl` (default 5 min, max 1 h) on the client side; by certificate/token lifetime on the server side with `ca-cert`/`jwt` |
| **Approval dialog spoofing** (a process pressing the dialog) | Main spec 4.4: hardware-input-only dialog, or the login gate |

**What it does not protect against (documented)**

- **Credential exfiltration by a trusted client.** Once kubectl holds the credential it can do
  anything with it, including writing it to disk. (An *untrusted* process posing as the CLI is
  check 0; a trusted client leaking is the limit.) `clients` says *who may receive* the
  credential; with `stored` the received credential is the long-lived cluster credential
  itself. `ca-cert`/`jwt` shrink what a leaking client can leak to a 5-15 minute window; until
  then, rotate `stored` credentials on a schedule and prefer dedicated, least-privilege users
  per context (a read-only `hydra-readonly` with its own RBAC, next to a rarely approved
  `hydra`).
- **Anything inside an approved scope.** A Claude Code tab approved for `hydra` with
  `scope: session` can run any kubectl command in that tab until the tab closes or `expire`
  passes. `scope: use` for powerful contexts is the mitigation, as in the config example.
- **What the cluster lets the credential do.** nazar gates *access to* the credential, not the
  RBAC behind it. A `system:masters` certificate stays `system:masters`.
- **A compromised Nazar.app process.** The stored credential is decryptable by the process
  whenever it decides to. With the Phase 2 store's **single** secrets key-agreement key (main
  spec 7.1) the Secure Enclave's user-presence ACL is a property of that key, not of an entry,
  so `gate: login` on a context's rules does **not** by itself put the Secure Enclave's own
  user-presence check between a compromised process and the `k8s/<context>` blob: the key's
  ACL is whatever the store chose for all secrets. A per-context key-agreement key with a
  user-presence ACL (created at import for contexts that ask for it, `presence: required`)
  would restore that property and is recorded as Q6 (section 13). The S13 default (cache the
  plaintext in Nazar.app memory for `ttl` after one decrypt) weakens it further for the
  duration of `ttl`. Until Q6 is decided the claim is simply not made.
- **Root or kernel compromise**, and malware driving an approved app through Automation
  (main spec 8).
- **A fake server that also has a stolen copy of the real CA key** can present the real CA and
  the real hostname only if it also controls DNS or the network path; nazar is not a replacement
  for TLS, it assumes it.

**Approved scope and the k8s `to:`.** Approvals are remembered per `(context, rule, scope,
client)`. Approving kubectl in a tab does not approve k9s in it, and the other way round. There
is no way to approve "all clients"; a rule applies to whatever client of the `clients` list
asked, one approval each.

---

## 11. Testing strategy

**Everything runs with `go test` and no real cluster, no Secure Enclave, no dialog.** The fake
platform (`core/platform/fake`) scripts chains and approvals as in Phase 1.

**Unit tests (`core/k8s/...`)**

- `exec_test.go`: parse `KUBERNETES_EXEC_INFO` for v1 with every `spec.cluster` field; refuse
  v1beta1, missing `spec.cluster`, `insecure-skip-tls-verify`, missing CA, junk JSON; encode the
  reply and check it round-trips through client-go's own `ExecCredential` type (test-only
  dependency on `k8s.io/client-go/pkg/apis/clientauthentication/v1`, pinned, not a core
  dependency).
- `cluster_test.go`: URL normalisation table (case, `:443`, trailing slash, path prefix kept,
  query refused); `ca_sha256` canonicalisation (PEM order, whitespace, comments, two-cert
  bundles, DER with trailing garbage refused); `tls-server-name` / `proxy-url` comparisons.
- `expiry_test.go`: `expirationTimestamp = min(now+ttl, approval end, notAfter)` for every
  combination, including `scope: use`, one-shot unknown chains, an expired certificate (refused),
  and wall-clock rather than monotonic comparison across a simulated sleep.
- `checks_test.go`: check 0 and the three checks in order with scripted chains: peer not the
  bundled CLI (ad-hoc, other team, PID-only), trusted client, stale cdhash, shell-as-parent,
  truncated chain / parent exited / PID-only parent (all refused), GUI client helper inside
  the bundle vs `python3` under the same app (refused), Apple-signed client rejected by config
  check, cluster mismatch on each field, rules judged on `chain[2:]` (an `apps: [kubectl]` rule
  and an inline `apps: [{path: /opt/homebrew/bin/kubectl}]` rule both rejected by config check,
  `apps: [lens]` with `lens` as an `app:` client accepted, `scope: session` on that rule
  rejected; malware ▸ kubectl ▸ nazar blocked), receiver = client identity,
  approvals not shared between kubectl and k9s, unknown callers one-shot, `scope: use` three
  parallel runs → three prompts, `scope: session` three parallel runs → one prompt.
- `rejected_test.go` (the `credential-rejected` counter of 1.4, on an injected clock): three
  parallel runs from one pid at start plus a fourth 2 s later → no warning; every run at or
  after the previous `expirationTimestamp` (k9s refreshing every `ttl` for an hour) → no
  warning; three runs from one pid, each more than 15 s after the first run and before the
  last credential's `expirationTimestamp`, within 10 minutes → `credential-rejected`; the same
  three spread over 11 minutes → no warning; counters are per `(context, client pid)`, so
  two kubectl processes never add up.
- `kubeconfig_test.go`: parse and rewrite against a corpus of real-shaped kubeconfigs (inline
  data, file refs with relative paths, tokens, `tokenFile`, exec users, cert+token users
  (refused), impersonating users (`as*` kept), shared users across same and different clusters,
  multiple `KUBECONFIG` files with shadowed names, symlinked files, comments and odd
  indentation); the printed diff never contains a credential byte of **any** user in the file
  (the test greps for every plaintext in the corpus, not only the imported user's, and
  `exec.env` values of other plugins' entries); a kubeconfig with `ESC[2J`, an OSC 8 link and
  `U+202E` in a user name, a context name, a server URL and a comment, plus a sidecar whose
  `subject` and `source` carry the same, produces `import`, `audit` and `list` output with no
  raw `ESC` (`0x1b`), `U+009B` or `U+202E` (the test greps the output bytes); the temp
  file is `0600`, lives in the symlink target's directory and is gone after success and after
  an injected write error; atomic write preserves mode and symlinks.
- `stored_test.go`: import → store → issue round trip on the fake secrets store; expired cert
  refused; metadata sidecar holds no credential bytes; a sidecar edited to add `credential_ref`
  changes nothing; `k8s/hydra.hpke` copied over `k8s/hydra-readonly.hpke` fails to open.
- `configstage` tests: one per row of the section 3 loosen/tighten paragraph (cluster field
  edits, clients edits, credential kind, `credential_ref`, ttl both ways).
- Fuzzers: `FuzzParseExecInfo`, `FuzzParseKubeconfig`, `FuzzCanonicalCA`.
- `cmd/nazar/k8scred_test.go` (untagged, so it tests the release code path): the passwd lookup
  is a package variable the test replaces with one returning a temp dir `P`; with `HOME`,
  `NAZAR_CONTROL_SOCKET` and `NAZAR_CONFIG` pointing at a decoy dir `D` that holds a listening
  socket and a config, `k8s credential hydra` dials `P/.nazar/run/control.sock` (a listener there
  sees the connection), `D`'s socket sees none, and `D`'s config is never opened. A lookup
  error or a relative `HomeDir` → exit 1 with no dial. This test fails if an implementation
  reuses `app.controlSocket()`.
- **Release check** (`make release-check`, a new Makefile target run before every release
  build): build `./cmd/nazar` exactly as the bundle build does and fail if the binary contains
  `NAZAR_TEST_CONTROL_SOCKET` or if `go list -f '{{.GoFiles}}' ./cmd/nazar` lists
  `k8scred_testsock.go` (1.1).

**The fake API server (`core/k8s/k8stest`)**

A `httptest.Server` with TLS from a test CA generated at test start, serving the minimal API
a client needs: `/version`, `/api`, `/api/v1`, `/api/v1/namespaces/default/pods` returning a
fixed list. It authenticates **both ways**:

- **mTLS:** `tls.Config{ClientAuth: VerifyClientCertIfGiven, ClientCAs: <test client CA>}`;
  a request with a valid client cert is `200`, with none or a wrong one `401`.
- **Bearer:** a fixed token (and, for the future `jwt` provider, ES256 verification against a
  JWKS served by the same test server at `/.well-known/openid-configuration` and `/jwks`).
- **Knobs:** return `401` once then `200` (the re-exec path), delay responses, present a
  *different* CA (the fake-server test), and record every `Authorization` header and client
  cert seen, so tests can assert that the credential reached the server only when nazar said
  so.

**Platform conformance (`core/platform/conformance`, subtest `keys/k8s-ca`)**

The one place the CA meets a real Secure Enclave without a person: the suite makes a CA with
`CAStore.Create` on the platform under test (its Vault in memory), issues one certificate,
verifies both certificates with the CA's public key alone (`ecdsa.VerifyASN1` over the TBS bytes,
and `x509.Verify` against a pool holding only the CA), deletes the CA and checks that its key no
longer signs. It runs on the fake, behind the C table (`bridge/cbridge`), and in
`NazarConformanceHost real` (Secure Enclave, `AuthNone`, no gate) and `seamed`. A platform that
signs only a message's first 64 bytes passes every other subtest and fails this one.

**Platform conformance (`core/platform/conformance`, group `pipes`)**

`platform.Pipes.StdoutReadBy(writer, reader)` against real children of `NazarConformanceHost`
(the host is the reader, as kubectl is): a pipe the host reads is yes (twice); a pipe a third
process reads, a pipe the host reads while another child holds its read end too, a pipe the
host reads through an fd that is not close-on-exec (as an inherited one is), an exec-hop relay
through `cat`, a file, a pty, a socket, the read end and a closed fd 1 are no; an exited writer,
stale generations, PID-only and zero refs are `ErrNoProcess`; the question is not symmetric. Six
broken fakes (any reader, the parent is enough, never, by PID, a shared read end, an inherited
read end) fail it. `core/platform/pipes` also runs the real `kubectl` against an
`httptest` server in a temp kubeconfig with the test binary as its exec plugin: fd 1 is a pipe,
the parent is kubectl and the check says yes; behind `bash -c 'exec > >(exec /bin/cat); exec
"$0"'` kubectl still gets the credential and the check says no; and when the test gives kubectl
a pipe on stdin and stderr, keeps its read end and the wrapper is `exec 1>&2`, the test reads the
plugin's output and the check says no; it says no too when the test closes its copy once kubectl
runs, leaving kubectl the only holder, on its stdin.

**Integration tests (`test/integration/k8s_test.go`, macOS, build tag `integration`)**

*As built in Milestone 12:* the scripted-chain kubectl cases of this list are
`core/daemon/kubectl_test.go` (in process, the real kubectl and the `nazartest` CLI, the
fake platform), and real chains are `bridge/conformancehost` (below).
`test/integration/k8s_test.go` runs every `nazar k8s` command of the
`nazartest` build (the CLI `make integration` builds) against `nazar-testd` in a temp home, in
the order of docs/CLI.md's Kubernetes section, and then the real kubectl on the kubeconfig
`import --write` wrote: the entry reaches `nazar-testd`, which vouches for no CLI, so check 0
refuses it (an audit line, kubectl's `exit code 3`). Each phrase docs/CLI.md, AGENTS.md and
section 6.1 quote is checked against what the command printed, and no output shows the old
client key. The rest of this list (`.hpke`, `audit`, `rotate`, `forget --write`, the injected
clock) is the original design of `stored`.

- Drive the **real `kubectl`** binary (whatever `kubectl` is on the machine; skipped if none)
  with a temp `KUBECONFIG` whose exec entry points at the `nazartest`-tagged `nazar` CLI (1.1)
  and a `nazar-testd` on the fake platform, against the fake API server. kubectl gets
  `NAZAR_TEST_CONTROL_SOCKET=<testd control socket>` in its environment, and client-go passes
  that on to the plugin; the harness's usual `HOME`/`NAZAR_CONTROL_SOCKET` are set to a decoy
  directory for these tests, so a plugin that honoured them would miss `nazar-testd` and fail:
  - **the hardening holds:** the kubeconfig's exec entry carries an `env:` block setting `HOME`,
    `NAZAR_CONTROL_SOCKET` and `NAZAR_CONFIG` to a decoy directory with a listening decoy
    socket and a permissive decoy config; `kubectl get pods` still reaches `nazar-testd` and is
    judged by its config, and the decoy socket accepts no connection;
  - `kubectl get pods` with a scripted approved chain → `200`, one audit line, the fake server
    saw the stored cert;
  - the same with the fake server presenting another CA → exit 3, `cluster mismatch`, the
    server saw nothing;
  - the plugin run from a shell instead of kubectl → exit 3, `not a trusted k8s client`;
  - `kubectl` with `KUBERNETES_EXEC_INFO` stripped (`provideClusterInfo: false`) → exit 3;
  - `expirationTimestamp` honoured: the test daemon runs with an **injected clock**
    (`nazar-testd --clock-socket`, the fake platform's `Now`) advanced by 6 minutes between two
    `kubectl get pods` against a `ttl: 5m` context → two plugin runs, one approval under `scope:
    session`, two under `scope: use`. `config check`'s `30s..1h` floor is not bypassed; kubectl
    compares `expirationTimestamp` with its own wall clock, so the daemon's injected `Now` is
    set *behind* real time at start and advanced past it, which is why the clock is injected
    rather than a test-only `ttl`;
  - `401` then `200`: client-go re-runs the plugin and succeeds within one approval.
- `nazar k8s import --write` on a temp kubeconfig, then `kubectl config view` shows the exec
  entry and no credential, the `.hpke` blob exists, and `nazar k8s audit` is clean; `rotate`
  and `forget --write` round trip. Ordering (5.2 steps 7 to 9): `import --write` with the login
  prompt scripted to deny → exit 3, kubeconfig byte-identical, no blob, no config entry, no
  temp file left; the same with `--json` → same result, never exit 4; with an unapproved edit
  already in `config.yaml` → exit 4 before any prompt, nothing stored; with `config.yaml`
  edited while the prompt is open → exit 4, nothing stored; `import` without `--write` → exit
  0, nothing stored or staged; a second `import --write` of the same context → exit 1 naming
  `rotate`; a read-only kubeconfig → exit 1 before any prompt.
- another build of the test CLI (the same identifier, ad-hoc signed, another cdhash) under
  another path, run by the real kubectl → exit 3, `not the nazar CLI` (check 0; the daemon pins
  the test build's cdhash in place of the team requirement). A copy of the pinned build under
  another path is the same program and passes (THREAT-MODEL 4.10). Both run on real chains in
  `bridge/conformancehost`, below.
- **Real binaries, scripted chains:** the fake platform returns the real `kubectl` process
  info for the peer's parent, so cdhash pinning is tested against the real file.

**Real caller chains (`bridge/conformancehost`, `make integration-run`)**

`nazar-testd` scripts the socket peer, so the chain check 0 and check 1 judge is never the
kernel's there. On the Mac the daemon also runs inside `NazarConformanceHost` on the Swift
platform's process seams through the real C ABI, as for `nazar run` (Milestone 10): the CLI's audit
token, its parent, their paths, command lines and running-code identities come from the kernel
and Security.framework, the genuine-CLI check pins the `nazartest` build's cdhash, and the stdout
check is `core/platform/pipes`. Keys, gates, the vault and the block warning are the fake's, so
nothing is shown and no keychain is used. The real `kubectl` on the PATH (skipped if none),
`nazar trust`ed in the test's home, runs the `nazartest` CLI from a temp kubeconfig against the
fake API server; the CLI reaches the test daemon only through `NAZAR_TEST_CONTROL_SOCKET`, set
in kubectl's environment and in the exec entry. kubectl gets its certificate (one dialog, one
signature, the server sees the identity); a copy of kubectl at another path, a trusted copy
replaced by one with another signature, `python3` running the CLI, and a CLI whose parent exited
(launchd's child, the chain the CLI alone) are refused by check 1 with the block warning; an
exec-hop `tee` relay with kubectl still the parent is refused by the stdout check and its file
gets nothing; another build of the CLI is refused by check 0; the pinned build at another path
gets its certificate. No refusal shows a dialog, signs, or lets the server see a certificate.

**Manual script** (dialogs cannot be automated): k9s in an approved tab prompts once and then
runs for an hour silently; closing the tab and reopening k9s prompts again; Claude Code
running `kubectl delete pod` in its tab gets the `dialog` gate with the full command line;
`nazar revoke --all` makes a running k9s prompt again within `ttl`; `KUBECONFIG` pointed at a
copy whose server is `https://127.0.0.1:16443` gets the fake-server block warning.

---

## 12. Code layout

```
core/k8s/
  module.go        Module: wires checks → broker → provider; ServeCredential(req) for the control socket
  exec.go          KUBERNETES_EXEC_INFO parsing, ExecCredential encoding (v1 only)
  cluster.go       ClusterInfo, URL normalisation, canonical CA hash, Match()
  checks.go        the three checks (client, cluster, rules) as pure functions over a Chain
  expiry.go        expirationTimestamp policy
  provider.go      Provider, IssueInput, Credential, Deps; registry
  stored/          the stored provider: import, rotate, issue, metadata sidecar
  kubeconfig/      multi-file loading, lookup, node-level rewrite, redacted diff, atomic write
  k8stest/         fake API server (TLS, mTLS, bearer, knobs), kubeconfig corpus
core/config/      K8sContext type, parsing and the validation table of section 3
core/configstage/ k8s-aware loosen/tighten rules (section 3)
core/control/     k8s.credential, k8s.import, k8s.rotate, k8s.list, k8s.forget requests; kinds of section 7; RequireBundledCLI
cmd/nazar/k8s*.go the CLI commands; `credential` is a thin stdout/stderr/exit-code shim that ignores NAZAR_* and HOME (1.1)
cmd/nazar/k8scred_testsock.go  nazartest build only: NAZAR_TEST_CONTROL_SOCKET for integration tests (1.1)
```

No new module dependencies in the core. `k8s.io/client-go` appears only under a test build tag
to cross-check the ExecCredential encoding; `yaml.v3` (already a dependency) does the kubeconfig
work.

### 12.1 Core changes Phase 3 needs

**As built in Milestone 12** (supersedes the table below where they differ):

| Package | Change |
|---|---|
| `core/config` | `Config.K8s map[string]*K8sContext` (`k8s.go`); `k8s` leaves `Unimplemented`; rules parsed by the shared `entry`/`rule` code with a third entry kind |
| `core/k8s/cluster` | the exec cluster info, server normalisation, the canonical CA hash and `Match` (pure, no nazar imports but nothing); used by config, policy and the module |
| `core/policy` | `EvaluateK8s(name, chain, got)`: check 1 (the client, `chain[1]`), check 2 (`got` against the context's `cluster`), check 3 (rules on `chain[2:]` through the shared `first`); `Receiver` always the client's identity; `LiveRuleIDs` covers `k8s:<name>` |
| `core/match` | `Client(ms, p)`: a `path:` or `signed:` matcher on one process (the existing `process` check) |
| `core/broker` | `Request.K8s` and `Request.Cluster`: target `k8s:<name>`, noun "Kubernetes credential", op `k8s:<name>` set by the broker, receiver chain `chain[1:]`, block warnings drafted on `chain[2:]` |
| `core/configstage` | `classifyK8s` (section 3, as built); pins cover k8s rules |
| `core/k8s` | exec info parsing and the ExecCredential encoding, the CA store (`k8s-ca/<name>`), `Issue`; since the AWS work, these wrap `core/certs` |
| `core/certs` | the certificate engine (aws design 2): CA records, the platform signer, leaf issuance and its check, for any kind of CA |
| `core/k8s/kubeconfig` | loading the set, lookup, node-level rewrite, redacted diff, atomic write, backup |
| `core/control` | `k8s.credential` (a value command), `k8s.ca.create`, `k8s.ca.show`, `k8s.import`, `k8s.list`, `k8s.forget`; the kinds of section 7 |
| `core/daemon` | the handlers; `refuseNotCLI` covers `k8s.credential` |
| `cmd/nazar` | `nazar k8s …`; `credential` resolves the socket from the passwd home and ignores `HOME`, `NAZAR_*`; `k8scred_testsock.go` (`nazartest`) |

No `RequireBundledCLI`, no `Chain.From`, no `Request.Evaluate` and no `Refuse` change: Milestone 8's
value-command guard is check 0, `Chain.Parent` (Milestone 8) twice is the caller view, and checks 1
and 2 refuse through the policy's block path, which audits and shows the block warning.

The original table:

The main spec 7.3 says "none of the modules need changes to the core". For `k8s` that is not
true of the code on `main` today; these are the changes, each small, each with its own tests:

| Package | Today | Change |
|---|---|---|
| `core/control` | `PeerVerifier` is UID-only (`SameUserVerifier`); the server's peer check is `unixsock.RequireSameUser` | M3's signature verifier in the CLI; a per-request `RequireBundledCLI` on the server (check 0) backed by `platform.CodeIdentity(auditToken)` |
| `core/policy` | `EvaluateSSH(key, chain)`; `Target` hard-wired to `ssh:`; `Outcome.Receiver` set only for rules with `to:`; `LiveRuleIDs` walks `SSHAgent.Keys` only | `EvaluateK8s(ctx *config.K8sContext, view *caller.Chain, receiver string)` sharing the rule loop with `EvaluateSSH` through an internal `evaluate(target, rules, fallback, view)`; `Receiver` always set from the argument; `LiveRuleIDs` adds `k8s:<ctx>|<rule>` for every context so `RetainRules` on a config reload keeps k8s approvals instead of dropping them all |
| `core/caller` | One `Chain` per peer | `Chain.From(i int) *Chain`: the caller view that starts at `chain[i]` and keeps `Session`, `App`, `Unknown`, `Truncated` |
| `core/match` | `Apps` matches `app:` against the chain's app; `Receiver` requires `App.Ref == peer` | `Client(ms []config.Matcher, p *caller.Process) (identity string, ok bool)`: path/cdhash, non-Apple signature, or signed helper inside the bundle (2.1) |
| `core/broker` | `Request.Key` is an SSH key name; `Handle` calls `EvaluateSSH`; `Refuse` hard-codes `"ssh:" + Key` | `Request{Target string; Evaluate func() policy.Outcome; Display ...}` (SSH wraps its key); `Refuse(req, reason)` takes the target from the request and **shows the block warning** for check 0/1/2 refusals (today `Refuse` only audits) |
| `core/approval` | `Flight` dedups by key | unchanged; `OneShot` bypasses it as today (2.4) |
| `core/configstage` | `k8s` in `Unimplemented`, always loosening | the k8s-aware rules of section 3; `Unimplemented` keeps only `k8s` (secrets are built since Phase 2, Milestone 8) until this module lands |
| `core/secrets` | **does not exist on `main`** | Phase 2's `Store` with name-bound `info`/`aad` (5.1) is a prerequisite |
| `core/daemon` | `RetainRules(policy.LiveRuleIDs(c), …)` | unchanged once `LiveRuleIDs` covers k8s; registers `k8s.Module` and its control handlers |

---

## 13. Open questions

| # | Question | Default if unanswered |
|---|---|---|
| **S10** (main spec 11) | Does `provideClusterInfo` deliver `spec.cluster` reliably from kubectl, k9s and helm, including `tls-server-name` and `proxy-url`? Do all three re-run the plugin when `expirationTimestamp` passes, and how many parallel runs does k9s start, and how far apart do they land? Does `interactiveMode: Never` behave while the dialog blocks for up to `defaults.timeout` (60 s)? | Keep `ttl` at 5 m; if a tool caches longer, document it in section 9; keep the 15 s `credential-rejected` burst window unless k9s's start runs spread over more than 5 s, then use three times the spread (1.4); if any tool misbehaves under a 60 s block, add `k8s.timeout` with a shorter default for the plugin only |
| S13 | Can the Phase 2 secrets store (HPKE to a Secure Enclave key-agreement key) decrypt a `k8s/<context>` entry fast enough that a k9s start with several parallel plugin runs is not noticeable? | Decrypt once per approval and keep the plaintext in Nazar.app memory for `ttl`, zeroised afterwards |
| S14 | Does yaml.v3 node-level rewriting keep real-world kubeconfigs (written by `kubectl`, `microk8s config`, `aws eks update-kubeconfig`, `gcloud`) readable by all of those tools afterwards? | Fall back to a full re-encode of the parsed file (loses comments), clearly stated in the diff |
| Q1 | Wrap *other* exec plugins (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`): nazar would run the inner plugin after its own checks and relay its ExecCredential. It gates *who* may obtain a cloud-issued token without storing anything. Is that worth a fourth provider kind, `exec`? | Not in Phase 3; `import` refuses exec users with a clear message |
| Q2 | Should check 2 also pin the API server's *serving* certificate chain, learned at import by connecting once? It would catch a CA that signs for a second host. | No: `ca_sha256` + `server` + TLS verification by the client already bind the host; a probe at import adds a network dependency to a local operation |
| Q3 | Should `ttl` be allowed above 1 h for `stored` contexts behind `gate: none` read-only users? | No; 1 h is the ceiling for everyone, since revocation latency is the whole reason for `ttl` |
| Q4 | For `ca-cert`, should nazar issue through the Kubernetes CSR API (`certificates.k8s.io`) instead of its own CA, so the cluster CA signs and no client-CA change is needed? | No: the CSR API needs an existing credential with approve rights, which reintroduces a stored credential; keep the nazar CA |
| Q5 | Host the `jwt` JWKS from nazar itself (a tiny HTTPS endpoint on the Mac behind a tunnel)? | No: the API server must reach it at any time, including when the Mac is asleep; static hosting is the answer |
| Q6 | Should a context be able to ask for its own Secure Enclave key-agreement key with a user-presence ACL (`presence: required`), so that a compromised Nazar.app cannot decrypt `k8s/<context>` without the Secure Enclave's own prompt (section 10)? One key per context costs one enclave key and one prompt per `ttl` under S13 | Not in Phase 3; the single Phase 2 key is used and section 10 makes no user-presence claim |


### 13.1 Ideas kept for later brainstorming

- **Cloud credentials module.** Guard the logins that managed clusters' plugins mint from.
  AWS: `credential_process` in `~/.aws/config` pointing at nazar (a secret with rules, gate and
  Touch ID), possibly returning STS session credentials instead of the long-lived keys. gcloud
  and the Azure CLI keep their own token caches, and how nazar could front them is open.
- **`jwt` on EKS.** An EKS OIDC identity provider association would accept nazar-signed tokens
  (6.2). It replaces IAM login for that cluster and needs hosted JWKS documents. Revisit only if
  a managed cluster can't be served by its own plugin plus the cloud credentials module.
- **A local TLS proxy holding an enclave client key.** kubectl talks to nazar on localhost,
  and nazar makes the real mTLS connection with a Secure Enclave P-256 client certificate
  issued by the cluster's CSR API. It is truly "sign per connection", and it can enforce
  per-verb rules (for example: Claude Code may only `get`/`list`). It is much bigger: TLS
  termination, its own serving certificate, streaming (`exec`, `logs`, `port-forward`) and the
  cluster's acceptance of ECDSA P-256 client certificates.
