# nazar 🧿 — `aws` module design: IAM Roles Anywhere on a shared certificate engine

**Status:** design. Builds on [`k8s-design.md`](k8s-design.md) (the `ca-cert` provider as built in
Milestones 12 and 13) and the main spec, [`nazar-design.md`](nazar-design.md). Where this document
is silent, the k8s design applies with `k8s` read as `aws` and "context" read as "entry"; where it
is silent too, the main spec applies (caller chains 4.1, config 4.2, approval cache 4.3, dialog
4.4, audit 4.6, config staging 4.8, CLI model 6, threat model 8).

**One sentence:** an AWS `credential_process` that hands short-lived AWS session credentials to the
program that ran it only when the person or tool behind that program passed the entry's rules,
minted through IAM Roles Anywhere with a certificate that a Secure Enclave CA issued for that one
request.

> **Decision (2026-11-05, the owner's): `path:` again, without a pin** (spec 4.2), as for k8s
> (k8s design, its block of that date): a `path:` to a file called aws is the `rule N names aws`
> error again, and a program launchd started that runs `credential_process` itself is judged as
> its own caller. It replaces the "no `path:` matcher" decision of 2026-11-01.
>
> **Decision (2026-10-31, the owner's): no client list,** as for k8s (k8s design, the "no client
> list" block at the top).
> - **What it means.** An entry names no program that may receive its credential: there is no
>   `clients:` key, no pinned `aws`, no `apps.aws` written by `ca create` and no `nazar trust`.
>   Whatever runs `nazar aws credential` (`chain[1]`: the AWS CLI v2, Homebrew's `awscli` or boto3
>   under any Python, an SDK program such as terraform, a shell's `$(…)`) receives the session when
>   the chain above it (`chain[2:]`) passes the entry's rules. Check 1 is only "is `chain[1]`
>   identified" (`identified` in `core/policy/k8s.go`, shared with k8s), refused otherwise with
>   `the program that ran nazar can't be identified`; that identity (`match.Identity`) stays the
>   receiver of every approval, so an approval for `aws` in a tab never covers terraform there. The
>   rule ids carry no client fingerprint.
> - **Why.** The caller chain is the boundary, as for SSH keys and k8s. A program inside an allowed
>   chain can already run `aws` (and `aws configure export-credentials`, 9.1), so a list only
>   narrowed what it could take away, at the price of a concept, a config key, a re-trust after
>   every upgrade, and Homebrew's `awscli` refused outright.
> - **The residual risk, accepted.** Any program in an allowed chain can hold a session itself, for
>   up to `duration` (1h by default, 15m at the least), and use it or send it elsewhere. It could
>   drive `aws` for that long anyway. A shorter `duration` narrows it.
> - **Kept:** check 0 (the genuine CLI), the stdout check (3.4) before any prompt and again at mint
>   time, the entry compared again at mint time, gates, scopes, the approval key, staging of
>   loosening edits and the audit line. A rule naming `aws` is refused, as one naming `kubectl` is
>   for k8s: it would never match aws asking, and would pass every program aws runs (the
>   `credential_process` of any profile, which any process can write).
> - **No migration.** No released nazar had an `aws` section, so a `clients:` line under
>   `aws.<name>` is an error (`aws entries have no clients: list; …: remove the line`), not k8s's
>   "context off" warning.

**Two parts.**

1. **A shared certificate engine.** The Kubernetes CA is already "a CA in the Secure Enclave that
   issues short-lived client certificates" (`core/k8s/ca.go`, `issue.go`). Its creation and leaf
   issuance move to a new package, `core/certs`, with no change to anything a user, a script or
   a record can see.
2. **The AWS adapter.** A second user of the engine, with AWS Roles Anywhere as the relying party.
   Its surface is the k8s one with `k8s` replaced by `aws`.

Sources are linked where they are used; the AWS ones are collected in section 12.

---

## 1. Summary of decisions

- **No long-lived AWS credential exists anywhere.** Not in `~/.aws`, not in nazar, not in the
  Keychain. Each `credential_process` run mints a leaf certificate for a fresh software P-256 key,
  signs one `CreateSession` request with it, and drops the key.
- **nazar-agent makes the HTTPS call.** The leaf key and the signed request never leave the agent;
  the CLI receives only the session credentials, which are what its parent needs anyway (3.3).
  This is the agent's first outbound connection (9.4).
- **The CA key signs only certificates nazar built.** The engine exposes "issue a client
  certificate with this subject and lifetime", never "sign these bytes" (2.3).
- **One CA per entry, never shared with k8s.** Vault item `aws-ca/<name>`, its own enclave key,
  its own trust anchor. A cluster that trusts a k8s CA can't accept an AWS leaf, and the reverse.
- **The surface is k8s's:** `aws ca create | show`, `aws list`, `aws rule add|set|remove`,
  `aws forget`, `aws credential`. No new flags beyond `--only-when-unlocked`, which `ca create`
  takes as `k8s ca create` does. Policy target `aws:<name>`.
- **nazar never edits `~/.aws`** and never calls AWS for setup. `ca create` prints the AWS-side
  steps and the `credential_process` line; the user runs them.
- **Identity:** `CN=<macOS short user name>-nazar`, issuer `CN=nazar aws CA <name>`, as for k8s.
  AWS makes the CN the session's source identity and both CNs principal tags (4.2).
- **Leaf lifetime 10 minutes** (`now-5m` to `now+5m`), independent of the session; **session
  `duration` 1h by default, 15m to 1h** (5.2).
- **No cache in nazar.** One run, one leaf, one `CreateSession`, one audit line (5.3).
- **Exit 3 means nazar refused.** An AWS refusal, a network failure or a bad reply is exit 1 with
  AWS's error code in the message (6.3).

---

## 2. Part 1: the shared certificate engine (`core/certs`)

### 2.1 What moves

From `core/k8s/ca.go` and `issue.go`, everything that does not know about Kubernetes:

| Moves to `core/certs` | Stays in `core/k8s` |
|---|---|
| the Vault record (`caRecord`, version 1, its JSON field names), `decode` | `VaultPrefix = "k8s-ca/"`, the k8s `Kind` |
| `Store`: `Create`, `Get`, `List`, `Delete`, `handleShared`, its mutex | `CAStore`, `NewCAStore`, `CA`, `CAInfo` as thin wrappers with their exact signatures |
| the CA template (10 years, `MaxPathLenZero`, `KeyUsageCertSign`, SKI = SHA-256(public key)[:20]) | the CA subject words: `nazar k8s CA <name>` |
| leaf issuance: key generation, template, `x509.CreateCertificate` through the signer, `check` | `(*CA).Issue(p, id, ttl, now, ref)`: the `ttl_cert` range, the identity checks, PEM encoding, `Credential` |
| `signer` (unexported), `errDigest`, `platformError`, `randomSerial` | `Provider`, `CACertProvider`, `exec.go`, `cluster/`, `kubeconfig/`, `k8stest/` |

The engine has no notion of a context, a cluster or a kubeconfig, and imports only `platform`.

### 2.2 The API

```go
package certs

// Kind is one adapter's CA records: the Vault prefix, the words its
// messages use, and which names it accepts.
type Kind struct { /* unexported: tag "k8s", prefix "k8s-ca/", noun "context", valid func(string) bool */ }

// NewKind makes a kind and its errors. tag starts every message ("k8s: …"),
// noun names an entry ("names another context", "invalid context name"),
// subject is the CA's CN before the name ("nazar k8s CA ").
func NewKind(tag, prefix, noun, subject string, valid func(string) bool) *Kind

// The kind's errors, with the texts core/k8s has today for k8s.
func (k *Kind) ErrExists() error      // "<tag>: a CA of that name exists"
func (k *Kind) ErrNotFound() error    // "<tag>: no CA of that name"
func (k *Kind) ErrInvalidName() error // "<tag>: invalid <noun> name"
func (k *Kind) ErrUnreadable() error  // "<tag>: the vault refused to return the CA record"
func (k *Kind) ErrBroken() error      // "<tag>: the CA record is unusable"

func NewStore(k *Kind, p platform.Platform, v platform.Vault, now func() time.Time) *Store
func (s *Store) Create(name string, access platform.Access) (*CA, error)
func (s *Store) Get(name string) (*CA, error)
func (s *Store) List() ([]CAInfo, error)
func (s *Store) Delete(name string) error

type CA struct { Name string; Handle, PublicKey []byte; Created time.Time; Cert *x509.Certificate; Access platform.Access /* kind, pub unexported */ }
func (ca *CA) CertPEM() []byte
func (ca *CA) Info() CAInfo

// LeafSpec is everything a caller chooses about a leaf. Its profile is
// fixed: digital signature, client auth, not a CA, no names but the subject.
type LeafSpec struct {
	CN        string
	O         []string  // one O= each; empty for AWS
	NotBefore time.Time // the caller's; whole seconds
	NotAfter  time.Time // the caller's; cut to the CA's end
	Serial    Serial    // zero: a new random one
}

// Serial is a positive 127-bit serial; only NewSerial makes one.
type Serial struct{ /* unexported *big.Int */ }
func NewSerial() (Serial, error)
func (s Serial) Hex() string     // 32 hex digits: the AWS role session name
func (s Serial) Decimal() string // the Credential= of an X509 SigV4 header

// Leaf is a minted certificate and its key. The key never leaves the
// process; the caller drops it once used.
type Leaf struct { Cert *x509.Certificate; Key *ecdsa.PrivateKey }

// Issue mints a leaf for spec: a fresh P-256 key made here, signed by the
// CA key through Platform.Sign with ref, read back and checked (check)
// before it is returned. The CA must be valid at now.
func (ca *CA) Issue(p platform.Platform, spec LeafSpec, now time.Time, ref platform.ApprovalRef) (Leaf, error)
```

Errors are values of the kind, so `errors.Is(err, k8s.ErrNotFound)` keeps working: core/k8s sets
`var ErrNotFound = kind.ErrNotFound()` and so on, and the text of every error is what it is
today. The two locked-Mac messages (`<tag>: the Mac is locked; …`) and the CA validity message
(`<tag>: the CA of <name> is not valid now …`) take the tag the same way.

### 2.3 Never a raw signing entry point

- The CA key is reached only through the unexported `signer`, whose `SignMessage` is handed bytes
  only by `x509.CreateCertificate` inside `Create` (the CA's own certificate) and `Issue` (a leaf
  built from a `LeafSpec`). `Sign(digest)` stays refused (`errDigest`): the enclave hashes what it
  signs, and a digest could be of anything.
- `LeafSpec` can't express a CA, a server certificate, a SAN, another key usage or an extension:
  the profile is fixed in the engine and `check` refuses any minted certificate that differs.
- Nothing exported returns the signer or a `crypto.Signer` over the CA key. `CA.Handle` stays
  exported for the record and listings, as today, and the daemon holds the platform, so a test
  asserts that no package but `core/certs` hands a CA's handle to `Platform.Sign`.
- A test pins the package's exported API (section 11.1), so adding an entry point is a reviewed
  diff, not an accident.

The point is the prompt: each adapter keeps nazar knowing what it is issuing, so "iTerm2 wants
to use AWS credential dev" means exactly one certificate for one session of one role.

### 2.4 What must not change

Part 1 is a refactor. Every one of these is identical before and after, and is pinned by a test
that exists (or is added first, on the old code) before anything moves:

- `nazar k8s …`: commands, flags, help, stdout, stderr, exit codes, `--json` objects
  (`cmd/nazar/testdata/cli-contract.golden` byte for byte).
- The `k8s:` section of `config.yaml`: parsing, validation messages, staging classification.
- `k8s-ca/<context>` Vault records: field names, order, version 1, how old records decode, which
  are broken or unreadable and why.
- The CA certificate (subject, validity, constraints, key usage, SKI) and the leaf profile.
- Audit lines of every k8s operation, prompts and their lines, the kubeconfig text written and
  removed, the `.crt` files.

---

## 3. Part 2: how the AWS credential is reached

### 3.1 The AWS config entry (the user's)

```ini
[profile dev]
credential_process = /Users/you/.local/bin/nazar aws credential dev
```

- The path is the absolute path the running CLI was started by, links not resolved, exactly as
  `k8s ca create` writes kubeconfig's `command` (k8s 1.5): an upgrade keeps it working, and the
  path is not the boundary (check 0 is). AWS wants a full path without `~` or variables and
  allows letters, digits, `- _ . /` and spaces in it
  ([SDK guide](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html)).
- nazar never writes `~/.aws/config`. `ca create` prints these lines; the user adds them.
- `region` in the profile is the region the client calls, unrelated to the Roles Anywhere region.

### 3.2 How clients run it

| Client | How it runs the command | What nazar sees |
|---|---|---|
| AWS CLI v2, boto3 (botocore) | `subprocess.Popen(shlex-split argv, stdout=PIPE)`, no shell | `chain[1]` = the Python process; stdout a close-on-exec pipe it holds |
| SDK for Go v2 (Terraform and other Go tools) | `sh -c "<command>"`, stdout a pipe; 1-minute timeout | `/bin/sh` is bash, which execs a lone command, so `chain[1]` = the Go program |
| SDK for JavaScript v3 | `child_process.exec` (libuv: stdout is a socketpair) | refused by the stdout check (3.4), as for k8s programs that do this |
| SDK for Java | `ProcessBuilder` | pipes without close-on-exec on some JVMs: refused, fail-closed |

Sources: botocore `ProcessProvider` and the Go SDK's `processcreds.DefaultNewCommandBuilder`
(section 12). The SDKs and the CLI do not cache `credential_process` results the way they cache
assume-role results; they re-run the command before `Expiration`
([CLI guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)).
botocore refreshes at 15 minutes before expiry and must refresh at 10.

### 3.3 The flow

```
aws s3 ls (or terraform …)          nazar CLI                    nazar-agent
──────────────────────────          ─────────                    ───────────
credential_process:
  nazar aws credential dev ───▶ 1. connect ~/.nazar/control.sock
                                2. aws.credential {name} ─────▶ 3. check 0: peer is the genuine CLI
                                                                4. entry aws.dev exists and is connected
                                                                5. stdout check (3.4)
                                                                6. check 1: chain[1] (aws, python, terraform …) identified
                                                                7. check 3: rules on chain[2:]
                                                                8. gate (login | dialog), approval cache
                                                                9. Do: config re-read and compared;
                                                                   leaf issued by the SE CA (one sign);
                                                                   CreateSession signed with the leaf key;
                                                                   POST https://rolesanywhere.<region>.amazonaws.com/sessions;
                                                                   reply checked; leaf key dropped
                                                               10. one audit line
                               11. ◀── {accessKeyId, secretAccessKey, sessionToken, expiration, accountId}
◀── stdout: credential_process JSON, one write; exit 0
```

- **Why the agent calls AWS, not the CLI.** With the CLI calling, either the leaf key or a signed
  request (replayable for minutes) would cross the socket and live in a process whose
  environment the caller wrote. With the agent calling, the only secret that leaves it is the
  session credential the program that ran nazar receives anyway, and the agent can check AWS's
  reply and audit the outcome on one line.
- **No check 2.** k8s check 2 exists because the cluster comes from the request
  (`KUBERNETES_EXEC_INFO`). Here nothing caller-supplied addresses the request: the host, the
  ARNs and the duration come from the config in force. The request carries only the name.
- **The CLI is a pipe, as `k8s credential` is** (k8s 1.1): no `--json`, no config file, no
  environment variable read at all, the socket from the user database's home, the agent checked
  by its signature, the `nazartest` build's test socket only. One write to stdout, or one line
  to stderr and the exit code.
- **The config in force is compared at mint time** (as `k8sCredential`'s `Do`): the entry, its
  rules and fallback must equal what the request was checked and shown against, or nothing is
  minted.

### 3.4 The reply goes straight to the program that ran nazar

The stdout check of k8s 2.1 applies unchanged (`platform.Pipes`, before the broker and again in
`Do`): fd 1 of the CLI is a pipe whose read end `chain[1]` alone holds, close-on-exec, with no
co-writer. A wrapper that copies the output (`tee`), a file, a terminal or a socket is refused,
audit `reason="the credential's output does not go straight to the program that ran it"`.

No document marker is needed, unlike k8s 1.3. The reply is one JSON object and the SDKs parse
stdout as one JSON text (`json.loads`, `json.Unmarshal`). A prefix written before the CLI runs
(the only bytes another writer can add) either is whitespace or makes the whole text invalid:
nazar's object is complete, so a prefix that opens a value can't be closed after it, and a
complete prefix value is followed by extra data. A fuzz test holds this (11.3).

### 3.5 The credential_process reply

```json
{"Version":1,"AccessKeyId":"ASIA…","SecretAccessKey":"…","SessionToken":"…","Expiration":"<RFC 3339, UTC>","AccountId":"123456789012"}
```

- `Version` 1 and the four credential fields as the CLI and SDK guides give them; `Expiration`
  is AWS's own, re-rendered as RFC 3339 UTC; `AccountId` is the role ARN's account, which the
  SDK guide documents as optional and used for account-scoped endpoints.
- Nothing is written to stderr on success. The guides warn that SDKs may log stderr; nazar's
  failure line never contains a credential, a certificate or a signature.

---

## 4. Roles Anywhere: what nazar sends and what AWS checks

### 4.1 CreateSession

`POST https://rolesanywhere.<region>.amazonaws.com/sessions`, body JSON
([API](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html)):

```json
{"durationSeconds":3600,"profileArn":"arn:aws:rolesanywhere:us-east-1:123456789012:profile/…","roleArn":"arn:aws:iam::123456789012:role/dev","trustAnchorArn":"arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/…"}
```

- All parameters in the body, none in the query. AWS accepts either; the official helper sends
  the ARNs in the query (`aws_signing_helper`, `rolesanywhere/serializers.go`), but CloudTrail
  flags "POST, query string, empty body" as non-conforming (`postEmptyBody`,
  [CloudTrail](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/logging-using-cloudtrail.html)),
  and one place for parameters is one thing to canonicalise.
- No `roleSessionName`: it needs `acceptRoleSessionName` on the profile, and the default session
  name, the certificate's hex serial, is unique per credential and joins CloudTrail to nazar's
  audit line (6.2).
- Reply 201 with `credentialSet[0].credentials{accessKeyId, secretAccessKey, sessionToken,
  expiration}`, `assumedRoleUser`, `roleArn`, `sourceIdentity`, and `subjectArn`.
- `Expiration = now + min(profile durationSeconds, request durationSeconds)`; a value above the
  role's `MaxSessionDuration` is an error from AWS, not a shorter session.
- Endpoints: `rolesanywhere.<region>.amazonaws.com` for the `aws` partition
  ([endpoints](https://docs.aws.amazon.com/general/latest/gr/rolesanywhere.html)).
  `CreateSession` is limited to 10 per second per account by default, far above one person's use.

### 4.2 Signing (AWS4-X509-ECDSA-SHA256)

SigV4 with the certificate's key in place of the HMAC
([signing process](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html)):

1. Headers set and signed: `content-type: application/json`, `host`,
   `x-amz-date: YYYYMMDDTHHMMSSZ` (UTC), `x-amz-x509: <base64 DER of the leaf>`. No
   `x-amz-x509-chain`: the leaf is issued by the trust anchor's own certificate. These are the
   headers CloudTrail's `missingSignedHeaders` checks; nazar signs every one it sends. A
   `user-agent` is sent unsigned, as AWS's helper does.
2. Canonical request: `POST\n/sessions\n\n` + the sorted `name:value\n` lines + `\n` +
   `content-type;host;x-amz-date;x-amz-x509\n` + hex SHA-256 of the body.
3. String to sign: `AWS4-X509-ECDSA-SHA256\n<x-amz-date>\n<YYYYMMDD>/<region>/rolesanywhere/aws4_request\n<hex SHA-256 of the canonical request>`.
4. Signature: ECDSA P-256 over SHA-256 of the string to sign, ASN.1 DER, hex
   (`ecdsa.SignASN1`; the helper DER-encodes too).
5. `Authorization: AWS4-X509-ECDSA-SHA256 Credential=<serial, decimal>/<scope>, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, Signature=<hex>`.

The leaf key is a software key, so step 4 needs no enclave and no approval: the one enclave
signature per run is the leaf's.

### 4.3 What AWS requires of the certificates

From the [trust model](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html):

| Requirement | nazar's leaf | nazar's CA |
|---|---|---|
| X.509 v3, SHA-256 or stronger | ecdsa-with-SHA256 | ecdsa-with-SHA256 |
| end entity: CA false if present, key usage includes digital signature | `CA:false`, digital signature, client auth | |
| trust anchor: `CA:true`, key usage includes certificate sign | | `CA:true`, pathlen 0, certificate sign |
| subject not empty (Subject resources are keyed by it) | `CN=you-nazar` | `CN=nazar aws CA dev` |
| subject CN at most 256 characters | at most 61 (below) | |

- **Source identity** is `CN=<cn>` when the CN has at most 61 characters (longer CNs drop the
  prefix), so `identity.user` is limited to 61 bytes and the source identity is always
  `CN=you-nazar`.
- **Principal tags:** `x509Subject/CN = you-nazar` and `x509Issuer/CN = nazar aws CA dev`. The role
  trust policy should require both and `aws:SourceArn` = the trust anchor (section 10). The tag
  pattern allows the space in the issuer CN.
- **Serial**: a positive 127-bit random number (the engine's), decimal in the `Credential`, hex
  as the role session name. Each run gets a new one.
- **Revocation** is by imported CRL only; nazar publishes none. A leaf lives 10 minutes and its
  key never exists outside one request, so there is nothing to revoke; the CA is withdrawn by
  disabling or deleting the trust anchor.
- A trust anchor holds at most 2 certificates; nazar's bundle is one.

---

## 5. Lifetimes and caching

### 5.1 The leaf: 10 minutes, `now-5m` to `now+5m`

The leaf is used once, within a second of being made, by the agent alone. Its lifetime only has
to survive clock skew between the Mac and AWS. SigV4 already ties a request to its
`x-amz-date` (AWS refuses requests whose time is too far from its own; the usual SigV4 window is
5 minutes, not restated in the Roles Anywhere guide, see 13), so a leaf valid 5 minutes either
side of the Mac's clock is never the reason a request fails while its date is still accepted.
k8s backdates by 1 minute because kubectl uses its certificate for 15 minutes after the clock it
was minted on; the engine takes both bounds from the caller, so k8s keeps its 1 minute.

The session does not depend on the leaf's end: AWS documents the session's `Expiration` as
`CurrentTime + finalDurationSeconds`, with no mention of the certificate. nazar passes on the
`Expiration` AWS returns, whatever it is, so the design holds either way (13, A1).

### 5.2 The session: `duration`, default 1h, 15m to 1h

- 15 minutes is AWS's minimum (`durationSeconds` 900).
- 1 hour is the ceiling, as `ttl_cert` is for k8s (k8s 1.4, Q3): revoking an approval stops new
  credentials at once, and the last one handed out lives at most `duration` longer, usable from
  anywhere. 1 hour is also the role's default `MaxSessionDuration`, so the default needs no role
  change, and the profile's default `durationSeconds`.
- With botocore's refresh windows a 15-minute session is re-fetched about 5 minutes after it
  starts; the default 1h is re-fetched after about 45 minutes.

### 5.3 No cache in nazar

Each run mints and returns a new session. The SDKs keep the credential in memory until shortly
before `Expiration`; the AWS CLI, run once per command, runs the process every time, which costs
one enclave signature and one HTTPS round trip (a few hundred milliseconds) and, under a
remembered approval, no prompt.

A cache in nazar would hand one bearer credential to several callers, so an approval for one
caller would deliver a credential another caller was given; it would keep secrets in the agent's
memory for an hour; and it would break "one audit line, one AWS session". If latency turns out to
matter, the place to fix it is a per-(entry, receiver, approval) cache with its own design (13, Q2).

---

## 6. Checks, policy and audit

### 6.1 The checks, in order

As k8s 2, minus check 2:

- **Check 0:** `aws.credential` is a `control.ValueCommand`; the control server verifies the peer
  is the genuine CLI (k8s 2.0), fail-closed, one blocked audit line, no prompt.
- **The entry:** an unknown name is usage (exit 2); an entry without its three ARNs is "not
  connected" (exit 1, with the fix: section 10, step 4); a missing or unusable CA is as for k8s
  (refused with the fix, or the spec 9 remedy for an unreadable item).
- **Check 1:** `chain[1]`, whatever program it is, is identified: a live, full record (not
  PID-only, not exited) whose code signature verified and gives it an identity (a team, or a
  cdhash for ad-hoc code such as Homebrew's), else `reason="the program that ran nazar can't be
  identified"` with the block warning. There is no client list (the decision at the top).
- **The stdout check** (3.4).
- **Check 3:** the entry's rules on `chain[2:]`, `Receiver` = the identity of `chain[1]`, scope on
  the full chain, rule ids fingerprinted with the entry's ARNs, identity and duration (as
  `k8sRuleID`), so an approved change of any of them ends the approvals given for the old ones.
- **Approval** keyed `(target aws:<name>, rule, scope, receiver, op aws:<name>)`. Prompt:

```
Title:  iTerm2 wants to use AWS credential "dev"
Lines:  aws s3 ls s3://bucket                 ← the command line of the program that ran nazar, redacted (4.6)
        for arn:aws:iam::123456789012:role/dev, 1h
        iTerm2 ▸ zsh ▸ claude(Q6L2SF6YDW) ▸ aws
        remembered for this tab until <time>
```

### 6.2 Audit

One line per request, from the broker, as for k8s:

| Field | Value |
|---|---|
| `target` | `aws:<name>` |
| `operation` | `aws credential session <32 hex digits>`: the leaf serial, drawn before the broker (`certs.NewSerial`) |
| `destination` | the role ARN |
| `decision`, `reason`, `rule`, `scope`, `gate`, chain, receiver | as for every request |

The serial is the role session name AWS gives the session, so CloudTrail's
`assumed-role/dev/<serial>` names the nazar line that produced it, and back. A request refused
before the serial is drawn (check 0, an unknown or unconnected entry, a missing or unusable CA)
has `operation` `aws credential` or none, and no serial; a later refusal or failure (the stdout
check, check 1, the rules, the gate, AWS's error) shows a serial that was never issued. No access key ID, secret, token, certificate or
signature is ever logged. AWS's error code and message are the reason of an `error` line, quoted
and cut as `cluster.Display` does.

### 6.3 Errors and exit codes of `aws credential`

| Exit | When |
|---|---|
| 0 | credentials on stdout |
| 2 | usage: an argument count or name nazar can't accept, `--json`, an unknown entry |
| 3 | refused by nazar: check 0, check 1, the stdout check, rules, the gate (denied, timed out) |
| 5 | nazar-agent not running |
| 1 | anything else: entry not connected; a CA this agent can't use (with its fix); the Mac is locked and the CA signs only while it's unlocked; the config changed during the prompt; AWS unreachable, timed out (10 s), throttled, or refusing (`AccessDeniedException: …`, `ValidationException: …`, `ResourceNotFoundException: …`); a reply that fails the checks below |

AWS's refusal is exit 1, not 3, on purpose: exit 3 means "the user decided" (AGENTS.md), and an
agent must not read a broken trust policy as that.

The reply is accepted only when: status 201; at most 64 KiB; one JSON object; `credentialSet`
non-empty; `accessKeyId` 16 to 128 of `[A-Z0-9]`; `secretAccessKey` and `sessionToken` non-empty
printable ASCII, at most 16 KiB each; `expiration` RFC 3339, after now and at most
`now + duration + 5m` (AWS's clock may be ahead of the Mac's by as much as the leaf allows, 5.1); `roleArn`, when present, the configured one. Redirects are refused, there
is one attempt (the client re-runs the process when it needs to), and no proxy is used.

### 6.4 `--only-when-unlocked`

`nazar aws ca create <name> --only-when-unlocked` makes the CA key with the access the k8s flag
gives (`createAccess(AuthNone, true)`): the chip refuses it while the Mac is locked, so nothing is
minted then, whatever the rules say (THREAT-MODEL 5.17). It is fixed for the CA's life; `list`
shows it as `whileLocked`. The failure is `aws: the Mac is locked; the CA of dev signs only while
it's unlocked`, exit 1. Without the flag a scheduled job can get credentials while the Mac is
locked, under a rule that needs no prompt.

---

## 7. Config schema

```yaml
aws:
  dev:                                   # the entry name: aws:dev, aws-ca/dev, aws-ca-dev.crt
    identity: {user: you-nazar}          # CN of every leaf; written by ca create; 1..61 bytes
    trustAnchorArn: arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/<id>
    profileArn: arn:aws:rolesanywhere:us-east-1:123456789012:profile/<id>
    roleArn: arn:aws:iam::123456789012:role/dev
    duration: 1h                         # optional; default 1h, 15m..1h
    gate: block                          # what ca create writes: blocked for everyone…
    rules:                               # …but the terminal it was typed in
      - apps: [iterm]
        scope: session
        gate: login
        expire: 8h
```

- **Keys are AWS's own names** (`trustAnchorArn`, `profileArn`, `roleArn`), so they read as they
  do in the AWS console and CLI output. There is no `region` key: the region is the trust
  anchor ARN's, and a separate key could only disagree with it. The profile ARN's region must
  equal it (as the official helper checks).
- **Validation**, in addition to the k8s table where it applies (name rule, case-folded names,
  `rules[*].to` refused, the entry's own `gate: none`, `any`/`unknown` with `gate: none`):

| Rule | Error or warning |
|---|---|
| `trustAnchorArn` not `arn:aws:rolesanywhere:<region>:<12 digits>:trust-anchor/<id>` | error |
| `profileArn` not `arn:aws:rolesanywhere:<region>:<12 digits>:profile/<id>`, or another region than the trust anchor | error |
| `roleArn` not `arn:aws:iam::<12 digits>:role/<path and name>` | error |
| another partition (`aws-cn`, `aws-us-gov`, …) | error `only the aws partition is in this version` |
| some but not all of the three ARNs | error |
| `duration` outside `15m`..`1h` | error |
| `identity.user` not 1 to 61 bytes of `[A-Za-z0-9._@:+=/-]` | error |
| `identity.groups` | error `the identity.groups: field is not in this version` |
| `<region>` not of the shape `[a-z]{2}-[a-z]+-[0-9]` | error |
| a `clients:` line | error `aws entries have no clients: list; any program your rules allow gets the credential: remove the line` |
| a rule matcher named `aws`, a `path:` to a file called `aws`, or a `signed:` of identifier `aws` | error `rule N names aws; rules are judged on who called it, and it would pass any program aws runs …` |

  An entry with none of the ARNs is valid and "not connected": `config check` warns
  `aws.dev is not connected yet: add trustAnchorArn, profileArn and roleArn (nazar aws ca create
  printed the steps)`, `list` prints that sentence under the entry (its `--json` `state` is
  `not-connected`), and `credential` fails with exit 1 and the same text.
- **Loosen vs tighten** (`configstage`, target `aws:<name>`), as for k8s: the slot proof for
  rules and the fallback; an entry added loosens even when every slot blocks; any change to an
  ARN (adding them included) or to `identity` loosens; a
  shorter `duration` tightens, a longer one loosens; removing the entry tightens.
- **Rules from the CLI** (`nazar aws rule add|set|remove <name> …`) edit `aws.<name>.rules` with
  the code that edits a k8s context's (`config.edit`, `config.Entry` of kind aws): no `--to`, no
  op touches `identity`, the ARNs, `duration` or the entry's own gate.

---

## 8. CLI

```
nazar aws ca create <name> [--only-when-unlocked]  # login prompt: the CA and the entry
nazar aws ca show <name>                           # read: the CA certificate PEM
nazar aws list                                     # read
nazar aws rule add|set|remove <name> …             # the flags of k8s rule
nazar aws forget <name>                            # login prompt: deletes the CA and the entry
nazar aws credential <name>                        # credential_process; run by the AWS CLI and SDKs, not by people
```

- **`ca create`** is `k8s ca create` without a cluster. One login prompt covers the CA (enclave
  key, Vault item `aws-ca/<name>`, `~/.nazar/keys/aws-ca-<name>.crt`), the `aws.<name>`
  entry (identity `<user>-nazar`, `gate: block`, one login rule for the terminal app it was typed
  in). No program is pinned and no `aws` is needed on `PATH`. The prompt shows each, says that
  the program that runs `credential_process` gets the credential when the rules allow whoever
  ran it, and that AWS accepts every certificate this CA issues for any role whose trust policy
  names it. A config changed during the prompt makes nothing; a later step that fails undoes the
  earlier ones. Output: the certificate path and
  fingerprint, then the AWS-side steps of section 10 with the name and ARN placeholders filled
  in, then the `~/.aws/config` lines. `--json`: `AWSEntry` with `ca.certPEM`.
- **`ca show`** prints the CA certificate PEM from the Vault item, never the file.
- **`list`**: every entry and every CA: `AWSEntryList`; each `AWSEntry {name, identity{user},
  trustAnchorArn, profileArn, roleArn, duration, rules, configured, state (ok,
  not-connected, no-entry, no-ca, ca-unusable, absent), remedy, policy, warnings,
  ca{fingerprint, created, notAfter, certFile, whileLocked} | null, caBroken, unusableReason}`.
- **`forget`**: one login prompt; deletes the CA key, Vault item, `.crt` file and the entry, and
  drops the remembered approvals, as `k8s forget`. Its output reminds the user to disable or
  delete the trust anchor (AWS keeps trusting the certificate until then, though nothing can be
  issued under it any more) and to remove the `credential_process` line.
- **`credential`** is listed in the usage text with its note, as `k8s credential` is; its exit
  codes are 6.3.
- **Control commands:** `aws.credential` (value command; args `name`), `aws.ca.create` (`name`,
  `onlyWhenUnlocked`), `aws.ca.show`, `aws.list`, `aws.forget`. Reply kinds
  `AWSCredential {name, accessKeyId, secretAccessKey, sessionToken, expiration, accountId}`,
  `AWSEntry`, `AWSEntryList`, `AWSCA`.

---

## 9. Threat model additions

### 9.1 Every program that gets the credential can hand it on

`aws configure export-credentials` prints the credential of any profile
([reference](https://docs.aws.amazon.com/cli/latest/reference/configure/export-credentials.html)),
and every SDK program holds it in memory. There is no client list (the decision at the top):
whatever program runs `credential_process` receives the session, and approvals are keyed per
program (the receiver). The boundary is check 3 and the gate on whoever ran that program, as for
secrets delivered on stdout
(THREAT-MODEL 5.9, 5.12): an approval for a terminal tab is an AWS session for anything in that
tab, for up to `duration`.

### 9.2 What a session credential is

A bearer credential for the role, usable from any network for up to `duration`. An approval
revoked in nazar stops new ones at once; one already handed out ends at its `Expiration`, or
earlier only through IAM's "revoke active sessions" (`aws:TokenIssueTime`,
[IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)).
The role's own policy is what bounds the damage; `ca create`'s steps leave that choice to the
user.

### 9.3 `~/.aws/config` is any process's to write

A changed `credential_process` that runs something else gets nothing from nazar (check 0). One
that runs nazar through a wrapper is the k8s 5.16 case: a hop that execs keeps the program that
ran it the parent but can't keep the pipe, and the stdout check refuses it. A profile pointed at another
entry name gets that entry's credential only if that entry's rules allow the caller.

### 9.4 The agent's first outbound connection

- To `rolesanywhere.<region>.amazonaws.com` only, the host built from the config in force, never
  from the request; HTTPS with the system's roots, TLS 1.2 or later; no proxy, no redirects; a
  10-second deadline; nothing read past 64 KiB.
- A network attacker sees TLS. One with a root certificate the Mac trusts (added by the user, or
  by an admin) could read the signed request and the reply, and so the session. The request is
  bound to the role, the time and the leaf, which ends in minutes. Pinning Amazon's roots is
  left out: it breaks with AWS's own CA rotations and gains little against an attacker who can
  add roots (13, Q4).
- A firewall that asks per app (Little Snitch, LuLu) asks about nazar-agent once; that is not a
  TCC prompt and no test triggers it (the tests use a loopback fake).

### 9.5 The CA

AWS trusts every leaf the CA signs for any role whose trust policy accepts it, the way a cluster
does for k8s (k8s 10). The CA key never leaves the enclave and signs only certificates built by
`Issue` (2.3), after an approval; the leaf key lives in the agent's memory for one request (Go
can't promise to wipe it; it is never in a reply, a log or a file). A compromised nazar-agent
can mint at will, as it can for every module (THREAT-MODEL 4.8).

---

## 10. AWS-side setup (the user's steps, as `ca create` prints them)

Run with the user's existing AWS admin credentials; nazar runs none of this.

1. **Trust anchor** with the CA as its certificate bundle
   ([CLI](https://docs.aws.amazon.com/cli/latest/reference/rolesanywhere/create-trust-anchor.html)).
   It needs `jq` (`brew install jq`), which puts the PEM into the JSON AWS
   takes; the printed step says so:
   ```sh
   aws rolesanywhere create-trust-anchor --name nazar-dev --enabled \
     --source "$(jq -n --rawfile pem ~/.nazar/keys/aws-ca-dev.crt \
       '{sourceType: "CERTIFICATE_BUNDLE", sourceData: {x509CertificateData: $pem}}')"
   ```
2. **Role** trusting Roles Anywhere, only for this trust anchor and this identity:
   ```json
   {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
     "Principal": {"Service": "rolesanywhere.amazonaws.com"},
     "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
     "Condition": {
       "ArnEquals": {"aws:SourceArn": "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/<id>"},
       "StringEquals": {"aws:PrincipalTag/x509Subject/CN": "you-nazar",
                        "aws:PrincipalTag/x509Issuer/CN": "nazar aws CA dev"}}}]}
   ```
   `aws iam create-role --role-name dev --assume-role-policy-document file://trust.json`, then
   attach the permissions the role should have.
3. **Profile** naming the role
   ([CLI](https://docs.aws.amazon.com/cli/latest/reference/rolesanywhere/create-profile.html)):
   `aws rolesanywhere create-profile --name nazar-dev --role-arns arn:aws:iam::123456789012:role/dev --duration-seconds 3600 --enabled`.
4. **Connect the entry:** add `trustAnchorArn`, `profileArn` and `roleArn` to `aws.dev` in
   `~/.nazar/config/config.yaml`. That loosens, so it waits for `nazar config apply` and
   Touch ID.
5. **The profile line** of 3.1 in `~/.aws/config`.
6. **Check:** `aws sts get-caller-identity --profile dev` shows
   `arn:aws:sts::123456789012:assumed-role/dev/<serial>`, and `nazar log --target aws:dev` the
   line with that serial.

---

## 11. Testing

Every rule of AGENTS.md holds: no Touch ID, Keychain, TCC or window; the fake platform signs;
no test reaches AWS or the network beyond loopback.

### 11.1 Part 1

- **Pins first, on the old code, in their own commit:** a golden of a `k8s-ca/` record as JSON
  (field names, order, version) made with the fake platform at a fixed time; a fixed record
  written by today's code that must decode the same afterwards; the CA template fields; a table
  of every error text core/k8s can return. They pass before the move and unchanged after it.
- **Unchanged tests:** `cmd/nazar/testdata/cli-contract.golden`, every test in `cmd/nazar`,
  `core/daemon`, `core/config`, `core/configstage`, `core/policy` and `test/integration` that
  touches k8s (the real-`kubectl` test included), and every black-box test in `core/k8s`. The
  only k8s tests that move are the two white-box ones that call unexported engine code
  (`TestSignerSignsOnlyMessages`, `TestIssueCheck`): they move to `core/certs` with their case
  tables as they are. `git diff main --stat -- '*_test.go'` shows only those moves and additions.
- **Engine tests:** the moved tests, run for two kinds (k8s and a test kind) so prefixes, words
  and case-folded names never cross kinds (a k8s store never lists or reads `aws-ca/` items);
  `Serial` is positive, 127 bits, even-length hex.
- **No raw signing entry point:** a test renders the package's exported API (`go/doc`) and
  compares it with `core/certs/testdata/api.golden`; another asserts the signer is reachable only
  from `Create` and `Issue` (an AST scan of call sites in the package).

### 11.2 The fake Roles Anywhere endpoint (`core/aws/awstest`)

An `httptest` TLS server that verifies requests as AWS documents it, written from the AWS signing
guide and **not** importing nazar's signer (a test checks `awstest`'s imports with `go list`):

- rebuilds the canonical request from the received `http.Request` (method, path, canonical query,
  the headers named in `SignedHeaders`, the body hash) and the string to sign;
- requires `AWS4-X509-ECDSA-SHA256`, `Credential` = the decimal serial of the `X-Amz-X509`
  certificate, a scope whose date, region and service match, `x-amz-date` within 5 minutes of
  its clock, and `host`, `content-type`, `x-amz-date`, `x-amz-x509` all signed;
- verifies the signature (`ecdsa.VerifyASN1` with the certificate's key over SHA-256 of the
  string to sign) and the certificate against the trust anchor bundle it was given (the CA PEM
  from the store): `x509.Verify` at its clock, digital signature, not a CA, SHA-256;
- accepts the parameters in the body or the query, as AWS does, and records which;
- answers 201 with a `credentialSet` (fixed fake secrets), or AWS's error shapes (403
  `AccessDeniedException`, 400 `ValidationException`, 404, 429) on demand.

**How the fake is checked** (`core/aws/awstest/rolesanywhere_test.go`): it accepts a request the
test signs itself, from the AWS guide, with the parameters in the body and in the query (as AWS's
helper sends them), and names the session for the leaf's serial; and it refuses each negative
case for its own reason (each signed header changed after signing, the host, the body changed,
the date 6 minutes off, a leaf from another CA, an expired leaf, an RSA algorithm string with an
ECDSA key, a header left unsigned), plus AWS's error shapes on demand. **Not built yet:** a
cross-check against AWS's own client, `aws_signing_helper credential-process` with a leaf from
the engine, `--endpoint` at the fake and `--no-verify-ssl`, which needs the helper baked into the
CI image at a pinned version. It is a follow-up; until then a fake that agreed with nazar's signer
on a misreading of the guide would go unnoticed here, and only the by-hand run on a real account
(11.3) would show it.

### 11.3 Part 2

- **Signer (`core/aws`):** canonical request and string to sign for fixed inputs, golden; the
  shape of the AWS guide's example (empty query, `content-type;host;x-amz-date;x-amz-x509`);
  nazar's request has an empty query and a non-empty body (`postEmptyBody` false); every
  request it builds passes the fake.
- **Session client:** each reply check of 6.3 has a failing case (status, size, JSON, each field,
  expiration in the past or too far, another role); a redirect and a slow server (deadline) fail;
  the transport has no proxy.
- **Daemon (fake platform, fake endpoint):** check 0, check 1 (any identified program in an
  allowed chain gets the session; one with no identity, or exited, gets nothing), the stdout
  check before the broker (a pipe the shell or the CLI's own child reads, an exec-hop relay
  through `tee`, a co-writer) and at mint time, rules on `chain[2:]`, the receiver per program,
  the config changed during the
  prompt mints nothing (and makes no request: the fake counts), not-connected, no CA, unusable CA,
  locked CA, AWS errors as exit 1 with the code in the message, one audit line per request with
  the serial the fake saw, no secret in any audit line, log or problem (the sink and the replies
  scanned for the fake's secret strings), and the reply to the CLI holds no certificate and no
  key.
- **CLI (`awscred`):** the exact `credential_process` JSON in one write; nothing on stdout on any
  failure; one stderr line; each exit code of 6.3; `--json` refused; the environment ignored
  (`HOME`, `NAZAR_CONTROL_SOCKET`, `AWS_*`); the release build has no test socket. A fuzz test:
  for any prefix, `json.Unmarshal(prefix + reply)` fails or yields nazar's values (3.4).
- **Config, staging, policy:** a case per validation row; a case per loosen/tighten row; rule ids
  change with each ARN, the identity and the duration.
- **CLI contract golden extended** with every `aws` command path, good and bad arguments, as the
  k8s ones are; the existing lines unchanged.
- **Integration** (`test/integration/aws_test.go`): every `nazar aws` command of the nazartest
  build against `nazar-testd` in a temp home, as docs/CLI.md orders them; then
  `credential_process` run as the Go SDK runs it (`sh -c`, a pipe, the 1-minute timeout) and as
  botocore does (`Popen` with `stdout=PIPE`). `nazar-testd` sets no `VerifyCLI` and no AWS
  endpoint, so both are refused at check 0, exit 3, with nothing on stdout; minting, the fake
  endpoint and the `tee` relay are the daemon tests'.
- **By hand (manual script, not CI):** the steps of section 10 on a real account;
  `aws sts get-caller-identity`, a boto3 script and `terraform plan` through the profile; the
  CloudTrail `CreateSession` event shows `missingSignedHeaders: []`, `postEmptyBody: false`,
  `algorithmMismatch: false`, and the session name equals the audit line's serial.

---

## 12. Sources

- Roles Anywhere signing process: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html
- CreateSession: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-create-session.html
- Trust model, certificate requirements, source identity, principal tags: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
- CloudTrail `additionalEventData`: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/logging-using-cloudtrail.html
- Endpoints and quotas: https://docs.aws.amazon.com/general/latest/gr/rolesanywhere.html
- `create-trust-anchor`: https://docs.aws.amazon.com/cli/latest/reference/rolesanywhere/create-trust-anchor.html
- `create-profile`: https://docs.aws.amazon.com/cli/latest/reference/rolesanywhere/create-profile.html
- `credential_process` (CLI): https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
- `credential_process` (SDKs, `AccountId`): https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html
- `export-credentials`: https://docs.aws.amazon.com/cli/latest/reference/configure/export-credentials.html
- Revoking role sessions: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
- AWS's helper (`aws_signing_helper/signer.go`, `credentials.go`, `rolesanywhere/serializers.go`): https://github.com/aws/rolesanywhere-credential-helper
- botocore `ProcessProvider`, refresh windows: https://github.com/boto/botocore/blob/develop/botocore/credentials.py
- Go SDK `processcreds` (`sh -c`, 1-minute timeout): https://github.com/aws/aws-sdk-go-v2/blob/main/credentials/processcreds/provider.go

---

## 13. Open questions

| # | Question | Default if unanswered |
|---|---|---|
| A1 | Does a session outlive a 10-minute leaf? AWS documents `Expiration` without the certificate; checked by hand (11.3) on a real account. | Keep 10 minutes. If AWS cuts the session to the leaf's end, the leaf lives `duration` + 5 minutes, which changes nothing else (the key still never leaves one request). |
| A2 | The clock window: the 5 minutes of 5.1 is SigV4's usual limit, not stated in the Roles Anywhere guide. | Keep `now±5m`; measure with a skewed clock in the manual script. |
| Q1 | Connecting the entry is a hand edit of `config.yaml` (10, step 4). Should a second `aws ca create <name> <trustAnchorArn> <profileArn> <roleArn>` fill them in on one login prompt instead? | Hand edit: no new mode of a command, and it is staged and approved like every other loosening. |
| Q2 | A cache per (entry, receiver, approval) if the AWS CLI's per-command `CreateSession` is too slow in practice. | No cache (5.3). |
| Q3 | Homebrew's `awscli` runs as the Python interpreter. Trust the interpreter as a client, or support only Mach-O clients? | Settled by the decision at the top: there is no client list. The interpreter is the program that receives the session, judged on who ran it, as any other program. |
| Q4 | Pin Amazon's roots for the one host the agent calls? | No (9.4). |

---

## 14. Implementation plan

Each step lands with its tests; `make check` passes after each; no step changes k8s behaviour.

### Part 1: `core/certs`

1. **Pins on the old code** (11.1, first bullet): record golden, old-record decode, CA template,
   error texts. Commit alone, before anything moves.
2. **Create `core/certs`**: `Kind`, `NewKind`, `Store`, `CA`, `CAInfo`, `LeafSpec`, `Serial`,
   `Leaf`, `Issue`, `check`, `signer`, moved from core/k8s with the kind's words in place of the
   literal `k8s`. Move `TestSignerSignsOnlyMessages` and `TestIssueCheck` with them; add the
   two-kind tests and the API golden.
3. **Rewire core/k8s** onto the engine: `kind = certs.NewKind("k8s", "k8s-ca/", "context",
   "nazar k8s CA ", config.ValidK8sContextName)`; `CAStore`, `CA`, `CAInfo`, the `Err…` values,
   `(*CA).Issue` and `CACertProvider` keep their exported names, signatures and texts; daemon,
   CLI and config untouched.
4. **Verify:** the step 1 pins, every unchanged test, the CLI contract golden and the real-kubectl
   integration test pass; the test diff is only moves and additions.

### Part 2: the AWS adapter

1. **Config:** `core/config/aws.go` (`AWSEntry`, parse, validation table, `AddAWSEntry`,
   `RemoveAWSEntry`, `AWSFallback`), `configstage` rules, `config.Entry` of kind aws for rule
   edits.
2. **Policy:** `EvaluateAWS(name, chain)` (check 1, check 3, rule id fingerprint), the broker's
   `AWS` request field, `aws:` op and prompt text.
3. **Signer and session client** (`core/aws`): canonical request, string to sign, Authorization,
   `CreateSession` over an injected transport, reply checks. The fake endpoint (`core/aws/awstest`)
   in the same step, written separately from the signer.
4. **Daemon:** `aws.credential` (value command, the stdout check, `Do` as 3.3), `aws.ca.create`,
   `aws.ca.show`, `aws.list`, `aws.forget`, `awsAdvice` for `status`; the transport and endpoint
   are a daemon option set only by tests, never by config, environment or `nazar-testd`.
5. **CLI:** `nazar aws …` (section 8), `awscred.go` on `credentialClient` and `credFail`, the
   printed setup steps, the contract golden extended.
6. **Integration:** every `nazar aws` command against `nazar-testd`, and the Go-SDK-like and
   botocore-like runners, refused there at check 0. The `tee` refusal is a daemon test (11.3).
   The `aws_signing_helper` cross-check of the fake is not built yet (11.2): it needs the pinned
   helper in the CI image.
7. **Docs:** docs/CLI.md (an AWS section), THREAT-MODEL (9.1 to 9.5), AGENTS.md (refused AWS
   credentials: exit 3 is the user's, exit 1 with an AWS error code is setup; never edit
   `~/.aws/config` or `credential_process` to get around a refusal; suggest
   `nazar aws rule add <name> --apps … --gate dialog --scope session`), the nazar skill.
8. **By hand:** section 10 on a real account and the manual checks of 11.3; settle A1 and A2.
