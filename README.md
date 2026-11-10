# nazar 🧿

*A watchful eye on every key.*

Your keys and secrets, locked to your Mac by the Secure Enclave. They can't be copied off it.
On Linux (preview) keys stay in the TPM and can't be copied off, but any program running as you
can use them, and read every secret.

- Restrict access per app
- Approve with Touch ID (your password on Linux) or a dialog
- Git commit signing
- API token vault for scripts and MCP servers
- Credential plugin for kubectl and the AWS CLI

## Install

### Mac

macOS 26 or later, Apple silicon:

```bash
brew install atas/tap/nazar
brew install atas/tap/nazar-ui     # optional window
```

### AI agent skill

Claude Code:

```
/plugin marketplace add atas/nazar
/plugin install nazar@nazar
```

Updates: `/plugin` → Marketplaces → nazar → Enable auto-update (off by default for this marketplace).

Codex:

```bash
mkdir -p ~/.agents/skills && curl -fsSL https://github.com/atas/nazar/archive/refs/heads/main.tar.gz | tar -xz -C ~/.agents/skills --strip-components=2 nazar-main/skills/nazar
```

Other agents: "read https://github.com/atas/nazar/blob/main/llms.txt and set nazar up".

Then ask it:

```
/nazar set up my GitHub SSH key and commit signing
/nazar move OPENAI_API_KEY out of ~/.zshrc
/nazar use nazar for kubectl on my cluster
```

### Linux

A preview: tested in containers with a software TPM, not yet on real hardware. It is weaker than
macOS: any program running as you can use your keys and read every secret without a prompt, and
whoever holds the machine can use every key unless the disk is encrypted
([threat model](docs/THREAT-MODEL.md#7-linux-preview)).

A systemd desktop with a TPM 2.0, amd64 or arm64, and full-disk encryption:

```bash
brew install atas/tap/nazar-linux
# or the release's install.sh, which prints the next two lines:
# curl -fsSL https://github.com/atas/nazar/releases/latest/download/install.sh | sh

sudo "$(command -v nazar)" install --system   # once; then log out and back in
nazar install                                 # and after every upgrade; from Homebrew add --no-links
```

The `sudo` line runs a file you own as root: run it right after installing, from the file you just
checked (install.sh checks it against `SHA256SUMS`), not from a line a program prints later.

Set up as below, except:

- `login` is your password through the system prompt (fingerprint where fprintd is set up)
- `dialog` is a zenity or kdialog window
- rules use `path:` and `app:` (`signed:` is macOS only)
- `secret add` has no hidden prompt: pipe the value in
- `nazar run` and `nazar ui` are not there

[Everything that differs](docs/CLI.md#linux).

## Security note

An SSH key passphrase saved in the Mac Keychain doesn't protect the key: a program can fake an
ssh-agent and get `ssh-add` to hand it the decrypted key. With nazar, the key never leaves the
Secure Enclave.

Password managers' SSH agents (1Password, Bitwarden) ask before use, but the private keys sync to
their cloud and to all your devices, are decrypted into the app's memory, and can't be limited to
specific apps.

## Set up

```bash
nazar ssh-key create github        # Touch ID
nazar ssh-key pubkey github        # add it on GitHub → Settings → SSH keys
```

`~/.ssh/config`:

```
Host github.com
  IdentityAgent ~/.nazar/run/agent.sock
  IdentityFile ~/.nazar/keys/github.pub
  IdentitiesOnly yes
```

Sign commits:

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program "$(brew --prefix)/bin/nazar-sign-git"
git config --global user.signingkey ~/.nazar/keys/github.pub
git config --global commit.gpgsign true
```

`nazar status` checks it all.

Secrets:

```bash
nazar secret add API_TOKEN         # macOS: paste it at the hidden prompt; Touch ID
printf '%s' "$API_TOKEN" | nazar secret add API_TOKEN    # or pipe it (the only way on Linux)
nazar get API_TOKEN | sed 's/^/Authorization: Bearer /' | curl -H @- https://api.example.com
```

Kubernetes (self-managed):

```bash
nazar k8s ca create                        # context, server, CA; Touch ID
nazar k8s ca show mycluster-nazar          # steps to run on the cluster
kubectl --context mycluster-nazar get pods # Touch ID once per tab
```

## Config

`~/.nazar/config/config.yaml`, for example:

```yaml
apiVersion: nazar/v1
kind: Config

apps:                          # who may ask, by code signature
  claude:
    signed: {team: Q6L2SF6YDW, id: com.anthropic.claude-code}
  iterm:
    app: com.googlecode.iterm2

ssh_agent:
  keys:
    github:
      rules:                   # first match wins; anything else is blocked
        - apps: [claude]
          scope: session       # once per Claude Code run
          gate: dialog         # Allow/Deny dialog
        - apps: [iterm]
          scope: session       # once per terminal tab
          gate: login          # Touch ID
          expire: 8h
    prod:
      scope: use               # every use, any app: Touch ID
      gate: login

secrets:
  API_TOKEN:
    rules:
      - apps: [iterm]
        scope: session
        gate: login
```

Changes that loosen access ask for Touch ID (your password on Linux). `nazar config check`
validates it.

## More

- [Guide](docs/GUIDE.md) · [CLI](docs/CLI.md) · [Threat model](docs/THREAT-MODEL.md) · [Security](SECURITY.md)
- For AI agents: [AGENTS.md](AGENTS.md) · [skill](skills/nazar/SKILL.md)

[Apache-2.0](LICENSE)
