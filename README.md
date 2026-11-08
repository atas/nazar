# nazar 🧿

*A watchful eye on every key.*

Your keys and secrets, locked to your device by the Mac's Secure Enclave (Linux TPM coming).
They can't be copied off it.

- Restrict access per app
- Approve with Touch ID or a dialog
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

Coming.

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
nazar secret add API_TOKEN         # paste it at the hidden prompt; Touch ID
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

Changes that loosen access ask for Touch ID. `nazar config check` validates it.

## More

- [Guide](docs/GUIDE.md) · [CLI](docs/CLI.md) · [Threat model](docs/THREAT-MODEL.md) · [Security](SECURITY.md)
- For AI agents: [AGENTS.md](AGENTS.md) · [skill](skills/nazar/SKILL.md)

[Apache-2.0](LICENSE)
