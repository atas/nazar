# Security policy

nazar guards SSH keys and API tokens, so a flaw in it matters. Please report one privately.

## Reporting a vulnerability

Use [GitHub's private reporting](https://github.com/atas/nazar/security/advisories/new). Please
don't open a public issue or pull request for it.

A useful report says:

- what an attacker can do, and what they need first (for example, code running as the user);
- the steps to reproduce it, with your macOS and nazar versions (`nazar version`);
- the `nazar log` lines that show it, with anything private removed.

Never send real keys, tokens or a full `config.yaml`.

Replies are best effort. Reports stay private until a fix is released, and you can be credited in
the advisory if you'd like.

## What counts

The [threat model](docs/THREAT-MODEL.md) says what nazar defends against and what it doesn't. In
scope, for example:

- getting a signature or a secret without the rule and gate that should allow it;
- faking the caller or the receiver a rule checks;
- loosening access without the approval it needs;
- a secret reaching a log, a prompt, a file or a process it wasn't meant for.

The limits the threat model already states are out of scope. If you're unsure, report it.

Some protections still wait on checks only a person at a Mac can run. They are listed in
[spec 10.1](docs/design/nazar-design.md#101-attended-checks); a result for any of them is welcome.

## Supported versions

Only the latest release gets fixes.
