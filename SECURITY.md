# Security policy

## Reporting a vulnerability

If you believe you have found a security issue in `bw-secrets-agent`,
please **do not open a public GitHub issue**. Instead, open a private
[security advisory](https://github.com/agustine-leo/bw-secrets-agent/security/advisories/new)
on this repository.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, including the affected version (`bw-secrets-agent --version`).
- Any proof-of-concept code or configuration, if applicable.

You can expect an acknowledgement within 7 days. We aim to issue a fix
or a coordinated disclosure plan within 30 days for confirmed reports.

## Scope

In scope:

- Authentication or decryption flaws in the agent's Bitwarden Secrets
  Manager client.
- Unintended leakage of secret material through logs, rendered files,
  process environment, or error paths.
- Privilege-escalation or sandbox-escape via the `template.exec` block
  beyond what the configured user already has.
- Denial-of-service issues with reasonable, realistic configurations.

Out of scope:

- Issues in the Bitwarden Secrets Manager service itself — please
  report those to Bitwarden directly.
- Configurations where the access token has been published or where
  the host running the agent is already compromised.
- Theoretical timing attacks against constant-time crypto primitives
  provided by the Go standard library.

## Supported versions

This project follows semver from `1.0.0` onward. Until then, only the
latest tagged release is supported with security fixes.
