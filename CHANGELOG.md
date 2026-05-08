# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Initial release.
- HCL configuration loaded from a `config.d/` directory; multiple files
  are merged.
- Bitwarden Secrets Manager REST client with native crypto: parses the
  machine-account access token, derives the working key via
  `HKDF-Expand(HMAC("bitwarden-accesstoken", seed), "sm-access-token", 64)`,
  performs the OAuth2 `client_credentials` exchange, decrypts the
  identity server's `encrypted_payload` to obtain the org symmetric key,
  and unwraps every EncString locally. No `bws` binary or CGo
  dependency.
- Two-call secret fetch flow: `GET /organizations/{orgId}/secrets`
  (metadata) followed by `POST /secrets/get-by-ids` (values).
- Go `text/template` renderer with three helpers: `secret PROJECT KEY`,
  `secret KEY`, `secretID UUID`.
- `template { exec { command } }` block fires only when the rendered
  output differs from the destination file.
- `template.owner` and `template.group` apply file ownership after the
  write and before `exec` runs. Both accept user/group names or numeric
  IDs; an empty value preserves the existing UID/GID.
- `SIGHUP` reloads `config.d/` without dropping the JWT (unless the
  access token itself changed).
- `--once` flag for init-container / CI rendering.
- JWT auto-renewal 60 seconds before expiry.
- Unit tests for token parsing, key derivation (against Bitwarden's
  published `derive_shareable_key` test vectors), EncString round-trip,
  PKCS#7 padding, JWT claim extraction, HCL config loader, and template
  rendering. `go test -race ./...` runs in <2s.
