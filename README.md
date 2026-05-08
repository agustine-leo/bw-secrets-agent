# bw-secrets-agent

A daemon that polls **Bitwarden Secrets Manager**, renders Go-template files
with the resolved values, and runs a command when the rendered output
changes. Modeled after [HashiCorp Vault Agent].

> **Unofficial.** This project is not affiliated with, endorsed by, or
> sponsored by Bitwarden, Inc. or HashiCorp, Inc. "Bitwarden" and
> "Vault" are trademarks of their respective owners. See [`NOTICE`](NOTICE).

[HashiCorp Vault Agent]: https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent

---

## Why

If you use Bitwarden Secrets Manager (BWS) and want secrets to land on
disk as `.env` files, TOML configs, certificates, etc. — and want a
service to be reloaded whenever those values change — you have two
options today:

1. Shell out to the `bws` CLI on a cron and write your own diff/exec glue.
2. Run this agent.

`bw-secrets-agent` is a single static Go binary. It speaks the
Bitwarden Secrets Manager REST API directly (no `bws` subprocess, no
CGo) and ships the Vault-Agent-style ergonomics: HCL config, a
`config.d/` directory, Go-template rendering, and an `exec` block that
fires when the destination file's contents actually change.

## Quick start

```sh
# 1. Build
make build

# 2. Set the access token in the environment
export BWS_ACCESS_TOKEN="0.<token-id>.<client-secret>:<encryption-key>"

# 3. Edit config.d/example.hcl + templates/app.tpl to point at your secrets

# 4. One-shot render (useful for init containers / CI):
./bw-secrets-agent --once --log-level=info

# 5. Run as a long-lived agent:
./bw-secrets-agent --log-level=info
```

## Configuration

Configuration lives in one or more `*.hcl` files inside a directory
(default: `./config.d`). Singleton blocks (`bitwarden`, `auto_auth`,
`template_config`) must appear in exactly one file. The `template`
block can be repeated and may live in any file; all are merged at
startup. See [`config.d/example.hcl`](config.d/example.hcl) for an
annotated example.

### Block reference

| Block             | Required | Repeats | Purpose |
|-------------------|----------|---------|---------|
| `bitwarden`       | no       | once    | Override identity/API URLs (self-hosted Bitwarden) |
| `auto_auth`       | yes      | once    | How the agent authenticates to BWS |
| `template_config` | no       | once    | Polling interval and failure behavior |
| `template`        | yes      | many    | A source/destination pair plus optional `exec` |

### `auto_auth`

```hcl
auto_auth {
  method       = "bitwarden-sm"
  access_token = "env:BWS_ACCESS_TOKEN"   # or a literal token string
}
```

`access_token` accepts either a literal value or `env:VAR_NAME` to read
from the process environment at startup. **Always use the env: form in
production** so the token is not committed to disk.

### `template_config`

```hcl
template_config {
  static_secret_render_interval = "5m"   # Go duration: 30s, 5m, 1h, …
  exit_on_retry_failure         = false  # if true, a fatal cycle stops the agent
}
```

### `template`

```hcl
template {
  source      = "templates/app.tpl"   # or use `contents = "..."` inline
  destination = "/etc/myapp/app.env"
  perms       = "0640"
  owner       = "root"                # optional; user name or numeric UID
  group       = "myapp"               # optional; group name or numeric GID
  left_delim  = "{{"                  # optional, defaults shown
  right_delim = "}}"

  exec {
    command          = ["systemctl", "reload", "myapp"]
    timeout          = "30s"
    restart_on_error = false
  }
}
```

`owner` and `group` are applied **after** the file is written and
**before** `exec.command` runs, so the reload target sees the file with
its final ownership. Either field may be a name or a numeric ID; if
omitted, the existing UID/GID is preserved. The agent must be running
as a user that can `chown` to the requested target (typically root).

If `command` is a single string it is passed to `sh -c`. If it is two or
more elements, they are exec'd directly (no shell expansion). The
command runs **only when the rendered output differs from the existing
destination file** — same semantics as Vault Agent.

## Template syntax

Templates use Go's [`text/template`] with three extra functions:

[`text/template`]: https://pkg.go.dev/text/template

| Function | Example | Resolves to |
|----------|---------|-------------|
| `secret PROJECT KEY` | `{{ secret "Infra" "DB_PASSWORD" }}` | The value of secret `DB_PASSWORD` in project `Infra` |
| `secret KEY` | `{{ secret "DB_PASSWORD" }}` | The value of any secret with key `DB_PASSWORD` (last writer wins on duplicates) |
| `secretID UUID` | `{{ secretID "b136d84c-…" }}` | The value of the secret with that Bitwarden ID |

Project and key names are matched **exactly as stored in Bitwarden** —
case-sensitive, no whitespace trimming. If you get
`secret "X/Y" not found`, run `bws secret list` to confirm the names.

## Operations

| Signal       | Behavior                                                       |
|--------------|----------------------------------------------------------------|
| `SIGHUP`     | Reload `config.d/`; the next cycle uses the new interval/templates. The JWT is re-issued if `access_token` changed. |
| `SIGTERM` / `SIGINT` | Graceful shutdown. |

The agent renews its identity-server JWT 60 seconds before expiry. If
the access token is revoked or rotated externally, send `SIGHUP` (with
the new value in the env) to pick it up without a restart.

### CLI flags

| Flag             | Default      | Description |
|------------------|--------------|-------------|
| `--config-dir`   | `config.d`   | Directory containing `*.hcl` files |
| `--log-level`    | from config  | `debug` \| `info` \| `warn` \| `error` |
| `--once`         | `false`      | Render once and exit (init-container / CI use) |
| `--version`      |              | Print version and exit |

## How it works

1. **Authentication.** The 16-byte seed inside the access token is
   expanded to a 64-byte AES-256-CBC + HMAC-SHA256 working key via the
   Bitwarden derivation
   `HKDF-Expand(HMAC("bitwarden-accesstoken", seed), "sm-access-token", 64)`.
   The agent then performs an OAuth2 `client_credentials` exchange
   against the Bitwarden identity server to obtain a JWT and an
   `encrypted_payload`. Decrypting the payload with the working key
   yields the organization's symmetric key.
2. **Fetch.** Each polling cycle calls
   `GET /organizations/{orgId}/secrets` (metadata) followed by
   `POST /secrets/get-by-ids` (values).
3. **Decrypt.** Every secret's `key` and `value` field is an
   AES-256-CBC + HMAC-SHA256 EncString; the org key from step 1 unwraps
   them in-process.
4. **Render → diff → write → exec.** Each template is rendered. If the
   bytes differ from the destination file, the file is rewritten with
   the configured perms and `exec.command` runs.

No plaintext secret ever touches disk except in the rendered template
files you ask for. No subprocess ever sees the access token except the
agent itself.

## Security model

- **Tokens.** The access token grants read access to your service
  account's projects. Treat it like an SSH key: file-mode `0600`,
  rotated periodically.
- **Cache.** Decrypted secret values live in the agent's heap for the
  process lifetime. Memory is not currently zeroed on rotation.
- **Logs.** The agent never logs secret values, secret keys, or project
  names. At `info` level it logs the count of refreshed secrets and
  rendered template paths only; at `debug` level it additionally logs
  the org UUID and exec output.
- **Permissions.** `template.perms` controls the destination file mode.
  Default `0644`; set `0640` (group-readable) or `0600` (owner-only)
  for files holding sensitive material.
- **TLS.** The default Go HTTP client and system trust store are used.
  No certificate pinning.

## Build

Requires Go 1.24+ (uses `crypto/hkdf` from the standard library).

```sh
go build -o bw-secrets-agent ./cmd/bw-secrets-agent
# or:
make build
```

## When to use what

|                                 | `bws` CLI on cron | `bw-secrets-agent` |
|---------------------------------|-------------------|--------------------|
| One-off scripts, ad-hoc fetch   | ✓                 |                    |
| Long-running daemon, polling    |                   | ✓                  |
| Triggers `systemctl reload …`   | DIY               | ✓ (`exec` block)   |
| Render multiple files at once   | DIY               | ✓                  |
| Single static binary deployment |                   | ✓                  |
| No CGo build chain              | ✓                 | ✓                  |

If you only need to read a secret occasionally, the `bws` CLI is the
right tool. If you need a service to react to vault changes without
restarting, this agent is the right tool.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
