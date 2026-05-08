# bw-secrets-agent — example configuration
#
# Place one or more *.hcl files in this directory. Singleton blocks
# (bitwarden, auto_auth, template_config) must appear in exactly one file.
# The `template` block can be repeated and may live in any file; all are
# merged at startup.

# ── Global ────────────────────────────────────────────────────────────────

log_level = "info"   # debug | info | warn | error

# pid_file = "/var/run/bw-secrets-agent.pid"

# ── Bitwarden Secrets Manager connection ──────────────────────────────────
#
# Omit the bitwarden block entirely to use Bitwarden cloud defaults
# (https://identity.bitwarden.com, https://api.bitwarden.com). For
# self-hosted deployments, set `server_url` to your base URL — the agent
# will derive the identity and API endpoints from it.

# bitwarden {
#   server_url = "https://vault.example.com"
# }

# ── Authentication ────────────────────────────────────────────────────────
#
# `access_token` takes either a literal token or "env:VAR_NAME" to read
# from the process environment at startup. Always prefer the env: form
# in production so the token is not committed to disk.

auto_auth {
  method       = "bitwarden-sm"
  access_token = "env:BWS_ACCESS_TOKEN"
}

# ── Polling ───────────────────────────────────────────────────────────────

template_config {
  static_secret_render_interval = "5m"   # Go duration: 30s, 5m, 1h, …
  exit_on_retry_failure         = false  # if true, fatal errors stop the agent
}

# ── Templates ─────────────────────────────────────────────────────────────
#
# Template syntax is Go text/template plus two helpers:
#
#   {{ secret "PROJECT" "KEY" }}   — project-qualified lookup
#   {{ secret "KEY" }}             — bare key lookup (across all projects)
#   {{ secretID "<uuid>" }}        — lookup by Bitwarden secret UUID
#
# Each template is re-rendered every static_secret_render_interval. If the
# output differs from the destination file, the file is rewritten with the
# given perms and the optional `exec` command is run.

template {
  source      = "templates/app.tpl"
  destination = "/tmp/app.env"
  perms       = "0640"

  exec {
    command = ["echo", "rendered /tmp/app.env"]
    timeout = "10s"
  }
}
