package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDir_HappyPath(t *testing.T) {
	t.Setenv("BW_TEST_TOKEN", "test-token-value")

	dir := writeConfigFiles(t, map[string]string{
		"main.hcl": `
log_level = "debug"
auto_auth {
  method       = "bitwarden-sm"
  access_token = "env:BW_TEST_TOKEN"
}
template_config {
  static_secret_render_interval = "30s"
  exit_on_retry_failure         = true
}
template {
  source      = "templates/a.tpl"
  destination = "/tmp/a"
  perms       = "0640"
  exec {
    command = ["echo", "ok"]
    timeout = "5s"
  }
}
`,
	})

	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: want debug, got %q", cfg.LogLevel)
	}
	if cfg.AutoAuth.AccessToken != "test-token-value" {
		t.Errorf("env: substitution failed, got %q", cfg.AutoAuth.AccessToken)
	}
	if cfg.TemplateConfig.RenderInterval != 30*time.Second {
		t.Errorf("RenderInterval: want 30s, got %v", cfg.TemplateConfig.RenderInterval)
	}
	if !cfg.TemplateConfig.ExitOnRetryFailure {
		t.Errorf("ExitOnRetryFailure: want true")
	}
	if len(cfg.Templates) != 1 {
		t.Fatalf("Templates: want 1, got %d", len(cfg.Templates))
	}
	tpl := cfg.Templates[0]
	if tpl.Destination != "/tmp/a" || tpl.Perms != "0640" {
		t.Errorf("template fields wrong: %+v", tpl)
	}
	if tpl.Exec == nil || tpl.Exec.Timeout != 5*time.Second {
		t.Errorf("exec fields wrong: %+v", tpl.Exec)
	}
}

func TestLoadDir_MergesTemplates(t *testing.T) {
	t.Setenv("BW_TEST_TOKEN", "x")
	dir := writeConfigFiles(t, map[string]string{
		"auth.hcl": `
auto_auth {
  access_token = "env:BW_TEST_TOKEN"
}`,
		"templates_a.hcl": `
template {
  source      = "a.tpl"
  destination = "/tmp/a"
}`,
		"templates_b.hcl": `
template {
  source      = "b.tpl"
  destination = "/tmp/b"
}`,
	})

	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(cfg.Templates) != 2 {
		t.Fatalf("expected 2 templates merged, got %d", len(cfg.Templates))
	}
	dests := map[string]bool{}
	for _, tpl := range cfg.Templates {
		dests[tpl.Destination] = true
	}
	if !dests["/tmp/a"] || !dests["/tmp/b"] {
		t.Errorf("expected /tmp/a and /tmp/b, got %v", dests)
	}
}

func TestLoadDir_DuplicateSingletonBlock(t *testing.T) {
	t.Setenv("BW_TEST_TOKEN", "x")
	dir := writeConfigFiles(t, map[string]string{
		"a.hcl": `auto_auth { access_token = "env:BW_TEST_TOKEN" }`,
		"b.hcl": `auto_auth { access_token = "env:BW_TEST_TOKEN" }`,
	})

	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected duplicate-block error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate auto_auth") {
		t.Errorf("error should mention duplicate auto_auth, got: %v", err)
	}
}

func TestLoadDir_MissingAccessToken(t *testing.T) {
	// Env var not set → access_token resolves to "".
	os.Unsetenv("BW_MISSING_TOKEN")
	dir := writeConfigFiles(t, map[string]string{
		"a.hcl": `auto_auth { access_token = "env:BW_MISSING_TOKEN" }`,
	})

	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
	if !strings.Contains(err.Error(), "access_token") {
		t.Errorf("error should mention access_token, got: %v", err)
	}
}

func TestLoadDir_InvalidDuration(t *testing.T) {
	t.Setenv("BW_TEST_TOKEN", "x")
	dir := writeConfigFiles(t, map[string]string{
		"a.hcl": `
auto_auth { access_token = "env:BW_TEST_TOKEN" }
template_config { static_secret_render_interval = "not-a-duration" }
`,
	})
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatal("expected duration parse error, got nil")
	}
}

func TestLoadDir_DefaultRenderInterval(t *testing.T) {
	t.Setenv("BW_TEST_TOKEN", "x")
	dir := writeConfigFiles(t, map[string]string{
		"a.hcl": `
auto_auth { access_token = "env:BW_TEST_TOKEN" }
template {
  source      = "x"
  destination = "/tmp/x"
}
`,
	})
	cfg, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if cfg.TemplateConfig.RenderInterval != 5*time.Minute {
		t.Errorf("default interval should be 5m, got %v", cfg.TemplateConfig.RenderInterval)
	}
}

func TestLoadDir_NoFilesFound(t *testing.T) {
	dir := t.TempDir() // empty
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected error for empty config dir, got nil")
	}
}

func TestLoadDir_TemplateMissingDestination(t *testing.T) {
	t.Setenv("BW_TEST_TOKEN", "x")
	dir := writeConfigFiles(t, map[string]string{
		"a.hcl": `
auto_auth { access_token = "env:BW_TEST_TOKEN" }
template { source = "x.tpl" }
`,
	})
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected error when template lacks destination, got nil")
	}
}

// ── helpers ────────────────────────────────────────────────────────────────

func writeConfigFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return dir
}
