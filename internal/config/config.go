// Package config loads and merges *.hcl files from a config.d directory.
// Singleton blocks (bitwarden, auto_auth, template_config) must appear in
// exactly one file; template blocks may appear any number of times.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// fileConfig is the raw decoded struct for a single HCL file.
type fileConfig struct {
	LogLevel       string          `hcl:"log_level,optional"`
	PIDFile        string          `hcl:"pid_file,optional"`
	Bitwarden      *BWConfig       `hcl:"bitwarden,block"`
	AutoAuth       *AutoAuth       `hcl:"auto_auth,block"`
	TemplateConfig *TemplateConfig `hcl:"template_config,block"`
	Templates      []*Template     `hcl:"template,block"`
	Remain         hcl.Body        `hcl:",remain"`
}

// Config is the merged, post-processed configuration.
type Config struct {
	LogLevel string
	PIDFile  string

	Bitwarden      *BWConfig
	AutoAuth       *AutoAuth
	TemplateConfig *TemplateConfig
	Templates      []*Template
}

type BWConfig struct {
	ServerURL   string `hcl:"server_url,optional"`
	IdentityURL string `hcl:"identity_url,optional"`
	APIURL      string `hcl:"api_url,optional"`
}

type AutoAuth struct {
	Method      string `hcl:"method,optional"`
	AccessToken string `hcl:"access_token"`
}

type TemplateConfig struct {
	RenderIntervalRaw  string `hcl:"static_secret_render_interval,optional"`
	ExitOnRetryFailure bool   `hcl:"exit_on_retry_failure,optional"`
	RenderInterval     time.Duration
}

type Template struct {
	Source      string      `hcl:"source,optional"`
	Contents    string      `hcl:"contents,optional"`
	Destination string      `hcl:"destination"`
	Perms       string      `hcl:"perms,optional"`
	LeftDelim   string      `hcl:"left_delim,optional"`
	RightDelim  string      `hcl:"right_delim,optional"`
	Exec        *ExecConfig `hcl:"exec,block"`
}

type ExecConfig struct {
	Command        []string `hcl:"command"`
	TimeoutRaw     string   `hcl:"timeout,optional"`
	RestartOnError bool     `hcl:"restart_on_error,optional"`
	Timeout        time.Duration
}

// LoadDir reads all *.hcl files from dir and returns a merged Config.
func LoadDir(dir string) (*Config, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading config dir %q: %w", dir, err)
	}

	parser := hclparse.NewParser()
	merged := &Config{}
	found := false

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".hcl" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, diags := parser.ParseHCLFile(path)
		if diags.HasErrors() {
			return nil, fmt.Errorf("parsing %s: %s", path, diags.Error())
		}

		var fc fileConfig
		if diags = gohcl.DecodeBody(f.Body, nil, &fc); diags.HasErrors() {
			return nil, fmt.Errorf("decoding %s: %s", path, diags.Error())
		}

		if err := mergeInto(merged, &fc, path); err != nil {
			return nil, err
		}
		found = true
	}

	if !found {
		return nil, fmt.Errorf("no .hcl files found in %q", dir)
	}

	return merged.postProcess()
}

func mergeInto(dst *Config, src *fileConfig, srcPath string) error {
	if src.LogLevel != "" {
		dst.LogLevel = src.LogLevel
	}
	if src.PIDFile != "" {
		dst.PIDFile = src.PIDFile
	}
	if src.Bitwarden != nil {
		if dst.Bitwarden != nil {
			return fmt.Errorf("%s: duplicate bitwarden block (already defined in a previous file)", srcPath)
		}
		dst.Bitwarden = src.Bitwarden
	}
	if src.AutoAuth != nil {
		if dst.AutoAuth != nil {
			return fmt.Errorf("%s: duplicate auto_auth block (already defined in a previous file)", srcPath)
		}
		dst.AutoAuth = src.AutoAuth
	}
	if src.TemplateConfig != nil {
		if dst.TemplateConfig != nil {
			return fmt.Errorf("%s: duplicate template_config block (already defined in a previous file)", srcPath)
		}
		dst.TemplateConfig = src.TemplateConfig
	}
	dst.Templates = append(dst.Templates, src.Templates...)
	return nil
}

func (c *Config) postProcess() (*Config, error) {
	if c.AutoAuth == nil {
		return nil, fmt.Errorf("auto_auth block is required")
	}
	c.AutoAuth.AccessToken = resolveEnvRef(c.AutoAuth.AccessToken)
	if c.AutoAuth.AccessToken == "" {
		return nil, fmt.Errorf("auto_auth.access_token is empty (check BWS_ACCESS_TOKEN env var)")
	}

	if c.TemplateConfig == nil {
		c.TemplateConfig = &TemplateConfig{}
	}
	if c.TemplateConfig.RenderIntervalRaw != "" {
		d, err := time.ParseDuration(c.TemplateConfig.RenderIntervalRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid static_secret_render_interval %q: %w", c.TemplateConfig.RenderIntervalRaw, err)
		}
		c.TemplateConfig.RenderInterval = d
	}
	if c.TemplateConfig.RenderInterval <= 0 {
		c.TemplateConfig.RenderInterval = 5 * time.Minute
	}

	for i, t := range c.Templates {
		if t.Source == "" && t.Contents == "" {
			return nil, fmt.Errorf("template[%d]: must have either source or contents", i)
		}
		if t.Destination == "" {
			return nil, fmt.Errorf("template[%d]: destination is required", i)
		}
		if t.LeftDelim == "" {
			t.LeftDelim = "{{"
		}
		if t.RightDelim == "" {
			t.RightDelim = "}}"
		}
		if t.Perms == "" {
			t.Perms = "0644"
		}
		if t.Exec != nil {
			if len(t.Exec.Command) == 0 {
				return nil, fmt.Errorf("template[%d].exec: command is required", i)
			}
			if t.Exec.TimeoutRaw != "" {
				d, err := time.ParseDuration(t.Exec.TimeoutRaw)
				if err != nil {
					return nil, fmt.Errorf("template[%d].exec: invalid timeout %q: %w", i, t.Exec.TimeoutRaw, err)
				}
				t.Exec.Timeout = d
			}
			if t.Exec.Timeout <= 0 {
				t.Exec.Timeout = 30 * time.Second
			}
		}
	}

	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return c, nil
}

// resolveEnvRef expands "env:VAR_NAME" references to their environment values.
func resolveEnvRef(s string) string {
	const prefix = "env:"
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return os.Getenv(s[len(prefix):])
	}
	return s
}
