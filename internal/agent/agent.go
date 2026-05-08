// Package agent runs the polling loop: refresh secrets from Bitwarden,
// render every configured template, write the destination file when its
// content has changed, and run the optional exec command.
package agent

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"github.com/agustine-leo/bw-secrets-agent/internal/bwclient"
	"github.com/agustine-leo/bw-secrets-agent/internal/config"
	"github.com/agustine-leo/bw-secrets-agent/internal/runner"
	"github.com/agustine-leo/bw-secrets-agent/internal/tmpl"
)

// Agent manages the polling loop: refresh secrets → render templates → exec on change.
type Agent struct {
	mu     sync.RWMutex
	cfg    *config.Config
	client *bwclient.Client

	// reloadCh receives a new *config.Config when SIGHUP triggers a reload.
	reloadCh chan *config.Config
}

func New(cfg *config.Config) *Agent {
	return &Agent{
		cfg:      cfg,
		reloadCh: make(chan *config.Config, 1),
	}
}

// Reload enqueues a config reload. Safe to call from any goroutine.
func (a *Agent) Reload(cfg *config.Config) {
	select {
	case a.reloadCh <- cfg:
	default:
		// A reload is already pending; drop this one — the pending one is newer enough.
	}
}

// Run starts the agent and blocks until ctx is done.
func (a *Agent) Run(ctx context.Context) error {
	cfg := a.getCfg()

	client := newClient(cfg)
	a.setClient(client)

	// Render immediately before starting the ticker.
	if err := a.tick(ctx, cfg, client); err != nil {
		slog.Error("initial render cycle failed", "err", err)
		if cfg.TemplateConfig.ExitOnRetryFailure {
			return err
		}
	}

	ticker := time.NewTicker(cfg.TemplateConfig.RenderInterval)
	defer ticker.Stop()
	slog.Info("agent started",
		"interval", cfg.TemplateConfig.RenderInterval,
		"templates", len(cfg.Templates),
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case newCfg := <-a.reloadCh:
			slog.Info("applying config reload")
			a.setCfg(newCfg)
			cfg = newCfg
			// Recreate client if the access token changed.
			if newCfg.AutoAuth.AccessToken != client.AccessToken() {
				client = newClient(newCfg)
				a.setClient(client)
			}
			// Restart ticker if the interval changed.
			ticker.Reset(newCfg.TemplateConfig.RenderInterval)

		case <-ticker.C:
			cfg = a.getCfg()
			client = a.getClient()
			if err := a.tick(ctx, cfg, client); err != nil {
				slog.Error("render cycle failed", "err", err)
				if cfg.TemplateConfig.ExitOnRetryFailure {
					return err
				}
			}
		}
	}
}

// RunOnce performs a single refresh + render cycle and returns.
func (a *Agent) RunOnce(ctx context.Context) error {
	cfg := a.getCfg()
	client := newClient(cfg)
	return a.tick(ctx, cfg, client)
}

func (a *Agent) tick(ctx context.Context, cfg *config.Config, client *bwclient.Client) error {
	slog.Debug("refreshing secrets")
	if err := client.Refresh(ctx); err != nil {
		return fmt.Errorf("refreshing secrets: %w", err)
	}

	renderer := tmpl.NewRenderer(client)
	for _, t := range cfg.Templates {
		if err := renderTemplate(ctx, renderer, t); err != nil {
			// Log and continue — one bad template should not block others.
			slog.Error("template render failed", "destination", t.Destination, "err", err)
		}
	}
	return nil
}

func renderTemplate(ctx context.Context, r *tmpl.Renderer, tpl *config.Template) error {
	var source []byte
	var err error
	if tpl.Source != "" {
		source, err = os.ReadFile(tpl.Source)
		if err != nil {
			return fmt.Errorf("reading source %q: %w", tpl.Source, err)
		}
	} else {
		source = []byte(tpl.Contents)
	}

	rendered, err := r.Render(tpl, source)
	if err != nil {
		return err
	}

	// Skip write if the destination already has identical content.
	if existing, err := os.ReadFile(tpl.Destination); err == nil && bytes.Equal(existing, rendered) {
		slog.Debug("destination unchanged, skipping", "destination", tpl.Destination)
		return nil
	}

	perm, err := parsePerms(tpl.Perms)
	if err != nil {
		return err
	}

	slog.Info("writing template", "destination", tpl.Destination)
	if err := os.WriteFile(tpl.Destination, rendered, perm); err != nil {
		return fmt.Errorf("writing %q: %w", tpl.Destination, err)
	}

	if tpl.Owner != "" || tpl.Group != "" {
		if err := chownFile(tpl.Destination, tpl.Owner, tpl.Group); err != nil {
			return fmt.Errorf("chown %q: %w", tpl.Destination, err)
		}
	}

	return runner.RunExec(ctx, tpl.Exec)
}

func parsePerms(s string) (fs.FileMode, error) {
	if s == "" {
		return 0o644, nil
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid perms %q: must be an octal string like 0640", s)
	}
	return fs.FileMode(v), nil
}

// chownFile sets the destination file's ownership. owner / group may be a
// name or a numeric ID; an empty string means "don't change". Passing -1 to
// os.Chown preserves the existing UID or GID.
func chownFile(path, owner, group string) error {
	uid, gid := -1, -1
	if owner != "" {
		u, err := resolveUID(owner)
		if err != nil {
			return err
		}
		uid = u
	}
	if group != "" {
		g, err := resolveGID(group)
		if err != nil {
			return err
		}
		gid = g
	}
	return os.Chown(path, uid, gid)
}

// resolveUID accepts either a numeric UID or a user name.
func resolveUID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return -1, fmt.Errorf("user %q: %w", s, err)
	}
	return strconv.Atoi(u.Uid)
}

// resolveGID accepts either a numeric GID or a group name.
func resolveGID(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		return n, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return -1, fmt.Errorf("group %q: %w", s, err)
	}
	return strconv.Atoi(g.Gid)
}

func newClient(cfg *config.Config) *bwclient.Client {
	serverURL := ""
	if cfg.Bitwarden != nil {
		serverURL = cfg.Bitwarden.ServerURL
	}
	return bwclient.New(cfg.AutoAuth.AccessToken, serverURL)
}

// Thread-safe cfg / client accessors.

func (a *Agent) getCfg() *config.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

func (a *Agent) setCfg(cfg *config.Config) {
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
}

func (a *Agent) getClient() *bwclient.Client {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.client
}

func (a *Agent) setClient(c *bwclient.Client) {
	a.mu.Lock()
	a.client = c
	a.mu.Unlock()
}
