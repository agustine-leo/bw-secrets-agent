// Command bw-secrets-agent renders Go-template files from Bitwarden Secrets
// Manager and runs an exec command when their contents change.
//
// See README.md for configuration reference and operational notes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/agustine-leo/bw-secrets-agent/internal/agent"
	"github.com/agustine-leo/bw-secrets-agent/internal/config"
)

var version = "dev"

func main() {
	var (
		configDir = flag.String("config-dir", "config.d", "Directory containing *.hcl config files")
		logLevel  = flag.String("log-level", "", "Log level override: debug, info, warn, error (default from config)")
		once      = flag.Bool("once", false, "Render templates once and exit (no polling)")
		ver       = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *ver {
		fmt.Println("bw-secrets-agent", version)
		return
	}

	cfg, err := config.LoadDir(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// CLI flag overrides config log level.
	level := parseLogLevel(cfg.LogLevel)
	if *logLevel != "" {
		level = parseLogLevel(*logLevel)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if cfg.PIDFile != "" {
		if err := writePID(cfg.PIDFile); err != nil {
			slog.Warn("could not write pid file", "path", cfg.PIDFile, "err", err)
		}
		defer os.Remove(cfg.PIDFile)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	a := agent.New(cfg)

	if *once {
		if err := a.RunOnce(ctx); err != nil {
			slog.Error("render failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// SIGHUP → reload config without restarting.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			slog.Info("SIGHUP received, reloading config")
			newCfg, err := config.LoadDir(*configDir)
			if err != nil {
				slog.Error("config reload failed", "err", err)
				continue
			}
			a.Reload(newCfg)
		}
	}()

	if err := a.Run(ctx); err != nil && err != context.Canceled {
		slog.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func writePID(path string) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
}
