// Package runner executes the optional `exec` block of a template after
// the rendered output has been written to disk.
package runner

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/agustine-leo/bw-secrets-agent/internal/config"
)

// RunExec runs the exec block command after a template is written.
// It is a no-op when e is nil.
func RunExec(ctx context.Context, e *config.ExecConfig) error {
	if e == nil || len(e.Command) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	var cmd *exec.Cmd
	if len(e.Command) == 1 {
		// Single string: run through shell so users can write "systemctl reload app".
		cmd = exec.CommandContext(ctx, "sh", "-c", e.Command[0])
	} else {
		cmd = exec.CommandContext(ctx, e.Command[0], e.Command[1:]...)
	}

	slog.Info("running exec command", "command", e.Command)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		slog.Debug("exec output", "output", string(out))
	}
	if err != nil {
		return fmt.Errorf("exec %v failed: %w\n%s", e.Command, err, out)
	}
	return nil
}
