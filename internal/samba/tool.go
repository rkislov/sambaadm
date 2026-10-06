package samba

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Default binary name.
const DefaultBinary = "samba-tool"

// Runner executes samba-tool subcommands.
type Runner struct {
	Binary string
	Timeout time.Duration
}

// NewRunner creates a samba-tool runner.
func NewRunner(binary string) *Runner {
	if binary == "" {
		binary = DefaultBinary
	}
	return &Runner{Binary: binary, Timeout: 2 * time.Minute}
}

// Result is stdout/stderr from a successful or failed run.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run executes samba-tool with args. Returns error if exit != 0 or binary missing.
func (r *Runner) Run(ctx context.Context, args ...string) (*Result, error) {
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, r.Binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := &Result{
		Stdout: strings.TrimSpace(stdout.String()),
		Stderr: strings.TrimSpace(stderr.String()),
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else if ctx.Err() != nil {
			return res, fmt.Errorf("samba-tool %s: %w", strings.Join(args, " "), ctx.Err())
		} else {
			return res, fmt.Errorf("samba-tool %s: %w (is samba-tool installed?)", strings.Join(args, " "), err)
		}
		msg := res.Stderr
		if msg == "" {
			msg = res.Stdout
		}
		if msg == "" {
			msg = err.Error()
		}
		return res, fmt.Errorf("samba-tool %s: %s", strings.Join(args, " "), msg)
	}
	return res, nil
}

// Available reports whether samba-tool is on PATH.
func (r *Runner) Available() bool {
	_, err := exec.LookPath(r.Binary)
	return err == nil
}

// Lines splits stdout into non-empty trimmed lines.
func (r *Result) Lines() []string {
	if r == nil || r.Stdout == "" {
		return nil
	}
	raw := strings.Split(r.Stdout, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
