package samba

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Default binary name.
const DefaultBinary = "samba-tool"

// Runner executes samba-tool subcommands.
type Runner struct {
	Binary   string
	Timeout  time.Duration
	Username string
	Password func() string
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

	// Bind tool operations to the same configured service identity as LDAP.
	// PASSWD_FILE is supported by Samba credentials guessing; never put a
	// service password in argv, inherited PASSWD, or diagnostic arguments.
	var credentialPath string
	if r.Username != "" {
		if strings.Contains(r.Username, "%") {
			return nil, fmt.Errorf("samba-tool username must not contain an inline password")
		}
		if r.Password == nil {
			return nil, fmt.Errorf("samba-tool service password is not configured")
		}
		password := r.Password()
		if password == "" {
			return nil, fmt.Errorf("samba-tool service password is not configured")
		}
		if strings.ContainsAny(password, "\r\n") {
			return nil, fmt.Errorf("samba-tool password must not contain line breaks")
		}
		file, err := os.CreateTemp("", "sambaadm-credentials-*")
		if err != nil {
			return nil, fmt.Errorf("create Samba credential file: %w", err)
		}
		credentialPath = file.Name()
		defer os.Remove(credentialPath)
		if _, err = file.WriteString(password); err != nil {
			file.Close()
			return nil, fmt.Errorf("write Samba credential file: %w", err)
		}
		if err = file.Close(); err != nil {
			return nil, fmt.Errorf("close Samba credential file: %w", err)
		}
		args = append(append([]string(nil), args...), "--username="+r.Username)
	}
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	if credentialPath != "" {
		env := []string{}
		for _, value := range os.Environ() {
			key, _, _ := strings.Cut(value, "=")
			if key != "PASSWD" && key != "PASSWD_FD" && key != "PASSWD_FILE" {
				env = append(env, value)
			}
		}
		cmd.Env = append(env, "PASSWD_FILE="+credentialPath)
	}
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
