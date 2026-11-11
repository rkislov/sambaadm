package service

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/config"
)

//go:embed helper_policy_install.py
var localPolicyInstallScript string

type policyInstallRequest struct {
	Target      string
	ACL         []byte
	Files       map[string][]byte
	Permissions map[string][]byte
}

func runLocalPolicyInstall(ctx context.Context, cfg *config.Config, conf string, raw json.RawMessage) error {
	credentials, present, err := agent.OperationCredentials(ctx)
	if err != nil {
		return err
	}
	if !present || os.Geteuid() != 0 {
		return fmt.Errorf("local SYSVOL staging requires root and domain credentials from the current session")
	}
	var request policyInstallRequest
	if err := decodeHost(raw, &request); err != nil {
		return err
	}
	target, err := helperSYSVOLPath(cfg.Helper.SYSVOLPrefix, request.Target)
	if err != nil {
		return err
	}
	request.Target = strings.ReplaceAll(target, `\`, "/")
	input := struct {
		policyInstallRequest
		Config string
		Port   int
		User   string
		Secret string
	}{request, conf, cfg.GPO.SMBPort, credentials.Username, credentials.Password}
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	defer clear(data)
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-c", localPolicyInstallScript)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 10 * time.Second
	output, err := cmd.Output()
	var result struct {
		OK    bool
		Error string
	}
	if json.Unmarshal(output, &result) == nil {
		if err == nil && result.OK {
			return nil
		}
		if result.Error != "" {
			return agent.RedactCredentialError(fmt.Errorf("SYSVOL policy install: %s", result.Error), credentials)
		}
	}
	return fmt.Errorf("SYSVOL policy install did not return a result; verify the destination before retrying")
}
