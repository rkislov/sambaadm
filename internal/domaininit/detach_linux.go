//go:build linux

package domaininit

import (
	"os/exec"
	"syscall"
)

// The bootstrap console may close while the privileged worker finishes.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
