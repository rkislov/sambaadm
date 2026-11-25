//go:build !linux

package dcdemote

import "os/exec"

func detach(*exec.Cmd) {}
