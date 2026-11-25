//go:build !linux

package domaininit

import "os/exec"

func detach(*exec.Cmd) {}
