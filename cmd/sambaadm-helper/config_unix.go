//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func checkHelperConfig(filename string) error {
	st, e := os.Lstat(filename)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("helper configuration must be a regular file not writable by group or others")
	}
	if os.Geteuid() == 0 {
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return fmt.Errorf("privileged helper configuration must be root-owned")
		}
	}
	return nil
}
