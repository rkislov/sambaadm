//go:build !windows

package agent

import (
	"os"
	"syscall"
)

func trustedOwner(st os.FileInfo) bool {
	if os.Geteuid() != 0 {
		return true
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0
}
