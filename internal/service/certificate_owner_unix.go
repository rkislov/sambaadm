//go:build !windows

package service

import (
	"os"
	"syscall"
)

func certificateRootOwned(st os.FileInfo) bool {
	owner, ok := st.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == 0
}
