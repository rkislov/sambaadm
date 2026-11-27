//go:build unix

package service

import (
	"fmt"
	"os"
	"syscall"
)

func shareMapFileIdentity(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d:%v", st.Dev, st.Ino, st.Uid, st.Gid, info.Mode())
}
