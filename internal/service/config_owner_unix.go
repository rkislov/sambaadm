//go:build !windows

package service

import (
	"os"
	"syscall"
)

func preserveConfigOwner(f *os.File, info os.FileInfo) error {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return f.Chown(int(stat.Uid), int(stat.Gid))
	}
	return nil
}
