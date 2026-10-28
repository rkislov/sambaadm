//go:build linux

package service

import "golang.org/x/sys/unix"

func diagnosticWriteAccess(path string, directory bool) (bool, bool) {
	mode := uint32(unix.W_OK)
	if directory {
		mode |= unix.X_OK
	}
	return unix.Faccessat(unix.AT_FDCWD, path, mode, unix.AT_EACCESS) == nil, true
}
