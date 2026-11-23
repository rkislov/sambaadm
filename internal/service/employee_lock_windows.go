//go:build windows

package service

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func lockEmployeeFile(dir string) (func(), error) {
	f, e := os.OpenFile(filepath.Join(dir, "operations.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	overlapped := new(windows.Overlapped)
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); e != nil {
		f.Close()
		return nil, ErrEmployeeBusy
	}
	return func() { windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, overlapped); f.Close() }, nil
}
func syncEmployeeDirectory(dir string) error { return nil }
