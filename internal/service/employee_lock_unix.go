//go:build !windows

package service

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func lockEmployeeFile(dir string) (func(), error) {
	f, e := os.OpenFile(filepath.Join(dir, "operations.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrEmployeeBusy
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func syncEmployeeDirectory(dir string) error {
	f, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
