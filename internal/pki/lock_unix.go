//go:build !windows

package pki

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

func lockAuthority(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "authority.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
