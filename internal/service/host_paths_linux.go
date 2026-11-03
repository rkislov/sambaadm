package service

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func pinHostPath(root *os.Root, rel, original string) (*pinnedHostPath, error) {
	f, e := root.OpenFile(rel, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !st.IsDir() && !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("share path must be a regular file or directory, never a symlink or device")
	}
	return &pinnedHostPath{File: f, Path: fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), f.Fd())}, nil
}
