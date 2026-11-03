//go:build !linux

package service

import "os"

// Native non-Linux services are retained for library compatibility; deployed
// privileged helpers reject non-Linux host operation modes at startup.
func pinHostPath(root *os.Root, rel, original string) (*pinnedHostPath, error) {
	f, e := root.Open(rel)
	if e != nil {
		return nil, e
	}
	return &pinnedHostPath{File: f, Path: original}, nil
}
