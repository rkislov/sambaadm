//go:build windows

package service

import "os"

func certificateRootOwned(os.FileInfo) bool { return false }
