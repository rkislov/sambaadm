//go:build windows

package agent

import "os"

func trustedOwner(os.FileInfo) bool { return true }
