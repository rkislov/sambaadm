//go:build !unix

package service

import (
	"fmt"
	"os"
)

func shareMapFileIdentity(info os.FileInfo) string {
	return fmt.Sprintf("%s:%v:%d", info.Name(), info.Mode(), info.ModTime().UnixNano())
}
