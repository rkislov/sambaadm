//go:build !unix

package service

import "os"

type ownerStat struct {
	uidName string
	gidName string
}

func fileOwner(info os.FileInfo) (ownerStat, bool) {
	return ownerStat{}, false
}
