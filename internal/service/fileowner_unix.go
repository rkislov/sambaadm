//go:build unix

package service

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

type ownerStat struct {
	uidName string
	gidName string
}

func fileOwner(info os.FileInfo) (ownerStat, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerStat{}, false
	}
	out := ownerStat{
		uidName: strconv.Itoa(int(st.Uid)),
		gidName: strconv.Itoa(int(st.Gid)),
	}
	if u, err := user.LookupId(strconv.Itoa(int(st.Uid))); err == nil {
		out.uidName = u.Username
	}
	if g, err := user.LookupGroupId(strconv.Itoa(int(st.Gid))); err == nil {
		out.gidName = g.Name
	}
	return out, true
}
