package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ShareDirectory struct {
	Name string `json:"name"`
	Path string `json:"path"`
}
type ShareDirectoryPage struct {
	Directories []ShareDirectory `json:"directories"`
	Next        int              `json:"next,omitempty"`
}

// Relative paths are portable API values, never absolute server paths.
func shareRelativePath(rel string) (string, error) {
	if rel == "" || rel == "." {
		return ".", nil
	}
	if strings.ContainsAny(rel, "\\\x00") || strings.HasPrefix(rel, "/") {
		return "", fmt.Errorf("invalid relative directory path")
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return "", fmt.Errorf("directory must remain inside the selected share")
		}
	}
	return filepath.FromSlash(rel), nil
}

// scopedACL pins the share root, so later path resolution cannot escape it even
// if a directory is renamed or a symlink is changed during the operation.
func (s *ShareService) scopedACL(ctx context.Context, name, rel string) (*FSACLService, string, error) {
	relative, err := shareRelativePath(rel)
	if err != nil {
		return nil, "", err
	}
	sh, err := s.Show(ctx, name)
	if err != nil {
		return nil, "", err
	}
	if sh.Printable || sh.Path == "" {
		return nil, "", fmt.Errorf("select a file share with a directory path")
	}
	pin, err := s.pinPath(sh.Path)
	if err != nil {
		return nil, "", err
	}
	defer pin.Close()
	root, err := os.OpenRoot(pin.Path)
	if err != nil {
		return nil, "", err
	}
	cfg := s.cfg
	cfg.SharesRoot = sh.Path
	cfg.AllowAnyPath = false
	scoped := newShareService(s.audit, cfg)
	return &FSACLService{audit: s.audit, shares: scoped, root: root}, filepath.Join(sh.Path, relative), nil
}

// Directories loads one bounded page without reading the entire directory tree.
func (s *ShareService) Directories(ctx context.Context, name, rel string, offset int) (*ShareDirectoryPage, error) {
	if _, err := shareRelativePath(rel); err != nil {
		return nil, err
	}
	if offset < 0 || offset > 1000000 {
		return nil, fmt.Errorf("invalid directory offset")
	}
	if s.helpers != nil {
		var out ShareDirectoryPage
		err := s.hostCall(ctx, "shares.directories", HostOperation{Name: name, Path: rel, Key: strconv.Itoa(offset)}, &out)
		return &out, err
	}
	acl, path, err := s.scopedACL(ctx, name, rel)
	if err != nil {
		return nil, err
	}
	defer acl.root.Close()
	relative, err := filepath.Rel(acl.shares.cfg.SharesRoot, path)
	if err != nil {
		return nil, err
	}
	dir, err := acl.root.Open(relative)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	for skipped := 0; skipped < offset; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(200, offset-skipped)
		entries, err := dir.ReadDir(n)
		skipped += len(entries)
		if err == io.EOF {
			return &ShareDirectoryPage{Directories: []ShareDirectory{}}, nil
		}
		if err != nil {
			return nil, err
		}
	}
	entries, err := dir.ReadDir(200)
	if err != nil && err != io.EOF {
		return nil, err
	}
	out := &ShareDirectoryPage{Directories: []ShareDirectory{}}
	for _, entry := range entries {
		if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			out.Directories = append(out.Directories, ShareDirectory{Name: entry.Name(), Path: filepath.ToSlash(filepath.Join(relative, entry.Name()))})
		}
	}
	sort.Slice(out.Directories, func(i, j int) bool { return out.Directories[i].Name < out.Directories[j].Name })
	if len(entries) == 200 {
		out.Next = offset + len(entries)
	}
	return out, nil
}

func (s *FSACLService) GetSharePath(ctx context.Context, name, rel string) (*PathACL, error) {
	if _, err := shareRelativePath(rel); err != nil {
		return nil, err
	}
	if s.shares.helpers != nil {
		var out PathACL
		err := s.shares.hostCall(ctx, "shares.path-acl.get", HostOperation{Name: name, Path: rel}, &out)
		return &out, err
	}
	scoped, path, err := s.shares.scopedACL(ctx, name, rel)
	if err != nil {
		return nil, err
	}
	defer scoped.root.Close()
	return scoped.Get(ctx, path)
}
func (s *FSACLService) SetSharePath(ctx context.Context, name, rel string, in SetACLInput, actor, ip string) (*PathACL, error) {
	if _, err := shareRelativePath(rel); err != nil {
		return nil, err
	}
	if s.shares.helpers != nil {
		var out PathACL
		err := s.shares.hostCall(ctx, "shares.path-acl.set", HostOperation{Name: name, Path: rel, Input: hostInput(in), Actor: actor, IP: ip}, &out)
		return &out, err
	}
	scoped, path, err := s.shares.scopedACL(ctx, name, rel)
	if err != nil {
		return nil, err
	}
	defer scoped.root.Close()
	in.Path = path
	// Recursive external tools can follow links beyond a share boundary. The tree
	// editor deliberately changes only the selected object (and its default ACL).
	if in.Recursive || in.DefaultRecursive {
		return nil, fmt.Errorf("recursive changes are unavailable in the directory editor")
	}
	return scoped.Set(ctx, in, actor, ip)
}

// ResolveFileGroup verifies the AD security group and resolves it on the target
// host. A GID from the management host is never used on another file server.
func (s *Services) ResolveFileGroup(ctx context.Context, name string) (map[string]string, error) {
	group, err := s.Groups.Show(ctx, name)
	if err != nil {
		return nil, err
	}
	if group.Category != "security" {
		return nil, fmt.Errorf("select a security group")
	}
	domain, err := s.Domain.Info(ctx)
	if err != nil {
		return nil, err
	}
	if domain.NetBIOS == "" || strings.ContainsAny(domain.NetBIOS+group.SAMAccountName, ":,;\r\n\x00") {
		return nil, fmt.Errorf("invalid domain group name")
	}
	prefix := domain.NetBIOS
	if group.Builtin {
		prefix = "BUILTIN"
	}
	qualified := prefix + "\\" + group.SAMAccountName
	var gid string
	if s.Shares.helpers != nil {
		err = s.Shares.hostCall(ctx, "nss.group", HostOperation{Name: qualified}, &gid)
	} else {
		gid, err = lookupHostGroup(ctx, qualified)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s on the selected server; check winbind/NSS: %w", qualified, err)
	}
	if _, err = strconv.ParseUint(gid, 10, 32); err != nil {
		return nil, fmt.Errorf("invalid group GID")
	}
	return map[string]string{"name": qualified, "gid": gid}, nil
}

func lookupHostGroupName(ctx context.Context, gid string) (string, error) {
	if runtime.GOOS != "linux" {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			return "", err
		}
		return group.Name, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "group", gid).Output()
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) != 4 {
		return "", fmt.Errorf("invalid NSS group response")
	}
	return fields[0], nil
}
