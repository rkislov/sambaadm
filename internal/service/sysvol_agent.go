package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/adremote"
	"sambaadm/internal/agent"
)

// sysvolShare preserves the editor's filesystem contract while delegating
// every DC file operation to that DC's registered helper.
type sysvolShare struct {
	local   *smb2.Share
	helpers *agent.Client
	node    string
	ctx     context.Context
}
type helperFSRequest struct {
	Path     string
	To       string
	Flags    int
	Mode     os.FileMode
	Offset   int64
	Size     int64
	Data     []byte
	Security uint32
}
type helperFileInfo struct {
	Filename string
	Length   int64
	FileMode os.FileMode
	Modified time.Time
}

func rootDSEHostRequest() *ldap.SearchRequest {
	return ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName"}, nil)
}
func (f helperFileInfo) Name() string       { return f.Filename }
func (f helperFileInfo) Size() int64        { return f.Length }
func (f helperFileInfo) Mode() os.FileMode  { return f.FileMode }
func (f helperFileInfo) ModTime() time.Time { return f.Modified }
func (f helperFileInfo) IsDir() bool        { return f.FileMode.IsDir() }
func (f helperFileInfo) Sys() any           { return nil }
func helperInfo(f os.FileInfo) helperFileInfo {
	return helperFileInfo{f.Name(), f.Size(), f.Mode(), f.ModTime()}
}
func (s *GPOService) sysvol(ctx context.Context, remote *adremote.Client, port int, fn func(*sysvolShare) error) error {
	if s.helpers != nil {
		node := remote.Host
		// A forwarded LDAP port may use localhost; use the authenticated DC name.
		if !s.helpers.Has(node) && s.remote != nil && strings.EqualFold(remote.Host, s.remote.Host) {
			c, e := s.ldap.Conn(ctx)
			if e != nil {
				return e
			}
			r, e := c.Search(rootDSEHostRequest())
			if e != nil {
				return e
			}
			if len(r.Entries) != 1 {
				return fmt.Errorf("missing DC identity")
			}
			node = r.Entries[0].GetEqualFoldAttributeValue("dNSHostName")
		}
		if !s.helpers.Has(node) {
			return fmt.Errorf("sambaadm-helper is required for DC %s", node)
		}
		return fn(&sysvolShare{helpers: s.helpers, node: node, ctx: ctx})
	}
	// A session identity must never silently become the configured service
	// account when no helper is available (including embedded web setups).
	if _, present, err := agent.OperationCredentials(ctx); err != nil {
		return err
	} else if present {
		return fmt.Errorf("session SYSVOL credentials require a registered sambaadm-helper")
	}
	return remote.SYSVOL(ctx, port, func(sh *smb2.Share) error { return fn(&sysvolShare{local: sh, ctx: ctx}) })
}
func (s *sysvolShare) call(op string, in helperFSRequest, out any) error {
	return s.helpers.Call(s.ctx, s.node, "sysvol."+op, in, out)
}
func (s *sysvolShare) Lstat(p string) (os.FileInfo, error) {
	if s.local != nil {
		return s.local.Lstat(p)
	}
	var out helperFileInfo
	e := s.call("stat", helperFSRequest{Path: p}, &out)
	return out, e
}
func (s *sysvolShare) Stat(p string) (os.FileInfo, error) { return s.Lstat(p) }
func (s *sysvolShare) ReadDir(p string) ([]os.FileInfo, error) {
	if s.local != nil {
		return s.local.ReadDir(p)
	}
	var out []helperFileInfo
	e := s.call("list", helperFSRequest{Path: p}, &out)
	files := []os.FileInfo{}
	for _, f := range out {
		files = append(files, f)
	}
	return files, e
}
func (s *sysvolShare) ReadFile(p string) ([]byte, error) {
	if s.local != nil {
		return s.local.ReadFile(p)
	}
	var out []byte
	e := s.call("read", helperFSRequest{Path: p, Size: consistencyBytes}, &out)
	return out, e
}
func (s *sysvolShare) WriteFile(p string, b []byte, m os.FileMode) error {
	if s.local != nil {
		return s.local.WriteFile(p, b, m)
	}
	return s.call("write-file", helperFSRequest{Path: p, Data: b, Mode: m}, nil)
}
func (s *sysvolShare) Mkdir(p string, m os.FileMode) error {
	if s.local != nil {
		return s.local.Mkdir(p, m)
	}
	return s.call("mkdir", helperFSRequest{Path: p, Mode: m}, nil)
}
func (s *sysvolShare) MkdirAll(p string, m os.FileMode) error {
	if s.local != nil {
		return s.local.MkdirAll(p, m)
	}
	return s.call("mkdir-all", helperFSRequest{Path: p, Mode: m}, nil)
}
func (s *sysvolShare) Remove(p string) error {
	if s.local != nil {
		return s.local.Remove(p)
	}
	return s.call("remove", helperFSRequest{Path: p}, nil)
}
func (s *sysvolShare) RemoveAll(p string) error {
	if s.local != nil {
		return s.local.RemoveAll(p)
	}
	return s.call("remove-tree", helperFSRequest{Path: p}, nil)
}
func (s *sysvolShare) Rename(p, to string) error {
	if s.local != nil {
		return s.local.Rename(p, to)
	}
	return s.call("rename", helperFSRequest{Path: p, To: to}, nil)
}
func (s *sysvolShare) SecurityInfoRaw(p string, flags smb2.SecurityInformationRequestFlags) ([]byte, error) {
	if s.local != nil {
		return s.local.SecurityInfoRaw(p, flags)
	}
	var out []byte
	e := s.call("get-acl", helperFSRequest{Path: p, Security: uint32(flags)}, &out)
	return out, e
}
func (s *sysvolShare) SetSecurityInfoRaw(p string, flags smb2.SecurityInformationRequestFlags, b adremote.SecurityBytes) error {
	if s.local != nil {
		return s.local.SetSecurityInfoRaw(p, flags, b)
	}
	return s.call("set-acl", helperFSRequest{Path: p, Security: uint32(flags), Data: []byte(b)}, nil)
}
func (s *sysvolShare) OpenFile(p string, flags int, m os.FileMode) (policyFile, error) {
	if s.local != nil {
		return s.local.OpenFile(p, flags, m)
	}
	if e := s.call("open", helperFSRequest{Path: p, Flags: helperOpenFlags(flags), Mode: m}, nil); e != nil {
		return nil, e
	}
	return &helperPolicyFile{share: s, path: p, flags: flags}, nil
}

// os.O_* values differ across operating systems; never put them on the wire.
func helperOpenFlags(flags int) int {
	out := 0
	if flags&os.O_WRONLY != 0 {
		out |= 1
	}
	if flags&os.O_RDWR != 0 {
		out |= 2
	}
	if flags&os.O_CREATE != 0 {
		out |= 4
	}
	if flags&os.O_EXCL != 0 {
		out |= 8
	}
	if flags&os.O_TRUNC != 0 {
		out |= 16
	}
	if flags&os.O_APPEND != 0 {
		out |= 32
	}
	return out
}
func helperNativeOpenFlags(flags int) (int, error) {
	if flags & ^63 != 0 || flags&3 == 3 {
		return 0, fmt.Errorf("unsupported helper open flags")
	}
	out := os.O_RDONLY
	for bit, native := range map[int]int{1: os.O_WRONLY, 2: os.O_RDWR, 4: os.O_CREATE, 8: os.O_EXCL, 16: os.O_TRUNC, 32: os.O_APPEND} {
		if flags&bit != 0 {
			out |= native
		}
	}
	return out, nil
}

type helperPolicyFile struct {
	share  *sysvolShare
	path   string
	flags  int
	offset int64
	closed bool
}

func (f *helperPolicyFile) Stat() (os.FileInfo, error) {
	if f.closed {
		return nil, os.ErrClosed
	}
	return f.share.Lstat(f.path)
}
func (f *helperPolicyFile) Read(b []byte) (int, error) {
	if f.closed {
		return 0, os.ErrClosed
	}
	var out []byte
	e := f.share.call("read-at", helperFSRequest{Path: f.path, Offset: f.offset, Size: int64(len(b))}, &out)
	if e != nil {
		return 0, e
	}
	n := copy(b, out)
	f.offset += int64(n)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func (f *helperPolicyFile) Write(b []byte) (int, error) {
	n, e := f.WriteAt(b, f.offset)
	f.offset += int64(n)
	return n, e
}
func (f *helperPolicyFile) WriteAt(b []byte, off int64) (int, error) {
	if f.closed {
		return 0, os.ErrClosed
	}
	if f.flags&(os.O_WRONLY|os.O_RDWR) == 0 {
		return 0, os.ErrPermission
	}
	var n int
	e := f.share.call("write-at", helperFSRequest{Path: f.path, Offset: off, Data: b}, &n)
	return n, e
}
func (f *helperPolicyFile) Truncate(n int64) error {
	if f.closed {
		return os.ErrClosed
	}
	if f.flags&(os.O_WRONLY|os.O_RDWR) == 0 {
		return os.ErrPermission
	}
	return f.share.call("truncate", helperFSRequest{Path: f.path, Size: n}, nil)
}
func (f *helperPolicyFile) Sync() error {
	if f.closed {
		return os.ErrClosed
	}
	return f.share.call("sync", helperFSRequest{Path: f.path}, nil)
}
func (f *helperPolicyFile) Close() error {
	if f.closed {
		return os.ErrClosed
	}
	f.closed = true
	return nil
}
