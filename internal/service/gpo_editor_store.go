package service

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sambaadm/internal/policy"
	"strings"

	smb2 "github.com/cloudsoda/go-smb2"
)

// The editor only sees paths relative to one validated GPO in SYSVOL.
// SMB FLUSH makes file data durable; CREATE/DELETE are acknowledged by the DC.
type policyFile interface {
	io.Reader
	io.Writer
	io.WriterAt
	Stat() (os.FileInfo, error)
	Truncate(int64) error
	Sync() error
	Close() error
}
type policyStore interface {
	Lstat(string) (os.FileInfo, error)
	ReadDir(string) ([]os.FileInfo, error)
	Open(string) (policyFile, error)
	OpenFile(string, int, os.FileMode) (policyFile, error)
	Remove(string) error
}
type smbPolicyStore struct {
	share *smb2.Share
	base  string
}

func (s *smbPolicyStore) checked(name string, missing bool) (string, error) {
	if name != "." && (name == "" || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, `\:`)) {
		return "", fmt.Errorf("invalid relative policy path")
	}
	parts := strings.Split(s.base, "/")
	if name != "." {
		parts = append(parts, strings.Split(name, "/")...)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `\:`) {
			return "", fmt.Errorf("invalid SYSVOL component")
		}
	}
	for i := range parts {
		p := strings.Join(parts[:i+1], `\`)
		info, err := s.share.Lstat(p)
		if err != nil {
			if missing && i == len(parts)-1 && os.IsNotExist(err) {
				return p, nil
			}
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) {
			return "", fmt.Errorf("SYSVOL path contains a symlink or non-directory")
		}
	}
	return strings.Join(parts, `\`), nil
}
func (s *smbPolicyStore) Lstat(name string) (os.FileInfo, error) {
	p, e := s.checked(name, false)
	if e != nil {
		return nil, e
	}
	return s.share.Lstat(p)
}
func (s *smbPolicyStore) ReadDir(name string) ([]os.FileInfo, error) {
	p, e := s.checked(name, false)
	if e != nil {
		return nil, e
	}
	return s.share.ReadDir(p)
}
func (s *smbPolicyStore) Open(name string) (policyFile, error) {
	return s.OpenFile(name, os.O_RDONLY, 0)
}
func (s *smbPolicyStore) OpenFile(name string, flags int, mode os.FileMode) (policyFile, error) {
	p, e := s.checked(name, flags&os.O_CREATE != 0)
	if e != nil {
		return nil, e
	}
	return s.share.OpenFile(p, flags, mode)
}
func (s *smbPolicyStore) Remove(name string) error {
	p, e := s.checked(name, false)
	if e != nil {
		return e
	}
	return s.share.Remove(p)
}

// Empty admx_path selects the domain Central Store. An explicit local template
// remains supported for administrators whose domain has no Central Store yet.
func (s *GPOService) editorDefinitions(share *smb2.Share, domain string) ([]policy.Definition, string, error) {
	if s.gpoCfg.ADMXPath != "" {
		defs, err := policy.SystemdDefinitions(s.gpoCfg.ADMXPath)
		return defs, "local ADMX: " + s.gpoCfg.ADMXPath, err
	}
	store := &smbPolicyStore{share: share, base: path.Join(domain, "Policies", "PolicyDefinitions")}
	name, err := policyChild(store, ".", "BaseALTSystemdUnits.admx", false)
	if err != nil {
		return nil, "", fmt.Errorf("ALT ADMX missing from SYSVOL Central Store: %w", err)
	}
	data, err := readPolicyFile(store, name)
	if err != nil {
		return nil, "", err
	}
	if len(data) > 2<<20 {
		return nil, "", fmt.Errorf("ALT ADMX exceeds 2 MiB")
	}
	defs, err := policy.ParseSystemdDefinitions(bytes.NewReader(data))
	return defs, "SYSVOL/" + store.base + "/" + name, err
}
