package service

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sambaadm/internal/adremote"
	"sambaadm/internal/policy"
	"sort"
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
	Mkdir(string, os.FileMode) error
	Rename(string, string) error
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

func (s *smbPolicyStore) Mkdir(name string, mode os.FileMode) error {
	p, err := s.checked(name, true)
	if err != nil {
		return err
	}
	return s.share.Mkdir(p, mode)
}

func (s *smbPolicyStore) Rename(from, to string) error {
	a, err := s.checked(from, false)
	if err != nil {
		return err
	}
	b, err := s.checked(to, true)
	if err != nil {
		return err
	}
	return s.share.Rename(a, b)
}

type policySecurityStore interface {
	GetACL(string) ([]byte, error)
	SetACL(string, []byte) error
}

func (s *smbPolicyStore) GetACL(name string) ([]byte, error) {
	p, e := s.checked(name, false)
	if e != nil {
		return nil, e
	}
	return s.share.SecurityInfoRaw(p, smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation)
}
func (s *smbPolicyStore) SetACL(name string, data []byte) error {
	p, e := s.checked(name, false)
	if e != nil {
		return e
	}
	flags := smb2.OwnerSecurityInformation | smb2.GroupSecurityInformation | smb2.DACLSecurityInformation
	if len(data) >= 4 && binary.LittleEndian.Uint16(data[2:4])&0x1000 != 0 {
		flags |= 0x80000000
	} else {
		flags |= 0x20000000
	}
	return s.share.SetSecurityInfoRaw(p, flags, adremote.SecurityBytes(data))
}

// Empty admx_path selects the domain Central Store; a local directory or
// a single ADMX file is also supported. SYSVOL editing always stays remote.
func (s *GPOService) editorDefinitions(share *smb2.Share, domain string) ([]policy.Definition, string, error) {
	var names []string
	var read func(string) ([]byte, error)
	source := ""
	singleFile := false
	if s.gpoCfg.ADMXPath != "" {
		file := s.gpoCfg.ADMXPath
		info, err := os.Stat(file)
		if err != nil {
			return nil, "", err
		}
		dir := file
		if !info.IsDir() {
			singleFile = true
			dir = filepath.Dir(file)
			names = []string{filepath.Base(file)}
		} else {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return nil, "", err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					names = append(names, entry.Name())
				}
			}
		}
		read = func(name string) ([]byte, error) {
			p := dir
			for _, part := range strings.Split(name, "/") {
				entries, err := os.ReadDir(p)
				if err != nil {
					return nil, err
				}
				actual := ""
				for _, entry := range entries {
					if strings.EqualFold(entry.Name(), part) {
						if actual != "" {
							return nil, fmt.Errorf("ambiguous template filename")
						}
						actual = entry.Name()
					}
				}
				if actual == "" {
					return nil, os.ErrNotExist
				}
				p = filepath.Join(p, actual)
			}
			info, err := os.Lstat(p)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() || info.Size() > 4<<20 {
				return nil, fmt.Errorf("invalid template file")
			}
			return os.ReadFile(p)
		}
		source = "local ADMX: " + file
	} else {
		store := &smbPolicyStore{share: share, base: path.Join(domain, "Policies", "PolicyDefinitions")}
		entries, err := store.ReadDir(".")
		if err != nil {
			return nil, "", fmt.Errorf("ALT ADMX missing from SYSVOL Central Store: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				names = append(names, entry.Name())
			}
		}
		read = func(name string) ([]byte, error) {
			actual, err := policyChild(store, path.Dir(name), path.Base(name), false)
			if err != nil { // A missing optional language file is a normal fallback.
				if errors.Is(err, os.ErrNotExist) {
					return nil, os.ErrNotExist
				}
				return nil, err
			}
			return readPolicyFile(store, actual)
		}
		source = "SYSVOL/" + store.base
	}
	sort.Strings(names)
	var defs []policy.Definition
	files, total := 0, 0
	categories := map[string]string{}
	for _, name := range names {
		if (!singleFile && !strings.HasPrefix(strings.ToLower(name), "basealt")) || !strings.HasSuffix(strings.ToLower(name), ".admx") {
			continue
		}
		files++
		if files > 64 {
			return nil, "", fmt.Errorf("too many ALT templates")
		}
		data, err := read(name)
		if err != nil {
			return nil, "", err
		}
		var language []byte
		for _, locale := range []string{"ru-RU", "en-US"} {
			language, err = read(locale + "/" + strings.TrimSuffix(name, path.Ext(name)) + ".adml")
			if err == nil {
				break
			}
			if !os.IsNotExist(err) {
				return nil, "", err
			}
		}
		total += len(data) + len(language)
		if total > 32<<20 {
			return nil, "", fmt.Errorf("ALT template catalog exceeds 32 MiB")
		}
		parsed, err := policy.ParseADMX(name, data, language)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", name, err)
		}
		defs = append(defs, parsed...)
		for key, value := range policy.CategoryLabels(name, data, language) {
			categories[key] = value
		}
	}
	if len(defs) == 0 {
		return nil, "", fmt.Errorf("no ALT policies found; install BaseALT*.admx in Central Store")
	}
	seen := map[string]bool{}
	for i := range defs {
		d := &defs[i]
		if label := categories[d.SupportedOn]; label != "" {
			d.SupportedOn = label
		}
		key := d.Scope + "/" + d.ID
		if seen[key] {
			return nil, "", fmt.Errorf("duplicate policy identity %s", key)
		}
		seen[key] = true
		if label := categories[d.Category]; label != "" {
			d.Category = label
		} else if label := categories[d.Template+"/"+d.Category]; label != "" {
			d.Category = label
		}
	}
	return defs, source, nil
}
