package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/policy"
)

const templateCacheLimit = 64 << 20

// Gob preserves registry literals, enum values and boolean encodings that are
// deliberately omitted from the public policy JSON. No credentials are stored.
func init() { gob.Register([]string{}) }

type templateCatalog struct {
	Schema      int
	Key         string
	Loaded      time.Time
	Source      string
	Definitions []policy.Definition
}
type freshTemplatesKey struct{}

func encodeTemplateCatalog(c templateCatalog) ([]byte, error) {
	var b bytes.Buffer
	if e := gob.NewEncoder(&b).Encode(c); e != nil {
		return nil, e
	}
	if b.Len() > templateCacheLimit {
		return nil, fmt.Errorf("template cache exceeds 64 MiB")
	}
	return b.Bytes(), nil
}
func decodeTemplateCatalog(raw []byte) (templateCatalog, error) {
	var c templateCatalog
	if len(raw) > templateCacheLimit {
		return c, fmt.Errorf("template cache exceeds 64 MiB")
	}
	e := gob.NewDecoder(bytes.NewReader(raw)).Decode(&c)
	// Gob collapses empty slices. ADMX list defaults must remain [] rather
	// than null so cached and freshly parsed optimistic revisions agree.
	for i := range c.Definitions {
		for j := range c.Definitions[i].Fields {
			f := &c.Definitions[i].Fields[j]
			if values, ok := f.Default.([]string); ok && len(values) == 0 {
				f.Default = []string{}
			}
		}
	}
	if e == nil && (c.Schema != 1 || len(c.Definitions) == 0) {
		e = fmt.Errorf("invalid template cache")
	}
	return c, e
}
func catalogResponse(defs []policy.Definition, source string) (helperADMXCatalog, error) {
	raw, e := encodeTemplateCatalog(templateCatalog{Schema: 1, Definitions: defs, Source: source})
	return helperADMXCatalog{Definitions: defs, Source: source, Encoded: raw, AllTemplates: true}, e
}
func decodedCatalog(out helperADMXCatalog) ([]policy.Definition, string, error) {
	if len(out.Encoded) == 0 {
		return out.Definitions, out.Source, nil
	} // Older helper compatibility.
	c, e := decodeTemplateCatalog(out.Encoded)
	return c.Definitions, c.Source, e
}
func (s *GPOService) templateCacheKey(share *sysvolShare, domain string) (string, error) {
	identity := "service"
	if s.remote != nil {
		identity += "/" + s.remote.Host + "/" + s.remote.User
	}
	if credentials, present, e := agent.OperationCredentials(share.ctx); e != nil {
		return "", e
	} else if present {
		identity = "session/" + strings.ToLower(credentials.Username)
	}
	nodes := ""
	if s.helpers != nil {
		nodes = fmt.Sprintf("%v/%s", s.helpers.Config.Nodes, s.helpers.Config.HostNode)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(domain+"\x00"+share.node+"\x00"+s.gpoCfg.ADMXPath+"\x00"+nodes+"\x00"+identity))), nil
}
func (s *GPOService) templateCacheDir() string {
	if !filepath.IsAbs(s.gpoCfg.ManagedEditorFile) {
		return ""
	}
	return filepath.Join(filepath.Dir(s.gpoCfg.ManagedEditorFile), "admx-cache")
}
func (s *GPOService) loadTemplateCache(key string) *templateCatalog {
	s.catalogMu.Lock()
	defer s.catalogMu.Unlock()
	if c := s.catalogs[key]; c != nil {
		return c
	}
	file := filepath.Join(s.templateCacheDir(), key+".gob")
	info, e := os.Lstat(file)
	if e != nil || !info.Mode().IsRegular() || info.Size() > templateCacheLimit || info.Mode().Perm()&0077 != 0 {
		return nil
	}
	f, e := os.Open(file)
	if e != nil {
		return nil
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, templateCacheLimit+1))
	if e != nil {
		return nil
	}
	c, e := decodeTemplateCatalog(raw)
	if e != nil || c.Key != key {
		return nil
	}
	s.rememberCatalog(&c)
	return &c
}
func (s *GPOService) rememberCatalog(c *templateCatalog) {
	if s.catalogs == nil {
		s.catalogs = map[string]*templateCatalog{}
	}
	if len(s.catalogs) >= 8 {
		for key := range s.catalogs {
			delete(s.catalogs, key)
			break
		}
	}
	s.catalogs[c.Key] = c
}
func (s *GPOService) storeTemplateCache(c templateCatalog) error {
	raw, e := encodeTemplateCatalog(c)
	if e != nil {
		return e
	}
	dir := s.templateCacheDir()
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("template cache directory must be private and not a symlink")
	}
	f, e := os.CreateTemp(dir, ".import-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), filepath.Join(dir, c.Key+".gob")); e != nil {
		return e
	}
	s.catalogMu.Lock()
	s.rememberCatalog(&c)
	s.catalogMu.Unlock()

	return nil
}
func (s *GPOService) editorDefinitions(share *sysvolShare, domain string) ([]policy.Definition, string, error) {
	if share == nil || s.templateCacheDir() == "" {
		return s.loadEditorDefinitions(share, domain)
	}
	key, e := s.templateCacheKey(share, domain)
	if e != nil {
		return nil, "", e
	}
	fresh, _ := share.ctx.Value(freshTemplatesKey{}).(bool)
	if !fresh {
		if c := s.loadTemplateCache(key); c != nil {
			return c.Definitions, c.Source, nil
		}
	}
	defs, source, e := s.loadEditorDefinitions(share, domain)
	if e != nil {
		return nil, "", e
	}
	// Save-time validation reads the live source without replacing the imported catalogue.
	if fresh {
		return defs, source, nil
	}
	// Cache failure must not turn a successful read into an unavailable editor.
	if e := s.storeTemplateCache(templateCatalog{Schema: 1, Key: key, Loaded: time.Now().UTC(), Source: source, Definitions: defs}); e != nil {
		slog.Warn("cannot persist ADMX cache", "err", e)
	}
	return defs, source, nil
}

// RefreshTemplateCache imports the current identity's complete supported catalog.
func (s *GPOService) RefreshTemplateCache(ctx context.Context) (int, error) {
	if s.remote == nil {
		return 0, fmt.Errorf("SYSVOL connection is not configured")
	}
	if s.templateCacheDir() == "" {
		return 0, fmt.Errorf("server.settings_dir is not configured")
	}
	if e := s.lockEditor(ctx); e != nil {
		return 0, e
	}
	defer s.editorMu.Unlock()
	var count int
	e := s.sysvol(ctx, s.remote, s.gpoCfg.SMBPort, func(share *sysvolShare) error {
		dns, e := s.domainDNS(ctx)
		if e != nil {
			return e
		}
		key, e := s.templateCacheKey(share, dns)
		if e != nil {
			return e
		}
		defs, source, e := s.loadEditorDefinitions(share, dns)
		if e != nil {
			return e
		}
		if e = s.storeTemplateCache(templateCatalog{Schema: 1, Key: key, Loaded: time.Now().UTC(), Source: source, Definitions: defs}); e != nil {
			return e
		}
		count = len(defs)
		return nil
	})
	return count, e
}
func (s *GPOService) lockEditor(ctx context.Context) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		if s.editorMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (s *GPOService) templateImportedAt(share *sysvolShare, domain string) *time.Time {
	if share == nil || s.templateCacheDir() == "" {
		return nil
	}
	key, e := s.templateCacheKey(share, domain)
	if e != nil {
		return nil
	}
	if c := s.loadTemplateCache(key); c != nil {
		stamp := c.Loaded
		return &stamp
	}
	return nil
}
