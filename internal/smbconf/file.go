package smbconf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// File is a parsed smb.conf-style configuration.
type File struct {
	mu       sync.Mutex
	path     string
	order    []string // section names in order (first occurrence)
	sections map[string]*Section
	preamble []string // comments/blank lines before first section
}

// Section is a named [share] block.
type Section struct {
	Name   string
	Keys   []Key   // preserve order
	index  map[string]int
	prefix []string // comments immediately before section header
}

// Key is a parameter assignment.
type Key struct {
	Name  string
	Value string
}

// ParseFile reads and parses an smb.conf file.
func ParseFile(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	doc, err := Parse(f)
	if err != nil {
		return nil, err
	}
	doc.path = path
	return doc, nil
}

// Parse reads smb.conf content from r.
func Parse(r io.Reader) (*File, error) {
	doc := &File{
		sections: make(map[string]*Section),
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var pending []string
	var cur *Section

	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			pending = append(pending, raw)
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" {
				return nil, fmt.Errorf("empty section name")
			}
			key := strings.ToLower(name)
			if existing, ok := doc.sections[key]; ok {
				cur = existing
				pending = nil
				continue
			}
			sec := &Section{
				Name:   name,
				index:  make(map[string]int),
				prefix: append([]string{}, pending...),
			}
			pending = nil
			doc.sections[key] = sec
			doc.order = append(doc.order, key)
			cur = sec
			continue
		}

		if cur == nil {
			doc.preamble = append(doc.preamble, pending...)
			pending = nil
			doc.preamble = append(doc.preamble, raw)
			continue
		}

		// Flush pending comments into section as ignored (keep before next key by attaching to preamble of key — drop into prefix of section body as raw comments via dummy).
		for _, p := range pending {
			// Store comments as keys with empty name to preserve roughly — skip; comments inside sections are dropped on rewrite for simplicity.
			_ = p
		}
		pending = nil

		name, value, ok := splitKV(line)
		if !ok {
			continue
		}
		cur.set(name, value)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return doc, nil
}

func splitKV(line string) (name, value string, ok bool) {
	// strip inline comments when preceded by whitespace
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
			line = strings.TrimSpace(line[:i])
		}
	}
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", "", false
	}
	name = strings.TrimSpace(line[:eq])
	value = strings.TrimSpace(line[eq+1:])
	if name == "" {
		return "", "", false
	}
	return name, value, true
}

func (s *Section) set(name, value string) {
	key := strings.ToLower(name)
	if i, ok := s.index[key]; ok {
		s.Keys[i].Value = value
		s.Keys[i].Name = name
		return
	}
	s.index[key] = len(s.Keys)
	s.Keys = append(s.Keys, Key{Name: name, Value: value})
}

// Path returns the source path if loaded from disk.
func (f *File) Path() string { return f.path }

// SectionNames returns section names in file order (original casing).
func (f *File) SectionNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.order))
	for _, k := range f.order {
		if sec := f.sections[k]; sec != nil {
			out = append(out, sec.Name)
		}
	}
	return out
}

// Get returns a section by name (case-insensitive).
func (f *File) Get(name string) (*Section, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sec, ok := f.sections[strings.ToLower(name)]
	return sec, ok
}

// GetParam returns a parameter value from a section.
func (f *File) GetParam(section, key string) (string, bool) {
	sec, ok := f.Get(section)
	if !ok {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := sec.index[strings.ToLower(key)]
	if !ok {
		return "", false
	}
	return sec.Keys[i].Value, true
}

// EnsureSection creates a section if missing and returns it.
func (f *File) EnsureSection(name string) *Section {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.ToLower(name)
	if sec, ok := f.sections[key]; ok {
		return sec
	}
	sec := &Section{Name: name, index: make(map[string]int)}
	f.sections[key] = sec
	f.order = append(f.order, key)
	return sec
}

// SetParam sets a key in a section (creates section if needed).
func (f *File) SetParam(section, key, value string) {
	sec := f.EnsureSection(section)
	f.mu.Lock()
	defer f.mu.Unlock()
	sec.set(key, value)
}

// DeleteParam removes a key from a section.
func (f *File) DeleteParam(section, key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	sec, ok := f.sections[strings.ToLower(section)]
	if !ok {
		return false
	}
	k := strings.ToLower(key)
	i, ok := sec.index[k]
	if !ok {
		return false
	}
	sec.Keys = append(sec.Keys[:i], sec.Keys[i+1:]...)
	sec.index = make(map[string]int, len(sec.Keys))
	for j, kv := range sec.Keys {
		sec.index[strings.ToLower(kv.Name)] = j
	}
	return true
}

// DeleteSection removes a section.
func (f *File) DeleteSection(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := strings.ToLower(name)
	if _, ok := f.sections[key]; !ok {
		return false
	}
	delete(f.sections, key)
	out := f.order[:0]
	for _, k := range f.order {
		if k != key {
			out = append(out, k)
		}
	}
	f.order = out
	return true
}

// ParamsMap returns all parameters of a section.
func (s *Section) ParamsMap() map[string]string {
	out := make(map[string]string, len(s.Keys))
	for _, k := range s.Keys {
		out[strings.ToLower(k.Name)] = k.Value
	}
	return out
}

// WriteTo serializes the configuration.
func (f *File) WriteTo(w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	bw := bufio.NewWriter(w)
	for _, line := range f.preamble {
		if _, err := bw.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	if len(f.preamble) > 0 {
		if _, err := bw.WriteString("\n"); err != nil {
			return err
		}
	}
	for i, key := range f.order {
		sec := f.sections[key]
		if sec == nil {
			continue
		}
		for _, p := range sec.prefix {
			if _, err := bw.WriteString(p + "\n"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(bw, "[%s]\n", sec.Name); err != nil {
			return err
		}
		for _, k := range sec.Keys {
			if _, err := fmt.Fprintf(bw, "   %s = %s\n", k.Name, k.Value); err != nil {
				return err
			}
		}
		if i < len(f.order)-1 {
			if _, err := bw.WriteString("\n"); err != nil {
				return err
			}
		}
	}
	return bw.Flush()
}

// SaveAtomic writes to path (or f.path) via temp + rename and keeps a .bak copy.
func (f *File) SaveAtomic(path string) error {
	if path == "" {
		path = f.path
	}
	if path == "" {
		return fmt.Errorf("no path to save")
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".smb.conf.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := f.WriteTo(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil {
		bak := path + ".bak"
		_ = os.Remove(bak)
		if err := os.Rename(path, bak); err != nil {
			// copy fallback if rename across devices fails later — same dir should be fine
			return fmt.Errorf("backup %s: %w", path, err)
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	f.path = path
	return nil
}
