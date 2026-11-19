package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ObjectBackupSummary struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Actor   string    `json:"actor"`
	BaseDN  string    `json:"baseDN"`
	Count   int       `json:"count"`
}

func (b *ObjectBackup) Summary() ObjectBackupSummary {
	return ObjectBackupSummary{b.ID, b.Created, b.Actor, b.BaseDN, len(b.Objects)}
}

type objectBackupEnvelope struct {
	SHA256   string          `json:"sha256"`
	Snapshot json.RawMessage `json:"snapshot"`
}

func (s *ObjectBackupService) store(create bool) (*os.Root, error) {
	if !filepath.IsAbs(s.root) {
		return nil, fmt.Errorf("server.backup_dir must be absolute")
	}
	if create {
		if err := os.MkdirAll(s.root, 0700); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&0077 != 0 {
		return nil, fmt.Errorf("backup directory must be a private directory (0700)")
	}
	return os.OpenRoot(s.root)
}
func (s *ObjectBackupService) save(b *ObjectBackup) error {
	if !validBackupID(b.ID) {
		return fmt.Errorf("invalid backup ID")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	data, err := json.Marshal(objectBackupEnvelope{hex.EncodeToString(sum[:]), raw})
	if err != nil {
		return err
	}
	if len(data) > maxObjectBackupBytes {
		return fmt.Errorf("backup too large")
	}
	root, err := s.store(true)
	if err != nil {
		return err
	}
	defer root.Close()
	name := "." + b.ID + ".pending"
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Link publishes exclusively, so even a UUID collision never replaces a copy.
	if err = root.Link(name, b.ID+".json"); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *ObjectBackupService) Load(id string) (*ObjectBackup, error) {
	if !validBackupID(id) {
		return nil, fmt.Errorf("invalid backup ID")
	}
	root, err := s.store(false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(id + ".json")
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&0077 != 0 {
		return nil, fmt.Errorf("backup must be a private regular file")
	}
	f, err := root.Open(id + ".json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxObjectBackupBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxObjectBackupBytes {
		return nil, fmt.Errorf("backup too large")
	}
	var envelope objectBackupEnvelope
	if err = json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(envelope.Snapshot)
	if hex.EncodeToString(sum[:]) != envelope.SHA256 {
		return nil, fmt.Errorf("backup checksum mismatch")
	}
	var b ObjectBackup
	if err = json.Unmarshal(envelope.Snapshot, &b); err != nil {
		return nil, err
	}
	if b.Format != objectBackupFormat || b.ID != id {
		return nil, fmt.Errorf("invalid backup format or ID")
	}
	seen := map[string]bool{}
	base, err := parseBackupBase(b.BaseDN)
	if err != nil {
		return nil, err
	}
	for _, o := range b.Objects {
		if _, err = objectGUIDFilter(o.GUID); err != nil {
			return nil, err
		}
		if seen[o.GUID] {
			return nil, fmt.Errorf("duplicate object GUID")
		}
		seen[o.GUID] = true
		if !backupDNWithin(o.DN, base) {
			return nil, fmt.Errorf("saved object outside domain")
		}
	}
	return &b, nil
}
func (s *ObjectBackupService) List() ([]ObjectBackupSummary, error) {
	out := []ObjectBackupSummary{}
	root, err := s.store(false)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	files, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".json")
		if !validBackupID(id) {
			continue
		}
		b, e := s.Load(id)
		if e != nil {
			return nil, fmt.Errorf("backup %s: %w", id, e)
		}
		out = append(out, b.Summary())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Export returns the checksummed on-disk format, suitable for offline safekeeping.
func (s *ObjectBackupService) Export(id string) ([]byte, error) {
	b, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return json.Marshal(objectBackupEnvelope{hex.EncodeToString(sum[:]), raw})
}
