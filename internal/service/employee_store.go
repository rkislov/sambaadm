package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"os"
	"path/filepath"
	"sambaadm/internal/pki"
	"sort"
	"time"
)

func (s *EmployeeService) lock() (func(), error) {
	if !filepath.IsAbs(s.root) {
		return nil, fmt.Errorf("для мастера нужен абсолютный приватный каталог состояния")
	}
	if e := pki.EnsureDir(s.root); e != nil {
		return nil, e
	}
	return lockEmployeeFile(s.root)
}
func (s *EmployeeService) save(r *employeeRecord) error {
	r.Plan.Updated = time.Now().UTC()
	r.Plan.Revision = randomEmployeeRevision()
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	data, e := json.Marshal(struct {
		Hash   string
		Record json.RawMessage
	}{hex.EncodeToString(sum[:]), raw})
	if e != nil {
		return e
	}
	if e = pki.SaveFile(filepath.Join(s.root, r.Plan.ID+".json"), data); e != nil {
		return e
	}
	return syncEmployeeDirectory(s.root)
}
func randomEmployeeRevision() string { return uuid.NewString() }
func (s *EmployeeService) load(id string) (*employeeRecord, error) {
	if raw, e := hex.DecodeString(id); e != nil || len(raw) != 16 {
		return nil, ErrEmployeeInput
	}
	root, e := os.OpenRoot(s.root)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	f, e := root.Open(id + ".json")
	if os.IsNotExist(e) {
		return nil, ErrEmployeeNotFound
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return nil, fmt.Errorf("журнал операции недоступен или имеет неверные права")
	}
	var envelope struct {
		Hash   string
		Record json.RawMessage
	}
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	if decoder.Decode(&envelope) != nil {
		return nil, fmt.Errorf("журнал операции повреждён; не повторяйте изменения вслепую")
	}
	sum := sha256.Sum256(envelope.Record)
	if envelope.Hash != hex.EncodeToString(sum[:]) {
		return nil, fmt.Errorf("контрольная сумма журнала не совпадает")
	}
	var r employeeRecord
	if json.Unmarshal(envelope.Record, &r) != nil || r.Version != 1 || r.Plan.ID != id || !employeeSameDN(r.BaseDN, s.ldap.BaseDN()) {
		return nil, fmt.Errorf("журнал операции не соответствует этому домену")
	}
	if e := validateEmployee(r.Plan.Input); e != nil {
		return nil, e
	}
	return &r, nil
}
func (s *EmployeeService) Get(id string) (*EmployeePlan, error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	r, e := s.load(id)
	if e != nil {
		return nil, e
	}
	if r.Plan.State == "running" {
		r.Plan.State = "interrupted"
		r.Plan.Error = "Выполнение прервано. Обновите план продолжения: успешные изменения будут проверены, пароль при необходимости нужно задать заново."
	}
	return &r.Plan, nil
}
func (s *EmployeeService) List() ([]EmployeePlan, error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return nil, e
	}
	type file struct {
		id   string
		time time.Time
	}
	files := []file{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		if raw, e := hex.DecodeString(id); e != nil || len(raw) != 16 {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		files = append(files, file{id, info.ModTime()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].time.After(files[j].time) })
	if len(files) > 30 {
		files = files[:30]
	}
	out := []EmployeePlan{}
	for _, f := range files {
		r, e := s.load(f.id)
		if e != nil {
			return nil, e
		}
		if r.Plan.State == "running" {
			r.Plan.State = "interrupted"
		}
		out = append(out, r.Plan)
	}
	return out, nil
}
