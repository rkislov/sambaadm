package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"sambaadm/internal/pki"
	"strconv"
	"strings"
	"time"
)

type BulkUserItem struct {
	Login    string `json:"login"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	DN       string `json:"dn"`
	State    string `json:"state"`
	Message  string `json:"message"`
}
type BulkUserPlan struct {
	ID       string         `json:"id"`
	Revision string         `json:"revision"`
	Action   string         `json:"action"`
	State    string         `json:"state"`
	Actor    string         `json:"actor"`
	Base     string         `json:"base"`
	Expires  time.Time      `json:"expires"`
	Items    []BulkUserItem `json:"items"`
}

func (s *EmployeeService) saveBulk(p *BulkUserPlan) error {
	p.Revision = uuid.NewString()
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	if e = pki.SaveFile(filepath.Join(s.root, "bulk-"+p.ID+".json"), raw); e != nil {
		return e
	}
	return syncEmployeeDirectory(s.root)
}
func (s *EmployeeService) readBulk(id string) (*BulkUserPlan, error) {
	if _, e := psoGUID(id); e != nil {
		return nil, ErrEmployeeInput
	}
	root, e := os.OpenRoot(s.root)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	raw, e := root.ReadFile("bulk-" + id + ".json")
	if e != nil {
		return nil, ErrEmployeeNotFound
	}
	var p BulkUserPlan
	if len(raw) > 1<<20 || json.Unmarshal(raw, &p) != nil || p.ID != id || !employeeSameDN(p.Base, s.ldap.BaseDN()) {
		return nil, ErrEmployeeConflict
	}
	return &p, nil
}
func (s *EmployeeService) BulkGet(id string) (*BulkUserPlan, error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	p, e := s.readBulk(id)
	if e == nil && p.State == "running" {
		p.State = "interrupted"
		for i := range p.Items {
			if p.Items[i].State == "running" {
				p.Items[i].State = "unknown"
				p.Items[i].Message = "Результат не подтверждён. Подготовьте новый предпросмотр."
			}
		}
	}
	return p, e
}
func (s *EmployeeService) BulkPreview(ctx context.Context, action string, logins []string, actor EmployeeActor) (*BulkUserPlan, error) {
	if action != "enable" && action != "disable" && action != "unlock" || len(logins) == 0 || len(logins) > 100 {
		return nil, fmt.Errorf("%w: выберите действие и от 1 до 100 пользователей", ErrEmployeeInput)
	}
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	p := &BulkUserPlan{ID: strings.ReplaceAll(uuid.NewString(), "-", ""), Base: s.ldap.BaseDN(), Actor: actor.Name, Action: action, State: "ready", Expires: time.Now().Add(15 * time.Minute), Items: []BulkUserItem{}}
	seen := map[string]bool{}
	for _, login := range logins {
		login = strings.TrimSpace(login)
		if login == "" || len(login) > 256 || seen[strings.ToLower(login)] {
			return nil, ErrEmployeeInput
		}
		seen[strings.ToLower(login)] = true
		item := BulkUserItem{Login: login, State: "ready"}
		snap, err := s.capture(ctx, login, "")
		if err == nil {
			err = s.protect(snap, actor)
		}
		if err != nil {
			item.State = "blocked"
			item.Message = err.Error()
		} else {
			entry, err := s.findUser(ctx, login, snap.Person.ID)
			if err != nil {
				return nil, err
			}
			item.ID = snap.Person.ID
			item.DN = snap.Person.DN
			item.Revision = loginRevision(entry)
			item.Message = map[string]string{"enable": "Включить учётную запись", "disable": "Отключить учётную запись", "unlock": "Снять блокировку входа"}[action]
			if action == "enable" && snap.Person.Enabled || action == "disable" && !snap.Person.Enabled {
				item.State = "skipped"
				item.Message = "Нужное состояние уже установлено"
			}
		}
		p.Items = append(p.Items, item)
	}
	if e = s.saveBulk(p); e != nil {
		return nil, e
	}
	s.event(actor, "users.bulk.preview", p.ID, nil)
	return p, nil
}
func (s *EmployeeService) BulkApply(ctx context.Context, id, revision string, actor EmployeeActor) (*BulkUserPlan, error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	p, e := s.readBulk(id)
	if e != nil {
		return nil, e
	}
	if p.State != "ready" || p.Revision != revision || time.Now().After(p.Expires) {
		return nil, ErrEmployeeConflict
	}
	p.State = "running"
	if e = s.saveBulk(p); e != nil {
		return nil, e
	}
	for i := range p.Items {
		item := &p.Items[i]
		if item.State != "ready" {
			continue
		}
		if ctx.Err() != nil {
			item.State = "failed"
			item.Message = "Запрос прерван; действие не запущено"
			continue
		}
		item.State = "running"
		if e = s.saveBulk(p); e != nil {
			return nil, e
		}
		err := func() error {
			snap, e := s.capture(ctx, "", item.ID)
			if e != nil {
				return e
			}
			if e = s.protect(snap, actor); e != nil {
				return e
			}
			entry, e := s.findUser(ctx, "", item.ID)
			if e != nil {
				return e
			}
			if entry.GetAttributeValue("uSNChanged") != snap.USN || loginRevision(entry) != item.Revision || !employeeSameDN(entry.DN, item.DN) || !strings.EqualFold(snap.Person.Login, item.Login) {
				return ErrEmployeeConflict
			}
			controls, e := employeeAssertion(snap.Person.EmployeeRef, entry.GetAttributeValue("uSNChanged"))
			if e != nil {
				return e
			}
			req := ldap.NewModifyRequest(entry.DN, controls)
			if p.Action == "unlock" {
				req.Replace("lockoutTime", []string{"0"})
			} else {
				uac, e := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
				if e != nil {
					return e
				}
				if p.Action == "disable" {
					uac |= 2
				} else {
					uac &^= 2
				}
				req.Replace("userAccountControl", []string{strconv.FormatUint(uac, 10)})
			}
			if e = s.ldap.Modify(ctx, req); e != nil {
				return e
			}
			after, e := s.findUser(ctx, "", item.ID)
			if e != nil {
				return fmt.Errorf("запись выполнена, но результат не прочитан: %w", e)
			}
			if p.Action == "unlock" {
				if after.GetAttributeValue("lockoutTime") != "0" {
					return ErrEmployeeConflict
				}
			} else {
				uac, e := strconv.ParseUint(after.GetAttributeValue("userAccountControl"), 10, 32)
				if e != nil || (uac&2 == 0) != (p.Action == "enable") {
					return ErrEmployeeConflict
				}
				if p.Action == "disable" && s.revoke != nil {
					if e = s.revoke(item.ID); e != nil {
						return e
					}
				}
			}
			return nil
		}()
		if err != nil {
			item.State = "failed"
			item.Message = err.Error()
		} else {
			item.State = "done"
			item.Message = "Результат подтверждён контроллером"
		}
		s.event(actor, "users.bulk."+p.Action, item.Login, err)
		if e = s.saveBulk(p); e != nil {
			return nil, e
		}
	}
	p.State = "completed"
	for _, item := range p.Items {
		if item.State == "failed" || item.State == "blocked" {
			p.State = "partial"
		}
	}
	if e = s.saveBulk(p); e != nil {
		return nil, e
	}
	return p, nil
}
