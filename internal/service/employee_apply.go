package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

// Apply never retries an uncertain write. Review reconciles directory state first.
func (s *EmployeeService) Apply(ctx context.Context, id, revision, password string, actor EmployeeActor) (*EmployeePlan, error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	r, e := s.load(id)
	if e != nil {
		return nil, e
	}
	if revision == "" || r.Plan.Revision != revision || r.Plan.State != "ready" || time.Now().After(r.Plan.Expires) {
		return nil, ErrEmployeeConflict
	}
	if r.Plan.NeedsPassword && (password == "" || len(password) > 4096 || !utf8.ValidString(password) || strings.ContainsRune(password, 0)) {
		return nil, fmt.Errorf("%w: задайте начальный пароль (до 4096 байт)", ErrEmployeeInput)
	}
	if e = s.normalize(ctx, &r.Plan.Input, true); e != nil {
		return nil, e
	}
	snap, e := s.recordSnapshot(ctx, r)
	if e != nil {
		return nil, e
	}
	if e = s.protect(snap, actor); e != nil {
		return nil, e
	}
	if employeeHash(snap) != employeeHash(r.Expected) {
		return nil, ErrEmployeeConflict
	}
	fail := func(step *EmployeeStep, err error) (*EmployeePlan, error) {
		message := err.Error()
		if password != "" {
			message = strings.ReplaceAll(message, password, "[скрыто]")
		}
		r.Plan.State = "partial"
		r.Plan.Error = message
		if step != nil {
			step.State = "failed"
			step.Error = message
		}
		if se := s.save(r); se != nil {
			return nil, fmt.Errorf("результат операции не удалось записать; перечитайте журнал: %w", se)
		}
		s.event(actor, "employee.apply", id, errors.New(message))
		return &r.Plan, nil
	}
	for i := range r.Plan.Steps {
		step := &r.Plan.Steps[i]
		if step.State == "done" || step.State == "skipped" {
			continue
		}
		if e = ctx.Err(); e != nil {
			return fail(step, e)
		}
		snap, e = s.recordSnapshot(ctx, r)
		if e != nil {
			return fail(step, e)
		}
		if employeeHash(snap) != employeeHash(r.Expected) {
			return fail(step, ErrEmployeeConflict)
		}
		if e = s.protect(snap, actor); e != nil {
			return fail(step, e)
		}
		step.State = "running"
		step.Attempts++
		step.Error = ""
		r.Plan.State = "running"
		if e = s.save(r); e != nil {
			return nil, e
		}
		if s.beforeStep != nil {
			if e = s.beforeStep(step.Kind); e != nil {
				return fail(step, e)
			}
		}
		if e = s.executeEmployeeStep(ctx, r, snap, *step, password); e != nil {
			return fail(step, e)
		}
		after, e := s.recordSnapshot(ctx, r)
		if e != nil {
			return fail(step, fmt.Errorf("запись выполнена, но результат не прочитан: %w", e))
		}
		if e = verifyEmployeeStep(r, snap, after, *step); e != nil {
			return fail(step, e)
		}
		if step.Kind == "password" {
			r.PasswordDone = true
		}
		if step.Kind == "revoke" {
			r.RevokeDone = true
		}
		step.State = "done"
		r.Expected = after
		r.Plan.Person = &after.Person
		if e = s.save(r); e != nil {
			return nil, fmt.Errorf("результат шага не записан; обновите план: %w", e)
		}
		s.event(actor, "employee.step."+step.Kind, id, nil)
	}
	r.Plan.State = "completed"
	r.Plan.Error = ""
	r.Plan.NeedsPassword = false
	if e = s.save(r); e != nil {
		return nil, e
	}
	s.event(actor, "employee.apply", id, nil)
	return &r.Plan, nil
}
func (s *EmployeeService) executeEmployeeStep(ctx context.Context, r *employeeRecord, snap *employeeSnapshot, step EmployeeStep, password string) error {
	in := r.Plan.Input
	if step.Kind == "create" {
		if snap != nil {
			return ErrEmployeeConflict
		}
		parent, _, e := s.refByID(ctx, *in.Parent, "parent", true)
		if e != nil {
			return e
		}
		dn := BuildDN("CN", in.DisplayName, parent.DN)
		req := ldap.NewAddRequest(dn, nil)
		req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
		req.Attribute("cn", []string{in.DisplayName})
		req.Attribute("displayName", []string{in.DisplayName})
		req.Attribute("sAMAccountName", []string{in.Login})
		req.Attribute("userAccountControl", []string{"514"})
		req.Attribute("adminDescription", []string{"sambaadm.employee:" + r.Plan.ID})
		// Derive UPN from the domain naming context, never from an untrusted request.
		parsed, e := ldap.ParseDN(s.ldap.BaseDN())
		if e != nil {
			return e
		}
		parts := []string{}
		for _, rdn := range parsed.RDNs {
			for _, a := range rdn.Attributes {
				if strings.EqualFold(a.Type, "DC") {
					parts = append(parts, a.Value)
				}
			}
		}
		if len(parts) == 0 {
			return ErrEmployeeInput
		}
		req.Attribute("userPrincipalName", []string{in.Login + "@" + strings.Join(parts, ".")})
		for key, value := range map[string]*string{"mail": in.Mail, "department": in.Department, "title": in.Title} {
			if value != nil && *value != "" {
				req.Attribute(key, []string{*value})
			}
		}
		conn, e := s.ldap.Conn(ctx)
		if e != nil {
			return e
		}
		return conn.Add(req)
	}
	if snap == nil {
		return ErrEmployeeConflict
	}
	if step.Kind == "revoke" {
		if s.revoke == nil {
			return fmt.Errorf("отзыв сессий sambaadm не настроен")
		}
		return s.revoke(snap.Person.ID)
	}
	if step.Kind == "add_group" || step.Kind == "remove_group" {
		g, usn, e := s.refByID(ctx, *step.Group, "group", true)
		if e != nil {
			return e
		}
		controls, e := employeeAssertion(g, usn)
		if e != nil {
			return e
		}
		req := ldap.NewModifyRequest(g.DN, controls)
		if step.Kind == "add_group" {
			req.Add("member", []string{employeeExtendedDN(snap.Person.EmployeeRef)})
		} else {
			req.Delete("member", []string{employeeExtendedDN(snap.Person.EmployeeRef)})
		}
		return s.ldap.Modify(ctx, req)
	}
	controls, e := employeeAssertion(snap.Person.EmployeeRef, snap.USN)
	if e != nil {
		return e
	}
	if step.Kind == "move" {
		parent, _, e := s.refByID(ctx, *in.Parent, "parent", true)
		if e != nil {
			return e
		}
		rdn, e := rdnFromDN(snap.Person.DN)
		if e != nil {
			return e
		}
		req := ldap.NewModifyDNWithControlsRequest(snap.Person.DN, rdn, true, parent.DN, controls)
		conn, e := s.ldap.Conn(ctx)
		if e != nil {
			return e
		}
		return conn.ModifyDN(req)
	}
	req := ldap.NewModifyRequest(snap.Person.DN, controls)
	switch step.Kind {
	case "enable", "disable":
		uac, e := strconv.ParseUint(snap.Values["userAccountControl"], 10, 32)
		if e != nil {
			return e
		}
		if step.Kind == "disable" {
			uac |= 2
		} else {
			if !r.PasswordDone {
				return fmt.Errorf("пароль ещё не подтверждён")
			}
			uac &^= 2
		}
		req.Replace("userAccountControl", []string{strconv.FormatUint(uac, 10)})
	case "profile":
		for key, value := range map[string]*string{"mail": in.Mail, "department": in.Department, "title": in.Title} {
			if value != nil {
				values := []string{}
				if *value != "" {
					values = append(values, *value)
				}
				req.Replace(key, values)
			}
		}
	case "password":
		if snap.Person.Enabled {
			return fmt.Errorf("до установки пароля учётная запись должна оставаться отключённой")
		}
		req.Replace("unicodePwd", []string{string(ldapproto.EncodeUnicodePwd(password))})
		last := "-1"
		if in.ForceChange {
			last = "0"
		}
		req.Replace("pwdLastSet", []string{last})
	default:
		return fmt.Errorf("неизвестный шаг мастера")
	}
	return s.ldap.Modify(ctx, req)
}
func verifyEmployeeStep(r *employeeRecord, before, after *employeeSnapshot, step EmployeeStep) error {
	if after == nil {
		return fmt.Errorf("результат шага не подтверждён")
	}
	if before == nil {
		in := r.Plan.Input
		if step.Kind != "create" || after.Person.Enabled || after.Person.Login != in.Login || after.Values["displayName"] != in.DisplayName || after.Values["adminDescription"] != "sambaadm.employee:"+r.Plan.ID {
			return ErrEmployeeConflict
		}
		for key, value := range map[string]*string{"mail": in.Mail, "department": in.Department, "title": in.Title} {
			if value != nil && after.Values[key] != *value {
				return ErrEmployeeConflict
			}
		}
		dn, e := ldap.ParseDN(after.Person.DN)
		if e != nil || len(dn.RDNs) < 2 || !employeeSameDN((&ldap.DN{RDNs: dn.RDNs[1:]}).String(), in.Parent.DN) {
			return ErrEmployeeConflict
		}
		if len(after.Person.Groups) != 1 || !after.Person.Groups[0].Primary {
			return ErrEmployeeConflict
		}
		return nil
	}
	if before.Person.ID != after.Person.ID {
		return ErrEmployeeConflict
	}
	raw, _ := json.Marshal(before)
	var expected employeeSnapshot
	_ = json.Unmarshal(raw, &expected)
	expected.USN = after.USN
	switch step.Kind {
	case "disable", "enable":
		expected.Person.Enabled = step.Kind == "enable"
		uac, _ := strconv.ParseUint(before.Values["userAccountControl"], 10, 32)
		if expected.Person.Enabled {
			uac &^= 2
		} else {
			uac |= 2
		}
		expected.Values["userAccountControl"] = strconv.FormatUint(uac, 10)
	case "move":
		dn, _ := ldap.ParseDN(after.Person.DN)
		if len(dn.RDNs) < 2 || !employeeSameDN((&ldap.DN{RDNs: dn.RDNs[1:]}).String(), r.Plan.Input.Parent.DN) {
			return ErrEmployeeConflict
		}
		expected.Person.DN = after.Person.DN
	case "profile":
		for key, value := range map[string]*string{"mail": r.Plan.Input.Mail, "department": r.Plan.Input.Department, "title": r.Plan.Input.Title} {
			if value != nil {
				expected.Values[key] = *value
			}
		}
	case "password":
		if r.Plan.Input.ForceChange && after.Values["pwdLastSet"] != "0" || !r.Plan.Input.ForceChange && (after.Values["pwdLastSet"] == "0" || after.Values["pwdLastSet"] == "") {
			return ErrEmployeeConflict
		}
		expected.Values["pwdLastSet"] = after.Values["pwdLastSet"]
	case "add_group", "remove_group":
		groups := employeeGroupSet(after)
		_, has := groups[step.Group.ID]
		if has != (step.Kind == "add_group") {
			return ErrEmployeeConflict
		}
		old := employeeGroupSet(before)
		if step.Kind == "add_group" {
			old[step.Group.ID] = groups[step.Group.ID]
		} else {
			delete(old, step.Group.ID)
		}
		if len(old) != len(groups) {
			return ErrEmployeeConflict
		}
		for id, g := range old {
			if a, ok := groups[id]; !ok || g.Primary != a.Primary || !employeeSameDN(g.DN, a.DN) {
				return ErrEmployeeConflict
			}
		}
		expected.Person.Groups = after.Person.Groups
	case "revoke":
	default:
		return ErrEmployeeConflict
	}
	if employeeHash(&expected) != employeeHash(after) {
		return fmt.Errorf("%w: проверка результата шага «%s»", ErrEmployeeConflict, step.Label)
	}
	return nil
}

func (s *EmployeeService) Context(ctx context.Context, login, id string, actor EmployeeActor) (*EmployeePerson, error) {
	snap, e := s.capture(ctx, login, id)
	if e != nil {
		return nil, e
	}
	if e = s.protect(snap, actor); e != nil {
		return nil, e
	}
	return &snap.Person, nil
}
