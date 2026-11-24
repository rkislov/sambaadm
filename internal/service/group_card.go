package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

var ErrGroupInput = errors.New("некорректные параметры группы")
var ErrGroupConflict = errors.New("группа изменена; обновите карточку и повторите действие")

func encodeGroupType(scope, category string) (string, error) {
	if scope == "" {
		scope = "global"
	}
	if category == "" {
		category = "security"
	}
	n, ok := map[string]uint32{"global": 2, "domain-local": 4, "universal": 8}[scope]
	if !ok {
		return "", fmt.Errorf("%w: неизвестная область", ErrGroupInput)
	}
	if category == "security" {
		n |= 0x80000000
	} else if category != "distribution" {
		return "", fmt.Errorf("%w: неизвестный тип", ErrGroupInput)
	}
	return strconv.FormatInt(int64(int32(n)), 10), nil
}
func decodeGroupType(raw string) (int64, string, string, bool) {
	n, e := strconv.ParseInt(raw, 10, 64)
	if e != nil {
		return 0, "unknown", "unknown", false
	}
	v := uint32(n)
	category := "distribution"
	if v&0x80000000 != 0 {
		category = "security"
	}
	scope := map[uint32]string{2: "global", 4: "domain-local", 8: "universal"}[v&14]
	if scope == "" {
		scope = "unknown"
	}
	return n, scope, category, v&1 != 0
}

type UpdateGroupInput struct {
	Revision    string `json:"revision"`
	Description string `json:"description"`
	Scope       string `json:"scope"`
	Category    string `json:"category"`
	Confirm     bool   `json:"confirm"`
}

func (s *GroupService) Update(ctx context.Context, name string, in UpdateGroupInput, actor, ip string) (*Group, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("%w: подтвердите изменение группы", ErrGroupInput)
	}
	controls, e := assertion(in.Revision)
	if e != nil {
		return nil, fmt.Errorf("%w: требуется версия группы", ErrGroupInput)
	}
	if !utf8.ValidString(in.Description) || utf8.RuneCountInString(in.Description) > 1024 || strings.ContainsAny(in.Description, "\x00\r\n") {
		return nil, fmt.Errorf("%w: описание должно содержать не более 1024 символов без переводов строк", ErrGroupInput)
	}
	if in.Scope == "" || in.Category == "" {
		return nil, fmt.Errorf("%w: укажите тип и область", ErrGroupInput)
	}
	gt, e := encodeGroupType(in.Scope, in.Category)
	if e != nil {
		return nil, e
	}
	g, e := s.Show(ctx, name)
	if e != nil {
		return nil, e
	}
	if g.Revision != in.Revision {
		return nil, ErrGroupConflict
	}
	changed := g.Scope != in.Scope || g.Category != in.Category
	if changed && g.Builtin {
		return nil, fmt.Errorf("%w: тип встроенной группы менять нельзя", ErrGroupInput)
	}
	if (g.Scope == "global" && in.Scope == "domain-local") || (g.Scope == "domain-local" && in.Scope == "global") {
		return nil, fmt.Errorf("%w: переход между глобальной и локальной областями выполняется через универсальную", ErrGroupInput)
	}
	req := ldap.NewModifyRequest(g.DN, controls)
	description := []string{}
	if in.Description != "" {
		description = []string{in.Description}
	}
	req.Replace("description", description)
	if changed {
		req.Replace("groupType", []string{gt})
	}
	e = s.ldap.Modify(ctx, req)
	if e != nil {
		s.audit.Failure(actor, "group.update", g.DN, ip, e)
		if ldap.IsErrorWithCode(e, 122) {
			return nil, ErrGroupConflict
		}
		return nil, e
	}
	s.audit.Success(actor, "group.update", g.DN, ip)
	return s.Show(ctx, name)
}

type GroupPerson struct {
	DN      string   `json:"dn"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Direct  bool     `json:"direct"`
	Primary bool     `json:"primary"`
	Via     []string `json:"via,omitempty"`
}
type GroupDetails struct {
	Group       *Group        `json:"group"`
	Members     []GroupPerson `json:"members"`
	Parents     []GroupPerson `json:"parents"`
	Limitations []string      `json:"limitations"`
}

func groupPerson(e *ldap.Entry) GroupPerson {
	p := GroupPerson{DN: e.DN, Name: e.GetAttributeValue("sAMAccountName"), Kind: "object"}
	if p.Name == "" {
		p.Name = e.GetAttributeValue("name")
	}
	if p.Name == "" {
		p.Name = e.DN
	}
	for _, c := range e.GetAttributeValues("objectClass") {
		switch strings.ToLower(c) {
		case "user":
			if p.Kind == "object" {
				p.Kind = "user"
			}
		case "group":
			p.Kind = "group"
		case "computer":
			p.Kind = "computer"
		}
	}
	return p
}
func sameGroupDN(a, b string) bool {
	x, e := ldap.ParseDN(a)
	y, f := ldap.ParseDN(b)
	return e == nil && f == nil && x.EqualFold(y)
}
func dnInList(dn string, list []string) bool {
	for _, v := range list {
		if sameGroupDN(dn, v) {
			return true
		}
	}
	return false
}

const groupChain = "1.2.840.113556.1.4.1941"

func (s *GroupService) Details(ctx context.Context, name string) (*GroupDetails, error) {
	entry, e := s.find(ctx, name)
	if e != nil {
		return nil, e
	}
	g := entryToGroup(entry)
	attrs := []string{"sAMAccountName", "name", "objectClass", "memberOf", "objectSid", "primaryGroupID"}
	entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(memberOf:" + groupChain + ":=" + ldap.EscapeFilter(g.DN) + ")", Attributes: attrs, MaxEntries: 10000})
	if e != nil {
		return nil, e
	}
	out := &GroupDetails{Group: &g, Members: []GroupPerson{}, Parents: []GroupPerson{}, Limitations: []string{"Членство показано по данным выбранного DC. Оно не является расчётом эффективного доступа к ресурсам или текущего Kerberos-токена.", "Внешние субъекты отображаются по доступным данным каталога; содержимое доверенных доменов не раскрывается."}}
	// memberOf avoids AD ranged member truncation and excludes primary membership.
	byDN := map[string]*ldap.Entry{}
	for _, v := range entries {
		byDN[strings.ToLower(v.DN)] = v
	}
	var path func(*ldap.Entry, map[string]bool, int) []string
	path = func(v *ldap.Entry, seen map[string]bool, depth int) []string {
		if depth > 32 {
			return nil
		}
		key := strings.ToLower(v.DN)
		if seen[key] {
			return nil
		}
		seen[key] = true
		defer delete(seen, key)
		for _, parent := range v.GetAttributeValues("memberOf") {
			if sameGroupDN(parent, g.DN) {
				return []string{g.DN}
			}
			if p := byDN[strings.ToLower(parent)]; p != nil {
				if rest := path(p, seen, depth+1); rest != nil {
					return append([]string{p.DN}, rest...)
				}
			}
		}
		return nil
	}
	direct := []string{}
	for _, v := range entries {
		p := groupPerson(v)
		p.Direct = dnInList(g.DN, v.GetAttributeValues("memberOf"))
		if p.Direct {
			direct = append(direct, p.DN)
		} else {
			p.Via = path(v, map[string]bool{}, 0)
		}
		out.Members = append(out.Members, p)
	}
	// Primary groups are absent from memberOf; only include objects with the same domain SID.
	sid := sidString(entry.GetRawAttributeValue("objectSid"))
	if strings.HasPrefix(sid, "S-1-5-21-") {
		cut := strings.LastIndex(sid, "-")
		rid := sid[cut+1:]
		primary, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=user)(primaryGroupID=" + ldap.EscapeFilter(rid) + "))", Attributes: attrs, MaxEntries: 10000})
		if err != nil {
			return nil, err
		}
		for _, v := range primary {
			other := sidString(v.GetRawAttributeValue("objectSid"))
			if i := strings.LastIndex(other, "-"); i > 0 && other[:i] == sid[:cut] {
				p := groupPerson(v)
				p.Primary = true
				out.Members = append(out.Members, p)
			}
		}
	}
	g.Members = direct
	parents, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=group)(member:" + groupChain + ":=" + ldap.EscapeFilter(g.DN) + "))", Attributes: attrs, MaxEntries: 10000})
	if e != nil {
		return nil, e
	}
	for _, v := range parents {
		p := groupPerson(v)
		p.Direct = dnInList(v.DN, entry.GetAttributeValues("memberOf"))
		out.Parents = append(out.Parents, p)
	}
	sortPeople := func(list []GroupPerson) {
		sort.Slice(list, func(i, j int) bool {
			if list[i].Direct != list[j].Direct {
				return list[i].Direct
			}
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
	}
	sortPeople(out.Members)
	sortPeople(out.Parents)
	return out, nil
}

type GroupMemberChange struct {
	Revision string `json:"revision"`
	MemberDN string `json:"memberDN"`
	Confirm  bool   `json:"confirm"`
}

func (s *GroupService) ChangeMember(ctx context.Context, name string, in GroupMemberChange, remove bool, actor, ip string) (*GroupDetails, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("%w: подтвердите изменение состава", ErrGroupInput)
	}
	controls, e := assertion(in.Revision)
	if e != nil {
		return nil, fmt.Errorf("%w: требуется версия группы", ErrGroupInput)
	}
	g, e := s.Show(ctx, name)
	if e != nil {
		return nil, e
	}
	if g.Revision != in.Revision {
		return nil, ErrGroupConflict
	}
	if remove {
		if dn, err := ldap.ParseDN(in.MemberDN); err != nil || len(dn.RDNs) == 0 {
			return nil, fmt.Errorf("%w: требуется DN участника", ErrGroupInput)
		}
	} else if e = s.validateMember(ctx, g.DN, in.MemberDN); e != nil {
		return nil, e
	}
	req := ldap.NewModifyRequest(g.DN, controls)
	action := "group.add-member"
	if remove {
		req.Delete("member", []string{in.MemberDN})
		action = "group.remove-member"
	} else {
		req.Add("member", []string{in.MemberDN})
	}
	e = s.ldap.Modify(ctx, req)
	if e != nil {
		s.audit.Failure(actor, action, g.DN, ip, e)
		if ldap.IsErrorWithCode(e, 122) {
			return nil, ErrGroupConflict
		}
		return nil, e
	}
	s.audit.Success(actor, action, g.DN+" / "+in.MemberDN, ip)
	return s.Details(ctx, name)
}
