package service

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net/mail"
	ldapproto "sambaadm/internal/ldap"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrUserConflict = errors.New("user changed; reload the profile before saving")
var ErrUserInput = errors.New("invalid user profile")

type UpdateUserInput struct {
	Revision    string  `json:"revision"`
	DisplayName *string `json:"displayName"`
	Mail        *string `json:"mail"`
	Description *string `json:"description"`
	GivenName   *string `json:"givenName"`
	Surname     *string `json:"surname"`
	Telephone   *string `json:"telephone"`
	Department  *string `json:"department"`
	Title       *string `json:"title"`
}

func (s *UserService) Update(ctx context.Context, login string, in UpdateUserInput, actor, ip string) (*User, error) {
	if _, e := strconv.ParseUint(in.Revision, 10, 64); e != nil {
		return nil, fmt.Errorf("%w: revision required", ErrUserInput)
	}
	fields := []struct {
		attr  string
		value *string
		max   int
	}{{"displayName", in.DisplayName, 256}, {"mail", in.Mail, 256}, {"description", in.Description, 1024}, {"givenName", in.GivenName, 64}, {"sn", in.Surname, 64}, {"telephoneNumber", in.Telephone, 64}, {"department", in.Department, 64}, {"title", in.Title, 64}}
	changed := false
	for _, f := range fields {
		if f.value == nil {
			continue
		}
		changed = true
		if !utf8.ValidString(*f.value) || utf8.RuneCountInString(*f.value) > f.max || strings.ContainsAny(*f.value, "\x00\r\n") {
			return nil, fmt.Errorf("%w: invalid %s", ErrUserInput, f.attr)
		}
	}
	if !changed {
		return nil, fmt.Errorf("%w: no attributes supplied", ErrUserInput)
	}
	if in.Mail != nil && *in.Mail != "" {
		address, e := mail.ParseAddress(*in.Mail)
		if e != nil || address.Address != *in.Mail {
			return nil, fmt.Errorf("%w: invalid mail", ErrUserInput)
		}
	}
	u, e := s.Show(ctx, login)
	if e != nil {
		return nil, e
	}
	if u.Revision != in.Revision {
		return nil, ErrUserConflict
	}
	assertion, _ := ldap.CompileFilter("(uSNChanged=" + in.Revision + ")")
	req := ldap.NewModifyRequest(u.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assertion.Bytes()))})
	for _, f := range fields {
		if f.value == nil {
			continue
		}
		values := []string{}
		if *f.value != "" {
			values = []string{*f.value}
		}
		req.Replace(f.attr, values)
	}
	if e = s.ldap.Modify(ctx, req); e != nil {
		s.audit.Failure(actor, "user.update", u.DN, ip, e)
		if ldap.IsErrorWithCode(e, 122) {
			return nil, ErrUserConflict
		}
		return nil, e
	}
	s.audit.Success(actor, "user.update", u.DN, ip)
	return s.Show(ctx, login)
}

type UserGroup struct {
	DN      string `json:"dn"`
	Name    string `json:"name"`
	Primary bool   `json:"primary"`
}

// Memberships returns direct membership plus the primary group, which AD does
// not expose in memberOf. Nested membership is intentionally not inferred.
func (s *UserService) Memberships(ctx context.Context, login string) ([]UserGroup, error) {
	entry, e := s.findByLogin(ctx, login)
	if e != nil {
		return nil, e
	}
	filter := "(member=" + ldap.EscapeFilter(entry.DN) + ")"
	var primarySID []byte
	if rid := entry.GetAttributeValue("primaryGroupID"); rid != "" {
		n, err := strconv.ParseUint(rid, 10, 32)
		sid := entry.GetRawAttributeValue("objectSid")
		if err != nil || len(sid) < 12 || len(sid) != 8+4*int(sid[1]) {
			return nil, fmt.Errorf("invalid user primary group SID")
		}
		primarySID = append([]byte(nil), sid...)
		binary.LittleEndian.PutUint32(primarySID[len(primarySID)-4:], uint32(n))
		filter = "(|" + filter + "(objectSid=" + ldap.EscapeFilter(string(primarySID)) + "))"
	}
	entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=group)" + filter + ")", Attributes: []string{"sAMAccountName", "cn", "objectSid"}})
	if e != nil {
		return nil, e
	}
	out := []UserGroup{}
	for _, g := range entries {
		name := g.GetAttributeValue("sAMAccountName")
		if name == "" {
			name = g.GetAttributeValue("cn")
		}
		out = append(out, UserGroup{g.DN, name, len(primarySID) > 0 && string(primarySID) == string(g.GetRawAttributeValue("objectSid"))})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Primary != out[j].Primary {
			return out[i].Primary
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}
