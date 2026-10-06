package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// User is a domain user account.
type User struct {
	DN             string `json:"dn"`
	SAMAccountName string `json:"samAccountName"`
	DisplayName    string `json:"displayName,omitempty"`
	UPN            string `json:"userPrincipalName,omitempty"`
	Mail           string `json:"mail,omitempty"`
	Enabled        bool   `json:"enabled"`
	Description    string `json:"description,omitempty"`
}

// CreateUserInput holds parameters for creating a user.
type CreateUserInput struct {
	Login       string `json:"login"`
	Password    string `json:"password,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	OU          string `json:"ou,omitempty"`
	Mail        string `json:"mail,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// UserService manages AD users.
type UserService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns users under optional OU, with optional substring filter.
func (s *UserService) List(ctx context.Context, ou, q string) ([]User, error) {
	filter := "(&(objectCategory=person)(objectClass=user))"
	if q != "" {
		esc := ldap.EscapeFilter(q)
		filter = fmt.Sprintf(
			"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*%s*)(displayName=*%s*)(cn=*%s*)))",
			esc, esc, esc,
		)
	}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     ou,
		Filter:     filter,
		Attributes: ldapproto.UserAttrs,
	})
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToUser(e))
	}
	return out, nil
}

// Show returns a single user by sAMAccountName.
func (s *UserService) Show(ctx context.Context, login string) (*User, error) {
	e, err := s.findByLogin(ctx, login)
	if err != nil {
		return nil, err
	}
	u := entryToUser(e)
	return &u, nil
}

// Create adds a new user account.
func (s *UserService) Create(ctx context.Context, in CreateUserInput, actor, ip string) (*User, error) {
	login := strings.TrimSpace(in.Login)
	if login == "" {
		return nil, fmt.Errorf("login is required")
	}
	cn := in.DisplayName
	if cn == "" {
		cn = login
	}
	parent := DefaultUsersOU(in.OU, s.ldap.BaseDN())
	dn := BuildDN("CN", cn, parent)

	upn := login
	if base := s.ldap.BaseDN(); base != "" {
		// DC=example,DC=com → example.com
		upn = login + "@" + dnsFromBaseDN(base)
	}

	// Create disabled first — Samba/AD typically require a password before enable.
	uac := ldapproto.UACNormalAccount | ldapproto.UACAccountDisable

	attrs := []ldap.Attribute{
		{Type: ldapproto.AttrObjectClass, Vals: []string{"top", "person", "organizationalPerson", "user"}},
		{Type: ldapproto.AttrCN, Vals: []string{cn}},
		{Type: ldapproto.AttrSAMAccountName, Vals: []string{login}},
		{Type: ldapproto.AttrUserPrincipal, Vals: []string{upn}},
		{Type: ldapproto.AttrUserAccountCtrl, Vals: []string{strconv.Itoa(uac)}},
		{Type: ldapproto.AttrDisplayName, Vals: []string{cn}},
	}
	if in.Mail != "" {
		attrs = append(attrs, ldap.Attribute{Type: ldapproto.AttrMail, Vals: []string{in.Mail}})
	}
	if in.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: ldapproto.AttrDescription, Vals: []string{in.Description}})
	}

	if err := s.ldap.Add(ctx, dn, attrs); err != nil {
		s.audit.Failure(actor, "user.create", dn, ip, err)
		return nil, err
	}

	if in.Password != "" {
		if err := s.setPasswordDN(ctx, dn, in.Password); err != nil {
			s.audit.Failure(actor, "user.create.password", dn, ip, err)
			return nil, fmt.Errorf("user created but password set failed: %w", err)
		}
	}
	// Honor Enabled independently of whether a password was supplied.
	if in.Enabled {
		if err := s.setEnabledDN(ctx, dn, true); err != nil {
			s.audit.Failure(actor, "user.create.enable", dn, ip, err)
			return nil, fmt.Errorf("user created but enable failed: %w", err)
		}
	}

	s.audit.Success(actor, "user.create", dn, ip)
	return s.Show(ctx, login)
}

// Delete removes a user by login.
func (s *UserService) Delete(ctx context.Context, login, actor, ip string) error {
	u, err := s.Show(ctx, login)
	if err != nil {
		return err
	}
	if err := s.ldap.Delete(ctx, u.DN); err != nil {
		s.audit.Failure(actor, "user.delete", u.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "user.delete", u.DN, ip)
	return nil
}

// Enable clears ACCOUNTDISABLE.
func (s *UserService) Enable(ctx context.Context, login, actor, ip string) error {
	return s.setEnabled(ctx, login, true, actor, ip)
}

// Disable sets ACCOUNTDISABLE.
func (s *UserService) Disable(ctx context.Context, login, actor, ip string) error {
	return s.setEnabled(ctx, login, false, actor, ip)
}

// SetPassword changes the user's password (requires LDAPS/ldapi).
func (s *UserService) SetPassword(ctx context.Context, login, password, actor, ip string) error {
	u, err := s.Show(ctx, login)
	if err != nil {
		return err
	}
	if err := s.setPasswordDN(ctx, u.DN, password); err != nil {
		s.audit.Failure(actor, "user.set-password", u.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "user.set-password", u.DN, ip)
	return nil
}

// Move relocates a user under a new OU.
func (s *UserService) Move(ctx context.Context, login, toOU, actor, ip string) error {
	u, err := s.Show(ctx, login)
	if err != nil {
		return err
	}
	rdn, err := rdnFromDN(u.DN)
	if err != nil {
		return err
	}
	if err := s.ldap.ModifyDN(ctx, u.DN, rdn, true, toOU); err != nil {
		s.audit.Failure(actor, "user.move", u.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "user.move", u.DN+" -> "+toOU, ip)
	return nil
}

func (s *UserService) setEnabled(ctx context.Context, login string, enabled bool, actor, ip string) error {
	e, err := s.findByLogin(ctx, login)
	if err != nil {
		return err
	}
	action := "user.disable"
	if enabled {
		action = "user.enable"
	}
	if err := s.setEnabledDN(ctx, e.DN, enabled); err != nil {
		s.audit.Failure(actor, action, e.DN, ip, err)
		return err
	}
	s.audit.Success(actor, action, e.DN, ip)
	return nil
}

func (s *UserService) setEnabledDN(ctx context.Context, dn string, enabled bool) error {
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		BaseDN:     dn,
		Scope:      ldapproto.ScopeBase(),
		Filter:     "(objectClass=user)",
		Attributes: []string{ldapproto.AttrUserAccountCtrl},
	})
	if err != nil {
		return err
	}
	uac := ldapproto.UACNormalAccount
	if v := e.GetAttributeValue(ldapproto.AttrUserAccountCtrl); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			uac = n
		}
	}
	if enabled {
		uac &^= ldapproto.UACAccountDisable
	} else {
		uac |= ldapproto.UACAccountDisable
	}
	return s.ldap.ReplaceAttr(ctx, dn, ldapproto.AttrUserAccountCtrl, strconv.Itoa(uac))
}

func (s *UserService) setPasswordDN(ctx context.Context, dn, password string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}
	encoded := ldapproto.EncodeUnicodePwd(password)
	req := ldap.NewModifyRequest(dn, nil)
	req.Replace(ldapproto.AttrUnicodePwd, []string{string(encoded)})
	return s.ldap.Modify(ctx, req)
}

func (s *UserService) findByLogin(ctx context.Context, login string) (*ldap.Entry, error) {
	filter := fmt.Sprintf(
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))",
		ldap.EscapeFilter(login),
	)
	return s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: ldapproto.UserAttrs,
	})
}

func entryToUser(e *ldap.Entry) User {
	enabled := true
	if uac := e.GetAttributeValue(ldapproto.AttrUserAccountCtrl); uac != "" {
		if v, err := strconv.Atoi(uac); err == nil {
			enabled = v&ldapproto.UACAccountDisable == 0
		}
	}
	return User{
		DN:             e.DN,
		SAMAccountName: e.GetAttributeValue(ldapproto.AttrSAMAccountName),
		DisplayName:    e.GetAttributeValue(ldapproto.AttrDisplayName),
		UPN:            e.GetAttributeValue(ldapproto.AttrUserPrincipal),
		Mail:           e.GetAttributeValue(ldapproto.AttrMail),
		Enabled:        enabled,
		Description:    e.GetAttributeValue(ldapproto.AttrDescription),
	}
}

func dnsFromBaseDN(base string) string {
	var parts []string
	for _, p := range strings.Split(base, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "DC=") {
			parts = append(parts, p[3:])
		}
	}
	return strings.Join(parts, ".")
}
