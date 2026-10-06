package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/samba"
)

// Trust describes a domain trust relationship.
type Trust struct {
	Domain    string `json:"domain"`
	Direction string `json:"direction,omitempty"`
	Type      string `json:"type,omitempty"`
	DN        string `json:"dn,omitempty"`
	RawDir    string `json:"rawDirection,omitempty"`
	RawType   string `json:"rawType,omitempty"`
}

// CreateTrustInput parameters for samba-tool domain trust create.
type CreateTrustInput struct {
	Domain    string `json:"domain"`
	Direction string `json:"direction"` // incoming|outgoing|both
	Type      string `json:"type"`      // external|forest
	Password  string `json:"password,omitempty"`
}

// TrustService manages domain trusts (LDAP read + samba-tool mutate).
type TrustService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
	tool  *samba.Runner
}

// List returns trust objects from LDAP.
func (s *TrustService) List(ctx context.Context) ([]Trust, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=trustedDomain)",
		Attributes: []string{"cn", "trustDirection", "trustType", "trustPartner", "flatName"},
	})
	if err != nil {
		return nil, fmt.Errorf("list trusts: %w", err)
	}
	out := make([]Trust, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToTrust(e))
	}
	return out, nil
}

// Show returns a trust by partner domain name / CN / flatName.
func (s *TrustService) Show(ctx context.Context, domain string) (*Trust, error) {
	esc := ldap.EscapeFilter(domain)
	filter := fmt.Sprintf("(&(objectClass=trustedDomain)(|(trustPartner=%s)(cn=%s)(flatName=%s)))", esc, esc, esc)
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: []string{"cn", "trustDirection", "trustType", "trustPartner", "flatName"},
	})
	if err != nil {
		return nil, err
	}
	t := entryToTrust(e)
	return &t, nil
}

// Create establishes a trust via samba-tool.
func (s *TrustService) Create(ctx context.Context, in CreateTrustInput, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	domain := strings.TrimSpace(in.Domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	direction := normalizeTrustDirection(in.Direction)
	typ := normalizeTrustType(in.Type)
	args := []string{
		"domain", "trust", "create", domain,
		"--type=" + typ,
		"--direction=" + direction,
		"--create-location=local",
	}
	if in.Password != "" {
		args = append(args, "--password="+in.Password)
	}
	if _, err := s.tool.Run(ctx, args...); err != nil {
		s.audit.Failure(actor, "trust.create", domain, ip, err)
		return err
	}
	s.audit.Success(actor, "trust.create", domain, ip)
	return nil
}

// Delete removes a trust via samba-tool.
func (s *TrustService) Delete(ctx context.Context, domain, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if _, err := s.tool.Run(ctx, "domain", "trust", "delete", domain); err != nil {
		s.audit.Failure(actor, "trust.delete", domain, ip, err)
		return err
	}
	s.audit.Success(actor, "trust.delete", domain, ip)
	return nil
}

// Validate checks a trust via samba-tool.
func (s *TrustService) Validate(ctx context.Context, domain, actor, ip string) (string, error) {
	if err := s.requireTool(); err != nil {
		return "", err
	}
	res, err := s.tool.Run(ctx, "domain", "trust", "validate", domain)
	if err != nil {
		s.audit.Failure(actor, "trust.validate", domain, ip, err)
		return "", err
	}
	s.audit.Success(actor, "trust.validate", domain, ip)
	return res.Stdout, nil
}

func (s *TrustService) requireTool() error {
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available on this host")
	}
	return nil
}

func entryToTrust(e *ldap.Entry) Trust {
	rawDir := e.GetAttributeValue("trustDirection")
	rawType := e.GetAttributeValue("trustType")
	domain := e.GetAttributeValue("trustPartner")
	if domain == "" {
		domain = e.GetAttributeValue("cn")
	}
	return Trust{
		Domain:    domain,
		Direction: TrustDirectionName(rawDir),
		Type:      TrustTypeName(rawType),
		DN:        e.DN,
		RawDir:    rawDir,
		RawType:   rawType,
	}
}

func normalizeTrustDirection(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "in", "incoming", "inbound", "1":
		return "incoming"
	case "out", "outgoing", "outbound", "2":
		return "outgoing"
	case "both", "two-way", "bidirectional", "3", "":
		return "both"
	default:
		return d
	}
}

func normalizeTrustType(t string) string {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "external", "1", "":
		return "external"
	case "forest", "2":
		return "forest"
	default:
		return t
	}
}
