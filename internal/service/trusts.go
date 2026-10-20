package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"sambaadm/internal/adremote"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
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

// CreateTrustInput parameters for native local trust creation.
type CreateTrustInput struct {
	Domain    string `json:"domain"`
	NetBIOS   string `json:"netbios"`
	SID       string `json:"sid"`
	Direction string `json:"direction"` // incoming|outgoing|both
	Type      string `json:"type"`      // external|forest
	Password  string `json:"password,omitempty"`
}

// TrustService manages domain trusts over LDAP and LSA/Netlogon RPC.
type TrustService struct {
	ldap   *ldapproto.Client
	audit  *audit.Logger
	remote *adremote.Client
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

// Create establishes a trust through native RPC.
func (s *TrustService) Create(ctx context.Context, in CreateTrustInput, actor, ip string) error {
	direction := map[string]uint32{"incoming": 1, "outgoing": 2, "both": 3}[normalizeTrustDirection(in.Direction)]
	typ := normalizeTrustType(in.Type)
	if typ != "external" && typ != "forest" {
		return fmt.Errorf("unsupported trust type")
	}
	err := s.remote.CreateTrust(ctx, in.Domain, in.NetBIOS, in.SID, in.Password, direction, typ == "forest")
	if err != nil {
		s.audit.Failure(actor, "trust.create", in.Domain, ip, err)
		return err
	}
	s.audit.Success(actor, "trust.create", in.Domain, ip)
	return nil
}

// Delete removes a trust through native RPC.
func (s *TrustService) Delete(ctx context.Context, domain, actor, ip string) error {
	trust, err := s.Show(ctx, domain)
	if err != nil {
		return err
	}
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: trust.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=trustedDomain)", Attributes: []string{"securityIdentifier"}})
	if err != nil {
		return err
	}
	var sid dtyp.SID
	if err = sid.DecodeBinary(entry.GetRawAttributeValue("securityIdentifier")); err != nil {
		return err
	}
	err = s.remote.DeleteTrust(ctx, sid.String())
	if err != nil {
		s.audit.Failure(actor, "trust.delete", domain, ip, err)
		return err
	}
	s.audit.Success(actor, "trust.delete", domain, ip)
	return nil
}

// Validate checks a trust through native RPC.
func (s *TrustService) Validate(ctx context.Context, domain, actor, ip string) (string, error) {
	if _, err := s.Show(ctx, domain); err != nil {
		return "", err
	}
	result, err := s.remote.ValidateTrust(ctx, domain)
	if err != nil {
		s.audit.Failure(actor, "trust.validate", domain, ip, err)
		return result, err
	}
	s.audit.Success(actor, "trust.validate", domain, ip)
	return result, nil
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
