package service

import (
	"context"
	"fmt"
	"strings"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/samba"
)

// ReplPartner is a replication partner / DSA summary.
type ReplPartner struct {
	Name   string `json:"name"`
	DN     string `json:"dn,omitempty"`
	Status string `json:"status,omitempty"`
}

// ReplStatus is raw / parsed replication status.
type ReplStatus struct {
	Raw      string       `json:"raw,omitempty"`
	Partners []ReplPartner `json:"partners,omitempty"`
}

// ReplService manages AD replication.
type ReplService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
	tool  *samba.Runner
}

// Partners returns known nTDSDSA objects from the configuration partition.
func (s *ReplService) Partners(ctx context.Context) ([]ReplPartner, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     ConfigDN(s.ldap.BaseDN()),
		Filter:     "(objectClass=nTDSDSA)",
		Attributes: []string{"cn", "dNSHostName", "invocationId"},
	})
	if err != nil {
		// Fallback: whole tree search
		entries, err = s.ldap.Search(ctx, ldapproto.SearchOptions{
			Filter:     "(objectClass=nTDSDSA)",
			Attributes: []string{"cn", "dNSHostName", "invocationId"},
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]ReplPartner, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("dNSHostName")
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		out = append(out, ReplPartner{Name: name, DN: e.DN, Status: "configured"})
	}
	return out, nil
}

// Status returns replication status via samba-tool drs showrepl when available.
func (s *ReplService) Status(ctx context.Context) (*ReplStatus, error) {
	partners, _ := s.Partners(ctx)
	st := &ReplStatus{Partners: partners}
	if s.tool != nil && s.tool.Available() {
		res, err := s.tool.Run(ctx, "drs", "showrepl")
		if err != nil {
			st.Raw = err.Error()
			return st, nil
		}
		st.Raw = res.Stdout
	}
	return st, nil
}

// Sync triggers replication from a source DC via samba-tool drs replicate.
// Naming context defaults to the domain NC (base DN).
func (s *ReplService) Sync(ctx context.Context, destDC, sourceDC, nc, actor, ip string) error {
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available on this host")
	}
	if destDC == "" || sourceDC == "" {
		return fmt.Errorf("destination and source DC are required")
	}
	if nc == "" {
		nc = s.ldap.BaseDN()
	}
	args := []string{"drs", "replicate", destDC, sourceDC, nc}
	target := fmt.Sprintf("%s <- %s (%s)", destDC, sourceDC, nc)
	if _, err := s.tool.Run(ctx, args...); err != nil {
		s.audit.Failure(actor, "repl.sync", target, ip, err)
		return err
	}
	s.audit.Success(actor, "repl.sync", target, ip)
	return nil
}

// SyncFrom is a convenience when only --from is known (uses localhost as dest).
func (s *ReplService) SyncFrom(ctx context.Context, sourceDC, actor, ip string) error {
	dest := "localhost"
	if host := hostnameFromURI(s.ldap.URI()); host != "" {
		dest = host
	}
	return s.Sync(ctx, dest, sourceDC, "", actor, ip)
}

func hostnameFromURI(uri string) string {
	uri = strings.TrimSpace(uri)
	for _, p := range []string{"ldaps://", "ldap://"} {
		if strings.HasPrefix(uri, p) {
			host := strings.TrimPrefix(uri, p)
			if i := strings.IndexAny(host, ":/"); i >= 0 {
				host = host[:i]
			}
			return host
		}
	}
	return ""
}
