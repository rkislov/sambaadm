package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
	Raw       string         `json:"raw,omitempty"`
	Server    string         `json:"server"`
	Health    string         `json:"health"`
	Neighbors []ReplNeighbor `json:"neighbors"`
	Partners  []ReplPartner  `json:"partners,omitempty"`
}

// ReplService manages AD replication.
type ReplService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
	tool  *samba.Runner
}

// Partners returns known nTDSDSA objects from the configuration partition.
func (s *ReplService) Partners(ctx context.Context) ([]ReplPartner, error) {
	controllers, err := (&SiteService{ldap: s.ldap}).Controllers(ctx)
	if err != nil {
		return nil, err
	}
	out := []ReplPartner{}
	for _, dc := range controllers {
		out = append(out, ReplPartner{Name: dc.DNS, DN: dc.NTDS, Status: "configured"})
	}
	return out, nil
}

// Status returns replication status via samba-tool drs showrepl when available.
func (s *ReplService) Status(ctx context.Context) (*ReplStatus, error) {
	return s.StatusFor(ctx, "")
}

// Sync triggers replication from a source DC via samba-tool drs replicate.
// Naming context defaults to the domain NC (base DN).
func (s *ReplService) Sync(ctx context.Context, destDC, sourceDC, nc, actor, ip string) error {
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available on this host")
	}
	if destDC == "" || sourceDC == "" || strings.ContainsAny(destDC+sourceDC, " /\\\t\r\n") || strings.HasPrefix(destDC, "-") || strings.HasPrefix(sourceDC, "-") {
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
	u, e := url.Parse(strings.TrimSpace(uri))
	if e != nil || !(u.Scheme == "ldap" || u.Scheme == "ldaps") {
		return ""
	}
	return u.Hostname()
}

type ReplNeighbor struct {
	Direction   string `json:"direction"`
	Partition   string `json:"partition"`
	Partner     string `json:"partner"`
	LastAttempt string `json:"lastAttempt"`
	LastSuccess string `json:"lastSuccess"`
	Failures    int    `json:"failures"`
	Result      string `json:"result"`
	Health      string `json:"health"`
}

func (s *ReplService) StatusFor(ctx context.Context, server string) (*ReplStatus, error) {
	if s.tool == nil || !s.tool.Available() {
		return nil, fmt.Errorf("samba-tool is not available")
	}
	if server == "" {
		server = hostnameFromURI(s.ldap.URI())
	}
	if server == "" {
		server = "localhost"
	}
	// Explicit targets must be configured DCs; do not accept arbitrary RPC hosts.
	if server != "localhost" && server != hostnameFromURI(s.ldap.URI()) {
		dc, e := (&SiteService{ldap: s.ldap}).controller(ctx, server)
		if e != nil {
			return nil, e
		}
		server = dc.DNS
	}
	res, e := s.tool.Run(ctx, "drs", "showrepl", server, "--json")
	if e != nil {
		return nil, e
	}
	st, e := parseReplStatus(res.Stdout)
	if e != nil {
		return nil, e
	}
	st.Server = server
	st.Partners, _ = s.Partners(ctx)
	return st, nil
}
func parseReplStatus(raw string) (*ReplStatus, error) {
	type neighbor struct {
		Partition string `json:"NC dn"`
		Partner   string `json:"DSA"`
		NTDS      string `json:"NTDS DN"`
		Attempt   string `json:"last attempt time"`
		Success   string `json:"last success"`
		Failures  int    `json:"consecutive failures"`
		Result    string `json:"last attempt message"`
		Deleted   bool   `json:"is deleted"`
	}
	var payload struct {
		From []neighbor `json:"repsFrom"`
		To   []neighbor `json:"repsTo"`
	}
	var keys map[string]json.RawMessage
	if e := json.Unmarshal([]byte(raw), &keys); e != nil {
		return nil, e
	}
	if keys["repsFrom"] == nil || keys["repsTo"] == nil {
		return nil, fmt.Errorf("unexpected Samba replication JSON")
	}
	if e := json.Unmarshal([]byte(raw), &payload); e != nil {
		return nil, e
	}
	st := &ReplStatus{Raw: raw, Health: "no-partners", Neighbors: []ReplNeighbor{}}
	for _, set := range []struct {
		direction string
		rows      []neighbor
	}{{"inbound", payload.From}, {"outbound", payload.To}} {
		for _, n := range set.rows {
			if n.Deleted {
				continue
			}
			health := "healthy"
			if n.Failures > 0 || n.Result != "was successful" {
				health = "failed"
			} else if n.Success == "" || strings.Contains(n.Success, "1601") || strings.Contains(n.Success, "NTTIME(0)") {
				health = "never-succeeded"
			}
			partner := n.Partner
			if partner == "" {
				partner = n.NTDS
			}
			st.Neighbors = append(st.Neighbors, ReplNeighbor{set.direction, n.Partition, partner, n.Attempt, n.Success, n.Failures, n.Result, health})
			if st.Health == "no-partners" {
				st.Health = "healthy"
			}
			if health != "healthy" {
				st.Health = "degraded"
			}
		}
	}
	return st, nil
}
func (s *ReplService) KCC(ctx context.Context, server, actor, ip string) error {
	dc, e := (&SiteService{ldap: s.ldap}).controller(ctx, server)
	if e != nil {
		return e
	}
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available")
	}
	_, e = s.tool.Run(ctx, "drs", "kcc", dc.DNS)
	if e != nil {
		s.audit.Failure(actor, "repl.kcc", dc.DNS, ip, e)
	} else {
		s.audit.Success(actor, "repl.kcc", dc.DNS, ip)
	}
	return e
}

func (s *ReplService) DefaultDestination() string {
	if host := hostnameFromURI(s.ldap.URI()); host != "" {
		return host
	}
	return "localhost"
}
