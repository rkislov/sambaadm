package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net/url"
	"sambaadm/internal/adremote"
	"strings"
	"time"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
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
	ldap   *ldapproto.Client
	audit  *audit.Logger
	remote *adremote.Client
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

// Status returns replication status through native DRS RPC.
func (s *ReplService) Status(ctx context.Context) (*ReplStatus, error) {
	return s.StatusFor(ctx, "")
}

// Sync triggers replication from a source DC through native DRS RPC.
// Naming context defaults to the domain NC (base DN).
func (s *ReplService) Sync(ctx context.Context, destDC, sourceDC, nc, actor, ip string) error {

	if destDC == "" || sourceDC == "" || strings.ContainsAny(destDC+sourceDC, " /\\\t\r\n") || strings.HasPrefix(destDC, "-") || strings.HasPrefix(sourceDC, "-") {
		return fmt.Errorf("destination and source DC are required")
	}
	if nc == "" {
		nc = s.ldap.BaseDN()
	}
	destination, err := s.remoteFor(ctx, destDC)
	if err != nil {
		return err
	}
	source, err := (&SiteService{ldap: s.ldap}).controller(ctx, sourceDC)
	if err != nil {
		return err
	}
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: source.NTDS, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=nTDSDSA)", Attributes: []string{"objectGUID"}})
	if err != nil {
		return err
	}
	target := fmt.Sprintf("%s <- %s (%s)", destDC, sourceDC, nc)
	if err := destination.Sync(ctx, nc, entry.GetRawAttributeValue("objectGUID")); err != nil {
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
	remote, err := s.remoteFor(ctx, server)
	if err != nil {
		return nil, err
	}
	neighbors, err := remote.Neighbors(ctx)
	if err != nil {
		return nil, fmt.Errorf("replication status on %s as service account %s (ldap.bind.user; browser login does not change this account): %w", remote.Host, remote.User, err)
	}
	st := &ReplStatus{Server: remote.Host, Health: "no-partners", Neighbors: []ReplNeighbor{}}
	for _, n := range neighbors {
		item := ReplNeighbor{Direction: "inbound", Partition: n.NamingContext, Partner: n.SourceDSADN, Failures: int(n.ConsecutiveSyncFailuresCount), Result: fmt.Sprintf("%d", n.LastSyncResult), Health: "healthy"}
		if n.LastSyncAttempt != nil && !n.LastSyncAttempt.IsZero() {
			item.LastAttempt = n.LastSyncAttempt.AsTime().Format(time.RFC3339)
		}
		if n.LastSyncSuccess != nil && !n.LastSyncSuccess.IsZero() {
			item.LastSuccess = n.LastSyncSuccess.AsTime().Format(time.RFC3339)
		}
		if item.Failures > 0 || n.LastSyncResult != 0 || item.LastSuccess == "" {
			item.Health = "degraded"
		}
		st.Neighbors = append(st.Neighbors, item)
		if st.Health == "no-partners" {
			st.Health = "healthy"
		}
		if item.Health == "degraded" {
			st.Health = "degraded"
		}
	}
	st.Partners, err = s.Partners(ctx)
	if err != nil {
		return nil, err
	}
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
	remote, e := s.remoteFor(ctx, server)
	if e != nil {
		return e
	}
	e = remote.KCC(ctx)
	if e != nil {
		s.audit.Failure(actor, "repl.kcc", remote.Host, ip, e)
	} else {
		s.audit.Success(actor, "repl.kcc", remote.Host, ip)
	}
	return e
}

func (s *ReplService) DefaultDestination() string {
	if host := hostnameFromURI(s.ldap.URI()); host != "" {
		return host
	}
	return "localhost"
}

func (s *ReplService) remoteFor(ctx context.Context, server string) (*adremote.Client, error) {
	remote := *s.remote
	if server == "" || server == remote.Host {
		return &remote, nil
	}
	dc, err := (&SiteService{ldap: s.ldap}).controller(ctx, server)
	if err != nil {
		return nil, err
	}
	conn, err := s.ldap.Conn(ctx)
	if err != nil {
		return nil, err
	}
	root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dNSHostName"}, nil))
	if err != nil {
		return nil, err
	}
	if len(root.Entries) != 1 {
		return nil, fmt.Errorf("missing RootDSE")
	}
	if !strings.EqualFold(dc.DNS, root.Entries[0].GetEqualFoldAttributeValue("dNSHostName")) {
		remote.Host = dc.DNS
	}
	return &remote, nil
}
