package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	ldapproto "sambaadm/internal/ldap"
)

const fullBackupRestoreKind = "live-dc-kerberos-ldap-sysvol-full-v1"

func expectedBackupRestoreKind(r DomainBackupRequest) string {
	if r.Purpose == "full" {
		return fullBackupRestoreKind
	}
	return backupRestoreKind
}
func fullBackupRevision(r DomainBackupRequest) string {
	r.PlanRevision = ""
	data, _ := json.Marshal(r)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func validateBackupPurpose(r DomainBackupRequest, now time.Time) error {
	switch r.Purpose {
	case "full":
		if r.Plan != nil || r.PreparedAt.IsZero() || now.Sub(r.PreparedAt) > 24*time.Hour || r.PreparedAt.After(now.Add(5*time.Minute)) || r.PlanRevision != fullBackupRevision(r) {
			return topologyBad("invalid or expired standalone backup preparation")
		}
	case "":
		if r.Plan == nil || r.Plan.Revision != r.PlanRevision {
			return topologyBad("cleanup plan required for verified backup")
		}
	default:
		return topologyBad("unsupported backup purpose")
	}
	return nil
}

// FullBackupService persists preparation on the management server before Samba
// is stopped. Start and Status deliberately need no live LDAP connection.
type FullBackupService struct {
	Sites *SiteService
	Store *ObjectBackupService
}

func (s *FullBackupService) configured(controller string) error {
	if s.Sites == nil || s.Sites.helpers == nil {
		return topologyBad("registered helper required")
	}
	for _, n := range s.Sites.helpers.Config.Nodes {
		if strings.EqualFold(n.Name, controller) {
			return nil
		}
	}
	return topologyBad("controller must have a registered helper")
}
func fullPlanName(id string) string { return ".full-plan-" + id + ".json" }
func (s *FullBackupService) Prepare(ctx context.Context, controller, actor, ip string) (out *DomainBackupRequest, err error) {
	defer func() { s.Store.record(actor, "domain.full-backup.prepare", controller, ip, err) }()
	if s.Sites == nil {
		return nil, topologyBad("domain services unavailable")
	}
	dc, err := s.Sites.controller(ctx, controller)
	if err != nil {
		return nil, err
	}
	if dc.RODC {
		return nil, topologyBad("writable DC required")
	}
	if err = s.configured(dc.DNS); err != nil {
		return nil, err
	}
	if _, err = backupHostFile(dc.DNS); err != nil {
		return nil, err
	}
	entry, err := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: s.Sites.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=domainDNS)", Attributes: []string{"objectGUID"}})
	if err != nil {
		return nil, err
	}
	guid := entry.GetEqualFoldRawAttributeValue("objectGUID")
	if len(guid) != 16 {
		return nil, topologyBad("domain identity unavailable")
	}
	out = &DomainBackupRequest{Purpose: "full", PreparedAt: time.Now().UTC(), ID: uuid.NewString(), Controller: dc.DNS, DomainGUID: guid, BaseDN: s.Sites.ldap.BaseDN()}
	out.PlanRevision = fullBackupRevision(*out)
	root, err := s.Store.store(true)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = createBackupJSON(root, fullPlanName(out.ID), out); err != nil {
		return nil, err
	}
	return out, nil
}
func (s *FullBackupService) Load(id string) (*DomainBackupRequest, error) {
	if !validBackupID(id) {
		return nil, topologyBad("valid job UUID required")
	}
	root, err := s.Store.store(false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var out DomainBackupRequest
	if err = readBackupJSON(root, fullPlanName(id), &out); err != nil {
		return nil, err
	}
	if out.ID != id || out.Purpose != "full" || out.Plan != nil || len(out.DomainGUID) != 16 || out.PlanRevision != fullBackupRevision(out) {
		return nil, topologyBad("invalid prepared backup identity")
	}
	if err = s.configured(out.Controller); err != nil {
		return nil, err
	}
	return &out, nil
}
func (s *FullBackupService) List() ([]DomainBackupRequest, error) {
	out := []DomainBackupRequest{}
	root, err := s.Store.store(false)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(2001)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 2000 {
		return nil, fmt.Errorf("backup directory entry limit exceeded")
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".full-plan-") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(e.Name(), ".full-plan-"), ".json")
		if !validBackupID(id) {
			continue
		}
		p, err := s.Load(id)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PreparedAt.After(out[j].PreparedAt) })
	return out, nil
}
func (s *FullBackupService) Start(ctx context.Context, id, revision, actor, ip string) (out *DomainBackupJob, err error) {
	defer func() { s.Store.record(actor, "domain.full-backup.start", id, ip, err) }()
	req, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	if revision == "" || revision != req.PlanRevision {
		return nil, ErrTopologyConflict
	}
	if err = validateBackupPurpose(*req, time.Now()); err != nil {
		return nil, err
	}
	out = &DomainBackupJob{}
	err = s.Sites.helpers.Call(ctx, req.Controller, "domain.backup.start", HostOperation{Input: hostInput(req), Actor: actor, IP: ip}, out)
	return out, err
}
func (s *FullBackupService) Status(ctx context.Context, id string) (*DomainBackupJob, error) {
	req, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	out := &DomainBackupJob{}
	if err = s.Sites.helpers.Call(ctx, req.Controller, "domain.backup.status", HostOperation{Name: id}, out); err != nil {
		return nil, err
	}
	if string(hostInput(out.DomainBackupRequest)) != string(hostInput(req)) {
		return nil, fmt.Errorf("helper backup job identity mismatch")
	}
	return out, nil
}
