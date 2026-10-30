package service

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

type smbRepairVolume struct {
	share  *smb2.Share
	parent string
}

func (v *smbRepairVolume) Tree(name string) policyStore {
	return &smbPolicyStore{share: v.share, base: path.Join(v.parent, name)}
}
func (v *smbRepairVolume) Rename(a, b string) error {
	// Cutover must never overwrite an unexpected live or backup directory.
	p := &smbPolicyStore{share: v.share, base: v.parent}
	if _, e := p.Lstat(b); !os.IsNotExist(e) {
		if e != nil {
			return e
		}
		return ErrTopologyConflict
	}
	return p.Rename(a, b)
}
func (v *smbRepairVolume) Mkdir(n string) error {
	return (&smbPolicyStore{share: v.share, base: v.parent}).Mkdir(n, 0700)
}

func repairLDAP(entry *ldap.Entry) (string, error) {
	m, e := consistencyMetadata(entry)
	if e != nil {
		return "", e
	}
	a, e := consistencyACL(entry.GetRawAttributeValue("nTSecurityDescriptor"))
	if e != nil {
		return "", e
	}
	v, e := strconv.ParseUint(entry.GetAttributeValue("versionNumber"), 10, 32)
	if e != nil {
		return "", e
	}
	return consistencyHash([]any{m, a, v, strings.ToLower(entry.DN)}), nil
}
func (s *GPOService) withRepairDC(ctx context.Context, gpo, host string, fn func(*GPOService, *ldap.Entry, repairVolume, string) error) error {
	dcs, e := (&SiteService{ldap: s.ldap}).Controllers(ctx)
	if e != nil {
		return e
	}
	found := false
	for _, dc := range dcs {
		if strings.EqualFold(dc.DNS, host) {
			found = true
			host = dc.DNS
			break
		}
	}
	if !found {
		return topologyBad("select a discovered DC DNS name")
	}
	uri, e := consistencyPeerURI(s.ldap.URI(), host)
	if e != nil {
		return e
	}
	if s.remote == nil {
		return fmt.Errorf("SYSVOL service credentials required")
	}
	remote := *s.remote
	remote.Host = host
	conn, e := s.ldap.Conn(ctx)
	if e != nil {
		return e
	}
	root, e := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName"}, nil))
	if e != nil {
		return e
	}
	if len(root.Entries) == 1 && strings.EqualFold(root.Entries[0].GetEqualFoldAttributeValue("dNSHostName"), host) {
		uri = s.ldap.URI()
		remote.Host = s.remote.Host
	}
	peer := s.ldap.ServicePeer(uri)
	defer peer.Close()
	other := &GPOService{ldap: peer, remote: &remote, gpoCfg: s.gpoCfg}
	pc, e := peer.Conn(ctx)
	if e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	root, e = pc.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName"}, nil))
	if e != nil {
		return e
	}
	if len(root.Entries) != 1 || !strings.EqualFold(root.Entries[0].GetEqualFoldAttributeValue("dNSHostName"), host) {
		return fmt.Errorf("DC identity mismatch")
	}
	entry, e := readConsistencyLDAP(ctx, other, gpo)
	if e != nil {
		return e
	}
	base, e := other.policyPath(ctx, entry)
	if e != nil {
		return e
	}
	base = strings.ReplaceAll(base, `\`, "/")
	return remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(sh *smb2.Share) error { return fn(other, entry, &smbRepairVolume{sh, path.Dir(base)}, base) })
}
func validateRepair(in RepairInput) error {
	switch in.Operation {
	case "repair":
		if in.Source == "" || in.Target == "" || strings.EqualFold(in.Source, in.Target) || in.Record != "" {
			return topologyBad("choose distinct source and target DCs")
		}
	case "complete", "rollback":
		if _, e := delegationRecordName(in.Record); e != nil {
			return e
		}
		if in.Source != "" || in.Target != "" {
			return topologyBad("recovery accepts record ID only")
		}
	default:
		return topologyBad("invalid repair operation")
	}
	return nil
}
func (s *GPOService) repairLocal() (*os.Root, error) {
	p, e := s.delegationStateRoot()
	if e != nil {
		return nil, e
	}
	defer p.Close()
	return repairStateRoot(p)
}
func (s *GPOService) RepairHistory(ctx context.Context, gpo string) ([]RepairSummary, error) {
	if !looksLikeGUID(gpo) {
		return nil, topologyBad("GPO GUID required")
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	local, e := s.repairLocal()
	if e != nil {
		return nil, e
	}
	defer local.Close()
	return repairRecords(local, braceGUID(gpo))
}
func (s *GPOService) buildRepair(ctx context.Context, local *os.Root, gpo string, in RepairInput) (*RepairPlan, error) {
	if s.remote == nil {
		return nil, fmt.Errorf("SYSVOL service credentials required")
	}
	// A pending coordinated ACL operation must be recovered before a tree swap.
	parent, e := s.delegationStateRoot()
	if e != nil {
		return nil, e
	}
	dnEntry, e := s.policyEntry(ctx, gpo)
	if e != nil {
		parent.Close()
		return nil, e
	}
	pending, e := delegationRecords(parent, "", dnEntry.DN)
	parent.Close()
	if e != nil {
		return nil, e
	}
	if id := delegationHistory(pending).Pending; id != "" {
		return nil, fmt.Errorf("recover pending delegation %s first", id)
	}
	p := &RepairPlan{Operation: in.Operation, Source: in.Source, Target: in.Target, Record: in.Record, Changes: []ConsistencyDifference{}, Warnings: []string{"Use a maintenance window: directory cutover has a brief interval with no live GPO directory.", "Pause external GPO editors and SYSVOL synchronizers; SMB has no compare-and-swap directory rename.", "Owner/group/DACL and ordinary file contents are copied; SACL, alternate streams and extended attributes are outside this repair format.", "Original directory and private local backup are retained; service metadata remains in the original directory."}}
	if in.Operation == "repair" {
		r := &RepairRecord{Format: 1, GPO: braceGUID(gpo), Source: in.Source, Target: in.Target, State: "pending", Direction: "complete"}
		p.record = r
		e := s.withRepairDC(ctx, gpo, in.Source, func(other *GPOService, entry *ldap.Entry, v repairVolume, base string) error {
			var e error
			r.LDAP, e = repairLDAP(entry)
			if e != nil {
				return e
			}
			r.After, e = captureRepair(ctx, v.Tree(path.Base(base)))
			if e != nil {
				return e
			}
			foundVersion := false
			for _, o := range r.After.Objects {
				if strings.EqualFold(o.Path, "GPT.INI") {
					foundVersion = true
					version, _, e := gptVersion(o.Data, nil)
					if e != nil {
						return e
					}
					if strconv.FormatUint(uint64(version), 10) != entry.GetAttributeValue("versionNumber") {
						return fmt.Errorf("source LDAP/GPT.INI versions differ")
					}
				}
			}
			if !foundVersion {
				return fmt.Errorf("source GPT.INI is missing")
			}
			again, e := readConsistencyLDAP(ctx, other, gpo)
			if e != nil {
				return e
			}
			if again.GetAttributeValue("uSNChanged") != entry.GetAttributeValue("uSNChanged") {
				return ErrTopologyConflict
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
		records, e := repairRecords(local, r.GPO)
		if e != nil {
			return nil, e
		}
		for _, old := range records {
			if old.State == "pending" && (strings.EqualFold(old.Target, r.Target) || strings.EqualFold(old.Target, r.Source)) {
				return nil, fmt.Errorf("recover pending repair %s first", old.ID)
			}
		}
		e = s.withRepairDC(ctx, gpo, in.Target, func(other *GPOService, entry *ldap.Entry, v repairVolume, base string) error {
			fp, e := repairLDAP(entry)
			if e != nil {
				return e
			}
			if fp != r.LDAP {
				return fmt.Errorf("LDAP metadata, security or version differs; resolve LDAP replication first")
			}
			r.Base = base
			if _, e = v.Tree(path.Base(base)).Lstat("."); os.IsNotExist(e) {
				r.Before = nil
				return nil
			} else if e != nil {
				return e
			}
			r.Before, e = captureRepair(ctx, v.Tree(path.Base(base)))
			if e != nil {
				return e
			}
			again, e := readConsistencyLDAP(ctx, other, gpo)
			if e != nil {
				return e
			}
			if again.GetAttributeValue("uSNChanged") != entry.GetAttributeValue("uSNChanged") {
				return ErrTopologyConflict
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
		if repairSignature(r.Before) == r.After.Signature {
			return nil, topologyBad("SYSVOL copies already match")
		}
		p.Changes = repairPlanChanges(r.Before, r.After)
		p.Preview = consistencyHash([]any{in.Operation, r.GPO, r.Source, r.Target, r.Base, r.LDAP, repairSignature(r.Before), r.After.Signature})
	} else {
		r, e := readRepair(local, in.Record)
		if e != nil {
			return nil, e
		}
		if r.GPO != braceGUID(gpo) {
			return nil, topologyBad("record belongs to another GPO")
		}
		if r.State == "rolled-back" {
			return nil, topologyBad("repair already rolled back")
		}
		if in.Operation == "complete" && r.Direction == "rollback" {
			return nil, topologyBad("rollback has started; continue rollback")
		}
		records, e := repairRecords(local, r.GPO)
		if e != nil {
			return nil, e
		}
		for _, newer := range records {
			if newer.ID != r.ID && strings.EqualFold(newer.Target, r.Target) && newer.Created.After(r.Created) && newer.State != "rolled-back" {
				return nil, fmt.Errorf("recover or roll back newer repair %s first", newer.ID)
			}
		}
		p.record = r
		p.Source = r.Source
		p.Target = r.Target
		e = s.withRepairDC(ctx, gpo, r.Target, func(_ *GPOService, entry *ldap.Entry, v repairVolume, base string) error {
			fp, e := repairLDAP(entry)
			if e != nil {
				return e
			}
			if fp != r.LDAP || base != r.Base {
				return ErrTopologyConflict
			}
			states := []string{}
			for _, n := range []string{repairLive(r), repairBackup(r), repairArchive(r)} {
				sig, e := repairTreeState(ctx, v, n, r)
				if e != nil {
					return e
				}
				states = append(states, sig)
			}
			if e := validateRepairLocations(r, states[0], states[1], states[2], in.Operation); e != nil {
				return e
			}
			p.Preview = consistencyHash([]any{in.Operation, r.ID, r.GPO, r.Target, r.LDAP, r.State, r.Direction, states})
			return nil
		})
		if e != nil {
			return nil, e
		}
		if in.Operation == "rollback" {
			p.Changes = repairPlanChanges(r.After, r.Before)
		} else {
			p.Changes = repairPlanChanges(r.Before, r.After)
		}
	}
	p.ACLChanges = repairACLChanges(p.record.Before, p.record.After)
	if in.Operation == "rollback" {
		p.ACLChanges = repairACLChanges(p.record.After, p.record.Before)
	}
	return p, nil
}
func (s *GPOService) RepairPreview(ctx context.Context, gpo string, in RepairInput) (*RepairPlan, error) {
	if !looksLikeGUID(gpo) {
		return nil, topologyBad("GPO GUID required")
	}
	if e := validateRepair(in); e != nil {
		return nil, e
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	local, e := s.repairLocal()
	if e != nil {
		return nil, e
	}
	defer local.Close()
	return s.buildRepair(ctx, local, gpo, in)
}
func (s *GPOService) RepairApply(ctx context.Context, gpo string, in RepairInput, actor, ip string) (out *RepairResult, err error) {
	if !looksLikeGUID(gpo) {
		return nil, topologyBad("GPO GUID required")
	}
	if e := validateRepair(in); e != nil {
		return nil, e
	}
	if in.Preview == "" {
		return nil, topologyBad("preview required")
	}
	auditTarget := gpo
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "gpo.sysvol."+in.Operation, auditTarget, ip, err)
		} else {
			s.audit.Success(actor, "gpo.sysvol."+in.Operation, auditTarget, ip)
		}
	}()
	err = func() error {
		s.editorMu.Lock()
		defer s.editorMu.Unlock()
		ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		local, e := s.repairLocal()
		if e != nil {
			return e
		}
		defer local.Close()
		p, e := s.buildRepair(ctx, local, gpo, in)
		if e != nil {
			return e
		}
		if p.Preview != in.Preview {
			return ErrTopologyConflict
		}
		r := p.record
		if in.Operation == "repair" {
			r.ID = uuid.NewString()
			r.Created = time.Now().UTC()
		} else if in.Operation == "rollback" {
			r.Direction = "rollback"
			r.State = "pending"
		}
		auditTarget = fmt.Sprintf("%s source=%s target=%s record=%s", gpo, r.Source, r.Target, r.ID)
		// Both original and desired contents are flushed locally before any SMB write.
		if e = saveRepair(local, r); e != nil {
			return e
		}
		e = s.withRepairDC(ctx, gpo, r.Target, func(other *GPOService, entry *ldap.Entry, v repairVolume, base string) error {
			if base != r.Base {
				return ErrTopologyConflict
			}
			check := func() error {
				entry, e := readConsistencyLDAP(ctx, other, gpo)
				if e != nil {
					return e
				}
				fp, e := repairLDAP(entry)
				if e != nil {
					return e
				}
				if fp != r.LDAP {
					return ErrTopologyConflict
				}
				return nil
			}
			return runRepair(ctx, v, local, r, check)
		})
		if e != nil {
			return fmt.Errorf("repair %s requires recovery; retain local journal and remote backup: %w", r.ID, e)
		}
		out = &RepairResult{Record: r.ID, State: r.State}
		return nil
	}()
	if err != nil {
		return nil, err
	}
	out.Report, err = s.CheckConsistency(ctx, gpo, ConsistencyInput{})
	if err != nil {
		out.VerificationError = err.Error()
		err = nil
	}
	return out, nil
}
