package service

import (
	"context"
	"errors"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

type smbRepairVolume struct {
	share  *sysvolShare
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
	return s.withRepairPeer(ctx, gpo, host, false, fn)
}
func (s *GPOService) withRepairPeer(ctx context.Context, gpo, host string, sourceOnly bool, fn func(*GPOService, *ldap.Entry, repairVolume, string) error) error {
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
	other := &GPOService{ldap: peer, remote: &remote, gpoCfg: s.gpoCfg, helpers: s.helpers}
	pc, e := peer.Conn(ctx)
	if e != nil {
		return e
	}
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	root, e = pc.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName", "defaultNamingContext"}, nil))
	if e != nil {
		return e
	}
	if len(root.Entries) != 1 || !strings.EqualFold(root.Entries[0].GetEqualFoldAttributeValue("dNSHostName"), host) {
		return fmt.Errorf("DC identity mismatch")
	}
	if (sourceOnly || ctx.Value(sysvolKerberosKey{}) == true) && !strings.EqualFold(root.Entries[0].GetEqualFoldAttributeValue("defaultNamingContext"), s.ldap.BaseDN()) {
		return fmt.Errorf("Выбранный DC относится к другому домену")
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
	if sourceOnly {
		remote.Host = host // CIFS SPN must use the authenticated DC name, never a forwarded LDAP address.
		realm, err := other.domainDNS(ctx)
		if err != nil {
			return err
		}
		return remote.SYSVOLKerberos(ctx, s.gpoCfg.SMBPort, realm, func(sh *smb2.Share) error {
			return fn(other, entry, &smbRepairVolume{&sysvolShare{local: sh, ctx: ctx, readOnly: true}, path.Dir(base)}, base)
		})
	}
	return s.sysvol(ctx, &remote, s.gpoCfg.SMBPort, func(sh *sysvolShare) error { return fn(other, entry, &smbRepairVolume{sh, path.Dir(base)}, base) })
}
func validateRepair(in RepairInput) error {
	switch in.Operation {
	case "repair":
		if in.Source == "" || in.Target == "" || strings.EqualFold(in.Source, in.Target) || in.Record != "" {
			return topologyBad("choose distinct source and target DCs")
		}
	case "complete", "rollback", "prune":
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
	records, e := repairRecords(local, braceGUID(gpo))
	return repairRetention(records, s.gpoCfg), e
}
func (s *GPOService) buildRepair(ctx context.Context, local *os.Root, gpo string, in RepairInput) (*RepairPlan, error) {
	if in.Operation == "prune" {
		return s.buildRepairPrune(ctx, local, gpo, in)
	}
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
		r := &RepairRecord{Kerberos: in.WindowsSource, Format: 1, GPO: braceGUID(gpo), Source: in.Source, Target: in.Target, State: "pending", Direction: "complete"}
		p.record = r
		e := s.withRepairPeer(ctx, gpo, in.Source, in.WindowsSource, func(other *GPOService, entry *ldap.Entry, v repairVolume, base string) error {
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
			if old.State == "pruning" || (old.State == "pending" && (strings.EqualFold(old.Target, r.Target) || strings.EqualFold(old.Target, r.Source))) {
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
			if in.WindowsSource {
				if _, err := v.Tree(".").Lstat("."); err != nil {
					return fmt.Errorf("Каталог Policies получателя не инициализирован или недоступен; сначала завершите начальное развёртывание SYSVOL: %w", err)
				}
			}
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
		if in.WindowsSource {
			if err := safeSyncVersions(r.Before, r.After); err != nil {
				return nil, err
			}
		}
		if repairSignature(r.Before) == r.After.Signature && !in.WindowsSource {
			return nil, errSYSVOLMatch
		}
		p.Changes = repairPlanChanges(r.Before, r.After)
		p.Preview = consistencyHash([]any{in.Operation, in.WindowsSource, r.GPO, r.Source, r.Target, r.Base, r.LDAP, repairSignature(r.Before), r.After.Signature})
	} else {
		r, e := readRepair(local, in.Record)
		if e != nil {
			return nil, e
		}
		if r.Kerberos {
			ctx = context.WithValue(ctx, sysvolKerberosKey{}, true)
		}
		if r.GPO != braceGUID(gpo) {
			return nil, topologyBad("record belongs to another GPO")
		}
		if r.State == "pruning" || r.State == "pruned" {
			return nil, topologyBad("repair archive is being pruned or already pruned")
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
			if newer.State == "pruning" {
				return nil, topologyBad("finish archive cleanup first")
			}
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
	if in.WindowsSource {
		ctx = context.WithValue(ctx, sysvolKerberosKey{}, true)
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
	if in.WindowsSource {
		ctx = context.WithValue(ctx, sysvolKerberosKey{}, true)
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
		if r.Kerberos {
			ctx = context.WithValue(ctx, sysvolKerberosKey{}, true)
		}
		if in.Operation == "repair" {
			r.ID = uuid.NewString()
			r.Created = time.Now().UTC()
		} else if in.Operation == "rollback" {
			r.Direction = "rollback"
			r.State = "pending"
		} else if in.Operation == "prune" {
			r.State = "pruning"
		}
		auditTarget = fmt.Sprintf("%s source=%s target=%s record=%s", gpo, r.Source, r.Target, r.ID)
		// Both original and desired contents are flushed locally before any SMB write.
		if e = saveRepair(local, r); e != nil {
			return e
		}
		out = &RepairResult{Record: r.ID, State: r.State}
		e = s.withRepairDC(ctx, gpo, r.Target, func(other *GPOService, entry *ldap.Entry, v repairVolume, base string) error {
			if base != r.Base {
				return ErrTopologyConflict
			}
			if in.Operation == "prune" {
				return runRepairPrune(ctx, v, local, r)
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
				if in.WindowsSource && in.Operation == "repair" {
					return s.withRepairPeer(ctx, gpo, r.Source, true, func(_ *GPOService, entry *ldap.Entry, source repairVolume, base string) error {
						fingerprint, e := repairLDAP(entry)
						if e != nil {
							return e
						}
						if fingerprint != r.LDAP {
							return ErrTopologyConflict
						}
						current, e := scanPolicyTree(ctx, source.Tree(path.Base(base)), true)
						if e != nil {
							return e
						}
						if current.Pending || current.Signature != r.After.Signature {
							return ErrTopologyConflict
						}
						return nil
					})
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
		return out, err
	}
	if in.Operation == "prune" {
		return out, nil
	}
	out.Report, err = s.CheckConsistency(ctx, gpo, ConsistencyInput{})
	if err != nil {
		out.VerificationError = err.Error()
		err = nil
	}
	return out, nil
}

var errSYSVOLMatch = topologyBad("Копии SYSVOL уже совпадают")

func snapshotVersion(s *repairSnapshot) (uint32, error) {
	if s != nil {
		for _, o := range s.Objects {
			if strings.EqualFold(o.Path, "GPT.INI") {
				v, _, e := gptVersion(o.Data, nil)
				return v, e
			}
		}
	}
	return 0, errors.New("Не удалось прочитать версию GPT.INI")
}
func safeSyncVersions(before, after *repairSnapshot) error {
	source, e := snapshotVersion(after)
	if e != nil {
		return e
	}
	if before == nil {
		return nil
	}
	target, e := snapshotVersion(before)
	if e != nil {
		return fmt.Errorf("Версия получателя неизвестна; используйте отдельное восстановление GPO: %w", e)
	}
	if uint16(target) > uint16(source) || uint16(target>>16) > uint16(source>>16) {
		return fmt.Errorf("Получатель содержит более новую пользовательскую или компьютерную версию; понижение версии запрещено")
	}
	return nil
}
