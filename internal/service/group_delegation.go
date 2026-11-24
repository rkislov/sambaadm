package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

// Only the selected group's DACL is read/written. These profiles grant neither
// WRITE_DAC/WRITE_OWNER nor inheritance to other directory objects.
type GroupAccess struct {
	Revision string        `json:"revision"`
	DN       string        `json:"dn"`
	Entries  []GPFilterACE `json:"entries"`
}

func (s *GroupService) accessEntry(ctx context.Context, name string) (*ldap.Entry, error) {
	g, e := s.find(ctx, name)
	if e != nil {
		return nil, e
	}
	return s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: g.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=group)", Attributes: []string{"nTSecurityDescriptor", "uSNChanged", "objectGUID"}, Controls: []ldap.Control{daclControl}})
}
func (s *GroupService) Access(ctx context.Context, name string) (*GroupAccess, error) {
	e, err := s.accessEntry(ctx, name)
	if err != nil {
		return nil, err
	}
	aces, err := policyACEs(e.GetRawAttributeValue("nTSecurityDescriptor"))
	if err != nil {
		return nil, err
	}
	out := &GroupAccess{DN: e.DN, Revision: e.GetAttributeValue("uSNChanged"), Entries: []GPFilterACE{}}
	for _, a := range aces {
		out.Entries = append(out.Entries, filterACE(a))
	}
	return out, nil
}
func groupAccessACE(sid []byte, profile string) ([]byte, error) {
	if sidString(sid) == "" {
		return nil, fmt.Errorf("%w: некорректный SID", ErrGroupInput)
	}
	if profile == "read" {
		a := make([]byte, 8)
		binary.LittleEndian.PutUint16(a[2:], uint16(8+len(sid)))
		binary.LittleEndian.PutUint32(a[4:], 0x20094)
		return append(a, sid...), nil
	}
	if profile != "manage-members" {
		return nil, fmt.Errorf("%w: неизвестный профиль делегирования", ErrGroupInput)
	}
	a := make([]byte, 28)
	a[0] = 5
	binary.LittleEndian.PutUint16(a[2:], uint16(28+len(sid)))
	binary.LittleEndian.PutUint32(a[4:], 0x20)
	binary.LittleEndian.PutUint32(a[8:], 1)
	// member attribute schemaIDGUID: bf9679c0-0de6-11d0-a285-00aa003049e2.
	copy(a[12:], []byte{0xc0, 0x79, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0, 0xaa, 0, 0x30, 0x49, 0xe2})
	return append(a, sid...), nil
}
func (s *GroupService) accessPlan(ctx context.Context, name string, in GPDelegationChange) (*GPDelegationPreview, []byte, error) {
	if _, e := assertion(in.Revision); e != nil {
		return nil, nil, fmt.Errorf("%w: требуется версия прав", ErrGroupInput)
	}
	entry, e := s.accessEntry(ctx, name)
	if e != nil {
		return nil, nil, e
	}
	if entry.GetAttributeValue("uSNChanged") != in.Revision {
		return nil, nil, ErrGroupConflict
	}
	sid, e := (&GPOService{ldap: s.ldap}).delegationSID(ctx, in.Principal)
	if e != nil {
		return nil, nil, e
	}
	ace, e := groupAccessACE(sid, in.Profile)
	if e != nil {
		return nil, nil, e
	}
	additions := [][]byte{ace}
	if in.Profile == "manage-members" {
		read, _ := groupAccessACE(sid, "read")
		additions = append([][]byte{read}, additions...)
	}
	old := entry.GetRawAttributeValue("nTSecurityDescriptor")
	sd, added, e := delegationDescriptor(old, additions)
	if e != nil {
		return nil, nil, e
	}
	raw, _ := json.Marshal([]any{entry.DN, entry.GetRawAttributeValue("objectGUID"), in.Revision, in.Principal, in.Profile, sid, old, sd})
	digest := sha256.Sum256(raw)
	aces, _ := policyACEs(old)
	return &GPDelegationPreview{Revision: in.Revision, Preview: hex.EncodeToString(digest[:]), DN: entry.DN, SID: sidString(sid), Profile: in.Profile, Added: added, Unchanged: len(aces), LDAPOnly: true, Warnings: []string{"existing-permissions-preserved", "effective-access-not-evaluated"}}, sd, nil
}
func (s *GroupService) AccessPreview(ctx context.Context, name string, in GPDelegationChange) (*GPDelegationPreview, error) {
	p, _, e := s.accessPlan(ctx, name, in)
	return p, e
}
func (s *GroupService) GrantAccess(ctx context.Context, name string, in GPDelegationChange, actor, ip string) error {
	if in.Preview == "" {
		return fmt.Errorf("%w: сначала выполните предпросмотр", ErrGroupInput)
	}
	p, sd, e := s.accessPlan(ctx, name, in)
	if e != nil {
		return e
	}
	if p.Preview != in.Preview {
		return ErrGroupConflict
	}
	if len(p.Added) == 0 {
		return nil
	}
	controls, e := assertion(in.Revision)
	if e != nil {
		return e
	}
	controls = append(controls, daclControl)
	req := ldap.NewModifyRequest(p.DN, controls)
	req.Replace("nTSecurityDescriptor", []string{string(sd)})
	e = s.ldap.Modify(ctx, req)
	target := p.DN + " / " + p.SID + " / " + p.Profile
	if e != nil {
		s.audit.Failure(actor, "group.delegate", target, ip, e)
		if ldap.IsErrorWithCode(e, 122) {
			return ErrGroupConflict
		}
		return e
	}
	s.audit.Success(actor, "group.delegate", target, ip)
	return nil
}
