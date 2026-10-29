package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

// Delegation changes are additive. Existing deny, inherited, administrative and
// opaque ACEs remain byte-for-byte intact. These permissions apply to LDAP only.
type GPDelegationChange struct {
	Revision  string `json:"revision"`
	Principal string `json:"principal"`
	Profile   string `json:"profile"`
	Preview   string `json:"preview,omitempty"`
}
type GPDelegationPreview struct {
	Revision  string        `json:"revision"`
	Preview   string        `json:"preview"`
	DN        string        `json:"dn"`
	SID       string        `json:"sid"`
	Profile   string        `json:"profile"`
	Added     []GPFilterACE `json:"added"`
	Unchanged int           `json:"unchanged"`
	LDAPOnly  bool          `json:"ldapOnly"`
	Warnings  []string      `json:"warnings"`
}

func (s *GPOService) delegationSID(ctx context.Context, principal string) ([]byte, error) {
	if principal == "S-1-5-11" {
		return []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}, nil
	}
	dn, err := ldap.ParseDN(principal)
	base, be := ldap.ParseDN(s.ldap.BaseDN())
	if err != nil || be != nil || !base.AncestorOfFold(dn) {
		return nil, topologyBad("select a principal in this domain")
	}
	p, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: principal, Scope: ldapproto.ScopeBase(), Filter: "(|(objectClass=user)(objectClass=group))", Attributes: []string{"objectSid", "groupType"}})
	if err != nil {
		return nil, err
	}
	if gt := p.GetAttributeValue("groupType"); gt != "" {
		n, err := strconv.ParseInt(gt, 10, 64)
		if err != nil || uint32(n)&0x80000000 == 0 {
			return nil, topologyBad("select a security group")
		}
	}
	sid := p.GetRawAttributeValue("objectSid")
	if sidString(sid) == "" {
		return nil, topologyBad("invalid principal SID")
	}
	return sid, nil
}

func delegationACEs(sid []byte, profile string) ([][]byte, error) {
	if sidString(sid) == "" {
		return nil, topologyBad("invalid principal SID")
	}
	// READ_CONTROL | LIST_CHILDREN | READ_PROPERTY | LIST_OBJECT.
	mask := uint32(0x20094)
	switch profile {
	case "read", "read-apply":
	case "edit-ldap":
		// Add CREATE_CHILD | DELETE_CHILD | WRITE_PROPERTY; not DELETE,
		// WRITE_DAC, WRITE_OWNER, or extended rights on the GPO itself.
		mask |= 0x23
	default:
		return nil, topologyBad("unknown LDAP delegation profile")
	}
	a := make([]byte, 8)
	a[1] = 2 // CONTAINER_INHERIT_ACE: LDAP directory descendants.
	binary.LittleEndian.PutUint16(a[2:], uint16(8+len(sid)))
	binary.LittleEndian.PutUint32(a[4:], mask)
	a = append(a, sid...)
	out := [][]byte{a}
	if profile == "read-apply" {
		apply := make([]byte, 28)
		apply[0] = 5
		binary.LittleEndian.PutUint16(apply[2:], uint16(28+len(sid)))
		binary.LittleEndian.PutUint32(apply[4:], 0x100)
		binary.LittleEndian.PutUint32(apply[8:], 1)
		copy(apply[12:], applyPolicyGUID)
		out = append(out, append(apply, sid...))
	}
	return out, nil
}

func delegationDescriptor(old []byte, additions [][]byte) ([]byte, []GPFilterACE, error) {
	aces, err := policyACEs(old)
	if err != nil {
		return nil, nil, err
	}
	// Refuse a malformed ordering instead of silently changing existing semantics.
	inherited, allow := false, false
	for _, a := range aces {
		if a[1]&16 != 0 {
			inherited = true
			continue
		}
		if inherited {
			return nil, nil, topologyBad("noncanonical DACL: explicit ACE follows inherited ACE")
		}
		if a[0] == 0 || a[0] == 5 {
			allow = true
		}
		if allow && (a[0] == 1 || a[0] == 6) {
			return nil, nil, topologyBad("noncanonical DACL: deny follows allow")
		}
	}
	added := []GPFilterACE{}
	for _, a := range additions {
		exists := false
		for _, current := range aces {
			if bytes.Equal(a, current) {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		at := len(aces)
		for i, current := range aces {
			if current[1]&16 != 0 {
				at = i
				break
			}
		}
		aces = append(aces, nil)
		copy(aces[at+1:], aces[at:])
		aces[at] = a
		added = append(added, filterACE(a))
	}
	sd, err := daclDescriptor(old, aces)
	if err == nil {
		for _, a := range aces {
			if a[0] == 5 || a[0] == 6 {
				sd[20] = 4
				break
			}
		}
	}
	return sd, added, err
}

func (s *GPOService) delegationPlan(ctx context.Context, gpo string, in GPDelegationChange) (*GPDelegationPreview, []byte, error) {
	if in.Revision == "" || in.Principal == "" {
		return nil, nil, topologyBad("revision and principal required")
	}
	if _, err := delegationACEs([]byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}, in.Profile); err != nil {
		return nil, nil, err
	}
	entry, err := s.filterEntry(ctx, gpo)
	if err != nil {
		return nil, nil, err
	}
	if entry.GetAttributeValue("uSNChanged") != in.Revision {
		return nil, nil, ErrTopologyConflict
	}
	sid, err := s.delegationSID(ctx, in.Principal)
	if err != nil {
		return nil, nil, err
	}
	additions, err := delegationACEs(sid, in.Profile)
	if err != nil {
		return nil, nil, err
	}
	old := entry.GetRawAttributeValue("nTSecurityDescriptor")
	sd, added, err := delegationDescriptor(old, additions)
	if err != nil {
		return nil, nil, err
	}
	aces, _ := policyACEs(old)
	// Bind the preview to the exact principal SID, profile, revision and ACL bytes.
	raw, _ := json.Marshal([]any{entry.DN, in.Revision, in.Principal, in.Profile, sid, old, sd})
	hash := sha256.Sum256(raw)
	preview := &GPDelegationPreview{Revision: in.Revision, Preview: hex.EncodeToString(hash[:]), DN: entry.DN, SID: sidString(sid), Profile: in.Profile, Added: added, Unchanged: len(aces), LDAPOnly: true, Warnings: []string{"sysvol-unchanged", "effective-access-not-evaluated", "existing-permissions-preserved"}}
	return preview, sd, nil
}
func (s *GPOService) DelegationPreview(ctx context.Context, gpo string, in GPDelegationChange) (*GPDelegationPreview, error) {
	p, _, err := s.delegationPlan(ctx, gpo, in)
	return p, err
}
func (s *GPOService) GrantDelegation(ctx context.Context, gpo string, in GPDelegationChange, actor, ip string) error {
	if in.Preview == "" {
		return topologyBad("preview required")
	}
	p, sd, err := s.delegationPlan(ctx, gpo, in)
	if err != nil {
		return err
	}
	if p.Preview != in.Preview {
		return ErrTopologyConflict
	}
	if len(p.Added) == 0 {
		return nil
	}
	controls, err := assertion(in.Revision)
	if err != nil {
		return err
	}
	controls = append(controls, daclControl)
	req := ldap.NewModifyRequest(p.DN, controls)
	req.Replace("nTSecurityDescriptor", []string{string(sd)})
	err = topologyError(s.ldap.Modify(ctx, req))
	target := p.DN + " / " + p.SID + " / " + p.Profile
	if err != nil {
		s.audit.Failure(actor, "gpo.delegation", target, ip, err)
	} else {
		s.audit.Success(actor, "gpo.delegation", target, ip)
	}
	return err
}
