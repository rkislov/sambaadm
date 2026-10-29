package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

// Apply Group Policy extended right, GUID in Windows wire order.
var applyPolicyGUID = []byte{0x8f, 0xfd, 0xac, 0xed, 0xb3, 0xff, 0xd1, 0x11, 0xb4, 0x1d, 0, 0xa0, 0xc9, 0x68, 0xf9, 0x39}
var daclControl = ldap.NewControlString("1.2.840.113556.1.4.801", true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}))

type GPFilterACE struct {
	ID        string `json:"id"`
	SID       string `json:"sid"`
	Name      string `json:"name"`
	Type      byte   `json:"type"`
	Mask      uint32 `json:"mask"`
	Inherited bool   `json:"inherited"`
	Apply     bool   `json:"apply"`
	Editable  bool   `json:"editable"`
}
type GPFilter struct {
	Revision string        `json:"revision"`
	Entries  []GPFilterACE `json:"entries"`
}
type FilterChange struct {
	Revision  string `json:"revision"`
	Principal string `json:"principal"`
	Remove    string `json:"remove"`
}

func sidString(b []byte) string {
	if len(b) < 8 || b[0] != 1 || int(b[1]) > 15 || len(b) != 8+4*int(b[1]) {
		return ""
	}
	authority := uint64(0)
	for _, v := range b[2:8] {
		authority = authority<<8 | uint64(v)
	}
	s := fmt.Sprintf("S-1-%d", authority)
	for i := 8; i < len(b); i += 4 {
		s += "-" + strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[i:])), 10)
	}
	return s
}
func policyACEs(sd []byte) ([][]byte, error) {
	bad := topologyBad("invalid GPO DACL")
	if len(sd) < 20 || sd[0] != 1 || binary.LittleEndian.Uint16(sd[2:])&0x8004 != 0x8004 {
		return nil, bad
	}
	off := int(binary.LittleEndian.Uint32(sd[16:]))
	if off < 20 || off+8 > len(sd) {
		return nil, bad
	}
	size := int(binary.LittleEndian.Uint16(sd[off+2:]))
	if size < 8 || off+size > len(sd) {
		return nil, bad
	}
	count := int(binary.LittleEndian.Uint16(sd[off+4:]))
	pos := off + 8
	out := [][]byte{}
	for i := 0; i < count; i++ {
		if pos+4 > off+size {
			return nil, bad
		}
		n := int(binary.LittleEndian.Uint16(sd[pos+2:]))
		if n < 4 || pos+n > off+size {
			return nil, bad
		}
		out = append(out, append([]byte(nil), sd[pos:pos+n]...))
		pos += n
	}
	if pos != off+size {
		return nil, bad
	}
	return out, nil
}
func filterACE(ace []byte) GPFilterACE {
	h := sha256.Sum256(ace)
	out := GPFilterACE{ID: hex.EncodeToString(h[:]), Type: ace[0], Inherited: ace[1]&16 != 0}
	if len(ace) < 8 {
		return out
	}
	out.Mask = binary.LittleEndian.Uint32(ace[4:])
	offset := 8
	switch ace[0] {
	case 0, 1:
		out.Apply = out.Mask&(0x100|0x10000000) != 0
	case 5, 6:
		if len(ace) < 12 {
			return out
		}
		flags := binary.LittleEndian.Uint32(ace[8:])
		offset = 12
		if flags&1 != 0 {
			if len(ace) < offset+16 {
				return out
			}
			out.Apply = bytes.Equal(ace[offset:offset+16], applyPolicyGUID) && out.Mask&0x100 != 0
			offset += 16
		} else {
			out.Apply = out.Mask&0x100 != 0
		}
		if flags&2 != 0 {
			offset += 16
		}
		out.Editable = ace[0] == 5 && flags == 1 && out.Mask == 0x100 && out.Apply && ace[1] & ^byte(3) == 0
	default:
		return out
	}
	if offset > len(ace) {
		return out
	}
	out.SID = sidString(ace[offset:])
	out.Editable = out.Editable && out.SID != ""
	return out
}
func daclDescriptor(old []byte, aces [][]byte) ([]byte, error) {
	off := int(binary.LittleEndian.Uint32(old[16:]))
	acl := append([]byte(nil), old[off:off+8]...)
	for _, a := range aces {
		acl = append(acl, a...)
	}
	if len(acl) > 65535 || len(aces) > 65535 {
		return nil, topologyBad("DACL too large")
	}
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(aces)))
	out := make([]byte, 20)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:], binary.LittleEndian.Uint16(old[2:]))
	binary.LittleEndian.PutUint32(out[16:], 20)
	return append(out, acl...), nil
}
func (s *GPOService) filterEntry(ctx context.Context, gpo string) (*ldap.Entry, error) {
	p, e := s.policyEntry(ctx, gpo)
	if e != nil {
		return nil, e
	}
	conn, e := s.ldap.Conn(ctx)
	if e != nil {
		return nil, e
	}
	r, e := conn.Search(ldap.NewSearchRequest(p.DN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=groupPolicyContainer)", []string{"nTSecurityDescriptor", "uSNChanged", "objectGUID"}, []ldap.Control{daclControl}))
	if e != nil {
		return nil, e
	}
	if len(r.Entries) != 1 {
		return nil, topologyBad("GPO not found")
	}
	return r.Entries[0], nil
}
func (s *GPOService) SecurityFilter(ctx context.Context, gpo string) (*GPFilter, error) {
	entry, e := s.filterEntry(ctx, gpo)
	if e != nil {
		return nil, e
	}
	aces, e := policyACEs(entry.GetRawAttributeValue("nTSecurityDescriptor"))
	if e != nil {
		return nil, e
	}
	out := &GPFilter{Revision: entry.GetAttributeValue("uSNChanged"), Entries: []GPFilterACE{}}
	for _, a := range aces {
		v := filterACE(a)
		v.Name = v.SID
		if v.SID == "S-1-5-11" {
			v.Name = "Authenticated Users"
		} else if v.SID != "" {
			es, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(objectSid=" + ldap.EscapeFilter(v.SID) + ")", Attributes: []string{"sAMAccountName", "name"}})
			if err == nil && len(es) > 0 {
				v.Name = es[0].GetAttributeValue("sAMAccountName")
				if v.Name == "" {
					v.Name = es[0].GetAttributeValue("name")
				}
			}
		}
		out.Entries = append(out.Entries, v)
	}
	return out, nil
}
func (s *GPOService) SetSecurityFilter(ctx context.Context, gpo string, in FilterChange, actor, ip string) error {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	if (in.Principal == "") == (in.Remove == "") {
		return topologyBad("choose a principal to allow or an explicit Apply ACE to remove")
	}
	entry, e := s.filterEntry(ctx, gpo)
	if e != nil {
		return e
	}
	if e := s.ensureNoDelegationPending(entry.DN); e != nil {
		return e
	}
	if entry.GetAttributeValue("uSNChanged") != in.Revision {
		return ErrTopologyConflict
	}
	old := entry.GetRawAttributeValue("nTSecurityDescriptor")
	aces, e := policyACEs(old)
	if e != nil {
		return e
	}
	target := in.Principal
	if in.Remove != "" {
		found := false
		kept := [][]byte{}
		for _, a := range aces {
			v := filterACE(a)
			if v.ID == in.Remove {
				if !v.Editable {
					return topologyBad("inherited, deny or combined permissions are read only")
				}
				found = true
				target = v.SID
			} else {
				kept = append(kept, a)
			}
		}
		if !found {
			return ErrTopologyConflict
		}
		aces = kept
	} else {
		var sid []byte
		if in.Principal == "S-1-5-11" {
			sid = []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
		} else {
			dn, e := ldap.ParseDN(in.Principal)
			base, _ := ldap.ParseDN(s.ldap.BaseDN())
			if e != nil || !base.AncestorOfFold(dn) {
				return topologyBad("select a principal in this domain")
			}
			p, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: in.Principal, Scope: ldapproto.ScopeBase(), Filter: "(|(objectClass=user)(objectClass=group))", Attributes: []string{"objectSid", "groupType"}})
			if e != nil {
				return e
			}
			if gt := p.GetAttributeValue("groupType"); gt != "" {
				n, e := strconv.ParseInt(gt, 10, 64)
				if e != nil || uint32(n)&0x80000000 == 0 {
					return topologyBad("select a security group")
				}
			}
			sid = p.GetRawAttributeValue("objectSid")
		}
		if sidString(sid) == "" {
			return topologyBad("invalid principal SID")
		}
		for _, a := range aces {
			v := filterACE(a)
			if v.SID == sidString(sid) && v.Apply && v.Type == 5 && a[1]&8 == 0 {
				return topologyBad("principal already has an Apply permission")
			}
		}
		a := make([]byte, 28)
		a[0] = 5
		binary.LittleEndian.PutUint16(a[2:], uint16(len(a)+len(sid)))
		binary.LittleEndian.PutUint32(a[4:], 0x100)
		binary.LittleEndian.PutUint32(a[8:], 1)
		copy(a[12:], applyPolicyGUID)
		a = append(a, sid...)
		// Explicit allow ACEs precede inherited ACEs; existing ACE order is retained.
		at := len(aces)
		for i, v := range aces {
			if v[1]&16 != 0 {
				at = i
				break
			}
		}
		aces = append(aces, nil)
		copy(aces[at+1:], aces[at:])
		aces[at] = a
	}
	sd, e := daclDescriptor(old, aces)
	if e != nil {
		return e
	}
	if e = checkTopologyRevision(ctx, s.ldap, entry.DN, in.Revision); e != nil {
		return e
	}
	controls, e := assertion(in.Revision)
	if e != nil {
		return e
	}
	controls = append(controls, daclControl)
	req := ldap.NewModifyRequest(entry.DN, controls)
	req.Replace("nTSecurityDescriptor", []string{string(sd)})
	e = topologyError(s.ldap.Modify(ctx, req))
	target = entry.DN + " / " + strings.TrimSpace(target)
	if e != nil {
		s.audit.Failure(actor, "gpo.filter", target, ip, e)
	} else {
		s.audit.Success(actor, "gpo.filter", target, ip)
	}
	return e
}
