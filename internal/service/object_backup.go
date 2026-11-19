package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// Object backups deliberately exclude credentials and replication state. Account
// identity is recovered only by reanimating the original tombstone, never Add.
const objectBackupFormat = "sambaadm-objects-v1"
const maxObjectBackupBytes = 256 << 20
const showDeletedOID = "1.2.840.113556.1.4.417"

var accountBackupAttrs = []string{"sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "mail", "description", "telephoneNumber", "department", "title", "company", "physicalDeliveryOfficeName", "streetAddress", "l", "st", "postalCode", "co", "dNSHostName", "operatingSystem", "operatingSystemVersion"}

type ObjectBackupEntry struct {
	GUID       string              `json:"guid"` // hex of LDAP's raw GUID, no byte-order conversion
	DN         string              `json:"dn"`
	Kind       string              `json:"kind"`
	Name       string              `json:"name"`
	Attributes map[string][]string `json:"attributes,omitempty"`
	Policy     *policyBackup       `json:"policy,omitempty"`
}
type ObjectBackup struct {
	Format     string              `json:"format"`
	ID         string              `json:"id"`
	Created    time.Time           `json:"created"`
	Actor      string              `json:"actor"`
	BaseDN     string              `json:"baseDN"`
	DomainGUID string              `json:"domainGUID"`
	Objects    []ObjectBackupEntry `json:"objects"`
}
type ObjectRestorePlan struct {
	BackupID   string `json:"backupID"`
	GUID       string `json:"guid"`
	DN         string `json:"dn"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Revision   string `json:"revision"`
	CanRestore bool   `json:"canRestore"`
	Reason     string `json:"reason,omitempty"`
	Warning    string `json:"warning"`
	DeletedDN  string `json:"-"`
	DeletedUSN string `json:"-"`
}

type ObjectBackupService struct {
	ldap interface {
		BaseDN() string
		Search(context.Context, ldapproto.SearchOptions) ([]*ldap.Entry, error)
		SearchOne(context.Context, ldapproto.SearchOptions) (*ldap.Entry, error)
		Modify(context.Context, *ldap.ModifyRequest) error
	}
	gpo   *GPOService
	root  string
	audit *audit.Logger
}

func NewObjectBackupService(client *ldapproto.Client, gpo *GPOService, root string, logger *audit.Logger) *ObjectBackupService {
	return &ObjectBackupService{ldap: client, gpo: gpo, root: root, audit: logger}
}
func (s *ObjectBackupService) domainIdentity(ctx context.Context) (string, error) {
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: s.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=domainDNS)", Attributes: []string{"objectGUID"}})
	if err != nil {
		return "", err
	}
	if len(e.GetEqualFoldRawAttributeValue("objectGUID")) != 16 {
		return "", fmt.Errorf("domain GUID unavailable")
	}
	return hex.EncodeToString(e.GetEqualFoldRawAttributeValue("objectGUID")), nil
}
func (s *ObjectBackupService) record(actor, action, target, ip string, err error) {
	if s.audit == nil {
		return
	}
	if err != nil {
		s.audit.Failure(actor, action, target, ip, err)
	} else {
		s.audit.Success(actor, action, target, ip)
	}
}

// Create publishes a snapshot only after every LDAP and SYSVOL read succeeds.
// It is an interval snapshot, not a transaction across LDAP and SMB.
func (s *ObjectBackupService) Create(ctx context.Context, actor, ip string) (out *ObjectBackup, err error) {
	defer func() { s.record(actor, "objects.backup", s.ldap.BaseDN(), ip, err) }()
	domain, err := s.domainIdentity(ctx)
	if err != nil {
		return nil, err
	}
	attrs := append([]string{"objectGUID", "objectClass", "userAccountControl", "cn", "name", "gPLink", "gPOptions", "groupType", "member", "description"}, accountBackupAttrs...)
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(|(&(objectCategory=person)(objectClass=user))(objectClass=computer)(objectClass=groupPolicyContainer)(objectClass=organizationalUnit)(objectClass=group)(objectClass=domainDNS))", Attributes: attrs, MaxEntries: 50000})
	if err != nil {
		return nil, err
	}
	out = &ObjectBackup{Format: objectBackupFormat, ID: uuid.NewString(), Created: time.Now().UTC(), Actor: actor, BaseDN: s.ldap.BaseDN(), DomainGUID: domain, Objects: []ObjectBackupEntry{}}
	total := 0
	for _, e := range entries {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		for _, attr := range e.Attributes {
			if strings.Contains(strings.ToLower(attr.Name), ";range=") {
				return nil, fmt.Errorf("ranged LDAP attribute %s on %s cannot be fully captured; snapshot not published", attr.Name, e.DN)
			}
		}
		kind := ""
		classes := e.GetEqualFoldAttributeValues("objectClass")
		for _, c := range classes {
			switch strings.ToLower(c) {
			case "user":
				if kind == "" {
					kind = "user"
				}
			case "computer":
				kind = "computer"
			case "grouppolicycontainer":
				kind = "gpo"
			case "organizationalunit":
				kind = "ou"
			case "group":
				kind = "group"
			case "domaindns":
				kind = "domain"
			}
		}
		if kind == "" {
			continue
		}
		raw := e.GetEqualFoldRawAttributeValue("objectGUID")
		if len(raw) != 16 {
			return nil, fmt.Errorf("object GUID unavailable: %s", e.DN)
		}
		obj := ObjectBackupEntry{GUID: hex.EncodeToString(raw), DN: e.DN, Kind: kind, Name: e.GetEqualFoldAttributeValue("sAMAccountName"), Attributes: map[string][]string{}}
		if obj.Name == "" {
			obj.Name = e.GetEqualFoldAttributeValue("name")
		}
		for _, a := range attrs {
			if a == "objectGUID" {
				continue
			}
			if values := e.GetEqualFoldAttributeValues(a); len(values) > 0 {
				obj.Attributes[a] = values
			}
		}
		if kind == "gpo" {
			if s.gpo == nil {
				return nil, fmt.Errorf("GPO service unavailable")
			}
			b, _, captureErr := s.gpo.captureNativeBackup(ctx, e.GetEqualFoldAttributeValue("name"))
			if captureErr != nil {
				return nil, fmt.Errorf("backup %s: %w", e.DN, captureErr)
			}
			obj.Policy = &b
			if names := b.Attributes["displayName"]; len(names) > 0 {
				obj.Name = names[0]
			}
		}
		encoded, encodeErr := json.Marshal(obj)
		if encodeErr != nil {
			return nil, encodeErr
		}
		total += len(encoded) + 1
		if total > maxObjectBackupBytes-(1<<20) {
			return nil, fmt.Errorf("snapshot exceeds 256 MiB limit")
		}
		out.Objects = append(out.Objects, obj)
	}
	if err = s.save(out); err != nil {
		return nil, err
	}
	return out, nil
}
func objectGUIDFilter(guid string) (string, error) {
	raw, err := hex.DecodeString(guid)
	if err != nil || len(raw) != 16 {
		return "", fmt.Errorf("invalid object GUID")
	}
	var b strings.Builder
	for _, v := range raw {
		fmt.Fprintf(&b, "\\%02x", v)
	}
	return "(objectGUID=" + b.String() + ")", nil
}
func backupObject(b *ObjectBackup, guid string) (*ObjectBackupEntry, error) {
	for i := range b.Objects {
		if b.Objects[i].GUID == guid {
			return &b.Objects[i], nil
		}
	}
	return nil, fmt.Errorf("object absent from backup")
}
func (s *ObjectBackupService) Preview(ctx context.Context, id, guid string) (*ObjectRestorePlan, error) {
	b, err := s.Load(id)
	if err != nil {
		return nil, err
	}
	o, err := backupObject(b, guid)
	if err != nil {
		return nil, err
	}
	domain, err := s.domainIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if domain != b.DomainGUID || !strings.EqualFold(s.ldap.BaseDN(), b.BaseDN) {
		return nil, fmt.Errorf("backup belongs to another domain")
	}
	p := &ObjectRestorePlan{BackupID: id, GUID: guid, DN: o.DN, Kind: o.Kind, Name: o.Name}
	if o.Kind != "user" && o.Kind != "computer" && o.Kind != "gpo" {
		p.Reason = "Этот тип сохранён для справки; выборочное восстановление не поддерживается"
		return p, nil
	}
	if o.Kind == "computer" {
		values := o.Attributes["userAccountControl"]
		if len(values) != 1 {
			p.Reason = "Тип учётной записи АРМ неизвестен"
			return p, nil
		}
		flags, e := strconv.ParseUint(values[0], 10, 32)
		if e != nil || flags&4096 == 0 || flags&(8192|67108864) != 0 {
			p.Reason = "Восстановление учётной записи контроллера домена запрещено"
			return p, nil
		}
	}
	p.Warning = "Восстановление исходного SID/GUID из tombstone. Пароли, ACL и членство в группах не восстанавливаются из снимка. Учётная запись будет отключена; проверьте права и задайте пароль. Для АРМ может потребоваться повторный ввод в домен."
	if o.Kind == "gpo" {
		p.Warning = "Будет создана новая непривязанная GPO с новым GUID, файлами и разрешениями SYSVOL. Привязки, LDAP-делегирование и WMI-фильтр проверьте и настройте вручную."
	}
	filter, err := objectGUIDFilter(guid)
	if err != nil {
		return nil, err
	}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: filter, Attributes: []string{"isDeleted", "isRecycled", "uSNChanged", "objectGUID", "userAccountControl", "objectClass"}, Controls: []ldap.Control{ldap.NewControlString(showDeletedOID, true, "")}, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	state := "missing"
	if len(entries) > 0 {
		e := entries[0]
		state = e.DN + "|" + e.GetEqualFoldAttributeValue("uSNChanged")
		if !strings.EqualFold(e.GetEqualFoldAttributeValue("isDeleted"), "TRUE") {
			p.Reason = "Исходный объект существует; перезапись запрещена"
			return p, nil
		}
		if o.Kind != "gpo" {
			flags, typeErr := strconv.ParseUint(e.GetEqualFoldAttributeValue("userAccountControl"), 10, 32)
			if typeErr != nil || flags&(8192|67108864) != 0 {
				p.Reason = "Тип удалённой учётной записи неизвестен или это контроллер домена"
				return p, nil
			}
			if (o.Kind == "computer" && flags&4096 == 0) || (o.Kind == "user" && flags&512 == 0) {
				p.Reason = "Тип удалённой учётной записи изменился после создания копии"
				return p, nil
			}
		}
		// Samba without AD Recycle Bin marks ordinary tombstones isRecycled.
		// Show Deleted visibility and the server's reanimation checks are the
		// authority; do not reject a visible Samba tombstone by this flag.
		p.DeletedDN = e.DN
		p.DeletedUSN = e.GetEqualFoldAttributeValue("uSNChanged")
	}
	if o.Kind != "gpo" && p.DeletedDN == "" {
		p.Reason = "Tombstone недоступен или срок хранения истёк; восстановление исходного SID невозможно"
		return p, nil
	}
	// Check both DN and account-name collisions, including renamed live objects.
	collision := "(distinguishedName=" + ldap.EscapeFilter(o.DN) + ")"
	if v := o.Attributes["sAMAccountName"]; len(v) > 0 {
		collision = "(|" + collision + "(sAMAccountName=" + ldap.EscapeFilter(v[0]) + "))"
	}
	if o.Kind == "gpo" {
		collision = "(&(objectClass=groupPolicyContainer)(displayName=" + ldap.EscapeFilter(o.Name) + "))"
	}
	live, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: collision, Attributes: []string{"objectGUID"}, MaxEntries: 2})
	if err != nil {
		return nil, err
	}
	if len(live) > 0 {
		p.Reason = "Имя или DN заняты другим объектом"
		return p, nil
	}
	if o.Kind != "gpo" {
		dn, e := ldap.ParseDN(o.DN)
		if e != nil || len(dn.RDNs) < 2 {
			return nil, fmt.Errorf("invalid saved DN")
		}
		parent := (&ldap.DN{RDNs: dn.RDNs[1:]}).String()
		_, e = s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: parent, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
		if ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
			p.Reason = "Исходный контейнер удалён; сначала восстановите его"
			return p, nil
		}
		if e != nil {
			return nil, e
		}
	}
	data, _ := json.Marshal(b)
	sum := sha256.Sum256(append(data, []byte(guid+"|"+state)...))
	p.Revision = hex.EncodeToString(sum[:])
	p.CanRestore = true
	return p, nil
}
func reanimateObjectRequest(deletedDN string, o *ObjectBackupEntry) *ldap.ModifyRequest {
	req := ldap.NewModifyRequest(deletedDN, []ldap.Control{ldap.NewControlString(showDeletedOID, true, "")})
	req.Delete("isDeleted", nil)
	req.Replace("distinguishedName", []string{o.DN})
	return req
}
func (s *ObjectBackupService) Restore(ctx context.Context, id, guid, revision, actor, ip string) (err error) {
	defer func() { s.record(actor, "objects.restore", id+"/"+guid, ip, err) }()
	p, err := s.Preview(ctx, id, guid)
	if err != nil {
		return err
	}
	if !p.CanRestore {
		return fmt.Errorf("%s", p.Reason)
	}
	if revision == "" || revision != p.Revision {
		return fmt.Errorf("restore preview changed; preview again")
	}
	b, err := s.Load(id)
	if err != nil {
		return err
	}
	o, err := backupObject(b, guid)
	if err != nil {
		return err
	}
	if o.Kind == "gpo" {
		if s.gpo == nil || o.Policy == nil {
			return fmt.Errorf("policy snapshot unavailable")
		}
		return s.gpo.restorePolicySnapshot(ctx, o.Name, *o.Policy, actor, ip)
	}
	undelete := reanimateObjectRequest(p.DeletedDN, o)
	controls, e := assertion(p.DeletedUSN)
	if e != nil {
		return e
	}
	undelete.Controls = append(undelete.Controls, controls...)
	if err = s.ldap.Modify(ctx, undelete); err != nil {
		return err
	}
	guidFilter, _ := objectGUIDFilter(o.GUID)
	guidAssertion, _ := ldap.CompileFilter(guidFilter)
	disable := ldap.NewModifyRequest(o.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(guidAssertion.Bytes()))})
	uac := "514"
	if o.Kind == "computer" {
		uac = "4098"
	}
	disable.Replace("userAccountControl", []string{uac})
	if err = s.ldap.Modify(ctx, disable); err != nil {
		return fmt.Errorf("object reanimated at %s but disabling failed; check account state immediately: %w", o.DN, err)
	}
	current, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID", "uSNChanged"}})
	if e != nil {
		return fmt.Errorf("object reanimated; cannot read restored identity: %w", e)
	}
	if hex.EncodeToString(current.GetEqualFoldRawAttributeValue("objectGUID")) != o.GUID {
		return fmt.Errorf("object reanimated; identity changed before profile restore")
	}
	filter, _ := objectGUIDFilter(o.GUID)
	compiled, e := ldap.CompileFilter("(&" + filter + "(uSNChanged=" + ldap.EscapeFilter(current.GetEqualFoldAttributeValue("uSNChanged")) + "))")
	if e != nil {
		return e
	}
	req := ldap.NewModifyRequest(o.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(compiled.Bytes()))})
	for _, attr := range accountBackupAttrs {
		if values := o.Attributes[attr]; len(values) > 0 {
			req.Replace(attr, values)
		}
	}
	if err = s.ldap.Modify(ctx, req); err != nil {
		return fmt.Errorf("object reanimated and disabled at %s; profile restore incomplete, inspect manually: %w", o.DN, err)
	}
	live, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID", "userAccountControl"}})
	if err != nil {
		return fmt.Errorf("restore written; verification failed: %w", err)
	}
	if hex.EncodeToString(live.GetEqualFoldRawAttributeValue("objectGUID")) != o.GUID {
		return fmt.Errorf("restored identity mismatch; inspect %s", o.DN)
	}
	flags, e := strconv.ParseUint(live.GetEqualFoldAttributeValue("userAccountControl"), 10, 32)
	if e != nil || flags&2 == 0 {
		return fmt.Errorf("restored account disabled state could not be verified; inspect %s", o.DN)
	}
	return nil
}
