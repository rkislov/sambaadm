package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"image"
	"image/jpeg"
	_ "image/png"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

type SelfProfile struct {
	SID string `json:"sid"`
	User
	Mobile   string      `json:"mobile"`
	Office   string      `json:"office"`
	Photo    bool        `json:"photo"`
	Groups   []UserGroup `json:"groups"`
	Warnings []string    `json:"warnings"`
}
type SelfEdit struct {
	Revision    string `json:"revision"`
	Description string `json:"description"`
	Telephone   string `json:"telephone"`
	Mobile      string `json:"mobile"`
	Office      string `json:"office"`
}

func identityFilter(guid string) (string, error) {
	raw, err := hex.DecodeString(guid)
	if err != nil || len(raw) != 16 {
		return "", fmt.Errorf("self.identity-required")
	}
	var b strings.Builder
	for _, v := range raw {
		fmt.Fprintf(&b, "\\%02x", v)
	}
	return "(objectGUID=" + b.String() + ")", nil
}
func (s *UserService) SelfEntry(ctx context.Context, guid string) (*ldap.Entry, error) {
	filter, err := identityFilter(guid)
	if err != nil {
		return nil, err
	}
	attrs := append(append([]string{}, ldapproto.UserAttrs...), "objectGUID", "objectSid", "primaryGroupID", "memberOf", "mobile", "physicalDeliveryOfficeName", "thumbnailPhoto", "msDS-UserPasswordExpiryTimeComputed", "lastLogonTimestamp", "lastLogon", "pwdLastSet", "lockoutTime")
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=user)(!(objectClass=computer))" + filter + ")", Attributes: attrs})
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(hex.EncodeToString(e.GetRawAttributeValue("objectGUID")), guid) {
		return nil, fmt.Errorf("self.identity-changed")
	}
	if !entryToUser(e).Enabled {
		return nil, fmt.Errorf("self.account-disabled")
	}
	return e, nil
}
func (s *UserService) Self(ctx context.Context, guid string) (*SelfProfile, error) {
	e, err := s.SelfEntry(ctx, guid)
	if err != nil {
		return nil, err
	}
	out := &SelfProfile{SID: sidString(e.GetRawAttributeValue("objectSid")), User: entryToUser(e), Mobile: e.GetAttributeValue("mobile"), Office: e.GetAttributeValue("physicalDeliveryOfficeName"), Photo: len(e.GetRawAttributeValue("thumbnailPhoto")) > 0, Groups: []UserGroup{}, Warnings: []string{}}
	out.Groups, err = s.membershipsForEntry(ctx, e)
	if err != nil {
		out.Groups = []UserGroup{}
		out.Warnings = append(out.Warnings, "self.groups-unavailable")
	}
	for _, attr := range []string{"msDS-UserPasswordExpiryTimeComputed", "lastLogonTimestamp", "lastLogon", "pwdLastSet", "lockoutTime"} {
		if v := e.GetAttributeValue(attr); v != "" {
			out.Attributes[attr] = []string{v}
		}
	}
	return out, nil
}
func selfControls(guid, revision string) ([]ldap.Control, error) {
	_, err := assertion(revision)
	if err != nil {
		return nil, err
	}
	filter, err := identityFilter(guid)
	if err != nil {
		return nil, err
	}
	compiled, err := ldap.CompileFilter("(&" + filter + "(uSNChanged=" + revision + ")(!(userAccountControl:1.2.840.113556.1.4.803:=2)))")
	if err != nil {
		return nil, err
	}
	return []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(compiled.Bytes()))}, nil
}
func (s *UserService) UpdateSelf(ctx context.Context, guid string, in SelfEdit) error {
	attrs := map[string]string{"description": in.Description, "telephoneNumber": in.Telephone, "mobile": in.Mobile, "physicalDeliveryOfficeName": in.Office}
	for name, v := range attrs {
		limit := 128
		if name == "description" {
			limit = 1024
		}
		if len([]rune(v)) > limit || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			return fmt.Errorf("self.invalid-field")
		}
	}
	e, err := s.SelfEntry(ctx, guid)
	if err != nil {
		return err
	}
	controls, err := selfControls(guid, in.Revision)
	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(e.DN, controls)
	for name, v := range attrs {
		if v == "" {
			req.Replace(name, nil)
		} else {
			req.Replace(name, []string{v})
		}
	}
	return topologyError(s.ldap.Modify(ctx, req))
}

// Decode and re-encode a bounded JPEG/PNG; never serve active SVG or raw uploads.
func NormalizeSelfPhoto(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return nil, fmt.Errorf("self.invalid-photo")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || (format != "jpeg" && format != "png") || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 2048 || cfg.Height > 2048 {
		return nil, fmt.Errorf("self.invalid-photo")
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("self.invalid-photo")
	}
	w, h := cfg.Width, cfg.Height
	if w > 256 || h > 256 {
		if w >= h {
			h = h * 256 / w
			w = 256
		} else {
			w = w * 256 / h
			h = 256
		}
	}
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			dst.Set(x, y, src.At(src.Bounds().Min.X+x*cfg.Width/w, src.Bounds().Min.Y+y*cfg.Height/h))
		}
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: 85}); err != nil {
		return nil, err
	}
	if out.Len() > 100<<10 {
		return nil, fmt.Errorf("self.invalid-photo")
	}
	return out.Bytes(), nil
}
func (s *UserService) SetSelfPhoto(ctx context.Context, guid, revision string, photo []byte) error {
	e, err := s.SelfEntry(ctx, guid)
	if err != nil {
		return err
	}
	controls, err := selfControls(guid, revision)
	if err != nil {
		return err
	}
	req := ldap.NewModifyRequest(e.DN, controls)
	if len(photo) == 0 {
		req.Replace("thumbnailPhoto", nil)
	} else {
		normalized, err := NormalizeSelfPhoto(photo)
		if err != nil {
			return err
		}
		req.Replace("thumbnailPhoto", []string{string(normalized)})
	}
	return topologyError(s.ldap.Modify(ctx, req))
}

func (s *UserService) ChangeSelfPassword(ctx context.Context, guid string, cfg config.LDAPConfig, oldPassword, newPassword string) error {
	if oldPassword == "" || newPassword == "" || oldPassword == newPassword || len(oldPassword) > 16384 || len(newPassword) > 16384 || strings.ContainsRune(newPassword, 0) {
		return fmt.Errorf("self.invalid-password")
	}
	uri := strings.ToLower(cfg.URI)
	if !strings.HasPrefix(uri, "ldaps://") && !strings.HasPrefix(uri, "ldapi://") {
		return fmt.Errorf("self.secure-ldap-required")
	}
	e, err := s.SelfEntry(ctx, guid)
	if err != nil {
		return err
	}
	client := ldapproto.NewClient(cfg)
	defer client.Close()
	if err := client.BindSimple(ctx, e.DN, oldPassword); err != nil {
		return fmt.Errorf("self.current-password-invalid")
	}
	bound, err := client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: e.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=user)", Attributes: []string{"objectGUID"}})
	if err != nil || !strings.EqualFold(hex.EncodeToString(bound.GetRawAttributeValue("objectGUID")), guid) {
		return fmt.Errorf("self.identity-changed")
	}
	filter, _ := identityFilter(guid)
	assert, _ := ldap.CompileFilter(filter)
	req := ldap.NewModifyRequest(bound.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assert.Bytes()))})
	req.Delete("unicodePwd", []string{string(ldapproto.EncodeUnicodePwd(oldPassword))})
	req.Add("unicodePwd", []string{string(ldapproto.EncodeUnicodePwd(newPassword))})
	if err := client.Modify(ctx, req); err != nil {
		return fmt.Errorf("self.password-change-failed: %w", err)
	}
	return nil
}
