package service

import "strings"

// Share access presets for UI / API.
const (
	PresetCustom            = "custom"
	PresetDomainRead        = "domain_read"
	PresetDomainReadWrite   = "domain_rw"
	PresetDomainGroupRW     = "domain_group_rw"
	PresetUsersOnly         = "users_only"
	PresetAuthenticatedAll  = "authenticated"
	PresetGuestPublic       = "guest_public"
)

// ApplyPreset fills empty access fields from a named preset.
// Explicit form values always win over preset defaults.
func ApplyPreset(in *CreateShareInput) {
	if in == nil {
		return
	}
	preset := strings.ToLower(strings.TrimSpace(in.Preset))
	switch preset {
	case "", PresetCustom:
		return
	case PresetDomainRead:
		if in.ValidUsers == "" {
			in.ValidUsers = `"Domain Users"`
		}
		if in.ReadOnly == nil {
			v := true
			in.ReadOnly = &v
		}
		if in.GuestOK == nil {
			v := false
			in.GuestOK = &v
		}
		if in.Mode == "" {
			in.Mode = "0755"
		}
		if in.ACL == "" && in.ForceGroup == "" {
			// winbind/sssd often exposes AD group as "domain users"
			in.ACL = `g:domain users:r-x,o::---`
		}
		if in.DefaultACL == "" {
			in.DefaultACL = `g:domain users:r-x,o::---`
		}
	case PresetDomainReadWrite:
		if in.ValidUsers == "" {
			in.ValidUsers = `"Domain Users"`
		}
		if in.WriteList == "" {
			in.WriteList = `"Domain Users"`
		}
		if in.ReadOnly == nil {
			v := false
			in.ReadOnly = &v
		}
		if in.GuestOK == nil {
			v := false
			in.GuestOK = &v
		}
		if in.Mode == "" {
			in.Mode = "0770"
		}
		if in.ACL == "" {
			in.ACL = `g:domain users:rwx,o::---`
		}
		if in.DefaultACL == "" {
			in.DefaultACL = `g:domain users:rwx,o::---`
		}
	case PresetDomainGroupRW:
		// Expect ValidUsers / WriteList / ForceGroup filled with @"Group Name"
		if in.ReadOnly == nil {
			v := false
			in.ReadOnly = &v
		}
		if in.GuestOK == nil {
			v := false
			in.GuestOK = &v
		}
		if in.Mode == "" {
			in.Mode = "0770"
		}
		if in.ACL == "" && in.ForceGroup != "" {
			g := strings.TrimPrefix(in.ForceGroup, "@")
			in.ACL = `g:` + g + `:rwx,o::---`
			if in.DefaultACL == "" {
				in.DefaultACL = in.ACL
			}
		}
	case PresetUsersOnly:
		if in.ReadOnly == nil {
			v := false
			in.ReadOnly = &v
		}
		if in.GuestOK == nil {
			v := false
			in.GuestOK = &v
		}
		if in.Mode == "" {
			in.Mode = "0750"
		}
	case PresetAuthenticatedAll:
		// Empty valid users → any authenticated (domain) user; no guest.
		in.ValidUsers = ""
		if in.ReadOnly == nil {
			v := false
			in.ReadOnly = &v
		}
		if in.GuestOK == nil {
			v := false
			in.GuestOK = &v
		}
		if in.Mode == "" {
			in.Mode = "0775"
		}
		if in.ACL == "" {
			in.ACL = `g:domain users:rwx,o::r-x`
		}
		if in.DefaultACL == "" {
			in.DefaultACL = `g:domain users:rwx,o::r-x`
		}
	case PresetGuestPublic:
		if in.GuestOK == nil {
			v := true
			in.GuestOK = &v
		}
		if in.ReadOnly == nil {
			v := true
			in.ReadOnly = &v
		}
		if in.Mode == "" {
			in.Mode = "0755"
		}
		if in.ACL == "" {
			in.ACL = `o::r-x`
		}
	}
}
