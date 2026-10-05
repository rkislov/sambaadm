package ldap

// Common Active Directory / Samba4 attribute names.
const (
	AttrDN              = "distinguishedName"
	AttrCN              = "cn"
	AttrSN              = "sn"
	AttrGivenName       = "givenName"
	AttrDisplayName     = "displayName"
	AttrSAMAccountName  = "sAMAccountName"
	AttrUserPrincipal   = "userPrincipalName"
	AttrMail            = "mail"
	AttrMember          = "member"
	AttrMemberOf        = "memberOf"
	AttrObjectClass     = "objectClass"
	AttrObjectGUID      = "objectGUID"
	AttrObjectSID       = "objectSid"
	AttrUserAccountCtrl = "userAccountControl"
	AttrDescription     = "description"
	AttrWhenCreated     = "whenCreated"
	AttrWhenChanged     = "whenChanged"
	AttrDNSHostName     = "dNSHostName"
	AttrOperatingSystem = "operatingSystem"
)

// UserAccountControl flags (subset).
const (
	UACAccountDisable     = 0x0002
	UACNormalAccount      = 0x0200
	UACPasswordNotReqd    = 0x0020
	UACDontExpirePassword = 0x10000
)

// Default attribute sets for common object types.
var (
	UserAttrs = []string{
		AttrCN, AttrSN, AttrGivenName, AttrDisplayName,
		AttrSAMAccountName, AttrUserPrincipal, AttrMail,
		AttrMemberOf, AttrUserAccountCtrl, AttrDescription,
		AttrWhenCreated, AttrWhenChanged, AttrObjectGUID, AttrObjectSID,
	}
	GroupAttrs = []string{
		AttrCN, AttrSAMAccountName, AttrDescription, AttrMember,
		AttrObjectGUID, AttrObjectSID, AttrWhenCreated,
	}
	ComputerAttrs = []string{
		AttrCN, AttrSAMAccountName, AttrDNSHostName, AttrOperatingSystem,
		AttrDescription, AttrUserAccountCtrl, AttrObjectGUID, AttrObjectSID,
	}
)
