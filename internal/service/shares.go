package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	"sambaadm/internal/smbconf"
)

// Share is a Samba file share from smb.conf.
type Share struct {
	Name           string            `json:"name"`
	Path           string            `json:"path,omitempty"`
	Comment        string            `json:"comment,omitempty"`
	Browseable     bool              `json:"browseable"`
	ReadOnly       bool              `json:"readOnly"`
	GuestOK        bool              `json:"guestOk"`
	ValidUsers     string            `json:"validUsers,omitempty"`
	WriteList      string            `json:"writeList,omitempty"`
	ReadList       string            `json:"readList,omitempty"`
	ForceUser      string            `json:"forceUser,omitempty"`
	ForceGroup     string            `json:"forceGroup,omitempty"`
	CreateMask     string            `json:"createMask,omitempty"`
	DirectoryMask  string            `json:"directoryMask,omitempty"`
	InheritACLs    bool              `json:"inheritAcls"`
	MapACLInherit  bool              `json:"mapAclInherit"`
	Printable      bool              `json:"printable"`
	Params         map[string]string `json:"params,omitempty"`
	PathExists     bool              `json:"pathExists"`
}

// CreateShareInput creates a share and optionally the filesystem path.
type CreateShareInput struct {
	Name           string `json:"name"`
	Path           string `json:"path"`
	Comment        string `json:"comment,omitempty"`
	Preset         string `json:"preset,omitempty"` // see share_presets.go
	Browseable     *bool  `json:"browseable,omitempty"`
	ReadOnly       *bool  `json:"readOnly,omitempty"`
	GuestOK        *bool  `json:"guestOk,omitempty"`
	ValidUsers     string `json:"validUsers,omitempty"`
	WriteList      string `json:"writeList,omitempty"`
	ReadList       string `json:"readList,omitempty"`
	ForceUser      string `json:"forceUser,omitempty"`
	ForceGroup     string `json:"forceGroup,omitempty"`
	CreateMask     string `json:"createMask,omitempty"`
	DirectoryMask  string `json:"directoryMask,omitempty"`
	InheritACLs    *bool  `json:"inheritAcls,omitempty"`    // smb.conf inherit acls
	MapACLInherit  *bool  `json:"mapAclInherit,omitempty"`  // smb.conf map acl inherit
	Owner          string `json:"owner,omitempty"`           // user or user:group
	Mode           string `json:"mode,omitempty"`            // octal
	ACL            string `json:"acl,omitempty"`             // setfacl -m
	DefaultACL     string `json:"defaultAcl,omitempty"`      // setfacl -d -m (inheritance)
	CreateDir      *bool  `json:"createDir,omitempty"`
	Reload         *bool  `json:"reload,omitempty"`
}

// UpdateShareAccessInput updates Samba-level access parameters on an existing share.
type UpdateShareAccessInput struct {
	Comment       string `json:"comment,omitempty"`
	Browseable    *bool  `json:"browseable,omitempty"`
	ReadOnly      *bool  `json:"readOnly,omitempty"`
	GuestOK       *bool  `json:"guestOk,omitempty"`
	ValidUsers    string `json:"validUsers,omitempty"`
	WriteList     string `json:"writeList,omitempty"`
	ReadList      string `json:"readList,omitempty"`
	ForceUser     string `json:"forceUser,omitempty"`
	ForceGroup    string `json:"forceGroup,omitempty"`
	CreateMask    string `json:"createMask,omitempty"`
	DirectoryMask string `json:"directoryMask,omitempty"`
	InheritACLs   *bool  `json:"inheritAcls,omitempty"`
	MapACLInherit *bool  `json:"mapAclInherit,omitempty"`
	ClearValid    bool   `json:"clearValidUsers,omitempty"`
	ClearWrite    bool   `json:"clearWriteList,omitempty"`
	ClearRead     bool   `json:"clearReadList,omitempty"`
}

// ShareService manages local smb.conf shares and directories.
type ShareService struct {
	audit *audit.Logger
	cfg   config.SambaConfig
}

func newShareService(auditLog *audit.Logger, cfg config.SambaConfig) *ShareService {
	if cfg.SMBConf == "" {
		cfg.SMBConf = "/etc/samba/smb.conf"
	}
	if cfg.SharesRoot == "" {
		cfg.SharesRoot = "/srv/samba"
	}
	if cfg.CreateMode == "" {
		cfg.CreateMode = "0755"
	}
	if cfg.ReloadCmd == "" {
		cfg.ReloadCmd = "smbcontrol all reload-config"
	}
	return &ShareService{audit: auditLog, cfg: cfg}
}

// List returns non-global share sections (file shares and printers).
func (s *ShareService) List(ctx context.Context) ([]Share, error) {
	_ = ctx
	doc, err := smbconf.ParseFile(s.cfg.SMBConf)
	if err != nil {
		return nil, err
	}
	var out []Share
	for _, name := range doc.SectionNames() {
		if isReservedSection(name) && !strings.EqualFold(name, "homes") && !strings.EqualFold(name, "printers") && !strings.EqualFold(name, "print$") {
			continue
		}
		if strings.EqualFold(name, "global") {
			continue
		}
		sec, _ := doc.Get(name)
		out = append(out, sectionToShare(sec))
	}
	return out, nil
}

// ListFileShares returns only non-printable shares.
func (s *ShareService) ListFileShares(ctx context.Context) ([]Share, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Share, 0, len(all))
	for _, sh := range all {
		if sh.Printable || strings.EqualFold(sh.Name, "printers") || strings.EqualFold(sh.Name, "print$") {
			continue
		}
		out = append(out, sh)
	}
	return out, nil
}

// Show returns one share by name.
func (s *ShareService) Show(ctx context.Context, name string) (*Share, error) {
	_ = ctx
	doc, err := smbconf.ParseFile(s.cfg.SMBConf)
	if err != nil {
		return nil, err
	}
	sec, ok := doc.Get(name)
	if !ok {
		return nil, fmt.Errorf("share %q not found", name)
	}
	sh := sectionToShare(sec)
	return &sh, nil
}

// Create adds a share, creates the directory, applies ownership/ACL, reloads smbd.
func (s *ShareService) Create(ctx context.Context, in CreateShareInput, actor, ip string) (*Share, error) {
	ApplyPreset(&in)
	name := strings.TrimSpace(in.Name)
	if err := validateShareName(name); err != nil {
		s.audit.Failure(actor, "share.create", name, ip, err)
		return nil, err
	}
	if isReservedSection(name) {
		err := fmt.Errorf("reserved share name %q", name)
		s.audit.Failure(actor, "share.create", name, ip, err)
		return nil, err
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		path = filepath.Join(s.cfg.SharesRoot, name)
	}
	path = filepath.Clean(path)
	if err := s.validatePath(path); err != nil {
		s.audit.Failure(actor, "share.create", name, ip, err)
		return nil, err
	}

	doc, err := smbconf.ParseFile(s.cfg.SMBConf)
	if err != nil {
		s.audit.Failure(actor, "share.create", name, ip, err)
		return nil, err
	}
	if _, ok := doc.Get(name); ok {
		err := fmt.Errorf("share %q already exists", name)
		s.audit.Failure(actor, "share.create", name, ip, err)
		return nil, err
	}

	createDir := true
	if in.CreateDir != nil {
		createDir = *in.CreateDir
	}
	if createDir {
		mode := s.cfg.CreateMode
		if in.Mode != "" {
			mode = in.Mode
		}
		if err := ensureDir(path, mode, in.Owner); err != nil {
			s.audit.Failure(actor, "share.create", name, ip, err)
			return nil, fmt.Errorf("create directory: %w", err)
		}
		if in.ACL != "" {
			if err := applyACL(path, normalizeACLSpec(in.ACL), false); err != nil {
				s.audit.Failure(actor, "share.create", name, ip, err)
				return nil, fmt.Errorf("set acl: %w", err)
			}
		}
		if in.DefaultACL != "" {
			if err := applyDefaultACL(path, normalizeACLSpec(in.DefaultACL)); err != nil {
				s.audit.Failure(actor, "share.create", name, ip, err)
				return nil, fmt.Errorf("set default acl: %w", err)
			}
		}
	}

	browseable := true
	if in.Browseable != nil {
		browseable = *in.Browseable
	}
	readOnly := false
	if in.ReadOnly != nil {
		readOnly = *in.ReadOnly
	}
	guestOK := false
	if in.GuestOK != nil {
		guestOK = *in.GuestOK
	}

	doc.SetParam(name, "path", path)
	doc.SetParam(name, "browseable", boolYesNo(browseable))
	doc.SetParam(name, "read only", boolYesNo(readOnly))
	doc.SetParam(name, "guest ok", boolYesNo(guestOK))
	if in.Comment != "" {
		doc.SetParam(name, "comment", in.Comment)
	}
	if in.ValidUsers != "" {
		doc.SetParam(name, "valid users", in.ValidUsers)
	}
	if in.WriteList != "" {
		doc.SetParam(name, "write list", in.WriteList)
	}
	if in.ReadList != "" {
		doc.SetParam(name, "read list", in.ReadList)
	}
	if in.ForceUser != "" {
		doc.SetParam(name, "force user", in.ForceUser)
	}
	if in.ForceGroup != "" {
		doc.SetParam(name, "force group", in.ForceGroup)
	}
	if in.CreateMask != "" {
		doc.SetParam(name, "create mask", in.CreateMask)
	}
	if in.DirectoryMask != "" {
		doc.SetParam(name, "directory mask", in.DirectoryMask)
	}
	if in.InheritACLs != nil {
		doc.SetParam(name, "inherit acls", boolYesNo(*in.InheritACLs))
	} else {
		doc.SetParam(name, "inherit acls", "yes")
	}
	if in.MapACLInherit != nil {
		doc.SetParam(name, "map acl inherit", boolYesNo(*in.MapACLInherit))
	} else {
		doc.SetParam(name, "map acl inherit", "yes")
	}

	if err := doc.SaveAtomic(s.cfg.SMBConf); err != nil {
		s.audit.Failure(actor, "share.create", name, ip, err)
		return nil, err
	}

	reload := true
	if in.Reload != nil {
		reload = *in.Reload
	}
	if reload {
		if err := s.Reload(ctx); err != nil {
			s.audit.Failure(actor, "share.create", name, ip, err)
			return nil, fmt.Errorf("share saved but reload failed: %w", err)
		}
	}

	s.audit.Success(actor, "share.create", name, ip)
	return s.Show(ctx, name)
}

// Delete removes a share from smb.conf. Optionally remove the directory.
func (s *ShareService) Delete(ctx context.Context, name string, removeDir bool, actor, ip string) error {
	if isReservedSection(name) || strings.EqualFold(name, "global") {
		err := fmt.Errorf("cannot delete reserved section %q", name)
		s.audit.Failure(actor, "share.delete", name, ip, err)
		return err
	}
	doc, err := smbconf.ParseFile(s.cfg.SMBConf)
	if err != nil {
		s.audit.Failure(actor, "share.delete", name, ip, err)
		return err
	}
	sec, ok := doc.Get(name)
	if !ok {
		err := fmt.Errorf("share %q not found", name)
		s.audit.Failure(actor, "share.delete", name, ip, err)
		return err
	}
	path := ""
	if p, ok := sec.ParamsMap()["path"]; ok {
		path = p
	}
	if !doc.DeleteSection(name) {
		return fmt.Errorf("share %q not found", name)
	}
	if err := doc.SaveAtomic(s.cfg.SMBConf); err != nil {
		s.audit.Failure(actor, "share.delete", name, ip, err)
		return err
	}
	if removeDir && path != "" {
		if err := s.validatePath(path); err == nil {
			_ = os.RemoveAll(path)
		}
	}
	if err := s.Reload(ctx); err != nil {
		s.audit.Failure(actor, "share.delete", name, ip, err)
		return fmt.Errorf("share removed but reload failed: %w", err)
	}
	s.audit.Success(actor, "share.delete", name, ip)
	return nil
}

// UpdateAccess updates Samba share access parameters.
func (s *ShareService) UpdateAccess(ctx context.Context, name string, in UpdateShareAccessInput, actor, ip string) (*Share, error) {
	doc, err := smbconf.ParseFile(s.cfg.SMBConf)
	if err != nil {
		return nil, err
	}
	if _, ok := doc.Get(name); !ok {
		err := fmt.Errorf("share %q not found", name)
		s.audit.Failure(actor, "share.access", name, ip, err)
		return nil, err
	}
	setOrClear := func(key, value string, clear bool) {
		if clear || value == "-" {
			doc.DeleteParam(name, key)
			return
		}
		if value != "" {
			doc.SetParam(name, key, value)
		}
	}
	if in.Comment != "" {
		doc.SetParam(name, "comment", in.Comment)
	}
	if in.Browseable != nil {
		doc.SetParam(name, "browseable", boolYesNo(*in.Browseable))
	}
	if in.ReadOnly != nil {
		doc.SetParam(name, "read only", boolYesNo(*in.ReadOnly))
	}
	if in.GuestOK != nil {
		doc.SetParam(name, "guest ok", boolYesNo(*in.GuestOK))
	}
	setOrClear("valid users", in.ValidUsers, in.ClearValid)
	setOrClear("write list", in.WriteList, in.ClearWrite)
	setOrClear("read list", in.ReadList, in.ClearRead)
	if in.ForceUser != "" {
		doc.SetParam(name, "force user", in.ForceUser)
	}
	if in.ForceGroup != "" {
		doc.SetParam(name, "force group", in.ForceGroup)
	}
	if in.CreateMask != "" {
		doc.SetParam(name, "create mask", in.CreateMask)
	}
	if in.DirectoryMask != "" {
		doc.SetParam(name, "directory mask", in.DirectoryMask)
	}
	if in.InheritACLs != nil {
		doc.SetParam(name, "inherit acls", boolYesNo(*in.InheritACLs))
	}
	if in.MapACLInherit != nil {
		doc.SetParam(name, "map acl inherit", boolYesNo(*in.MapACLInherit))
	}
	if err := doc.SaveAtomic(s.cfg.SMBConf); err != nil {
		s.audit.Failure(actor, "share.access", name, ip, err)
		return nil, err
	}
	if err := s.Reload(ctx); err != nil {
		s.audit.Failure(actor, "share.access", name, ip, err)
		return nil, err
	}
	s.audit.Success(actor, "share.access", name, ip)
	return s.Show(ctx, name)
}

// SetParam updates a single smb.conf parameter for a share.
func (s *ShareService) SetParam(ctx context.Context, name, key, value, actor, ip string) error {
	if strings.EqualFold(name, "global") {
		// allow carefully — still admin
	}
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("empty key")
	}
	doc, err := smbconf.ParseFile(s.cfg.SMBConf)
	if err != nil {
		return err
	}
	if _, ok := doc.Get(name); !ok {
		return fmt.Errorf("share %q not found", name)
	}
	if strings.EqualFold(key, "path") {
		value = filepath.Clean(value)
		if err := s.validatePath(value); err != nil {
			return err
		}
	}
	doc.SetParam(name, key, value)
	if err := doc.SaveAtomic(s.cfg.SMBConf); err != nil {
		s.audit.Failure(actor, "share.set", name+"."+key, ip, err)
		return err
	}
	if err := s.Reload(ctx); err != nil {
		return err
	}
	s.audit.Success(actor, "share.set", name+"."+key, ip)
	return nil
}

// Reload asks smbd to reload configuration.
func (s *ShareService) Reload(ctx context.Context) error {
	cmdLine := strings.TrimSpace(s.cfg.ReloadCmd)
	if cmdLine == "" {
		return nil
	}
	parts := strings.Fields(cmdLine)
	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", cmdLine, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ConfigPath returns the configured smb.conf path.
func (s *ShareService) ConfigPath() string { return s.cfg.SMBConf }

// SharesRoot returns the default root for new share paths.
func (s *ShareService) SharesRoot() string { return s.cfg.SharesRoot }

func (s *ShareService) validatePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %s", path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("invalid path: %s", path)
	}
	if s.cfg.AllowAnyPath {
		return nil
	}
	root := filepath.Clean(s.cfg.SharesRoot)
	clean := filepath.Clean(path)
	if clean == root {
		return nil
	}
	prefix := root + string(os.PathSeparator)
	if !strings.HasPrefix(clean, prefix) {
		return fmt.Errorf("path %q must be under shares_root %q (or set samba.allow_any_path)", clean, root)
	}
	return nil
}

func sectionToShare(sec *smbconf.Section) Share {
	p := sec.ParamsMap()
	path := p["path"]
	_, err := os.Stat(path)
	sh := Share{
		Name:          sec.Name,
		Path:          path,
		Comment:       p["comment"],
		Browseable:    parseYes(p["browseable"], true),
		ReadOnly:      parseYes(p["read only"], true),
		GuestOK:       parseYes(p["guest ok"], false),
		ValidUsers:    p["valid users"],
		WriteList:     p["write list"],
		ReadList:      p["read list"],
		ForceUser:     p["force user"],
		ForceGroup:    p["force group"],
		CreateMask:    firstNonEmpty(p["create mask"], p["create mode"]),
		DirectoryMask: firstNonEmpty(p["directory mask"], p["directory mode"]),
		InheritACLs:   parseYes(p["inherit acls"], false),
		MapACLInherit: parseYes(p["map acl inherit"], false),
		Printable:     parseYes(p["printable"], false),
		Params:        p,
		PathExists:    err == nil,
	}
	return sh
}

// normalizeACLSpec cleans UI-friendly ACL text into setfacl -m form.
func normalizeACLSpec(acl string) string {
	acl = strings.TrimSpace(acl)
	acl = strings.ReplaceAll(acl, "\n", ",")
	acl = strings.ReplaceAll(acl, ";", ",")
	parts := strings.Split(acl, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ",")
}

func validateShareName(name string) error {
	if name == "" {
		return fmt.Errorf("empty share name")
	}
	if len(name) > 80 {
		return fmt.Errorf("share name too long")
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '$' {
			continue
		}
		return fmt.Errorf("invalid share name %q", name)
	}
	return nil
}

func isReservedSection(name string) bool {
	switch strings.ToLower(name) {
	case "global", "printers", "print$":
		return true
	default:
		return false
	}
}

func parseYes(v string, def bool) bool {
	if v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on":
		return true
	case "no", "false", "0", "off":
		return false
	default:
		return def
	}
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func ensureDir(path, modeStr, owner string) error {
	perm := os.FileMode(0755)
	if modeStr != "" {
		v, err := strconv.ParseUint(strings.TrimPrefix(modeStr, "0"), 8, 32)
		if err != nil {
			return fmt.Errorf("mode: %w", err)
		}
		perm = os.FileMode(v)
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	// MkdirAll may leave existing perms; enforce.
	if err := os.Chmod(path, perm); err != nil {
		return err
	}
	if owner != "" {
		if err := chownPath(path, owner); err != nil {
			return err
		}
	}
	return nil
}

func chownPath(path, owner string) error {
	userName := owner
	groupName := ""
	if i := strings.IndexByte(owner, ':'); i >= 0 {
		userName = owner[:i]
		groupName = owner[i+1:]
	}
	uid := -1
	gid := -1
	if userName != "" {
		u, err := user.Lookup(userName)
		if err != nil {
			return fmt.Errorf("user %q: %w", userName, err)
		}
		id, err := strconv.Atoi(u.Uid)
		if err != nil {
			return err
		}
		uid = id
		if groupName == "" {
			id, err := strconv.Atoi(u.Gid)
			if err != nil {
				return err
			}
			gid = id
		}
	}
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return fmt.Errorf("group %q: %w", groupName, err)
		}
		id, err := strconv.Atoi(g.Gid)
		if err != nil {
			return err
		}
		gid = id
	}
	return os.Chown(path, uid, gid)
}
