package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"sambaadm/internal/audit"
)

// ACLEntry is one POSIX ACL line.
type ACLEntry struct {
	Kind      string `json:"kind"`                // user|group|mask|other
	Qualifier string `json:"qualifier,omitempty"` // name or empty
	Perms     string `json:"perms"`               // rwx / r-x / ---
	Default   bool   `json:"default"`
	Raw       string `json:"raw"`
}

// XAttr is an extended attribute.
type XAttr struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PathACL is POSIX ACL / mode / xattr info for a directory or file.
type PathACL struct {
	Path       string     `json:"path"`
	Mode       string     `json:"mode,omitempty"`
	Owner      string     `json:"owner,omitempty"`
	Group      string     `json:"group,omitempty"`
	ACLText    string     `json:"acl,omitempty"`
	DefaultACL string     `json:"defaultAcl,omitempty"`
	Entries    []ACLEntry `json:"entries,omitempty"`
	XAttrs     []XAttr    `json:"xattrs,omitempty"`
	Exists     bool       `json:"exists"`
	IsDir      bool       `json:"isDir"`
}

// SetACLInput applies ownership, mode, POSIX ACL and/or xattrs.
type SetACLInput struct {
	Path             string `json:"path"`
	Owner            string `json:"owner,omitempty"` // user[:group]
	Mode             string `json:"mode,omitempty"`  // octal
	ACL              string `json:"acl,omitempty"`   // setfacl -m
	DefaultACL       string `json:"defaultAcl,omitempty"`
	Recursive        bool   `json:"recursive,omitempty"`
	DefaultRecursive bool   `json:"defaultRecursive,omitempty"` // also apply default ACL with -R via setfacl -d -R -m (not portable) — we set default then recurse access
	ClearACL         bool   `json:"clearAcl,omitempty"`         // setfacl -b
	ClearDefault     bool   `json:"clearDefault,omitempty"`     // setfacl -k
	RemoveACL        string `json:"removeAcl,omitempty"`        // setfacl -x
	CopyToDefault    bool   `json:"copyToDefault,omitempty"`    // copy access ACL → default (inheritance)
	XAttrName        string `json:"xattrName,omitempty"`
	XAttrValue       string `json:"xattrValue,omitempty"`
	XAttrRemove      string `json:"xattrRemove,omitempty"`
}

// FSACLService manages filesystem permissions for share paths.
type FSACLService struct {
	audit  *audit.Logger
	shares *ShareService
}

func newFSACLService(auditLog *audit.Logger, shares *ShareService) *FSACLService {
	return &FSACLService{audit: auditLog, shares: shares}
}

// Get returns mode/owner, ACL entries and xattrs for a path.
func (s *FSACLService) Get(ctx context.Context, path string) (*PathACL, error) {
	path = filepath.Clean(path)
	if err := s.shares.validatePath(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	out := &PathACL{Path: path}
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	out.Exists = true
	out.IsDir = info.IsDir()
	out.Mode = fmt.Sprintf("%04o", info.Mode().Perm())

	if st, ok := fileOwner(info); ok {
		out.Owner = st.uidName
		out.Group = st.gidName
	}

	acl, def, err := readACL(ctx, path)
	if err == nil {
		out.ACLText = acl
		out.DefaultACL = def
		out.Entries = parseACLEntries(acl, def)
	} else {
		out.ACLText = err.Error()
	}
	if xattrs, err := listXAttrs(ctx, path); err == nil {
		out.XAttrs = xattrs
	}
	return out, nil
}

// Set applies chown/chmod/setfacl/setfattr.
func (s *FSACLService) Set(ctx context.Context, in SetACLInput, actor, ip string) (*PathACL, error) {
	path := filepath.Clean(strings.TrimSpace(in.Path))
	if err := s.shares.validatePath(path); err != nil {
		s.audit.Failure(actor, "acl.set", path, ip, err)
		return nil, err
	}
	if _, err := os.Lstat(path); err != nil {
		s.audit.Failure(actor, "acl.set", path, ip, err)
		return nil, err
	}
	if in.Owner != "" {
		if err := chownPath(path, in.Owner); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.Mode != "" {
		v, err := strconv.ParseUint(strings.TrimPrefix(in.Mode, "0"), 8, 32)
		if err != nil {
			return nil, fmt.Errorf("mode: %w", err)
		}
		if err := os.Chmod(path, os.FileMode(v)); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.ClearACL {
		if err := clearACL(path, in.Recursive); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.ClearDefault {
		if err := clearDefaultACL(path); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.RemoveACL != "" {
		if err := removeACL(path, normalizeACLSpec(in.RemoveACL), in.Recursive); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.ACL != "" {
		if err := applyACL(path, normalizeACLSpec(in.ACL), in.Recursive); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.DefaultACL != "" {
		if err := applyDefaultACL(path, normalizeACLSpec(in.DefaultACL)); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.CopyToDefault {
		access, _, err := readACL(ctx, path)
		if err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
		spec := accessACLToDefaultSpec(access)
		if spec != "" {
			if err := applyDefaultACL(path, spec); err != nil {
				s.audit.Failure(actor, "acl.set", path, ip, err)
				return nil, err
			}
		}
	}
	if in.DefaultRecursive && in.DefaultACL != "" {
		// Re-apply access recursively so children get same named entries (defaults already on dir).
		if err := applyACL(path, normalizeACLSpec(in.DefaultACL), true); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, fmt.Errorf("recursive apply after default: %w", err)
		}
	}
	if in.XAttrRemove != "" {
		if err := removeXAttr(path, in.XAttrRemove); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	if in.XAttrName != "" {
		if err := setXAttr(path, in.XAttrName, in.XAttrValue); err != nil {
			s.audit.Failure(actor, "acl.set", path, ip, err)
			return nil, err
		}
	}
	s.audit.Success(actor, "acl.set", path, ip)
	return s.Get(ctx, path)
}

// BuildACLSpec builds setfacl -m spec from kind/name/perms (+ optional default).
func BuildACLSpec(kind, name, perms string) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	perms = normalizePerms(perms)
	name = strings.TrimSpace(name)
	switch kind {
	case "u", "user":
		if name == "" {
			return "u::" + perms, nil
		}
		return "u:" + name + ":" + perms, nil
	case "g", "group":
		if name == "" {
			return "g::" + perms, nil
		}
		return "g:" + name + ":" + perms, nil
	case "o", "other":
		return "o::" + perms, nil
	case "m", "mask":
		return "m::" + perms, nil
	default:
		return "", fmt.Errorf("unknown ACL kind %q", kind)
	}
}

func normalizePerms(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "---"
	}
	r, w, x := '-', '-', '-'
	if strings.Contains(p, "r") {
		r = 'r'
	}
	if strings.Contains(p, "w") {
		w = 'w'
	}
	if strings.Contains(p, "x") {
		x = 'x'
	}
	return string([]byte{byte(r), byte(w), byte(x)})
}

func applyACL(path, acl string, recursive bool) error {
	args := []string{"-m", acl}
	if recursive {
		args = append(args, "-R")
	}
	args = append(args, path)
	cmd := exec.Command("setfacl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyDefaultACL(path, acl string) error {
	cmd := exec.Command("setfacl", "-d", "-m", acl, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl -d: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func clearACL(path string, recursive bool) error {
	args := []string{"-b"}
	if recursive {
		args = append(args, "-R")
	}
	args = append(args, path)
	cmd := exec.Command("setfacl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl -b: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func clearDefaultACL(path string) error {
	cmd := exec.Command("setfacl", "-k", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl -k: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeACL(path, spec string, recursive bool) error {
	args := []string{"-x", spec}
	if recursive {
		args = append(args, "-R")
	}
	args = append(args, path)
	cmd := exec.Command("setfacl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfacl -x: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func readACL(ctx context.Context, path string) (access, def string, err error) {
	cmd := exec.CommandContext(ctx, "getfacl", "-p", path)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("getfacl: %w (%s)", err, strings.TrimSpace(buf.String()))
	}
	var accessLines, defaultLines []string
	for _, line := range strings.Split(buf.String(), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.HasPrefix(trim, "default:") {
			defaultLines = append(defaultLines, trim)
		} else {
			accessLines = append(accessLines, trim)
		}
	}
	return strings.Join(accessLines, "\n"), strings.Join(defaultLines, "\n"), nil
}

func parseACLEntries(access, def string) []ACLEntry {
	var out []ACLEntry
	for _, line := range strings.Split(access, "\n") {
		if e, ok := parseACLLine(line, false); ok {
			out = append(out, e)
		}
	}
	for _, line := range strings.Split(def, "\n") {
		if e, ok := parseACLLine(line, true); ok {
			out = append(out, e)
		}
	}
	return out
}

func parseACLLine(line string, forceDefault bool) (ACLEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return ACLEntry{}, false
	}
	isDef := forceDefault || strings.HasPrefix(line, "default:")
	raw := line
	if strings.HasPrefix(line, "default:") {
		line = strings.TrimPrefix(line, "default:")
	}
	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		return ACLEntry{}, false
	}
	e := ACLEntry{Raw: raw, Default: isDef, Kind: parts[0]}
	switch len(parts) {
	case 2: // other:rwx or mask:rwx (short) — uncommon
		e.Perms = parts[1]
	case 3:
		e.Qualifier = parts[1]
		e.Perms = parts[2]
	default:
		e.Qualifier = strings.Join(parts[1:len(parts)-1], ":")
		e.Perms = parts[len(parts)-1]
	}
	return e, true
}

func accessACLToDefaultSpec(access string) string {
	var parts []string
	for _, line := range strings.Split(access, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "default:") {
			continue
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, ",")
}

func listXAttrs(ctx context.Context, path string) ([]XAttr, error) {
	cmd := exec.CommandContext(ctx, "getfattr", "-d", "-m", "-", "--absolute-names", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// getfattr missing or no attrs
		if len(bytes.TrimSpace(out)) == 0 {
			return nil, err
		}
	}
	var attrs []XAttr
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eq])
		val := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
		attrs = append(attrs, XAttr{Name: name, Value: val})
	}
	return attrs, nil
}

func setXAttr(path, name, value string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty xattr name")
	}
	cmd := exec.Command("setfattr", "-n", name, "-v", value, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfattr: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeXAttr(path, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty xattr name")
	}
	cmd := exec.Command("setfattr", "-x", name, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("setfattr -x: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
