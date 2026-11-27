package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const shareMapMaxDirectories = 2000
const shareMapMaxEntries = 100000

var ErrShareMapConflict = errors.New("дерево или права изменились; снимите карту и выполните предпросмотр заново")

type SharePermissionNode struct {
	Path     string     `json:"path"`
	Parent   string     `json:"parent,omitempty"`
	Name     string     `json:"name"`
	Identity string     `json:"identity"`
	Mode     string     `json:"mode"`
	Owner    string     `json:"owner"`
	Group    string     `json:"group"`
	Access   string     `json:"access"`
	Default  string     `json:"default"`
	Entries  []ACLEntry `json:"entries"`
	Error    string     `json:"error,omitempty"`
	Revision string     `json:"revision"`
}
type SharePermissionSnapshot struct {
	Share        string                `json:"share"`
	Root         string                `json:"root"`
	Created      time.Time             `json:"created"`
	Revision     string                `json:"revision"`
	Complete     bool                  `json:"complete"`
	SkippedLinks int                   `json:"skippedLinks"`
	Warnings     []string              `json:"warnings"`
	Nodes        []SharePermissionNode `json:"nodes"`
}
type SharePermissionRule struct {
	Group       string `json:"group"`
	GID         string `json:"gid,omitempty"`
	Permissions string `json:"permissions"` // r-x, rwx, or remove (no explicit deny in POSIX ACL).
}
type SharePermissionTemplate struct {
	Name    string                `json:"name"`
	Rules   []SharePermissionRule `json:"rules"`
	Inherit bool                  `json:"inherit"`
}
type SharePermissionOverlay struct {
	Path      string                  `json:"path"`
	Recursive bool                    `json:"recursive"`
	Template  SharePermissionTemplate `json:"template"`
}
type SharePermissionMapRequest struct {
	Root             string                   `json:"root"`
	SnapshotRevision string                   `json:"snapshotRevision"`
	PlanRevision     string                   `json:"planRevision,omitempty"`
	Overlays         []SharePermissionOverlay `json:"overlays"`
	Confirm          bool                     `json:"confirm,omitempty"`
}
type SharePermissionChange struct {
	Path      string              `json:"path"`
	Before    SharePermissionNode `json:"before"`
	Access    string              `json:"access"`
	Default   string              `json:"default"`
	Templates []string            `json:"templates"`
}
type SharePermissionPlan struct {
	SnapshotRevision string                  `json:"snapshotRevision"`
	Revision         string                  `json:"revision"`
	Changes          []SharePermissionChange `json:"changes"`
	Directories      int                     `json:"directories"`
	Groups           map[string]string       `json:"groups"`
}
type SharePermissionApplyItem struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type SharePermissionApplyResult struct {
	Error   string                     `json:"error,omitempty"`
	ID      string                     `json:"id"`
	Status  string                     `json:"status"`
	Journal string                     `json:"journal"`
	Items   []SharePermissionApplyItem `json:"items"`
}

func shareMapDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func canonicalShareACL(access, defaults string) (string, string, error) {
	normalize := func(text string, defaultACL bool) (string, error) {
		entries := []string{}
		seen := map[string]bool{}
		for _, line := range strings.Split(text, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			entry, ok := parseACLLine(line, defaultACL)
			if !ok || !strings.Contains("|user|group|mask|other|", "|"+entry.Kind+"|") || normalizePerms(entry.Perms) != entry.Perms {
				return "", fmt.Errorf("не удалось разобрать POSIX ACL")
			}
			if entry.Qualifier != "" {
				if _, err := strconv.ParseUint(entry.Qualifier, 10, 32); err != nil {
					return "", fmt.Errorf("ACL должен содержать числовые UID/GID")
				}
			}
			key := entry.Kind + ":" + entry.Qualifier
			if seen[key] {
				return "", fmt.Errorf("повторная запись ACL")
			}
			seen[key] = true
			prefix := ""
			if defaultACL {
				prefix = "default:"
			}
			entries = append(entries, prefix+key+":"+entry.Perms)
		}
		if len(entries) > 0 {
			for _, key := range []string{"user:", "group:", "other:"} {
				if !seen[key] {
					return "", fmt.Errorf("неполный POSIX ACL")
				}
			}
		}
		sort.Strings(entries)
		return strings.Join(entries, "\n"), nil
	}
	a, err := normalize(access, false)
	if err != nil || a == "" {
		if err == nil {
			err = fmt.Errorf("пустой ACL доступа")
		}
		return "", "", err
	}
	d, err := normalize(defaults, true)
	return a, d, err
}
func shareMapNodeRevision(n SharePermissionNode) string {
	return shareMapDigest([]string{n.Path, n.Identity, n.Mode, n.Access, n.Default, n.Error})
}
func (s *FSACLService) readMapNode(ctx context.Context, rel string) (SharePermissionNode, error) {
	n := SharePermissionNode{Path: rel, Name: filepath.Base(filepath.FromSlash(rel))}
	if rel != "." {
		n.Parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
	}
	path := filepath.Join(s.shares.cfg.SharesRoot, filepath.FromSlash(rel))
	pin, err := s.pinPath(path)
	if err != nil {
		return n, err
	}
	defer pin.Close()
	info, err := pin.File.Stat()
	if err != nil {
		return n, err
	}
	if !info.IsDir() {
		return n, fmt.Errorf("объект больше не является каталогом")
	}
	n.Identity = shareMapFileIdentity(info)
	n.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
	if info.Mode()&os.ModeSetgid != 0 {
		n.Mode = "setgid " + n.Mode
	}
	if owner, ok := fileOwner(info); ok {
		n.Owner = owner.uidName
		n.Group = owner.gidName
	}
	access, defaults, err := readACL(ctx, pin.Path)
	if err != nil {
		return n, err
	}
	n.Access, n.Default, err = canonicalShareACL(access, defaults)
	if err != nil {
		return n, err
	}
	n.Entries = parseACLEntries(access, defaults)
	n.Revision = shareMapNodeRevision(n)
	return n, nil
}
func (s *FSACLService) capturePermissionMap(ctx context.Context, name, rel string) (*SharePermissionSnapshot, error) {
	relative, err := shareRelativePath(rel)
	if err != nil {
		return nil, err
	}
	rel = filepath.ToSlash(filepath.Clean(relative))
	out := &SharePermissionSnapshot{Share: name, Root: rel, Created: time.Now().UTC(), Complete: true, Warnings: []string{}, Nodes: []SharePermissionNode{}}
	queue := []string{rel}
	inspected := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := queue[0]
		queue = queue[1:]
		if len(out.Nodes) >= shareMapMaxDirectories {
			out.Complete = false
			out.Warnings = append(out.Warnings, "Достигнут предел 2000 каталогов. Выберите поддерево меньшего размера.")
			break
		}
		node, err := s.readMapNode(ctx, path)
		if path == rel {
			node.Parent = ""
			node.Name = name
			if rel != "." {
				node.Name = filepath.Base(filepath.FromSlash(rel))
			}
		}
		if err != nil {
			node.Error = err.Error()
			node.Revision = shareMapNodeRevision(node)
			out.Complete = false
			out.Nodes = append(out.Nodes, node)
			continue
		}
		out.Nodes = append(out.Nodes, node)
		dir, err := s.root.Open(filepath.FromSlash(path))
		if err != nil {
			out.Complete = false
			out.Nodes[len(out.Nodes)-1].Error = err.Error()
			continue
		}
		stop := false
		for {
			entries, readErr := dir.ReadDir(128)
			for _, entry := range entries {
				inspected++
				if inspected > shareMapMaxEntries {
					stop = true
					out.Complete = false
					out.Warnings = append(out.Warnings, "Достигнут предел просмотра 100000 объектов. Выберите поддерево меньшего размера.")
					break
				}
				if entry.Type()&os.ModeSymlink != 0 {
					out.SkippedLinks++
					continue
				}
				if entry.IsDir() {
					child := filepath.ToSlash(filepath.Join(filepath.FromSlash(path), entry.Name()))
					childFromRoot, _ := filepath.Rel(filepath.FromSlash(rel), filepath.FromSlash(child))
					if strings.Count(filepath.ToSlash(childFromRoot), "/") >= 64 || len(queue)+len(out.Nodes) >= shareMapMaxDirectories {
						out.Complete = false
						stop = true
						out.Warnings = append(out.Warnings, "Ограничение размера или глубины карты. Выберите поддерево меньшего размера.")
						break
					}
					queue = append(queue, child)
				}
			}
			if stop || readErr == io.EOF {
				break
			}
			if readErr != nil {
				out.Complete = false
				out.Nodes[len(out.Nodes)-1].Error = readErr.Error()
				break
			}
			if err := ctx.Err(); err != nil {
				dir.Close()
				return nil, err
			}
		}
		dir.Close()
		if stop {
			break
		}
	}
	sort.Slice(out.Nodes, func(i, j int) bool { return out.Nodes[i].Path < out.Nodes[j].Path })
	// Display names are excluded from revision checks and cached across the tree.
	names := map[string]string{}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for i := range out.Nodes {
		if _, parseErr := strconv.ParseUint(out.Nodes[i].Group, 10, 32); parseErr == nil {
			gid := out.Nodes[i].Group
			display, ok := names[gid]
			if !ok {
				display, err = lookupHostGroupName(lookupCtx, gid)
				if err != nil {
					display = gid
				}
				names[gid] = display
			}
			out.Nodes[i].Group = display
		}
		for j := range out.Nodes[i].Entries {
			e := &out.Nodes[i].Entries[j]
			if e.Kind != "group" || e.Qualifier == "" {
				continue
			}
			name, ok := names[e.Qualifier]
			if !ok {
				name, err = lookupHostGroupName(lookupCtx, e.Qualifier)
				if err != nil {
					name = e.Qualifier
				}
				names[e.Qualifier] = name
			}
			e.Identity = name
		}
	}
	revisions := []string{name, rel, strconv.FormatBool(out.Complete)}
	for _, n := range out.Nodes {
		revisions = append(revisions, n.Path, n.Identity, n.Mode, n.Access, n.Default, n.Error)
	}
	out.Revision = shareMapDigest(revisions)
	return out, nil
}
func (s *ShareService) PermissionMap(ctx context.Context, name, rel string) (*SharePermissionSnapshot, error) {
	if _, err := shareRelativePath(rel); err != nil {
		return nil, err
	}
	if s.helpers != nil {
		var out SharePermissionSnapshot
		err := s.hostCall(ctx, "shares.permission-map", HostOperation{Name: name, Path: rel}, &out)
		return &out, err
	}
	scoped, _, err := s.scopedACL(ctx, name, rel)
	if err != nil {
		return nil, err
	}
	defer scoped.root.Close()
	return scoped.capturePermissionMap(ctx, name, rel)
}

func shareMapContains(parent, child string) bool {
	return parent == "." || parent == child || strings.HasPrefix(child, parent+"/")
}
func shareACLBits(perms string) int {
	v := 0
	for i, c := range "rwx" {
		if strings.ContainsRune(perms, c) {
			v |= 4 >> i
		}
	}
	return v
}
func shareACLPerms(bits int) string {
	out := []byte("---")
	for i, c := range []byte("rwx") {
		if bits&(4>>i) != 0 {
			out[i] = c
		}
	}
	return string(out)
}

// Normalise effective rights before widening a mask: unrelated masked entries
// retain their effective permissions, rather than regaining hidden rights.
func overlayShareACL(text string, rules []SharePermissionRule, defaultACL bool, base string) (string, error) {
	entries := map[string]int{}
	mask := 7
	source := text
	if source == "" {
		if len(rules) == 0 {
			return "", nil
		}
		onlyRemove := true
		for _, r := range rules {
			if r.Permissions != "remove" {
				onlyRemove = false
			}
		}
		if onlyRemove {
			return "", nil
		}
		for _, e := range parseACLEntries(base, "") {
			if e.Qualifier == "" && (e.Kind == "user" || e.Kind == "group" || e.Kind == "other") {
				entries[e.Kind+":"] = shareACLBits(e.Perms)
			}
		}
		// The owning group's effective ACL is constrained by the access mask.
		for _, e := range parseACLEntries(base, "") {
			if e.Kind == "mask" {
				entries["group:"] &= shareACLBits(e.Perms)
			}
		}
	} else {
		for _, e := range parseACLEntries(strings.ReplaceAll(source, "default:", ""), "") {
			entries[e.Kind+":"+e.Qualifier] = shareACLBits(e.Perms)
			if e.Kind == "mask" {
				mask = shareACLBits(e.Perms)
			}
		}
	}
	for key, value := range entries {
		if strings.HasPrefix(key, "group:") || strings.HasPrefix(key, "user:") && key != "user:" {
			entries[key] = value & mask
		}
	}
	for _, r := range rules {
		if r.Permissions == "remove" {
			delete(entries, "group:"+r.GID)
		} else {
			entries["group:"+r.GID] = shareACLBits(r.Permissions)
		}
	}
	union := 0
	named := false
	for key, value := range entries {
		if strings.HasPrefix(key, "group:") || strings.HasPrefix(key, "user:") && key != "user:" {
			union |= value
		}
		if strings.HasPrefix(key, "group:") && key != "group:" || strings.HasPrefix(key, "user:") && key != "user:" {
			named = true
		}
	}
	if _, ok := entries["mask:"]; ok || named {
		entries["mask:"] = union
	}
	lines := []string{}
	prefix := ""
	if defaultACL {
		prefix = "default:"
	}
	for key, value := range entries {
		lines = append(lines, prefix+key+":"+shareACLPerms(value))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}
func planSharePermissionMap(snapshot *SharePermissionSnapshot, in SharePermissionMapRequest) (*SharePermissionPlan, error) {
	if !snapshot.Complete {
		return nil, fmt.Errorf("нельзя применять шаблоны по неполной карте")
	}
	if in.SnapshotRevision == "" || in.SnapshotRevision != snapshot.Revision {
		return nil, ErrShareMapConflict
	}
	if len(in.Overlays) == 0 || len(in.Overlays) > 64 {
		return nil, fmt.Errorf("выберите от 1 до 64 наложений шаблонов")
	}
	known := map[string]bool{}
	for _, n := range snapshot.Nodes {
		known[n.Path] = true
	}
	for _, overlay := range in.Overlays {
		if !known[overlay.Path] || !shareMapContains(snapshot.Root, overlay.Path) {
			return nil, fmt.Errorf("папка шаблона отсутствует на карте")
		}
		if strings.TrimSpace(overlay.Template.Name) == "" || len(overlay.Template.Name) > 120 || len(overlay.Template.Rules) == 0 || len(overlay.Template.Rules) > 32 {
			return nil, fmt.Errorf("шаблон должен содержать название и 1–32 группы")
		}
		seen := map[string]bool{}
		for _, rule := range overlay.Template.Rules {
			if _, err := strconv.ParseUint(rule.GID, 10, 32); err != nil {
				return nil, fmt.Errorf("неверный GID шаблона")
			}
			if seen[rule.GID] {
				return nil, fmt.Errorf("группа повторяется в шаблоне")
			}
			seen[rule.GID] = true
			if rule.Permissions != "r-x" && rule.Permissions != "rwx" && rule.Permissions != "remove" {
				return nil, fmt.Errorf("неподдерживаемые права шаблона")
			}
		}
	}
	plan := &SharePermissionPlan{Groups: map[string]string{}, SnapshotRevision: snapshot.Revision, Directories: len(snapshot.Nodes), Changes: []SharePermissionChange{}}
	for _, overlay := range in.Overlays {
		for _, rule := range overlay.Template.Rules {
			plan.Groups[rule.GID] = rule.Group
		}
	}
	for _, node := range snapshot.Nodes {
		access, defaults := node.Access, node.Default
		templates := []string{}
		for _, overlay := range in.Overlays {
			if overlay.Path != node.Path && (!overlay.Recursive || !shareMapContains(overlay.Path, node.Path)) {
				continue
			}
			templates = append(templates, overlay.Template.Name)
			var err error
			access, err = overlayShareACL(access, overlay.Template.Rules, false, node.Access)
			if err != nil {
				return nil, err
			}
			if overlay.Template.Inherit {
				defaults, err = overlayShareACL(defaults, overlay.Template.Rules, true, access)
				if err != nil {
					return nil, err
				}
			}
		}
		if access != node.Access || defaults != node.Default {
			plan.Changes = append(plan.Changes, SharePermissionChange{Path: node.Path, Before: node, Access: access, Default: defaults, Templates: templates})
		}
	}
	revisions := []string{snapshot.Revision, shareMapDigest(in.Overlays)}
	for _, change := range plan.Changes {
		revisions = append(revisions, change.Path, change.Before.Revision, change.Access, change.Default)
	}
	plan.Revision = shareMapDigest(revisions)
	return plan, nil
}
func (s *ShareService) PlanPermissionMap(ctx context.Context, name string, in SharePermissionMapRequest) (*SharePermissionPlan, error) {
	if s.helpers != nil {
		var out SharePermissionPlan
		err := s.hostCall(ctx, "shares.permission-map.plan", HostOperation{Name: name, Input: hostInput(in)}, &out)
		return &out, err
	}
	scoped, _, err := s.scopedACL(ctx, name, in.Root)
	if err != nil {
		return nil, err
	}
	defer scoped.root.Close()
	snapshot, err := scoped.capturePermissionMap(ctx, name, in.Root)
	if err != nil {
		return nil, err
	}
	return planSharePermissionMap(snapshot, in)
}
