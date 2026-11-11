package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shirou/gopsutil/v4/cpu"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"sambaadm/internal/adremote"
	"sambaadm/internal/agent"
	"sambaadm/internal/config"
	"sambaadm/internal/policy"
)

type HostOperation struct {
	Name      string          `json:"name,omitempty"`
	Path      string          `json:"path,omitempty"`
	Key       string          `json:"key,omitempty"`
	Value     string          `json:"value,omitempty"`
	Revision  string          `json:"revision,omitempty"`
	Actor     string          `json:"actor,omitempty"`
	IP        string          `json:"ip,omitempty"`
	RemoveDir bool            `json:"removeDir,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
}
type helperADMXCatalog struct {
	Definitions  []policy.Definition
	Source       string
	Encoded      []byte `json:",omitempty"`
	AllTemplates bool   `json:",omitempty"`
}

func hostInput(in any) json.RawMessage { b, _ := json.Marshal(in); return b }
func decodeHost(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return fmt.Errorf("invalid helper operation parameters")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("trailing helper operation parameters")
	}
	return nil
}

// HelperDispatch is the closed host-operation allowlist. There is no shell,
// arbitrary executable, credential export, or general filesystem endpoint.
func (s *Services) HelperDispatch(ctx context.Context, cfg *config.Config, method string, raw json.RawMessage) (result any, err error) {
	unlock, e := lockHelper(ctx, cfg.Helper.StateDir)
	if e != nil {
		return nil, e
	}
	defer unlock()
	defer func() {
		actor := "sambaadm-key"
		if credentials, present, e := agent.OperationCredentials(ctx); present && e == nil {
			actor = credentials.Username
			err = agent.RedactCredentialError(err, credentials)
		}
		if err != nil {
			s.Audit.Failure(actor, method, cfg.Helper.Node, "", err)
		} else {
			s.Audit.Success(actor, method, cfg.Helper.Node, "")
		}
	}()
	if strings.HasPrefix(method, "sysvol.") {
		return s.helperSYSVOL(ctx, cfg, strings.TrimPrefix(method, "sysvol."), raw)
	}
	if method == "health" {
		return map[string]any{"protocol": agent.Version, "credential_protocol": agent.CredentialVersion, "node": cfg.Helper.Node}, nil
	}
	if method == "rodc.preload" {
		return runLocalRODCPreload(ctx, cfg.Helper.Node, raw)
	}
	if method == "rodc.auth" {
		var in struct {
			After   string
			Account string
		}
		if e := decodeHost(raw, &in); e != nil {
			return nil, e
		}
		return readLocalRODCAuth(ctx, cfg.Helper.Node, cfg.Helper.AuthLog, in.After, in.Account)
	}
	var in HostOperation
	if e := decodeHost(raw, &in); e != nil {
		return nil, e
	}
	switch method {
	case "shares.list":
		return s.Shares.List(ctx)
	case "shares.show":
		return s.Shares.Show(ctx, in.Name)
	case "shares.create":
		var data CreateShareInput
		if e := decodeHost(in.Input, &data); e != nil {
			return nil, e
		}
		return s.Shares.Create(ctx, data, in.Actor, in.IP)
	case "shares.delete":
		return nil, s.Shares.Delete(ctx, in.Name, in.RemoveDir, in.Actor, in.IP)
	case "shares.access":
		var data UpdateShareAccessInput
		if e := decodeHost(in.Input, &data); e != nil {
			return nil, e
		}
		return s.Shares.UpdateAccess(ctx, in.Name, data, in.Actor, in.IP)
	case "shares.param":
		return nil, s.Shares.SetParam(ctx, in.Name, in.Key, in.Value, in.Actor, in.IP)
	case "shares.reload":
		return nil, s.Shares.Reload(ctx)
	case "shares.validate-path":
		return nil, s.Shares.validatePath(in.Path)
	case "shares.config":
		return map[string]string{"config": s.Shares.ConfigPath(), "root": s.Shares.SharesRoot()}, nil
	case "nss.group":
		return lookupHostGroup(ctx, in.Name)
	case "printers.list":
		return s.Printers.List(ctx)
	case "printers.create":
		var data CreatePrinterInput
		if e := decodeHost(in.Input, &data); e != nil {
			return nil, e
		}
		return s.Printers.Create(ctx, data, in.Actor, in.IP)
	case "printers.delete":
		return nil, s.Printers.Delete(ctx, in.Name, in.Actor, in.IP)
	case "acl.get":
		return s.FSACL.Get(ctx, in.Path)
	case "acl.set":
		var data SetACLInput
		if e := decodeHost(in.Input, &data); e != nil {
			return nil, e
		}
		return s.FSACL.Set(ctx, data, in.Actor, in.IP)
	case "samba.profile.plan":
		return s.Shares.PlanProfile(ctx, in.Name)
	case "samba.profile.apply":
		return s.Shares.ApplyProfile(ctx, in.Name, in.Revision, in.Actor, in.IP)
	case "host.inventory":
		return localControllerInventory(ctx, cfg.Helper.Node), nil
	case "host.metrics":
		var m HostMonitor
		metrics := m.Snapshot(ctx)
		if values, e := cpu.PercentWithContext(ctx, 100*time.Millisecond, false); e == nil && len(values) > 0 && len(metrics.Samples) > 0 {
			metrics.Samples[0].CPU = &values[0]
		}
		return metrics, nil
	case "host.diagnostics":
		hostCfg := *cfg
		hostCfg.LDAP = config.LDAPConfig{}
		return NewDiagnosticService(&hostCfg).RunFor(ctx, "")
	case "admx.catalog":
		requested := in.Path
		if requested == "" {
			requested = cfg.GPO.ADMXPath
		}
		if requested == "" {
			return nil, fmt.Errorf("local ADMX catalog is not configured on helper")
		}
		if cfg.Helper.ADMXRoot != "" {
			base, e := filepath.EvalSymlinks(cfg.Helper.ADMXRoot)
			if e != nil {
				return nil, e
			}
			actual, e := filepath.EvalSymlinks(requested)
			if e != nil {
				return nil, e
			}
			rel, e := filepath.Rel(base, actual)
			if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("ADMX path outside helper.admx_root")
			}
			requested = actual
		} else if filepath.Clean(requested) != filepath.Clean(cfg.GPO.ADMXPath) {
			return nil, fmt.Errorf("ADMX path is not configured on helper")
		}
		local := GPOService{gpoCfg: cfg.GPO}
		local.gpoCfg.ADMXPath = requested
		var issues []TemplateImportIssue
		defs, source, e := local.loadEditorDefinitionsReport(nil, "", &issues)
		if e != nil {
			return nil, e
		}
		response, e := catalogResponse(defs, source, issues...)
		if in.Name == "binary" {
			response.Definitions = nil
		}
		return response, e
	case "topology.cleanup.reserve", "topology.cleanup.event":
		return helperCleanupApply(ctx, cfg, method, in)
	case "domain.backup.start", "domain.backup.status":
		return helperDomainBackup(ctx, cfg, method, in)
	case "topology.snapshot.store", "topology.snapshot.load":
		return helperTopologySnapshot(cfg, method, in)
	case "backup.store", "backup.load":
		return helperBackup(cfg, method, in)
	default:
		return nil, fmt.Errorf("unsupported helper method")
	}
}

func helperSYSVOLPath(prefix, value string) (string, error) {
	value = strings.ReplaceAll(value, `\`, "/")
	prefix = strings.Trim(strings.ReplaceAll(prefix, `\`, "/"), "/")
	if prefix == "" || strings.HasPrefix(value, "/") || strings.Contains(value, ":") {
		return "", fmt.Errorf("invalid helper SYSVOL path")
	}
	value = strings.TrimSuffix(value, "/")
	if path.Clean(value) != value {
		return "", fmt.Errorf("invalid helper SYSVOL path")
	}
	if !strings.EqualFold(value, prefix) && !strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)+"/") {
		return "", fmt.Errorf("path outside configured helper SYSVOL prefix")
	}
	for _, p := range strings.Split(value, "/") {
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("invalid helper SYSVOL component")
		}
	}
	return strings.ReplaceAll(value, "/", `\`), nil
}
func (s *Services) helperSYSVOL(ctx context.Context, cfg *config.Config, method string, raw json.RawMessage) (out any, err error) {
	if method == "install-policy" {
		return nil, runLocalPolicyInstall(ctx, cfg, s.Shares.ConfigPath(), raw)
	}
	var in helperFSRequest
	if e := decodeHost(raw, &in); e != nil {
		return nil, e
	}
	p, e := helperSYSVOLPath(cfg.Helper.SYSVOLPrefix, in.Path)
	if e != nil {
		return nil, e
	}
	if in.Size < 0 || in.Size > consistencyBytes || in.Offset < 0 || in.Offset > consistencyBytes || len(in.Data) > consistencyBytes || in.Offset+int64(len(in.Data)) > consistencyBytes {
		return nil, fmt.Errorf("helper SYSVOL file limit exceeded")
	}
	remote := *s.GPO.remote
	remote.Host = "127.0.0.1"
	if credentials, present, e := agent.OperationCredentials(ctx); e != nil {
		return nil, e
	} else if present {
		remote.User = credentials.Username
		remote.Password = func() string { return credentials.Password }
	}
	err = remote.SYSVOL(ctx, cfg.GPO.SMBPort, func(sh *smb2.Share) error {
		// Existing path checking rejects symlinked ancestors, including the root.
		root := &smbPolicyStore{share: &sysvolShare{local: sh, ctx: ctx}, base: strings.ReplaceAll(p, `\`, "/")}
		missing := method == "mkdir" || method == "mkdir-all" || method == "open" || method == "write-file"
		if method != "mkdir-all" {
			if _, e := root.checked(".", missing); e != nil {
				if method == "remove-tree" && os.IsNotExist(e) {
					return nil
				}
				return e
			}
		}
		switch method {
		case "admx-catalog":
			parts := strings.Split(strings.ReplaceAll(p, `\`, "/"), "/")
			if len(parts) != 3 || !strings.EqualFold(parts[1], "Policies") || !strings.EqualFold(parts[2], "PolicyDefinitions") {
				return fmt.Errorf("invalid SYSVOL template catalog path")
			}
			local := GPOService{}
			var issues []TemplateImportIssue
			defs, source, e := local.loadEditorDefinitionsReport(&sysvolShare{local: sh, ctx: ctx}, parts[0], &issues)
			if e != nil {
				return e
			}
			response, e := catalogResponse(defs, source, issues...)
			response.Definitions = nil // Binary catalogue retains all registry encodings without duplicating the public JSON.
			out = response
			return e
		case "stat":
			f, e := sh.Lstat(p)
			if e == nil {
				out = helperInfo(f)
			}
			return e
		case "list":
			items, e := sh.ReadDir(p)
			if e != nil {
				return e
			}
			if len(items) > 10000 {
				return fmt.Errorf("SYSVOL directory entry limit exceeded")
			}
			list := []helperFileInfo{}
			for _, f := range items {
				list = append(list, helperInfo(f))
			}
			out = list
			return nil
		case "read":
			f, e := sh.OpenFile(p, os.O_RDONLY, 0)
			if e != nil {
				return e
			}
			info, e := f.Stat()
			if e != nil {
				_ = f.Close()
				return e
			}
			if !info.Mode().IsRegular() {
				_ = f.Close()
				return fmt.Errorf("SYSVOL path is not a regular file")
			}
			limit := int64(consistencyBytes)
			if in.Size > 0 {
				limit = in.Size
			}
			if info.Size() > limit {
				_ = f.Close()
				return fmt.Errorf("SYSVOL file too large")
			}
			b, e := io.ReadAll(io.LimitReader(f, limit+1))
			e = errors.Join(e, f.Close())
			if int64(len(b)) > limit {
				return fmt.Errorf("SYSVOL file too large")
			}
			out = b
			return e
		case "read-at":
			f, e := sh.OpenFile(p, os.O_RDONLY, 0)
			if e != nil {
				return e
			}
			b := make([]byte, in.Size)
			n, e := f.ReadAt(b, in.Offset)
			if e == io.EOF {
				e = nil
			}
			out = b[:n]
			return errors.Join(e, f.Close())
		case "open":
			flags, e := helperNativeOpenFlags(in.Flags)
			if e != nil {
				return e
			}
			f, e := sh.OpenFile(p, flags, in.Mode.Perm())
			if e != nil {
				return e
			}
			return f.Close()
		case "write-file":
			return sh.WriteFile(p, in.Data, in.Mode.Perm())
		case "write-at":
			f, e := sh.OpenFile(p, os.O_WRONLY, 0)
			if e != nil {
				return e
			}
			n, e := f.WriteAt(in.Data, in.Offset)
			out = n
			return errors.Join(e, f.Close())
		case "truncate":
			f, e := sh.OpenFile(p, os.O_WRONLY, 0)
			if e != nil {
				return e
			}
			return errors.Join(f.Truncate(in.Size), f.Close())
		case "sync":
			f, e := sh.OpenFile(p, os.O_WRONLY, 0)
			if e != nil {
				return e
			}
			return errors.Join(f.Sync(), f.Close())
		case "mkdir":
			return sh.Mkdir(p, in.Mode.Perm())
		case "mkdir-all":
			// Walk components and reject links before allowing MkdirAll.
			parts := strings.Split(p, `\`)
			for i := range parts {
				part := strings.Join(parts[:i+1], `\`)
				st, e := sh.Lstat(part)
				if os.IsNotExist(e) {
					if e = sh.Mkdir(part, in.Mode.Perm()); e != nil {
						return e
					}
				} else if e != nil {
					return e
				} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("invalid SYSVOL ancestor")
				}
			}
			return nil
		case "remove":
			if strings.EqualFold(strings.ReplaceAll(p, `\`, "/"), strings.ReplaceAll(cfg.Helper.SYSVOLPrefix, `\`, "/")) {
				return fmt.Errorf("cannot remove SYSVOL prefix")
			}
			return sh.Remove(p)
		case "remove-tree":
			if strings.EqualFold(strings.ReplaceAll(p, `\`, "/"), strings.ReplaceAll(cfg.Helper.SYSVOLPrefix, `\`, "/")) {
				return fmt.Errorf("cannot remove SYSVOL prefix")
			}
			return removeHelperTree(ctx, sh, p, 0)
		case "rename":
			to, e := helperSYSVOLPath(cfg.Helper.SYSVOLPrefix, in.To)
			if e != nil {
				return e
			}
			prefix, _ := helperSYSVOLPath(cfg.Helper.SYSVOLPrefix, cfg.Helper.SYSVOLPrefix)
			if strings.EqualFold(p, prefix) || strings.EqualFold(to, prefix) {
				return fmt.Errorf("cannot rename SYSVOL prefix")
			}
			target := &smbPolicyStore{share: &sysvolShare{local: sh, ctx: ctx}, base: strings.ReplaceAll(to, `\`, "/")}
			if _, e = target.checked(".", true); e != nil {
				return e
			}
			return sh.Rename(p, to)
		case "get-acl":
			if in.Security & ^uint32(7) != 0 {
				return fmt.Errorf("unsupported security information")
			}
			out, e = sh.SecurityInfoRaw(p, smb2.SecurityInformationRequestFlags(in.Security))
			return e
		case "set-acl":
			const permitted = uint32(0xA0000007)
			if in.Security & ^permitted != 0 {
				return fmt.Errorf("unsupported security information")
			}
			return sh.SetSecurityInfoRaw(p, smb2.SecurityInformationRequestFlags(in.Security), adremote.SecurityBytes(in.Data))
		default:
			return fmt.Errorf("unsupported SYSVOL helper method")
		}
	})
	return out, err
}
func removeHelperTree(ctx context.Context, sh *smb2.Share, p string, depth int) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if depth > 64 {
		return fmt.Errorf("SYSVOL nesting limit")
	}
	st, e := sh.Lstat(p)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SYSVOL symlinks cannot be removed recursively")
	}
	if st.IsDir() {
		items, e := sh.ReadDir(p)
		if e != nil {
			return e
		}
		if len(items) > 10000 {
			return fmt.Errorf("SYSVOL object limit")
		}
		for _, f := range items {
			if strings.ContainsAny(f.Name(), `/\:`) || f.Name() == "." || f.Name() == ".." {
				return fmt.Errorf("invalid SYSVOL entry")
			}
			if e = removeHelperTree(ctx, sh, p+`\`+f.Name(), depth+1); e != nil {
				return e
			}
		}
	}
	return sh.Remove(p)
}
