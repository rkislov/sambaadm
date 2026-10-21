package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type SambaProfilePlan struct {
	Profile    string            `json:"profile"`
	Revision   string            `json:"revision"`
	Path       string            `json:"path"`
	Parameters map[string]string `json:"parameters"`
	Changes    string            `json:"changes"`
	Ready      bool              `json:"ready"`
	Warning    string            `json:"warning"`
}

func configRevision(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func profileParameters(profile string) (map[string]string, error) {
	p := map[string]string{"server min protocol": "SMB2_02", "server signing": "mandatory", "max log size": "10240"}
	switch profile {
	case "compatible":
	case "secure":
		p["server min protocol"] = "SMB3_11"
		p["server smb encrypt"] = "required"
	default:
		return nil, topologyBad("unknown Samba profile")
	}
	return p, nil
}

// Preserve unrelated lines, comments, domain membership and per-share settings.
func patchGlobal(raw []byte, params map[string]string) ([]byte, error) {
	lines := strings.Split(string(raw), "\n")
	start, end := -1, len(lines)
	section := ""
	for i, line := range lines {
		v := strings.TrimSpace(line)
		if strings.HasPrefix(v, "#") || strings.HasPrefix(v, ";") || v == "" {
			continue
		}
		if strings.HasSuffix(v, "\\") {
			return nil, topologyBad("multiline configuration requires manual editing")
		}
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			name := strings.TrimSpace(v[1 : len(v)-1])
			if strings.EqualFold(name, "global") {
				if start >= 0 {
					return nil, topologyBad("multiple global sections require manual editing")
				}
				start = i
			} else if section == "global" {
				end = i
			}
			section = strings.ToLower(name)
			continue
		}
		key, _, ok := strings.Cut(v, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok {
			return nil, topologyBad("unrecognized configuration line")
		}
		if key == "include" || key == "config backend" || key == "registry shares" {
			return nil, topologyBad("included or registry configuration requires manual editing")
		}
	}
	if start < 0 {
		return nil, topologyBad("global section required")
	}
	out := append([]string(nil), lines[:start+1]...)
	for _, line := range lines[start+1 : end] {
		v := strings.TrimSpace(line)
		key, _, ok := strings.Cut(v, "=")
		if ok && !strings.HasPrefix(v, "#") && !strings.HasPrefix(v, ";") {
			if _, exists := params[strings.ToLower(strings.TrimSpace(key))]; exists {
				continue
			}
		}
		out = append(out, line)
	}
	keys := []string{}
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, "    "+k+" = "+params[k])
	}
	out = append(out, lines[end:]...)
	return []byte(strings.Join(out, "\n")), nil
}
func (s *ShareService) PlanProfile(ctx context.Context, profile string) (*SambaProfilePlan, error) {
	raw, e := os.ReadFile(s.cfg.SMBConf)
	if e != nil {
		return nil, e
	}
	params, e := profileParameters(profile)
	if e != nil {
		return nil, e
	}
	plan := &SambaProfilePlan{Profile: profile, Revision: configRevision(raw), Path: s.cfg.SMBConf, Parameters: params, Ready: true}
	if _, e := patchGlobal(raw, params); e != nil {
		plan.Ready = false
		plan.Warning = e.Error()
	}
	if _, e := exec.LookPath("testparm"); e != nil {
		plan.Ready = false
		plan.Warning = "testparm is not installed on the sambaadm host"
	}
	keys := []string{}
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("[global]\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "    %s = %s\n", k, params[k])
	}
	plan.Changes = b.String()
	return plan, nil
}
func (s *ShareService) ApplyProfile(ctx context.Context, profile, revision, actor, ip string) (backup string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "samba.profile", profile, ip, err)
		} else {
			s.audit.Success(actor, "samba.profile", profile, ip)
		}
	}()
	plan, e := s.PlanProfile(ctx, profile)
	if e != nil {
		return "", e
	}
	if !plan.Ready {
		return "", topologyBad(plan.Warning)
	}
	if revision == "" || revision != plan.Revision {
		return "", ErrTopologyConflict
	}
	info, e := os.Lstat(s.cfg.SMBConf)
	if e != nil {
		return "", e
	}
	if !info.Mode().IsRegular() {
		return "", topologyBad("configuration must be a regular file")
	}
	raw, e := os.ReadFile(s.cfg.SMBConf)
	if e != nil {
		return "", e
	}
	if configRevision(raw) != revision {
		return "", ErrTopologyConflict
	}
	updated, e := patchGlobal(raw, plan.Parameters)
	if e != nil {
		return "", e
	}
	tmp, e := os.CreateTemp(filepath.Dir(s.cfg.SMBConf), ".sambaadm-profile-*")
	if e != nil {
		return "", e
	}
	name := tmp.Name()
	defer os.Remove(name)
	defer tmp.Close()
	if _, e = tmp.Write(updated); e != nil {
		return "", e
	}
	if e = tmp.Chmod(info.Mode().Perm()); e != nil {
		return "", e
	}
	if e = preserveConfigOwner(tmp, info); e != nil {
		return "", e
	}
	if e = tmp.Sync(); e != nil {
		return "", e
	}
	if e = tmp.Close(); e != nil {
		return "", e
	}
	check, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	validation, validationErr := exec.CommandContext(check, "testparm", "-s", name).CombinedOutput()
	if validationErr != nil || bytes.Contains(bytes.ToLower(validation), []byte("unknown parameter")) {
		return "", fmt.Errorf("testparm rejected the profile; configuration unchanged")
	}
	current, e := os.ReadFile(s.cfg.SMBConf)
	if e != nil {
		return "", e
	}
	if !bytes.Equal(current, raw) {
		return "", ErrTopologyConflict
	}
	backup = s.cfg.SMBConf + ".sambaadm-" + time.Now().UTC().Format("20060102T150405.000000000") + ".bak"
	f, e := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", e
	}
	_, e = f.Write(raw)
	closeErr := f.Close()
	if e != nil {
		return "", e
	}
	if closeErr != nil {
		return "", closeErr
	}
	if e = os.Rename(name, s.cfg.SMBConf); e != nil {
		return backup, e
	}
	return backup, nil
}
