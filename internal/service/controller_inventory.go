package service

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// ControllerInventory contains observations made locally by the selected helper.
// Commands and service names are fixed; callers cannot supply executable arguments.
type ControllerInventory struct {
	Controller string            `json:"controller"`
	Observed   time.Time         `json:"observed"`
	Checks     []DiagnosticCheck `json:"checks"`
}

func localControllerInventory(ctx context.Context, node string) *ControllerInventory {
	out := &ControllerInventory{Controller: node, Observed: time.Now().UTC(), Checks: []DiagnosticCheck{}}
	for _, p := range []struct {
		id, command string
		args        []string
	}{
		{"samba_version", "samba", []string{"--version"}},
		{"samba_service", "systemctl", []string{"is-active", "samba.service"}},
		{"samba_ad_dc_service", "systemctl", []string{"is-active", "samba-ad-dc.service"}},
		{"smb_service", "systemctl", []string{"is-active", "smb.service"}},
	} {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		b, err := exec.CommandContext(probe, p.command, p.args...).Output()
		cancel()
		detail := strings.TrimSpace(string(b))
		status := "ok"
		if err != nil {
			status = "unknown"
			if detail == "" {
				detail = "Unavailable: command missing, failed or timed out"
			}
		}
		if len(detail) > 1024 {
			detail = detail[:1024]
		}
		out.Checks = append(out.Checks, DiagnosticCheck{ID: p.id, Status: status, Detail: detail})
	}
	return out
}

func (s *RODCService) Inventory(ctx context.Context, name string) (*ControllerInventory, error) {
	dc, err := (&SiteService{ldap: s.ldap}).controller(ctx, name)
	if err != nil {
		return nil, err
	}
	if s.helpers == nil {
		return nil, topologyBad("helper is not configured")
	}
	var out ControllerInventory
	err = s.helpers.Call(ctx, dc.DNS, "host.inventory", HostOperation{}, &out)
	return &out, err
}
