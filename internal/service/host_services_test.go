package service

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestServiceUnitsUseLoadStateAndAliases(t *testing.T) {
	units := parseSystemdUnits(`Id=samba.service
Names=samba.service samba-ad-dc.service
ActiveState=active
LoadState=loaded
SubState=running
UnitFileState=enabled

Id=smb.service
Names=smb.service
ActiveState=inactive
LoadState=loaded
SubState=dead
UnitFileState=disabled

Id=smbd.service
Names=smbd.service
ActiveState=inactive
LoadState=not-found
UnitFileState=

Id=kea-dhcp4.service
Names=kea-dhcp4.service
ActiveState=failed
LoadState=loaded
SubState=failed
UnitFileState=enabled

Id=kea-dhcp6.service
Names=kea-dhcp6.service
ActiveState=inactive
LoadState=not-found
UnitFileState=`)
	for i, want := range []string{"active", "inactive", "failed", "absent", "unknown"} {
		if got := selectServiceUnit(monitoredServices[i], units); got.State != want {
			t.Errorf("%s: %#v, want %s", got.ID, got, want)
		}
	}
	if samba := selectServiceUnit(monitoredServices[0], units); samba.Unit != "samba.service" || !samba.Enabled {
		t.Fatalf("missing canonical unit or enabled state: %#v", samba)
	}
}

func TestKeaDHCPHealthProjectsRuntimeAndDoesNotExposeConfig(t *testing.T) {
	h, commands := testKeaControl(t, "4", func(cmd keaTestCommand) any {
		return map[string]any{"result": 0, "arguments": json.RawMessage(`{
			"uptime": 5, "sockets": {"status": "ready"},
			"high-availability": [{"ha-mode": "hot-standby", "ha-servers": {
				"local": {"role": "standby", "state": "partner-down", "server-name": "secondary", "scopes": ["primary", "secondary"]},
				"remote": {"last-state": "hot-standby", "age": 4, "communication-interrupted": true, "in-touch": true}
			}}], "not-status": "secret"
		}`)}
	})
	raw, _, err := h.read()
	if err != nil {
		t.Fatal(err)
	}
	doc, root, err := keaRoot(raw, "4")
	if err != nil {
		t.Fatal(err)
	}
	root["hooks-libraries"] = json.RawMessage(`[{"library":"libdhcp_ha.so","parameters":{"high-availability":[{
		"this-server-name":"secondary","mode":"hot-standby",
		"peers":[{"name":"primary","role":"primary","url":"http://example.test/private"},{"name":"secondary","role":"standby"}]
	}]}}]`)
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(h.path, raw, 0640); err != nil {
		t.Fatal(err)
	}
	configured := h.dhcpHealth(context.Background(), false)
	if configured.Source != "config" || configured.Standalone || len(configured.Relationships) != 1 ||
		configured.Relationships[0].Peer != "primary" || configured.Relationships[0].State != "" {
		t.Fatalf("misrepresented configuration: %+v", configured)
	}
	health := h.dhcpHealth(context.Background(), true)
	if health.Source != "runtime" || len(health.Relationships) != 1 || health.Standalone || health.SocketState != "ready" {
		t.Fatalf("unexpected health: %+v", health)
	}
	ha := health.Relationships[0]
	if ha.Peer != "primary" || ha.Role != "standby" || ha.State != "partner-down" || ha.Serving == nil || !*ha.Serving || ha.Interrupted == nil || !*ha.Interrupted {
		t.Fatalf("missing runtime status: %+v", ha)
	}
	if cmd := <-commands; cmd.Command != "status-get" {
		t.Fatalf("unexpected request: %+v", cmd)
	}
	out, _ := json.Marshal(health)
	if strings.Contains(string(out), "secret") || strings.Contains(string(out), "http://") {
		t.Fatalf("private details leaked: %s", out)
	}
}
