package service

import (
	"context"
	"path/filepath"
	"sambaadm/internal/agent"
	"testing"
)

func TestIntegrationFullBackupPreparation(t *testing.T) {
	services, _ := integrationServices(t, false)
	dcs, err := services.Sites.Controllers(context.Background())
	if err != nil || len(dcs) == 0 {
		t.Fatalf("controllers: %v", err)
	}
	var host string
	for _, dc := range dcs {
		if !dc.RODC {
			host = dc.DNS
			break
		}
	}
	if host == "" {
		t.Fatal("no writable DC")
	}
	services.Sites.helpers = &agent.Client{Config: agent.Config{Nodes: []agent.Node{{Name: host}}}}
	client := &FullBackupService{Sites: services.Sites, Store: &ObjectBackupService{root: filepath.Join(t.TempDir(), "backups")}}
	request, err := client.Prepare(context.Background(), host, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if request.Purpose != "full" || request.Plan != nil || len(request.DomainGUID) != 16 {
		t.Fatalf("invalid prepared full backup: %+v", request)
	}
	services.Sites.ldap = nil // Standalone preparation remains readable while LDAP is unavailable.
	saved, err := client.Load(request.ID)
	if err != nil || saved.PlanRevision != request.PlanRevision {
		t.Fatalf("offline preparation: %+v %v", saved, err)
	}
}
