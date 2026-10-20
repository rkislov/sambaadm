package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sambaadm/internal/samba"
	"strings"
	"testing"
	"time"
)

func TestIntegrationTwoDCTopology(t *testing.T) {
	oracle := samba.NewRunner("")
	oracle.Username = os.Getenv("SAMBAADM_IT_USER")
	oracle.Password = func() string { return os.Getenv("SAMBAADM_PASSWORD") }
	if os.Getenv("SAMBAADM_IT_SECOND_DC") == "" {
		t.Skip("requires disposable two-DC domain")
	}
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	const actor = "topology-integration"
	const ip = "127.0.0.1"
	const site = "Integration-Branch"
	const link = "Integration-WAN"
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	// A new DC can still be running its startup KCC pass after LDAP becomes
	// healthy. DsExecuteKCC then returns DS_BUSY; retry this idempotent test
	// request with a bound, while preserving persistent KCC failures.
	kcc := func(server string) {
		t.Helper()
		var last error
		for attempt := 0; attempt < 15; attempt++ {
			last = s.Repl.KCC(ctx, server, actor, ip)
			if last == nil {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(time.Second):
			}
		}
		t.Fatal(last)
	}
	controllers, e := s.Sites.Controllers(ctx)
	must(e)
	if len(controllers) != 2 {
		t.Fatalf("want two actual DCs: %+v", controllers)
	}
	dc2, e := s.Sites.controller(ctx, os.Getenv("SAMBAADM_IT_SECOND_DC"))
	must(e)
	original := dc2.Site
	_, e = s.Sites.Create(ctx, site, actor, ip)
	must(e)
	t.Cleanup(func() {
		if e := s.Sites.Delete(context.Background(), site, actor, ip); e != nil {
			t.Errorf("site cleanup: %v", e)
		}
	})
	input := SiteLinkInput{Sites: []string{original, site}, Cost: 125, Interval: 30}
	must(s.Sites.SaveLink(ctx, link, input, actor, ip))
	getLink := func() SiteLink {
		t.Helper()
		rows, e := s.Sites.Links(context.Background())
		must(e)
		for _, r := range rows {
			if r.Name == link {
				return r
			}
		}
		t.Fatal("missing real site link")
		return SiteLink{}
	}
	t.Cleanup(func() {
		r := getLink()
		if e := s.Sites.DeleteLink(context.Background(), link, r.Revision, actor, ip); e != nil {
			t.Errorf("link cleanup: %v", e)
		}
	})
	first := getLink()
	if first.Cost != 125 || first.Interval != 30 || !first.ScheduleSupported {
		t.Fatalf("link readback: %+v", first)
	}
	input.Revision = first.Revision
	input.Cost = 150
	must(s.Sites.SaveLink(ctx, link, input, actor, ip))
	if e = s.Sites.SaveLink(ctx, link, input, actor, ip); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale update accepted: %v", e)
	}
	days := []string{"", "08:15-18:45", "08:15-18:45", "08:15-18:45", "08:15-18:45", "08:15-18:45", ""}
	r := getLink()
	if e = s.Sites.LinkSchedule(ctx, link, r.Revision, days, actor, ip); !errors.Is(e, ErrTopologyInput) {
		t.Fatalf("unsafe Site Link schedule was not blocked: %v", e)
	}
	r = getLink()
	if r.Cost != 150 || r.ScheduleEditable {
		t.Fatalf("link readback: %+v", r)
	}

	// Samba's independent NDR decoder must accept our binary format.
	encoded, e := EncodeSchedule(days)
	must(e)
	file := filepath.Join(t.TempDir(), "schedule.bin")
	must(os.WriteFile(file, encoded, 0600))
	defer os.Remove(file)
	out, err := exec.CommandContext(ctx, "python3", "-c", "from samba.ndr import ndr_unpack; from samba.dcerpc import drsblobs; import sys; s=ndr_unpack(drsblobs.schedule,open(sys.argv[1],'rb').read()); assert s.size==188 and s.numberOfSchedules==1 and s.dataArray[0].slots[32]==14", file).CombinedOutput()
	if err != nil {
		t.Fatalf("Samba NDR schedule oracle: %s: %v", out, err)
	}
	// The integration container owns this path; no host files or production AD are used.
	_, e = oracle.Run(ctx, "drs", "showrepl", "dc1.sambaadm.test", "--json")
	must(e)
	_, e = s.Subnets.Create(ctx, "192.0.2.0/24", original, actor, ip)
	must(e)
	t.Cleanup(func() {
		if e := s.Subnets.Delete(context.Background(), "192.0.2.0/24", actor, ip); e != nil {
			t.Error(e)
		}
	})
	must(s.Subnets.SetSite(ctx, "192.0.2.0/24", site, actor, ip))
	subs, e := s.Subnets.List(ctx)
	must(e)
	if len(subs) != 1 || !strings.Contains(subs[0].Site, site) {
		t.Fatalf("subnet assignment: %+v", subs)
	}
	if e = s.Sites.Delete(ctx, site, actor, ip); !errors.Is(e, ErrTopologyInput) {
		t.Fatalf("referenced site delete: %v", e)
	}
	must(s.Sites.MoveController(ctx, dc2.Name, site, dc2.Revision, actor, ip))
	t.Cleanup(func() {
		dc, e := s.Sites.controller(context.Background(), dc2.Name)
		if e == nil {
			e = s.Sites.MoveController(context.Background(), dc.Name, original, dc.Revision, actor, ip)
		}
		if e != nil {
			t.Errorf("move back: %v", e)
		}
	})
	moved, e := s.Sites.controller(ctx, dc2.Name)
	must(e)
	if moved.Site != site {
		t.Fatalf("DC move not persisted: %+v", moved)
	}
	if e = s.Sites.MoveController(ctx, dc2.Name, original, dc2.Revision, actor, ip); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale DC move: %v", e)
	}
	must(s.Sites.CreateConnection(ctx, "dc1.sambaadm.test", dc2.DNS, actor, ip))
	getConnection := func() Connection {
		t.Helper()
		rows, e := s.Sites.Connections(ctx)
		must(e)
		for _, r := range rows {
			if strings.HasPrefix(r.ID, "manual-") {
				return r
			}
		}
		t.Fatal("manual connection missing")
		return Connection{}
	}
	conn := getConnection()
	if conn.Automatic || !conn.Enabled || conn.Source != "dc1.sambaadm.test" || conn.Destination != dc2.DNS {
		t.Fatalf("connection: %+v", conn)
	}
	enabled := false
	must(s.Sites.UpdateConnection(ctx, conn.ID, conn.Revision, &enabled, nil, false, actor, ip))
	if e = s.Sites.UpdateConnection(ctx, conn.ID, conn.Revision, &enabled, nil, false, actor, ip); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale connection: %v", e)
	}
	conn = getConnection()
	if conn.Enabled {
		t.Fatal("disable not persisted")
	}
	enabled = true
	must(s.Sites.UpdateConnection(ctx, conn.ID, conn.Revision, &enabled, days, false, actor, ip))
	conn = getConnection()
	if !conn.Enabled || conn.Schedule[1] != days[1] {
		t.Fatalf("connection schedule: %+v", conn)
	}
	kcc("dc1.sambaadm.test")
	// Configuration moves must reach DC2 before its own KCC recalculates topology.
	must(s.Repl.Sync(ctx, dc2.DNS, "dc1.sambaadm.test", "CN=Configuration,"+cfg.BaseDN, actor, ip))
	kcc(dc2.DNS)
	conn = getConnection()
	if conn.Schedule[1] != days[1] {
		t.Fatalf("KCC lost user-owned connection schedule: %+v", conn)
	}
	must(s.Sites.UpdateConnection(ctx, conn.ID, conn.Revision, nil, nil, true, actor, ip))

	login := "itreplproof"
	_, e = s.Users.Create(ctx, CreateUserInput{Login: login, Password: "Lab-Replication-Pass1!", Enabled: true}, actor, ip)
	must(e)
	t.Cleanup(func() { s.Users.Delete(context.Background(), login, actor, ip) })
	must(s.Repl.Sync(ctx, dc2.DNS, "dc1.sambaadm.test", cfg.BaseDN, actor, ip))
	res, e := oracle.Run(ctx, "user", "show", login, "--URL=ldap://"+dc2.DNS)
	must(e)
	if !strings.Contains(res.Stdout, login) {
		t.Fatal("object did not replicate to DC2")
	}
	st, e := s.Repl.StatusFor(ctx, dc2.DNS)
	must(e)
	if len(st.Neighbors) == 0 {
		t.Fatalf("real replication has no parsed neighbors: %+v", st)
	}
	t.Logf("two DC replication verified: server=%s neighbors=%d health=%s", st.Server, len(st.Neighbors), st.Health)
}
