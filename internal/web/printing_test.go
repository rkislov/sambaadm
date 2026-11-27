package web

import (
	"bytes"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/auth"
	"sambaadm/internal/i18n"
)

func TestPrintingJournalPersistence(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	row := map[string]any{"node": "print.example.test", "id": 1, "created": 100, "state": 9, "title": "test"}
	rows, err := s.savePrintHistory([]map[string]any{row})
	if err != "" || len(rows) != 1 {
		t.Fatalf("save: %v %s", rows, err)
	}
	path := filepath.Join(s.cfg.Server.SettingsDir, "printing-journal.json")
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private journal: %v %v", info, e)
	}
	other := testWorkspaceServer(t)
	other.cfg.Server.SettingsDir = s.cfg.Server.SettingsDir
	rows, err = other.savePrintHistory([]map[string]any{{"node": "print.example.test", "id": 1, "created": 100, "state": 3}})
	if err != "" || len(rows) != 1 || number(rows[0]["state"]) != 9 {
		t.Fatalf("final state regressed: %v %s", rows, err)
	}
	rows, err = other.savePrintHistory(nil)
	if err != "" || len(rows) != 1 {
		t.Fatalf("deleted queue lost journal: %v %s", rows, err)
	}
}
func TestPrintingJournalRetriesWriteAndProtectsCorruptArchive(t *testing.T) {
	s := testWorkspaceServer(t)
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	s.cfg.Server.SettingsDir = dir
	s.savePrintHistory(nil) // No existing archive, then a transient filesystem failure.
	if err := os.WriteFile(dir, []byte("temporarily unavailable"), 0600); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"node": "n", "id": 1, "created": 100, "state": 5}
	if _, err := s.savePrintHistory([]map[string]any{row}); err == "" {
		t.Fatal("expected write error")
	}
	os.Remove(dir)
	if _, err := s.savePrintHistory(nil); err != "" {
		t.Fatal("write was not retried:", err)
	}
	path := filepath.Join(dir, "printing-journal.json")
	raw, e := os.ReadFile(path)
	if e != nil || !bytes.Contains(raw, []byte(`"id":1`)) {
		t.Fatalf("retry did not persist: %s %v", raw, e)
	}
	os.WriteFile(path, []byte("corrupt"), 0600)
	other := testWorkspaceServer(t)
	other.cfg.Server.SettingsDir = dir
	if _, err := other.savePrintHistory([]map[string]any{row}); err == "" {
		t.Fatal("corrupt journal must be visible")
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "corrupt" {
		t.Fatal("overwrote corrupt archive")
	}
}
func TestPrintingPermissionsAndPage(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("tester", "CN=test", role)
		for _, operation := range []string{"service", "queue.apply", "keytab.upload", "windows.register", "install.start"} {
			req := httptest.NewRequest("POST", "/api/v1/printing/"+operation+"?node=n", strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			req.Header.Set("X-CSRF-Token", sess.CSRFToken)
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if role != auth.RoleAdmin && rec.Code != 403 {
				t.Fatalf("role %s operation %s: %d", role, operation, rec.Code)
			}
		}
		req := httptest.NewRequest("GET", "/printers", nil)
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `id="printing-console"`) {
			t.Fatal(rec.Body.String())
		}
		if role != auth.RoleAdmin && strings.Contains(rec.Body.String(), `data-view="security"`) {
			t.Fatal("operator sees keytab upload")
		}
	}
}
func TestPrintingBrowserFixtures(t *testing.T) {
	dir := os.Getenv("SAMBAADM_PRINTING_FIXTURE_DIR")
	if dir == "" {
		t.Skip("browser fixture")
	}
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReadonly} {
		rec := httptest.NewRecorder()
		s.render(rec, "printers/console.html", pageData{Lang: i18n.RU, CSRF: "test-csrf", Role: role, Content: map[string]any{"Nodes": []string{"print.example.test"}}})
		if err := os.WriteFile(filepath.Join(dir, "printing-"+string(role)+".html"), rec.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	s.render(rec, "dashboard.html", pageData{Lang: i18n.RU, CSRF: "test-csrf", Role: auth.RoleAdmin, Content: map[string]any{}})
	if err := os.WriteFile(filepath.Join(dir, "roles.html"), rec.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

}
