package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestSurveyImportAndReview(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.SurveyDir = filepath.Join(t.TempDir(), "surveys")
	admin, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	reader, _ := s.sessions.Create("reader", "CN=reader", auth.RoleReadonly)
	request := func(method, path, body string, sessionID, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sessionID})
		req.Header.Set(csrfHeader, token)
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		return w
	}
	url := "/api/v1/surveys?format=audit&node=dc1.example"
	logLine := `prefix {"type":"Authentication","timestamp":"2026-11-05T08:30:00Z","Authentication":{"clientAccount":"operator","status":"NT_STATUS_OK","unused":"omitted-secret"}}`
	if got := request("POST", url, logLine, reader.ID, reader.CSRFToken); got.Code != 403 {
		t.Fatal(got.Code)
	}
	if got := request("POST", url, logLine, admin.ID, ""); got.Code != 403 {
		t.Fatal(got.Code)
	}
	got := request("POST", url, logLine, admin.ID, admin.CSRFToken)
	if got.Code != 201 {
		t.Fatal(got.Code, got.Body)
	}
	var imported struct{ ID string }
	if err := json.Unmarshal(got.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if got := request("POST", url, logLine, admin.ID, admin.CSRFToken); got.Code != 200 {
		t.Fatal(got.Code)
	}
	path := "/api/v1/surveys/" + imported.ID
	if got := request("GET", path, "", reader.ID, ""); got.Code != 403 {
		t.Fatal(got.Code)
	}
	got = request("GET", path, "", admin.ID, "")
	if got.Code != 200 || !strings.Contains(got.Body.String(), "operator") || strings.Contains(got.Body.String(), "omitted-secret") {
		t.Fatal(got.Code, got.Body)
	}
	if got := request("GET", "/surveys", "", admin.ID, ""); got.Code != 200 || !strings.Contains(got.Body.String(), "survey-import") {
		t.Fatal(got.Code, got.Body)
	}
	if got := request("POST", url, "{}", admin.ID, admin.CSRFToken); got.Code != 400 {
		t.Fatal(got.Code)
	}
}
