package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	"strings"
	"testing"
	"time"
)

func TestHelperInstallCredentialsNotPersistedAndPlanBoundToOwner(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.EnrollmentDir = filepath.Join(t.TempDir(), "enrollment")
	admin, _ := s.sessions.Create("admin", "cn=admin", auth.RoleAdmin)
	other, _ := s.sessions.Create("other", "cn=other", auth.RoleAdmin)
	readonly, _ := s.sessions.Create("reader", "cn=reader", auth.RoleReadonly)
	j := &helperInstallJob{ID: uuid.NewString(), Actor: "admin", Created: time.Now().Add(-16 * time.Minute), Status: "ready", Nodes: []helperInstallNode{{Node: "dc.example.com", Fingerprint: "SHA256:checked", Phase: "ready"}}}
	if e := s.saveInstall(j); e != nil {
		t.Fatal(e)
	}
	request := func(sess *auth.Session, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", sess.CSRFToken)
		r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		return w
	}
	body := `{"action":"start","id":"` + j.ID + `","user":"tester","password":"ssh-secret-value","rootPassword":"root-secret-value","confirm":true}`
	if w := request(admin, "POST", "/api/v1/helper-install", body); w.Code != 409 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request(other, "POST", "/api/v1/helper-install", body); w.Code != 404 {
		t.Fatal(w.Code, w.Body)
	}
	for _, method := range []string{"GET", "POST"} {
		if w := request(readonly, method, "/api/v1/helper-install", body); w.Code != 403 {
			t.Fatal(w.Code, w.Body)
		}
	}
	raw, e := os.ReadFile(filepath.Join(s.cfg.Server.EnrollmentDir, "install-jobs", j.ID+".json"))
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"ssh-secret-value", "root-secret-value", "tester"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("credential persisted")
		}
	}
	if v := redactInstall("password ssh-secret-value and root-secret-value\x1b[31m", "ssh-secret-value", "root-secret-value"); strings.Contains(v, "secret-value") || strings.Contains(v, "\x1b") {
		t.Fatal(v)
	}
}
func TestHelperRegistrationStagedUntilCommit(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.EnrollmentDir = t.TempDir()
	s.cfg.LDAP.BaseDN = "DC=example,DC=com"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}))
	p, e := s.prepareInstallRegistration("dc.example.com", csr)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(s.cfg.Server.EnrollmentDir, "nodes.json")); !os.IsNotExist(e) {
		t.Fatal("binding published before verification", e)
	}
	if _, ok := p.files["tls.key"]; ok {
		t.Fatal("private TLS key left its node")
	}
	var cfg map[string]any
	if e = json.Unmarshal(p.files["config.yaml"], &cfg); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(p.files["config.yaml"]), "password_file") {
		t.Fatal("domain credential storage enabled implicitly")
	}
	if e = s.commitInstallRegistration(p); e != nil {
		t.Fatal(e)
	}
	c, e := config.ManagedHelpers(s.cfg.Server.EnrollmentDir)
	if e != nil || len(c.Nodes) != 1 || c.Nodes[0].Name != "dc.example.com" {
		t.Fatal(c, e)
	}
}

func TestInstallArchitectureIgnoresShellNotices(t *testing.T) {
	for _, output := range []string{"SAMBAADM_ARCH=x86_64\n", "shell: locale warning\nSAMBAADM_ARCH=x86_64\r\n"} {
		if v, e := installArchitecture(output); e != nil || v != "x86_64" {
			t.Fatal(v, e)
		}
	}
	for _, output := range []string{"x86_64", "SAMBAADM_ARCH=unknown\n", "SAMBAADM_ARCH=x86_64; id"} {
		if _, e := installArchitecture(output); e == nil {
			t.Fatal("unmarked or unsafe architecture accepted")
		}
	}
}

func TestHelperInstallHistoryPagesDoNotHideOldJobsOrOtherOwners(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.EnrollmentDir = t.TempDir()
	sess, _ := s.sessions.Create("owner", "cn=owner", auth.RoleAdmin)
	s.helperInstallActive = true
	ids := map[string]bool{}
	for i := 0; i < 42; i++ {
		actor := "owner"
		if i >= 35 {
			actor = "someone-else"
		}
		status := "complete"
		if i == 0 {
			status = "running"
		}
		j := &helperInstallJob{ID: uuid.NewString(), Actor: actor, Created: time.Date(2026, 11, 24, 10, 0, i, 0, time.UTC), Status: status, Nodes: []helperInstallNode{{Node: "dc.example.com", Logs: []string{"line"}}}}
		if e := s.saveInstall(j); e != nil {
			t.Fatal(e)
		}
		if actor == "owner" {
			ids[j.ID] = true
		}
	}
	get := func(query string) (int, struct {
		Jobs                         []helperInstallJob
		Page, PageSize, Total, Pages int
		Running                      bool
	}) { r := httptest.NewRequest("GET", "/api/v1/helper-install"+query, nil); r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID}); w := httptest.NewRecorder(); s.Router().ServeHTTP(w, r); var result struct {
		Jobs                         []helperInstallJob
		Page, PageSize, Total, Pages int
		Running                      bool
	}; if w.Code == 200 {
		if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
			t.Fatal(e)
		}
	}; return w.Code, result }
	seen := map[string]bool{}
	for _, query := range []string{"?page=1&pageSize=10", "?page=2&pageSize=10", "?page=3&pageSize=10", "?page=4&pageSize=10"} {
		code, v := get(query)
		if code != 200 || v.Total != 35 || v.Pages != 4 || !v.Running {
			t.Fatal(code, v)
		}
		for _, j := range v.Jobs {
			if !ids[j.ID] || seen[j.ID] {
				t.Fatal("foreign or duplicated job", j.ID)
			}
			seen[j.ID] = true
		}
	}
	if len(seen) != 35 {
		t.Fatal("history truncated", len(seen))
	}
	code, last := get("?page=999&pageSize=10")
	if code != 200 || last.Page != 4 || len(last.Jobs) != 5 {
		t.Fatal(code, last)
	}
	for _, q := range []string{"?page=0", "?page=-1", "?page=word", "?pageSize=0", "?pageSize=51"} {
		if code, _ := get(q); code != 400 {
			t.Fatal(q, code)
		}
	}
}
