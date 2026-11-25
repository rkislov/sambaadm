package domaininit

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

type resumeRunner struct {
	fakeRunner
	resumes int
}

func (f *resumeRunner) Resume(_ context.Context, id, user, password string) (*Status, error) {
	f.resumes++
	f.secret = password
	return &Status{ID: id, State: "queued", Mode: "existing"}, nil
}
func TestExistingResumeAllowsOnlyCredentialsThroughLockedConsole(t *testing.T) {
	runner := &resumeRunner{}
	h := Bootstrap(runner, "console-code", true)
	post := func(path, body, csrf, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://setup.example"+path, strings.NewReader(body))
		r.Header.Set("Cookie", cookie)
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"id":"` + strings.Repeat("a", 32) + `","username":"Administrator@corp.example","password":"private-secret"}`
	if post("/api/resume", body, "", "").Code != 401 {
		t.Fatal("unauthenticated resume")
	}
	w := post("/api/unlock", `{"token":"console-code"}`, "", "")
	var meta map[string]string
	json.Unmarshal(w.Body.Bytes(), &meta)
	cookie := w.Result().Cookies()[0].String()
	if post("/api/resume", body, "", cookie).Code != 403 {
		t.Fatal("CSRF bypass")
	}
	if post("/api/resume", strings.TrimSuffix(body, "}")+`,"source":"evil.example"}`, meta["csrf"], cookie).Code != 400 {
		t.Fatal("target override accepted")
	}
	if post("/api/start", `{"mode":"existing"}`, meta["csrf"], cookie).Code != 409 {
		t.Fatal("fresh join permitted on deployed DC")
	}
	w = post("/api/resume", body, meta["csrf"], cookie)
	if w.Code != 202 || runner.resumes != 1 || strings.Contains(w.Body.String(), "private-secret") {
		t.Fatal(w.Code, w.Body, runner.resumes)
	}
}
func TestExistingDomainUsesDiscoveredLevelAndIdentity(t *testing.T) {
	in := Input{Mode: "existing", Realm: "corp.example", Hostname: "dc2", Source: "dc1.corp.example", Address: "192.0.2.20", Forwarder: "192.0.2.53", Level: "auto", PanelName: "sambaadm.corp.example", ServiceUser: "sadm-dc2"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*Input){func(v *Input) { v.Level = "2008_R2" }, func(v *Input) { v.Source = "dc1.other.example" }, func(v *Input) { v.ServiceUser = "invalid/name" }, func(v *Input) { v.Mode = "forest" }} {
		candidate := in
		alter(&candidate)
		if candidate.Validate() == nil {
			t.Fatal("incompatible or unsafe existing-domain parameters accepted")
		}
	}
}
