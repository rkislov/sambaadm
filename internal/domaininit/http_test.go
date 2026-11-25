package domaininit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeRunner struct {
	plans, starts int
	secret        string
}

func (f *fakeRunner) Plan(_ context.Context, in Input) (*Plan, error) {
	f.plans++
	if in.Password != "" {
		f.secret = in.Password
	}
	return &Plan{Revision: strings.Repeat("a", 64)}, nil
}
func (f *fakeRunner) Start(_ context.Context, in Input) (*Status, error) {
	f.starts++
	f.secret = in.Password
	return &Status{ID: strings.Repeat("a", 32), State: "queued"}, nil
}
func (*fakeRunner) Read(id string) (*Status, error) { return &Status{ID: id, State: "completed"}, nil }
func TestBootstrapAuthorizationCSRFAndForestScope(t *testing.T) {
	runner := &fakeRunner{}
	h := Bootstrap(runner, "console-code")
	call := func(path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://setup.example"+path, strings.NewReader(body))
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("/api/start", `{"mode":"forest"}`, "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := call("/api/unlock", `{"token":"wrong"}`, "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := call("/api/unlock", `{"token":"console-code"}`, "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal(cookies)
	}
	var response map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	csrf := response["csrf"]
	if w := call("/api/start", `{"mode":"forest","password":"private-value"}`, "", cookies[0]); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := call("/api/start", `{"mode":"DC","password":"private-value"}`, csrf, cookies[0]); w.Code != 400 {
		t.Fatal(w.Code)
	}
	w = call("/api/start", `{"mode":"forest","password":"private-value"}`, csrf, cookies[0])
	if w.Code != 202 || runner.starts != 1 || runner.secret != "private-value" || strings.Contains(w.Body.String(), "private-value") {
		t.Fatal(w.Code, w.Body, runner.starts)
	}
	r := httptest.NewRequest("POST", "https://setup.example/api/unlock", strings.NewReader(`{"token":"console-code"}`))
	r.Header.Set("Origin", "https://elsewhere.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestInputValidationAndNoPasswordFormatting(t *testing.T) {
	in := Input{Mode: "forest", Realm: "corp.example", NetBIOS: "CORP", Hostname: "dc1", Address: "192.0.2.10", Forwarder: "192.0.2.53", Site: "Main", Level: "2008_R2", PanelName: "sambaadm.corp.example", Password: "private-value"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Input){func(v *Input) { v.Mode = "MEMBER" }, func(v *Input) { v.Hostname = "dc;id" }, func(v *Input) { v.Address = "127.0.0.1" }, func(v *Input) { v.Forwarder = v.Address }, func(v *Input) { v.PanelName = "else.example" }, func(v *Input) { v.Site = "Main\ncmd" }, func(v *Input) { v.Realm = "corp..example" }} {
		v := in
		change(&v)
		if v.Validate() == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	if strings.Contains(in.String(), in.Password) || strings.Contains(in.GoString(), in.Password) {
		t.Fatal("password leaked")
	}
}
