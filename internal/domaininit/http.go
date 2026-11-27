package domaininit

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Runner interface {
	Plan(context.Context, Input) (*Plan, error)
	Start(context.Context, Input) (*Status, error)
	Read(string) (*Status, error)
}
type bootstrapHTTP struct {
	readOnly             bool
	runner               Runner
	token, session, csrf string
	expires              time.Time
	mu                   sync.Mutex
	attempts             int
	window               time.Time
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func Bootstrap(runner Runner, token string, readOnly ...bool) http.Handler {
	h := &bootstrapHTTP{runner: runner, token: token, session: randomToken(), csrf: randomToken(), expires: time.Now().Add(2 * time.Hour)}
	if len(readOnly) > 0 {
		h.readOnly = readOnly[0]
	}
	return h
}
func (h *bootstrapHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
	reply := func(code int, value any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(value)
	}
	fail := func(code int, msg string) { reply(code, map[string]string{"error": msg}) }
	if time.Now().After(h.expires) {
		fail(410, "Срок работы мастера истёк. Проверьте состояние сервера и запустите samba-domain-init заново.")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/assets/") && r.Method == "GET" {
		assets, _ := fs.Sub(Files, "assets")
		http.StripPrefix("/assets/", http.FileServer(http.FS(assets))).ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		raw, _ := Files.ReadFile("assets/index.html")
		_, _ = w.Write(raw)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		fail(405, "Метод не поддерживается")
		return
	}
	if r.Method == "POST" {
		origin := r.Header.Get("Origin")
		if origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, r.Host) {
				fail(403, "Недопустимый источник запроса")
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	}
	if r.URL.Path == "/api/unlock" && r.Method == "POST" {
		h.mu.Lock()
		defer h.mu.Unlock()
		if time.Since(h.window) > time.Minute {
			h.window = time.Now()
			h.attempts = 0
		}
		h.attempts++
		if h.attempts > 10 {
			fail(429, "Слишком много попыток; повторите через минуту")
			return
		}
		var in struct {
			Token string `json:"token"`
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil || subtle.ConstantTimeCompare([]byte(in.Token), []byte(h.token)) != 1 {
			fail(401, "Неверный код из консоли сервера")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "domain-init", Value: h.session, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 7200})
		reply(200, map[string]string{"csrf": h.csrf})
		return
	}
	cookie, err := r.Cookie("domain-init")
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(h.session)) != 1 {
		fail(401, "Введите код из консоли сервера")
		return
	}
	if r.Method == "POST" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(h.csrf)) != 1 {
		fail(403, "Обновите страницу мастера")
		return
	}
	if r.URL.Path == "/api" && r.Method == "GET" {
		meta := map[string]any{"csrf": h.csrf, "readOnly": h.readOnly}
		if reader, ok := h.runner.(interface{ Latest() (*Status, error) }); ok {
			latest, err := reader.Latest()
			if err != nil {
				fail(500, "Не удалось прочитать журнал установки")
				return
			}
			meta["job"] = latest
		}
		reply(200, meta)
		return
	}
	if r.URL.Path == "/api/status" && r.Method == "GET" {
		value, err := h.runner.Read(r.URL.Query().Get("id"))
		if err != nil {
			fail(404, "Задание не найдено")
			return
		}
		reply(200, value)
		return
	}
	if r.URL.Path == "/api/resume" && r.Method == "POST" {
		runner, ok := h.runner.(interface {
			Resume(context.Context, string, string, string) (*Status, error)
		})
		if !ok {
			fail(409, "Продолжение не поддерживается")
			return
		}
		var in struct {
			ID       string `json:"id"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF {
			fail(400, "Некорректные параметры")
			return
		}
		out, err := runner.Resume(r.Context(), in.ID, in.Username, in.Password)
		if err != nil {
			fail(409, err.Error())
			return
		}
		reply(202, out)
		return
	}
	if r.Method != "POST" || (r.URL.Path != "/api/plan" && r.URL.Path != "/api/start") {
		http.NotFound(w, r)
		return
	}
	if h.readOnly {
		fail(409, "Домен уже создан. Этот запуск мастера доступен только для чтения журнала; откройте рабочую панель.")
		return
	}
	var in Input
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		fail(400, "Некорректные параметры")
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		fail(400, "Некорректные параметры")
		return
	}
	if in.Mode != "forest" && in.Mode != "existing" && in.Mode != "member" {
		fail(400, "Выберите новый лес или присоединение к существующему домену")
		return
	}
	if r.URL.Path == "/api/plan" {
		ctx, cancel := context.WithTimeout(r.Context(), 190*time.Second)
		defer cancel()
		out, err := h.runner.Plan(ctx, in)
		if err != nil {
			fail(409, err.Error())
			return
		}
		if len(out.CSR) > 0 {
			if err := SignPlan(out, in, "/var/lib/sambaadm/certificates"); err != nil {
				fail(409, err.Error())
				return
			}
		}
		reply(200, out)
		return
	}
	out, err := h.runner.Start(r.Context(), in)
	if err != nil {
		fail(409, err.Error())
		return
	}
	reply(202, out)
}
