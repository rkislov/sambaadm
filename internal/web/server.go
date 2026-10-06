package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

//go:embed templates static
var assets embed.FS

// Options wires dependencies into the HTTP server.
type Options struct {
	Config   *config.Config
	Services *service.Services
	Sessions *auth.Store
	RBAC     *auth.RBAC
	LDAP     *ldapproto.Client
	Audit    *audit.Logger
}

// Server is the HTTP front-end (SSR UI + REST API).
type Server struct {
	cfg      *config.Config
	svcs     *service.Services
	sessions *auth.Store
	rbac     *auth.RBAC
	ldap     *ldapproto.Client
	audit    *audit.Logger
	tmpl     *template.Template
	router   chi.Router
}

// New constructs the web server and router.
func New(opts Options) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"year": func() int { return time.Now().Year() },
	}).ParseFS(assets, "templates/*.html", "templates/*/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}

	s := &Server{
		cfg:      opts.Config,
		svcs:     opts.Services,
		sessions: opts.Sessions,
		rbac:     opts.RBAC,
		ldap:     opts.LDAP,
		audit:    opts.Audit,
		tmpl:     tmpl,
	}
	s.router = s.buildRouter()
	return s, nil
}

// Router returns the chi router.
func (s *Server) Router() http.Handler {
	return s.router
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(s.requestLogger)

	staticFS, err := fs.Sub(assets, "static")
	if err == nil {
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}

	r.Get("/healthz", s.handleHealthz)
	if s.cfg.Server.Metrics {
		r.Handle("/metrics", promhttp.Handler())
	}

	r.Get("/login", s.handleLoginGet)
	r.Post("/login", s.handleLoginPost)
	r.Post("/logout", s.handleLogout)

	r.Group(func(r chi.Router) {
		r.Use(s.requireSession)
		r.Get("/", s.handleDashboard)
		r.Get("/users", s.handleUsers)
		r.Get("/users/new", s.handleUserCreateForm)
		r.Post("/users", s.handleUserCreatePost)
		r.Get("/groups", s.handleGroups)
		r.Get("/computers", s.handleComputers)
		r.Get("/ou", s.handleOU)
		r.Get("/domain", s.handleDomainPage)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.requireSession)
		r.Get("/users", s.handleAPIUsers)
		r.Post("/users", s.handleAPIUserCreate)
		r.Get("/users/{login}", s.handleAPIUserGet)
		r.Delete("/users/{login}", s.handleAPIUserDelete)
		r.Post("/users/{login}/enable", s.handleAPIUserEnable)
		r.Post("/users/{login}/disable", s.handleAPIUserDisable)
		r.Post("/users/{login}/password", s.handleAPIUserPassword)

		r.Get("/groups", s.handleAPIGroups)
		r.Post("/groups", s.handleAPIGroupCreate)
		r.Delete("/groups/{name}", s.handleAPIGroupDelete)

		r.Get("/computers", s.handleAPIComputers)
		r.Delete("/computers/{name}", s.handleAPIComputerDelete)

		r.Get("/ou", s.handleAPIOUs)
		r.Post("/ou", s.handleAPIOUCreate)
		r.Delete("/ou", s.handleAPIOUDelete)

		r.Get("/domain", s.handleAPIDomain)
	})

	return r
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Debug("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"dur", time.Since(start),
		)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template", "name", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

type pageData struct {
	Title   string
	User    string
	Role    auth.Role
	Content any
	Flash   string
	Error   string
}
