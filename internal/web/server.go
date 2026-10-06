package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	"sambaadm/internal/i18n"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

//go:embed templates static openapi.yaml
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
	s := &Server{
		cfg:      opts.Config,
		svcs:     opts.Services,
		sessions: opts.Sessions,
		rbac:     opts.RBAC,
		ldap:     opts.LDAP,
		audit:    opts.Audit,
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"year":        func() int { return time.Now().Year() },
		"urlpath":     url.PathEscape,
		"t":           func(lang i18n.Lang, key string) string { return i18n.T(lang, key) },
		"eq":          func(a, b any) bool { return a == b },
		"canAdmin":    auth.CanAdmin,
		"canHelpdesk": auth.CanHelpdesk,
		"navClass": func(active, href string) string {
			if active == href {
				return "active"
			}
			if href != "/" && strings.HasPrefix(active, href) {
				return "active"
			}
			return ""
		},
	}).ParseFS(assets, "templates/*.html", "templates/*/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s.tmpl = tmpl
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
	r.Use(s.withLang)

	staticFS, err := fs.Sub(assets, "static")
	if err == nil {
		r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	}

	r.Get("/healthz", s.handleHealthz)
	if s.cfg.Server.Metrics {
		r.Handle("/metrics", promhttp.Handler())
	}
	r.Get("/api/openapi.yaml", s.handleOpenAPISpec)
	r.Get("/api/docs", s.handleAPIDocs)

	r.Get("/login", s.handleLoginGet)
	r.Post("/login", s.handleLoginPost)
	r.With(s.requireSession, s.csrfProtect).Post("/logout", s.handleLogout)

	r.Group(func(r chi.Router) {
		r.Use(s.requireSession)
		r.Use(s.csrfProtect)
		r.Get("/", s.handleDashboard)
		r.Get("/users", s.handleUsers)
		r.Get("/users/new", s.handleUserCreateForm)
		r.Post("/users", s.handleUserCreatePost)
		r.Get("/groups", s.handleGroups)
		r.Get("/computers", s.handleComputers)
		r.Get("/ou", s.handleOU)
		r.Get("/trusts", s.handleTrusts)
		r.Get("/repl", s.handleRepl)
		r.Get("/sites", s.handleSites)
		r.Get("/dns", s.handleDNS)
		r.Get("/gpo", s.handleGPO)
		r.Get("/domain", s.handleDomainPage)
		r.Get("/shares", s.handleShares)
		r.Get("/shares/new", s.handleShareCreateForm)
		r.Post("/shares", s.handleShareCreatePost)
		r.Get("/shares/{name}/acl", s.handleShareACL)
		r.Post("/shares/{name}/acl", s.handleShareACLPost)
		r.Get("/printers", s.handlePrinters)
		r.Get("/printers/new", s.handlePrinterCreateForm)
		r.Post("/printers", s.handlePrinterCreatePost)
		r.Get("/audit", s.handleAudit)
		r.Get("/settings", s.handleSettings)
		r.Post("/settings", s.handleSettingsPost)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.requireSession)
		r.Use(s.csrfProtect)
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

		r.Get("/trusts", s.handleAPITrusts)
		r.Post("/trusts", s.handleAPITrustCreate)
		r.Delete("/trusts/{domain}", s.handleAPITrustDelete)
		r.Post("/trusts/{domain}/validate", s.handleAPITrustValidate)

		r.Get("/domain", s.handleAPIDomain)
		r.Get("/domain/fsmo", s.handleAPIFSMO)
		r.Post("/domain/fsmo/transfer", s.handleAPIFSMOTransfer)
		r.Get("/domain/level", s.handleAPIDomainLevel)

		r.Get("/repl/partners", s.handleAPIReplPartners)
		r.Get("/repl/status", s.handleAPIReplStatus)
		r.Post("/repl/sync", s.handleAPIReplSync)

		r.Get("/sites", s.handleAPISites)
		r.Post("/sites", s.handleAPISiteCreate)
		r.Delete("/sites/{name}", s.handleAPISiteDelete)
		r.Get("/subnets", s.handleAPISubnets)
		r.Post("/subnets", s.handleAPISubnetCreate)

		r.Get("/dns/zones", s.handleAPIDNSZones)
		r.Post("/dns/zones", s.handleAPIDNSZoneCreate)
		r.Delete("/dns/zones/{zone}", s.handleAPIDNSZoneDelete)
		r.Get("/dns/zones/{zone}/records", s.handleAPIDNSRecords)
		r.Post("/dns/zones/{zone}/records", s.handleAPIDNSRecordAdd)
		r.Delete("/dns/zones/{zone}/records", s.handleAPIDNSRecordDelete)

		r.Get("/gpo", s.handleAPIGPOs)
		r.Post("/gpo", s.handleAPIGPOCreate)
		r.Delete("/gpo/{gpo}", s.handleAPIGPODelete)
		r.Post("/gpo/{gpo}/link", s.handleAPIGPOLink)
		r.Post("/gpo/{gpo}/unlink", s.handleAPIGPOUnlink)
		r.Post("/gpo/{gpo}/backup", s.handleAPIGPOBackup)
		r.Post("/gpo/{gpo}/restore", s.handleAPIGPORestore)
		r.Post("/gpo/{gpo}/distribute", s.handleAPIGPODistribute)
		r.Get("/gpo/distribute/{jobID}", s.handleAPIGPODistributeStatus)

		r.Get("/shares", s.handleAPIShares)
		r.Post("/shares", s.handleAPIShareCreate)
		r.Get("/shares/{name}", s.handleAPIShareGet)
		r.Delete("/shares/{name}", s.handleAPIShareDelete)
		r.Get("/shares/{name}/acl", s.handleAPIShareACLGet)
		r.Post("/shares/{name}/acl", s.handleAPIShareACLSet)

		r.Get("/printers", s.handleAPIPrinters)
		r.Post("/printers", s.handleAPIPrinterCreate)
		r.Delete("/printers/{name}", s.handleAPIPrinterDelete)

		r.Get("/acl", s.handleAPIACLGet)
		r.Post("/acl", s.handleAPIACLSet)
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

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("openapi.yaml")
	if err != nil {
		http.Error(w, "openapi missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	s.render(w, "api_docs.html", pageData{Title: "OpenAPI", Lang: langFrom(r)})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template", "name", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) page(r *http.Request, titleKey string, content any) pageData {
	lang := langFrom(r)
	sess := sessionFrom(r)
	pd := pageData{
		Title:   i18n.T(lang, titleKey),
		Lang:    lang,
		Content: content,
		Active:  r.URL.Path,
	}
	if sess != nil {
		pd.User = sess.Username
		pd.Role = sess.Role
		pd.CSRF = sess.CSRFToken
	}
	return pd
}

type pageData struct {
	Title   string
	User    string
	Role    auth.Role
	Lang    i18n.Lang
	CSRF    string
	Active  string
	Content any
	Flash   string
	Error   string
}
