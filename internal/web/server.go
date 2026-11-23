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
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	"sambaadm/internal/i18n"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/pki"
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
	kerberos          http.Handler
	backupMu          sync.Mutex
	certMu            sync.Mutex
	certRolloutMu     sync.Mutex
	certRolloutActive map[string]bool
	enrollMu          sync.Mutex
	surveyMu          sync.Mutex
	cfg               *config.Config
	svcs              *service.Services
	sessions          *auth.Store
	rbac              *auth.RBAC
	ldap              *ldapproto.Client
	audit             *audit.Logger
	tmpl              *template.Template
	router            chi.Router
	monitor           service.HostMonitor // Local host only; helpers may refer to a different server.
	diagnostics       *service.DiagnosticService
}

// New constructs the web server and router.
func New(opts Options) (*Server, error) {
	s := &Server{
		cfg:         opts.Config,
		diagnostics: service.NewDiagnosticService(opts.Config),
		svcs:        opts.Services,
		sessions:    opts.Sessions,
		rbac:        opts.RBAC,
		ldap:        opts.LDAP,
		audit:       opts.Audit,
	}
	if opts.Services != nil {
		s.diagnostics = service.NewDiagnosticService(opts.Config, opts.Services.Helpers)
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"year":        func() int { return time.Now().Year() },
		"urlpath":     url.PathEscape,
		"t":           func(lang i18n.Lang, key string) string { return i18n.T(lang, key) },
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
	if opts.Config.Auth.SSO.Enabled {
		if !strings.EqualFold(opts.Config.Auth.SSO.Realm, dnsFromBaseDN(opts.Config.LDAP.BaseDN)) {
			return nil, fmt.Errorf("SSO realm must match the configured AD domain")
		}
		if err := opts.Config.ValidateWeb(); err != nil {
			return nil, err
		}
		if len(opts.Config.Auth.Roles.Admins) == 0 {
			return nil, fmt.Errorf("configure auth.roles.admins before enabling SSO")
		}
		if opts.Config.Server.TLS.Cert == "" || opts.Config.Server.TLS.Key == "" {
			return nil, fmt.Errorf("Kerberos SSO requires HTTPS on this server")
		}
		u, _ := url.Parse(opts.Config.Server.PublicURL)
		pair, e := pki.LoadServerPair(opts.Config.Server.TLS.Cert, opts.Config.Server.TLS.Key, u.Hostname())
		if e != nil {
			return nil, e
		}
		s.kerberos, err = auth.KerberosHandler(opts.Config.Auth.SSO, opts.Config.Server.PublicURL, http.HandlerFunc(s.finishKerberosLogin), pair.Certificate[0])
		if err != nil {
			return nil, err
		}
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
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.WithPeerAddress(r.Context(), r.RemoteAddr)))
		})
	})
	r.Use(chimw.RealIP)
	r.Use(s.requestLogger)
	r.Use(chimw.Recoverer)
	r.Use(s.withLang)
	r.Use(selfRequestLimit)

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

	r.Get("/auth/kerberos", func(w http.ResponseWriter, r *http.Request) {
		if s.kerberos == nil {
			http.NotFound(w, r)
			return
		}
		s.kerberos.ServeHTTP(w, r)
	})
	r.Get("/login", s.handleLoginGet)
	r.Post("/login", s.handleLoginPost)
	r.With(s.requireSession, s.csrfProtect).Post("/logout", s.handleLogout)

	r.Group(func(r chi.Router) {
		r.Use(s.requireSession)
		r.Use(s.csrfProtect)
		r.Get("/", s.handleDashboard)
		r.Get("/users", s.handleWorkspace)
		r.Get("/users/new", s.handleUserCreateForm)
		r.Post("/users", s.handleUserCreatePost)
		r.Get("/groups", s.handleWorkspace)
		r.Get("/computers", s.handleWorkspace)
		r.Get("/ou", s.handleWorkspace)
		r.Get("/trusts", s.handleWorkspace)
		r.Get("/repl", s.handleWorkspace)
		r.Get("/sites", s.handleWorkspace)
		r.Get("/dns", s.handleWorkspace)
		r.Get("/gpo", s.handleWorkspace)
		r.Get("/domain", s.handleWorkspace)
		r.Get("/shares", s.handleWorkspace)
		r.Get("/shares/new", s.handleShareCreateForm)
		r.Post("/shares", s.handleShareCreatePost)
		r.Get("/shares/{name}/acl", s.handleShareACL)
		r.Post("/shares/{name}/acl", s.handleShareACLPost)
		r.Get("/printers", s.handleWorkspace)
		r.Get("/printers/new", s.handlePrinterCreateForm)
		r.Post("/printers", s.handlePrinterCreatePost)
		r.Get("/backups", s.handleObjectBackups)
		r.Post("/backups", s.handleObjectBackups)
		r.Get("/audit", s.handleAudit)
		r.Get("/surveys", s.surveyPage)
		r.Get("/diagnostics", s.handleDiagnostics)
		r.Post("/diagnostics/run", s.handleDiagnosticsRun)
		r.Get("/settings/certificates", s.handleCertificates)
		r.Get("/settings/time", s.handleTimeSettings)
		r.Post("/settings/time", s.handleTimeSettings)
		r.Post("/settings/certificates", s.handleCertificates)
		r.Get("/settings/helpers", s.enrollHelper)
		r.Post("/settings/helpers", s.enrollHelper)
		r.Get("/me", s.handleSelfPage)
		r.Get("/settings", s.handleSettings)
		r.Post("/settings", s.handleSettingsPost)
		r.Post("/settings/gpo-editor", s.handleGPOEditorSettings)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.requireSession)
		r.Use(s.csrfProtect)
		r.Get("/certificates/rollouts", s.handleCertificateRollouts)
		r.Post("/certificates/rollouts", s.handleCertificateRollouts)
		r.Get("/backups", s.handleAPIObjectBackups)
		r.Post("/backups", s.handleAPIObjectBackups)
		r.Post("/backups/restore/plan", s.handleAPIDomainRestore)
		r.Post("/backups/restore/start", s.handleAPIDomainRestore)
		r.Get("/backups/restore/status", s.handleAPIDomainRestore)
		r.Get("/backups/full", s.handleAPIFullBackups)
		r.Post("/backups/full/prepare", s.handleAPIFullBackups)
		r.Get("/backups/full/{id}", s.handleAPIFullBackups)
		r.Post("/backups/full/{id}/start", s.handleAPIFullBackups)
		r.Get("/backups/{id}", s.handleAPIObjectBackups)
		r.Get("/backups/{id}/objects/{guid}/preview", s.handleAPIObjectBackups)
		r.Post("/backups/{id}/objects/{guid}/restore", s.handleAPIObjectBackups)
		r.Get("/me", s.handleSelfGet)
		r.Put("/me", s.handleSelfUpdate)
		r.Get("/me/photo", s.handleSelfPhotoGet)
		r.Post("/me/photo", s.handleSelfPhotoSet)
		r.Post("/me/password", s.handleSelfPassword)
		r.Get("/me/history", s.handleSelfHistory)
		r.Get("/me/location", s.handleSelfLocation)

		r.Post("/shares/wizard", s.handleAPIShareWizard)
		r.Get("/samba/profile", s.handleAPISambaProfile)
		r.Put("/samba/profile", s.handleAPISambaProfile)
		r.Get("/surveys", s.surveysAPI)
		r.Get("/surveys/{id}", s.surveysAPI)
		r.Post("/surveys", s.surveysAPI)
		r.Post("/system/diagnostics", s.handleAPIDiagnostics)
		r.Get("/system/metrics", s.handleAPIHostMetrics)
		r.Get("/system/time", s.handleAPITime)
		r.Post("/system/time/plan", s.handleAPITime)
		r.Put("/system/time", s.handleAPITime)
		r.Post("/gpo/templates/import", s.handleAPITemplateImport)
		r.Get("/directory/tree", s.handleAPIDirectoryTree)
		r.Get("/groups/{name}", s.handleAPIGroupGet)
		r.Get("/groups/{name}/members", s.handleAPIGroupMembers)
		r.Post("/groups/{name}/members", s.handleAPIGroupMemberAdd)
		r.Delete("/groups/{name}/members", s.handleAPIGroupMemberRemove)
		r.Post("/users/{login}/move", s.handleAPIUserMove)
		r.Post("/computers/{name}/move", s.handleAPIComputerMove)
		r.Get("/computers/{name}", s.handleAPIComputerGet)
		r.Post("/ou/move", s.handleAPIOUMove)
		r.Post("/subnets/delete", s.handleAPISubnetDelete)
		r.Post("/domain/fsmo/seize", s.handleAPIFSMOSeize)
		r.Post("/domain/level/raise", s.handleAPILevelRaise)
		r.Get("/gpo/{gpo}", s.handleAPIGPOGet)
		r.Get("/gpo/{gpo}/alt-settings", s.handleAPIGPOALT)
		r.Get("/gpo/{gpo}/drives", s.handleAPIGPODrives)
		r.Put("/gpo/{gpo}/drives", s.handleAPIGPODriveSet)
		r.Get("/gpo/{gpo}/scripts", s.handleAPIGPOScripts)
		r.Put("/gpo/{gpo}/scripts", s.handleAPIGPOScriptsSet)
		r.Get("/gpo/{gpo}/scripts/file", s.handleAPIGPOScriptFile)
		r.Get("/gpo/{gpo}/scripts/maintenance", s.handleAPIScriptMaintenance)
		r.Post("/gpo/{gpo}/scripts/maintenance", s.handleAPIScriptMaintenance)
		r.Get("/gpo/{gpo}/scripts/preview", s.handleAPIScriptRestorePreview)
		r.Get("/gpo/{gpo}/scripts/backup", s.handleAPIScriptBackup)
		r.Put("/gpo/{gpo}/alt-settings", s.handleAPIGPOALTSet)
		r.Get("/gpo/links", s.handleAPIGPOLinks)
		r.Post("/gpo/model", s.handleAPIGPOModel)
		r.Post("/gpo/explain", s.handleAPIGPOExplain)
		r.Get("/gpo/scope", s.handleAPIGPOScope)
		r.Put("/gpo/scope", s.handleAPIGPOScope)
		r.Get("/gpo/{gpo}/delegation/full", s.handleAPIGPOFullDelegation)
		r.Post("/gpo/{gpo}/delegation/full", s.handleAPIGPOFullDelegation)
		r.Put("/gpo/{gpo}/delegation/full", s.handleAPIGPOFullDelegation)
		r.Get("/gpo/{gpo}/delegation", s.handleAPIGPODelegation)
		r.Post("/gpo/{gpo}/delegation", s.handleAPIGPODelegation)
		r.Put("/gpo/{gpo}/delegation", s.handleAPIGPODelegation)
		r.Post("/gpo/{gpo}/consistency", s.handleAPIGPOConsistency)
		r.Get("/gpo/{gpo}/repair", s.handleAPIGPORepair)
		r.Post("/gpo/{gpo}/repair", s.handleAPIGPORepair)
		r.Put("/gpo/{gpo}/repair", s.handleAPIGPORepair)
		r.Get("/gpo/{gpo}/filter", s.handleAPIGPOFilter)
		r.Put("/gpo/{gpo}/filter", s.handleAPIGPOFilter)
		r.Put("/dns/zones/{zone}/records", s.handleAPIDNSRecordUpdate)
		r.Post("/shares/reload", s.handleAPIShareReload)
		r.Post("/shares/{name}/param", s.handleAPIShareParam)
		r.Get("/users", s.handleAPIUsers)
		r.Post("/users", s.handleAPIUserCreate)
		r.Get("/users/{login}", s.handleAPIUserGet)
		r.Put("/users/{login}", s.handleAPIUserUpdate)
		r.Get("/users/{login}/groups", s.handleAPIUserGroups)
		r.Delete("/users/{login}", s.handleAPIUserDelete)
		r.Post("/users/{login}/enable", s.handleAPIUserEnable)
		r.Post("/users/{login}/disable", s.handleAPIUserDisable)
		r.Post("/users/{login}/password", s.handleAPIUserPassword)
		r.Get("/users/{login}/login-status", s.handleAPIUserLoginStatus)
		r.Get("/users/{login}/password-policy", s.handleEffectivePasswordPolicy)
		r.Post("/users/{login}/unlock", s.handleAPIUserUnlock)

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
		r.Get("/domain/password-policies", s.handlePSOList)
		r.Post("/domain/password-policies", s.handlePSOWrite)
		r.Get("/domain/password-policies/subjects", s.handlePSOSubjects)
		r.Get("/domain/password-policies/{id}", s.handlePSOGet)
		r.Put("/domain/password-policies/{id}", s.handlePSOWrite)
		r.Delete("/domain/password-policies/{id}", s.handlePSODelete)
		r.Get("/domain/password-policy", s.handleDomainPasswordPolicy)
		r.Put("/domain/password-policy", s.handleDomainPasswordPolicy)
		r.Get("/domain/level", s.handleAPIDomainLevel)

		r.Get("/repl/partners", s.handleAPIReplPartners)
		r.Get("/repl/status", s.handleAPIReplStatus)
		r.Post("/repl/sync", s.handleAPIReplSync)

		r.Get("/sites/topology", s.handleAPITopology)
		r.Post("/sites/topology/audit", s.handleAPITopologyAudit)
		r.Post("/sites/topology/cleanup/apply", s.handleAPICleanupApply)
		r.Post("/sites/topology/cleanup/preview", s.handleAPICleanupPreview)
		r.Post("/sites/topology/cleanup/snapshot", s.handleAPICleanupSnapshot)
		r.Post("/sites/topology/cleanup/backup", s.handleAPIDomainBackupStart)
		r.Post("/sites/topology/cleanup/checks", s.handleAPICleanupChecks)
		r.Get("/sites/controllers/{name}/backups/{id}", s.handleAPIDomainBackupStatus)
		r.Get("/sites/controllers", s.handleAPIControllers)
		r.Get("/sites/controllers/{name}/inventory", s.handleAPIControllerInventory)
		r.Get("/sites/controllers/{name}/authentications", s.handleAPIControllerAuth)
		r.Get("/sites/controllers/{name}/rodc", s.handleAPIRODC)
		r.Post("/sites/controllers/{name}/rodc", s.handleAPIRODC)
		r.Put("/sites/controllers/{name}/rodc", s.handleAPIRODC)
		r.Get("/sites/controllers/{name}/rodc/authentications", s.handleAPIRODCAuth)
		r.Post("/sites/controllers/{name}/move", s.handleAPIMoveController)
		r.Get("/sites/links", s.handleAPISiteLinks)
		r.Post("/sites/links", s.handleAPISiteLinks)
		r.Put("/sites/links/{name}", s.handleAPISiteLinks)
		r.Put("/sites/links/{name}/schedule", s.handleAPISiteLinkSchedule)
		r.Delete("/sites/links/{name}", s.handleAPISiteLinkDelete)
		r.Put("/subnets/site", s.handleAPISetSubnetSite)
		r.Get("/repl/connections", s.handleAPIConnections)
		r.Post("/repl/connections", s.handleAPIConnections)
		r.Put("/repl/connections/{id}", s.handleAPIConnectionUpdate)
		r.Delete("/repl/connections/{id}", s.handleAPIConnectionUpdate)
		r.Post("/repl/kcc", s.handleAPIKCC)
		r.Get("/sites", s.handleAPISites)
		r.Post("/sites", s.handleAPISiteCreate)
		r.Delete("/sites/{name}", s.handleAPISiteDelete)
		r.Get("/subnets", s.handleAPISubnets)
		r.Post("/subnets", s.handleAPISubnetCreate)

		r.Get("/dns/zones", s.handleAPIDNSZones)
		r.Post("/dns/zones", s.handleAPIDNSZoneCreate)
		r.Delete("/dns/zones/{zone}", s.handleAPIDNSZoneDelete)
		r.Get("/dns/zones/{zone}/nodes", s.handleAPIDNSNodes)
		r.Get("/dns/zones/{zone}/records", s.handleAPIDNSRecords)
		r.Post("/dns/zones/{zone}/records", s.handleAPIDNSRecordAdd)
		r.Delete("/dns/zones/{zone}/records", s.handleAPIDNSRecordDelete)

		r.Get("/gpo", s.handleAPIGPOs)
		r.Post("/gpo", s.handleAPIGPOCreate)
		r.Post("/gpo/restore", s.handleAPIGPORestore)
		r.Delete("/gpo/{gpo}", s.handleAPIGPODelete)
		r.Post("/gpo/{gpo}/link", s.handleAPIGPOLink)
		r.Post("/gpo/{gpo}/unlink", s.handleAPIGPOUnlink)
		r.Post("/gpo/{gpo}/backup", s.handleAPIGPOBackup)
		r.Post("/gpo/{gpo}/restore", s.handleAPIGPORestore)
		r.Post("/gpo/distribute", s.handleAPIGPODistributeAll)
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
		level := slog.LevelDebug
		if ww.Status() >= 500 {
			level = slog.LevelError
		} else if ww.Status() >= 400 {
			level = slog.LevelWarn
		}
		slog.Log(r.Context(), level, "http",
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
		pd.SSOUser = sess.AuthMethod == "kerberos"
		pd.User = sess.Username
		pd.Role = sess.Role
		pd.CSRF = sess.CSRFToken
		pd.HelperSession = s.sessions.HasHelperCredentials(sess.ID)
		pd.LegacyCN = sess.AllowLegacyCN
		pd.SkipLDAPVerify = sess.SkipLDAPVerify
	}
	return pd
}

type pageData struct {
	SSOEnabled     bool
	SSOAuto        bool
	SSOUser        bool
	LegacyCN       bool
	SkipLDAPVerify bool
	HelperSession  bool
	Title          string
	User           string
	Role           auth.Role
	Lang           i18n.Lang
	CSRF           string
	Active         string
	Content        any
	Flash          string
	Error          string
}
