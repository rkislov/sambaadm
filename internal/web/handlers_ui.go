package web

import (
	"log/slog"
	"net/http"

	"sambaadm/internal/auth"
	"sambaadm/internal/i18n"
	"sambaadm/internal/service"
)

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.FromRequest(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	lang := langFrom(r)
	s.render(w, "login.html", pageData{
		Title: i18n.T(lang, "login.title"),
		Lang:  lang,
	})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	lang := langFrom(r)
	loginPage := func(errKey string, extra string) {
		msg := i18n.T(lang, errKey)
		if extra != "" {
			msg = msg + ": " + extra
		}
		s.render(w, "login.html", pageData{
			Title: i18n.T(lang, "login.title"),
			Lang:  lang,
			Error: msg,
		})
	}

	if err := r.ParseForm(); err != nil {
		loginPage("login.error.form", "")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		loginPage("login.error.empty", "")
		return
	}

	if err := s.ldap.Connect(r.Context()); err != nil {
		loginPage("login.error.ldap", err.Error())
		return
	}
	if err := s.ldap.BindSimple(r.Context(), username, password); err != nil {
		s.audit.Failure(username, "login", "", r.RemoteAddr, err)
		loginPage("login.error.auth", "")
		return
	}

	dn, role, err := s.resolveLoginIdentity(r.Context(), username)
	if err != nil {
		slog.Warn("login identity lookup", "user", username, "err", err)
	}
	if dn == "" {
		dn = username
	}

	if s.cfg.LDAP.Bind.User != "" {
		pass := s.cfg.BindPassword()
		if err := s.ldap.BindSimple(r.Context(), s.cfg.LDAP.Bind.User, pass); err != nil {
			slog.Warn("service account rebind failed", "err", err)
		}
	}

	sess, err := s.sessions.Create(username, dn, role)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	secure := s.cfg.Server.TLS.Cert != ""
	s.sessions.SetCookie(w, sess, secure)
	s.audit.Success(username, "login", dn, r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.sessions.FromRequest(r); ok {
		s.sessions.Delete(sess.ID)
		s.audit.Success(sess.Username, "logout", "", r.RemoteAddr)
	}
	s.sessions.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "dashboard.title", map[string]any{
		"LDAP": s.cfg.LDAP.URI,
		"Base": s.cfg.LDAP.BaseDN,
	})
	s.render(w, "dashboard.html", pd)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.users", nil)
	users, err := s.svcs.Users.List(r.Context(), "", r.URL.Query().Get("q"))
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "users/list.html", pd)
		return
	}
	pd.Content = users
	s.render(w, "users/list.html", pd)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.groups", nil)
	groups, err := s.svcs.Groups.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "groups/list.html", pd)
		return
	}
	pd.Content = groups
	s.render(w, "groups/list.html", pd)
}

func (s *Server) handleDomainPage(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.domain", nil)
	info, err := s.svcs.Domain.Info(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "domain/info.html", pd)
		return
	}
	fsmo, _ := s.svcs.Domain.FSMOShow(r.Context())
	lvl, _ := s.svcs.Domain.LevelShow(r.Context())
	pd.Content = map[string]any{"Info": info, "FSMO": fsmo, "Level": lvl}
	s.render(w, "domain/info.html", pd)
}

func (s *Server) handleTrusts(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.trusts", nil)
	trusts, err := s.svcs.Trusts.List(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "trusts/list.html", pd)
		return
	}
	pd.Content = trusts
	s.render(w, "trusts/list.html", pd)
}

func (s *Server) handleRepl(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.repl", nil)
	st, err := s.svcs.Repl.Status(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "repl/status.html", pd)
		return
	}
	pd.Content = st
	s.render(w, "repl/status.html", pd)
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.sites", nil)
	sites, err := s.svcs.Sites.List(r.Context())
	subnets, _ := s.svcs.Subnets.List(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "sites/list.html", pd)
		return
	}
	pd.Content = map[string]any{"Sites": sites, "Subnets": subnets}
	s.render(w, "sites/list.html", pd)
}

func (s *Server) handleComputers(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.computers", nil)
	computers, err := s.svcs.Computers.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "computers/list.html", pd)
		return
	}
	pd.Content = computers
	s.render(w, "computers/list.html", pd)
}

func (s *Server) handleOU(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.ou", nil)
	ous, err := s.svcs.OU.List(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "ou/list.html", pd)
		return
	}
	pd.Content = ous
	s.render(w, "ou/list.html", pd)
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.dns", nil)
	zones, err := s.svcs.DNS.ListZones(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "dns/list.html", pd)
		return
	}
	pd.Content = zones
	s.render(w, "dns/list.html", pd)
}

func (s *Server) handleGPO(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.gpo", nil)
	gpos, err := s.svcs.GPO.List(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "gpo/list.html", pd)
		return
	}
	pd.Content = gpos
	s.render(w, "gpo/list.html", pd)
}

func (s *Server) handleUserCreateForm(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.users", nil)
	s.render(w, "users/create.html", pd)
}

func (s *Server) handleUserCreatePost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	pd := s.page(r, "nav.users", nil)
	if !auth.CanAdmin(sess.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		pd.Error = i18n.T(pd.Lang, "login.error.form")
		s.render(w, "users/create.html", pd)
		return
	}
	_, err := s.svcs.Users.Create(r.Context(), service.CreateUserInput{
		Login:       r.FormValue("login"),
		Password:    r.FormValue("password"),
		DisplayName: r.FormValue("display"),
		OU:          r.FormValue("ou"),
		Mail:        r.FormValue("mail"),
		Enabled:     r.FormValue("enabled") == "on" || r.FormValue("enabled") == "1",
	}, sess.Username, r.RemoteAddr)
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "users/create.html", pd)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "audit.title", nil)
	events, err := s.audit.Recent(200)
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "audit/list.html", pd)
		return
	}
	// Newest first for UI.
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	pd.Content = map[string]any{
		"Events": events,
		"Path":   s.audit.Path(),
	}
	s.render(w, "audit/list.html", pd)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "settings.title", map[string]any{
		"Lang": langFrom(r),
	})
	s.render(w, "settings/index.html", pd)
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	lang := i18n.Normalize(r.FormValue("lang"))
	secure := s.cfg.Server.TLS.Cert != ""
	setLangCookie(w, lang, secure)
	if sess := sessionFrom(r); sess != nil {
		s.audit.Success(sess.Username, "settings.lang", string(lang), r.RemoteAddr)
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
