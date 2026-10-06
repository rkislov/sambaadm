package web

import (
	"net/http"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.FromRequest(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", pageData{Title: "Вход"})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, "login.html", pageData{Title: "Вход", Error: "Некорректная форма"})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		s.render(w, "login.html", pageData{Title: "Вход", Error: "Укажите логин и пароль"})
		return
	}

	// Bind as the user to verify credentials.
	if err := s.ldap.Connect(r.Context()); err != nil {
		s.render(w, "login.html", pageData{Title: "Вход", Error: "LDAP недоступен: " + err.Error()})
		return
	}
	if err := s.ldap.BindSimple(r.Context(), username, password); err != nil {
		s.audit.Failure(username, "login", "", r.RemoteAddr, err)
		s.render(w, "login.html", pageData{Title: "Вход", Error: "Неверный логин или пароль"})
		return
	}

	// Until memberOf → RBAC is wired, authenticated operators get admin.
	// When role groups are configured, default to readonly (memberOf mapping later).
	role := auth.RoleAdmin
	if len(s.cfg.Auth.Roles.Admins) > 0 || len(s.cfg.Auth.Roles.Helpdesk) > 0 {
		role = auth.RoleReadonly
	}
	if s.cfg.LDAP.Bind.User != "" {
		// Re-bind as service account for subsequent directory ops if configured.
		pass := s.cfg.BindPassword()
		_ = s.ldap.BindSimple(r.Context(), s.cfg.LDAP.Bind.User, pass)
	}

	sess, err := s.sessions.Create(username, username, role)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	secure := s.cfg.Server.TLS.Cert != ""
	s.sessions.SetCookie(w, sess, secure)
	s.audit.Success(username, "login", "", r.RemoteAddr)
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
	sess := sessionFrom(r)
	s.render(w, "dashboard.html", pageData{
		Title: "Дашборд",
		User:  sess.Username,
		Role:  sess.Role,
		Content: map[string]any{
			"LDAP": s.cfg.LDAP.URI,
			"Base": s.cfg.LDAP.BaseDN,
		},
	})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	q := r.URL.Query().Get("q")
	users, err := s.svcs.Users.List(r.Context(), "", q)
	if err != nil {
		s.render(w, "users/list.html", pageData{
			Title: "Пользователи", User: sess.Username, Role: sess.Role, Error: err.Error(),
		})
		return
	}
	s.render(w, "users/list.html", pageData{
		Title: "Пользователи", User: sess.Username, Role: sess.Role, Content: users,
	})
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	groups, err := s.svcs.Groups.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.render(w, "groups/list.html", pageData{
			Title: "Группы", User: sess.Username, Role: sess.Role, Error: err.Error(),
		})
		return
	}
	s.render(w, "groups/list.html", pageData{
		Title: "Группы", User: sess.Username, Role: sess.Role, Content: groups,
	})
}

func (s *Server) handleDomainPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	info, err := s.svcs.Domain.Info(r.Context())
	if err != nil {
		s.render(w, "domain/info.html", pageData{
			Title: "Домен", User: sess.Username, Role: sess.Role, Error: err.Error(),
		})
		return
	}
	s.render(w, "domain/info.html", pageData{
		Title: "Домен", User: sess.Username, Role: sess.Role, Content: info,
	})
}

func (s *Server) handleComputers(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	computers, err := s.svcs.Computers.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		s.render(w, "computers/list.html", pageData{
			Title: "Компьютеры", User: sess.Username, Role: sess.Role, Error: err.Error(),
		})
		return
	}
	s.render(w, "computers/list.html", pageData{
		Title: "Компьютеры", User: sess.Username, Role: sess.Role, Content: computers,
	})
}

func (s *Server) handleOU(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	ous, err := s.svcs.OU.List(r.Context())
	if err != nil {
		s.render(w, "ou/list.html", pageData{
			Title: "OU", User: sess.Username, Role: sess.Role, Error: err.Error(),
		})
		return
	}
	s.render(w, "ou/list.html", pageData{
		Title: "OU", User: sess.Username, Role: sess.Role, Content: ous,
	})
}

func (s *Server) handleUserCreateForm(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	s.render(w, "users/create.html", pageData{Title: "Новый пользователь", User: sess.Username, Role: sess.Role})
}

func (s *Server) handleUserCreatePost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !auth.CanAdmin(sess.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, "users/create.html", pageData{Title: "Новый пользователь", User: sess.Username, Role: sess.Role, Error: "Некорректная форма"})
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
		s.render(w, "users/create.html", pageData{
			Title: "Новый пользователь", User: sess.Username, Role: sess.Role, Error: err.Error(),
		})
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
