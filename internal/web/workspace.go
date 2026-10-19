package web

import "net/http"

func (s *Server) handleWorkspace(w http.ResponseWriter, r *http.Request) {
	titles := map[string]string{"/users": "nav.users", "/groups": "nav.groups", "/computers": "nav.computers", "/ou": "nav.ou", "/trusts": "nav.trusts", "/repl": "nav.repl", "/sites": "nav.sites", "/dns": "nav.dns", "/gpo": "nav.gpo", "/domain": "nav.domain", "/shares": "nav.shares", "/printers": "nav.printers"}
	pd := s.page(r, titles[r.URL.Path], map[string]string{"Module": r.URL.Path, "BaseDN": s.cfg.LDAP.BaseDN})
	s.render(w, "workspace.html", pd)
}
