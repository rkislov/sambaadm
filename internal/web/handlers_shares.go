package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleShares(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.shares", nil)
	list, err := s.svcs.Shares.ListFileShares(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "shares/list.html", pd)
		return
	}
	pd.Content = map[string]any{
		"Shares":     list,
		"SMBConf":    s.svcs.Shares.ConfigPath(),
		"SharesRoot": s.svcs.Shares.SharesRoot(),
	}
	s.render(w, "shares/list.html", pd)
}

func (s *Server) handleShareCreateForm(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "shares.create", map[string]any{
		"SharesRoot": s.svcs.Shares.SharesRoot(),
	})
	s.render(w, "shares/create.html", pd)
}

func (s *Server) handleShareCreatePost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !auth.CanAdmin(sess.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pd := s.page(r, "shares.create", map[string]any{"SharesRoot": s.svcs.Shares.SharesRoot()})
	if err := r.ParseForm(); err != nil {
		pd.Error = "bad form"
		s.render(w, "shares/create.html", pd)
		return
	}
	ro := formOn(r, "read_only")
	guest := formOn(r, "guest_ok")
	browse := formOn(r, "browseable")
	createDir := formOn(r, "create_dir")
	inherit := formOn(r, "inherit_acls")
	mapInherit := formOn(r, "map_acl_inherit")
	_, err := s.svcs.Shares.Create(r.Context(), service.CreateShareInput{
		Name:          r.FormValue("name"),
		Path:          r.FormValue("path"),
		Comment:       r.FormValue("comment"),
		Preset:        r.FormValue("preset"),
		ValidUsers:    r.FormValue("valid_users"),
		WriteList:     r.FormValue("write_list"),
		ReadList:      r.FormValue("read_list"),
		ForceUser:     r.FormValue("force_user"),
		ForceGroup:    r.FormValue("force_group"),
		Owner:         r.FormValue("owner"),
		Mode:          r.FormValue("mode"),
		ACL:           r.FormValue("acl"),
		DefaultACL:    r.FormValue("default_acl"),
		ReadOnly:      &ro,
		GuestOK:       &guest,
		Browseable:    &browse,
		CreateDir:     &createDir,
		InheritACLs:   &inherit,
		MapACLInherit: &mapInherit,
	}, sess.Username, r.RemoteAddr)
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "shares/create.html", pd)
		return
	}
	http.Redirect(w, r, "/shares", http.StatusSeeOther)
}

func (s *Server) handleShareACL(w http.ResponseWriter, r *http.Request) {
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	pd := s.page(r, "shares.acl", nil)
	sh, err := s.svcs.Shares.Show(r.Context(), name)
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "shares/acl.html", pd)
		return
	}
	acl, err := s.svcs.FSACL.Get(r.Context(), sh.Path)
	if err != nil {
		pd.Error = err.Error()
	}
	pd.Content = map[string]any{"Share": sh, "ACL": acl}
	s.render(w, "shares/acl.html", pd)
}

func (s *Server) handleShareACLPost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !auth.CanAdmin(sess.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	sh, err := s.svcs.Shares.Show(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	renderErr := func(msg string) {
		pd := s.page(r, "shares.acl", nil)
		pd.Error = msg
		acl, _ := s.svcs.FSACL.Get(r.Context(), sh.Path)
		fresh, _ := s.svcs.Shares.Show(r.Context(), name)
		if fresh != nil {
			sh = fresh
		}
		pd.Content = map[string]any{"Share": sh, "ACL": acl}
		s.render(w, "shares/acl.html", pd)
	}

	switch r.FormValue("action") {
	case "samba":
		ro, guest, browse := formOn(r, "read_only"), formOn(r, "guest_ok"), formOn(r, "browseable")
		inherit, mapInh := formOn(r, "inherit_acls"), formOn(r, "map_acl_inherit")
		_, err := s.svcs.Shares.UpdateAccess(r.Context(), name, service.UpdateShareAccessInput{
			ValidUsers:    r.FormValue("valid_users"),
			WriteList:     r.FormValue("write_list"),
			ReadList:      r.FormValue("read_list"),
			ForceUser:     r.FormValue("force_user"),
			ForceGroup:    r.FormValue("force_group"),
			ReadOnly:      &ro,
			GuestOK:       &guest,
			Browseable:    &browse,
			InheritACLs:   &inherit,
			MapACLInherit: &mapInh,
			ClearValid:    formOn(r, "clear_valid"),
			ClearWrite:    formOn(r, "clear_write"),
			ClearRead:     formOn(r, "clear_read"),
		}, sess.Username, r.RemoteAddr)
		if err != nil {
			renderErr(err.Error())
			return
		}
	case "xattr":
		_, err := s.svcs.FSACL.Set(r.Context(), service.SetACLInput{
			Path:        sh.Path,
			XAttrName:   r.FormValue("xattr_name"),
			XAttrValue:  r.FormValue("xattr_value"),
			XAttrRemove: r.FormValue("xattr_remove"),
		}, sess.Username, r.RemoteAddr)
		if err != nil {
			renderErr(err.Error())
			return
		}
	default: // fs
		aclSpec := strings.TrimSpace(r.FormValue("acl"))
		if aclSpec == "" && r.FormValue("acl_kind") != "" {
			perms := ""
			if formOn(r, "acl_r") {
				perms += "r"
			}
			if formOn(r, "acl_w") {
				perms += "w"
			}
			if formOn(r, "acl_x") {
				perms += "x"
			}
			built, err := service.BuildACLSpec(r.FormValue("acl_kind"), r.FormValue("acl_name"), perms)
			if err != nil {
				renderErr(err.Error())
				return
			}
			aclSpec = built
		}
		_, err := s.svcs.FSACL.Set(r.Context(), service.SetACLInput{
			Path:             sh.Path,
			Owner:            r.FormValue("owner"),
			Mode:             r.FormValue("mode"),
			ACL:              aclSpec,
			DefaultACL:       r.FormValue("default_acl"),
			RemoveACL:        r.FormValue("remove_acl"),
			Recursive:        formOn(r, "recursive"),
			DefaultRecursive: formOn(r, "default_recursive"),
			ClearACL:         formOn(r, "clear_acl"),
			ClearDefault:     formOn(r, "clear_default"),
			CopyToDefault:    formOn(r, "inherit_default"),
		}, sess.Username, r.RemoteAddr)
		if err != nil {
			renderErr(err.Error())
			return
		}
	}
	http.Redirect(w, r, "/shares/"+url.PathEscape(name)+"/acl", http.StatusSeeOther)
}

func formOn(r *http.Request, name string) bool {
	v := r.FormValue(name)
	return v == "on" || v == "1" || v == "true" || v == "yes"
}

func (s *Server) handlePrinters(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "nav.printers", nil)
	list, err := s.svcs.Printers.List(r.Context())
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "printers/list.html", pd)
		return
	}
	pd.Content = list
	s.render(w, "printers/list.html", pd)
}

func (s *Server) handlePrinterCreateForm(w http.ResponseWriter, r *http.Request) {
	pd := s.page(r, "printers.create", nil)
	s.render(w, "printers/create.html", pd)
}

func (s *Server) handlePrinterCreatePost(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if !auth.CanAdmin(sess.Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pd := s.page(r, "printers.create", nil)
	if err := r.ParseForm(); err != nil {
		pd.Error = "bad form"
		s.render(w, "printers/create.html", pd)
		return
	}
	guest := r.FormValue("guest_ok") == "on" || r.FormValue("guest_ok") == "1"
	_, err := s.svcs.Printers.Create(r.Context(), service.CreatePrinterInput{
		Name:        r.FormValue("name"),
		Path:        r.FormValue("path"),
		Comment:     r.FormValue("comment"),
		PrinterName: r.FormValue("cups_name"),
		GuestOK:     &guest,
	}, sess.Username, r.RemoteAddr)
	if err != nil {
		pd.Error = err.Error()
		s.render(w, "printers/create.html", pd)
		return
	}
	http.Redirect(w, r, "/printers", http.StatusSeeOther)
}

// --- API ---

func (s *Server) handleAPIShares(w http.ResponseWriter, r *http.Request) {
	list, err := s.svcs.Shares.ListFileShares(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleAPIShareGet(w http.ResponseWriter, r *http.Request) {
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sh, err := s.svcs.Shares.Show(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sh)
}

func (s *Server) handleAPIShareCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.CreateShareInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	sh, err := s.svcs.Shares.Create(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, sh)
}

func (s *Server) handleAPIShareDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	removeDir := r.URL.Query().Get("remove_dir") == "1" || r.URL.Query().Get("remove_dir") == "true"
	sess := sessionFrom(r)
	if err := s.svcs.Shares.Delete(r.Context(), name, removeDir, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAPIShareACLGet(w http.ResponseWriter, r *http.Request) {
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sh, err := s.svcs.Shares.Show(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	acl, err := s.svcs.FSACL.Get(r.Context(), sh.Path)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, acl)
}

func (s *Server) handleAPIShareACLSet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sh, err := s.svcs.Shares.Show(r.Context(), name)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	var in service.SetACLInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	in.Path = sh.Path
	sess := sessionFrom(r)
	acl, err := s.svcs.FSACL.Set(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, acl)
}

func (s *Server) handleAPIPrinters(w http.ResponseWriter, r *http.Request) {
	list, err := s.svcs.Printers.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleAPIPrinterCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.CreatePrinterInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	p, err := s.svcs.Printers.Create(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleAPIPrinterDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sess := sessionFrom(r)
	if err := s.svcs.Printers.Delete(r.Context(), name, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAPIACLGet(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
		return
	}
	acl, err := s.svcs.FSACL.Get(r.Context(), path)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, acl)
}

func (s *Server) handleAPIACLSet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.SetACLInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	acl, err := s.svcs.FSACL.Set(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, acl)
}
