package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/service"
)

func (s *Server) handleSelfPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "self.html", s.page(r, "self.title", nil))
}
func selfJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		writeJSON(w, 400, map[string]string{"error": "self.invalid-request"})
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "self.invalid-request"})
		return false
	}
	return true
}
func selfError(w http.ResponseWriter, err error) {
	status := 400
	if err == service.ErrTopologyConflict {
		status = 409
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func (s *Server) selfReady(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if sessionFrom(r).ObjectGUID == "" {
		writeJSON(w, 403, map[string]string{"error": "self.identity-required"})
		return false
	}
	if s.svcs == nil || s.svcs.Users == nil {
		writeJSON(w, 503, map[string]string{"error": "self.unavailable"})
		return false
	}
	return true
}
func (s *Server) handleSelfGet(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	profile, err := s.svcs.Users.Self(r.Context(), sessionFrom(r).ObjectGUID)
	if err != nil {
		selfError(w, err)
		return
	}
	writeJSON(w, 200, profile)
}
func (s *Server) handleSelfUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	var in service.SelfEdit
	if !selfJSON(w, r, &in) {
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Users.UpdateSelf(r.Context(), sess.ObjectGUID, in)
	if s.audit != nil {
		if err != nil {
			s.audit.Failure(sess.Username, "self.profile", sess.ObjectGUID, r.RemoteAddr, err)
		} else {
			s.audit.Success(sess.Username, "self.profile", sess.ObjectGUID, r.RemoteAddr)
		}
	}
	if err != nil {
		selfError(w, err)
		return
	}
	s.handleSelfGet(w, r)
}
func (s *Server) handleSelfPhotoGet(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	entry, err := s.svcs.Users.SelfEntry(r.Context(), sessionFrom(r).ObjectGUID)
	if err != nil {
		selfError(w, err)
		return
	}
	raw := entry.GetRawAttributeValue("thumbnailPhoto")
	if len(raw) == 0 {
		w.WriteHeader(404)
		return
	}
	photo, err := service.NormalizeSelfPhoto(raw)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(photo)
}
func (s *Server) handleSelfPhotoSet(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, (2<<20)+16384)
	if err := r.ParseMultipartForm(3 << 20); err != nil {
		selfError(w, fmt.Errorf("self.invalid-photo"))
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	var photo []byte
	if r.FormValue("remove") != "true" {
		f, _, err := r.FormFile("photo")
		if err != nil {
			selfError(w, fmt.Errorf("self.invalid-photo"))
			return
		}
		defer f.Close()
		photo, err = io.ReadAll(io.LimitReader(f, (2<<20)+1))
		if err != nil || len(photo) > 2<<20 {
			selfError(w, fmt.Errorf("self.invalid-photo"))
			return
		}
	}
	sess := sessionFrom(r)
	err := s.svcs.Users.SetSelfPhoto(r.Context(), sess.ObjectGUID, r.FormValue("revision"), photo)
	if s.audit != nil {
		if err != nil {
			s.audit.Failure(sess.Username, "self.photo", sess.ObjectGUID, r.RemoteAddr, err)
		} else {
			s.audit.Success(sess.Username, "self.photo", sess.ObjectGUID, r.RemoteAddr)
		}
	}
	if err != nil {
		selfError(w, err)
		return
	}
	s.handleSelfGet(w, r)
}
func (s *Server) handleSelfPassword(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	var in struct {
		Current  string `json:"current"`
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if !selfJSON(w, r, &in) {
		return
	}
	defer func() { in.Current = ""; in.Password = ""; in.Confirm = "" }()
	if in.Password != in.Confirm {
		selfError(w, fmt.Errorf("self.password-mismatch"))
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Users.ChangeSelfPassword(r.Context(), sess.ObjectGUID, s.cfg.LDAP, in.Current, in.Password)
	if s.audit != nil {
		if err != nil {
			s.audit.Failure(sess.Username, "self.password", sess.ObjectGUID, r.RemoteAddr, fmt.Errorf("self.password-change-failed"))
		} else {
			s.audit.Success(sess.Username, "self.password", sess.ObjectGUID, r.RemoteAddr)
		}
	}
	if err != nil {
		selfError(w, err)
		return
	}
	s.sessions.RevokeIdentity(sess.ObjectGUID)
	s.sessions.ClearCookie(w)
	writeJSON(w, 200, map[string]string{"status": "self.password-changed", "signIn": "/login"})
}
func (s *Server) handleSelfLocation(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	if _, err := s.svcs.Users.SelfEntry(r.Context(), sessionFrom(r).ObjectGUID); err != nil {
		selfError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip, _ := netip.ParseAddr(host)
	ip = ip.Unmap()
	out := map[string]any{"connectionIP": host, "site": "", "subnet": "", "ldapController": "", "ldapControllerSite": "", "siteControllers": []string{}, "warning": "self.site-context"}
	if c, err := s.ldap.Conn(ctx); err == nil {
		if root, e := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"dNSHostName"}, nil)); e == nil && len(root.Entries) == 1 {
			out["ldapController"] = root.Entries[0].GetAttributeValue("dNSHostName")
		}
	}
	subnets, err := s.svcs.Subnets.List(ctx)
	if err != nil {
		out["warning"] = "self.location-unavailable"
		writeJSON(w, 200, out)
		return
	}
	best := -1
	siteDN := ""
	for _, sub := range subnets {
		prefix, e := netip.ParsePrefix(sub.Name)
		if e == nil && prefix.Contains(ip) && prefix.Bits() > best {
			best = prefix.Bits()
			siteDN = sub.Site
			out["subnet"] = sub.Name
		}
	}
	sites, _ := s.svcs.Sites.List(ctx)
	for _, site := range sites {
		if strings.EqualFold(site.DN, siteDN) {
			out["site"] = site.Name
		}
	}
	dcs, _ := s.svcs.Sites.Controllers(ctx)
	names := []string{}
	for _, dc := range dcs {
		if strings.EqualFold(dc.DNS, out["ldapController"].(string)) {
			out["ldapControllerSite"] = dc.Site
		}
		if out["site"] != "" && dc.Site == out["site"] {
			names = append(names, dc.DNS)
		}
	}
	out["siteControllers"] = names
	writeJSON(w, 200, out)
}

type selfAuthEvent struct {
	service.RODCAuthEvent
	Controller string `json:"controller"`
}

// Only an immutable SID can disambiguate reused/renamed account names. Old
// helpers or audit events without a SID are not disclosed as personal history.
func ownAuthEvent(event service.RODCAuthEvent, sid string) bool {
	return strings.HasPrefix(sid, "S-1-") && strings.EqualFold(event.SID, sid)
}
func (s *Server) handleSelfHistory(w http.ResponseWriter, r *http.Request) {
	if !s.selfReady(w, r) {
		return
	}
	profile, err := s.svcs.Users.Self(r.Context(), sessionFrom(r).ObjectGUID)
	if err != nil {
		selfError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if !strings.HasPrefix(profile.SID, "S-1-") {
		writeJSON(w, 200, map[string]any{"events": []selfAuthEvent{}, "sources": []any{}, "warning": "self.audit-unavailable"})
		return
	}
	dcs, err := s.svcs.Sites.Controllers(ctx)
	if err != nil {
		selfError(w, err)
		return
	}
	limited := len(dcs) > 64
	if limited {
		dcs = dcs[:64]
	}
	events := []selfAuthEvent{}
	sources := []map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, dc := range dcs {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				sources = append(sources, map[string]string{"controller": host, "status": "unavailable"})
				mu.Unlock()
				return
			}
			defer func() { <-slots }()
			report, e := s.svcs.RODC.ControllerAuthentications(ctx, host, time.Now().Add(-7*24*time.Hour), "")
			mu.Lock()
			defer mu.Unlock()
			state := "unavailable"
			if e == nil && report != nil {
				state = report.Status
				for _, event := range report.Events {
					if event.SID == "" {
						state = "partial"
					}
					if ownAuthEvent(event, profile.SID) {
						events = append(events, selfAuthEvent{event, host})
					}
				}
			}
			sources = append(sources, map[string]string{"controller": host, "status": state})
		}(dc.DNS)
	}
	wg.Wait()
	sort.Slice(events, func(i, j int) bool { return events[i].Time.After(events[j].Time) })
	if len(events) > 100 {
		events = events[:100]
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i]["controller"] < sources[j]["controller"] })
	writeJSON(w, 200, map[string]any{"events": events, "sources": sources, "limited": limited, "warning": "self.audit-coverage"})
}

// Apply upload limits before CSRF middleware can parse a multipart form.
func selfRequestLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/me") && r.Method != "GET" && r.Method != "HEAD" {
			limit := int64(32 << 10)
			if r.URL.Path == "/api/v1/me/photo" {
				limit = (2 << 20) + 16384
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
