package web

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

type timePageContent struct {
	Nodes    []string
	Node     string
	Status   *service.TimeStatus
	Settings service.TimeSettings
	Sources  string
	Allow    string
	Plan     *service.TimePlan
}

func (s *Server) timeClient() service.TimeService {
	c := service.TimeService{Audit: s.audit}
	if s.svcs != nil {
		c.Helpers = s.svcs.Helpers
	}
	return c
}
func (s *Server) timePageNodes() []string {
	var nodes []string
	c := s.timeClient()
	if c.Helpers != nil {
		cfg, e := c.Helpers.Configuration()
		if e != nil {
			return nil
		}
		for _, n := range cfg.Nodes {
			nodes = append(nodes, n.Name)
		}
	}
	return nodes
}
func lines(value string) []string {
	var out []string
	for _, v := range strings.Split(value, "\n") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func (s *Server) handleTimeSettings(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	pd := s.page(r, "Настройки времени", nil)
	c := timePageContent{Nodes: s.timePageNodes(), Settings: service.TimeSettings{Mode: "isolated", Stratum: 10}}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if r.ParseForm() != nil {
			http.Error(w, "invalid form", 400)
			return
		}
	}
	c.Node = r.FormValue("node")
	if c.Node == "" && len(c.Nodes) > 0 {
		c.Node = c.Nodes[0]
	}
	client := s.timeClient()
	if r.Method == http.MethodGet {
		if c.Node != "" {
			var status service.TimeStatus
			if e := client.Call(r.Context(), c.Node, "time.inspect", service.TimeRequest{}, sessionFrom(r).Username, r.RemoteAddr, &status); e != nil {
				pd.Error = e.Error()
			} else {
				c.Status = &status
				c.Settings = status.Settings
			}
		}
	} else {
		stratum, e := strconv.Atoi(r.FormValue("stratum"))
		if e != nil {
			http.Error(w, "invalid stratum", 400)
			return
		}
		c.Settings = service.TimeSettings{Mode: r.FormValue("mode"), Stratum: stratum, LocalReference: r.FormValue("localReference") == "true", Sources: lines(r.FormValue("sources")), Allow: lines(r.FormValue("allow"))}
		req := service.TimeRequest{Settings: c.Settings, Revision: r.FormValue("revision"), ProposedRevision: r.FormValue("proposedRevision"), Confirm: r.FormValue("confirm") == "true"}
		switch r.FormValue("action") {
		case "plan":
			var plan service.TimePlan
			if e := client.Call(r.Context(), c.Node, "time.plan", req, sessionFrom(r).Username, r.RemoteAddr, &plan); e != nil {
				pd.Error = e.Error()
			} else {
				c.Plan = &plan
			}
		case "apply":
			var result service.TimeApplyResult
			if e := client.Call(r.Context(), c.Node, "time.apply", req, sessionFrom(r).Username, r.RemoteAddr, &result); e != nil {
				pd.Error = e.Error()
			} else {
				c.Status = result.Status
				pd.Flash = "Настройки записаны, служба перезапущена. Резервная копия: " + result.Backup + ". Проверьте фактическую синхронизацию."
			}
		default:
			http.Error(w, "invalid action", 400)
			return
		}
	}
	c.Sources = strings.Join(c.Settings.Sources, "\n")
	c.Allow = strings.Join(c.Settings.Allow, "\n")
	pd.Content = c
	s.render(w, "settings/time.html", pd)
}
func (s *Server) handleAPITime(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	node := r.URL.Query().Get("node")
	client := s.timeClient()
	sess := sessionFrom(r)
	var out any
	if r.Method == http.MethodGet {
		v := &service.TimeStatus{}
		if e := client.Call(r.Context(), node, "time.inspect", service.TimeRequest{}, sess.Username, r.RemoteAddr, v); e != nil {
			writeJSON(w, 409, map[string]string{"error": e.Error()})
			return
		}
		out = v
	} else {
		var in service.TimeRequest
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, 400, map[string]string{"error": "invalid time request"})
			return
		}
		method := "time.plan"
		if r.Method == http.MethodPut {
			method = "time.apply"
			out = &service.TimeApplyResult{}
		} else {
			out = &service.TimePlan{}
		}
		if e := client.Call(r.Context(), node, method, in, sess.Username, r.RemoteAddr, out); e != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": e.Error()})
			return
		}
	}
	writeJSON(w, 200, out)
}
