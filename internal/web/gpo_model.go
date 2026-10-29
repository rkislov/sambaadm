package web

import (
	"net/http"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPOModel(w http.ResponseWriter, r *http.Request) {
	var in service.GPModelInput
	if !topologyJSON(w, r, &in) {
		return
	}
	result, err := s.svcs.GPO.Model(r.Context(), in)
	topologyResult(w, result, err)
}

func (s *Server) handleAPIGPOExplain(w http.ResponseWriter, r *http.Request) {
	var in service.GPExplainInput
	if !topologyJSON(w, r, &in) {
		return
	}
	result, err := s.svcs.GPO.Explain(r.Context(), in)
	topologyResult(w, result, err)
}
