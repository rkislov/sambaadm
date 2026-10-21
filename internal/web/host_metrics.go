package web

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) handleAPIHostMetrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, s.monitor.Snapshot(ctx))
}
