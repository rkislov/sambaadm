package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func API(verifier *Verifier, handler Handler) http.Handler {
	gate := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" || r.URL.Path != "/v1/execute" {
			http.NotFound(w, r)
			return
		}
		select {
		case gate <- struct{}{}:
			defer func() { <-gate }()
		default:
			http.Error(w, "helper is busy", http.StatusServiceUnavailable)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMessage))
		if e != nil {
			http.Error(w, "invalid helper message", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
		defer cancel()
		result := verifier.Dispatch(ctx, raw, handler)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}
func Stdio(ctx context.Context, r io.Reader, w io.Writer, v *Verifier, handler Handler) error {
	raw, e := ReadFrame(r)
	if e != nil {
		return e
	}
	result := v.Dispatch(ctx, raw, handler)
	encoded, e := json.Marshal(result)
	if e != nil {
		return e
	}
	return WriteFrame(w, encoded)
}
