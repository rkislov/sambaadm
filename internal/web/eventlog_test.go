package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogLevelsAndNoRequestSecrets(t *testing.T) {
	old := slog.Default()
	defer slog.SetDefault(old)
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
		s := &Server{}
		for _, status := range []int{200, 403, 500} {
			r := httptest.NewRequest("POST", "/login?password=query-secret", strings.NewReader("password=body-secret"))
			r.Header.Set("Authorization", "Bearer header-secret")
			r.Header.Set("Cookie", "session=cookie-secret")
			s.requestLogger(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })).ServeHTTP(httptest.NewRecorder(), r)
		}
		log := buf.String()
		if strings.Contains(log, "secret") || !strings.Contains(log, "level=WARN") || !strings.Contains(log, "level=ERROR") || strings.Contains(log, "status=200") != (level == slog.LevelDebug) {
			t.Fatal(log)
		}
	}
}
