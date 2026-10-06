package web

import (
	"context"
	"net/http"

	"sambaadm/internal/i18n"
)

const (
	langCookie = "sambaadm_lang"
	langKey    ctxKey = 2
)

func (s *Server) withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := i18n.RU
		if c, err := r.Cookie(langCookie); err == nil {
			lang = i18n.Normalize(c.Value)
		} else if al := r.Header.Get("Accept-Language"); al != "" {
			lang = i18n.Normalize(al)
		}
		ctx := context.WithValue(r.Context(), langKey, lang)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func langFrom(r *http.Request) i18n.Lang {
	if v, ok := r.Context().Value(langKey).(i18n.Lang); ok {
		return v
	}
	return i18n.RU
}

func setLangCookie(w http.ResponseWriter, lang i18n.Lang, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     langCookie,
		Value:    string(lang),
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}
