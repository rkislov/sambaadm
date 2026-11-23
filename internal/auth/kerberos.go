package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/jcmturner/gokrb5/v8/keytab"
	"sambaadm/internal/config"
)

// LoadSSOKeytab accepts only the configured HTTP service's keys, never a DC's
// complete keytab. Ticket names are checked by decryption against these entries.
func LoadSSOKeytab(cfg config.SSOConfig) (*keytab.Keytab, error) {
	if !filepath.IsAbs(cfg.Keytab) {
		return nil, fmt.Errorf("auth.sso.keytab must be an absolute path")
	}
	if cfg.Realm == "" || cfg.Realm != strings.ToUpper(cfg.Realm) || strings.ContainsAny(cfg.Realm, "/\\@ \t\r\n") {
		return nil, fmt.Errorf("auth.sso.realm must be an uppercase Kerberos realm")
	}
	if !strings.HasPrefix(cfg.Principal, "HTTP/") || strings.ContainsAny(cfg.Principal, "@ \\?\t\r\n") || strings.Count(cfg.Principal, "/") != 1 {
		return nil, fmt.Errorf("auth.sso.principal must be HTTP/FQDN without realm")
	}
	st, err := os.Lstat(cfg.Keytab)
	if err != nil {
		return nil, fmt.Errorf("SSO keytab: %w", err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0027 != 0 || st.Size() > 128<<10 {
		return nil, fmt.Errorf("SSO keytab must be a private regular file (0600 or 0640), at most 128 KiB")
	}
	data, err := os.ReadFile(cfg.Keytab)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	kt := keytab.New()
	if err = kt.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("invalid HTTP keytab: %w", err)
	}
	if len(kt.Entries) == 0 {
		return nil, fmt.Errorf("HTTP keytab is empty")
	}
	for _, entry := range kt.Entries {
		if strings.Join(entry.Principal.Components, "/") != cfg.Principal || entry.Principal.Realm != cfg.Realm {
			return nil, fmt.Errorf("keytab must contain only %s@%s; export that principal separately", cfg.Principal, cfg.Realm)
		}
	}
	return kt, nil
}
func KerberosHandler(cfg config.SSOConfig, publicURL string, inner http.Handler, certificates ...[]byte) (http.Handler, error) {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("SSO requires server.public_url=https://FQDN")
	}
	if cfg.Principal != "HTTP/"+strings.ToLower(u.Hostname()) {
		return nil, fmt.Errorf("SSO principal must match the HTTPS hostname")
	}
	kt, err := LoadSSOKeytab(cfg)
	if err != nil {
		return nil, err
	}
	var certDER []byte
	if len(certificates) > 0 {
		certDER = certificates[0]
	}
	wrapped := kerberosHTTP(kt, inner, certDER)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Vary", "Authorization, Cookie")
		w.Header().Set("X-Frame-Options", "DENY")
		requestURL, err := url.Parse("https://" + r.Host)
		port := func(v *url.URL) string {
			if v.Port() == "" {
				return "443"
			}
			return v.Port()
		}
		if r.TLS == nil || err != nil || !strings.EqualFold(requestURL.Hostname(), u.Hostname()) || port(requestURL) != port(u) {
			http.Error(w, "Для доменного входа откройте "+u.String(), http.StatusBadRequest)
			return
		}
		if len(r.Header.Get("Authorization")) > 64<<10 {
			http.Error(w, "Превышен размер билета Negotiate", http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		wrapped.ServeHTTP(w, r)
	}), nil
}
