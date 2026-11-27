package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/credentials"
	ldapproto "sambaadm/internal/ldap"
)

func (s *Server) finishKerberosLogin(w http.ResponseWriter, r *http.Request) {
	identity := goidentity.FromHTTPRequestContext(r)
	creds, ok := identity.(*credentials.Credentials)
	if !ok || !creds.Authenticated() || creds.Domain() != s.cfg.Auth.SSO.Realm || len(creds.CName().NameString) != 1 || creds.UserName() == "" || strings.ContainsAny(creds.UserName(), "/\\\x00") || !creds.ValidUntil().After(time.Now()) {
		http.Error(w, "Не удалось подтвердить доменную учётную запись", 401)
		return
	}
	username := creds.UserName()
	if !strings.Contains(username, "@") {
		username += "@" + strings.ToLower(s.cfg.Auth.SSO.Realm)
	}
	ctx := ldapproto.WithInsecureTLS(ldapproto.WithLegacyCN(r.Context(), false), false)
	dn, role, guid, err := s.resolveLoginIdentity(ctx, s.ldap, username)
	if err != nil {
		s.auditSignIn(r, username, "login.kerberos.identity", "", "failure")
		http.Error(w, "Не удалось получить учётную запись из домена", 503)
		return
	}
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=user)", Attributes: []string{"userAccountControl", "accountExpires"}})
	if err == nil {
		var uac uint64
		uac, err = strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
		if err == nil && uac&2 != 0 {
			err = fmt.Errorf("domain account disabled")
		}
		expiry := entry.GetAttributeValue("accountExpires")
		if expiry != "" && expiry != "0" && expiry != "9223372036854775807" {
			ticks, e := strconv.ParseInt(expiry, 10, 64)
			if e != nil || time.Now().Unix() >= ticks/10000000-11644473600 {
				err = fmt.Errorf("domain account expired")
			}
		}
	}
	if err != nil {
		s.auditSignIn(r, username, "login.kerberos.account", role, "failure")
		http.Error(w, "Доменная учётная запись недоступна", 403)
		return
	}
	sess, err := s.sessions.Create(username, dn, role)
	if err != nil {
		s.auditSignIn(r, username, "login.kerberos.session", role, "failure")
		http.Error(w, "Не удалось создать сессию", 500)
		return
	}
	sess.ObjectGUID = guid
	sess.AuthMethod = "kerberos"
	if sess.ExpiresAt.After(creds.ValidUntil()) {
		sess.ExpiresAt = creds.ValidUntil()
	}
	s.sessions.SetCookie(w, sess, true)
	s.auditSignIn(r, username, "login.kerberos", role, "success")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
