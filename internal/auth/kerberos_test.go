package auth

import (
	"crypto/tls"
	"encoding/base64"
	"github.com/jcmturner/goidentity/v6"
	"github.com/jcmturner/gokrb5/v8/spnego"
	krbmessages "github.com/oiweiwei/gokrb5.fork/v9/messages"
	krbtypes "github.com/oiweiwei/gokrb5.fork/v9/types"
	"net/http"
	"net/http/httptest"
	"os"
	"sambaadm/internal/config"
	"sambaadm/internal/testkerberos"
	"strings"
	"testing"
	"time"
)

func TestKerberosHTTPProofAndReplayProtection(t *testing.T) {
	principal, realm := "HTTP/sambaadm.example.test", "EXAMPLE.TEST"
	kt, path := testkerberos.Keytab(t, principal, realm)
	cfg := config.SSOConfig{Enabled: true, Keytab: path, Principal: principal, Realm: realm}
	calls := 0
	h, err := KerberosHandler(cfg, "https://sambaadm.example.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := goidentity.FromHTTPRequestContext(r)
		if id == nil || !id.Authenticated() || id.UserName() != "alice" {
			t.Error("no proven user identity")
		}
		calls++
		w.WriteHeader(204)
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := func(token, url string, secure bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", url, nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		r.Header.Set("Authorization", token)
		r.Header.Set("X-Remote-User", "Administrator")
		r.Header.Set("X-Forwarded-User", "Administrator")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, token := range []string{"", "Negotiate garbage", "Basic QWRtaW46cGFzcw=="} {
		w := request(token, "https://sambaadm.example.test/auth/kerberos", true)
		if w.Code != 401 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("invalid credentials accepted: %d", w.Code)
		}
	}
	token := testkerberos.Token(t, kt, principal, realm, "alice", realm, time.Hour)
	if w := request(token, "http://sambaadm.example.test/auth/kerberos", false); w.Code != 400 {
		t.Fatal("SSO accepted over HTTP")
	}
	if w := request(token, "https://other.example.test/auth/kerberos", true); w.Code != 400 {
		t.Fatal("wrong hostname accepted")
	}
	w := request(token, "https://sambaadm.example.test/auth/kerberos", true)
	if w.Code != 204 {
		t.Fatal("valid ticket rejected", w.Code, w.Body)
	}
	input, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "Negotiate "))
	var sent spnego.KRB5Token
	if err = sent.Unmarshal(input); err != nil {
		t.Fatal(err)
	}
	if err = sent.APReq.Ticket.DecryptEncPart(kt, &sent.APReq.Ticket.SName); err != nil {
		t.Fatal(err)
	}
	sessionKey := sent.APReq.Ticket.DecryptedEncPart.Key
	if err = sent.APReq.DecryptAuthenticator(sessionKey); err != nil {
		t.Fatal(err)
	}
	output, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(w.Header().Get("WWW-Authenticate"), "Negotiate "))
	if err != nil {
		t.Fatal(err)
	}
	var reply spnego.KRB5Token
	if err = reply.Unmarshal(output); err != nil || !reply.IsAPRep() {
		t.Fatal("missing mutual-authentication response", err)
	}
	serverReply := krbmessages.APRep{EncPart: krbtypes.EncryptedData{EType: reply.APRep.EncPart.EType, KVNO: reply.APRep.EncPart.KVNO, Cipher: reply.APRep.EncPart.Cipher}}
	if err = serverReply.DecryptEncPart(krbtypes.EncryptionKey{KeyType: sessionKey.KeyType, KeyValue: sessionKey.KeyValue}); err != nil {
		t.Fatal("server did not prove the ticket session key", err)
	}
	if !serverReply.DecryptedEncPart.CTime.Equal(sent.APReq.Authenticator.CTime) || serverReply.DecryptedEncPart.Cusec != sent.APReq.Authenticator.Cusec {
		t.Fatal("AP_REP does not match the initiating authenticator")
	}
	if w := request(token, "https://sambaadm.example.test/auth/kerberos", true); w.Code != 401 {
		t.Fatal("replayed authenticator accepted", w.Code)
	}
	expired := testkerberos.Token(t, kt, principal, realm, "alice", realm, -time.Hour)
	if w := request(expired, "https://sambaadm.example.test/auth/kerberos", true); w.Code != 401 {
		t.Fatal("expired ticket accepted")
	}
	otherKT, _ := testkerberos.Keytab(t, "HTTP/other.example.test", realm)
	wrong := testkerberos.Token(t, otherKT, "HTTP/other.example.test", realm, "alice", realm, time.Hour)
	if w := request(wrong, "https://sambaadm.example.test/auth/kerberos", true); w.Code != 401 {
		t.Fatal("wrong service ticket accepted")
	}
	if calls != 1 {
		t.Fatal("unproven identity reached the session handler", calls)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadSSOKeytab(cfg); err == nil {
		t.Fatal("world-readable keytab accepted")
	}
}
