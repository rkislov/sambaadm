package web

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/agent"
	"sambaadm/internal/auth"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

func TestKeaGSSPairSharedSecretNeverReturnsToBrowser(t *testing.T) {
	s := testWorkspaceServer(t)
	dir := t.TempDir()
	key, pub := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if err := agent.GenerateKey(key, pub); err != nil {
		t.Fatal(err)
	}
	client := &agent.Client{Config: agent.Config{PrivateKey: key}}
	nodes := []string{"dhcp1.example.test", "dhcp2.example.test"}
	enrollments := map[string]string{}
	applied := 0
	for _, node := range nodes {
		verifier, err := agent.NewVerifier(node, []string{pub})
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(agent.API(verifier, func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
			var operation service.HostOperation
			if err := json.Unmarshal(raw, &operation); err != nil {
				return nil, err
			}
			encoded, _ := json.Marshal(operation.Input)
			var request service.KeaRequest
			json.Unmarshal(encoded, &request)
			switch method {
			case "kea.gss.ad.plan":
				return map[string]any{"revision": fmt.Sprintf("%s-%d", node, applied), "principal": "kea-shared@EXAMPLE.TEST", "keytab": "/etc/kea/ddns.keytab"}, nil
			case "kea.gss.ad.apply":
				if request.GSSSecret == "" || len(request.GSSSecret) < 48 {
					t.Error("missing shared enrollment secret")
				}
				if node == nodes[1] && !request.GSSJoin {
					t.Error("partner would rotate the password instead of enrolling")
				}
				enrollments[node] = request.GSSSecret
				applied++
				return map[string]any{"ready": true, "principal": "kea-shared@EXAMPLE.TEST"}, nil
			}
			return nil, fmt.Errorf("unexpected operation %s", method)
		}))
		t.Cleanup(server.Close)
		ca := filepath.Join(dir, node+".pem")
		os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
		client.Config.Nodes = append(client.Config.Nodes, agent.Node{Name: node, Transport: "https", Endpoint: server.URL, CACert: ca})
	}
	s.svcs = service.NewWithOptions(ldapproto.NewClient(s.cfg.LDAP), nil, service.ServiceOptions{Helpers: client})
	sess, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	send := func(path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path+"?node="+nodes[0], strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		req.Header.Set(csrfHeader, sess.CSRFToken)
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		return rec
	}
	request := service.KeaRequest{Family: "4", GSS: &service.KeaGSSSettings{Controller: "dc.example.test", Members: nodes}, DDNS: &service.KeaDDNSSettings{}}
	encoded, _ := json.Marshal(request)
	preview := send("/api/v1/dhcp/gss/ad/pair/plan", string(encoded))
	if preview.Code != 200 {
		t.Fatal(preview.Body.String())
	}
	var plan keaGSSPairPlan
	json.Unmarshal(preview.Body.Bytes(), &plan)
	request.Revision = plan.Revision
	request.Confirm = true
	encoded, _ = json.Marshal(request)
	result := send("/api/v1/dhcp/gss/ad/pair/apply", string(encoded))
	if result.Code != 200 {
		t.Fatal(result.Body.String())
	}
	if enrollments[nodes[0]] == "" || enrollments[nodes[0]] != enrollments[nodes[1]] {
		t.Fatal("different secrets on HA members")
	}
	if strings.Contains(result.Body.String(), enrollments[nodes[0]]) || strings.Contains(result.Body.String(), "gssSecret") {
		t.Fatal("shared password exposed")
	}
	request.GSSSecret = "browser-must-not-supply-this"
	encoded, _ = json.Marshal(request)
	if result := send("/api/v1/dhcp/gss/ad/pair/apply", string(encoded)); result.Code != 400 {
		t.Fatal("browser supplied internal enrollment parameters")
	}
}
