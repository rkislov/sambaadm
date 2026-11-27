package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"sambaadm/internal/service"
)

type keaGSSPairPlan struct {
	Revision string                     `json:"revision"`
	Nodes    []string                   `json:"nodes"`
	Plans    map[string]json.RawMessage `json:"plans"`
}

// Shared HA credentials exist only during this request, inside the server and
// signed helper transports. Neither passwords nor keytabs enter the response.
func (s *Server) handleKeaGSSPair(w http.ResponseWriter, r *http.Request, req service.KeaRequest) {
	if req.GSS == nil || len(req.GSS.Members) != 2 || req.GSS.Members[0] == req.GSS.Members[1] {
		writeJSON(w, 400, map[string]string{"error": "укажите два различных узла HA"})
		return
	}
	nodes := append([]string(nil), req.GSS.Members...)
	sort.Strings(nodes)
	if r.URL.Query().Get("node") != nodes[0] && r.URL.Query().Get("node") != nodes[1] {
		writeJSON(w, 400, map[string]string{"error": "выбранный узел не входит в HA"})
		return
	}
	sess := sessionFrom(r)
	client := s.keaClient()
	call := func(node, method string, request service.KeaRequest) (json.RawMessage, error) {
		var result json.RawMessage
		err := client.Call(r.Context(), node, method, request, sess.Username, r.RemoteAddr, &result)
		return result, err
	}
	plan := keaGSSPairPlan{Nodes: nodes, Plans: map[string]json.RawMessage{}}
	for _, node := range nodes {
		raw, err := call(node, "kea.gss.ad.plan", req)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": node + ": " + err.Error()})
			return
		}
		plan.Plans[node] = raw
	}
	encoded, _ := json.Marshal(plan.Plans)
	hash := sha256.Sum256(encoded)
	plan.Revision = hex.EncodeToString(hash[:])
	if strings.HasSuffix(r.URL.Path, "/plan") {
		writeJSON(w, 200, plan)
		return
	}
	if !req.Confirm || req.Revision != plan.Revision {
		writeJSON(w, 409, map[string]string{"error": "подтвердите актуальный план общей DNS-идентичности HA"})
		return
	}
	var first struct {
		AccountState any    `json:"accountState"`
		Principal    string `json:"principal"`
		DomainGUID   string `json:"domainGUID"`
	}
	if json.Unmarshal(plan.Plans[nodes[0]], &first) != nil || first.Principal == "" {
		writeJSON(w, 409, map[string]string{"error": "некорректный план helper"})
		return
	}
	for _, node := range nodes {
		var identity struct {
			Principal  string `json:"principal"`
			DomainGUID string `json:"domainGUID"`
		}
		if json.Unmarshal(plan.Plans[node], &identity) != nil || identity.Principal != first.Principal || identity.DomainGUID != first.DomainGUID {
			writeJSON(w, 409, map[string]string{"error": "узлы HA относятся к разным доменам или учётным записям"})
			return
		}
	}
	if first.AccountState == nil || req.GSS.Rotate {
		secret := make([]byte, 48)
		if _, err := rand.Read(secret); err != nil {
			writeJSON(w, 500, map[string]string{"error": "не удалось создать ключ HA"})
			return
		}
		req.GSSSecret = "Aa1!" + hex.EncodeToString(secret)
		clear(secret)
	}
	profiles := map[string]json.RawMessage{}
	for index, node := range nodes {
		current := plan.Plans[node]
		if index > 0 {
			// First enrollment changes account KVNO and zone ACL revisions.
			var err error
			current, err = call(node, "kea.gss.ad.plan", req)
			if err != nil {
				writeJSON(w, 409, map[string]any{"error": fmt.Sprintf("%s: %v; предыдущий узел подготовлен; повторите план, при отсутствующем keytab выберите смену ключа всей пары", node, err), "profiles": profiles})
				return
			}
		}
		var own struct {
			Revision   string `json:"revision"`
			Principal  string `json:"principal"`
			DomainGUID string `json:"domainGUID"`
		}
		if json.Unmarshal(current, &own) != nil || own.Principal != first.Principal || own.DomainGUID != first.DomainGUID {
			writeJSON(w, 409, map[string]string{"error": "узлы HA относятся к разным доменам или учётным записям"})
			return
		}
		req.Revision = own.Revision
		req.GSSJoin = index > 0 && req.GSSSecret != ""
		result, err := call(node, "kea.gss.ad.apply", req)
		if err != nil {
			detail := err.Error()
			if req.GSSSecret != "" {
				detail = strings.ReplaceAll(detail, req.GSSSecret, "[скрыто]")
			}
			writeJSON(w, 409, map[string]any{"error": node + ": " + detail + "; при частичном выполнении сохранённые keytab не удаляются; повторите план пары", "profiles": profiles})
			return
		}
		profiles[node] = result
	}
	writeJSON(w, 200, map[string]any{"ready": true, "profiles": profiles})
}
