package web

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

type backupPageContent struct {
	RestorePlan *service.DomainRestorePlan
	RestoreJob  *service.DomainRestoreJob
	RestoreNode string
	Backups     []service.ObjectBackupSummary
	Snapshot    *service.ObjectBackup
	Plan        *service.ObjectRestorePlan
	FullPlans   []service.DomainBackupRequest
	FullPlan    *service.DomainBackupRequest
	FullJob     *service.DomainBackupJob
	Nodes       []string
}

func (s *Server) objectBackupClient() *service.ObjectBackupService {
	var gpo *service.GPOService
	if s.svcs != nil {
		gpo = s.svcs.GPO
	}
	return service.NewObjectBackupService(s.ldap, gpo, s.cfg.Server.BackupDir, s.audit)
}
func (s *Server) handleObjectBackups(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	pd := s.page(r, "Резервные копии домена", nil)
	content := backupPageContent{Nodes: s.fullBackupNodes(), RestoreNode: r.FormValue("restoreNode")}
	full := s.fullBackupClient()
	fullID := r.FormValue("full")
	client := s.objectBackupClient()
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		s.backupMu.Lock()
		switch r.FormValue("action") {
		case "domain-restore-plan":
			input := service.DomainRestoreInput{BackupID: r.FormValue("backupID"), NewName: r.FormValue("newName"), Address: r.FormValue("address")}
			var plan service.DomainRestorePlan
			if err := s.callDomainRestore(r, content.RestoreNode, "domain.restore.plan", input, &plan); err != nil {
				pd.Error = err.Error()
			} else {
				content.RestorePlan = &plan
			}
		case "domain-restore-start":
			input := service.DomainRestoreInput{ID: r.FormValue("restoreID"), Revision: r.FormValue("restoreRevision"), ConfirmDomainLost: r.FormValue("confirmDomainLost") == "true", ConfirmIsolated: r.FormValue("confirmIsolated") == "true"}
			var job service.DomainRestoreJob
			if err := s.callDomainRestore(r, content.RestoreNode, "domain.restore.start", input, &job); err != nil {
				pd.Error = err.Error()
			} else {
				content.RestoreJob = &job
				pd.Flash = "Задача восстановления отправлена. Дождитесь ready; запуск службы выполняется вручную."
			}
		case "full-prepare":
			out, err := full.Prepare(r.Context(), r.FormValue("controller"), sessionFrom(r).Username, r.RemoteAddr)
			if err != nil {
				pd.Error = err.Error()
			} else {
				content.FullPlan = out
				fullID = out.ID
				pd.Flash = "Подготовка сохранена. Остановите Samba на выбранном DC, затем запустите полную копию."
			}
		case "full-start":
			fullID = r.FormValue("full")
			if r.FormValue("confirmStopped") != "true" {
				pd.Error = "Подтвердите остановку Samba на выбранном контроллере"
			} else {
				out, err := full.Start(r.Context(), fullID, r.FormValue("revision"), sessionFrom(r).Username, r.RemoteAddr)
				if err != nil {
					pd.Error = err.Error()
				} else {
					content.FullJob = out
					pd.Flash = "Задача полного копирования отправлена helper. Проверьте статус и результат пробного восстановления."
				}
			}
		case "create":
			snapshot, err := client.Create(r.Context(), sessionFrom(r).Username, r.RemoteAddr)
			if err != nil {
				pd.Error = err.Error()
			} else {
				content.Snapshot = snapshot
				pd.Flash = "Снимок сохранён: " + snapshot.ID
			}
		case "restore":
			if r.FormValue("confirm") != "true" {
				pd.Error = "Подтвердите восстановление показанного объекта"
			} else if err := client.Restore(r.Context(), r.FormValue("id"), r.FormValue("guid"), r.FormValue("revision"), sessionFrom(r).Username, r.RemoteAddr); err != nil {
				pd.Error = err.Error()
			} else {
				pd.Flash = "Объект восстановлен. Проверьте права, пароль или доверие АРМ; для GPO настройте привязки."
			}
		default:
			pd.Error = "Неизвестная операция"
		}
		s.backupMu.Unlock()
	}
	id := r.FormValue("id")
	if content.Snapshot != nil {
		id = content.Snapshot.ID
	}
	if id != "" {
		snapshot, err := client.Load(id)
		if err != nil {
			pd.Error = err.Error()
		} else {
			content.Snapshot = snapshot
		}
		if guid := r.FormValue("guid"); guid != "" && r.Method == http.MethodGet {
			plan, err := client.Preview(r.Context(), id, guid)
			if err != nil {
				pd.Error = err.Error()
			} else {
				content.Plan = plan
			}
		}
	}
	if fullID != "" {
		p, err := full.Load(fullID)
		if err != nil {
			pd.Error = err.Error()
		} else {
			content.FullPlan = p
		}
		if r.Method == http.MethodGet && r.FormValue("status") == "true" {
			job, err := full.Status(r.Context(), fullID)
			if err != nil {
				pd.Error = err.Error()
			} else {
				content.FullJob = job
			}
		}
	}
	if restoreID := r.FormValue("restoreID"); restoreID != "" && r.Method == http.MethodGet {
		var job service.DomainRestoreJob
		if err := s.callDomainRestore(r, content.RestoreNode, "domain.restore.status", service.DomainRestoreInput{ID: restoreID}, &job); err != nil {
			pd.Error = err.Error()
		} else {
			content.RestoreJob = &job
		}
	}
	plans, planErr := full.List()
	if planErr != nil {
		if pd.Error == "" {
			pd.Error = planErr.Error()
		}
	} else {
		content.FullPlans = plans
	}
	backups, err := client.List()
	if err != nil {
		pd.Error = err.Error()
	} else {
		content.Backups = backups
	}
	pd.Content = content
	s.render(w, "backups.html", pd)
}
func (s *Server) handleAPIObjectBackups(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	client := s.objectBackupClient()
	id := chi.URLParam(r, "id")
	guid := chi.URLParam(r, "guid")
	fail := func(err error) { writeJSON(w, 400, map[string]string{"error": err.Error()}) }
	if r.Method == http.MethodGet {
		if id == "" {
			out, err := client.List()
			if err != nil {
				fail(err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		if guid != "" {
			out, err := client.Preview(r.Context(), id, guid)
			if err != nil {
				fail(err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		out, err := client.Load(id)
		if err != nil {
			fail(err)
			return
		}
		if r.URL.Query().Get("download") == "true" {
			data, err := client.Export(id)
			if err != nil {
				fail(err)
				return
			}
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, id))
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
			return
		}
		// Inventory omits potentially large policy files and profile data.
		items := make([]map[string]string, 0, len(out.Objects))
		for _, o := range out.Objects {
			items = append(items, map[string]string{"guid": o.GUID, "dn": o.DN, "name": o.Name, "kind": o.Kind})
		}
		writeJSON(w, 200, map[string]any{"backup": out.Summary(), "objects": items})
		return
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if id == "" {
		out, err := client.Create(r.Context(), sessionFrom(r).Username, r.RemoteAddr)
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 201, out.Summary())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var in struct {
		Revision string `json:"revision"`
		Confirm  bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !in.Confirm {
		writeJSON(w, 400, map[string]string{"error": "revision and confirm:true required"})
		return
	}
	if err := client.Restore(r.Context(), id, guid, in.Revision, sessionFrom(r).Username, r.RemoteAddr); err != nil {
		fail(err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "restored"})
}
