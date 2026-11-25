package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"sambaadm/internal/agent"
	ldapproto "sambaadm/internal/ldap"
)

// A sync is a pull of GPO trees. No writes or helper calls go to its source.
// Each pair has its own optimistic token and recoverable repair transaction.
type SYSVOLSyncInput struct {
	Source   string   `json:"source"`
	Targets  []string `json:"targets"`
	Policies []string `json:"policies"`
}
type SYSVOLSyncItem struct {
	GPO                string   `json:"gpo"`
	Name               string   `json:"name"`
	Target             string   `json:"target"`
	State              string   `json:"state"`
	Message            string   `json:"message,omitempty"`
	Preview            string   `json:"-"`
	Signature          string   `json:"-"`
	TargetVersion      uint32   `json:"targetVersion"`
	TargetVersionKnown bool     `json:"targetVersionKnown"`
	VersionKnown       bool     `json:"versionKnown"`
	Version            uint32   `json:"version"`
	Changes            int      `json:"changes"`
	ACLChanges         int      `json:"aclChanges"`
	Paths              []string `json:"paths,omitempty"`
	ACLPaths           []string `json:"aclPaths,omitempty"`
	Record             string   `json:"record,omitempty"`
}
type SYSVOLSyncJob struct {
	ID       string           `json:"id"`
	Input    SYSVOLSyncInput  `json:"input"`
	State    string           `json:"state"`
	Revision string           `json:"revision"`
	Actor    string           `json:"actor"`
	IP       string           `json:"-"`
	Created  time.Time        `json:"created"`
	Updated  time.Time        `json:"updated"`
	Items    []SYSVOLSyncItem `json:"items"`
	Error    string           `json:"error,omitempty"`
}

// Private transport includes the tokens that public JSON deliberately omits.
type storedSYSVOLSync struct {
	Job        *SYSVOLSyncJob
	Tokens     []string
	Signatures []string
	IP         string
}
type sysvolSyncBaseline struct {
	Signature string
	Source    string
	Created   time.Time
}

func (s *GPOService) syncRoot() (*os.Root, error) {
	parent, e := s.delegationStateRoot()
	if e != nil {
		return nil, e
	}
	defer parent.Close()
	if e = parent.Mkdir("sysvol-sync", 0700); e != nil && !os.IsExist(e) {
		return nil, e
	}
	st, e := parent.Lstat("sysvol-sync")
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("Журнал SYSVOL требует отдельного каталога 0700")
	}
	return parent.OpenRoot("sysvol-sync")
}
func syncWrite(root *os.Root, name string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if len(raw) > 8<<20 {
		return fmt.Errorf("План превышает 8 МиБ; выберите меньше политик")
	}
	tmp := ".sync-" + uuid.NewString()
	f, e := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(tmp)
	_, e = f.Write(raw)
	e = errors.Join(e, f.Sync(), f.Close())
	if e != nil {
		return e
	}
	if e = root.Rename(tmp, name); e != nil {
		return e
	}
	dir, e := root.Open(".")
	if e != nil {
		return e
	}
	return errors.Join(dir.Sync(), dir.Close())
}
func syncRead(root *os.Root, name string, out any) error {
	st, e := root.Lstat(name)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 8<<20 {
		return fmt.Errorf("Некорректный защищённый журнал SYSVOL")
	}
	f, e := root.Open(name)
	if e != nil {
		return e
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 8<<20))
	if e = dec.Decode(out); e != nil {
		return e
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("Некорректный журнал SYSVOL")
	}
	return nil
}
func (s *GPOService) saveSync(j *SYSVOLSyncJob) error {
	s.sysvolSyncMu.Lock()
	defer s.sysvolSyncMu.Unlock()
	return s.saveSyncLocked(j)
}
func (s *GPOService) saveSyncLocked(j *SYSVOLSyncJob) error {
	root, e := s.syncRoot()
	if e != nil {
		return e
	}
	defer root.Close()
	j.Updated = time.Now().UTC()
	record := storedSYSVOLSync{Job: j, IP: j.IP}
	for _, i := range j.Items {
		record.Tokens = append(record.Tokens, i.Preview)
		record.Signatures = append(record.Signatures, i.Signature)
	}
	return syncWrite(root, j.ID+".json", record)
}
func (s *GPOService) readSyncLocked(id string) (*SYSVOLSyncJob, error) {
	if _, e := delegationRecordName(id); e != nil {
		return nil, e
	}
	root, e := s.syncRoot()
	if e != nil {
		return nil, e
	}
	defer root.Close()
	var record storedSYSVOLSync
	if e = syncRead(root, id+".json", &record); e != nil {
		return nil, e
	}
	j := record.Job
	if j == nil || j.ID != id || len(j.Items) != len(record.Tokens) || len(j.Items) != len(record.Signatures) {
		return nil, fmt.Errorf("Повреждён журнал SYSVOL")
	}
	for i := range j.Items {
		j.Items[i].Preview = record.Tokens[i]
		j.Items[i].Signature = record.Signatures[i]
	}
	j.IP = record.IP
	if (j.State == "planning" || j.State == "running") && !s.sysvolSyncRunning[id] {
		j.State = "interrupted"
		j.Error = "Процесс прерван. Перечитайте журнал восстановления GPO и подготовьте новый предпросмотр; доставка автоматически не повторяется."
		for i := range j.Items {
			if j.Items[i].State == "running" {
				j.Items[i].State = "unknown"
			}
		}
		if e = s.saveSyncLocked(j); e != nil {
			return nil, e
		}
	}
	return j, nil
}
func (s *GPOService) SYSVOLSyncRead(id string) (*SYSVOLSyncJob, error) {
	s.sysvolSyncMu.Lock()
	defer s.sysvolSyncMu.Unlock()
	return s.readSyncLocked(id)
}
func (s *GPOService) SYSVOLSyncHistory() ([]*SYSVOLSyncJob, error) {
	s.sysvolSyncMu.Lock()
	defer s.sysvolSyncMu.Unlock()
	root, e := s.syncRoot()
	if e != nil {
		return nil, e
	}
	defer root.Close()
	dir, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	defer dir.Close()
	entries, e := dir.ReadDir(-1)
	if e != nil {
		return nil, e
	}
	type candidate struct {
		id       string
		modified time.Time
	}
	list := []candidate{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if _, e := delegationRecordName(id); e != nil {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return nil, e
		}
		list = append(list, candidate{id, info.ModTime()})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].modified.After(list[j].modified) })
	if len(list) > 30 {
		list = list[:30]
	}
	out := []*SYSVOLSyncJob{}
	for _, c := range list {
		job, e := s.readSyncLocked(c.id)
		if e != nil {
			return nil, e
		}
		out = append(out, job)
	}
	return out, nil
}
func syncBaselineKey(gpo, target string) string { return strings.ToLower(gpo + "|" + target) }
func (s *GPOService) syncBaseline(gpo, target string) (string, error) {
	s.sysvolSyncMu.Lock()
	defer s.sysvolSyncMu.Unlock()
	root, e := s.syncRoot()
	if e != nil {
		return "", e
	}
	defer root.Close()
	all := map[string]sysvolSyncBaseline{}
	e = syncRead(root, "baselines.json", &all)
	if e != nil && !os.IsNotExist(e) {
		return "", e
	}
	return all[syncBaselineKey(gpo, target)].Signature, nil
}
func (s *GPOService) syncRemember(j *SYSVOLSyncJob, item SYSVOLSyncItem) error {
	s.sysvolSyncMu.Lock()
	defer s.sysvolSyncMu.Unlock()
	root, e := s.syncRoot()
	if e != nil {
		return e
	}
	defer root.Close()
	all := map[string]sysvolSyncBaseline{}
	if e = syncRead(root, "baselines.json", &all); e != nil && !os.IsNotExist(e) {
		return e
	}
	all[syncBaselineKey(item.GPO, item.Target)] = sysvolSyncBaseline{item.Signature, j.Input.Source, time.Now().UTC()}
	return syncWrite(root, "baselines.json", all)
}
func validateSyncInput(in SYSVOLSyncInput) error {
	if in.Source == "" || len(in.Targets) == 0 || len(in.Policies) == 0 || len(in.Targets) > 16 || len(in.Targets)*len(in.Policies) > 256 {
		return topologyBad("Выберите источник, политики и получателей: не более 16 DC и 256 пар GPO/DC за один запуск")
	}
	seen := map[string]bool{}
	for _, target := range in.Targets {
		k := strings.ToLower(target)
		if k == strings.ToLower(in.Source) || seen[k] || k == "" {
			return topologyBad("Источник и получатели должны различаться; повторы запрещены")
		}
		seen[k] = true
	}
	seen = map[string]bool{}
	for _, gpo := range in.Policies {
		if !looksLikeGUID(gpo) {
			return topologyBad("Некорректный GUID политики")
		}
		k := strings.ToLower(braceGUID(gpo))
		if seen[k] {
			return topologyBad("Политика выбрана повторно")
		}
		seen[k] = true
	}
	return nil
}
func (s *GPOService) SYSVOLSyncPlan(ctx context.Context, in SYSVOLSyncInput, actor, ip string) (*SYSVOLSyncJob, error) {
	if e := validateSyncInput(in); e != nil {
		return nil, e
	}
	controllers, e := (&SiteService{ldap: s.ldap}).Controllers(ctx)
	if e != nil {
		return nil, e
	}
	valid := map[string]Controller{}
	for _, dc := range controllers {
		valid[strings.ToLower(dc.DNS)] = dc
	}
	source, ok := valid[strings.ToLower(in.Source)]
	if !ok || source.RODC {
		return nil, topologyBad("Выберите обнаруженный записываемый исходный DC")
	}
	in.Source = source.DNS
	for i, target := range in.Targets {
		dc, ok := valid[strings.ToLower(target)]
		if !ok || s.helpers == nil || !s.helpers.Has(dc.DNS) {
			return nil, topologyBad("Для каждого получателя нужен зарегистрированный helper")
		}
		in.Targets[i] = dc.DNS
	}
	policies, e := s.List(ctx)
	if e != nil {
		return nil, e
	}
	names := map[string]string{}
	for _, p := range policies {
		names[strings.ToLower(braceGUID(p.GUID))] = p.DisplayName
	}
	j := &SYSVOLSyncJob{ID: uuid.NewString(), Input: in, State: "planning", Actor: actor, IP: ip, Created: time.Now().UTC(), Items: []SYSVOLSyncItem{}}
	for _, gpo := range in.Policies {
		gpo = braceGUID(gpo)
		name, ok := names[strings.ToLower(gpo)]
		if !ok {
			return nil, topologyBad("Политика не найдена в текущем домене")
		}
		for _, target := range in.Targets {
			j.Items = append(j.Items, SYSVOLSyncItem{GPO: gpo, Name: name, Target: target, State: "pending"})
		}
	}
	s.sysvolSyncMu.Lock()
	if len(s.sysvolSyncRunning) > 0 {
		s.sysvolSyncMu.Unlock()
		return nil, topologyBad("Уже выполняется подготовка или доставка SYSVOL. Дождитесь отчёта текущего задания.")
	}
	if s.sysvolSyncRunning == nil {
		s.sysvolSyncRunning = map[string]bool{}
	}
	s.sysvolSyncRunning[j.ID] = true
	e = s.saveSyncLocked(j)
	s.sysvolSyncMu.Unlock()
	if e != nil {
		s.endSync(j.ID)
		return nil, e
	}
	go s.runSyncPlan(j, ldapproto.CarryTLSProfile(agent.CarryCredentials(context.Background(), ctx), ctx))
	return s.SYSVOLSyncRead(j.ID)
}
func (s *GPOService) endSync(id string) {
	s.sysvolSyncMu.Lock()
	delete(s.sysvolSyncRunning, id)
	s.sysvolSyncMu.Unlock()
}
func syncPlanItem(item *SYSVOLSyncItem, p *RepairPlan, baseline string, err error) {
	if err != nil {
		item.State = "blocked"
		item.Message = syncError(err)
		return
	}
	item.Preview = p.Preview
	item.Signature = p.record.After.Signature
	item.Version, _ = snapshotVersion(p.record.After)
	item.VersionKnown = true
	if p.record.Before != nil {
		v, err := snapshotVersion(p.record.Before)
		if err == nil {
			item.TargetVersion = v
			item.TargetVersionKnown = true
		}
	}
	if p.record.Before != nil && baseline != "" && p.record.Before.Signature != baseline && p.record.Before.Signature != p.record.After.Signature {
		item.State = "conflict"
		item.Message = "Получатель изменён после последней синхронизации. Разберите изменения через свойства GPO и восстановление SYSVOL."
		return
	}
	item.Changes = len(p.Changes)
	item.ACLChanges = len(p.ACLChanges)
	for _, c := range p.Changes {
		if len(item.Paths) == 50 {
			break
		}
		item.Paths = append(item.Paths, syncKind(c.Kind)+": "+syncShortPath(c.Path))
	}
	for _, c := range p.ACLChanges {
		if len(item.ACLPaths) == 50 {
			break
		}
		item.ACLPaths = append(item.ACLPaths, syncShortPath(c.Path))
	}
	if len(p.Changes) == 0 {
		item.State = "identical"
		item.Message = "Версии, файлы, владельцы, группы и DACL совпадают"
	} else {
		item.State = "ready"
		item.Message = "Готово к синхронизации после подтверждения"
	}
}
func syncShortPath(p string) string {
	r := []rune(p)
	if len(r) > 250 {
		return string(r[:250]) + "…"
	}
	return p
}
func (s *GPOService) runSyncPlan(j *SYSVOLSyncJob, base context.Context) {
	defer s.endSync(j.ID)
	ctx, cancel := context.WithTimeout(base, 30*time.Minute)
	defer cancel()
	for i := range j.Items {
		item := &j.Items[i]
		item.State = "running"
		if e := s.saveSync(j); e != nil {
			return
		}
		p, e := s.RepairPreview(ctx, item.GPO, RepairInput{Operation: "repair", Source: j.Input.Source, Target: item.Target, WindowsSource: true})
		baseline, be := s.syncBaseline(item.GPO, item.Target)
		if be != nil {
			e = be
		}
		syncPlanItem(item, p, baseline, e)
		if e := s.saveSync(j); e != nil {
			return
		}
	}
	j.State = "planned"
	parts := []any{j.ID, j.Input}
	for _, i := range j.Items {
		parts = append(parts, []string{i.GPO, i.Target, i.State, i.Preview, i.Signature})
	}
	j.Revision = consistencyHash(parts)
	if e := s.saveSync(j); e != nil {
		return
	}
	s.audit.Success(j.Actor, "gpo.sysvol.sync.preview", j.ID, j.IP)
}
func (s *GPOService) SYSVOLSyncApply(ctx context.Context, id, revision, actor, ip string, confirm bool) (*SYSVOLSyncJob, error) {
	s.sysvolSyncMu.Lock()
	j, e := s.readSyncLocked(id)
	if e != nil {
		s.sysvolSyncMu.Unlock()
		return nil, e
	}
	if !confirm || j.State != "planned" || revision == "" || j.Revision != revision {
		s.sysvolSyncMu.Unlock()
		return nil, ErrTopologyConflict
	}
	if s.jobs == nil {
		s.jobs = newJobStore()
	}
	if e = s.jobs.reserveSYSVOL(); e != nil {
		s.sysvolSyncMu.Unlock()
		return nil, e
	}
	j.State = "running"
	j.Actor = actor
	j.IP = ip
	if s.sysvolSyncRunning == nil {
		s.sysvolSyncRunning = map[string]bool{}
	}
	s.sysvolSyncRunning[id] = true
	e = s.saveSyncLocked(j)
	s.sysvolSyncMu.Unlock()
	if e != nil {
		s.endSync(id)
		s.jobs.releaseSYSVOL()
		return nil, e
	}
	go s.runSyncApply(j, ldapproto.CarryTLSProfile(agent.CarryCredentials(context.Background(), ctx), ctx))
	return s.SYSVOLSyncRead(id)
}
func (s *GPOService) runSyncApply(j *SYSVOLSyncJob, base context.Context) {
	defer s.jobs.releaseSYSVOL()
	defer s.endSync(j.ID)
	ctx, cancel := context.WithTimeout(base, 30*time.Minute)
	defer cancel()
	for i := range j.Items {
		item := &j.Items[i]
		if item.State != "ready" && item.State != "identical" {
			continue
		}
		// Identical observations must also be rechecked, never trust an old preview.
		if item.State == "identical" {
			p, e := s.RepairPreview(ctx, item.GPO, RepairInput{Operation: "repair", Source: j.Input.Source, Target: item.Target, WindowsSource: true})
			if e != nil || p.Preview != item.Preview {
				item.State = "conflict"
				item.Message = "Источник или получатель изменился после предпросмотра"
			} else if e = s.syncRemember(j, *item); e != nil {
				item.State = "failed"
				item.Message = syncError(e)
			}
			if e := s.saveSync(j); e != nil {
				return
			}
			continue
		}
		item.State = "running"
		if e := s.saveSync(j); e != nil {
			return
		}
		out, e := s.RepairApply(ctx, item.GPO, RepairInput{Operation: "repair", Source: j.Input.Source, Target: item.Target, WindowsSource: true, Preview: item.Preview}, j.Actor, j.IP)
		if out != nil {
			item.Record = out.Record
		}
		if e != nil {
			item.State = "failed"
			item.Message = syncError(e)
			if errors.Is(e, ErrTopologyConflict) {
				item.State = "conflict"
			}
		} else if out == nil || out.State != "complete" {
			item.State = "unknown"
			item.Message = "Результат не подтверждён; откройте журнал восстановления GPO"
		} else {
			item.State = "applied"
			item.Message = "Файлы и права записаны, контрольный снимок получателя проверен"
			if e = s.syncRemember(j, *item); e != nil {
				item.State = "unknown"
				item.Message = "Доставка выполнена, но квитанция не сохранена: " + e.Error()
			}
		}
		if e := s.saveSync(j); e != nil {
			return
		}
	}
	j.State = "completed"
	for _, i := range j.Items {
		if i.State != "applied" && i.State != "identical" {
			j.State = "partial"
			break
		}
	}
	if e := s.saveSync(j); e != nil {
		return
	}
	if j.State == "completed" {
		s.audit.Success(j.Actor, "gpo.sysvol.sync.apply", j.ID, j.IP)
	} else {
		s.audit.Failure(j.Actor, "gpo.sysvol.sync.apply", j.ID, j.IP, errors.New("Часть пар GPO/DC не синхронизирована; проверьте отчёт"))
	}
}

func syncKind(kind string) string {
	if v, ok := map[string]string{"add": "Добавить", "remove": "Удалить", "content": "Содержимое", "type": "Тип объекта", "sysvol-acl": "Права"}[kind]; ok {
		return v
	}
	return "Изменение"
}
func syncError(err error) string {
	if errors.Is(err, ErrTopologyConflict) {
		return "Источник, получатель или LDAP изменились после предпросмотра. Подготовьте новый план."
	}
	text := err.Error()
	if len(text) > 3000 {
		text = text[:3000] + "…"
	}
	for key, message := range map[string]string{"source LDAP/GPT.INI versions differ": "На источнике не совпадают версии LDAP и GPT.INI; дождитесь завершения редактирования GPO", "source GPT.INI is missing": "На источнике отсутствует GPT.INI", "LDAP metadata, security or version differs": "LDAP, версия или права GPO ещё не совпадают на получателе; сначала проверьте репликацию AD", "recover pending": "Обнаружена незавершённая операция. Откройте журнал восстановления SYSVOL этой GPO"} {
		if strings.Contains(text, key) {
			return message
		}
	}
	return "Операция SYSVOL не подтверждена: " + text
}
