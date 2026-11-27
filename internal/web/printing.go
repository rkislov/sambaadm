package web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) printingPage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanRead) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "printers/console.html", s.page(r, "nav.printers", map[string]any{
		"Module": "/printers", "BaseDN": s.cfg.LDAP.BaseDN, "Nodes": s.timePageNodes(),
	}))
}
func (s *Server) handlePrinting(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanRead) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	operation := chi.URLParam(r, "operation")
	if operation == "journal" && r.Method == "GET" {
		s.printingJournal(w, r)
		return
	}
	read := operation == "inspect" || operation == "models" || operation == "jobs" || operation == "windows.catalog" || operation == "install.status"
	if !read && !requireRole(w, r, auth.CanAdmin) {
		return
	}
	if !service.PrintingOperationAllowed(operation) || (r.Method == "GET" && !read) {
		writeJSON(w, 405, map[string]string{"error": "недопустимая операция печати"})
		return
	}
	input := map[string]any{}
	if r.Method == "POST" {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 68<<20))
		if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, 400, map[string]string{"error": "некорректный запрос печати"})
			return
		}
	} else {
		for _, key := range []string{"search", "sort", "id"} {
			input[key] = r.URL.Query().Get(key)
		}
		for _, key := range []string{"offset", "limit"} {
			if n, err := strconv.Atoi(r.URL.Query().Get(key)); err == nil {
				input[key] = n
			}
		}
		input["descending"] = r.URL.Query().Get("descending") == "true"
	}
	var out json.RawMessage
	session := sessionFrom(r)
	if s.svcs == nil {
		writeJSON(w, 409, map[string]string{"error": "helper недоступен"})
		return
	}
	err := service.PrintingCall(r.Context(), s.svcs.Helpers, r.URL.Query().Get("node"), operation, input, session.Username, r.RemoteAddr, &out)
	if !read && s.audit != nil {
		if err != nil {
			s.audit.Failure(session.Username, "printing."+operation, r.URL.Query().Get("node"), r.RemoteAddr, err)
		} else {
			s.audit.Success(session.Username, "printing."+operation, r.URL.Query().Get("node"), r.RemoteAddr)
		}
	}
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) printingJournal(w http.ResponseWriter, r *http.Request) {
	nodes := s.timePageNodes()
	if selected := r.URL.Query().Get("node"); selected != "" {
		nodes = []string{selected}
	}
	if len(nodes) > 64 {
		writeJSON(w, 400, map[string]string{"error": "выберите сервер; общий журнал ограничен 64 узлами за запрос"})
		return
	}
	if s.svcs == nil {
		writeJSON(w, 409, map[string]string{"error": "helper недоступен"})
		return
	}
	rows := []map[string]any{}
	errors := map[string]string{}
	var mutex sync.Mutex
	gate := make(chan struct{}, 4)
	var wg sync.WaitGroup
	session := sessionFrom(r)
	for _, node := range nodes {
		wg.Add(1)
		go func(node string) {
			defer wg.Done()
			select {
			case gate <- struct{}{}:
			case <-r.Context().Done():
				return
			}
			defer func() { <-gate }()
			var result struct {
				Rows []map[string]any `json:"rows"`
			}
			err := service.PrintingCall(r.Context(), s.svcs.Helpers, node, "jobs", nil, session.Username, r.RemoteAddr, &result)
			mutex.Lock()
			defer mutex.Unlock()
			if err != nil {
				errors[node] = err.Error()
				return
			}
			for _, row := range result.Rows {
				row["node"] = node
				rows = append(rows, row)
			}
		}(node)
	}
	wg.Wait()
	rows, archiveError := s.savePrintHistory(rows)
	if archiveError != "" {
		errors["Архив журнала"] = archiveError
	}
	if selected := r.URL.Query().Get("node"); selected != "" {
		filtered := rows[:0]
		for _, row := range rows {
			if row["node"] == selected {
				filtered = append(filtered, row)
			}
		}
		rows = filtered
	}
	search := strings.ToLower(r.URL.Query().Get("search"))
	printer, user, state := r.URL.Query().Get("printer"), r.URL.Query().Get("user"), r.URL.Query().Get("state")
	from, _ := time.Parse("2006-01-02", r.URL.Query().Get("from"))
	to, _ := time.Parse("2006-01-02", r.URL.Query().Get("to"))
	filtered := rows[:0]
	for _, row := range rows {
		if !from.IsZero() && number(row["created"]) < float64(from.Unix()) || !to.IsZero() && number(row["created"]) >= float64(to.Add(24*time.Hour).Unix()) {
			continue
		}
		if printer != "" && row["printer"] != printer || user != "" && row["user"] != user || state != "" && fmt.Sprint(row["state"]) != state {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(fmt.Sprint(row["node"], " ", row["printer"], " ", row["user"], " ", row["title"], " ", row["id"])), search) {
			continue
		}
		filtered = append(filtered, row)
	}
	sortKey := r.URL.Query().Get("sort")
	switch sortKey {
	case "created", "node", "id", "printer", "user", "title", "state", "pages":
	default:
		sortKey = "created"
	}
	descending := r.URL.Query().Get("descending") == "true"
	if r.URL.Query().Get("sort") == "" {
		descending = true
	}
	sort.Slice(filtered, func(i, j int) bool {
		a, b := filtered[i][sortKey], filtered[j][sortKey]
		less, equal := false, false
		switch sortKey {
		case "created", "id", "state", "pages":
			less = number(a) < number(b)
			equal = number(a) == number(b)
		default:
			as, bs := strings.ToLower(fmt.Sprint(a)), strings.ToLower(fmt.Sprint(b))
			less = as < bs
			equal = as == bs
		}
		if equal {
			return printHistoryKey(filtered[i]) < printHistoryKey(filtered[j])
		}
		if descending {
			return !less
		}
		return less
	})
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 250 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := min(len(filtered), offset+limit)
	writeJSON(w, 200, map[string]any{"rows": filtered[offset:end], "total": len(filtered), "offset": offset, "limit": limit, "errors": errors, "retention": "История CUPS: до 10000 заданий на узел. Общий архив панели: до 100000 наблюдавшихся заданий при настроенном server.settings_dir; сбор каждые 30 секунд"})
}
