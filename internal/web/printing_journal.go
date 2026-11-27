package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"sambaadm/internal/service"
)

type printingJournalStore struct {
	mu       sync.Mutex
	loaded   bool
	rows     map[string]map[string]any
	writeErr string
	blocked  bool
	dirty    bool
}

func (s *Server) savePrintHistory(incoming []map[string]any) ([]map[string]any, string) {
	h := &s.printingHistory
	h.mu.Lock()
	defer h.mu.Unlock()
	path := ""
	if s.cfg.Server.SettingsDir != "" {
		path = filepath.Join(s.cfg.Server.SettingsDir, "printing-journal.json")
	}
	if !h.loaded {
		h.rows = map[string]map[string]any{}
		if path != "" {
			if raw, err := os.ReadFile(path); err == nil {
				if len(raw) > 64<<20 {
					h.writeErr = "архив журнала больше 64 МиБ"
				} else {
					var stored []map[string]any
					if json.Unmarshal(raw, &stored) != nil {
						h.writeErr = "не удалось прочитать архив журнала"
					} else {
						for _, row := range stored {
							h.rows[printHistoryKey(row)] = row
						}
					}
				}
			} else if !os.IsNotExist(err) {
				h.writeErr = err.Error()
			}
		}
		h.blocked = h.writeErr != ""
		h.loaded = true
	}
	changed := false
	for _, row := range incoming {
		key := printHistoryKey(row)
		previous := h.rows[key]
		if number(previous["state"]) >= 7 && number(row["state"]) < 7 {
			continue
		}
		a, _ := json.Marshal(previous)
		b, _ := json.Marshal(row)
		if string(a) != string(b) {
			h.rows[key] = row
			changed = true
		}
	}
	rows := make([]map[string]any, 0, len(h.rows))
	for _, row := range h.rows {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return number(rows[i]["created"]) > number(rows[j]["created"]) })
	if len(rows) > 100000 {
		for _, row := range rows[100000:] {
			delete(h.rows, printHistoryKey(row))
		}
		rows = rows[:100000]
		changed = true
	}
	h.dirty = h.dirty || changed
	if path != "" && h.dirty && !h.blocked {
		raw, err := json.Marshal(rows)
		if err == nil && len(raw) > 64<<20 {
			err = fmt.Errorf("журнал превышает 64 МиБ")
		}
		if err == nil {
			err = os.MkdirAll(filepath.Dir(path), 0700)
		}
		if err == nil {
			var file *os.File
			file, err = os.CreateTemp(filepath.Dir(path), ".printing-journal-")
			if err == nil {
				temporary := file.Name()
				defer os.Remove(temporary)
				if err = file.Chmod(0600); err == nil {
					_, err = file.Write(raw)
				}
				if err == nil {
					err = file.Sync()
				}
				closeErr := file.Close()
				if err == nil {
					err = closeErr
				}
				if err == nil {
					err = os.Rename(temporary, path)
				}
			}
		}
		if err == nil {
			directory, openErr := os.Open(filepath.Dir(path))
			if openErr == nil {
				err = directory.Sync()
				directory.Close()
			} else {
				err = openErr
			}
		}
		if err != nil {
			h.writeErr = err.Error()
		} else {
			h.writeErr = ""
			h.dirty = false
		}
	}
	return rows, h.writeErr
}
func number(value any) float64 {
	switch n := value.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		result, _ := n.Float64()
		return result
	}
	return 0
}
func printHistoryKey(row map[string]any) string {
	return fmt.Sprint(row["node"], "|", row["id"], "|", row["created"])
}

// Collect independently of open browsers so queue deletion does not erase an
// already-observed print history. CUPS itself retains jobs between collections.
func (s *Server) MonitorPrinting(ctx context.Context) {
	if s.cfg.Server.SettingsDir == "" || s.svcs == nil || s.svcs.Helpers == nil {
		return
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		cfg, err := s.svcs.Helpers.Configuration()
		if err == nil {
			var rows []map[string]any
			var mutex sync.Mutex
			var wg sync.WaitGroup
			gate := make(chan struct{}, 4)
			for _, node := range cfg.Nodes {
				wg.Add(1)
				go func(name string) {
					defer wg.Done()
					select {
					case gate <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-gate }()
					bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
					defer cancel()
					var result struct {
						Rows []map[string]any `json:"rows"`
					}
					if service.PrintingCall(bounded, s.svcs.Helpers, name, "jobs", nil, "printing-monitor", "", &result) != nil {
						return
					}
					mutex.Lock()
					defer mutex.Unlock()
					for _, row := range result.Rows {
						row["node"] = name
						rows = append(rows, row)
					}
				}(node.Name)
			}
			wg.Wait()
			s.savePrintHistory(rows)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
