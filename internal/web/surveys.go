package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) surveyPage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "surveys.html", s.page(r, "nav.diagnostics", nil))
}

func (s *Server) surveyDir() (string, error) {
	dir := s.cfg.Server.SurveyDir
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("absolute survey directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("private survey directory required")
	}
	return dir, nil
}

type surveyEntry struct {
	ID       string    `json:"id"`
	Imported time.Time `json:"imported"`
}

func surveyID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == sha256.Size && id == strings.ToLower(id)
}

func (s *Server) surveysAPI(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	dir, err := s.surveyDir()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "survey storage unavailable"})
		return
	}
	if r.Method == http.MethodPost {
		s.importSurvey(w, r, dir)
		return
	}
	if id := chi.URLParam(r, "id"); id != "" {
		if !surveyID(id) {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(filepath.Join(dir, id+".json"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, f)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "cannot list surveys"})
		return
	}
	list := []surveyEntry{}
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || !surveyID(id) || !entry.Type().IsRegular() {
			continue
		}
		st, err := entry.Info()
		if err != nil {
			continue
		}
		list = append(list, surveyEntry{id, st.ModTime().UTC()})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Imported.After(list[j].Imported) })
	writeJSON(w, 200, list)
}
func (s *Server) importSurvey(w http.ResponseWriter, r *http.Request, dir string) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, service.SurveyLimit))
	if err != nil {
		var limit *http.MaxBytesError
		code := 400
		if errors.As(err, &limit) {
			code = 413
		}
		writeJSON(w, code, map[string]string{"error": "cannot read import (maximum 16 MiB)"})
		return
	}
	q := r.URL.Query()
	m, err := service.ParseSurvey(r.Context(), q.Get("format"), q.Get("node"), q.Get("site"), data)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	record, err := json.Marshal(m)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid material"})
		return
	}
	id := fmt.Sprintf("%x", sha256.Sum256(record))
	name := filepath.Join(dir, id+".json")
	s.surveyMu.Lock()
	defer s.surveyMu.Unlock()
	if _, err = os.Stat(name); err == nil {
		writeJSON(w, 200, map[string]string{"id": id})
		return
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "cannot access survey storage"})
		return
	}
	if len(files) >= 128 {
		writeJSON(w, 409, map[string]string{"error": "survey storage limit reached (128 files)"})
		return
	}
	f, err := os.CreateTemp(dir, ".import-*")
	if err == nil {
		defer os.Remove(f.Name())
		_, err = f.Write(record)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Link(f.Name(), name)
		}
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "cannot save survey"})
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "survey.import", id, r.RemoteAddr)
	}
	writeJSON(w, 201, map[string]string{"id": id})
}
