package filecluster

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var restoreSnapshot = regexp.MustCompile(`^sambaadm_[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[0-9]{2}\.[0-9]{2}\.[0-9]{2}$`)

// RestoreInput addresses one path within the named snapshot's data dataset.
type RestoreInput struct {
	ClusterReadInput
	RequestID    string `json:"requestID"`
	Snapshot     string `json:"snapshot"`
	Path         string `json:"path"`
	Offset       int    `json:"offset,omitempty"`
	Overwrite    bool   `json:"overwrite,omitempty"`
	PlanRevision string `json:"planRevision,omitempty"`
	Confirm      bool   `json:"confirm,omitempty"`
}

func (in RestoreInput) Validate(action string) error {
	if err := in.ClusterReadInput.Validate(); err != nil {
		return err
	}
	if !validJob.MatchString(in.RequestID) || !restoreSnapshot.MatchString(in.Snapshot) {
		return fmt.Errorf("выберите именной снимок")
	}
	if in.Path != "" {
		parts := strings.Split(in.Path, "/")
		if len(in.Path) > 2048 || len(parts) > 48 || !utf8.ValidString(in.Path) ||
			strings.Contains(in.Path, "\\") || strings.ContainsFunc(in.Path, unicode.IsControl) {
			return fmt.Errorf("нужен относительный путь внутри ресурса")
		}
		for _, part := range parts {
			if part == "" || len(part) > 255 || part == "." || part == ".." || strings.EqualFold(part, ".zfs") {
				return fmt.Errorf("недопустимый компонент пути")
			}
		}
	}
	if action == "browse" {
		if in.Offset < 0 || in.Offset > 50000 {
			return fmt.Errorf("недопустимая страница каталога")
		}
		return nil
	}
	if in.Path == "" {
		return fmt.Errorf("выберите отдельный файл или папку")
	}
	if action == "apply" && (!in.Confirm || !revisionID.MatchString(in.PlanRevision)) {
		return fmt.Errorf("подтвердите актуальный предпросмотр")
	}
	return nil
}
