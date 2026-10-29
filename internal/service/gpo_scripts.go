package service

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Scripts are independent of ADMX/Registry.pol and can be inspected even when
// the ALT registry editor is disabled. The service never executes scripts.
type GPOScript struct {
	Scope      string `json:"scope"`
	Event      string `json:"event"`
	Kind       string `json:"kind"`
	Order      int    `json:"order"`
	Command    string `json:"command"`
	Parameters string `json:"parameters"`
	Source     string `json:"source"`
}

type GPOScripts struct {
	Controller      string           `json:"controller"`
	Scripts         []GPOScript      `json:"scripts"`
	MachineDisabled bool             `json:"machineDisabled"`
	UserDisabled    bool             `json:"userDisabled"`
	Revision        string           `json:"revision"`
	Version         uint32           `json:"version"`
	Files           []ScriptFileInfo `json:"files"`
	Backup          string           `json:"backup,omitempty"`
	BackupWarning   string           `json:"backupWarning,omitempty"`
}

// MS-GPSCR 2.2.2/2.2.3 uses UTF-16LE with BOM; GPUI also writes UTF-8.
func parseGPOScripts(data []byte, scope, source string) ([]GPOScript, error) {
	text, _, err := decodePolicyText(data)
	if err != nil {
		return nil, err
	}
	kind := "script"
	if strings.EqualFold(path.Base(source), "psscripts.ini") {
		kind = "PowerShell"
	}
	rows := map[string]map[int]map[string]string{}
	event := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			event = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if !((scope == "Machine" && (event == "startup" || event == "shutdown")) || (scope == "User" && (event == "logon" || event == "logoff"))) {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid script entry")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		field := "cmdline"
		if strings.HasSuffix(key, "parameters") {
			field = "parameters"
		} else if !strings.HasSuffix(key, field) {
			continue
		}
		index, err := strconv.ParseUint(strings.TrimSuffix(key, field), 10, 31)
		if err != nil {
			return nil, fmt.Errorf("invalid script index")
		}
		if rows[event] == nil {
			rows[event] = map[int]map[string]string{}
		}
		if rows[event][int(index)] == nil {
			rows[event][int(index)] = map[string]string{}
		}
		if _, duplicate := rows[event][int(index)][field]; duplicate {
			return nil, fmt.Errorf("duplicate script entry")
		}
		rows[event][int(index)][field] = strings.TrimSpace(value)
	}
	out := []GPOScript{}
	for _, event := range []string{"startup", "shutdown", "logon", "logoff"} {
		indices := []int{}
		for index := range rows[event] {
			indices = append(indices, index)
		}
		sort.Ints(indices)
		for _, index := range indices {
			entry := rows[event][index]
			if entry["cmdline"] == "" {
				return nil, fmt.Errorf("script %d has no command", index)
			}
			out = append(out, GPOScript{Scope: scope, Event: event, Kind: kind, Order: index, Command: entry["cmdline"], Parameters: entry["parameters"], Source: source})
		}
	}
	return out, nil
}
