package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	smb2 "github.com/cloudsoda/go-smb2"
)

// Scripts are independent of ADMX/Registry.pol and can be inspected even when
// the ALT registry editor is disabled. No script is fetched or executed.
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
	Controller      string      `json:"controller"`
	Scripts         []GPOScript `json:"scripts"`
	MachineDisabled bool        `json:"machineDisabled"`
	UserDisabled    bool        `json:"userDisabled"`
}

func (s *GPOService) Scripts(ctx context.Context, gpo string) (*GPOScripts, error) {
	entry, err := s.policyEntry(ctx, gpo)
	if err != nil {
		return nil, err
	}
	base, err := s.policyPath(ctx, entry)
	if err != nil {
		return nil, err
	}
	if s.remote == nil {
		return nil, fmt.Errorf("SYSVOL service credentials are required")
	}
	out := &GPOScripts{Controller: s.remote.Host, Scripts: []GPOScript{}}
	flags, _ := strconv.ParseUint(entry.GetAttributeValue("flags"), 10, 32)
	out.MachineDisabled, out.UserDisabled = flags&2 != 0, flags&1 != 0
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		root := &smbPolicyStore{share: share, base: strings.ReplaceAll(base, `\`, "/")}
		var err error
		out.Scripts, err = readGPOScripts(root)
		return err
	})
	return out, err
}

func readGPOScripts(root policyStore) ([]GPOScript, error) {
	out := []GPOScript{}
	for _, scope := range []string{"Machine", "User"} {
		dir := "."
		missing := false
		for _, component := range []string{scope, "Scripts"} {
			var err error
			dir, err = policyChild(root, dir, component, false)
			if errors.Is(err, os.ErrNotExist) {
				missing = true
				break
			}
			if err != nil {
				return nil, err
			}
		}
		if missing {
			continue
		}
		for _, filename := range []string{"scripts.ini", "psscripts.ini"} {
			file, err := policyChild(root, dir, filename, false)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			data, err := readPolicyFile(root, file)
			if err != nil {
				return nil, err
			}
			rows, err := parseGPOScripts(data, scope, file)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			out = append(out, rows...)
		}
	}
	return out, nil
}

// MS-GPSCR 2.2.2/2.2.3 uses UTF-16LE with BOM; GPUI also writes UTF-8.
func parseGPOScripts(data []byte, scope, source string) ([]GPOScript, error) {
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) {
		data = data[2:]
		if len(data)%2 != 0 {
			return nil, fmt.Errorf("invalid UTF-16 scripts file")
		}
		chars := make([]uint16, len(data)/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(data[2*i:])
		}
		for i := 0; i < len(chars); i++ {
			if utf16.IsSurrogate(rune(chars[i])) {
				if chars[i] > 0xdbff || i+1 == len(chars) || chars[i+1] < 0xdc00 || chars[i+1] > 0xdfff {
					return nil, fmt.Errorf("invalid UTF-16 surrogate")
				}
				i++
			}
		}
		data = []byte(string(utf16.Decode(chars)))
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return nil, fmt.Errorf("unsupported scripts file encoding")
	}
	kind := "script"
	if strings.EqualFold(path.Base(source), "psscripts.ini") {
		kind = "PowerShell"
	}
	rows := map[string]map[int]map[string]string{}
	event := ""
	for _, line := range strings.Split(string(data), "\n") {
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
