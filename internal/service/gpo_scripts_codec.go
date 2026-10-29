package service

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"sambaadm/internal/policy"
)

func decodePolicyText(data []byte) (string, bool, error) {
	wide := bytes.HasPrefix(data, []byte{0xff, 0xfe})
	if wide {
		data = data[2:]
		if len(data)%2 != 0 {
			return "", wide, fmt.Errorf("invalid UTF-16 policy file")
		}
		chars := make([]uint16, len(data)/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(data[2*i:])
		}
		for i := 0; i < len(chars); i++ {
			if utf16.IsSurrogate(rune(chars[i])) {
				if chars[i] > 0xdbff || i+1 == len(chars) || chars[i+1] < 0xdc00 || chars[i+1] > 0xdfff {
					return "", wide, fmt.Errorf("invalid UTF-16 surrogate")
				}
				i++
			}
		}
		data = []byte(string(utf16.Decode(chars)))
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return "", wide, fmt.Errorf("unsupported policy file encoding")
	}
	return string(data), wide, nil
}

func encodePolicyText(text string, wide bool) []byte {
	if !wide {
		return []byte(text)
	}
	data := []byte{0xff, 0xfe}
	for _, ch := range utf16.Encode([]rune(text)) {
		data = binary.LittleEndian.AppendUint16(data, ch)
	}
	return data
}

var scriptIndexedKey = regexp.MustCompile(`^[0-9]+(.*)$`)
var windowsScriptDevice = regexp.MustCompile(`^(COM|LPT)[1-9]$`)

// Replace one event, retaining comments, other events, Script(s)Config and
// unknown non-indexed metadata. Numbered foreign fields cannot safely follow a
// reordered command, so refuse those instead of silently assigning them anew.
func patchScriptINI(data []byte, scope, event, kind string, entries []ScriptAssignment) ([]byte, error) {
	text, _, err := decodePolicyText(data)
	if err != nil {
		return nil, err
	}
	if _, err = parseGPOScripts(data, scope, scriptININame(kind)); err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	start, end, inside := -1, len(lines), false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			if inside {
				end = i
				inside = false
			}
			if strings.EqualFold(strings.TrimSpace(trim[1:len(trim)-1]), event) {
				if start >= 0 {
					return nil, fmt.Errorf("%w: duplicate script section", policy.ErrInvalidValue)
				}
				start = i
				inside = true
			}
		}
	}
	generated := []string{"[" + scriptEventTitle(event) + "]"}
	if start >= 0 {
		for _, line := range lines[start+1 : end] {
			key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok {
				if match := scriptIndexedKey.FindStringSubmatch(strings.TrimSpace(key)); match != nil {
					if !strings.EqualFold(match[1], "CmdLine") && !strings.EqualFold(match[1], "Parameters") {
						return nil, fmt.Errorf("%w: unsupported numbered script metadata %s", policy.ErrInvalidValue, key)
					}
					continue
				}
			}
			generated = append(generated, line)
		}
	}
	for i, entry := range entries {
		generated = append(generated, strconv.Itoa(i)+"CmdLine="+entry.Command, strconv.Itoa(i)+"Parameters="+entry.Parameters)
	}
	if start < 0 {
		lines = append(lines, generated...)
	} else {
		lines = append(append(append([]string{}, lines[:start]...), generated...), lines[end:]...)
	}
	// Both GPUI's INI plugin and gpupdate use UTF-16LE. CmdLine must precede
	// Parameters because the ALT client constructs its script at CmdLine.
	return encodePolicyText(strings.Join(lines, "\r\n")+"\r\n", true), nil
}

func scriptEventTitle(event string) string {
	return map[string]string{"startup": "Startup", "shutdown": "Shutdown", "logon": "Logon", "logoff": "Logoff"}[event]
}
func scriptININame(kind string) string {
	if kind == "PowerShell" {
		return "psscripts.ini"
	}
	return "scripts.ini"
}

type ScriptAssignment struct {
	Command    string `json:"command"`
	Parameters string `json:"parameters"`
}

type ScriptFileChange struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type ScriptChange struct {
	Revision string             `json:"revision"`
	Scope    string             `json:"scope"`
	Event    string             `json:"event"`
	Kind     string             `json:"kind"`
	Entries  []ScriptAssignment `json:"entries"`
	Files    []ScriptFileChange `json:"files,omitempty"`
}

func validateScriptChange(in ScriptChange) error {
	bad := func() error { return fmt.Errorf("%w: invalid script change", policy.ErrInvalidValue) }
	if in.Revision == "" || len(in.Revision) > 128 || (in.Kind != "script" && in.Kind != "PowerShell") || !validScriptEvent(in.Scope, in.Event) || in.Entries == nil || len(in.Entries) > 128 || len(in.Files) > 32 {
		return bad()
	}
	for _, entry := range in.Entries {
		if strings.TrimSpace(entry.Command) == "" || entry.Command != strings.TrimSpace(entry.Command) || len(utf16.Encode([]rune(entry.Command))) >= 260 || len(entry.Parameters) > 8192 || !utf8.ValidString(entry.Command+entry.Parameters) || strings.ContainsAny(entry.Command+entry.Parameters, "\x00\r\n") {
			return bad()
		}
	}
	seen := map[string]bool{}
	total := 0
	for _, f := range in.Files {
		if !validScriptFilename(f.Name) || seen[strings.ToLower(f.Name)] || len(f.Data) > 2<<20 || f.Data == nil {
			return bad()
		}
		seen[strings.ToLower(f.Name)] = true
		total += len(f.Data)
	}
	if total > 4<<20 {
		return bad()
	}
	return nil
}

func validScriptEvent(scope, event string) bool {
	return (scope == "Machine" && (event == "startup" || event == "shutdown")) || (scope == "User" && (event == "logon" || event == "logoff"))
}
func validScriptFilename(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 200 || name != strings.TrimSpace(name) || strings.HasSuffix(name, ".") || strings.ContainsAny(name, "/\\:\x00\r\n<>\"|?*") || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 32 {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "CONIN$" || base == "CONOUT$" || base == "PRN" || base == "AUX" || base == "NUL" || windowsScriptDevice.MatchString(base) {
		return false
	}
	return true
}
