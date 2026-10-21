package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

var ErrInvalidValue = errors.New("invalid policy value")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidValue, fmt.Sprintf(format, args...))
}
func decodeString(r Record) (string, bool) {
	if r.Type != 1 || len(r.Data) < 2 || len(r.Data)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(r.Data)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(r.Data[2*i:])
	}
	if u[len(u)-1] != 0 {
		return "", false
	}
	u = u[:len(u)-1]
	for i := 0; i < len(u); i++ {
		if u[i] == 0 {
			return "", false
		}
		if utf16.IsSurrogate(rune(u[i])) {
			if u[i] < 0xd800 || u[i] > 0xdbff || i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", false
			}
			i++
		}
	}
	return string(utf16.Decode(u)), true
}
func matches(r Record, v *Literal) bool {
	return v != nil && r.Type == v.Type && bytes.Equal(r.Data, v.Data)
}
func states(d Definition) (*Literal, *Literal) {
	a, b := d.Enabled, d.Disabled
	if a == nil {
		a = dwordLiteral(1)
	}
	if b == nil {
		b = dwordLiteral(0)
	}
	return a, b
}
func target(r Record, key, value string) bool {
	return strings.EqualFold(r.Key, key) && (strings.EqualFold(r.Name, value) || strings.EqualFold(r.Name, "**del."+value))
}
func owns(d Definition, r Record) bool {
	if d.Value != "" && target(r, d.Key, d.Value) {
		return true
	}
	for _, f := range d.Fields {
		if f.Kind == "list" {
			if strings.EqualFold(r.Key, f.Key) {
				return true
			}
		} else if target(r, f.Key, f.Value) {
			return true
		}
	}
	return false
}
func deleted(r Record) bool {
	if !strings.HasPrefix(strings.ToLower(r.Name), "**del.") {
		return false
	}
	s, ok := decodeString(r)
	return ok && (s == " " || s == "")
}
func fieldValue(f Field, r Record) (any, bool) {
	switch f.Kind {
	case "boolean":
		if matches(r, f.True) {
			return true, true
		}
		if matches(r, f.False) {
			return false, true
		}
	case "enum":
		for i, c := range f.Choices {
			if matches(r, &c.Value) {
				return strconv.Itoa(i), true
			}
		}
	case "decimal":
		if r.Type == 4 && len(r.Data) == 4 {
			n := uint64(binary.LittleEndian.Uint32(r.Data))
			if n >= f.Min && n <= f.Max {
				return strconv.FormatUint(n, 10), true
			}
		}
	case "text":
		v, ok := decodeString(r)
		return v, ok && len(utf16.Encode([]rune(v))) <= f.MaxLength
	}
	return nil, false
}

// SettingState never interprets unrecognized owned records as defaults.
func SettingState(d Definition, records []Record) (string, map[string]any) {
	values := map[string]any{}
	for _, f := range d.Fields {
		values[f.ID] = f.Default
		if f.Kind == "list" {
			values[f.ID] = []string{}
		}
	}
	if d.Unsupported != "" {
		return "unsupported", values
	}
	active, disabled := 0, 0
	seen := map[string]bool{}
	en, dis := states(d)
	for _, r := range records {
		if !owns(d, r) {
			continue
		}
		key := strings.ToLower(r.Key + "\x00" + r.Name)
		if seen[key] {
			return "unsupported", values
		}
		seen[key] = true
		if d.Value != "" && target(r, d.Key, d.Value) {
			if deleted(r) || matches(r, dis) {
				disabled++
			} else if matches(r, en) {
				active++
			} else {
				return "unsupported", values
			}
			continue
		}
		for _, f := range d.Fields {
			if f.Kind == "list" && strings.EqualFold(f.Key, r.Key) {
				if deleted(r) {
					disabled++
					continue
				}
				v, ok := decodeString(r)
				if !ok || v == "" || strings.HasPrefix(r.Name, "**") || r.Name != v {
					return "unsupported", values
				}
				values[f.ID] = append(values[f.ID].([]string), v)
				active++
				continue
			}
			if f.Kind != "list" && target(r, f.Key, f.Value) {
				if deleted(r) {
					disabled++
					continue
				}
				v, ok := fieldValue(f, r)
				if !ok {
					return "unsupported", values
				}
				values[f.ID] = v
				active++
			}
		}
	}
	if active > 0 && disabled > 0 {
		return "unsupported", values
	}
	if active > 0 {
		return "enabled", values
	}
	if disabled > 0 {
		return "disabled", values
	}
	return "not-configured", values
}
func fieldRecords(f Field, raw json.RawMessage) ([]Record, error) {
	one := func(v *Literal) []Record { return []Record{{Key: f.Key, Name: f.Value, Type: v.Type, Data: v.Data}} }
	switch f.Kind {
	case "boolean":
		var b bool
		if e := json.Unmarshal(raw, &b); e != nil || string(raw) == "null" {
			return nil, invalid("%s requires a boolean", f.ID)
		}
		if b {
			return one(f.True), nil
		}
		return one(f.False), nil
	case "enum", "decimal", "text":
		var v string
		if e := json.Unmarshal(raw, &v); e != nil || string(raw) == "null" {
			return nil, invalid("%s requires a string", f.ID)
		}
		if strings.ContainsRune(v, 0) {
			return nil, invalid("NUL in %s", f.ID)
		}
		switch f.Kind {
		case "enum":
			i, e := strconv.Atoi(v)
			if e != nil || i < 0 || i >= len(f.Choices) {
				return nil, invalid("unknown choice for %s", f.ID)
			}
			return one(&f.Choices[i].Value), nil
		case "decimal":
			n, e := strconv.ParseUint(v, 10, 32)
			if e != nil || n < f.Min || n > f.Max {
				return nil, invalid("%s must be between %d and %d", f.ID, f.Min, f.Max)
			}
			return one(dwordLiteral(uint32(n))), nil
		case "text":
			if len(utf16.Encode([]rune(v))) > f.MaxLength || (f.Required && v == "") {
				return nil, invalid("%s has invalid length", f.ID)
			}
			return one(stringLiteral(v)), nil
		}
	case "list":
		var values []string
		if e := json.Unmarshal(raw, &values); e != nil || string(raw) == "null" || len(values) > 1024 {
			return nil, invalid("%s requires a list of at most 1024 entries", f.ID)
		}
		seen := map[string]bool{}
		var out []Record
		for _, v := range values {
			if v == "" || strings.ContainsAny(v, "\x00\r\n") || strings.HasPrefix(v, "**") || len(utf16.Encode([]rune(v))) > 16380 || seen[strings.ToLower(v)] {
				return nil, invalid("invalid or duplicate list entry in %s", f.ID)
			}
			seen[strings.ToLower(v)] = true
			lit := stringLiteral(v)
			out = append(out, Record{Key: f.Key, Name: v, Type: lit.Type, Data: lit.Data})
		}
		return out, nil
	}
	return nil, invalid("unsupported field %s", f.Kind)
}

// ApplySetting replaces only the records owned by this template definition.
func ApplySetting(d Definition, records []Record, state string, values map[string]json.RawMessage) ([]Record, error) {
	if d.Unsupported != "" {
		return nil, invalid("%s", d.Unsupported)
	}
	if state != "enabled" && state != "disabled" && state != "not-configured" {
		return nil, invalid("unknown state")
	}
	if old, _ := SettingState(d, records); old == "unsupported" {
		return nil, invalid("existing setting has unsupported type or value; use GPUI")
	}
	known := map[string]bool{}
	for _, f := range d.Fields {
		known[f.ID] = true
	}
	for id := range values {
		if !known[id] {
			return nil, invalid("unknown element %s", id)
		}
	}
	var out []Record
	for _, r := range records {
		if !owns(d, r) {
			out = append(out, r)
		}
	}
	if state == "not-configured" {
		return out, nil
	}
	if d.Value != "" {
		en, dis := states(d)
		v := en
		if state == "disabled" {
			v = dis
		}
		out = append(out, Record{Key: d.Key, Name: d.Value, Type: v.Type, Data: v.Data})
	}
	for _, f := range d.Fields {
		if state == "enabled" {
			raw, ok := values[f.ID]
			if !ok {
				return nil, invalid("missing element %s", f.ID)
			}
			rs, e := fieldRecords(f, raw)
			if e != nil {
				return nil, e
			}
			out = append(out, rs...)
			continue
		}
		del := func(name string) {
			lit := stringLiteral(" ")
			out = append(out, Record{Key: f.Key, Name: "**del." + name, Type: lit.Type, Data: lit.Data})
		}
		if f.Kind == "list" {
			for _, r := range records {
				if strings.EqualFold(r.Key, f.Key) {
					name := r.Name
					if strings.HasPrefix(strings.ToLower(name), "**del.") {
						name = name[6:]
					}
					del(name)
				}
			}
		} else {
			del(f.Value)
		}
	}
	if actual, _ := SettingState(d, out); actual != state {
		return nil, invalid("empty list has no stored state; select not-configured or add values")
	}
	return out, nil
}
