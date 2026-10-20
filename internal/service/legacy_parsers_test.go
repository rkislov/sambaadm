package service

import "strings"

func splitDNSData(data string) []string {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return []string{data}
	}
	return fields
}
func parseDNSZoneList(stdout string) []DNSZone {
	var out []DNSZone
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		// Common: "pszZoneName                 : example.com"
		if i := strings.Index(trimmed, ":"); i >= 0 && (strings.Contains(lower, "zonename") || strings.Contains(lower, "psz")) {
			name := strings.TrimSpace(trimmed[i+1:])
			if name != "" {
				out = append(out, DNSZone{Name: name, Source: "samba-tool"})
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	// Fallback: simple one-zone-per-line output
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") {
			continue
		}
		if strings.Contains(line, " ") && !strings.Contains(line, ".") {
			continue
		}
		out = append(out, DNSZone{Name: line, Source: "samba-tool"})
	}
	return out
}
func parseGPOListAll(stdout string) []GPO {
	var out []GPO
	var cur GPO
	flush := func() {
		if cur.GUID != "" || cur.DisplayName != "" {
			cur.Source = "samba-tool"
			out = append(out, cur)
			cur = GPO{}
		}
	}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		lower := strings.ToLower(line)
		if i := strings.Index(line, ":"); i >= 0 {
			key := strings.ReplaceAll(strings.TrimSpace(lower[:i]), " ", "")
			val := strings.TrimSpace(line[i+1:])
			switch {
			case strings.Contains(key, "displayname"), key == "name":
				if cur.DisplayName != "" && cur.GUID != "" {
					flush()
				}
				cur.DisplayName = val
			case strings.Contains(key, "guid"), key == "gpo":
				if cur.GUID != "" && cur.DisplayName != "" {
					flush()
				}
				cur.GUID = val
			case strings.Contains(key, "dn"), strings.Contains(key, "path"):
				cur.DN = val
			}
			continue
		}
	}
	flush()
	return out
}
func parseFSMOShow(stdout string) []FSMORole {
	var out []FSMORole
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Typical: "SchemaMasterRole owner: CN=NTDS Settings,..."
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			out = append(out, FSMORole{Role: line, Source: "samba-tool"})
			continue
		}
		role := strings.TrimSpace(parts[0])
		role = strings.TrimSuffix(role, " owner")
		role = strings.TrimSuffix(role, " Role")
		out = append(out, FSMORole{
			Role:   strings.TrimSpace(role),
			Owner:  strings.TrimSpace(parts[1]),
			Source: "samba-tool",
		})
	}
	return out
}
