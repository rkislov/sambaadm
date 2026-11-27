package service

import (
	"fmt"
	"strconv"
	"strings"
)

// The tree editor must not grant list/write access without directory search.
// Zero access and search-only grants remain possible. File permissions are
// deliberately checked separately: read-only files do not need execute bits.
func validateDirectorySearchInput(in SetACLInput) error {
	if in.Mode != "" {
		mode, err := strconv.ParseUint(strings.TrimSpace(in.Mode), 8, 32)
		if err != nil {
			return fmt.Errorf("неверный режим каталога: %w", err)
		}
		for shift := uint(0); shift <= 6; shift += 3 {
			bits := (mode >> shift) & 7
			if bits&6 != 0 && bits&1 == 0 {
				return fmt.Errorf("для чтения или записи каталога нужен проход x: используйте r-x/rwx (например, 0750 вместо 0640)")
			}
		}
	}
	var hasGrant, hasMask [2]bool
	var masks [2]int
	for _, source := range []struct {
		spec     string
		defaults bool
	}{{in.ACL, false}, {in.DefaultACL, true}} {
		for _, spec := range strings.Split(normalizeACLSpec(source.spec), ",") {
			if spec == "" {
				continue
			}
			scope := 0
			if source.defaults {
				scope = 1
			}
			if strings.HasPrefix(spec, "default:") {
				scope = 1
				spec = strings.TrimPrefix(spec, "default:")
			} else if strings.HasPrefix(spec, "d:") {
				scope = 1
				spec = strings.TrimPrefix(spec, "d:")
			}
			parts := strings.Split(spec, ":")
			if len(parts) < 2 || len(parts) > 3 {
				return fmt.Errorf("неверная запись ACL каталога")
			}
			kind := strings.ToLower(parts[0])
			perms := strings.TrimSpace(parts[len(parts)-1])
			bits := 0
			if number, err := strconv.ParseUint(perms, 8, 3); err == nil {
				bits = int(number)
			} else {
				for _, char := range strings.ToLower(perms) {
					if !strings.ContainsRune("rwx-", char) {
						return fmt.Errorf("неверные разрешения ACL каталога")
					}
				}
				bits = shareACLBits(strings.ToLower(perms))
			}
			switch kind {
			case "u", "user", "g", "group", "o", "other", "m", "mask":
			default:
				return fmt.Errorf("неверный тип записи ACL каталога")
			}
			if bits&6 != 0 && bits&1 == 0 {
				return fmt.Errorf("для доступа к папке нужен x: назначайте r-x/rwx; ACL-маска также должна сохранять проход")
			}
			if kind == "m" || kind == "mask" {
				hasMask[scope] = true
				masks[scope] = bits
			} else if bits&6 != 0 && (kind == "g" || kind == "group" || (kind == "u" || kind == "user") && len(parts) == 3 && parts[1] != "") {
				hasGrant[scope] = true
			}
		}
	}
	for scope := range hasGrant {
		if hasGrant[scope] && hasMask[scope] && masks[scope]&1 == 0 {
			return fmt.Errorf("ACL-маска убирает x у назначенных прав каталога; сохраните проход в маске")
		}
	}
	return nil
}

// Builder profiles used by the directory UI always include search when read or
// write is selected. Explicit textual ACL/mode input is validated, not changed.
func BuildDirectoryACLSpec(kind, name, perms string) (string, error) {
	if strings.ContainsAny(strings.ToLower(perms), "rw") {
		perms += "x"
	}
	return BuildACLSpec(kind, name, perms)
}
