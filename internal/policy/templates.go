package policy

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
)

const SystemdKey = `Software\BaseALT\Policies\SystemdUnits`

type Definition struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Key   string `json:"key"`
	Value string `json:"value"`
	Scope string `json:"scope"`
}

// SystemdDefinitions reads the installed ALT templates instead of assuming a
// template version or redistributing the upstream template collection.
func SystemdDefinitions(path string) ([]Definition, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var raw struct {
		Policies []struct {
			Name    string `xml:"name,attr"`
			Class   string `xml:"class,attr"`
			Key     string `xml:"key,attr"`
			Value   string `xml:"valueName,attr"`
			Enabled struct {
				Decimal struct {
					Value string `xml:"value,attr"`
				} `xml:"decimal"`
			} `xml:"enabledValue"`
			Disabled struct {
				Decimal struct {
					Value string `xml:"value,attr"`
				} `xml:"decimal"`
			} `xml:"disabledValue"`
		} `xml:"policies>policy"`
	}
	if err = xml.NewDecoder(io.LimitReader(f, 2<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("read ALT ADMX: %w", err)
	}
	var out []Definition
	seen := map[string]bool{}
	for _, p := range raw.Policies {
		if p.Name == "" || p.Class != "Machine" || !strings.EqualFold(p.Key, SystemdKey) || p.Value == "" || !strings.HasSuffix(p.Value, ".service") || p.Enabled.Decimal.Value != "1" || p.Disabled.Decimal.Value != "0" {
			continue
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("duplicate ALT policy %q", p.Name)
		}
		seen[p.Name] = true
		out = append(out, Definition{p.Name, p.Value, p.Key, p.Value, p.Class})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no supported ALT systemd policies in installed template")
	}
	return out, nil
}
