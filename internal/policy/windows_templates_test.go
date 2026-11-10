package policy

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestWindowsUTF16ResourcesAndReadOnlyUnsupportedMappings(t *testing.T) {
	source := `<?xml version="1.0" encoding="utf-16"?><policyDefinitions><policies><policy name="Example" class="Machine" key="Software\Policies\Microsoft\Example" valueName="Enabled" displayName="$(string.name)"><enabledValue><decimal value="1"/></enabledValue><disabledValue><decimal value="0"/></disabledValue></policy></policies></policyDefinitions>`
	labels := `<?xml version="1.0" encoding="utf-16"?><policyDefinitionResources><resources><stringTable><string id="name">Политика Windows</string></stringTable></resources></policyDefinitionResources>`
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		encode := func(s string) []byte {
			units := utf16.Encode([]rune(s))
			out := make([]byte, 2+2*len(units))
			order.PutUint16(out, 0xfeff)
			for i, u := range units {
				order.PutUint16(out[2+2*i:], u)
			}
			return out
		}
		defs, e := ParseADMX("WindowsExample.admx", encode(source), encode(labels))
		if e != nil || len(defs) != 1 || defs[0].Label != "Политика Windows" || defs[0].Unsupported != "" {
			t.Fatalf("UTF16 or explicit mapping failed: %+v %v", defs, e)
		}
		data := strings.ReplaceAll(strings.ReplaceAll(source, `<enabledValue><decimal value="1"/></enabledValue>`, ""), `<disabledValue><decimal value="0"/></disabledValue>`, "")
		defs, e = ParseADMX("WindowsExample.admx", encode(data), encode(labels))
		if e != nil || len(defs) != 1 || defs[0].Unsupported == "" {
			t.Fatal("ALT default encodings inferred for a Windows template", e)
		}
		if _, e = ApplySetting(defs[0], nil, "enabled", nil); e == nil {
			t.Fatal("unsupported definition became writable")
		}
	}
	if _, e := ParseADMX("bad.admx", []byte{0xff, 0xfe, 0, 0xd8}, nil); e == nil {
		t.Fatal("malformed UTF16 accepted")
	}
}
