package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const catalogFixture = `<policyDefinitions><policies>
<policy name="complex" class="Both" key="Software\BaseALT\Test" displayName="$(string.title)" presentation="$(presentation.form)"><elements>
<enum id="choice" valueName="Mode"><item displayName="One"><value><string>one</string></value></item><item displayName="Two"><value><decimal value="2"/></value></item></enum>
<decimal id="number" valueName="Number" minValue="8" maxValue="64"/>
<text id="text" valueName="Text" required="true" maxLength="20"/>
<boolean id="flag" key="Software\BaseALT\Locks" valueName="Flag"><trueValue><decimal value="1"/></trueValue><falseValue><decimal value="0"/></falseValue></boolean>
<list id="list" key="Software\BaseALT\Test\List" additive="true"/>
</elements></policy>
<policy name="future" class="Machine" key="Software\BaseALT\Future"><elements><multiText id="x" valueName="x"/></elements></policy>
</policies></policyDefinitions>`
const catalogLabels = `<policyDefinitionResources><resources><stringTable><string id="title">Настройка &lt;script&gt;</string></stringTable><presentationTable><presentation id="form"><decimalTextBox refId="number" defaultValue="14">Длина:</decimalTextBox><textBox refId="text"><label>Текст:</label><defaultValue>пример</defaultValue></textBox></presentation></presentationTable></resources></policyDefinitionResources>`

func rawValues(v map[string]any) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, value := range v {
		out[k], _ = json.Marshal(value)
	}
	return out
}
func TestCatalogTypedRoundTrip(t *testing.T) {
	defs, e := ParseADMX("BaseALTTest.admx", []byte(catalogFixture), []byte(catalogLabels))
	if e != nil {
		t.Fatal(e)
	}
	if len(defs) != 3 || defs[0].Scope != "Machine" || defs[1].Scope != "User" || defs[0].Label != "Настройка <script>" || defs[2].Unsupported == "" {
		t.Fatalf("catalog %+v", defs)
	}
	d := defs[0]
	if d.Fields[1].Default != "14" || d.Fields[2].Label != "Текст:" {
		t.Fatal("ADML presentation lost")
	}
	foreign := Record{Key: "Other", Name: "Preserve", Type: 3, Data: []byte{1, 2, 3}}
	values := map[string]any{"choice": "1", "number": "14", "text": "Пример 😀", "flag": false, "list": []string{"pkg-a", "pkg-b"}}
	rs, e := ApplySetting(d, []Record{foreign}, "enabled", rawValues(values))
	if e != nil {
		t.Fatal(e)
	}
	pol, e := Encode(rs)
	if e != nil {
		t.Fatal(e)
	}
	rs, e = Parse(pol)
	if e != nil {
		t.Fatal(e)
	}
	state, got := SettingState(d, rs)
	if state != "enabled" || got["text"] != values["text"] || got["choice"] != "1" || got["flag"] != false {
		t.Fatalf("state %s %+v", state, got)
	}
	rs, e = ApplySetting(d, rs, "disabled", nil)
	if e != nil {
		t.Fatal(e)
	}
	if state, _ = SettingState(d, rs); state != "disabled" {
		t.Fatal(state)
	}
	rs, e = ApplySetting(d, rs, "not-configured", nil)
	if e != nil || len(rs) != 1 || !bytes.Equal(rs[0].Data, foreign.Data) {
		t.Fatal("foreign record changed", e)
	}
	for id, bad := range map[string]any{"number": "65", "choice": "200", "text": "", "flag": "false", "list": []string{"x", "X"}, "extra": "x"} {
		invalid := rawValues(values)
		invalid[id], _ = json.Marshal(bad)
		if _, e = ApplySetting(d, nil, "enabled", invalid); e == nil {
			t.Errorf("accepted invalid %s", id)
		}
	}
	corrupt := []Record{{Key: d.Fields[0].Key, Name: d.Fields[0].Value, Type: 3, Data: []byte{4}}}
	if state, _ := SettingState(d, corrupt); state != "unsupported" {
		t.Fatal("unknown enum was treated as a default")
	}
	if _, e = ApplySetting(d, corrupt, "not-configured", nil); e == nil {
		t.Fatal("overwrote unknown data")
	}
	if _, e = ApplySetting(defs[2], nil, "enabled", nil); e == nil {
		t.Fatal("unknown template writable")
	}
}

// Optional compatibility check against the upstream templates, never bundled
// into the application or fetched implicitly during ordinary tests.
func TestALTTemplateCollection(t *testing.T) {
	dir := os.Getenv("SAMBAADM_ALT_TEMPLATES")
	if dir == "" {
		t.Skip("set SAMBAADM_ALT_TEMPLATES to admx-basealt checkout")
	}
	files, e := filepath.Glob(filepath.Join(dir, "BaseALT*.admx"))
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, file := range files {
		data, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		adml, _ := os.ReadFile(filepath.Join(dir, "ru-RU", strings.ToLower(strings.TrimSuffix(filepath.Base(file), ".admx"))+".adml"))
		defs, e := ParseADMX(filepath.Base(file), data, adml)
		if e != nil {
			t.Fatal(file, e)
		}
		for _, d := range defs {
			if d.Unsupported != "" {
				t.Errorf("%s %s: %s", d.Template, d.ID, d.Unsupported)
				continue
			}
			count++
			v := map[string]any{}
			for _, f := range d.Fields {
				v[f.ID] = f.Default
				if f.Kind == "text" && f.Required && f.Default == "" {
					v[f.ID] = "sample"
				}
				if f.Kind == "list" {
					v[f.ID] = []string{"sample"}
				}
			}
			rs, e := ApplySetting(d, nil, "enabled", rawValues(v))
			if e != nil {
				t.Errorf("%s: %v", d.ID, e)
				continue
			}
			encoded, e := Encode(rs)
			if e != nil {
				t.Error(d.ID, e)
				continue
			}
			rs, e = Parse(encoded)
			if e != nil {
				t.Fatal(e)
			}
			if state, _ := SettingState(d, rs); state != "enabled" {
				t.Error(d.ID, state)
			}
			rs, e = ApplySetting(d, rs, "disabled", nil)
			if e != nil {
				t.Error(d.ID, e)
				continue
			}
			if state, _ := SettingState(d, rs); state != "disabled" {
				t.Error(d.ID, state)
			}
			rs, e = ApplySetting(d, rs, "not-configured", nil)
			if e != nil || len(rs) != 0 {
				t.Error(d.ID, "clear", e)
			}
		}
	}
	if count < 600 {
		t.Fatalf("unexpectedly small catalog: %d", count)
	}
	t.Logf("%d scoped definitions across %d ADMX files passed round trips", count, len(files))
}
