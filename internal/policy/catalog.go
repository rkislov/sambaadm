package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

type Literal struct {
	Type uint32
	Data []byte
}
type Choice struct {
	Label string  `json:"label"`
	Value Literal `json:"-"`
}
type Field struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Kind        string   `json:"kind"`
	Key         string   `json:"key"`
	Value       string   `json:"value"`
	Required    bool     `json:"required"`
	Min         uint64   `json:"min"`
	Max         uint64   `json:"max"`
	MaxLength   int      `json:"maxLength"`
	Default     any      `json:"default"`
	Choices     []Choice `json:"choices,omitempty"`
	True, False *Literal `json:"-"`
}

// xmlNode retains unknown constructs so unsupported templates fail closed.
type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Text     string     `xml:",chardata"`
	Children []xmlNode  `xml:",any"`
}

func (n xmlNode) attr(key string) string {
	for _, a := range n.Attrs {
		if strings.EqualFold(a.Name.Local, key) {
			return a.Value
		}
	}
	return ""
}
func (n xmlNode) child(key string) xmlNode {
	for _, c := range n.Children {
		if c.XMLName.Local == key {
			return c
		}
	}
	return xmlNode{}
}
func (n xmlNode) text() string {
	b := n.Text
	for _, c := range n.Children {
		b += c.text()
	}
	return strings.TrimSpace(b)
}
func stringLiteral(s string) *Literal { return &Literal{Type: 1, Data: u16(s + "\x00")} }
func dwordLiteral(v uint32) *Literal {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return &Literal{Type: 4, Data: b}
}
func literal(n xmlNode) (*Literal, error) {
	if len(n.Children) != 1 {
		return nil, fmt.Errorf("expected one registry value")
	}
	c := n.Children[0]
	switch c.XMLName.Local {
	case "decimal":
		v, e := strconv.ParseUint(c.attr("value"), 10, 32)
		if e != nil {
			return nil, e
		}
		return dwordLiteral(uint32(v)), nil
	case "string":
		if strings.ContainsRune(c.Text, 0) {
			return nil, fmt.Errorf("NUL in value")
		}
		return stringLiteral(c.Text), nil
	}
	return nil, fmt.Errorf("unsupported literal %s", c.XMLName.Local)
}
func resourceID(s string) string {
	if strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")") {
		_, id, _ := strings.Cut(s[2:len(s)-1], ".")
		return id
	}
	return s
}
func registryTarget(key, value string) bool {
	return key != "" && !strings.ContainsRune(key, 0) && value != "" && !strings.ContainsRune(value, 0) && !strings.HasPrefix(value, "**")
}

// ParseADMX reads the ALT ADMX schema and optional ADML labels/presentations.
// Unknown editing constructs remain visible with a reason but cannot be saved.
func ParseADMX(name string, data, resources []byte) ([]Definition, error) {
	if len(data) > 2<<20 || len(resources) > 4<<20 {
		return nil, fmt.Errorf("template exceeds size limit")
	}
	var root, lang xmlNode
	if e := xml.Unmarshal(data, &root); e != nil {
		return nil, e
	}
	if root.XMLName.Local != "policyDefinitions" {
		return nil, fmt.Errorf("not an ADMX document")
	}
	if len(resources) > 0 {
		if e := xml.Unmarshal(resources, &lang); e != nil {
			return nil, fmt.Errorf("ADML: %w", e)
		}
	}
	labels := map[string]string{}
	presentations := map[string]xmlNode{}
	for _, n := range lang.child("resources").child("stringTable").Children {
		labels[n.attr("id")] = n.text()
	}
	for _, n := range lang.child("resources").child("presentationTable").Children {
		presentations[n.attr("id")] = n
	}
	label := func(s string) string {
		if v := labels[resourceID(s)]; v != "" {
			return v
		}
		return resourceID(s)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(append(append([]byte{}, data...), resources...)))
	var out []Definition
	seen := map[string]bool{}
	for _, n := range root.child("policies").Children {
		if n.XMLName.Local != "policy" {
			return nil, fmt.Errorf("unknown policies child %s", n.XMLName.Local)
		}
		scopes := []string{n.attr("class")}
		if scopes[0] == "Both" {
			scopes = []string{"Machine", "User"}
		}
		for _, scope := range scopes {
			d := Definition{ID: name + "/" + n.attr("name"), Label: label(n.attr("displayName")), Key: n.attr("key"), Value: n.attr("valueName"), Scope: scope, Template: name, Category: resourceID(n.child("parentCategory").attr("ref")), Description: label(n.attr("explainText")), SupportedOn: resourceID(n.child("supportedOn").attr("ref")), Digest: digest}
			if strings.EqualFold(d.Key, SystemdKey) && d.Value != "" && len(n.child("elements").Children) == 0 {
				d.ID = n.attr("name")
				d.Label = d.Value
			}
			if d.Label == "" {
				d.Label = n.attr("name")
			}
			reject := func(e error) {
				if e != nil && d.Unsupported == "" {
					d.Unsupported = e.Error()
				}
			}
			if scope != "Machine" && scope != "User" {
				reject(fmt.Errorf("unsupported policy scope"))
			}
			if n.attr("name") == "" || d.Key == "" || strings.ContainsRune(d.Key, 0) {
				reject(fmt.Errorf("missing or invalid policy identity"))
			}
			for _, c := range n.Children {
				switch c.XMLName.Local {
				case "parentCategory", "supportedOn", "elements", "enabledValue", "disabledValue":
				default:
					reject(fmt.Errorf("unsupported policy construct %s", c.XMLName.Local))
				}
			}
			var e error
			if v := n.child("enabledValue"); v.XMLName.Local != "" {
				d.Enabled, e = literal(v)
				reject(e)
			}
			if v := n.child("disabledValue"); v.XMLName.Local != "" {
				d.Disabled, e = literal(v)
				reject(e)
			}
			controls := map[string]xmlNode{}
			for _, c := range presentations[resourceID(n.attr("presentation"))].Children {
				controls[c.attr("refId")] = c
			}
			ids := map[string]bool{}
			for _, el := range n.child("elements").Children {
				f := Field{ID: el.attr("id"), Kind: el.XMLName.Local, Key: el.attr("key"), Value: el.attr("valueName"), Required: el.attr("required") == "true", Max: 4294967295, MaxLength: 32766}
				if f.Key == "" {
					f.Key = d.Key
				}
				f.Label = f.ID
				if f.ID == "" || ids[f.ID] {
					reject(fmt.Errorf("missing/duplicate element ID"))
				}
				ids[f.ID] = true
				c := controls[f.ID]
				if c.text() != "" {
					f.Label = c.text()
				}
				if c.child("label").text() != "" {
					f.Label = c.child("label").text()
				}
				// Additional semantics must not be silently ignored when templates evolve.
				for _, a := range el.Attrs {
					switch a.Name.Local {
					case "id", "key", "valueName", "required", "minValue", "maxValue", "maxLength", "additive":
					default:
						reject(fmt.Errorf("unsupported element attribute %s", a.Name.Local))
					}
				}
				for _, child := range el.Children {
					allowed := f.Kind == "enum" && child.XMLName.Local == "item" || f.Kind == "boolean" && (child.XMLName.Local == "trueValue" || child.XMLName.Local == "falseValue")
					if !allowed {
						reject(fmt.Errorf("unsupported element construct %s", child.XMLName.Local))
					}
				}
				switch f.Kind {
				case "enum":
					for _, item := range el.Children {
						if item.XMLName.Local != "item" {
							reject(fmt.Errorf("unsupported enum construct"))
							continue
						}
						v, err := literal(item.child("value"))
						reject(err)
						if err == nil {
							f.Choices = append(f.Choices, Choice{Label: label(item.attr("displayName")), Value: *v})
						}
					}
					if len(f.Choices) == 0 {
						reject(fmt.Errorf("empty enum"))
					}
					f.Default = "0"
					if c.attr("defaultItem") != "" {
						f.Default = c.attr("defaultItem")
					}
				case "boolean":
					f.True, e = literal(el.child("trueValue"))
					reject(e)
					f.False, e = literal(el.child("falseValue"))
					reject(e)
					f.Default = c.attr("defaultChecked") == "true"
				case "decimal":
					if el.attr("minValue") != "" {
						f.Min, e = strconv.ParseUint(el.attr("minValue"), 10, 32)
						reject(e)
					}
					if el.attr("maxValue") != "" {
						f.Max, e = strconv.ParseUint(el.attr("maxValue"), 10, 32)
						reject(e)
					}
					if f.Min > f.Max {
						reject(fmt.Errorf("invalid decimal bounds"))
					}
					f.Default = strconv.FormatUint(f.Min, 10)
					if c.attr("defaultValue") != "" {
						f.Default = c.attr("defaultValue")
					}
				case "text":
					if el.attr("maxLength") != "" {
						f.MaxLength, e = strconv.Atoi(el.attr("maxLength"))
						reject(e)
						if f.MaxLength < 0 || f.MaxLength > 32766 {
							reject(fmt.Errorf("invalid text bound"))
						}
					}
					f.Default = c.child("defaultValue").Text
				case "list":
					if el.attr("additive") != "true" {
						reject(fmt.Errorf("only additive ALT lists are supported"))
					}
					f.Default = []string{}
				default:
					reject(fmt.Errorf("unsupported element type %s", f.Kind))
				}
				if f.Kind != "list" && !registryTarget(f.Key, f.Value) {
					reject(fmt.Errorf("invalid registry target"))
				}
				d.Fields = append(d.Fields, f)
			}
			// An element can own the policy valueName (e.g. Polkit); don't also
			// synthesize a DWORD marker that would overwrite its string selection.
			for _, f := range d.Fields {
				if strings.EqualFold(f.Key, d.Key) && strings.EqualFold(f.Value, d.Value) {
					if d.Enabled != nil || d.Disabled != nil {
						reject(fmt.Errorf("overlapping policy marker and element"))
					}
					d.Value = ""
					break
				}
			}
			if d.Value != "" {
				if !registryTarget(d.Key, d.Value) {
					reject(fmt.Errorf("invalid policy registry target"))
				}
				if d.Enabled == nil {
					d.Enabled = dwordLiteral(1)
				}
				if d.Disabled == nil {
					d.Disabled = dwordLiteral(0)
				}
			}
			if d.Value == "" && len(d.Fields) == 0 {
				reject(fmt.Errorf("no registry settings"))
			}
			if seen[scope+"/"+d.ID] {
				return nil, fmt.Errorf("duplicate policy ID %s", d.ID)
			}
			seen[scope+"/"+d.ID] = true
			out = append(out, d)
		}
	}
	return out, nil
}

// CategoryLabels resolves both local category names and cross-template prefixes.
func CategoryLabels(name string, data, resources []byte) map[string]string {
	var root, lang xmlNode
	_ = xml.Unmarshal(data, &root)
	_ = xml.Unmarshal(resources, &lang)
	labels := map[string]string{}
	for _, n := range lang.child("resources").child("stringTable").Children {
		labels[n.attr("id")] = n.text()
	}
	prefix := root.child("policyNamespaces").child("target").attr("prefix")
	out := map[string]string{}
	for _, c := range append(root.child("categories").Children, root.child("supportedOn").child("definitions").Children...) {
		title := labels[resourceID(c.attr("displayName"))]
		if title == "" {
			continue
		}
		out[name+"/"+c.attr("name")] = title
		out[prefix+":"+c.attr("name")] = title
	}
	return out
}
