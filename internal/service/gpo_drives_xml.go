package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"sambaadm/internal/policy"
)

const driveClassID = "{935D1B74-9CB8-4E3C-9914-7DD559B7A417}"
const drivesClassID = "{8FDDCC1A-0C3C-43CD-A6B4-71A6DF20DA8C}"
const drivesCSE = "{5794DAFD-BE60-433F-88A2-1A31939AC01F}"
const drivesEditor = "{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}"

// DriveMap never exposes legacy stored passwords. Unknown XML attributes and
// targeting filters stay on the server and survive edits to supported fields.
type DriveMap struct {
	UID         string `json:"uid"`
	Action      string `json:"action"`
	Path        string `json:"path"`
	Label       string `json:"label"`
	Letter      string `json:"letter"`
	UseLetter   bool   `json:"useLetter"`
	Persistent  bool   `json:"persistent"`
	Disabled    bool   `json:"disabled"`
	ThisDrive   string `json:"thisDrive"`
	AllDrives   string `json:"allDrives"`
	Description string `json:"description"`
	HasFilters  bool   `json:"hasFilters"`
	ReadOnly    string `json:"readOnly,omitempty"`
}

type DriveChange struct {
	Revision  string   `json:"revision"`
	Scope     string   `json:"scope"`
	Operation string   `json:"operation"`
	Drive     DriveMap `json:"drive"`
	Disabled  bool     `json:"disabled"`
	Direction int      `json:"direction"`
}

type driveXMLItem struct {
	view                                                DriveMap
	start, openEnd, end, closeStart                     int
	propsStart, propsOpenEnd, propsEnd, propsCloseStart int
	attrs, props                                        []xml.Attr
}
type drivesXML struct {
	text                string
	openEnd, closeStart int
	attrs               []xml.Attr
	items               []driveXMLItem
	disabled            bool
}

var policyXMLEncoding = regexp.MustCompile(`(?i)(encoding\s*=\s*["'])(?:utf-16|unicode|utf-16le)(["'])`)

func xmlAttr(attrs []xml.Attr, name string) string {
	for _, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}
func xmlBool(s string) bool { return s == "1" || strings.EqualFold(s, "true") }
func setXMLAttr(attrs []xml.Attr, name, value string) []xml.Attr {
	for i, a := range attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			attrs[i].Value = value
			return attrs
		}
	}
	return append(attrs, xml.Attr{Name: xml.Name{Local: name}, Value: value})
}
func xmlStart(name string, attrs []xml.Attr) string {
	var b bytes.Buffer
	e := xml.NewEncoder(&b)
	_ = e.EncodeToken(xml.StartElement{Name: xml.Name{Local: name}, Attr: attrs})
	_ = e.Flush()
	return b.String()
}
func parseDriveXML(data []byte) (*drivesXML, error) {
	if len(data) > 2<<20 {
		return nil, fmt.Errorf("Drives.xml exceeds 2 MiB")
	}
	if len(data) == 0 {
		data = []byte(xml.Header + `<Drives clsid="` + drivesClassID + `"></Drives>`)
	}
	text, wide, err := decodePolicyText(data)
	if err != nil {
		return nil, err
	}
	if wide {
		text = policyXMLEncoding.ReplaceAllString(text, "${1}utf-8${2}")
	}
	doc := &drivesXML{text: text, items: []driveXMLItem{}}
	dec := xml.NewDecoder(strings.NewReader(text))
	depth, roots, tokens := 0, 0, 0
	var item *driveXMLItem
	seen := map[string]bool{}
	for {
		start := int(dec.InputOffset())
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Drives.xml: %w", err)
		}
		tokens++
		if tokens > 30000 {
			return nil, fmt.Errorf("Drives.xml exceeds token limit")
		}
		switch t := token.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("Drives.xml directives are unsupported")
		case xml.ProcInst:
			if t.Target != "xml" {
				return nil, fmt.Errorf("Drives.xml processing instructions are unsupported")
			}
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(t)) != "" {
				return nil, fmt.Errorf("unexpected text outside Drives")
			}
		case xml.StartElement:
			depth++
			attrNames := map[xml.Name]bool{}
			for _, a := range t.Attr {
				if attrNames[a.Name] {
					return nil, fmt.Errorf("duplicate XML attribute")
				}
				attrNames[a.Name] = true
			}
			if depth > 24 {
				return nil, fmt.Errorf("Drives.xml nesting exceeds limit")
			}
			if depth == 1 {
				roots++
				if roots != 1 || t.Name.Local != "Drives" || t.Name.Space != "" {
					return nil, fmt.Errorf("expected one Drives document")
				}
				doc.attrs = t.Attr
				doc.openEnd = int(dec.InputOffset())
				doc.disabled = xmlBool(xmlAttr(t.Attr, "disabled"))
				if c := xmlAttr(t.Attr, "clsid"); c != "" && !strings.EqualFold(c, drivesClassID) {
					return nil, fmt.Errorf("unexpected Drives class ID")
				}
			} else if depth == 2 {
				if t.Name.Local != "Drive" || t.Name.Space != "" {
					return nil, fmt.Errorf("unsupported Drives child element")
				}
				if len(doc.items) >= 256 {
					return nil, fmt.Errorf("too many mapped drives")
				}
				item = &driveXMLItem{start: start, openEnd: int(dec.InputOffset()), attrs: t.Attr, propsStart: -1}
				item.view.UID = xmlAttr(t.Attr, "uid")
				if _, err := uuid.Parse(item.view.UID); err != nil {
					item.view.ReadOnly = "Invalid or missing drive identity"
					item.view.UID = "legacy-" + strconv.Itoa(len(doc.items))
				}
				key := strings.ToUpper(item.view.UID)
				if seen[key] {
					return nil, fmt.Errorf("duplicate drive identity")
				}
				seen[key] = true
				item.view.Description = xmlAttr(t.Attr, "desc")
				item.view.Disabled = xmlBool(xmlAttr(t.Attr, "disabled"))
				if c := xmlAttr(t.Attr, "clsid"); c != "" && !strings.EqualFold(c, driveClassID) {
					item.view.ReadOnly = "Unsupported drive class ID"
				}
			} else if item != nil && depth == 3 && t.Name.Local == "Properties" {
				if item.propsStart >= 0 {
					return nil, fmt.Errorf("duplicate drive Properties")
				}
				item.propsStart = start
				item.propsOpenEnd = int(dec.InputOffset())
				item.props = t.Attr
				v := &item.view
				v.Action = xmlAttr(t.Attr, "action")
				if v.Action == "" {
					v.Action = "U"
				}
				v.Path = xmlAttr(t.Attr, "path")
				v.Label = xmlAttr(t.Attr, "label")
				v.Letter = xmlAttr(t.Attr, "letter")
				v.UseLetter = xmlBool(xmlAttr(t.Attr, "useLetter"))
				v.Persistent = xmlBool(xmlAttr(t.Attr, "persistent"))
				v.Disabled = v.Disabled || xmlBool(xmlAttr(t.Attr, "disabled"))
				v.ThisDrive = xmlAttr(t.Attr, "thisDrive")
				if v.ThisDrive == "" {
					v.ThisDrive = "NOCHANGE"
				}
				v.AllDrives = xmlAttr(t.Attr, "allDrives")
				if v.AllDrives == "" {
					v.AllDrives = "NOCHANGE"
				}
				if xmlAttr(t.Attr, "cpassword") != "" || xmlAttr(t.Attr, "userName") != "" {
					v.ReadOnly = "Stored credentials require migration before editing"
				}
				for _, a := range append(append([]xml.Attr{}, item.attrs...), item.props...) {
					if a.Name.Space != "" {
						v.ReadOnly = "Namespaced drive attributes are unsupported"
					}
				}
			} else if item != nil && t.Name.Local == "Filters" {
				item.view.HasFilters = true
			}
		case xml.EndElement:
			if depth == 3 && item != nil && t.Name.Local == "Properties" {
				item.propsCloseStart = start
				item.propsEnd = int(dec.InputOffset())
				if item.propsCloseStart < item.propsOpenEnd {
					item.propsCloseStart = item.propsOpenEnd
				}
			}
			if depth == 2 && item != nil {
				item.closeStart = start
				item.end = int(dec.InputOffset())
				if item.propsStart < 0 {
					item.view.ReadOnly = "Missing drive properties"
				}
				doc.items = append(doc.items, *item)
				item = nil
			}
			if depth == 1 {
				doc.closeStart = start
			}
			depth--
		}
	}
	if roots != 1 || depth != 0 {
		return nil, fmt.Errorf("incomplete Drives.xml")
	}
	// A self-closing empty root must become an ordinary start/end pair before insertion.
	if strings.HasSuffix(strings.TrimSpace(doc.text[:doc.openEnd]), "/>") {
		doc.text = xml.Header + xmlStart("Drives", doc.attrs) + "</Drives>"
		doc.openEnd = len(xml.Header) + len(xmlStart("Drives", doc.attrs))
		doc.closeStart = doc.openEnd
	}
	return doc, nil
}
func validDriveText(s string, max int) bool {
	return len(s) <= max && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}
func validateDriveChange(in DriveChange) error {
	invalid := func() error { return fmt.Errorf("%w: invalid network drive change", policy.ErrInvalidValue) }
	if in.Revision == "" || (in.Scope != "Machine" && in.Scope != "User") {
		return invalid()
	}
	switch in.Operation {
	case "set-disabled":
		return nil
	case "remove":
		if in.Drive.UID == "" {
			return invalid()
		}
		return nil
	case "move":
		if in.Drive.UID == "" || (in.Direction != -1 && in.Direction != 1) {
			return invalid()
		}
		return nil
	case "upsert":
	default:
		return invalid()
	}
	v := in.Drive
	if v.UID != "" {
		if _, e := uuid.Parse(v.UID); e != nil {
			return invalid()
		}
	}
	if !strings.Contains("CRUD", v.Action) || len(v.Action) != 1 || len(v.Letter) != 1 || v.Letter[0] < 'A' || v.Letter[0] > 'Z' {
		return invalid()
	}
	for _, x := range []string{v.ThisDrive, v.AllDrives} {
		if x != "NOCHANGE" && x != "SHOW" && x != "HIDE" {
			return invalid()
		}
	}
	if !validDriveText(v.Label, 256) || !validDriveText(v.Description, 1024) || !validDriveText(v.Path, 2048) {
		return invalid()
	}
	if v.Action != "D" || v.Path != "" {
		if !strings.HasPrefix(v.Path, `\\`) {
			return invalid()
		}
		parts := strings.Split(v.Path[2:], `\`)
		if len(parts) < 2 {
			return invalid()
		}
		for _, part := range parts {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, `/:*?"<>|`) {
				return invalid()
			}
		}
	}
	return nil
}
func patchDriveXML(doc *drivesXML, in DriveChange) ([]byte, error) {
	if err := validateDriveChange(in); err != nil {
		return nil, err
	}
	if in.Operation == "set-disabled" {
		attrs := append([]xml.Attr{}, doc.attrs...)
		attrs = setXMLAttr(attrs, "disabled", strconv.Itoa(boolInt(in.Disabled)))
		// Replace only the root opening tag, preserving all records and targeting.
		start := strings.LastIndex(doc.text[:doc.openEnd], "<Drives")
		if start < 0 {
			return nil, fmt.Errorf("missing Drives start")
		}
		return []byte(doc.text[:start] + xmlStart("Drives", attrs) + doc.text[doc.openEnd:]), nil
	}
	index := -1
	for i, x := range doc.items {
		if strings.EqualFold(x.view.UID, in.Drive.UID) {
			index = i
			break
		}
	}
	if in.Operation != "upsert" && index < 0 {
		return nil, fmt.Errorf("%w: drive no longer exists", policy.ErrInvalidValue)
	}
	if in.Operation == "remove" {
		x := doc.items[index]
		return []byte(doc.text[:x.start] + doc.text[x.end:]), nil
	}
	if in.Operation == "move" {
		target := index + in.Direction
		if target < 0 || target >= len(doc.items) {
			return []byte(doc.text), nil
		}
		a, b := doc.items[index], doc.items[target]
		if a.start > b.start {
			a, b = b, a
		}
		return []byte(doc.text[:a.start] + doc.text[b.start:b.end] + doc.text[a.end:b.start] + doc.text[a.start:a.end] + doc.text[b.end:]), nil
	}
	v := in.Drive
	if index < 0 && v.UID != "" {
		return nil, fmt.Errorf("%w: drive no longer exists", policy.ErrInvalidValue)
	}
	attrs := []xml.Attr{}
	props := []xml.Attr{}
	inner := ""
	beforeProps, afterProps := "", ""
	if index >= 0 {
		x := doc.items[index]
		if x.view.ReadOnly != "" {
			return nil, fmt.Errorf("%w: %s", policy.ErrInvalidValue, x.view.ReadOnly)
		}
		attrs = append(attrs, x.attrs...)
		props = append(props, x.props...)
		beforeProps = doc.text[x.openEnd:x.propsStart]
		afterProps = doc.text[x.propsEnd:x.closeStart]
		if x.propsCloseStart > x.propsOpenEnd {
			inner = doc.text[x.propsOpenEnd:x.propsCloseStart]
		}
	} else {
		v.UID = "{" + strings.ToUpper(uuid.NewString()) + "}"
	}
	for _, a := range [][2]string{{"clsid", driveClassID}, {"uid", v.UID}, {"name", v.Letter + ":"}, {"status", v.Letter + ":"}, {"image", "2"}, {"changed", time.Now().UTC().Format("2006-01-02 15:04:05")}, {"disabled", strconv.Itoa(boolInt(v.Disabled))}, {"desc", v.Description}} {
		attrs = setXMLAttr(attrs, a[0], a[1])
	}
	if index < 0 {
		for _, a := range [][2]string{{"bypassErrors", "0"}, {"userContext", "0"}, {"removePolicy", "0"}} {
			attrs = setXMLAttr(attrs, a[0], a[1])
		}
	}
	for _, a := range [][2]string{{"action", v.Action}, {"path", v.Path}, {"label", v.Label}, {"letter", v.Letter}, {"useLetter", strconv.Itoa(boolInt(v.UseLetter))}, {"persistent", strconv.Itoa(boolInt(v.Persistent))}, {"thisDrive", v.ThisDrive}, {"allDrives", v.AllDrives}, {"disabled", "0"}} {
		props = setXMLAttr(props, a[0], a[1])
	}
	node := xmlStart("Drive", attrs) + beforeProps + xmlStart("Properties", props) + inner + "</Properties>" + afterProps + "</Drive>"
	if index >= 0 {
		x := doc.items[index]
		return []byte(doc.text[:x.start] + node + doc.text[x.end:]), nil
	}
	return []byte(doc.text[:doc.closeStart] + "\n" + node + "\n" + doc.text[doc.closeStart:]), nil
}
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
