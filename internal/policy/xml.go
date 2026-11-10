package policy

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// Windows and third-party template stores may contain UTF-16 XML. Convert only
// recognized UTF-16 byte orders; XML declarations cannot select arbitrary codecs.
func decodeTemplateXML(data []byte, out any) error {
	converted := false
	var order binary.ByteOrder
	if bytes.HasPrefix(data, []byte{0xff, 0xfe}) {
		order = binary.LittleEndian
		data = data[2:]
	} else if bytes.HasPrefix(data, []byte{0xfe, 0xff}) {
		order = binary.BigEndian
		data = data[2:]
	} else if bytes.HasPrefix(data, []byte{'<', 0, '?', 0}) {
		order = binary.LittleEndian
	} else if bytes.HasPrefix(data, []byte{0, '<', 0, '?'}) {
		order = binary.BigEndian
	}
	if order != nil {
		if len(data)%2 != 0 {
			return fmt.Errorf("invalid UTF-16 template")
		}
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = order.Uint16(data[2*i:])
		}
		for i := 0; i < len(units); i++ {
			u := units[i]
			if u >= 0xd800 && u <= 0xdbff {
				if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
					return fmt.Errorf("invalid UTF-16 template surrogate")
				}
				i++
			} else if u >= 0xdc00 && u <= 0xdfff {
				return fmt.Errorf("invalid UTF-16 template surrogate")
			}
		}
		data = []byte(string(utf16.Decode(units)))
		converted = true
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		if converted && (strings.EqualFold(label, "utf-16") || strings.EqualFold(label, "utf-16le") || strings.EqualFold(label, "utf-16be")) {
			return input, nil
		}
		return nil, fmt.Errorf("unsupported template charset %s", label)
	}
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing XML template content")
	}
	return nil
}
