// Package policy implements the MS-GPREG registry policy wire format.
package policy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

const MaxFileSize = 4 << 20

type Record struct {
	Key, Name string
	Type      uint32
	Data      []byte
}

func u16(s string) []byte {
	var b bytes.Buffer
	for _, c := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, c)
	}
	return b.Bytes()
}
func Parse(data []byte) ([]Record, error) {
	if len(data) > MaxFileSize || len(data) < 8 || string(data[:4]) != "PReg" || binary.LittleEndian.Uint32(data[4:8]) != 1 {
		return nil, fmt.Errorf("invalid Registry.pol header or size")
	}
	pos := 8
	token := func(want uint16) error {
		if pos+2 > len(data) || binary.LittleEndian.Uint16(data[pos:]) != want {
			return fmt.Errorf("invalid Registry.pol delimiter at %d", pos)
		}
		pos += 2
		return nil
	}
	str := func() (string, error) {
		var chars []uint16
		for pos+2 <= len(data) {
			c := binary.LittleEndian.Uint16(data[pos:])
			pos += 2
			if c == 0 {
				for i := 0; i < len(chars); i++ {
					if utf16.IsSurrogate(rune(chars[i])) {
						if chars[i] < 0xD800 || chars[i] > 0xDBFF || i+1 >= len(chars) || chars[i+1] < 0xDC00 || chars[i+1] > 0xDFFF {
							return "", fmt.Errorf("invalid UTF-16 in Registry.pol")
						}
						i++
					}
				}
				return string(utf16.Decode(chars)), nil
			}
			chars = append(chars, c)
		}
		return "", fmt.Errorf("unterminated Registry.pol string")
	}
	var out []Record
	for pos < len(data) {
		if err := token('['); err != nil {
			return nil, err
		}
		key, err := str()
		if err != nil {
			return nil, err
		}
		if err = token(';'); err != nil {
			return nil, err
		}
		name, err := str()
		if err != nil {
			return nil, err
		}
		if err = token(';'); err != nil {
			return nil, err
		}
		if pos+4 > len(data) {
			return nil, fmt.Errorf("truncated type")
		}
		typ := binary.LittleEndian.Uint32(data[pos:])
		pos += 4
		if err = token(';'); err != nil {
			return nil, err
		}
		if pos+4 > len(data) {
			return nil, fmt.Errorf("truncated size")
		}
		size := int(binary.LittleEndian.Uint32(data[pos:]))
		pos += 4
		if err = token(';'); err != nil {
			return nil, err
		}
		if size > 65535 || size > len(data)-pos {
			return nil, fmt.Errorf("invalid Registry.pol data size")
		}
		value := bytes.Clone(data[pos : pos+size])
		pos += size
		if err = token(']'); err != nil {
			return nil, err
		}
		out = append(out, Record{key, name, typ, value})
	}
	return out, nil
}
func Encode(records []Record) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("PReg")
	binary.Write(&b, binary.LittleEndian, uint32(1))
	for _, r := range records {
		if r.Key == "" || bytes.ContainsRune([]byte(r.Key+r.Name), 0) || len(r.Data) > 65535 {
			return nil, fmt.Errorf("invalid registry record")
		}
		b.Write(u16("[" + r.Key + "\x00;" + r.Name + "\x00;"))
		binary.Write(&b, binary.LittleEndian, r.Type)
		b.Write(u16(";"))
		binary.Write(&b, binary.LittleEndian, uint32(len(r.Data)))
		b.Write(u16(";"))
		b.Write(r.Data)
		b.Write(u16("]"))
	}
	if b.Len() > MaxFileSize {
		return nil, fmt.Errorf("Registry.pol exceeds size limit")
	}
	return b.Bytes(), nil
}
