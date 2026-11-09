package service

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// GPT.INI's section/key/version syntax is ASCII. Preserve single-byte metadata
// verbatim instead of guessing its Windows code page or requiring UTF-8.
// UTF-16 is decoded separately and written in its original byte order/BOM style.
func decodeGPTText(data []byte) (string, func(string) []byte, error) {
	var order binary.ByteOrder
	var bom []byte
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe, 0, 0}), bytes.HasPrefix(data, []byte{0, 0, 0xfe, 0xff}):
		return "", nil, fmt.Errorf("GPT.INI: unsupported UTF-32 encoding")
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order, bom = binary.LittleEndian, data[:2]
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order, bom = binary.BigEndian, data[:2]
	case len(data) >= 2 && data[0] != 0 && data[1] == 0:
		order = binary.LittleEndian
	case len(data) >= 2 && data[0] == 0 && data[1] != 0:
		order = binary.BigEndian
	}
	if order == nil {
		if bytes.IndexByte(data, 0) >= 0 {
			return "", nil, fmt.Errorf("GPT.INI: unexpected NUL bytes or unsupported encoding")
		}
		return string(data), func(s string) []byte { return []byte(s) }, nil
	}
	body := data[len(bom):]
	if len(body)%2 != 0 {
		return "", nil, fmt.Errorf("GPT.INI: invalid UTF-16 length")
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = order.Uint16(body[2*i:])
	}
	for i := 0; i < len(units); i++ {
		if units[i] == 0 {
			return "", nil, fmt.Errorf("GPT.INI: unexpected NUL character")
		}
		if utf16.IsSurrogate(rune(units[i])) {
			if units[i] > 0xdbff || i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", nil, fmt.Errorf("GPT.INI: invalid UTF-16 surrogate")
			}
			i++
		}
	}
	encode := func(text string) []byte {
		out := append([]byte(nil), bom...)
		for _, u := range utf16.Encode([]rune(text)) {
			out = append(out, 0, 0)
			order.PutUint16(out[len(out)-2:], u)
		}
		return out
	}
	return string(utf16.Decode(units)), encode, nil
}
