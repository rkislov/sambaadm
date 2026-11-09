package service

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestGPTVersionPreservesLegacyAndUnicodeMetadata(t *testing.T) {
	text := "; комментарий\r\n[General]\r\nVersion=65537\r\nDisplayName=Политика 😀\r\n[Other]\r\nVersion=9\r\n"
	encodings := map[string]func(string) []byte{
		"UTF8":     func(s string) []byte { return []byte(s) },
		"UTF8 BOM": func(s string) []byte { return append([]byte{0xef, 0xbb, 0xbf}, []byte(s)...) },
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, bom := range []bool{false, true} {
			name := order.String()
			if bom {
				name += " BOM"
			}
			encodings[name] = func(s string) []byte {
				var out []byte
				if bom {
					out = append(out, 0, 0)
					order.PutUint16(out[len(out)-2:], 0xfeff)
				}
				for _, unit := range utf16.Encode([]rune(s)) {
					out = append(out, 0, 0)
					order.PutUint16(out[len(out)-2:], unit)
				}
				return out
			}
		}
	}
	for name, encode := range encodings {
		t.Run(name, func(t *testing.T) {
			original := encode(text)
			before, unchanged, err := gptVersion(original, nil)
			if err != nil || before != 65537 || !bytes.Equal(unchanged, original) {
				t.Fatalf("read changed bytes: %d %v", before, err)
			}
			next := uint32(65538)
			_, after, err := gptVersion(original, &next)
			want := bytes.Replace(original, encodeFragment(encode, "65537"), encodeFragment(encode, "65538"), 1)
			if err != nil || !bytes.Equal(after, want) {
				t.Fatalf("metadata/encoding changed: %x; want %x; %v", after, want, err)
			}
		})
	}
	// A non-UTF8 DisplayName, e.g. Windows-1251, is opaque byte metadata.
	original := []byte("[General]\r\nVersion=7\r\nDisplayName=\xcf\xee\xeb\xe8\xf2\xe8\xea\xe0\r\n")
	next := uint32(8)
	version, after, err := gptVersion(original, &next)
	if err != nil || version != 7 || !bytes.Equal(after, bytes.Replace(original, []byte("Version=7"), []byte("Version=8"), 1)) {
		t.Fatalf("legacy metadata modified: %x %v", after, err)
	}
}

// Drop an encoder's BOM to form a substring within the already encoded file.
func encodeFragment(encode func(string) []byte, s string) []byte {
	return encode(s)[len(encode("")):]
}

func TestGPTRejectsMalformedUnicodeAndInvalidVersions(t *testing.T) {
	for _, data := range [][]byte{
		{0xff, 0xfe, 1}, {0xfe, 0xff, 1}, {0xff, 0xfe, 0, 0xd8}, {0xfe, 0xff, 0xd8, 0},
		{0xff, 0xfe, 0, 0}, {0, 0, 0xfe, 0xff}, []byte("[General]\nVersion=1\x00garbage"),
		[]byte("[General]\nVersion=4294967296"), []byte("[General]\nVersion=1\nVersion=2"),
	} {
		if _, _, err := gptVersion(data, nil); err == nil {
			t.Errorf("accepted %x", data)
		}
	}
}
