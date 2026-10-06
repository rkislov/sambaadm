package ldap

import (
	"encoding/binary"
	"unicode/utf16"
)

// EncodeUnicodePwd encodes a password for the AD/Samba unicodePwd attribute:
// UTF-16LE of the password wrapped in double quotes.
func EncodeUnicodePwd(password string) []byte {
	quoted := `"` + password + `"`
	u16 := utf16.Encode([]rune(quoted))
	out := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}
