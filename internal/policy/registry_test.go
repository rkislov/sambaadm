package policy

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRegistryWireFormat(t *testing.T) {
	// Independent MS-GPREG example: [K;V;REG_DWORD;4;1].
	golden, _ := hex.DecodeString("50526567010000005b004b0000003b00560000003b00040000003b00040000003b00010000005d00")
	records, e := Parse(golden)
	if e != nil || len(records) != 1 || records[0].Key != "K" || records[0].Name != "V" || records[0].Type != 4 || !bytes.Equal(records[0].Data, []byte{1, 0, 0, 0}) {
		t.Fatalf("decode: %+v %v", records, e)
	}
	unknown := Record{Key: "Неизвестный\\ключ", Name: "**DelValues", Type: 3, Data: []byte{0, 59, 0, 93, 255}}
	records = append(records, unknown)
	encoded, e := Encode(records)
	if e != nil {
		t.Fatal(e)
	}
	again, e := Parse(encoded)
	if e != nil {
		t.Fatal(e)
	}
	encodedAgain, e := Encode(again)
	if e != nil || !bytes.Equal(encoded, encodedAgain) {
		t.Fatal("unknown data or instruction order changed")
	}
	for i := 0; i < len(golden); i++ {
		if i == 8 {
			continue
		}
		if _, e = Parse(golden[:i]); e == nil {
			t.Fatalf("accepted truncated record at %d", i)
		}
	}
	if _, e = Parse(append(golden, 0)); e == nil {
		t.Fatal("accepted trailing garbage")
	}
}
