package service

import "testing"

func TestDNSRecordValidation(t *testing.T) {
	for _, tt := range []struct {
		typ, data string
		valid     bool
	}{
		{"A", "192.0.2.20", true}, {"A", "999.1.2.3", false},
		{"AAAA", "2001:db8::1", true}, {"AAAA", "192.0.2.20", false},
		{"SRV", "dc1.example.com 389 0 100", true}, {"SRV", "dc1.example.com 99999 0 0", false},
		{"MX", "mail.example.com 10", true}, {"MX", "mail.example.com bad", false},
		{"TXT", `"hello world"`, true}, {"CNAME", "files.example.com.", true},
	} {
		t.Run(tt.typ+tt.data, func(t *testing.T) {
			err := validateDNSRecord("example.com", "files", tt.typ, tt.data)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v err=%v", tt.valid, err)
			}
		})
	}
}
