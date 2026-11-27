package domaininit

import "testing"

func TestMemberValidationAndNoDCCertificate(t *testing.T) {
	in := Input{Mode: "member", Realm: "corp.example", NetBIOS: "CORP", Hostname: "fs1", Address: "192.0.2.20", Forwarder: "192.0.2.10", Source: "dc1.corp.example", PanelName: "sambaadm.corp.example", IdentityProvider: "winbind"}
	for _, profile := range []string{"winbind", "sssd"} {
		in.IdentityProvider = profile
		if err := in.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []func(*Input){func(v *Input) { v.IdentityProvider = "shell" }, func(v *Input) { v.Site = "Main" }, func(v *Input) { v.TransferRoles = true }, func(v *Input) { v.Certificate = []byte("cert") }, func(v *Input) { v.Source = "evil.other.example" }, func(v *Input) { v.Username = "user%password" }, func(v *Input) { v.Address = "127.0.0.1" }} {
		v := in
		change(&v)
		if v.Validate() == nil {
			t.Fatal("unsafe member configuration accepted", v)
		}
	}
	e := Engine{Dir: t.TempDir()}
	files, err := e.deploymentTLS(in)
	if err != nil || len(files) != 0 {
		t.Fatal("member unnecessarily requires DC LDAPS certificates", err)
	}
}
