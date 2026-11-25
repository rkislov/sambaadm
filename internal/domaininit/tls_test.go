package domaininit

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestDestinationKeyAndCentralIssuerAreBoundToPlan(t *testing.T) {
	e := &Engine{Dir: filepath.Join(t.TempDir(), "domain-init")}
	if err := e.base(); err != nil {
		t.Fatal(err)
	}
	in := Input{Mode: "DC", Realm: "corp.example", Hostname: "dc2", Revision: strings.Repeat("a", 64)}
	key, csr, err := e.certificateKey(in.Revision, in)
	if err != nil {
		t.Fatal(err)
	}
	plan := &Plan{Revision: in.Revision, CSR: csr}
	caDir := filepath.Join(t.TempDir(), "certificates")
	if err := SignPlan(plan, in, caDir); err != nil {
		t.Fatal(err)
	}
	in.Certificate, in.CA = plan.Certificate, plan.CA
	if err := ValidateCertificate(in, plan.CA); err != nil {
		t.Fatal(err)
	}
	files, err := e.deploymentTLS(in)
	if err != nil || string(files["tls.key"]) != string(key) {
		t.Fatal(err)
	}
	public, _ := json.Marshal(plan)
	if strings.Contains(string(public), "PRIVATE KEY") || strings.Contains(string(public), string(key)) {
		t.Fatal("private key returned to management server")
	}
	changed := in
	changed.Hostname = "other"
	if ValidateCertificate(changed, plan.CA) == nil {
		t.Fatal("wrong hostname accepted")
	}
	if ValidateCertificate(in, []byte("different CA")) == nil {
		t.Fatal("changed issuer accepted")
	}
	other := &Engine{Dir: filepath.Join(t.TempDir(), "other")}
	_ = other.base()
	if _, err := other.deploymentTLS(in); err == nil {
		t.Fatal("certificate accepted with a different destination key")
	}
}
