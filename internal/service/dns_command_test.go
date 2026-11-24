package service

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestDNSCommandOutputExcludesDiagnostics(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestDNSOutputHelperProcess$")
	cmd.Env = append(os.Environ(), "SAMBAADM_DNS_OUTPUT_HELPER=1")
	out, err := dnsCommandOutput(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if out != "s3fs, rpc, dns" {
		t.Fatalf("diagnostics entered configuration value: %q", out)
	}
}
func TestDNSOutputHelperProcess(t *testing.T) {
	if os.Getenv("SAMBAADM_DNS_OUTPUT_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stderr, "Load smb config files from /etc/samba/smb.conf")
	fmt.Fprintln(os.Stderr, "Loaded services file OK.")
	fmt.Fprintln(os.Stdout, "s3fs, rpc, dns")
	os.Exit(0)
}
