package filecluster_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/filecluster"
)

func TestIntegrationZFSSMBFailover(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_ZFS_FAILOVER") != "1" {
		t.Skip("disposable active cluster only")
	}
	client, root := clusterIntegrationClient(t)
	name, powerPort, iscsiPort := "files11", "18081", "3260"
	if os.Getenv("SAMBAADM_CLUSTER_BRANCH") == "p10" {
		name, powerPort, iscsiPort = "files10", "18082", "3261"
	}
	revision, err := os.ReadFile(filepath.Join(root, "active-revision"))
	if err != nil {
		t.Fatal(err)
	}
	password := os.Getenv("SAMBAADM_LAB_DOMAIN_PASSWORD")
	deniedPassword := os.Getenv("SAMBAADM_LAB_DENIED_PASSWORD")
	if password == "" || deniedPassword == "" {
		t.Fatal("lab passwords required")
	}
	pool := "sambaadm_" + name
	data := "/srv/samba-ha/" + name + "/data"
	id := "qa-" + nonce(t)[:10]
	ssh := func(index int, command, input string) string {
		t.Helper()
		out, err := labSSH(root, index, command, input)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	owner := -1
	for retry := 0; retry < 45; retry++ {
		for n := range labNodes {
			if _, e := labSSH(root, n, "systemctl is-active sambaadm-"+name+"-smb", ""); e == nil {
				owner = n
				break
			}
		}
		if owner >= 0 {
			break
		}
		time.Sleep(time.Second)
	}
	if owner < 0 {
		t.Fatal("SMB did not start")
	}
	peer := 1 - owner
	// Access fixture is installed only on the disposable dataset. Domain Users
	// can reach the share, but the private test folder permits just one AD SID.
	sid := strings.TrimSpace(os.Getenv("SAMBAADM_LAB_DOMAIN_SID"))
	if !regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$`).MatchString(sid) {
		t.Fatal("invalid lab domain SID")
	}
	fixture := data + "/" + id
	ssh(owner, fmt.Sprintf("test -f /etc/sambaadm-ha-lab && mountpoint -q %[1]s && mkdir -m 0700 %[2]s && setfacl -m u:1000500:rwx,d:u::rwx,d:u:1000500:rwx,d:g::---,d:m::rwx,d:o::--- %[2]s && getfacl -cpn %[2]s", data, fixture), "")
	smb := func(index int, user, pass, command string) (string, error) {
		// Password is passed only in stdin and a short-lived mode-0600 client file.
		script := fmt.Sprintf(`set -eu
umask 077
auth=$(mktemp)
trap 'rm -f "$auth"' EXIT
cat >"$auth"
timeout 10 smbclient //%s.sambaadm.test/files -I 10.77.0.50 -A "$auth" --client-protection=sign -c '%s'
`, name, command)
		return labSSH(root, index, "bash -c '"+strings.ReplaceAll(script, "'", "'\\''")+"'", "username = "+user+"\npassword = "+pass+"\ndomain = SAMBAADM\n")
	}
	assertRead := func(index int, path, expected string) {
		t.Helper()
		contents, e := smb(index, "Administrator", password, "get "+path+" -")
		if e != nil || !strings.Contains(contents, expected) {
			t.Fatalf("SMB read %s: %v %s", path, e, contents)
		}
	}
	before, after := "before-"+id, "after-"+id
	ssh(peer, "printf '%s' '"+before+"' > /tmp/"+id+"-before; printf '%s' '"+after+"' > /tmp/"+id+"-after", "")
	file := id + "/nested/document.txt"
	for deadline := time.Now().Add(25 * time.Second); ; {
		if output, loginErr := smb(peer, "Administrator", password, "ls"); loginErr == nil && !strings.Contains(output, "NT_STATUS") {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("SMB did not accept signed domain login: %v %s", loginErr, output)
		}
		time.Sleep(time.Second)
	}
	out, e := smb(peer, "Administrator", password, "mkdir "+id+"/nested; put /tmp/"+id+"-before "+file)
	if e != nil || strings.Contains(out, "NT_STATUS") {
		t.Fatalf("signed SMB write: %v %s", e, out)
	}
	assertRead(peer, file, before)
	acl := ssh(owner, "getfacl -cpn "+fixture+"/nested", "")
	if !strings.Contains(acl, "user:1000500:rwx") {
		t.Fatalf("inherited AD ACL missing: %s", acl)
	}
	denied := func() {
		t.Helper()
		listing, _ := smb(peer, "hadenied", deniedPassword, "ls "+id+"/nested/*")
		if !strings.Contains(listing, "NT_STATUS_ACCESS_DENIED") {
			t.Fatalf("nonmember was not denied: %s", listing)
		}
	}
	denied()
	var snap struct{ Name, Label, SMBTimestamp string }
	label := "До отключения активного узла"
	if err := labJob(client, labNodes[owner], "filecluster.snapshot", filecluster.ActivationInput{RequestID: nonce(t), Name: name, Revision: string(revision), Label: label}, &snap); err != nil {
		t.Fatal(err)
	}
	out, e = smb(peer, "Administrator", password, "put /tmp/"+id+"-after "+file)
	if e != nil || strings.Contains(out, "NT_STATUS") {
		t.Fatalf("signed SMB overwrite: %v %s", e, out)
	}
	assertRead(peer, file, after)
	assertRead(peer, snap.SMBTimestamp+"/"+file, before)

	// Interrupt one actual iSCSI session while SMB is serving from the map.
	portal := "10.0.3.2:" + iscsiPort
	target := "iqn.2026-11.test.sambaadm:ha"
	pathCommand := "iscsiadm -m node -T " + target + " -p " + portal
	ssh(owner, pathCommand+" --logout", "")
	defer func() { _, _ = labSSH(root, owner, pathCommand+" --login", "") }()
	assertRead(peer, file, after)
	topology := ssh(owner, "multipath -ll sambaadm-"+name, "")
	if strings.Count(topology, "active ready running") != 1 {
		t.Fatalf("expected one path during outage: %s", topology)
	}
	ssh(owner, pathCommand+" --login && udevadm settle && zpool sync "+pool, "")
	t.Log("PASS signed SMB with one iSCSI path disconnected")

	ca, err := os.ReadFile(filepath.Join(root, "power.crt"))
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca) {
		t.Fatal("invalid lab CA")
	}
	credential, err := os.ReadFile(filepath.Join(root, "power.secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credential)
	powerClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}}, Timeout: 20 * time.Second}
	endpoint := "https://127.0.0.1:" + powerPort + "/redfish/v1/Systems/" + strings.Split(labNodes[owner], ".")[0]
	power := func(method, path, payload string) (int, error) {
		request, e := http.NewRequest(method, endpoint+path, strings.NewReader(payload))
		if e != nil {
			return 0, e
		}
		request.SetBasicAuth("lab", string(bytes.TrimSpace(credential)))
		request.Header.Set("Content-Type", "application/json")
		result, e := powerClient.Do(request)
		if e != nil {
			return 0, e
		}
		defer result.Body.Close()
		if method == "GET" {
			var status struct{ PowerState string }
			if e = json.NewDecoder(result.Body).Decode(&status); e != nil || status.PowerState != "Off" {
				return result.StatusCode, fmt.Errorf("expected physical power off: %v %q", e, status.PowerState)
			}
		}
		return result.StatusCode, nil
	}
	start := time.Now()
	if code, e := power("POST", "/Actions/ComputerSystem.Reset", `{"ResetType":"ForceOff"}`); e != nil || code != 204 {
		t.Fatalf("power off: %d %v", code, e)
	}
	defer func() {
		if code, e := power("POST", "/Actions/ComputerSystem.Reset", `{"ResetType":"On"}`); e != nil || code != 204 {
			t.Errorf("restore original node: %d %v", code, e)
		}
	}()
	var last string
	for deadline := time.Now().Add(165 * time.Second); time.Now().Before(deadline); {
		last, e = smb(peer, "Administrator", password, "get "+file+" -")
		if e == nil && strings.Contains(last, after) {
			break
		}
		time.Sleep(time.Second)
	}
	if e != nil || !strings.Contains(last, after) {
		t.Fatalf("SMB never returned on surviving node: %v %s", e, last)
	}
	elapsed := time.Since(start)
	if _, e := power("GET", "", ""); e != nil {
		t.Fatal(e)
	}
	ssh(peer, "systemctl is-active sambaadm-"+name+"-smb && mountpoint -q "+data, "")
	fencing := ssh(peer, "stonith_admin --history "+labNodes[owner], "")
	if !strings.Contains(strings.ToLower(fencing), "success") {
		t.Fatalf("no successful fencing in cluster history: %s", fencing)
	}
	aclAfter := ssh(peer, "getfacl -cpn "+fixture+"/nested", "")
	if aclAfter != acl {
		t.Fatalf("ACL changed after failover: %q vs %q", acl, aclAfter)
	}
	denied()
	assertRead(peer, snap.SMBTimestamp+"/"+file, before)
	got := ssh(peer, "zfs get -H -o value org.sambaadm:label "+pool+"/data@"+snap.Name, "")
	if got != label {
		t.Fatalf("snapshot name changed: %q", got)
	}
	newFile := id + "/nested/after-failover.txt"
	out, e = smb(peer, "Administrator", password, "put /tmp/"+id+"-after "+newFile)
	if e != nil || strings.Contains(out, "NT_STATUS") {
		t.Fatalf("write after failover: %v %s", e, out)
	}
	assertRead(peer, newFile, after)
	t.Logf("PASS %s → %s in %s: signed SMB, identical inherited ACL, access denial, named snapshot and Previous Versions; fencing: %s", labNodes[owner], labNodes[peer], elapsed.Round(time.Second), fencing)
}
