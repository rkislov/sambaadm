package service

// Certificate operations run only through the authenticated, root helper.
// Private DC keys are generated here and never returned to the management host.
import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sambaadm/internal/config"
	"sambaadm/internal/smbconf"
)

type CertificateDeployInput struct {
	ID          string `json:"id"`
	Node        string `json:"node"`
	CA          []byte `json:"ca,omitempty"`
	Certificate []byte `json:"certificate,omitempty"`
}
type CertificateDeployState struct {
	ID      string    `json:"id"`
	Node    string    `json:"node"`
	Phase   string    `json:"phase"`
	CSR     []byte    `json:"csr,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
	Backup  string    `json:"backup"`
	// These are operational metadata, never private keys.
	Service          string    `json:"service"`
	Revision         string    `json:"revision"`
	PreviousRevision string    `json:"previousRevision,omitempty"`
	Created          time.Time `json:"created"`
	Error            string    `json:"error,omitempty"`
}

func certificateDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func certificateRead(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !certificateRootOwned(st) || !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || st.Size() > 1<<20 {
		return nil, fmt.Errorf("unsafe certificate/configuration file: %s", path)
	}
	return os.ReadFile(path)
}
func certificateReplaceConfig(path string, data []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !certificateRootOwned(info) || !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe smb.conf")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".sambaadm-tls-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = preserveConfigOwner(f, info); err == nil {
		err = f.Chmod(info.Mode().Perm())
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func certificateWrite(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func certificateCommand(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %.1200s", filepath.Base(path), err, stderr.Bytes())
	}
	return bytes.TrimSpace(out), nil
}
func certificateParse(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("one PEM certificate required")
	}
	return x509.ParseCertificate(block.Bytes)
}
func certificateSafeDir(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("absolute certificate directory required")
	}
	// Refuse symlink traversal in every existing component, including a configured state path.
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(path), current), current) {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err = os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !certificateRootOwned(st) || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("unsafe certificate directory: %s", current)
		}
	}
	return nil
}
func certificateProbe(ctx context.Context, node string, expected []byte, ca []byte) error {
	conf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: node}
	if len(ca) > 0 {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			return fmt.Errorf("invalid CA")
		}
		conf.RootCAs = roots
	} else {
		// Pre-existing expired/legacy certificates are compared byte-for-byte, without credentials.
		conf.InsecureSkipVerify = true
	}
	conf.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, expected) {
			return fmt.Errorf("unexpected LDAPS certificate")
		}
		return nil
	}
	deadline := time.Now().Add(25 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: conf}
		conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:636")
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("LDAPS verification: %w", last)
}
func certificateConfig(conf string, values map[string]string) ([]byte, error) {
	data, err := certificateRead(conf)
	if err != nil {
		return nil, err
	}
	doc, err := smbconf.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	for key, value := range values {
		doc.SetParam("global", key, value)
	}
	var buf bytes.Buffer
	err = doc.Write(&buf)
	return buf.Bytes(), err
}

type certificateRuntime struct {
	command                          func(context.Context, string, ...string) ([]byte, error)
	probe                            func(context.Context, string, []byte, []byte) error
	tlsRoot, trustRoot, trustCommand string
}

func helperCertificate(ctx context.Context, cfg *config.Config, method string, raw json.RawMessage) (*CertificateDeployState, error) {
	return helperCertificateWith(ctx, cfg, method, raw, certificateRuntime{certificateCommand, certificateProbe, "/etc/samba/tls-sambaadm", "/etc/pki/ca-trust/source/anchors", "/usr/bin/update-ca-trust"})
}
func helperCertificateWith(ctx context.Context, cfg *config.Config, method string, raw json.RawMessage, runtime certificateRuntime) (*CertificateDeployState, error) {
	command := runtime.command
	probe := runtime.probe
	testparm := func(ctx context.Context, conf, param string) (string, error) {
		out, err := command(ctx, "/usr/bin/testparm", "-s", "--parameter-name="+param, conf)
		return string(out), err
	}
	restart := func(ctx context.Context, unit string) error {
		_, err := command(ctx, "/bin/systemctl", "restart", unit)
		return err
	}
	switch method {
	case "certificate.prepare", "certificate.status", "certificate.trust", "certificate.install", "certificate.rollback":
	default:
		return nil, fmt.Errorf("unsupported certificate operation")
	}
	var in CertificateDeployInput
	if err := decodeHost(raw, &in); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("certificate deployment requires root helper")
	}
	id, err := hex.DecodeString(in.ID)
	if err != nil || len(id) != 16 || hex.EncodeToString(id) != in.ID {
		return nil, fmt.Errorf("invalid certificate deployment ID")
	}
	if len(in.CA) > 64<<10 || len(in.Certificate) > 64<<10 {
		return nil, fmt.Errorf("certificate payload exceeds 64 KiB")
	}
	if in.Node == "" || !strings.EqualFold(in.Node, cfg.Helper.Node) {
		return nil, fmt.Errorf("certificate target does not match helper identity")
	}
	base := filepath.Join(cfg.Helper.StateDir, "ldap-certificates")
	if err = certificateSafeDir(base); err != nil {
		return nil, err
	}
	dir := filepath.Join(base, in.ID)
	statePath := filepath.Join(dir, "state.json")
	conf := cfg.Samba.SMBConf
	if !filepath.IsAbs(conf) {
		return nil, fmt.Errorf("absolute smb.conf path required")
	}
	if err = certificateSafeDir(filepath.Dir(conf)); err != nil {
		return nil, err
	}
	save := func(st *CertificateDeployState) error {
		data, e := json.Marshal(st)
		if e != nil {
			return e
		}
		return certificateWrite(statePath, data)
	}
	if method == "certificate.prepare" {
		if _, e := os.Lstat(dir); !os.IsNotExist(e) {
			return nil, fmt.Errorf("deployment ID already exists; inspect status instead of repeating prepare")
		}
		role, e := testparm(ctx, conf, "server role")
		if e != nil || !strings.EqualFold(role, "active directory domain controller") {
			return nil, fmt.Errorf("target is not a Samba AD DC")
		}
		realm, e := testparm(ctx, conf, "realm")
		if e != nil {
			return nil, e
		}
		name, e := testparm(ctx, conf, "netbios name")
		if e != nil {
			return nil, e
		}
		if !strings.EqualFold(name+"."+realm, in.Node) {
			return nil, fmt.Errorf("local Samba identity does not match requested DC")
		}
		original, e := certificateRead(conf)
		if e != nil {
			return nil, e
		}
		// External includes/registry configuration need a separate explicit migration.
		doc, e := smbconf.Parse(bytes.NewReader(original))
		if e != nil {
			return nil, e
		}
		for _, sectionName := range doc.SectionNames() {
			section, _ := doc.Get(sectionName)
			for _, key := range section.Keys {
				if strings.EqualFold(key.Name, "include") || strings.EqualFold(key.Name, "config backend") {
					return nil, fmt.Errorf("included/registry smb.conf is not supported for automatic certificate deployment")
				}
			}
		}
		unit := ""
		for _, candidate := range []string{"samba.service", "samba-ad-dc.service"} {
			if _, e = command(ctx, "/bin/systemctl", "is-active", "--quiet", candidate); e == nil {
				unit = candidate
				break
			}
		}
		if unit == "" {
			return nil, fmt.Errorf("active samba.service or samba-ad-dc.service required")
		}
		// Validate all platform tools before preparing a key or changing any DC.
		if _, e = os.Stat(runtime.trustCommand); e != nil {
			return nil, fmt.Errorf("ALT update-ca-trust is required")
		}
		if e = certificateSafeDir(runtime.trustRoot); e != nil {
			return nil, e
		}
		oldCertPath, e := testparm(ctx, conf, "tls certfile")
		if e != nil {
			return nil, e
		}
		caPath, e := testparm(ctx, conf, "tls cafile")
		if e != nil {
			return nil, e
		}
		private, e := testparm(ctx, conf, "private dir")
		if e != nil {
			return nil, e
		}
		resolve := func(path string) string {
			if !filepath.IsAbs(path) {
				return filepath.Join(private, path)
			}
			return path
		}
		oldCertPEM, e := certificateRead(resolve(oldCertPath))
		if e != nil {
			return nil, e
		}
		block, _ := pem.Decode(oldCertPEM)
		if block == nil {
			return nil, fmt.Errorf("current certificate missing")
		}
		if _, e = x509.ParseCertificate(block.Bytes); e != nil {
			return nil, e
		}
		oldCA, e := certificateRead(resolve(caPath))
		if e != nil {
			return nil, e
		}
		if e = probe(ctx, in.Node, block.Bytes, nil); e != nil {
			return nil, e
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return nil, e
		}
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		der, e := x509.MarshalECPrivateKey(key)
		if e != nil {
			return nil, e
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: in.Node}, DNSNames: []string{in.Node}}, key)
		if e != nil {
			return nil, e
		}
		for file, data := range map[string][]byte{"original.conf": original, "old-ca.pem": oldCA, "old-cert.der": block.Bytes, "key.pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})} {
			if e = certificateWrite(filepath.Join(dir, file), data); e != nil {
				return nil, e
			}
		}
		st := &CertificateDeployState{ID: in.ID, Node: in.Node, Phase: "prepared", CSR: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), Backup: dir, Service: unit, Revision: certificateDigest(original), Created: time.Now()}
		return st, save(st)
	}
	data, err := certificateRead(statePath)
	if err != nil {
		return nil, err
	}
	var st CertificateDeployState
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if st.Node != in.Node || st.ID != in.ID {
		return nil, fmt.Errorf("stored certificate target mismatch")
	}
	if method == "certificate.status" {
		return &st, nil
	}
	current, err := certificateRead(conf)
	if err != nil {
		return nil, err
	}
	if certificateDigest(current) != st.Revision {
		original, _ := certificateRead(filepath.Join(dir, "original.conf"))
		known := certificateDigest(current) == st.PreviousRevision || bytes.Equal(current, original)
		if method != "certificate.rollback" || !known || (st.Phase != "applying" && st.Phase != "rolling-back" && st.Phase != "failed") {
			return nil, fmt.Errorf("smb.conf changed since the reviewed certificate plan")
		}
	}

	if method == "certificate.rollback" {
		if st.Phase != "trusted" && st.Phase != "installed" && st.Phase != "failed" && st.Phase != "applying" && st.Phase != "rolling-back" {
			return nil, fmt.Errorf("no applied certificate state to roll back")
		}
		original, e := certificateRead(filepath.Join(dir, "original.conf"))
		if e != nil {
			return nil, e
		}
		st.PreviousRevision = certificateDigest(current)
		st.Revision = certificateDigest(original)
		st.Phase = "rolling-back"
		if e = save(&st); e != nil {
			return nil, e
		}
		if e = certificateReplaceConfig(conf, original); e != nil {
			return &st, e
		}
		e = restart(ctx, st.Service)
		if e == nil {
			old, _ := certificateRead(filepath.Join(dir, "old-cert.der"))
			e = probe(ctx, in.Node, old, nil)
		}
		if e != nil {
			st.Error = e.Error()
			save(&st)
			return &st, e
		}
		st.Phase = "rolled-back"
		st.Error = ""
		return &st, save(&st)
	}
	if time.Since(st.Created) > time.Hour && st.Phase == "prepared" {
		return nil, fmt.Errorf("certificate plan expired; prepare a new plan")
	}
	ca, err := certificateParse(in.CA)
	if err != nil {
		return nil, err
	}
	if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(ca.NotBefore) || time.Now().After(ca.NotAfter) {
		return nil, fmt.Errorf("valid signing CA required")
	}
	certDir := filepath.Join(runtime.tlsRoot, in.ID)
	if err = certificateSafeDir(certDir); err != nil {
		return nil, err
	}
	values := map[string]string{}
	expected, _ := certificateRead(filepath.Join(dir, "old-cert.der"))
	verifyCA := []byte(nil)
	switch method {
	case "certificate.trust":
		if st.Phase != "prepared" {
			return nil, fmt.Errorf("trust phase already attempted; inspect status")
		}
		oldCA, e := certificateRead(filepath.Join(dir, "old-ca.pem"))
		if e != nil {
			return nil, e
		}
		bundle := append([]byte{}, oldCA...)
		if !bytes.Contains(bundle, in.CA) {
			bundle = append(append(bundle, '\n'), in.CA...)
		}
		if e = certificateWrite(filepath.Join(certDir, "ca.pem"), bundle); e != nil {
			return nil, e
		}
		if e = certificateWrite(filepath.Join(certDir, "root.pem"), in.CA); e != nil {
			return nil, e
		}
		anchor := filepath.Join(runtime.trustRoot, "sambaadm-ldap-"+certificateDigest(ca.Raw)+".crt")
		if e = certificateWrite(anchor, in.CA); e != nil {
			return nil, e
		}
		if _, e = command(ctx, runtime.trustCommand); e != nil {
			return nil, e
		}
		values["tls cafile"] = filepath.Join(certDir, "ca.pem")
	case "certificate.install":
		if st.Phase != "trusted" {
			return nil, fmt.Errorf("trust must be deployed on every DC before certificate installation")
		}
		root, e := certificateRead(filepath.Join(certDir, "root.pem"))
		if e != nil || !bytes.Equal(root, in.CA) {
			return nil, fmt.Errorf("CA changed after trust phase")
		}
		leaf, e := certificateParse(in.Certificate)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		if _, e = leaf.Verify(x509.VerifyOptions{DNSName: in.Node, Roots: roots}); e != nil {
			return nil, e
		}
		keyPEM, e := certificateRead(filepath.Join(dir, "key.pem"))
		if e != nil {
			return nil, e
		}
		if _, e = tls.X509KeyPair(in.Certificate, keyPEM); e != nil {
			return nil, e
		}
		for file, data := range map[string][]byte{"key.pem": keyPEM, "cert.pem": in.Certificate} {
			if e = certificateWrite(filepath.Join(certDir, file), data); e != nil {
				return nil, e
			}
		}
		values["tls enabled"] = "yes"
		values["tls keyfile"] = filepath.Join(certDir, "key.pem")
		values["tls certfile"] = filepath.Join(certDir, "cert.pem")
		expected = leaf.Raw
		verifyCA = in.CA
		st.Expires = leaf.NotAfter
	default:
		return nil, fmt.Errorf("unsupported certificate operation")
	}
	proposed, err := certificateConfig(conf, values)
	if err != nil {
		return nil, err
	}
	candidate := filepath.Join(filepath.Dir(conf), ".sambaadm-certificate-"+in.ID+".conf")
	if err = certificateWrite(candidate, proposed); err != nil {
		return nil, err
	}
	defer os.Remove(candidate)
	if _, err = command(ctx, "/usr/bin/testparm", "-s", candidate); err != nil {
		return nil, err
	}
	// Persist the attempt before replacing the live configuration, so a lost response is inspectable.
	st.Phase = "applying"
	st.PreviousRevision = certificateDigest(current)
	st.Revision = certificateDigest(proposed)
	if err = save(&st); err != nil {
		return nil, err
	}
	if err = certificateReplaceConfig(conf, proposed); err == nil {
		err = restart(ctx, st.Service)
	}
	if err == nil {
		err = probe(ctx, in.Node, expected, verifyCA)
	}
	if err != nil {
		// Restore this node's immediately preceding configuration; other nodes are untouched.
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		live, readErr := certificateRead(conf)
		rollbackErr := readErr
		if readErr == nil {
			if !bytes.Equal(live, proposed) && !bytes.Equal(live, current) {
				rollbackErr = fmt.Errorf("smb.conf changed externally; automatic rollback refused")
			} else {
				rollbackErr = certificateReplaceConfig(conf, current)
				if rollbackErr == nil {
					rollbackErr = restart(recoveryCtx, st.Service)
				}
			}
		}
		st.PreviousRevision = certificateDigest(proposed)

		st.Phase = "failed"
		st.Error = fmt.Sprintf("%v; rollback: %v", err, rollbackErr)
		st.Revision = certificateDigest(current)
		save(&st)
		return &st, fmt.Errorf("%s", st.Error)
	}
	if method == "certificate.trust" {
		st.Phase = "trusted"
	} else {
		st.Phase = "installed"
	}
	st.Error = ""
	return &st, save(&st)
}
