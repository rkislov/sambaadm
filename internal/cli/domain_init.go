package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sambaadm/internal/domaininit"
	"strings"
	"time"
)

func init() {
	var addr, dir string
	cmd := &cobra.Command{Use: "domain-init", Short: "Открыть веб-мастер создания нового леса Active Directory", Args: cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS != "linux" || os.Geteuid() != 0 {
				return fmt.Errorf("Запустите samba-domain-init от root на новом сервере ALT Linux")
			}
			engine := &domaininit.Engine{Dir: filepath.Join(dir, "domain-init")}
			readOnly := false
			for _, p := range []string{"/var/lib/samba/private/sam.ldb", "/var/lib/samba/sam.ldb", "/var/lib/samba/private/secrets.ldb"} {
				if _, err := os.Stat(p); err == nil {
					readOnly = true
				}
			}
			if readOnly {
				latest, err := engine.Latest()
				if err != nil || latest == nil {
					return fmt.Errorf("На сервере уже есть данные AD. Для дополнительного DC используйте мастер в работающей панели")
				}
			}

			if !filepath.IsAbs(dir) {
				return fmt.Errorf("Нужен абсолютный --state-dir")
			}
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			st, err := os.Lstat(dir)
			if err != nil {
				return err
			}
			if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("Каталог мастера требует прав 0700")
			}
			cert, fingerprint, err := initTLS()
			if err != nil {
				return err
			}
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			defer listener.Close()
			var nonce [32]byte
			if _, err = rand.Read(nonce[:]); err != nil {
				return err
			}
			token := hex.EncodeToString(nonce[:])
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			if host == "0.0.0.0" || host == "::" {
				host = "127.0.0.1"
				addresses, _ := net.InterfaceAddrs()
				for _, address := range addresses {
					ip, _, err := net.ParseCIDR(address.String())
					if err == nil && ip.To4() != nil && !ip.IsLoopback() {
						host = ip.String()
						break
					}
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Веб-интерфейс готов: https://%s\nКод доступа: %s\nSHA-256 сертификата: %s\nСверьте сертификат в браузере. Мастер доступен 2 часа; Ctrl+C закрывает доступ, запущенное развёртывание продолжает работу.\n", net.JoinHostPort(host, port), token, fingerprint)
			srv := &http.Server{Handler: domaininit.Bootstrap(engine, token, readOnly), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 210 * time.Second, MaxHeaderBytes: 16 << 10, IdleTimeout: 60 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
			go func() { <-cmd.Context().Done(); _ = srv.Close() }()
			err = srv.Serve(tls.NewListener(listener, srv.TLSConfig))
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		}}
	cmd.Flags().StringVar(&addr, "listen", "0.0.0.0:8445", "Адрес HTTPS мастера")
	cmd.Flags().StringVar(&dir, "state-dir", "/var/lib/sambaadm-domain-init", "Закрытый каталог журнала первоначальной установки")
	rootCmd.AddCommand(cmd)
}
func initTLS() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	host, _ := os.Hostname()
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "sambaadm initial setup"}, DNSNames: []string{"localhost", strings.ToLower(host)}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	addresses, _ := net.InterfaceAddrs()
	for _, a := range addresses {
		if ip, _, err := net.ParseCIDR(a.String()); err == nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	hash := sha256.Sum256(raw)
	return pair, hex.EncodeToString(hash[:]), err
}
