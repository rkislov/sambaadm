package adremote

import (
	"context"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"net"
	"strconv"
	"strings"
	"time"
)

// SYSVOLKerberos uses a discovered DC as KDC and CIFS peer. It never falls
// back to NTLM or writes a ticket cache. The caller restricts source access.
func (c *Client) SYSVOLKerberos(ctx context.Context, port int, realm string, fn func(*smb2.Share) error) (err error) {
	defer func() {
		if problem := recover(); problem != nil {
			err = fmt.Errorf("Kerberos/SMB источника или получателя не подтверждён: %v", problem)
		}
	}()
	if c.Password == nil || c.User == "" {
		return fmt.Errorf("Настройте доменную служебную учётную запись панели")
	}
	realm = strings.ToUpper(realm)
	if strings.ContainsAny(realm+c.Host, "\r\n[]{} ") || realm == "" {
		return fmt.Errorf("Некорректное имя домена или DC")
	}
	user := c.User
	if _, u, ok := strings.Cut(user, `\`); ok {
		user = u
	} else if u, r, ok := strings.Cut(user, "@"); ok {
		if !strings.EqualFold(r, realm) {
			return fmt.Errorf("Для Kerberos задайте служебный логин с основным UPN домена или NETBIOS\\логин")
		}
		user = u
	}
	cfg, err := krbconfig.NewFromString("[libdefaults]\n default_realm = " + realm + "\n dns_lookup_kdc = false\n rdns = false\n[realms]\n " + realm + " = {\n  kdc = " + c.Host + ":88\n }\n")
	if err != nil {
		return err
	}
	k := client.NewWithPassword(user, realm, c.Password(), cfg, client.DisablePAFXFAST(true))
	defer k.Destroy()
	if err = k.Login(); err != nil {
		return fmt.Errorf("Kerberos источника SYSVOL: %w", err)
	}
	if port == 0 {
		port = 445
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	d := smb2.Dialer{Negotiator: smb2.Negotiator{RequireMessageSigning: true}, Initiator: &smb2.Krb5Initiator{Client: k, TargetSPN: "cifs/" + c.Host}}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	session, err := d.DialConn(ctx, conn, net.JoinHostPort(c.Host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer session.Logoff()
	sh, err := session.WithContext(ctx).Mount("SYSVOL")
	if err != nil {
		return err
	}
	defer sh.Umount()
	return fn(sh.WithContext(ctx))
}
