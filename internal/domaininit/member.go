package domaininit

import (
	"fmt"
	"net/netip"
	"strings"
)

func (in Input) validateMember() error {
	if !DNS(in.Realm) || !shortName.MatchString(in.Hostname) || !shortName.MatchString(in.NetBIOS) || strings.EqualFold(in.Hostname, in.NetBIOS) {
		return fmt.Errorf("Укажите домен, NetBIOS и отдельное короткое имя файлового сервера")
	}
	if !DNS(in.Source) || !strings.HasSuffix(in.Source, "."+in.Realm) {
		return fmt.Errorf("Укажите контроллер этого домена")
	}
	if !DNS(in.PanelName) || !strings.HasSuffix(in.PanelName, "."+in.Realm) {
		return fmt.Errorf("Укажите HTTPS-имя существующей панели в домене")
	}
	if in.IdentityProvider != "winbind" && in.IdentityProvider != "sssd" {
		return fmt.Errorf("Выберите Winbind или SSSD + Winbind")
	}
	if in.Site != "" || in.Level != "" || in.ServiceUser != "" || in.TransferRoles || len(in.Certificate) > 0 || len(in.CA) > 0 {
		return fmt.Errorf("Файловый сервер не принимает параметры развёртывания контроллера")
	}
	for _, address := range []string{in.Address, in.Forwarder} {
		ip, e := netip.ParseAddr(address)
		if e != nil || !ip.Is4() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("Укажите IPv4 сервера и доменного DNS")
		}
	}
	if in.Address == in.Forwarder {
		return fmt.Errorf("Доменный DNS должен быть на другом сервере")
	}
	if len(in.Password) > 1024 || len(in.Username) > 256 || strings.ContainsAny(in.Password+in.Username, "\x00\r\n") || strings.ContainsAny(in.Username, "%") {
		return fmt.Errorf("Недопустимые учётные данные")
	}
	return nil
}
