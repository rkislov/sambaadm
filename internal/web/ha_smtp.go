package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type smtpOutcome struct {
	state  string
	reason string
}

func smtpFailure(phase string, err error, final bool) smtpOutcome {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		switch {
		case reply.Code >= 400 && reply.Code < 500:
			return smtpOutcome{"retry", fmt.Sprintf("%s · SMTP %d", phase, reply.Code)}
		case reply.Code >= 500 && reply.Code < 600:
			return smtpOutcome{"failed", fmt.Sprintf("%s · SMTP %d", phase, reply.Code)}
		}
	}
	if final {
		return smtpOutcome{"uncertain", "Соединение прервано до подтверждения приёма письма."}
	}
	var dnsErr *net.DNSError
	var networkErr net.Error
	var tlsAuthority x509.UnknownAuthorityError
	var tlsHost x509.HostnameError
	var tlsInvalid x509.CertificateInvalidError
	switch {
	case errors.As(err, &networkErr) && networkErr.Timeout(), errors.Is(err, context.DeadlineExceeded):
		phase += " · истекло время ожидания"
	case errors.Is(err, syscall.ECONNREFUSED):
		phase += " · сервер отказал в подключении"
	case errors.As(err, &dnsErr):
		phase += " · имя SMTP-сервера не удалось разрешить"
	case errors.As(err, &tlsAuthority):
		phase += " · центр сертификации не доверен"
	case errors.As(err, &tlsHost):
		phase += " · имя сервера не совпадает с сертификатом"
	case errors.As(err, &tlsInvalid):
		phase += " · сертификат недействителен"
	}
	return smtpOutcome{"retry", phase}
}

func sendHAMail(ctx context.Context, cfg haSMTPConfig, item haMailDelivery, id, publicURL string) smtpOutcome {
	password := ""
	if cfg.Username != "" {
		password = os.Getenv(haSMTPPassword)
		if password == "" {
			return smtpOutcome{"retry", "Пароль SMTP не задан в окружении Samba Admin."}
		}
	}
	remote := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	wire, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", remote)
	if err != nil {
		return smtpFailure("Не удалось подключиться к SMTP", err, false)
	}
	defer wire.Close()
	cancel := context.AfterFunc(ctx, func() { _ = wire.Close() })
	defer cancel()
	conn := wire
	timeout := func(limit time.Duration) {
		_ = wire.SetDeadline(time.Now().Add(limit))
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host}
	timeout(20 * time.Second)
	if cfg.Security == "tls" {
		secured := tls.Client(wire, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return smtpFailure("Не удалось установить TLS с SMTP", err, false)
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return smtpFailure("SMTP не подтвердил подключение", err, false)
	}
	defer client.Close()
	timeout(20 * time.Second)
	if cfg.Security == "starttls" {
		if err := client.StartTLS(tlsConfig); err != nil {
			return smtpFailure("SMTP не установил STARTTLS", err, false)
		}
	}
	if cfg.Username != "" {
		timeout(20 * time.Second)
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return smtpFailure("SMTP не подтвердил вход", err, false)
		}
	}
	timeout(20 * time.Second)
	if err := client.Mail(cfg.From); err != nil {
		return smtpFailure("SMTP отклонил отправителя", err, false)
	}
	timeout(20 * time.Second)
	if err := client.Rcpt(item.To); err != nil {
		return smtpFailure("SMTP отклонил получателя", err, false)
	}
	timeout(20 * time.Second)
	data, err := client.Data()
	if err != nil {
		return smtpFailure("SMTP отклонил начало передачи письма", err, false)
	}
	timeout(20 * time.Second)
	if _, err := data.Write(haMailMessage(cfg.From, item, id, publicURL)); err != nil {
		// Without the terminating dot, this envelope cannot be accepted.
		return smtpFailure("Передача письма прервалась", err, false)
	}
	timeout(90 * time.Second)
	if err := data.Close(); err != nil {
		return smtpFailure("SMTP отклонил приём письма", err, true)
	}
	return smtpOutcome{state: "sent"}
}

func haMailTitle(event string) string {
	switch event {
	case "smtp-test":
		return "Тестовое письмо"
	case "node-down":
		return "Узел недоступен"
	case "smb-moved":
		return "Переключение SMB"
	case "dhcp-moved":
		return "Переключение DHCP"
	case "reserve-restored":
		return "Резерв восстановлен"
	}
	return "Событие HA"
}

func haMailMessage(from string, item haMailDelivery, id, publicURL string) []byte {
	n := item.Event
	title := haMailTitle(haMailEvent(n))
	_, domain, _ := strings.Cut(from, "@")
	var message bytes.Buffer
	fmt.Fprintf(&message, "From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\n",
		from, item.To, mime.QEncoding.Encode("UTF-8", "Samba Admin · "+title), n.At.Format(time.RFC1123Z), id, domain)
	message.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	content := quotedprintable.NewWriter(&message)
	if n.Type == "smtp-test" {
		fmt.Fprint(content, "Тестовое письмо из Samba Admin. Оно отправлено при проверке настроек SMTP.\r\n")
		_ = content.Close()
		return message.Bytes()
	}
	fmt.Fprintf(content, "%s\r\nПодтверждено панелью: %s UTC\r\n", title, n.At.UTC().Format("2006-01-02 15:04:05"))
	if n.Node != "" {
		fmt.Fprintf(content, "Узел: %s\r\n", n.Node)
	}
	if len(n.Previous) > 0 {
		fmt.Fprintf(content, "Было: %s\r\n", strings.Join(n.Previous, ", "))
	}
	if len(n.Serving) > 0 {
		fmt.Fprintf(content, "Обслуживает: %s\r\n", strings.Join(n.Serving, ", "))
	}
	if len(n.Reserve) > 0 {
		fmt.Fprintf(content, "Резерв: %s\r\n", strings.Join(n.Reserve, ", "))
	}
	for _, source := range n.Sources {
		fmt.Fprintf(content, "\r\n%s\r\n", source.Label)
		if publicURL != "" {
			if link, err := url.Parse(publicURL); err == nil && (link.Scheme == "https" || link.Scheme == "http") && link.Host != "" {
				link.Path = strings.TrimRight(link.Path, "/") + "/"
				link.RawQuery = url.Values{"haKind": {source.Kind}, "haID": {source.ID}}.Encode()
				link.Fragment = "dashboard-services"
				fmt.Fprintf(content, "%s\r\n", link.String())
			}
		}
	}
	_ = content.Close()
	return message.Bytes()
}
