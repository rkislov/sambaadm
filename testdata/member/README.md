# Файловый сервер: Winbind и SSSD + Winbind

```sh
ALT_BRANCH=p11 testdata/member/run.sh /tmp/sambaadm-member-results
ALT_BRANCH=p10 testdata/member/run.sh /tmp/sambaadm-member-p10-results
```

Требуются Docker с Linux-контейнерами и сеть для первоначальной сборки образов. Сценарий запускает отдельный Samba AD и два настоящих ALT p10 или p11 member server, без публикации портов на хост. Проверяет генерируемые приложением smb.conf/sssd.conf, Kerberos-присоединение, согласованные SID/UID/GID в Samba и NSS, занятое имя компьютера, подписанный SMB, права файла и наследуемый проход папок. Для SSSD проверяет также смену машинного пароля и вход по обновлённому keytab.

Контейнеры и их сеть удаляются при завершении; журналы сохраняются в выбранную папку. Фиксированный пароль относится только к одноразовому тестовому домену. Службы запускаются непосредственно внутри контейнеров: это не проверка загрузки systemd или полного мастера на ALT СП.

Проверки защитных условий установщика:

```sh
python3 -m unittest discover -s internal/domaininit -p 'test_*.py'
go test -race ./internal/domaininit ./internal/web ./internal/cli
```

Проверка интерфейса: `node testdata/web/server-init-member.cjs` с доступным Playwright.
