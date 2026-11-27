# sambaadm

**Единая панель управления доменом Samba Active Directory.** Русский веб-интерфейс для повседневной работы администратора: учётные записи, групповые политики, DNS, контроллеры и репликация. Предпросмотр изменений, защита от конфликтов и отчёт по каждому серверу помогают выполнять массовые операции и разбирать частичные сбои.

Для автоматизации доступны CLI и REST API. Отдельный `sambaadm-helper` выполняет операции на Linux-серверах: доставка SYSVOL, настройка служб, сертификаты, резервное копирование и восстановление. Панель поддерживает Kerberos SSO и вход по логину и паролю.

[Скачать последний релиз](https://github.com/rkislov/sambaadm/releases/latest) · [Вся документация](docs/README.md) · [Плагин Caja: скачать и установить](docs/caja-plugin.md) · [Быстрая установка](docs/quick-install.md) · [Полная инструкция для ALT](docs/alt-install.md) · [Развёртывание нового домена](docs/domain-init.md) · [Руководство администратора](docs/admin.md) · [Руководство пользователя](docs/user.md)

## Релиз v0.55.2

Карточки, таблицы, диалоги и мастера используют общий стиль Tailwind. Добавление ролей доступно через кнопку «+» над списком серверов.

В выпуск вошли управление DHCP Kea и CUPS, файловые HA-кластеры, карта прав каталогов и мастер Windows/Samba AD для присоединения файлового сервера. Операции на узлах выполняет `sambaadm-helper`.

[Описание v0.55.2](docs/releases/v0.55.2.md) · [Быстрая установка и обновление](docs/quick-install.md).

## Возможности

- **Каталог Active Directory.** Пользователи, группы, компьютеры и подразделения (OU). Просмотр свойств, управление членством в группах, перенос объектов и сброс паролей. [Работа с каталогом](docs/web.md#каталог).
- **Домен, сайты и репликация.** Роли FSMO, функциональные уровни, сайты, подсети, межсайтовые связи, доверия и соединения репликации. Можно проверить репликацию по разделам каталога, запустить синхронизацию и пересчёт KCC. Интерактивная карта показывает RWDC, RODC и связи между доменами. Раскладку можно выгрузить в редактируемый файл Draw.io. [Интерактивная топология](docs/releases/v0.43.1.md) · [Управление связями](docs/releases/v0.43.4.md).
- **DNS.** Делегирование поддоменов, условная пересылка и доставка правил на BIND9 DLZ через helper, переключение бэкенда на ALT Linux. [Настройка маршрутизации DNS](docs/dns-routing.md). Диспетчер в стиле RSAT с зонами прямого и обратного просмотра, деревом имён, поиском и фильтром по типу записи. Создание зон и записей, редактирование значений и TTL через DNS RPC. [Диспетчер DNS](docs/web.md#dns).
- **DHCP Kea.** Оснастка в стиле RSAT через helper: установка пакетов АЛЬТ p10/p11, службы IPv4/IPv6, области, пулы, резервирования, активные аренды, relay, HA-пара и автонастройка DDNS с подсказками DNS-зон. Защищённый DNS Samba AD: установка GSS-TSIG, AES keytab, права зон и общая DNS-идентичность HA-пары через helper. Поиск, страницы и сортировка в таблицах. [Установка и настройка](docs/dhcp-kea.md).
- **Групповые политики.** Создание и привязка GPO, резервное копирование и восстановление, редактирование сценариев и поддерживаемых параметров ADMX/ADML из каталога шаблонов Windows, ALT Linux и других поставщиков. Доступны моделирование результирующей политики для пользователя и компьютера с экспортом JSON и просмотр фактического отчёта RSoP из Windows `gpresult /x result.xml`. [Редактор GPO](docs/web.md#gpo) · [Моделирование и RSoP](docs/releases/v0.42.1.md).
- **Доставка и проверка SYSVOL.** Доставка одной или всех политик домена с отображением прогресса и ошибок по контроллерам. Проверка согласованности GPO поддерживает до 100 обнаруженных DC и формирует отчёты HTML и JSON. Для устранения расхождений доступно управляемое исправление с архивом и журналом. [Проверка SYSVOL](docs/web.md#согласованность-sysvol) · [Массовая доставка](docs/releases/v0.42.7.md).
- **RODC и аутентификация.** Управление Password Replication Policy и принудительное заполнение кэша выбранного RODC. По настроенному JSON-аудиту Samba можно просматривать входы на RWDC и RODC и искать учётную запись по контроллерам. [Работа с RODC](docs/admin.md#назначение-учётных-записей-для-rodc) · [Журналы аутентификации](docs/releases/v0.42.6.md).
- **Резервное копирование и восстановление домена.** Логические снимки пользователей, АРМ и GPO с SYSVOL; выборочное восстановление удалённых учётных записей с исходными SID/GUID и политик в новую GPO. Предпросмотр, проверка конфликтов и аудит. Полный холодный бэкап RWDC через helper с изолированной проверкой восстановления. При полной потере однодоменного леса — восстановление первого DC с новым именем в новый каталог, через helper или локальные команды без LDAP. [Восстановление домена](docs/domain-recovery.md). [Возможности и ограничения](docs/domain-object-backups.md).
- **Личный кабинет.** Собственный профиль, контактные данные и фотография, смена пароля, просмотр групп, истории входов и сведений о сайте/DC. Личность привязана к GUID учётной записи.
- **Время и NTP.** Наблюдение за chrony и настройка источников через helper: предпросмотр, проверка синтаксиса, резервная копия и подтверждённое применение. Поддерживается внутренняя опора изолированного стенда. [Настройка времени](docs/time-settings.md).
- **Обследование домена.** Обзор состояния контроллеров, экспорт результатов, поиск остатков выведенных DC и подготовка плана очистки LDAP. Для площадок без сетевого доступа можно собрать снимки локально через `sambaadm-helper collect`, затем импортировать их и сформировать сводный отчёт. Профиль рабочей станции ALT собирает наблюдения SSSD/Kerberos, DNS/DC/KDC и машинного GPResult; доступны карточка станции, сравнение снимков и оценка полноты материалов. [Обследование домена](docs/admin.md#обзор-и-обследование-домена) · [Автономный сбор](docs/offline-survey.md).
- **Файловые ресурсы и печать.** Публикация общих папок Samba и очередей CUPS, настройка параметров ресурсов, POSIX ACL и расширенных атрибутов. Для ALT p10 есть отдельное расширение Caja для просмотра предыдущих версий SMB. [Общие папки и принтеры](docs/web.md#остальные-разделы) · [Расширение Caja](contrib/caja-shadow-copies/README.md).

## Агент для операций на серверах

Установите `sambaadm-helper` на каждом Linux-узле, где sambaadm должен выполнять
операции с файлами, SYSVOL или службами. Для доставки GPO агент нужен на
контроллерах-источниках и получателях. Поддерживаются HTTPS API и SSH, запросы
подписываются ключом управляющего сервера. Операции LDAP, DNS RPC и DRS выполняет
само приложение. [Настройка и регистрация helper](docs/helper.md).

Для RPM начиная с 0.45.5 используйте [короткую инструкцию установки](docs/quick-install.md):
мастер настраивает HTTPS с доменным именем; Kerberos SSO подключается дополнительно,
вход по паролю сохраняется. В панели доступен общий поиск пользователей, групп и компьютеров.

PSO доступны в разделе «Домен и FSMO»: параметры, приоритеты и назначения
пользователям/глобальным группам безопасности. В карточке пользователя показана
[результирующая парольная политика с DC](docs/admin.md#детальные-парольные-политики-pso).

## Быстрый старт

### Готовый бинарник

При первом `sambaadm serve`, если конфигурация отсутствует, приложение определяет
домен и контроллер по локальной Samba/DNS и создаёт `config.yaml` в текущем
каталоге (либо по пути `--config`, родительский каталог должен существовать).
Существующий конфиг не изменяется. Если обнаружение неоднозначно, задайте параметры:

```bash
sambaadm discover --realm corp.example --dc dc1.corp.example --output config.yaml
```

Проверьте предложенную запись `svc-sambaadm@corp.example` и группу администраторов;
служебная запись должна уже существовать в домене. Задайте её пароль через
`SAMBAADM_PASSWORD`, при необходимости укажите доверенный CA через `discover --ca`.
Пароли в генерируемый файл не записываются. Автонастройка не создаёт доменную запись.
Для работы службы нужны доступные ей каталоги `/var/lib/sambaadm` и
`/var/log/sambaadm`; на Linux их готовит установка с systemd, описанная ниже.
`serve --check` только проверяет настройки и не создаёт конфигурацию.


Скачайте релиз для вашей ОС из [Releases](https://github.com/rkislov/sambaadm/releases/latest) и сделайте файл исполняемым (Linux):

```bash
chmod +x sambaadm-linux-amd64
./sambaadm-linux-amd64 version
./sambaadm-linux-amd64 serve --listen=:8080
```

### ALT SP Workstation 10.2.2 (x86-64)

Используйте `sambaadm-linux-amd64`. Сборки через `make build`, `make release`
и `make release-github` выполняются с `CGO_ENABLED=0`: Linux-бинарник статический
и не требует glibc, в том числе `GLIBC_2.34`. Обновлять системную glibc для запуска
не нужно. Для пересборки на другой ОС:

```bash
make release-github
# Перенесите dist/sambaadm-linux-amd64 на ALT Linux, затем:
chmod +x sambaadm-linux-amd64
./sambaadm-linux-amd64 version
./sambaadm-linux-amd64 serve --listen=:8081
```

Откройте http://localhost:8081/login. Для работы с доменом настройте LDAP;
операции Samba, ACL и печати используют внешние системные утилиты
(`getfacl`/`setfacl`, `getfattr`/`setfattr`, `lpstat`).

Windows:

```powershell
.\sambaadm-windows-amd64.exe version
.\sambaadm-windows-amd64.exe serve --listen=:8080
```

Откройте http://localhost:8080/login

### Сборка из исходников

Требуется Go 1.26 или новее.

```bash
git clone https://github.com/rkislov/sambaadm.git
cd sambaadm
make build
./bin/sambaadm serve --listen=:8080
```

`make release` собирает sambaadm для Linux, macOS и Windows, а также helper для Linux. Готовые файлы появляются в `dist/`.

---

## Конфигурация

Приоритет: **флаги > переменные окружения `SAMBAADM_*` > YAML > значения по умолчанию**.

Для веб-входа обязательны служебная запись `ldap.bind.user` и её пароль в переменной `password_env`. Проверка пароля и групп входящего пользователя выполняется на отдельном соединении; операции каталога используют служебную запись. Ошибка определения прав или служебного Bind отклоняет вход.

Пример: [`configs/config.example.yaml`](configs/config.example.yaml)

```yaml
server:
  listen: ":8080"
  metrics: true

ldap:
  uri: "ldaps://dc1.example.com:636"
  # uri: "ldapi://%2Fvar%2Frun%2Fsamba%2Fldapi"
  base_dn: "DC=example,DC=com"
  bind:
    type: simple
    user: "administrator@example.com"
    password_env: SAMBAADM_PASSWORD

auth:
  session_ttl: 8h
  roles:
    admins:
      - "CN=Domain Admins,CN=Users,DC=example,DC=com"
    helpdesk:
      - "CN=Helpdesk,OU=Groups,DC=example,DC=com"

audit:
  file: /var/log/sambaadm/audit.log

logging:
  level: info
```

Пароль **никогда** не передаётся в argv — только через ENV:

```bash
export SAMBAADM_PASSWORD='...'
./sambaadm --config /etc/sambaadm/config.yaml -S ldaps://dc1.example.com user list
```

На DC локально:

```bash
./sambaadm -S 'ldapi://%2Fvar%2Frun%2Fsamba%2Fldapi' --config /etc/sambaadm/config.yaml serve
```

---

## CLI

```bash
sambaadm [global flags] <command>
```

**Глобальные флаги**

| Флаг | Описание |
|------|----------|
| `-S, --server` | LDAP URI (`ldap://`, `ldaps://`, `ldapi://`) |
| `-U, --user` | учётная запись для bind |
| `--realm` | Kerberos realm |
| `--config` | путь к YAML |
| `--json` | машиночитаемый вывод |
| `-v, --verbose` | подробный лог |

**Команды**

```bash
sambaadm version
sambaadm serve [--listen=:8080] [--tls-cert=...] [--tls-key=...]

sambaadm user list|show|create|delete|enable|disable|set-password|move
sambaadm group list|show|create|delete|add-member|remove-member|members
sambaadm computer list|show|delete|move
sambaadm ou list|tree|create|delete|move
sambaadm trust list|show|create|delete|validate
sambaadm domain info|fsmo|level
sambaadm repl partners|status|sync
sambaadm site list|create|delete
sambaadm subnet list|create|delete
sambaadm dns zone list|create|delete
sambaadm dns record query|add|update|delete
sambaadm gpo list|show|create|delete|link|unlink|backup|restore
sambaadm gpo distribute <gpo>   # доставка GPO на контроллеры со статусом

sambaadm share list|show|create|delete|set|reload
sambaadm printer list|create|delete
sambaadm acl get|set <path>
```

Пароль пользователя: только через `--prompt` / интерактивный ввод (не в argv). Смена `unicodePwd` требует `ldaps://` или `ldapi://`.

Подробнее: [`docs/cli.md`](docs/cli.md).

---

## Web UI и API

После `sambaadm serve`:

| URL | Назначение |
|-----|------------|
| `/login` | вход (LDAP bind → `memberOf` → роль → сессия) |
| `/` | дашборд |
| `/users` … `/gpo`, `/domain` | разделы UI |
| `/shares`, `/printers` | общие папки Samba и принтеры на управляемом узле |
| `/surveys` | материалы автономного обследования |
| `/settings/helpers` | регистрация управляемых узлов |
| `/audit` | журнал аудита |
| `/settings` | настройки интерфейса и редактора GPO |
| `/api/v1/users`, `/api/docs` | пример ресурса REST API и встроенная документация OpenAPI |
| `/healthz` | liveness |
| `/metrics` | Prometheus |

Фронтенд — серверный HTML (`html/template`) + HTMX; CSS/JS вшиты в бинарник через `embed`. Node.js в рантайме не нужен.

Роли задаются группами в `auth.roles` (DN). Если группы не заданы — все успешно вошедшие получают `admin`. CSRF обязателен для POST/PUT/PATCH/DELETE при наличии сессии (форма `csrf_token` или заголовок `X-CSRF-Token`). Для доступа к SYSVOL через helper доступны зашифрованные учётные данные текущей сессии. [Настройка доступа к SYSVOL](docs/session-credentials.md).

---

## Архитектура

CLI и HTTP используют общую логику из `internal/service`. Приложение подключается
к Samba AD через LDAP, RPC и SMB и делегирует операции на Linux-узлах
зарегистрированным агентам.

```text
cmd/sambaadm/          приложение и CLI
cmd/sambaadm-helper/   агент для Linux-узлов
internal/
  cli/                 команды cobra
  service/             бизнес-логика
  ldap/                клиент LDAP
  smbconf/             разбор/запись smb.conf
  web/                 UI + API + embed
  auth/                сессии, RBAC
  config/              Viper (YAML/ENV/flags)
  audit/               журнал действий
deploy/                systemd unit
configs/               примеры конфигурации
```

---

## Установка на ALT Linux (RPM)

[Короткая инструкция](docs/quick-install.md) — установка, мастер и вход через SSH-туннель.
Мастер `sambaadm-setup` включён в новые сборки из main; в старом релизе v0.45.0
его ещё нет. Используйте RPM и инструкции одной сборки.

В [релизах](https://github.com/rkislov/sambaadm/releases/latest) доступны отдельные
RPM и комплекты установки для ALT Linux p10 и p11 на x86_64 и aarch64.
Сверьте SHA-256 архива, распакуйте его и выполните из каталога комплекта:

```bash
sh setup-alt.sh all --check
sudo sh setup-alt.sh all
```

После установки отдельного RPM выполните `sudo sambaadm-setup`: мастер определит
домен, запросит служебную запись и пароль, проверит LDAPS и запустит интерфейс.
Мастер входит в RPM; искать скрипт в архиве или вручную редактировать конфиги
для первого запуска больше не требуется.

После настройки проверьте `systemctl is-active sambaadm`. Панель доступна на
`http://127.0.0.1:8080/login` самого сервера. Для входа с рабочего компьютера
выполните на нём `ssh -N -L 127.0.0.1:8080:127.0.0.1:8080 linux-user@server.example`,
откройте тот же адрес в браузере и войдите доменной записью `login@domain`.

Режим `all` устанавливает sambaadm и локальный helper. Для установки только
приложения используйте `server`, для удалённого узла — `helper`.
[Установка, обновление и откат](docs/alt-install.md).

## Ручная установка на Linux (systemd)

```bash
# Из каталога исходников соответствующей версии:
sudo sh deploy/install.sh ./sambaadm-linux-amd64
sudoedit /etc/sambaadm/config.yaml
sudoedit /etc/sambaadm/env
# В env: SAMBAADM_PASSWORD="пароль служебной доменной записи"
sudo systemctl enable --now sambaadm
sudo journalctl -u sambaadm -n 100 --no-pager
```

Скрипт создаёт системного пользователя и группу `sambaadm`, каталог журналов
с нужным владельцем и обязательный `/etc/sambaadm/env`. Существующие YAML и env
не перезаписываются. Сам сервис скрипт не запускает: сначала настройте подключение.
При обновлении уже работающего сервиса выполните `sudo systemctl restart sambaadm`.

`User=sambaadm` — локальная учётная запись процесса. Доменными операциями управляет
`ldap.bind.user` из конфигурации (пароль из переменной, указанной в `password_env`).
Вход администратора домена в браузере **не переключает** служебную доменную запись.
Отказ `ERROR_DS_DRA_ACCESS_DENIED` нужно проверять для этой записи на выбранном DC.
Отсутствие локального пользователя — другая ошибка: systemd не сможет запустить процесс.

---

## Docker

```bash
docker build -t sambaadm .
docker run --rm -p 8080:8080 \
  -e SAMBAADM_PASSWORD=... \
  sambaadm serve --listen=:8080
```

---

## Разработка

```bash
make build     # bin/sambaadm
make test
make lint      # golangci-lint
make release   # Linux/macOS amd64 и arm64, Windows amd64
make docker
```

После изменения шаблонов или стилей выполните `make ui`. Исходные стили находятся в `ui/styles.css`, результат сборки — в `internal/web/static/css/ui.css`.

---

## Совместимость

- Samba 4.15+. Интеграционные проверки описаны в [testdata/README.md](testdata/README.md).
- Готовые сборки sambaadm доступны для Linux и macOS (amd64, arm64) и Windows (amd64). Для helper используется Linux.
- Для сборки из исходников нужен Go 1.26 или новее.

## Документация

- [Руководство администратора](docs/admin.md) · [версия Word](docs/admin-guide/sambaadm-admin-guide.docx)
- [Руководство пользователя](docs/user.md) · [версия Word](docs/user-guide/sambaadm-user-guide.docx)
- [Веб-интерфейс](docs/web.md) · [CLI](docs/cli.md) · [REST API](docs/api.md)
- [Резервные копии объектов и DC](docs/domain-object-backups.md) · [Восстановление домена](docs/domain-recovery.md) · [Время и NTP](docs/time-settings.md) · [Обследование рабочих станций](docs/offline-survey.md)
- [Безопасность](docs/security.md) · [Дорожная карта](docs/ROADMAP.md) · [История релизов](https://github.com/rkislov/sambaadm/releases)

## Лицензия

[Apache License 2.0](LICENSE) · [NOTICE](NOTICE)

<!-- owner-maintenance:start -->
**Автор проекта, изменений и публикаций — Кислов Роман Сергеевич ([@rkislov](https://github.com/rkislov)).**

Ошибки и предложения принимаются через **Issues**, изменения — через **Pull Requests** из форков. Прямую запись в основной репозиторий и публикацию версий выполняет только владелец `rkislov`.
<!-- owner-maintenance:end -->

## Делегирование и пересылка DNS

[Поддомены, доставка правил на BIND9 DLZ и переключение DNS-бэкенда](docs/dns-routing.md).
