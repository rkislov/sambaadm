# sambaadm

**Аналог RSAT для Samba4 Active Directory** — управление доменом из одного бинарника: CLI, веб-интерфейс и REST API.

```text
go build → один файл sambaadm
         ├── CLI (cobra)
         ├── Web UI (SSR + HTMX, без SPA и без Node.js)
         └── REST API (/api/v1)
```

Linux-first: на контроллере домена удобно работать через `ldapi://` (Unix-сокет). Также поддерживаются `ldaps://` и кроссплатформенный запуск (Linux, Windows, macOS).

> **Статус:** этап 6 по ТЗ — тесты, документация, упаковка и релизный пайплайн. (Локальные шары `smb.conf` — дополнение вне нумерации этапов ТЗ, см. ниже.)

---

## Возможности

| Слой | Что есть сейчас |
|------|-----------------|
| **CLI** | … + `share`, `printer`, `acl` |
| **Web UI** | … + `/shares`, `/printers`, `/audit`, `/settings` |
| **REST** | … + `/api/v1/shares`, `/printers`, `/acl` |
| **LDAP** | `ldap://`, `ldaps://`, `ldapi://`, bind, paged search, add/modify/delete/moddn |
| **Безопасность** | cookie-сессии (HttpOnly), CSRF, RBAC по `memberOf`, журнал аудита |

Общая бизнес-логика живёт в `internal/service` и вызывается и из CLI, и из HTTP-хендлеров.

---

Обновлённые инструкции с иллюстрациями: [администратору в Word](docs/admin-guide/sambaadm-admin-guide.docx) и [пользователю в Word](docs/user-guide/sambaadm-user-guide.docx). Текстовые версии: [администратор](docs/admin.md), [пользователь](docs/user.md). Описывают текущую main / v0.23.0-dev, включая наследование GPO, удалённые политики ALT, топологию, мастер папок, профили Samba и метрики.

В main после v0.23.0 добавлен [отдельный файловый журнал событий](docs/web.md#файловый-журнал-событий-приложения): `logging.file` или `serve --log-file`, с сохранением вывода в stderr и отдельного аудита.


Актуальные возможности [веб-интерфейса](docs/web.md): дерево каталога, операции пользователей и групп, DNS, GPO и остальные административные разделы.

## Быстрый старт

### Готовый бинарник

Скачайте релиз для вашей ОС из [Releases](../../releases) и сделайте файл исполняемым (Linux):

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

Кросс-сборка Linux amd64 и Windows amd64:

```bash
make release-github
# → dist/sambaadm-linux-amd64
# → dist/sambaadm-windows-amd64.exe
# → dist/SHA256SUMS
```

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
sambaadm gpo distribute <gpo>   # SYSVOL → все DC + ACL, со статусом

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
| `/shares`, `/printers` | локальные шары smb.conf и принтеры |
| `/audit` | журнал аудита |
| `/settings` | язык интерфейса (ru/en) |
| `/api/v1/users` | JSON API (мутации: заголовок `X-CSRF-Token`) |
| `/healthz` | liveness |
| `/metrics` | Prometheus |

Фронтенд — серверный HTML (`html/template`) + HTMX; CSS/JS вшиты в бинарник через `embed`. Node.js в рантайме не нужен.

Роли задаются группами в `auth.roles` (DN). Если группы не заданы — все успешно вошедшие получают `admin`. CSRF обязателен для POST/PUT/PATCH/DELETE при наличии сессии (форма `csrf_token` или заголовок `X-CSRF-Token`).

---

## Архитектура

```text
┌─────────────────────────────────────────────┐
│                 sambaadm                    │
│  CLI (cobra)  │  HTTP (chi)  │  REST /api   │
│               └──────┬───────┴───────┬──────┘
│                      ▼               ▼
│              internal/service (ядро)
│                      ▼
│         LDAP / RPC / SMB
│                      ▼
│         embed: templates + static
└─────────────────────────────────────────────┘
                      ▼
               Samba4 AD DC
```

```text
cmd/sambaadm/          точка входа
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

## Установка на Linux (systemd)

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
make release   # linux/darwin/windows amd64+arm64
make docker
```

Целевой размер бинарника: ≤ 30 МБ (`-ldflags "-s -w"`).

---

## Совместимость

- Samba 4.15+ (интеграционные smoke-тесты — опционально через `testdata/`)
- Linux (основная платформа), Windows, macOS
- Go 1.22+ для сборки

---

## Дорожная карта (по ТЗ §12)

| # | Содержание | Статус |
|---|------------|--------|
| 1 | Каркас: cobra, chi, embed, конфиг, LDAP-клиент, auth | ✅ |
| 2 | Пользователи, группы, OU, компьютеры (CLI + Web + API) | ✅ |
| 3 | Доверия, домен, FSMO, репликация, сайты | ✅ |
| 4 | DNS, GPO (базовый) | ✅ |
| 5 | SSR-шаблоны, HTMX, локализация, RBAC, аудит | ✅ |
| 6 | Тесты, документация, упаковка, релиз | ✅ |

Подробнее: [`docs/ROADMAP.md`](docs/ROADMAP.md).

**Вне нумерации этапов ТЗ:** управление локальным `smb.conf` (общие папки, принтеры, POSIX ACL) — CLI `share`/`printer`/`acl`, UI `/shares` `/printers`, API `/api/v1/shares|printers|acl`.

---

## Документация

| Документ | Описание |
|----------|----------|
| [`docs/cli.md`](docs/cli.md) | CLI-справочник |
| [`docs/api.md`](docs/api.md) | REST API |
| [`docs/admin.md`](docs/admin.md) | Установка и администрирование |
| [`docs/security.md`](docs/security.md) | Безопасность |
| `/api/docs` | OpenAPI (встроенный просмотрщик) |

---

## Лицензия

[Apache License 2.0](LICENSE)

Разработано **Кисловым Романом Сергеевичем**. См. [NOTICE](NOTICE).

- GitHub: https://github.com/rkislov/sambaadm

### Сайты и репликация (v0.11.0)

Веб-интерфейс поддерживает топологию сайтов/DC/подсетей, перенос DC, IP Site Links со стоимостью и интервалом, расписания UTC для соединений, управление соединениями и запуск KCC. Состояние репликации показывает реальные результаты `drs showrepl` по разделам; зарегистрированный в AD контроллер не считается автоматически исправным. Подробнее: [веб-интерфейс](docs/web.md#сайты-и-репликация-v0110), [API](docs/api.md#топология-и-репликация-v0110).

Для проверки на двух одноразовых Samba DC: `SAMBAADM_TWO_DC=1 make integration`. DRS не копирует файлы SYSVOL; применение на ALT СП 10.2.2 требует отдельной приёмки.

Запись расписаний Site Link заблокирована из-за обнаруженного сбоя KCC Samba 4.17; причина показана в интерфейсе.

## Нативный доменный клиент v0.20.0

Доменные операции работают без `samba-tool` и Python Samba. [Запуск тестового домена на Mac, подключение и ограничения](docs/mac-domain.md).
