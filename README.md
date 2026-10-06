# sambaadm

**Аналог RSAT для Samba4 Active Directory** — управление доменом из одного бинарника: CLI, веб-интерфейс и REST API.

```text
go build → один файл sambaadm
         ├── CLI (cobra)
         ├── Web UI (SSR + HTMX, без SPA и без Node.js)
         └── REST API (/api/v1)
```

Linux-first: на контроллере домена удобно работать через `ldapi://` (Unix-сокет). Также поддерживаются `ldaps://` и кроссплатформенный запуск (Linux, Windows, macOS).

> **Статус:** этап 6 — локальный `smb.conf`: общие папки (mkdir + ACL), принтеры, права на каталоги (CLI/Web/API).

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

## Быстрый старт

### Готовый бинарник

Скачайте релиз для вашей ОС из [Releases](../../releases) и сделайте файл исполняемым (Linux):

```bash
chmod +x sambaadm-linux-amd64
./sambaadm-linux-amd64 version
./sambaadm-linux-amd64 serve --listen=:8080
```

Windows:

```powershell
.\sambaadm-windows-amd64.exe version
.\sambaadm-windows-amd64.exe serve --listen=:8080
```

Откройте http://localhost:8080/login

### Сборка из исходников

Требуется Go 1.24+ (модуль собирается с `go 1.26` toolchain).

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
│         LDAP / Kerberos / samba-tool
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
sudo install -m 755 sambaadm-linux-amd64 /usr/local/bin/sambaadm
sudo mkdir -p /etc/sambaadm /var/log/sambaadm
sudo cp configs/config.example.yaml /etc/sambaadm/config.yaml
sudo cp deploy/sambaadm.service /etc/systemd/system/
# отредактируйте /etc/sambaadm/config.yaml и ENV с паролем
sudo systemctl daemon-reload
sudo systemctl enable --now sambaadm
```

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

- Samba 4.15+ (тесты планируются на 4.19–4.21)
- Linux (основная платформа), Windows, macOS
- Go 1.22+ для сборки

---

## Дорожная карта

1. ~~Каркас: cobra, chi, embed, конфиг, LDAP, auth~~
2. ~~CRUD пользователей, групп, OU, компьютеров~~
3. ~~Доверия, FSMO, репликация, сайты~~
4. ~~DNS и базовый GPO~~
5. Полный SSR/HTMX, локализация, RBAC, аудит
6. Интеграционные тесты, документация, релизный пайплайн

---

## Лицензия

[Apache License 2.0](LICENSE)

Разработано **Кисловым Романом Сергеевичем**. См. [NOTICE](NOTICE).

- GitHub: https://github.com/rkislov/sambaadm
