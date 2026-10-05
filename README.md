# sambaadm

**Аналог RSAT для Samba4 Active Directory** — управление доменом из одного бинарника: CLI, веб-интерфейс и REST API.

```text
go build → один файл sambaadm
         ├── CLI (cobra)
         ├── Web UI (SSR + HTMX, без SPA и без Node.js)
         └── REST API (/api/v1)
```

Linux-first: на контроллере домена удобно работать через `ldapi://` (Unix-сокет). Также поддерживаются `ldaps://` и кроссплатформенный запуск (Linux, Windows, macOS).

> **Статус:** этап 1 — каркас. Есть конфиг, LDAP-клиент, сессии/RBAC-заготовки, `serve`, базовые команды `user` / `group` / `domain` и SSR-страницы. CRUD, доверия, FSMO, DNS и GPO — в следующих этапах.

---

## Возможности

| Слой | Что есть сейчас |
|------|-----------------|
| **CLI** | `serve`, `version`, `user list\|show`, `group list`, `domain info` |
| **Web UI** | логин, дашборд, пользователи, группы, домен (SSR + HTMX) |
| **REST** | `GET /api/v1/users`, `/groups`, `/domain`; `/healthz`, `/metrics` |
| **LDAP** | `ldap://`, `ldaps://`, `ldapi://`, simple bind, paged search |
| **Безопасность** | cookie-сессии (HttpOnly), роли readonly/helpdesk/admin (каркас), журнал аудита |

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

Требуется Go 1.22+.

```bash
git clone https://github.com/OWNER/sambaadm.git
cd sambaadm
make build
./bin/sambaadm serve --listen=:8080
```

Кросс-сборка Linux и Windows:

```bash
make release-github   # dist/sambaadm-linux-amd64, dist/sambaadm-windows-amd64.exe
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

sambaadm user list [--ou=DN]
sambaadm user show <login>

sambaadm group list
sambaadm domain info
```

Подробнее: [`docs/cli.md`](docs/cli.md).

---

## Web UI и API

После `sambaadm serve`:

| URL | Назначение |
|-----|------------|
| `/login` | вход (LDAP bind → сессия) |
| `/` | дашборд |
| `/users`, `/groups`, `/domain` | разделы UI |
| `/api/v1/users` | JSON API |
| `/healthz` | liveness |
| `/metrics` | Prometheus |

Фронтенд — серверный HTML (`html/template`) + HTMX; CSS/JS вшиты в бинарник через `embed`. Node.js в рантайме не нужен.

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
2. CRUD пользователей, групп, OU, компьютеров
3. Доверия, FSMO, репликация, сайты
4. DNS и базовый GPO
5. Полный SSR/HTMX, локализация, RBAC, аудит
6. Интеграционные тесты, документация, релизный пайплайн

---

## Лицензия

Пока не выбрана — уточняется. Исходный код публикуется для раннего ознакомления и обратной связи.
