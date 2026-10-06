# Безопасность

## Транспорт

- Production LDAP: только `ldaps://` или локальный `ldapi://`.
- Plain `ldap://` — только для изолированных лабораторий.
- Web UI: рекомендуется TLS (`server.tls.cert` / `key`).

## Секреты

- Пароль bind — `password_env` (по умолчанию `SAMBAADM_PASSWORD`), никогда в argv.
- Смена пароля пользователя: `--prompt` / интерактивный ввод.
- Файлы с секретами: права `0600`.

## Сессии и CSRF

- Cookie: `HttpOnly`, `SameSite=Lax`, `Secure` при TLS.
- Мутации (POST/PUT/PATCH/DELETE) требуют CSRF: поле `csrf_token` или заголовок `X-CSRF-Token`.

## RBAC

Роли из `memberOf` и `auth.roles` в YAML. Минимальный принцип привилегий: задайте группы Admins/Helpdesk явно.

## Аудит

Все мутирующие операции пишутся в `audit.file` (JSON lines) или в stderr. Просмотр: `/audit`.

## smb.conf / ACL

Изменение локального `smb.conf` и POSIX ACL выполняется **на хосте, где запущен sambaadm**, от имени процесса. Ограничьте `samba.shares_root` и права пользователя сервиса. `guest ok` на чувствительных шарах не включайте.

## Заголовки и поверхность атаки

- `/healthz`, `/metrics` — без сессии (не публикуйте metrics в интернет без защиты).
- OpenAPI `/api/docs` — справочный UI; в production при необходимости закройте reverse-proxy.
