# CLI (каркас этапа 1)

```bash
sambaadm [global flags] <command>
```

## Глобальные флаги

| Флаг | Описание |
|------|----------|
| `-S, --server` | LDAP URI |
| `-U, --user` | bind-пользователь |
| `--realm` | Kerberos realm |
| `--config` | путь к YAML |
| `--json` | JSON-вывод |
| `-v, --verbose` | подробный лог |

## Команды

- `sambaadm version`
- `sambaadm serve [--listen=:8080] [--tls-cert] [--tls-key]`
- `sambaadm user list [--ou=...]` / `sambaadm user show <login>`
- `sambaadm group list`
- `sambaadm domain info`

Пароль bind — только через `SAMBAADM_PASSWORD` (или `password_env` из конфига).
