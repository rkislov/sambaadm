# CLI

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

Пароль bind — через `SAMBAADM_PASSWORD` (или `password_env` из конфига).

## Команды

### Сервер
- `sambaadm version`
- `sambaadm serve [--listen=:8080] [--tls-cert] [--tls-key]`

### Пользователи
- `sambaadm user list [--ou=DN]`
- `sambaadm user show <login>`
- `sambaadm user create --login=... [--display=...] [--ou=...] [--mail=...] [--prompt]`
- `sambaadm user delete <login>`
- `sambaadm user enable|disable <login>`
- `sambaadm user set-password <login>` — пароль с prompt; нужен LDAPS/ldapi
- `sambaadm user move <login> --to-ou=DN`

### Группы
- `sambaadm group list|show|create|delete`
- `sambaadm group add-member|remove-member <group> <member-dn>`
- `sambaadm group members <group>`

### Компьютеры
- `sambaadm computer list|show|delete`
- `sambaadm computer move <name> --to-ou=DN`

### OU
- `sambaadm ou list|tree`
- `sambaadm ou create --name=... [--parent=DN]`
- `sambaadm ou delete <dn>`
- `sambaadm ou move <dn> --to=DN`

### Домен
- `sambaadm domain info`
