# Руководство администратора

## Быстрый старт (≤ 30 минут)

1. Скачайте бинарник с [Releases](https://github.com/rkislov/sambaadm/releases) или соберите: `make build`.
2. Скопируйте конфиг:

```bash
sudo mkdir -p /etc/sambaadm /var/log/sambaadm
sudo cp configs/config.example.yaml /etc/sambaadm/config.yaml
```

3. Задайте LDAP URI / Base DN и роли. Пароль bind — только через ENV:

```bash
export SAMBAADM_PASSWORD='...'
```

4. Запуск:

```bash
sambaadm --config /etc/sambaadm/config.yaml serve --listen=:8080
```

5. Откройте `http://DC:8080/login`, войдите доменной УЗ.

На DC предпочтительно `ldap.uri: "ldapi://%2Fvar%2Frun%2Fsamba%2Fldapi"`.

## systemd

См. [`deploy/sambaadm.service`](../deploy/sambaadm.service) и раздел «Установка» в README.

Файл `/etc/sambaadm/env`:

```bash
SAMBAADM_PASSWORD=...
```

## Роли (RBAC)

В `auth.roles` указываются DN групп. При логине читается `memberOf`:

| Роль | Возможности |
|------|-------------|
| `readonly` | только чтение |
| `helpdesk` | сброс пароля, enable/disable |
| `admin` | все мутации |

Если группы не заданы — все успешно вошедшие получают `admin` (удобно для первого запуска).

## Локальные шары (дополнение)

Секция `samba:` в конфиге: путь к `smb.conf`, `shares_root`, команда reload. Процесс должен иметь права на запись конфига и создание каталогов. Подробнее — подсказки в UI `/shares`.

## Тестовый Samba4

```bash
cd testdata
docker compose up -d
# дождаться provisioning, затем:
export SAMBAADM_PASSWORD='Passw0rd'
./bin/sambaadm -S 'ldap://127.0.0.1:389' -U 'Administrator@SAMBAADM.TEST' serve
```

См. `testdata/README.md`.

## Shell completion

```bash
sambaadm completion bash > /etc/bash_completion.d/sambaadm
# или: source <(sambaadm completion zsh)
```
