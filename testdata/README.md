# Тестовый Samba4 (Docker)

Минимальный стенд для ручных и интеграционных проверок.

```bash
docker compose -f testdata/docker-compose.yml up -d
# дождаться окончания provisioning (логи: docker compose logs -f dc)

export SAMBAADM_PASSWORD='Passw0rd'
sambaadm -S 'ldap://127.0.0.1:389' -U 'Administrator@SAMBAADM.TEST' domain info
sambaadm -S 'ldap://127.0.0.1:389' -U 'Administrator@SAMBAADM.TEST' serve --listen=:8080
```

Интеграционные тесты (опционально):

```bash
SAMBAADM_IT=1 SAMBAADM_IT_URI='ldap://127.0.0.1:389' \
  SAMBAADM_IT_USER='Administrator@SAMBAADM.TEST' \
  SAMBAADM_PASSWORD='Passw0rd' \
  go test ./internal/service -run Integration -count=1
```
