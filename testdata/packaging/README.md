# Проверка RPM на ALT p10

На Linux с Docker (amd64), либо `RPM_ARCH=arm64` на ARM:

```bash
make rpm-alt VERSION=0.25.0 RPM_ARCH=amd64
docker run --rm -v "$PWD:/src:ro" sambaadm-rpm-builder:p10-amd64 \
  bash testdata/packaging/test-alt.sh /src/dist/sambaadm-linux-amd64
```

Сценарий устанавливает настоящие RPM в одноразовом ALT p10 и проверяет обновление,
`.rpmnew`, сохранность YAML/env/прав, downgrade/rollback, восстановление при отказе
старта, stopped-state, блокировку и удаление. Вызовы systemd моделируются: это
проверка транзакций и файловой системы, а не приёмка systemd или ALT СП.

Для проверки реального systemd (одноразовый привилегированный контейнер):

```bash
docker run -d --name sambaadm-alt-systemd --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock -v "$PWD:/src:ro" \
  sambaadm-rpm-builder:p10-amd64 /lib/systemd/systemd
docker exec -e SAMBAADM_REAL_SYSTEMD=1 sambaadm-alt-systemd \
  bash /src/testdata/packaging/test-alt.sh /src/dist/sambaadm-linux-amd64
docker rm -f sambaadm-alt-systemd
```

Этот вариант проверяет реальный MainPID, старт, обновление, откат, восстановление
после поставки намеренно сломанного unit и HTTP `/healthz`. Он включён в CI.

Пакет содержит systemd-unit, который также проверяется `systemd-analyze
verify` в сборочном образе. Для целевой системы нужны отдельные проверки:

1. Установка RPM и запуск с реальным LDAP/TLS/env, проверка `systemctl status` и
   журнала, веб-входа, `/diagnostics`.
2. Обновление активного и остановленного сервиса с изменённым YAML/env/drop-in.
3. `rollback` с проверкой версии, настроек и состояния процесса.
4. Убедиться, что ProtectSystem/ReadWritePaths соответствуют выбранным сценариям
   локальных шаров; права на AD и SYSVOL проверяются отдельно.

## Сетевой bootstrap

```sh
docker run --rm -v "$PWD:/src:ro" sambaadm-rpm-builder:p10-amd64 \
  bash testdata/packaging/test-build-deps.sh
```

Тест не обращается к сети: проверяет переход к следующему зеркалу, жёсткие
таймауты update/install, отказ при ошибке всех зеркал и сохранение политики
проверки подписей. Настоящая загрузка зависимостей проверяется самой сборкой
чистого Docker-образа. CI и release используют один reusable workflow для
обеих архитектур, с Docker cache и зависимостью публикации от всех проверок.
