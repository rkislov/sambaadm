# Проверки на настоящем Samba AD

Запуск из корня репозитория (нужны Docker Compose и Go):

```sh
make integration
```

Скрипт собирает Debian Bookworm с Samba, создаёт временный домен
`SAMBAADM.TEST`, ожидает LDAP и запускает Linux-тесты внутри контейнера.
Проверяются пользователи, группы, OU, смена пароля, DNS, создание и привязка
GPO, резервное копирование и восстановление файлов SYSVOL. HTTP-тест
дополнительно проверяет вход, дерево объектов, RBAC и CSRF.

Каждый запуск получает свой Compose project и случайные порты только на
loopback. Контейнер и сеть удаляются после завершения, включая ошибку.
Тома хоста, привилегированный режим и рабочие домены не используются.
Фиксированный пароль в Compose предназначен только для этого стенда.
LDAPS проверяет сертификат с SAN, доверенный внутри контейнера.
Для NT ACL стенд использует xattr_tdb; это тестовая конфигурация.

Сервисные интеграционные тесты по умолчанию пропускаются. Изменения
разрешаются только при одновременном `SAMBAADM_IT=1` и
`SAMBAADM_IT_MUTATE=SAMBAADM.TEST`, с проверкой Base DN. Скрипт задаёт
эти параметры внутри собственного стенда. Не используйте их на рабочем DC.

Для ручной диагностики:

```sh
docker compose -p sambaadm-it -f testdata/docker-compose.yml up -d --build --wait
docker compose -p sambaadm-it -f testdata/docker-compose.yml logs dc
docker compose -p sambaadm-it -f testdata/docker-compose.yml down --volumes
```

Можно задать `SAMBAADM_LDAP_PORT` и `SAMBAADM_LDAPS_PORT` для фиксированных
локальных портов. Доверие тестового сертификата на хост не устанавливается.
Успешный тест в Debian не заменяет проверку запуска на ALT SP Workstation.
