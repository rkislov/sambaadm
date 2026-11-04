# sambaadm-helper

`sambaadm-helper` — отдельный пакет и процесс на каждом управляемом сервере,
включая основной файловый сервер. Sambaadm сохраняет веб-интерфейс, вход,
RBAC, LDAP, DNS и DRS. Операции ОС, NSS, smb.conf, принтеров, ACL и файлов
SYSVOL выполняет helper соответствующего узла. Копирование политик читает
данные через helper источника и пишет через helper получателя. При отсутствии
helper запись напрямую по SMB не выполняется.

Поддерживаются SSH и HTTPS. В обоих случаях запрос подписан Ed25519-ключом
сервера sambaadm и содержит имя узла, версию протокола, время и уникальный ID.
Helper хранит только доверенные открытые ключи. HTTPS требует TLS 1.3 с
проверкой сертификата; SSH требует отдельный транспортный SSH-ключ и заранее
проверенный `known_hosts`. Переадресация HTTPS и автоматическое принятие
SSH host key отключены. Произвольного запуска команд через API нет.

## Установка

Сборка бинарников: `make build`. Отдельный RPM:
`make rpm-helper-alt VERSION=0.33.0 RPM_ARCH=amd64` (также `arm64`). Используйте бинарники и RPM одной версии с управляющим приложением.

Установите RPM helper на нужные серверы. Пакет не запускает сервис и не
добавляет доверенных ключей автоматически. Настройка каждого узла:
`/etc/sambaadm-helper/config.yaml`, пример — `configs/helper.example.yaml`.
Для ручной установки скопируйте бинарник в `/usr/bin/sambaadm-helper`,
unit из `deploy/` в `/etc/systemd/system/`, пример конфигурации — в
`/etc/sambaadm-helper/config.yaml`. Каталоги конфигурации и состояния должны
быть root-only; создайте `/var/log/sambaadm-helper` и каталог `backup_root`.

Helper использует локальные системные утилиты и локальный SYSVOL через SMB
на `127.0.0.1`, сохраняя Samba security descriptors. Для файлов SYSVOL задайте
на каждом helper служебную доменную запись с нужными правами и её пароль в
`helper.password_file` (обычный root-only файл 0600 с одной строкой) либо в
переменной `ldap.bind.password_env` окружения процесса helper. Sambaadm не
передаёт этот пароль по управляющему каналу. Поле `helper.sysvol_prefix`
ограничивает файловые запросы, например `example.com/Policies`.

Для RODC preload нужны Python 3, Python-модули Samba и `/usr/bin/samba-tool`
на самом RODC. Эта операция использует машинную учётную запись RODC и
проверяет локальный DSA GUID перед записью; пароли и хэши в ответ не входят.

## Ключ подписи на сервере sambaadm

Создайте ключ один раз на управляющем сервере:

```sh
sudo install -d -m 0750 -o root -g sambaadm /etc/sambaadm/keys
sudo sambaadm-helper keygen \
  --private /etc/sambaadm/keys/helper-signing.key \
  --public /etc/sambaadm/keys/helper-signing.pub
sudo chown sambaadm:sambaadm /etc/sambaadm/keys/helper-signing.key
```

Закрытый ключ остаётся здесь (0600). Передайте только `.pub` на управляемые
серверы и укажите его в `helper.trusted_keys`. Для ротации сначала добавьте
новый открытый ключ на helpers, затем переключите private_key в sambaadm и
после проверки удалите прежний открытый ключ из списка доверия. Для HTTPS перезапускайте helper после изменения списка доверия; SSH-процесс читает его при каждом запуске.

## HTTPS

В helper-конфигурации задайте уникальный FQDN в `helper.node`, адрес
`helper.listen`, сертификат и закрытый TLS-ключ в `helper.tls`. Сертификат
должен соответствовать имени в URL. Откройте порт для управляющего сервера,
затем запустите `systemctl enable --now sambaadm-helper`.

На сервере sambaadm:

```yaml
helpers:
  private_key: /etc/sambaadm/keys/helper-signing.key
  host_node: dc1.example.com
  nodes:
    - name: dc1.example.com
      transport: https
      endpoint: https://dc1.example.com:8444
      ca_cert: /etc/sambaadm/keys/helper-ca.pem
    - name: rodc1.example.com
      transport: https
      endpoint: https://rodc1.example.com:8444
      ca_cert: /etc/sambaadm/keys/helper-ca.pem
```

`host_node` выбирает сервер для файловых шар, NSS, локальных ADMX, метрик и
резервных копий. Имена DC в `nodes` должны совпадать с обнаруженными DNS-именами.
При использовании собственного CA его сертификат нужен на сервере sambaadm;
проверку TLS отключать нельзя.

## SSH

Сгенерируйте отдельный SSH-ключ для транспорта на сервере sambaadm и сохраните
его в доступном сервису каталоге `/etc/sambaadm/keys`. Заранее проверьте
SSH host key целевого сервера и сохраните его в отдельный known_hosts.

На helper-сервере для пользователя `sambaadm-agent` настройте root-owned
authorized_keys с принудительной командой:

```text
restrict,command="sudo -n /usr/bin/sambaadm-helper stdio" ssh-ed25519 AAAA... management-server
```

Путь authorized_keys можно задать в sshd как
`AuthorizedKeysFile /etc/ssh/authorized_keys/%u`. Доступ по паролю этому
пользователю не нужен. В root-owned файле sudoers 0440 разрешите только:

```text
sambaadm-agent ALL=(root) NOPASSWD: /usr/bin/sambaadm-helper stdio
```

Проверьте sudoers через `visudo -cf`. Не разрешайте shell и произвольные
аргументы helper. Root-конфигурация helper и доверенный ключ подписи нужны
также для SSH; один транспортный SSH-ключ не заменяет подпись протокола.

```yaml
helpers:
  private_key: /etc/sambaadm/keys/helper-signing.key
  host_node: dc1.example.com
  nodes:
    - name: dc1.example.com
      transport: ssh
      endpoint: sambaadm-agent@dc1.example.com
      ssh_key: /etc/sambaadm/keys/helper-ssh
      known_hosts: /etc/sambaadm/keys/helper-known-hosts
```

Сервис HTTPS для SSH-режима включать не требуется. На основном сервере
используется тот же SSH/HTTPS-канал к его helper. Основному процессу sambaadm
не требуется снимать `NoNewPrivileges` ради sudo.

## RODC и журнал

В «Сайты» или «Репликация» откройте «Кэш и авторизации RODC», выберите
контроллер. Разрешения PRP, запреты, кэшированные записи и список записей,
проходивших через RODC, показываются раздельно. Добавление/удаление назначений
и принудительное заполнение имеют предпросмотр и подтверждение. Для preload
выбираются отдельные пользователи/компьютеры; группы не разворачиваются.
Неизвестный полный токен и любое совпадение запрета блокируют заполнение.
Окончательное решение о репликации принимает Samba на RWDC.

Для работы с PRP настройте LDAP sambaadm на записываемый DC. Учётная запись
службы LDAP должна иметь соответствующие права; браузерный вход её не меняет.
Снятие разрешения или добавление запрета не стирает уже закэшированные пароли.

Для журнала задайте на helper выбранного RODC `helper.auth_log` и включите
Samba JSON-аудит, например `auth_json_audit:3@/var/log/samba/auth.json` в
`log level`, с файловым backend журналирования. Файл читается на самом RODC
через helper. Путь из HTTP-запроса пользователя не принимается. Доступны
фильтры времени и учётной записи, успешные/неуспешные Authentication-события,
клиент и служба. Читаются последние 8 MiB, выдаются до 500 подходящих событий;
усечение и повреждённые записи отмечаются. Успешная аутентификация не равна
интерактивному входу. Отсутствие источника, отключённый аудит или ротация
не доказывают отсутствие авторизаций.

## Эксплуатация

Helper работает с полномочиями для файлов и ACL; в поставляемом unit это root.
Операции ограничены фиксированным списком, SYSVOL-prefix, shares_root и
backup_root. Пути backup/restore теперь относятся к helper `host_node`.
Если шары размещены вне `/srv/samba`, настройте ReadWritePaths в override unit
helper. Аудит helper хранится отдельно; время на узлах должно быть согласовано.
Использованные ID запросов сохраняются в приватном state_dir, поэтому перезапуск HTTPS или новый SSH-процесс не разрешает повтор ранее принятого запроса. При потере ответа запись может быть уже выполнена: сначала проверьте состояние
или продолжите штатное восстановление по журналу, не повторяйте запись вслепую.


В v0.33.0 обзор контроллера использует новый read-only метод `host.inventory`:
фиксированные команды версии Samba и состояния известных systemd units, без
параметров команд от пользователя. Для него требуется обновить helper.
`helper.auth_log` и существующее чтение `rodc.auth` используются также для аудита
выбранного записываемого DC; проверка принадлежности DC каталогу и роль admin
выполняются в sambaadm. Период хранения и включение аудита проверяются отдельно.
