# REST API (v1)

Префикс: `/api/v1`. Аутентификация: session cookie после `/login`.

Мутирующие методы (`POST`/`PUT`/`PATCH`/`DELETE`) требуют CSRF: заголовок `X-CSRF-Token` (значение из cookie-сессии / meta `csrf-token` в UI) или поле формы `csrf_token`.

| Method | Path | Роль | Описание |
|--------|------|------|----------|
| GET | `/users?ou=&q=` | read | список пользователей |
| GET | `/users/{login}` | read | карточка |
| POST | `/users` | admin | создать |
| DELETE | `/users/{login}` | admin | удалить |
| POST | `/users/{login}/enable` | helpdesk+ | включить |
| POST | `/users/{login}/disable` | helpdesk+ | отключить |
| POST | `/users/{login}/password` | helpdesk+ | `{"password":"..."}` |
| GET/POST | `/groups` | read/admin | список / создать |
| DELETE | `/groups/{name}` | admin | удалить |
| GET | `/computers` | read | список |
| DELETE | `/computers/{name}` | admin | удалить |
| GET/POST | `/ou` | read/admin | список / создать |
| DELETE | `/ou?dn=` | admin | удалить OU |
| GET/POST | `/trusts` | read/admin | список / создать (LSA RPC, локальная сторона) |
| DELETE | `/trusts/{domain}` | admin | удалить |
| POST | `/trusts/{domain}/validate` | admin | проверить |
| GET | `/domain` | read | инфо о домене |
| GET | `/domain/fsmo` | read | FSMO роли |
| POST | `/domain/fsmo/transfer` | admin | `{"role":"pdc"}` |
| GET | `/domain/level` | read | functional level |
| GET | `/repl/partners` | read | партнёры |
| GET | `/repl/status` | read | showrepl |
| POST | `/repl/sync` | admin | `{"from":"dc2"}` |
| GET/POST | `/sites` | read/admin | сайты |
| DELETE | `/sites/{name}` | admin | удалить сайт |
| GET/POST | `/subnets` | read/admin | подсети |
| GET/POST | `/dns/zones` | read/admin | DNS-зоны |
| DELETE | `/dns/zones/{zone}` | admin | удалить зону |
| GET | `/dns/zones/{zone}/records?name=&type=` | read | query |
| POST/DELETE | `/dns/zones/{zone}/records` | admin | add / delete (`name,type,data`) |
| GET/POST | `/gpo` | read/admin | список / создать |
| DELETE | `/gpo/{gpo}` | admin | удалить |
| POST | `/gpo/{gpo}/link` | admin | `{"container":"DN"}` |
| POST | `/gpo/{gpo}/unlink` | admin | `{"container":"DN"}` |
| POST | `/gpo/{gpo}/backup` | admin | `{"path":"..."}` |
| POST | `/gpo/{gpo}/restore` | admin | `{"path":"..."}` |
| POST | `/gpo/{gpo}/distribute` | admin | запуск распространения на все DC |
| GET | `/gpo/distribute/{jobID}` | read | статус job (прогресс/шаги) |
| GET/POST | `/shares` | read/admin | список / создать шару (+ mkdir/ACL) |
| GET/DELETE | `/shares/{name}` | read/admin | карточка / удалить (`?remove_dir=1`) |
| GET/POST | `/shares/{name}/acl` | read/admin | POSIX ACL каталога шары |
| GET/POST | `/printers` | read/admin | принтерные шары + CUPS |
| DELETE | `/printers/{name}` | admin | удалить printable share |
| GET/POST | `/acl?path=` / body | read/admin | права на произвольный путь под `shares_root` |

Также: `GET /healthz`, `GET /metrics`.

## Топология и репликация v0.11.0

Чтение доступно всем аутентифицированным ролям: `GET /sites/topology`, `/sites/controllers`, `/sites/links`, `/repl/connections`, `/repl/status?dc=dc2.example.com`. Последний запрос возвращает `server`, `health` (`healthy`, `degraded`, `no-partners`), `neighbors` и исходный JSON `raw`. Каждый сосед содержит `direction`, `partner`, `partition`, `lastAttempt`, `lastSuccess`, `failures`, `result`, `health`.

Изменения требуют admin и CSRF:

- `POST /sites/links`: `{"name":"WAN","sites":["HQ","Branch"],"cost":100,"interval":180}`.
- `PUT /sites/links/{name}`: `{"revision":"123","sites":["HQ","Branch"],"cost":200,"interval":30}`.
- `DELETE /sites/links/{name}`: `{"revision":"123"}`.
- `PUT /sites/links/{name}/schedule` **заблокирован (400) из-за дефекта KCC Samba**; формат для будущей совместимости: `{"revision":"123","schedule":["","08:00-18:00","08:00-18:00","08:00-18:00","08:00-18:00","08:00-18:00",""]}`.
- `POST /sites/controllers/{name}/move`: `{"site":"Branch","revision":"123"}`.
- `PUT /subnets/site`: `{"subnet":"192.0.2.0/24","site":"Branch"}`.
- `POST /repl/connections`: `{"source":"dc1.example.com","destination":"dc2.example.com"}`.
- `PUT /repl/connections/{id}`: `{"revision":"123","enabled":false}`; также принимает `schedule` из семи строк.
- `DELETE /repl/connections/{id}`: `{"revision":"123"}`.
- `POST /repl/kcc`: `{"dc":"dc2.example.com"}`.

`revision` читается из списка соответствующих объектов. Конфликт — 409, неверный ввод — 400, отказ LDAP/RPC — 502. Расписание: воскресенье первым, UTC, четвертьчасовые интервалы; пустая строка означает закрытый день. Неизвестный двоичный формат возвращается с `scheduleSupported:false` и не предлагается к редактированию. Эти операции не заменяют доставку файлов SYSVOL.

Для Site Links `scheduleEditable:false` и `scheduleWarning` объясняют блокировку записи расписания; существующее значение читается. `schedule` в POST/PUT связи также отвергается. Расписания `/repl/connections/{id}` доступны.


Редактор ALT: `GET /api/v1/gpo/{guid}/alt-settings?scope=Machine|User`
возвращает каталог параметров, `values` и ревизию. PUT на тот же путь принимает
`id`, `scope`, `state`, `revision`, `values` (объект по ID элементов ADMX).
Числа и индексы вариантов enum передаются строками, флаги — boolean,
списки — массивами строк. Для `disabled`/`not-configured` значения не нужны.
Пропущенный scope означает Machine. Ошибочные типы/диапазоны возвращают 400,
устаревшая ревизия — 409; сохранение требует admin и CSRF.

### Область действия GPO и локальный сервер

- `GET /api/v1/gpo/scope` — домен/OU, прямые ссылки, ревизии и каталог GPO.
- `GET /api/v1/gpo/scope?container=<DN>` — кандидаты по наследованию (не RSoP).
- `PUT /api/v1/gpo/scope` — полный набор ссылок контейнера:
  `{"container":"OU=People,DC=example,DC=com","revision":"123","block":true,"links":[{"dn":"CN={GUID},CN=Policies,CN=System,DC=example,DC=com","enabled":true,"enforced":false}]}`.
  Первый элемент links имеет высший приоритет. Пустой массив удаляет ссылки.
- `GET /api/v1/gpo/{guid}/filter` — DACL с SID, именами, типом, маской, признаком Apply и возможностью удаления отдельной ACE.
- `PUT /api/v1/gpo/{guid}/filter` — `{"revision":"123","principal":"<DN>"}`
  либо `{"revision":"123","remove":"<ACE hash>"}`. Для Authenticated Users допустим principal `S-1-5-11`. Чтение GPO/SYSVOL не предоставляется.
- `POST /api/v1/shares/wizard` — расчёт `{name,path,comment,profile,groups:[DN...]}`;
  profile `team` или `read`. `?apply=1` повторно рассчитывает права и создаёт папку.
- `GET /api/v1/samba/profile?profile=compatible|secure` — рассчитанные параметры и ревизия smb.conf.
- `PUT /api/v1/samba/profile` — `{profile,revision}`; возвращает backup и activation=reload-required. Перечитывание отдельно через `/shares/reload`.
- `GET /api/v1/system/metrics` — host, os, cpus, diskPath, samples (time в Unix ms; cpu/memory/disk в процентах либо null). До 120 образцов, один раз в 5 секунд при запросах.

Мутации и профили Samba требуют admin и CSRF. Остальное чтение требует сессию.
Конфликты ревизий возвращают 409; некорректные запросы — 400. Неизвестные ACE
сохраняются, автоматическое редактирование их семантики не поддерживается.

### Расширенные атрибуты пользователя

`GET /api/v1/users/{login}` дополнительно возвращает `name` (CN) и `attributes`:
словарь явно разрешённых текстовых LDAP-атрибутов со списками значений.
`PUT /api/v1/users/{login}` принимает `revision` и частичный словарь `attributes`
со строковыми значениями, например:

```json
{"revision":"12345","attributes":{"company":"Организация","l":"Москва","mobile":""}}
```

Пустая строка удаляет атрибут; пропущенные поля не изменяются. Допустимы initials,
physicalDeliveryOfficeName, wWWHomePage, mobile, homePhone, pager,
facsimileTelephoneNumber, streetAddress, l, st, postalCode, co, company, division,
employeeID, employeeNumber. Остальные ключи отклоняются с 400. Изменение доступно
только admin, требует CSRF и актуальной revision; конфликт возвращает 409.
Все изменения используют прежнюю LDAP assertion-проверку uSNChanged и журнал аудита.

### POST /api/v1/gpo/model — моделирование ALT / Registry.pol

Операция только читает данные, доступна всем авторизованным ролям; нужен
`X-CSRF-Token`. Требуются настройки редактора ALT и доступ к SYSVOL.

```json
{
  "user": "CN=alice,OU=People,DC=example,DC=com",
  "computer": "CN=pc01,OU=Computers,DC=example,DC=com",
  "userOU": "",
  "computerOU": "OU=Test,DC=example,DC=com",
  "loopback": "merge",
  "security": "unknown",
  "wmi": "unknown",
  "securityOverrides": {"{00000000-0000-0000-0000-000000000001}": "allow"},
  "wmiOverrides": {"{00000000-0000-0000-0000-000000000001}": "deny"}
}
```

Хотя бы один получатель обязателен; вместо объекта можно передать DN домена/OU.
`userOU` / `computerOU` задают условное расположение и не перемещают объект.
`loopback`: `none`, `merge`, `replace`; Merge/Replace требуют обоих получателей.
`security` и `wmi`: `unknown`, `allow`, `deny`. Исключения задаются по GUID GPO
и имеют те же значения. Это допущения для обоих разделов, а не проверка ACL/WMI.
При неизвестном условии GPO исключается из расчёта и раздел помечается неполным.

Ответ содержит `generatedAt`, `scenario`, `controller`, `templateSource`,
`limitations` и `sections`. Каждый раздел содержит `scope` (`Machine` / `User`),
`container`, `links` с причинами применения/исключения (сначала высокий приоритет),
`settings` с итоговыми параметрами ALT и `sources`, `values` с эффективными записями
Registry.pol, `incomplete` и `warnings`. У значения есть `winner`, `precedence`,
`conflict` и `contributions` (GPO, тип, значение, удаление); у параметра ALT —
`conflicts`. `data` содержит исходные байты в base64. Совпадающие значения из разных
GPO не считаются конфликтом. Специальные директивы кроме `**del.` не вычисляются
и приводят к `incomplete=true`. Ограничения модели описаны в docs/web.md.

Коды: 200 — отчёт (возможен неполный), 400 — некорректный сценарий,
401 — нет сессии, 403 — нет CSRF, 502 — чтение LDAP/SYSVOL или шаблонов недоступно.

### Диагностика

`POST /api/v1/system/diagnostics` — admin + CSRF, отчёт `started`, `finished`, `platform`, `checks` (`id`, `status`, `detail`, `hint`, `durationMs`). Не изменяет конфигурацию или файлы. HTTP 409 при уже активном запуске.

### Просмотр сценариев GPO

`GET /api/v1/gpo/{gpo}/scripts` доступен всем авторизованным ролям. Возвращает `controller`, `revision`, `version`, `files` (scope/event/name/size), признаки `machineDisabled` и `userDisabled`, массив `scripts`: `scope` (Machine/User), `event` (startup/shutdown/logon/logoff), `kind` (script/PowerShell), `order` (индекс с нуля внутри раздела и типа), `command`, `parameters`, `source` (относительный путь в GPO). Читаются scripts.ini и psscripts.ini в SYSVOL; редактор ALT и ADMX не требуются. Команды не исполняются. Отсутствующие файлы дают пустой массив; ошибка чтения или формата возвращается как ошибка, а не как отсутствие назначений.

Отказы LDAP/DRS в доступе в расширенных операциях и проверке репликации возвращаются с HTTP 403, `code: upstream_access_denied`, исходным `error` и подсказкой `hint`. Ошибка недопустимого участника группы получает HTTP 400. Значения дат в JSON сохраняют формат LDAP; человекочитаемое представление формируется веб-интерфейсом. Объект компьютера дополнен полем `whenCreated`.


### Запись сценариев

`PUT /api/v1/gpo/{gpo}/scripts` — admin + X-CSRF-Token. JSON: `revision`, `scope` (Machine/User), `event` (startup/shutdown для Machine, logon/logoff для User), `kind` (script/PowerShell), `entries` (упорядоченный массив `{command, parameters}`), необязательный `files` (массив `{name, data}`, где data — base64 точных байтов файла). Пустой entries очищает только выбранное событие и тип. Удаление назначений не удаляет файлы. Загрузки создаются/заменяются в Scripts/<Event>; имя — только имя файла, без каталогов, потоков, специальных имён Windows и переходов по пути. Исполнение и физическое удаление файлов через этот API отсутствуют.

До 128 назначений, 32 файлов, 2 МиБ на файл, 4 МиБ суммарных данных и 8 МиБ JSON. Ответ — свежая модель GET и `backup` с именем резервной копии, если была запись. HTTP 400 — недопустимый ввод; 403 — роль/CSRF/права служебной записи; 409 — изменившаяся ревизия или рассогласование версий. При неопределённом результате HTTP 502 сообщает о сохранённом журнале восстановления. Запись не требует ADMX или gpo.editor_enabled.

`GET /api/v1/gpo/{gpo}/scripts/file?revision=...&scope=Machine&event=startup&name=example.sh` — скачивание существующего файла из модели GET. Возвращает application/octet-stream, Content-Disposition: attachment, X-Content-Type-Options: nosniff и Cache-Control: no-store. Путь берётся только из найденного файла снимка; произвольный доступ к SYSVOL не допускается. Изменение ревизии даёт 409; отсутствующий файл — 400.


### Обслуживание копий и восстановление сценариев

Все операции ниже требуют admin; POST дополнительно требует X-CSRF-Token.

- `GET /api/v1/gpo/{gpo}/scripts/maintenance`: revision списка, backups (name/size/modified/protected), pending, recoveryError, keep/maxBytes/totalBytes и prunable — план очистки.
- `GET /api/v1/gpo/{gpo}/scripts/backup?name=...&revision=...`: скачивание копии как вложения. name=pending выбирает журнал; произвольные пути не принимаются.
- `GET /api/v1/gpo/{gpo}/scripts/preview?source=...&mode=before|after`: source=pending для возврата/завершения; имя копии с mode=before для исторического восстановления. Ответ: revision плана, scope, version/nextVersion, files (path/state/action/size) и conflicts.
- `POST /api/v1/gpo/{gpo}/scripts/maintenance`: JSON operation=restore/delete/prune и revision. Для restore — revision предпросмотра, source и mode; при conflicts обязательно allowConflicts=true. Для delete — source с именем незапрещённой копии. Для delete/prune — revision списка. Пустая/устаревшая ревизия не разрешает изменение. Ответ — свежая модель обслуживания.

Восстановление всегда повышает версию текущего раздела, создаёт страховочную копию и сохраняет журнал до успешного LDAP commit. HTTP 409 — изменившаяся ревизия/версия либо неподтверждённая замена конфликтов; 400 — недопустимый источник/план/защищённая копия; 403 — роль/CSRF/права службы. При сбое записи сохраняется журнал восстановления. Автоочистка после успешных сохранений использует gpo.script_backup_keep и gpo.script_backup_max_mib; последняя копия не удаляется, при pending очистка не выполняется.

`POST /api/v1/system/diagnostics` принимает необязательный JSON `{ "gpo": "{GUID}" }`. Без тела проверяются общие возможности, а проверки прав выбранной GPO пропускаются. Ответ содержит serviceUser и gpo, отдельные проверки drs, ldap_permissions, sysvol_permissions. allowedAttributesEffective проверяется чтением, GPT.INI — открытием O_RDWR без записи/усечения. KCC не вызывается. Неверный GUID даёт 400, занятая диагностика — 409; результаты отдельных проверок остаются в отчёте HTTP 200.
