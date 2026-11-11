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
| POST | `/gpo/distribute` | admin | доставка всех GPO домена одной задачей, 202 с идентификатором, 409 при параллельной доставке |
| GET | `/gpo/distribute/{jobID}` | read / admin для массовой доставки | статус задачи, прогресс и шаги |
| GET/POST | `/shares` | read/admin | список / создать шару (+ mkdir/ACL) |
| GET/DELETE | `/shares/{name}` | read/admin | карточка / удалить (`?remove_dir=1`) |
| GET/POST | `/shares/{name}/acl` | read/admin | POSIX ACL каталога шары |
| GET/POST | `/printers` | read/admin | принтерные шары + CUPS |
| DELETE | `/printers/{name}` | admin | удалить printable share |
| GET/POST | `/acl?path=` / body | read/admin | права на произвольный путь под `shares_root` |

Также: `GET /healthz`, `GET /metrics`.

## Топология и репликация v0.11.0

Чтение доступно всем аутентифицированным ролям: `GET /sites/topology`, `/sites/controllers`, `/sites/links`, `/repl/connections`, `/repl/status?dc=dc2.example.com`. Последний запрос возвращает `server`, `health` и `neighbors`. Поле `controller` содержит DNS-имя контроллера из AD, если его удалось сопоставить. Каждый сосед содержит `direction`, `partner`, `partition`, `lastAttempt`, `lastSuccess`, `failures`, `result`, `health`. Для RODC запрос проверяет входящих соседей по каждому разделу. Если раздел не вернул соседей или запрос по нему завершился ошибкой, ответ включает `partitionIssues` с полем `partition` и, при ошибке, полем `error`. Статус `unverified` означает, что данных для подтверждения состояния RODC недостаточно. Известные ошибки репликации дают статус `degraded`. Для RWDC сохраняются статусы `healthy`, `degraded` и `no-partners`.

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
`X-CSRF-Token`. Требуются шаблоны ALT и доступ к SYSVOL. Флаг
`gpo.editor_enabled` не требуется и не изменяется моделированием.

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

### Объяснение области действия GPO

`POST /api/v1/gpo/explain` принимает `{"user":"CN=alice,OU=People,DC=example,DC=com","computer":""}`. Нужен хотя бы один получатель; вместо DN пользователя/компьютера можно указать домен или OU. Все аутентифицированные роли, включая readonly, имеют доступ; требуется `X-CSRF-Token`. Неизвестные поля отклоняются. Операция читает только LDAP и работает без редактора GPO, SMB и ADMX.

Ответ содержит `generatedAt`, `sections`, `limitations`. В разделе: `scope` (Machine/User), исходный `target`, фактический `container`, `path` от домена до OU и `links`. Для каждой ссылки сохраняются её исходный контейнер, порядок, Enforced, флаги разделов и WMI; добавляются:

- `checks`: условия с `code`, `state` (`pass`, `fail`, `unknown`) и `detail`. Для отказа наследования `detail` содержит DN блокирующего контейнера. Проверки не прекращаются после первого отказа.
- `status`: `excluded` — установлено исключающее условие либо та же GPO уже представлена ссылкой выше приоритетом; `conditional` — применение ещё требует проверки.
- `priority`: 1 — наивысший приоритет среди известных, не исключённых ссылок. `processingOrder` задаёт обратный порядок обработки этих кандидатов. Неопределимые ссылки не получают номера. Фильтры могут изменить состав списка.

Токен групп получателя, права чтения/применения, доступ получателя к SYSVOL и результат связанного WMI-фильтра остаются `unknown`. Отсутствующая/невидимая GPO также остаётся неопределённой. Отчёт не вычисляет сайт, локальные политики, loopback и фактическое выполнение расширений; чтение LDAP не является атомарным снимком. Для моделирования параметров с явными допущениями остаётся `/gpo/model`.

### Дополнительные разрешения GPO в LDAP

`GET /api/v1/gpo/{gpo}/delegation` возвращает текущие `revision` и `entries` DACL (как `/filter`). Все аутентифицированные роли могут читать ACL. Поле `editable` описывает возможности прежнего редактора Apply Group Policy; в интерфейсе делегирования удаление не предлагается.

`POST` на тот же адрес выполняет предпросмотр, `PUT` — запись. Обе операции требуют admin и CSRF. Тело предпросмотра: `{"revision":"123","principal":"CN=Editors,OU=Groups,DC=example,DC=com","profile":"edit-ldap"}`. Профили: `read`, `read-apply`, `edit-ldap`. Ответ содержит `preview`, `revision`, `dn`, `sid`, `profile`, список `added`, число неизменённых ACE `unchanged`, `ldapOnly:true` и `warnings`. Для PUT передайте те же поля запроса и токен `preview` из ответа.

Разрешены только дополнительные allow ACE: `read` — маска `0x20094`, `edit-ldap` — `0x200b7`, флаг Container Inherit. `read-apply` дополнительно добавляет object ACE с маской `0x100` и GUID Apply Group Policy. Точные дубликаты пропускаются. Токен предпросмотра связывает исходный и будущий DACL, ревизию, профиль и SID; 409 требует обновления и нового предпросмотра. SYSVOL, владелец, роли приложения и существующие ACE не изменяются. Это не расчёт эффективных прав и не полноценное делегирование доступа к файлам GPO.

### Согласованные ACL LDAP/SYSVOL

`/api/v1/gpo/{gpo}/delegation/full` доступен только admin; POST/PUT требуют CSRF. GET возвращает `records` и ID `pending`. История содержит только операции этого доверенного локального журнала для текущего контроллера/GPO.

POST выполняет предпросмотр:

- Выдача: `{"operation":"grant","principal":"CN=Editors,OU=Groups,DC=example,DC=com","profile":"edit"}`. Профили: `read`, `read-apply`, `edit`.
- Отзыв: `{"operation":"revoke","source":"UUID-завершённой-выдачи"}`.
- Восстановление: `{"operation":"complete","source":"UUID-незавершённой-операции"}` или `rollback`.

Ответ: `preview`, `operation`, `source`, `dn`, `sid`, `profile`, `ldapState`, `ldapChanged`, `ldapAdded`/`ldapRemoved`, `files` (path/state/changed/added/removed), `conflicts`. Состояния: `before`, `after`, `unchanged`, `conflict`. PUT принимает те же параметры плюс `preview`. Токен связан с локальной записью, текущими DACL, набором путей и ревизией LDAP; устаревший токен даёт 409. После любой ошибки PUT обновите GET: если появилась pending-операция, выполните её предпросмотр восстановления. Конфликты не допускают применения.

Профиль `edit` соответствует LDAP `edit-ldap`; на существующих файлах SYSVOL добавляется `0x1301bf`, на каталогах — `0x1201ff` с Object/Container Inherit (без DELETE на сам каталог). Профили чтения добавляют `0x1200a9`. Исходные ACE сохраняются. Отзыв и восстановление работают с записанными DACL, не меняют владельца/группу/SACL и не восстанавливают содержимое файлов. Сторонние изменения ACL или набора путей блокируются; новых разрешений на изменение ACL/владельца профили не дают.

## Проверка согласованности GPO между DC

`POST /gpo/{gpo}/consistency`, JSON `{}` либо `{"reference":"dc1.example.test"}`. Доступен всем аутентифицированным ролям, включая readonly; требуется CSRF. Проверка только читает LDAP/SYSVOL. Контроллеры обнаруживаются в AD; произвольный адрес не принимается. HTTP 409 означает, что другая проверка уже выполняется.

Ответ содержит `started`, `finished`, `reference`, `complete`, `hasDifferences`, `status`, `controllers` и `limitations`. `ldapDN` указывает DN объекта GPO, а `sysvolPath` — путь к папке GPO внутри SYSVOL. Общий статус: `consistent`, `different`, `incomplete` или `single-controller`. HTTP 200 с `incomplete` — успешно сформированный неполный отчёт, а не подтверждение согласованности. Явно выбранный недоступный reference не заменяется автоматически. Без выбора используется первая полностью прочитанная стабильная копия в порядке DNS-имён.

У каждого DC отдельно указаны `ldap`, `sysvol`, `ldapVersion`, `gptVersion`, `pending`, `errors`, `files`, `differences`, `differenceCount`. Версия — uint32: старшие 16 бит User, младшие Machine; нулевая версия допустима. Манифест файлов содержит путь, тип, размер, SHA-256 и отпечаток ACL, без содержимого. `metadataFields` содержит GUID, flags, CSE и WMI-атрибуты LDAP. Различия: `local-version`, `ldap-version`, `gpt-version`, `ldap-acl`, `ldap-metadata`, `content`, `sysvol-acl`, `missing`, `extra`, `type`, `path-case`. Сравниваются только доступные стабильные части; недоступный SYSVOL не превращается в список якобы отсутствующих файлов.

Поддерживается 1–100 DC. Проверка обрабатывает до четырёх DC одновременно, с бюджетом 15 секунд на каждый DC после начала чтения. На подготовку отводится 45 секунд, а общий бюджет чтения зависит от размера очереди и для 100 DC составляет 6 минут 15 секунд. На один проход по DC отводится до 2048 объектов, глубина обхода до 64 и до 64 МиБ содержимого. SYSVOL читается дважды. В `differences` не более 500 записей на DC, `differenceCount` сохраняет полный счётчик. Превышение лимитов, ошибки доступа и изменения во время чтения дают неполный результат.

## Управляемое исправление SYSVOL (v0.31.0)

`GET /gpo/{gpo}/repair` возвращает историю исправлений выбранной GPO: `id`, `source`, `target`, `state`, `created`. Доступ только admin. `POST` строит предпросмотр; `PUT` применяет показанную операцию с обязательным `preview`. POST/PUT требуют CSRF.

Первичное исправление: `{"operation":"repair","source":"dc1.example.test","target":"dc2.example.test"}`. Источник и приёмник — различные обнаруженные DNS-имена DC. Восстановление: `{"operation":"complete","record":"UUID"}` либо `{"operation":"rollback","record":"UUID"}`. Для PUT добавляется токен `preview` из свежего POST. Предпросмотр возвращает `changes`, подробности `aclChanges`, выбранные DC и предупреждения; содержимое файлов и локальные снимки не выдаются.

LDAP identity, metadata, security и versionNumber должны совпадать на обоих DC, версия источника GPT.INI должна совпадать с LDAP. LDAP не изменяется. Отсутствующее дерево или повреждённый/отсутствующий GPT.INI на целевом DC допускаются. Изменение копий после предпросмотра приводит к HTTP 409. При незавершённом редактировании/делегировании, несовпадении LDAP, чужих изменениях резервной копии или более новой операции исправление/восстановление блокируется.

Результат PUT: `record`, `state` (`complete` или `rolled-back`), повторная проверка `report`; если проверку выполнить не удалось — `verificationError`. Ошибка после создания журнала содержит его ID: получить историю и построить предпросмотр завершения/отката. `pending` в истории требует восстановления. После начала отката можно продолжать только откат. Выполненный откат не запускается повторно; более старые исправления откатываются после более новых.

Исходное и желаемое дерево сохраняются в закрытом локальном журнале до записи SMB. Лимиты одного снимка соответствуют проверке согласованности (2048 объектов, глубина 64, 64 MiB файлов); журнал ограничен 200 MiB, число попыток подготовки каталога — восемью. История ограничена 4096 записями. Автоматическая очистка резервных и временных каталогов не выполняется.

## Очистка архивов исправления SYSVOL

`GET /api/v1/gpo/{gpo}/repair` возвращает историю с полями `bytes` (локальный
размер журнала), `protected` и `prunable`. Для предварительного просмотра
очистки отправьте `POST` на тот же адрес с `operation: "prune"` и `record`.
Применение — `PUT` с теми же полями и полученным `preview`.
Требуются роль admin и CSRF; успешное применение возвращает `state: "pruned"`.
Очистка необратима: удаляет перечисленные архивные каталоги на DC, служебные
копии и локальные снимки; сохраняет компактную историю. Последний архив
каждого DC защищён, незавершённое восстановление приостанавливает очистку.
При `state: "pruning"` повторите предпросмотр и применение `prune` для
продолжения по сохранённому списку. Параметры хранения описаны в [Web UI](web.md#хранение-и-очистка-архивов-исправления).

## RODC

`GET /api/v1/sites/controllers` отмечает RODC полем `rodc` и возвращает
связанную учётную запись `computer`. Для выбранного обнаруженного RODC:

- `GET /sites/controllers/{name}/rodc` — PRP, кэш и список аутентифицировавшихся записей на RWDC.
- `POST` на тот же адрес — предпросмотр `allow`, `deny`, `remove-allow`,
  `remove-deny` с `principal` (DN) либо `preload` с `accounts` (1–50 DN).
- `PUT` — те же поля и `preview`; состояние и полный токен проверяются заново.
- `GET /sites/controllers/{name}/rodc/authentications?after=<RFC3339>&account=<filter>` —
  успешные и неудачные Authentication-события из локального журнала выбранного
  RODC через helper; отдельные статусы доступности и усечения.

Все операции RODC требуют admin, POST/PUT также CSRF. Preload выполняется
на RODC с его машинными полномочиями. Неизвестность или запрет PRP блокируют
заполнение; результаты возвращаются по каждой записи. При `unconfirmed`
сначала проверьте кэш и репликацию. Снятие разрешения не удаляет пароль из кэша.

Файловые операции остальных API выполняются через [SSH/HTTPS helpers](helper.md).
LDAP/DNS/DRS остаются в управляющем приложении. Путь backup/restore относится
к файловой системе helper `helpers.host_node` и ограничен `helper.backup_root`.

## Обследование контроллеров и остатков топологии

- `GET /api/v1/sites/controllers/{name}/inventory` — admin, сведения ОС выбранного
  обнаруженного DC через helper: `controller`, `observed`, `checks` версии Samba
  и фиксированного набора systemd units. Ошибка helper не заменяется локальной проверкой.
- `GET /api/v1/sites/controllers/{name}/authentications?after=...&before=...&account=...`
  — admin, Authentication JSON audit RWDC/RODC. Даты RFC3339, начало не позже конца,
  account до 256 символов. Ответ и ограничения совпадают с RODC audit; `before`
  фильтрует уже ограниченный хвост. Старый RODC endpoint также принимает `before`.
- `POST /api/v1/sites/topology/audit` — admin + CSRF, только чтение. Ответ:
  `started`, `finished`, `status` (`complete`/`partial` — полнота сбора, не исправность),
  `ldapServer` (имя хоста без реквизитов), `baseDN`, `objects`, `warnings`, `findings` (`code`, `severity`: `review`/`unknown`, `dn`,
  `reference`, `detail`, `changed`). Проверяются структурные остатки DC/сайтов/связей;
  автоматического удаления, проверки возраста пользователей и компьютеров нет.

Все три endpoint возвращают `Cache-Control: no-store`. JSON-экспорт обзора собирает
результаты этих и существующих API в браузере, с источником и временем каждого.

### Подготовка очистки LDAP

`POST /api/v1/sites/topology/cleanup/preview`, admin + CSRF:
`{"dns":["<DN из текущего отчёта>"]}`. От 1 до 50 уникальных объектов.
Повторяет аудит и отклоняет неполный сбор, посторонние DN и отсутствие GUID/USN.
Ответ содержит `revision`, `observed`, выбранные атрибуты (бинарные значения —
base64), находки и блокирующие условия. `canApply` в предпросмотре всегда false: он сам по себе не разрешает удаление.
Для сайтов план включает стандартные дочерние объекты; они также связаны ревизией.

`POST /api/v1/sites/topology/cleanup/snapshot`, admin + CSRF:
`{"dns":["<DN>"],"revision":"<revision предпросмотра>"}`. Повторно строит план;
изменение даёт 409. Сохраняет снимок через host_node helper и читает обратно с
проверкой SHA-256. Ответ: `id`, `sha256`, `created`, `verified`.
Снимок ограничен 2 МиБ, содержит только разрешённый набор атрибутов, без паролей,
ACL и полной структуры. Это подготовительный архив, не копия для восстановления
домена. Проверки второго RWDC, всех зависимостей/FSMO/репликации и репетиция
восстановления ещё обязательны перед выполнением очистки.

`POST /sites/topology/cleanup/checks`: `{dns, revision, peer}`. Admin + CSRF.
Читает видимые DC, ссылки fromServer/serverReference/siteObject/siteList,
владельцев FSMO и сравнивает экспортированные атрибуты с другим обнаруженным RWDC.
USN и whenChanged между DC не сравниваются. Проверяется идентичность DSA,
поэтому два DNS-псевдонима одного DC не считаются независимой проверкой.
Возвращает checks/dependencies и DRS-состояние выбранного RWDC. Ограничения
видимости и охвата сохраняются; canApply всегда false.

`POST /sites/topology/cleanup/backup`: `{dns, revision, controller, id}`.
Admin + CSRF, id — заранее созданный UUID. Повторно проверяет план и запускает
холодную копию на обнаруженном RWDC через helper. Доменные секреты не передаются
в ответе. Требуются остановленный выбранный DC, доступный LDAP другого RWDC и
настроенный helper с domain_backup_enabled.

`GET /sites/controllers/{name}/backups/{id}`: admin. Статусы queued, running,
backed_up, failed, interrupted, unknown. Время — RFC3339; UI форматирует местное
время. SHA-256 относится к завершённому архиву на момент создания. Проверка
архива не равна репетиции восстановления; restoreVerified выставляется только
по отдельному успешному результату репетиции этого архива. Поля applyReserved и
applyEvents отражают одноразовый запуск и сохранённый журнал применения.

Проверки очистки при репликации дополнены: зависимости и FSMO читаются на основном
LDAP-сервере и выбранном втором RWDC. Поле `dependencies[].controller` указывает
источник находки; найденные ссылки дают `references=blocked` либо
`peer_references=blocked`. Совпадение атрибутов выбранного объекта не отменяет
этих блокировок. Отдельно показываются запреты входящей/исходящей репликации
(`replication_enabled`, `peer_replication_enabled`). Пустые/недоступные значения
не считаются успешной проверкой. После обследования основной план перечитывается;
изменение его ревизии требует нового предпросмотра.


`POST /api/v1/sites/topology/cleanup/apply`: admin + CSRF.
Тело: `{dns, revision, controller, id, confirm:true}`; `id` — UUID проверенной
копии. Поддерживаются пустые сайты со стандартными детьми, siteLink и
nTDSConnection из текущего аудита. RODC-реплики, леса с несколькими доменами,
менее двух или более 16 контроллеров блокируются. Требуется копия не старше 24 часов,
совпадение GUID домена и ревизии, проверка восстановления и неизменный SHA-256.
Повторно проверяются все обнаруженные RWDC: DRS health, запреты репликации,
GUID/атрибуты выбранных объектов, дочерние объекты, FSMO и DN-ссылки по схеме
во всех размещённых разделах. Любая ошибка останавливает запуск.

Удаления идут по одному, от детей к родителю, с критическим LDAP assertion по
uSNChanged и журналом helper до/после каждой записи. Затем выполняется DRS
синхронизация Configuration и проверка отсутствия каждого DN на всех RWDC.
Ответ 200 содержит `status:completed|stopped` и `events`; **stopped не является
успехом**, возможно частичное выполнение. Ошибки до первой записи возвращают
400/409/502. При обрыве клиент читает журнал через статус копии, не повторяет
запрос: слот применения этой копии уже занят. Автоматического отката нет.
На время операции администраторы должны приостановить другие изменения топологии:
LDAP не предоставляет общую транзакцию для всех контроллеров и объектов.


### Расширенная очистка выведенного DC

В полном аудите выберите сервер выведенного DC. Кандидат должен иметь отключённую
учётную запись DC либо подтверждённо отсутствующую учётную запись/ссылку на неё.
Само отсутствие сетевого ответа и возраст объекта не считаются доказательством
вывода. Отдельное подтверждение окончательного вывода (`confirmDecommissioned`)
обязательно; повторное подключение старого DC после очистки недопустимо.

Предпросмотр перечисляет все операции: NTDS Settings и связанные подключения,
RID Set, разрешённые локальные DFSR LocalSettings/Subscriber/Subscription,
глобальный DFSR Member и его подключения, ссылки размещения разделов, а также
конкретные значения DNS-записей. Новые или неизвестные дочерние объекты блокируют
выполнение. Рекурсивное удаление произвольного поддерева не применяется.

Для DNS различаются удаление выбранных значений и удаление LDAP-объекта. В общих
SRV/NS/A-узлах сохраняются записи остальных контроллеров. Удаляются A/AAAA имени
DC, его адреса в доменных DNS-корнях (при однозначной принадлежности), ссылки
SRV/CNAME/PTR/NS/MX на это имя. Последняя NS, SOA с этим DC как primary и адрес,
используемый другим именем, блокируют план: сначала исправьте DNS-конфигурацию.
Поддерживается AD-integrated DNS в доменном разделе, DomainDnsZones и
ForestDnsZones; внешние DNS-провайдеры/перенос зоны через AXFR не обслуживаются.
Клиентские DNS-кэши очищаются согласно TTL, а не этим планом.

Холодная копия создаётся на **оставшемся** RWDC. Helper восстанавливает именно
этот архив в изоляции, применяет весь план с фиксацией каждого шага, проверяет базу и сохранность
остальных значений, затем заново восстанавливает архив в другой изолированный
каталог и сверяет возврат исходных GUID/атрибутов. Это проверяет реальное
восстановление после зафиксированной очистки, включая отложенное обслуживание
связанных атрибутов Samba. Для двух развёрнутых копий требуется дополнительное место.
Копия и квитанция связаны с ревизией плана и SHA-256. До применения нужно снова
запустить DC копирования и дождаться исправной репликации.

Перед записью повторяются сверка плана на всех оставшихся RWDC, проверки FSMO,
зависимостей и DRS. Ответ LDAP от удаляемого DC блокирует очистку; текущий
LDAP-контроллер удалить нельзя. Ошибки DRS к подтверждённо удаляемому DSA могут
быть исключены, ошибки между оставшимися DC — нет. Локальные счётчики RID не
сравниваются между репликами; вычисляемые обратные ссылки не изменяются вручную.
Перед удалением NTDS снова проверяются ревизии сервера/учётной записи и отсутствие
LDAP-ответа. Чужие одновременные изменения топологии должны быть приостановлены.

Каждая запись защищена LDAP assertion и журналируется до/после выполнения.
После очистки синхронизируются Configuration, доменный раздел, DomainDnsZones и
ForestDnsZones. На каждом оставшемся RWDC проверяются удалённые объекты,
изменённые ссылки и сохранность остальных значений DNS. При конфликте, ошибке
или потере ответа возможен частичный результат: сначала читайте журнал по ID
копии. Слепой повтор и автоматический откат в рабочий домен не выполняются.

Текущие ограничения: один домен, минимум два оставшихся RWDC, максимум 16
зарегистрированных контроллеров; RODC-реплики и удаление NTDS RODC требуют
отдельного сценария. До 50 выбранных находок, до 150 объектов после расширения,
до 10 000 DNS-узлов при обследовании, копия моложе 24 часов. Требуется обновить
и sambaadm, и helper. Проверенная платформа — Samba 4.17/TDB; ALT/MDB и Windows DC
требуют отдельной приёмки. Для каждой новой холодной копии после повторного восстановления DC запускается
в изоляции: проверяются вход временного обычного пользователя по LDAP, отказ
неверного пароля и чтение GPT.INI политики домена через SMB SYSVOL. Пользователь
создаётся только во временной восстановленной базе; пароли рабочих пользователей
не запрашиваются. Затем отдельно получаются свежий Kerberos TGT и сервисные
билеты для LDAP и CIFS: обязательны LDAP-вход и чтение того же GPT.INI через
SMB с Kerberos, без перехода на NTLM. Проверка не заменяет вход рабочей
станции или фактическое применение GPO. Рабочий домен и исходный архив не изменяются.


Для расширенного плана `objects[].remove` содержит отображение атрибут → список
удаляемых значений (base64). Отсутствие `remove` означает удаление объекта;
все эти поля входят в SHA-256 ревизии. Браузер не присылает произвольные операции:
`apply` принимает прежние `{dns,revision,controller,id,confirm:true,
confirmDecommissioned:true}`, а сервер строит и проверяет план заново.
Журнал дополнен состояниями `updating`/`updated`; `stopped` по-прежнему означает
остановку, возможно после частичных изменений, а не успешное завершение.

## Материалы обследования

Все три операции требуют сессии администратора. Пути указаны относительно /api/v1.

- `GET /surveys` возвращает список сохранённых материалов с полями `id` и `imported`.
- `POST /surveys?format=helper` принимает содержимое файла в теле запроса, до 16 МиБ. Для JSON обзора используйте `format=overview`, для строк Samba Authentication — `format=audit&node=dc1.corp.example`. Параметр `site` задаёт площадку для журнала или обзора. Для снимка helper обе метки читаются из файла. Передайте CSRF-токен в заголовке. Ответ содержит `id`: HTTP 201 при создании, HTTP 200 при повторном импорте.
- `GET /surveys/{id}` возвращает материал с SHA-256 исходного файла. Для запроса используйте `id` из ответа импорта.
