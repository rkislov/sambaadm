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
