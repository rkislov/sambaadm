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
| GET/POST | `/trusts` | read/admin | список / создать (samba-tool) |
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
