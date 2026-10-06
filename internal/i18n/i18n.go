package i18n

import "strings"

// Lang is a UI language code.
type Lang string

const (
	RU Lang = "ru"
	EN Lang = "en"
)

// Normalize returns ru or en.
func Normalize(s string) Lang {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "en") {
		return EN
	}
	return RU
}

var catalog = map[Lang]map[string]string{
	RU: {
		"app.name":          "sambaadm",
		"nav.dashboard":     "Дашборд",
		"nav.users":         "Пользователи",
		"nav.groups":        "Группы",
		"nav.computers":     "Компьютеры",
		"nav.ou":            "OU",
		"nav.trusts":        "Доверия",
		"nav.repl":          "Репликация",
		"nav.sites":         "Сайты",
		"nav.dns":           "DNS",
		"nav.gpo":           "GPO",
		"nav.domain":        "Домен",
		"nav.shares":        "Общие папки",
		"nav.printers":      "Принтеры",
		"nav.audit":         "Аудит",
		"nav.settings":      "Настройки",
		"nav.logout":        "Выход",
		"shares.create":     "Новая общая папка",
		"shares.acl":        "Права на каталог",
		"shares.hint":       "Локальный smb.conf: шары, каталоги и POSIX ACL.",
		"printers.create":   "Новый принтер",
		"printers.hint":     "Печатные шары Samba и очереди CUPS.",
		"login.title":       "Вход",
		"login.subtitle":    "Администрирование Samba4 AD",
		"login.username":    "Логин",
		"login.password":    "Пароль",
		"login.submit":      "Войти",
		"login.error.form":  "Некорректная форма",
		"login.error.empty": "Укажите логин и пароль",
		"login.error.ldap":  "LDAP недоступен",
		"login.error.auth":  "Неверный логин или пароль",
		"dashboard.title":   "Дашборд",
		"dashboard.hint":    "Состояние подключения к контроллеру домена.",
		"audit.title":       "Журнал аудита",
		"audit.empty":       "Нет записей",
		"audit.hint":        "Мутирующие операции: кто, что, когда, результат.",
		"settings.title":    "Настройки",
		"settings.lang":     "Язык интерфейса",
		"settings.save":     "Сохранить",
		"common.error":      "Ошибка",
		"common.no_data":    "Нет данных",
	},
	EN: {
		"app.name":          "sambaadm",
		"nav.dashboard":     "Dashboard",
		"nav.users":         "Users",
		"nav.groups":        "Groups",
		"nav.computers":     "Computers",
		"nav.ou":            "OU",
		"nav.trusts":        "Trusts",
		"nav.repl":          "Replication",
		"nav.sites":         "Sites",
		"nav.dns":           "DNS",
		"nav.gpo":           "GPO",
		"nav.domain":        "Domain",
		"nav.shares":        "Shares",
		"nav.printers":      "Printers",
		"nav.audit":         "Audit",
		"nav.settings":      "Settings",
		"nav.logout":        "Sign out",
		"shares.create":     "New share",
		"shares.acl":        "Directory permissions",
		"shares.hint":       "Local smb.conf: shares, directories and POSIX ACLs.",
		"printers.create":   "New printer share",
		"printers.hint":     "Samba printable shares and CUPS queues.",
		"login.title":       "Sign in",
		"login.subtitle":    "Samba4 AD administration",
		"login.username":    "Username",
		"login.password":    "Password",
		"login.submit":      "Sign in",
		"login.error.form":  "Invalid form",
		"login.error.empty": "Username and password required",
		"login.error.ldap":  "LDAP unavailable",
		"login.error.auth":  "Invalid username or password",
		"dashboard.title":   "Dashboard",
		"dashboard.hint":    "Domain controller connection status.",
		"audit.title":       "Audit log",
		"audit.empty":       "No entries",
		"audit.hint":        "Mutating operations: who, what, when, result.",
		"settings.title":    "Settings",
		"settings.lang":     "Interface language",
		"settings.save":     "Save",
		"common.error":      "Error",
		"common.no_data":    "No data",
	},
}

// T translates a key for the given language.
func T(lang Lang, key string) string {
	lang = Normalize(string(lang))
	if m, ok := catalog[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := catalog[RU]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}
