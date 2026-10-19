package i18n

func init() {
	catalog[RU]["login.error.identity"] = "Не удалось определить учётную запись и права доступа"
	catalog[RU]["login.error.service"] = "Служебное подключение LDAP недоступно. Проверьте ldap.bind и переменную пароля"
	catalog[EN]["login.error.identity"] = "Could not resolve account identity and permissions"
	catalog[EN]["login.error.service"] = "LDAP service connection unavailable. Check ldap.bind and the password environment variable"
}
