package i18n

func init() {
	ru := map[string]string{
		"diagnostics.gpo": "Проверить полномочия на GPO", "diagnostics.no_gpo": "Без проверки конкретной GPO", "diagnostics.identity": "Служебная учётная запись", "diagnostics.drs": "Права чтения DRS", "diagnostics.ldap_permissions": "Права изменения атрибутов GPO", "diagnostics.sysvol_permissions": "Права открытия GPT.INI на запись",
		"diagnostics.local_write_access": "Права записи локальной Samba",
		"nav.diagnostics":                "Диагностика",
		"diagnostics.hint":               "Проверки выполняются на машине sambaadm от имени процесса сервиса. Настройки, ACL и файлы не изменяются. Проверка чтения не подтверждает права записи или применение GPO. Результаты сетевых проверок могут занять до 25 секунд.",
		"diagnostics.run":                "Запустить проверки", "diagnostics.running": "Выполняются проверки…",
		"diagnostics.ldap": "LDAP, TLS и служебная учётная запись", "diagnostics.controller_dns": "Разрешение адреса контроллера", "diagnostics.domain_srv": "Поиск контроллеров через DNS SRV", "diagnostics.sysvol": "Чтение SYSVOL по SMB", "diagnostics.smb_conf": "Локальный smb.conf и testparm", "diagnostics.shares_root": "Каталог общих папок", "diagnostics.local_tools": "Локальные зависимости", "diagnostics.service_identity": "Окружение процесса",
		"diagnostics.status.ok": "Успешно", "diagnostics.status.error": "Ошибка", "diagnostics.status.warning": "Требует внимания", "diagnostics.status.skipped": "Пропущено", "diagnostics.status.info": "Информация",
	}
	en := map[string]string{
		"diagnostics.gpo": "Check GPO permissions", "diagnostics.no_gpo": "No specific GPO", "diagnostics.identity": "Service account", "diagnostics.drs": "DRS read permissions", "diagnostics.ldap_permissions": "GPO attribute write permissions", "diagnostics.sysvol_permissions": "GPT.INI write-open permissions",
		"diagnostics.local_write_access": "Local Samba write access",
		"nav.diagnostics":                "Diagnostics", "diagnostics.hint": "Checks run on the sambaadm host as the service process. No configuration, ACLs or files are changed. Read checks do not confirm write access or GPO application. Network checks can take up to 25 seconds.", "diagnostics.run": "Run checks", "diagnostics.running": "Running checks…",
		"diagnostics.ldap": "LDAP, TLS and service identity", "diagnostics.controller_dns": "Controller name resolution", "diagnostics.domain_srv": "Domain controller DNS SRV discovery", "diagnostics.sysvol": "SYSVOL read over SMB", "diagnostics.smb_conf": "Local smb.conf and testparm", "diagnostics.shares_root": "Share root directory", "diagnostics.local_tools": "Local dependencies", "diagnostics.service_identity": "Process environment",
		"diagnostics.status.ok": "Passed", "diagnostics.status.error": "Failed", "diagnostics.status.warning": "Attention required", "diagnostics.status.skipped": "Skipped", "diagnostics.status.info": "Information",
	}
	for k, v := range ru {
		catalog[RU][k] = v
	}
	for k, v := range en {
		catalog[EN][k] = v
	}
}
