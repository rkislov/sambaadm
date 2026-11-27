# Проверки печати

`python3 testdata/printing/test_worker.py` выполняет изолированные проверки без root, CUPS, AD и сетевого доступа: URI, ревизии, активные задания, команды и пути PPD, вложенные архивы, Windows ZIP и сохранение ключевого материала при проверке HTTP keytab.

`node testdata/web/printing.cjs` проверяет интерфейс с синтетическими ответами: права, XSS, страницы, поиск, журнал, очистку поля keytab, установку с главной страницы и кнопку «＋». Требуются Playwright/Chromium; используйте NODE_PATH своего окружения.

`provision-ad.py` запускается только внутри отдельного AD стенда SAMBAADM.TEST: создаёт тестовые записи HTTP/SMB/Windows/client и экспортирует keytab. Не запускайте его на рабочем домене.

Нативный прогон 27.11.2026: ALT p10/p11 aarch64, собственные CUPS и ippeveprinter; keytab для входа HTTP проверен с реальным AD, PDF принят по IPPS/SPNEGO и завершён (state=9, 1 страница). SMB backend с cache служебной записи передал PostScript 570732 байта на отдельный Samba AD сервер. RPC-регистрация синтетического Windows x64 V3 пакета и enumdrivers проверены на отдельном Samba member. Настоящего Windows-клиента и физического принтера в стенде нет. Настройка и ограничения описаны в ../../docs/printing.md.
