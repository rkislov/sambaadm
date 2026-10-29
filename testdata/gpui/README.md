# Проверка формата сценариев через GPUI и gpupdate

CI job `gpui-compatibility` собирает исходный INI-плагин GPUI, читает и перезаписывает UTF-16LE-файл sambaadm и проверяет сохранность назначений в Go. Затем исходный парсер gpupdate читает файлы до и после GPUI. Проверяются порядок команд, аргументы с Unicode и соседнее событие. Исходники внешних проектов закреплены SHA в `.github/workflows/ci.yml`; они не копируются в проект и не входят в релизный бинарник.

`roundtrip.cpp` использует `plugins/ini/iniformat.h` и `src/io/inifile.cpp` из GPUI. Для компиляции нужны Qt5Core, Boost headers и C++17. `check_gpupdate.py` загружает настоящий scriptsini.py и DynamicAttributes без запуска посторонних NSS/storage-инициализаторов пакета. Парсер и его классы не подменяются.

Для локальной проверки задайте `SAMBAADM_GPUI_FIXTURES` существующим временным каталогом и выполните `go test ./internal/service -run '^TestGPUIINIInterop$' -count=1`. Скомпилируйте и запустите roundtrip с input.ini и gpui.ini в этом каталоге, затем повторите Go-тест с `SAMBAADM_GPUI_ROUNDTRIP=1`. Команды компиляции и проверки gpupdate приведены в CI workflow.

Это проверка кодека и парсера, а не запуск всего GUI и не исполнение сценариев на введённом в домен ALT СП. Приёмка конкретных версий gpui/gpupdate и клиентской обработки остаётся отдельной проверкой.
