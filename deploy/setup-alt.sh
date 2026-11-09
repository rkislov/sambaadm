#!/bin/sh
# Install or update the selected components; RPM noreplace preserves configuration.
set -eu
umask 077
usage() { echo "Usage: sh setup-alt.sh [all|server|helper] [--check]"; }
case ${1:-all} in
  all) components='sambaadm sambaadm-helper' ;;
  server) components=sambaadm ;;
  helper) components=sambaadm-helper ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
mode=${2:-install}
[ "$#" -le 2 ] && { [ "$#" -lt 2 ] || [ "$mode" = --check ]; } || { usage >&2; exit 2; }
cd "$(dirname "$0")"
[ -f /etc/altlinux-release ] || { echo 'Требуется ОС семейства ALT.' >&2; exit 1; }
arch=$(uname -m)
set --
new_server=false
release=''
changed=''
for name in $components; do
  file="./$name.rpm"
  metadata=$(rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}' "$file")
  version=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$file")
  [ "$metadata" = "$name $version $arch" ] || { echo "Неверный пакет для $name ($arch): $metadata" >&2; exit 1; }
  [ -z "$release" ] || [ "$release" = "$version" ] || { echo 'Версии компонентов различаются.' >&2; exit 1; }
  release=$version
  if rpm -q "$name" >/dev/null 2>&1; then
    installed=$(rpm -q --qf '%{VERSION}-%{RELEASE} %{ARCH}' "$name")
    if [ "$installed" = "$version $arch" ]; then continue; fi
    echo "Обновление $name: $installed → $version $arch"
  elif [ "$name" = sambaadm ]; then
    new_server=true
  fi
  changed="$changed $name"
  set -- "$@" "$file"
done
if [ "$mode" = --check ]; then
  if [ "$#" -gt 0 ]; then apt-get -s install "$@"; else echo 'Выбранные версии уже установлены.'; fi
  exit
fi
[ "$(id -u)" = 0 ] || { echo 'Для установки запустите через sudo.' >&2; exit 1; }
if [ "$#" -gt 0 ]; then
  # Resolve dependencies and validate the transaction before stopping services.
  apt-get -s install "$@"
  install -d -m 0700 -o root -g root /var/lib/sambaadm-install
  backup=$(mktemp -d /var/lib/sambaadm-install/config-XXXXXXXX)
  backup_config() {
    set --
    for config_path in etc/sambaadm etc/sambaadm-helper; do
      if [ -e "/$config_path" ] || [ -L "/$config_path" ]; then set -- "$@" "$config_path"; fi
    done
    if [ "$#" -gt 0 ]; then
      tar --acls --xattrs --numeric-owner -cpf "$backup/config.tar" -C / "$@"
    else
      tar -cpf "$backup/config.tar" -T /dev/null
    fi
  }
  backup_config
  echo "Копия конфигурации: $backup/config.tar"
  active=''
  if [ -d /run/systemd/system ]; then
    for name in $changed; do
      if systemctl is-active --quiet "$name"; then active="$active $name"; fi
    done
  fi
  restart_active() {
    restart_failed=false
    for service_name in $active; do systemctl start "$service_name" || restart_failed=true; done
    [ "$restart_failed" = false ]
  }
  # Quiesce selected, changed services during replacement.
  # Previously stopped services remain stopped.
  trap 'restart_active || : ' EXIT
  for name in $active; do systemctl stop "$name"; done
  trap 'exit 1' HUP INT TERM
  if ! apt-get install "$@"; then
    echo "Обновление не завершено. Конфигурация сохранена в $backup/config.tar; проверьте состояние пакетов." >&2
    exit 1
  fi
  restart_active
  trap - EXIT HUP INT TERM
fi
# Remember the main RPM so subsequent transactional updates can roll back to it.
case " $components " in *' sambaadm '*)
  install -d -m 0700 -o root -g root /var/cache/sambaadm-packages
  cache_name=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' ./sambaadm.rpm)
  if [ ! -e "/var/cache/sambaadm-packages/$cache_name.rpm" ]; then
    install -m 0600 ./sambaadm.rpm "/var/cache/sambaadm-packages/$cache_name.rpm"
  fi
;; esac
if [ -x /usr/libexec/sambaadm-prepare-logs ]; then /usr/libexec/sambaadm-prepare-logs; fi
echo "Компоненты $components версии $release установлены; существующие настройки сохранены."
if [ "$new_server" = true ] && [ -d /run/systemd/system ] && { [ -t 0 ] || [ -n "${SAMBAADM_PASSWORD:-}" ]; }; then
  bash ./configure-server.sh
elif [ "$new_server" = true ]; then
  echo 'Для первичной настройки выполните sudo bash configure-server.sh из каталога комплекта.'
fi
