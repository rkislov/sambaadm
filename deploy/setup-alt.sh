#!/bin/sh
set -eu
usage() {
  echo "Usage: sh setup-alt.sh [all|server|helper] [--check]"
}
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
for name in $components; do
  file="./$name.rpm"
  metadata=$(rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}' "$file")
  version=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$file")
  [ "$metadata" = "$name $version $arch" ] || { echo "Неверный пакет для $name ($arch): $metadata" >&2; exit 1; }
  [ -z "$release" ] || [ "$release" = "$version" ] || { echo 'Версии компонентов различаются.' >&2; exit 1; }
  release=$version
  if rpm -q "$name" >/dev/null 2>&1; then
    installed=$(rpm -q --qf '%{VERSION}-%{RELEASE} %{ARCH}' "$name")
    [ "$installed" = "$version $arch" ] || { echo "Уже установлен $name $installed. Выполните обновление по alt-install.md." >&2; exit 1; }
  else
    if [ "$name" = sambaadm ]; then new_server=true; fi
    set -- "$@" "$file"
  fi
done
if [ "$#" -gt 0 ]; then
  if [ "$mode" = --check ]; then
    apt-get -s install "$@"
    exit
  fi
  [ "$(id -u)" = 0 ] || { echo 'Для установки запустите через sudo.' >&2; exit 1; }
  apt-get install "$@"
fi
echo "Компоненты $components версии $release установлены."
if [ "$new_server" = true ] && [ -d /run/systemd/system ] && { [ -t 0 ] || [ -n "${SAMBAADM_PASSWORD:-}" ]; }; then
  bash ./configure-server.sh
else
case " $components " in *' sambaadm '*) echo 'Для первичной настройки выполните sudo bash configure-server.sh из каталога комплекта.' ;; esac
fi
case " $components " in *' sambaadm-helper '*) echo 'Укажите helper.node в /etc/sambaadm-helper/config.yaml. Для управления по SSH или HTTPS настройте доверие по инструкции helper.md.' ;; esac
