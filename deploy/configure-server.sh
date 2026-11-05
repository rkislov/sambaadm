#!/bin/bash
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077
cd /etc/sambaadm
[[ $EUID == 0 ]] || { echo 'Запустите через sudo' >&2; exit 1; }
exec 9>/run/sambaadm-configure.lock
flock -n 9 || { echo 'Настройка уже выполняется' >&2; exit 1; }
rpm -V sambaadm || { echo 'Для первоначальной настройки требуется исходный RPM' >&2; exit 1; }
if systemctl is-active --quiet sambaadm; then echo 'Служба уже запущена' >&2; exit 1; fi
work=$(mktemp -d /etc/sambaadm/.setup-XXXXXX)
trap 'rm -rf -- "$work"' EXIT
chgrp sambaadm "$work"; chmod 0750 "$work"
/usr/bin/sambaadm discover "$@" > "$work/config.yaml"
chgrp sambaadm "$work/config.yaml"; chmod 0640 "$work/config.yaml"
cat "$work/config.yaml"
if [[ -z ${SAMBAADM_PASSWORD:-} ]]; then
  read -rs -p 'Пароль служебной записи: ' SAMBAADM_PASSWORD </dev/tty
  echo >&2
fi
[[ -n $SAMBAADM_PASSWORD && $SAMBAADM_PASSWORD != *$'\n'* && $SAMBAADM_PASSWORD != *$'\r'* ]] || exit 1
export SAMBAADM_PASSWORD
runuser -u sambaadm -- /usr/bin/sambaadm --config "$work/config.yaml" serve --check
escaped=${SAMBAADM_PASSWORD//\\/\\\\}
escaped=${escaped//\"/\\\"}
printf 'SAMBAADM_PASSWORD="%s"\n' "$escaped" > "$work/env"
unset SAMBAADM_PASSWORD escaped
ln config.yaml "$work/original.yaml"
ln env "$work/original.env"
rollback() {
  systemctl stop sambaadm || true
  mv -f "$work/original.yaml" config.yaml
  mv -f "$work/original.env" env
}
trap 'rollback' ERR
trap 'rollback; exit 1' INT TERM HUP
mv "$work/env" env
mv "$work/config.yaml" config.yaml
systemctl start sambaadm
systemctl enable sambaadm
trap - ERR INT TERM HUP
echo 'Сервер готов: http://127.0.0.1:8080/settings/helpers'
