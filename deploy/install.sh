#!/bin/sh
# Install from a checkout/extracted source tree. Existing configuration is preserved.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root (sudo).' >&2; exit 1; }
[ "$#" = 1 ] && [ -f "$1" ] || { echo "Usage: sudo $0 /path/to/sambaadm-linux-amd64" >&2; exit 1; }
if command -v rpm >/dev/null 2>&1 && rpm -q sambaadm >/dev/null 2>&1; then
  echo 'RPM installation detected; use sambaadm-package update instead.' >&2
  exit 1
fi
was_active=false
if systemctl is-active --quiet sambaadm; then was_active=true; fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
getent group sambaadm >/dev/null || groupadd --system sambaadm
if ! getent passwd sambaadm >/dev/null; then
  nologin=$(command -v nologin || true)
  [ -n "$nologin" ] || nologin=/bin/false
  useradd --system --gid sambaadm --home-dir /var/lib/sambaadm --no-create-home --shell "$nologin" sambaadm
fi
install -d -o root -g sambaadm -m 0750 /etc/sambaadm
install -d -o root -g root -m 0755 /usr/local/libexec
install -m 0755 "$source_dir/deploy/sambaadm-prepare-logs" /usr/local/libexec/sambaadm-prepare-logs
/usr/local/libexec/sambaadm-prepare-logs
# Rename a new inode over the executable, including while the old one is running.
new_binary=$(mktemp /usr/local/bin/.sambaadm.XXXXXX)
trap 'rm -f "$new_binary"' EXIT
install -m 0755 "$1" "$new_binary"
mv -f "$new_binary" /usr/local/bin/sambaadm
trap - EXIT
if [ ! -e /etc/sambaadm/config.yaml ] && [ ! -L /etc/sambaadm/config.yaml ]; then
  if /usr/local/bin/sambaadm discover --output /etc/sambaadm/config.yaml; then
    chown root:sambaadm /etc/sambaadm/config.yaml
    chmod 0640 /etc/sambaadm/config.yaml
  else
    [ ! -e /etc/sambaadm/config.yaml ] && [ ! -L /etc/sambaadm/config.yaml ] || exit 1
    echo 'Домен не обнаружен. Установлен пример config.yaml; настройте LDAP вручную.' >&2
    install -o root -g sambaadm -m 0640 "$source_dir/configs/config.example.yaml" /etc/sambaadm/config.yaml
  fi
fi
if [ ! -e /etc/sambaadm/env ]; then
  (umask 077; printf '%s\n' '# Set the password for ldap.bind.user before starting:' '# SAMBAADM_PASSWORD="replace-me"' > /etc/sambaadm/env)
fi
install -m 0644 "$source_dir/deploy/sambaadm.service" /etc/systemd/system/sambaadm.service
systemctl daemon-reload
if [ "$was_active" = true ]; then systemctl restart sambaadm; fi
printf '%s\n' 'Installed. Existing config/env were preserved.' 'Edit /etc/sambaadm/config.yaml and /etc/sambaadm/env, then:' '  systemctl enable --now sambaadm' 'For an already running service, apply the upgrade with: systemctl restart sambaadm'
