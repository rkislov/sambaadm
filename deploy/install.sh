#!/bin/sh
# Install from a checkout/extracted source tree. Existing configuration is preserved.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root (sudo).' >&2; exit 1; }
[ "$#" = 1 ] && [ -f "$1" ] || { echo "Usage: sudo $0 /path/to/sambaadm-linux-amd64" >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
getent group sambaadm >/dev/null || groupadd --system sambaadm
if ! getent passwd sambaadm >/dev/null; then
  nologin=$(command -v nologin || true)
  [ -n "$nologin" ] || nologin=/bin/false
  useradd --system --gid sambaadm --home-dir /var/lib/sambaadm --no-create-home --shell "$nologin" sambaadm
fi
install -d -o root -g sambaadm -m 0750 /etc/sambaadm
install -d -o sambaadm -g sambaadm -m 0750 /var/log/sambaadm
install -m 0755 "$1" /usr/local/bin/sambaadm
if [ ! -e /etc/sambaadm/config.yaml ]; then
  install -o root -g sambaadm -m 0640 "$source_dir/configs/config.example.yaml" /etc/sambaadm/config.yaml
fi
if [ ! -e /etc/sambaadm/env ]; then
  (umask 077; printf '%s\n' '# Set the password for ldap.bind.user before starting:' '# SAMBAADM_PASSWORD="replace-me"' > /etc/sambaadm/env)
fi
install -m 0644 "$source_dir/deploy/sambaadm.service" /etc/systemd/system/sambaadm.service
systemctl daemon-reload
printf '%s\n' 'Installed. Existing config/env were preserved.' 'Edit /etc/sambaadm/config.yaml and /etc/sambaadm/env, then:' '  systemctl enable --now sambaadm' 'For an already running service, apply the upgrade with: systemctl restart sambaadm'
