#!/bin/bash
# Real ALT RPM lifecycle; systemd calls simulated inside a disposable container.
set -euo pipefail
[[ -f /.dockerenv && $(id -u) == 0 ]] || { echo 'Run only in a disposable Docker container.' >&2; exit 1; }
repo=$(cd -- "$(dirname "$0")/../.." && pwd)
binary=${1:?static native Linux binary required}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$work/rpms"
cp -a "$repo/packaging" "$repo/deploy" "$repo/docs" "$repo/LICENSE" "$repo/NOTICE" "$work/src/"
# Alter shipped examples between versions to exercise .rpmnew behavior.
for version in 0.25.0 0.25.1 0.25.2; do
 if [[ $version == 0.25.2 ]]; then sed -i 's@^ExecStart=.*@ExecStart=/bin/false@' "$work/src/packaging/alt/sambaadm.service"; fi
 printf '\n# Package default %s\n' "$version" >> "$work/src/packaging/alt/config.yaml"
 bash "$work/src/packaging/alt/build-rpm.sh" "$version" "$binary" "$work/rpms"
done
arch=$(uname -m)
old="$work/rpms/sambaadm-0.25.0-alt1.$arch.rpm"
new="$work/rpms/sambaadm-0.25.1-alt1.$arch.rpm"
bad="$work/rpms/sambaadm-0.25.2-alt1.$arch.rpm"
# No active systemd needed for the actual initial installation.
bash "$repo/deploy/sambaadm-package" install "$old"
test "$(rpm -q --qf '%{VERSION}' sambaadm)" == 0.25.0
/usr/bin/sambaadm version
getent passwd sambaadm
[[ $(stat -c '%a' /etc/sambaadm/env) == 600 ]]
[[ $(stat -c '%U:%G' /etc/sambaadm/config.yaml) == root:sambaadm ]]
if [[ ${SAMBAADM_REAL_SYSTEMD:-0} == 1 ]]; then
 [[ $(cat /proc/1/comm) == systemd ]] || { echo 'Real systemd PID 1 required'; exit 1; }
 printf "SAMBAADM_PASSWORD='test-secret'\n" > /etc/sambaadm/env
 printf '\n# operator configuration\n' >> /etc/sambaadm/config.yaml
 sha256sum /etc/sambaadm/config.yaml /etc/sambaadm/env > "$work/before.sha"
 systemctl enable --now sambaadm.service
 systemctl is-active --quiet sambaadm.service
 sambaadm-package update "$new"
 [[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.1 ]]
 sha256sum -c "$work/before.sha"
 first=$(sambaadm-package list | head -1 | cut -d' ' -f1)
 sambaadm-package rollback "$first"
 [[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.0 ]]
 if sambaadm-package update "$bad"; then echo 'Broken unit was accepted'; exit 1; fi
 [[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.0 ]]
 systemctl is-active --quiet sambaadm.service
 systemctl is-enabled --quiet sambaadm.service
 sha256sum -c "$work/before.sha"
 exec 3<>/dev/tcp/127.0.0.1/8080
 printf 'GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
 IFS= read -r response <&3
 [[ $response == *' 200 '* ]]
 exec 3>&-
 systemctl stop sambaadm.service
 sambaadm-package update "$new"
 if systemctl is-active --quiet sambaadm.service; then echo 'Stopped service was started'; exit 1; fi
 rpm -e sambaadm
 test -f /etc/sambaadm/config.yaml.rpmsave
 test -f /etc/sambaadm/env.rpmsave
 echo 'PASS: real ALT p10 systemd start/update/rollback/failure recovery/HTTP/removal.'
 exit 0
fi
# Exercise start/restart/failure handling, keeping a real RPM database/filesystem.
mkdir -p /run/systemd/system /run/lock /etc/systemd/system/sambaadm.service.d
cat > /usr/local/bin/systemctl <<'MOCK'
#!/bin/bash
set -eu
case "$1" in
 is-active) test -f /run/sambaadm-active;;
 stop) rm -f /run/sambaadm-active;;
 start) if [[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.2 ]]; then exit 1; fi; touch /run/sambaadm-active;;
 show) case "$3" in MainPID) echo 321;; NRestarts) echo 0;; *) exit 2;; esac;;
 daemon-reload) :;;
 disable) rm -f /run/sambaadm-enabled;;
 *) exit 2;;
esac
MOCK
chmod 755 /usr/local/bin/systemctl
export PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
printf '\n# operator configuration\n' >> /etc/sambaadm/config.yaml
printf "SAMBAADM_PASSWORD='test-secret'\n" > /etc/sambaadm/env
printf '[Service]\nUMask=0077\n' > /etc/systemd/system/sambaadm.service.d/local.conf
sha256sum /etc/sambaadm/config.yaml /etc/sambaadm/env > "$work/before.sha"
touch /run/sambaadm-active /run/sambaadm-enabled
rm /var/cache/sambaadm-packages/sambaadm-0.25.0-alt1."$arch".rpm
if sambaadm-package update "$new"; then echo 'Missing rollback RPM was accepted'; exit 1; fi
sambaadm-package update "$new" --previous-rpm "$old"
[[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.1 ]]
sha256sum -c "$work/before.sha"
test -f /etc/sambaadm/config.yaml.rpmnew
test -f /run/sambaadm-active
first=$(sambaadm-package list | head -1 | cut -d' ' -f1)
printf '\n# changed after update\n' >> /etc/sambaadm/config.yaml
rm /etc/systemd/system/sambaadm.service.d/local.conf
sambaadm-package rollback "$first"
[[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.0 ]]
sha256sum -c "$work/before.sha"
test -f /etc/systemd/system/sambaadm.service.d/local.conf
test -f /run/sambaadm-active
test -f /run/sambaadm-enabled
# New process fails to start -> previous package and settings must return.
if sambaadm-package update "$bad"; then echo 'Broken update was accepted'; exit 1; fi
[[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.25.0 ]]
sha256sum -c "$work/before.sha"
test -f /run/sambaadm-active
# Stopped service remains stopped after a valid update.
rm /run/sambaadm-active
sambaadm-package update "$new"
test ! -f /run/sambaadm-active
# Path traversal and concurrent helper operations must be rejected.
if sambaadm-package rollback ../../etc; then exit 1; fi
(flock 8; sleep 3) 8>/run/lock/sambaadm-package.lock & lock_pid=$!
sleep 1
if sambaadm-package list; then exit 1; fi
wait "$lock_pid"
# Config replacement + deletion lifecycle, without destroying secrets.
rpm -e sambaadm
test -f /etc/sambaadm/config.yaml.rpmsave
test -f /etc/sambaadm/env.rpmsave
test -d /var/lib/sambaadm-packages
printf 'PASS: ALT RPM install/update/rollback/recovery/config/permissions/removal (simulated systemd).\n'
