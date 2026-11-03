#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv && $(id -u) == 0 ]] || { echo 'Disposable Docker container required.' >&2; exit 1; }
repo=$(cd -- "$(dirname "$0")/../.." && pwd)
binary=${1:?static helper binary required}
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src" "$work/rpms"
cp -a "$repo/packaging" "$repo/deploy" "$repo/docs" "$repo/configs" "$repo/LICENSE" "$repo/NOTICE" "$work/src/"
for version in 0.31.0 0.31.1; do
 printf '\n# Shipped helper default %s\n' "$version" >> "$work/src/configs/helper.example.yaml"
 bash "$work/src/packaging/alt/build-helper-rpm.sh" "$version" "$binary" "$work/rpms"
done
arch=$(uname -m)
rpm -Uvh "$work/rpms/sambaadm-helper-0.31.0-alt1.$arch.rpm"
/usr/bin/sambaadm-helper version
test "$(stat -c '%a:%U:%G' /etc/sambaadm-helper/config.yaml)" == 600:root:root
test "$(stat -c '%a:%U:%G' /var/lib/sambaadm-helper)" == 700:root:root
test ! -e /etc/systemd/system/multi-user.target.wants/sambaadm-helper.service
systemd-analyze verify /lib/systemd/system/sambaadm-helper.service
if /usr/bin/sambaadm-helper stdio </dev/null; then echo 'Unconfigured helper accepted a request' >&2; exit 1; fi
printf '\n# Operator configuration\n' >> /etc/sambaadm-helper/config.yaml
sha256sum /etc/sambaadm-helper/config.yaml > "$work/config.sha"
printf 'retained data\n' > /var/lib/sambaadm-helper/backups/keep
rpm -Uvh "$work/rpms/sambaadm-helper-0.31.1-alt1.$arch.rpm"
sha256sum -c "$work/config.sha"
test -f /etc/sambaadm-helper/config.yaml.rpmnew
test -s /var/lib/sambaadm-helper/backups/keep
rpm -e sambaadm-helper
test ! -e /usr/bin/sambaadm-helper
test -f /etc/sambaadm-helper/config.yaml.rpmsave
test -s /var/lib/sambaadm-helper/backups/keep
echo 'PASS: separate helper RPM install/update/noreplace/permissions/unit/fail-closed/removal/data preservation'
