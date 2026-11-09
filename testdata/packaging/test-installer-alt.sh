#!/bin/bash
# Real first install, cross-version update and repeat via the combined installer.
set -euo pipefail
[[ -f /.dockerenv && $(id -u) == 0 ]] || { echo 'Disposable root Docker container required'; exit 1; }
repo=$(cd -- "$(dirname "$0")/../.." && pwd)
binary=${1:?main binary}; helper=${2:?helper binary}
work=$(mktemp -d);trap 'rm -rf "$work"' EXIT
mkdir -p "$work/rpms" "$work/old" "$work/new"
for version in 0.37.8 0.37.9; do
 bash "$repo/packaging/alt/build-rpm.sh" "$version" "$binary" "$work/rpms"
 bash "$repo/packaging/alt/build-helper-rpm.sh" "$version" "$helper" "$work/rpms"
done
arch=$(uname -m)
for entry in old:0.37.8 new:0.37.9; do
 dir="$work/${entry%:*}";version=${entry#*:}
 cp "$repo/deploy/setup-alt.sh" "$dir/"
 cp "$work/rpms/sambaadm-$version-alt1.$arch.rpm" "$dir/sambaadm.rpm"
 cp "$work/rpms/sambaadm-helper-$version-alt1.$arch.rpm" "$dir/sambaadm-helper.rpm"
done
sh "$work/old/setup-alt.sh" all
printf '\n# operator setting\n' >> /etc/sambaadm/config.yaml
printf '\n# helper operator setting\n' >> /etc/sambaadm-helper/config.yaml
printf 'SAMBAADM_PASSWORD="operator-secret"\n' > /etc/sambaadm/env
mkdir -p /etc/sambaadm/keys /var/lib/sambaadm/certificates
printf 'preserved-key\n' > /etc/sambaadm/keys/operator.key
printf 'preserved-state\n' > /var/lib/sambaadm/certificates/operator.pem
sha256sum /etc/sambaadm/config.yaml /etc/sambaadm/env /etc/sambaadm-helper/config.yaml /etc/sambaadm/keys/operator.key /var/lib/sambaadm/certificates/operator.pem > "$work/before.sha"
sh "$work/new/setup-alt.sh" all --check
[[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.37.8 ]]
sh "$work/new/setup-alt.sh" all
[[ $(rpm -q --qf '%{VERSION}' sambaadm) == 0.37.9 ]]
[[ $(rpm -q --qf '%{VERSION}' sambaadm-helper) == 0.37.9 ]]
sha256sum -c "$work/before.sha"
sh "$work/new/setup-alt.sh" all
sh "$work/new/setup-alt.sh" all --check
bash "$repo/deploy/sambaadm-package" install "$work/new/sambaadm.rpm"
sha256sum -c "$work/before.sha"
test -n "$(find /var/lib/sambaadm-install -name config.tar -print -quit)"
echo 'PASS: combined installer initial install/update/repeat/check preserves configuration, credentials, keys and certificate state.'
