#!/bin/bash
# Transaction checks in a disposable root container only.
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || exit 1
repo=$(cd -- "$(dirname "$0")/../.." && pwd)
getent group sambaadm >/dev/null || groupadd -r sambaadm
getent passwd sambaadm >/dev/null || useradd -r -g sambaadm -s /bin/false sambaadm
mkdir -p /etc/sambaadm /var/lib/sambaadm-install /run
printf 'original-config\n' > /etc/sambaadm/config.yaml
printf 'SAMBAADM_PASSWORD="literal-$-value"\n' > /etc/sambaadm/env
cat > /usr/bin/sambaadm <<'MOCK'
#!/bin/bash
set -eu
if [[ $3 == certificates && $4 == renew ]];then
 while (($#));do if [[ $1 == --output ]];then printf 'renewed-config\n' > "$2";exit;fi;shift;done
elif [[ $3 == certificates && $4 == verify ]];then
 [[ ${FAIL_VERIFY:-0} == 0 ]]
else exit 2;fi
MOCK
cat > /usr/bin/systemd-run <<'MOCK'
#!/bin/bash
set -eu
[[ $* == *EnvironmentFile=/etc/sambaadm/env* && $* == *'serve --check'* ]]
grep -Fq 'literal-$-value' /etc/sambaadm/env
[[ ${FAIL_PREFLIGHT:-0} == 0 ]]
MOCK
cat > /usr/bin/systemctl <<'MOCK'
#!/bin/bash
set -eu
case $1 in
 is-active) [[ -f /run/test-renew-running ]];;
 stop) rm -f /run/test-renew-running;;
 start) touch /run/test-renew-running;;
 show) echo 42;;
 *) exit 2;;
esac
MOCK
# runuser clears no relevant non-secret test markers; avoid five real sleeps.
printf '#!/bin/sh\nexit 0\n' > /usr/bin/sleep
chmod +x /usr/bin/{sambaadm,systemd-run,systemctl,sleep}
script=$repo/deploy/sambaadm-renew-certificates
touch /run/test-renew-running
FAIL_PREFLIGHT=1 "$script" > /run/preflight.log 2>&1 && exit 1
grep -qx original-config /etc/sambaadm/config.yaml
[[ -f /run/test-renew-running ]]
FAIL_VERIFY=1 "$script" > /run/rollback.log 2>&1 && exit 1
grep -qx original-config /etc/sambaadm/config.yaml
[[ -f /run/test-renew-running ]]
"$script" > /run/success.log
grep -qx renewed-config /etc/sambaadm/config.yaml
[[ -f /run/test-renew-running ]]
rm /run/test-renew-running
"$script" > /run/stopped.log
[[ ! -e /run/test-renew-running ]]
[[ $(stat -c '%a:%U:%G' /etc/sambaadm/config.yaml) == 640:root:sambaadm ]]
echo 'PASS: renewal preflight, rollback on HTTPS mismatch, success, permissions, literal environment and stopped state'
