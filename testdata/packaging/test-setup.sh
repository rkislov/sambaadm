#!/bin/bash
# Exercise first-start transactions without touching a host service or real AD.
set -euo pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || { echo 'Disposable root Docker container required';exit 1; }
repo=$(cd -- "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d);trap 'rm -rf "$work"' EXIT
getent group sambaadm >/dev/null || groupadd -r sambaadm
mkdir -p "$work/bin" "$work/etc" "$work/state"
cp "$repo/packaging/alt/config.yaml" "$work/sample"
cp "$work/sample" "$work/etc/config.yaml"
printf '# original env\n' > "$work/etc/env";chmod 600 "$work/etc/env"
export SETUP_TEST_DIR=$work SAMBAADM_PASSWORD='setup-password-$-"-\-test'
export PATH="$work/bin:$PATH"
cat > "$work/bin/sambaadm" <<'MOCK'
#!/bin/bash
set -eu
if [[ $1 == discover ]]; then
 shift;ca='';legacy=false;while (($#));do case $1 in --ca) ca=$2;shift 2;;--allow-legacy-cn) legacy=true;shift;;*) shift 2;;esac;done
 printf 'ldap:\n  uri: ldaps://dc1.example.com:636\n  bind:\n    user: svc-sambaadm@example.com\n  ca_cert: "%s"\n  allow_legacy_cn: %s\n' "$ca" "$legacy"
else
 [[ ${SETUP_FAIL_PREFLIGHT:-0} == 0 ]] || exit 7
 if [[ ${SETUP_REQUIRE_LEGACY:-0} == 1 ]] && ! grep -q 'allow_legacy_cn: true' "$2";then echo 'certificate relies on legacy Common Name';exit 7;fi
 [[ -n ${SAMBAADM_PASSWORD:-} ]]
fi
MOCK
cat > "$work/bin/systemctl" <<'MOCK'
#!/bin/bash
set -eu
root=$SETUP_TEST_DIR
case $1 in
 is-active) [[ -e $root/running ]];;
 is-enabled) [[ -e $root/enabled ]];;
 start) [[ ${SETUP_FAIL_START:-0} == 0 ]] || exit 8;touch "$root/running";;
 stop) rm -f "$root/running";;
 show) [[ ! -e $root/running ]] || echo 4242;;
 enable) touch "$root/enabled";;
 disable) rm -f "$root/enabled";;
 *) exit 3;;
esac
MOCK
cat > "$work/bin/runuser" <<'MOCK'
#!/bin/bash
shift 3
exec "$@"
MOCK
printf '#!/bin/sh\nexit 0\n' > "$work/bin/sleep"
printf '#!/bin/sh\nexit 1\n' > "$work/bin/testparm"
chmod 755 "$work/bin/"*
cat > "$work/run" <<RUN
#!/bin/bash
set -euo pipefail
source '$repo/deploy/sambaadm-setup'
setup_main '$work/etc' '$work/state' '$work/lock' '$work/sample' '$work/bin/sambaadm' "\$@"
RUN
chmod 755 "$work/run"
args=(--yes --realm example.com --dc dc1.example.com --user svc@example.com)
# Check-only is also usable before first start and must not replace files.
sha256sum "$work/etc/config.yaml" "$work/etc/env" > "$work/initial.sha"
"$work/run" "${args[@]}" --check > "$work/check.log" 2>&1
sha256sum -c "$work/initial.sha"
[[ ! -e $work/running && ! -e $work/enabled ]]
# Failed preflight retains configuration and does not create an activation backup.
if SETUP_FAIL_PREFLIGHT=1 "$work/run" "${args[@]}" > "$work/fail-check.log" 2>&1;then exit 1;fi
sha256sum -c "$work/initial.sha"
[[ -z $(find "$work/state" -mindepth 1 -print -quit) ]]
# Failed first start rolls back both YAML and credentials.
if SETUP_FAIL_START=1 "$work/run" "${args[@]}" > "$work/fail-start.log" 2>&1;then exit 1;fi
sha256sum -c "$work/initial.sha"
[[ ! -e $work/running && ! -e $work/enabled ]]
# CA in a private directory must be staged for the service and retained at a stable path.
mkdir -m700 "$work/private";printf 'test CA\n' > "$work/private/ca.pem"
SETUP_REQUIRE_LEGACY=1 "$work/run" "${args[@]}" --allow-legacy-cn --ca "$work/private/ca.pem" > "$work/success.log" 2>&1
[[ -e $work/running && -e $work/enabled ]]
cmp "$work/private/ca.pem" "$work/etc/domain-ca.pem"
grep -q 'allow_legacy_cn: true' "$work/etc/config.yaml"
grep -q "$work/etc/domain-ca.pem" "$work/etc/config.yaml"
[[ $(stat -c '%a:%U:%G' "$work/etc/config.yaml") == 640:root:sambaadm ]]
[[ $(stat -c '%a' "$work/etc/env") == 600 ]]
# EnvironmentFile keeps dollar signs literal; it must never be sourced as shell code.
grep -Fqx 'SAMBAADM_PASSWORD="setup-password-$-\"-\\-test"' "$work/etc/env"
sha256sum "$work/etc/config.yaml" "$work/etc/env" "$work/etc/domain-ca.pem" > "$work/ready.sha"
if "$work/run" "${args[@]}" > "$work/repeat.log" 2>&1;then exit 1;fi
sha256sum -c "$work/ready.sha"
"$work/run" "${args[@]}" --check > "$work/recheck.log" 2>&1
sha256sum -c "$work/ready.sha"
[[ -e $work/running && -e $work/enabled ]]
# Existing CA also returns on rollback when the replacement does not supply one.
if SETUP_FAIL_START=1 "$work/run" "${args[@]}" --replace > "$work/replace-fail.log" 2>&1;then exit 1;fi
sha256sum -c "$work/ready.sha"
! grep -F 'setup-password' "$work/"*.log
"$repo/deploy/sambaadm-setup" --help | grep -q 'sambaadm-setup'
echo 'PASS: setup preflight/check, password escaping, stable CA, permissions, first start, repeat protection and rollback'
