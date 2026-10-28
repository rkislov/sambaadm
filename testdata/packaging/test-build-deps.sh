#!/bin/bash
# Deterministic mirror/deadline tests; no network calls or host mutations.
set -euo pipefail
[[ -f /.dockerenv ]] || { echo 'Run in a disposable ALT container.' >&2; exit 1; }
repo=$(cd -- "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/apt-get" <<'MOCK'
#!/bin/bash
set -eu
[[ "$*" != *'AllowUnauthenticated'* && "$*" != *'--allow-unauthenticated'* && "$*" != *'--nosignature'* ]] || exit 99
source=/etc/apt/sources.list.d/sambaadm-builder.list
[[ $(wc -l < "$source") == 2 ]]
grep -q 'rpm \[p10\]' "$source"
! grep -q x86_64-i586 "$source"
mirror=$(awk 'NR==1{print $3}' "$source")
action=unknown
for arg; do case $arg in update|install|clean) action=$arg;; esac; done
printf '%s %s\n' "$mirror" "$action" >> "$MOCK_APT_LOG"
[[ $action != clean ]] || exit 0
[[ ${MOCK_APT_MODE:-} != allfail ]] || exit 100
if [[ $mirror == http://bad.invalid/altlinux ]]; then
 case ${MOCK_APT_MODE:-} in
  timeout) sleep 3;;
  install-timeout) [[ $action != install ]] || sleep 3; exit 0;;
  *) exit 100;;
 esac
fi
if [[ $action == install ]]; then [[ "$*" == *systemd-analyze* && "$*" == *rpm-build* ]]; fi
MOCK
chmod 755 "$work/bin/apt-get"
export PATH="$work/bin:$PATH" MOCK_APT_LOG="$work/apt.log"
export ALT_APT_MIRRORS='http://bad.invalid/altlinux http://good.invalid/altlinux'
export ALT_APT_UPDATE_TIMEOUT=1 ALT_APT_INSTALL_TIMEOUT=1
for mode in fallback timeout install-timeout; do
 export MOCK_APT_MODE=$mode
 : > "$MOCK_APT_LOG"
 bash "$repo/packaging/alt/install-build-deps.sh" > "$work/$mode.log" 2>&1
 grep -q 'http://good.invalid/altlinux install' "$MOCK_APT_LOG"
 grep -q 'ALT mirror failed or exceeded deadline' "$work/$mode.log"
done
export MOCK_APT_MODE=allfail
if bash "$repo/packaging/alt/install-build-deps.sh" > "$work/failure.log" 2>&1; then
 echo 'All failed mirrors were accepted'; exit 1
fi
grep -q 'All ALT mirrors failed' "$work/failure.log"
export ALT_APT_UPDATE_TIMEOUT=invalid
if bash "$repo/packaging/alt/install-build-deps.sh" > "$work/invalid.log" 2>&1; then
 echo 'Invalid deadline was accepted'; exit 1
fi
echo 'PASS: fallback, update/install deadlines, all-mirror failure and signature policy.'
