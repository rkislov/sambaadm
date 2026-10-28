#!/bin/bash
# Run only inside the disposable ALT builder. Keep repository signature checks enabled.
set -euo pipefail
[[ -f /.dockerenv || ${SAMBAADM_RPM_CONTAINER_BUILD:-} == 1 ]] || { echo 'Use the ALT build container.' >&2; exit 1; }
mirrors=${ALT_APT_MIRRORS:-'http://mirror.yandex.ru/altlinux http://mirror.truenetwork.ru/altlinux http://ftp.altlinux.org/pub/distributions/ALTLinux'}
update_timeout=${ALT_APT_UPDATE_TIMEOUT:-60}
install_timeout=${ALT_APT_INSTALL_TIMEOUT:-180}
for limit in "$update_timeout" "$install_timeout"; do
 [[ $limit =~ ^[1-9][0-9]*$ ]] || { echo 'APT timeout must be a positive integer.' >&2; exit 2; }
done
arch=$(uname -m)
case $arch in x86_64|aarch64) ;; *) echo "Unsupported ALT architecture: $arch" >&2; exit 2;; esac
source_file=/etc/apt/sources.list.d/sambaadm-builder.list
mkdir -p /etc/apt/sambaadm-empty-sources /var/lib/apt/lists/partial
options=(-o "Dir::Etc::sourcelist=$source_file" -o Dir::Etc::sourceparts=/etc/apt/sambaadm-empty-sources
 -o Acquire::http::Timeout=20 -o Acquire::Retries=2 -o Acquire::http::No-Cache=true)
for mirror in $mirrors; do
 [[ $mirror == http://* && $mirror != *'@'* ]] || { echo 'Bootstrap APT mirror must be an HTTP URL without credentials.' >&2; exit 2; }
 mirror=${mirror%/}
 printf 'rpm [p10] %s p10/branch/%s classic\nrpm [p10] %s p10/branch/noarch classic\n' "$mirror" "$arch" "$mirror" > "$source_file"
 # Never fall back to stale indexes from an unsuccessful mirror.
 find /var/lib/apt/lists -type f ! -name lock -delete
 echo "ALT build dependencies: mirror=$mirror update_timeout=${update_timeout}s install_timeout=${install_timeout}s"
 if timeout --kill-after=10s "${update_timeout}s" apt-get "${options[@]}" update &&
    timeout --kill-after=10s "${install_timeout}s" apt-get "${options[@]}" install -y \
      rpm-build file shadow-utils systemd systemd-analyze util-linux tar coreutils; then
  apt-get "${options[@]}" clean
  echo "ALT build dependencies ready: $mirror"
  exit 0
 fi
 echo "ALT mirror failed or exceeded deadline: $mirror; trying the next mirror." >&2
done
echo 'All ALT mirrors failed. Check network, signed repository indexes and mirror availability.' >&2
exit 1
