#!/bin/bash
# Build inside an ALT p10/p11 userspace with rpm-build installed.
set -euo pipefail
if (( $# != 3 )); then echo "Usage: $0 VERSION STATIC_LINUX_BINARY OUTPUT_DIRECTORY" >&2; exit 2; fi
version=${1#v}; binary=$(realpath "$2"); mkdir -p "$3"; out=$(realpath "$3")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Use a numeric release version X.Y.Z.' >&2; exit 2; }
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
arch=$(uname -m)
case $arch in x86_64|aarch64) ;; *) echo "Unsupported architecture $arch" >&2; exit 2;; esac
file "$binary" | grep -q 'statically linked' || { echo 'Expected a static Linux ELF binary.' >&2; exit 1; }
case $arch in x86_64) file "$binary" | grep -q 'x86-64';; aarch64) file "$binary" | grep -q 'ARM aarch64';; esac
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,payload} "$out"
cp "$binary" "$work/payload/sambaadm"
cp "$repo/packaging/alt/"{sambaadm.service,config.yaml,env} "$work/payload/"
cp "$repo/deploy/sambaadm-package" "$work/payload/"
cp "$repo/"{LICENSE,NOTICE} "$work/payload/"
cp "$repo/docs/alt-install.md" "$work/payload/"
systemd-analyze verify "$work/payload/sambaadm.service" 2>"$work/unit-check.log" || {
 # ExecStart is provided by the RPM, not yet installed in the builder.
 sed "s@/usr/bin/sambaadm@$binary@g; s@WorkingDirectory=/var/lib/sambaadm@WorkingDirectory=/tmp@" "$repo/packaging/alt/sambaadm.service" > "$work/sambaadm.service"
 systemd-analyze verify "$work/sambaadm.service"
}
cp "$repo/packaging/alt/sambaadm.spec" "$work/SPECS/"
builder=()
if [[ $(id -u) == 0 ]]; then
 getent passwd rpm-builder >/dev/null || { echo 'Build as an unprivileged user or use packaging/alt/Dockerfile.' >&2; exit 1; }
 chown -R rpm-builder:rpm-builder "$work"
 builder=(runuser -u rpm-builder --)
fi
"${builder[@]}" rpmbuild -bb --buildroot "$work/BUILDROOT" --define "_topdir $work" --define "payload_dir $work/payload" \
 --define "package_version $version" --define "package_release alt1" "$work/SPECS/sambaadm.spec"
find "$work/RPMS" -type f -name '*.rpm' -exec cp -v '{}' "$out/" \;
