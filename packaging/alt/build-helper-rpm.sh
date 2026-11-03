#!/bin/bash
set -euo pipefail
if (( $# != 3 )); then echo 'Usage: build-helper-rpm.sh VERSION STATIC_HELPER_BINARY OUTPUT_DIRECTORY' >&2; exit 2; fi
version=${1#v}; binary=$(realpath "$2"); mkdir -p "$3"; out=$(realpath "$3")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Use X.Y.Z version.' >&2; exit 2; }
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
arch=$(uname -m)
case $arch in x86_64|aarch64) ;; *) echo 'Unsupported architecture' >&2; exit 2;; esac
file "$binary" | grep -q 'statically linked'
case $arch in x86_64) file "$binary" | grep -q 'x86-64';; aarch64) file "$binary" | grep -q 'ARM aarch64';; esac
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS,payload}
cp "$binary" "$work/payload/sambaadm-helper"
cp "$repo/deploy/sambaadm-helper.service" "$work/payload/"
cp "$repo/configs/helper.example.yaml" "$work/payload/helper-config.yaml"
cp "$repo/docs/helper.md" "$repo/LICENSE" "$repo/NOTICE" "$work/payload/"
cp "$repo/packaging/alt/sambaadm-helper.spec" "$work/SPECS/"
builder=()
if [[ $(id -u) == 0 ]]; then
 getent passwd rpm-builder >/dev/null
 chown -R rpm-builder:rpm-builder "$work"
 builder=(runuser -u rpm-builder --)
fi
"${builder[@]}" rpmbuild -bb --buildroot "$work/BUILDROOT" --define "_topdir $work" \
 --define "payload_dir $work/payload" --define "package_version $version" \
 --define "package_release alt1" "$work/SPECS/sambaadm-helper.spec"
find "$work/RPMS" -type f -name '*.rpm' -exec cp -v '{}' "$out/" \;
