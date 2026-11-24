#!/bin/bash
# Run inside ALT p10/p11 with rpm-build installed.
set -euo pipefail
if (( $# != 1 )); then
 echo 'Usage: build-caja-rpm.sh OUTPUT_DIRECTORY' >&2
 exit 2
fi
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$1"
out=$(realpath "$1")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$repo/contrib/caja-shadow-copies/sambaadm_previous_versions.py" "$work/SOURCES/"
cp "$repo/contrib/caja-shadow-copies/README.md" "$repo/LICENSE" "$work/SOURCES/"
cp "$repo/packaging/alt/caja-smb-previous-versions.spec" "$work/SPECS/"
builder=()
if [[ $(id -u) == 0 ]]; then
 getent passwd rpm-builder >/dev/null || useradd -r -d /tmp -s /bin/false rpm-builder
 chown -R rpm-builder "$work"
 builder=(runuser -u rpm-builder --)
fi
"${builder[@]}" rpmbuild -ba --buildroot "$work/BUILDROOT" --define "_topdir $work" \
 "$work/SPECS/caja-smb-previous-versions.spec"
find "$work/RPMS" "$work/SRPMS" -type f -name '*.rpm' -exec cp -v '{}' "$out/" \;
(cd "$out" && sha256sum caja-smb-previous-versions-*.rpm > SHA256SUMS)
