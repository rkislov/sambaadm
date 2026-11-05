#!/bin/sh
# Assemble release RPMs and deployment instructions into a per-architecture kit.
set -eu
version=${1#v}
arch=$2
dist=$(cd "$3" && pwd)
root=$(CDPATH= cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
name="sambaadm-install-$version-$arch"
kit="$tmp/$name"
mkdir "$kit"
for pkg in sambaadm sambaadm-helper; do
  cp "$dist/$pkg-$version-alt1.$arch.rpm" "$kit/$pkg.rpm"
done
cp "$root/deploy/configure-server.sh" "$root/deploy/setup-alt.sh" "$root/docs/alt-install.md" "$root/docs/helper.md" "$kit/"
tar -czf "$dist/$name.tar.gz" -C "$tmp" "$name"
