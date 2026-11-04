#!/bin/sh
# Native libraries only; a disposable offline domain in a networkless container.
set -eu
cd "$(dirname "$0")/../.."
image=sambaadm-domain-backup-test
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT TERM
cp internal/service/helper_domain_backup.py testdata/samba/test-domain-backup.py "$work/"
docker build -q -t "$image" testdata/samba >/dev/null
docker run --rm --network none --entrypoint /usr/bin/python3 -v "$work:/work:ro" "$image" /work/test-domain-backup.py
