#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp internal/service/helper_domain_backup.py internal/service/helper_domain_restore.py testdata/samba/test-domain-restore.py "$work/"
docker build -q -t sambaadm-domain-restore-test testdata/samba >/dev/null
docker run --rm --network none --add-host recover.sambaadm.test:127.0.0.1 --entrypoint /usr/bin/python3 -v "$work:/work:ro" sambaadm-domain-restore-test /work/test-domain-restore.py
