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
docker run --rm --network none --add-host dc1.sambaadm.test:127.0.0.1 --entrypoint /usr/bin/python3 -v "$work:/work:ro" "$image" /work/test-domain-backup.py
# The same guard must reject a normal network namespace before restoring data.
docker run --rm --entrypoint /usr/bin/python3 -v "$work:/work:ro" "$image" -c '
import sys
sys.path.insert(0,"/work")
import helper_domain_backup as worker
try:
    worker.require_isolated_network()
except ValueError:
    print("PASS: active external interface blocks restore verification")
else:
    raise AssertionError("non-isolated network accepted")
'
